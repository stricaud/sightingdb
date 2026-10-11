//! Turning MISP's ZMQ publications into sightings.
//!
//! MISP's publisher sends one frame per message shaped as `<topic> <json>`, so
//! the topic has to come off before the body will parse. The body is either a
//! single attribute, or a whole event carrying attributes directly and inside
//! objects. Rather than model MISP's schema — which varies by version and by
//! which plugin published — we walk the JSON for the parts we need and ignore
//! everything else.

use std::collections::HashMap;

use serde::Deserialize;
use serde_json::Value;

/// One observation ready to be written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sighting {
    pub namespace: String,
    pub value: String,
    /// Unix seconds, or `None` to record it as seen now.
    pub timestamp: Option<i64>,
    /// End of the observation window, when the source gives a range. The first
    /// write lands at `timestamp` and the rest at `last_timestamp`, so both
    /// ends of the window survive.
    pub last_timestamp: Option<i64>,
    /// How many observations this represents. STIX carries a count; MISP
    /// attributes are one apiece.
    pub count: u64,
    /// What the source said about the value beyond the value itself — its
    /// observable type, markings, who published it. Written as tags on the
    /// attribute, which is what the STIX export reads back. See the tag
    /// vocabulary in the README.
    pub tags: Vec<String>,
}

impl Sighting {
    /// A single observation, which is what most sources publish.
    pub fn once(
        namespace: impl Into<String>,
        value: impl Into<String>,
        timestamp: Option<i64>,
    ) -> Self {
        Self {
            namespace: namespace.into(),
            value: value.into(),
            timestamp,
            last_timestamp: None,
            count: 1,
            tags: Vec::new(),
        }
    }

    pub fn with_tags(mut self, tags: Vec<String>) -> Self {
        self.tags = tags;
        self
    }
}

/// Make one tag safe to put in a comma-separated set.
///
/// A comma inside a tag would split it in two, so it becomes a semicolon —
/// keeping the information rather than dropping the tag, which is what matters
/// for a name or a description coming from someone else's feed.
pub fn sanitize_tag(tag: &str) -> String {
    tag.trim().replace(',', ";")
}

/// Which MISP attribute types are ingested, and where they land.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mapping {
    /// MISP attribute type (`ip-src`, `md5`, ...) to namespace.
    pub types: HashMap<String, String>,
    /// Where unmapped types go. `None` drops them.
    pub default_namespace: Option<String>,
    /// Ingest only attributes MISP has flagged as actionable.
    pub require_to_ids: bool,
    /// Where the SHA-256 of every ingested value is also recorded. This is
    /// what MISP's own SightingDB connection queries: it never sends a value,
    /// only `hash('sha256', $attribute['value'])`, against one namespace.
    pub hashed_namespace: Option<String>,
    /// Whether the value itself is written to its mapped namespace. `false`
    /// keeps only the digest, so the database never holds the cleartext; the
    /// configuration refuses it without a `hashed_namespace`.
    pub store_values: bool,
}

impl Default for Mapping {
    fn default() -> Self {
        Self {
            types: HashMap::new(),
            default_namespace: None,
            require_to_ids: false,
            hashed_namespace: None,
            store_values: true,
        }
    }
}

impl Mapping {
    fn namespace_for(&self, misp_type: &str) -> Option<&str> {
        self.types
            .get(misp_type)
            .map(String::as_str)
            .or(self.default_namespace.as_deref())
    }
}

/// Native format, for publishers that speak SightingDB rather than MISP.
#[derive(Debug, Deserialize)]
struct NativeBatch {
    items: Vec<NativeItem>,
}

#[derive(Debug, Deserialize)]
struct NativeItem {
    namespace: String,
    value: String,
    #[serde(default)]
    timestamp: Option<i64>,
}

/// What an event says that its attributes inherit.
///
/// MISP puts the things that describe a whole report on the *event* — above
/// all the TLP marking, and usually the galaxy and OSINT tags — and the
/// attributes underneath carry only what is specific to them. An importer that
/// reads attribute tags alone therefore loses the marking: a sighting from a
/// `tlp:amber` event arrives unmarked and exports unmarked, which is the one
/// kind of data loss here that could mislead someone about how a value may be
/// shared.
#[derive(Debug, Default, Clone)]
struct EventContext {
    /// The event's own tags, already sanitized.
    tags: Vec<String>,
    /// The event id, for attributes that do not name it themselves.
    id: Option<String>,
}

impl EventContext {
    fn of(event: &Value) -> Self {
        let tags = match event.get("Tag") {
            Some(Value::Array(tags)) => tags
                .iter()
                .filter_map(|tag| tag.get("name").and_then(Value::as_str))
                .map(sanitize_tag)
                .collect(),
            _ => Vec::new(),
        };
        // The uuid is stable across servers where a numeric id is not, so it
        // is preferred when both are present.
        let id = event
            .get("uuid")
            .and_then(id_like)
            .or_else(|| event.get("id").and_then(id_like));
        Self { tags, id }
    }
}

/// Taxonomies where exactly one value can be true at a time.
///
/// An attribute that carries its own `tlp:` must not also inherit the event's:
/// a value tagged both `tlp:amber` and `tlp:white` says nothing useful about
/// how it may be shared, and the STIX export would pick whichever came first.
/// MISP's own model is that the more specific tag wins, so the attribute's is
/// kept and the event's dropped.
///
/// Only TLP for now. Most taxonomies are genuinely multi-valued — an event and
/// an attribute can each contribute a different `misp-galaxy:` tag and both are
/// worth having — so this is a list of exceptions rather than a rule.
const SINGLE_VALUED: &[&str] = &["tlp"];

/// Does `candidate` belong to a single-valued taxonomy that `tags` already
/// has an entry for?
fn conflicts(tags: &[String], candidate: &str) -> bool {
    let Some((namespace, _)) = candidate.split_once(':') else {
        return false;
    };
    if !SINGLE_VALUED.contains(&namespace) {
        return false;
    }
    tags.iter().any(|tag| {
        tag.split_once(':')
            .is_some_and(|(known, _)| known == namespace)
    })
}

/// Remove the `<topic> ` prefix MISP puts in front of the JSON body.
///
/// Publishers that put the topic in its own frame are handled by the caller, so
/// a body that already starts with `{` is passed through untouched.
pub fn strip_topic(text: &str) -> &str {
    let trimmed = text.trim_start();
    if trimmed.starts_with('{') || trimmed.starts_with('[') {
        return trimmed;
    }
    match trimmed.find(' ') {
        Some(space) => trimmed[space + 1..].trim_start(),
        None => trimmed,
    }
}

/// Pull every sighting out of one MISP message body.
pub fn parse(json: &str, mapping: &Mapping) -> Result<Vec<Sighting>, serde_json::Error> {
    let value: Value = serde_json::from_str(json)?;
    let mut sightings = Vec::new();

    // Read first, because a single-attribute publication carries the event as
    // context beside the attribute rather than around it — so the attribute
    // below inherits the marking too.
    let event = value.get("Event");
    let context = event.map(EventContext::of).unwrap_or_default();

    // A single attribute, which is what `misp_json_attribute` carries.
    if let Some(attribute) = value.get("Attribute") {
        collect(attribute, mapping, &context, &mut sightings);
    }

    // A whole event, which is what `misp_json` carries on publish.
    if let Some(event) = event {
        if let Some(attributes) = event.get("Attribute") {
            collect(attributes, mapping, &context, &mut sightings);
        }
        // Attributes can also hang off objects within the event.
        if let Some(Value::Array(objects)) = event.get("Object") {
            for object in objects {
                if let Some(attributes) = object.get("Attribute") {
                    collect(attributes, mapping, &context, &mut sightings);
                }
            }
        }
    }

    Ok(sightings)
}

/// Parse the native batch format.
pub fn parse_native(json: &str) -> Result<Vec<Sighting>, serde_json::Error> {
    let batch: NativeBatch = serde_json::from_str(json)?;
    Ok(batch
        .items
        .into_iter()
        .map(|item| Sighting::once(item.namespace, item.value, item.timestamp))
        .collect())
}

/// Accepts either one attribute object or an array of them.
fn collect(node: &Value, mapping: &Mapping, context: &EventContext, out: &mut Vec<Sighting>) {
    match node {
        Value::Array(items) => {
            for item in items {
                collect(item, mapping, context, out);
            }
        }
        Value::Object(_) => attribute_to_sightings(node, mapping, context, out),
        _ => {}
    }
}

/// The plain sighting of an attribute and, when configured, its digest.
fn attribute_to_sightings(
    attribute: &Value,
    mapping: &Mapping,
    context: &EventContext,
    out: &mut Vec<Sighting>,
) {
    if mapping.require_to_ids && !truthy(attribute.get("to_ids")) {
        return;
    }

    let Some(misp_type) = attribute.get("type").and_then(Value::as_str) else {
        return;
    };

    // Composite types (`filename|md5`) live in `value`; some publishers only
    // fill in `value1`.
    let Some(value) = attribute
        .get("value")
        .and_then(Value::as_str)
        .or_else(|| attribute.get("value1").and_then(Value::as_str))
        .filter(|value| !value.is_empty())
    else {
        return;
    };

    let namespace = mapping.namespace_for(misp_type);
    let hashed_namespace = mapping.hashed_namespace.as_deref();
    // Neither write would happen, so do not bother building the tags. An
    // unmapped type with `store_values = false` and no hashed namespace cannot
    // happen — the configuration refuses it — but costs nothing to handle.
    let plain = namespace.filter(|_| mapping.store_values);
    if plain.is_none() && hashed_namespace.is_none() {
        return;
    }

    let timestamp = timestamp_of(attribute);
    let tags = tags_of(attribute, misp_type, context);

    // The digest is written for *every* attribute that passes the filters
    // above, mapped or not. MISP looks up whatever attribute it is showing,
    // of any type, in the one namespace its connection names — so hashing only
    // the mapped types would leave MISP blind to the rest for no gain. A
    // digest gives nothing away about the value, and `[zmq.types]` still
    // decides where (and whether) the cleartext goes. `require_to_ids` is a
    // statement about which attributes are worth recording at all, so it
    // applies to both.
    //
    // It is the digest of the whole `value` field as MISP holds it: for
    // `ip-dst|port` that is `1.2.3.4|80`, never one half, because that is
    // exactly the string MISP hashes when it asks. (A publisher that sends
    // only `value1` gets that hashed instead; for a non-composite type it is
    // the same string, and for a composite it is the best there is.)
    let hashed = hashed_namespace.map(|hashed_namespace| {
        Sighting::once(hashed_namespace, sha256_hex(value), timestamp).with_tags(hashed_tags(&tags))
    });

    if let Some(namespace) = plain {
        out.push(Sighting::once(namespace, value, timestamp).with_tags(tags));
    }
    out.extend(hashed);
}

/// The lowercase hex SHA-256 of a value's UTF-8 bytes, which is what PHP's
/// `hash('sha256', $value)` returns and therefore what MISP asks for.
pub fn sha256_hex(value: &str) -> String {
    use sha2::{Digest, Sha256};
    use std::fmt::Write;

    let digest = Sha256::digest(value.as_bytes());
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        // Writing to a String cannot fail.
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

/// Tag families that are kept off a digest.
///
/// The point of storing only a digest is that the database cannot say what
/// the value was, so anything that would say it for the digest goes:
///
/// - `description:` is the attribute's free-text comment, which routinely
///   restates the value or enough of it ("C2 at 1.2.3.4", "dropper.exe").
/// - `misp-event:` points at the MISP event holding the cleartext: anyone who
///   can read that event can undo the hashing by following the pointer.
/// - `stix-type:` would make the STIX export claim the digest *is* an
///   `ipv4-addr` or a `domain-name` and build a pattern saying something
///   false. The `misp-type:` tag stays, since a type is not a value.
///
/// Markings (`tlp:`), galaxy and taxonomy tags, and `misp-category:` describe
/// the value rather than spell it, and the marking in particular must travel
/// with whatever is shared.
const VALUE_REVEALING_TAGS: &[&str] = &["description:", "misp-event:", "stix-type:"];

fn hashed_tags(tags: &[String]) -> Vec<String> {
    tags.iter()
        .filter(|tag| {
            !VALUE_REVEALING_TAGS
                .iter()
                .any(|family| tag.starts_with(family))
        })
        .cloned()
        .collect()
}

/// What MISP knows about an attribute, as tags.
///
/// The MISP type is kept as it was published *and* translated to the STIX
/// observable type where there is one, so the STIX export can build a pattern
/// without having to know anything about MISP.
fn tags_of(attribute: &Value, misp_type: &str, context: &EventContext) -> Vec<String> {
    let mut tags = vec![format!("misp-type:{misp_type}")];

    if let Some(stix_type) = stix_type_for_misp(misp_type) {
        tags.push(format!("stix-type:{stix_type}"));
    }
    if let Some(category) = attribute.get("category").and_then(Value::as_str) {
        tags.push(format!("misp-category:{}", sanitize_tag(category)));
    }
    // The attribute's own event id, falling back to the event it arrived in:
    // attributes published as part of an event do not always name it.
    if let Some(event) = attribute
        .get("event_id")
        .and_then(id_like)
        .or_else(|| context.id.clone())
    {
        tags.push(format!("misp-event:{event}"));
    }
    if let Some(comment) = attribute
        .get("comment")
        .and_then(Value::as_str)
        .filter(|comment| !comment.trim().is_empty())
    {
        tags.push(format!("description:{}", sanitize_tag(comment)));
    }

    // MISP's own tags are already `namespace:predicate` shaped — `tlp:amber`,
    // `misp-galaxy:threat-actor="..."` — so they are carried across as they
    // are, which is what makes `tlp:` work end to end.
    if let Some(Value::Array(misp_tags)) = attribute.get("Tag") {
        for name in misp_tags
            .iter()
            .filter_map(|tag| tag.get("name").and_then(Value::as_str))
        {
            tags.push(sanitize_tag(name));
        }
    }

    // Then what the event says, which is where MISP keeps the marking and
    // usually the galaxy tags. Added *after* the attribute's own, so the more
    // specific tag is the one the export finds first — and skipped entirely
    // where the two would contradict each other. See [`SINGLE_VALUED`].
    for tag in &context.tags {
        if conflicts(&tags, tag) {
            continue;
        }
        tags.push(tag.clone());
    }

    // An event and an attribute can carry the same tag, and a set should not
    // hold it twice.
    tags.dedup_by(|a, b| a == b);
    let mut seen: Vec<String> = Vec::with_capacity(tags.len());
    tags.retain(|tag| {
        let first = !seen.contains(tag);
        if first {
            seen.push(tag.clone());
        }
        first
    });

    tags
}

/// MISP attribute types to STIX observable types, for the ones that map one to
/// one. Anything absent keeps only its `misp-type:` tag, and the export falls
/// back to recognising the value by its shape.
fn stix_type_for_misp(misp_type: &str) -> Option<&'static str> {
    Some(match misp_type {
        "ip-src" | "ip-dst" | "ip-src|port" | "ip-dst|port" => "ipv4-addr",
        "domain" | "hostname" | "domain|ip" => "domain-name",
        "url" | "uri" => "url",
        "email" | "email-src" | "email-dst" | "email-reply-to" => "email-addr",
        "md5" | "filename|md5" => "file.MD5",
        "sha1" | "filename|sha1" => "file.SHA-1",
        "sha256" | "filename|sha256" => "file.SHA-256",
        "filename" => "file",
        "mutex" => "mutex",
        "regkey" => "windows-registry-key",
        "mac-address" => "mac-addr",
        "AS" => "autonomous-system",
        _ => return None,
    })
}

/// MISP ids arrive as numbers or as strings of digits.
fn id_like(value: &Value) -> Option<String> {
    match value {
        Value::String(text) if !text.is_empty() => Some(text.clone()),
        Value::Number(number) => Some(number.to_string()),
        _ => None,
    }
}

/// MISP sends timestamps as strings of Unix seconds, but not always.
fn timestamp_of(attribute: &Value) -> Option<i64> {
    let raw = attribute.get("timestamp")?;
    match raw {
        Value::String(text) => text.parse().ok(),
        Value::Number(number) => number.as_i64(),
        _ => None,
    }
}

/// MISP writes booleans as `true`, `"1"` or `1` depending on the endpoint.
fn truthy(value: Option<&Value>) -> bool {
    match value {
        Some(Value::Bool(flag)) => *flag,
        Some(Value::String(text)) => text == "1" || text.eq_ignore_ascii_case("true"),
        Some(Value::Number(number)) => number.as_i64().is_some_and(|n| n != 0),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mapping() -> Mapping {
        Mapping {
            types: [
                ("ip-src", "misp/ips"),
                ("ip-dst", "misp/ips"),
                ("domain", "misp/domains"),
                ("md5", "misp/hashes"),
            ]
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
            default_namespace: None,
            require_to_ids: false,
            hashed_namespace: None,
            store_values: true,
        }
    }

    // -- framing -----------------------------------------------------------

    #[test]
    fn the_topic_prefix_is_removed() {
        assert_eq!(
            strip_topic(r#"misp_json_attribute {"Attribute": {}}"#),
            r#"{"Attribute": {}}"#
        );
    }

    #[test]
    fn a_body_without_a_topic_is_left_alone() {
        assert_eq!(strip_topic(r#"{"Attribute": {}}"#), r#"{"Attribute": {}}"#);
        assert_eq!(strip_topic(r#"  {"a": 1}"#), r#"{"a": 1}"#);
    }

    // -- attributes --------------------------------------------------------

    #[test]
    fn a_single_attribute_becomes_one_sighting() {
        let body = r#"{"Attribute": {"id": "7", "type": "ip-src", "value": "1.2.3.4",
                       "timestamp": "1600000000"}}"#;

        assert_eq!(
            parse(body, &mapping()).unwrap(),
            vec![
                Sighting::once("misp/ips", "1.2.3.4", Some(1_600_000_000)).with_tags(vec![
                    "misp-type:ip-src".to_string(),
                    "stix-type:ipv4-addr".to_string(),
                ])
            ]
        );
    }

    /// What MISP knows beyond the value is kept as tags, which is what the
    /// STIX export reads back when it has to build an indicator.
    #[test]
    fn an_attribute_carries_what_misp_said_about_it() {
        let body = r#"{"Attribute": {"type": "md5", "value": "d41d8cd98f00b204e9800998ecf8427e",
                       "category": "Payload delivery", "event_id": 42,
                       "comment": "dropper, second stage",
                       "Tag": [{"name": "tlp:amber"}, {"name": "malware:emotet"}]}}"#;

        let tags = &parse(body, &mapping()).unwrap()[0].tags;

        assert_eq!(
            tags,
            &[
                "misp-type:md5",
                "stix-type:file.MD5",
                "misp-category:Payload delivery",
                "misp-event:42",
                // The comma would have split one tag into two, so it is not
                // left in place.
                "description:dropper; second stage",
                "tlp:amber",
                "malware:emotet",
            ]
        );
    }

    #[test]
    fn an_unmapped_misp_type_still_says_what_misp_called_it() {
        let body = r#"{"Attribute": {"type": "domain", "value": "evil.com"}}"#;
        let mut mapping = mapping();
        mapping.types.insert("btc".into(), "misp/wallets".into());

        let tags = &parse(body, &mapping).unwrap()[0].tags;
        assert_eq!(tags, &["misp-type:domain", "stix-type:domain-name"]);

        let body = r#"{"Attribute": {"type": "btc", "value": "1BvBMSEY"}}"#;
        let tags = &parse(body, &mapping).unwrap()[0].tags;
        assert_eq!(tags, &["misp-type:btc"], "no STIX type to claim");
    }

    #[test]
    fn a_numeric_timestamp_is_accepted_too() {
        let body =
            r#"{"Attribute": {"type": "domain", "value": "evil.com", "timestamp": 1600000000}}"#;
        assert_eq!(
            parse(body, &mapping()).unwrap()[0].timestamp,
            Some(1_600_000_000)
        );
    }

    #[test]
    fn a_missing_timestamp_means_now() {
        let body = r#"{"Attribute": {"type": "domain", "value": "evil.com"}}"#;
        assert_eq!(parse(body, &mapping()).unwrap()[0].timestamp, None);
    }

    #[test]
    fn unmapped_types_are_dropped_by_default() {
        let body = r#"{"Attribute": {"type": "comment", "value": "just a note"}}"#;
        assert!(parse(body, &mapping()).unwrap().is_empty());
    }

    #[test]
    fn a_default_namespace_catches_unmapped_types() {
        let mut mapping = mapping();
        mapping.default_namespace = Some("misp/other".into());

        let body = r#"{"Attribute": {"type": "comment", "value": "just a note"}}"#;
        assert_eq!(parse(body, &mapping).unwrap()[0].namespace, "misp/other");
    }

    #[test]
    fn to_ids_can_be_required() {
        let mut mapping = mapping();
        mapping.require_to_ids = true;

        let actionable = r#"{"Attribute": {"type": "ip-src", "value": "1.2.3.4", "to_ids": true}}"#;
        let contextual =
            r#"{"Attribute": {"type": "ip-src", "value": "5.6.7.8", "to_ids": false}}"#;
        let missing = r#"{"Attribute": {"type": "ip-src", "value": "9.9.9.9"}}"#;

        assert_eq!(parse(actionable, &mapping).unwrap().len(), 1);
        assert!(parse(contextual, &mapping).unwrap().is_empty());
        assert!(parse(missing, &mapping).unwrap().is_empty());
    }

    /// MISP is inconsistent about how it spells booleans.
    #[test]
    fn to_ids_is_recognised_in_every_spelling() {
        let mut mapping = mapping();
        mapping.require_to_ids = true;

        for spelling in ["true", "\"1\"", "1", "\"true\""] {
            let body = format!(
                r#"{{"Attribute": {{"type": "ip-src", "value": "1.2.3.4", "to_ids": {spelling}}}}}"#
            );
            assert_eq!(parse(&body, &mapping).unwrap().len(), 1, "{spelling}");
        }
        for spelling in ["false", "\"0\"", "0"] {
            let body = format!(
                r#"{{"Attribute": {{"type": "ip-src", "value": "1.2.3.4", "to_ids": {spelling}}}}}"#
            );
            assert!(parse(&body, &mapping).unwrap().is_empty(), "{spelling}");
        }
    }

    #[test]
    fn value1_is_used_when_value_is_absent() {
        let body =
            r#"{"Attribute": {"type": "md5", "value1": "d41d8cd98f00b204e9800998ecf8427e"}}"#;
        assert_eq!(
            parse(body, &mapping()).unwrap()[0].value,
            "d41d8cd98f00b204e9800998ecf8427e"
        );
    }

    #[test]
    fn empty_and_malformed_attributes_are_skipped() {
        for body in [
            r#"{"Attribute": {"type": "ip-src", "value": ""}}"#,
            r#"{"Attribute": {"value": "1.2.3.4"}}"#,
            r#"{"Attribute": {"type": "ip-src"}}"#,
            r#"{"Attribute": "not an object"}"#,
            r#"{"something": "else"}"#,
        ] {
            assert!(parse(body, &mapping()).unwrap().is_empty(), "{body}");
        }
    }

    #[test]
    fn malformed_json_is_an_error_not_a_panic() {
        assert!(parse("{not json", &mapping()).is_err());
    }

    // -- events ------------------------------------------------------------

    #[test]
    fn an_event_yields_all_of_its_attributes() {
        let body = r#"{"Event": {"id": "1", "Attribute": [
            {"type": "ip-src", "value": "1.2.3.4"},
            {"type": "domain", "value": "evil.com"},
            {"type": "comment", "value": "ignored"}
        ]}}"#;

        let sightings = parse(body, &mapping()).unwrap();
        assert_eq!(sightings.len(), 2);
        assert_eq!(sightings[0].value, "1.2.3.4");
        assert_eq!(sightings[1].namespace, "misp/domains");
    }

    /// The marking lives on the event, and it has to reach the values.
    ///
    /// It did not: only attribute tags were read, so every sighting from a
    /// `tlp:amber` event arrived unmarked and exported unmarked. That is the
    /// one kind of loss here that could mislead someone about how a value may
    /// be shared, which is worse than losing it outright.
    #[test]
    fn an_events_marking_reaches_its_attributes() {
        let body = r#"{"Event": {"id": "7", "Tag": [
                {"name": "tlp:amber"},
                {"name": "misp-galaxy:threat-actor=\"Callisto\""},
                {"name": "type:OSINT"}
            ], "Attribute": [{"type": "ip-src", "value": "1.2.3.4"}]}}"#;

        let sightings = parse(body, &mapping()).unwrap();
        assert_eq!(sightings.len(), 1);
        let tags = &sightings[0].tags;
        assert!(tags.contains(&"tlp:amber".to_string()), "{tags:?}");
        assert!(
            tags.contains(&"misp-galaxy:threat-actor=\"Callisto\"".to_string()),
            "{tags:?}"
        );
        assert!(tags.contains(&"type:OSINT".to_string()), "{tags:?}");
        // And what the attribute itself says is still there.
        assert!(tags.contains(&"misp-type:ip-src".to_string()), "{tags:?}");
    }

    /// Attributes inside objects inherit it too, which is where most of a
    /// modern MISP event's attributes live.
    #[test]
    fn an_events_marking_reaches_attributes_inside_objects() {
        let body = r#"{"Event": {"Tag": [{"name": "tlp:green"}],
            "Object": [
              {"name": "file", "Attribute": [
                {"type": "md5", "value": "d41d8cd98f00b204e9800998ecf8427e"}]}
            ]}}"#;

        let sightings = parse(body, &mapping()).unwrap();
        assert_eq!(sightings.len(), 1);
        assert!(sightings[0].tags.contains(&"tlp:green".to_string()));
    }

    /// A single-attribute publication carries its event as context beside the
    /// attribute rather than around it, and the marking is in that context.
    #[test]
    fn a_lone_attribute_inherits_from_the_event_beside_it() {
        let body = r#"{"Attribute": {"type": "domain", "value": "evil.com"},
            "Event": {"id": "9", "Tag": [{"name": "tlp:red"}]}}"#;

        let sightings = parse(body, &mapping()).unwrap();
        assert_eq!(sightings.len(), 1);
        assert!(sightings[0].tags.contains(&"tlp:red".to_string()));
        assert!(sightings[0].tags.contains(&"misp-event:9".to_string()));
    }

    /// The attribute's own marking wins, and the event's is not added beside
    /// it. A value tagged both amber and white says nothing useful about how
    /// it may be shared.
    #[test]
    fn an_attributes_own_marking_is_not_contradicted_by_the_events() {
        let body = r#"{"Event": {"Tag": [{"name": "tlp:white"}], "Attribute": [
                {"type": "ip-src", "value": "1.2.3.4",
                 "Tag": [{"name": "tlp:amber"}]}
            ]}}"#;

        let tags = &parse(body, &mapping()).unwrap()[0].tags;
        assert!(tags.contains(&"tlp:amber".to_string()), "{tags:?}");
        assert!(
            !tags.contains(&"tlp:white".to_string()),
            "the event's marking overrode the attribute's own: {tags:?}"
        );
        // The stricter one is also the one the export will find first.
        let joined = tags.join(",");
        assert_eq!(crate::attribute::tag_value(&joined, "tlp"), Some("amber"));
    }

    /// A taxonomy that genuinely takes several values keeps them all: an event
    /// and an attribute can each contribute one worth having.
    #[test]
    fn a_multi_valued_taxonomy_keeps_both_contributions() {
        let body = r#"{"Event": {"Tag": [{"name": "misp-galaxy:country=\"ukraine\""}],
            "Attribute": [{"type": "ip-src", "value": "1.2.3.4",
                "Tag": [{"name": "misp-galaxy:threat-actor=\"Callisto\""}]}]}}"#;

        let tags = &parse(body, &mapping()).unwrap()[0].tags;
        assert!(
            tags.contains(&"misp-galaxy:country=\"ukraine\"".to_string()),
            "{tags:?}"
        );
        assert!(
            tags.contains(&"misp-galaxy:threat-actor=\"Callisto\"".to_string()),
            "{tags:?}"
        );
    }

    /// The same tag on the event and on the attribute is one tag, not two.
    #[test]
    fn a_tag_on_both_is_not_duplicated() {
        let body = r#"{"Event": {"Tag": [{"name": "type:OSINT"}], "Attribute": [
                {"type": "ip-src", "value": "1.2.3.4",
                 "Tag": [{"name": "type:OSINT"}]}]}}"#;

        let tags = &parse(body, &mapping()).unwrap()[0].tags;
        assert_eq!(
            tags.iter().filter(|t| *t == "type:OSINT").count(),
            1,
            "{tags:?}"
        );
    }

    /// An event with no tags changes nothing, which is what every message from
    /// a publisher that does not tag looks like.
    #[test]
    fn an_untagged_event_adds_nothing() {
        let body = r#"{"Event": {"id": "1", "Attribute": [
                {"type": "ip-src", "value": "1.2.3.4"}]}}"#;

        let tags = &parse(body, &mapping()).unwrap()[0].tags;
        assert!(!tags.iter().any(|t| t.starts_with("tlp:")), "{tags:?}");
    }

    /// Against the real thing: an event from CIRCL's public OSINT feed, with
    /// its tag block and one object attribute copied verbatim.
    ///
    /// The shapes here are the ones that actually turn up and that a
    /// hand-written fixture gets wrong — a quoted value inside a machine tag,
    /// `local` and `colour` fields beside the name, a timestamp as a string,
    /// and an attribute inside an object with no `event_id` of its own.
    #[test]
    fn a_real_event_from_the_circl_feed_keeps_its_marking() {
        let body = r##"{"Event": {
            "uuid": "cf909fc3-0e55-4962-b462-2219981ea53c",
            "info": "OSINT - PhantomCaptcha",
            "Tag": [
              {"colour": "#0088cc", "local": false,
               "name": "misp-galaxy:country=\"ukraine\"",
               "relationship_type": "targets"},
              {"colour": "#004646", "local": false, "name": "type:OSINT",
               "relationship_type": ""},
              {"colour": "#ffffff", "local": false, "name": "tlp:white",
               "relationship_type": ""},
              {"colour": "#0071c3", "local": false,
               "name": "osint:certainty=\"50\"", "relationship_type": ""}
            ],
            "Object": [
              {"name": "domain-ip", "Attribute": [
                {"type": "domain", "value": "bsnowcommunications.com",
                 "category": "Network activity", "timestamp": "1762792503"}
              ]}
            ]}}"##;

        let sightings = parse(body, &mapping()).unwrap();
        assert_eq!(sightings.len(), 1);
        let s = &sightings[0];

        assert_eq!(s.namespace, "misp/domains");
        assert_eq!(s.value, "bsnowcommunications.com");
        // A string timestamp is still a timestamp.
        assert_eq!(s.timestamp, Some(1_762_792_503));

        // What the attribute says about itself.
        assert!(
            s.tags.contains(&"misp-type:domain".to_string()),
            "{:?}",
            s.tags
        );
        assert!(
            s.tags.contains(&"stix-type:domain-name".to_string()),
            "{:?}",
            s.tags
        );
        assert!(
            s.tags
                .contains(&"misp-category:Network activity".to_string()),
            "{:?}",
            s.tags
        );
        // The event it came from, which the attribute does not name itself.
        assert!(
            s.tags
                .contains(&"misp-event:cf909fc3-0e55-4962-b462-2219981ea53c".to_string()),
            "{:?}",
            s.tags
        );
        // And the marking, which is the whole point.
        assert!(s.tags.contains(&"tlp:white".to_string()), "{:?}", s.tags);
        assert!(s.tags.contains(&"type:OSINT".to_string()), "{:?}", s.tags);
        assert!(
            s.tags.contains(&"osint:certainty=\"50\"".to_string()),
            "{:?}",
            s.tags
        );
        assert!(
            s.tags
                .contains(&"misp-galaxy:country=\"ukraine\"".to_string()),
            "{:?}",
            s.tags
        );

        // The tag set is written as one comma-separated field, so it has to
        // survive being joined and read back.
        let joined = s.tags.join(",");
        assert_eq!(crate::attribute::tag_value(&joined, "tlp"), Some("white"));
        assert_eq!(
            crate::attribute::tag_value(&joined, "stix-type"),
            Some("domain-name")
        );
    }

    /// Attributes hang off objects as well as off the event directly, and
    /// missing them would silently drop most of a modern MISP event.
    #[test]
    fn attributes_inside_objects_are_found_too() {
        let body = r#"{"Event": {"Attribute": [{"type": "ip-src", "value": "1.1.1.1"}],
            "Object": [
              {"name": "file", "Attribute": [{"type": "md5", "value": "d41d8cd98f00b204e9800998ecf8427e"}]},
              {"name": "url",  "Attribute": [{"type": "domain", "value": "evil.com"}]}
            ]}}"#;

        let values: Vec<String> = parse(body, &mapping())
            .unwrap()
            .into_iter()
            .map(|s| s.value)
            .collect();
        assert_eq!(
            values,
            ["1.1.1.1", "d41d8cd98f00b204e9800998ecf8427e", "evil.com"]
        );
    }

    // -- digests for MISP --------------------------------------------------

    fn hashing(store_values: bool) -> Mapping {
        Mapping {
            hashed_namespace: Some("misp/sha256".into()),
            store_values,
            ..mapping()
        }
    }

    /// What PHP's `hash('sha256', '8.8.8.8')` returns, which is what MISP sends.
    #[test]
    fn the_digest_is_the_one_misp_asks_for() {
        assert_eq!(
            sha256_hex("8.8.8.8"),
            "838c4c2573848f58e74332341a7ca6bc5cd86a8aec7d644137d53b4d597f10f5"
        );
    }

    #[test]
    fn a_hashed_namespace_records_the_digest_beside_the_value() {
        let body = r#"{"Attribute": {"type": "ip-dst", "value": "8.8.8.8",
                       "timestamp": "1600000000"}}"#;

        let sightings = parse(body, &hashing(true)).unwrap();
        assert_eq!(sightings.len(), 2, "{sightings:?}");
        assert_eq!(sightings[0].namespace, "misp/ips");
        assert_eq!(sightings[0].value, "8.8.8.8");
        assert_eq!(sightings[1].namespace, "misp/sha256");
        assert_eq!(
            sightings[1].value,
            "838c4c2573848f58e74332341a7ca6bc5cd86a8aec7d644137d53b4d597f10f5"
        );
        // Same timestamp handling as the plain write.
        assert_eq!(sightings[1].timestamp, Some(1_600_000_000));
    }

    /// MISP hashes the whole `value` field, so a composite has to be hashed
    /// whole too, not split.
    #[test]
    fn a_composite_value_is_hashed_whole() {
        let mut mapping = hashing(true);
        mapping
            .types
            .insert("ip-dst|port".into(), "misp/ips".into());
        let body = r#"{"Attribute": {"type": "ip-dst|port", "value": "1.2.3.4|80",
                       "value1": "1.2.3.4", "value2": "80"}}"#;

        let sightings = parse(body, &mapping).unwrap();
        let hashed: Vec<&Sighting> = sightings
            .iter()
            .filter(|s| s.namespace == "misp/sha256")
            .collect();
        assert_eq!(hashed.len(), 1);
        assert_eq!(hashed[0].value, sha256_hex("1.2.3.4|80"));
        assert_ne!(hashed[0].value, sha256_hex("1.2.3.4"));
    }

    #[test]
    fn without_store_values_only_the_digest_is_written() {
        let body = r#"{"Event": {"Attribute": [
            {"type": "ip-dst", "value": "8.8.8.8"},
            {"type": "domain", "value": "evil.com"}
        ]}}"#;

        let sightings = parse(body, &hashing(false)).unwrap();
        assert_eq!(sightings.len(), 2, "{sightings:?}");
        assert!(sightings.iter().all(|s| s.namespace == "misp/sha256"));
        let values: Vec<&str> = sightings.iter().map(|s| s.value.as_str()).collect();
        assert_eq!(values, [sha256_hex("8.8.8.8"), sha256_hex("evil.com")]);
    }

    /// MISP may look up any attribute it shows, so the digest is recorded for
    /// types [zmq.types] does not map — while the cleartext still is not.
    #[test]
    fn unmapped_types_are_still_hashed() {
        let body = r#"{"Attribute": {"type": "btc", "value": "1BvBMSEY"}}"#;

        let sightings = parse(body, &hashing(true)).unwrap();
        assert_eq!(
            sightings,
            vec![
                Sighting::once("misp/sha256", sha256_hex("1BvBMSEY"), None)
                    .with_tags(vec!["misp-type:btc".to_string()])
            ]
        );
        // And without a hashed namespace, nothing changes.
        assert!(parse(body, &mapping()).unwrap().is_empty());
    }

    #[test]
    fn to_ids_still_filters_the_digest() {
        let mut mapping = hashing(true);
        mapping.require_to_ids = true;
        let body = r#"{"Attribute": {"type": "ip-dst", "value": "8.8.8.8", "to_ids": false}}"#;
        assert!(parse(body, &mapping).unwrap().is_empty());
    }

    /// The digest is there so the value cannot be read back; a tag that spells
    /// it out, or points at where it is spelled out, would defeat that.
    #[test]
    fn tags_that_reveal_the_value_are_not_carried_to_the_digest() {
        let body = r#"{"Attribute": {"type": "ip-dst", "value": "8.8.8.8",
                       "category": "Network activity", "event_id": 42,
                       "comment": "C2 at 8.8.8.8",
                       "Tag": [{"name": "tlp:amber"}]}}"#;

        let sightings = parse(body, &hashing(true)).unwrap();
        let plain = &sightings[0].tags;
        let hashed = &sightings[1].tags;
        assert!(plain.contains(&"description:C2 at 8.8.8.8".to_string()));

        assert_eq!(
            hashed,
            &[
                "misp-type:ip-dst",
                "misp-category:Network activity",
                "tlp:amber"
            ]
        );
        assert!(!hashed.iter().any(|t| t.contains("8.8.8.8")), "{hashed:?}");
    }

    // -- native format -----------------------------------------------------

    #[test]
    fn the_native_batch_format_round_trips() {
        let body = r#"{"items": [
            {"namespace": "feeds/a", "value": "1.2.3.4", "timestamp": 1600000000},
            {"namespace": "feeds/b", "value": "evil.com"}
        ]}"#;

        assert_eq!(
            parse_native(body).unwrap(),
            vec![
                Sighting::once("feeds/a", "1.2.3.4", Some(1_600_000_000)),
                Sighting::once("feeds/b", "evil.com", None),
            ]
        );
    }

    #[test]
    fn a_malformed_native_batch_is_an_error() {
        assert!(parse_native(r#"{"items": [{"value": "no namespace"}]}"#).is_err());
    }
}
