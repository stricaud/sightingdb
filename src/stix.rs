//! Writing sightings out as a STIX 2.1 bundle.
//!
//! A sighting in this database is `<namespace, value, count, first_seen,
//! last_seen>`. A STIX sighting needs rather more: what kind of observable the
//! value is, an indicator to point at, who saw it, how it may be shared. The
//! missing parts come from the value's tags, which the STIX and MISP importers
//! write and a person can add by hand — see the tag vocabulary in the README.
//!
//! Shaped after the OASIS "Sighting of an Indicator" example: an `indicator`
//! carrying the pattern, a `sighting` pointing at it with a count and a window,
//! and the `identity` objects both refer to.
//!
//! **Ids are deterministic.** Every id is a UUIDv5 over [`SIGHTINGDB`] and the
//! thing it names, so exporting the same namespace twice produces the same
//! bundle byte for byte, and the same value in two namespaces yields *one*
//! indicator with a sighting each — which is what a consumer merging the two
//! wants. Where an imported bundle carried an indicator id of its own, the
//! `stix-id:` tag holds it and it is used instead of a minted one, so a value
//! that came in as STIX goes back out under the id its publisher gave it.
//! The specification prefers v4 for objects other than observables, but a
//! random id would make every export a new set of objects to a consumer, which
//! is worse than departing from a SHOULD.

use chrono::{DateTime, SecondsFormat};
use serde_json::{Map, Value, json};
use uuid::Uuid;

use crate::attribute::{AttributeView, tag_value, tag_values};

/// Namespace for every id this module mints. A constant of our own, so ids are
/// stable across releases and unique to SightingDB.
pub const SIGHTINGDB: Uuid = Uuid::from_u128(0x3ef1_1775_6174_4718_92bf_1670_5b73_2650);

/// The identity the bundle is published under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    /// Name of the organisation or system publishing the bundle.
    pub identity: String,
    /// A STIX identity class: `organization`, `system`, `individual`, ...
    pub identity_class: String,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            identity: "SightingDB".to_string(),
            // What this is: a database reporting what it saw, not a person or
            // a company. A deployment speaking for its organisation says so in
            // the configuration.
            identity_class: "system".to_string(),
        }
    }
}

/// A finished bundle, with what had to be left out of it.
#[derive(Debug, Clone)]
pub struct Export {
    pub bundle: Value,
    pub exported: usize,
    /// Values whose observable type could not be worked out. A STIX indicator
    /// is a pattern, and there is no pattern without a type.
    pub skipped: Vec<String>,
    /// The namespace holds more values than the export was allowed to read.
    pub truncated: bool,
    /// Namespaces asked for that do not exist.
    pub missing: Vec<String>,
}

/// The TLP marking definitions defined by the specification, which are
/// referenced by fixed id rather than invented per bundle.
const TLP: [(&str, &str); 4] = [
    (
        "white",
        "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
    ),
    (
        "green",
        "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
    ),
    (
        "amber",
        "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
    ),
    (
        "red",
        "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
    ),
];
/// When the specification says those four were created.
const TLP_CREATED: &str = "2017-01-20T00:00:00.000Z";

/// The TLP level a marking definition id stands for, for the importer.
pub fn tlp_of_id(id: &str) -> Option<&'static str> {
    TLP.iter()
        .find(|(_, marking)| *marking == id)
        .map(|(level, _)| *level)
}

fn tlp_id(level: &str) -> Option<&'static str> {
    let level = level.trim().to_ascii_lowercase();
    let level = level.strip_prefix("tlp:").unwrap_or(&level);
    TLP.iter()
        .find(|(name, _)| *name == level)
        .map(|(_, id)| *id)
}

/// One namespace's worth of a bundle.
///
/// `default_type` is the observable type the namespace holds when a value does
/// not say — taken from the `[stix.types]` import mapping read backwards, since
/// a namespace configured to receive `ipv4-addr` holds ipv4 addresses whichever
/// way the data arrived.
#[derive(Debug, Clone, Copy)]
pub struct Part<'a> {
    pub namespace: &'a str,
    pub values: &'a [AttributeView],
    pub default_type: Option<&'a str>,
}

/// Build a bundle for one namespace. The tests' way in; everything else goes
/// through [`export_namespaces`], which reads the values itself.
#[cfg(test)]
pub fn bundle(
    namespace: &str,
    values: &[AttributeView],
    default_type: Option<&str>,
    settings: &Settings,
) -> Export {
    bundle_of(
        &[Part {
            namespace,
            values,
            default_type,
        }],
        settings,
    )
}

/// Build one bundle spanning several namespaces.
///
/// Objects are deduplicated by id, which is what makes this worth doing: the
/// same value in two namespaces has one indicator between them and a sighting
/// each, so a consumer sees a value sighted twice rather than two unrelated
/// indicators.
pub fn bundle_of(parts: &[Part<'_>], settings: &Settings) -> Export {
    let author = identity(&settings.identity, &settings.identity_class);
    let author_id = author["id"].as_str().unwrap_or_default().to_string();

    let mut objects: Vec<Value> = vec![author];
    // Identities and markings are shared, so they are collected as they are
    // met and appended once.
    let mut identities: Vec<(String, Value)> = Vec::new();
    let mut markings: Vec<&str> = Vec::new();
    let mut skipped = Vec::new();
    let mut exported = 0;

    for part in parts {
        let (namespace, default_type) = (part.namespace, part.default_type);
        for view in part.values {
            let Some(observable) = observable_type(view, default_type) else {
                skipped.push(view.value.clone());
                continue;
            };
            let Some(pattern) = pattern_for(&observable, &view.value) else {
                skipped.push(view.value.clone());
                continue;
            };

            let mut marking_refs = Vec::new();
            for level in tag_values(&view.tags, "tlp") {
                if let Some(id) = tlp_id(level) {
                    if !markings.contains(&id) {
                        markings.push(id);
                    }
                    if !marking_refs.contains(&Value::from(id)) {
                        marking_refs.push(Value::from(id));
                    }
                }
            }

            // Whoever the tags say saw it; failing that, we did.
            let mut sighted_by: Vec<Value> = Vec::new();
            for name in tag_values(&view.tags, "identity") {
                let object = identity(name, "organization");
                let id = object["id"].as_str().unwrap_or_default().to_string();
                if !identities.iter().any(|(known, _)| *known == id) {
                    identities.push((id.clone(), object));
                }
                if !sighted_by.contains(&Value::from(id.clone())) {
                    sighted_by.push(Value::from(id));
                }
            }
            if sighted_by.is_empty() {
                sighted_by.push(Value::from(author_id.clone()));
            }

            let indicator_id = indicator_id(view, &observable);
            objects.push(indicator(
                &indicator_id,
                view,
                &pattern,
                &author_id,
                &marking_refs,
            ));
            objects.push(sighting(
                namespace,
                &observable,
                view,
                &indicator_id,
                &author_id,
                &sighted_by,
                &marking_refs,
            ));
            exported += 1;
        }
    }

    for (_, object) in identities {
        objects.push(object);
    }
    for level in TLP.iter().filter(|(_, id)| markings.contains(id)) {
        objects.push(marking(level.0, level.1));
    }

    // A value present in two of the namespaces asked for shares one indicator,
    // which would otherwise appear once per namespace.
    let mut seen: Vec<String> = Vec::with_capacity(objects.len());
    objects.retain(|object| {
        let Some(id) = object["id"].as_str() else {
            return true;
        };
        let first = !seen.iter().any(|known| known == id);
        if first {
            seen.push(id.to_string());
        }
        first
    });

    let key: Vec<&str> = parts.iter().map(|part| part.namespace).collect();
    Export {
        truncated: false,
        missing: Vec::new(),
        bundle: json!({
            "type": "bundle",
            // Derived from what was asked for, so re-exporting is idempotent
            // rather than looking like a new bundle every time.
            "id": format!("bundle--{}", uuid_for(&format!("bundle:{}", key.join(",")))),
            "objects": objects,
        }),
        exported,
        skipped,
    }
}

/// Export one namespace straight from the database.
///
/// Returns `None` if the namespace does not exist. `limit` caps how many values
/// are read: a bundle is one response held in memory, and a namespace can hold
/// a great many.
pub fn export_namespace(
    db: &crate::db::Database,
    settings: &crate::config::StixSettings,
    namespace: &str,
    limit: usize,
) -> Option<Export> {
    let mut export = export_namespaces(db, settings, std::slice::from_ref(&namespace), "", limit);
    (export.missing.is_empty()).then(|| {
        export.missing = Vec::new();
        export
    })
}

/// Export several namespaces into one bundle.
///
/// `filter` is the same substring match browsing uses, so an automation can ask
/// for the part of a namespace it cares about. Namespaces that do not exist are
/// reported rather than failing the request: an automation naming ten feeds
/// should not lose the nine that are there because one has yet to be written to.
pub fn export_namespaces(
    db: &crate::db::Database,
    settings: &crate::config::StixSettings,
    namespaces: &[&str],
    filter: &str,
    limit: usize,
) -> Export {
    let mut pages = Vec::with_capacity(namespaces.len());
    let mut missing = Vec::new();
    let mut truncated = false;

    for namespace in namespaces {
        match db.value_page(namespace, filter, 0, limit, false) {
            Some(page) => {
                truncated |= page.total > page.items.len();
                pages.push((*namespace, page.items));
            }
            None => missing.push((*namespace).to_string()),
        }
    }

    let parts: Vec<Part<'_>> = pages
        .iter()
        .map(|(namespace, values)| Part {
            namespace,
            values,
            default_type: settings.type_of_namespace(namespace),
        })
        .collect();

    let mut export = bundle_of(&parts, &settings.export);
    export.truncated = truncated;
    export.missing = missing;
    export
}

/// What kind of observable a value is: what its tags say, else what the
/// namespace is configured to hold, else what the value looks like.
fn observable_type(view: &AttributeView, default_type: Option<&str>) -> Option<String> {
    if let Some(tagged) = tag_value(&view.tags, "stix-type") {
        return Some(tagged.to_string());
    }
    if let Some(configured) = default_type {
        return Some(configured.to_string());
    }
    infer_type(&view.value).map(str::to_string)
}

/// Recognise the common observables by shape.
///
/// Deliberately conservative: a wrong type produces a pattern that says
/// something false, which is worse than declining to export the value.
pub fn infer_type(value: &str) -> Option<&'static str> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }

    if value.contains("://") {
        return Some("url");
    }
    if value.parse::<std::net::Ipv4Addr>().is_ok() {
        return Some("ipv4-addr");
    }
    if value.parse::<std::net::Ipv6Addr>().is_ok() {
        return Some("ipv6-addr");
    }
    // A CIDR block is still an address observable in STIX.
    if let Some((address, prefix)) = value.split_once('/')
        && prefix.parse::<u8>().is_ok()
    {
        if address.parse::<std::net::Ipv4Addr>().is_ok() {
            return Some("ipv4-addr");
        }
        if address.parse::<std::net::Ipv6Addr>().is_ok() {
            return Some("ipv6-addr");
        }
    }
    if value.contains('@') && value.split('@').count() == 2 && !value.starts_with('@') {
        return Some("email-addr");
    }

    let hex = value.chars().all(|c| c.is_ascii_hexdigit());
    match (hex, value.len()) {
        (true, 32) => return Some("file.MD5"),
        (true, 40) => return Some("file.SHA-1"),
        (true, 64) => return Some("file.SHA-256"),
        (true, 128) => return Some("file.SHA-512"),
        _ => {}
    }

    // A dotted name with a plausible TLD, which is as far as guessing goes.
    let looks_like_a_domain = value.contains('.')
        && !value.contains(' ')
        && value
            .rsplit('.')
            .next()
            .is_some_and(|tld| tld.len() >= 2 && tld.chars().all(|c| c.is_ascii_alphabetic()));
    looks_like_a_domain.then_some("domain-name")
}

/// The STIX pattern for one value of a given observable type.
///
/// Hashes carry the algorithm in the type (`file.SHA-256`), which is the same
/// spelling the importer uses, and become a `file:hashes` comparison.
fn pattern_for(observable: &str, value: &str) -> Option<String> {
    let literal = escape(value);

    if let Some(algorithm) = observable.strip_prefix("file.") {
        return Some(format!("[file:hashes.'{algorithm}' = '{literal}']"));
    }

    let property = match observable {
        "file" => "name",
        "mutex" => "name",
        "windows-registry-key" => "key",
        "process" => "command_line",
        "user-account" => "user_id",
        "autonomous-system" => "number",
        "" => return None,
        _ => "value",
    };
    Some(format!("[{observable}:{property} = '{literal}']"))
}

/// Quote a value for a STIX pattern literal.
fn escape(value: &str) -> String {
    value.replace('\\', "\\\\").replace('\'', "\\'")
}

fn indicator(
    id: &str,
    view: &AttributeView,
    pattern: &str,
    author: &str,
    markings: &[Value],
) -> Value {
    let mut object = Map::new();
    object.insert("type".into(), "indicator".into());
    object.insert("spec_version".into(), "2.1".into());
    object.insert("id".into(), id.into());
    object.insert("created_by_ref".into(), author.into());
    object.insert("created".into(), rfc3339(view.first_seen).into());
    object.insert("modified".into(), rfc3339(view.last_seen).into());

    if let Some(name) = tag_value(&view.tags, "name") {
        object.insert("name".into(), name.into());
    }
    if let Some(description) = tag_value(&view.tags, "description") {
        object.insert("description".into(), description.into());
    }

    let kinds: Vec<Value> = tag_values(&view.tags, "indicator-type")
        .map(Value::from)
        .collect();
    if !kinds.is_empty() {
        object.insert("indicator_types".into(), Value::Array(kinds));
    }

    object.insert("pattern".into(), pattern.into());
    object.insert("pattern_type".into(), "stix".into());
    object.insert("valid_from".into(), rfc3339(view.first_seen).into());

    // A TTL is exactly a validity window: the value stops being visible here
    // once it has gone unseen for that long, so say so rather than leaving a
    // consumer to believe the indicator is good forever.
    if let Some(until) = valid_until(view) {
        object.insert("valid_until".into(), until.into());
    }
    if let Some(confidence) = confidence(view) {
        object.insert("confidence".into(), confidence.into());
    }
    if !markings.is_empty() {
        object.insert(
            "object_marking_refs".into(),
            Value::Array(markings.to_vec()),
        );
    }

    Value::Object(object)
}

fn sighting(
    namespace: &str,
    observable: &str,
    view: &AttributeView,
    indicator_id: &str,
    author: &str,
    sighted_by: &[Value],
    markings: &[Value],
) -> Value {
    let mut object = Map::new();
    object.insert("type".into(), "sighting".into());
    object.insert("spec_version".into(), "2.1".into());
    object.insert(
        "id".into(),
        format!(
            "sighting--{}",
            uuid_for(&format!("sighting:{namespace}:{observable}:{}", view.value))
        )
        .into(),
    );
    object.insert("created_by_ref".into(), author.into());
    object.insert("created".into(), rfc3339(view.first_seen).into());
    object.insert("modified".into(), rfc3339(view.last_seen).into());
    object.insert("first_seen".into(), rfc3339(view.first_seen).into());
    object.insert("last_seen".into(), rfc3339(view.last_seen).into());
    // STIX caps the count; a value seen more often than that is still one
    // sighting object, just one that stops counting.
    object.insert("count".into(), view.count.clamp(1, 999_999_999).into());
    object.insert("sighting_of_ref".into(), indicator_id.into());
    object.insert(
        "where_sighted_refs".into(),
        Value::Array(sighted_by.to_vec()),
    );

    // Which namespace it was seen in is ours, not STIX's, so it goes in a
    // custom property — the `x_` prefix the specification reserves for that.
    object.insert("x_sightingdb_namespace".into(), namespace.into());
    if let Some(confidence) = confidence(view) {
        object.insert("confidence".into(), confidence.into());
    }
    if !markings.is_empty() {
        object.insert(
            "object_marking_refs".into(),
            Value::Array(markings.to_vec()),
        );
    }

    Value::Object(object)
}

fn identity(name: &str, class: &str) -> Value {
    json!({
        "type": "identity",
        "spec_version": "2.1",
        "id": format!("identity--{}", uuid_for(&format!("identity:{name}"))),
        // Fixed rather than "now", so an export is reproducible.
        "created": TLP_CREATED,
        "modified": TLP_CREATED,
        "name": name,
        "identity_class": class,
    })
}

fn marking(level: &str, id: &str) -> Value {
    json!({
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": id,
        "created": TLP_CREATED,
        "definition_type": "tlp",
        "name": format!("TLP:{}", level.to_ascii_uppercase()),
        "definition": { "tlp": level },
    })
}

/// The indicator's id: the one it arrived with, or one derived from the value.
fn indicator_id(view: &AttributeView, observable: &str) -> String {
    if let Some(given) = tag_value(&view.tags, "stix-id")
        && given.starts_with("indicator--")
        && Uuid::parse_str(given.trim_start_matches("indicator--")).is_ok()
    {
        return given.to_string();
    }
    format!(
        "indicator--{}",
        uuid_for(&format!("indicator:{observable}:{}", view.value))
    )
}

fn confidence(view: &AttributeView) -> Option<u64> {
    tag_value(&view.tags, "confidence")?
        .parse::<u64>()
        .ok()
        .filter(|value| *value <= 100)
}

/// An explicit `valid-until:` tag wins; otherwise a TTL is one, counted from
/// the last sighting exactly as the database counts it.
fn valid_until(view: &AttributeView) -> Option<String> {
    if let Some(tagged) = tag_value(&view.tags, "valid-until") {
        if let Ok(parsed) = DateTime::parse_from_rfc3339(tagged) {
            return Some(rfc3339(parsed.timestamp()));
        }
        if let Ok(seconds) = tagged.parse::<i64>() {
            return Some(rfc3339(seconds));
        }
        return None;
    }
    (view.ttl > 0).then(|| {
        rfc3339(
            view.last_seen
                .saturating_add(i64::try_from(view.ttl).unwrap_or(i64::MAX)),
        )
    })
}

/// STIX timestamps are RFC 3339 with milliseconds, in UTC.
fn rfc3339(seconds: i64) -> String {
    DateTime::from_timestamp(seconds, 0)
        .unwrap_or(DateTime::UNIX_EPOCH)
        .to_rfc3339_opts(SecondsFormat::Millis, true)
}

fn uuid_for(key: &str) -> Uuid {
    Uuid::new_v5(&SIGHTINGDB, key.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn view(value: &str, tags: &str) -> AttributeView {
        AttributeView {
            value: value.to_string(),
            first_seen: 1_600_000_000,
            last_seen: 1_600_003_600,
            count: 5,
            tags: tags.to_string(),
            ttl: 0,
            consensus: 1,
            stats: None,
        }
    }

    fn objects_of<'a>(export: &'a Export, kind: &str) -> Vec<&'a Value> {
        export.bundle["objects"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|object| object["type"] == kind)
            .collect()
    }

    #[test]
    fn a_namespace_becomes_an_indicator_and_a_sighting() {
        let export = bundle(
            "feeds/ips",
            &[view("1.2.3.4", "stix-type:ipv4-addr")],
            None,
            &Settings::default(),
        );

        assert_eq!(export.exported, 1);
        assert!(export.skipped.is_empty());
        assert_eq!(export.bundle["type"], "bundle");

        let indicator = objects_of(&export, "indicator")[0];
        assert_eq!(indicator["spec_version"], "2.1");
        assert_eq!(indicator["pattern"], "[ipv4-addr:value = '1.2.3.4']");
        assert_eq!(indicator["pattern_type"], "stix");
        assert_eq!(indicator["valid_from"], "2020-09-13T12:26:40.000Z");

        let sighting = objects_of(&export, "sighting")[0];
        assert_eq!(sighting["count"], 5);
        assert_eq!(sighting["first_seen"], "2020-09-13T12:26:40.000Z");
        assert_eq!(sighting["last_seen"], "2020-09-13T13:26:40.000Z");
        assert_eq!(sighting["sighting_of_ref"], indicator["id"]);
        assert_eq!(sighting["x_sightingdb_namespace"], "feeds/ips");

        // Both point at the identity publishing the bundle.
        let author = objects_of(&export, "identity")[0];
        assert_eq!(author["name"], "SightingDB");
        assert_eq!(author["identity_class"], "system");
        assert_eq!(indicator["created_by_ref"], author["id"]);
        assert_eq!(sighting["where_sighted_refs"][0], author["id"]);
    }

    /// The point of deriving ids rather than generating them: two exports of
    /// the same data are the same bundle, and one value in two namespaces is
    /// one indicator.
    #[test]
    fn ids_are_stable_across_exports_and_namespaces() {
        let settings = Settings::default();
        let values = [view("1.2.3.4", "stix-type:ipv4-addr")];

        let once = bundle("feeds/ips", &values, None, &settings);
        let again = bundle("feeds/ips", &values, None, &settings);
        assert_eq!(once.bundle, again.bundle);

        let elsewhere = bundle("other/ips", &values, None, &settings);
        assert_eq!(
            objects_of(&once, "indicator")[0]["id"],
            objects_of(&elsewhere, "indicator")[0]["id"],
        );
        // The sighting is per namespace, so those must differ.
        assert_ne!(
            objects_of(&once, "sighting")[0]["id"],
            objects_of(&elsewhere, "sighting")[0]["id"],
        );
    }

    #[test]
    fn an_imported_indicator_keeps_the_id_it_arrived_with() {
        let export = bundle(
            "feeds/ips",
            &[view(
                "1.2.3.4",
                "stix-type:ipv4-addr,stix-id:indicator--9299f726-ce06-492e-8472-2b52ccb53191",
            )],
            None,
            &Settings::default(),
        );

        let indicator = objects_of(&export, "indicator")[0];
        assert_eq!(
            indicator["id"],
            "indicator--9299f726-ce06-492e-8472-2b52ccb53191"
        );
        assert_eq!(
            objects_of(&export, "sighting")[0]["sighting_of_ref"],
            indicator["id"]
        );
    }

    /// A malformed id is not a reason to emit an invalid bundle.
    #[test]
    fn a_nonsense_stix_id_tag_is_ignored() {
        let export = bundle(
            "feeds/ips",
            &[view(
                "1.2.3.4",
                "stix-type:ipv4-addr,stix-id:indicator--nope",
            )],
            None,
            &Settings::default(),
        );
        let id = objects_of(&export, "indicator")[0]["id"].as_str().unwrap();
        assert!(
            Uuid::parse_str(id.trim_start_matches("indicator--")).is_ok(),
            "{id}"
        );
    }

    #[test]
    fn tags_fill_in_what_the_value_cannot_say() {
        let export = bundle(
            "feeds/ips",
            &[view(
                "1.2.3.4",
                "stix-type:ipv4-addr, tlp:amber, confidence:80, \
                 indicator-type:malicious-activity, indicator-type:anomalous-activity, \
                 name:Known scanner, description:Seen hitting the perimeter, \
                 identity:Beta Cyber Intelligence Company",
            )],
            None,
            &Settings::default(),
        );

        let indicator = objects_of(&export, "indicator")[0];
        assert_eq!(indicator["name"], "Known scanner");
        assert_eq!(indicator["description"], "Seen hitting the perimeter");
        assert_eq!(
            indicator["indicator_types"],
            json!(["malicious-activity", "anomalous-activity"])
        );
        assert_eq!(indicator["confidence"], 80);
        assert_eq!(
            indicator["object_marking_refs"],
            json!(["marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"])
        );

        // The marking it references is in the bundle, so it stands alone.
        let markings = objects_of(&export, "marking-definition");
        assert_eq!(markings.len(), 1);
        assert_eq!(markings[0]["name"], "TLP:AMBER");
        assert_eq!(markings[0]["definition"]["tlp"], "amber");

        // `identity:` says who saw it, which is what where_sighted_refs means.
        let sighting = objects_of(&export, "sighting")[0];
        let seen_by = sighting["where_sighted_refs"][0].as_str().unwrap();
        let named = objects_of(&export, "identity")
            .into_iter()
            .find(|object| object["id"] == seen_by)
            .expect("the identity it points at is in the bundle");
        assert_eq!(named["name"], "Beta Cyber Intelligence Company");
    }

    #[test]
    fn a_ttl_becomes_a_validity_window() {
        let mut value = view("1.2.3.4", "stix-type:ipv4-addr");
        value.ttl = 3600;
        let export = bundle("feeds/ips", &[value], None, &Settings::default());

        assert_eq!(
            objects_of(&export, "indicator")[0]["valid_until"],
            "2020-09-13T14:26:40.000Z"
        );
    }

    #[test]
    fn hashes_become_a_file_hash_pattern() {
        let digest = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let export = bundle(
            "feeds/hashes",
            &[view(digest, "stix-type:file.SHA-256")],
            None,
            &Settings::default(),
        );

        assert_eq!(
            objects_of(&export, "indicator")[0]["pattern"],
            format!("[file:hashes.'SHA-256' = '{digest}']")
        );
    }

    #[test]
    fn a_quote_in_a_value_is_escaped_rather_than_ending_the_pattern() {
        let export = bundle(
            "feeds/urls",
            &[view("http://a/it's", "stix-type:url")],
            None,
            &Settings::default(),
        );

        assert_eq!(
            objects_of(&export, "indicator")[0]["pattern"],
            r"[url:value = 'http://a/it\'s']"
        );
    }

    #[test]
    fn the_type_is_inferred_when_nothing_says_what_it_is() {
        for (value, expected) in [
            ("1.2.3.4", "ipv4-addr"),
            ("2001:db8::1", "ipv6-addr"),
            ("10.0.0.0/8", "ipv4-addr"),
            ("evil.example.com", "domain-name"),
            ("http://evil.example/x", "url"),
            ("someone@example.com", "email-addr"),
            ("d41d8cd98f00b204e9800998ecf8427e", "file.MD5"),
        ] {
            assert_eq!(infer_type(value), Some(expected), "{value}");
        }

        let export = bundle(
            "feeds/mixed",
            &[view("1.2.3.4", ""), view("evil.example.com", "")],
            None,
            &Settings::default(),
        );
        assert_eq!(export.exported, 2);
        let patterns: Vec<&str> = objects_of(&export, "indicator")
            .iter()
            .map(|object| object["pattern"].as_str().unwrap())
            .collect();
        assert!(
            patterns.contains(&"[ipv4-addr:value = '1.2.3.4']"),
            "{patterns:?}"
        );
        assert!(
            patterns.contains(&"[domain-name:value = 'evil.example.com']"),
            "{patterns:?}"
        );
    }

    /// The namespace's configured import type is better than a guess: it is
    /// what the operator said the namespace holds.
    #[test]
    fn the_configured_type_beats_inference_and_the_tag_beats_both() {
        let export = bundle(
            "feeds/things",
            &[
                view("some-internal-token", ""),
                view("1.2.3.4", "stix-type:ipv4-addr"),
            ],
            Some("x-internal-token"),
            &Settings::default(),
        );

        let patterns: Vec<&str> = objects_of(&export, "indicator")
            .iter()
            .map(|object| object["pattern"].as_str().unwrap())
            .collect();
        assert!(
            patterns.contains(&"[x-internal-token:value = 'some-internal-token']"),
            "{patterns:?}"
        );
        assert!(
            patterns.contains(&"[ipv4-addr:value = '1.2.3.4']"),
            "{patterns:?}"
        );
    }

    #[test]
    fn a_value_of_no_recognisable_type_is_reported_rather_than_guessed_at() {
        let export = bundle(
            "feeds/notes",
            &[view("whatever this is", "")],
            None,
            &Settings::default(),
        );

        assert_eq!(export.exported, 0);
        assert_eq!(export.skipped, ["whatever this is"]);
        // Only the publishing identity, with nothing to say about it.
        assert_eq!(export.bundle["objects"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn the_publishing_identity_comes_from_the_configuration() {
        let export = bundle(
            "feeds/ips",
            &[view("1.2.3.4", "stix-type:ipv4-addr")],
            None,
            &Settings {
                identity: "Alpha Threat Analysis Org.".to_string(),
                identity_class: "organization".to_string(),
            },
        );

        let author = objects_of(&export, "identity")[0];
        assert_eq!(author["name"], "Alpha Threat Analysis Org.");
        assert_eq!(author["identity_class"], "organization");
    }
}
