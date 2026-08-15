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
        }
    }
}

/// Which MISP attribute types are ingested, and where they land.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Mapping {
    /// MISP attribute type (`ip-src`, `md5`, ...) to namespace.
    pub types: HashMap<String, String>,
    /// Where unmapped types go. `None` drops them.
    pub default_namespace: Option<String>,
    /// Ingest only attributes MISP has flagged as actionable.
    pub require_to_ids: bool,
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

    // A single attribute, which is what `misp_json_attribute` carries.
    if let Some(attribute) = value.get("Attribute") {
        collect(attribute, mapping, &mut sightings);
    }

    // A whole event, which is what `misp_json` carries on publish.
    if let Some(event) = value.get("Event") {
        if let Some(attributes) = event.get("Attribute") {
            collect(attributes, mapping, &mut sightings);
        }
        // Attributes can also hang off objects within the event.
        if let Some(Value::Array(objects)) = event.get("Object") {
            for object in objects {
                if let Some(attributes) = object.get("Attribute") {
                    collect(attributes, mapping, &mut sightings);
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
fn collect(node: &Value, mapping: &Mapping, out: &mut Vec<Sighting>) {
    match node {
        Value::Array(items) => {
            for item in items {
                collect(item, mapping, out);
            }
        }
        Value::Object(_) => {
            if let Some(sighting) = attribute_to_sighting(node, mapping) {
                out.push(sighting);
            }
        }
        _ => {}
    }
}

fn attribute_to_sighting(attribute: &Value, mapping: &Mapping) -> Option<Sighting> {
    if mapping.require_to_ids && !truthy(attribute.get("to_ids")) {
        return None;
    }

    let misp_type = attribute.get("type")?.as_str()?;
    let namespace = mapping.namespace_for(misp_type)?.to_string();

    // Composite types (`filename|md5`) live in `value`; some publishers only
    // fill in `value1`.
    let value = attribute
        .get("value")
        .and_then(Value::as_str)
        .or_else(|| attribute.get("value1").and_then(Value::as_str))?;
    if value.is_empty() {
        return None;
    }

    Some(Sighting::once(namespace, value, timestamp_of(attribute)))
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
            vec![Sighting::once("misp/ips", "1.2.3.4", Some(1_600_000_000))]
        );
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
