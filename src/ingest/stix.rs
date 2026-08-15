//! Reading sightings out of STIX 2.1 bundles.
//!
//! Three kinds of object carry observations, in decreasing order of how much
//! they tell us:
//!
//! * `sighting` — an explicit count and time window, which is exactly our data
//!   model. It points at what was seen via `sighting_of_ref` and
//!   `observed_data_refs`.
//! * `observed-data` — `number_observed` between `first_observed` and
//!   `last_observed`, pointing at cyber-observable objects.
//! * `indicator` — a STIX pattern, from which we lift the literal values.
//!
//! Objects reference each other by id, so a bundle is indexed first and walked
//! second. Anything we do not understand is skipped rather than failing the
//! import: bundles routinely carry objects that have nothing to do with
//! observations.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use regex::Regex;
use serde_json::Value;
use std::sync::OnceLock;

use crate::ingest::misp::Sighting;

/// Which STIX observable types are ingested, and where they land.
///
/// Keys are STIX SCO types (`ipv4-addr`, `domain-name`) and, for files, the
/// hash algorithm as `file.MD5` or `file.SHA-256`. A dot rather than STIX's own
/// colon because `:` is a key/value delimiter in INI files, so `file:MD5=...`
/// would silently parse as the key `file`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Mapping {
    pub types: HashMap<String, String>,
    pub default_namespace: Option<String>,
}

impl Mapping {
    fn namespace_for(&self, stix_type: &str) -> Option<&str> {
        self.types
            .get(stix_type)
            .map(String::as_str)
            .or(self.default_namespace.as_deref())
    }
}

/// An observable lifted out of the bundle, before timing is applied.
struct Observable {
    stix_type: String,
    value: String,
}

/// Parse a bundle, or a bare array of STIX objects.
pub fn parse_bundle(json: &str, mapping: &Mapping) -> Result<Vec<Sighting>, serde_json::Error> {
    let root: Value = serde_json::from_str(json)?;

    let objects = match root.get("objects") {
        Some(Value::Array(objects)) => objects.clone(),
        _ => match root {
            Value::Array(objects) => objects,
            // A single loose object is a legitimate, if unusual, file.
            object @ Value::Object(_) => vec![object],
            _ => Vec::new(),
        },
    };

    let by_id: HashMap<&str, &Value> = objects
        .iter()
        .filter_map(|object| Some((object.get("id")?.as_str()?, object)))
        .collect();

    let mut sightings = Vec::new();
    for object in &objects {
        match object.get("type").and_then(Value::as_str) {
            Some("sighting") => from_sighting(object, &by_id, mapping, &mut sightings),
            Some("observed-data") => from_observed_data(object, &by_id, mapping, &mut sightings),
            Some("indicator") => from_indicator(object, mapping, &mut sightings),
            _ => {}
        }
    }

    Ok(sightings)
}

/// A `sighting` SRO: the count and window come from the sighting itself, the
/// values from whatever it points at.
fn from_sighting(
    sighting: &Value,
    by_id: &HashMap<&str, &Value>,
    mapping: &Mapping,
    out: &mut Vec<Sighting>,
) {
    let count = sighting
        .get("count")
        .and_then(Value::as_u64)
        .unwrap_or(1)
        .max(1);
    let first = timestamp(sighting.get("first_seen"));
    let last = timestamp(sighting.get("last_seen"));

    let mut observables = Vec::new();

    // What was seen: usually an indicator, sometimes an observable directly.
    if let Some(target) = sighting
        .get("sighting_of_ref")
        .and_then(Value::as_str)
        .and_then(|id| by_id.get(id))
    {
        match target.get("type").and_then(Value::as_str) {
            Some("indicator") => {
                if let Some(pattern) = target.get("pattern").and_then(Value::as_str) {
                    observables.extend(from_pattern(pattern));
                }
            }
            _ => collect_observable(target, &mut observables),
        }
    }

    // Plus anything the referenced observed-data saw.
    if let Some(Value::Array(refs)) = sighting.get("observed_data_refs") {
        for id in refs.iter().filter_map(Value::as_str) {
            if let Some(observed) = by_id.get(id) {
                observables.extend(observables_of(observed, by_id));
            }
        }
    }

    emit(observables, mapping, first, last, count, out);
}

fn from_observed_data(
    observed: &Value,
    by_id: &HashMap<&str, &Value>,
    mapping: &Mapping,
    out: &mut Vec<Sighting>,
) {
    let count = observed
        .get("number_observed")
        .and_then(Value::as_u64)
        .unwrap_or(1)
        .max(1);
    let first = timestamp(observed.get("first_observed"));
    let last = timestamp(observed.get("last_observed"));

    emit(
        observables_of(observed, by_id),
        mapping,
        first,
        last,
        count,
        out,
    );
}

/// An indicator on its own is one observation, timed by `valid_from`.
fn from_indicator(indicator: &Value, mapping: &Mapping, out: &mut Vec<Sighting>) {
    let Some(pattern) = indicator.get("pattern").and_then(Value::as_str) else {
        return;
    };
    let seen = timestamp(indicator.get("valid_from"));
    emit(from_pattern(pattern), mapping, seen, None, 1, out);
}

/// The observables an `observed-data` points at, whether by reference or
/// embedded the pre-2.1 way.
fn observables_of(observed: &Value, by_id: &HashMap<&str, &Value>) -> Vec<Observable> {
    let mut found = Vec::new();

    if let Some(Value::Array(refs)) = observed.get("object_refs") {
        for id in refs.iter().filter_map(Value::as_str) {
            if let Some(object) = by_id.get(id) {
                collect_observable(object, &mut found);
            }
        }
    }

    // `objects` was deprecated in 2.1 but plenty of tooling still emits it.
    if let Some(Value::Object(embedded)) = observed.get("objects") {
        for object in embedded.values() {
            collect_observable(object, &mut found);
        }
    }

    found
}

/// Lift the value(s) out of one cyber-observable object.
fn collect_observable(object: &Value, out: &mut Vec<Observable>) {
    let Some(stix_type) = object.get("type").and_then(Value::as_str) else {
        return;
    };

    // A file has no single value: each hash is its own observable.
    if stix_type == "file" {
        if let Some(Value::Object(hashes)) = object.get("hashes") {
            for (algorithm, digest) in hashes {
                if let Some(digest) = digest.as_str().filter(|d| !d.is_empty()) {
                    out.push(Observable {
                        stix_type: format!("file.{algorithm}"),
                        value: digest.to_string(),
                    });
                }
            }
        }
        return;
    }

    // Everything else keeps its value under a predictable property.
    let value = match stix_type {
        "mutex" | "windows-registry-key" => object.get("key").or_else(|| object.get("name")),
        _ => object.get("value"),
    };

    if let Some(value) = value.and_then(Value::as_str).filter(|v| !v.is_empty()) {
        out.push(Observable {
            stix_type: stix_type.to_string(),
            value: value.to_string(),
        });
    }
}

/// Pull literal comparisons out of a STIX pattern.
///
/// Patterns are a small language of their own; rather than implement it, we
/// take the `<type>:<path> = '<value>'` comparisons, which is what carries the
/// indicator values in practice. Qualifiers, operators and observation
/// expressions around them are ignored.
fn from_pattern(pattern: &str) -> Vec<Observable> {
    static COMPARISON: OnceLock<Regex> = OnceLock::new();
    let comparison = COMPARISON.get_or_init(|| {
        Regex::new(r"([a-z0-9_-]+):([a-zA-Z0-9_.\[\]'-]+)\s*=\s*'((?:[^'\\]|\\.)*)'")
            .expect("the pattern regex is a constant")
    });

    comparison
        .captures_iter(pattern)
        .filter_map(|captures| {
            let stix_type = captures.get(1)?.as_str();
            let path = captures.get(2)?.as_str();
            let value = captures.get(3)?.as_str().replace("\\'", "'");
            if value.is_empty() {
                return None;
            }

            // `file:hashes.'SHA-256'` maps to the same key a file SCO produces.
            let key = if stix_type == "file" && path.starts_with("hashes") {
                let algorithm = path
                    .trim_start_matches("hashes")
                    .trim_matches(|c| c == '.' || c == '\'' || c == '[' || c == ']');
                format!("file.{algorithm}")
            } else {
                stix_type.to_string()
            };

            Some(Observable {
                stix_type: key,
                value,
            })
        })
        .collect()
}

fn emit(
    observables: Vec<Observable>,
    mapping: &Mapping,
    first: Option<i64>,
    last: Option<i64>,
    count: u64,
    out: &mut Vec<Sighting>,
) {
    for observable in observables {
        let Some(namespace) = mapping.namespace_for(&observable.stix_type) else {
            continue;
        };
        out.push(Sighting {
            namespace: namespace.to_string(),
            value: observable.value,
            timestamp: first.or(last),
            last_timestamp: last,
            count,
        });
    }
}

/// STIX timestamps are RFC 3339.
fn timestamp(value: Option<&Value>) -> Option<i64> {
    let text = value?.as_str()?;
    DateTime::parse_from_rfc3339(text)
        .ok()
        .map(|parsed| parsed.with_timezone(&Utc).timestamp())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mapping() -> Mapping {
        Mapping {
            types: [
                ("ipv4-addr", "stix/ips"),
                ("ipv6-addr", "stix/ips"),
                ("domain-name", "stix/domains"),
                ("url", "stix/urls"),
                ("file.MD5", "stix/hashes"),
                ("file.SHA-256", "stix/hashes"),
            ]
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
            default_namespace: None,
        }
    }

    fn bundle(objects: &str) -> String {
        format!(r#"{{"type":"bundle","id":"bundle--1","objects":[{objects}]}}"#)
    }

    // -- observed-data -----------------------------------------------------

    #[test]
    fn observed_data_carries_its_count_and_window() {
        let body = bundle(
            r#"
            {"type":"ipv4-addr","id":"ipv4-addr--1","value":"1.2.3.4"},
            {"type":"observed-data","id":"observed-data--1","number_observed":5,
             "first_observed":"2020-09-13T12:26:40Z","last_observed":"2020-09-13T13:26:40Z",
             "object_refs":["ipv4-addr--1"]}"#,
        );

        let sightings = parse_bundle(&body, &mapping()).unwrap();
        assert_eq!(sightings.len(), 1);
        assert_eq!(sightings[0].namespace, "stix/ips");
        assert_eq!(sightings[0].value, "1.2.3.4");
        assert_eq!(sightings[0].count, 5);
        assert_eq!(sightings[0].timestamp, Some(1_600_000_000));
        assert_eq!(sightings[0].last_timestamp, Some(1_600_003_600));
    }

    /// 2.1 deprecated embedded `objects`, but real exports still contain them.
    #[test]
    fn embedded_objects_are_read_as_well_as_references() {
        let body = bundle(
            r#"{"type":"observed-data","id":"observed-data--1","number_observed":1,
             "first_observed":"2020-09-13T12:26:40Z","last_observed":"2020-09-13T12:26:40Z",
             "objects":{"0":{"type":"domain-name","value":"evil.com"}}}"#,
        );

        let sightings = parse_bundle(&body, &mapping()).unwrap();
        assert_eq!(sightings[0].value, "evil.com");
        assert_eq!(sightings[0].namespace, "stix/domains");
    }

    #[test]
    fn a_file_yields_one_sighting_per_hash() {
        let body = bundle(
            r#"
            {"type":"file","id":"file--1","name":"x.exe","hashes":{
              "MD5":"d41d8cd98f00b204e9800998ecf8427e",
              "SHA-256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}},
            {"type":"observed-data","id":"observed-data--1","number_observed":1,
             "first_observed":"2020-09-13T12:26:40Z","last_observed":"2020-09-13T12:26:40Z",
             "object_refs":["file--1"]}"#,
        );

        let mut values: Vec<String> = parse_bundle(&body, &mapping())
            .unwrap()
            .into_iter()
            .map(|s| s.value)
            .collect();
        values.sort();
        assert_eq!(values.len(), 2);
        assert!(values[0].starts_with("d41d8cd9") || values[1].starts_with("d41d8cd9"));
    }

    // -- indicators --------------------------------------------------------

    #[test]
    fn an_indicator_pattern_yields_its_literals() {
        let body = bundle(
            r#"{"type":"indicator","id":"indicator--1","valid_from":"2020-09-13T12:26:40Z",
             "pattern_type":"stix","pattern":"[ipv4-addr:value = '1.2.3.4']"}"#,
        );

        let sightings = parse_bundle(&body, &mapping()).unwrap();
        assert_eq!(sightings[0].value, "1.2.3.4");
        assert_eq!(sightings[0].timestamp, Some(1_600_000_000));
        assert_eq!(sightings[0].count, 1);
    }

    #[test]
    fn compound_patterns_yield_every_literal() {
        let body = bundle(
            r#"{"type":"indicator","id":"indicator--1","valid_from":"2020-09-13T12:26:40Z",
             "pattern":"[ipv4-addr:value = '1.2.3.4' OR domain-name:value = 'evil.com']"}"#,
        );

        let values: Vec<String> = parse_bundle(&body, &mapping())
            .unwrap()
            .into_iter()
            .map(|s| s.value)
            .collect();
        assert_eq!(values, ["1.2.3.4", "evil.com"]);
    }

    #[test]
    fn hash_patterns_map_to_the_same_key_as_file_objects() {
        let body = bundle(
            r#"{"type":"indicator","id":"indicator--1",
             "pattern":"[file:hashes.'SHA-256' = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855']"}"#,
        );

        let sightings = parse_bundle(&body, &mapping()).unwrap();
        assert_eq!(sightings.len(), 1);
        assert_eq!(sightings[0].namespace, "stix/hashes");
    }

    #[test]
    fn escaped_quotes_inside_a_pattern_survive() {
        let observables = from_pattern(r"[url:value = 'http://a/it\'s']");
        assert_eq!(observables[0].value, "http://a/it's");
    }

    #[test]
    fn patterns_with_no_literals_yield_nothing() {
        assert!(from_pattern("[ipv4-addr:value ISSUBSET '10.0.0.0/8']").is_empty());
        assert!(from_pattern("").is_empty());
    }

    // -- sightings ---------------------------------------------------------

    #[test]
    fn a_sighting_uses_its_own_count_and_window() {
        let body = bundle(
            r#"
            {"type":"indicator","id":"indicator--1","pattern":"[ipv4-addr:value = '1.2.3.4']"},
            {"type":"sighting","id":"sighting--1","count":42,
             "first_seen":"2020-09-13T12:26:40Z","last_seen":"2020-09-13T13:26:40Z",
             "sighting_of_ref":"indicator--1"}"#,
        );

        let sightings = parse_bundle(&body, &mapping()).unwrap();
        // The indicator is counted once in its own right, the sighting 42 times.
        let from_sighting = sightings.iter().find(|s| s.count == 42).unwrap();
        assert_eq!(from_sighting.value, "1.2.3.4");
        assert_eq!(from_sighting.timestamp, Some(1_600_000_000));
        assert_eq!(from_sighting.last_timestamp, Some(1_600_003_600));
    }

    #[test]
    fn a_sighting_resolves_its_observed_data() {
        let body = bundle(
            r#"
            {"type":"domain-name","id":"domain-name--1","value":"evil.com"},
            {"type":"observed-data","id":"observed-data--1","number_observed":1,
             "first_observed":"2020-09-13T12:26:40Z","last_observed":"2020-09-13T12:26:40Z",
             "object_refs":["domain-name--1"]},
            {"type":"sighting","id":"sighting--1","count":3,
             "first_seen":"2020-09-13T12:26:40Z",
             "sighting_of_ref":"indicator--missing",
             "observed_data_refs":["observed-data--1"]}"#,
        );

        let sightings = parse_bundle(&body, &mapping()).unwrap();
        assert!(
            sightings
                .iter()
                .any(|s| s.count == 3 && s.value == "evil.com")
        );
    }

    // -- robustness --------------------------------------------------------

    #[test]
    fn unmapped_types_are_skipped_unless_a_default_is_set() {
        let body = bundle(
            r#"
            {"type":"email-addr","id":"email-addr--1","value":"a@b.example"},
            {"type":"observed-data","id":"observed-data--1","number_observed":1,
             "object_refs":["email-addr--1"]}"#,
        );

        assert!(parse_bundle(&body, &mapping()).unwrap().is_empty());

        let mut mapping = mapping();
        mapping.default_namespace = Some("stix/other".into());
        assert_eq!(
            parse_bundle(&body, &mapping).unwrap()[0].namespace,
            "stix/other"
        );
    }

    #[test]
    fn unrelated_objects_are_ignored_rather_than_failing_the_bundle() {
        let body = bundle(
            r#"
            {"type":"identity","id":"identity--1","name":"Acme"},
            {"type":"marking-definition","id":"marking-definition--1"},
            {"type":"relationship","id":"relationship--1","relationship_type":"indicates"},
            {"type":"ipv4-addr","id":"ipv4-addr--1","value":"1.2.3.4"},
            {"type":"observed-data","id":"observed-data--1","number_observed":1,
             "object_refs":["ipv4-addr--1"]}"#,
        );

        assert_eq!(parse_bundle(&body, &mapping()).unwrap().len(), 1);
    }

    #[test]
    fn a_dangling_reference_does_not_panic() {
        let body = bundle(
            r#"{"type":"observed-data","id":"observed-data--1","number_observed":1,
             "object_refs":["ipv4-addr--gone"]}"#,
        );
        assert!(parse_bundle(&body, &mapping()).unwrap().is_empty());
    }

    #[test]
    fn a_bare_array_of_objects_is_accepted() {
        let body = r#"[{"type":"indicator","id":"indicator--1",
                        "pattern":"[ipv4-addr:value = '1.2.3.4']"}]"#;
        assert_eq!(parse_bundle(body, &mapping()).unwrap().len(), 1);
    }

    #[test]
    fn malformed_json_is_an_error() {
        assert!(parse_bundle("{not json", &mapping()).is_err());
    }

    #[test]
    fn a_missing_count_defaults_to_one() {
        let body = bundle(
            r#"
            {"type":"ipv4-addr","id":"ipv4-addr--1","value":"1.2.3.4"},
            {"type":"observed-data","id":"observed-data--1","object_refs":["ipv4-addr--1"]}"#,
        );
        assert_eq!(parse_bundle(&body, &mapping()).unwrap()[0].count, 1);
    }
}
