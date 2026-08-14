use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::attribute::AttributeView;
use crate::db::{ALL_NAMESPACE, CONFIG_PREFIX, Database, NotFound, SHADOW_PREFIX, WriteOpts};
use crate::error::ApiError;

/// Every attribute in a namespace, returned when `/r/<ns>` is called without a
/// `val=` argument.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NamespaceView {
    pub attributes: Vec<AttributeView>,
}

/// Read one value out of a namespace.
///
/// Reading is not side-effect free: unless `with_shadow` is cleared, the lookup
/// is itself recorded under `_shadow/<namespace>` so that we can report how
/// often something was searched for. That happens whether or not the value was
/// found, since a miss is still a search.
pub fn read(
    db: &Database,
    namespace: &str,
    value: &str,
    with_stats: bool,
    with_shadow: bool,
) -> Result<AttributeView, ApiError> {
    if namespace.starts_with(CONFIG_PREFIX) {
        return Err(ApiError::ConfigNamespace);
    }

    let consensus = db.count(ALL_NAMESPACE, value);
    let result = match db.view(namespace, value, consensus, with_stats) {
        Some(view) => Ok(view),
        None if db.namespace_exists(namespace) => {
            Err(ApiError::NotFound(NotFound::value(namespace, value)))
        }
        None => Err(ApiError::NotFound(NotFound::namespace(namespace, value))),
    };

    if with_shadow {
        // Shadow sightings never contribute to consensus, and take their TTL
        // from the database policy rather than from the caller.
        db.write(
            &format!("{SHADOW_PREFIX}{namespace}"),
            value,
            Utc::now(),
            WriteOpts::default(),
        );
    }

    result
}

/// Read every value in a namespace. This does not raise shadow sightings.
pub fn read_namespace(db: &Database, namespace: &str) -> Result<NamespaceView, ApiError> {
    if namespace.starts_with(CONFIG_PREFIX) {
        return Err(ApiError::ConfigNamespace);
    }

    db.namespace_views(namespace)
        .map(|attributes| NamespaceView { attributes })
        .ok_or_else(|| ApiError::NotFound(NotFound::namespace(namespace, "")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{DateTime, Utc};

    fn at(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(secs, 0).expect("timestamp in range")
    }

    fn consensus() -> WriteOpts {
        WriteOpts {
            consensus: true,
            ttl: None,
        }
    }

    #[test]
    fn reading_a_known_value_reports_its_consensus() {
        let db = Database::default();
        db.write("a/ns", "1.2.3.4", at(100), consensus());
        db.write("b/ns", "1.2.3.4", at(200), consensus());

        let view = read(&db, "a/ns", "1.2.3.4", false, false).unwrap();

        assert_eq!(view.count, 1);
        assert_eq!(view.consensus, 2);
        assert_eq!(view.stats, None);
    }

    #[test]
    fn reading_raises_a_shadow_sighting() {
        let db = Database::default();
        db.write("a/ns", "v", at(100), consensus());

        read(&db, "a/ns", "v", false, true).unwrap();
        read(&db, "a/ns", "v", false, true).unwrap();

        assert_eq!(db.count("_shadow/a/ns", "v"), 2);
        // Shadow writes must not inflate consensus.
        assert_eq!(db.count(ALL_NAMESPACE, "v"), 1);
    }

    #[test]
    fn a_missed_read_still_raises_a_shadow_sighting() {
        let db = Database::default();
        db.write("a/ns", "known", at(100), consensus());

        assert!(read(&db, "a/ns", "unknown", false, true).is_err());
        assert_eq!(db.count("_shadow/a/ns", "unknown"), 1);
    }

    #[test]
    fn noshadow_suppresses_the_shadow_sighting() {
        let db = Database::default();
        db.write("a/ns", "v", at(100), consensus());

        read(&db, "a/ns", "v", false, false).unwrap();

        assert_eq!(db.count("_shadow/a/ns", "v"), 0);
    }

    #[test]
    fn missing_namespace_and_missing_value_are_distinguished() {
        let db = Database::default();
        db.write("a/ns", "known", at(100), consensus());

        let missing_value = read(&db, "a/ns", "other", false, false).unwrap_err();
        let missing_ns = read(&db, "z/ns", "other", false, false).unwrap_err();

        assert_eq!(
            missing_value,
            ApiError::NotFound(NotFound::value("a/ns", "other"))
        );
        assert_eq!(
            missing_ns,
            ApiError::NotFound(NotFound::namespace("z/ns", "other"))
        );
    }

    #[test]
    fn config_namespace_is_not_readable() {
        let db = Database::new();

        assert_eq!(
            read(&db, "_config/acl/apikeys/changeme", "", false, false).unwrap_err(),
            ApiError::ConfigNamespace
        );
        assert_eq!(
            read_namespace(&db, "_config/acl/apikeys/changeme").unwrap_err(),
            ApiError::ConfigNamespace
        );
    }

    #[test]
    fn namespace_read_returns_every_value() {
        let db = Database::default();
        db.write("a/ns", "one", at(100), consensus());
        db.write("a/ns", "two", at(100), consensus());

        let view = read_namespace(&db, "a/ns").unwrap();
        let mut values: Vec<_> = view.attributes.iter().map(|a| a.value.as_str()).collect();
        values.sort_unstable();

        assert_eq!(values, ["one", "two"]);
    }

    #[test]
    fn stats_are_included_on_request() {
        let db = Database::default();
        db.write("a/ns", "v", at(3600), consensus());
        db.write("a/ns", "v", at(3601), consensus());

        let view = read(&db, "a/ns", "v", true, false).unwrap();

        assert_eq!(view.stats.unwrap().get(&3600), Some(&2));
    }
}
