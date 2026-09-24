use chrono::{DateTime, Utc};

use crate::db::{CONFIG_PREFIX, Database, WriteOpts};
use crate::error::ApiError;

/// Record one sighting, returning the new count for that value.
///
/// `when` is `None` for "right now", which is what a write without an explicit
/// `timestamp=` argument means. `ttl` is `None` to leave whatever expiry the
/// attribute already had.
#[cfg(test)]
pub fn write(
    db: &Database,
    namespace: &str,
    value: &str,
    when: Option<DateTime<Utc>>,
    ttl: Option<u64>,
) -> Result<u64, ApiError> {
    write_tagged(db, namespace, value, when, ttl, "")
}

/// The same, carrying what is known about the value alongside the sighting.
///
/// Tags are merged with whatever the value already had — see
/// [`crate::attribute::split_tags`] for the format and the README for the
/// vocabulary the STIX export understands.
pub fn write_tagged(
    db: &Database,
    namespace: &str,
    value: &str,
    when: Option<DateTime<Utc>>,
    ttl: Option<u64>,
    tags: &str,
) -> Result<u64, ApiError> {
    check(namespace, value)?;

    Ok(db.write_tagged(
        namespace,
        value,
        when.unwrap_or_else(Utc::now),
        WriteOpts {
            consensus: true,
            ttl,
        },
        tags,
    ))
}

/// Everything [`write_tagged`] refuses before it touches the database.
///
/// Split out so that the dry run behind `/vwb` can answer "would this be
/// accepted?" with the very check the writer uses. A validator that is a
/// second copy of the rules is worse than no validator at all: it drifts, and
/// then it tells a client yes where the writer says no.
///
/// Everything here is decided from the namespace and the value alone, which is
/// what makes the dry run possible — none of it depends on database state, so
/// passing this check today means the write is accepted today. It says nothing
/// about a later write, since the ACL can change underneath it.
pub fn check(namespace: &str, value: &str) -> Result<(), ApiError> {
    if value.is_empty() {
        return Err(ApiError::EmptyValue);
    }
    // The `_config` tree holds API keys. Letting it be written over HTTP would
    // let any key holder mint further keys for themselves.
    if namespace.starts_with(CONFIG_PREFIX) {
        return Err(ApiError::ConfigNamespace);
    }
    Ok(())
}

/// Convert a client-supplied Unix timestamp into an instant.
pub fn timestamp_to_instant(timestamp: i64) -> Result<DateTime<Utc>, ApiError> {
    DateTime::from_timestamp(timestamp, 0).ok_or(ApiError::InvalidTimestamp(timestamp))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_write_without_a_timestamp_is_recorded_now() {
        let db = Database::default();
        let before = Utc::now().timestamp();

        write(&db, "ns", "v", None, None).unwrap();

        let view = db.view("ns", "v", 0, false).unwrap();
        assert!(
            view.first_seen >= before,
            "first_seen was {}, expected >= {before}",
            view.first_seen
        );
        assert_ne!(view.first_seen, 0);
    }

    #[test]
    fn an_explicit_timestamp_is_honoured() {
        let db = Database::default();

        write(
            &db,
            "ns",
            "v",
            Some(timestamp_to_instant(1_566_624_658).unwrap()),
            None,
        )
        .unwrap();

        let view = db.view("ns", "v", 0, false).unwrap();
        assert_eq!(view.first_seen, 1_566_624_658);
        assert_eq!(view.last_seen, 1_566_624_658);
    }

    #[test]
    fn write_returns_the_running_count() {
        let db = Database::default();

        assert_eq!(write(&db, "ns", "v", None, None).unwrap(), 1);
        assert_eq!(write(&db, "ns", "v", None, None).unwrap(), 2);
    }

    #[test]
    fn a_ttl_is_recorded_and_expires_the_value() {
        let db = Database::default();

        write(&db, "ns", "live", None, Some(3600)).unwrap();
        assert_eq!(db.view("ns", "live", 0, false).unwrap().ttl, 3600);

        // Sighted in 1970 with a one minute TTL: already gone.
        write(
            &db,
            "ns",
            "dead",
            Some(timestamp_to_instant(1000).unwrap()),
            Some(60),
        )
        .unwrap();
        assert!(db.view("ns", "dead", 0, false).is_none());
    }

    #[test]
    fn empty_values_are_rejected() {
        let db = Database::default();
        assert_eq!(
            write(&db, "ns", "", None, None).unwrap_err(),
            ApiError::EmptyValue
        );
    }

    #[test]
    fn config_namespace_is_not_writable() {
        let db = Database::new();

        assert_eq!(
            write(&db, "_config/acl/apikeys/mine", "x", None, None).unwrap_err(),
            ApiError::ConfigNamespace
        );
        assert!(!db.namespace_exists("_config/acl/apikeys/mine"));
    }

    #[test]
    fn out_of_range_timestamps_are_rejected() {
        assert_eq!(
            timestamp_to_instant(i64::MAX).unwrap_err(),
            ApiError::InvalidTimestamp(i64::MAX)
        );
    }
}
