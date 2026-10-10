use chrono::{DateTime, Utc};

use crate::db::{Database, WriteOpts};
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
) -> Result<crate::db::Written, ApiError> {
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
) -> Result<crate::db::Written, ApiError> {
    write_tagged_as(db, None, namespace, value, when, ttl, tags)
}

/// The same, counted for whoever the sighting came from.
///
/// `origin` is `Some` when the write was forwarded here: it is counted for the
/// server it arrived from rather than for this one, so one write fanned out to
/// several mirrors is one contribution on all of them instead of a separate one
/// each. Merging mirrors that already agree then changes nothing, which is the
/// point.
pub fn write_tagged_as(
    db: &Database,
    origin: Option<&str>,
    namespace: &str,
    value: &str,
    when: Option<DateTime<Utc>>,
    ttl: Option<u64>,
    tags: &str,
) -> Result<crate::db::Written, ApiError> {
    check(db, namespace, value)?;

    let node = origin.unwrap_or_else(|| db.node());
    Ok(db.write_tagged_as(
        node,
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
pub fn check(db: &Database, namespace: &str, value: &str) -> Result<(), ApiError> {
    if value.is_empty() {
        return Err(ApiError::EmptyValue);
    }
    // `_all`, `_shadow/*` and `_config` are written by the database about
    // itself. A client writing `_all` could claim a consensus no namespace
    // supports; a client writing `_config` could mint itself keys on an older
    // deployment. Neither is reachable from here — see [`crate::db::is_internal`].
    if crate::db::is_internal(namespace) {
        return Err(ApiError::InternalNamespace(namespace.to_string()));
    }
    // A server told which namespaces it holds will not quietly take one it was
    // not given. Forwarding does not exist yet, so for now this is where such
    // a write stops rather than where it is passed on.
    if !db.holds(namespace) {
        return Err(ApiError::NotStored(namespace.to_string()));
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

        let first = write(&db, "ns", "v", None, None).unwrap();
        assert_eq!(first.count, 1);
        assert!(first.new, "the first sighting was not reported as new");

        let second = write(&db, "ns", "v", None, None).unwrap();
        assert_eq!(second.count, 2);
        assert!(!second.new, "a repeat sighting was reported as new");
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

    /// No internal namespace is writable from outside — not just `_config`.
    ///
    /// `_all` is the one that matters most: a client able to write it could
    /// claim a consensus no namespace supports, and consensus is the number
    /// this database exists to be trusted about.
    #[test]
    fn no_internal_namespace_is_writable() {
        for namespace in [
            "_all",
            "_shadow/feeds/ips",
            "_config/acl/apikeys/mine",
            "_internal",
            "_anything/at/all",
        ] {
            let db = Database::new();
            assert_eq!(
                write(&db, namespace, "x", None, None).unwrap_err(),
                ApiError::InternalNamespace(namespace.to_string()),
                "{namespace} was writable"
            );
            assert!(!db.namespace_exists(namespace), "{namespace} was created");
        }
    }

    /// The underscore only counts at the front: a namespace is internal
    /// because of its first segment, which is the same rule that decides
    /// which shard holds it.
    #[test]
    fn an_underscore_further_in_is_an_ordinary_namespace() {
        let db = Database::new();

        assert_eq!(
            write(&db, "feeds/_private/ips", "x", None, None)
                .unwrap()
                .count,
            1
        );
        assert!(db.namespace_exists("feeds/_private/ips"));
    }

    /// Refusing the writes must not stop the database writing them itself:
    /// consensus is maintained through `Database::write_tagged`, which does
    /// not go through this guard.
    #[test]
    fn the_guard_does_not_break_consensus_bookkeeping() {
        let db = Database::new();

        write(&db, "feeds/a", "1.2.3.4", None, None).unwrap();
        assert_eq!(
            db.view(
                "feeds/a",
                "1.2.3.4",
                db.count(crate::db::ALL_NAMESPACE, "1.2.3.4"),
                false
            )
            .unwrap()
            .consensus,
            1
        );

        write(&db, "feeds/b", "1.2.3.4", None, None).unwrap();
        assert_eq!(
            db.count(crate::db::ALL_NAMESPACE, "1.2.3.4"),
            2,
            "the consensus tally stopped being kept"
        );
    }

    #[test]
    fn out_of_range_timestamps_are_rejected() {
        assert_eq!(
            timestamp_to_instant(i64::MAX).unwrap_err(),
            ApiError::InvalidTimestamp(i64::MAX)
        );
    }
}
