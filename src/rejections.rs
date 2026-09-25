//! A record of what would not be written, and why.
//!
//! Every write path answers its own caller about a rejected value — `/wb` in
//! the item's `status`, the management interface in `errors` — but a caller is
//! not always there to read it. The ZMQ ingest has no caller at all: a feed
//! that sends a malformed value gets it counted and dropped, and the value
//! reaches nothing but a `debug` log nobody has switched on.
//!
//! This is where all of them land instead, so the question "which values were
//! rejected, and why?" can be answered after the fact rather than only in the
//! response to the request that caused it.
//!
//! **Bounded and in memory.** A misbehaving feed can reject at the rate it can
//! send, so this is a ring buffer with a fixed cap: the oldest entry goes when
//! a new one arrives and the buffer is full. It is diagnostic, not evidence —
//! it does not survive a restart, and it is deliberately kept out of snapshots,
//! consensus and the STIX export, where a value that was never written has no
//! business appearing.
//!
//! **Not a sighting tree.** Storing these as sightings under some `_rejected/`
//! namespace would have come for free, but a rejected value is by definition
//! one the sighting rules refused: the commonest rejection of all is the empty
//! value, which cannot be a key in a namespace. Keeping them apart also keeps
//! them out of `/r`, where they would read as things the database had seen.

use std::collections::VecDeque;
use std::sync::{Mutex, PoisonError};

use serde::Serialize;

/// How many rejections are kept when the configuration does not say.
pub const DEFAULT_CAPACITY: usize = 1000;

/// Which write path turned a value away.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Source {
    /// `/w`, a single sighting over HTTP.
    Write,
    /// `/wb`, one item of a bulk write.
    BulkWrite,
    /// The management interface adding values to a namespace.
    Management,
    /// A feed consumed over ZMQ.
    Ingest,
}

/// One value that was not written.
#[derive(Debug, Clone, Serialize)]
pub struct Rejection {
    /// Unix seconds, so this reads the same way as `first_seen` elsewhere.
    pub when: i64,
    pub namespace: String,
    /// The value as it arrived, which for the commonest rejection of all is
    /// the empty string.
    pub value: String,
    /// Why it was turned away, in the words the caller was given.
    pub reason: String,
    pub source: Source,
}

/// The rejections kept in memory, newest last.
#[derive(Debug)]
pub struct Rejections {
    entries: Mutex<VecDeque<Rejection>>,
    capacity: usize,
}

impl Default for Rejections {
    fn default() -> Self {
        Self::new(DEFAULT_CAPACITY)
    }
}

impl Rejections {
    /// A log holding at most `capacity` entries. A capacity of 0 switches the
    /// record off: nothing is kept and `record` becomes a cheap no-op.
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: Mutex::new(VecDeque::with_capacity(capacity.min(DEFAULT_CAPACITY))),
            capacity,
        }
    }

    /// Whether anything is being kept at all.
    pub fn enabled(&self) -> bool {
        self.capacity > 0
    }

    /// Note that `value` was not written, dropping the oldest entry if the
    /// buffer is full.
    ///
    /// Takes no database lock and is called only from places that hold none,
    /// which is what keeps it outside the ordering rule in [`crate::db`].
    pub fn record(&self, namespace: &str, value: &str, reason: &str, source: Source) {
        if !self.enabled() {
            return;
        }

        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        while entries.len() >= self.capacity {
            entries.pop_front();
        }
        entries.push_back(Rejection {
            when: chrono::Utc::now().timestamp(),
            namespace: namespace.to_string(),
            value: value.to_string(),
            reason: reason.to_string(),
            source,
        });
    }

    /// The most recent rejections first, optionally only those under
    /// `namespace`, and at most `limit` of them.
    ///
    /// Newest first because the question this answers is almost always "what
    /// has just started failing?", and a feed that rejects steadily would
    /// otherwise bury the answer behind a thousand older copies of it.
    pub fn recent(&self, namespace: Option<&str>, limit: usize) -> Vec<Rejection> {
        let entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        entries
            .iter()
            .rev()
            .filter(|entry| match namespace {
                // A prefix match, so `feeds` finds `feeds/misp/ips` — the same
                // way an ACL grant scopes to a subtree.
                Some(wanted) => {
                    entry.namespace == wanted
                        || entry
                            .namespace
                            .strip_prefix(wanted)
                            .is_some_and(|rest| rest.starts_with('/'))
                }
                None => true,
            })
            .take(limit)
            .cloned()
            .collect()
    }

    /// The cap this log was built with.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// How many are held right now.
    pub fn len(&self) -> usize {
        self.entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }

    /// Forget everything, which is how an operator marks a feed as dealt with.
    pub fn clear(&self) {
        self.entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn log() -> Rejections {
        Rejections::new(3)
    }

    #[test]
    fn the_oldest_entry_goes_when_the_buffer_is_full() {
        let log = log();
        for value in ["a", "b", "c", "d"] {
            log.record("ns", value, "nope", Source::Ingest);
        }

        assert_eq!(log.len(), 3, "the cap was not honoured");
        let recent = log.recent(None, 10);
        // Newest first, and "a" has been pushed out.
        let values: Vec<&str> = recent.iter().map(|r| r.value.as_str()).collect();
        assert_eq!(values, ["d", "c", "b"]);
    }

    #[test]
    fn a_capacity_of_zero_keeps_nothing() {
        let log = Rejections::new(0);
        log.record("ns", "a", "nope", Source::Write);

        assert!(!log.enabled());
        assert_eq!(log.len(), 0);
        assert!(log.recent(None, 10).is_empty());
    }

    #[test]
    fn a_namespace_filter_matches_the_subtree_and_not_a_neighbour() {
        let log = Rejections::new(10);
        log.record("feeds/misp/ips", "a", "nope", Source::Ingest);
        log.record("feeds", "b", "nope", Source::Ingest);
        log.record("feeds-internal", "c", "nope", Source::Ingest);
        log.record("other", "d", "nope", Source::Ingest);

        let found = log.recent(Some("feeds"), 10);
        let values: Vec<&str> = found.iter().map(|r| r.value.as_str()).collect();

        // `feeds-internal` is a different namespace, not a child of `feeds`.
        assert_eq!(values, ["b", "a"], "prefix match caught a neighbour");
    }

    #[test]
    fn an_empty_value_is_recorded_as_itself() {
        let log = Rejections::new(10);
        log.record(
            "ns",
            "",
            "Refusing to write an empty value.",
            Source::BulkWrite,
        );

        let recent = log.recent(None, 10);
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].value, "");
        assert_eq!(recent[0].source, Source::BulkWrite);
    }

    #[test]
    fn clearing_empties_the_log() {
        let log = log();
        log.record("ns", "a", "nope", Source::Write);
        log.clear();
        assert_eq!(log.len(), 0);
    }
}
