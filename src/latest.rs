//! The values written most recently, and where.
//!
//! What `/_api/latest` reads: "what has arrived lately?", answered per key —
//! every entry names the namespace it was written to, and a caller is shown
//! only the entries in namespaces its key may read. Two keys asking the same
//! question get different answers, which is the point.
//!
//! **Not a namespace.** An internal `_latest` namespace would have been the
//! obvious shape, and it is the wrong one. A namespace is an unordered map of
//! value to counts, so "the last N" would be a scan and a sort; and read access
//! is granted by namespace path, so a key allowed to read `_latest` would read
//! every write in it, whatever namespace it went to. Filtering has to be by
//! the namespace each value was written to, so that is what is stored.
//!
//! **One entry per value and namespace.** Writing a value again moves it to
//! the front rather than adding a second copy, so a feed that sends the same
//! address all day does not push everything else out. Bounded by `capacity`:
//! once full, the entry written longest ago goes. A key that may read only a
//! quiet namespace can therefore be shown fewer than it asked for — the
//! namespace's values have aged out of what the server remembers.
//!
//! Recorded by [`crate::sighting_writer`] for every accepted write — `/w`,
//! `/wb`, the ZMQ ingest and the management interface. Not by a galaxy merge,
//! which is a copy rather than a write, and not on a router, which stores
//! nothing and so has nothing to report. Saved with snapshots, so a client
//! polling for what is new does not lose its place at a restart.

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, PoisonError};

use serde::{Deserialize, Serialize};

/// How many values are remembered when the configuration does not say.
pub const DEFAULT_CAPACITY: usize = 10_000;
/// The most one request can return, whatever it asks for.
pub const MAX_LIMIT: usize = 1000;
/// What a request without `limit=` gets.
pub const DEFAULT_LIMIT: usize = 100;

/// One value, the namespace it was written to, and when.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub namespace: String,
    pub value: String,
    /// Unix seconds when the write arrived — not the sighting's own
    /// timestamp, which a client may have set in the past. "Latest" is about
    /// arrival.
    pub written: i64,
}

#[derive(Debug, Default)]
struct Inner {
    /// Entries in the order they were last written, oldest first.
    order: BTreeMap<u64, Entry>,
    /// Where each namespace and value sits in `order`.
    position: HashMap<String, u64>,
    next: u64,
    /// Changed since the last save.
    dirty: bool,
}

/// `namespace` and `value` joined into one map key. A NUL cannot appear in a
/// namespace, so no two pairs can produce the same key.
fn key_of(namespace: &str, value: &str) -> String {
    let mut key = String::with_capacity(namespace.len() + value.len() + 1);
    key.push_str(namespace);
    key.push('\0');
    key.push_str(value);
    key
}

impl Inner {
    fn remove(&mut self, key: &str) {
        if let Some(at) = self.position.remove(key) {
            self.order.remove(&at);
        }
    }

    fn push(&mut self, entry: Entry, capacity: usize) {
        let key = key_of(&entry.namespace, &entry.value);
        self.remove(&key);
        let at = self.next;
        self.next += 1;
        self.order.insert(at, entry);
        self.position.insert(key, at);
        self.trim(capacity);
    }

    fn trim(&mut self, capacity: usize) {
        while self.order.len() > capacity {
            let Some((_, oldest)) = self.order.pop_first() else {
                break;
            };
            self.position
                .remove(&key_of(&oldest.namespace, &oldest.value));
        }
    }
}

#[derive(Debug)]
pub struct Latest {
    /// `latest_writes` in `[daemon]`. 0 switches the record off, and makes
    /// recording one relaxed load.
    capacity: AtomicUsize,
    inner: Mutex<Inner>,
}

impl Default for Latest {
    fn default() -> Self {
        Latest {
            capacity: AtomicUsize::new(DEFAULT_CAPACITY),
            inner: Mutex::default(),
        }
    }
}

/// Whether `namespace` is `prefix` or below it, on whole path segments: the
/// rule the ACL and recursive exports use, so `feeds` never takes in
/// `feeds-internal`.
fn under(namespace: &str, prefix: &str) -> bool {
    prefix.is_empty()
        || namespace == prefix
        || namespace
            .strip_prefix(prefix)
            .is_some_and(|rest| rest.starts_with('/'))
}

impl Latest {
    pub fn capacity(&self) -> usize {
        self.capacity.load(Ordering::Relaxed)
    }

    /// Change how much is remembered, dropping the oldest if it shrank.
    pub fn set_capacity(&self, capacity: usize) {
        self.capacity.store(capacity, Ordering::Relaxed);
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        let before = inner.order.len();
        inner.trim(capacity);
        if inner.order.len() != before {
            inner.dirty = true;
        }
    }

    /// Note that `value` was just written to `namespace`.
    pub fn record(&self, namespace: &str, value: &str) {
        self.record_at(namespace, value, chrono::Utc::now().timestamp());
    }

    fn record_at(&self, namespace: &str, value: &str, written: i64) {
        let capacity = self.capacity();
        if capacity == 0 || crate::db::is_internal(namespace) {
            return;
        }
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        inner.push(
            Entry {
                namespace: namespace.to_string(),
                value: value.to_string(),
                written,
            },
            capacity,
        );
        inner.dirty = true;
    }

    /// Forget everything written to `namespace`, which has been deleted.
    /// Exactly that namespace: deleting one does not delete those below it.
    pub fn forget_namespace(&self, namespace: &str) {
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        let gone: Vec<String> = inner
            .order
            .values()
            .filter(|entry| entry.namespace == namespace)
            .map(|entry| key_of(&entry.namespace, &entry.value))
            .collect();
        if gone.is_empty() {
            return;
        }
        for key in &gone {
            inner.remove(key);
        }
        inner.dirty = true;
    }

    /// The most recent first: at most `limit`, written at or after `since`,
    /// under `prefix`, and only in namespaces `visible` lets through.
    pub fn recent(
        &self,
        limit: usize,
        since: Option<i64>,
        prefix: &str,
        visible: impl Fn(&str) -> bool,
    ) -> Vec<Entry> {
        let prefix = prefix.trim_matches('/');
        let limit = limit.min(MAX_LIMIT);
        let inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);

        // The ACL is asked once per namespace rather than once per entry: a
        // busy namespace fills most of the record, and the answer is the same
        // every time.
        let mut allowed: HashMap<&str, bool> = HashMap::new();
        let mut found = Vec::new();
        for entry in inner.order.values().rev() {
            if found.len() >= limit {
                break;
            }
            // Arrival order is time order, so nothing older can follow.
            if since.is_some_and(|since| entry.written < since) {
                break;
            }
            if !under(&entry.namespace, prefix) {
                continue;
            }
            let ok = *allowed
                .entry(entry.namespace.as_str())
                .or_insert_with(|| visible(&entry.namespace));
            if ok {
                found.push(entry.clone());
            }
        }
        found
    }

    /// Everything, oldest first, for a save — if anything changed since the
    /// last one, or regardless when `force` is set.
    pub fn take_snapshot(&self, force: bool) -> Option<Vec<Entry>> {
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        if !inner.dirty && !force {
            return None;
        }
        inner.dirty = false;
        Some(inner.order.values().cloned().collect())
    }

    /// Put a failed save's changes back so the next one retries.
    pub fn mark_dirty(&self) {
        self.inner
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .dirty = true;
    }

    /// Restore what a previous run saved, oldest first. Anything recorded
    /// since startup stays newer than all of it.
    pub fn restore(&self, saved: Vec<Entry>) {
        let capacity = self.capacity();
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        let since_startup: Vec<Entry> = std::mem::take(&mut inner.order).into_values().collect();
        inner.position.clear();
        for entry in saved.into_iter().chain(since_startup) {
            inner.push(entry, capacity);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(entries: &[Entry]) -> Vec<String> {
        entries
            .iter()
            .map(|e| format!("{}:{}", e.namespace, e.value))
            .collect()
    }

    #[test]
    fn newest_first_and_a_rewrite_moves_to_the_front() {
        let latest = Latest::default();
        latest.record_at("a", "1", 10);
        latest.record_at("a", "2", 11);
        latest.record_at("b", "1", 12);
        latest.record_at("a", "1", 13);

        let found = latest.recent(10, None, "", |_| true);
        assert_eq!(names(&found), ["a:1", "b:1", "a:2"]);
        assert_eq!(found[0].written, 13);
    }

    #[test]
    fn the_same_value_in_two_namespaces_is_two_entries() {
        let latest = Latest::default();
        latest.record_at("a", "v", 1);
        latest.record_at("b", "v", 2);
        assert_eq!(latest.recent(10, None, "", |_| true).len(), 2);
    }

    #[test]
    fn capacity_drops_the_oldest() {
        let latest = Latest::default();
        latest.set_capacity(2);
        for (i, value) in ["1", "2", "3"].iter().enumerate() {
            latest.record_at("a", value, i as i64);
        }
        assert_eq!(
            names(&latest.recent(10, None, "", |_| true)),
            ["a:3", "a:2"]
        );

        latest.set_capacity(1);
        assert_eq!(names(&latest.recent(10, None, "", |_| true)), ["a:3"]);
    }

    #[test]
    fn nothing_is_kept_when_switched_off() {
        let latest = Latest::default();
        latest.set_capacity(0);
        latest.record_at("a", "1", 1);
        assert!(latest.recent(10, None, "", |_| true).is_empty());
    }

    #[test]
    fn what_a_key_sees_is_filtered_by_what_it_may_read() {
        let latest = Latest::default();
        latest.record_at("feeds/ips", "1", 1);
        latest.record_at("secret", "2", 2);
        latest.record_at("feeds/urls", "3", 3);

        let found = latest.recent(10, None, "", |ns| ns.starts_with("feeds"));
        assert_eq!(names(&found), ["feeds/urls:3", "feeds/ips:1"]);
    }

    #[test]
    fn limit_since_and_prefix_narrow_the_answer() {
        let latest = Latest::default();
        latest.record_at("feeds", "1", 10);
        latest.record_at("feeds-internal", "2", 20);
        latest.record_at("feeds/ips", "3", 30);
        latest.record_at("feeds/ips", "4", 40);

        assert_eq!(latest.recent(1, None, "", |_| true).len(), 1);
        assert_eq!(
            names(&latest.recent(10, Some(30), "", |_| true)),
            ["feeds/ips:4", "feeds/ips:3"]
        );
        // Whole segments: `feeds` is not a prefix of `feeds-internal`.
        assert_eq!(
            names(&latest.recent(10, None, "feeds", |_| true)),
            ["feeds/ips:4", "feeds/ips:3", "feeds:1"]
        );
        assert_eq!(
            latest.recent(MAX_LIMIT + 50, None, "", |_| true).len(),
            4,
            "an oversized limit is clamped, not refused"
        );
    }

    #[test]
    fn a_deleted_namespace_is_forgotten_and_its_children_are_not() {
        let latest = Latest::default();
        latest.record_at("a", "1", 1);
        latest.record_at("a/b", "2", 2);
        latest.forget_namespace("a");
        assert_eq!(names(&latest.recent(10, None, "", |_| true)), ["a/b:2"]);
    }

    #[test]
    fn internal_namespaces_are_not_recorded() {
        let latest = Latest::default();
        latest.record_at("_shadow/a", "1", 1);
        latest.record_at("_all", "1", 1);
        assert!(latest.recent(10, None, "", |_| true).is_empty());
    }

    #[test]
    fn a_restore_keeps_what_arrived_since_startup_newest() {
        let saved = Latest::default();
        saved.record_at("a", "old", 1);
        saved.record_at("a", "both", 2);
        let snapshot = saved.take_snapshot(false).unwrap();
        assert!(
            saved.take_snapshot(false).is_none(),
            "nothing changed since"
        );

        let restarted = Latest::default();
        restarted.record_at("a", "both", 50);
        restarted
            .restore(serde_json::from_str(&serde_json::to_string(&snapshot).unwrap()).unwrap());
        let found = restarted.recent(10, None, "", |_| true);
        assert_eq!(names(&found), ["a:both", "a:old"]);
        assert_eq!(found[0].written, 50);
    }
}
