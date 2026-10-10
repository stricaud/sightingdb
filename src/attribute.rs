use std::collections::BTreeMap;
use std::fmt;

use chrono::serde::ts_seconds;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Statistics are bucketed per hour.
const STATS_BUCKET_SECS: i64 = 3600;

/// A value observed inside a namespace, with the bookkeeping we keep about it.
///
/// This is the *stored* representation. What we hand back over HTTP is
/// [`AttributeView`], which additionally carries the consensus (derived at read
/// time from the `_all` namespace) and optionally the hourly statistics.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attribute {
    pub value: String,
    #[serde(with = "ts_seconds")]
    pub first_seen: DateTime<Utc>,
    #[serde(with = "ts_seconds")]
    pub last_seen: DateTime<Utc>,
    /// Sightings contributed by each server, keyed by node id, reported as the
    /// sum.
    ///
    /// Per node rather than one total, because an increment is not idempotent:
    /// a sync that read a peer's total and replayed it would double the count,
    /// and double it again next time round. Each server only ever writes its
    /// own entry, so merging two copies is a union of disjoint contributions
    /// and applying the same merge twice changes nothing.
    ///
    /// A server that has never been in a galaxy has one entry, under
    /// [`crate::db::LOCAL_NODE`], and the sum is what it always was.
    #[serde(default)]
    pub counts: BTreeMap<String, u64>,
    pub tags: String,
    /// When the tag set was last *replaced* wholesale, in milliseconds since
    /// the Unix epoch. Zero means it never was, and every tag on it arrived
    /// by merging.
    ///
    /// Milliseconds rather than seconds because two edits a moment apart are
    /// the normal case when someone is fixing tags by hand, and at second
    /// granularity they tie — which falls back to the union and so quietly
    /// fails to remove anything. Measured, not assumed: two retags in the
    /// same second left the first one's tag in place.
    ///
    /// Here because tags otherwise merge as a union, and a union cannot
    /// express a removal: taking a wrong tag off one server would be undone
    /// the next time a peer that still had it synced. So a replacement
    /// carries the moment it happened, and the later replacement wins
    /// wherever two copies meet — a last-write-wins register beside the
    /// grow-only set, which is exactly the shape of the problem. A plain
    /// write never touches it, so ordinary tagging still accumulates.
    ///
    /// Ties fall back to the union. Two servers that replaced a set in the
    /// same second would otherwise converge on whichever copy moved last,
    /// which is not convergence at all.
    #[serde(default)]
    pub tags_at: i64,
    pub ttl: u64,
    /// Hourly buckets, per node, for the same reason as `counts`. The inner key
    /// is a Unix timestamp because `DateTime::timestamp()` returns an `i64`.
    ///
    /// Reported merged, so a reader sees one bucket per hour however many
    /// servers contributed to it.
    #[serde(default, rename = "node_stats")]
    pub stats: BTreeMap<String, BTreeMap<i64, u64>>,

    /// A total written by a build that kept one, folded into `counts` on load
    /// by [`Attribute::migrate`]. Read, never written.
    #[serde(default, rename = "count", skip_serializing)]
    legacy_count: u64,
    /// Buckets written by a build that did not keep them per node. As above.
    #[serde(default, rename = "stats", skip_serializing)]
    legacy_stats: BTreeMap<i64, u64>,
}

/// One value as a peer holds it, for merging into a local copy.
///
/// Every field merges by a rule that does not care about order or repetition,
/// so applying the same merge twice is the same as applying it once and two
/// peers exchanging copies converge. That is the whole point: a sync that has
/// to be applied exactly once is a sync that cannot be retried.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Merge {
    /// The peer's view of each server's contribution.
    pub counts: BTreeMap<String, u64>,
    /// The peer's view of each server's hourly buckets.
    #[serde(default)]
    pub stats: BTreeMap<String, BTreeMap<i64, u64>>,
    pub first_seen: i64,
    pub last_seen: i64,
    #[serde(default)]
    pub tags: String,
    /// When the peer last replaced its tag set. See [`Attribute::tags_at`].
    #[serde(default)]
    pub tags_at: i64,
    #[serde(default)]
    pub ttl: u64,
}

/// What a merge changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Merged {
    /// Whether anything about the local copy changed. A merge that already
    /// held everything offered is reported rather than hidden, because during
    /// catch-up it is how a caller knows it has converged.
    pub changed: bool,
    /// Entries for this server's own id that were ignored. A peer does not get
    /// to say what this server has seen.
    pub ignored_self: usize,
    /// The total after merging.
    pub count: u64,
}

/// The wire representation of an [`Attribute`].
///
/// `stats` is omitted entirely unless the caller asked for it, which is what
/// separates `/r` from `/rs`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttributeView {
    pub value: String,
    pub first_seen: i64,
    pub last_seen: i64,
    pub count: u64,
    pub tags: String,
    pub ttl: u64,
    pub consensus: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stats: Option<BTreeMap<i64, u64>>,
}

/// Tags are a comma-separated set: either a bare label (`malicious-activity`)
/// or `key:value` (`stix-type:ipv4-addr`).
///
/// Comma is the separator because the interesting values — an identity name, a
/// description — contain spaces, and a set that cannot hold them would push
/// that information somewhere else. A value therefore cannot contain a comma,
/// which is the one thing this asks of a caller.
pub fn split_tags(tags: &str) -> impl Iterator<Item = &str> {
    tags.split(',').map(str::trim).filter(|tag| !tag.is_empty())
}

/// The value of the first `key:value` tag with this key, if there is one.
pub fn tag_value<'a>(tags: &'a str, key: &'a str) -> Option<&'a str> {
    tag_values(tags, key).next()
}

/// Every value carried under one key. Keys repeat: an indicator can be both
/// `indicator-type:malicious-activity` and `indicator-type:anomalous-activity`.
pub fn tag_values<'a>(tags: &'a str, key: &'a str) -> impl Iterator<Item = &'a str> {
    split_tags(tags).filter_map(move |tag| {
        let (name, value) = tag.split_once(':')?;
        // Trimmed because `key: value` is what a person types.
        (name.trim().eq_ignore_ascii_case(key) && !value.trim().is_empty()).then(|| value.trim())
    })
}

impl Attribute {
    pub fn new(value: &str) -> Attribute {
        Attribute {
            value: String::from(value),
            first_seen: DateTime::UNIX_EPOCH,
            last_seen: DateTime::UNIX_EPOCH,
            counts: BTreeMap::new(),
            tags: String::new(),
            tags_at: 0,
            ttl: 0,
            stats: BTreeMap::new(),
            legacy_count: 0,
            legacy_stats: BTreeMap::new(),
        }
    }

    /// Every server's sightings added together, which is the number a client
    /// has always been given.
    pub fn count(&self) -> u64 {
        self.counts.values().copied().sum()
    }

    /// Fold a total written by an older build into `node`'s entry.
    ///
    /// Called once per attribute when a snapshot is loaded. A build before this
    /// one kept one total and one set of buckets with nobody's name on them;
    /// the server reading them is the only server that can have written them,
    /// so they become its own contribution.
    pub fn migrate(&mut self, node: &str) {
        if self.legacy_count > 0 {
            *self.counts.entry(node.to_string()).or_insert(0) += self.legacy_count;
            self.legacy_count = 0;
        }
        if !self.legacy_stats.is_empty() {
            let buckets = self.stats.entry(node.to_string()).or_default();
            for (bucket, hits) in std::mem::take(&mut self.legacy_stats) {
                *buckets.entry(bucket).or_insert(0) += hits;
            }
        }
    }

    /// Record one sighting at `when`, keeping at most `stats_retention` hourly
    /// buckets (0 keeps all of them).
    ///
    /// The first sighting seeds both `first_seen` and `last_seen`; later ones
    /// only widen the window. We key "is this the first sighting?" off the
    /// count rather than off a sentinel timestamp, so a legitimate sighting at
    /// the Unix epoch is handled correctly.
    ///
    /// `node` is this server's id: the sighting is counted as its contribution,
    /// never as a peer's.
    pub fn increment(&mut self, node: &str, when: DateTime<Utc>, stats_retention: usize) {
        if self.count() == 0 {
            self.first_seen = when;
            self.last_seen = when;
        } else {
            if when < self.first_seen {
                self.first_seen = when;
            }
            if when > self.last_seen {
                self.last_seen = when;
            }
        }

        self.make_stats(node, when);
        self.trim_stats(node, stats_retention);
        *self.counts.entry(node.to_string()).or_insert(0) += 1;
    }

    /// Undo one sighting. Only used to keep the `_all` consensus tally honest
    /// when a value is evicted from a namespace.
    ///
    /// Takes it off `node`'s own entry: a server gives back what it put in, and
    /// never spends a peer's contribution. Returns the total that remains, so
    /// the caller can see when the value is gone from everywhere.
    pub fn decrement(&mut self, node: &str) -> u64 {
        if let Some(mine) = self.counts.get_mut(node) {
            *mine = mine.saturating_sub(1);
            if *mine == 0 {
                // Dropped rather than left at zero, so a server that has given
                // everything back stops appearing as a contributor.
                self.counts.remove(node);
            }
        }
        self.count()
    }

    pub fn set_ttl(&mut self, ttl: u64) {
        self.ttl = ttl;
    }

    /// Merge `tags` into the set already held, dropping repeats.
    ///
    /// Merging rather than replacing is what makes tags useful across sources:
    /// one feed contributes `stix-type:ipv4-addr`, another `tlp:amber`, and the
    /// value ends up knowing both. Replacing is a deliberate act, and goes
    /// through [`Attribute::set_tags`].
    pub fn add_tags(&mut self, tags: &str) {
        let mut merged: Vec<&str> = split_tags(&self.tags).collect();
        let mut changed = false;
        for tag in split_tags(tags) {
            if !merged.contains(&tag) {
                merged.push(tag);
                changed = true;
            }
        }
        if changed {
            self.tags = merged.join(",");
        }
    }

    /// This value as a peer should be offered it.
    ///
    /// Exactly the shape [`Attribute::merge`] takes, so a sync reads it from
    /// one server and posts it to another unchanged. The per-node counts are
    /// the point: offering a *total* would make the receiver attribute every
    /// server's sightings to the sender, and two servers exchanging totals
    /// inflate each other without bound.
    pub fn as_merge(&self) -> Merge {
        Merge {
            counts: self.counts.clone(),
            stats: self.stats.clone(),
            first_seen: self.first_seen.timestamp(),
            last_seen: self.last_seen.timestamp(),
            tags: self.tags.clone(),
            tags_at: self.tags_at,
            ttl: self.ttl,
        }
    }

    /// Fold a peer's copy of this value into ours.
    ///
    /// The rules, and why each one cannot care about order:
    ///
    ///  * **counts** — the greater of the two, per server. A server's own
    ///    count only ever rises, so taking the larger converges whichever
    ///    copy arrives first, and re-applying one changes nothing. Setting it
    ///    outright would let a stale copy undo a newer one.
    ///  * **stats** — the same, per bucket.
    ///  * **first_seen** — the earlier. **last_seen** — the later.
    ///  * **tags** — the union, which is what [`Attribute::add_tags`] already
    ///    does, unless one side replaced its set more recently: then that
    ///    replacement is taken whole, empty included. A union cannot express a
    ///    removal, and `tags_at` says which replacement is later. Equal
    ///    timestamps fall back to the union, so the rule stays
    ///    order-independent.
    ///  * **ttl** — the shortest of the non-zero ones, with zero meaning never.
    ///    Order-independent, and it errs towards expiring: a value is kept only
    ///    as long as the most cautious server says.
    ///
    /// **An entry under `mine` is ignored.** A peer does not get to tell this
    /// server what it has seen; that entry is the one thing here this server is
    /// the authority on, and accepting it would let a stale copy roll local
    /// writes backwards.
    pub fn merge(&mut self, incoming: &Merge, mine: &str) -> Merged {
        let mut changed = false;
        let mut ignored_self = 0;

        // Captured before anything is merged. Once a count has landed the
        // value no longer looks unseen, and the window below would then take
        // the earlier of a real time and the epoch.
        let unseen = self.count() == 0 && self.first_seen == DateTime::UNIX_EPOCH;

        for (node, count) in &incoming.counts {
            if node == mine {
                ignored_self += 1;
                continue;
            }
            let entry = self.counts.entry(node.clone()).or_insert(0);
            if *count > *entry {
                *entry = *count;
                changed = true;
            }
        }

        for (node, buckets) in &incoming.stats {
            if node == mine {
                continue;
            }
            let ours = self.stats.entry(node.clone()).or_default();
            for (bucket, hits) in buckets {
                let entry = ours.entry(*bucket).or_insert(0);
                if *hits > *entry {
                    *entry = *hits;
                    changed = true;
                }
            }
        }

        // A value we had not seen at all starts at the epoch, so seed the
        // window rather than taking the earlier of a real time and 1970.
        if let Some(theirs) = DateTime::from_timestamp(incoming.first_seen, 0)
            && (unseen || theirs < self.first_seen)
        {
            if theirs != self.first_seen {
                changed = true;
            }
            self.first_seen = theirs;
        }
        if let Some(theirs) = DateTime::from_timestamp(incoming.last_seen, 0)
            && (unseen || theirs > self.last_seen)
        {
            if theirs != self.last_seen {
                changed = true;
            }
            self.last_seen = theirs;
        }

        // Tags: a union, except where one side has been replaced more
        // recently, in which case that replacement is the whole answer. See
        // `tags_at` for why a union alone cannot be right.
        let before = self.tags.clone();
        if incoming.tags_at > self.tags_at {
            // Taken verbatim, including an empty set: that is what removing
            // the last tag looks like, and merging it as a union would be
            // exactly the bug this exists to fix.
            self.tags = incoming.tags.clone();
            self.tags_at = incoming.tags_at;
        } else if incoming.tags_at < self.tags_at {
            // Ours is the newer replacement, so theirs is history. Not even
            // unioned: the tags they still carry may be the ones we removed.
        } else if !incoming.tags.is_empty() {
            self.add_tags(&incoming.tags);
        }
        if self.tags != before {
            changed = true;
        }

        let merged_ttl = match (self.ttl, incoming.ttl) {
            (0, theirs) => theirs,
            (ours, 0) => ours,
            (ours, theirs) => ours.min(theirs),
        };
        if merged_ttl != self.ttl {
            self.ttl = merged_ttl;
            changed = true;
        }

        Merged {
            changed,
            ignored_self,
            count: self.count(),
        }
    }

    /// Replace the whole set, which is the only way a wrong tag comes off.
    ///
    /// `at` is when the replacement happened, in epoch milliseconds, which
    /// travels with it so that peers still holding the old set do not put it
    /// back. See `tags_at`.
    pub fn set_tags(&mut self, tags: &str, at: i64) {
        let cleaned: Vec<&str> = {
            let mut seen: Vec<&str> = Vec::new();
            for tag in split_tags(tags) {
                if !seen.contains(&tag) {
                    seen.push(tag);
                }
            }
            seen
        };
        self.tags = cleaned.join(",");
        // Never goes backwards: two replacements in the same second must not
        // let the earlier one win somewhere else.
        self.tags_at = self.tags_at.max(at);
    }

    /// When this attribute stops being visible, or `None` if it never does.
    pub fn expires_at(&self) -> Option<i64> {
        (self.ttl > 0).then(|| {
            self.last_seen
                .timestamp()
                .saturating_add(i64::try_from(self.ttl).unwrap_or(i64::MAX))
        })
    }

    /// A TTL is measured from the *last* sighting, so an attribute that keeps
    /// being seen keeps living.
    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        self.expires_at()
            .is_some_and(|deadline| now.timestamp() > deadline)
    }

    fn make_stats(&mut self, node: &str, when: DateTime<Utc>) {
        // `div_euclid` so that pre-epoch timestamps round down rather than
        // toward zero, keeping buckets uniformly one hour wide.
        let bucket = when.timestamp().div_euclid(STATS_BUCKET_SECS) * STATS_BUCKET_SECS;
        *self
            .stats
            .entry(node.to_string())
            .or_default()
            .entry(bucket)
            .or_insert(0) += 1;
    }

    /// Drop the oldest buckets so that statistics cannot grow without bound.
    /// `BTreeMap` is ordered by timestamp, so the oldest are simply the first.
    ///
    /// Trimmed within this server's own buckets. Retention is "how far back
    /// this server remembers", and spending it on a peer's history would make
    /// one server's retention depend on how many others there are.
    fn trim_stats(&mut self, node: &str, keep: usize) {
        let Some(buckets) = self.stats.get_mut(node) else {
            return;
        };
        if keep == 0 || buckets.len() <= keep {
            return;
        }
        let excess = buckets.len() - keep;
        let oldest: Vec<i64> = buckets.keys().take(excess).copied().collect();
        for bucket in oldest {
            buckets.remove(&bucket);
        }
    }

    /// Every server's buckets added together, so a reader sees one entry per
    /// hour however many contributed to it.
    fn merged_stats(&self) -> BTreeMap<i64, u64> {
        let mut merged = BTreeMap::new();
        for buckets in self.stats.values() {
            for (bucket, hits) in buckets {
                *merged.entry(*bucket).or_insert(0) += hits;
            }
        }
        merged
    }

    /// Build the wire representation. `consensus` is supplied by the caller
    /// because it lives in the `_all` namespace, not on the attribute itself.
    pub fn view(&self, consensus: u64, with_stats: bool) -> AttributeView {
        AttributeView {
            value: self.value.clone(),
            first_seen: self.first_seen.timestamp(),
            last_seen: self.last_seen.timestamp(),
            count: self.count(),
            tags: self.tags.clone(),
            ttl: self.ttl,
            consensus,
            stats: with_stats.then(|| self.merged_stats()),
        }
    }
}

impl fmt::Debug for Attribute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Attribute")
            .field("value", &self.value)
            .field("first_seen", &self.first_seen)
            .field("last_seen", &self.last_seen)
            .field("count", &self.count())
            .field("tags", &self.tags)
            .field("ttl", &self.ttl)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(secs, 0).expect("timestamp in range")
    }

    #[test]
    fn tags_are_a_set_that_merges_rather_than_replaces() {
        let mut attribute = Attribute::new("1.2.3.4");
        assert_eq!(attribute.tags, "");

        attribute.add_tags("stix-type:ipv4-addr, tlp:amber");
        // Another source knows one of the same things and one new one.
        attribute.add_tags("tlp:amber,confidence:80");

        assert_eq!(
            attribute.tags,
            "stix-type:ipv4-addr,tlp:amber,confidence:80"
        );

        // Replacing is the only way something comes off again.
        attribute.set_tags(
            "tlp:red,,  tlp:red ,identity:Beta Cyber Intelligence Company",
            0,
        );
        assert_eq!(
            attribute.tags,
            "tlp:red,identity:Beta Cyber Intelligence Company"
        );
    }

    #[test]
    fn a_tag_key_can_be_looked_up_and_can_repeat() {
        let tags = "stix-type:ipv4-addr, indicator-type:malicious-activity, \
                    indicator-type:anomalous-activity, bare-label, empty:";

        assert_eq!(tag_value(tags, "stix-type"), Some("ipv4-addr"));
        assert_eq!(
            tag_values(tags, "indicator-type").collect::<Vec<_>>(),
            ["malicious-activity", "anomalous-activity"]
        );
        // A label with no value is not a key, and a key with no value is not
        // an answer.
        assert_eq!(tag_value(tags, "bare-label"), None);
        assert_eq!(tag_value(tags, "empty"), None);
        assert_eq!(tag_value(tags, "absent"), None);

        // A value may hold anything but a comma — colons included, which is
        // what a URL or a timestamp needs.
        let tags = "name:Seen: on the proxy, valid-until:2021-09-13T12:26:40Z";
        assert_eq!(tag_value(tags, "name"), Some("Seen: on the proxy"));
        assert_eq!(tag_value(tags, "valid-until"), Some("2021-09-13T12:26:40Z"));
    }

    /// The last second of year 9999 — far future, but still representable.
    const FAR_FUTURE: i64 = 253_402_300_799;

    #[test]
    fn view_round_trips_through_json() {
        let mut attr = Attribute::new("test");
        for i in 0..5 {
            attr.increment(crate::db::LOCAL_NODE, at(i * STATS_BUCKET_SECS), 0);
        }

        let serialized = serde_json::to_string(&attr.view(3, true)).unwrap();
        let deserialized: AttributeView = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized, attr.view(3, true));
    }

    #[test]
    fn view_omits_stats_unless_requested() {
        let mut attr = Attribute::new("test");
        attr.increment(crate::db::LOCAL_NODE, at(1_600_000_000), 0);

        let without = serde_json::to_string(&attr.view(0, false)).unwrap();
        assert!(!without.contains("stats"), "{without}");

        let with = serde_json::to_string(&attr.view(0, true)).unwrap();
        assert!(with.contains("stats"), "{with}");
    }

    #[test]
    fn first_sighting_seeds_both_timestamps() {
        let mut attr = Attribute::new("v");
        attr.increment(crate::db::LOCAL_NODE, at(1_000_000), 0);

        assert_eq!(attr.first_seen.timestamp(), 1_000_000);
        assert_eq!(attr.last_seen.timestamp(), 1_000_000);
        assert_eq!(attr.count(), 1);
    }

    #[test]
    fn out_of_order_sightings_widen_the_window() {
        let mut attr = Attribute::new("v");
        attr.increment(crate::db::LOCAL_NODE, at(1_000_000), 0);
        attr.increment(crate::db::LOCAL_NODE, at(500_000), 0); // older than first_seen
        attr.increment(crate::db::LOCAL_NODE, at(2_000_000), 0); // newer than last_seen

        assert_eq!(attr.first_seen.timestamp(), 500_000);
        assert_eq!(attr.last_seen.timestamp(), 2_000_000);
        assert_eq!(attr.count(), 3);
    }

    fn merge_of(counts: &[(&str, u64)], first: i64, last: i64, tags: &str, ttl: u64) -> Merge {
        Merge {
            counts: counts.iter().map(|(n, c)| ((*n).to_string(), *c)).collect(),
            stats: BTreeMap::new(),
            first_seen: first,
            last_seen: last,
            tags: tags.to_string(),
            // Unset, so these merges exercise the union rule. The
            // last-write-wins path has its own tests below.
            tags_at: 0,
            ttl,
        }
    }

    /// The bug this exists to fix: a tag removed on one server came back the
    /// next time a peer that still had it synced, because tags merge as a
    /// union and a union cannot express a removal.
    #[test]
    fn a_removed_tag_is_not_resurrected_by_a_peer_that_still_has_it() {
        let mut mine = Attribute::new("1.2.3.4");
        mine.add_tags("tlp:green,wrong-tag");

        // The peer's copy, from before the removal.
        let theirs = mine.as_merge();

        // The wrong tag comes off here, at a known moment.
        mine.set_tags("tlp:green", 1_000);
        assert_eq!(mine.tags, "tlp:green");

        // The peer syncs its older copy in.
        mine.merge(&theirs, "me");
        assert_eq!(
            mine.tags, "tlp:green",
            "the removed tag was put back by a peer that still had it"
        );
    }

    /// The other direction: a replacement made on a peer reaches us, even
    /// though a union of the two sets would have kept what it dropped.
    #[test]
    fn a_peers_newer_replacement_wins_here_too() {
        let mut mine = Attribute::new("1.2.3.4");
        mine.add_tags("tlp:green,wrong-tag");

        let mut theirs = Attribute::new("1.2.3.4");
        theirs.add_tags("tlp:green,wrong-tag");
        theirs.set_tags("tlp:green", 2_000);

        mine.merge(&theirs.as_merge(), "me");
        assert_eq!(mine.tags, "tlp:green");
        assert_eq!(
            mine.tags_at, 2_000,
            "the timestamp has to travel, or the next merge undoes this one"
        );
    }

    /// Removing every tag is a replacement with an empty set, which must not
    /// be mistaken for "nothing to say".
    #[test]
    fn clearing_every_tag_propagates() {
        let mut mine = Attribute::new("1.2.3.4");
        mine.add_tags("tlp:green");

        let mut theirs = Attribute::new("1.2.3.4");
        theirs.add_tags("tlp:green");
        theirs.set_tags("", 2_000);

        mine.merge(&theirs.as_merge(), "me");
        assert_eq!(mine.tags, "", "an emptied set was treated as no change");
    }

    /// A stale replacement does not undo a newer one, whichever order they
    /// arrive in.
    #[test]
    fn the_later_replacement_wins_in_either_order() {
        let mut older = Attribute::new("v");
        older.set_tags("old", 1_000);
        let mut newer = Attribute::new("v");
        newer.set_tags("new", 2_000);

        let mut a = older.clone();
        a.merge(&newer.as_merge(), "me");
        let mut b = newer.clone();
        b.merge(&older.as_merge(), "me");

        assert_eq!(a.tags, "new");
        assert_eq!(b.tags, "new", "the older replacement won by arriving later");
        assert_eq!(a.tags, b.tags, "the two did not converge");
    }

    /// An ordinary write still accumulates tags from several sources, which is
    /// what makes them useful across feeds. Only a *replacement* is a
    /// last-write-wins event.
    #[test]
    fn ordinary_tagging_still_merges_as_a_union() {
        let mut mine = Attribute::new("v");
        mine.add_tags("from-feed-a");

        let mut theirs = Attribute::new("v");
        theirs.add_tags("from-feed-b");

        mine.merge(&theirs.as_merge(), "me");
        assert!(mine.tags.contains("from-feed-a"));
        assert!(mine.tags.contains("from-feed-b"));
    }

    /// Two replacements in the same second fall back to the union, because
    /// preferring either would depend on which copy moved last.
    #[test]
    fn replacements_in_the_same_second_fall_back_to_the_union() {
        let mut a = Attribute::new("v");
        a.set_tags("one", 1_000);
        let mut b = Attribute::new("v");
        b.set_tags("two", 1_000);

        let mut left = a.clone();
        left.merge(&b.as_merge(), "me");
        let mut right = b.clone();
        right.merge(&a.as_merge(), "me");

        assert_eq!(left.tags, "one,two");
        assert_eq!(right.tags, "two,one");
        // Order differs, the set does not -- which is what convergence means
        // for a set rendered as a string.
        let set = |tags: &str| {
            let mut parts: Vec<&str> = split_tags(tags).collect();
            parts.sort_unstable();
            parts.join(",")
        };
        assert_eq!(set(&left.tags), set(&right.tags));
    }

    /// Merging the same replacement twice changes nothing the second time,
    /// which is what lets a sync be retried.
    #[test]
    fn a_replacement_merges_idempotently() {
        let mut mine = Attribute::new("v");
        mine.add_tags("old");

        let mut theirs = Attribute::new("v");
        theirs.set_tags("new", 2_000);

        let first = mine.merge(&theirs.as_merge(), "me");
        let second = mine.merge(&theirs.as_merge(), "me");
        assert!(first.changed);
        assert!(
            !second.changed,
            "the second merge claimed to change something"
        );
        assert_eq!(mine.tags, "new");
    }

    /// Applying the same merge twice must be the same as applying it once.
    /// Without this a sync cannot be retried, and a sync that cannot be
    /// retried is no use.
    #[test]
    fn merging_is_idempotent() {
        let mut attr = Attribute::new("1.2.3.4");
        attr.increment("node-a", at(1_600_000_000), 0);

        let incoming = merge_of(
            &[("node-b", 5)],
            1_500_000_000,
            1_700_000_000,
            "tlp:amber",
            3600,
        );

        let first = attr.merge(&incoming, "node-a");
        assert!(first.changed);
        assert_eq!(first.count, 6);
        let after_once = attr.clone();

        let again = attr.merge(&incoming, "node-a");
        assert!(!again.changed, "a repeat merge reported a change");
        assert_eq!(again.count, 6);
        assert_eq!(attr, after_once, "a repeat merge altered the value");
    }

    /// Two peers' copies must converge to the same thing whichever arrives
    /// first.
    #[test]
    fn merging_is_order_independent() {
        let b = merge_of(
            &[("node-b", 5)],
            1_500_000_000,
            1_650_000_000,
            "tlp:amber",
            7200,
        );
        let c = merge_of(
            &[("node-c", 2)],
            1_550_000_000,
            1_700_000_000,
            "confidence:80",
            3600,
        );

        let mut one = Attribute::new("1.2.3.4");
        one.increment("node-a", at(1_600_000_000), 0);
        one.merge(&b, "node-a");
        one.merge(&c, "node-a");

        let mut other = Attribute::new("1.2.3.4");
        other.increment("node-a", at(1_600_000_000), 0);
        other.merge(&c, "node-a");
        other.merge(&b, "node-a");

        assert_eq!(one.count(), 8);
        assert_eq!(one.counts, other.counts);
        assert_eq!(one.first_seen, other.first_seen);
        assert_eq!(one.last_seen, other.last_seen);
        assert_eq!(one.ttl, other.ttl, "ttl merge depended on order");
        // Tags are a set, so compare as one rather than by string order.
        let mut a: Vec<&str> = split_tags(&one.tags).collect();
        let mut d: Vec<&str> = split_tags(&other.tags).collect();
        a.sort_unstable();
        d.sort_unstable();
        assert_eq!(a, d);
    }

    /// A stale copy must not roll a newer one backwards. Taking the greater
    /// per server is what prevents it; setting outright would not.
    #[test]
    fn a_stale_merge_cannot_lower_a_count() {
        let mut attr = Attribute::new("1.2.3.4");
        attr.merge(
            &merge_of(&[("node-b", 9)], 1_600_000_000, 1_600_000_000, "", 0),
            "node-a",
        );
        assert_eq!(attr.count(), 9);

        attr.merge(
            &merge_of(&[("node-b", 4)], 1_600_000_000, 1_600_000_000, "", 0),
            "node-a",
        );
        assert_eq!(attr.count(), 9, "a stale merge lowered the count");
    }

    /// A peer does not get to say what this server has seen.
    #[test]
    fn a_merge_cannot_rewrite_this_servers_own_entry() {
        let mut attr = Attribute::new("1.2.3.4");
        for _ in 0..3 {
            attr.increment("node-a", at(1_600_000_000), 0);
        }

        // A peer offers a wildly different figure for us, and one for itself.
        let outcome = attr.merge(
            &merge_of(
                &[("node-a", 999), ("node-b", 2)],
                1_600_000_000,
                1_600_000_000,
                "",
                0,
            ),
            "node-a",
        );

        assert_eq!(outcome.ignored_self, 1);
        assert_eq!(
            attr.counts.get("node-a").copied(),
            Some(3),
            "our own count was rewritten"
        );
        assert_eq!(attr.counts.get("node-b").copied(), Some(2));
        assert_eq!(attr.count(), 5);
    }

    /// Merging a value this server has never seen seeds the window rather than
    /// taking the earlier of a real time and the epoch.
    #[test]
    fn merging_into_an_unseen_value_seeds_the_window() {
        let mut attr = Attribute::new("1.2.3.4");
        attr.merge(
            &merge_of(&[("node-b", 2)], 1_600_000_000, 1_600_003_600, "", 0),
            "node-a",
        );

        assert_eq!(
            attr.first_seen.timestamp(),
            1_600_000_000,
            "first_seen stayed at the epoch"
        );
        assert_eq!(attr.last_seen.timestamp(), 1_600_003_600);
        assert_eq!(attr.count(), 2);
    }

    /// Zero means never, so it loses to any real expiry: a value is kept only
    /// as long as the most cautious server says.
    #[test]
    fn ttl_merges_to_the_shortest_real_expiry() {
        let cases = [
            (0u64, 0u64, 0u64),
            (0, 3600, 3600),
            (3600, 0, 3600),
            (7200, 3600, 3600),
        ];
        for (ours, theirs, expected) in cases {
            let mut attr = Attribute::new("v");
            attr.set_ttl(ours);
            attr.merge(
                &merge_of(&[("node-b", 1)], 1_600_000_000, 1_600_000_000, "", theirs),
                "node-a",
            );
            assert_eq!(attr.ttl, expected, "ours={ours} theirs={theirs}");
        }
    }

    /// Hourly buckets merge the same way, and the view shows them merged.
    #[test]
    fn merging_stats_takes_the_greater_bucket() {
        let mut attr = Attribute::new("v");
        attr.increment("node-a", at(3600), 0);

        let mut incoming = merge_of(&[("node-b", 4)], 3600, 7200, "", 0);
        incoming.stats.insert(
            "node-b".to_string(),
            [(3600_i64, 3_u64), (7200, 1)].into_iter().collect(),
        );
        attr.merge(&incoming, "node-a");

        let stats = attr.view(0, true).stats.unwrap();
        // 1 of ours plus 3 of theirs in the first hour, 1 of theirs in the next.
        assert_eq!(stats.get(&3600), Some(&4));
        assert_eq!(stats.get(&7200), Some(&1));

        // And again changes nothing.
        attr.merge(&incoming, "node-a");
        let stats = attr.view(0, true).stats.unwrap();
        assert_eq!(stats.get(&3600), Some(&4));
    }

    #[test]
    fn sightings_in_the_same_hour_share_a_bucket() {
        let mut attr = Attribute::new("v");
        attr.increment(crate::db::LOCAL_NODE, at(3600), 0);
        attr.increment(crate::db::LOCAL_NODE, at(3600 + 59), 0);
        attr.increment(crate::db::LOCAL_NODE, at(7200), 0);

        // Asserted through the view, which is the merged shape a reader gets.
        let stats = attr.view(0, true).stats.unwrap();
        assert_eq!(stats.get(&3600), Some(&2));
        assert_eq!(stats.get(&7200), Some(&1));
    }

    #[test]
    fn stats_retention_drops_the_oldest_buckets() {
        let mut attr = Attribute::new("v");
        for hour in 0..10 {
            attr.increment(crate::db::LOCAL_NODE, at(hour * STATS_BUCKET_SECS), 3);
        }

        let buckets: Vec<i64> = attr.view(0, true).stats.unwrap().into_keys().collect();
        assert_eq!(
            buckets,
            [
                7 * STATS_BUCKET_SECS,
                8 * STATS_BUCKET_SECS,
                9 * STATS_BUCKET_SECS
            ]
        );
        // Trimming statistics must not touch the count or the seen window.
        assert_eq!(attr.count(), 10);
        assert_eq!(attr.first_seen.timestamp(), 0);
    }

    #[test]
    fn zero_retention_keeps_every_bucket() {
        let mut attr = Attribute::new("v");
        for hour in 0..10 {
            attr.increment(crate::db::LOCAL_NODE, at(hour * STATS_BUCKET_SECS), 0);
        }

        assert_eq!(attr.view(0, true).stats.unwrap().len(), 10);
    }

    #[test]
    fn a_zero_ttl_never_expires() {
        let mut attr = Attribute::new("v");
        attr.increment(crate::db::LOCAL_NODE, at(1000), 0);

        assert_eq!(attr.expires_at(), None);
        assert!(!attr.is_expired(at(FAR_FUTURE)));
    }

    #[test]
    fn a_ttl_is_measured_from_the_last_sighting() {
        let mut attr = Attribute::new("v");
        attr.increment(crate::db::LOCAL_NODE, at(1000), 0);
        attr.set_ttl(60);

        assert_eq!(attr.expires_at(), Some(1060));
        assert!(!attr.is_expired(at(1060)), "still alive on the deadline");
        assert!(attr.is_expired(at(1061)));

        // Being seen again pushes the deadline out.
        attr.increment(crate::db::LOCAL_NODE, at(2000), 0);
        assert!(!attr.is_expired(at(2060)));
        assert!(attr.is_expired(at(2061)));
    }

    #[test]
    fn an_enormous_ttl_saturates_instead_of_overflowing() {
        let mut attr = Attribute::new("v");
        attr.increment(crate::db::LOCAL_NODE, at(1000), 0);
        attr.set_ttl(u64::MAX);

        assert_eq!(attr.expires_at(), Some(i64::MAX));
        assert!(!attr.is_expired(at(FAR_FUTURE)));
    }

    #[test]
    fn decrement_saturates_at_zero() {
        let mut attr = Attribute::new("v");
        attr.increment(crate::db::LOCAL_NODE, at(1000), 0);

        assert_eq!(attr.decrement(crate::db::LOCAL_NODE), 0);
        assert_eq!(attr.decrement(crate::db::LOCAL_NODE), 0);
    }

    #[test]
    fn epoch_sighting_is_not_treated_as_unset() {
        let mut attr = Attribute::new("v");
        attr.increment(crate::db::LOCAL_NODE, DateTime::UNIX_EPOCH, 0);
        attr.increment(crate::db::LOCAL_NODE, at(3600), 0);

        assert_eq!(attr.first_seen, DateTime::UNIX_EPOCH);
        assert_eq!(attr.last_seen.timestamp(), 3600);
        assert_eq!(attr.count(), 2);
    }
}
