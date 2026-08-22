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
    pub count: u64,
    pub tags: String,
    pub ttl: u64,
    /// Count per hourly bucket. The key is a Unix timestamp because
    /// `DateTime::timestamp()` returns an `i64`.
    pub stats: BTreeMap<i64, u64>,
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
            count: 0,
            tags: String::new(),
            ttl: 0,
            stats: BTreeMap::new(),
        }
    }

    pub fn count(&self) -> u64 {
        self.count
    }

    /// Record one sighting at `when`, keeping at most `stats_retention` hourly
    /// buckets (0 keeps all of them).
    ///
    /// The first sighting seeds both `first_seen` and `last_seen`; later ones
    /// only widen the window. We key "is this the first sighting?" off `count`
    /// rather than off a sentinel timestamp, so a legitimate sighting at the
    /// Unix epoch is handled correctly.
    pub fn increment(&mut self, when: DateTime<Utc>, stats_retention: usize) {
        if self.count == 0 {
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

        self.make_stats(when);
        self.trim_stats(stats_retention);
        self.count += 1;
    }

    /// Undo one sighting. Only used to keep the `_all` consensus tally honest
    /// when a value is evicted from a namespace.
    pub fn decrement(&mut self) -> u64 {
        self.count = self.count.saturating_sub(1);
        self.count
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

    /// Replace the whole set, which is the only way a wrong tag comes off.
    pub fn set_tags(&mut self, tags: &str) {
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

    fn make_stats(&mut self, when: DateTime<Utc>) {
        // `div_euclid` so that pre-epoch timestamps round down rather than
        // toward zero, keeping buckets uniformly one hour wide.
        let bucket = when.timestamp().div_euclid(STATS_BUCKET_SECS) * STATS_BUCKET_SECS;
        *self.stats.entry(bucket).or_insert(0) += 1;
    }

    /// Drop the oldest buckets so that statistics cannot grow without bound.
    /// `BTreeMap` is ordered by timestamp, so the oldest are simply the first.
    fn trim_stats(&mut self, keep: usize) {
        if keep == 0 || self.stats.len() <= keep {
            return;
        }
        let excess = self.stats.len() - keep;
        let oldest: Vec<i64> = self.stats.keys().take(excess).copied().collect();
        for bucket in oldest {
            self.stats.remove(&bucket);
        }
    }

    /// Build the wire representation. `consensus` is supplied by the caller
    /// because it lives in the `_all` namespace, not on the attribute itself.
    pub fn view(&self, consensus: u64, with_stats: bool) -> AttributeView {
        AttributeView {
            value: self.value.clone(),
            first_seen: self.first_seen.timestamp(),
            last_seen: self.last_seen.timestamp(),
            count: self.count,
            tags: self.tags.clone(),
            ttl: self.ttl,
            consensus,
            stats: with_stats.then(|| self.stats.clone()),
        }
    }
}

impl fmt::Debug for Attribute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Attribute")
            .field("value", &self.value)
            .field("first_seen", &self.first_seen)
            .field("last_seen", &self.last_seen)
            .field("count", &self.count)
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
        attribute.set_tags("tlp:red,,  tlp:red ,identity:Beta Cyber Intelligence Company");
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
            attr.increment(at(i * STATS_BUCKET_SECS), 0);
        }

        let serialized = serde_json::to_string(&attr.view(3, true)).unwrap();
        let deserialized: AttributeView = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized, attr.view(3, true));
    }

    #[test]
    fn view_omits_stats_unless_requested() {
        let mut attr = Attribute::new("test");
        attr.increment(at(1_600_000_000), 0);

        let without = serde_json::to_string(&attr.view(0, false)).unwrap();
        assert!(!without.contains("stats"), "{without}");

        let with = serde_json::to_string(&attr.view(0, true)).unwrap();
        assert!(with.contains("stats"), "{with}");
    }

    #[test]
    fn first_sighting_seeds_both_timestamps() {
        let mut attr = Attribute::new("v");
        attr.increment(at(1_000_000), 0);

        assert_eq!(attr.first_seen.timestamp(), 1_000_000);
        assert_eq!(attr.last_seen.timestamp(), 1_000_000);
        assert_eq!(attr.count(), 1);
    }

    #[test]
    fn out_of_order_sightings_widen_the_window() {
        let mut attr = Attribute::new("v");
        attr.increment(at(1_000_000), 0);
        attr.increment(at(500_000), 0); // older than first_seen
        attr.increment(at(2_000_000), 0); // newer than last_seen

        assert_eq!(attr.first_seen.timestamp(), 500_000);
        assert_eq!(attr.last_seen.timestamp(), 2_000_000);
        assert_eq!(attr.count(), 3);
    }

    #[test]
    fn sightings_in_the_same_hour_share_a_bucket() {
        let mut attr = Attribute::new("v");
        attr.increment(at(3600), 0);
        attr.increment(at(3600 + 59), 0);
        attr.increment(at(7200), 0);

        assert_eq!(attr.stats.get(&3600), Some(&2));
        assert_eq!(attr.stats.get(&7200), Some(&1));
    }

    #[test]
    fn stats_retention_drops_the_oldest_buckets() {
        let mut attr = Attribute::new("v");
        for hour in 0..10 {
            attr.increment(at(hour * STATS_BUCKET_SECS), 3);
        }

        let buckets: Vec<i64> = attr.stats.keys().copied().collect();
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
            attr.increment(at(hour * STATS_BUCKET_SECS), 0);
        }

        assert_eq!(attr.stats.len(), 10);
    }

    #[test]
    fn a_zero_ttl_never_expires() {
        let mut attr = Attribute::new("v");
        attr.increment(at(1000), 0);

        assert_eq!(attr.expires_at(), None);
        assert!(!attr.is_expired(at(FAR_FUTURE)));
    }

    #[test]
    fn a_ttl_is_measured_from_the_last_sighting() {
        let mut attr = Attribute::new("v");
        attr.increment(at(1000), 0);
        attr.set_ttl(60);

        assert_eq!(attr.expires_at(), Some(1060));
        assert!(!attr.is_expired(at(1060)), "still alive on the deadline");
        assert!(attr.is_expired(at(1061)));

        // Being seen again pushes the deadline out.
        attr.increment(at(2000), 0);
        assert!(!attr.is_expired(at(2060)));
        assert!(attr.is_expired(at(2061)));
    }

    #[test]
    fn an_enormous_ttl_saturates_instead_of_overflowing() {
        let mut attr = Attribute::new("v");
        attr.increment(at(1000), 0);
        attr.set_ttl(u64::MAX);

        assert_eq!(attr.expires_at(), Some(i64::MAX));
        assert!(!attr.is_expired(at(FAR_FUTURE)));
    }

    #[test]
    fn decrement_saturates_at_zero() {
        let mut attr = Attribute::new("v");
        attr.increment(at(1000), 0);

        assert_eq!(attr.decrement(), 0);
        assert_eq!(attr.decrement(), 0);
    }

    #[test]
    fn epoch_sighting_is_not_treated_as_unset() {
        let mut attr = Attribute::new("v");
        attr.increment(DateTime::UNIX_EPOCH, 0);
        attr.increment(at(3600), 0);

        assert_eq!(attr.first_seen, DateTime::UNIX_EPOCH);
        assert_eq!(attr.last_seen.timestamp(), 3600);
        assert_eq!(attr.count(), 2);
    }
}
