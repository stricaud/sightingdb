//! How busy each top-level namespace has been.
//!
//! Every read and every accepted write is counted against the namespace's
//! first path segment — `feeds/misp/ips` counts towards `feeds` — in hourly
//! and daily buckets. That is what the management interface draws as a strip
//! per namespace, the way a status page draws uptime.
//!
//! Two resolutions rather than one because the questions differ: "what
//! happened this afternoon?" wants hours, "is this feed still being used?"
//! wants a year, and a year of hours per namespace is more than either needs.
//!
//! Counted at the reader and the writer rather than inside the database, so
//! what is counted is what a client asked for: the shadow sighting a read
//! leaves behind is not a second, write-shaped event, and a galaxy merge is
//! not a client writing anything.
//!
//! Internal namespaces (`_all`, `_shadow/*`, `_config/*`) are not counted:
//! they are the database talking to itself.

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, PoisonError};

use chrono::Utc;
use serde::{Deserialize, Serialize};

pub const HOUR: i64 = 3600;
pub const DAY: i64 = 86_400;
/// A month of hours: enough to look back at any day in detail.
pub const HOURLY_BUCKETS: i64 = 31 * 24;
/// A little over a year of days, so the same week last year is still there.
pub const DAILY_BUCKETS: i64 = 400;

/// Reads and writes in one bucket.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counts {
    #[serde(rename = "r", default)]
    pub reads: u64,
    #[serde(rename = "w", default)]
    pub writes: u64,
}

impl Counts {
    fn add(&mut self, other: Counts) {
        self.reads += other.reads;
        self.writes += other.writes;
    }
}

/// One namespace's history at both resolutions, keyed by the bucket's start.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Series {
    #[serde(default)]
    hourly: BTreeMap<i64, Counts>,
    #[serde(default)]
    daily: BTreeMap<i64, Counts>,
}

impl Series {
    fn record(&mut self, now: i64, counts: Counts) {
        bump(&mut self.hourly, now, HOUR, HOURLY_BUCKETS, counts);
        bump(&mut self.daily, now, DAY, DAILY_BUCKETS, counts);
    }

    fn is_empty(&self) -> bool {
        self.hourly.is_empty() && self.daily.is_empty()
    }
}

/// Add to the bucket holding `now`, dropping what has aged out when a new
/// bucket starts — once an hour per namespace, not on every event.
fn bump(buckets: &mut BTreeMap<i64, Counts>, now: i64, step: i64, keep: i64, counts: Counts) {
    let start = now.div_euclid(step) * step;
    if let Some(bucket) = buckets.get_mut(&start) {
        bucket.add(counts);
        return;
    }
    buckets.insert(start, counts);
    let oldest = start - (keep - 1) * step;
    *buckets = buckets.split_off(&oldest);
}

/// What is written to disk.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ActivityData {
    #[serde(default)]
    roots: HashMap<String, Series>,
}

#[derive(Debug, Default)]
struct Inner {
    roots: HashMap<String, Series>,
    /// Changed since the last save.
    dirty: bool,
}

#[derive(Debug)]
pub struct Activity {
    /// `activity = false` in `[daemon]`. Checked before anything else, so a
    /// server that does not want the counts pays one relaxed load per event
    /// and never touches the lock.
    enabled: AtomicBool,
    inner: Mutex<Inner>,
}

impl Default for Activity {
    fn default() -> Self {
        Activity {
            enabled: AtomicBool::new(true),
            inner: Mutex::default(),
        }
    }
}

/// The namespace a path is counted against, or `None` for an internal one.
pub fn root_of(namespace: &str) -> Option<&str> {
    let root = namespace.split('/').find(|segment| !segment.is_empty())?;
    (!root.starts_with('_')).then_some(root)
}

/// Bucket width in seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Granularity {
    Hour,
    Day,
}

impl Granularity {
    pub fn step(self) -> i64 {
        match self {
            Granularity::Hour => HOUR,
            Granularity::Day => DAY,
        }
    }

    /// The most buckets that can hold anything, and so the widest window
    /// worth asking for.
    pub fn retained(self) -> i64 {
        match self {
            Granularity::Hour => HOURLY_BUCKETS,
            Granularity::Day => DAILY_BUCKETS,
        }
    }
}

/// One namespace over a window.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct RootReport {
    pub name: String,
    /// One entry per bucket, oldest first, zero where nothing happened.
    pub reads: Vec<u64>,
    pub writes: Vec<u64>,
    pub total: Counts,
    /// The window of the same length just before this one, for "up or down?".
    pub previous: Counts,
}

#[derive(Debug, Serialize)]
pub struct Report {
    /// Whether counting is on. When it is off, what was counted before is
    /// still reported, and nothing new is added to it.
    pub enabled: bool,
    pub granularity: Granularity,
    /// Seconds per bucket.
    pub step: i64,
    /// Start of the first bucket; bucket `i` starts at `start + i * step`.
    pub start: i64,
    pub buckets: usize,
    /// Start of the oldest bucket held at this resolution for any namespace
    /// shown, so the interface knows how far back browsing can usefully go.
    pub oldest: Option<i64>,
    /// The bucket holding the present moment.
    pub now: i64,
    /// Busiest first.
    pub roots: Vec<RootReport>,
}

impl Activity {
    pub fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::Relaxed);
    }

    pub fn record_read(&self, namespace: &str) {
        self.record(
            namespace,
            Counts {
                reads: 1,
                writes: 0,
            },
        );
    }

    pub fn record_write(&self, namespace: &str) {
        self.record(
            namespace,
            Counts {
                reads: 0,
                writes: 1,
            },
        );
    }

    fn record(&self, namespace: &str, counts: Counts) {
        if !self.enabled.load(Ordering::Relaxed) {
            return;
        }
        self.record_at(namespace, Utc::now().timestamp(), counts);
    }

    fn record_at(&self, namespace: &str, now: i64, counts: Counts) {
        let Some(root) = root_of(namespace) else {
            return;
        };
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        // Looked up before inserting so the hot path does not allocate a key.
        match inner.roots.get_mut(root) {
            Some(series) => series.record(now, counts),
            None => {
                let mut series = Series::default();
                series.record(now, counts);
                inner.roots.insert(root.to_string(), series);
            }
        }
        inner.dirty = true;
    }

    /// `buckets` buckets ending with the one that holds `end`, for every
    /// namespace `visible` lets through.
    pub fn report(
        &self,
        granularity: Granularity,
        end: i64,
        buckets: usize,
        visible: impl Fn(&str) -> bool,
    ) -> Report {
        let step = granularity.step();
        let buckets = buckets.clamp(1, granularity.retained() as usize);
        let last = end.div_euclid(step) * step;
        let start = last - (buckets as i64 - 1) * step;
        let previous_start = start - buckets as i64 * step;

        let inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        let mut oldest: Option<i64> = None;
        let mut roots: Vec<RootReport> = inner
            .roots
            .iter()
            .filter(|(name, _)| visible(name))
            .map(|(name, series)| {
                let held = match granularity {
                    Granularity::Hour => &series.hourly,
                    Granularity::Day => &series.daily,
                };
                if let Some((&first, _)) = held.first_key_value() {
                    oldest = Some(oldest.map_or(first, |o| o.min(first)));
                }

                let mut reads = vec![0; buckets];
                let mut writes = vec![0; buckets];
                let mut total = Counts::default();
                for (&at, counts) in held.range(start..=last) {
                    let i = ((at - start) / step) as usize;
                    reads[i] = counts.reads;
                    writes[i] = counts.writes;
                    total.add(*counts);
                }
                let mut previous = Counts::default();
                for counts in held.range(previous_start..start).map(|(_, c)| c) {
                    previous.add(*counts);
                }

                RootReport {
                    name: name.clone(),
                    reads,
                    writes,
                    total,
                    previous,
                }
            })
            .collect();
        drop(inner);

        roots.sort_by(|a, b| {
            (b.total.reads + b.total.writes)
                .cmp(&(a.total.reads + a.total.writes))
                .then_with(|| a.name.cmp(&b.name))
        });

        Report {
            enabled: self.enabled.load(Ordering::Relaxed),
            granularity,
            step,
            start,
            buckets,
            oldest,
            now: Utc::now().timestamp().div_euclid(step) * step,
            roots,
        }
    }

    /// Everything, for a save, if anything changed since the last one.
    /// `force` takes it regardless, which is what a shutdown wants.
    pub fn take_snapshot(&self, force: bool) -> Option<ActivityData> {
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        if !inner.dirty && !force {
            return None;
        }
        inner.dirty = false;
        // Namespaces whose history has entirely aged out are not worth keeping.
        inner.roots.retain(|_, series| !series.is_empty());
        Some(ActivityData {
            roots: inner.roots.clone(),
        })
    }

    /// Put a failed save's changes back so the next one retries.
    pub fn mark_dirty(&self) {
        self.inner
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .dirty = true;
    }

    /// Restore what a previous run saved. Merged rather than replaced, so a
    /// read that arrived before the restore is not lost.
    pub fn restore(&self, data: ActivityData) {
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        for (root, saved) in data.roots {
            let series = inner.roots.entry(root).or_default();
            for (at, counts) in saved.hourly {
                series.hourly.entry(at).or_default().add(counts);
            }
            for (at, counts) in saved.daily {
                series.daily.entry(at).or_default().add(counts);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const READ: Counts = Counts {
        reads: 1,
        writes: 0,
    };
    const WRITE: Counts = Counts {
        reads: 0,
        writes: 1,
    };

    #[test]
    fn counts_go_to_the_first_segment_and_skip_internal_namespaces() {
        assert_eq!(root_of("feeds/misp/ips"), Some("feeds"));
        assert_eq!(root_of("/feeds"), Some("feeds"));
        assert_eq!(root_of("_all"), None);
        assert_eq!(root_of("_shadow/feeds"), None);
        assert_eq!(root_of(""), None);
    }

    #[test]
    fn a_report_is_dense_and_ends_at_the_requested_bucket() {
        let activity = Activity::default();
        let day0 = 100 * DAY;
        activity.record_at("feeds/a", day0 + 5, READ);
        activity.record_at("feeds/b", day0 + 7, READ);
        activity.record_at("feeds", day0 + 2 * DAY, WRITE);
        activity.record_at("_all", day0, WRITE);

        let report = activity.report(Granularity::Day, day0 + 2 * DAY + 10, 3, |_| true);
        assert_eq!(report.start, day0);
        assert_eq!(report.buckets, 3);
        assert_eq!(report.roots.len(), 1);
        let feeds = &report.roots[0];
        assert_eq!(feeds.reads, vec![2, 0, 0]);
        assert_eq!(feeds.writes, vec![0, 0, 1]);
        assert_eq!(
            feeds.total,
            Counts {
                reads: 2,
                writes: 1
            }
        );
        assert_eq!(report.oldest, Some(day0));
    }

    #[test]
    fn the_previous_window_is_totalled_for_comparison() {
        let activity = Activity::default();
        let day0 = 100 * DAY;
        activity.record_at("a", day0, READ);
        activity.record_at("a", day0 + DAY, READ);
        activity.record_at("a", day0 + 2 * DAY, WRITE);

        let report = activity.report(Granularity::Day, day0 + 2 * DAY, 1, |_| true);
        assert_eq!(report.roots[0].total.writes, 1);
        assert_eq!(report.roots[0].previous.reads, 1);
    }

    #[test]
    fn nothing_is_counted_when_switched_off() {
        let activity = Activity::default();
        activity.set_enabled(false);
        activity.record_read("feeds");
        activity.record_write("feeds");
        assert!(activity.take_snapshot(false).is_none());
        let report = activity.report(Granularity::Day, Utc::now().timestamp(), 1, |_| true);
        assert!(!report.enabled);
        assert!(report.roots.is_empty());
    }

    #[test]
    fn hidden_namespaces_are_left_out() {
        let activity = Activity::default();
        activity.record_at("public", 0, READ);
        activity.record_at("secret", 0, READ);
        let report = activity.report(Granularity::Hour, 0, 1, |name| name == "public");
        let names: Vec<_> = report.roots.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(names, ["public"]);
    }

    #[test]
    fn old_buckets_age_out() {
        let activity = Activity::default();
        activity.record_at("a", 0, READ);
        activity.record_at("a", HOURLY_BUCKETS * HOUR, READ);
        let data = activity.take_snapshot(true).unwrap();
        let series = &data.roots["a"];
        assert_eq!(series.hourly.len(), 1, "the first hour has aged out");
        assert_eq!(series.daily.len(), 2, "but its day has not");
    }

    #[test]
    fn a_snapshot_round_trips_and_is_only_taken_when_something_changed() {
        let activity = Activity::default();
        activity.record_at("a", 0, WRITE);
        let data = activity.take_snapshot(false).expect("changed");
        assert!(activity.take_snapshot(false).is_none());

        let json = serde_json::to_string(&data).unwrap();
        let restored = Activity::default();
        restored.restore(serde_json::from_str(&json).unwrap());
        let report = restored.report(Granularity::Hour, 0, 1, |_| true);
        assert_eq!(report.roots[0].writes, vec![1]);
    }
}
