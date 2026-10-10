use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError, RwLock};

use chrono::{DateTime, Utc};
use serde::ser::SerializeStruct;
use serde::{Deserialize, Serialize, Serializer};

use crate::attribute::{Attribute, AttributeView, Merge, Merged};
use crate::db_log::log_attribute;
use crate::tier::TierPolicy;

/// Namespace holding every value ever written, used to derive consensus.
pub const ALL_NAMESPACE: &str = "_all";
/// Prefix under which reads are recorded ("shadow sightings").
pub const SHADOW_PREFIX: &str = "_shadow/";
/// Prefix holding the server's own configuration, including API keys.
pub const CONFIG_PREFIX: &str = "_config/";
/// Namespace under which API keys live.
pub const APIKEYS_NAMESPACE: &str = "_config/acl/apikeys/";
/// API key seeded on a fresh database, unless `-k` supplies one.
pub const DEFAULT_APIKEY: &str = "changeme";
/// Bumped whenever the on-disk snapshot layout changes incompatibly.
/// The snapshot format this build writes.
///
/// 2 keeps counts and hourly buckets per node; 1 kept one total of each.
/// Version 1 is still read and migrated on load — see [`Attribute::migrate`] —
/// because refusing it would mean a build upgrade looked like total data loss.
pub const SNAPSHOT_VERSION: u32 = 2;

/// The node id a server uses when it has not been given one.
///
/// A standalone server keeps all its sightings under this name, so its counts
/// sum to exactly what they always did. Set `node_id` in `[daemon]` before
/// putting it in a galaxy: two servers sharing an id would each think the
/// other's contribution was their own, and a merge would lose one of them.
pub const LOCAL_NODE: &str = "local";

/// A lookup that did not resolve, rendered as-is into the JSON body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NotFound {
    pub error: &'static str,
    pub namespace: String,
    pub value: String,
}

impl NotFound {
    pub fn namespace(namespace: &str, value: &str) -> Self {
        Self {
            error: "Path not found",
            namespace: namespace.to_string(),
            value: value.to_string(),
        }
    }

    pub fn value(namespace: &str, value: &str) -> Self {
        Self {
            error: "Value not found",
            namespace: namespace.to_string(),
            value: value.to_string(),
        }
    }
}

/// Retention rules applied to every write. Both default to "keep everything",
/// so an existing deployment does not start discarding data on upgrade.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DatabasePolicy {
    /// Hourly statistics buckets kept per attribute; 0 keeps all of them.
    pub stats_retention: usize,
    /// TTL applied to shadow sightings; 0 means they never expire.
    pub shadow_ttl: u64,
}

/// Which namespaces this server stores.
///
/// A server always holds the internal namespaces — see [`is_internal`] — because
/// it cannot operate without its own consensus tally and shadow record. So this
/// is about ordinary namespaces only, and an empty policy is a pure router:
/// it stores nothing of its own and exists to forward.
///
/// Prefixes match on whole path segments, the same rule the ACL and
/// [`Database::namespaces_under`] use, so `feeds` holds `feeds/misp/ips` and
/// never `feeds-internal`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoragePolicy {
    /// Namespace prefixes held. Meaningless when `everything` is set.
    prefixes: Vec<String>,
    /// Hold every namespace. The default, and what every release before this
    /// one did.
    everything: bool,
}

impl Default for StoragePolicy {
    fn default() -> Self {
        StoragePolicy::everything()
    }
}

impl StoragePolicy {
    /// Hold everything, which is what a server with no `namespaces` setting
    /// does.
    pub fn everything() -> Self {
        StoragePolicy {
            prefixes: Vec::new(),
            everything: true,
        }
    }

    /// Hold only what these prefixes cover.
    ///
    /// `/` anywhere in the list means everything, since a prefix that covers
    /// the root covers all of it. Entries are trimmed of slashes so that `/`,
    /// `feeds/` and `feeds` all mean what they look like.
    pub fn from_prefixes<I, S>(prefixes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut held: Vec<String> = Vec::new();
        for prefix in prefixes {
            let prefix = prefix.as_ref().trim().trim_matches('/').to_string();
            if prefix.is_empty() {
                // `/` on its own: the whole tree.
                return StoragePolicy::everything();
            }
            if !held.contains(&prefix) {
                held.push(prefix);
            }
        }
        StoragePolicy {
            prefixes: held,
            everything: false,
        }
    }

    /// Whether this server stores `namespace`.
    pub fn holds(&self, namespace: &str) -> bool {
        // Ours regardless: a router still keeps its own `_all`, which under a
        // galaxy is the consensus every node below it rolls up into.
        if is_internal(namespace) {
            return true;
        }
        if self.everything {
            return true;
        }
        let namespace = namespace.trim_matches('/');
        self.prefixes.iter().any(|prefix| {
            namespace == prefix
                || namespace
                    .strip_prefix(prefix.as_str())
                    .is_some_and(|rest| rest.starts_with('/'))
        })
    }

    /// Whether this server holds no ordinary namespace at all.
    pub fn is_router(&self) -> bool {
        !self.everything && self.prefixes.is_empty()
    }

    pub fn stores_everything(&self) -> bool {
        self.everything
    }

    /// The prefixes as configured, for reporting. Empty when everything is
    /// held, or when nothing is.
    pub fn prefixes(&self) -> &[String] {
        &self.prefixes
    }
}

/// What a write did.
///
/// `new` is the fact a router cannot work out for itself: whether this was the
/// first sighting of the value in this namespace, which is what decides a
/// consensus increment. The node knows it under the write lock; without
/// reporting it, anything in front of the node would have to hold the
/// namespace to find out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Written {
    pub count: u64,
    pub new: bool,
}

/// How a single write should behave.
#[derive(Debug, Clone, Copy, Default)]
pub struct WriteOpts {
    /// Count this value towards consensus in [`ALL_NAMESPACE`].
    pub consensus: bool,
    /// Set the attribute's TTL. `None` leaves whatever it already had.
    pub ttl: Option<u64>,
}

/// One namespace as the management interface sees it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NamespaceEntry {
    pub namespace: String,
    /// The top-level namespace, which is the unit eviction acts on.
    pub shard: String,
    pub tier: String,
    pub resident: bool,
    /// The settings in force here, and whether they were set on this namespace
    /// or inherited from one above it.
    #[serde(flatten)]
    pub storage: StorageView,
}

/// What the interface needs to show and edit a row's storage settings.
///
/// These belong to the shard, so every namespace under one reports the same
/// thing — which is the point: changing it from any row changes all of them,
/// and the row names the shard it will change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StorageView {
    /// Seconds a warm shard may sit untouched before it is written out.
    pub warm_idle: u64,
    /// Set on the shard itself, rather than taken from the configured default.
    pub own_tier: bool,
    pub own_warm_idle: bool,
}

/// One step down the namespace tree, as the management interface browses it.
///
/// A path can be both at once: `myorg` may hold values of its own and still
/// have `myorg/feeds` underneath it, the way a directory holds files as well as
/// subdirectories.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TreeEntry {
    /// The path segment, which is what a row is labelled with.
    pub name: String,
    /// The whole path, which is what the row links to.
    pub path: String,
    /// Whether the path is a namespace in its own right, and so may hold values.
    /// Named apart from [`NamespaceEntry::namespace`], which is a path: one
    /// listing saying `namespace` for a string and the other for a flag is how
    /// a caller ends up sending `true` where a name was wanted.
    #[serde(rename = "is_namespace")]
    pub is_namespace: bool,
    /// Namespaces below this one, so a folder can say how much is inside it.
    pub descendants: usize,
    /// The top-level namespace, which is the unit eviction acts on.
    pub shard: String,
    pub tier: String,
    pub resident: bool,
    /// The settings in force at this path. A folder that is not a namespace of
    /// its own still has them: they are what its children inherit.
    #[serde(flatten)]
    pub storage: StorageView,
}

/// One namespace a value has been seen in, for the relationship view.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Sighting {
    pub namespace: String,
    /// The top-level namespace, which is what colours a cluster.
    pub shard: String,
    pub count: u64,
    pub first_seen: i64,
    pub last_seen: i64,
}

/// Everywhere one value was found, and what the search cost.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Default)]
pub struct Sightings {
    pub items: Vec<Sighting>,
    /// True when the search stopped at the limit, so there may be more.
    pub truncated: bool,
    /// True when finding them all meant reading shards back from disk.
    pub paged_in: bool,
}

impl StorageView {
    fn of(policy: &TierPolicy, shard: &str) -> (String, StorageView) {
        let resolved = policy.resolve(shard);
        (
            resolved.tier.as_str().to_string(),
            StorageView {
                warm_idle: resolved.warm_idle,
                own_tier: resolved.own_tier.is_some(),
                own_warm_idle: resolved.own_warm_idle.is_some(),
            },
        )
    }
}

/// A slice of a listing, with the total so a caller can page through it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Page<T> {
    pub items: Vec<T>,
    /// Matches before paging, not the number returned.
    pub total: usize,
    pub offset: usize,
}

/// What an eviction pass did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct EvictReport {
    pub evicted: usize,
    /// Still in use by a request, so left for the next sweep.
    pub busy: usize,
    /// Could not be written out, so deliberately kept in memory.
    pub failed: usize,
}

impl EvictReport {
    pub fn is_empty(&self) -> bool {
        self.evicted == 0 && self.busy == 0 && self.failed == 0
    }
}

/// How many values a namespace holds.
///
/// Answered from the map's own length rather than by walking it, so the cost
/// does not grow with the namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ValueCount {
    pub values: usize,
    /// Whether `values` is the number a reader would see.
    ///
    /// False when the namespace has ever held a TTL. A value stops being
    /// visible the moment it expires, but is only removed when the sweeper
    /// next runs, so between those two moments the stored count is an upper
    /// bound. Nothing fires at the moment of expiry, so this is a property of
    /// the design rather than something a tighter count could fix.
    pub exact: bool,
    /// Whether answering this had to read the shard back into memory.
    pub paged_in: bool,
}

/// What a sweep reclaimed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SweepReport {
    pub values_removed: usize,
    pub namespaces_removed: usize,
}

impl SweepReport {
    pub fn is_empty(&self) -> bool {
        self.values_removed == 0 && self.namespaces_removed == 0
    }
}

/// One namespace's values.
///
/// Values are behind their own mutex so that concurrent writes to *different*
/// values in the same namespace do not contend: the map lock is only taken for
/// writing when a value is seen for the first time.
#[derive(Default)]
struct Namespace {
    values: RwLock<HashMap<String, Mutex<Attribute>>>,
    /// Set once any attribute here is given a TTL, so that sweeps can skip
    /// namespaces that can never expire — which is all of them by default.
    has_ttl: AtomicBool,
}

impl Namespace {
    fn from_values(values: HashMap<String, Attribute>, node: &str) -> Self {
        let has_ttl = values.values().any(|attr| attr.ttl > 0);
        Self {
            values: RwLock::new(
                values
                    .into_iter()
                    .map(|(value, mut attr)| {
                        // A snapshot from before counts were kept per node has
                        // a total with nobody's name on it. This server wrote
                        // it, so it is this server's.
                        attr.migrate(node);
                        (value, Mutex::new(attr))
                    })
                    .collect(),
            ),
            has_ttl: AtomicBool::new(has_ttl),
        }
    }

    /// Record a sighting, reporting the new count, whether this was the first
    /// time the value appeared here, and a snapshot for the write log.
    fn record(
        &self,
        node: &str,
        value: &str,
        when: DateTime<Utc>,
        ttl: Option<u64>,
        retention: usize,
        tags: &str,
    ) -> (u64, bool, AttributeView) {
        if ttl.is_some_and(|ttl| ttl > 0) {
            self.has_ttl.store(true, Ordering::Relaxed);
        }

        // Fast path: the value already exists, so a read lock is enough and
        // other values in this namespace stay writable.
        {
            let values = self.values.read().unwrap_or_else(PoisonError::into_inner);
            if let Some(cell) = values.get(value) {
                let mut attr = cell.lock().unwrap_or_else(PoisonError::into_inner);
                if let Some(ttl) = ttl {
                    attr.set_ttl(ttl);
                }
                if !tags.is_empty() {
                    attr.add_tags(tags);
                }
                attr.increment(node, when, retention);
                return (attr.count(), false, attr.view(0, false));
            }
        }

        // Slow path: first sighting of this value here. Deciding "is this new?"
        // under the write lock is what keeps consensus from being double
        // counted when two writers race.
        let mut values = self.values.write().unwrap_or_else(PoisonError::into_inner);
        let is_new = !values.contains_key(value);
        let cell = values
            .entry(value.to_string())
            .or_insert_with(|| Mutex::new(Attribute::new(value)));
        // We hold the map's write lock, so the mutex needs no locking here.
        let attr = cell.get_mut().unwrap_or_else(PoisonError::into_inner);
        if let Some(ttl) = ttl {
            attr.set_ttl(ttl);
        }
        if !tags.is_empty() {
            attr.add_tags(tags);
        }
        attr.increment(node, when, retention);
        (attr.count(), is_new, attr.view(0, false))
    }

    /// Set one value's count outright, reporting whether it changed.
    ///
    /// Not a sighting and not a merge: the caller has surveyed the truth and
    /// is correcting a tally that drifted. Attributed to `node` because the
    /// server doing the correcting is the one asserting it, and a count of 0
    /// removes the value — a tally of nothing is nothing, not a zero entry.
    fn set_count(&self, node: &str, value: &str, count: u64) -> bool {
        let mut values = self.values.write().unwrap_or_else(PoisonError::into_inner);

        if count == 0 {
            return values.remove(value).is_some();
        }

        let cell = values
            .entry(value.to_string())
            .or_insert_with(|| Mutex::new(Attribute::new(value)));
        let attr = cell.get_mut().unwrap_or_else(PoisonError::into_inner);
        if attr.count() == count {
            return false;
        }

        // One entry, under the correcting server's name, replacing whatever
        // was there: the tally is an assertion about the galaxy rather than a
        // sum of contributions.
        attr.counts.clear();
        attr.counts.insert(node.to_string(), count);
        if attr.first_seen == DateTime::UNIX_EPOCH {
            let now = Utc::now();
            attr.first_seen = now;
            attr.last_seen = now;
        }
        true
    }

    /// Fold a peer's copy in, reporting whether the value was absent here.
    ///
    /// Takes the map's write lock rather than the fast read-lock path, because
    /// a merge may be bringing a value this namespace has never held.
    fn merge(&self, node: &str, value: &str, incoming: &Merge) -> (Merged, bool) {
        if incoming.ttl > 0 {
            self.has_ttl.store(true, Ordering::Relaxed);
        }

        let mut values = self.values.write().unwrap_or_else(PoisonError::into_inner);
        let is_new = !values.contains_key(value);
        let cell = values
            .entry(value.to_string())
            .or_insert_with(|| Mutex::new(Attribute::new(value)));
        // We hold the map's write lock, so the mutex needs no locking here.
        let attr = cell.get_mut().unwrap_or_else(PoisonError::into_inner);
        (attr.merge(incoming, node), is_new)
    }

    fn merge_page(&self, offset: usize, limit: usize, now: DateTime<Utc>) -> Page<(String, Merge)> {
        let values = self.values.read().unwrap_or_else(PoisonError::into_inner);
        let mut names: Vec<&String> = values.keys().collect();
        names.sort_unstable();

        // Expired values are not offered, and are not counted either: a caller
        // paging through should not have to wonder why a page came back short.
        let live: Vec<&&String> = names
            .iter()
            .filter(|value| {
                values.get(**value).is_some_and(|cell| {
                    !cell
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .is_expired(now)
                })
            })
            .collect();

        let total = live.len();
        let items = live
            .into_iter()
            .skip(offset)
            .take(limit)
            .filter_map(|value| {
                let attr = values
                    .get(*value)?
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                Some(((*value).clone(), attr.as_merge()))
            })
            .collect();

        Page {
            items,
            total,
            offset,
        }
    }

    fn merge_payload(&self, value: &str, now: DateTime<Utc>) -> Option<Merge> {
        let values = self.values.read().unwrap_or_else(PoisonError::into_inner);
        let attr = values
            .get(value)?
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        // An expired value is not offered: a peer that took it would hold
        // something this server has already stopped showing.
        (!attr.is_expired(now)).then(|| attr.as_merge())
    }

    /// An expired attribute is invisible to readers even before the sweeper
    /// gets round to reclaiming it.
    fn view(
        &self,
        value: &str,
        consensus: u64,
        with_stats: bool,
        now: DateTime<Utc>,
    ) -> Option<AttributeView> {
        let values = self.values.read().unwrap_or_else(PoisonError::into_inner);
        let cell = values.get(value)?;
        let attr = cell.lock().unwrap_or_else(PoisonError::into_inner);
        (!attr.is_expired(now)).then(|| attr.view(consensus, with_stats))
    }

    fn count(&self, value: &str, now: DateTime<Utc>) -> u64 {
        let values = self.values.read().unwrap_or_else(PoisonError::into_inner);
        values.get(value).map_or(0, |cell| {
            let attr = cell.lock().unwrap_or_else(PoisonError::into_inner);
            if attr.is_expired(now) {
                0
            } else {
                attr.count()
            }
        })
    }

    /// Every live value here, with a placeholder consensus the caller fills in
    /// afterwards — see the lock-ordering note on [`Database`].
    fn all_views(&self, with_stats: bool, now: DateTime<Utc>) -> Vec<AttributeView> {
        let values = self.values.read().unwrap_or_else(PoisonError::into_inner);
        values
            .values()
            .filter_map(|cell| {
                let attr = cell.lock().unwrap_or_else(PoisonError::into_inner);
                (!attr.is_expired(now)).then(|| attr.view(0, with_stats))
            })
            .collect()
    }

    /// Drop expired attributes, returning the values that went.
    fn remove_expired(&self, now: DateTime<Utc>) -> Vec<String> {
        // Nothing here has ever had a TTL, so nothing here can expire.
        if !self.has_ttl.load(Ordering::Relaxed) {
            return Vec::new();
        }

        // Check under a read lock first: sweeps usually find nothing, and
        // taking the write lock would block every reader of this namespace.
        {
            let values = self.values.read().unwrap_or_else(PoisonError::into_inner);
            let any_expired = values.values().any(|cell| {
                cell.lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .is_expired(now)
            });
            if !any_expired {
                return Vec::new();
            }
        }

        let mut values = self.values.write().unwrap_or_else(PoisonError::into_inner);
        let mut removed = Vec::new();
        values.retain(|value, cell| {
            let expired = cell
                .get_mut()
                .unwrap_or_else(PoisonError::into_inner)
                .is_expired(now);
            if expired {
                removed.push(value.clone());
            }
            !expired
        });
        removed
    }

    /// Replace one value's tag set, reporting whether the value was there.
    fn retag(&self, value: &str, tags: &str, now: DateTime<Utc>) -> bool {
        let values = self.values.read().unwrap_or_else(PoisonError::into_inner);
        let Some(cell) = values.get(value) else {
            return false;
        };
        let mut attr = cell.lock().unwrap_or_else(PoisonError::into_inner);
        if attr.is_expired(now) {
            return false;
        }
        attr.set_tags(tags, now.timestamp_millis());
        true
    }

    /// Give back one consensus count, dropping the entry when it reaches zero.
    /// Done under the write lock so a concurrent write cannot resurrect a value
    /// between the decrement and the removal.
    fn release(&self, node: &str, value: &str) {
        let mut values = self.values.write().unwrap_or_else(PoisonError::into_inner);
        let Some(cell) = values.get_mut(value) else {
            return;
        };
        let remaining = cell
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner)
            .decrement(node);
        if remaining == 0 {
            values.remove(value);
        }
    }

    /// The values stored here, live or not, for consensus bookkeeping on delete.
    fn value_names(&self) -> Vec<String> {
        self.values
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .keys()
            .cloned()
            .collect()
    }

    fn is_empty(&self) -> bool {
        self.values
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .is_empty()
    }

    /// How many values are stored here.
    ///
    /// O(1): the map already keeps this, so nothing has to be counted. It is
    /// the number *stored*, which is the number visible only when nothing here
    /// can expire — see [`Namespace::has_ttl`].
    fn len(&self) -> usize {
        self.values
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }

    /// Whether anything here was ever given a TTL.
    ///
    /// Sticky: it stays set once a TTL has been seen, even if that value has
    /// since gone. Erring this way is deliberate — it makes [`Namespace::len`]
    /// claim to be exact only when it certainly is.
    fn has_ttl(&self) -> bool {
        self.has_ttl.load(Ordering::Relaxed)
    }
}

/// In-memory store: namespace -> value -> attribute.
///
/// Every method takes `&self`; there is no global lock. Namespaces are handed
/// out as `Arc`s so the outer map's lock is released before any value is
/// touched.
///
/// **Lock ordering:** outer map, then a namespace's value map, then a single
/// attribute — and never two namespaces at once. Anything needing a second
/// namespace (consensus lives in `_all`) must finish with the first one before
/// reaching for it, or two writers can deadlock.
/// What is known about a shard, whether or not its data is in memory.
#[derive(Debug, Default, Clone)]
struct ShardMeta {
    /// Namespace names belonging to this shard. Kept even while evicted, so
    /// the management interface can list namespaces without paging data in.
    namespaces: HashSet<String>,
    resident: bool,
    /// Unix seconds of the last read or write.
    last_access: i64,
}

/// Where shards are read from and written to when they are paged in and out.
#[derive(Debug, Clone)]
pub struct Store {
    pub dbdir: PathBuf,
    pub level: i32,
}

#[derive(Default)]
pub struct Database {
    namespaces: RwLock<HashMap<String, Arc<Namespace>>>,
    policy: DatabasePolicy,
    /// Which namespaces this server is willing to store. Everything, unless
    /// the configuration narrows it.
    stores: StoragePolicy,
    /// This server's name in its own counters. See [`LOCAL_NODE`].
    node: String,
    /// Shards written to since the last save, so a snapshot costs what changed
    /// rather than what exists.
    dirty: Mutex<HashSet<String>>,
    /// Catalogue of shards, resident or not.
    shards: RwLock<HashMap<String, ShardMeta>>,
    /// Set once persistence is configured; without it nothing is ever evicted,
    /// because there would be nowhere to put it.
    store: RwLock<Option<Store>>,
    tiers: RwLock<TierPolicy>,
}

impl Database {
    /// A database with the default (keep-everything) policy. Production code
    /// always has a policy to hand and calls [`Database::with_policy`].
    #[cfg(test)]
    pub fn new() -> Database {
        Database::with_policy(DatabasePolicy::default())
    }

    /// A database that stores everything. Only the tests reach for this now:
    /// production goes through [`Database::with_storage`], because what a
    /// server stores is a configured thing.
    #[cfg(test)]
    pub fn with_policy(policy: DatabasePolicy) -> Database {
        Database::with_storage(policy, StoragePolicy::everything())
    }

    /// The same, narrowed to the namespaces this server is willing to store.
    /// Tests only: production names the server, because an unnamed one cannot
    /// join a galaxy without taking a peer's contribution for its own.
    #[cfg(test)]
    pub fn with_storage(policy: DatabasePolicy, stores: StoragePolicy) -> Database {
        Database::with_node(policy, stores, LOCAL_NODE.to_string())
    }

    /// The same, named: this server's sightings are counted under `node`.
    pub fn with_node(policy: DatabasePolicy, stores: StoragePolicy, node: String) -> Database {
        Database {
            namespaces: RwLock::new(HashMap::new()),
            policy,
            stores,
            node,
            dirty: Mutex::new(HashSet::new()),
            shards: RwLock::new(HashMap::new()),
            store: RwLock::new(None),
            tiers: RwLock::new(TierPolicy::default()),
        }
    }

    /// Rebuild a database from a snapshot. No API key is seeded here: the
    /// snapshot carries whatever keys were registered when it was written.
    /// The same, restoring a snapshot. Tests only, as above.
    #[cfg(test)]
    pub fn from_snapshot(data: SnapshotData, policy: DatabasePolicy) -> Database {
        Database::from_snapshot_with(data, policy, StoragePolicy::everything())
    }

    /// The same, narrowed to what this server stores.
    ///
    /// A snapshot written when this server held more than it does now is loaded
    /// as it stands: narrowing the policy is not a licence to discard data
    /// silently. What it stops is *new* writes outside the policy.
    /// Tests only, as above.
    #[cfg(test)]
    pub fn from_snapshot_with(
        data: SnapshotData,
        policy: DatabasePolicy,
        stores: StoragePolicy,
    ) -> Database {
        Database::from_snapshot_as(data, policy, stores, LOCAL_NODE.to_string())
    }

    /// The same, named. Totals written by a build that kept one become this
    /// server's own contribution, which is the only thing they can be.
    pub fn from_snapshot_as(
        data: SnapshotData,
        policy: DatabasePolicy,
        stores: StoragePolicy,
        node: String,
    ) -> Database {
        let namespaces: HashMap<String, Arc<Namespace>> = data
            .namespaces
            .into_iter()
            .map(|(name, values)| (name, Arc::new(Namespace::from_values(values, &node))))
            .collect();

        let mut shards: HashMap<String, ShardMeta> = HashMap::new();
        let seen = now_secs();
        for name in namespaces.keys() {
            let meta = shards
                .entry(crate::persistence::shard_of(name).to_string())
                .or_default();
            meta.namespaces.insert(name.clone());
            meta.resident = true;
            meta.last_access = seen;
        }

        Database {
            namespaces: RwLock::new(namespaces),
            policy,
            stores,
            node,
            dirty: Mutex::new(HashSet::new()),
            shards: RwLock::new(shards),
            store: RwLock::new(None),
            tiers: RwLock::new(TierPolicy::default()),
        }
    }

    /// API keys found in a snapshot written by an older build, which stored
    /// them as `_config/acl/apikeys/<key>` namespaces.
    ///
    /// Permissions now come from the configuration instead; this exists only so
    /// that upgrading does not lock an existing deployment out of its own data.
    pub fn legacy_apikeys(&self) -> Vec<String> {
        self.namespaces
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .keys()
            .filter_map(|name| name.strip_prefix(APIKEYS_NAMESPACE))
            .filter(|key| !key.is_empty())
            .map(String::from)
            .collect()
    }

    /// Record one sighting of `value` in `path` at `when`, returning the new count.
    ///
    /// When `opts.consensus` is set, the value is also counted in
    /// [`ALL_NAMESPACE`] — but only the *first* time it appears in this
    /// namespace, since consensus means "how many namespaces have seen this
    /// value", not "how many times was it written".
    pub fn write(&self, path: &str, value: &str, when: DateTime<Utc>, opts: WriteOpts) -> u64 {
        self.write_tagged(path, value, when, opts, "").count
    }

    /// A sighting that also carries what is known about the value.
    ///
    /// Tags are merged into whatever the value already had, in the same lock as
    /// the sighting itself: an importer contributing `stix-type:ipv4-addr` and
    /// a writer contributing `tlp:amber` both end up on the value, and neither
    /// write can be lost to the other. See [`crate::attribute::split_tags`] for
    /// the format.
    pub fn write_tagged(
        &self,
        path: &str,
        value: &str,
        when: DateTime<Utc>,
        opts: WriteOpts,
        tags: &str,
    ) -> Written {
        self.record_write(&self.node, path, value, when, opts, tags)
    }

    fn record_write(
        &self,
        node: &str,
        path: &str,
        value: &str,
        when: DateTime<Utc>,
        opts: WriteOpts,
        tags: &str,
    ) -> Written {
        // Shadow sightings get their retention from policy rather than from the
        // caller, which is what bounds `_shadow/*` growth.
        let ttl = match opts.ttl {
            Some(ttl) => Some(ttl),
            None if path.starts_with(SHADOW_PREFIX) && self.policy.shadow_ttl > 0 => {
                Some(self.policy.shadow_ttl)
            }
            None => None,
        };

        let namespace = self.namespace_or_create(path);
        let (count, is_new, mut view) =
            namespace.record(node, value, when, ttl, self.policy.stats_retention, tags);

        // The namespace's locks are released by now, so reaching into `_all`
        // here respects the ordering rule above.
        if opts.consensus && is_new {
            self.write(ALL_NAMESPACE, value, when, WriteOpts::default());
        }

        view.consensus = self.count(ALL_NAMESPACE, value);
        log_attribute(path, &view);
        self.mark_dirty(path);

        Written { count, new: is_new }
    }

    /// Fold a peer's copy of one value into ours.
    ///
    /// Not a sighting: nothing is counted here, the peer's own counts are
    /// taken as they are, and `_all` is updated only when this merge brings a
    /// value into a namespace that did not have it — which is a new namespace
    /// holding it, exactly as a first write would be.
    ///
    /// See [`Attribute::merge`] for the rules and why each is order
    /// independent.
    pub fn merge(&self, path: &str, value: &str, incoming: &Merge) -> Merged {
        let namespace = self.namespace_or_create(path);
        let (outcome, is_new) = namespace.merge(&self.node, value, incoming);

        if is_new && counts_towards_consensus(path) {
            self.write(ALL_NAMESPACE, value, Utc::now(), WriteOpts::default());
        }
        if outcome.changed {
            self.mark_dirty(path);
        }
        outcome
    }

    /// Put the consensus tally right from a survey of who holds what.
    ///
    /// `holders` maps each value to the set of namespaces holding it, so the
    /// tally is the size of that set. A set rather than a sum: the same
    /// namespace mirrored three times is still one namespace.
    ///
    /// Used by a server in front of a galaxy, whose tally it keeps by counting
    /// forwarded writes and which therefore only ever rises — values expire and
    /// namespaces are deleted on the nodes, and neither reaches it. See
    /// [`crate::galaxy::reconcile`].
    ///
    /// Returns how many values were wrong. A value this server had a tally for
    /// and the survey did not find at all is set to nothing: it has gone
    /// everywhere, so saying otherwise would be the drift this exists to undo.
    pub fn set_consensus(
        &self,
        holders: &HashMap<String, std::collections::BTreeSet<String>>,
    ) -> usize {
        let all = self.namespace_or_create(ALL_NAMESPACE);
        let mut corrected = 0;

        for (value, namespaces) in holders {
            let truth = namespaces.len() as u64;
            if all.set_count(&self.node, value, truth) {
                corrected += 1;
            }
        }

        // Anything we have a tally for that the survey never saw has gone from
        // every namespace that held it.
        for value in all.value_names() {
            if !holders.contains_key(&value) && all.set_count(&self.node, &value, 0) {
                corrected += 1;
            }
        }

        if corrected > 0 {
            self.mark_dirty(ALL_NAMESPACE);
        }
        corrected
    }

    /// Replace a value's tags outright, which is how a wrong one comes off.
    ///
    /// This is not a sighting: nothing is counted, and `first_seen` and
    /// `last_seen` do not move. Returns false if the value is not there.
    pub fn set_tags(&self, path: &str, value: &str, tags: &str) -> bool {
        let Some(namespace) = self.namespace(path) else {
            return false;
        };
        let changed = namespace.retag(value, tags, Utc::now());
        if changed {
            self.mark_dirty(path);
        }
        changed
    }

    pub fn view(
        &self,
        path: &str,
        value: &str,
        consensus: u64,
        with_stats: bool,
    ) -> Option<AttributeView> {
        self.namespace(path)?
            .view(value, consensus, with_stats, Utc::now())
    }

    /// Every value in a namespace, in the shape a peer should be offered them.
    ///
    /// Paged, because a namespace can hold millions and a catch-up has to be
    /// able to make progress in bounded steps. Ordered by value so that paging
    /// is stable while the namespace is being written to: a new value appears
    /// in its place rather than shifting everything after it.
    pub fn merge_page(
        &self,
        path: &str,
        offset: usize,
        limit: usize,
    ) -> Option<Page<(String, Merge)>> {
        let namespace = self.namespace(path)?;
        Some(namespace.merge_page(offset, limit, Utc::now()))
    }

    /// One value in the shape a peer should be offered it, or `None` if it is
    /// not here or has expired.
    ///
    /// The read side of [`Database::merge`]: what comes back here is what goes
    /// there, unchanged.
    pub fn merge_payload(&self, path: &str, value: &str) -> Option<Merge> {
        self.namespace(path)?.merge_payload(value, Utc::now())
    }

    pub fn count(&self, path: &str, value: &str) -> u64 {
        let now = Utc::now();
        self.namespace(path)
            .map_or(0, |namespace| namespace.count(value, now))
    }

    /// Whether a namespace exists at all, resident or evicted.
    pub fn namespace_exists(&self, namespace: &str) -> bool {
        if self
            .namespaces
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .contains_key(namespace)
        {
            return true;
        }
        self.shards
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(crate::persistence::shard_of(namespace))
            .is_some_and(|meta| meta.namespaces.contains(namespace))
    }

    /// Every live attribute stored in `namespace`, or `None` if it does not exist.
    ///
    /// Consensus is filled in only after the namespace's lock has been dropped,
    /// so that this never holds two namespaces at once.
    pub fn namespace_views(&self, namespace: &str) -> Option<Vec<AttributeView>> {
        let mut views = self.namespace(namespace)?.all_views(false, Utc::now());
        for view in &mut views {
            view.consensus = self.count(ALL_NAMESPACE, &view.value);
        }
        Some(views)
    }

    /// Drop a namespace, giving back the consensus its values were holding.
    pub fn delete(&self, name: &str) -> bool {
        let Some(namespace) = self.namespace(name) else {
            return false;
        };
        let values = namespace.value_names();
        drop(namespace);

        let removed = self
            .namespaces
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(name)
            .is_some();

        if removed {
            self.mark_dirty(name);
            if let Some(meta) = self
                .shards
                .write()
                .unwrap_or_else(PoisonError::into_inner)
                .get_mut(crate::persistence::shard_of(name))
            {
                meta.namespaces.remove(name);
            }
        }
        if removed && counts_towards_consensus(name) {
            for value in values {
                self.release_consensus(&value);
            }
        }
        removed
    }

    /// Reclaim expired attributes and the namespaces left empty by them.
    pub fn sweep(&self, now: DateTime<Utc>) -> SweepReport {
        let entries: Vec<(String, Arc<Namespace>)> = {
            let map = self
                .namespaces
                .read()
                .unwrap_or_else(PoisonError::into_inner);
            map.iter()
                .map(|(name, namespace)| (name.clone(), Arc::clone(namespace)))
                .collect()
        };

        let mut report = SweepReport::default();
        // Namespaces this pass emptied, which are the only ones it may reclaim.
        let mut emptied: Vec<String> = Vec::new();
        for (name, namespace) in &entries {
            // API keys have no TTL and must never be swept out from under the ACL.
            if name.starts_with(CONFIG_PREFIX) {
                continue;
            }

            let expired = namespace.remove_expired(now);
            if !expired.is_empty() {
                self.mark_dirty(name);
                if namespace.is_empty() {
                    emptied.push(name.clone());
                }
            }
            report.values_removed += expired.len();

            if counts_towards_consensus(name) {
                for value in expired {
                    self.release_consensus(&value);
                }
            }
        }

        // Our own handles must go before pruning, or `strong_count` below would
        // see them and conclude every namespace is still in use.
        drop(entries);
        report.namespaces_removed = self.prune_empty(&emptied);
        report
    }

    /// Note that a shard is dirty, so the next save rewrites it.
    pub fn mark_dirty(&self, namespace: &str) {
        self.mark_shard_dirty(crate::persistence::shard_of(namespace));
    }

    pub fn mark_shard_dirty(&self, shard: &str) {
        self.dirty
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(shard.to_string());
    }

    /// Take the dirty set, leaving it empty. A failed save puts its shard back.
    pub fn take_dirty(&self) -> HashSet<String> {
        std::mem::take(&mut *self.dirty.lock().unwrap_or_else(PoisonError::into_inner))
    }

    /// Every shard that currently holds a namespace.
    pub fn shards(&self) -> HashSet<String> {
        self.namespaces
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .keys()
            .map(|name| crate::persistence::shard_of(name).to_string())
            .collect()
    }

    /// A borrowed, streaming view of one shard.
    pub fn shard_snapshot<'a>(&'a self, shard: &'a str) -> ShardSnapshot<'a> {
        ShardSnapshot(self, shard)
    }

    /// A borrowed, streaming view of the whole database. Shards are what gets
    /// written now; this remains for tests and for comparing against the
    /// single-file format.
    #[cfg(test)]
    pub fn snapshot(&self) -> Snapshot<'_> {
        Snapshot(self)
    }

    pub fn namespace_count(&self) -> usize {
        self.shards
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .values()
            .map(|meta| meta.namespaces.len())
            .sum()
    }

    /// Which tags are in use, and on how many values.
    ///
    /// **Only what is in memory is counted**, and the second return value says
    /// how many namespaces that was out of how many exist. Reading every tag
    /// otherwise means paging every cold shard back in, which would turn
    /// opening a page in the management interface into the most expensive thing
    /// the server does — and on a large install would evict the working set to
    /// do it. An approximate count of what is loaded, labelled as such, is
    /// worth more than an exact one nobody can afford.
    ///
    /// Internal namespaces are left out: `_shadow` values carry no tags and
    /// `_all` is a tally.
    pub fn tag_usage(&self) -> (std::collections::BTreeMap<String, u64>, usize, usize) {
        // Counted the same way as the tally below — ordinary namespaces only —
        // so that "2 of 3" means two were read and one is paged out, rather
        // than counting `_shadow` in the total and never in the tally.
        let total = {
            let shards = self.shards.read().unwrap_or_else(PoisonError::into_inner);
            shards
                .values()
                .flat_map(|meta| meta.namespaces.iter())
                .filter(|name| !is_internal(name))
                .count()
        };
        let resident: Vec<(String, Arc<Namespace>)> = {
            let namespaces = self
                .namespaces
                .read()
                .unwrap_or_else(PoisonError::into_inner);
            namespaces
                .iter()
                .filter(|(name, _)| !is_internal(name))
                .map(|(name, namespace)| (name.clone(), Arc::clone(namespace)))
                .collect()
        };

        let now = Utc::now();
        let mut counts: std::collections::BTreeMap<String, u64> = std::collections::BTreeMap::new();
        let looked_at = resident.len();
        for (_, namespace) in resident {
            let values = namespace
                .values
                .read()
                .unwrap_or_else(PoisonError::into_inner);
            for cell in values.values() {
                let attr = cell.lock().unwrap_or_else(PoisonError::into_inner);
                if attr.is_expired(now) {
                    continue;
                }
                for tag in crate::tags::split(&attr.tags) {
                    *counts.entry(tag.to_string()).or_default() += 1;
                }
            }
        }
        (counts, looked_at, total)
    }

    /// Namespace names matching `filter`, sorted, one page at a time.
    ///
    /// `_config` (server state) and `_all` (the consensus tally) are left out:
    /// they are bookkeeping, not data anyone browses. `_shadow/*` is kept,
    /// since what was searched for is genuinely interesting.
    /// `allowed` decides which namespaces the caller may even know about, so a
    /// key scoped to one subtree does not learn the names of the others.
    pub fn namespace_page(
        &self,
        filter: &str,
        offset: usize,
        limit: usize,
        allowed: impl Fn(&str) -> bool,
    ) -> Page<NamespaceEntry> {
        let filter = filter.to_ascii_lowercase();

        // The catalogue, not the resident map: an evicted namespace still
        // exists and must still be listed.
        let shards = self.shards.read().unwrap_or_else(PoisonError::into_inner);
        let mut names: Vec<&String> = shards
            .values()
            .flat_map(|meta| meta.namespaces.iter())
            .filter(|name| !name.starts_with(CONFIG_PREFIX) && *name != ALL_NAMESPACE)
            .filter(|name| filter.is_empty() || name.to_ascii_lowercase().contains(&filter))
            .filter(|name| allowed(name))
            .collect();
        names.sort_unstable();
        names.dedup();

        let total = names.len();
        let tiers = self.tiers.read().unwrap_or_else(PoisonError::into_inner);
        let items = names
            .into_iter()
            .skip(offset)
            .take(limit)
            .map(|name| {
                let shard = crate::persistence::shard_of(name);
                let (tier, storage) = StorageView::of(&tiers, shard);
                NamespaceEntry {
                    namespace: name.clone(),
                    shard: shard.to_string(),
                    tier,
                    resident: shards.get(shard).is_some_and(|meta| meta.resident),
                    storage,
                }
            })
            .collect();

        Page {
            items,
            total,
            offset,
        }
    }

    /// This server's name in its own counters. See [`LOCAL_NODE`].
    pub fn node(&self) -> &str {
        &self.node
    }

    /// Record a sighting counted for someone else.
    ///
    /// Used when a write was forwarded here: it is counted for the server it
    /// arrived from rather than for this one. Without that, one write fanned
    /// out to two mirrors is counted twice over — once under each mirror's own
    /// name — and merging them adds the two together.
    pub fn write_tagged_as(
        &self,
        origin: &str,
        path: &str,
        value: &str,
        when: DateTime<Utc>,
        opts: WriteOpts,
        tags: &str,
    ) -> Written {
        self.record_write(origin, path, value, when, opts, tags)
    }

    /// Whether this server stores `namespace`. See [`StoragePolicy`].
    pub fn holds(&self, namespace: &str) -> bool {
        self.stores.holds(namespace)
    }

    /// Every namespace at or under `prefix`, in order, that `allowed` permits.
    ///
    /// Namespaces are flat paths, so "under" is a prefix match on whole
    /// segments: `feeds` finds `feeds` itself and `feeds/misp/ips`, and never
    /// `feeds-internal`, which is a different namespace rather than a child.
    ///
    /// Read from the catalogue rather than the resident map, so an evicted
    /// namespace is still found — it is paged in when its values are read, not
    /// when it is listed.
    pub fn namespaces_under(&self, prefix: &str, allowed: impl Fn(&str) -> bool) -> Vec<String> {
        let prefix = prefix.trim_matches('/');
        let shards = self.shards.read().unwrap_or_else(PoisonError::into_inner);

        let mut names: Vec<String> = shards
            .values()
            .flat_map(|meta| meta.namespaces.iter())
            // Internal namespaces are the database's own. They are readable
            // one at a time — `/r/_all` is how consensus is asked for — but
            // they are not something to enumerate, or a recursive export of
            // `/` would carry every shadow sighting with it.
            .filter(|name| !is_internal(name))
            .filter(|name| {
                prefix.is_empty()
                    || name.as_str() == prefix
                    || name
                        .strip_prefix(prefix)
                        .is_some_and(|rest| rest.starts_with('/'))
            })
            .filter(|name| allowed(name))
            .cloned()
            .collect();

        names.sort_unstable();
        names.dedup();
        names
    }

    /// Declare a namespace before anything has been written to it, so the
    /// management interface can make one the way a file browser makes a folder.
    ///
    /// Returns false if it already exists. Nothing else is needed to make it
    /// last: an empty namespace is written to its shard like any other, and
    /// sweeps only reclaim namespaces they emptied themselves.
    pub fn create_namespace(&self, name: &str) -> bool {
        if self.namespace_exists(name) {
            return false;
        }
        // Held only long enough to register it; the handle must not outlive
        // this call or a sweep would take it for a namespace in use.
        drop(self.namespace_or_create(name));
        self.mark_dirty(name);
        true
    }

    /// One level of the namespace tree: what sits directly under `prefix`.
    ///
    /// Namespaces are flat paths in the database — `feeds/misp/ips` is a name,
    /// not a nesting — so the tree is derived here by grouping on the segment
    /// that follows the prefix. The same exclusions as [`Database::namespace_page`]
    /// apply, and `allowed` decides which names the caller may know about, so a
    /// folder whose whole contents are out of reach is not even listed.
    pub fn namespace_children(
        &self,
        prefix: &str,
        filter: &str,
        offset: usize,
        limit: usize,
        allowed: impl Fn(&str) -> bool,
    ) -> Page<TreeEntry> {
        let prefix = prefix.trim_matches('/');
        let filter = filter.to_ascii_lowercase();

        // (is a namespace itself, namespaces below it)
        let mut children: HashMap<&str, (bool, usize)> = HashMap::new();
        let shards = self.shards.read().unwrap_or_else(PoisonError::into_inner);
        for name in shards
            .values()
            .flat_map(|meta| meta.namespaces.iter())
            .filter(|name| !name.starts_with(CONFIG_PREFIX) && *name != ALL_NAMESPACE)
            .filter(|name| allowed(name))
        {
            let rest = if prefix.is_empty() {
                name.as_str()
            } else if let Some(rest) = name.strip_prefix(prefix).and_then(|r| r.strip_prefix('/')) {
                rest
            } else {
                // Either unrelated, or the prefix itself: neither is a child.
                continue;
            };
            let segment = rest.split('/').next().unwrap_or("");
            if segment.is_empty() {
                continue;
            }

            let entry = children.entry(segment).or_insert((false, 0));
            if segment.len() == rest.len() {
                entry.0 = true;
            } else {
                entry.1 += 1;
            }
        }

        let mut names: Vec<&str> = children
            .keys()
            .copied()
            .filter(|name| filter.is_empty() || name.to_ascii_lowercase().contains(&filter))
            .collect();
        names.sort_unstable();

        let total = names.len();
        let tiers = self.tiers.read().unwrap_or_else(PoisonError::into_inner);
        let items = names
            .into_iter()
            .skip(offset)
            .take(limit)
            .map(|name| {
                let path = if prefix.is_empty() {
                    name.to_string()
                } else {
                    format!("{prefix}/{name}")
                };
                let (is_namespace, descendants) = children[name];
                let shard = crate::persistence::shard_of(&path);
                let (tier, storage) = StorageView::of(&tiers, shard);
                TreeEntry {
                    name: name.to_string(),
                    is_namespace,
                    descendants,
                    shard: shard.to_string(),
                    tier,
                    resident: shards.get(shard).is_some_and(|meta| meta.resident),
                    storage,
                    path,
                }
            })
            .collect();

        Page {
            items,
            total,
            offset,
        }
    }

    /// Every namespace holding `value`, so the interface can draw what a value
    /// relates to rather than only where you happened to click.
    ///
    /// The cost is one lookup per namespace, so the search is arranged to do as
    /// little of it as possible. `_all` already knows how many namespaces hold
    /// the value, which gives a target to stop at; namespaces already in memory
    /// are searched first, and evicted shards are read back only if the target
    /// has not been reached by then. A value in two namespaces out of a hundred
    /// thousand therefore normally touches the disk not at all.
    ///
    /// `allowed` decides which namespaces the caller may know about, exactly as
    /// when browsing. A hidden namespace is still counted towards the target,
    /// or a scoped key would drive the search to read the whole database.
    ///
    /// `_shadow/*` is left out. It records what was *searched* for rather than
    /// what was seen, does not count towards consensus, and including it would
    /// make the result depend on where the search happened to stop.
    pub fn sightings_of(
        &self,
        value: &str,
        limit: usize,
        allowed: impl Fn(&str) -> bool,
    ) -> Sightings {
        let target = self.count(ALL_NAMESPACE, value);

        // Resident first, so the common case never goes near the disk.
        let (resident, evicted): (Vec<String>, Vec<String>) = {
            let shards = self.shards.read().unwrap_or_else(PoisonError::into_inner);
            let mut resident = Vec::new();
            let mut evicted = Vec::new();
            for meta in shards.values() {
                for name in &meta.namespaces {
                    if !counts_towards_consensus(name) {
                        continue;
                    }
                    if meta.resident {
                        resident.push(name.clone());
                    } else {
                        evicted.push(name.clone());
                    }
                }
            }
            (resident, evicted)
        };

        let mut found = Sightings::default();
        // Namespaces holding the value, visible to this caller or not, counted
        // against `target`.
        let mut seen = 0u64;

        'search: for (names, from_disk) in [(resident, false), (evicted, true)] {
            for name in names {
                // Everything is accounted for; the rest cannot hold the value.
                if target > 0 && seen >= target {
                    break 'search;
                }
                let Some(view) = self.view(&name, value, 0, false) else {
                    continue;
                };
                if from_disk {
                    found.paged_in = true;
                }
                seen += 1;
                if !allowed(&name) {
                    continue;
                }
                if found.items.len() >= limit {
                    found.truncated = true;
                    break 'search;
                }
                found.items.push(Sighting {
                    shard: crate::persistence::shard_of(&name).to_string(),
                    namespace: name,
                    count: view.count,
                    first_seen: view.first_seen,
                    last_seen: view.last_seen,
                });
            }
        }

        found.items.sort_by(|a, b| a.namespace.cmp(&b.namespace));
        found
    }

    /// Change a shard's storage settings, taking effect at once.
    ///
    /// A shard is the whole of a top-level namespace, so this covers every
    /// namespace under it. An empty entry removes the setting and the shard
    /// goes back to the configured defaults. Promoting to `hot` does not load
    /// anything: the shard is paged in when it is next used, as it would have
    /// been anyway.
    pub fn set_policy(&self, shard: &str, entry: crate::tier::Entry) {
        self.tiers
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .set(shard, entry);
    }

    /// What a shard's settings work out to.
    pub fn resolved_policy(&self, shard: &str) -> crate::tier::Resolved {
        self.tiers
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .resolve(shard)
    }

    /// What a shard will do, in a sentence, for the interface to show.
    pub fn shard_effect(&self, shard: &str) -> String {
        match self.resolved_policy(shard).idle_allowance() {
            None => format!("'{shard}' and everything under it stays in memory"),
            Some(window) if window.is_zero() => {
                format!("'{shard}' and everything under it is dropped at the next sweep once idle")
            }
            Some(window) => format!(
                "'{shard}' and everything under it is dropped after {}s untouched",
                window.as_secs()
            ),
        }
    }

    /// The current policy, for writing back to disk.
    /// The tier overrides this server holds, for offering to peers.
    ///
    /// Only the shards that name their own, since the default travels in the
    /// configuration rather than through the management interface. Each is
    /// `(shard, tier, warm_idle)` with `None` where the entry leaves it to the
    /// default.
    pub fn tier_overrides(&self) -> Vec<(String, Option<String>, Option<u64>)> {
        let tiers = self.tiers.read().unwrap_or_else(PoisonError::into_inner);
        let mut found: Vec<(String, Option<String>, Option<u64>)> = tiers
            .entries
            .iter()
            .map(|(shard, entry)| {
                (
                    shard.clone(),
                    entry.tier.map(|tier| tier.as_str().to_string()),
                    entry.warm_idle,
                )
            })
            .collect();
        // Named order, so an offer does not reshuffle between passes.
        found.sort_by(|a, b| a.0.cmp(&b.0));
        found
    }

    pub fn tier_policy(&self) -> TierPolicy {
        self.tiers
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Values inside one namespace, sorted, one page at a time.
    ///
    /// Only the page's attributes are cloned. The sort is still O(n log n) over
    /// the namespace, which is the price of stable paging over a hash map — a
    /// namespace with millions of values will feel it.
    /// How many values `namespace` holds, without walking them.
    ///
    /// Returns `None` if there is no such namespace. A resident namespace is
    /// answered from memory; an evicted one is read back in first, and says so
    /// in [`ValueCount::paged_in`] so a caller can see what the answer cost.
    pub fn value_count(&self, namespace: &str) -> Option<ValueCount> {
        // Asking about a namespace is a use of it, the same as reading one.
        self.touch(crate::persistence::shard_of(namespace));

        let (ns, paged_in) = match self.resident(namespace) {
            Some(ns) => (ns, false),
            // Not in memory: `namespace` pages the shard in, or answers None
            // if the catalogue has never heard of it.
            None => (self.namespace(namespace)?, true),
        };

        Some(ValueCount {
            values: ns.len(),
            exact: !ns.has_ttl(),
            paged_in,
        })
    }

    pub fn value_page(
        &self,
        namespace: &str,
        filter: &str,
        offset: usize,
        limit: usize,
        with_stats: bool,
    ) -> Option<Page<AttributeView>> {
        let now = Utc::now();
        let filter = filter.to_ascii_lowercase();
        let ns = self.namespace(namespace)?;
        let values = ns.values.read().unwrap_or_else(PoisonError::into_inner);

        let mut matching: Vec<&String> = values
            .iter()
            .filter(|(value, _)| filter.is_empty() || value.to_ascii_lowercase().contains(&filter))
            .filter(|(_, cell)| {
                !cell
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .is_expired(now)
            })
            .map(|(value, _)| value)
            .collect();
        matching.sort_unstable();

        let total = matching.len();
        let items: Vec<AttributeView> = matching
            .into_iter()
            .skip(offset)
            .take(limit)
            .filter_map(|value| {
                let attr = values
                    .get(value)?
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                Some(attr.view(0, with_stats))
            })
            .collect();
        drop(values);

        // Consensus comes from `_all`, so fill it in once this namespace is
        // released — see the lock-ordering note above.
        let items = items
            .into_iter()
            .map(|mut view| {
                view.consensus = self.count(ALL_NAMESPACE, &view.value);
                view
            })
            .collect();

        Some(Page {
            items,
            total,
            offset,
        })
    }

    /// Tell the database where shards live, which is what makes eviction
    /// possible: without somewhere to put a shard, it can never leave memory.
    pub fn attach_store(&self, store: Store, tiers: TierPolicy) {
        *self.store.write().unwrap_or_else(PoisonError::into_inner) = Some(store);
        *self.tiers.write().unwrap_or_else(PoisonError::into_inner) = tiers;
    }

    #[cfg(test)]
    pub fn is_shard_resident(&self, shard: &str) -> bool {
        self.shards
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(shard)
            .is_some_and(|meta| meta.resident)
    }

    /// How many shards are in memory, out of how many exist.
    pub fn residency(&self) -> (usize, usize) {
        let shards = self.shards.read().unwrap_or_else(PoisonError::into_inner);
        (shards.values().filter(|m| m.resident).count(), shards.len())
    }

    /// Read a shard back into memory.
    ///
    /// Two requests can race here; the second finds the shard already resident
    /// and does nothing rather than loading it twice.
    fn page_in(&self, shard: &str) -> anyhow::Result<()> {
        let store = self
            .store
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let Some(store) = store else {
            return Ok(());
        };

        // Held across the load so a second caller waits rather than duplicating
        // the work, and so nothing observes a half-populated shard.
        let mut namespaces = self
            .namespaces
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        {
            let shards = self.shards.read().unwrap_or_else(PoisonError::into_inner);
            if shards.get(shard).is_some_and(|meta| meta.resident) {
                return Ok(());
            }
        }

        let data = crate::persistence::read_shard_file(&store.dbdir, shard)?;
        let mut names = HashSet::new();
        for (name, values) in data {
            names.insert(name.clone());
            namespaces.insert(name, Arc::new(Namespace::from_values(values, &self.node)));
        }
        drop(namespaces);

        let mut shards = self.shards.write().unwrap_or_else(PoisonError::into_inner);
        let meta = shards.entry(shard.to_string()).or_default();
        meta.namespaces.extend(names);
        meta.resident = true;
        meta.last_access = now_secs();

        log::debug!("Paged in shard '{shard}'");
        Ok(())
    }

    /// Write out and drop shards that have been idle longer than their tier
    /// allows.
    ///
    /// A dirty shard is always saved first: dropping it otherwise would lose
    /// everything written since the last snapshot.
    pub fn evict_idle(&self, now: i64) -> EvictReport {
        let store = self
            .store
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let Some(store) = store else {
            return EvictReport::default();
        };
        let tiers = self
            .tiers
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();

        let candidates: Vec<String> = {
            let shards = self.shards.read().unwrap_or_else(PoisonError::into_inner);
            shards
                .iter()
                .filter(|(_, meta)| meta.resident)
                .filter(|(shard, meta)| match tiers.idle_allowance(shard) {
                    None => false,
                    Some(allowance) => {
                        now.saturating_sub(meta.last_access) >= allowance.as_secs() as i64
                    }
                })
                .map(|(shard, _)| shard.clone())
                .collect()
        };

        let mut report = EvictReport::default();
        for shard in candidates {
            if self
                .dirty
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .contains(&shard)
                && let Err(e) =
                    crate::persistence::save_shard(self, &store.dbdir, &shard, store.level)
            {
                // Keep it in memory rather than lose it.
                log::error!("Not evicting '{shard}': could not save it: {e:#}");
                report.failed += 1;
                continue;
            }
            self.dirty
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .remove(&shard);

            if self.drop_shard(&shard) {
                report.evicted += 1;
            } else {
                report.busy += 1;
            }
        }

        report
    }

    /// Remove a shard's namespaces from memory. Returns false if anything is
    /// still holding one, in which case it stays for the next sweep.
    fn drop_shard(&self, shard: &str) -> bool {
        let mut namespaces = self
            .namespaces
            .write()
            .unwrap_or_else(PoisonError::into_inner);

        let mine: Vec<String> = namespaces
            .keys()
            .filter(|name| crate::persistence::shard_of(name) == shard)
            .cloned()
            .collect();

        // A writer that already took an `Arc` would otherwise record its
        // sighting into an orphan and lose it.
        if mine.iter().any(|name| {
            namespaces
                .get(name)
                .is_some_and(|ns| Arc::strong_count(ns) > 1)
        }) {
            return false;
        }
        for name in &mine {
            namespaces.remove(name);
        }
        drop(namespaces);

        if let Some(meta) = self
            .shards
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .get_mut(shard)
        {
            meta.resident = false;
        }
        log::debug!("Evicted shard '{shard}'");
        true
    }

    fn release_consensus(&self, value: &str) {
        if let Some(all) = self.namespace(ALL_NAMESPACE) {
            all.release(&self.node, value);
        }
    }

    /// Reclaim the namespaces a sweep has just emptied.
    ///
    /// Only those are candidates. An empty namespace is not litter by itself:
    /// one created through the management interface exists before anything is
    /// written to it, the way a new directory does, and must survive until it
    /// is deleted.
    fn prune_empty(&self, emptied: &[String]) -> usize {
        if emptied.is_empty() {
            return 0;
        }

        let mut removed: Vec<&str> = Vec::new();
        {
            let mut map = self
                .namespaces
                .write()
                .unwrap_or_else(PoisonError::into_inner);
            for name in emptied {
                if name.starts_with(CONFIG_PREFIX) {
                    continue;
                }
                // Only drop a namespace nobody else is holding: a writer that
                // already took an `Arc` would otherwise record its sighting into
                // an orphaned namespace and lose it. A write between the sweep
                // and here leaves it non-empty again, so check that too.
                let gone = map.get(name).is_some_and(|namespace| {
                    Arc::strong_count(namespace) == 1 && namespace.is_empty()
                });
                if gone {
                    map.remove(name);
                    removed.push(name);
                }
            }
        }

        if !removed.is_empty() {
            let mut shards = self.shards.write().unwrap_or_else(PoisonError::into_inner);
            for name in &removed {
                if let Some(meta) = shards.get_mut(crate::persistence::shard_of(name)) {
                    meta.namespaces.remove(*name);
                }
            }
        }
        removed.len()
    }

    /// Fetch a namespace, paging its shard in from disk if it has been evicted.
    fn namespace(&self, name: &str) -> Option<Arc<Namespace>> {
        let shard = crate::persistence::shard_of(name);
        self.touch(shard);

        if let Some(namespace) = self.resident(name) {
            return Some(namespace);
        }
        // Only worth going to disk if the catalogue says this shard holds it.
        if !self.catalogued(shard, name) {
            return None;
        }
        if let Err(e) = self.page_in(shard) {
            log::error!("Could not load shard '{shard}': {e:#}");
            return None;
        }
        self.resident(name)
    }

    fn resident(&self, name: &str) -> Option<Arc<Namespace>> {
        self.namespaces
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(name)
            .cloned()
    }

    fn catalogued(&self, shard: &str, name: &str) -> bool {
        self.shards
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(shard)
            .is_some_and(|meta| !meta.resident && meta.namespaces.contains(name))
    }

    fn namespace_or_create(&self, name: &str) -> Arc<Namespace> {
        if let Some(namespace) = self.namespace(name) {
            return namespace;
        }

        // The shard may exist on disk with other namespaces in it. Registering
        // a namespace marks its shard resident, so the rest of the shard has to
        // be back in memory first: otherwise everything else in it would read
        // as missing, and the next snapshot would write the shard out without
        // it. Only a namespace that is genuinely new gets here — an existing
        // one was paged in by `namespace` above.
        let shard = crate::persistence::shard_of(name);
        let evicted = self
            .shards
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(shard)
            .is_some_and(|meta| !meta.resident);
        if evicted && let Err(e) = self.page_in(shard) {
            // Nothing here can recover it; refusing to create the namespace
            // would only lose the write as well.
            log::error!("Could not load shard '{shard}' before extending it: {e:#}");
        }

        let namespace = self
            .namespaces
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .entry(name.to_string())
            .or_default()
            .clone();
        self.record(name);
        namespace
    }

    /// Note a namespace in the catalogue and mark its shard resident.
    fn record(&self, name: &str) {
        let shard = crate::persistence::shard_of(name);
        let mut shards = self.shards.write().unwrap_or_else(PoisonError::into_inner);
        let meta = shards.entry(shard.to_string()).or_default();
        meta.namespaces.insert(name.to_string());
        meta.resident = true;
        meta.last_access = now_secs();
    }

    fn touch(&self, shard: &str) {
        if let Some(meta) = self
            .shards
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .get_mut(shard)
        {
            meta.last_access = now_secs();
        }
    }
}

/// Whether a namespace is one of ours: the `_all` tally, `_shadow/*`, or
/// `_config`.
///
/// Decided on the first path segment, which is the same rule
/// [`crate::persistence::shard_of`] uses to send these to the internal shard,
/// so "internal" means one thing throughout. `foo/_bar` is therefore an
/// ordinary namespace — the underscore only counts at the front.
///
/// These are written by the database about itself: `_all` by the consensus
/// bookkeeping in [`Database::write_tagged`], `_shadow/*` by reads. Letting a
/// client write them would let it state a consensus the data does not support,
/// so every write path over HTTP refuses them. Reading is another matter and
/// stays allowed, apart from `_config`: `/r/_all` is how consensus is asked
/// for, and `/r/_shadow/<ns>` is how searches are reviewed.
pub fn is_internal(namespace: &str) -> bool {
    namespace
        .split('/')
        .find(|segment| !segment.is_empty())
        .is_some_and(|first| first.starts_with('_'))
}

/// Namespaces whose values were counted towards consensus when written, and so
/// must give that count back when they go away.
fn now_secs() -> i64 {
    Utc::now().timestamp()
}

pub fn counts_towards_consensus(name: &str) -> bool {
    name != ALL_NAMESPACE && !name.starts_with(SHADOW_PREFIX) && !name.starts_with(CONFIG_PREFIX)
}

// ---------------------------------------------------------------------------
// Snapshots
// ---------------------------------------------------------------------------

/// Owned form of a snapshot, used when loading from disk.
#[derive(Debug, Deserialize)]
pub struct SnapshotData {
    pub version: u32,
    pub namespaces: HashMap<String, HashMap<String, Attribute>>,
}

/// Owned form of one shard, which has the same shape as a whole snapshot.
pub type ShardData = SnapshotData;

#[cfg(test)]
pub struct Snapshot<'a>(&'a Database);

/// One shard, serialized in the same shape as a full snapshot so that either
/// can be read by the same code.
pub struct ShardSnapshot<'a>(&'a Database, &'a str);

impl Serialize for ShardSnapshot<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut out = serializer.serialize_struct("Snapshot", 2)?;
        out.serialize_field("version", &SNAPSHOT_VERSION)?;
        out.serialize_field("namespaces", &NamespacesRef(self.0, Some(self.1)))?;
        out.end()
    }
}

#[cfg(test)]
impl Serialize for Snapshot<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut out = serializer.serialize_struct("Snapshot", 2)?;
        out.serialize_field("version", &SNAPSHOT_VERSION)?;
        out.serialize_field("namespaces", &NamespacesRef(self.0, None))?;
        out.end()
    }
}

/// All namespaces, or only those in one shard.
struct NamespacesRef<'a>(&'a Database, Option<&'a str>);

impl Serialize for NamespacesRef<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;

        // Only the names are copied up front; each namespace is locked, written
        // and released in turn.
        let entries: Vec<(String, Arc<Namespace>)> = {
            let map = self
                .0
                .namespaces
                .read()
                .unwrap_or_else(PoisonError::into_inner);
            map.iter()
                .filter(|(name, _)| {
                    self.1
                        .is_none_or(|shard| crate::persistence::shard_of(name) == shard)
                })
                .map(|(name, namespace)| (name.clone(), Arc::clone(namespace)))
                .collect()
        };

        let mut out = serializer.serialize_map(Some(entries.len()))?;
        for (name, namespace) in &entries {
            out.serialize_entry(name, &NamespaceRef(namespace))?;
        }
        out.end()
    }
}

struct NamespaceRef<'a>(&'a Namespace);

impl Serialize for NamespaceRef<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;

        let values = self.0.values.read().unwrap_or_else(PoisonError::into_inner);

        let mut out = serializer.serialize_map(Some(values.len()))?;
        for (value, cell) in values.iter() {
            let attr = cell.lock().unwrap_or_else(PoisonError::into_inner);
            out.serialize_entry(value, &*attr)?;
        }
        out.end()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(secs, 0).expect("timestamp in range")
    }

    /// Listings carry the shard and tier now; most tests only care about names.
    fn names(page: &Page<NamespaceEntry>) -> Vec<&str> {
        page.items.iter().map(|e| e.namespace.as_str()).collect()
    }

    fn consensus() -> WriteOpts {
        WriteOpts {
            consensus: true,
            ttl: None,
        }
    }

    fn with_ttl(ttl: u64) -> WriteOpts {
        WriteOpts {
            consensus: true,
            ttl: Some(ttl),
        }
    }

    #[test]
    fn write_returns_the_running_count() {
        let db = Database::default();

        assert_eq!(db.write("ns", "1.2.3.4", at(100), consensus()), 1);
        assert_eq!(db.write("ns", "1.2.3.4", at(200), consensus()), 2);
        assert_eq!(db.count("ns", "1.2.3.4"), 2);
    }

    #[test]
    fn consensus_counts_namespaces_not_writes() {
        let db = Database::default();

        db.write("my/namespace", "127.0.0.1", at(100), consensus());
        db.write("another/namespace", "127.0.0.1", at(200), consensus());
        db.write("another/namespace", "127.0.0.1", at(300), consensus());

        assert_eq!(db.count(ALL_NAMESPACE, "127.0.0.1"), 2);
    }

    #[test]
    fn a_new_value_in_an_existing_namespace_still_counts_for_consensus() {
        let db = Database::default();

        db.write("ns", "a", at(100), consensus());
        db.write("ns", "b", at(100), consensus());

        assert_eq!(db.count(ALL_NAMESPACE, "b"), 1);
    }

    #[test]
    fn writes_without_consensus_leave_all_alone() {
        let db = Database::default();

        db.write("ns", "a", at(100), WriteOpts::default());

        assert_eq!(db.count(ALL_NAMESPACE, "a"), 0);
    }

    #[test]
    fn missing_lookups_are_zero_and_none() {
        let db = Database::default();

        assert_eq!(db.count("nope", "nope"), 0);
        assert!(db.view("nope", "nope", 0, false).is_none());
        assert!(!db.namespace_exists("nope"));
        assert!(db.namespace_views("nope").is_none());
    }

    /// Older builds kept API keys as namespaces. We no longer write them, but
    /// we must still recognise them in a restored snapshot.
    #[test]
    fn legacy_apikeys_are_recovered_from_old_snapshots() {
        let db = Database::default();
        assert!(db.legacy_apikeys().is_empty());

        db.write(
            &format!("{APIKEYS_NAMESPACE}{DEFAULT_APIKEY}"),
            "",
            at(100),
            WriteOpts::default(),
        );
        db.write(
            &format!("{APIKEYS_NAMESPACE}secret"),
            "",
            at(100),
            WriteOpts::default(),
        );

        let mut keys = db.legacy_apikeys();
        keys.sort();
        assert_eq!(keys, [DEFAULT_APIKEY, "secret"]);
    }

    #[test]
    fn a_fresh_database_stores_no_keys() {
        let db = Database::new();
        assert!(db.legacy_apikeys().is_empty());
    }

    // -- delete ------------------------------------------------------------

    #[test]
    fn delete_removes_the_namespace_once() {
        let db = Database::default();
        db.write("ns", "a", at(100), consensus());

        assert!(db.delete("ns"));
        assert!(!db.delete("ns"));
        assert!(!db.namespace_exists("ns"));
    }

    #[test]
    fn delete_gives_back_the_consensus_it_was_holding() {
        let db = Database::default();
        db.write("a/ns", "v", at(100), consensus());
        db.write("b/ns", "v", at(100), consensus());
        assert_eq!(db.count(ALL_NAMESPACE, "v"), 2);

        db.delete("a/ns");
        assert_eq!(db.count(ALL_NAMESPACE, "v"), 1);

        // The last holder going away retires the `_all` entry entirely.
        db.delete("b/ns");
        assert_eq!(db.count(ALL_NAMESPACE, "v"), 0);
    }

    // -- TTL ---------------------------------------------------------------

    #[test]
    fn an_expired_attribute_is_invisible_before_it_is_swept() {
        let db = Database::default();
        // Written in 1970 with a one minute TTL, so it is long expired by now.
        db.write("ns", "v", at(1000), with_ttl(60));

        assert!(db.view("ns", "v", 0, false).is_none());
        assert_eq!(db.count("ns", "v"), 0);
        assert_eq!(db.namespace_views("ns").unwrap().len(), 0);
    }

    #[test]
    fn a_live_attribute_reports_its_ttl() {
        let db = Database::default();
        db.write("ns", "v", Utc::now(), with_ttl(3600));

        let view = db.view("ns", "v", 0, false).unwrap();
        assert_eq!(view.ttl, 3600);
    }

    #[test]
    fn writing_again_without_a_ttl_keeps_the_existing_one() {
        let db = Database::default();
        db.write("ns", "v", Utc::now(), with_ttl(3600));
        db.write("ns", "v", Utc::now(), consensus());

        assert_eq!(db.view("ns", "v", 0, false).unwrap().ttl, 3600);
    }

    #[test]
    fn sweeping_reclaims_expired_values_and_their_consensus() {
        let db = Database::default();
        db.write("a/ns", "v", at(1000), with_ttl(60));
        db.write("b/ns", "v", at(1000), consensus());
        assert_eq!(db.count(ALL_NAMESPACE, "v"), 2);

        let report = db.sweep(Utc::now());

        assert_eq!(report.values_removed, 1);
        assert_eq!(report.namespaces_removed, 1); // a/ns is now empty
        assert!(!db.namespace_exists("a/ns"));
        assert!(db.namespace_exists("b/ns"));
        // b/ns still holds the value, so consensus drops to one rather than zero.
        assert_eq!(db.count(ALL_NAMESPACE, "v"), 1);
    }

    /// A namespace made in advance holds nothing, and holding nothing is not a
    /// reason to reclaim it: it is a folder someone created, not litter.
    #[test]
    fn a_created_namespace_is_empty_and_survives_a_sweep() {
        let db = Database::default();

        assert!(db.create_namespace("feeds/domains"));
        // Already there, so making it again changes nothing.
        assert!(!db.create_namespace("feeds/domains"));

        assert!(db.namespace_exists("feeds/domains"));
        assert_eq!(
            db.value_page("feeds/domains", "", 0, 10, false)
                .unwrap()
                .total,
            0
        );

        assert_eq!(db.sweep(Utc::now()), SweepReport::default());
        assert!(db.namespace_exists("feeds/domains"));
    }

    /// Namespaces are flat paths; the tree is grouped out of them by segment.
    #[test]
    fn the_tree_groups_namespaces_by_segment() {
        let db = Database::default();
        for namespace in ["feeds", "feeds/misp/ips", "feeds/misp/domains", "other/x"] {
            db.write(namespace, "v", at(100), WriteOpts::default());
        }

        let root = db.namespace_children("", "", 0, 10, |_| true);
        assert_eq!(root.total, 2);
        // `feeds` holds values of its own *and* has namespaces under it.
        assert_eq!(root.items[0].name, "feeds");
        assert_eq!(root.items[0].path, "feeds");
        assert!(root.items[0].is_namespace);
        assert_eq!(root.items[0].descendants, 2);
        assert_eq!(root.items[1].name, "other");
        assert!(!root.items[1].is_namespace);

        // A level in, `misp` is a folder holding two namespaces.
        let feeds = db.namespace_children("feeds", "", 0, 10, |_| true);
        assert_eq!(feeds.total, 1);
        assert_eq!(feeds.items[0].path, "feeds/misp");
        assert!(!feeds.items[0].is_namespace);
        assert_eq!(feeds.items[0].descendants, 2);

        let misp = db.namespace_children("feeds/misp", "", 0, 10, |_| true);
        assert_eq!(
            misp.items
                .iter()
                .map(|e| e.name.as_str())
                .collect::<Vec<_>>(),
            ["domains", "ips"]
        );
        // A leaf has nothing under it.
        assert_eq!(
            db.namespace_children("other/x", "", 0, 10, |_| true).total,
            0
        );
    }

    #[test]
    fn the_tree_filters_pages_and_respects_permission() {
        let db = Database::default();
        for namespace in ["a/one", "a/two", "b/three"] {
            db.write(namespace, "v", at(100), consensus());
        }

        // Bookkeeping namespaces are left out, as they are of the flat listing.
        assert!(db.namespace_exists(ALL_NAMESPACE));
        let root = db.namespace_children("", "", 0, 10, |_| true);
        assert_eq!(
            root.items
                .iter()
                .map(|e| e.name.as_str())
                .collect::<Vec<_>>(),
            ["a", "b"]
        );

        let page = db.namespace_children("a", "", 1, 1, |_| true);
        assert_eq!(page.total, 2);
        assert_eq!(page.items[0].name, "two");

        let filtered = db.namespace_children("a", "ON", 0, 10, |_| true);
        assert_eq!(filtered.items.len(), 1);
        assert_eq!(filtered.items[0].name, "one");

        // A folder whose whole contents are out of reach is not listed at all.
        let scoped = db.namespace_children("", "", 0, 10, |name| name.starts_with("a"));
        assert_eq!(scoped.total, 1);
        assert_eq!(scoped.items[0].name, "a");
    }

    #[test]
    fn a_value_reports_every_namespace_holding_it() {
        let db = Database::default();
        for namespace in ["feeds/misp/ips", "feeds/otx/ips", "internal/allowlist"] {
            db.write(namespace, "1.2.3.4", at(100), consensus());
        }
        db.write("feeds/misp/ips", "1.2.3.4", at(200), consensus());
        db.write("feeds/misp/ips", "9.9.9.9", at(100), consensus());

        let found = db.sightings_of("1.2.3.4", 100, |_| true);
        assert_eq!(
            found
                .items
                .iter()
                .map(|s| s.namespace.as_str())
                .collect::<Vec<_>>(),
            ["feeds/misp/ips", "feeds/otx/ips", "internal/allowlist"]
        );
        // The count is per namespace, which is what sizes a node.
        assert_eq!(found.items[0].count, 2);
        assert_eq!(found.items[0].shard, "feeds");
        assert_eq!(found.items[1].count, 1);
        assert!(!found.truncated);
        assert!(!found.paged_in);

        // A value nobody has seen relates to nothing.
        assert!(db.sightings_of("nope", 100, |_| true).items.is_empty());
    }

    /// The same rule as browsing: a scoped key is told about its own subtree
    /// and nothing else.
    #[test]
    fn sightings_leave_out_namespaces_the_caller_cannot_read() {
        let db = Database::default();
        for namespace in ["feeds/ips", "private/ips"] {
            db.write(namespace, "1.2.3.4", at(100), consensus());
        }

        let found = db.sightings_of("1.2.3.4", 100, |name| name.starts_with("feeds"));
        assert_eq!(found.items.len(), 1);
        assert_eq!(found.items[0].namespace, "feeds/ips");
    }

    #[test]
    fn a_value_in_too_many_namespaces_is_cut_off() {
        let db = Database::default();
        for i in 0..5 {
            db.write(&format!("feeds/{i}"), "1.2.3.4", at(100), consensus());
        }

        let found = db.sightings_of("1.2.3.4", 2, |_| true);
        assert_eq!(found.items.len(), 2);
        assert!(found.truncated);
    }

    /// The count must not grow more expensive as the namespace does — that is
    /// the whole reason it reads the map's length instead of walking it.
    ///
    /// A timing test rather than an assertion about the code, because the
    /// property that matters is the cost, and a later change could reintroduce
    /// a walk without changing any of the values this returns.
    #[test]
    fn storing_everything_is_the_default_and_holds_anything() {
        let policy = StoragePolicy::default();

        assert!(policy.stores_everything());
        assert!(!policy.is_router());
        for namespace in ["feeds", "feeds/misp/ips", "anything", "_all"] {
            assert!(policy.holds(namespace), "{namespace}");
        }
    }

    /// `/` anywhere in the list means the whole tree, because a prefix that
    /// covers the root covers everything under it.
    #[test]
    fn a_root_prefix_means_everything() {
        for list in [vec!["/"], vec![""], vec!["feeds", "/"]] {
            let policy = StoragePolicy::from_prefixes(&list);
            assert!(policy.stores_everything(), "{list:?}");
            assert!(policy.holds("anything/at/all"), "{list:?}");
        }
    }

    /// Prefixes match whole segments, so a namespace that merely shares
    /// leading characters is not held.
    #[test]
    fn a_narrowed_policy_holds_its_subtrees_and_nothing_beside_them() {
        let policy = StoragePolicy::from_prefixes(["feeds", "threats/apt"]);

        assert!(!policy.stores_everything());
        assert!(!policy.is_router());

        for held in ["feeds", "feeds/misp/ips", "threats/apt", "threats/apt/x"] {
            assert!(policy.holds(held), "{held} should be held");
        }
        for not in ["feeds-internal", "threats", "threats/apt-other", "other"] {
            assert!(!policy.holds(not), "{not} should not be held");
        }
    }

    /// A router stores no ordinary namespace — but still its own internal
    /// ones, because it cannot keep a consensus tally otherwise, and that
    /// tally is the whole reason to put one in front of a galaxy.
    #[test]
    fn a_router_stores_nothing_but_the_internal_namespaces() {
        let policy = StoragePolicy::from_prefixes(Vec::<String>::new());

        assert!(policy.is_router());
        assert!(!policy.stores_everything());

        assert!(!policy.holds("feeds"));
        assert!(!policy.holds("anything"));

        for internal in ["_all", "_shadow/feeds/ips", "_config/acl/apikeys/x"] {
            assert!(policy.holds(internal), "{internal} must stay held");
        }
    }

    /// Internal namespaces are held whatever the policy says, so a narrowed
    /// server still counts consensus for what it does hold.
    #[test]
    fn a_narrowed_database_still_keeps_its_own_consensus() {
        let db = Database::with_storage(
            DatabasePolicy::default(),
            StoragePolicy::from_prefixes(["feeds"]),
        );

        assert!(db.holds("feeds/a"));
        assert!(!db.holds("other"));
        assert!(db.holds(ALL_NAMESPACE));

        db.write(
            "feeds/a",
            "1.2.3.4",
            Utc::now(),
            WriteOpts {
                consensus: true,
                ttl: None,
            },
        );
        db.write(
            "feeds/b",
            "1.2.3.4",
            Utc::now(),
            WriteOpts {
                consensus: true,
                ttl: None,
            },
        );
        assert_eq!(db.count(ALL_NAMESPACE, "1.2.3.4"), 2);
    }

    #[test]
    fn counting_does_not_get_slower_as_a_namespace_grows() {
        let db = Database::default();

        for n in 0..1_000 {
            db.write("small", &format!("v{n}"), Utc::now(), WriteOpts::default());
        }
        for n in 0..200_000 {
            db.write("big", &format!("v{n}"), Utc::now(), WriteOpts::default());
        }

        assert_eq!(db.value_count("small").unwrap().values, 1_000);
        assert_eq!(db.value_count("big").unwrap().values, 200_000);

        // Warm both paths before timing either.
        for _ in 0..100 {
            db.value_count("small");
            db.value_count("big");
        }

        let small = {
            let at = std::time::Instant::now();
            for _ in 0..1_000 {
                std::hint::black_box(db.value_count("small"));
            }
            at.elapsed()
        };
        let big = {
            let at = std::time::Instant::now();
            for _ in 0..1_000 {
                std::hint::black_box(db.value_count("big"));
            }
            at.elapsed()
        };

        // 200x the values. A walk would show it plainly; the generous bound is
        // there so that a loaded machine cannot fail this spuriously.
        assert!(
            big < small * 10,
            "counting 200000 values took {big:?} against {small:?} for 1000 — \
             this looks like a walk, not a length"
        );
    }

    #[test]
    fn sweeping_leaves_live_data_alone() {
        let db = Database::default();
        db.write("ns", "forever", at(1000), consensus());
        db.write("ns", "later", Utc::now(), with_ttl(3600));

        assert_eq!(db.sweep(Utc::now()), SweepReport::default());
        assert_eq!(db.namespace_views("ns").unwrap().len(), 2);
    }

    /// A legacy key namespace has no TTL, but the sweeper skips the whole
    /// `_config` tree anyway rather than relying on that.
    #[test]
    fn sweeping_never_touches_api_keys() {
        let db = Database::default();
        let namespace = format!("{APIKEYS_NAMESPACE}{DEFAULT_APIKEY}");
        db.write(&namespace, "", at(100), WriteOpts::default());

        db.sweep(Utc::now());

        assert!(db.namespace_exists(&namespace));
        assert_eq!(db.legacy_apikeys(), [DEFAULT_APIKEY]);
    }

    #[test]
    fn shadow_sightings_inherit_the_policy_ttl() {
        let db = Database::with_policy(DatabasePolicy {
            stats_retention: 0,
            shadow_ttl: 60,
        });
        db.write("_shadow/ns", "v", at(1000), WriteOpts::default());

        // Expired by policy, without the caller asking for a TTL.
        assert_eq!(db.count("_shadow/ns", "v"), 0);
        assert_eq!(db.sweep(Utc::now()).values_removed, 1);
    }

    #[test]
    fn the_policy_ttl_does_not_leak_into_ordinary_namespaces() {
        let db = Database::with_policy(DatabasePolicy {
            stats_retention: 0,
            shadow_ttl: 60,
        });
        db.write("ns", "v", at(1000), consensus());

        assert_eq!(db.count("ns", "v"), 1);
    }

    #[test]
    fn stats_retention_is_applied_on_write() {
        let db = Database::with_policy(DatabasePolicy {
            stats_retention: 2,
            shadow_ttl: 0,
        });
        for hour in 0..5 {
            db.write("ns", "v", at(hour * 3600), consensus());
        }

        let view = db.view("ns", "v", 0, true).unwrap();
        assert_eq!(view.stats.unwrap().len(), 2);
        assert_eq!(view.count, 5);
    }

    // -- snapshots ---------------------------------------------------------

    #[test]
    fn a_snapshot_round_trips() {
        let db = Database::new();
        db.write("my/ns", "1.2.3.4", at(1_600_000_000), consensus());
        db.write("my/ns", "1.2.3.4", at(1_600_003_600), consensus());
        db.write("other/ns", "1.2.3.4", at(1_600_000_000), with_ttl(99));

        let json = serde_json::to_string(&db.snapshot()).unwrap();
        let data: SnapshotData = serde_json::from_str(&json).unwrap();
        assert_eq!(data.version, SNAPSHOT_VERSION);

        let restored = Database::from_snapshot(data, DatabasePolicy::default());

        assert_eq!(restored.count("my/ns", "1.2.3.4"), 2);
        assert_eq!(restored.count(ALL_NAMESPACE, "1.2.3.4"), 2);

        let view = restored.view("my/ns", "1.2.3.4", 0, true).unwrap();
        assert_eq!(view.first_seen, 1_600_000_000);
        assert_eq!(view.last_seen, 1_600_003_600);
        assert_eq!(view.stats.unwrap().len(), 2);
    }

    #[test]
    fn a_restored_database_still_knows_about_ttls() {
        let db = Database::new();
        db.write("ns", "v", at(1000), with_ttl(60));

        let json = serde_json::to_string(&db.snapshot()).unwrap();
        let restored = Database::from_snapshot(
            serde_json::from_str(&json).unwrap(),
            DatabasePolicy::default(),
        );

        // `has_ttl` must survive the round trip, or the sweeper would skip this.
        assert_eq!(restored.sweep(Utc::now()).values_removed, 1);
    }

    /// A version 1 snapshot must open, and its totals must become this
    /// server's own contribution.
    ///
    /// This is the one migration that cannot be got wrong: a build that
    /// refused the previous format would look exactly like total data loss,
    /// and the next save would make it so.
    #[test]
    fn a_version_one_snapshot_is_migrated_on_load() {
        // Written by hand in the old shape: one `count`, one flat `stats`.
        let old = serde_json::json!({
            "version": 1,
            "namespaces": {
                "feeds/ips": {
                    "1.2.3.4": {
                        "value": "1.2.3.4",
                        "first_seen": 1_600_000_000,
                        "last_seen": 1_600_003_600,
                        "count": 7,
                        "tags": "tlp:amber",
                        "ttl": 0,
                        "stats": { "1600000000": 3, "1600003600": 4 }
                    }
                }
            }
        });

        let data: SnapshotData = serde_json::from_value(old).unwrap();
        let db = Database::from_snapshot_as(
            data,
            DatabasePolicy::default(),
            StoragePolicy::everything(),
            "node-a".to_string(),
        );

        let view = db.view("feeds/ips", "1.2.3.4", 0, true).unwrap();

        // The total survived, and the window and tags with it.
        assert_eq!(view.count, 7, "the count was lost in migration");
        assert_eq!(view.first_seen, 1_600_000_000);
        assert_eq!(view.last_seen, 1_600_003_600);
        assert_eq!(view.tags, "tlp:amber");

        // The buckets survived, merged as a reader sees them.
        let stats = view.stats.unwrap();
        assert_eq!(stats.get(&1_600_000_000), Some(&3));
        assert_eq!(stats.get(&1_600_003_600), Some(&4));

        // And it is attributed to the server that read it, which is the only
        // server that could have written it.
        let next = db.write("feeds/ips", "1.2.3.4", Utc::now(), WriteOpts::default());
        assert_eq!(next, 8, "the migrated total was not added to");
    }

    /// Writing a snapshot and reading it back must not change any count — the
    /// round trip is where a per-node map could quietly collapse.
    #[test]
    fn counts_survive_a_round_trip_under_their_own_node() {
        let db = Database::with_node(
            DatabasePolicy::default(),
            StoragePolicy::everything(),
            "node-a".to_string(),
        );
        for _ in 0..3 {
            db.write("feeds/ips", "1.2.3.4", Utc::now(), WriteOpts::default());
        }

        let json = serde_json::to_string(&db.snapshot()).unwrap();
        // The new shape is what is written: a map, not a total.
        assert!(json.contains("\"counts\""), "{json}");
        assert!(json.contains("node-a"), "{json}");
        assert!(
            !json.contains("\"count\":"),
            "a legacy total was written back out: {json}"
        );

        let restored = Database::from_snapshot_as(
            serde_json::from_str(&json).unwrap(),
            DatabasePolicy::default(),
            StoragePolicy::everything(),
            "node-a".to_string(),
        );
        assert_eq!(restored.count("feeds/ips", "1.2.3.4"), 3);
    }

    /// Two servers' contributions add up, and merging the same contribution
    /// twice changes nothing. This is the property the whole change exists for.
    #[test]
    fn contributions_from_two_nodes_sum_and_are_idempotent() {
        let mut attr = crate::attribute::Attribute::new("1.2.3.4");
        for _ in 0..3 {
            attr.increment("node-a", Utc::now(), 0);
        }
        for _ in 0..2 {
            attr.increment("node-b", Utc::now(), 0);
        }
        assert_eq!(attr.count(), 5);

        // What a merge does: take a peer's entry wholesale. Applying it again
        // is a no-op, which is what makes sync safe to retry.
        let peer = attr.counts.get("node-b").copied().unwrap();
        attr.counts.insert("node-b".to_string(), peer);
        assert_eq!(
            attr.count(),
            5,
            "re-applying a peer's entry changed the sum"
        );
        attr.counts.insert("node-b".to_string(), peer);
        assert_eq!(attr.count(), 5);
    }

    /// A server gives back only what it put in. Releasing consensus must not
    /// spend a peer's contribution.
    #[test]
    fn releasing_takes_from_this_nodes_own_entry_only() {
        let mut attr = crate::attribute::Attribute::new("1.2.3.4");
        attr.increment("node-a", Utc::now(), 0);
        attr.increment("node-b", Utc::now(), 0);
        assert_eq!(attr.count(), 2);

        assert_eq!(attr.decrement("node-a"), 1);
        assert_eq!(
            attr.counts.get("node-b").copied(),
            Some(1),
            "a peer's contribution was spent"
        );
        // Nothing left of its own, so it stops appearing as a contributor.
        assert!(!attr.counts.contains_key("node-a"));

        // And a server with nothing to give back cannot go negative.
        assert_eq!(attr.decrement("node-a"), 1);
    }

    /// A survey of who holds what puts the tally right — including downward,
    /// which is the whole reason it exists: a tally kept by counting forwarded
    /// writes only ever rises.
    #[test]
    fn set_consensus_corrects_a_tally_in_both_directions() {
        use std::collections::{BTreeSet, HashMap};

        let db = Database::with_node(
            DatabasePolicy::default(),
            StoragePolicy::everything(),
            "lb".to_string(),
        );

        // A tally as a router would have built it: three writes said "new",
        // so it believes three namespaces hold this.
        for _ in 0..3 {
            db.write(ALL_NAMESPACE, "1.2.3.4", Utc::now(), WriteOpts::default());
        }
        db.write(
            ALL_NAMESPACE,
            "gone-everywhere",
            Utc::now(),
            WriteOpts::default(),
        );
        assert_eq!(db.count(ALL_NAMESPACE, "1.2.3.4"), 3);

        // The survey finds it in two, and does not find the other at all.
        let mut holders: HashMap<String, BTreeSet<String>> = HashMap::new();
        holders.insert(
            "1.2.3.4".to_string(),
            ["feeds/a", "feeds/b"]
                .iter()
                .map(|n| n.to_string())
                .collect(),
        );
        holders.insert(
            "new-to-us".to_string(),
            ["feeds/c"].iter().map(|n| n.to_string()).collect(),
        );

        let corrected = db.set_consensus(&holders);

        assert_eq!(
            db.count(ALL_NAMESPACE, "1.2.3.4"),
            2,
            "the tally did not come down"
        );
        assert_eq!(
            db.count(ALL_NAMESPACE, "gone-everywhere"),
            0,
            "a value the survey never saw kept its tally"
        );
        assert_eq!(db.count(ALL_NAMESPACE, "new-to-us"), 1);
        assert_eq!(corrected, 3, "wrong number reported as corrected");

        // And again changes nothing, so a reconciliation on a timer is quiet
        // once it agrees.
        assert_eq!(db.set_consensus(&holders), 0);
    }

    /// The same namespace mirrored several times is still one namespace. A set
    /// is what makes that true; a sum would be the double counting the whole
    /// design exists to avoid.
    #[test]
    fn set_consensus_counts_namespaces_not_mirrors() {
        use std::collections::{BTreeSet, HashMap};

        let db = Database::with_node(
            DatabasePolicy::default(),
            StoragePolicy::everything(),
            "lb".to_string(),
        );

        let mut holders: HashMap<String, BTreeSet<String>> = HashMap::new();
        // Surveyed from three mirrors, all holding the same two namespaces.
        let mut found = BTreeSet::new();
        for _ in 0..3 {
            found.insert("feeds/a".to_string());
            found.insert("feeds/b".to_string());
        }
        holders.insert("1.2.3.4".to_string(), found);

        db.set_consensus(&holders);
        assert_eq!(db.count(ALL_NAMESPACE, "1.2.3.4"), 2);
    }

    #[test]
    fn an_empty_database_snapshots_cleanly() {
        let db = Database::default();
        let json = serde_json::to_string(&db.snapshot()).unwrap();

        // Pinned literally: the version in a written snapshot is a contract
        // with every build that will read it.
        assert_eq!(
            json,
            format!(r#"{{"version":{SNAPSHOT_VERSION},"namespaces":{{}}}}"#)
        );
    }

    // -- paging ------------------------------------------------------------

    #[test]
    fn namespaces_page_in_sorted_order() {
        let db = Database::default();
        for name in ["c/ns", "a/ns", "b/ns"] {
            db.write(name, "v", at(100), consensus());
        }

        let first = db.namespace_page("", 0, 2, |_| true);
        assert_eq!(names(&first), ["a/ns", "b/ns"]);
        // `total` counts matches, not the page, so a UI knows how far it can go.
        assert_eq!(first.total, 3);
        assert_eq!(first.offset, 0);

        let second = db.namespace_page("", 2, 2, |_| true);
        assert_eq!(names(&second), ["c/ns"]);
    }

    #[test]
    fn namespaces_can_be_filtered() {
        let db = Database::default();
        db.write("feeds/misp", "v", at(100), consensus());
        db.write("feeds/otx", "v", at(100), consensus());
        db.write("internal/notes", "v", at(100), consensus());

        let page = db.namespace_page("feeds", 0, 10, |_| true);
        assert_eq!(names(&page), ["feeds/misp", "feeds/otx"]);
        assert_eq!(page.total, 2);
    }

    /// The admin interface browses data, so server state must not show up in it.
    #[test]
    fn the_config_tree_is_not_listed() {
        let db = Database::default();
        db.write(
            "_config/acl/apikeys/changeme",
            "",
            at(100),
            WriteOpts::default(),
        );
        db.write("ns", "v", at(100), consensus());

        let page = db.namespace_page("", 0, 100, |_| true);
        assert!(!names(&page).iter().any(|n| n.starts_with("_config")));
        // `_all` is a consensus tally, not something to browse.
        assert!(!names(&page).contains(&ALL_NAMESPACE));
        assert_eq!(names(&page), ["ns"]);
    }

    #[test]
    fn values_page_in_sorted_order_with_a_total() {
        let db = Database::default();
        for value in ["ccc", "aaa", "bbb", "ddd"] {
            db.write("ns", value, at(100), consensus());
        }

        let page = db.value_page("ns", "", 1, 2, false).unwrap();
        let values: Vec<&str> = page.items.iter().map(|v| v.value.as_str()).collect();
        assert_eq!(values, ["bbb", "ccc"]);
        assert_eq!(page.total, 4);
        assert_eq!(page.offset, 1);
    }

    #[test]
    fn values_can_be_filtered_and_carry_consensus() {
        let db = Database::default();
        db.write("a/ns", "1.2.3.4", at(100), consensus());
        db.write("b/ns", "1.2.3.4", at(100), consensus());
        db.write("a/ns", "9.9.9.9", at(100), consensus());

        let page = db.value_page("a/ns", "1.2", 0, 10, false).unwrap();
        assert_eq!(page.total, 1);
        assert_eq!(page.items[0].value, "1.2.3.4");
        assert_eq!(page.items[0].consensus, 2);
    }

    #[test]
    fn stats_are_included_only_when_asked_for() {
        let db = Database::default();
        db.write("ns", "v", at(3600), consensus());

        assert!(
            db.value_page("ns", "", 0, 10, false).unwrap().items[0]
                .stats
                .is_none()
        );
        let with = db.value_page("ns", "", 0, 10, true).unwrap();
        assert_eq!(with.items[0].stats.as_ref().unwrap().get(&3600), Some(&1));
    }

    #[test]
    fn expired_values_do_not_appear_in_a_page() {
        let db = Database::default();
        db.write("ns", "live", Utc::now(), consensus());
        db.write("ns", "dead", at(1000), with_ttl(60));

        let page = db.value_page("ns", "", 0, 10, false).unwrap();
        assert_eq!(page.total, 1);
        assert_eq!(page.items[0].value, "live");
    }

    #[test]
    fn paging_a_missing_namespace_is_none() {
        assert!(
            Database::default()
                .value_page("nope", "", 0, 10, false)
                .is_none()
        );
    }

    #[test]
    fn an_offset_past_the_end_is_an_empty_page_not_an_error() {
        let db = Database::default();
        db.write("ns", "v", at(100), consensus());

        let page = db.value_page("ns", "", 500, 10, false).unwrap();
        assert!(page.items.is_empty());
        assert_eq!(page.total, 1);
    }

    /// A key that cannot read a namespace should not learn it exists.
    #[test]
    fn the_listing_hides_namespaces_the_caller_cannot_read() {
        let db = Database::default();
        db.write("feeds/misp", "v", at(100), consensus());
        db.write("secrets/hr", "v", at(100), consensus());

        let page = db.namespace_page("", 0, 100, |name| name.starts_with("feeds"));

        assert_eq!(names(&page), ["feeds/misp"]);
        // The total must reflect what was allowed, or paging would show gaps.
        assert_eq!(page.total, 1);
    }

    // -- tiering -----------------------------------------------------------

    struct Scratch(std::path::PathBuf);
    impl Scratch {
        fn new(tag: &str) -> Self {
            let path = std::env::temp_dir().join(format!("sightingdb-tier-{tag}"));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).unwrap();
            Scratch(path)
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn tiered(dir: &std::path::Path, tier: crate::tier::Tier) -> Database {
        let db = Database::default();
        db.attach_store(
            Store {
                dbdir: dir.to_path_buf(),
                level: 1,
            },
            TierPolicy {
                default_tier: tier,
                entries: HashMap::new(),
                warm_idle: std::time::Duration::from_secs(3600),
            },
        );
        db
    }

    /// The one that must never fail: everything written since the last save
    /// has to reach disk before the shard leaves memory.
    #[test]
    fn eviction_writes_out_before_dropping() {
        let dir = Scratch::new("nodataloss");
        let db = tiered(&dir.0, crate::tier::Tier::Cold);
        db.write("myorg/ns", "1.2.3.4", at(1000), consensus());

        let report = db.evict_idle(now_secs());
        assert_eq!(report.evicted, 1, "{report:?}");
        assert!(!db.is_shard_resident("myorg"));

        // Still readable: the read pages the shard back in.
        assert_eq!(db.count("myorg/ns", "1.2.3.4"), 1);
        assert!(db.is_shard_resident("myorg"));
    }

    #[test]
    fn an_evicted_namespace_is_still_listed_and_still_exists() {
        let dir = Scratch::new("listing");
        let db = tiered(&dir.0, crate::tier::Tier::Cold);
        db.write("myorg/ns", "v", at(1000), consensus());
        db.evict_idle(now_secs());

        // The management interface must not lose sight of it.
        let page = db.namespace_page("", 0, 10, |_| true);
        assert!(names(&page).contains(&"myorg/ns"), "{page:?}");
        assert!(db.namespace_exists("myorg/ns"));
        assert_eq!(db.namespace_count(), 2); // myorg/ns and _all
    }

    #[test]
    fn writing_to_an_evicted_namespace_pages_it_back_in() {
        let dir = Scratch::new("writeback");
        let db = tiered(&dir.0, crate::tier::Tier::Cold);
        db.write("myorg/ns", "v", at(1000), consensus());
        db.evict_idle(now_secs());

        db.write("myorg/ns", "v", at(2000), consensus());

        assert_eq!(
            db.count("myorg/ns", "v"),
            2,
            "the earlier sighting was lost"
        );
    }

    /// A new namespace in an evicted shard must not make the shard look
    /// resident while the rest of it is still on disk: everything else in it
    /// would read as missing, and the next snapshot would write the shard back
    /// without it.
    #[test]
    fn creating_a_namespace_in_an_evicted_shard_brings_the_shard_back() {
        let dir = Scratch::new("createevicted");
        let db = tiered(&dir.0, crate::tier::Tier::Cold);
        db.write("myorg/ns", "v", at(1000), consensus());
        db.evict_idle(now_secs());
        assert!(!db.is_shard_resident("myorg"));

        assert!(db.create_namespace("myorg/second"));

        assert_eq!(
            db.count("myorg/ns", "v"),
            1,
            "the evicted namespace was lost"
        );
        assert!(db.namespace_exists("myorg/second"));
    }

    /// The same hazard reached through an ordinary write rather than through
    /// the management interface.
    #[test]
    fn writing_a_new_namespace_into_an_evicted_shard_keeps_the_rest_of_it() {
        let dir = Scratch::new("writeevicted");
        let db = tiered(&dir.0, crate::tier::Tier::Cold);
        db.write("myorg/ns", "v", at(1000), consensus());
        db.evict_idle(now_secs());

        db.write("myorg/second", "v", at(2000), consensus());

        assert_eq!(
            db.count("myorg/ns", "v"),
            1,
            "the evicted namespace was lost"
        );
        assert_eq!(db.count("myorg/second", "v"), 1);
    }

    #[test]
    fn a_hot_shard_is_never_evicted() {
        let dir = Scratch::new("hot");
        let db = tiered(&dir.0, crate::tier::Tier::Hot);
        db.write("myorg/ns", "v", at(1000), consensus());

        assert_eq!(db.evict_idle(now_secs() + 100_000).evicted, 0);
        assert!(db.is_shard_resident("myorg"));
    }

    #[test]
    fn a_warm_shard_survives_until_its_window_passes() {
        let dir = Scratch::new("warm");
        let db = tiered(&dir.0, crate::tier::Tier::Warm);
        db.write("myorg/ns", "v", at(1000), consensus());

        // Inside the hour.
        assert_eq!(db.evict_idle(now_secs() + 60).evicted, 0);
        assert!(db.is_shard_resident("myorg"));

        // Past it.
        assert_eq!(db.evict_idle(now_secs() + 3601).evicted, 1);
        assert!(!db.is_shard_resident("myorg"));
    }

    /// "If the namespace is used, we keep the access for one hour again."
    #[test]
    fn using_a_warm_shard_restarts_its_hour() {
        let dir = Scratch::new("touch");
        let db = tiered(&dir.0, crate::tier::Tier::Warm);
        db.write("myorg/ns", "v", at(1000), consensus());

        // A read counts as use, so the window starts again from now.
        assert_eq!(db.count("myorg/ns", "v"), 1);
        assert_eq!(db.evict_idle(now_secs() + 3599).evicted, 0);
        assert!(db.is_shard_resident("myorg"));
    }

    /// Consensus is consulted on every write, so paying a load for it would
    /// undo the point of tiering.
    #[test]
    fn the_internal_shard_stays_resident_even_when_everything_is_cold() {
        let dir = Scratch::new("internal");
        let db = tiered(&dir.0, crate::tier::Tier::Cold);
        db.write("myorg/ns", "v", at(1000), consensus());

        db.evict_idle(now_secs() + 100_000);

        assert!(db.is_shard_resident(crate::persistence::INTERNAL_SHARD));
        assert_eq!(db.count(ALL_NAMESPACE, "v"), 1);
    }

    /// A request holding an `Arc` would otherwise write into an orphan.
    #[test]
    fn a_shard_in_use_is_left_for_the_next_sweep() {
        let dir = Scratch::new("busy");
        let db = tiered(&dir.0, crate::tier::Tier::Cold);
        db.write("myorg/ns", "v", at(1000), consensus());

        let held = db.namespace("myorg/ns").unwrap();
        let report = db.evict_idle(now_secs());
        assert_eq!(report.evicted, 0);
        assert_eq!(report.busy, 1);

        drop(held);
        assert_eq!(db.evict_idle(now_secs()).evicted, 1);
    }

    #[test]
    fn nothing_is_evicted_without_somewhere_to_put_it() {
        let db = Database::default();
        db.write("myorg/ns", "v", at(1000), consensus());

        // No store attached, so eviction would be data loss.
        assert_eq!(db.evict_idle(now_secs() + 100_000), EvictReport::default());
        assert_eq!(db.count("myorg/ns", "v"), 1);
    }

    #[test]
    fn residency_is_reported() {
        let dir = Scratch::new("residency");
        let db = tiered(&dir.0, crate::tier::Tier::Cold);
        db.write("myorg/ns", "v", at(1000), consensus());
        db.write("acme/ns", "v", at(1000), consensus());

        let (resident, total) = db.residency();
        assert_eq!((resident, total), (3, 3)); // myorg, acme, internal

        db.evict_idle(now_secs());
        let (resident, total) = db.residency();
        assert_eq!((resident, total), (1, 3));
    }

    // -- concurrency -------------------------------------------------------

    #[test]
    fn concurrent_writes_to_one_value_are_all_counted() {
        const THREADS: usize = 8;
        const PER_THREAD: usize = 500;

        let db = Arc::new(Database::default());
        std::thread::scope(|scope| {
            for _ in 0..THREADS {
                let db = Arc::clone(&db);
                scope.spawn(move || {
                    for i in 0..PER_THREAD {
                        db.write("ns", "shared", at(i as i64), consensus());
                    }
                });
            }
        });

        assert_eq!(db.count("ns", "shared"), (THREADS * PER_THREAD) as u64);
        // Every writer raced on the same first sighting; consensus must still
        // have counted the namespace exactly once.
        assert_eq!(db.count(ALL_NAMESPACE, "shared"), 1);
    }

    #[test]
    fn concurrent_writes_across_namespaces_agree_on_consensus() {
        const THREADS: usize = 8;

        let db = Arc::new(Database::default());
        std::thread::scope(|scope| {
            for t in 0..THREADS {
                let db = Arc::clone(&db);
                scope.spawn(move || {
                    for i in 0..200 {
                        db.write(&format!("ns/{t}"), "shared", at(i), consensus());
                    }
                });
            }
        });

        assert_eq!(db.count(ALL_NAMESPACE, "shared"), THREADS as u64);
        for t in 0..THREADS {
            assert_eq!(db.count(&format!("ns/{t}"), "shared"), 200);
        }
    }

    /// Readers and writers hitting `_all` and a namespace from both directions
    /// at once: the lock-ordering rule is what keeps this from deadlocking.
    #[test]
    fn readers_and_writers_do_not_deadlock() {
        let db = Arc::new(Database::default());
        std::thread::scope(|scope| {
            for t in 0..8 {
                let db = Arc::clone(&db);
                scope.spawn(move || {
                    for i in 0..500 {
                        // 3 and 20 are coprime, so every value really does land
                        // in all three namespaces rather than sticking to one.
                        let value = format!("v{}", i % 20);
                        db.write(&format!("ns/{}", i % 3), &value, at(i), consensus());
                        db.count(ALL_NAMESPACE, &value);
                        db.view(&format!("ns/{}", t % 3), &value, 0, true);
                        db.namespace_views(&format!("ns/{}", i % 3));
                    }
                });
            }
        });

        for v in 0..20 {
            assert_eq!(db.count(ALL_NAMESPACE, &format!("v{v}")), 3);
        }
    }

    /// A sweep running against live writers must never lose a sighting to the
    /// empty-namespace pruning race.
    #[test]
    fn sweeping_concurrently_with_writers_loses_nothing() {
        let db = Arc::new(Database::default());
        let stop = Arc::new(AtomicBool::new(false));

        std::thread::scope(|scope| {
            let sweeper_db = Arc::clone(&db);
            let sweeper_stop = Arc::clone(&stop);
            scope.spawn(move || {
                while !sweeper_stop.load(Ordering::Relaxed) {
                    sweeper_db.sweep(Utc::now());
                }
            });

            for t in 0..4 {
                let db = Arc::clone(&db);
                scope.spawn(move || {
                    for _ in 0..500 {
                        db.write(&format!("ns/{t}"), "v", Utc::now(), consensus());
                    }
                });
            }

            // Writers finish inside the scope; stop the sweeper afterwards.
            scope.spawn({
                let stop = Arc::clone(&stop);
                move || {
                    std::thread::sleep(std::time::Duration::from_millis(300));
                    stop.store(true, Ordering::Relaxed);
                }
            });
        });

        for t in 0..4 {
            assert_eq!(db.count(&format!("ns/{t}"), "v"), 500, "namespace ns/{t}");
        }
    }
}
