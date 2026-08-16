use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError, RwLock};

use chrono::{DateTime, Utc};
use serde::ser::SerializeStruct;
use serde::{Deserialize, Serialize, Serializer};

use crate::attribute::{Attribute, AttributeView};
use crate::db_log::log_attribute;
use crate::tier::{Tier, TierPolicy};

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
pub const SNAPSHOT_VERSION: u32 = 1;

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
    /// The top-level namespace, which is what a tier applies to.
    pub shard: String,
    pub tier: String,
    pub resident: bool,
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
    fn from_values(values: HashMap<String, Attribute>) -> Self {
        let has_ttl = values.values().any(|attr| attr.ttl > 0);
        Self {
            values: RwLock::new(
                values
                    .into_iter()
                    .map(|(value, attr)| (value, Mutex::new(attr)))
                    .collect(),
            ),
            has_ttl: AtomicBool::new(has_ttl),
        }
    }

    /// Record a sighting, reporting the new count, whether this was the first
    /// time the value appeared here, and a snapshot for the write log.
    fn record(
        &self,
        value: &str,
        when: DateTime<Utc>,
        ttl: Option<u64>,
        retention: usize,
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
                attr.increment(when, retention);
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
        attr.increment(when, retention);
        (attr.count(), is_new, attr.view(0, false))
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

    /// Give back one consensus count, dropping the entry when it reaches zero.
    /// Done under the write lock so a concurrent write cannot resurrect a value
    /// between the decrement and the removal.
    fn release(&self, value: &str) {
        let mut values = self.values.write().unwrap_or_else(PoisonError::into_inner);
        let Some(cell) = values.get_mut(value) else {
            return;
        };
        let remaining = cell
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner)
            .decrement();
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

    pub fn with_policy(policy: DatabasePolicy) -> Database {
        Database {
            namespaces: RwLock::new(HashMap::new()),
            policy,
            dirty: Mutex::new(HashSet::new()),
            shards: RwLock::new(HashMap::new()),
            store: RwLock::new(None),
            tiers: RwLock::new(TierPolicy::default()),
        }
    }

    /// Rebuild a database from a snapshot. No API key is seeded here: the
    /// snapshot carries whatever keys were registered when it was written.
    pub fn from_snapshot(data: SnapshotData, policy: DatabasePolicy) -> Database {
        let namespaces: HashMap<String, Arc<Namespace>> = data
            .namespaces
            .into_iter()
            .map(|(name, values)| (name, Arc::new(Namespace::from_values(values))))
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
            namespace.record(value, when, ttl, self.policy.stats_retention);

        // The namespace's locks are released by now, so reaching into `_all`
        // here respects the ordering rule above.
        if opts.consensus && is_new {
            self.write(ALL_NAMESPACE, value, when, WriteOpts::default());
        }

        view.consensus = self.count(ALL_NAMESPACE, value);
        log_attribute(path, &view);
        self.mark_dirty(path);

        count
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
        for (name, namespace) in &entries {
            // API keys have no TTL and must never be swept out from under the ACL.
            if name.starts_with(CONFIG_PREFIX) {
                continue;
            }

            let expired = namespace.remove_expired(now);
            if !expired.is_empty() {
                self.mark_dirty(name);
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
        report.namespaces_removed = self.prune_empty();
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
                NamespaceEntry {
                    namespace: name.clone(),
                    shard: shard.to_string(),
                    tier: tiers.tier_of(shard).as_str().to_string(),
                    resident: shards.get(shard).is_some_and(|meta| meta.resident),
                }
            })
            .collect();

        Page {
            items,
            total,
            offset,
        }
    }

    /// Change a shard's tier, taking effect at once.
    ///
    /// Promoting to `hot` does not load anything: the shard is paged in when
    /// it is next used, as it would have been anyway.
    pub fn set_tier(&self, shard: &str, tier: Tier) {
        self.tiers
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .shards
            .insert(shard.to_string(), tier);
    }

    /// The current policy, for writing back to disk.
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
            namespaces.insert(name, Arc::new(Namespace::from_values(values)));
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
            all.release(value);
        }
    }

    fn prune_empty(&self) -> usize {
        let mut map = self
            .namespaces
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        let before = map.len();
        map.retain(|name, namespace| {
            if name.starts_with(CONFIG_PREFIX) {
                return true;
            }
            // Only drop a namespace nobody else is holding: a writer that
            // already took an `Arc` would otherwise record its sighting into an
            // orphaned namespace and lose it.
            Arc::strong_count(namespace) > 1 || !namespace.is_empty()
        });
        let removed: Vec<String> = map.keys().cloned().collect();
        drop(map);

        if before != removed.len() {
            let mut shards = self.shards.write().unwrap_or_else(PoisonError::into_inner);
            for meta in shards.values_mut() {
                meta.namespaces.retain(|name| removed.contains(name));
            }
        }
        before - removed.len()
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

/// Namespaces whose values were counted towards consensus when written, and so
/// must give that count back when they go away.
fn now_secs() -> i64 {
    Utc::now().timestamp()
}

fn counts_towards_consensus(name: &str) -> bool {
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

    #[test]
    fn an_empty_database_snapshots_cleanly() {
        let db = Database::default();
        let json = serde_json::to_string(&db.snapshot()).unwrap();

        assert_eq!(json, r#"{"version":1,"namespaces":{}}"#);
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
                shards: HashMap::new(),
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
