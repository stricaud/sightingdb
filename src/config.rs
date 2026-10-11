//! Reading `sightingdb.toml`.
//!
//! The file is deserialized straight into these structures, so a missing key
//! gets its default and a misspelled one is an error rather than something
//! silently ignored. Values that need interpreting — TLS paths relative to the
//! config file, grant specifications, DNS encodings — are converted once here
//! so the rest of the program never sees a raw string.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use serde::Deserialize;

use crate::acl::{Acl, parse_grants};
use crate::db::DatabasePolicy;
use crate::dns::name::{Encoding, Exposed};
use crate::ingest::misp::Mapping;
use crate::ingest::stix::Mapping as StixMapping;
use crate::ingest::{Format, Settings as ZmqSettings};
use crate::tier::{Tier, TierPolicy};

/// Body size limit for bulk POSTs.
const DEFAULT_POST_LIMIT: usize = 2_500_000_000;

// ---------------------------------------------------------------------------
// What the rest of the program sees
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsSettings {
    pub cert: PathBuf,
    pub key: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    /// Serve the HTTP API. `false` runs a DNS- or ingest-only instance.
    pub http_enabled: bool,
    pub listen: String,
    pub authenticate: bool,
    pub daemonize: bool,
    /// `None` means serve plain HTTP.
    pub tls: Option<TlsSettings>,
    pub post_limit: usize,
    pub log_out: PathBuf,
    pub log_err: PathBuf,
    /// Where snapshots live. `None` disables persistence entirely.
    pub dbdir: Option<PathBuf>,
    pub snapshot_interval: u64,
    /// zstd level for shard files. 3 is the knee of the curve; higher levels
    /// cost compression time for little size on a file rewritten this often.
    pub compression_level: i32,
    pub sweep_interval: u64,
    pub stats_retention: usize,
    pub shadow_ttl: u64,
    /// How many rejected values to keep in memory for `/_management/api/rejections`.
    /// 0 switches the record off.
    pub rejection_log: usize,
    /// This server's name in its own counters. See [`crate::db::LOCAL_NODE`].
    pub node_id: String,
    /// API keys. `None` means no `[acl]` table and no `acl_file`.
    pub acl: Option<Acl>,
    /// File holding the keys, which the management interface rewrites.
    pub acl_file: Option<PathBuf>,
    /// How tags are shown: a colour and a description each.
    pub tags: crate::tags::Vocabulary,
    /// File holding the tag vocabulary, which the management interface
    /// rewrites. Without one, tags can still be read and set on values; only
    /// their colours become read-only.
    pub tags_file: Option<PathBuf>,
    /// Which shards stay in memory, and for how long.
    pub tiers: TierPolicy,
    /// File the management interface rewrites when a tier is changed. Without
    /// it, tiers are read-only and come from `[storage]`.
    pub tiers_file: Option<PathBuf>,
    pub dns: Option<DnsSettings>,
    pub zmq: Option<ZmqSettings>,
    pub stix: StixSettings,
    /// Which namespaces this server stores. Everything, unless `[storage]`
    /// narrows it with `namespaces`.
    pub storage: crate::db::StoragePolicy,
    /// The other servers this one knows about. `None` means it stands alone.
    pub galaxy: Option<GalaxySettings>,
}

/// The other servers in this one's galaxy.
///
/// Configuration only at this stage: nothing is forwarded yet. It is parsed,
/// validated and reported so that the topology can be described before it can
/// be used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GalaxySettings {
    pub peers: Vec<Peer>,
    /// Seconds between health probes of each peer.
    pub health_interval: u64,
    /// Seconds between catch-up passes. 0 switches catching up off, which
    /// leaves a server that was down behind until someone syncs it by hand.
    pub sync_interval: u64,
    /// Seconds between rebuilds of the consensus tally from the galaxy. 0
    /// switches it off, which leaves the tally drifting upward as values
    /// expire on the nodes.
    pub reconcile_interval: u64,
    /// Seconds between offering this server's keys to its peers. 0 switches
    /// the periodic offer off, leaving only the push made when a key changes.
    pub gossip_interval: u64,
    /// Whether this server's key list is the galaxy's.
    ///
    /// Off by default. On, the periodic offer sends the whole list and asks a
    /// peer to hold exactly that — which is what makes a revocation reach a
    /// server that was offline for it. A peer only obeys if it has said it may
    /// be replaced, so this takes agreement at both ends.
    pub acl_authority: bool,
    /// Whether another server may replace this one's key list wholesale.
    ///
    /// Off by default, because a server quietly having its keys rewritten is
    /// not something to arrive at by accident. On, an admin key may replace
    /// them — which is how a galaxy gets one place to manage keys.
    pub acl_replaceable: bool,
    /// Whether a peer's TLS certificate is verified. Off is for a galaxy of
    /// self-signed instances, which is what `--setup` produces.
    pub verify_tls: bool,
    /// How many hops a forwarded request may take before it is refused. A
    /// cascade can be miswired into a cycle, and a cycle inflates every count
    /// it carries, so this is a limit rather than a tuning knob.
    pub max_hops: u8,
    /// File holding peers added through the management interface, which it
    /// rewrites. Without one, the galaxy is read-only there.
    ///
    /// A separate file for the same reason the ACL has one: the main
    /// configuration is hand-maintained and comment-rich, and a program that
    /// rewrites it destroys those comments. Peers listed in `[galaxy] peers`
    /// are therefore *not* editable here — the interface shows them and says
    /// where they came from.
    pub peers_file: Option<PathBuf>,
    /// URLs of the peers that came from the main configuration, and so cannot
    /// be changed or removed by the interface.
    pub fixed: Vec<String>,
}

/// One peer, and the key this server authenticates to it with.
///
/// The key is the capability bound: a peer's own ACL decides what this server
/// may read and write there, so a key granted `rw:feeds` cannot be used to
/// write anywhere else however this server is configured or compromised.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Peer {
    pub url: String,
    pub key: String,
    /// What this peer stores, so a request can be sent where it can be served.
    ///
    /// Declared here rather than asked of the peer: discovery would need the
    /// peer key to carry an `admin` grant, and the whole point of that key is
    /// that it can be the narrowest thing that does the job. The cost is that
    /// it must agree with the peer's own `[storage] namespaces`.
    pub stores: crate::db::StoragePolicy,
    /// Whether this server will use the peer at all.
    ///
    /// A disabled peer is kept — its address, its key, what it holds — and
    /// nothing is sent to it: no forwarded request, no catch-up, no gossip,
    /// not even a health probe. It is for taking a node out of service
    /// without forgetting how to reach it, which is otherwise a matter of
    /// removing it and getting the key back out of wherever it was written
    /// down.
    ///
    /// True unless something says otherwise, so every existing configuration
    /// and peers file means what it meant before.
    pub enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsSettings {
    pub listen: String,
    /// Zone we answer for, without a trailing dot.
    pub zone: String,
    pub ttl: u32,
    /// Queries per second per source address; 0 disables the limit.
    pub rate_limit: u32,
    pub threads: usize,
    /// Whether a DNS lookup raises a shadow sighting. Off by default: DNS has
    /// no authentication, so this would be an unauthenticated write path.
    pub shadow: bool,
    /// The only namespaces reachable over DNS.
    pub exposed: Vec<Exposed>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StixSettings {
    pub mapping: StixMapping,
    pub ttl: u64,
    /// Who the STIX export publishes as.
    pub export: crate::stix::Settings,
}

impl StixSettings {
    /// The observable type a namespace holds, from the import mapping read
    /// backwards: a namespace configured to receive `ipv4-addr` holds ipv4
    /// addresses however the data actually arrived.
    ///
    /// The longest matching prefix wins, so `ipv4-addr = "feeds"` still says
    /// something useful about `feeds/misp/ips` while a mapping for that exact
    /// namespace overrides it.
    pub fn type_of_namespace(&self, namespace: &str) -> Option<&str> {
        self.mapping
            .types
            .iter()
            .filter(|(_, mapped)| covers(mapped, namespace))
            .max_by_key(|(_, mapped)| mapped.len())
            .map(|(stix_type, _)| stix_type.as_str())
    }
}

/// Whether `mapped` is `namespace` or a parent of it, matching whole segments
/// so `feeds/misp` does not cover `feeds/misp-internal`.
fn covers(mapped: &str, namespace: &str) -> bool {
    let mapped = mapped.trim_matches('/');
    namespace == mapped
        || namespace
            .strip_prefix(mapped)
            .is_some_and(|rest| rest.starts_with('/'))
}

impl Settings {
    pub fn database_policy(&self) -> DatabasePolicy {
        DatabasePolicy {
            stats_retention: self.stats_retention,
            shadow_ttl: self.shadow_ttl,
        }
    }

    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading config file {}", path.display()))?;
        let raw: RawConfig =
            toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        raw.into_settings(path)
    }
}

// ---------------------------------------------------------------------------
// The file's own shape
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    #[serde(default)]
    daemon: RawDaemon,
    /// Inline keys, for installs that do not use a separate `acl_file`.
    acl: Option<HashMap<String, String>>,
    storage: Option<RawStorage>,
    galaxy: Option<RawGalaxy>,
    dns: Option<RawDns>,
    zmq: Option<RawZmq>,
    stix: Option<RawStix>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDaemon {
    #[serde(default = "yes")]
    enabled: bool,
    #[serde(default = "default_listen_ip")]
    listen_ip: String,
    #[serde(default = "default_listen_port")]
    listen_port: u16,
    /// Defaults on: an unauthenticated database should be a deliberate choice.
    #[serde(default = "yes")]
    authenticate: bool,
    #[serde(default)]
    daemonize: bool,
    #[serde(default = "yes")]
    ssl: bool,
    ssl_cert: Option<PathBuf>,
    ssl_key: Option<PathBuf>,
    #[serde(default = "default_post_limit")]
    post_limit: usize,
    #[serde(default = "dev_null")]
    log_out: PathBuf,
    #[serde(default = "dev_null")]
    log_err: PathBuf,
    dbdir: Option<PathBuf>,
    #[serde(default = "default_snapshot_interval")]
    snapshot_interval: u64,
    #[serde(default = "default_compression_level")]
    compression_level: i32,
    #[serde(default = "default_sweep_interval")]
    sweep_interval: u64,
    #[serde(default)]
    stats_retention: usize,
    #[serde(default)]
    shadow_ttl: u64,
    #[serde(default = "default_rejection_log")]
    rejection_log: usize,
    /// This server's name in its own counters. Absent means "local", which is
    /// right until it joins a galaxy — two servers sharing an id would each
    /// take the other's contribution for their own.
    node_id: Option<String>,
    acl_file: Option<PathBuf>,
    tags_file: Option<PathBuf>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawGalaxy {
    #[serde(default)]
    peers: Vec<RawPeer>,
    peers_file: Option<PathBuf>,
    #[serde(default = "default_max_hops")]
    max_hops: u8,
    #[serde(default = "default_health_interval")]
    health_interval: u64,
    #[serde(default = "default_sync_interval")]
    sync_interval: u64,
    #[serde(default = "default_reconcile_interval")]
    reconcile_interval: u64,
    #[serde(default = "default_gossip_interval")]
    gossip_interval: u64,
    #[serde(default)]
    acl_authority: bool,
    #[serde(default)]
    acl_replaceable: bool,
    #[serde(default = "yes")]
    verify_tls: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPeer {
    url: String,
    key: String,
    /// What the peer stores. Absent means everything — a full mirror, which is
    /// the common case and the one a reader should assume.
    namespaces: Option<Vec<String>>,
    /// Absent means enabled. See [`Peer::enabled`].
    enabled: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawStorage {
    #[serde(default = "default_tier")]
    default_tier: String,
    /// Seconds a warm shard may sit untouched before it is written out and
    /// dropped from memory.
    #[serde(default = "default_warm_idle")]
    warm_idle: u64,
    /// Overrides keyed by namespace, inherited by everything under each one.
    #[serde(default)]
    tiers: HashMap<String, toml::Value>,
    tiers_file: Option<PathBuf>,
    /// Which namespaces this server stores. Absent means all of them, which is
    /// what every release before this one did. `["/"]` says the same thing
    /// explicitly; `[]` makes this a router that stores nothing of its own.
    namespaces: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDns {
    #[serde(default = "yes")]
    enabled: bool,
    #[serde(default = "default_dns_ip")]
    listen_ip: String,
    #[serde(default = "default_dns_port")]
    listen_port: u16,
    zone: String,
    #[serde(default = "default_dns_ttl")]
    ttl: u32,
    #[serde(default = "default_rate_limit")]
    rate_limit: u32,
    #[serde(default = "default_dns_threads")]
    threads: usize,
    #[serde(default)]
    shadow: bool,
    #[serde(default)]
    namespaces: HashMap<String, RawExposed>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawExposed {
    namespace: String,
    encoding: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawZmq {
    #[serde(default = "yes")]
    enabled: bool,
    endpoint: String,
    #[serde(default)]
    topics: Vec<String>,
    #[serde(default = "default_format")]
    format: String,
    #[serde(default)]
    require_to_ids: bool,
    default_namespace: Option<String>,
    #[serde(default)]
    ttl: u64,
    #[serde(default = "default_reconnect")]
    reconnect: u64,
    #[serde(default)]
    types: Option<toml::Value>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawStix {
    default_namespace: Option<String>,
    #[serde(default)]
    ttl: u64,
    #[serde(default)]
    types: Option<toml::Value>,
    /// Name the STIX export publishes under. Defaults to "SightingDB".
    identity: Option<String>,
    /// STIX identity class for that name: `organization`, `system`, ...
    identity_class: Option<String>,
}

fn yes() -> bool {
    true
}
fn dev_null() -> PathBuf {
    PathBuf::from("/dev/null")
}
fn default_listen_ip() -> String {
    "0.0.0.0".into()
}
fn default_listen_port() -> u16 {
    9999
}
fn default_post_limit() -> usize {
    DEFAULT_POST_LIMIT
}
fn default_snapshot_interval() -> u64 {
    300
}
fn default_compression_level() -> i32 {
    crate::persistence::default_level()
}
fn default_sweep_interval() -> u64 {
    60
}
fn default_rejection_log() -> usize {
    crate::rejections::DEFAULT_CAPACITY
}
fn default_dns_ip() -> String {
    // Loopback, not every interface: DNS answers without authentication.
    "127.0.0.1".into()
}
fn default_dns_port() -> u16 {
    5353
}
fn default_dns_ttl() -> u32 {
    60
}
fn default_rate_limit() -> u32 {
    100
}
fn default_dns_threads() -> usize {
    2
}
fn default_format() -> String {
    "misp".into()
}
fn default_reconnect() -> u64 {
    5
}
fn default_tier() -> String {
    // Everything resident, which is how the database behaved before tiering.
    "hot".into()
}
fn default_max_hops() -> u8 {
    4
}
fn default_health_interval() -> u64 {
    30
}
fn default_reconcile_interval() -> u64 {
    // It walks the galaxy, so rarely. Long enough to be a repair rather than a
    // steady cost, short enough that a tally does not drift for a working day.
    3600
}
fn default_gossip_interval() -> u64 {
    // A key change is pushed as it happens; this only catches up a peer that
    // was down for one, so it need not be frequent.
    600
}
fn default_sync_interval() -> u64 {
    // Often enough that a server which was briefly down catches up without
    // anyone noticing, rarely enough that a steady galaxy is not walking its
    // namespaces over and over.
    300
}
fn default_warm_idle() -> u64 {
    3600
}

// ---------------------------------------------------------------------------
// Conversion
// ---------------------------------------------------------------------------

impl RawConfig {
    fn into_settings(self, path: &Path) -> Result<Settings> {
        let base = path.parent().unwrap_or_else(|| Path::new("."));
        let daemon = self.daemon;

        let tls = if daemon.ssl {
            let cert = daemon
                .ssl_cert
                .ok_or_else(|| anyhow!("ssl is on but 'ssl_cert' is missing from [daemon]"))?;
            let key = daemon
                .ssl_key
                .ok_or_else(|| anyhow!("ssl is on but 'ssl_key' is missing from [daemon]"))?;
            Some(TlsSettings {
                cert: resolve(base, &cert),
                key: resolve(base, &key),
            })
        } else {
            None
        };

        // Read before `self.storage` is consumed below.
        let storage_policy = match self.storage.as_ref().and_then(|s| s.namespaces.as_ref()) {
            Some(list) => crate::db::StoragePolicy::from_prefixes(list),
            None => crate::db::StoragePolicy::everything(),
        };
        for prefix in storage_policy.prefixes() {
            crate::acl::validate_namespace(prefix).with_context(|| {
                format!("in the [storage] namespaces list in {}", path.display())
            })?;
        }

        let node_id = match daemon.node_id.as_deref().map(str::trim) {
            None | Some("") => crate::db::LOCAL_NODE.to_string(),
            Some(id) => {
                // It is a key in every snapshot this server writes and in every
                // merge it sends, so keep it to something that survives both.
                if id.len() > 64 {
                    bail!(
                        "node_id must be 64 characters or fewer, in {}",
                        path.display()
                    );
                }
                if !id
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
                {
                    bail!(
                        "node_id may use letters, digits, '-', '_' and '.' only, in {}",
                        path.display()
                    );
                }
                id.to_string()
            }
        };

        let galaxy = match self.galaxy {
            Some(raw) => Some(raw.into_settings(path)?),
            None => None,
        };

        let (tiers, tiers_file) = match self.storage {
            Some(storage) => {
                let file = storage.tiers_file.as_ref().map(|f| resolve(base, f));
                // The file wins when there is one, since it is the copy the
                // interface maintains.
                let policy = match &file {
                    Some(path) if path.exists() => TierPolicy::load(path)?,
                    Some(path) => {
                        log::info!(
                            "tiers_file {} does not exist yet; it will be created when a tier \
                             is changed",
                            path.display()
                        );
                        storage.to_policy()?
                    }
                    None => storage.to_policy()?,
                };
                (policy, file)
            }
            None => (TierPolicy::default(), None),
        };
        let acl_file = daemon.acl_file.map(|file| resolve(base, &file));
        let acl = load_acl(self.acl, acl_file.as_deref(), path)?;

        let tags_file = daemon.tags_file.map(|file| resolve(base, &file));
        let tags = load_tags(tags_file.as_deref());

        let dns = match self.dns {
            Some(dns) => dns.into_settings(path)?,
            None => None,
        };
        let zmq = match self.zmq {
            Some(zmq) => zmq.into_settings(path)?,
            None => None,
        };
        let stix = match self.stix {
            Some(stix) => stix.into_settings(path)?,
            None => StixSettings::default(),
        };

        if !daemon.enabled && dns.is_none() && zmq.is_none() {
            bail!(
                "the HTTP API is disabled in {} and neither DNS nor ZMQ is configured, so there \
                 is nothing to do",
                path.display()
            );
        }

        Ok(Settings {
            http_enabled: daemon.enabled,
            listen: format!("{}:{}", daemon.listen_ip, daemon.listen_port),
            authenticate: daemon.authenticate,
            daemonize: daemon.daemonize,
            tls,
            post_limit: daemon.post_limit,
            log_out: daemon.log_out,
            log_err: daemon.log_err,
            dbdir: daemon.dbdir,
            snapshot_interval: daemon.snapshot_interval,
            compression_level: daemon.compression_level,
            sweep_interval: daemon.sweep_interval,
            stats_retention: daemon.stats_retention,
            shadow_ttl: daemon.shadow_ttl,
            rejection_log: daemon.rejection_log,
            node_id,
            acl,
            acl_file,
            tags,
            tags_file,
            tiers,
            tiers_file,
            dns,
            zmq,
            stix,
            storage: storage_policy,
            galaxy,
        })
    }
}

/// Check one peer and normalise it, wherever it was declared.
///
/// Shared by `[galaxy] peers`, the peers file and the management interface, so
/// that a peer added through the interface is held to exactly the rules a
/// hand-written one is. `namespaces` of `None` means a full mirror, which is
/// the common case and the one a reader should assume.
pub fn validated_peer(
    url: &str,
    key: &str,
    namespaces: Option<&[String]>,
    enabled: bool,
) -> std::result::Result<Peer, String> {
    let url = url.trim().trim_end_matches('/').to_string();
    let key = key.trim().to_string();

    if url.is_empty() {
        return Err("a peer has no url".to_string());
    }
    if !url.starts_with("http://") && !url.starts_with("https://") {
        return Err(format!("peer '{url}' needs an http:// or https:// url"));
    }
    // A peer we cannot authenticate to is a peer we cannot use, and finding
    // that out at the first forward is worse than at startup.
    if key.is_empty() {
        return Err(format!(
            "peer '{url}' has no key. The key is what bounds what this server may do there."
        ));
    }

    let stores = match namespaces {
        Some(list) => crate::db::StoragePolicy::from_prefixes(list),
        None => crate::db::StoragePolicy::everything(),
    };
    for prefix in stores.prefixes() {
        crate::acl::validate_namespace(prefix)
            .map_err(|e| format!("in the namespaces for peer '{url}': {e}"))?;
    }
    if stores.is_router() {
        // A peer that stores nothing can still be forwarded *through*, but
        // saying so here would be saying it holds nothing, which is not what a
        // routing table is for. Let it be a full mirror or a named subtree.
        return Err(format!(
            "peer '{url}' declares an empty namespaces list. Leave it out for a full \
             mirror, or name what it holds."
        ));
    }
    Ok(Peer {
        url,
        key,
        stores,
        enabled,
    })
}

/// The shape of the peers file the management interface writes.
#[derive(Debug, Default, Deserialize)]
pub struct PeersFile {
    #[serde(default)]
    pub peers: Vec<FilePeer>,
}

#[derive(Debug, Deserialize)]
pub struct FilePeer {
    pub url: String,
    pub key: String,
    #[serde(default)]
    pub namespaces: Option<Vec<String>>,
    #[serde(default)]
    pub enabled: Option<bool>,
}

impl PeersFile {
    /// Render the peers for writing, with the comment saying who owns the file.
    pub fn to_toml(peers: &[Peer]) -> String {
        let mut out = String::from(
            "# Written by the SightingDB management interface. Comments added\n\
             # here are replaced the next time a peer is saved.\n\
             #\n\
             # Peers listed in [galaxy] peers in the main configuration are not\n\
             # here and are not editable from the interface.\n\
             \n",
        );
        for peer in peers {
            out.push_str("[[peers]]\n");
            out.push_str(&format!("url = \"{}\"\n", peer.url));
            out.push_str(&format!("key = \"{}\"\n", peer.key));
            if !peer.stores.stores_everything() {
                let list: Vec<String> = peer
                    .stores
                    .prefixes()
                    .iter()
                    .map(|p| format!("\"{p}\""))
                    .collect();
                out.push_str(&format!("namespaces = [{}]\n", list.join(", ")));
            }
            // Written only when it is off, since absent means on — so the
            // file stays quiet about the ordinary case.
            if !peer.enabled {
                out.push_str("enabled = false\n");
            }
            out.push('\n');
        }
        out
    }
}

/// Peers the management interface added, from their file.
///
/// A missing file is normal: it is written the first time a peer is added. A
/// malformed one is reported and skipped rather than fatal, for the same
/// reason as the tag vocabulary — a server that will not start is worse than a
/// galaxy missing a mirror it can be told about again.
fn load_file_peers(file: Option<&Path>) -> Vec<Peer> {
    let Some(path) = file else {
        return Vec::new();
    };
    if !path.exists() {
        log::info!(
            "[galaxy] peers_file {} does not exist yet; it will be created when a \
             peer is added",
            path.display()
        );
        return Vec::new();
    }
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) => {
            log::error!("reading [galaxy] peers_file {}: {e}", path.display());
            return Vec::new();
        }
    };
    let parsed: PeersFile = match toml::from_str(&text) {
        Ok(parsed) => parsed,
        Err(e) => {
            log::error!("parsing [galaxy] peers_file {}: {e}", path.display());
            return Vec::new();
        }
    };
    let mut peers = Vec::new();
    for entry in parsed.peers {
        match validated_peer(
            &entry.url,
            &entry.key,
            entry.namespaces.as_deref(),
            entry.enabled.unwrap_or(true),
        ) {
            Ok(peer) => peers.push(peer),
            Err(e) => log::error!("in {}: {e}", path.display()),
        }
    }
    peers
}

impl RawGalaxy {
    fn into_settings(self, path: &Path) -> Result<GalaxySettings> {
        let base = path.parent().unwrap_or_else(|| Path::new("."));
        let peers_file = self.peers_file.as_ref().map(|file| resolve(base, file));

        let mut peers: Vec<Peer> = Vec::new();
        for raw in self.peers {
            let peer = validated_peer(
                &raw.url,
                &raw.key,
                raw.namespaces.as_deref(),
                raw.enabled.unwrap_or(true),
            )
            .map_err(|e| anyhow::anyhow!("[galaxy] {e}, in {}", path.display()))?;
            if peers.iter().any(|known| known.url == peer.url) {
                bail!(
                    "[galaxy] lists peer '{}' twice, in {}",
                    peer.url,
                    path.display()
                );
            }
            peers.push(peer);
        }
        // What the main configuration declared, which the interface may show
        // but not change.
        let fixed: Vec<String> = peers.iter().map(|peer| peer.url.clone()).collect();

        // Added through the interface. A URL already declared in the main
        // configuration wins there, because that is the file a human is
        // maintaining.
        for peer in load_file_peers(peers_file.as_deref()) {
            if peers.iter().any(|known| known.url == peer.url) {
                log::warn!(
                    "peer '{}' is in both the configuration and the peers file; the \
                     configuration wins",
                    peer.url
                );
                continue;
            }
            peers.push(peer);
        }

        if self.max_hops == 0 {
            bail!(
                "[galaxy] max_hops must be at least 1, in {}",
                path.display()
            );
        }

        if self.acl_authority && self.acl_replaceable {
            bail!(
                "[galaxy] sets both acl_authority and acl_replaceable, in {}. A server \
                 that owns the galaxy's keys cannot also let another server replace \
                 them: the two would take turns overwriting each other.",
                path.display()
            );
        }

        if self.health_interval == 0 {
            bail!(
                "[galaxy] health_interval must be at least 1 second, in {}",
                path.display()
            );
        }

        Ok(GalaxySettings {
            peers,
            peers_file,
            fixed,
            max_hops: self.max_hops,
            health_interval: self.health_interval,
            sync_interval: self.sync_interval,
            reconcile_interval: self.reconcile_interval,
            gossip_interval: self.gossip_interval,
            acl_authority: self.acl_authority,
            acl_replaceable: self.acl_replaceable,
            verify_tls: self.verify_tls,
        })
    }
}

impl RawStorage {
    fn to_policy(&self) -> Result<TierPolicy> {
        let mut entries = HashMap::new();
        for (namespace, value) in &self.tiers {
            // Either `"archive" = "cold"` or
            // `"feeds/misp" = { tier = "warm", warm_idle = 86400 }`.
            let entry = crate::tier::parse_entry(value)
                .with_context(|| format!("in [storage.tiers] entry '{namespace}'"))?;
            entries.insert(namespace.trim().trim_matches('/').to_string(), entry);
        }

        Ok(TierPolicy {
            default_tier: Tier::parse(&self.default_tier)
                .context("in 'default_tier' of [storage]")?,
            entries,
            warm_idle: std::time::Duration::from_secs(self.warm_idle),
        })
    }
}

impl RawDns {
    fn into_settings(self, path: &Path) -> Result<Option<DnsSettings>> {
        if !self.enabled {
            return Ok(None);
        }

        let zone = self.zone.trim().trim_matches('.').to_ascii_lowercase();
        if zone.is_empty() {
            bail!("'zone' in [dns] of {} is empty", path.display());
        }

        let mut exposed = Vec::new();
        for (label, entry) in self.namespaces {
            if entry.namespace.starts_with('_') {
                bail!(
                    "[dns.namespaces] entry '{label}' exposes the internal namespace '{}'",
                    entry.namespace
                );
            }
            exposed.push(Exposed {
                label: label.trim().to_ascii_lowercase(),
                namespace: entry.namespace,
                encoding: Encoding::parse(&entry.encoding)
                    .with_context(|| format!("in [dns.namespaces] entry '{label}'"))?,
            });
        }
        exposed.sort_by(|a, b| a.label.cmp(&b.label));

        if exposed.is_empty() {
            log::warn!(
                "[dns] is configured in {} but [dns.namespaces] exposes nothing, so every query \
                 will be NXDOMAIN",
                path.display()
            );
        }

        Ok(Some(DnsSettings {
            listen: format!("{}:{}", self.listen_ip, self.listen_port),
            zone,
            ttl: self.ttl,
            rate_limit: self.rate_limit,
            threads: self.threads,
            shadow: self.shadow,
            exposed,
        }))
    }
}

impl RawZmq {
    fn into_settings(self, path: &Path) -> Result<Option<ZmqSettings>> {
        if !self.enabled {
            return Ok(None);
        }

        let format = Format::parse(&self.format)
            .with_context(|| format!("in [zmq] of {}", path.display()))?;
        let types = type_map(self.types.as_ref(), "zmq.types", path)?;
        let default_namespace = namespace_option(self.default_namespace, "zmq")?;

        if types.is_empty() && default_namespace.is_none() && format == Format::Misp {
            log::warn!(
                "[zmq] is configured in {} but [zmq.types] maps nothing and no \
                 default_namespace is set, so every attribute will be discarded",
                path.display()
            );
        }

        Ok(Some(ZmqSettings {
            endpoint: self.endpoint,
            topics: self.topics,
            format,
            mapping: Mapping {
                types,
                default_namespace,
                require_to_ids: self.require_to_ids,
            },
            ttl: self.ttl,
            reconnect: self.reconnect,
        }))
    }
}

impl RawStix {
    fn into_settings(self, path: &Path) -> Result<StixSettings> {
        let default_export = crate::stix::Settings::default();
        Ok(StixSettings {
            mapping: StixMapping {
                types: type_map(self.types.as_ref(), "stix.types", path)?,
                default_namespace: namespace_option(self.default_namespace, "stix")?,
            },
            ttl: self.ttl,
            export: crate::stix::Settings {
                identity: self
                    .identity
                    .map(|name| name.trim().to_string())
                    .filter(|name| !name.is_empty())
                    .unwrap_or_else(|| default_export.identity.clone()),
                identity_class: self
                    .identity_class
                    .map(|class| class.trim().to_string())
                    .filter(|class| !class.is_empty())
                    .unwrap_or(default_export.identity_class),
            },
        })
    }
}

/// Read a `<type> = "<namespace>"` table.
///
/// A key containing a dot must be quoted in TOML, or it becomes a nested table
/// instead — `file.MD5 = "x"` is `{file = {MD5 = "x"}}`. That is easy to get
/// wrong and would map nothing, so it is reported rather than ignored.
fn type_map(
    value: Option<&toml::Value>,
    table: &str,
    path: &Path,
) -> Result<HashMap<String, String>> {
    let mut map = HashMap::new();
    let Some(toml::Value::Table(entries)) = value else {
        return Ok(map);
    };

    for (key, entry) in entries {
        let namespace = match entry {
            toml::Value::String(namespace) => namespace.trim(),
            toml::Value::Table(_) => bail!(
                "[{table}] entry '{key}' in {} is a table, not a namespace. A key containing a \
                 dot has to be quoted, as in \"file.MD5\" = \"stix/hashes\"",
                path.display()
            ),
            other => bail!(
                "[{table}] entry '{key}' in {} should be a namespace string, found {}",
                path.display(),
                other.type_str()
            ),
        };
        if namespace.starts_with('_') {
            bail!(
                "[{table}] entry '{key}' in {} targets the internal namespace '{namespace}'",
                path.display()
            );
        }
        map.insert(key.trim().to_string(), namespace.to_string());
    }

    Ok(map)
}

fn namespace_option(value: Option<String>, table: &str) -> Result<Option<String>> {
    let Some(namespace) = value
        .map(|n| n.trim().to_string())
        .filter(|n| !n.is_empty())
    else {
        return Ok(None);
    };
    if namespace.starts_with('_') {
        bail!("'default_namespace' in [{table}] is the internal namespace '{namespace}'");
    }
    Ok(Some(namespace))
}

/// Keys come from the separate file when there is one, since that is the file
/// the management interface maintains.
/// The tag vocabulary, from its file or seeded.
///
/// A missing file is normal rather than an error: it is written the first time
/// a tag is edited, and until then MISP's own TLP colours plus a colour per
/// family of SightingDB's vocabulary are a better starting point than nothing.
/// A file that will not parse is reported and the seed used, because this
/// decides colours and refusing to start over them would be a poor trade.
fn load_tags(file: Option<&Path>) -> crate::tags::Vocabulary {
    let Some(path) = file else {
        return crate::tags::Vocabulary::seeded();
    };
    if !path.exists() {
        log::info!(
            "tags_file {} does not exist yet; it will be created when a tag is \
             edited, and the standard colours are used until then",
            path.display()
        );
        return crate::tags::Vocabulary::seeded();
    }
    match std::fs::read_to_string(path).map(|text| crate::tags::Vocabulary::from_toml(&text)) {
        Ok(Ok(vocabulary)) => vocabulary,
        Ok(Err(e)) => {
            log::error!(
                "parsing tags_file {}: {e}; using the standard colours",
                path.display()
            );
            crate::tags::Vocabulary::seeded()
        }
        Err(e) => {
            log::error!(
                "reading tags_file {}: {e}; using the standard colours",
                path.display()
            );
            crate::tags::Vocabulary::seeded()
        }
    }
}

fn load_acl(
    inline: Option<HashMap<String, String>>,
    acl_file: Option<&Path>,
    path: &Path,
) -> Result<Option<Acl>> {
    if let Some(file) = acl_file {
        if inline.is_some() {
            log::warn!(
                "{} has both an [acl] table and acl_file {}; the file wins",
                path.display(),
                file.display()
            );
        }
        if !file.exists() {
            log::info!(
                "acl_file {} does not exist yet; it will be created when a key is saved",
                file.display()
            );
            return Ok(Some(Acl::new()));
        }

        #[derive(Deserialize)]
        struct AclFile {
            #[serde(default)]
            acl: HashMap<String, String>,
        }

        let text = std::fs::read_to_string(file)
            .with_context(|| format!("reading acl_file {}", file.display()))?;
        let parsed: AclFile = toml::from_str(&text)
            .with_context(|| format!("parsing acl_file {}", file.display()))?;
        return build_acl(parsed.acl, file).map(Some);
    }

    match inline {
        Some(entries) => build_acl(entries, path).map(Some),
        None => Ok(None),
    }
}

fn build_acl(entries: HashMap<String, String>, path: &Path) -> Result<Acl> {
    let mut acl = Acl::new();
    for (key, spec) in entries {
        let grants = parse_grants(&spec)
            .with_context(|| format!("in the [acl] entry for '{key}' in {}", path.display()))?;
        acl.set(&key, grants);
    }
    Ok(acl)
}

fn resolve(base: &Path, value: &Path) -> PathBuf {
    let joined = if value.is_absolute() {
        value.to_path_buf()
    } else {
        base.join(value)
    };
    // Anchored now so the path keeps resolving wherever the process ends up.
    // Lexical, unlike `canonicalize`, so the file need not exist yet.
    std::path::absolute(&joined).unwrap_or(joined)
}

/// Locate the configuration when `-c` was not given.
pub fn locate() -> Result<PathBuf> {
    let mut candidates = vec![PathBuf::from("/etc/sightingdb/sightingdb.toml")];
    if let Some(mut home) = dirs::home_dir() {
        home.push(".sightingdb");
        home.push("sightingdb.toml");
        candidates.push(home);
    }

    for candidate in &candidates {
        if candidate.exists() {
            return Ok(candidate.clone());
        }
    }

    Err(anyhow!(
        "no configuration found.\n\
         Run `sightingdb --setup` to create one, or pass -c to point at an existing file.\n\
         Looked in: {}",
        candidates
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            let path = std::env::temp_dir().join(format!("sightingdb-cfg-{tag}"));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).unwrap();
            TempDir(path)
        }

        fn write(&self, name: &str, body: &str) -> PathBuf {
            let path = self.0.join(name);
            let mut f = std::fs::File::create(&path).unwrap();
            f.write_all(body.as_bytes()).unwrap();
            path
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    const MINIMAL: &str = r#"
[daemon]
listen_ip = "127.0.0.1"
listen_port = 9999
authenticate = false
ssl = false
"#;

    #[test]
    fn a_minimal_config_gets_sensible_defaults() {
        let dir = TempDir::new("minimal");
        let settings = Settings::load(&dir.write("c.toml", MINIMAL)).unwrap();

        assert_eq!(settings.listen, "127.0.0.1:9999");
        assert!(settings.http_enabled);
        assert!(!settings.authenticate);
        assert_eq!(settings.tls, None);
        assert_eq!(settings.post_limit, DEFAULT_POST_LIMIT);
        assert_eq!(settings.snapshot_interval, 300);
        assert_eq!(settings.sweep_interval, 60);
        assert_eq!(settings.dbdir, None);
        assert_eq!(settings.acl, None);
        assert_eq!(settings.dns, None);
        assert_eq!(settings.zmq, None);
    }

    #[test]
    fn types_are_real_types_now() {
        let dir = TempDir::new("types");
        let settings = Settings::load(&dir.write(
            "c.toml",
            r#"
[daemon]
ssl = false
authenticate = true
daemonize = false
post_limit = 1234
sweep_interval = 30
stats_retention = 720
"#,
        ))
        .unwrap();

        assert!(settings.authenticate);
        assert!(!settings.daemonize);
        assert_eq!(settings.post_limit, 1234);
        assert_eq!(settings.sweep_interval, 30);
        assert_eq!(settings.stats_retention, 720);
    }

    /// A misspelled key used to be silently ignored, which is how a setting
    /// quietly fails to apply.
    #[test]
    fn a_misspelled_key_is_an_error() {
        let dir = TempDir::new("typo");
        let err =
            Settings::load(&dir.write("c.toml", "[daemon]\nssl = false\nsweep_intervall = 30\n"))
                .unwrap_err();

        let text = format!("{err:#}");
        assert!(text.contains("sweep_intervall"), "{text}");
    }

    #[test]
    fn tls_paths_resolve_against_the_config_file() {
        let dir = TempDir::new("tls");
        let path = dir.write(
            "c.toml",
            "[daemon]\nssl = true\nssl_cert = \"ssl/cert.pem\"\nssl_key = \"/abs/key.pem\"\n",
        );
        let tls = Settings::load(&path).unwrap().tls.unwrap();

        assert_eq!(tls.cert, dir.0.join("ssl/cert.pem"));
        assert_eq!(tls.key, PathBuf::from("/abs/key.pem"));
    }

    #[test]
    fn ssl_without_a_certificate_is_an_error() {
        let dir = TempDir::new("nocert");
        let err = Settings::load(&dir.write("c.toml", "[daemon]\nssl = true\n"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("ssl_cert"), "{err}");
    }

    #[test]
    fn disabling_everything_is_an_error() {
        let dir = TempDir::new("nothing");
        let err = Settings::load(&dir.write("c.toml", "[daemon]\nenabled = false\nssl = false\n"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("nothing to do"), "{err}");
    }

    // -- acl ---------------------------------------------------------------

    #[test]
    fn inline_keys_are_read() {
        let dir = TempDir::new("acl");
        let settings = Settings::load(&dir.write(
            "c.toml",
            "[daemon]\nssl = false\n\n[acl]\nchangeme = \"rw, admin\"\nanalyst = \"r\"\n",
        ))
        .unwrap();

        let acl = settings.acl.unwrap();
        assert!(acl.is_admin("changeme"));
        assert!(acl.can_read("analyst", "anything"));
        assert!(!acl.can_write("analyst", "anything"));
    }

    /// Absent `namespaces` must behave as it always has: store everything.
    #[test]
    fn storage_defaults_to_everything_and_no_galaxy() {
        let dir = TempDir::new("nogalaxy");
        let settings = Settings::load(&dir.write("c.toml", "[daemon]\nssl = false\n")).unwrap();

        assert!(settings.storage.stores_everything());
        assert!(settings.galaxy.is_none());
    }

    #[test]
    fn storage_namespaces_narrow_what_is_held() {
        let dir = TempDir::new("narrow");
        let settings = Settings::load(&dir.write(
            "c.toml",
            "[daemon]\nssl = false\n\n[storage]\nnamespaces = [\"feeds\", \"threats/apt\"]\n",
        ))
        .unwrap();

        assert!(!settings.storage.stores_everything());
        assert!(settings.storage.holds("feeds/misp/ips"));
        assert!(!settings.storage.holds("other"));
    }

    #[test]
    fn an_empty_namespaces_list_is_a_router() {
        let dir = TempDir::new("router");
        let settings = Settings::load(&dir.write(
            "c.toml",
            "[daemon]\nssl = false\n\n[storage]\nnamespaces = []\n",
        ))
        .unwrap();

        assert!(settings.storage.is_router());
        // Still its own internal namespaces.
        assert!(settings.storage.holds("_all"));
    }

    #[test]
    fn a_galaxy_is_parsed_with_its_peers() {
        let dir = TempDir::new("galaxy");
        let settings = Settings::load(&dir.write(
            "c.toml",
            "[daemon]\nssl = false\n\n[galaxy]\nmax_hops = 2\n\
             peers = [\n  { url = \"https://a:9999/\", key = \"k1\" },\n  \
             { url = \"http://b:9999\", key = \"k2\" },\n]\n",
        ))
        .unwrap();

        let galaxy = settings.galaxy.unwrap();
        assert_eq!(galaxy.max_hops, 2);
        assert_eq!(galaxy.peers.len(), 2);
        // Trailing slash trimmed, so the same peer written two ways is one peer.
        assert_eq!(galaxy.peers[0].url, "https://a:9999");
        assert_eq!(galaxy.peers[0].key, "k1");
    }

    /// Each of these would only be discovered at the first forward, which is
    /// the worst time to discover it.
    #[test]
    fn a_misconfigured_galaxy_is_refused_at_startup() {
        let cases = [
            // No key: nothing bounds what this server may do there.
            (
                "nokey",
                "peers = [{ url = \"https://a:9999\", key = \"\" }]",
                "no key",
            ),
            // Not a url we can call.
            (
                "noscheme",
                "peers = [{ url = \"a:9999\", key = \"k\" }]",
                "http",
            ),
            // The same peer twice doubles every write sent to it.
            (
                "dupe",
                "peers = [{ url = \"https://a:9999\", key = \"k\" }, \
                 { url = \"https://a:9999/\", key = \"k\" }]",
                "twice",
            ),
            // A cascade with no hop budget cannot refuse a cycle.
            ("hops", "max_hops = 0\npeers = []", "max_hops"),
        ];

        for (name, body, expected) in cases {
            let dir = TempDir::new(name);
            let err = Settings::load(&dir.write(
                "c.toml",
                &format!("[daemon]\nssl = false\n\n[galaxy]\n{body}\n"),
            ))
            .expect_err(&format!("{name} was accepted"));
            let text = format!("{err:#}");
            assert!(
                text.contains(expected),
                "{name}: expected {expected:?} in {text}"
            );
        }
    }

    /// An internal namespace cannot be a storage prefix: the server holds
    /// those regardless, and listing one would suggest it were optional.
    #[test]
    fn an_internal_storage_prefix_is_refused() {
        let dir = TempDir::new("internalprefix");
        let err = Settings::load(&dir.write(
            "c.toml",
            "[daemon]\nssl = false\n\n[storage]\nnamespaces = [\"_all\"]\n",
        ))
        .expect_err("_all was accepted as a storage prefix");
        assert!(format!("{err:#}").contains("internal"), "{err:#}");
    }

    #[test]
    fn a_separate_acl_file_takes_precedence() {
        let dir = TempDir::new("aclfile");
        dir.write("acl.toml", "[acl]\nfromfile = \"rw, admin\"\n");
        let settings = Settings::load(&dir.write(
            "c.toml",
            "[daemon]\nssl = false\nacl_file = \"acl.toml\"\n\n[acl]\ninline = \"rw\"\n",
        ))
        .unwrap();

        let acl = settings.acl.unwrap();
        assert!(acl.is_admin("fromfile"));
        assert!(!acl.contains("inline"));
    }

    #[test]
    fn a_missing_acl_file_is_not_fatal() {
        let dir = TempDir::new("noaclfile");
        let settings = Settings::load(
            &dir.write("c.toml", "[daemon]\nssl = false\nacl_file = \"acl.toml\"\n"),
        )
        .unwrap();

        // Empty rather than absent, so the interface can create it.
        assert!(settings.acl.unwrap().is_empty());
        assert!(settings.acl_file.is_some());
    }

    #[test]
    fn a_malformed_grant_names_the_key() {
        let dir = TempDir::new("badgrant");
        let err = format!(
            "{:#}",
            Settings::load(&dir.write(
                "c.toml",
                "[daemon]\nssl = false\n\n[acl]\nbroken = \"superuser\"\n",
            ))
            .unwrap_err()
        );
        assert!(err.contains("broken"), "{err}");
        assert!(err.contains("unknown permission"), "{err}");
    }

    // -- dns ---------------------------------------------------------------

    #[test]
    fn dns_namespaces_are_structured() {
        let dir = TempDir::new("dns");
        let settings = Settings::load(&dir.write(
            "c.toml",
            r#"
[daemon]
ssl = false

[dns]
zone = "SDB.Example.Com."
listen_port = 5353

[dns.namespaces]
malware = { namespace = "malware/ips", encoding = "ip" }
domains = { namespace = "malware/domains", encoding = "domain" }
"#,
        ))
        .unwrap();

        let dns = settings.dns.unwrap();
        assert_eq!(dns.zone, "sdb.example.com");
        assert_eq!(dns.listen, "127.0.0.1:5353");
        assert_eq!(dns.rate_limit, 100);
        assert_eq!(dns.exposed.len(), 2);
        assert_eq!(dns.exposed[0].label, "domains");
        assert_eq!(dns.exposed[1].encoding, Encoding::Ip);
    }

    #[test]
    fn dns_can_be_disabled_without_deleting_the_table() {
        let dir = TempDir::new("dnsoff");
        let settings = Settings::load(&dir.write(
            "c.toml",
            "[daemon]\nssl = false\n\n[dns]\nenabled = false\nzone = \"x.example\"\n",
        ))
        .unwrap();
        assert_eq!(settings.dns, None);
    }

    #[test]
    fn exposing_an_internal_namespace_over_dns_is_refused() {
        let dir = TempDir::new("dnsinternal");
        let err = Settings::load(&dir.write(
            "c.toml",
            r#"
[daemon]
ssl = false
[dns]
zone = "x.example"
[dns.namespaces]
keys = { namespace = "_config/acl", encoding = "domain" }
"#,
        ))
        .unwrap_err()
        .to_string();
        assert!(err.contains("_config/acl"), "{err}");
    }

    // -- ingest ------------------------------------------------------------

    #[test]
    fn zmq_topics_are_a_real_list() {
        let dir = TempDir::new("zmq");
        let settings = Settings::load(&dir.write(
            "c.toml",
            r#"
[daemon]
ssl = false

[zmq]
endpoint = "tcp://misp:50000"
topics = ["misp_json_attribute", "misp_json"]
require_to_ids = true

[zmq.types]
ip-src = "misp/ips"
"#,
        ))
        .unwrap();

        let zmq = settings.zmq.unwrap();
        assert_eq!(zmq.topics, ["misp_json_attribute", "misp_json"]);
        assert!(zmq.mapping.require_to_ids);
        assert_eq!(zmq.mapping.types["ip-src"], "misp/ips");
        assert_eq!(zmq.reconnect, 5);
    }

    #[test]
    fn quoted_keys_carry_dots_through_to_the_mapping() {
        let dir = TempDir::new("stix");
        let settings = Settings::load(&dir.write(
            "c.toml",
            r#"
[daemon]
ssl = false

[stix.types]
ipv4-addr = "stix/ips"
"file.MD5" = "stix/hashes"
"#,
        ))
        .unwrap();

        assert_eq!(settings.stix.mapping.types["file.MD5"], "stix/hashes");
    }

    #[test]
    fn the_export_identity_defaults_and_can_be_configured() {
        let dir = TempDir::new("stixidentity");

        let settings = Settings::load(&dir.write("d.toml", "[daemon]\nssl = false\n")).unwrap();
        assert_eq!(settings.stix.export, crate::stix::Settings::default());

        let settings = Settings::load(&dir.write(
            "c.toml",
            r#"
[daemon]
ssl = false

[stix]
identity = "Alpha Threat Analysis Org."
identity_class = "organization"
"#,
        ))
        .unwrap();

        assert_eq!(settings.stix.export.identity, "Alpha Threat Analysis Org.");
        assert_eq!(settings.stix.export.identity_class, "organization");
    }

    /// The import mapping read backwards tells the export what a namespace
    /// holds, so values written by other means still get the right pattern.
    #[test]
    fn a_namespace_inherits_the_type_it_was_mapped_to() {
        let dir = TempDir::new("stixinverse");
        let settings = Settings::load(&dir.write(
            "c.toml",
            r#"
[daemon]
ssl = false

[stix.types]
ipv4-addr = "feeds"
domain-name = "feeds/domains"
"#,
        ))
        .unwrap();

        // The most specific mapping wins.
        assert_eq!(
            settings.stix.type_of_namespace("feeds/domains"),
            Some("domain-name")
        );
        assert_eq!(
            settings.stix.type_of_namespace("feeds/misp/ips"),
            Some("ipv4-addr")
        );
        assert_eq!(settings.stix.type_of_namespace("feeds"), Some("ipv4-addr"));
        // Whole segments only, and nothing to say about an unrelated tree.
        assert_eq!(settings.stix.type_of_namespace("feeds-internal"), None);
        assert_eq!(settings.stix.type_of_namespace("other"), None);
    }

    /// The INI version of this mistake silently mapped nothing. TOML turns it
    /// into a nested table, which is at least detectable — so detect it.
    #[test]
    fn an_unquoted_dotted_key_is_reported() {
        let dir = TempDir::new("stixdot");
        let err = Settings::load(&dir.write(
            "c.toml",
            "[daemon]\nssl = false\n\n[stix.types]\nfile.MD5 = \"stix/hashes\"\n",
        ))
        .unwrap_err()
        .to_string();

        assert!(err.contains("has to be quoted"), "{err}");
    }

    #[test]
    fn a_missing_file_says_so() {
        let err = Settings::load(Path::new("/nonexistent/sightingdb.toml"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("reading config file"), "{err}");
    }
}
