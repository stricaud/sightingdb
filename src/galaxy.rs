//! The other servers this one knows about, and whether they are answering.
//!
//! A galaxy is a set of peers, each reached over the same HTTP API a client
//! uses. Nothing is forwarded to them yet; what exists here is the part a
//! topology view needs first — who they are, and whether they are up.
//!
//! **Health is probed, not assumed.** Each peer's `/health` is called on an
//! interval and the result kept. `/health` needs no API key, so a probe
//! carries no credential: a peer that is up answers it to anyone, and the
//! answer also carries the peer's version, which is worth knowing before a
//! mixed-version galaxy starts behaving oddly.
//!
//! The probe deliberately reports *reachability from here*. A peer that is
//! running but unreachable from this server is, for this server's purposes,
//! down — and saying so is more useful than saying it is up.

use std::collections::HashMap;
use std::sync::{Arc, PoisonError, RwLock};
use std::time::{Duration, Instant};

use serde::Serialize;

use crate::config::{GalaxySettings, Peer};
use crate::maintenance::Shutdown;

/// How long a single probe may take before it counts as a failure.
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// How long a forwarded request may take.
///
/// Longer than a probe, because it is doing work rather than answering a
/// liveness question, and short enough that a client is not left waiting on a
/// peer that has stopped answering mid-request.
const FORWARD_TIMEOUT: Duration = Duration::from_secs(20);

/// Carries how many more hops a forwarded request may take.
///
/// A cascade can be miswired into a cycle, and a cycle inflates every count
/// that travels round it. This is the only thing that stops it, so it is a
/// limit rather than a tuning knob.
pub const HOPS_HEADER: &str = "X-SightingDB-Hops";

/// Names the server a forwarded write originated at.
///
/// Without this, fanning one write out to two mirrors has each mirror count it
/// under *its own* name — and merging the two then adds them together. Measured
/// on a real cascade: three writes through a load balancer became six after the
/// mirrors synced.
///
/// So the origin travels with the write and every mirror counts it under the
/// same name. Merging is then a no-op between mirrors that already agree, which
/// is what it should be. In a cascade the header is passed along unchanged, so
/// the attribution is the entry point the client actually talked to.
pub const ORIGIN_HEADER: &str = "X-SightingDB-Origin";

/// What the last probe of one peer found.
#[derive(Debug, Clone, Serialize)]
pub struct PeerHealth {
    pub url: String,
    /// Whether the last probe succeeded. `false` before the first one has run,
    /// which is why `probed` exists — "not yet asked" is not "down".
    pub online: bool,
    /// Whether this peer has been probed at all since startup.
    pub probed: bool,
    /// Unix seconds of the last *successful* probe, or 0 if there has not been
    /// one. Kept across failures so an operator can see how stale a peer is.
    pub last_seen: i64,
    /// Round trip of the last successful probe.
    pub latency_ms: Option<u64>,
    /// The peer's version, from its own `/health`. A galaxy running mixed
    /// versions is worth seeing before it misbehaves.
    pub version: Option<String>,
    /// Why the last probe failed, in the words the client gave us.
    pub error: Option<String>,
    /// Consecutive failures, so a flapping peer reads differently from one
    /// that has been gone all week.
    pub failures: u32,
    /// Whether the peer said it is still pulling what it missed.
    ///
    /// Reads are sent elsewhere while it is: its data is incomplete and a read
    /// would under-report. Writes still go to it — they land directly, and its
    /// catch-up fills in the history behind them.
    pub catching_up: bool,
}

impl PeerHealth {
    pub fn unprobed(url: &str) -> Self {
        PeerHealth {
            url: url.to_string(),
            online: false,
            probed: false,
            last_seen: 0,
            latency_ms: None,
            version: None,
            error: None,
            failures: 0,
            catching_up: false,
        }
    }
}

/// The peers, and what is known about them.
#[derive(Debug)]
pub struct Galaxy {
    /// The peers, which the management interface can add to and remove from
    /// while the server runs. Behind a lock for that reason, like the ACL:
    /// adding a mirror should not need a restart, and a restart of a router is
    /// a gap in service for everything behind it.
    ///
    /// Read as a snapshot rather than held across a request, so a long
    /// forward cannot block an edit. The cost is a handful of small clones
    /// per request, which is nothing beside the HTTP call they are for.
    peers: RwLock<Vec<Peer>>,
    /// How many hops a forwarded request may still take. Spent on each hop and
    /// refused at zero, which is what stops a miswired cycle.
    max_hops: u8,
    /// How often each peer is probed.
    health_interval: u64,
    /// How often a catch-up pass runs. 0 switches it off.
    sync_interval: u64,
    /// How often the consensus tally is rebuilt from the galaxy. 0 switches it
    /// off, which leaves the tally drifting upward as values expire.
    reconcile_interval: u64,
    /// How often this server's keys are offered to its peers. 0 switches it
    /// off, leaving only the push made when a key is changed.
    gossip_interval: u64,
    /// Whether this server's key list is the galaxy's, so the offer replaces a
    /// peer's list rather than adding to it.
    acl_authority: bool,
    /// Whether a peer's TLS certificate is verified. Off is for a galaxy of
    /// self-signed instances, which is what `--setup` produces.
    verify_tls: bool,
    health: RwLock<HashMap<String, PeerHealth>>,
    /// URLs declared in the main configuration, which the management
    /// interface may show but not change. See
    /// [`crate::config::GalaxySettings::peers_file`].
    fixed: Vec<String>,
}

/// A forwarded response body is read into memory, so it needs a ceiling. Large
/// enough for a STIX bundle at the default export limit.
const FORWARD_BODY_LIMIT: usize = 64 * 1024 * 1024;

/// Why a request could not be forwarded.
#[derive(Debug)]
pub enum ForwardError {
    /// No peer stores this namespace.
    NoHolder,
    /// Every peer that stores this namespace is unreachable.
    AllDown { namespace: String },
    /// The hop budget ran out, which means a cycle or a cascade deeper than
    /// `max_hops`.
    TooManyHops,
    /// The peer could not be reached for this request.
    Unreachable(String),
}

impl std::fmt::Display for ForwardError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ForwardError::NoHolder => {
                write!(f, "no server in this galaxy stores that namespace")
            }
            ForwardError::AllDown { namespace } => {
                write!(
                    f,
                    "every server storing '{namespace}' is unreachable from here"
                )
            }
            ForwardError::TooManyHops => write!(
                f,
                "the hop limit was reached: the galaxy is wired in a loop, or is deeper than max_hops allows"
            ),
            ForwardError::Unreachable(e) => write!(f, "could not reach the server holding it: {e}"),
        }
    }
}

impl Galaxy {
    pub fn new(settings: &GalaxySettings) -> Self {
        let health = settings
            .peers
            .iter()
            .map(|peer| (peer.url.clone(), PeerHealth::unprobed(&peer.url)))
            .collect();

        Galaxy {
            peers: RwLock::new(settings.peers.clone()),
            fixed: settings.fixed.clone(),
            max_hops: settings.max_hops,
            health_interval: settings.health_interval,
            sync_interval: settings.sync_interval,
            reconcile_interval: settings.reconcile_interval,
            gossip_interval: settings.gossip_interval,
            acl_authority: settings.acl_authority,
            verify_tls: settings.verify_tls,
            health: RwLock::new(health),
        }
    }

    pub fn max_hops(&self) -> u8 {
        self.max_hops
    }

    /// Every peer, as a snapshot.
    pub fn peers(&self) -> Vec<Peer> {
        self.peers
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Peers that store `namespace`, in configured order.
    pub fn holders(&self, namespace: &str) -> Vec<Peer> {
        self.peers
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .filter(|peer| peer.stores.holds(namespace))
            .cloned()
            .collect()
    }

    /// Peers that store `namespace` *and* are answering.
    ///
    /// A peer not yet probed counts as usable: refusing to forward for the
    /// first few seconds of a server's life would be worse than trying and
    /// finding out.
    pub fn live_holders(&self, namespace: &str) -> Vec<Peer> {
        let health = self.health.read().unwrap_or_else(PoisonError::into_inner);
        self.holders(namespace)
            .into_iter()
            .filter(|peer| {
                health
                    .get(&peer.url)
                    .is_none_or(|known| known.online || !known.probed)
            })
            .collect()
    }

    /// Which live holder should serve a read of `value`.
    ///
    /// Chosen by rendezvous hashing over the holders, so the same value is
    /// always read from the same mirror while the set is unchanged. Mirrors
    /// diverge transiently under async sync, and without this two consecutive
    /// reads could be served by different mirrors and show a count going
    /// *down*.
    ///
    /// SHA-256 rather than something faster: appending a peer name to a value
    /// must perturb the whole hash, or the comparison between peers becomes
    /// correlated and the choice stops being evenly spread. Measured in
    /// doc/sharding-experiment.py.
    /// A mirror still catching up is passed over, because its data is
    /// incomplete and a read of it would under-report. If every mirror is
    /// catching up, one of them answers anyway: an under-reported count beats
    /// no answer at all, and refusing would make a whole galaxy unreadable
    /// for as long as it took to start.
    pub fn reader_for(&self, namespace: &str, value: &str) -> Option<Peer> {
        let behind: Vec<String> = {
            let health = self.health.read().unwrap_or_else(PoisonError::into_inner);
            health
                .values()
                .filter(|known| known.catching_up)
                .map(|known| known.url.clone())
                .collect()
        };

        let live = self.live_holders(namespace);
        let current: Vec<Peer> = live
            .iter()
            .filter(|peer| !behind.contains(&peer.url))
            .cloned()
            .collect();

        let choose_from = if current.is_empty() { live } else { current };
        choose_from
            .into_iter()
            .max_by_key(|peer| weigh(value, &peer.url))
    }

    /// Every peer's health, in the order they were configured.
    ///
    /// Configured order rather than whatever the map iterates in, so the view
    /// does not reshuffle itself between refreshes.
    pub fn health(&self) -> Vec<PeerHealth> {
        let health = self.health.read().unwrap_or_else(PoisonError::into_inner);
        self.peers()
            .iter()
            .map(|peer| {
                health
                    .get(&peer.url)
                    .cloned()
                    .unwrap_or_else(|| PeerHealth::unprobed(&peer.url))
            })
            .collect()
    }

    fn record(&self, url: &str, outcome: Result<Probed, String>) {
        let mut health = self.health.write().unwrap_or_else(PoisonError::into_inner);
        let entry = health
            .entry(url.to_string())
            .or_insert_with(|| PeerHealth::unprobed(url));

        entry.probed = true;
        match outcome {
            Ok(probed) => {
                if !entry.online && entry.failures > 0 {
                    log::info!("Galaxy peer {url} is answering again");
                }
                if probed.catching_up && !entry.catching_up {
                    log::info!("Galaxy peer {url} is catching up; reads will go elsewhere");
                } else if !probed.catching_up && entry.catching_up {
                    log::info!("Galaxy peer {url} has caught up");
                }
                entry.online = true;
                entry.last_seen = chrono::Utc::now().timestamp();
                entry.latency_ms = Some(probed.latency_ms);
                entry.version = probed.version;
                entry.error = None;
                entry.failures = 0;
                entry.catching_up = probed.catching_up;
            }
            Err(error) => {
                // Logged on the first failure only: a peer that has been gone
                // for a week should not fill the log saying so.
                if entry.online || !entry.probed || entry.failures == 0 {
                    log::warn!("Galaxy peer {url} is not answering: {error}");
                }
                entry.online = false;
                entry.latency_ms = None;
                entry.error = Some(error);
                entry.failures = entry.failures.saturating_add(1);
            }
        }
    }
}

/// Why a peer was not taken into the galaxy.
///
/// Two cases because they are two different answers: a peer that cannot be
/// used however it is sent is a bad request, and one that is simply already
/// known is a conflict. Collapsing them would make "you already have this"
/// indistinguishable from "this is not a URL".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddPeer {
    /// Not usable as a peer at all.
    Invalid(String),
    /// This galaxy already has it.
    AlreadyThere(String),
}

impl std::fmt::Display for AddPeer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AddPeer::Invalid(message) | AddPeer::AlreadyThere(message) => write!(f, "{message}"),
        }
    }
}

/// Does this URL point at the server doing the asking?
///
/// Best effort, and only for catching the obvious mistake of adding a server
/// to its own galaxy. A hostname that resolves to the same machine, or a proxy
/// in front of it, is not caught — which is why the hop count, not this, is
/// what makes a loop safe.
fn is_own_address(url: &str, own_listen: &str) -> bool {
    let host_port = url
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_end_matches('/');
    if host_port == own_listen {
        return true;
    }
    // A server listening on every interface answers on localhost too, so
    // "0.0.0.0:9999" and "127.0.0.1:9999" are the same server.
    let Some((own_host, own_port)) = own_listen.rsplit_once(':') else {
        return false;
    };
    let Some((host, port)) = host_port.rsplit_once(':') else {
        return false;
    };
    port == own_port
        && matches!(own_host, "0.0.0.0" | "[::]" | "::")
        && matches!(host, "127.0.0.1" | "localhost" | "[::1]" | "::1")
}

/// The rendezvous weight of one (value, peer) pair.
fn weigh(value: &str, url: &str) -> u64 {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(value.as_bytes());
    hasher.update(b":");
    hasher.update(url.as_bytes());
    let digest = hasher.finalize();
    u64::from_be_bytes(digest[..8].try_into().unwrap_or([0; 8]))
}

/// Who a forwarded write should be counted for.
///
/// Only honoured on a request that was forwarded — one carrying a hops header.
/// The origin is part of the forwarding protocol, not the client API, and a
/// client naming it would only mislabel its own writes rather than change any
/// total. Keeping it to forwarded requests says plainly which it is.
///
/// Passed along unchanged in a cascade, so every mirror however deep counts the
/// write for the entry point the client actually talked to.
pub fn origin_of(req: &actix_web::HttpRequest) -> Option<String> {
    // Present only on a forwarded request, which is the point of checking it.
    req.headers().get(HOPS_HEADER)?;
    let origin = req.headers().get(ORIGIN_HEADER)?.to_str().ok()?.trim();
    (!origin.is_empty()).then(|| origin.to_string())
}

/// How many hops a request arriving here may still take.
///
/// Absent means it came from a client, which gets the full budget. Present
/// means it was forwarded, and the sender has already spent one.
pub fn hops_left(req: &actix_web::HttpRequest, max: u8) -> Option<u8> {
    match req.headers().get(HOPS_HEADER) {
        None => Some(max),
        Some(value) => {
            let left: u8 = value.to_str().ok()?.trim().parse().ok()?;
            (left > 0).then_some(left)
        }
    }
}

/// Probe every peer on an interval until asked to stop.
///
/// Runs as one task on the actix runtime beside the ZMQ ingest, rather than on
/// a thread of its own: the client is not `Send`, and a probe is almost all
/// waiting.
pub async fn run(state: Arc<crate::handlers::SharedState>, shutdown: Arc<Shutdown>) {
    let Some(galaxy) = state.galaxy.as_ref() else {
        return;
    };
    // No check for an empty peer list. Peers can be added while the server
    // runs — see [`Galaxy::add_peer`] — and a poller that gave up at startup
    // would leave every one of them for ever unprobed, which the interface
    // shows as "not asked yet" rather than as a server it knows nothing
    // about. An idle round over an empty list costs nothing.
    let Some(client) = client(galaxy.verify_tls) else {
        log::error!("Galaxy health checks disabled: no HTTP client could be built");
        return;
    };

    let tls_note = if galaxy.verify_tls {
        ""
    } else {
        " (TLS verification off)"
    };
    match galaxy.peers().len() {
        0 => log::info!(
            "Galaxy health checks every {}s, once there are peers to check{tls_note}",
            galaxy.health_interval
        ),
        n => log::info!(
            "Galaxy health checks every {}s for {n} peer(s){tls_note}",
            galaxy.health_interval
        ),
    }

    let period = Duration::from_secs(galaxy.health_interval);
    loop {
        for peer in &galaxy.peers() {
            if shutdown.is_stopped() {
                return;
            }
            let outcome = probe(&client, &peer.url).await;
            galaxy.record(&peer.url, outcome);
        }

        if shutdown.is_stopped() {
            return;
        }
        actix_web::rt::time::sleep(period).await;
    }
}

/// What a forwarded request came back with.
pub struct Forwarded {
    pub status: u16,
    pub body: Vec<u8>,
    /// Headers worth passing back to our client: the content type, and
    /// anything this API says about the answer in a header rather than in the
    /// body.
    ///
    /// A STIX export puts how much it exported and what it skipped in
    /// `X-SightingDB-*`, so relaying only the status and the body would hand
    /// the client a bundle and silently drop the part that says whether
    /// anything was left out of it.
    pub headers: Vec<(String, String)>,
}

impl Galaxy {
    /// Send a request to one peer, spending a hop.
    ///
    /// The peer's own key goes with it, which is what bounds what this server
    /// can do there: a peer granted `rw:feeds` cannot be made to write
    /// anywhere else by anything this server sends.
    async fn send(
        &self,
        peer: &Peer,
        method: awc::http::Method,
        path: &str,
        body: Option<&[u8]>,
        hops_left: u8,
        origin: &str,
    ) -> Result<Forwarded, ForwardError> {
        let client = client(self.verify_tls).ok_or_else(|| {
            ForwardError::Unreachable("no HTTP client could be built".to_string())
        })?;

        let mut request = client
            .request(method, format!("{}{path}", peer.url))
            // Per request rather than on the client, which the health poller
            // shares: a probe should give up long before a forwarded write.
            .timeout(FORWARD_TIMEOUT)
            .insert_header(("Authorization", peer.key.as_str()))
            // One hop spent. The receiver refuses at zero, so a cycle dies
            // rather than circulating.
            .insert_header((HOPS_HEADER, (hops_left - 1).to_string()))
            // Who the write is counted for, wherever it lands.
            .insert_header((ORIGIN_HEADER, origin));

        let mut response = match body {
            Some(bytes) => {
                request = request.insert_header(("Content-Type", "application/json"));
                request.send_body(bytes.to_vec()).await
            }
            None => request.send().await,
        }
        .map_err(|e| ForwardError::Unreachable(e.to_string()))?;

        let status = response.status().as_u16();
        // Taken before the body, which consumes the response.
        let headers: Vec<(String, String)> = response
            .headers()
            .iter()
            .filter(|(name, _)| {
                let name = name.as_str().to_ascii_lowercase();
                name == "content-type" || name.starts_with("x-sightingdb-")
            })
            .filter_map(|(name, value)| {
                Some((name.as_str().to_string(), value.to_str().ok()?.to_string()))
            })
            .collect();
        let body = response
            .body()
            .limit(FORWARD_BODY_LIMIT)
            .await
            .map_err(|e| ForwardError::Unreachable(e.to_string()))?
            .to_vec();

        Ok(Forwarded {
            status,
            body,
            headers,
        })
    }

    /// Forward a read to the one mirror that should serve it.
    pub async fn forward_read(
        &self,
        namespace: &str,
        value: &str,
        path: &str,
        hops_left: u8,
        origin: &str,
    ) -> Result<Forwarded, ForwardError> {
        if hops_left == 0 {
            return Err(ForwardError::TooManyHops);
        }
        if self.holders(namespace).is_empty() {
            return Err(ForwardError::NoHolder);
        }
        let peer = self
            .reader_for(namespace, value)
            .ok_or_else(|| ForwardError::AllDown {
                namespace: namespace.to_string(),
            })?;

        self.send(&peer, awc::http::Method::GET, path, None, hops_left, origin)
            .await
    }

    /// Was this peer declared in the main configuration?
    ///
    /// Such a peer is read-only here: it lives in a hand-maintained file that
    /// this program does not rewrite, so letting the interface "remove" one
    /// would mean it came back at the next restart.
    pub fn is_fixed(&self, url: &str) -> bool {
        let url = url.trim().trim_end_matches('/');
        self.fixed.iter().any(|known| known == url)
    }

    /// The peers that belong in the peers file: everything the interface
    /// added, and nothing the main configuration declared.
    pub fn editable_peers(&self) -> Vec<Peer> {
        self.peers()
            .into_iter()
            .filter(|peer| !self.is_fixed(&peer.url))
            .collect()
    }

    /// Take a peer into the galaxy while the server runs.
    ///
    /// Returns the reason it was refused, if it was. Deliberately **does not**
    /// require the peer to be reachable: a mirror that is down should still be
    /// addable, or a galaxy could not be rebuilt after whatever took it down.
    /// The health poller picks it up on its next pass and the interface shows
    /// it offline until it answers.
    ///
    /// A loop is not checked for beyond the obvious case of this server's own
    /// address. Two routers pointed at each other is legitimate — that is what
    /// cascading is — and what makes it safe is the hop count, spent on every
    /// forward and refused at zero.
    pub fn add_peer(&self, peer: Peer, own_listen: &str) -> Result<Peer, AddPeer> {
        let peer = Peer {
            url: peer.url.trim().trim_end_matches('/').to_string(),
            key: peer.key.trim().to_string(),
            stores: peer.stores,
        };
        if !(peer.url.starts_with("http://") || peer.url.starts_with("https://")) {
            return Err(AddPeer::Invalid(
                "a peer URL starts with http:// or https://".to_string(),
            ));
        }
        if peer
            .url
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .is_empty()
        {
            return Err(AddPeer::Invalid("a peer URL needs a host".to_string()));
        }
        if peer.key.is_empty() {
            return Err(AddPeer::Invalid(
                "a peer needs the key this server will authenticate with there".to_string(),
            ));
        }
        if is_own_address(&peer.url, own_listen) {
            return Err(AddPeer::Invalid(format!(
                "{} is this server's own address, which would make it its own mirror",
                peer.url
            )));
        }

        let mut peers = self.peers.write().unwrap_or_else(PoisonError::into_inner);
        if peers.iter().any(|known| known.url == peer.url) {
            return Err(AddPeer::AlreadyThere(format!(
                "{} is already in this galaxy",
                peer.url
            )));
        }
        if self.is_fixed(&peer.url) {
            return Err(AddPeer::AlreadyThere(format!(
                "{} is declared in the configuration file, so it cannot be changed here",
                peer.url
            )));
        }
        peers.push(peer.clone());
        Ok(peer)
    }

    /// Drop a peer. Returns false if it was not there.
    ///
    /// Its health is forgotten with it, so re-adding the same URL starts
    /// unprobed rather than inheriting a stale "offline".
    pub fn remove_peer(&self, url: &str) -> bool {
        let url = url.trim().trim_end_matches('/');
        let mut peers = self.peers.write().unwrap_or_else(PoisonError::into_inner);
        let before = peers.len();
        peers.retain(|peer| peer.url != url);
        let removed = peers.len() != before;
        drop(peers);
        if removed {
            self.health
                .write()
                .unwrap_or_else(PoisonError::into_inner)
                .remove(url);
        }
        removed
    }

    /// Replace a peer's key or namespace list, keeping its place in the order.
    pub fn update_peer(&self, peer: Peer) -> Option<Peer> {
        let peer = Peer {
            url: peer.url.trim().trim_end_matches('/').to_string(),
            key: peer.key.trim().to_string(),
            stores: peer.stores,
        };
        if peer.key.is_empty() {
            return None;
        }
        let mut peers = self.peers.write().unwrap_or_else(PoisonError::into_inner);
        match peers.iter_mut().find(|known| known.url == peer.url) {
            Some(known) => {
                *known = peer.clone();
                Some(peer)
            }
            None => None,
        }
    }

    /// Push one value's state to every mirror that holds its namespace.
    ///
    /// For a change that is not a sighting and so has no other way to travel:
    /// a tag set or removed in the management interface. Sent through
    /// `/_api/merge`, the same channel the periodic catch-up uses, so the
    /// mirrors apply it by the merge rules — it converges, it can be retried,
    /// and it needs only the write grant a peer key already has. Forwarding
    /// the management request instead would need `admin` on every peer key,
    /// which is the opposite of keeping those keys narrow.
    ///
    /// A mirror that is down gets it at the next catch-up instead, because
    /// what is pushed is state rather than an instruction: the mirror pulls
    /// the same thing when it comes back. So a failure here is reported and
    /// not retried.
    pub async fn push_value(
        &self,
        namespace: &str,
        value: &str,
        state: &crate::attribute::Merge,
        hops_left: u8,
    ) -> Vec<(String, Result<u16, String>)> {
        let body = serde_json::to_vec(&serde_json::json!({
            "items": [{
                "namespace": namespace,
                "value": value,
                "counts": state.counts,
                "stats": state.stats,
                "first_seen": state.first_seen,
                "last_seen": state.last_seen,
                "tags": state.tags,
                "tags_at": state.tags_at,
                "ttl": state.ttl,
            }]
        }))
        .unwrap_or_default();

        let mut outcomes = Vec::new();
        for peer in self.live_holders(namespace) {
            let sent = self
                .send(
                    &peer,
                    awc::http::Method::POST,
                    "/_api/merge",
                    Some(&body),
                    hops_left,
                    "",
                )
                .await;
            outcomes.push((
                peer.url.clone(),
                match sent {
                    Ok(answer) if (200..300).contains(&answer.status) => Ok(answer.status),
                    Ok(answer) => Err(format!(
                        "answered {}: {}",
                        answer.status,
                        String::from_utf8_lossy(&answer.body)
                    )),
                    Err(e) => Err(e.to_string()),
                },
            ));
        }
        outcomes
    }

    /// Which live mirror should serve a read of `value`, by URL.
    ///
    /// The same choice [`forward_read`](Self::forward_read) makes, exposed so
    /// a bulk read can group its items by mirror before sending anything. The
    /// error says which of the two "not here" cases it is, so a batch can
    /// report it per item instead of failing whole.
    pub fn reader_url(&self, namespace: &str, value: &str) -> Result<String, ForwardError> {
        if self.holders(namespace).is_empty() {
            return Err(ForwardError::NoHolder);
        }
        self.reader_for(namespace, value)
            .map(|peer| peer.url.clone())
            .ok_or_else(|| ForwardError::AllDown {
                namespace: namespace.to_string(),
            })
    }

    /// Send a request to one mirror already chosen by URL.
    ///
    /// For a request the caller has worked out the destination for itself —
    /// a bulk read grouped by mirror, where sending the whole batch to every
    /// holder would both cost more and break the per-value stickiness that
    /// [`reader_for`](Self::reader_for) exists to provide.
    pub async fn forward_to(
        &self,
        url: &str,
        method: awc::http::Method,
        path: &str,
        body: Option<&[u8]>,
        hops_left: u8,
        origin: &str,
    ) -> Result<Forwarded, ForwardError> {
        if hops_left == 0 {
            return Err(ForwardError::TooManyHops);
        }
        let peer = self
            .peers()
            .into_iter()
            .find(|peer| peer.url == url)
            .ok_or_else(|| ForwardError::Unreachable(format!("{url} is not a configured peer")))?;
        self.send(&peer, method, path, body, hops_left, origin)
            .await
    }

    /// Forward a write to every live mirror of the namespace.
    ///
    /// Returns what each said. The caller decides what a partial success
    /// means, because that differs between a single write and a batch.
    ///
    /// Accepting on one mirror and not another is not a lost write: the
    /// mirror that took it is the record the others catch up from. What must
    /// never happen is acknowledging a write that reached *no* mirror, which
    /// is why an empty result is an error rather than a success.
    pub async fn forward_write(
        &self,
        namespace: &str,
        method: awc::http::Method,
        path: &str,
        body: Option<&[u8]>,
        hops_left: u8,
        origin: &str,
    ) -> Result<Vec<(String, Forwarded)>, ForwardError> {
        if hops_left == 0 {
            return Err(ForwardError::TooManyHops);
        }
        if self.holders(namespace).is_empty() {
            return Err(ForwardError::NoHolder);
        }

        let live: Vec<Peer> = self.live_holders(namespace);
        if live.is_empty() {
            return Err(ForwardError::AllDown {
                namespace: namespace.to_string(),
            });
        }

        let mut answers = Vec::with_capacity(live.len());
        let mut last_error = None;
        for peer in &live {
            match self
                .send(peer, method.clone(), path, body, hops_left, origin)
                .await
            {
                Ok(answer) => answers.push((peer.url.clone(), answer)),
                Err(e) => {
                    log::warn!("Forwarding to {} failed: {e}", peer.url);
                    last_error = Some(e);
                }
            }
        }

        if answers.is_empty() {
            return Err(last_error.unwrap_or_else(|| ForwardError::AllDown {
                namespace: namespace.to_string(),
            }));
        }
        Ok(answers)
    }
}

impl Galaxy {
    /// Forward a whole batch to every live peer that holds any part of it.
    ///
    /// The batch is sent unchanged, so item indices line up with what came in
    /// and a peer's per-item answers can be merged back without translation.
    /// A peer refuses the items it does not hold with its own `421`, which is
    /// exactly the per-item status the bulk routes already report — so letting
    /// it refuse is cheaper than working out in advance what to send where.
    pub async fn forward_batch(
        &self,
        namespaces: &[String],
        path: &str,
        body: &[u8],
        hops_left: u8,
        origin: &str,
    ) -> Result<Vec<(String, Forwarded)>, ForwardError> {
        if hops_left == 0 {
            return Err(ForwardError::TooManyHops);
        }

        let mut wanted: Vec<Peer> = Vec::new();
        for namespace in namespaces {
            for peer in self.live_holders(namespace) {
                if !wanted.iter().any(|known| known.url == peer.url) {
                    wanted.push(peer.clone());
                }
            }
        }
        if wanted.is_empty() {
            return Err(ForwardError::NoHolder);
        }

        let mut answers = Vec::with_capacity(wanted.len());
        let mut last_error = None;
        for peer in &wanted {
            match self
                .send(
                    peer,
                    awc::http::Method::POST,
                    path,
                    Some(body),
                    hops_left,
                    origin,
                )
                .await
            {
                Ok(answer) => answers.push((peer.url.clone(), answer)),
                Err(e) => {
                    log::warn!("Forwarding a batch to {} failed: {e}", peer.url);
                    last_error = Some(e);
                }
            }
        }
        if answers.is_empty() {
            return Err(last_error.unwrap_or(ForwardError::NoHolder));
        }
        Ok(answers)
    }
}

impl Galaxy {
    /// Ask each peer for its own galaxy, so one request describes a cascade.
    ///
    /// One level per hop, bounded by `max_hops`: a view of a miswired galaxy
    /// must terminate like everything else here. What comes back is each peer's
    /// own answer, unexamined beyond being valid JSON — it describes that
    /// peer's view, which is the only honest thing a cascade can report.
    ///
    /// A peer that cannot be reached contributes nothing but its health, which
    /// is already known. The walk does not fail for it: half a picture of a
    /// galaxy with a server down is the picture.
    pub async fn walk(&self, hops_left: u8) -> Vec<(String, serde_json::Value)> {
        if hops_left == 0 {
            return Vec::new();
        }
        let mut found = Vec::new();
        for peer in &self.peers() {
            match self
                .send(
                    peer,
                    awc::http::Method::GET,
                    "/_management/api/galaxy",
                    None,
                    hops_left,
                    "",
                )
                .await
            {
                Ok(answer) if (200..300).contains(&answer.status) => {
                    if let Ok(view) = serde_json::from_slice(&answer.body) {
                        found.push((peer.url.clone(), view));
                    }
                }
                // Unreachable, or it refused us. Its health already says so,
                // and a topology view that failed because one server is down
                // would be useless exactly when it is needed.
                _ => {}
            }
        }
        found
    }
}

/// Pull what this server missed, on a timer, until asked to stop.
///
/// A galaxy heals itself this way rather than needing someone with curl: a
/// server that was down comes back, finds it is behind, and fills in from a
/// peer that was up.
///
/// **Writes are accepted throughout.** A catch-up withholds *reads* instead —
/// through the `catching_up` flag on `/health`, which something in front of
/// this server reads to send reads elsewhere. Withholding writes would mean
/// the target keeps moving: under continuous load the pass would have no point
/// at which it provably finished.
///
/// The first pass is a full one, because a server that has just started has no
/// idea what it missed. Later passes use `?count` as a cheap trigger — it is
/// O(1) — and skip a namespace whose peer has no more values than we do. That
/// is a heuristic and not a proof: equal counts do not mean equal contents,
/// two servers can each hold a hundred values the other lacks and report the
/// same total. It is the right trade for a timer, and the full pass on startup
/// is what stops the heuristic being load-bearing.
pub async fn sync(state: Arc<crate::handlers::SharedState>, shutdown: Arc<Shutdown>) {
    let Some(galaxy) = state.galaxy.as_ref() else {
        return;
    };
    if galaxy.sync_interval == 0 {
        // Catching up is off, so this server is as current as it is going to
        // get.
        state.set_catching_up(false);
        return;
    }
    // An empty peer list is *not* a reason to stop: peers can be added while
    // the server runs. It does mean there is nothing to be behind, so the
    // flag is cleared now and the loop below picks up any peer that appears.
    if galaxy.peers().is_empty() {
        state.set_catching_up(false);
    }

    match galaxy.peers().len() {
        0 => log::info!(
            "Catching up every {}s, once there are peers to catch up from",
            galaxy.sync_interval
        ),
        n => log::info!(
            "Catching up from {n} peer(s) every {}s",
            galaxy.sync_interval
        ),
    }

    let period = Duration::from_secs(galaxy.sync_interval);
    // Whether the next pass is the full one. A server that started with no
    // peers has not compared itself with anything, so the first pass after one
    // appears is still the full pass rather than the cheap heuristic.
    let mut first = true;
    loop {
        if galaxy.peers().is_empty() {
            if nap(&shutdown, period).await {
                return;
            }
            continue;
        }
        let report = galaxy.catch_up(&state, first).await;
        if first {
            // Current as of one full pass. Reads can be served from here.
            state.set_catching_up(false);
            first = false;
            log::info!(
                "Caught up: {} namespace(s) checked, {} value(s) taken from peers",
                report.namespaces,
                report.merged
            );
        } else if report.merged > 0 {
            log::info!(
                "Caught up on {} value(s) across {} namespace(s)",
                report.merged,
                report.namespaces
            );
        }

        if nap(&shutdown, period).await {
            return;
        }
    }
}

impl Galaxy {
    /// Pass a key change on to the peers this server administers.
    ///
    /// Gossip rather than a shared file: a change is pushed through the peer's
    /// own management interface, so **the peer's ACL decides whether it is
    /// allowed**. A key granted `rw:feeds` there cannot change keys there, and
    /// a server holding only that key cannot push anything — which is the
    /// right answer, not a failure to work around. Only a server trusted with
    /// `admin` on a peer can administer it.
    ///
    /// That makes gossip directional by construction. It flows from a server
    /// that holds admin credentials towards the ones it administers, and a
    /// narrowly-scoped peer cannot push back.
    ///
    /// Safe to repeat: saving a key sets its grants rather than adding to
    /// them, so the same change arriving twice is the same as once. Unlike a
    /// sighting, where that was the whole difficulty.
    ///
    /// Best effort. A peer that is down misses the change and does not learn it
    /// from the next live push — only from the periodic one, which re-pushes
    /// what this server knows. A *deletion* missed while a peer was down does
    /// not propagate at all; see [`gossip`].
    pub async fn push_key(&self, entry: &serde_json::Value, hops_left: u8) -> Gossiped {
        let body = serde_json::to_vec(entry).unwrap_or_default();
        self.spread(
            awc::http::Method::POST,
            "/_management/api/keys",
            Some(&body),
            hops_left,
        )
        .await
    }

    /// Offer a peer the whole key list, to hold exactly.
    ///
    /// Used when this server owns the galaxy's keys. Unlike offering them one
    /// at a time, this can *remove* — which is what makes a revocation reach a
    /// server that was offline for it.
    ///
    /// A peer that has not said it may be replaced answers 403, and the caller
    /// falls back to offering the keys individually. That is not a failure: a
    /// server that has not opted in keeps its own keys, which is the point of
    /// the opt-in.
    pub async fn push_key_list(&self, keys: &serde_json::Value, hops_left: u8) -> Gossiped {
        let body = serde_json::to_vec(&serde_json::json!({ "keys": keys })).unwrap_or_default();
        self.spread(
            awc::http::Method::PUT,
            "/_management/api/keys",
            Some(&body),
            hops_left,
        )
        .await
    }

    /// Whether this server owns the galaxy's keys.
    pub fn owns_the_acl(&self) -> bool {
        self.acl_authority
    }

    /// Pass a tier change on, the same way and under the same rule.
    ///
    /// A tier is purely a setting — there is no "unset", only a different
    /// value — so unlike a key it has no deletion to miss. That makes the
    /// periodic offer of tiers complete rather than merely additive: whatever
    /// this server holds is what a peer ends up with.
    pub async fn push_tier(&self, change: &serde_json::Value, hops_left: u8) -> Gossiped {
        let body = serde_json::to_vec(change).unwrap_or_default();
        self.spread(
            awc::http::Method::POST,
            "/_management/api/tier",
            Some(&body),
            hops_left,
        )
        .await
    }

    /// The same, for a revocation.
    pub async fn push_key_removal(&self, key: &str, hops_left: u8) -> Gossiped {
        let path = format!("/_management/api/keys/{}", urlencoding_of(key));
        self.spread(awc::http::Method::DELETE, &path, None, hops_left)
            .await
    }

    /// Send one management change to every peer, and report how it went.
    async fn spread(
        &self,
        method: awc::http::Method,
        path: &str,
        body: Option<&[u8]>,
        hops_left: u8,
    ) -> Gossiped {
        let mut report = Gossiped::default();
        if hops_left == 0 {
            // A cycle, or a cascade deeper than max_hops. The same budget that
            // stops a forwarded write circulating stops this.
            return report;
        }

        for peer in &self.peers() {
            match self
                .send(peer, method.clone(), path, body, hops_left, "")
                .await
            {
                Ok(answer) if (200..300).contains(&answer.status) => report.accepted += 1,
                Ok(answer) if answer.status == 403 || answer.status == 401 => {
                    // This server is not trusted to administer that peer. Said
                    // once at debug, because for a deliberately narrow key it
                    // is the expected answer rather than a problem.
                    report.refused += 1;
                    log::debug!(
                        "{} does not let this server change its keys ({})",
                        peer.url,
                        answer.status
                    );
                }
                Ok(answer) => {
                    report.failed += 1;
                    log::warn!(
                        "{} refused a key change: {} {}",
                        peer.url,
                        answer.status,
                        String::from_utf8_lossy(&answer.body).trim()
                    );
                }
                Err(e) => {
                    report.failed += 1;
                    log::warn!("Could not reach {} with a key change: {e}", peer.url);
                }
            }
        }
        report
    }
}

/// How a gossiped change was received.
#[derive(Debug, Default, Clone, Copy)]
pub struct Gossiped {
    /// Peers that applied it.
    pub accepted: usize,
    /// Peers that do not let this server administer them. Expected, not a
    /// problem: the peer's own ACL is what decides.
    pub refused: usize,
    /// Peers that could not be reached, or answered something else.
    pub failed: usize,
}

/// Percent-encode what has to go in a path segment.
///
/// An API key is whatever an operator typed, so it may hold a slash or a space
/// and cannot be pasted into a URL as it stands.
pub fn urlencoding_of(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*byte as char);
            }
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

impl Galaxy {
    /// Which keys each peer holds, as far as this server may ask.
    ///
    /// Asked through the peer's management interface, so it answers only where
    /// this server holds an `admin` key — the same boundary that decides
    /// whether a change may be pushed.
    pub async fn peer_keys(&self) -> Vec<PeerKeys> {
        let known = self.peers();
        let mut found = Vec::with_capacity(known.len());

        for peer in &self.peers() {
            let mut row = PeerKeys {
                url: peer.url.clone(),
                keys: Vec::new(),
                readable: false,
                error: None,
            };

            match self
                .send(
                    peer,
                    awc::http::Method::GET,
                    "/_management/api/keys",
                    None,
                    1,
                    "",
                )
                .await
            {
                Ok(answer) if (200..300).contains(&answer.status) => {
                    row.readable = true;
                    row.keys = serde_json::from_slice::<Vec<serde_json::Value>>(&answer.body)
                        .map(|list| {
                            list.iter()
                                .filter_map(|k| k.get("key")?.as_str().map(str::to_string))
                                .collect()
                        })
                        .unwrap_or_default();
                }
                Ok(answer) if answer.status == 401 || answer.status == 403 => {
                    // Not ours to administer. Expected for a deliberately
                    // narrow key, so it is a fact about the galaxy rather than
                    // a fault.
                    row.error = Some("this server does not administer that peer".to_string());
                }
                Ok(answer) => row.error = Some(format!("answered {}", answer.status)),
                Err(e) => row.error = Some(e.to_string()),
            }

            found.push(row);
        }

        found
    }
}

/// What keys one peer holds.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PeerKeys {
    pub url: String,
    pub keys: Vec<String>,
    /// Whether this server was allowed to ask at all.
    pub readable: bool,
    pub error: Option<String>,
}

/// Re-push the keys this server knows about, on a timer.
///
/// Live pushes are best effort, so a peer that was down misses them. This is
/// how it catches up on *additions*: the keys this server holds are offered
/// again, and setting a key it already has is a no-op.
///
/// **Deliberately additive.** It does not delete keys a peer has and this
/// server does not, because this server is not necessarily the only place keys
/// are managed, and a timer that quietly revoked a key somebody added
/// elsewhere would be far worse than one that failed to propagate a deletion.
///
/// The consequence, stated plainly: a revocation made while a peer was down
/// does not reach it. Re-revoke it once the peer is back, or check the peer's
/// own key list. Making this authoritative instead would need a server to be
/// declared the owner of the galaxy's ACL, which is a decision for whoever runs
/// it and not one to assume.
pub async fn gossip(state: Arc<crate::handlers::SharedState>, shutdown: Arc<Shutdown>) {
    let Some(galaxy) = state.galaxy.as_ref() else {
        return;
    };
    if galaxy.gossip_interval == 0 {
        return;
    }
    // Nothing to offer, and nothing to offer it with.
    if state.acl_file.is_none() {
        log::info!("Keys are read-only here, so none are offered to peers");
        return;
    }

    log::info!(
        "Offering this server's keys to its peers every {}s",
        galaxy.gossip_interval
    );
    let period = Duration::from_secs(galaxy.gossip_interval);

    loop {
        if nap(&shutdown, period).await {
            return;
        }

        // Taken as owned values, so the ACL lock is not held across an await.
        let entries: Vec<serde_json::Value> = state
            .acl()
            .entries()
            .iter()
            .map(|(key, grants)| {
                serde_json::json!(crate::admin::KeyEntry::from_grants(key, grants))
            })
            .collect();

        let mut accepted = 0;
        let mut refused = 0;

        if galaxy.owns_the_acl() {
            // The whole list, to be held exactly. This is the only offer that
            // can remove, and so the only one a revocation survives a peer's
            // downtime through.
            let report = galaxy
                .push_key_list(&serde_json::json!(entries), galaxy.max_hops)
                .await;
            accepted += report.accepted;
            refused += report.refused;

            if report.refused > 0 {
                // A peer that has not opted in keeps its own keys. Offer them
                // individually instead, which at least carries the additions.
                for entry in &entries {
                    let per_key = galaxy.push_key(entry, galaxy.max_hops).await;
                    accepted += per_key.accepted;
                }
            }
        } else {
            for entry in &entries {
                let report = galaxy.push_key(entry, galaxy.max_hops).await;
                accepted += report.accepted;
                refused += report.refused;
            }
        }

        // Tiers go with them. Unlike a key, a tier has no deletion to miss —
        // there is no "unset", only a different value — so offering what this
        // server holds leaves a peer with exactly that.
        let tiers = state.db.tier_overrides();
        for (namespace, tier, warm_idle) in &tiers {
            let change = serde_json::json!({
                "namespace": namespace,
                "tier": tier,
                "warm_idle": warm_idle,
            });
            let report = galaxy.push_tier(&change, galaxy.max_hops).await;
            accepted += report.accepted;
            refused += report.refused;
        }

        if accepted > 0 {
            log::debug!(
                "Offered {} key(s) and {} tier(s) to peers: {accepted} applied, {refused} \
                 not ours to administer",
                entries.len(),
                tiers.len()
            );
        }
    }
}

/// Rebuild this server's consensus tally from the galaxy, on a slow timer.
///
/// A server passing writes along counts a value towards consensus when a
/// mirror says the sighting was new there. That only ever rises: values expire
/// and namespaces are deleted on the nodes, consensus is released there, and
/// neither event reaches anything in front of them. So the tally drifts upward,
/// faster the more TTLs are in use, and something has to put it back.
///
/// The honest way is to ask. For every namespace the galaxy holds, walk its
/// values and record which namespaces hold each one; consensus is then the
/// size of that set. Union rather than sum, because the same namespace mirrored
/// three times is still one namespace — summing would be the double counting
/// this whole design exists to avoid.
///
/// **This walks the galaxy**, which is why it has a timer of its own and a long
/// default. It is a repair, not a steady-state cost: the incremental tally is
/// what answers reads in between.
pub async fn reconcile(state: Arc<crate::handlers::SharedState>, shutdown: Arc<Shutdown>) {
    let Some(galaxy) = state.galaxy.as_ref() else {
        return;
    };
    if galaxy.reconcile_interval == 0 {
        return;
    }

    log::info!(
        "Reconciling the consensus tally every {}s",
        galaxy.reconcile_interval
    );
    let period = Duration::from_secs(galaxy.reconcile_interval);

    loop {
        // Waited first: at startup the catch-up pass is the thing to run, and
        // a tally rebuilt before anything has been forwarded says nothing.
        if nap(&shutdown, period).await {
            return;
        }
        match galaxy.rebuild_consensus(&state).await {
            Ok(report) => {
                if report.corrected > 0 {
                    log::info!(
                        "Consensus tally rebuilt: {} value(s) across {} namespace(s), \
                         {} corrected",
                        report.values,
                        report.namespaces,
                        report.corrected
                    );
                } else {
                    log::debug!(
                        "Consensus tally rebuilt: {} value(s) across {} namespace(s), \
                         nothing to correct",
                        report.values,
                        report.namespaces
                    );
                }
            }
            Err(e) => log::warn!("Could not rebuild the consensus tally: {e}"),
        }
    }
}

/// What one reconciliation found.
#[derive(Debug, Default, Clone, Copy)]
pub struct Reconciled {
    pub namespaces: usize,
    pub values: usize,
    /// Values whose tally was wrong and has been put right.
    pub corrected: usize,
}

impl Galaxy {
    async fn rebuild_consensus(
        &self,
        state: &crate::handlers::SharedState,
    ) -> Result<Reconciled, ForwardError> {
        use std::collections::{BTreeSet, HashMap};

        let mut holders: HashMap<String, BTreeSet<String>> = HashMap::new();
        let mut report = Reconciled::default();
        let mut seen_namespaces: BTreeSet<String> = BTreeSet::new();

        for peer in &self.peers() {
            let names = self.namespaces_of(peer).await?;
            for namespace in names {
                if !crate::db::counts_towards_consensus(&namespace) {
                    continue;
                }
                // A namespace mirrored several times is walked once: the
                // answers agree, and if they do not the union is still right.
                if !seen_namespaces.insert(namespace.clone()) {
                    continue;
                }

                let mut offset = 0usize;
                loop {
                    let path = format!("/r/{namespace}?for_merge&offset={offset}&limit=500");
                    let answer = self
                        .send(peer, awc::http::Method::GET, &path, None, 1, "")
                        .await?;
                    if !(200..300).contains(&answer.status) {
                        break;
                    }
                    let page: MergeOfferPage = serde_json::from_slice(&answer.body)
                        .map_err(|e| ForwardError::Unreachable(e.to_string()))?;

                    let taken = page.items.len();
                    for offer in &page.items {
                        holders
                            .entry(offer.value.clone())
                            .or_default()
                            .insert(namespace.clone());
                    }
                    offset += taken;
                    if taken == 0 || offset >= page.total {
                        break;
                    }
                }
            }
        }

        report.namespaces = seen_namespaces.len();
        report.values = holders.len();
        report.corrected = state.db.set_consensus(&holders);
        Ok(report)
    }
}

/// Sleep until the period is up or shutdown is asked for.
///
/// In slices rather than one long sleep: a catch-up interval is minutes, and a
/// process asked to stop should not take minutes to do it. Returns true when it
/// is time to stop.
async fn nap(shutdown: &Shutdown, period: Duration) -> bool {
    const SLICE: Duration = Duration::from_secs(2);
    let mut left = period;
    while !left.is_zero() {
        if shutdown.is_stopped() {
            return true;
        }
        let slice = left.min(SLICE);
        actix_web::rt::time::sleep(slice).await;
        left -= slice;
    }
    shutdown.is_stopped()
}

/// What one catch-up pass did.
#[derive(Debug, Default, Clone, Copy)]
pub struct CaughtUp {
    /// Namespaces looked at.
    pub namespaces: usize,
    /// Values whose local copy a peer changed.
    pub merged: usize,
}

impl Galaxy {
    /// One pass: find where this server is behind, and fill it in.
    async fn catch_up(&self, state: &crate::handlers::SharedState, full: bool) -> CaughtUp {
        let mut report = CaughtUp::default();

        for peer in &self.peers() {
            // Namespaces the peer has that we are willing to store. Asked of
            // the peer rather than taken from our own catalogue, because a
            // server that was down does not know about namespaces created
            // while it was away.
            let names = match self.namespaces_of(peer).await {
                Ok(names) => names,
                Err(e) => {
                    log::debug!("Catch-up could not list {}: {e}", peer.url);
                    continue;
                }
            };

            for namespace in names {
                if !state.db.holds(&namespace) || crate::db::is_internal(&namespace) {
                    continue;
                }
                report.namespaces += 1;

                if !full && !self.behind_on(peer, &namespace, state).await {
                    continue;
                }
                report.merged += self.pull_namespace(peer, &namespace, state).await;
            }
        }

        report
    }

    /// Every namespace the peers hold that sits under one of `prefixes`.
    ///
    /// For a request about a subtree rather than a namespace — a recursive
    /// STIX export — on a server that does not hold the subtree. The local
    /// catalogue answers that question for a node; for a router it is empty,
    /// and the question has to be put to the mirrors.
    ///
    /// Matching is on whole path segments, the same rule
    /// [`crate::db::Database::namespaces_under`] uses, so `misp` covers
    /// `misp/ips` and never `misp-internal`. An empty prefix matches
    /// everything, which is what exporting `/` means.
    ///
    /// A peer that cannot be reached contributes nothing. Half a subtree is
    /// reported through the export's own `missing` rather than failing here:
    /// what is being asked is what exists, and an unreachable mirror does not
    /// make the rest of the answer wrong.
    pub async fn namespaces_under(&self, prefixes: &[String]) -> Vec<String> {
        let mut found: Vec<String> = Vec::new();
        for peer in &self.peers() {
            let Ok(names) = self.namespaces_of(peer).await else {
                continue;
            };
            for name in names {
                let under = prefixes.iter().any(|prefix| {
                    let prefix = prefix.trim_matches('/');
                    prefix.is_empty()
                        || name == prefix
                        || name
                            .strip_prefix(prefix)
                            .is_some_and(|rest| rest.starts_with('/'))
                });
                if under && !found.contains(&name) {
                    found.push(name);
                }
            }
        }
        found
    }

    /// The namespaces a peer holds that fall under what we store.
    async fn namespaces_of(&self, peer: &Peer) -> Result<Vec<String>, ForwardError> {
        let answer = self
            .send(
                peer,
                awc::http::Method::GET,
                "/_api/namespaces",
                None,
                // Not a forwarded request: this is between us and the peer, so
                // it gets a hop of its own rather than spending the budget of
                // something a client sent.
                1,
                "",
            )
            .await?;

        if !(200..300).contains(&answer.status) {
            return Err(ForwardError::Unreachable(format!(
                "listing namespaces answered {}",
                answer.status
            )));
        }
        let parsed: serde_json::Value = serde_json::from_slice(&answer.body)
            .map_err(|e| ForwardError::Unreachable(e.to_string()))?;
        Ok(parsed
            .get("namespaces")
            .and_then(|list| list.as_array())
            .map(|list| {
                list.iter()
                    .filter_map(|name| name.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default())
    }

    /// Whether the peer holds more values in this namespace than we do.
    ///
    /// O(1) on both sides, which is what makes it usable on a timer. Not a
    /// proof of divergence — see [`sync`].
    async fn behind_on(
        &self,
        peer: &Peer,
        namespace: &str,
        state: &crate::handlers::SharedState,
    ) -> bool {
        let path = format!("/r/{namespace}?count");
        let Ok(answer) = self
            .send(peer, awc::http::Method::GET, &path, None, 1, "")
            .await
        else {
            return false;
        };
        let Ok(parsed) = serde_json::from_slice::<serde_json::Value>(&answer.body) else {
            return false;
        };
        let theirs = parsed.get("values").and_then(|v| v.as_u64()).unwrap_or(0);
        let mine = state
            .db
            .value_count(namespace)
            .map_or(0, |count| count.values as u64);
        theirs > mine
    }

    /// Walk a peer's copy of one namespace and merge every page.
    ///
    /// Applied in-process rather than posted back to ourselves: the merge rules
    /// are the same either way, and going out over HTTP to our own port would
    /// be a hop spent for nothing.
    async fn pull_namespace(
        &self,
        peer: &Peer,
        namespace: &str,
        state: &crate::handlers::SharedState,
    ) -> usize {
        const PAGE: usize = 500;
        let mut offset = 0usize;
        let mut merged = 0usize;

        loop {
            let path = format!("/r/{namespace}?for_merge&offset={offset}&limit={PAGE}");
            let answer = match self
                .send(peer, awc::http::Method::GET, &path, None, 1, "")
                .await
            {
                Ok(answer) => answer,
                Err(e) => {
                    log::warn!("Catch-up of '{namespace}' from {} stopped: {e}", peer.url);
                    break;
                }
            };
            if !(200..300).contains(&answer.status) {
                log::warn!(
                    "Catch-up of '{namespace}' from {} stopped: answered {}",
                    peer.url,
                    answer.status
                );
                break;
            }
            // Logged rather than shrugged off: a catch-up that silently takes
            // nothing looks exactly like one that had nothing to take, and the
            // difference is the whole point of running it.
            let page = match serde_json::from_slice::<MergeOfferPage>(&answer.body) {
                Ok(page) => page,
                Err(e) => {
                    log::warn!(
                        "Catch-up of '{namespace}' from {} could not read the page: {e}",
                        peer.url
                    );
                    break;
                }
            };

            let taken = page.items.len();
            for offer in page.items {
                let outcome = state.db.merge(namespace, &offer.value, &offer.state());
                if outcome.changed {
                    merged += 1;
                }
            }

            offset += taken;
            if taken == 0 || offset >= page.total {
                break;
            }
        }

        if merged > 0 {
            log::debug!("Took {merged} value(s) of '{namespace}' from {}", peer.url);
        }
        merged
    }
}

/// One page of a peer's namespace, as `/r/<ns>?for_merge` answers.
#[derive(serde::Deserialize)]
struct MergeOfferPage {
    items: Vec<MergeOfferItem>,
    total: usize,
}

/// One value from that page.
///
/// The fields are spelled out rather than flattening
/// [`crate::attribute::Merge`] into them — for the same reason
/// [`crate::handlers::MergeItem`] does. `serde`'s `flatten` buffers through an
/// intermediate that cannot coerce JSON's string object keys back to the `i64`
/// hours in `stats`, so a page read from a peer would fail to parse and a
/// catch-up would quietly take nothing.
#[derive(serde::Deserialize)]
struct MergeOfferItem {
    value: String,
    counts: std::collections::BTreeMap<String, u64>,
    #[serde(default)]
    stats: std::collections::BTreeMap<String, std::collections::BTreeMap<i64, u64>>,
    first_seen: i64,
    last_seen: i64,
    #[serde(default)]
    tags: String,
    /// When the peer last replaced its tag set. Absent from a peer too old to
    /// send it, which reads as zero and so loses to any replacement here.
    #[serde(default)]
    tags_at: i64,
    #[serde(default)]
    ttl: u64,
}

impl MergeOfferItem {
    fn state(&self) -> crate::attribute::Merge {
        crate::attribute::Merge {
            counts: self.counts.clone(),
            stats: self.stats.clone(),
            first_seen: self.first_seen,
            last_seen: self.last_seen,
            tags: self.tags.clone(),
            tags_at: self.tags_at,
            ttl: self.ttl,
        }
    }
}

/// Ask one peer whether it is well, and how long it took to say so.
///
/// No API key: `/health` needs none, so a probe cannot leak the credential
/// this server holds for the peer.
/// What one peer's `/health` said.
struct Probed {
    version: Option<String>,
    latency_ms: u64,
    catching_up: bool,
}

async fn probe(client: &awc::Client, url: &str) -> Result<Probed, String> {
    let at = Instant::now();
    let mut response = client
        .get(format!("{url}/health"))
        .send()
        .await
        .map_err(|e| e.to_string())?;

    let latency_ms = at.elapsed().as_millis() as u64;
    if !response.status().is_success() {
        return Err(format!("answered {}", response.status()));
    }

    // A peer that answers but says something unreadable is reachable, which is
    // what was being asked. The version is a bonus, not a requirement.
    let body = response.json::<serde_json::Value>().await.ok();
    let version = body
        .as_ref()
        .and_then(|body| body.get("version")?.as_str().map(str::to_string));
    // Absent on a peer older than this field, which is the same as not
    // catching up as far as anything here is concerned.
    let catching_up = body
        .as_ref()
        .and_then(|body| body.get("catching_up")?.as_bool())
        .unwrap_or(false);

    Ok(Probed {
        version,
        latency_ms,
        catching_up,
    })
}

/// This thread's HTTP client.
///
/// One per worker thread rather than one shared: `awc::Client` is built on
/// `Rc`, so it is neither `Send` nor `Sync` and cannot live on the state every
/// worker shares. A client per thread keeps connection pooling, which building
/// one per request would throw away.
///
/// The clone is cheap — the client is a handle — and owning it rather than
/// borrowing is what lets it be held across an `await`.
///
/// `verify_tls` is read on this thread's first call. A process has one galaxy,
/// so there is nothing for a later differing value to mean.
fn client(verify_tls: bool) -> Option<awc::Client> {
    CLIENT.with(|cell| {
        cell.get_or_init(|| match build_client(verify_tls) {
            Ok(client) => Some(client),
            Err(e) => {
                log::error!("Could not build an HTTP client for the galaxy: {e:#}");
                None
            }
        })
        .clone()
    })
}

thread_local! {
    static CLIENT: std::cell::OnceCell<Option<awc::Client>> =
        const { std::cell::OnceCell::new() };
}

fn build_client(verify_tls: bool) -> anyhow::Result<awc::Client> {
    use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};

    let mut ssl = SslConnector::builder(SslMethod::tls())?;
    if !verify_tls {
        ssl.set_verify(SslVerifyMode::NONE);
    }

    Ok(awc::Client::builder()
        .connector(awc::Connector::new().openssl(ssl.build()))
        .timeout(PROBE_TIMEOUT)
        .finish())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn probed(version: Option<&str>, latency_ms: u64, catching_up: bool) -> Probed {
        Probed {
            version: version.map(str::to_string),
            latency_ms,
            catching_up,
        }
    }

    fn galaxy(urls: &[&str]) -> Galaxy {
        Galaxy::new(&GalaxySettings {
            peers: urls
                .iter()
                .map(|url| Peer {
                    url: (*url).to_string(),
                    key: "k".to_string(),
                    stores: crate::db::StoragePolicy::everything(),
                })
                .collect(),
            max_hops: 4,
            peers_file: None,
            fixed: Vec::new(),
            health_interval: 30,
            sync_interval: 300,
            reconcile_interval: 3600,
            gossip_interval: 600,
            acl_authority: false,
            acl_replaceable: false,
            verify_tls: true,
        })
    }

    /// A peer added while the server runs is reachable by the health poller.
    ///
    /// The poller used to return at startup when the peer list was empty,
    /// which was fine while the list was fixed in the configuration. Once the
    /// management interface could add one, that early return left every
    /// runtime-added peer permanently unprobed: online in fact, "not asked
    /// yet" in the interface, and `Last answered: never` for ever.
    ///
    /// This pins the property the poller depends on — that the list it reads
    /// each round is the live one, not a copy taken at startup.
    #[test]
    fn a_peer_added_after_startup_is_in_the_list_the_poller_reads() {
        let galaxy = galaxy(&[]);
        assert!(galaxy.peers().is_empty(), "starts with none");

        galaxy
            .add_peer(
                Peer {
                    url: "https://added:9999".to_string(),
                    key: "k".to_string(),
                    stores: crate::db::StoragePolicy::everything(),
                },
                "127.0.0.1:9999",
            )
            .expect("added");

        // What `run` iterates every round.
        let seen: Vec<String> = galaxy.peers().into_iter().map(|peer| peer.url).collect();
        assert_eq!(seen, vec!["https://added:9999".to_string()]);

        // And it is reported, as unprobed rather than as absent.
        let health = galaxy.health();
        assert_eq!(health.len(), 1);
        assert!(!health[0].probed, "it has not been asked yet");
        assert_eq!(health[0].last_seen, 0);
    }

    /// Before the first probe a peer is neither up nor down, and the view has
    /// to be able to say which — "not asked yet" is not "offline".
    #[test]
    fn a_peer_starts_unprobed_rather_than_offline() {
        let galaxy = galaxy(&["https://a:9999"]);

        let health = galaxy.health();
        assert_eq!(health.len(), 1);
        assert!(!health[0].probed);
        assert!(!health[0].online);
        assert_eq!(health[0].last_seen, 0);
        assert!(health[0].error.is_none());
    }

    #[test]
    fn a_successful_probe_clears_the_failure_count() {
        let galaxy = galaxy(&["https://a:9999"]);

        galaxy.record("https://a:9999", Err("refused".into()));
        galaxy.record("https://a:9999", Err("refused".into()));
        assert_eq!(galaxy.health()[0].failures, 2);
        assert!(!galaxy.health()[0].online);

        galaxy.record("https://a:9999", Ok(probed(Some("0.6.1"), 12, false)));
        let health = galaxy.health();
        assert!(health[0].online);
        assert!(health[0].probed);
        assert_eq!(health[0].failures, 0);
        assert_eq!(health[0].version.as_deref(), Some("0.6.1"));
        assert_eq!(health[0].latency_ms, Some(12));
        assert!(health[0].error.is_none());
        assert!(health[0].last_seen > 0);
    }

    /// `last_seen` is how stale a peer is, so it must survive the peer going
    /// away — otherwise a dead peer looks like one that was never there.
    #[test]
    fn last_seen_survives_a_later_failure() {
        let galaxy = galaxy(&["https://a:9999"]);

        galaxy.record("https://a:9999", Ok(probed(None, 5, false)));
        let seen = galaxy.health()[0].last_seen;
        assert!(seen > 0);

        galaxy.record("https://a:9999", Err("timed out".into()));
        let health = galaxy.health();
        assert!(!health[0].online);
        assert_eq!(health[0].last_seen, seen, "last_seen was lost");
        assert_eq!(health[0].error.as_deref(), Some("timed out"));
        assert!(health[0].latency_ms.is_none(), "a stale latency was kept");
    }

    /// An API key is whatever an operator typed, so it may hold a slash or a
    /// space and cannot go into a URL path as it stands. A key containing `/`
    /// would otherwise address a different route entirely.
    #[test]
    fn a_key_is_encoded_before_it_goes_in_a_path() {
        let cases = [
            ("simple", "simple"),
            ("with/slash", "with%2Fslash"),
            ("with space", "with%20space"),
            ("keep-._~", "keep-._~"),
            ("../escape", "..%2Fescape"),
            ("q?a=b&c", "q%3Fa%3Db%26c"),
        ];
        for (key, expected) in cases {
            assert_eq!(urlencoding_of(key), expected, "{key}");
        }
    }

    /// A change that has run out of hops is not passed on. The same budget
    /// that stops a forwarded write circulating stops a key change going round
    /// a miswired galaxy for ever.
    #[actix_web::test]
    async fn a_key_change_out_of_hops_is_not_passed_on() {
        let galaxy = galaxy(&["https://a:9999"]);

        let report = galaxy
            .push_key(
                &serde_json::json!({"key": "k", "admin": false, "read": [], "write": []}),
                0,
            )
            .await;

        assert_eq!(report.accepted, 0);
        assert_eq!(report.refused, 0);
        assert_eq!(report.failed, 0, "it tried anyway");
    }

    /// A peer that cannot be reached is counted as failed rather than refused:
    /// the two mean different things to whoever reads the log, and only one of
    /// them is expected.
    #[actix_web::test]
    async fn an_unreachable_peer_is_a_failure_not_a_refusal() {
        // Nothing listens on port 1.
        let galaxy = galaxy(&["http://127.0.0.1:1"]);

        let report = galaxy
            .push_key(
                &serde_json::json!({"key": "k", "admin": false, "read": [], "write": []}),
                4,
            )
            .await;

        assert_eq!(report.failed, 1);
        assert_eq!(report.refused, 0);
        assert_eq!(report.accepted, 0);
    }

    /// A mirror still catching up is passed over for reads: its data is
    /// incomplete and a read of it would under-report.
    #[test]
    fn reads_avoid_a_mirror_that_is_catching_up() {
        let galaxy = galaxy(&["https://a:9999", "https://b:9999"]);
        galaxy.record("https://a:9999", Ok(probed(None, 1, false)));
        galaxy.record("https://b:9999", Ok(probed(None, 1, true)));

        // Whatever the value, the choice is the one that is current. Several
        // values, because the pick is by hash and one could land on `a` by
        // luck.
        for value in ["1.2.3.4", "8.8.8.8", "evil.example", "a.b.c", "x"] {
            let chosen = galaxy.reader_for("feeds", value).expect("a mirror");
            assert_eq!(
                chosen.url, "https://a:9999",
                "{value} was read from a mirror that is catching up"
            );
        }
    }

    /// If every mirror is catching up, one answers anyway. An under-reported
    /// count beats no answer, and refusing would make a whole galaxy
    /// unreadable for as long as it took to start.
    #[test]
    fn reads_are_served_even_when_every_mirror_is_catching_up() {
        let galaxy = galaxy(&["https://a:9999", "https://b:9999"]);
        galaxy.record("https://a:9999", Ok(probed(None, 1, true)));
        galaxy.record("https://b:9999", Ok(probed(None, 1, true)));

        assert!(galaxy.reader_for("feeds", "1.2.3.4").is_some());
    }

    /// Catching up is reported per peer and clears when it finishes.
    #[test]
    fn catching_up_is_tracked_and_cleared() {
        let galaxy = galaxy(&["https://a:9999"]);

        galaxy.record("https://a:9999", Ok(probed(None, 1, true)));
        assert!(galaxy.health()[0].catching_up);

        galaxy.record("https://a:9999", Ok(probed(None, 1, false)));
        assert!(!galaxy.health()[0].catching_up);
    }

    /// The same value always picks the same mirror while the set is unchanged.
    /// Without that, consecutive reads could be served by mirrors at different
    /// stages of catching up and show a count going down.
    #[test]
    fn a_value_always_reads_from_the_same_mirror() {
        let galaxy = galaxy(&["https://a:9999", "https://b:9999", "https://c:9999"]);
        for url in ["https://a:9999", "https://b:9999", "https://c:9999"] {
            galaxy.record(url, Ok(probed(None, 1, false)));
        }

        for value in ["1.2.3.4", "evil.example", "deadbeef"] {
            let first = galaxy.reader_for("feeds", value).unwrap().url.clone();
            for _ in 0..5 {
                assert_eq!(
                    galaxy.reader_for("feeds", value).unwrap().url,
                    first,
                    "{value} moved between reads"
                );
            }
        }
    }

    /// Reported in configured order, so the view does not reshuffle between
    /// refreshes.
    #[test]
    fn health_is_reported_in_configured_order() {
        let galaxy = galaxy(&["https://c:9999", "https://a:9999", "https://b:9999"]);

        galaxy.record("https://a:9999", Ok(probed(None, 1, false)));
        let health = galaxy.health();
        let urls: Vec<&str> = health.iter().map(|h| h.url.as_str()).collect();
        assert_eq!(urls, ["https://c:9999", "https://a:9999", "https://b:9999"]);
    }
}
