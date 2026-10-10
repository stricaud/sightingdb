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
}

impl PeerHealth {
    fn unprobed(url: &str) -> Self {
        PeerHealth {
            url: url.to_string(),
            online: false,
            probed: false,
            last_seen: 0,
            latency_ms: None,
            version: None,
            error: None,
            failures: 0,
        }
    }
}

/// The peers, and what is known about them.
#[derive(Debug)]
pub struct Galaxy {
    peers: Vec<Peer>,
    /// How many hops a forwarded request may still take. Spent on each hop and
    /// refused at zero, which is what stops a miswired cycle.
    max_hops: u8,
    /// How often each peer is probed.
    health_interval: u64,
    /// Whether a peer's TLS certificate is verified. Off is for a galaxy of
    /// self-signed instances, which is what `--setup` produces.
    verify_tls: bool,
    health: RwLock<HashMap<String, PeerHealth>>,
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
            peers: settings.peers.clone(),
            max_hops: settings.max_hops,
            health_interval: settings.health_interval,
            verify_tls: settings.verify_tls,
            health: RwLock::new(health),
        }
    }

    pub fn max_hops(&self) -> u8 {
        self.max_hops
    }

    /// Peers that store `namespace`, in configured order.
    pub fn holders(&self, namespace: &str) -> Vec<&Peer> {
        self.peers
            .iter()
            .filter(|peer| peer.stores.holds(namespace))
            .collect()
    }

    /// Peers that store `namespace` *and* are answering.
    ///
    /// A peer not yet probed counts as usable: refusing to forward for the
    /// first few seconds of a server's life would be worse than trying and
    /// finding out.
    pub fn live_holders(&self, namespace: &str) -> Vec<&Peer> {
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
    pub fn reader_for<'a>(&'a self, namespace: &str, value: &str) -> Option<&'a Peer> {
        self.live_holders(namespace)
            .into_iter()
            .max_by_key(|peer| weigh(value, &peer.url))
    }

    /// Every peer's health, in the order they were configured.
    ///
    /// Configured order rather than whatever the map iterates in, so the view
    /// does not reshuffle itself between refreshes.
    pub fn health(&self) -> Vec<PeerHealth> {
        let health = self.health.read().unwrap_or_else(PoisonError::into_inner);
        self.peers
            .iter()
            .map(|peer| {
                health
                    .get(&peer.url)
                    .cloned()
                    .unwrap_or_else(|| PeerHealth::unprobed(&peer.url))
            })
            .collect()
    }

    fn record(&self, url: &str, outcome: Result<(Option<String>, u64), String>) {
        let mut health = self.health.write().unwrap_or_else(PoisonError::into_inner);
        let entry = health
            .entry(url.to_string())
            .or_insert_with(|| PeerHealth::unprobed(url));

        entry.probed = true;
        match outcome {
            Ok((version, latency_ms)) => {
                if !entry.online && entry.failures > 0 {
                    log::info!("Galaxy peer {url} is answering again");
                }
                entry.online = true;
                entry.last_seen = chrono::Utc::now().timestamp();
                entry.latency_ms = Some(latency_ms);
                entry.version = version;
                entry.error = None;
                entry.failures = 0;
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
    if galaxy.peers.is_empty() {
        return;
    }

    let Some(client) = client(galaxy.verify_tls) else {
        log::error!("Galaxy health checks disabled: no HTTP client could be built");
        return;
    };

    log::info!(
        "Galaxy health checks every {}s for {} peer(s){}",
        galaxy.health_interval,
        galaxy.peers.len(),
        if galaxy.verify_tls {
            ""
        } else {
            " (TLS verification off)"
        }
    );

    let period = Duration::from_secs(galaxy.health_interval);
    loop {
        for peer in &galaxy.peers {
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
        let body = response
            .body()
            .limit(FORWARD_BODY_LIMIT)
            .await
            .map_err(|e| ForwardError::Unreachable(e.to_string()))?
            .to_vec();

        Ok(Forwarded { status, body })
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

        self.send(peer, awc::http::Method::GET, path, None, hops_left, origin)
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

        let live: Vec<Peer> = self.live_holders(namespace).into_iter().cloned().collect();
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
        for peer in &self.peers {
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

/// Ask one peer whether it is well, and how long it took to say so.
///
/// No API key: `/health` needs none, so a probe cannot leak the credential
/// this server holds for the peer.
async fn probe(client: &awc::Client, url: &str) -> Result<(Option<String>, u64), String> {
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
    let version = response
        .json::<serde_json::Value>()
        .await
        .ok()
        .and_then(|body| body.get("version")?.as_str().map(str::to_string));

    Ok((version, latency_ms))
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
            health_interval: 30,
            verify_tls: true,
        })
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

        galaxy.record("https://a:9999", Ok((Some("0.6.1".to_string()), 12)));
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

        galaxy.record("https://a:9999", Ok((None, 5)));
        let seen = galaxy.health()[0].last_seen;
        assert!(seen > 0);

        galaxy.record("https://a:9999", Err("timed out".into()));
        let health = galaxy.health();
        assert!(!health[0].online);
        assert_eq!(health[0].last_seen, seen, "last_seen was lost");
        assert_eq!(health[0].error.as_deref(), Some("timed out"));
        assert!(health[0].latency_ms.is_none(), "a stale latency was kept");
    }

    /// Reported in configured order, so the view does not reshuffle between
    /// refreshes.
    #[test]
    fn health_is_reported_in_configured_order() {
        let galaxy = galaxy(&["https://c:9999", "https://a:9999", "https://b:9999"]);

        galaxy.record("https://a:9999", Ok((None, 1)));
        let health = galaxy.health();
        let urls: Vec<&str> = health.iter().map(|h| h.url.as_str()).collect();
        assert_eq!(urls, ["https://c:9999", "https://a:9999", "https://b:9999"]);
    }
}
