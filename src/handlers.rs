use actix_web::{HttpRequest, HttpResponse, Responder, web};
use serde::{Deserialize, Serialize};

use crate::acl::Acl;
use crate::attribute::AttributeView;
use crate::db::{CONFIG_PREFIX, Database, NotFound};
use crate::error::{ApiError, Message};
use crate::sighting_reader;
use crate::sighting_writer::{self, timestamp_to_instant};

/// Everything a request handler can reach.
pub struct SharedState {
    pub db: Database,
    pub authenticate: bool,
    /// Which API keys exist and what each may reach.
    ///
    /// Behind a lock because the management interface can rewrite it while the
    /// server is running; a saved key takes effect without a restart.
    pub acl: std::sync::RwLock<Acl>,
    /// A snapshot of what this server was configured to do, for the management
    /// interface to report.
    pub info: crate::admin::ServerInfo,
    /// Where the ACL is written back. `None` makes keys read-only.
    pub acl_file: Option<std::path::PathBuf>,
    /// Where tiers are written back. `None` makes them read-only.
    pub tiers_file: Option<std::path::PathBuf>,
    /// How tags are shown: a colour and a description each. Behind a lock so
    /// an edit takes effect without a restart, like the ACL.
    pub tags: std::sync::RwLock<crate::tags::Vocabulary>,
    /// Where the tag vocabulary is written back. `None` makes colours
    /// read-only; tags on values are unaffected either way.
    pub tags_file: Option<std::path::PathBuf>,
    /// What the STIX export needs: who we publish as, and which observable
    /// type each namespace is configured to hold.
    pub stix: crate::config::StixSettings,
    /// When the process came up, which is what `/health` reports.
    pub started: std::time::Instant,
    /// Values that were not written, from every path that writes. See
    /// [`crate::rejections`] for why this is bounded and in memory.
    pub rejections: crate::rejections::Rejections,
    /// The other servers this one knows about, and whether they answer.
    /// `None` when it stands alone.
    pub galaxy: Option<crate::galaxy::Galaxy>,
    /// Where peers added through the management interface are written.
    /// `None` makes the galaxy read-only there.
    pub galaxy_peers_file: Option<std::path::PathBuf>,
    /// Keys revoked on this server, so the interface can say which of them a
    /// peer still holds.
    ///
    /// Needed because this server cannot otherwise tell a revocation that did
    /// not land from a key the peer has always had of its own — including the
    /// very key this server authenticates with there, which would be reported
    /// as stale for ever.
    ///
    /// In memory, like the rejection log: a record kept to make something
    /// visible, not a fact about the data. It is lost on restart, so a
    /// revocation that never reached a peer stops being flagged once this
    /// server is restarted. Checking the peer's own key list is then the only
    /// way to see it.
    pub revoked: std::sync::RwLock<std::collections::BTreeMap<String, i64>>,
    /// Whether another server may replace this one's key list wholesale.
    /// Off unless `[galaxy] acl_replaceable` says otherwise.
    pub acl_replaceable: bool,
    /// Set until the first catch-up pass has finished.
    ///
    /// A server that has just started may be behind its peers, and a read of
    /// a value it has not caught up on yet would under-report. Writes are
    /// accepted throughout: they land directly, and the catch-up fills in the
    /// history behind them. Stopping writes instead would mean the target
    /// keeps moving and the catch-up never provably finishes.
    pub joining: std::sync::atomic::AtomicBool,
}

impl SharedState {
    /// `main` builds this directly, because it restores the database from a
    /// snapshot first. This is the shorthand the tests use: one full-access
    /// key named after the historical default.
    #[cfg(test)]
    pub fn new(authenticate: bool) -> Self {
        let mut acl = Acl::new();
        acl.grant_full(crate::db::DEFAULT_APIKEY);
        Self {
            db: Database::new(),
            authenticate,
            acl: std::sync::RwLock::new(acl),
            info: crate::admin::ServerInfo::default(),
            acl_file: None,
            tiers_file: None,
            tags: std::sync::RwLock::new(crate::tags::Vocabulary::seeded()),
            tags_file: None,
            stix: crate::config::StixSettings::default(),
            started: std::time::Instant::now(),
            rejections: crate::rejections::Rejections::default(),
            galaxy: None,
            galaxy_peers_file: None,
            revoked: std::sync::RwLock::new(std::collections::BTreeMap::new()),
            acl_replaceable: false,
            joining: std::sync::atomic::AtomicBool::new(false),
        }
    }
}

impl SharedState {
    /// Note that a key was revoked here, so a peer still holding it can be
    /// pointed out.
    ///
    /// Bounded, because a long-lived server rotating keys should not grow a
    /// list for ever. The oldest go first; a revocation old enough to fall off
    /// has either propagated or been noticed.
    pub fn note_revoked(&self, key: &str) {
        const KEEP: usize = 1000;
        let mut revoked = self
            .revoked
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        revoked.insert(key.to_string(), chrono::Utc::now().timestamp());
        while revoked.len() > KEEP {
            // Oldest by when it was revoked, not by name.
            if let Some(oldest) = revoked
                .iter()
                .min_by_key(|(_, when)| **when)
                .map(|(key, _)| key.clone())
            {
                revoked.remove(&oldest);
            } else {
                break;
            }
        }
    }

    /// A key put back is no longer revoked.
    pub fn note_unrevoked(&self, key: &str) {
        self.revoked
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(key);
    }

    /// Keys revoked here, newest first.
    pub fn revoked_keys(&self) -> Vec<String> {
        let revoked = self
            .revoked
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut keys: Vec<(&String, &i64)> = revoked.iter().collect();
        keys.sort_by(|a, b| b.1.cmp(a.1));
        keys.into_iter().map(|(key, _)| key.clone()).collect()
    }

    /// Whether this server is still pulling what it missed.
    pub fn catching_up(&self) -> bool {
        self.joining.load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn set_catching_up(&self, catching_up: bool) {
        self.joining
            .store(catching_up, std::sync::atomic::Ordering::Relaxed);
    }

    /// Read access to the ACL. Poisoning is recovered from rather than
    /// propagated: one failed request must not lock everyone out.
    pub fn acl(&self) -> std::sync::RwLockReadGuard<'_, Acl> {
        self.acl
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

pub type State = web::Data<SharedState>;

/// The API description, for `/_api/openapi.yaml`.
///
/// The file carries a version of its own so that it stands alone when someone
/// imports it straight from the repository, but a running server knows better:
/// it rewrites that line with the version it actually is, so the two cannot
/// drift into describing a release nobody is running.
static OPENAPI: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
    const SPEC: &str = include_str!("../doc/openapi.yaml");
    let stated = format!("\n  version: \"{}\"", env!("CARGO_PKG_VERSION"));

    let Some(info) = SPEC.find("\ninfo:") else {
        return SPEC.to_string();
    };
    let Some(line) = SPEC[info..].find("\n  version: ").map(|at| info + at) else {
        return SPEC.to_string();
    };
    let end = SPEC[line + 1..]
        .find('\n')
        .map_or(SPEC.len(), |at| line + 1 + at);

    let mut spec = String::with_capacity(SPEC.len() + stated.len());
    spec.push_str(&SPEC[..line]);
    spec.push_str(&stated);
    spec.push_str(&SPEC[end..]);
    spec
});

fn error_response(err: &ApiError) -> HttpResponse {
    HttpResponse::build(err.status()).json(err.body())
}

// ---------------------------------------------------------------------------
// Request and response shapes
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct ReadQuery {
    val: Option<String>,
    /// Present at any value (including empty) to suppress the shadow sighting.
    noshadow: Option<String>,
    /// Present at any value to answer with how many values the namespace holds
    /// instead of the values themselves.
    count: Option<String>,
    /// Present at any value to answer in the shape `POST /_api/merge` takes,
    /// so a sync reads from one server and posts to another unchanged.
    for_merge: Option<String>,
    /// Where to start when `for_merge` is asked of a whole namespace.
    offset: Option<usize>,
    /// How many values to answer with. A catch-up walks a namespace in
    /// bounded steps rather than asking for all of it at once.
    limit: Option<usize>,
}

impl ReadQuery {
    fn limit(&self) -> usize {
        self.limit.unwrap_or(500).clamp(1, 5_000)
    }
}

/// One page of a namespace, in the shape `POST /_api/merge` takes.
#[derive(Debug, Serialize)]
struct MergePage {
    namespace: String,
    items: Vec<MergeOffer>,
    /// Live values in the namespace, before paging — so a caller knows how
    /// much is left to walk.
    total: usize,
    offset: usize,
}

/// One value, ready to be posted to `/_api/merge` with nothing added.
#[derive(Debug, Serialize)]
struct MergeOffer {
    namespace: String,
    value: String,
    #[serde(flatten)]
    state: crate::attribute::Merge,
}

/// How many values a namespace holds, for `/r/<namespace>?count`.
#[derive(Debug, Serialize)]
struct CountResponse {
    namespace: String,
    #[serde(flatten)]
    count: crate::db::ValueCount,
}

#[derive(Debug, Deserialize)]
pub struct WriteQuery {
    val: Option<String>,
    /// Unix seconds. Absent means "now".
    timestamp: Option<i64>,
    /// Seconds from the last sighting until the value expires. Absent leaves
    /// whatever TTL the attribute already had; 0 clears it.
    ttl: Option<u64>,
    /// Comma-separated tags, merged with whatever the value already carried.
    tags: Option<String>,
}

/// An export asked for by an automation rather than by hand.
///
/// POST because a namespace is a path — putting `feeds/misp/ips` in a query
/// string means encoding it — and because asking for several at once is the
/// normal thing to want.
#[derive(Debug, Deserialize)]
pub struct ExportRequest {
    /// One namespace, or several to gather into one bundle.
    #[serde(default)]
    pub namespaces: Vec<String>,
    /// Shorthand for a single namespace, so a one-liner stays a one-liner.
    #[serde(default)]
    pub namespace: Option<String>,
    /// Substring filter over values, as when browsing.
    #[serde(default)]
    pub q: String,
    pub limit: Option<usize>,
    /// What to do with values whose observable type cannot be worked out.
    /// Defaults to leaving them out, which is what this route has always done.
    #[serde(default)]
    pub untyped: crate::stix::Untyped,
    /// Also export every namespace below each one named. Off by default, so a
    /// caller that named one namespace still gets one namespace.
    #[serde(default)]
    pub recursive: bool,
}

impl ExportRequest {
    fn wanted(&self) -> Vec<String> {
        let mut wanted: Vec<String> = Vec::new();
        for namespace in self.namespace.iter().chain(self.namespaces.iter()) {
            let namespace = namespace.trim().trim_matches('/').to_string();
            if !namespace.is_empty() && !wanted.contains(&namespace) {
                wanted.push(namespace);
            }
        }
        wanted
    }

    fn limit(&self) -> usize {
        self.limit.unwrap_or(10_000).clamp(1, 100_000)
    }
}

/// How much of a namespace one export may carry.
#[derive(Debug, Deserialize)]
pub struct ExportQuery {
    limit: Option<usize>,
    /// Present at any value to export the namespaces below this one too.
    recursive: Option<String>,
    /// `include` exports values nothing could identify; anything else, or
    /// absent, leaves them out. Absent is the default so that an existing
    /// caller's bundle does not change shape under it.
    untyped: Option<String>,
}

impl ExportQuery {
    fn untyped(&self) -> crate::stix::Untyped {
        match self.untyped.as_deref() {
            Some("include") => crate::stix::Untyped::Include,
            _ => crate::stix::Untyped::Skip,
        }
    }

    /// Two objects per value plus the identities: a bundle is read by a
    /// machine, but it is still one response held in memory.
    fn limit(&self) -> usize {
        self.limit.unwrap_or(10_000).clamp(1, 100_000)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkRequest {
    pub items: Vec<BulkSighting>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkSighting {
    pub namespace: String,
    pub value: String,
    #[serde(default)]
    pub timestamp: Option<i64>,
    #[serde(default)]
    pub ttl: Option<u64>,
    /// Comma-separated, merged with whatever the value already carried.
    #[serde(default)]
    pub tags: String,
    #[serde(default)]
    pub noshadow: bool,
}

#[derive(Debug, Serialize)]
struct WriteResponse {
    message: &'static str,
    count: u64,
    /// Whether this was the first sighting of the value in this namespace.
    ///
    /// Reported because a server in front of this one cannot work it out: it
    /// is what decides a consensus increment, and answering it needs the
    /// namespace, which a router does not hold.
    new: bool,
}

#[derive(Debug, Serialize)]
struct BulkReadResponse {
    items: Vec<BulkReadItem>,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
enum BulkReadItem {
    Found(Box<AttributeView>),
    Error(serde_json::Value),
    /// What a mirror answered for this item, passed through unchanged.
    ///
    /// Untagged like the rest, so a relayed answer is indistinguishable on
    /// the wire from one this server read itself — which is the point: a
    /// client talking to a router sees the same shape either way. Separate
    /// from `Error` because a mirror's answer is usually a found value.
    Relayed(serde_json::Value),
}

#[derive(Debug, Serialize)]
struct BulkWriteResponse {
    message: &'static str,
    written: usize,
    /// One entry per request item, in request order.
    items: Vec<BulkWriteItem>,
    /// The failures alone, kept because this field predates `items` and
    /// clients read it. Every entry here also appears in `items`.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    errors: Vec<BulkWriteError>,
}

/// A batch of peers' copies, for `POST /_api/merge`.
#[derive(Debug, Deserialize)]
pub struct MergeRequest {
    pub items: Vec<MergeItem>,
}

/// One value as a peer holds it.
///
/// The fields are spelled out rather than flattening [`crate::attribute::Merge`]
/// into them. `serde`'s `flatten` buffers through an intermediate that cannot
/// coerce JSON's string object keys back to the `i64` hours in `stats`, so a
/// payload read straight from `/r?for_merge` would be refused by the route
/// meant to take it.
#[derive(Debug, Deserialize)]
pub struct MergeItem {
    pub namespace: String,
    pub value: String,
    pub counts: std::collections::BTreeMap<String, u64>,
    #[serde(default)]
    pub stats: std::collections::BTreeMap<String, std::collections::BTreeMap<i64, u64>>,
    pub first_seen: i64,
    pub last_seen: i64,
    #[serde(default)]
    pub tags: String,
    /// When the peer last replaced its tag set. Absent from a peer too old to
    /// send it, which reads as zero and so loses to any replacement here.
    #[serde(default)]
    pub tags_at: i64,
    #[serde(default)]
    pub ttl: u64,
}

impl MergeItem {
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

#[derive(Debug, Serialize)]
struct MergeResponse {
    message: &'static str,
    /// Items that changed the local copy. An item that changed nothing is a
    /// success, not a failure: during catch-up it is how a caller learns it
    /// has converged.
    changed: usize,
    items: Vec<MergeResult>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    errors: Vec<BulkWriteError>,
}

#[derive(Debug, Serialize)]
struct MergeResult {
    index: usize,
    namespace: String,
    value: String,
    /// `"ok"` or `"error"`.
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    changed: Option<bool>,
    /// The total after merging, so a caller can see where the value stands
    /// without reading it back.
    #[serde(skip_serializing_if = "Option::is_none")]
    count: Option<u64>,
    /// Entries for this server's own id that were ignored. Non-zero means the
    /// sender is confused about who it is talking to, which is worth seeing.
    #[serde(skip_serializing_if = "Option::is_none")]
    ignored_self: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

/// What a dry run found, in the shape `/wb` would have answered with.
///
/// `writable` rather than `written`, because nothing was: the name is the one
/// place a reader is certain to look, so it is the place to say so.
#[derive(Debug, Serialize)]
struct BulkValidateResponse {
    message: &'static str,
    /// How many items would be recorded. Nothing has been.
    writable: usize,
    items: Vec<BulkWriteItem>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    errors: Vec<BulkWriteError>,
}

/// What happened to one item of a bulk write.
///
/// Carries `index` as well as the namespace and value so that a caller can map
/// an outcome back onto what it sent even when the same value appears twice in
/// one batch. `count` is that value's running total after this sighting — the
/// number `/w` returns, taken under the same lock that incremented it, so no
/// follow-up read is needed to learn it.
#[derive(Debug, Serialize)]
struct BulkWriteItem {
    index: usize,
    namespace: String,
    value: String,
    /// `"ok"` or `"error"`.
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    count: Option<u64>,
    /// Whether this was the first sighting of the value in this namespace.
    /// Absent on an item that was not written, and on a dry run.
    #[serde(skip_serializing_if = "Option::is_none")]
    new: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Debug, Serialize)]
struct BulkWriteError {
    namespace: String,
    value: String,
    error: String,
}

/// What a health check gets: enough to tell a live database from a process
/// that is merely running, and nothing that would be worth an unauthenticated
/// request to find out.
#[derive(Debug, Serialize)]
struct HealthData {
    status: &'static str,
    version: &'static str,
    uptime_seconds: u64,
    /// Shards in memory, out of how many exist. A restored database that has
    /// not been touched yet reports 0 of n, which is normal rather than ill.
    resident_shards: usize,
    shards: usize,
    /// Whether this server is still pulling what it missed from its peers.
    ///
    /// Reported so that something in front of it can send reads elsewhere
    /// while it is behind. Writes are fine — they land directly and the
    /// catch-up fills in the history behind them — but a read would
    /// under-report, which is the one thing a sightings database must not do.
    catching_up: bool,
}

#[derive(Debug, Serialize)]
struct InfoData {
    implementation: &'static str,
    version: &'static str,
    vendor: &'static str,
    author: &'static str,
}

// ---------------------------------------------------------------------------
// Authorization
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
enum Access {
    Read,
    Write,
}

/// A stable handle for a key, so refusals can be followed through a log
/// without the log becoming a list of credentials.
///
/// The first four bytes of its SHA-256: enough to tell one misconfigured
/// client from another, and not enough to be worth stealing.
fn fingerprint(key: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(key.as_bytes());
    format!(
        "{:08x}",
        u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]])
    )
}

/// What a refusal says in the log.
///
/// Unlike the answer to the client, this *does* distinguish a key that does not
/// exist from one that exists but is not allowed here — the point of hiding
/// that from a caller is to stop it probing, and the point of the log is to
/// tell the person running the server which of the two they are looking at.
pub(crate) fn refusal(peer: &str, key: &str, known: bool, verb: &str, namespace: &str) -> String {
    let key = fingerprint(key);
    if known {
        format!("Refused {peer}: key {key} may not {verb} '{namespace}'")
    } else {
        format!("Refused {peer}: no such key {key}, asked to {verb} '{namespace}'")
    }
}

/// The address the request actually came from.
///
/// The socket, not `X-Forwarded-For`: a header a client controls is no use for
/// deciding who to complain about. Behind a proxy this is the proxy, which is
/// the truth about what this process can see.
pub(crate) fn peer_of(req: &HttpRequest) -> String {
    req.peer_addr()
        .map(|addr| addr.to_string())
        .unwrap_or_else(|| "an unknown address".to_string())
}

/// The API key on this request, if authentication is switched on.
///
/// `Ok(None)` means authentication is disabled, which every permission check
/// treats as "allowed". This is split out from [`refusal_for`] because the two
/// answer different questions: whether a key was *supplied* is a fact about the
/// request, while whether it reaches a given namespace is a fact about each
/// namespace asked for. A bulk request needs the first once and the second per
/// item.
fn api_key<'r>(state: &SharedState, req: &'r HttpRequest) -> Result<Option<&'r str>, HttpResponse> {
    if !state.authenticate {
        return Ok(None);
    }

    let Some(header) = req.headers().get("Authorization") else {
        // Common enough on an open port to be noise at warn level, and still
        // worth having when someone is working out why a client fails.
        log::debug!("Refused {}: no API key supplied", peer_of(req));
        return Err(HttpResponse::Unauthorized().json(Message::new(
            "Please add the API key in the Authorization headers.",
        )));
    };

    // A non-UTF-8 header is a client error, not a reason to panic the worker.
    let Ok(apikey) = header.to_str() else {
        return Err(HttpResponse::BadRequest()
            .json(Message::new("Authorization header is not valid UTF-8.")));
    };

    Ok(Some(apikey))
}

/// Why `apikey` may not reach `namespace`, or `None` if it may.
///
/// The message is built here rather than by the caller so that a refusal reads
/// identically whether it comes back as a whole-request `403` or as one item's
/// status in a bulk response. That matters: the wording deliberately does not
/// say whether the key exists, and a second copy of it elsewhere is exactly how
/// that property gets lost.
///
/// A refusal is logged, because a client with the wrong key otherwise gets a
/// `403` that nobody but the client ever sees.
fn refusal_for(
    state: &SharedState,
    req: &HttpRequest,
    apikey: Option<&str>,
    namespace: &str,
    access: Access,
) -> Option<String> {
    // Authentication disabled: everything is permitted.
    let apikey = apikey?;

    let acl = state.acl();
    let (allowed, verb) = match access {
        Access::Read => (acl.can_read(apikey, namespace), "read"),
        Access::Write => (acl.can_write(apikey, namespace), "write"),
    };

    if allowed {
        return None;
    }

    log::warn!(
        "{}",
        refusal(&peer_of(req), apikey, acl.contains(apikey), verb, namespace)
    );
    // Deliberately the same answer whether the key is unknown or merely
    // unauthorised here, so that probing cannot distinguish the two.
    Some(format!(
        "API key is not permitted to {verb} this namespace."
    ))
}

/// Check the `Authorization` header against the ACL.
///
/// Returns the response to send on refusal. When authentication is disabled in
/// the config this is a no-op — including for `/d` and `/wb`, which previously
/// demanded a key regardless of that setting.
fn authorize(
    state: &SharedState,
    req: &HttpRequest,
    namespace: &str,
    access: Access,
) -> Result<(), HttpResponse> {
    let apikey = api_key(state, req)?;
    match refusal_for(state, req, apikey, namespace, access) {
        None => Ok(()),
        Some(message) => Err(HttpResponse::Forbidden().json(Message::new(message))),
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

pub async fn help() -> impl Responder {
    HttpResponse::Ok()
        .content_type("text/plain; charset=utf-8")
        .body(concat!(
            "SightingDB ",
            env!("CARGO_PKG_VERSION"),
            ", written by Sebastien Tricaud\n",
            "REST Endpoints:\n",
            "\t/w: write (GET)\n",
            "\t/wb: write in bulk mode (POST)\n",
            "\t/vwb: check a bulk write without recording it (POST)\n",
            "\t/_api/merge: fold a peer's copy of values into ours (POST)\n",
            "\t/_api/namespaces: which namespaces exist here (GET)\n",
            "\t/r: read (GET)\n",
            "\t/rs: read with statistics (GET)\n",
            "\t/rb: read in bulk mode (POST)\n",
            "\t/rbs: read with statistics in bulk mode (POST)\n",
            "\t/d: delete (GET)\n",
            "\t/stix: export a namespace as a STIX 2.1 bundle (GET)\n",
            "\t/_api/stix: export one or more namespaces as STIX 2.1 (POST)\n",
            "\t/_api/tier: set a namespace's tier and idle window (POST)\n",
            "\t/c: configure (GET)\n",
            "\t/i: info (GET)\n",
            "\t/health: liveness and readiness, no key required (GET)\n",
            "\t/_api/openapi.yaml: this API as an OpenAPI 3 document (GET)\n",
        ))
}

pub async fn info() -> impl Responder {
    HttpResponse::Ok().json(InfoData {
        implementation: "SightingDB",
        version: env!("CARGO_PKG_VERSION"),
        vendor: "github.com/stricaud/sightingdb",
        author: "Sebastien Tricaud",
    })
}

/// The OpenAPI description of this API, as shipped in `doc/openapi.yaml`.
///
/// Compiled in rather than read from disk so a running instance always hands
/// out the description of *itself*, and unauthenticated because a specification
/// is documentation — `/help` already lists every route to anyone who asks.
pub async fn openapi() -> impl Responder {
    HttpResponse::Ok()
        .content_type("application/yaml; charset=utf-8")
        .insert_header(("Cache-Control", "public, max-age=86400"))
        .body(OPENAPI.as_str())
}

/// Liveness and readiness in one, for orchestrators.
///
/// Unauthenticated on purpose: a kubelet has no API key, and this reports the
/// process rather than the data. There is no separate readiness endpoint
/// because there is no window where this answers and the database is not yet
/// loaded — the snapshot is restored before the listener is bound, so a
/// response at all means the database is up.
pub async fn health(state: State) -> HttpResponse {
    let (resident_shards, shards) = state.db.residency();
    HttpResponse::Ok().json(HealthData {
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
        uptime_seconds: state.started.elapsed().as_secs(),
        resident_shards,
        shards,
        catching_up: state.catching_up(),
    })
}

pub async fn configure_endpoint() -> impl Responder {
    HttpResponse::NotImplemented().json(Message::new("The /c endpoint is not implemented yet."))
}

pub async fn read(
    state: State,
    path: web::Path<String>,
    query: web::Query<ReadQuery>,
    req: HttpRequest,
) -> HttpResponse {
    let namespace = path.into_inner();
    if let Some(resp) = forwarded_read(&state, &req, &namespace, &query).await {
        return resp;
    }
    do_read(&state, &req, &namespace, &query, false)
}

pub async fn read_with_stats(
    state: State,
    path: web::Path<String>,
    query: web::Query<ReadQuery>,
    req: HttpRequest,
) -> HttpResponse {
    let namespace = path.into_inner();
    if let Some(resp) = forwarded_read(&state, &req, &namespace, &query).await {
        return resp;
    }
    do_read(&state, &req, &namespace, &query, true)
}

/// Pass a read to the mirror that should serve it, if this server does not.
///
/// `None` means answer it here. The authorization happens before this, in
/// [`do_read`]'s caller chain — so a refusal is this server's, not a peer's.
async fn forwarded_read(
    state: &State,
    req: &HttpRequest,
    namespace: &str,
    query: &ReadQuery,
) -> Option<HttpResponse> {
    if let Err(resp) = authorize(state, req, namespace, Access::Read) {
        return Some(resp);
    }

    let hops = match should_forward(state, req, namespace)? {
        Ok(hops) => hops,
        Err(resp) => return Some(resp),
    };
    let galaxy = state.galaxy.as_ref()?;

    // The search is recorded here, not wherever the read happens to land.
    //
    // This server is where the client actually is, so this is where "how often
    // was this looked for" is true. Recorded on the mirror instead, the count
    // would be split across whichever mirrors happened to serve each read —
    // arbitrary, and wrong in a way nobody would notice.
    //
    // It also means a read costs the mirror no write at all, which is what
    // stops serving more clients multiplying write load across a galaxy.
    //
    // Before forwarding and whatever the outcome: a miss is still a search,
    // which is already how a single server behaves.
    if query.noshadow.is_none()
        && let Some(value) = query.val.as_deref()
    {
        state.db.write(
            &format!("{}{namespace}", crate::db::SHADOW_PREFIX),
            value,
            chrono::Utc::now(),
            crate::db::WriteOpts::default(),
        );
    }

    let path = suppressing_shadow(req);

    // Read from one mirror, chosen by the value so the same value always comes
    // from the same place while the mirror set is unchanged. Without that,
    // consecutive reads could land on mirrors at different stages of catching
    // up and show a count going down.
    //
    // A namespace listing has no value to choose by, so it goes to whichever
    // mirror the empty string picks — consistently, which is the property that
    // matters.
    let value = query.val.as_deref().unwrap_or("");
    Some(
        match galaxy.forward_read(namespace, value, &path, hops, "").await {
            Ok(answer) => relayed(answer),
            Err(e) => forward_failed(&e),
        },
    )
}

fn do_read(
    state: &State,
    req: &HttpRequest,
    namespace: &str,
    query: &ReadQuery,
    with_stats: bool,
) -> HttpResponse {
    if let Err(resp) = authorize(state, req, namespace, Access::Read) {
        return resp;
    }

    // A count is about the namespace, so a value alongside it is a request for
    // two different things at once rather than a narrowing of one.
    if query.count.is_some() {
        if query.val.is_some() {
            return HttpResponse::BadRequest().json(Message::new(
                "count applies to a namespace, not to one value. Drop val= to count, \
                 or drop count to read the value.",
            ));
        }
        return match state.db.value_count(namespace) {
            Some(count) => HttpResponse::Ok().json(CountResponse {
                namespace: namespace.to_string(),
                count,
            }),
            None => error_response(&ApiError::NotFound(NotFound::namespace(namespace, ""))),
        };
    }

    // The read side of /_api/merge. Answered before the ordinary read because
    // it is a different shape, not a variation on one: per-node counts rather
    // than the sum, which is the whole reason it exists.
    if query.for_merge.is_some() {
        // With a value: that one, as the merge route takes it. Without one: a
        // page of the whole namespace, which is what a catch-up walks.
        let Some(value) = query.val.as_deref() else {
            let Some(page) =
                state
                    .db
                    .merge_page(namespace, query.offset.unwrap_or(0), query.limit())
            else {
                return error_response(&ApiError::NotFound(NotFound::namespace(namespace, "")));
            };
            return HttpResponse::Ok().json(MergePage {
                namespace: namespace.to_string(),
                items: page
                    .items
                    .into_iter()
                    .map(|(value, state)| MergeOffer {
                        namespace: namespace.to_string(),
                        value,
                        state,
                    })
                    .collect(),
                total: page.total,
                offset: page.offset,
            });
        };
        return match state.db.merge_payload(namespace, value) {
            Some(payload) => HttpResponse::Ok().json(payload),
            None => error_response(&ApiError::NotFound(NotFound::value(namespace, value))),
        };
    }

    let with_shadow = query.noshadow.is_none();

    match &query.val {
        Some(value) => {
            match sighting_reader::read(&state.db, namespace, value, with_stats, with_shadow) {
                Ok(view) => HttpResponse::Ok().json(view),
                Err(e) => error_response(&e),
            }
        }
        // Listing a whole namespace has no per-value statistics to report.
        None if with_stats => HttpResponse::BadRequest().json(Message::new(
            "Error: val= not found! Use /r/<namespace> to list a whole namespace.",
        )),
        None => match sighting_reader::read_namespace(&state.db, namespace) {
            Ok(view) => HttpResponse::Ok().json(view),
            Err(e) => error_response(&e),
        },
    }
}

pub async fn write(
    state: State,
    path: web::Path<String>,
    query: web::Query<WriteQuery>,
    req: HttpRequest,
) -> HttpResponse {
    let namespace = path.into_inner();
    if let Err(resp) = authorize(&state, &req, &namespace, Access::Write) {
        return resp;
    }

    // Checked before forwarding: a request with no value is malformed wherever
    // it lands, so answering it here saves a hop and gives one consistent
    // error rather than whatever the mirror would have said.
    let Some(value) = query.val.as_deref() else {
        return HttpResponse::BadRequest().json(Message::new(
            "Did not receive a val= argument in the query string.",
        ));
    };

    // Not ours to store: pass it to every mirror that holds it.
    //
    // Fanned out rather than sent to one, because a write that reached only
    // one mirror is a write the others have to catch up — and catch-up is
    // repair, not the normal path. One mirror refusing is not a lost write
    // though: the mirror that took it is what the others converge from.
    if let Some(hops) = should_forward(&state, &req, &namespace) {
        let hops = match hops {
            Ok(hops) => hops,
            Err(resp) => return resp,
        };
        let galaxy = state.galaxy.as_ref().expect("checked by should_forward");
        let path = req
            .uri()
            .path_and_query()
            .map(|pq| pq.as_str().to_string())
            .unwrap_or_default();

        return match galaxy
            .forward_write(
                &namespace,
                awc::http::Method::GET,
                &path,
                None,
                hops,
                &origin_to_send(&state, &req),
            )
            .await
        {
            Err(e) => forward_failed(&e),
            Ok(answers) => {
                // The first mirror that accepted it answers the client. Its
                // count is that mirror's view, which is what any single server
                // can honestly report.
                let accepted = answers
                    .into_iter()
                    .find(|(_, answer)| (200..300).contains(&answer.status));
                match accepted {
                    Some((_, answer)) => {
                        note_consensus(&state, &namespace, value, &answer.body);
                        relayed(answer)
                    }
                    None => forward_failed(&crate::galaxy::ForwardError::AllDown {
                        namespace: namespace.clone(),
                    }),
                }
            }
        };
    }

    let when = match query.timestamp.map(timestamp_to_instant).transpose() {
        Ok(when) => when,
        Err(e) => {
            // Recorded here as well as below: a value turned away for its
            // timestamp is as much a rejection as one turned away for itself,
            // and this arm returns before the writer is ever reached.
            state.rejections.record(
                &namespace,
                value,
                &e.to_string(),
                crate::rejections::Source::Write,
            );
            return error_response(&e);
        }
    };

    let tags = query.tags.as_deref().unwrap_or_default();
    // Counted for whoever forwarded it, if anyone did.
    let origin = crate::galaxy::origin_of(&req);
    match sighting_writer::write_tagged_as(
        &state.db,
        origin.as_deref(),
        &namespace,
        value,
        when,
        query.ttl,
        tags,
    ) {
        Ok(written) => HttpResponse::Ok().json(WriteResponse {
            message: "ok",
            count: written.count,
            new: written.new,
        }),
        Err(e) => {
            state.rejections.record(
                &namespace,
                value,
                &e.to_string(),
                crate::rejections::Source::Write,
            );
            error_response(&e)
        }
    }
}

/// Export a namespace as a STIX 2.1 bundle.
///
/// A read of the whole namespace in another shape, so it needs read access and
/// nothing more. What each value becomes, and how tags fill in what a value on
/// its own cannot say, is in [`crate::stix`].
pub async fn export_stix(
    state: State,
    path: web::Path<String>,
    query: web::Query<ExportQuery>,
    req: HttpRequest,
) -> HttpResponse {
    let namespace = path.into_inner();
    if let Err(resp) = authorize(&state, &req, &namespace, Access::Read) {
        return resp;
    }

    if namespace.starts_with(CONFIG_PREFIX) {
        return error_response(&ApiError::ConfigNamespace);
    }

    if query.recursive.is_some() {
        let wanted = expand_subtrees(&state, &req, std::slice::from_ref(&namespace));
        if wanted.is_empty() {
            return error_response(&ApiError::NotFound(NotFound::namespace(&namespace, "")));
        }
        let names: Vec<&str> = wanted.iter().map(String::as_str).collect();
        return stix_response(crate::stix::export_namespaces(
            &state.db,
            &state.stix,
            &names,
            "",
            query.limit(),
            query.untyped(),
        ));
    }

    let Some(export) = crate::stix::export_namespace(
        &state.db,
        &state.stix,
        &namespace,
        query.limit(),
        query.untyped(),
    ) else {
        return error_response(&ApiError::NotFound(NotFound::namespace(&namespace, "")));
    };

    stix_response(export)
}

/// The same export, for automation: `POST /_api/stix`.
///
/// Every namespace asked for is authorized on its own, exactly as a bulk read
/// is, so a key scoped to one subtree cannot widen its reach by naming another
/// in the same request.
pub async fn export_stix_api(
    state: State,
    body: web::Json<ExportRequest>,
    req: HttpRequest,
) -> HttpResponse {
    let body = body.into_inner();
    let wanted = body.wanted();
    if wanted.is_empty() {
        return HttpResponse::BadRequest()
            .json(Message::new("Name at least one namespace to export."));
    }

    for namespace in &wanted {
        if namespace.starts_with(CONFIG_PREFIX) {
            return error_response(&ApiError::ConfigNamespace);
        }
        if let Err(resp) = authorize(&state, &req, namespace, Access::Read) {
            return resp;
        }
    }

    // Expanded after authorizing what was named, so the subtree is reached
    // only through a namespace the key was already allowed to export.
    let wanted = if body.recursive {
        let found = expand_subtrees(&state, &req, &wanted);
        if found.is_empty() {
            return error_response(&ApiError::NotFound(NotFound::namespace(&wanted[0], "")));
        }
        found
    } else {
        wanted
    };

    let names: Vec<&str> = wanted.iter().map(String::as_str).collect();
    let export = crate::stix::export_namespaces(
        &state.db,
        &state.stix,
        &names,
        &body.q,
        body.limit(),
        body.untyped,
    );

    // Nothing asked for exists: that is a mistake worth reporting rather than
    // an empty bundle to be puzzled over.
    if export.missing.len() == wanted.len() {
        return error_response(&ApiError::NotFound(NotFound::namespace(&wanted[0], "")));
    }

    stix_response(export)
}

/// A bundle, with what it could not carry reported in headers: the body has to
/// be a STIX bundle and nothing else.
/// Expand each namespace into itself plus everything below it that this key
/// may read.
///
/// The namespaces named are authorized by the caller before this runs, and a
/// refusal there is a `403`. What is *found* underneath follows the browsing
/// rule instead: a namespace the key may not read is left out rather than
/// failing the export, exactly as it is absent from the namespace tree. The
/// count that comes back in `X-SightingDB-Namespaces` is what the bundle
/// actually covers, so a caller can tell it got a subtree and how much of one.
fn expand_subtrees(state: &SharedState, req: &HttpRequest, wanted: &[String]) -> Vec<String> {
    // Read the key once: this asks about every namespace in the catalogue, and
    // going through `refusal_for` would log a warning for each refusal.
    let apikey = match api_key(state, req) {
        Ok(apikey) => apikey,
        // The caller has already authorized `wanted`, so a key that was going
        // to be refused never reaches this.
        Err(_) => return wanted.to_vec(),
    };
    let acl = state.acl();
    let allowed = |name: &str| match apikey {
        None => true,
        Some(key) => acl.can_read(key, name),
    };

    let mut found: Vec<String> = Vec::new();
    for namespace in wanted {
        for name in state.db.namespaces_under(namespace, allowed) {
            if !found.contains(&name) {
                found.push(name);
            }
        }
    }
    found
}

/// Count a forwarded write towards this server's own consensus tally.
///
/// A server passing writes along sees the *logical* write — one namespace, one
/// value — while mirroring is a detail below it. That makes it the only place
/// the galaxy-wide number can be kept without double counting: a value held by
/// three mirrors of one namespace is still one namespace.
///
/// It needs the one thing it cannot work out for itself — whether this was the
/// first sighting of the value in that namespace — which is why write responses
/// carry `new`. Counted once, from the mirror that answered, however many
/// mirrors took it.
///
/// Read it back with `/r/_all?val=<value>`, which is an ordinary namespace read
/// and so needs no endpoint of its own.
///
/// This only ever rises. Values expire and namespaces are deleted on the nodes,
/// and neither reaches a server in front of them, so the tally drifts upward
/// between reconciliations — see [`crate::galaxy::reconcile`].
fn note_consensus(state: &SharedState, namespace: &str, value: &str, body: &[u8]) {
    if !crate::db::counts_towards_consensus(namespace) {
        return;
    }
    let Ok(answer) = serde_json::from_slice::<serde_json::Value>(body) else {
        return;
    };
    if answer.get("new").and_then(|new| new.as_bool()) != Some(true) {
        return;
    }

    state.db.write(
        crate::db::ALL_NAMESPACE,
        value,
        chrono::Utc::now(),
        crate::db::WriteOpts::default(),
    );
}

/// The same, for every item of a forwarded batch.
fn note_consensus_batch(state: &SharedState, items: &[serde_json::Value]) {
    for entry in items {
        if entry.get("new").and_then(|new| new.as_bool()) != Some(true) {
            continue;
        }
        let Some(namespace) = entry.get("namespace").and_then(|n| n.as_str()) else {
            continue;
        };
        let Some(value) = entry.get("value").and_then(|v| v.as_str()) else {
            continue;
        };
        if !crate::db::counts_towards_consensus(namespace) {
            continue;
        }
        state.db.write(
            crate::db::ALL_NAMESPACE,
            value,
            chrono::Utc::now(),
            crate::db::WriteOpts::default(),
        );
    }
}

/// This request's path and query, with `noshadow` added.
///
/// The shadow sighting is recorded at the entry point, so the mirror serving
/// the read must not record one too — otherwise one search is counted twice,
/// in two places, and neither is the truth.
fn suppressing_shadow(req: &HttpRequest) -> String {
    let path = req.uri().path();
    let query = req.uri().query().unwrap_or_default();

    if query.is_empty() {
        return format!("{path}?noshadow");
    }
    // Already asked for, so nothing to add.
    if query
        .split('&')
        .any(|part| part == "noshadow" || part.starts_with("noshadow="))
    {
        return format!("{path}?{query}");
    }
    format!("{path}?{query}&noshadow")
}

/// Relay a peer's answer to our client, unchanged.
///
/// The peer's status and body are passed through rather than reinterpreted: a
/// `404` from the server that holds the value means the same thing to the
/// client as if it had asked directly, and rewriting it would only lose
/// detail.
fn relayed(answer: crate::galaxy::Forwarded) -> HttpResponse {
    let status = actix_web::http::StatusCode::from_u16(answer.status)
        .unwrap_or(actix_web::http::StatusCode::BAD_GATEWAY);
    let mut response = HttpResponse::build(status);
    response.insert_header(("X-SightingDB-Forwarded", "1"));

    // The mirror's own content type and `X-SightingDB-*` headers. A STIX
    // export is `application/stix+json` and says in headers how much it left
    // out, so replacing them with `application/json` and nothing else would
    // lose the part of the answer that is not in the body.
    let mut typed = false;
    for (name, value) in &answer.headers {
        if name.eq_ignore_ascii_case("content-type") {
            typed = true;
            response.content_type(value.as_str());
        } else {
            response.insert_header((name.as_str(), value.as_str()));
        }
    }
    if !typed {
        response.content_type("application/json");
    }
    response.body(answer.body)
}

/// What to answer when a request could not be forwarded.
///
/// `NoHolder` is the galaxy-wide version of 421: nowhere in reach stores this,
/// which is neither forbidden nor missing. Everything else is a `502` — the
/// request was this server's to pass on and it could not.
fn forward_failed(e: &crate::galaxy::ForwardError) -> HttpResponse {
    use crate::galaxy::ForwardError;
    let status = match e {
        ForwardError::NoHolder => actix_web::http::StatusCode::MISDIRECTED_REQUEST,
        ForwardError::TooManyHops => actix_web::http::StatusCode::LOOP_DETECTED,
        _ => actix_web::http::StatusCode::BAD_GATEWAY,
    };
    log::warn!("Could not forward: {e}");
    HttpResponse::build(status).json(Message::new(e.to_string()))
}

/// Who a write this server is about to forward should be counted for.
///
/// Whatever arrived, so a cascade preserves the entry point the client talked
/// to; failing that, this server, because it is the entry point.
fn origin_to_send(state: &SharedState, req: &HttpRequest) -> String {
    crate::galaxy::origin_of(req).unwrap_or_else(|| state.db.node().to_string())
}

/// Whether this server should pass a request for `namespace` along, and with
/// how many hops left.
///
/// `None` means handle it here: either this server stores the namespace, or it
/// has no galaxy to pass it to. `Some(hops)` means forward.
fn should_forward(
    state: &SharedState,
    req: &HttpRequest,
    namespace: &str,
) -> Option<Result<u8, HttpResponse>> {
    if state.db.holds(namespace) {
        return None;
    }
    let galaxy = state.galaxy.as_ref()?;
    // An internal namespace is this server's own and is never someone else's
    // to answer for.
    if crate::db::is_internal(namespace) {
        return None;
    }

    Some(match crate::galaxy::hops_left(req, galaxy.max_hops()) {
        Some(hops) => Ok(hops),
        None => Err(forward_failed(&crate::galaxy::ForwardError::TooManyHops)),
    })
}

fn stix_response(export: crate::stix::Export) -> HttpResponse {
    let mut response = HttpResponse::Ok();
    response
        .insert_header(("X-SightingDB-Exported", export.exported.to_string()))
        .insert_header(("X-SightingDB-Skipped", export.skipped.len().to_string()))
        .insert_header(("X-SightingDB-Untyped", export.untyped.to_string()))
        .insert_header(("X-SightingDB-Namespaces", export.namespaces.to_string()))
        .insert_header(("X-SightingDB-Truncated", export.truncated.to_string()))
        .content_type("application/stix+json;version=2.1");
    if !export.missing.is_empty() {
        response.insert_header(("X-SightingDB-Missing", export.missing.join(",")));
    }
    response.json(export.bundle)
}

pub async fn delete(state: State, path: web::Path<String>, req: HttpRequest) -> HttpResponse {
    let namespace = path.into_inner();
    if let Err(resp) = authorize(&state, &req, &namespace, Access::Write) {
        return resp;
    }

    // Deleting is a write. `/d/_all` would discard every consensus tally the
    // database holds, which is exactly the damage the write guard prevents.
    if crate::db::is_internal(&namespace) {
        return error_response(&ApiError::InternalNamespace(namespace));
    }

    if state.db.delete(&namespace) {
        HttpResponse::Ok().json(Message::new("ok"))
    } else {
        error_response(&ApiError::NotFound(NotFound::namespace(&namespace, "")))
    }
}

pub async fn read_bulk(
    state: State,
    body: web::Json<BulkRequest>,
    req: HttpRequest,
) -> HttpResponse {
    do_read_bulk(&state, &req, &body, false).await
}

pub async fn read_bulk_with_stats(
    state: State,
    body: web::Json<BulkRequest>,
    req: HttpRequest,
) -> HttpResponse {
    do_read_bulk(&state, &req, &body, true).await
}

/// Read one item from this server's own database.
fn read_here(state: &SharedState, item: &BulkSighting, with_stats: bool) -> BulkReadItem {
    match sighting_reader::read(
        &state.db,
        &item.namespace,
        &item.value,
        with_stats,
        !item.noshadow,
    ) {
        Ok(view) => BulkReadItem::Found(Box::new(view)),
        Err(e) => BulkReadItem::Error(e.body()),
    }
}

/// Answer a bulk read, gathering from mirrors whatever this server does not hold.
///
/// Items are grouped by the mirror that should serve each one and sent as one
/// sub-batch per mirror, rather than the whole batch to every holder the way
/// `/wb` does. A write has to reach every mirror; a read has to reach exactly
/// one, the one [`crate::galaxy::Galaxy::reader_for`] picks, or two consecutive
/// reads of a value could be served by mirrors at different stages of catching
/// up and show a count going down.
///
/// Each item keeps its request index through the round trip, so a mixed batch
/// — some namespaces here, some on two different mirrors, some nowhere at all
/// — still answers in request order.
async fn do_read_bulk(
    state: &State,
    req: &HttpRequest,
    body: &BulkRequest,
    with_stats: bool,
) -> HttpResponse {
    // The whole call is authorized up front. An item this key may not read
    // fails the request rather than the item, which is how `/rb` has always
    // behaved; deciding it before anything is read also keeps a refusal from
    // depending on how far down the batch it sits.
    for item in &body.items {
        if let Err(resp) = authorize(state, req, &item.namespace, Access::Read) {
            return resp;
        }
    }

    let mut answers: Vec<Option<BulkReadItem>> = (0..body.items.len()).map(|_| None).collect();

    // Items to fetch, grouped by the mirror that will serve them. Each entry
    // keeps the request indices so the answers can be put back in order.
    let mut grouped: Vec<(String, Vec<usize>)> = Vec::new();

    let hops = match state.galaxy.as_ref() {
        Some(galaxy) => crate::galaxy::hops_left(req, galaxy.max_hops()),
        None => None,
    };

    for (index, item) in body.items.iter().enumerate() {
        let elsewhere = state.galaxy.as_ref().filter(|_| {
            !state.db.holds(&item.namespace) && !crate::db::is_internal(&item.namespace)
        });

        let Some(galaxy) = elsewhere else {
            answers[index] = Some(read_here(state, item, with_stats));
            continue;
        };

        // Out of hops: this batch has been around a cascade already.
        if hops.is_none() {
            answers[index] = Some(BulkReadItem::Error(serde_json::json!(Message::new(
                crate::galaxy::ForwardError::TooManyHops.to_string()
            ))));
            continue;
        }

        match galaxy.reader_url(&item.namespace, &item.value) {
            Ok(url) => {
                // The search is recorded here, where the client is, for the
                // same reason a single read records it here — see
                // `forwarded_read`. The forwarded copy asks for no shadow, so
                // one search is not counted in two places.
                if !item.noshadow {
                    state.db.write(
                        &format!("{}{}", crate::db::SHADOW_PREFIX, item.namespace),
                        &item.value,
                        chrono::Utc::now(),
                        crate::db::WriteOpts::default(),
                    );
                }
                match grouped.iter_mut().find(|(known, _)| *known == url) {
                    Some((_, indices)) => indices.push(index),
                    None => grouped.push((url, vec![index])),
                }
            }
            // Nowhere in reach holds it. Reported per item, so the rest of
            // the batch still answers.
            Err(e) => {
                answers[index] = Some(BulkReadItem::Error(serde_json::json!(Message::new(
                    e.to_string()
                ))));
            }
        }
    }

    if let Some(galaxy) = state.galaxy.as_ref()
        && !grouped.is_empty()
    {
        let hops = hops.unwrap_or(0);
        let path = if with_stats { "/rbs" } else { "/rb" };
        let origin = origin_to_send(state, req);

        for (url, indices) in &grouped {
            let sub = BulkRequest {
                items: indices
                    .iter()
                    .map(|&index| {
                        let mut item = body.items[index].clone();
                        // The entry point already recorded the search.
                        item.noshadow = true;
                        item
                    })
                    .collect(),
            };
            let payload = match serde_json::to_vec(&sub) {
                Ok(payload) => payload,
                Err(e) => {
                    return HttpResponse::InternalServerError()
                        .json(Message::new(format!("could not forward the batch: {e}")));
                }
            };

            let relayed = galaxy
                .forward_to(
                    url,
                    awc::http::Method::POST,
                    path,
                    Some(&payload),
                    hops,
                    &origin,
                )
                .await;

            // A mirror that fails answers for its own items only. Reported
            // rather than swallowed: a batch quietly missing entries is the
            // bug that made bulk reads look empty through a router.
            let parsed = match &relayed {
                Ok(answer) => serde_json::from_slice::<serde_json::Value>(&answer.body)
                    .ok()
                    .and_then(|body| body.get("items")?.as_array().cloned()),
                Err(e) => {
                    log::warn!("Bulk read from {url} failed: {e}");
                    None
                }
            };

            for (position, &index) in indices.iter().enumerate() {
                answers[index] = Some(match parsed.as_ref().and_then(|got| got.get(position)) {
                    Some(entry) => BulkReadItem::Relayed(entry.clone()),
                    None => BulkReadItem::Error(serde_json::json!(Message::new(format!(
                        "No answer from {url} for this item."
                    )))),
                });
            }
        }
    }

    // Every index was filled: either read here, answered by a mirror, or
    // given a reason it could not be.
    let items = answers
        .into_iter()
        .map(|answer| {
            answer.unwrap_or_else(|| {
                BulkReadItem::Error(serde_json::json!(Message::new("No answer for this item.")))
            })
        })
        .collect();

    HttpResponse::Ok().json(BulkReadResponse { items })
}

/// One bulk item's fate, decided without touching the database.
///
/// `/wb` and `/vwb` both go through this and differ only in what they do with
/// the answer: the first writes on `Ok`, the second reports it. That is the
/// whole point of the dry run — the two cannot disagree about what is writable
/// because there is only one set of rules, here.
enum ItemCheck {
    /// Writable, carrying the parsed timestamp so the writer need not parse it
    /// a second time. `None` means "now".
    Ok(Option<chrono::DateTime<chrono::Utc>>),
    /// The ACL refused this namespace to this key.
    Refused(String),
    /// The item is not something we would write whoever asked.
    Invalid(String),
}

/// Decide one item: may this key write it, and is it writable at all?
///
/// Deliberately does not read the database. Nothing it checks depends on
/// stored state, which is what lets `/vwb` promise that a passing item would be
/// accepted rather than merely that it looks plausible.
fn check_item(
    state: &SharedState,
    req: &HttpRequest,
    apikey: Option<&str>,
    item: &BulkSighting,
) -> ItemCheck {
    if let Some(message) = refusal_for(state, req, apikey, &item.namespace, Access::Write) {
        return ItemCheck::Refused(message);
    }

    if let Err(e) = sighting_writer::check(&state.db, &item.namespace, &item.value) {
        return ItemCheck::Invalid(e.to_string());
    }

    match item.timestamp.map(timestamp_to_instant).transpose() {
        Ok(when) => ItemCheck::Ok(when),
        Err(e) => ItemCheck::Invalid(e.to_string()),
    }
}

pub async fn write_bulk(
    state: State,
    body: web::Json<BulkRequest>,
    req: HttpRequest,
) -> HttpResponse {
    // A missing or unreadable key fails the whole call: that is a fact about
    // the request, not about any one item. Whether the key reaches a given
    // namespace is decided per item below, so that one out-of-scope entry no
    // longer discards the outcome of every item beside it.
    let apikey = match api_key(&state, &req) {
        Ok(apikey) => apikey,
        Err(resp) => return resp,
    };

    // Namespaces in this batch that this server does not store. If any, the
    // batch goes to the peers that do — unchanged, so their per-item answers
    // line up with ours by index.
    let elsewhere: Vec<String> = body
        .items
        .iter()
        .map(|item| item.namespace.clone())
        .filter(|namespace| !state.db.holds(namespace) && !crate::db::is_internal(namespace))
        .collect();

    if !elsewhere.is_empty()
        && let Some(galaxy) = state.galaxy.as_ref()
    {
        let hops = match crate::galaxy::hops_left(&req, galaxy.max_hops()) {
            Some(hops) => hops,
            None => return forward_failed(&crate::galaxy::ForwardError::TooManyHops),
        };
        let payload = match serde_json::to_vec(&*body) {
            Ok(payload) => payload,
            Err(e) => {
                return HttpResponse::InternalServerError()
                    .json(Message::new(format!("could not forward the batch: {e}")));
            }
        };

        match galaxy
            .forward_batch(
                &elsewhere,
                "/wb",
                &payload,
                hops,
                &origin_to_send(&state, &req),
            )
            .await
        {
            Err(e) => return forward_failed(&e),
            Ok(answers) => {
                return merged_batch(&state, &req, apikey, &body, answers).await;
            }
        }
    }

    let origin = crate::galaxy::origin_of(&req);
    let mut items = Vec::with_capacity(body.items.len());
    let mut errors = Vec::new();
    let mut written = 0usize;
    let mut refusals = 0usize;

    for (index, item) in body.items.iter().enumerate() {
        let outcome = match check_item(&state, &req, apikey, item) {
            // The check has already ruled out everything `write_tagged` can
            // refuse, so this cannot fail; if it ever does, the error is
            // reported rather than swallowed.
            ItemCheck::Ok(when) => sighting_writer::write_tagged_as(
                &state.db,
                origin.as_deref(),
                &item.namespace,
                &item.value,
                when,
                item.ttl,
                &item.tags,
            )
            .map_err(|e| e.to_string()),
            ItemCheck::Refused(message) => {
                refusals += 1;
                Err(message)
            }
            ItemCheck::Invalid(message) => Err(message),
        };

        match outcome {
            Ok(done) => {
                written += 1;
                items.push(BulkWriteItem {
                    index,
                    namespace: item.namespace.clone(),
                    value: item.value.clone(),
                    status: "ok",
                    count: Some(done.count),
                    new: Some(done.new),
                    error: None,
                });
            }
            Err(message) => {
                state.rejections.record(
                    &item.namespace,
                    &item.value,
                    &message,
                    crate::rejections::Source::BulkWrite,
                );
                errors.push(BulkWriteError {
                    namespace: item.namespace.clone(),
                    value: item.value.clone(),
                    error: message.clone(),
                });
                items.push(BulkWriteItem {
                    index,
                    namespace: item.namespace.clone(),
                    value: item.value.clone(),
                    status: "error",
                    count: None,
                    new: None,
                    error: Some(message),
                });
            }
        }
    }

    // An ACL refusal is reported like any other per-item failure: it is one
    // item's outcome, not a verdict on the batch, and the items beside it that
    // were permitted have been recorded.
    //
    // The exception is a request that achieved nothing and was refused all the
    // way through, which is a permission failure entire and answers as one. A
    // batch that wrote nothing for *mixed* reasons is a bad request, since a
    // 403 would misdescribe the items that failed for their own sake; the
    // refusals are still in `items` either way.
    let (status, message) = if errors.is_empty() {
        (actix_web::http::StatusCode::OK, "ok")
    } else if written > 0 {
        (actix_web::http::StatusCode::OK, "partial")
    } else if refusals == errors.len() {
        (actix_web::http::StatusCode::FORBIDDEN, "failed")
    } else {
        (actix_web::http::StatusCode::BAD_REQUEST, "failed")
    };

    HttpResponse::build(status).json(BulkWriteResponse {
        message,
        written,
        items,
        errors,
    })
}

/// Combine what this server wrote with what the mirrors said.
///
/// Items this server stores are written here; the rest were sent to the peers
/// that hold them, which answered per item in the same order. An item counts
/// as written if *anywhere* took it — the mirror that did is what the others
/// catch up from, so one refusal is not a lost sighting.
async fn merged_batch(
    state: &State,
    req: &HttpRequest,
    apikey: Option<&str>,
    body: &BulkRequest,
    answers: Vec<(String, crate::galaxy::Forwarded)>,
) -> HttpResponse {
    // Each peer's items array, parsed once.
    let peer_items: Vec<Vec<serde_json::Value>> = answers
        .iter()
        .filter_map(|(_, answer)| {
            let parsed: serde_json::Value = serde_json::from_slice(&answer.body).ok()?;
            parsed.get("items")?.as_array().cloned()
        })
        .collect();

    let mut items = Vec::with_capacity(body.items.len());
    let mut errors = Vec::new();
    let mut written = 0usize;

    for (index, item) in body.items.iter().enumerate() {
        // Ours to store: write it here.
        if state.db.holds(&item.namespace) || crate::db::is_internal(&item.namespace) {
            let outcome = match check_item(state, req, apikey, item) {
                ItemCheck::Ok(when) => sighting_writer::write_tagged_as(
                    &state.db,
                    crate::galaxy::origin_of(req).as_deref(),
                    &item.namespace,
                    &item.value,
                    when,
                    item.ttl,
                    &item.tags,
                )
                .map_err(|e| e.to_string()),
                ItemCheck::Refused(message) | ItemCheck::Invalid(message) => Err(message),
            };
            match outcome {
                Ok(done) => {
                    written += 1;
                    items.push(BulkWriteItem {
                        index,
                        namespace: item.namespace.clone(),
                        value: item.value.clone(),
                        status: "ok",
                        count: Some(done.count),
                        new: Some(done.new),
                        error: None,
                    });
                }
                Err(message) => {
                    state.rejections.record(
                        &item.namespace,
                        &item.value,
                        &message,
                        crate::rejections::Source::BulkWrite,
                    );
                    errors.push(BulkWriteError {
                        namespace: item.namespace.clone(),
                        value: item.value.clone(),
                        error: message.clone(),
                    });
                    items.push(BulkWriteItem {
                        index,
                        namespace: item.namespace.clone(),
                        value: item.value.clone(),
                        status: "error",
                        count: None,
                        new: None,
                        error: Some(message),
                    });
                }
            }
            continue;
        }

        // Someone else's: take the first mirror that accepted it.
        let accepted = peer_items
            .iter()
            .filter_map(|answer| answer.get(index))
            .find(|entry| entry.get("status").and_then(|s| s.as_str()) == Some("ok"));

        match accepted {
            Some(entry) => {
                written += 1;
                // Counted once, from the mirror that answered. See
                // `note_consensus`.
                note_consensus_batch(state, std::slice::from_ref(entry));
                items.push(BulkWriteItem {
                    index,
                    namespace: item.namespace.clone(),
                    value: item.value.clone(),
                    status: "ok",
                    count: entry.get("count").and_then(|c| c.as_u64()),
                    new: entry.get("new").and_then(|n| n.as_bool()),
                    error: None,
                });
            }
            None => {
                // No mirror in reach stores the namespace at all, which is a
                // fact about the galaxy and not about any one mirror. Said
                // here rather than relaying a peer's own "this server does not
                // store it", which is true of that peer but reads as a claim
                // about the server the client is talking to.
                let message = if state
                    .galaxy
                    .as_ref()
                    .is_some_and(|galaxy| galaxy.holders(&item.namespace).is_empty())
                {
                    crate::galaxy::ForwardError::NoHolder.to_string()
                } else {
                    // Mirrors do hold it and still refused: their reason is
                    // the useful one.
                    peer_items
                        .iter()
                        .filter_map(|answer| answer.get(index))
                        .find_map(|entry| entry.get("error").and_then(|e| e.as_str()))
                        .unwrap_or("no server holding this namespace accepted it")
                        .to_string()
                };
                errors.push(BulkWriteError {
                    namespace: item.namespace.clone(),
                    value: item.value.clone(),
                    error: message.clone(),
                });
                items.push(BulkWriteItem {
                    index,
                    namespace: item.namespace.clone(),
                    value: item.value.clone(),
                    status: "error",
                    count: None,
                    new: None,
                    error: Some(message),
                });
            }
        }
    }

    let (status, message) = if errors.is_empty() {
        (actix_web::http::StatusCode::OK, "ok")
    } else if written > 0 {
        (actix_web::http::StatusCode::OK, "partial")
    } else {
        (actix_web::http::StatusCode::BAD_REQUEST, "failed")
    };

    HttpResponse::build(status)
        .insert_header(("X-SightingDB-Forwarded", "1"))
        .json(BulkWriteResponse {
            message,
            written,
            items,
            errors,
        })
}

/// `POST /vwb` — would this batch be accepted?
///
/// Answers exactly what [`write_bulk`] would answer for the same body, down to
/// the status code and each item's status, and writes nothing. That equivalence
/// is the contract: a client can send a batch here, and a `message: ok` means
/// the same batch sent to `/wb` is accepted in full.
///
/// Both routes decide each item with [`check_item`], so the preview cannot
/// drift from the writer. What it cannot promise is that the answer survives:
/// the ACL can be rewritten and a value can expire between the two calls, so
/// this reports what is true now, not a reservation. Callers that need the
/// outcome of the write itself should read the `items` that `/wb` returns —
/// which is why this route exists to check a batch *before* committing to it,
/// not to replace reading what came back.
///
/// It reveals nothing `/wb` would not: the same refusal, worded the same way,
/// for the same items. What it adds is the option of finding out without
/// leaving a sighting behind.
pub async fn validate_bulk(
    state: State,
    body: web::Json<BulkRequest>,
    req: HttpRequest,
) -> HttpResponse {
    let apikey = match api_key(&state, &req) {
        Ok(apikey) => apikey,
        Err(resp) => return resp,
    };

    let mut items = Vec::with_capacity(body.items.len());
    let mut errors = Vec::new();
    let mut writable = 0usize;
    let mut refusals = 0usize;

    for (index, item) in body.items.iter().enumerate() {
        let message = match check_item(&state, &req, apikey, item) {
            ItemCheck::Ok(_) => {
                writable += 1;
                items.push(BulkWriteItem {
                    index,
                    namespace: item.namespace.clone(),
                    value: item.value.clone(),
                    status: "ok",
                    // Nothing was recorded, so there is no count to give and
                    // no answer to whether it would have been the first.
                    count: None,
                    new: None,
                    error: None,
                });
                continue;
            }
            ItemCheck::Refused(message) => {
                refusals += 1;
                message
            }
            ItemCheck::Invalid(message) => message,
        };

        errors.push(BulkWriteError {
            namespace: item.namespace.clone(),
            value: item.value.clone(),
            error: message.clone(),
        });
        items.push(BulkWriteItem {
            index,
            namespace: item.namespace.clone(),
            value: item.value.clone(),
            status: "error",
            count: None,
            new: None,
            error: Some(message),
        });
    }

    // The same rule `write_bulk` applies, so that the dry run and the write
    // answer alike. See the comment there for why a wholly refused batch is a
    // 403 and a mixed failure a 400.
    let (status, message) = if errors.is_empty() {
        (actix_web::http::StatusCode::OK, "ok")
    } else if writable > 0 {
        (actix_web::http::StatusCode::OK, "partial")
    } else if refusals == errors.len() {
        (actix_web::http::StatusCode::FORBIDDEN, "failed")
    } else {
        (actix_web::http::StatusCode::BAD_REQUEST, "failed")
    };

    HttpResponse::build(status).json(BulkValidateResponse {
        message,
        writable,
        items,
        errors,
    })
}

/// `GET /_api/namespaces?prefix=<prefix>` — which namespaces exist here.
///
/// What a catch-up needs that nothing else gave it: a server that was down
/// does not know about namespaces created while it was away, so it cannot ask
/// for their values. This is how it finds out.
///
/// Read-authorized per namespace, like browsing, so a name out of a key's
/// reach is simply absent rather than refused. That means the answer is "what
/// you may know about", which is the only thing it could honestly be.
///
/// Deliberately not the management interface's namespace listing: that needs an
/// `admin` grant, and a peer key should be able to be the narrowest thing that
/// does the job.
pub async fn namespaces(
    state: State,
    query: web::Query<NamespacesQuery>,
    req: HttpRequest,
) -> HttpResponse {
    let apikey = match api_key(&state, &req) {
        Ok(apikey) => apikey,
        Err(resp) => return resp,
    };

    let prefix = query.prefix.as_deref().unwrap_or("");
    let acl = state.acl();
    let allowed = |name: &str| match apikey {
        None => true,
        Some(key) => acl.can_read(key, name),
    };
    let found = state.db.namespaces_under(prefix, allowed);
    drop(acl);

    HttpResponse::Ok().json(serde_json::json!({ "namespaces": found }))
}

#[derive(Debug, Deserialize)]
pub struct NamespacesQuery {
    /// Only namespaces at or under this one. Absent means all of them.
    prefix: Option<String>,
}

/// `POST /_api/merge` — fold peers' copies of values into ours.
///
/// This is how a galaxy syncs. Unlike `/w` it is **not a sighting**: nothing is
/// counted here. The sender states what each server has seen, and each field is
/// combined by a rule that does not care about order or repetition, so the same
/// merge can be sent twice, or two peers' copies can arrive either way round,
/// and the result is the same. See [`crate::attribute::Attribute::merge`].
///
/// That is the whole reason this route exists rather than reusing `/wb`. `/w`
/// means "add one"; replaying it doubles the count. Measured on two instances
/// before this existed: three sightings became nine after two rounds of
/// read-the-peer-and-write-it-back.
///
/// Authorized as a write, because it changes stored data: the same ACL, the
/// same refusal of internal namespaces, and the same 421 for a namespace this
/// server does not store. A peer's key therefore bounds what it can merge here
/// exactly as it bounds what it can write.
///
/// An entry naming *this* server is ignored. A peer does not get to say what
/// this server has seen.
pub async fn merge(state: State, body: web::Json<MergeRequest>, req: HttpRequest) -> HttpResponse {
    let apikey = match api_key(&state, &req) {
        Ok(apikey) => apikey,
        Err(resp) => return resp,
    };

    let mut items = Vec::with_capacity(body.items.len());
    let mut errors = Vec::new();
    let mut changed = 0usize;
    let mut refusals = 0usize;
    let mut failures = 0usize;

    for (index, item) in body.items.iter().enumerate() {
        // The ACL first, then everything the writer itself would refuse —
        // internal namespaces, and namespaces this server does not store.
        // Counted separately because an all-refused batch answers 403 while a
        // batch that failed for mixed reasons answers 400.
        let refusal = if let Some(message) =
            refusal_for(&state, &req, apikey, &item.namespace, Access::Write)
        {
            refusals += 1;
            Some(message)
        } else {
            sighting_writer::check(&state.db, &item.namespace, &item.value)
                .err()
                .map(|e| e.to_string())
        };

        if let Some(message) = refusal {
            failures += 1;
            errors.push(BulkWriteError {
                namespace: item.namespace.clone(),
                value: item.value.clone(),
                error: message.clone(),
            });
            items.push(MergeResult {
                index,
                namespace: item.namespace.clone(),
                value: item.value.clone(),
                status: "error",
                changed: None,
                count: None,
                ignored_self: None,
                error: Some(message),
            });
            continue;
        }

        let outcome = state.db.merge(&item.namespace, &item.value, &item.state());
        if outcome.changed {
            changed += 1;
        }
        items.push(MergeResult {
            index,
            namespace: item.namespace.clone(),
            value: item.value.clone(),
            status: "ok",
            changed: Some(outcome.changed),
            count: Some(outcome.count),
            ignored_self: Some(outcome.ignored_self),
            error: None,
        });
    }

    // The same rule the write routes use, so a peer can treat the three alike.
    let accepted = body.items.len() - failures;
    let (status, message) = if failures == 0 {
        (actix_web::http::StatusCode::OK, "ok")
    } else if accepted > 0 {
        (actix_web::http::StatusCode::OK, "partial")
    } else if refusals == failures {
        (actix_web::http::StatusCode::FORBIDDEN, "failed")
    } else {
        (actix_web::http::StatusCode::BAD_REQUEST, "failed")
    };

    HttpResponse::build(status).json(MergeResponse {
        message,
        changed,
        items,
        errors,
    })
}

// ---------------------------------------------------------------------------
// Wiring
// ---------------------------------------------------------------------------

/// Register every route. Shared by `main` and the tests so they cannot drift.
pub fn routes(cfg: &mut web::ServiceConfig) {
    cfg.route("/r/{namespace:.*}", web::get().to(read))
        .route("/rs/{namespace:.*}", web::get().to(read_with_stats))
        .route("/rb", web::post().to(read_bulk))
        .route("/rbs", web::post().to(read_bulk_with_stats))
        .route("/w/{namespace:.*}", web::get().to(write))
        .route("/wb", web::post().to(write_bulk))
        .route("/vwb", web::post().to(validate_bulk))
        .route("/_api/merge", web::post().to(merge))
        .route("/_api/namespaces", web::get().to(namespaces))
        .route("/d/{namespace:.*}", web::get().to(delete))
        .route("/stix/{namespace:.*}", web::get().to(export_stix))
        .route("/_api/stix", web::post().to(export_stix_api))
        .route("/_api/tier", web::post().to(crate::admin::set_tier))
        .route("/c/{namespace:.*}", web::get().to(configure_endpoint))
        .route("/i", web::get().to(info))
        .route("/health", web::get().to(health))
        .route("/_api/openapi.yaml", web::get().to(openapi))
        .default_service(web::to(help));
}

/// JSON body limit plus a JSON — rather than plain-text — error body.
pub fn json_config(limit: usize) -> web::JsonConfig {
    web::JsonConfig::default()
        .limit(limit)
        .error_handler(|err, _| {
            let response =
                HttpResponse::BadRequest().json(Message::new(format!("Invalid JSON body: {err}")));
            actix_web::error::InternalError::from_response(err, response).into()
        })
}

/// Same idea for malformed query strings.
pub fn query_config() -> web::QueryConfig {
    web::QueryConfig::default().error_handler(|err, _| {
        let response =
            HttpResponse::BadRequest().json(Message::new(format!("Invalid query string: {err}")));
        actix_web::error::InternalError::from_response(err, response).into()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acl::parse_grants;
    use actix_web::http::StatusCode;
    use actix_web::{App, test};
    use serde_json::{Value, json};

    const KEY: &str = "changeme";

    fn state(authenticate: bool) -> State {
        web::Data::new(SharedState::new(authenticate))
    }

    /// A state whose database only stores the given namespace prefixes.
    fn narrowed(prefixes: &[&str]) -> State {
        let mut inner = SharedState::new(false);
        inner.db = crate::db::Database::with_storage(
            crate::db::DatabasePolicy::default(),
            crate::db::StoragePolicy::from_prefixes(prefixes),
        );
        web::Data::new(inner)
    }

    macro_rules! app {
        ($state:expr) => {
            test::init_service(
                App::new()
                    .app_data($state.clone())
                    .app_data(json_config(1024 * 1024))
                    .app_data(query_config())
                    .configure(routes),
            )
            .await
        };
    }

    #[actix_web::test]
    async fn write_then_read_round_trip() {
        let st = state(false);
        let app = app!(st);

        let resp = test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/w/my/namespace/?val=127.0.0.1")
                .to_request(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);

        let resp = test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/r/my/namespace/?val=127.0.0.1&noshadow")
                .to_request(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);

        let body: Value = test::read_body_json(resp).await;
        assert_eq!(body["value"], "127.0.0.1");
        assert_eq!(body["count"], 1);
        assert_eq!(body["consensus"], 1);
        assert!(body.get("stats").is_none(), "{body}");
    }

    /// Regression: a write with no `timestamp=` used to be recorded at the Unix
    /// epoch, so `first_seen`/`last_seen` came back as 0.
    #[actix_web::test]
    async fn a_write_without_a_timestamp_is_not_stamped_at_the_epoch() {
        let st = state(false);
        let app = app!(st);

        test::call_service(
            &app,
            test::TestRequest::get().uri("/w/ns?val=x").to_request(),
        )
        .await;

        let resp = test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/r/ns?val=x&noshadow")
                .to_request(),
        )
        .await;
        let body: Value = test::read_body_json(resp).await;

        assert_ne!(body["first_seen"], 0, "{body}");
        assert_ne!(body["last_seen"], 0, "{body}");
    }

    #[actix_web::test]
    async fn an_explicit_timestamp_is_stored() {
        let st = state(false);
        let app = app!(st);

        test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/w/ns?val=x&timestamp=1566624658")
                .to_request(),
        )
        .await;

        let resp = test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/r/ns?val=x&noshadow")
                .to_request(),
        )
        .await;
        let body: Value = test::read_body_json(resp).await;

        assert_eq!(body["first_seen"], 1_566_624_658_i64);
    }

    #[actix_web::test]
    async fn a_garbage_timestamp_is_a_json_bad_request() {
        let st = state(false);
        let app = app!(st);

        let resp = test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/w/ns?val=x&timestamp=soon")
                .to_request(),
        )
        .await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body: Value = test::read_body_json(resp).await;
        assert!(body["message"].is_string(), "{body}");
    }

    /// Regression: consensus counts namespaces, not repeat writes. The README
    /// example writes once to one namespace and twice to another, expecting 2.
    #[actix_web::test]
    async fn consensus_counts_namespaces() {
        let st = state(false);
        let app = app!(st);

        for uri in [
            "/w/my/namespace/?val=127.0.0.1",
            "/w/another/namespace/?val=127.0.0.1",
            "/w/another/namespace/?val=127.0.0.1",
        ] {
            test::call_service(&app, test::TestRequest::get().uri(uri).to_request()).await;
        }

        let resp = test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/r/another/namespace/?val=127.0.0.1&noshadow")
                .to_request(),
        )
        .await;
        let body: Value = test::read_body_json(resp).await;

        assert_eq!(body["count"], 2);
        assert_eq!(body["consensus"], 2);
    }

    #[actix_web::test]
    async fn read_with_stats_includes_the_hourly_buckets() {
        let st = state(false);
        let app = app!(st);

        test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/w/ns?val=x&timestamp=1593719022")
                .to_request(),
        )
        .await;

        let resp = test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/rs/ns?val=x&noshadow")
                .to_request(),
        )
        .await;
        let body: Value = test::read_body_json(resp).await;

        assert_eq!(body["stats"]["1593716400"], 1, "{body}");
    }

    /// Counting is a read of the namespace, answered from the map's own length
    /// rather than by walking it.
    #[actix_web::test]
    async fn counting_a_namespace_reports_how_many_values_it_holds() {
        let st = state(false);
        let app = app!(st);

        for uri in ["/w/ns?val=a", "/w/ns?val=b", "/w/ns?val=a"] {
            test::call_service(&app, test::TestRequest::get().uri(uri).to_request()).await;
        }

        let resp = test::call_service(
            &app,
            test::TestRequest::get().uri("/r/ns?count").to_request(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body: Value = test::read_body_json(resp).await;

        // Two distinct values, written three times between them.
        assert_eq!(body["namespace"], "ns", "{body}");
        assert_eq!(body["values"], 2, "{body}");
        assert_eq!(body["paged_in"], false, "{body}");

        // Nothing here can expire, so the stored count is the visible one.
        assert_eq!(body["exact"], true, "{body}");
    }

    /// A TTL anywhere in the namespace makes the count an upper bound, because
    /// a value stops being visible at expiry but is only removed by the next
    /// sweep. The response has to say so rather than quietly be wrong.
    #[actix_web::test]
    async fn a_namespace_with_a_ttl_reports_its_count_as_inexact() {
        let st = state(false);
        let app = app!(st);

        test::call_service(
            &app,
            test::TestRequest::get().uri("/w/ns?val=a").to_request(),
        )
        .await;

        let resp = test::call_service(
            &app,
            test::TestRequest::get().uri("/r/ns?count").to_request(),
        )
        .await;
        let body: Value = test::read_body_json(resp).await;
        assert_eq!(body["exact"], true, "before any ttl: {body}");

        // One TTL is enough, and it stays that way afterwards.
        test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/w/ns?val=b&ttl=3600")
                .to_request(),
        )
        .await;

        let resp = test::call_service(
            &app,
            test::TestRequest::get().uri("/r/ns?count").to_request(),
        )
        .await;
        let body: Value = test::read_body_json(resp).await;
        assert_eq!(body["values"], 2, "{body}");
        assert_eq!(body["exact"], false, "a ttl was not reported: {body}");
    }

    /// Counting must not be a way round the ACL, and must not invent a
    /// namespace that is not there.
    #[actix_web::test]
    async fn counting_is_authorized_and_404s_for_an_unknown_namespace() {
        let mut inner = SharedState::new(true);
        inner
            .acl
            .get_mut()
            .unwrap()
            .set("feed", parse_grants("rw:feeds").unwrap());
        let st: State = web::Data::new(inner);
        let app = app!(st);

        let resp = test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/r/secrets?count")
                .insert_header(("Authorization", "feed"))
                .to_request(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        let resp = test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/r/feeds/nothing-here?count")
                .insert_header(("Authorization", "feed"))
                .to_request(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    /// Counting a namespace is not a search for a value, so it must not leave
    /// a shadow sighting behind the way reading one does.
    #[actix_web::test]
    async fn counting_raises_no_shadow_sighting() {
        let st = state(false);
        let app = app!(st);

        test::call_service(
            &app,
            test::TestRequest::get().uri("/w/ns?val=a").to_request(),
        )
        .await;
        test::call_service(
            &app,
            test::TestRequest::get().uri("/r/ns?count").to_request(),
        )
        .await;

        assert!(
            !st.db.namespace_exists("_shadow/ns"),
            "counting raised a shadow sighting"
        );
    }

    /// `count` and `val` ask for two different things, so asking for both is a
    /// mistake worth naming rather than resolving silently.
    #[actix_web::test]
    async fn counting_and_reading_a_value_at_once_is_rejected() {
        let st = state(false);
        let app = app!(st);

        test::call_service(
            &app,
            test::TestRequest::get().uri("/w/ns?val=a").to_request(),
        )
        .await;

        let resp = test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/r/ns?val=a&count")
                .to_request(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body: Value = test::read_body_json(resp).await;
        assert!(
            body["message"].as_str().unwrap().contains("namespace"),
            "{body}"
        );
    }

    /// A recursive export covers the subtree; without it, one namespace means
    /// one namespace.
    #[actix_web::test]
    async fn a_stix_export_can_be_asked_for_the_whole_subtree() {
        let st = state(false);
        let app = app!(st);

        for uri in [
            "/w/feeds?val=1.1.1.1",
            "/w/feeds/misp/ips?val=2.2.2.2",
            "/w/feeds/misp/domains?val=evil.example",
            // A sibling that merely shares the first few characters. A prefix
            // match on raw text would drag this in; it is not a child.
            "/w/feeds-internal?val=3.3.3.3",
            "/w/other?val=4.4.4.4",
        ] {
            test::call_service(&app, test::TestRequest::get().uri(uri).to_request()).await;
        }

        // Default: just `feeds` itself.
        let resp = test::call_service(
            &app,
            test::TestRequest::get().uri("/stix/feeds").to_request(),
        )
        .await;
        assert_eq!(resp.headers().get("X-SightingDB-Namespaces").unwrap(), "1");
        assert_eq!(resp.headers().get("X-SightingDB-Exported").unwrap(), "1");

        // Recursive: `feeds` and the two below it, and nothing else.
        let resp = test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/stix/feeds?recursive")
                .to_request(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers().get("X-SightingDB-Namespaces").unwrap(), "3");
        assert_eq!(resp.headers().get("X-SightingDB-Exported").unwrap(), "3");

        let body: Value = test::read_body_json(resp).await;
        let covered: Vec<&str> = body["objects"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|o| o["x_sightingdb_namespace"].as_str())
            .collect();
        assert!(covered.contains(&"feeds"), "{covered:?}");
        assert!(covered.contains(&"feeds/misp/ips"), "{covered:?}");
        assert!(covered.contains(&"feeds/misp/domains"), "{covered:?}");
        assert!(
            !covered.contains(&"feeds-internal"),
            "a sibling sharing the prefix was treated as a child: {covered:?}"
        );
        assert!(!covered.contains(&"other"), "{covered:?}");
    }

    /// The same through the POST route, which takes it in the body.
    #[actix_web::test]
    async fn the_stix_api_route_can_be_asked_for_the_whole_subtree() {
        let st = state(false);
        let app = app!(st);

        for uri in ["/w/feeds/a?val=1.1.1.1", "/w/feeds/b?val=2.2.2.2"] {
            test::call_service(&app, test::TestRequest::get().uri(uri).to_request()).await;
        }

        let resp = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/_api/stix")
                .set_json(json!({"namespace": "feeds", "recursive": true}))
                .to_request(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        // `feeds` itself holds nothing, so only the two below it contribute.
        assert_eq!(resp.headers().get("X-SightingDB-Namespaces").unwrap(), "2");
        assert_eq!(resp.headers().get("X-SightingDB-Exported").unwrap(), "2");
    }

    /// A namespace below the one asked for that this key may not read is left
    /// out, rather than failing the whole export.
    ///
    /// The namespace *named* is authorized as always — that is a 403. What is
    /// found underneath follows the browsing rule, where something out of
    /// reach is simply not there.
    #[actix_web::test]
    async fn a_recursive_export_leaves_out_what_the_key_may_not_read() {
        let mut inner = SharedState::new(true);
        inner
            .acl
            .get_mut()
            .unwrap()
            .set("scoped", parse_grants("rw:feeds/open").unwrap());
        inner
            .acl
            .get_mut()
            .unwrap()
            .set("full", parse_grants("rw").unwrap());
        let st: State = web::Data::new(inner);
        let app = app!(st);

        for uri in [
            "/w/feeds/open/a?val=1.1.1.1",
            "/w/feeds/closed/b?val=2.2.2.2",
        ] {
            test::call_service(
                &app,
                test::TestRequest::get()
                    .uri(uri)
                    .insert_header(("Authorization", "full"))
                    .to_request(),
            )
            .await;
        }

        // The scoped key may read `feeds/open`, so it may export that subtree.
        let resp = test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/stix/feeds/open?recursive")
                .insert_header(("Authorization", "scoped"))
                .to_request(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers().get("X-SightingDB-Namespaces").unwrap(), "1");
        let body: Value = test::read_body_json(resp).await;
        let covered: Vec<&str> = body["objects"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|o| o["x_sightingdb_namespace"].as_str())
            .collect();
        assert!(covered.contains(&"feeds/open/a"), "{covered:?}");
        assert!(
            !covered.contains(&"feeds/closed/b"),
            "a recursive export reached outside the key's scope: {covered:?}"
        );

        // And asking for the parent it may not read is still a refusal.
        let resp = test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/stix/feeds?recursive")
                .insert_header(("Authorization", "scoped"))
                .to_request(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    /// `limit` is the budget for the export, not for each namespace in it —
    /// otherwise a recursive export of a large tree reads a multiple of it.
    #[actix_web::test]
    async fn the_export_limit_is_spent_across_the_whole_subtree() {
        let st = state(false);
        let app = app!(st);

        // Addresses rather than arbitrary strings: an untyped value is left
        // out of the bundle entirely, which would make this test about the
        // wrong thing.
        for n in 0..4 {
            for (ns, octet) in [("feeds/a", 10), ("feeds/b", 20)] {
                test::call_service(
                    &app,
                    test::TestRequest::get()
                        .uri(&format!("/w/{ns}?val={octet}.0.0.{n}"))
                        .to_request(),
                )
                .await;
            }
        }

        // Eight values across two namespaces, and a budget of five.
        let resp = test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/stix/feeds?recursive&limit=5")
                .to_request(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get("X-SightingDB-Exported").unwrap(),
            "5",
            "the limit was applied per namespace rather than to the export"
        );
        assert_eq!(
            resp.headers().get("X-SightingDB-Truncated").unwrap(),
            "true"
        );
    }

    /// The export routes must honour the choice, and say what they did in the
    /// headers the page reads.
    #[actix_web::test]
    async fn the_stix_routes_can_be_asked_to_export_untyped_values() {
        let st = state(false);
        let app = app!(st);

        for uri in ["/w/notes?val=1.2.3.4", "/w/notes?val=whatever%20this%20is"] {
            test::call_service(&app, test::TestRequest::get().uri(uri).to_request()).await;
        }

        // Default: the unidentifiable value is left out and reported.
        let resp = test::call_service(
            &app,
            test::TestRequest::get().uri("/stix/notes").to_request(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get("X-SightingDB-Exported").unwrap(),
            "1",
            "default should export only the recognised value"
        );
        assert_eq!(resp.headers().get("X-SightingDB-Skipped").unwrap(), "1");
        assert_eq!(resp.headers().get("X-SightingDB-Untyped").unwrap(), "0");

        // Asked for everything: both go, and the fallback is counted.
        let resp = test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/stix/notes?untyped=include")
                .to_request(),
        )
        .await;
        assert_eq!(resp.headers().get("X-SightingDB-Exported").unwrap(), "2");
        assert_eq!(resp.headers().get("X-SightingDB-Skipped").unwrap(), "0");
        assert_eq!(resp.headers().get("X-SightingDB-Untyped").unwrap(), "1");

        // And the same through the POST route, which takes it in the body.
        let resp = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/_api/stix")
                .set_json(json!({"namespace": "notes", "untyped": "include"}))
                .to_request(),
        )
        .await;
        assert_eq!(resp.headers().get("X-SightingDB-Untyped").unwrap(), "1");
        let body: Value = test::read_body_json(resp).await;
        let patterns: Vec<&str> = body["objects"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|o| o["pattern"].as_str())
            .collect();
        assert!(
            patterns.contains(&"[x-sightingdb-value:value = 'whatever this is']"),
            "{patterns:?}"
        );
    }

    /// Every write route refuses the internal namespaces, and the refusal is
    /// not merely cosmetic: nothing lands.
    ///
    /// `_all` is the one that matters. Before this guard a client could write
    /// it directly and give a value a consensus no namespace supported — the
    /// one number this database exists to be trusted about.
    #[actix_web::test]
    async fn no_write_route_can_reach_an_internal_namespace() {
        let st = state(false);
        let app = app!(st);

        // An honest sighting first, so there is a real consensus to corrupt.
        test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/w/feeds/ips?val=1.2.3.4")
                .to_request(),
        )
        .await;
        assert_eq!(st.db.count(crate::db::ALL_NAMESPACE, "1.2.3.4"), 1);

        // /w
        for namespace in ["_all", "_shadow/feeds/ips", "_config/acl/apikeys/mine"] {
            let resp = test::call_service(
                &app,
                test::TestRequest::get()
                    .uri(&format!("/w/{namespace}?val=1.2.3.4"))
                    .to_request(),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::FORBIDDEN, "/w/{namespace}");
        }

        // /wb reports it per item, and writes nothing
        let resp = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/wb")
                .set_json(json!({"items": [{"namespace": "_all", "value": "1.2.3.4"}]}))
                .to_request(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body: Value = test::read_body_json(resp).await;
        assert_eq!(body["written"], 0, "{body}");
        assert_eq!(body["items"][0]["status"], "error", "{body}");

        // /vwb agrees, as it must
        let resp = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/vwb")
                .set_json(json!({"items": [{"namespace": "_all", "value": "1.2.3.4"}]}))
                .to_request(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        // /d would discard every tally at once
        let resp =
            test::call_service(&app, test::TestRequest::get().uri("/d/_all").to_request()).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        // The consensus is exactly what the one honest write made it.
        assert_eq!(
            st.db.count(crate::db::ALL_NAMESPACE, "1.2.3.4"),
            1,
            "consensus was reachable after all"
        );
    }

    /// Reads of the internal namespaces stay open, apart from `_config`.
    ///
    /// `/r/_all?val=` is how consensus is asked for, and `/r/_shadow/<ns>` is
    /// how searches are reviewed. Closing writes must not close these.
    #[actix_web::test]
    async fn internal_namespaces_are_still_readable_except_config() {
        let st = state(false);
        let app = app!(st);

        // A write and a read, so both `_all` and `_shadow` have something.
        test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/w/feeds/ips?val=1.2.3.4")
                .to_request(),
        )
        .await;
        test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/r/feeds/ips?val=1.2.3.4")
                .to_request(),
        )
        .await;

        let resp = test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/r/_all?val=1.2.3.4&noshadow")
                .to_request(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK, "consensus became unreadable");
        let body: Value = test::read_body_json(resp).await;
        assert_eq!(body["count"], 1, "{body}");

        let resp = test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/r/_shadow/feeds/ips?val=1.2.3.4&noshadow")
                .to_request(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK, "shadows became unreadable");

        // `_config` holds keys on an older deployment and stays closed.
        let resp = test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/r/_config/acl/apikeys/mine?val=x&noshadow")
                .to_request(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    /// A server told which namespaces it stores will not take a write outside
    /// them. Until forwarding exists this is where such a write stops, and it
    /// says so rather than failing as a missing namespace.
    #[actix_web::test]
    async fn a_narrowed_server_refuses_writes_it_does_not_store() {
        let st = narrowed(&["feeds"]);
        let app = app!(st);

        // Inside the policy: ordinary.
        let resp = test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/w/feeds/misp/ips?val=1.2.3.4")
                .to_request(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);

        // Outside it: 421, which is neither "forbidden" nor "missing" — the
        // request arrived somewhere that cannot serve it.
        for outside in ["other", "feeds-internal"] {
            let resp = test::call_service(
                &app,
                test::TestRequest::get()
                    .uri(&format!("/w/{outside}?val=1.2.3.4"))
                    .to_request(),
            )
            .await;
            assert_eq!(
                resp.status(),
                StatusCode::MISDIRECTED_REQUEST,
                "/w/{outside}"
            );
            assert!(!st.db.namespace_exists(outside), "{outside} was created");
        }

        // /wb reports it per item, and the item inside the policy still lands.
        let resp = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/wb")
                .set_json(json!({"items": [
                    {"namespace": "feeds/a", "value": "1.1.1.1"},
                    {"namespace": "other", "value": "2.2.2.2"}
                ]}))
                .to_request(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body: Value = test::read_body_json(resp).await;
        assert_eq!(body["message"], "partial", "{body}");
        assert_eq!(body["items"][0]["status"], "ok", "{body}");
        assert_eq!(body["items"][1]["status"], "error", "{body}");
        assert!(
            body["items"][1]["error"]
                .as_str()
                .unwrap()
                .contains("does not store"),
            "{body}"
        );

        // And the dry run agrees with the writer, as it must.
        let resp = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/vwb")
                .set_json(json!({"items": [{"namespace": "other", "value": "x"}]}))
                .to_request(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body: Value = test::read_body_json(resp).await;
        assert_eq!(body["writable"], 0, "{body}");
    }

    /// A router stores no ordinary namespace, but keeps its own consensus
    /// tally — which is the whole point of putting one in front of a galaxy.
    #[actix_web::test]
    async fn a_router_refuses_every_ordinary_write_but_keeps_its_tally() {
        let st = narrowed(&[]);
        let app = app!(st);

        let resp = test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/w/feeds/ips?val=1.2.3.4")
                .to_request(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::MISDIRECTED_REQUEST);

        // Its own `_all` is still storage it holds, and still not writable
        // from outside — the guard from the other direction.
        assert!(st.db.holds(crate::db::ALL_NAMESPACE));
        let resp = test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/w/_all?val=1.2.3.4")
                .to_request(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    /// A search is recorded where the client is, not on whichever mirror
    /// happened to serve the read.
    #[actix_web::test]
    async fn a_forwarded_read_records_the_shadow_at_the_entry_point() {
        // A router with one peer that cannot be reached: the forward fails,
        // which is the point — a miss is still a search, and the shadow is
        // recorded before the forward is even attempted.
        let mut inner = SharedState::new(false);
        inner.db = crate::db::Database::with_storage(
            crate::db::DatabasePolicy::default(),
            crate::db::StoragePolicy::from_prefixes(Vec::<String>::new()),
        );
        inner.galaxy = Some(crate::galaxy::Galaxy::new(&crate::config::GalaxySettings {
            peers: vec![crate::config::Peer {
                url: "http://127.0.0.1:1".to_string(),
                key: "k".to_string(),
                stores: crate::db::StoragePolicy::everything(),
            }],
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
        }));
        let st: State = web::Data::new(inner);
        let app = app!(st);

        for _ in 0..3 {
            test::call_service(
                &app,
                test::TestRequest::get()
                    .uri("/r/feeds/ips?val=1.2.3.4")
                    .to_request(),
            )
            .await;
        }

        // A router stores no ordinary namespace, but `_shadow/*` is its own.
        assert_eq!(
            st.db.count("_shadow/feeds/ips", "1.2.3.4"),
            3,
            "the searches were not recorded at the entry point"
        );
    }

    /// A galaxy of one mirror that cannot be reached.
    ///
    /// Unreachable on purpose: these tests are about where a request is sent,
    /// not about what comes back, and a port nothing listens on fails fast
    /// and without a fixture.
    fn unreachable_galaxy(stores: &[&str]) -> crate::galaxy::Galaxy {
        crate::galaxy::Galaxy::new(&crate::config::GalaxySettings {
            peers: vec![crate::config::Peer {
                url: "http://127.0.0.1:1".to_string(),
                key: "k".to_string(),
                stores: if stores == ["/"] {
                    crate::db::StoragePolicy::everything()
                } else {
                    crate::db::StoragePolicy::from_prefixes(stores)
                },
            }],
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

    /// A router: stores nothing of its own, one mirror that holds `stores`.
    fn router_towards(stores: &[&str]) -> State {
        let mut inner = SharedState::new(false);
        inner.db = crate::db::Database::with_storage(
            crate::db::DatabasePolicy::default(),
            crate::db::StoragePolicy::from_prefixes(Vec::<&str>::new()),
        );
        inner.galaxy = Some(unreachable_galaxy(stores));
        web::Data::new(inner)
    }

    /// A router holding nothing must still answer a bulk read, by asking the
    /// mirrors that hold it.
    ///
    /// It did not: `/rb` had no forwarding path at all, so a router answered
    /// every bulk read out of its own empty database and reported "Path not
    /// found" for data that existed one hop away. That made the client's
    /// `exists()` and `read_many()` return nothing through a load balancer
    /// while working perfectly against a node.
    ///
    /// The peer here is deliberately unreachable, because what is under test
    /// is that the router *tries the mirror* rather than what the mirror says.
    #[actix_web::test]
    async fn a_router_forwards_a_bulk_read_instead_of_answering_it_empty() {
        let st = router_towards(&["/"]);
        let app = app!(st);

        let resp = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/rb")
                .set_json(json!({"items": [{"namespace": "feeds/ips", "value": "1.2.3.4"}]}))
                .to_request(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);

        let body: Value = test::read_body_json(resp).await;
        let answer = body["items"][0].to_string();
        assert!(
            !answer.contains("Path not found"),
            "the router answered a bulk read from its own empty database: {answer}"
        );
        assert!(
            answer.contains("No answer from"),
            "expected the unreachable mirror to be reported, got {answer}"
        );
    }

    /// A bulk read of a namespace nowhere in the galaxy says so, per item,
    /// and the items beside it still answer.
    #[actix_web::test]
    async fn a_bulk_read_reports_a_namespace_no_mirror_holds() {
        let st = router_towards(&["feeds/ips"]);
        let app = app!(st);

        let resp = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/rb")
                .set_json(json!({"items": [
                    {"namespace": "other/thing", "value": "nowhere"},
                    {"namespace": "feeds/ips", "value": "1.2.3.4"},
                ]}))
                .to_request(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);

        let body: Value = test::read_body_json(resp).await;
        let items = body["items"].as_array().expect("items");
        assert_eq!(items.len(), 2, "a batch answers every item it was given");
        assert!(
            items[0].to_string().contains("no server in this galaxy"),
            "a namespace nobody holds should say so: {}",
            items[0]
        );
        // The second went to the mirror, which is down -- but it was *tried*,
        // which is what distinguishes it from the first.
        assert!(
            items[1].to_string().contains("No answer from"),
            "the held namespace should have been forwarded: {}",
            items[1]
        );
    }

    /// A batch half this server's and half a mirror's answers in request
    /// order.
    ///
    /// Items are grouped by mirror before being sent, so they come back in
    /// the mirror's order rather than the client's. Putting them back by
    /// index is what keeps a client able to match answers to what it asked.
    #[actix_web::test]
    async fn a_mixed_bulk_read_answers_in_request_order() {
        let mut inner = SharedState::new(false);
        // Stores `mine/*` itself; everything else is the mirror's.
        inner.db = crate::db::Database::with_storage(
            crate::db::DatabasePolicy::default(),
            crate::db::StoragePolicy::from_prefixes(["mine"]),
        );
        inner.galaxy = Some(unreachable_galaxy(&["/"]));
        let st: State = web::Data::new(inner);
        let app = app!(st);

        test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/w/mine/here?val=kept")
                .to_request(),
        )
        .await;

        let resp = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/rb")
                .set_json(json!({"items": [
                    {"namespace": "theirs/far", "value": "a", "noshadow": true},
                    {"namespace": "mine/here", "value": "kept", "noshadow": true},
                    {"namespace": "theirs/far", "value": "b", "noshadow": true},
                ]}))
                .to_request(),
        )
        .await;

        let body: Value = test::read_body_json(resp).await;
        let items = body["items"].as_array().expect("items");
        assert_eq!(items.len(), 3);
        assert_eq!(
            items[1]["value"], "kept",
            "the local item did not come back in its own position: {body}"
        );
        assert!(items[0].get("value").is_none() && items[2].get("value").is_none());
    }

    /// The search is counted where the client is, once, even though the read
    /// happened on a mirror.
    #[actix_web::test]
    async fn a_forwarded_bulk_read_records_one_search_at_the_entry_point() {
        let st = router_towards(&["/"]);
        let app = app!(st);

        for _ in 0..3 {
            let resp = test::call_service(
                &app,
                test::TestRequest::post()
                    .uri("/rb")
                    .set_json(json!({"items": [{"namespace": "feeds/ips", "value": "1.2.3.4"}]}))
                    .to_request(),
            )
            .await;
            // Asserted alongside the count, because a router answering out of
            // its own database would record the shadow too and the count
            // alone would pass for the wrong reason.
            let body: Value = test::read_body_json(resp).await;
            assert!(
                body["items"][0].to_string().contains("No answer from"),
                "this read was not forwarded, so the count below proves nothing: {body}"
            );
        }

        assert_eq!(
            st.db.count("_shadow/feeds/ips", "1.2.3.4"),
            3,
            "a bulk read did not record its search at the entry point"
        );
    }

    /// `noshadow` is honoured for a forwarded bulk read too.
    #[actix_web::test]
    async fn a_bulk_read_asking_for_no_shadow_records_nothing() {
        let st = router_towards(&["/"]);
        let app = app!(st);

        let resp = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/rb")
                .set_json(json!({"items": [
                    {"namespace": "feeds/ips", "value": "1.2.3.4", "noshadow": true}
                ]}))
                .to_request(),
        )
        .await;

        let body: Value = test::read_body_json(resp).await;
        assert!(
            body["items"][0].to_string().contains("No answer from"),
            "this read was not forwarded, so the count below proves nothing: {body}"
        );
        assert_eq!(st.db.count("_shadow/feeds/ips", "1.2.3.4"), 0);
    }

    /// `noshadow` from the client is still honoured: the entry point records
    /// nothing either.
    #[actix_web::test]
    async fn noshadow_is_honoured_at_the_entry_point() {
        let mut inner = SharedState::new(false);
        inner.db = crate::db::Database::with_storage(
            crate::db::DatabasePolicy::default(),
            crate::db::StoragePolicy::from_prefixes(Vec::<String>::new()),
        );
        inner.galaxy = Some(crate::galaxy::Galaxy::new(&crate::config::GalaxySettings {
            peers: vec![crate::config::Peer {
                url: "http://127.0.0.1:1".to_string(),
                key: "k".to_string(),
                stores: crate::db::StoragePolicy::everything(),
            }],
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
        }));
        let st: State = web::Data::new(inner);
        let app = app!(st);

        test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/r/feeds/ips?val=1.2.3.4&noshadow")
                .to_request(),
        )
        .await;

        assert!(!st.db.namespace_exists("_shadow/feeds/ips"));
    }

    /// The forwarded request must carry `noshadow`, or the mirror records a
    /// second shadow for the same search and neither count is the truth.
    #[actix_web::test]
    async fn a_forwarded_read_suppresses_the_mirrors_shadow() {
        let cases = [
            (
                "/r/feeds/ips?val=1.2.3.4",
                "/r/feeds/ips?val=1.2.3.4&noshadow",
            ),
            // Already asked for: left alone rather than doubled up.
            (
                "/r/feeds/ips?val=1.2.3.4&noshadow",
                "/r/feeds/ips?val=1.2.3.4&noshadow",
            ),
            ("/r/feeds/ips?noshadow=1", "/r/feeds/ips?noshadow=1"),
            // No query at all.
            ("/r/feeds/ips", "/r/feeds/ips?noshadow"),
        ];

        for (asked, expected) in cases {
            let req = test::TestRequest::get().uri(asked).to_http_request();
            assert_eq!(suppressing_shadow(&req), expected, "{asked}");
        }
    }

    /// A forwarded write is counted for the server it came from, not for the
    /// one that stores it.
    ///
    /// This is what stops fan-out double-counting. Measured on a real cascade
    /// before the origin travelled with the write: three writes through a load
    /// balancer became six once the two mirrors synced, because each had
    /// counted the same write under its own name.
    #[actix_web::test]
    async fn a_forwarded_write_is_counted_for_its_origin() {
        let st = state(false);
        let app = app!(st);

        for _ in 0..3 {
            test::call_service(
                &app,
                test::TestRequest::get()
                    .uri("/w/feeds/ips?val=1.2.3.4")
                    .insert_header((crate::galaxy::HOPS_HEADER, "3"))
                    .insert_header((crate::galaxy::ORIGIN_HEADER, "lb1"))
                    .to_request(),
            )
            .await;
        }

        let payload: Value = test::read_body_json(
            test::call_service(
                &app,
                test::TestRequest::get()
                    .uri("/r/feeds/ips?val=1.2.3.4&noshadow&for_merge")
                    .to_request(),
            )
            .await,
        )
        .await;

        assert_eq!(payload["counts"]["lb1"], 3, "{payload}");
        assert!(
            payload["counts"]["local"].is_null(),
            "the write was counted for this server as well: {payload}"
        );
    }

    /// The origin is part of the forwarding protocol, not the client API: a
    /// client naming one without having been forwarded is ignored.
    #[actix_web::test]
    async fn an_origin_without_a_hop_header_is_ignored() {
        let st = state(false);
        let app = app!(st);

        test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/w/feeds/ips?val=1.2.3.4")
                .insert_header((crate::galaxy::ORIGIN_HEADER, "pretending"))
                .to_request(),
        )
        .await;

        let payload: Value = test::read_body_json(
            test::call_service(
                &app,
                test::TestRequest::get()
                    .uri("/r/feeds/ips?val=1.2.3.4&noshadow&for_merge")
                    .to_request(),
            )
            .await,
        )
        .await;
        assert_eq!(payload["counts"]["local"], 1, "{payload}");
        assert!(payload["counts"]["pretending"].is_null(), "{payload}");
    }

    /// Bulk writes carry the origin per item too, or a fanned-out batch
    /// double-counts exactly as a single write would.
    #[actix_web::test]
    async fn a_forwarded_batch_is_counted_for_its_origin() {
        let st = state(false);
        let app = app!(st);

        test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/wb")
                .insert_header((crate::galaxy::HOPS_HEADER, "2"))
                .insert_header((crate::galaxy::ORIGIN_HEADER, "lb1"))
                .set_json(json!({"items": [
                    {"namespace": "feeds/a", "value": "1.1.1.1"},
                    {"namespace": "feeds/b", "value": "2.2.2.2"}
                ]}))
                .to_request(),
        )
        .await;

        for (ns, value) in [("feeds/a", "1.1.1.1"), ("feeds/b", "2.2.2.2")] {
            let payload: Value = test::read_body_json(
                test::call_service(
                    &app,
                    test::TestRequest::get()
                        .uri(&format!("/r/{ns}?val={value}&noshadow&for_merge"))
                        .to_request(),
                )
                .await,
            )
            .await;
            assert_eq!(payload["counts"]["lb1"], 1, "{ns}: {payload}");
        }
    }

    /// A request that has run out of hops is refused rather than passed on.
    /// Without this a miswired cascade circulates writes and inflates every
    /// count that goes round.
    #[actix_web::test]
    async fn a_request_out_of_hops_is_refused() {
        // A router with a peer, so forwarding is what it would otherwise do.
        let mut inner = SharedState::new(false);
        inner.db = crate::db::Database::with_storage(
            crate::db::DatabasePolicy::default(),
            crate::db::StoragePolicy::from_prefixes(Vec::<String>::new()),
        );
        inner.galaxy = Some(crate::galaxy::Galaxy::new(&crate::config::GalaxySettings {
            peers: vec![crate::config::Peer {
                url: "http://127.0.0.1:1".to_string(),
                key: "k".to_string(),
                stores: crate::db::StoragePolicy::everything(),
            }],
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
        }));
        let st: State = web::Data::new(inner);
        let app = app!(st);

        let resp = test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/w/feeds/ips?val=1.2.3.4")
                .insert_header((crate::galaxy::HOPS_HEADER, "0"))
                .to_request(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::LOOP_DETECTED);

        let resp = test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/r/feeds/ips?val=1.2.3.4&noshadow")
                .insert_header((crate::galaxy::HOPS_HEADER, "0"))
                .to_request(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::LOOP_DETECTED);
    }

    /// A router with no peer holding the namespace says so, rather than
    /// pretending the namespace does not exist.
    #[actix_web::test]
    async fn a_router_with_no_holder_answers_421() {
        let mut inner = SharedState::new(false);
        inner.db = crate::db::Database::with_storage(
            crate::db::DatabasePolicy::default(),
            crate::db::StoragePolicy::from_prefixes(Vec::<String>::new()),
        );
        inner.galaxy = Some(crate::galaxy::Galaxy::new(&crate::config::GalaxySettings {
            peers: vec![crate::config::Peer {
                url: "http://127.0.0.1:1".to_string(),
                key: "k".to_string(),
                // Holds only `feeds`, so `other` is nobody's.
                stores: crate::db::StoragePolicy::from_prefixes(["feeds"]),
            }],
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
        }));
        let st: State = web::Data::new(inner);
        let app = app!(st);

        let resp = test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/w/other?val=1.2.3.4")
                .to_request(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::MISDIRECTED_REQUEST);
        let body: Value = test::read_body_json(resp).await;
        assert!(
            body["message"].as_str().unwrap().contains("no server"),
            "{body}"
        );
    }

    /// The read side of the merge route. What comes back must be postable to
    /// `/_api/merge` unchanged — if it is not, a sync cannot be written at all.
    ///
    /// Pinned because `serde(flatten)` broke exactly this once: it cannot
    /// coerce JSON's string object keys back to the `i64` hours in `stats`, so
    /// a payload read from here was refused by the route meant to take it.
    #[actix_web::test]
    async fn what_for_merge_returns_can_be_posted_to_merge_unchanged() {
        let st = state(false);
        let app = app!(st);

        for _ in 0..3 {
            test::call_service(
                &app,
                test::TestRequest::get()
                    .uri("/w/feeds/ips?val=1.2.3.4&tags=tlp:amber&ttl=3600")
                    .to_request(),
            )
            .await;
        }

        let payload: Value = test::read_body_json(
            test::call_service(
                &app,
                test::TestRequest::get()
                    .uri("/r/feeds/ips?val=1.2.3.4&noshadow&for_merge")
                    .to_request(),
            )
            .await,
        )
        .await;

        // Per-node counts, not a total: offering a total would make the
        // receiver attribute every server's sightings to the sender.
        assert_eq!(payload["counts"]["local"], 3, "{payload}");
        assert!(payload["stats"]["local"].is_object(), "{payload}");
        assert_eq!(payload["tags"], "tlp:amber", "{payload}");
        assert_eq!(payload["ttl"], 3600, "{payload}");

        // Post it back verbatim, with only the two routing fields added.
        let mut item = payload.clone();
        item["namespace"] = Value::from("feeds/copy");
        item["value"] = Value::from("1.2.3.4");

        let resp = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/_api/merge")
                .set_json(json!({"items": [item]}))
                .to_request(),
        )
        .await;
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "a payload from for_merge was refused by merge: {:?}",
            test::read_body(resp).await
        );

        // Accepted — but the only contributor named is this server itself, and
        // a peer does not get to say what this server has seen. So the counts
        // are ignored and reported, which is the rule working rather than
        // failing.
        let body: Value = test::read_body_json(
            test::call_service(
                &app,
                test::TestRequest::post()
                    .uri("/_api/merge")
                    .set_json(json!({"items": [item.clone()]}))
                    .to_request(),
            )
            .await,
        )
        .await;
        assert_eq!(body["items"][0]["ignored_self"], 1, "{body}");

        // Relabelled as a peer's — which is what it would be in a real sync,
        // since the payload would have come from a server with its own id —
        // the attribution comes across intact.
        let mut from_peer = item.clone();
        from_peer["namespace"] = Value::from("feeds/frompeer");
        from_peer["counts"] = json!({"node-b": 3});
        from_peer["stats"] = json!({"node-b": payload["stats"]["local"].clone()});

        let resp = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/_api/merge")
                .set_json(json!({"items": [from_peer]}))
                .to_request(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);

        let copy: Value = test::read_body_json(
            test::call_service(
                &app,
                test::TestRequest::get()
                    .uri("/r/feeds/frompeer?val=1.2.3.4&noshadow&for_merge")
                    .to_request(),
            )
            .await,
        )
        .await;
        assert_eq!(copy["counts"]["node-b"], 3, "attribution was lost: {copy}");
        assert_eq!(copy["stats"]["node-b"], payload["stats"]["local"]);
        assert_eq!(copy["ttl"], 3600);
        assert_eq!(copy["tags"], "tlp:amber");
    }

    /// An expired value is not offered: a peer that took it would hold
    /// something this server has already stopped showing.
    #[actix_web::test]
    async fn for_merge_does_not_offer_an_expired_value() {
        let st = state(false);
        let app = app!(st);

        // Sighted in 1970 with a one minute ttl: already gone.
        test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/w/feeds/ips?val=gone&timestamp=1000&ttl=60")
                .to_request(),
        )
        .await;

        let resp = test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/r/feeds/ips?val=gone&noshadow&for_merge")
                .to_request(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    /// The problem this route exists to solve, demonstrated: replaying `/w`
    /// doubles a count, and merging the same thing twice does not.
    #[actix_web::test]
    async fn merging_twice_does_not_double_what_writing_twice_would() {
        let st = state(false);
        let app = app!(st);

        // Three sightings on a peer called node-b, as /wb would have produced
        // there, offered to us.
        let offer = json!({"items": [{
            "namespace": "feeds/ips",
            "value": "1.2.3.4",
            "counts": {"node-b": 3},
            "first_seen": 1_600_000_000i64,
            "last_seen": 1_600_003_600i64,
            "tags": "tlp:amber"
        }]});

        let resp = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/_api/merge")
                .set_json(offer.clone())
                .to_request(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body: Value = test::read_body_json(resp).await;
        assert_eq!(body["message"], "ok", "{body}");
        assert_eq!(body["changed"], 1, "{body}");
        assert_eq!(body["items"][0]["count"], 3, "{body}");
        assert_eq!(body["items"][0]["changed"], true, "{body}");

        // Again. The count must not move, and the response must say nothing
        // changed — which during catch-up is how a caller knows it is done.
        let resp = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/_api/merge")
                .set_json(offer)
                .to_request(),
        )
        .await;
        let body: Value = test::read_body_json(resp).await;
        assert_eq!(
            body["changed"], 0,
            "a repeat merge changed something: {body}"
        );
        assert_eq!(body["items"][0]["changed"], false, "{body}");
        assert_eq!(body["items"][0]["count"], 3, "{body}");

        assert_eq!(st.db.count("feeds/ips", "1.2.3.4"), 3, "the count drifted");

        // The window and tags came across too.
        let view = st.db.view("feeds/ips", "1.2.3.4", 0, false).unwrap();
        assert_eq!(view.first_seen, 1_600_000_000);
        assert_eq!(view.last_seen, 1_600_003_600);
        assert_eq!(view.tags, "tlp:amber");
    }

    /// A merge brings the value into a namespace that did not hold it, which
    /// is a new namespace holding it — so consensus must rise exactly as a
    /// first write would have made it.
    #[actix_web::test]
    async fn a_merge_that_introduces_a_value_counts_towards_consensus() {
        let st = state(false);
        let app = app!(st);

        test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/w/feeds/a?val=1.2.3.4")
                .to_request(),
        )
        .await;
        assert_eq!(st.db.count(crate::db::ALL_NAMESPACE, "1.2.3.4"), 1);

        let offer = json!({"items": [{
            "namespace": "feeds/b", "value": "1.2.3.4",
            "counts": {"node-b": 2},
            "first_seen": 1_600_000_000i64, "last_seen": 1_600_000_000i64
        }]});
        for _ in 0..3 {
            test::call_service(
                &app,
                test::TestRequest::post()
                    .uri("/_api/merge")
                    .set_json(offer.clone())
                    .to_request(),
            )
            .await;
        }

        // Two namespaces hold it, however many times the merge was replayed.
        assert_eq!(
            st.db.count(crate::db::ALL_NAMESPACE, "1.2.3.4"),
            2,
            "consensus moved with the number of merges"
        );
    }

    /// Merging changes stored data, so it is a write: the ACL, the internal
    /// namespaces and the storage policy all apply.
    #[actix_web::test]
    async fn merging_is_authorized_and_bounded_like_a_write() {
        let mut inner = SharedState::new(true);
        inner
            .acl
            .get_mut()
            .unwrap()
            .set("feed", parse_grants("rw:feeds").unwrap());
        inner
            .acl
            .get_mut()
            .unwrap()
            .set("full", parse_grants("rw").unwrap());
        let st: State = web::Data::new(inner);
        let app = app!(st);

        let offer = |ns: &str| {
            json!({"items": [{
                "namespace": ns, "value": "1.2.3.4",
                "counts": {"node-b": 1},
                "first_seen": 1_600_000_000i64, "last_seen": 1_600_000_000i64
            }]})
        };
        let send = |key: &'static str, body: Value| {
            test::TestRequest::post()
                .uri("/_api/merge")
                .insert_header(("Authorization", key))
                .set_json(body)
                .to_request()
        };

        // Out of scope for this key.
        let resp = test::call_service(&app, send("feed", offer("secrets"))).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert_eq!(st.db.count("secrets", "1.2.3.4"), 0);

        // An internal namespace, asked for by a key the ACL would otherwise
        // allow anywhere: a peer must not be able to merge a consensus tally
        // into us, which would be the forgery guard bypassed by another door.
        let resp = test::call_service(&app, send("full", offer("_all"))).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body: Value = test::read_body_json(resp).await;
        assert!(
            body["items"][0]["error"]
                .as_str()
                .unwrap()
                .contains("internal namespace"),
            "{body}"
        );
        assert_eq!(st.db.count(crate::db::ALL_NAMESPACE, "1.2.3.4"), 0);

        // In scope.
        let resp = test::call_service(&app, send("feed", offer("feeds/ips"))).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(st.db.count("feeds/ips", "1.2.3.4"), 1);
    }

    /// A peer offering an entry under our own id is ignored, and the response
    /// says so — a sender that does it is confused about who it is talking to.
    #[actix_web::test]
    async fn a_merge_cannot_rewrite_this_servers_own_contribution() {
        let st = state(false);
        let app = app!(st);

        for _ in 0..2 {
            test::call_service(
                &app,
                test::TestRequest::get()
                    .uri("/w/feeds/ips?val=1.2.3.4")
                    .to_request(),
            )
            .await;
        }

        let resp = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/_api/merge")
                .set_json(json!({"items": [{
                    "namespace": "feeds/ips", "value": "1.2.3.4",
                    "counts": {"local": 999, "node-b": 1},
                    "first_seen": 1_600_000_000i64, "last_seen": 1_600_000_000i64
                }]}))
                .to_request(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body: Value = test::read_body_json(resp).await;
        assert_eq!(body["items"][0]["ignored_self"], 1, "{body}");
        // Our two, plus the peer's one. Not 1001.
        assert_eq!(body["items"][0]["count"], 3, "{body}");
    }

    /// `/w` and `/wb` report whether a sighting was the first in its
    /// namespace, which is what a router needs to maintain consensus without
    /// holding the namespace itself.
    #[actix_web::test]
    async fn write_responses_say_whether_the_sighting_was_new() {
        let st = state(false);
        let app = app!(st);

        let first: Value = test::read_body_json(
            test::call_service(
                &app,
                test::TestRequest::get()
                    .uri("/w/feeds/ips?val=1.2.3.4")
                    .to_request(),
            )
            .await,
        )
        .await;
        assert_eq!(first["count"], 1);
        assert_eq!(first["new"], true, "{first}");

        let again: Value = test::read_body_json(
            test::call_service(
                &app,
                test::TestRequest::get()
                    .uri("/w/feeds/ips?val=1.2.3.4")
                    .to_request(),
            )
            .await,
        )
        .await;
        assert_eq!(again["count"], 2);
        assert_eq!(again["new"], false, "{again}");

        // And per item in bulk: same value in a new namespace is new there.
        let body: Value = test::read_body_json(
            test::call_service(
                &app,
                test::TestRequest::post()
                    .uri("/wb")
                    .set_json(json!({"items": [
                        {"namespace": "feeds/ips", "value": "1.2.3.4"},
                        {"namespace": "feeds/other", "value": "1.2.3.4"}
                    ]}))
                    .to_request(),
            )
            .await,
        )
        .await;
        assert_eq!(body["items"][0]["new"], false, "{body}");
        assert_eq!(body["items"][1]["new"], true, "{body}");
    }

    #[actix_web::test]
    async fn read_with_stats_needs_a_value() {
        let st = state(false);
        let app = app!(st);

        let resp =
            test::call_service(&app, test::TestRequest::get().uri("/rs/ns").to_request()).await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[actix_web::test]
    async fn reading_a_namespace_lists_every_value() {
        let st = state(false);
        let app = app!(st);

        for uri in ["/w/ns?val=a", "/w/ns?val=b"] {
            test::call_service(&app, test::TestRequest::get().uri(uri).to_request()).await;
        }

        let resp =
            test::call_service(&app, test::TestRequest::get().uri("/r/ns").to_request()).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let body: Value = test::read_body_json(resp).await;
        let mut values: Vec<&str> = body["attributes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| a["value"].as_str().unwrap())
            .collect();
        values.sort_unstable();

        assert_eq!(values, ["a", "b"]);
    }

    /// Regression: missing things used to come back as `200 OK`.
    #[actix_web::test]
    async fn missing_values_and_namespaces_are_404() {
        let st = state(false);
        let app = app!(st);
        test::call_service(
            &app,
            test::TestRequest::get().uri("/w/ns?val=known").to_request(),
        )
        .await;

        let resp = test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/r/ns?val=unknown&noshadow")
                .to_request(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        let body: Value = test::read_body_json(resp).await;
        assert_eq!(body["error"], "Value not found");

        let resp = test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/r/nope?val=x&noshadow")
                .to_request(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        let body: Value = test::read_body_json(resp).await;
        assert_eq!(body["error"], "Path not found");
    }

    #[actix_web::test]
    async fn a_write_with_no_value_is_400() {
        let st = state(false);
        let app = app!(st);

        let resp =
            test::call_service(&app, test::TestRequest::get().uri("/w/ns").to_request()).await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[actix_web::test]
    async fn reads_raise_shadow_sightings_unless_suppressed() {
        let st = state(false);
        let app = app!(st);
        test::call_service(
            &app,
            test::TestRequest::get().uri("/w/ns?val=x").to_request(),
        )
        .await;

        // Two shadowed reads, one suppressed.
        test::call_service(
            &app,
            test::TestRequest::get().uri("/r/ns?val=x").to_request(),
        )
        .await;
        test::call_service(
            &app,
            test::TestRequest::get().uri("/r/ns?val=x").to_request(),
        )
        .await;
        test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/r/ns?val=x&noshadow")
                .to_request(),
        )
        .await;

        assert_eq!(st.db.count("_shadow/ns", "x"), 2);
    }

    // -- authentication ----------------------------------------------------

    #[actix_web::test]
    async fn a_missing_api_key_is_401() {
        let st = state(true);
        let app = app!(st);

        for uri in ["/w/ns?val=x", "/r/ns?val=x", "/d/ns"] {
            let resp =
                test::call_service(&app, test::TestRequest::get().uri(uri).to_request()).await;
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "{uri}");
        }
    }

    #[actix_web::test]
    async fn an_unknown_api_key_is_403() {
        let st = state(true);
        let app = app!(st);

        let resp = test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/w/ns?val=x")
                .insert_header(("Authorization", "wrong"))
                .to_request(),
        )
        .await;

        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[actix_web::test]
    async fn a_valid_api_key_is_accepted() {
        let st = state(true);
        let app = app!(st);

        let resp = test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/w/ns?val=x")
                .insert_header(("Authorization", KEY))
                .to_request(),
        )
        .await;

        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// Regression: `to_str().unwrap()` on the header panicked the worker.
    #[actix_web::test]
    async fn a_non_utf8_api_key_is_400_not_a_panic() {
        let st = state(true);
        let app = app!(st);

        let resp = test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/w/ns?val=x")
                .insert_header((
                    "Authorization",
                    actix_web::http::header::HeaderValue::from_bytes(&[0xff, 0xfe]).unwrap(),
                ))
                .to_request(),
        )
        .await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    /// A bulk write is a sighting, not a replacement: writing a value that is
    /// already there must add to it.
    ///
    /// Pinned because the accumulation is spread across three places that could
    /// each regress independently — `Attribute::increment` widens the seen
    /// window and bumps the count, `Attribute::add_tags` merges rather than
    /// assigns, and an item that omits `ttl` must leave the stored one alone.
    #[actix_web::test]
    async fn a_bulk_write_accumulates_onto_an_existing_value() {
        let st = state(false);
        let app = app!(st);

        // Both sightings must land inside the TTL window, or the value expires
        // and the read below sees nothing.
        let earlier = chrono::Utc::now().timestamp() - 60;
        let later = earlier + 30;

        // Seed with a plain write carrying a tag and a TTL.
        test::call_service(
            &app,
            test::TestRequest::get()
                .uri(&format!(
                    "/w/ns?val=1.2.3.4&tags=tlp:amber&ttl=3600&timestamp={earlier}"
                ))
                .to_request(),
        )
        .await;

        // The same value again in bulk: a second tag, no TTL, later timestamp.
        let resp = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/wb")
                .set_json(json!({"items": [{
                    "namespace": "ns",
                    "value": "1.2.3.4",
                    "tags": "stix-type:ipv4-addr",
                    "timestamp": later,
                }]}))
                .to_request(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);

        let resp = test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/r/ns?val=1.2.3.4&noshadow")
                .to_request(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value = test::read_body_json(resp).await;

        // The sighting was counted, not overwritten.
        assert_eq!(body["count"], 2, "bulk write replaced the count: {body}");

        // Both sightings are inside the seen window.
        assert_eq!(body["first_seen"], earlier, "first_seen moved: {body}");
        assert_eq!(body["last_seen"], later, "last_seen did not widen: {body}");

        // Tags merged; neither writer's tag was lost.
        let tags = body["tags"].as_str().unwrap();
        assert!(tags.contains("tlp:amber"), "seed tag was dropped: {body}");
        assert!(
            tags.contains("stix-type:ipv4-addr"),
            "bulk tag was dropped: {body}"
        );

        // An item with no `ttl` leaves the stored one alone.
        assert_eq!(
            body["ttl"], 3600,
            "an absent ttl cleared the stored one: {body}"
        );
    }

    /// Regression: `/d` and `/wb` used to demand a key even with
    /// `authenticate=false`.
    #[actix_web::test]
    async fn delete_and_bulk_write_honour_disabled_authentication() {
        let st = state(false);
        let app = app!(st);
        test::call_service(
            &app,
            test::TestRequest::get().uri("/w/ns?val=x").to_request(),
        )
        .await;

        let resp = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/wb")
                .set_json(json!({"items": [{"namespace": "ns2", "value": "y"}]}))
                .to_request(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);

        let resp =
            test::call_service(&app, test::TestRequest::get().uri("/d/ns").to_request()).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// A key scoped to one subtree must be usable there and nowhere else.
    #[actix_web::test]
    async fn a_scoped_key_is_confined_to_its_namespace() {
        let mut inner = SharedState::new(true);
        inner
            .acl
            .get_mut()
            .unwrap()
            .set("feed", parse_grants("rw:feeds/misp").unwrap());
        let st: State = web::Data::new(inner);
        let app = app!(st);

        let cases = [
            ("/w/feeds/misp/ips?val=1.2.3.4", StatusCode::OK),
            ("/w/feeds/misp?val=1.2.3.4", StatusCode::OK),
            // A sibling that merely starts with the same characters.
            ("/w/feeds/misp-internal?val=x", StatusCode::FORBIDDEN),
            ("/w/feeds?val=x", StatusCode::FORBIDDEN),
            ("/w/other?val=x", StatusCode::FORBIDDEN),
            ("/d/other", StatusCode::FORBIDDEN),
        ];

        for (uri, expected) in cases {
            let resp = test::call_service(
                &app,
                test::TestRequest::get()
                    .uri(uri)
                    .insert_header(("Authorization", "feed"))
                    .to_request(),
            )
            .await;
            assert_eq!(resp.status(), expected, "{uri}");
        }
    }

    #[actix_web::test]
    async fn a_read_only_key_cannot_write() {
        let mut inner = SharedState::new(true);
        inner
            .acl
            .get_mut()
            .unwrap()
            .set("analyst", parse_grants("r").unwrap());
        let st: State = web::Data::new(inner);
        let app = app!(st);

        let write = test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/w/ns?val=x")
                .insert_header(("Authorization", "analyst"))
                .to_request(),
        )
        .await;
        assert_eq!(write.status(), StatusCode::FORBIDDEN);

        // Reading a namespace it cannot write is still fine.
        let read = test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/r/ns?val=x&noshadow")
                .insert_header(("Authorization", "analyst"))
                .to_request(),
        )
        .await;
        assert_eq!(read.status(), StatusCode::NOT_FOUND);
    }

    /// Bulk requests are checked per item, so one out-of-scope entry must not
    /// ride in on the back of an in-scope one.
    ///
    /// The refusal is reported as that item's status rather than as the status
    /// of the request, so what this pins is the part that matters: the value
    /// the key may not write is not written.
    #[actix_web::test]
    async fn bulk_requests_are_authorized_per_item() {
        let mut inner = SharedState::new(true);
        inner
            .acl
            .get_mut()
            .unwrap()
            .set("feed", parse_grants("rw:feeds").unwrap());
        let st: State = web::Data::new(inner);
        let app = app!(st);

        let resp = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/wb")
                .insert_header(("Authorization", "feed"))
                .set_json(json!({"items": [
                    {"namespace": "feeds/a", "value": "ok"},
                    {"namespace": "secrets", "value": "nope"}
                ]}))
                .to_request(),
        )
        .await;

        assert_eq!(resp.status(), StatusCode::OK);
        let body: Value = test::read_body_json(resp).await;
        assert_eq!(body["message"], "partial", "{body}");
        assert_eq!(body["items"][0]["status"], "ok", "{body}");
        assert_eq!(body["items"][1]["status"], "error", "{body}");

        assert_eq!(st.db.count("feeds/a", "ok"), 1);
        assert_eq!(st.db.count("secrets", "nope"), 0);
    }

    /// The refusal must read the same whether the key is unknown or merely
    /// out of scope, so that probing cannot tell valid keys from invalid ones.
    #[actix_web::test]
    async fn refusals_do_not_reveal_whether_a_key_exists() {
        let mut inner = SharedState::new(true);
        inner
            .acl
            .get_mut()
            .unwrap()
            .set("real", parse_grants("rw:allowed").unwrap());
        let st: State = web::Data::new(inner);
        let app = app!(st);

        let mut bodies = Vec::new();
        for key in ["real", "totally-made-up"] {
            let resp = test::call_service(
                &app,
                test::TestRequest::get()
                    .uri("/w/denied?val=x")
                    .insert_header(("Authorization", key))
                    .to_request(),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::FORBIDDEN);
            bodies.push(test::read_body(resp).await);
        }

        assert_eq!(bodies[0], bodies[1]);
    }

    #[actix_web::test]
    async fn several_grants_on_one_key_are_unioned() {
        let mut inner = SharedState::new(true);
        inner
            .acl
            .get_mut()
            .unwrap()
            .set("mixed", parse_grants("r:public, w:inbox").unwrap());
        let st: State = web::Data::new(inner);
        let app = app!(st);

        let write_inbox = test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/w/inbox/x?val=v")
                .insert_header(("Authorization", "mixed"))
                .to_request(),
        )
        .await;
        assert_eq!(write_inbox.status(), StatusCode::OK);

        let write_public = test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/w/public/x?val=v")
                .insert_header(("Authorization", "mixed"))
                .to_request(),
        )
        .await;
        assert_eq!(write_public.status(), StatusCode::FORBIDDEN);
    }

    // -- the _config tree --------------------------------------------------

    #[actix_web::test]
    async fn the_config_tree_is_not_reachable() {
        let st = state(false);
        let app = app!(st);

        for uri in [
            "/r/_config/acl/apikeys/changeme?val=",
            "/w/_config/acl/apikeys/mine?val=x",
            "/d/_config/acl/apikeys/changeme",
        ] {
            let resp =
                test::call_service(&app, test::TestRequest::get().uri(uri).to_request()).await;
            assert_eq!(resp.status(), StatusCode::FORBIDDEN, "{uri}");
        }

        // Nothing was created under _config, and the ACL still holds the key
        // the delete tried to revoke.
        assert!(!st.db.namespace_exists("_config/acl/apikeys/mine"));
        assert!(st.db.legacy_apikeys().is_empty());
        assert!(st.acl().can_write(KEY, "any/namespace"));
    }

    /// The specification is only useful if it still describes this server, so
    /// every route registered here has to appear in it. A route added without
    /// a line in the document fails this rather than being found by whoever
    /// imports it into Postman.
    #[actix_web::test]
    async fn the_openapi_document_describes_every_route() {
        let st = state(false);
        let app = app!(st);

        let resp = test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/_api/openapi.yaml")
                .to_request(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = test::read_body(resp).await;
        let spec = String::from_utf8_lossy(&body);

        // Parsed rather than searched. This test used to grep for path strings,
        // which passed happily on a document no importer could read: an
        // unquoted colon in a description is enough to break the parse while
        // leaving every string it looks for present.
        let doc: serde_yaml_ng::Value = serde_yaml_ng::from_str(&spec)
            .unwrap_or_else(|e| panic!("the served document is not valid YAML: {e}"));

        let paths = doc
            .get("paths")
            .and_then(|paths| paths.as_mapping())
            .expect("a paths section");

        for route in [
            "/w/{namespace}",
            "/r/{namespace}",
            "/rs/{namespace}",
            "/d/{namespace}",
            "/wb",
            "/vwb",
            "/rb",
            "/rbs",
            "/stix/{namespace}",
            "/_api/merge",
            "/_api/namespaces",
            "/_api/stix",
            "/_api/tier",
            "/_api/openapi.yaml",
            "/c/{namespace}",
            "/i",
            "/health",
            "/_management/api/session",
            "/_management/api/info",
            "/_management/api/namespaces",
            "/_management/api/tree",
            "/_management/api/galaxy",
            "/_management/api/rejections",
            "/_management/api/values",
            "/_management/api/value",
            "/_management/api/sightings",
            "/_management/api/tags",
            "/_management/api/tags/vocabulary",
            "/_management/api/galaxy/peers",
            "/_management/api/tier",
            "/_management/api/keys",
            "/_management/api/keys/drift",
            "/_management/api/keys/generate",
            "/_management/api/keys/{key}",
        ] {
            assert!(
                paths.contains_key(serde_yaml_ng::Value::from(route)),
                "{route} is not a path in the OpenAPI document"
            );
        }

        // Every internal reference has to resolve. Adding a schema and
        // referring to it by a name that does not exist leaves a document that
        // parses and still describes nothing.
        let mut refs = Vec::new();
        collect_refs(&doc, &mut refs);
        assert!(!refs.is_empty(), "no $refs found, so this proves nothing");
        for reference in &refs {
            let Some(pointer) = reference.strip_prefix("#/") else {
                panic!("{reference} is not a local reference");
            };
            let mut at = &doc;
            for segment in pointer.split('/') {
                at = at
                    .get(segment)
                    .unwrap_or_else(|| panic!("{reference} does not resolve: no '{segment}'"));
            }
        }

        // Whatever the file says, the server says what it is.
        assert_eq!(
            doc.get("info").and_then(|info| info.get("version")),
            Some(&serde_yaml_ng::Value::from(env!("CARGO_PKG_VERSION"))),
            "the served document names the wrong version"
        );
    }

    /// Every `$ref` string anywhere in the document.
    fn collect_refs(node: &serde_yaml_ng::Value, found: &mut Vec<String>) {
        match node {
            serde_yaml_ng::Value::Mapping(map) => {
                for (key, value) in map {
                    if key.as_str() == Some("$ref") {
                        if let Some(target) = value.as_str() {
                            found.push(target.to_string());
                        }
                    } else {
                        collect_refs(value, found);
                    }
                }
            }
            serde_yaml_ng::Value::Sequence(items) => {
                for item in items {
                    collect_refs(item, found);
                }
            }
            _ => {}
        }
    }

    /// Issue #5: a client with the wrong key was told `403` and the server said
    /// nothing, so the one person who could fix it — whoever runs the server —
    /// never saw it.
    // `use actix_web::test` shadows the built-in attribute in this module, so
    // even a test with nothing to await is spelled the same as its neighbours.
    #[actix_web::test]
    async fn a_refusal_says_what_happened_without_quoting_the_key() {
        let unknown = refusal("10.0.0.9:5000", "hunter2", false, "write", "feeds/ips");
        assert!(unknown.contains("10.0.0.9:5000"), "{unknown}");
        assert!(unknown.contains("no such key"), "{unknown}");
        assert!(unknown.contains("write"), "{unknown}");
        assert!(unknown.contains("feeds/ips"), "{unknown}");
        // The key itself never reaches the log: a log is copied, shipped and
        // read by more people than a credential should be.
        assert!(!unknown.contains("hunter2"), "{unknown}");
        assert!(unknown.contains(&fingerprint("hunter2")), "{unknown}");

        // A key that exists but is not allowed here is a different problem,
        // and the log says which — even though the client is told neither.
        let known = refusal("10.0.0.9:5000", "analyst", true, "read", "private");
        assert!(known.contains("may not read 'private'"), "{known}");
        assert!(!known.contains("no such key"), "{known}");

        // The same key gives the same handle every time, or following one
        // through a log would be impossible.
        assert_eq!(fingerprint("analyst"), fingerprint("analyst"));
        assert_ne!(fingerprint("analyst"), fingerprint("analyst2"));
        assert_eq!(fingerprint("analyst").len(), 8);
    }

    #[actix_web::test]
    async fn health_answers_without_a_key_even_when_authentication_is_on() {
        let st = state(true);
        let app = app!(st);

        let resp =
            test::call_service(&app, test::TestRequest::get().uri("/health").to_request()).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let body: Value = test::read_body_json(resp).await;
        assert_eq!(body["status"], "ok");
        assert_eq!(body["version"], env!("CARGO_PKG_VERSION"));
        assert!(body["uptime_seconds"].is_u64(), "{body}");
        // Nothing is stored yet, so nothing is resident.
        assert_eq!(body["shards"], 0);
        assert_eq!(body["resident_shards"], 0);
    }

    #[actix_web::test]
    async fn health_reports_what_is_in_memory() {
        let st = state(false);
        let app = app!(st);
        test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/w/feeds/ips?val=1.2.3.4")
                .to_request(),
        )
        .await;

        let body: Value = test::read_body_json(
            test::call_service(&app, test::TestRequest::get().uri("/health").to_request()).await,
        )
        .await;
        // The namespace's own shard, plus the internal one holding `_all`.
        assert_eq!(body["shards"], 2);
        assert_eq!(body["resident_shards"], 2);
    }

    // -- tags and STIX -------------------------------------------------------

    /// Requests in this section are plain GETs; a helper keeps them readable.
    macro_rules! visit {
        ($app:expr, $uri:expr) => {
            test::call_service(&$app, test::TestRequest::get().uri($uri).to_request()).await
        };
        ($app:expr, $uri:expr, $key:expr) => {
            test::call_service(
                &$app,
                test::TestRequest::get()
                    .uri($uri)
                    .insert_header(("Authorization", $key))
                    .to_request(),
            )
            .await
        };
    }

    #[actix_web::test]
    async fn a_write_can_carry_tags_and_they_accumulate() {
        let st = state(false);
        let app = app!(st);

        visit!(
            app,
            "/w/feeds/ips?val=1.2.3.4&tags=stix-type:ipv4-addr,tlp:amber"
        );
        // A second source knows something else about the same value.
        visit!(app, "/w/feeds/ips?val=1.2.3.4&tags=tlp:amber,confidence:80");

        let view = st.db.view("feeds/ips", "1.2.3.4", 0, false).unwrap();
        assert_eq!(view.tags, "stix-type:ipv4-addr,tlp:amber,confidence:80");
        assert_eq!(view.count, 2, "tagging is still a sighting");
    }

    #[actix_web::test]
    async fn bulk_writes_carry_tags_per_item() {
        let st = state(false);
        let app = app!(st);

        let resp = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/wb")
                .set_json(json!({"items": [
                    {"namespace": "feeds/ips", "value": "1.2.3.4", "tags": "stix-type:ipv4-addr"},
                    {"namespace": "feeds/domains", "value": "evil.example", "tags": "tlp:green"},
                ]}))
                .to_request(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);

        assert_eq!(
            st.db.view("feeds/ips", "1.2.3.4", 0, false).unwrap().tags,
            "stix-type:ipv4-addr"
        );
        assert_eq!(
            st.db
                .view("feeds/domains", "evil.example", 0, false)
                .unwrap()
                .tags,
            "tlp:green"
        );
    }

    #[actix_web::test]
    async fn a_namespace_exports_as_a_stix_bundle() {
        let st = state(false);
        let app = app!(st);
        visit!(
            app,
            "/w/feeds/ips?val=1.2.3.4&tags=stix-type:ipv4-addr,tlp:green"
        );

        let resp = visit!(app, "/stix/feeds/ips");
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get("content-type").unwrap(),
            "application/stix+json;version=2.1"
        );
        assert_eq!(resp.headers().get("X-SightingDB-Exported").unwrap(), "1");
        assert_eq!(resp.headers().get("X-SightingDB-Skipped").unwrap(), "0");

        let body: Value = test::read_body_json(resp).await;
        assert_eq!(body["type"], "bundle");
        let kinds: Vec<&str> = body["objects"]
            .as_array()
            .unwrap()
            .iter()
            .map(|object| object["type"].as_str().unwrap())
            .collect();
        assert!(kinds.contains(&"indicator"), "{kinds:?}");
        assert!(kinds.contains(&"sighting"), "{kinds:?}");
        assert!(kinds.contains(&"identity"), "{kinds:?}");
        assert!(kinds.contains(&"marking-definition"), "{kinds:?}");
    }

    #[actix_web::test]
    async fn exporting_needs_read_access_and_a_namespace_that_exists() {
        let st = state(true);
        let app = app!(st);
        visit!(app, "/w/feeds/ips?val=1.2.3.4", KEY);

        // The export is a read, so it answers to the same rules as `/r`.
        assert_eq!(
            visit!(app, "/stix/feeds/ips").status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(visit!(app, "/stix/feeds/ips", KEY).status(), StatusCode::OK);
        assert_eq!(
            visit!(app, "/stix/nope", KEY).status(),
            StatusCode::NOT_FOUND
        );
        // The ACL refuses `_config` before the handler gets a say.
        assert_eq!(
            visit!(app, "/stix/_config/acl", KEY).status(),
            StatusCode::FORBIDDEN
        );
    }

    /// With authentication off there is no ACL to refuse it, so the handler's
    /// own guard is what keeps the key store out of an export.
    #[actix_web::test]
    async fn an_export_never_reaches_the_config_namespace() {
        let st = state(false);
        let app = app!(st);

        assert_eq!(
            visit!(app, "/stix/_config/acl/apikeys").status(),
            StatusCode::FORBIDDEN
        );
    }

    #[actix_web::test]
    async fn the_api_endpoint_exports_several_namespaces_at_once() {
        let st = state(false);
        let app = app!(st);
        visit!(
            app,
            "/w/feeds/misp/ips?val=1.2.3.4&tags=stix-type:ipv4-addr"
        );
        visit!(app, "/w/feeds/otx/ips?val=1.2.3.4&tags=stix-type:ipv4-addr");
        visit!(app, "/w/feeds/otx/ips?val=5.6.7.8&tags=stix-type:ipv4-addr");

        let resp = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/_api/stix")
                .set_json(json!({"namespaces": ["feeds/misp/ips", "feeds/otx/ips"]}))
                .to_request(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers().get("X-SightingDB-Exported").unwrap(), "3");

        let body: Value = test::read_body_json(resp).await;
        let objects = body["objects"].as_array().unwrap();
        let of_type =
            |kind: &str| -> Vec<&Value> { objects.iter().filter(|o| o["type"] == kind).collect() };

        // 1.2.3.4 was seen in both namespaces: one indicator, two sightings.
        assert_eq!(of_type("indicator").len(), 2);
        assert_eq!(of_type("sighting").len(), 3);
        let shared: Vec<&Value> = of_type("sighting")
            .into_iter()
            .filter(|sighting| {
                sighting["sighting_of_ref"]
                    == of_type("indicator")
                        .iter()
                        .find(|indicator| indicator["pattern"] == "[ipv4-addr:value = '1.2.3.4']")
                        .unwrap()["id"]
            })
            .collect();
        assert_eq!(shared.len(), 2);
        let namespaces: Vec<&str> = shared
            .iter()
            .map(|sighting| sighting["x_sightingdb_namespace"].as_str().unwrap())
            .collect();
        assert!(namespaces.contains(&"feeds/misp/ips"), "{namespaces:?}");
        assert!(namespaces.contains(&"feeds/otx/ips"), "{namespaces:?}");
    }

    #[actix_web::test]
    async fn the_api_endpoint_authorizes_every_namespace_it_is_given() {
        let st = state(true);
        st.acl
            .write()
            .unwrap()
            .set("scoped", parse_grants("rw:feeds").unwrap());
        let app = app!(st);
        visit!(app, "/w/feeds/ips?val=1.2.3.4", KEY);
        visit!(app, "/w/private/ips?val=1.2.3.4", KEY);

        let ask = |namespaces: Value, key: Option<&'static str>| {
            let mut req = test::TestRequest::post()
                .uri("/_api/stix")
                .set_json(json!({ "namespaces": namespaces }));
            if let Some(key) = key {
                req = req.insert_header(("Authorization", key));
            }
            req.to_request()
        };

        assert_eq!(
            test::call_service(&app, ask(json!(["feeds/ips"]), None))
                .await
                .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            test::call_service(&app, ask(json!(["feeds/ips"]), Some("scoped")))
                .await
                .status(),
            StatusCode::OK
        );
        // Naming a namespace it may not read refuses the whole request rather
        // than quietly returning the half it is allowed.
        assert_eq!(
            test::call_service(
                &app,
                ask(json!(["feeds/ips", "private/ips"]), Some("scoped"))
            )
            .await
            .status(),
            StatusCode::FORBIDDEN
        );
    }

    #[actix_web::test]
    async fn an_api_export_reports_namespaces_that_are_not_there() {
        let st = state(false);
        let app = app!(st);
        visit!(app, "/w/feeds/ips?val=1.2.3.4&tags=stix-type:ipv4-addr");

        // One real, one not: the real one still comes back.
        let resp = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/_api/stix")
                .set_json(json!({"namespaces": ["feeds/ips", "feeds/nope"]}))
                .to_request(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers().get("X-SightingDB-Exported").unwrap(), "1");
        assert_eq!(
            resp.headers().get("X-SightingDB-Missing").unwrap(),
            "feeds/nope"
        );

        // None of them real is a mistake worth reporting.
        let resp = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/_api/stix")
                .set_json(json!({"namespace": "feeds/nope"}))
                .to_request(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        // As is asking for nothing at all.
        let resp = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/_api/stix")
                .set_json(json!({"namespaces": []}))
                .to_request(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[actix_web::test]
    async fn an_api_export_can_filter_and_cap_what_it_reads() {
        let st = state(false);
        let app = app!(st);
        for value in ["10.0.0.1", "10.0.0.2", "192.0.2.1"] {
            visit!(
                app,
                &format!("/w/feeds/ips?val={value}&tags=stix-type:ipv4-addr")
            );
        }

        let resp = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/_api/stix")
                .set_json(json!({"namespace": "feeds/ips", "q": "10.0.0."}))
                .to_request(),
        )
        .await;
        assert_eq!(resp.headers().get("X-SightingDB-Exported").unwrap(), "2");

        let resp = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/_api/stix")
                .set_json(json!({"namespace": "feeds/ips", "limit": 1}))
                .to_request(),
        )
        .await;
        assert_eq!(resp.headers().get("X-SightingDB-Exported").unwrap(), "1");
        assert_eq!(
            resp.headers().get("X-SightingDB-Truncated").unwrap(),
            "true"
        );
    }

    #[actix_web::test]
    async fn an_api_export_refuses_the_config_namespace() {
        let st = state(false);
        let app = app!(st);

        let resp = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/_api/stix")
                .set_json(json!({"namespace": "_config/acl/apikeys"}))
                .to_request(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    // -- bulk --------------------------------------------------------------

    /// Regression: the hand-rolled JSON assembly chewed into its own header when
    /// there were no items, emitting a malformed document.
    #[actix_web::test]
    async fn an_empty_bulk_read_returns_an_empty_list() {
        let st = state(false);
        let app = app!(st);

        let resp = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/rb")
                .set_json(json!({"items": []}))
                .to_request(),
        )
        .await;

        assert_eq!(resp.status(), StatusCode::OK);
        let body: Value = test::read_body_json(resp).await;
        assert_eq!(body, json!({"items": []}));
    }

    #[actix_web::test]
    async fn bulk_read_reports_hits_and_misses_per_item() {
        let st = state(false);
        let app = app!(st);
        test::call_service(
            &app,
            test::TestRequest::get().uri("/w/ns?val=x").to_request(),
        )
        .await;

        let resp = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/rb")
                .set_json(json!({"items": [
                    {"namespace": "ns", "value": "x", "noshadow": true},
                    {"namespace": "ns", "value": "missing", "noshadow": true}
                ]}))
                .to_request(),
        )
        .await;

        let body: Value = test::read_body_json(resp).await;
        let items = body["items"].as_array().unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0]["count"], 1);
        assert_eq!(items[1]["error"], "Value not found");
    }

    #[actix_web::test]
    async fn bulk_sightings_do_not_require_a_noshadow_field() {
        let st = state(false);
        let app = app!(st);

        let resp = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/wb")
                .set_json(json!({"items": [{"namespace": "ns", "value": "x"}]}))
                .to_request(),
        )
        .await;

        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// Each item carries its own outcome, indexed back onto the request.
    #[actix_web::test]
    async fn a_bulk_write_reports_a_status_per_item() {
        let st = state(false);
        let app = app!(st);

        let resp = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/wb")
                .set_json(json!({"items": [
                    {"namespace": "ns", "value": "good"},
                    {"namespace": "ns", "value": ""},
                    {"namespace": "ns", "value": "good"}
                ]}))
                .to_request(),
        )
        .await;

        assert_eq!(resp.status(), StatusCode::OK);
        let body: Value = test::read_body_json(resp).await;
        let items = body["items"].as_array().unwrap();

        assert_eq!(items.len(), 3, "one entry per request item: {body}");

        // Index-aligned with the request, so a repeated value is still
        // traceable back to the entry that produced it.
        for (n, item) in items.iter().enumerate() {
            assert_eq!(item["index"], n, "{body}");
        }

        // A successful item reports the running count for that value, which is
        // what removes the need for a follow-up read.
        assert_eq!(items[0]["status"], "ok");
        assert_eq!(items[0]["count"], 1, "{body}");
        assert!(items[0]["error"].is_null(), "{body}");

        assert_eq!(items[1]["status"], "error");
        assert!(items[1]["error"].is_string(), "{body}");
        assert!(items[1]["count"].is_null(), "{body}");

        // Second sighting of the same value: the count moved on.
        assert_eq!(items[2]["status"], "ok");
        assert_eq!(items[2]["count"], 2, "{body}");

        assert_eq!(body["written"], 2);
        assert_eq!(body["message"], "partial");
    }

    /// An out-of-scope item fails on its own account: the items beside it were
    /// permitted, so they are recorded and the request is a partial success.
    #[actix_web::test]
    async fn a_refused_item_does_not_discard_the_rest_of_the_batch() {
        let mut inner = SharedState::new(true);
        inner
            .acl
            .get_mut()
            .unwrap()
            .set("feed", parse_grants("rw:feeds").unwrap());
        let st: State = web::Data::new(inner);
        let app = app!(st);

        let resp = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/wb")
                .insert_header(("Authorization", "feed"))
                .set_json(json!({"items": [
                    {"namespace": "secrets", "value": "nope"},
                    {"namespace": "feeds/a", "value": "yes"}
                ]}))
                .to_request(),
        )
        .await;

        // A refusal alongside a success is a partial write, not a 403: the
        // refusal is item 0's status, and `items` is where a client reads it.
        assert_eq!(resp.status(), StatusCode::OK);
        let body: Value = test::read_body_json(resp).await;
        let items = body["items"].as_array().unwrap();

        assert_eq!(items[0]["status"], "error", "{body}");
        assert!(items[0]["error"].is_string(), "{body}");
        assert_eq!(items[1]["status"], "ok", "{body}");
        assert_eq!(body["written"], 1, "{body}");
        assert_eq!(body["message"], "partial", "{body}");

        // The in-scope sighting landed even though it came after the refusal;
        // the out-of-scope one did not.
        assert_eq!(st.db.count("feeds/a", "yes"), 1);
        assert_eq!(st.db.count("secrets", "nope"), 0);
    }

    /// A batch where every item is refused keeps the old whole-request answer.
    #[actix_web::test]
    async fn a_wholly_refused_bulk_write_is_403_and_writes_nothing() {
        let mut inner = SharedState::new(true);
        inner
            .acl
            .get_mut()
            .unwrap()
            .set("feed", parse_grants("rw:feeds").unwrap());
        let st: State = web::Data::new(inner);
        let app = app!(st);

        let resp = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/wb")
                .insert_header(("Authorization", "feed"))
                .set_json(json!({"items": [{"namespace": "secrets", "value": "nope"}]}))
                .to_request(),
        )
        .await;

        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let body: Value = test::read_body_json(resp).await;
        assert_eq!(body["written"], 0, "{body}");
        assert_eq!(body["message"], "failed", "{body}");
        assert_eq!(st.db.count("secrets", "nope"), 0);
    }

    /// Nothing written, but not everything was refused: the failures did not
    /// share a cause, so the request is a bad one rather than a forbidden one.
    /// The refusal is still reported, as that item's status.
    #[actix_web::test]
    async fn an_all_failed_batch_with_mixed_causes_is_400_not_403() {
        let mut inner = SharedState::new(true);
        inner
            .acl
            .get_mut()
            .unwrap()
            .set("feed", parse_grants("rw:feeds").unwrap());
        let st: State = web::Data::new(inner);
        let app = app!(st);

        let resp = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/wb")
                .insert_header(("Authorization", "feed"))
                .set_json(json!({"items": [
                    {"namespace": "secrets", "value": "refused"},
                    {"namespace": "feeds/a", "value": ""}
                ]}))
                .to_request(),
        )
        .await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body: Value = test::read_body_json(resp).await;
        assert_eq!(body["written"], 0, "{body}");
        assert_eq!(body["message"], "failed", "{body}");
        assert_eq!(body["items"][0]["status"], "error", "{body}");
        assert_eq!(body["items"][1]["status"], "error", "{body}");
        assert_eq!(st.db.count("secrets", "refused"), 0);
    }

    /// The dry run must agree with the writer on every item and on the status,
    /// or it is worse than useless: it would give a client confidence that the
    /// write then fails to honour.
    ///
    /// Runs the same batches through both routes and compares the answers.
    #[actix_web::test]
    async fn vwb_answers_what_wb_would_answer() {
        let batches = [
            // Everything writable.
            json!({"items": [
                {"namespace": "feeds/a", "value": "1.2.3.4"},
                {"namespace": "feeds/b", "value": "evil.example", "ttl": 86400}
            ]}),
            // Some writable, some not.
            json!({"items": [
                {"namespace": "feeds/a", "value": "good"},
                {"namespace": "feeds/a", "value": ""},
                {"namespace": "secrets", "value": "refused"}
            ]}),
            // Nothing writable, every failure a refusal.
            json!({"items": [
                {"namespace": "secrets", "value": "a"},
                {"namespace": "other", "value": "b"}
            ]}),
            // Nothing writable, failures of mixed cause.
            json!({"items": [
                {"namespace": "secrets", "value": "refused"},
                {"namespace": "feeds/a", "value": ""}
            ]}),
            // A timestamp that is not an instant.
            json!({"items": [
                {"namespace": "feeds/a", "value": "x", "timestamp": i64::MAX}
            ]}),
            // The _config tree, which no key may write.
            json!({"items": [
                {"namespace": "_config/acl/apikeys/mine", "value": "x"}
            ]}),
        ];

        for batch in batches {
            // A fresh database each time, so the write half of the comparison
            // starts where the dry run did.
            let grants = || {
                let mut inner = SharedState::new(true);
                inner
                    .acl
                    .get_mut()
                    .unwrap()
                    .set("feed", parse_grants("rw:feeds").unwrap());
                web::Data::new(inner)
            };

            let dry_state: State = grants();
            let dry_app = app!(dry_state);
            let dry = test::call_service(
                &dry_app,
                test::TestRequest::post()
                    .uri("/vwb")
                    .insert_header(("Authorization", "feed"))
                    .set_json(batch.clone())
                    .to_request(),
            )
            .await;
            let dry_status = dry.status();
            let dry_body: Value = test::read_body_json(dry).await;

            let wet_state: State = grants();
            let wet_app = app!(wet_state);
            let wet = test::call_service(
                &wet_app,
                test::TestRequest::post()
                    .uri("/wb")
                    .insert_header(("Authorization", "feed"))
                    .set_json(batch.clone())
                    .to_request(),
            )
            .await;
            let wet_status = wet.status();
            let wet_body: Value = test::read_body_json(wet).await;

            assert_eq!(
                dry_status, wet_status,
                "status differs for {batch}: /vwb {dry_body}, /wb {wet_body}"
            );
            assert_eq!(
                dry_body["message"], wet_body["message"],
                "message differs for {batch}"
            );
            assert_eq!(
                dry_body["writable"], wet_body["written"],
                "count of accepted items differs for {batch}"
            );

            let dry_items = dry_body["items"].as_array().unwrap();
            let wet_items = wet_body["items"].as_array().unwrap();
            assert_eq!(dry_items.len(), wet_items.len(), "item count for {batch}");
            for (d, w) in dry_items.iter().zip(wet_items) {
                assert_eq!(d["index"], w["index"], "{batch}");
                assert_eq!(d["namespace"], w["namespace"], "{batch}");
                assert_eq!(d["value"], w["value"], "{batch}");
                assert_eq!(d["status"], w["status"], "status for {d} vs {w}");
                assert_eq!(d["error"], w["error"], "error for {d} vs {w}");
            }
        }
    }

    /// The whole point: it must not record anything, including under `_all`
    /// and `_shadow`, and including for the items it says are writable.
    #[actix_web::test]
    async fn vwb_records_nothing() {
        let st = state(false);
        let app = app!(st);

        let resp = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/vwb")
                .set_json(json!({"items": [
                    {"namespace": "ns", "value": "writable"},
                    {"namespace": "ns", "value": ""}
                ]}))
                .to_request(),
        )
        .await;

        assert_eq!(resp.status(), StatusCode::OK);
        let body: Value = test::read_body_json(resp).await;
        assert_eq!(body["message"], "partial", "{body}");
        assert_eq!(body["writable"], 1, "{body}");
        assert_eq!(body["items"][0]["status"], "ok", "{body}");
        assert_eq!(body["items"][1]["status"], "error", "{body}");

        // Nothing was counted, so no count is reported.
        assert!(body["items"][0]["count"].is_null(), "{body}");

        // And nothing reached the database, by any door.
        assert_eq!(st.db.count("ns", "writable"), 0);
        assert!(!st.db.namespace_exists("ns"), "the namespace was created");
        assert_eq!(st.db.count(crate::db::ALL_NAMESPACE, "writable"), 0);
        assert!(
            !st.db.namespace_exists("_shadow/ns"),
            "a shadow sighting was raised"
        );
    }

    /// A dry run still needs a key when authentication is on, and still says
    /// nothing about which keys exist.
    #[actix_web::test]
    async fn vwb_needs_a_key_and_reveals_nothing_extra() {
        let mut inner = SharedState::new(true);
        inner
            .acl
            .get_mut()
            .unwrap()
            .set("known", parse_grants("rw:feeds").unwrap());
        let st: State = web::Data::new(inner);
        let app = app!(st);

        let body = json!({"items": [{"namespace": "secrets", "value": "x"}]});

        let resp = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/vwb")
                .set_json(body.clone())
                .to_request(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let mut seen = Vec::new();
        for key in ["known", "no-such-key"] {
            let resp = test::call_service(
                &app,
                test::TestRequest::post()
                    .uri("/vwb")
                    .insert_header(("Authorization", key))
                    .set_json(body.clone())
                    .to_request(),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::FORBIDDEN);
            let got: Value = test::read_body_json(resp).await;
            seen.push(got["items"][0]["error"].as_str().unwrap().to_string());
        }
        assert_eq!(
            seen[0], seen[1],
            "the dry run told the keys apart: {seen:?}"
        );
    }

    /// A per-item refusal must read exactly like a whole-request one, or the
    /// bulk route becomes the way to tell a valid key from an invalid one.
    #[actix_web::test]
    async fn a_per_item_refusal_reveals_no_more_than_a_whole_request_one() {
        let mut inner = SharedState::new(true);
        inner
            .acl
            .get_mut()
            .unwrap()
            .set("known", parse_grants("rw:feeds").unwrap());
        let st: State = web::Data::new(inner);
        let app = app!(st);

        let mut seen = Vec::new();
        for key in ["known", "no-such-key"] {
            let resp = test::call_service(
                &app,
                test::TestRequest::post()
                    .uri("/wb")
                    .insert_header(("Authorization", key))
                    .set_json(json!({"items": [{"namespace": "secrets", "value": "x"}]}))
                    .to_request(),
            )
            .await;
            let body: Value = test::read_body_json(resp).await;
            seen.push(body["items"][0]["error"].as_str().unwrap().to_string());
        }

        assert_eq!(
            seen[0], seen[1],
            "a known key and an unknown one got different refusals: {seen:?}"
        );

        // And the same wording the single-value route uses.
        let resp = test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/w/secrets?val=x")
                .insert_header(("Authorization", "known"))
                .to_request(),
        )
        .await;
        let single: Value = test::read_body_json(resp).await;
        assert_eq!(single["message"], seen[0].as_str(), "{single}");
    }

    /// Regression: the old handler reported only the last item's outcome.
    #[actix_web::test]
    async fn bulk_write_reports_every_failure() {
        let st = state(false);
        let app = app!(st);

        let resp = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/wb")
                .set_json(json!({"items": [
                    {"namespace": "ns", "value": ""},
                    {"namespace": "ns", "value": "good"}
                ]}))
                .to_request(),
        )
        .await;

        assert_eq!(resp.status(), StatusCode::OK);
        let body: Value = test::read_body_json(resp).await;
        assert_eq!(body["message"], "partial");
        assert_eq!(body["written"], 1);
        assert_eq!(body["errors"].as_array().unwrap().len(), 1);
    }

    #[actix_web::test]
    async fn a_bulk_write_where_everything_fails_is_400() {
        let st = state(false);
        let app = app!(st);

        let resp = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/wb")
                .set_json(json!({"items": [{"namespace": "ns", "value": ""}]}))
                .to_request(),
        )
        .await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body: Value = test::read_body_json(resp).await;
        assert_eq!(body["message"], "failed");
    }

    #[actix_web::test]
    async fn a_malformed_json_body_gets_a_json_error() {
        let st = state(false);
        let app = app!(st);

        let resp = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/wb")
                .insert_header(("Content-Type", "application/json"))
                .set_payload("{not json")
                .to_request(),
        )
        .await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body: Value = test::read_body_json(resp).await;
        assert!(body["message"].is_string(), "{body}");
    }

    // -- ttl ---------------------------------------------------------------

    #[actix_web::test]
    async fn a_ttl_is_reported_back() {
        let st = state(false);
        let app = app!(st);

        test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/w/ns?val=x&ttl=3600")
                .to_request(),
        )
        .await;

        let resp = test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/r/ns?val=x&noshadow")
                .to_request(),
        )
        .await;
        let body: Value = test::read_body_json(resp).await;

        assert_eq!(body["ttl"], 3600);
    }

    #[actix_web::test]
    async fn an_expired_value_reads_as_not_found() {
        let st = state(false);
        let app = app!(st);

        // Sighted in 1970 with a one minute TTL, so it is long gone.
        test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/w/ns?val=x&timestamp=1000&ttl=60")
                .to_request(),
        )
        .await;

        let resp = test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/r/ns?val=x&noshadow")
                .to_request(),
        )
        .await;

        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[actix_web::test]
    async fn bulk_writes_accept_a_ttl() {
        let st = state(false);
        let app = app!(st);

        let resp = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/wb")
                .set_json(json!({"items": [
                    {"namespace": "ns", "value": "keep", "ttl": 3600},
                    {"namespace": "ns", "value": "gone", "ttl": 60, "timestamp": 1000}
                ]}))
                .to_request(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);

        assert_eq!(st.db.view("ns", "keep", 0, false).unwrap().ttl, 3600);
        assert!(st.db.view("ns", "gone", 0, false).is_none());
    }

    #[actix_web::test]
    async fn a_garbage_ttl_is_a_bad_request() {
        let st = state(false);
        let app = app!(st);

        let resp = test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/w/ns?val=x&ttl=forever")
                .to_request(),
        )
        .await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    // -- misc --------------------------------------------------------------

    #[actix_web::test]
    async fn info_reports_the_crate_version() {
        let st = state(false);
        let app = app!(st);

        let resp = test::call_service(&app, test::TestRequest::get().uri("/i").to_request()).await;
        let body: Value = test::read_body_json(resp).await;

        assert_eq!(body["version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(body["implementation"], "SightingDB");
    }

    #[actix_web::test]
    async fn deleting_an_unknown_namespace_is_404() {
        let st = state(false);
        let app = app!(st);

        let resp =
            test::call_service(&app, test::TestRequest::get().uri("/d/nope").to_request()).await;

        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[actix_web::test]
    async fn an_unknown_route_falls_back_to_help() {
        let st = state(false);
        let app = app!(st);

        let resp =
            test::call_service(&app, test::TestRequest::get().uri("/nonsense").to_request()).await;

        assert_eq!(resp.status(), StatusCode::OK);
        let body = test::read_body(resp).await;
        assert!(String::from_utf8_lossy(&body).contains("REST Endpoints"));
    }
}
