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
    /// What the STIX export needs: who we publish as, and which observable
    /// type each namespace is configured to hold.
    pub stix: crate::config::StixSettings,
    /// When the process came up, which is what `/health` reports.
    pub started: std::time::Instant,
    /// Values that were not written, from every path that writes. See
    /// [`crate::rejections`] for why this is bounded and in memory.
    pub rejections: crate::rejections::Rejections,
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
            stix: crate::config::StixSettings::default(),
            started: std::time::Instant::now(),
            rejections: crate::rejections::Rejections::default(),
        }
    }
}

impl SharedState {
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
    do_read(&state, &req, &path.into_inner(), &query, false)
}

pub async fn read_with_stats(
    state: State,
    path: web::Path<String>,
    query: web::Query<ReadQuery>,
    req: HttpRequest,
) -> HttpResponse {
    do_read(&state, &req, &path.into_inner(), &query, true)
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

    let Some(value) = query.val.as_deref() else {
        return HttpResponse::BadRequest().json(Message::new(
            "Did not receive a val= argument in the query string.",
        ));
    };

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
    match sighting_writer::write_tagged(&state.db, &namespace, value, when, query.ttl, tags) {
        Ok(count) => HttpResponse::Ok().json(WriteResponse {
            message: "ok",
            count,
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
fn stix_response(export: crate::stix::Export) -> HttpResponse {
    let mut response = HttpResponse::Ok();
    response
        .insert_header(("X-SightingDB-Exported", export.exported.to_string()))
        .insert_header(("X-SightingDB-Skipped", export.skipped.len().to_string()))
        .insert_header(("X-SightingDB-Untyped", export.untyped.to_string()))
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

    if namespace.starts_with(CONFIG_PREFIX) {
        return error_response(&ApiError::ConfigNamespace);
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
    do_read_bulk(&state, &req, &body, false)
}

pub async fn read_bulk_with_stats(
    state: State,
    body: web::Json<BulkRequest>,
    req: HttpRequest,
) -> HttpResponse {
    do_read_bulk(&state, &req, &body, true)
}

fn do_read_bulk(
    state: &State,
    req: &HttpRequest,
    body: &BulkRequest,
    with_stats: bool,
) -> HttpResponse {
    let mut items = Vec::with_capacity(body.items.len());

    for item in &body.items {
        if let Err(resp) = authorize(state, req, &item.namespace, Access::Read) {
            return resp;
        }

        let result = sighting_reader::read(
            &state.db,
            &item.namespace,
            &item.value,
            with_stats,
            !item.noshadow,
        );

        items.push(match result {
            Ok(view) => BulkReadItem::Found(Box::new(view)),
            Err(e) => BulkReadItem::Error(e.body()),
        });
    }

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

    if let Err(e) = sighting_writer::check(&item.namespace, &item.value) {
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

    let mut items = Vec::with_capacity(body.items.len());
    let mut errors = Vec::new();
    let mut written = 0usize;
    let mut refusals = 0usize;

    for (index, item) in body.items.iter().enumerate() {
        let outcome = match check_item(&state, &req, apikey, item) {
            // The check has already ruled out everything `write_tagged` can
            // refuse, so this cannot fail; if it ever does, the error is
            // reported rather than swallowed.
            ItemCheck::Ok(when) => sighting_writer::write_tagged(
                &state.db,
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
            Ok(count) => {
                written += 1;
                items.push(BulkWriteItem {
                    index,
                    namespace: item.namespace.clone(),
                    value: item.value.clone(),
                    status: "ok",
                    count: Some(count),
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
                    // No sighting was recorded, so there is no count to give.
                    count: None,
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

        assert!(spec.starts_with("openapi:"), "not an OpenAPI document");
        for path in [
            "  /w/{namespace}:",
            "  /r/{namespace}:",
            "  /rs/{namespace}:",
            "  /d/{namespace}:",
            "  /wb:",
            "  /vwb:",
            "  /rb:",
            "  /rbs:",
            "  /stix/{namespace}:",
            "  /_api/stix:",
            "  /_api/tier:",
            "  /_api/openapi.yaml:",
            "  /c/{namespace}:",
            "  /i:",
            "  /health:",
            "  /_management/api/session:",
            "  /_management/api/info:",
            "  /_management/api/namespaces:",
            "  /_management/api/tree:",
            "  /_management/api/rejections:",
            "  /_management/api/values:",
            "  /_management/api/value:",
            "  /_management/api/sightings:",
            "  /_management/api/tags:",
            "  /_management/api/tier:",
            "  /_management/api/keys:",
            "  /_management/api/keys/generate:",
            "  /_management/api/keys/{key}:",
        ] {
            assert!(spec.contains(path), "{path} is not in the OpenAPI document");
        }

        // Whatever the file says, the server says what it is.
        let info = spec.find("\ninfo:").expect("an info section");
        let version = spec[info..]
            .lines()
            .find(|line| line.starts_with("  version:"))
            .expect("a version");
        assert_eq!(
            version.trim(),
            format!("version: \"{}\"", env!("CARGO_PKG_VERSION")),
            "the served document names the wrong version"
        );
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
