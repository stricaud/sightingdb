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
}

#[derive(Debug, Deserialize)]
pub struct WriteQuery {
    val: Option<String>,
    /// Unix seconds. Absent means "now".
    timestamp: Option<i64>,
    /// Seconds from the last sighting until the value expires. Absent leaves
    /// whatever TTL the attribute already had; 0 clears it.
    ttl: Option<u64>,
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
    #[serde(skip_serializing_if = "Vec::is_empty")]
    errors: Vec<BulkWriteError>,
}

#[derive(Debug, Serialize)]
struct BulkWriteError {
    namespace: String,
    value: String,
    error: String,
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
    if !state.authenticate {
        return Ok(());
    }

    let Some(header) = req.headers().get("Authorization") else {
        return Err(HttpResponse::Unauthorized().json(Message::new(
            "Please add the API key in the Authorization headers.",
        )));
    };

    // A non-UTF-8 header is a client error, not a reason to panic the worker.
    let Ok(apikey) = header.to_str() else {
        return Err(HttpResponse::BadRequest()
            .json(Message::new("Authorization header is not valid UTF-8.")));
    };

    let acl = state.acl();
    let (allowed, verb) = match access {
        Access::Read => (acl.can_read(apikey, namespace), "read"),
        Access::Write => (acl.can_write(apikey, namespace), "write"),
    };

    if allowed {
        Ok(())
    } else {
        // Deliberately the same answer whether the key is unknown or merely
        // unauthorised here, so that probing cannot distinguish the two.
        Err(HttpResponse::Forbidden().json(Message::new(format!(
            "API key is not permitted to {verb} this namespace."
        ))))
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
            "\t/r: read (GET)\n",
            "\t/rs: read with statistics (GET)\n",
            "\t/rb: read in bulk mode (POST)\n",
            "\t/rbs: read with statistics in bulk mode (POST)\n",
            "\t/d: delete (GET)\n",
            "\t/c: configure (GET)\n",
            "\t/i: info (GET)\n",
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
        Err(e) => return error_response(&e),
    };

    match sighting_writer::write(&state.db, &namespace, value, when, query.ttl) {
        Ok(count) => HttpResponse::Ok().json(WriteResponse {
            message: "ok",
            count,
        }),
        Err(e) => error_response(&e),
    }
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

pub async fn write_bulk(
    state: State,
    body: web::Json<BulkRequest>,
    req: HttpRequest,
) -> HttpResponse {
    let mut written = 0usize;
    let mut errors = Vec::new();

    for item in &body.items {
        if let Err(resp) = authorize(&state, &req, &item.namespace, Access::Write) {
            return resp;
        }

        let outcome = match item.timestamp.map(timestamp_to_instant).transpose() {
            Ok(when) => {
                sighting_writer::write(&state.db, &item.namespace, &item.value, when, item.ttl)
                    .map(|_| ())
            }
            Err(e) => Err(e),
        };

        match outcome {
            Ok(()) => written += 1,
            Err(e) => errors.push(BulkWriteError {
                namespace: item.namespace.clone(),
                value: item.value.clone(),
                error: e.to_string(),
            }),
        }
    }

    // Every item failing is a client error; a mix is reported as partial so the
    // caller can see exactly which items did not land.
    if errors.is_empty() {
        HttpResponse::Ok().json(BulkWriteResponse {
            message: "ok",
            written,
            errors,
        })
    } else if written == 0 {
        HttpResponse::BadRequest().json(BulkWriteResponse {
            message: "failed",
            written,
            errors,
        })
    } else {
        HttpResponse::Ok().json(BulkWriteResponse {
            message: "partial",
            written,
            errors,
        })
    }
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
        .route("/d/{namespace:.*}", web::get().to(delete))
        .route("/c/{namespace:.*}", web::get().to(configure_endpoint))
        .route("/i", web::get().to(info))
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

        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
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
