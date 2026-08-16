//! The admin interface served at `/_management/`.
//!
//! This is a read-only browser over the database plus a view of what the
//! server is configured to do.
//!
//! It is deliberately *not* served under `_config`, even though there would be
//! no routing conflict: `_config` already names the database namespace holding
//! API keys, and the data paths refuse it outright. Serving an interface under
//! the same word would leave `/_config/` and `/r/_config/` looking alike while
//! doing opposite things.
//!
//! Access requires a key holding the `admin` grant, *regardless* of the
//! `authenticate` setting. Turning authentication off is a decision about the
//! sighting API — it should not hand the admin interface to anyone who can
//! reach the port.

use std::path::PathBuf;

use actix_web::{HttpRequest, HttpResponse, Responder, web};
use serde::{Deserialize, Serialize};

use crate::acl::{Grant, validate_key, validate_namespace};

use crate::error::Message;
use crate::handlers::{SharedState, State};

/// The single-page interface, compiled in so there is nothing to deploy.
const UI: &str = include_str!("ui.html");
/// Vendored so the interface works without internet access. See assets/README.md.
const ECHARTS: &str = include_str!("../../assets/echarts.min.js");

/// Paging is capped so one request cannot ask the server to sort and serialize
/// an entire large namespace.
const MAX_LIMIT: usize = 500;
const DEFAULT_LIMIT: usize = 50;

#[derive(Debug, Deserialize)]
pub struct BrowseQuery {
    /// Substring filter, case-insensitive.
    #[serde(default)]
    q: String,
    #[serde(default)]
    offset: usize,
    limit: Option<usize>,
}

impl BrowseQuery {
    fn limit(&self) -> usize {
        self.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT)
    }
}

#[derive(Debug, Deserialize)]
pub struct ValuesQuery {
    namespace: String,
    #[serde(default)]
    q: String,
    #[serde(default)]
    offset: usize,
    limit: Option<usize>,
}

impl ValuesQuery {
    fn limit(&self) -> usize {
        self.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT)
    }
}

#[derive(Debug, Deserialize)]
pub struct ValueQuery {
    namespace: String,
    value: String,
}

/// What the server is doing, for the configuration view.
///
/// Configuration is read from a file at startup, so this reports rather than
/// edits: changing it means editing the file and restarting.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ServerInfo {
    pub version: &'static str,
    pub authenticate: bool,
    pub http_enabled: bool,
    pub config_path: String,
    pub dbdir: Option<String>,
    pub snapshot_interval: u64,
    pub sweep_interval: u64,
    pub stats_retention: usize,
    pub shadow_ttl: u64,
    pub dns: Option<DnsInfo>,
    pub zmq: Option<ZmqInfo>,
    pub namespaces: usize,
    pub apikeys: usize,
    pub default_tier: String,
    pub warm_idle: u64,
    /// Shards with a tier of their own.
    pub tiers: Vec<(String, String)>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DnsInfo {
    pub listen: String,
    pub zone: String,
    pub ttl: u32,
    pub rate_limit: u32,
    pub shadow: bool,
    pub exposed: Vec<ExposedInfo>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExposedInfo {
    pub label: String,
    pub namespace: String,
    pub encoding: String,
}

/// One key as the interface sees it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeyEntry {
    pub key: String,
    pub admin: bool,
    /// Namespace prefixes this key may read. An empty string means all.
    pub read: Vec<String>,
    pub write: Vec<String>,
}

impl KeyEntry {
    fn from_grants(key: &str, grants: &[Grant]) -> Self {
        let mut entry = KeyEntry {
            key: key.to_string(),
            admin: false,
            read: Vec::new(),
            write: Vec::new(),
        };
        for grant in grants {
            if grant.admin {
                entry.admin = true;
            }
            if grant.read {
                entry.read.push(grant.prefix.clone());
            }
            if grant.write {
                entry.write.push(grant.prefix.clone());
            }
        }
        entry
    }

    /// Back to grants, collapsing a prefix granted for both into one `rw`.
    fn to_grants(&self) -> Vec<Grant> {
        let mut grants = Vec::new();
        for prefix in &self.read {
            grants.push(Grant {
                prefix: prefix.clone(),
                read: true,
                write: self.write.contains(prefix),
                admin: false,
            });
        }
        for prefix in &self.write {
            if !self.read.contains(prefix) {
                grants.push(Grant {
                    prefix: prefix.clone(),
                    read: false,
                    write: true,
                    admin: false,
                });
            }
        }
        if self.admin {
            grants.push(Grant::admin());
        }
        grants
    }

    fn validate(&self) -> anyhow::Result<()> {
        validate_key(&self.key)?;
        for prefix in self.read.iter().chain(self.write.iter()) {
            validate_namespace(prefix)?;
        }
        if !self.admin && self.read.is_empty() && self.write.is_empty() {
            anyhow::bail!("a key with no grants at all cannot do anything");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ZmqInfo {
    pub endpoint: String,
    pub topics: Vec<String>,
    pub format: String,
    pub require_to_ids: bool,
    pub mapped_types: usize,
}

/// Check the caller holds an admin grant, handing back the key so the caller
/// can go on to check its rights over a particular namespace.
fn require_admin<'a>(state: &SharedState, req: &'a HttpRequest) -> Result<&'a str, HttpResponse> {
    let Some(header) = req.headers().get("Authorization") else {
        return Err(
            HttpResponse::Unauthorized().json(Message::new("An admin API key is required."))
        );
    };
    let Ok(key) = header.to_str() else {
        return Err(HttpResponse::BadRequest()
            .json(Message::new("Authorization header is not valid UTF-8.")));
    };
    if state.acl().is_admin(key) {
        Ok(key)
    } else {
        Err(HttpResponse::Forbidden().json(Message::new("That key is not an admin key.")))
    }
}

/// Reaching the interface is not the same as being allowed to read the data in
/// it: an `admin, r:feeds` key browses `feeds/*` and nothing else.
fn require_read(state: &SharedState, key: &str, namespace: &str) -> Result<(), HttpResponse> {
    if state.acl().can_read(key, namespace) {
        Ok(())
    } else {
        // Same answer as a namespace that does not exist, so browsing cannot
        // be used to enumerate what is out of reach.
        Err(HttpResponse::NotFound().json(Message::new("No such namespace.")))
    }
}

pub async fn index() -> impl Responder {
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(UI)
}

pub async fn echarts() -> impl Responder {
    HttpResponse::Ok()
        .content_type("application/javascript; charset=utf-8")
        // Immutable: it only changes when the binary does.
        .insert_header(("Cache-Control", "public, max-age=86400"))
        .body(ECHARTS)
}

/// Confirms a key is an admin key, so the interface can show its login result.
pub async fn session(state: State, req: HttpRequest) -> HttpResponse {
    if let Err(resp) = require_admin(&state, &req) {
        return resp;
    }
    HttpResponse::Ok().json(Message::new("ok"))
}

pub async fn info(state: State, req: HttpRequest) -> HttpResponse {
    if let Err(resp) = require_admin(&state, &req) {
        return resp;
    }
    HttpResponse::Ok().json(state.info.clone())
}

pub async fn namespaces(
    state: State,
    query: web::Query<BrowseQuery>,
    req: HttpRequest,
) -> HttpResponse {
    let key = match require_admin(&state, &req) {
        Ok(key) => key.to_string(),
        Err(resp) => return resp,
    };

    let acl = state.acl();
    let page = state
        .db
        .namespace_page(&query.q, query.offset, query.limit(), |name| {
            acl.can_read(&key, name)
        });
    drop(acl);
    HttpResponse::Ok().json(page)
}

pub async fn values(
    state: State,
    query: web::Query<ValuesQuery>,
    req: HttpRequest,
) -> HttpResponse {
    let key = match require_admin(&state, &req) {
        Ok(key) => key,
        Err(resp) => return resp,
    };
    if let Err(resp) = require_read(&state, key, &query.namespace) {
        return resp;
    }

    // Statistics are per value and can be large, so the list omits them; the
    // detail view fetches them for one value at a time.
    match state.db.value_page(
        &query.namespace,
        &query.q,
        query.offset,
        query.limit(),
        false,
    ) {
        Some(page) => HttpResponse::Ok().json(page),
        None => HttpResponse::NotFound().json(Message::new("No such namespace.")),
    }
}

/// One value with its hourly statistics, which is what the histogram draws.
pub async fn value(state: State, query: web::Query<ValueQuery>, req: HttpRequest) -> HttpResponse {
    let key = match require_admin(&state, &req) {
        Ok(key) => key,
        Err(resp) => return resp,
    };
    if let Err(resp) = require_read(&state, key, &query.namespace) {
        return resp;
    }

    let consensus = state.db.count(crate::db::ALL_NAMESPACE, &query.value);
    match state
        .db
        .view(&query.namespace, &query.value, consensus, true)
    {
        Some(view) => HttpResponse::Ok().json(view),
        None => HttpResponse::NotFound().json(Message::new("No such value.")),
    }
}

// ---------------------------------------------------------------------------
// Key management
// ---------------------------------------------------------------------------

/// Where the ACL is written. Without one configured, keys are read-only:
/// rewriting the daemon configuration in place is not something this does.
fn acl_file(state: &SharedState) -> Result<&PathBuf, HttpResponse> {
    state.acl_file.as_ref().ok_or_else(|| {
        HttpResponse::Conflict().json(Message::new(
            "No acl_file is configured, so keys cannot be edited here. Set acl_file in \
             [daemon] and restart.",
        ))
    })
}

/// Persist the ACL, then adopt it. Written to a temporary file and renamed, so
/// a crash mid-write cannot leave a truncated file that locks everyone out.
fn save_acl(state: &SharedState, acl: crate::acl::Acl) -> Result<(), HttpResponse> {
    let path = acl_file(state)?;

    let write = || -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let temp = path.with_extension("tmp");
        std::fs::write(&temp, acl.to_toml())?;
        std::fs::rename(&temp, path)
    };

    if let Err(e) = write() {
        log::error!("Could not write {}: {e}", path.display());
        return Err(HttpResponse::InternalServerError()
            .json(Message::new(format!("Could not write the ACL file: {e}"))));
    }

    *state
        .acl
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = acl;
    Ok(())
}

pub async fn list_keys(state: State, req: HttpRequest) -> HttpResponse {
    if let Err(resp) = require_admin(&state, &req) {
        return resp;
    }
    let entries: Vec<KeyEntry> = state
        .acl()
        .entries()
        .iter()
        .map(|(key, grants)| KeyEntry::from_grants(key, grants))
        .collect();
    HttpResponse::Ok().json(entries)
}

/// Create or replace one key.
pub async fn save_key(state: State, body: web::Json<KeyEntry>, req: HttpRequest) -> HttpResponse {
    let caller = match require_admin(&state, &req) {
        Ok(key) => key.to_string(),
        Err(resp) => return resp,
    };

    let entry = body.into_inner();
    if let Err(e) = entry.validate() {
        return HttpResponse::BadRequest().json(Message::new(e.to_string()));
    }

    let mut acl = state.acl().clone();
    let was_admin = acl.is_admin(&entry.key);
    acl.set(&entry.key, entry.to_grants());

    // Removing the admin grant from the last admin would lock everyone out of
    // the interface with no way back in short of editing the file by hand.
    if was_admin && !entry.admin && acl.admin_count() == 0 {
        return HttpResponse::Conflict().json(Message::new(
            "That would leave no admin key. Grant admin to another key first.",
        ));
    }

    if let Err(resp) = save_acl(&state, acl) {
        return resp;
    }
    log::info!("Key '{}' saved by '{caller}'", entry.key);
    HttpResponse::Ok().json(entry)
}

pub async fn delete_key(state: State, path: web::Path<String>, req: HttpRequest) -> HttpResponse {
    let caller = match require_admin(&state, &req) {
        Ok(key) => key.to_string(),
        Err(resp) => return resp,
    };
    let key = path.into_inner();

    let mut acl = state.acl().clone();
    if !acl.contains(&key) {
        return HttpResponse::NotFound().json(Message::new("No such key."));
    }
    acl.remove(&key);

    if acl.admin_count() == 0 {
        return HttpResponse::Conflict().json(Message::new(
            "That would revoke the last admin key. Grant admin to another key first.",
        ));
    }

    if let Err(resp) = save_acl(&state, acl) {
        return resp;
    }
    log::warn!("Key '{key}' revoked by '{caller}'");
    HttpResponse::Ok().json(Message::new("ok"))
}

/// Suggest a strong key, so nobody has to invent one.
pub async fn generate_key(state: State, req: HttpRequest) -> HttpResponse {
    if let Err(resp) = require_admin(&state, &req) {
        return resp;
    }
    HttpResponse::Ok().json(serde_json::json!({ "key": random_key() }))
}

fn random_key() -> String {
    use rand::RngExt;
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut rng = rand::rng();
    (0..40)
        .map(|_| ALPHABET[rng.random_range(0..ALPHABET.len())] as char)
        .collect()
}

/// Register the admin routes.
pub fn routes(cfg: &mut web::ServiceConfig) {
    // Order matters: the catch-all must come last or it would swallow the API.
    cfg.route("/_management/echarts.min.js", web::get().to(echarts))
        .route("/_management/api/session", web::get().to(session))
        .route("/_management/api/info", web::get().to(info))
        .route("/_management/api/namespaces", web::get().to(namespaces))
        .route("/_management/api/values", web::get().to(values))
        .route("/_management/api/value", web::get().to(value))
        .route("/_management/api/keys", web::get().to(list_keys))
        .route("/_management/api/keys", web::post().to(save_key))
        .route(
            "/_management/api/keys/generate",
            web::get().to(generate_key),
        )
        .route("/_management/api/keys/{key}", web::delete().to(delete_key))
        .route("/_management", web::get().to(index))
        .route("/_management/{namespace:.*}", web::get().to(index));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acl::parse_grants;
    use crate::db::WriteOpts;
    use actix_web::http::StatusCode;
    use actix_web::{App, test};
    use chrono::Utc;
    use serde_json::{Value as Json, json};

    const ADMIN: &str = "changeme";
    /// Spelled out so `None` has a type at the call sites.
    const NO_KEY: Option<&str> = None;

    fn state() -> State {
        let mut inner = SharedState::new(false);
        inner.acl.get_mut().unwrap().grant_full(ADMIN);
        inner
            .acl
            .get_mut()
            .unwrap()
            .set("plain", parse_grants("rw").unwrap());

        for value in ["1.2.3.4", "5.6.7.8", "9.9.9.9"] {
            inner.db.write(
                "feeds/ips",
                value,
                Utc::now(),
                WriteOpts {
                    consensus: true,
                    ttl: None,
                },
            );
        }
        web::Data::new(inner)
    }

    macro_rules! app {
        ($state:expr) => {
            test::init_service(App::new().app_data($state.clone()).configure(routes)).await
        };
    }

    /// A GET with an optional key; a macro rather than a function so the
    /// service type does not have to be named.
    macro_rules! get {
        ($app:expr, $uri:expr, $key:expr $(,)?) => {{
            let mut req = test::TestRequest::get().uri($uri);
            if let Some(key) = $key {
                req = req.insert_header(("Authorization", key));
            }
            test::call_service(&$app, req.to_request()).await
        }};
    }

    #[actix_web::test]
    async fn the_interface_is_served_without_a_key() {
        let st = state();
        let app = app!(st);

        // The page itself is just markup; everything it shows needs the key.
        let resp = get!(app, "/_management/", NO_KEY);
        assert_eq!(resp.status(), StatusCode::OK);
        let body = test::read_body(resp).await;
        assert!(String::from_utf8_lossy(&body).contains("<title>"));
    }

    #[actix_web::test]
    async fn the_data_endpoints_need_an_admin_key() {
        let st = state();
        let app = app!(st);

        for uri in [
            "/_management/api/info",
            "/_management/api/namespaces",
            "/_management/api/values?namespace=feeds/ips",
            "/_management/api/value?namespace=feeds/ips&value=1.2.3.4",
            "/_management/api/session",
        ] {
            assert_eq!(
                get!(app, uri, NO_KEY).status(),
                StatusCode::UNAUTHORIZED,
                "{uri}"
            );
            // A valid key that is not an admin key is not enough either.
            assert_eq!(
                get!(app, uri, Some("plain")).status(),
                StatusCode::FORBIDDEN,
                "{uri}"
            );
            assert_eq!(
                get!(app, uri, Some(ADMIN)).status(),
                StatusCode::OK,
                "{uri}"
            );
        }
    }

    #[actix_web::test]
    async fn namespaces_are_paged_and_filtered() {
        let st = state();
        let app = app!(st);

        let resp = get!(app, "/_management/api/namespaces?limit=1", Some(ADMIN));
        let body: Json = test::read_body_json(resp).await;
        assert_eq!(body["items"].as_array().unwrap().len(), 1);
        assert_eq!(body["total"], 1);

        let resp = get!(app, "/_management/api/namespaces?q=nomatch", Some(ADMIN));
        let body: Json = test::read_body_json(resp).await;
        assert_eq!(body["total"], 0);
    }

    #[actix_web::test]
    async fn values_are_paged_and_omit_statistics() {
        let st = state();
        let app = app!(st);

        let resp = get!(
            app,
            "/_management/api/values?namespace=feeds/ips&offset=1&limit=1",
            Some(ADMIN),
        );
        let body: Json = test::read_body_json(resp).await;

        assert_eq!(body["total"], 3);
        assert_eq!(body["offset"], 1);
        let items = body["items"].as_array().unwrap();
        assert_eq!(items.len(), 1);
        // The list would be enormous with per-value histograms in it.
        assert!(items[0].get("stats").is_none(), "{items:?}");
    }

    #[actix_web::test]
    async fn a_single_value_carries_its_histogram() {
        let st = state();
        let app = app!(st);

        let resp = get!(
            app,
            "/_management/api/value?namespace=feeds/ips&value=1.2.3.4",
            Some(ADMIN),
        );
        let body: Json = test::read_body_json(resp).await;

        assert_eq!(body["value"], "1.2.3.4");
        assert!(body["stats"].is_object(), "{body}");
    }

    #[actix_web::test]
    async fn missing_things_are_404_not_500() {
        let st = state();
        let app = app!(st);

        assert_eq!(
            get!(app, "/_management/api/values?namespace=nope", Some(ADMIN)).status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            get!(
                app,
                "/_management/api/value?namespace=feeds/ips&value=nope",
                Some(ADMIN)
            )
            .status(),
            StatusCode::NOT_FOUND
        );
    }

    #[actix_web::test]
    async fn the_page_size_is_capped() {
        let st = state();
        let app = app!(st);

        let resp = get!(
            app,
            "/_management/api/values?namespace=feeds/ips&limit=100000",
            Some(ADMIN),
        );
        assert_eq!(resp.status(), StatusCode::OK);
        // Capped rather than refused, so a careless caller still gets an answer.
        let body: Json = test::read_body_json(resp).await;
        assert_eq!(body["items"].as_array().unwrap().len(), 3);
    }

    // -- key management ----------------------------------------------------

    /// State with a real acl_file, so saves actually hit the disk.
    fn writable_state(dir: &std::path::Path) -> State {
        let mut inner = SharedState::new(true);
        inner.acl.get_mut().unwrap().grant_full(ADMIN);
        inner.acl_file = Some(dir.join("acl.toml"));
        web::Data::new(inner)
    }

    struct TempDir(std::path::PathBuf);
    impl TempDir {
        fn new(tag: &str) -> Self {
            let path = std::env::temp_dir().join(format!("sightingdb-keys-{tag}"));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).unwrap();
            TempDir(path)
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    macro_rules! post_key {
        ($app:expr, $body:expr, $key:expr) => {
            test::call_service(
                &$app,
                test::TestRequest::post()
                    .uri("/_management/api/keys")
                    .insert_header(("Authorization", $key))
                    .set_json($body)
                    .to_request(),
            )
            .await
        };
    }

    #[actix_web::test]
    async fn a_saved_key_lands_on_disk_and_takes_effect_at_once() {
        let dir = TempDir::new("save");
        let st = writable_state(&dir.0);
        let app = app!(st);

        let resp = post_key!(
            app,
            json!({"key": "analyst", "admin": false, "read": ["feeds"], "write": []}),
            ADMIN
        );
        assert_eq!(resp.status(), StatusCode::OK);

        // In the running ACL, with no restart.
        assert!(st.acl().can_read("analyst", "feeds/misp"));
        assert!(!st.acl().can_write("analyst", "feeds/misp"));
        assert!(!st.acl().can_read("analyst", "secrets"));

        // And on disk, in a form that reads back.
        let written = std::fs::read_to_string(dir.0.join("acl.toml")).unwrap();
        assert!(written.contains("\"analyst\" = \"r:feeds\""), "{written}");
        assert!(written.contains("\"changeme\""), "{written}");
    }

    #[actix_web::test]
    async fn read_and_write_on_one_prefix_collapse_to_rw() {
        let dir = TempDir::new("rw");
        let st = writable_state(&dir.0);
        let app = app!(st);

        post_key!(
            app,
            json!({"key": "feed", "admin": false, "read": ["feeds"], "write": ["feeds"]}),
            ADMIN
        );

        let written = std::fs::read_to_string(dir.0.join("acl.toml")).unwrap();
        assert!(written.contains("\"feed\" = \"rw:feeds\""), "{written}");
    }

    #[actix_web::test]
    async fn a_key_can_be_revoked() {
        let dir = TempDir::new("revoke");
        let st = writable_state(&dir.0);
        let app = app!(st);
        post_key!(
            app,
            json!({"key": "temp", "admin": false, "read": [""], "write": []}),
            ADMIN
        );
        assert!(st.acl().contains("temp"));

        let resp = test::call_service(
            &app,
            test::TestRequest::delete()
                .uri("/_management/api/keys/temp")
                .insert_header(("Authorization", ADMIN))
                .to_request(),
        )
        .await;

        assert_eq!(resp.status(), StatusCode::OK);
        assert!(!st.acl().contains("temp"));
        assert!(
            !std::fs::read_to_string(dir.0.join("acl.toml"))
                .unwrap()
                .contains("temp")
        );
    }

    /// Locking every admin out would leave no way back in short of editing the
    /// file by hand, so both routes to it are refused.
    #[actix_web::test]
    async fn the_last_admin_cannot_be_removed() {
        let dir = TempDir::new("lastadmin");
        let st = writable_state(&dir.0);
        let app = app!(st);

        let demote = post_key!(
            app,
            json!({"key": ADMIN, "admin": false, "read": [""], "write": [""]}),
            ADMIN
        );
        assert_eq!(demote.status(), StatusCode::CONFLICT);

        let revoke = test::call_service(
            &app,
            test::TestRequest::delete()
                .uri(&format!("/_management/api/keys/{ADMIN}"))
                .insert_header(("Authorization", ADMIN))
                .to_request(),
        )
        .await;
        assert_eq!(revoke.status(), StatusCode::CONFLICT);

        // Still an admin, on disk and in memory.
        assert!(st.acl().is_admin(ADMIN));
    }

    #[actix_web::test]
    async fn demoting_an_admin_is_fine_once_another_exists() {
        let dir = TempDir::new("secondadmin");
        let st = writable_state(&dir.0);
        let app = app!(st);

        post_key!(
            app,
            json!({"key": "other", "admin": true, "read": [""], "write": [""]}),
            ADMIN
        );
        let resp = post_key!(
            app,
            json!({"key": ADMIN, "admin": false, "read": [""], "write": [""]}),
            ADMIN
        );

        assert_eq!(resp.status(), StatusCode::OK);
        assert!(!st.acl().is_admin(ADMIN));
        assert!(st.acl().is_admin("other"));
    }

    /// A key carrying `"` or a newline could rewrite the file as something
    /// else, so it never reaches the disk.
    #[actix_web::test]
    async fn keys_that_would_corrupt_the_file_are_refused() {
        let dir = TempDir::new("badkey");
        let st = writable_state(&dir.0);
        let app = app!(st);

        for bad in ["", "has space", "has\"quote", "has\nnewline", "has=equals"] {
            let resp = post_key!(
                app,
                json!({"key": bad, "admin": false, "read": [""], "write": []}),
                ADMIN
            );
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{bad:?}");
        }
    }

    #[actix_web::test]
    async fn granting_an_internal_namespace_is_refused() {
        let dir = TempDir::new("internal");
        let st = writable_state(&dir.0);
        let app = app!(st);

        let resp = post_key!(
            app,
            json!({"key": "sneaky", "admin": false, "read": ["_config/acl"], "write": []}),
            ADMIN
        );
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(!st.acl().contains("sneaky"));
    }

    #[actix_web::test]
    async fn a_key_with_no_grants_is_refused() {
        let dir = TempDir::new("nogrants");
        let st = writable_state(&dir.0);
        let app = app!(st);

        let resp = post_key!(
            app,
            json!({"key": "useless", "admin": false, "read": [], "write": []}),
            ADMIN
        );
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    /// Without an acl_file there is nowhere to write, and rewriting the daemon
    /// configuration in place is not something this does.
    #[actix_web::test]
    async fn editing_without_an_acl_file_says_so() {
        let st = state(); // no acl_file
        let app = app!(st);

        let resp = post_key!(
            app,
            json!({"key": "x", "admin": false, "read": [""], "write": []}),
            ADMIN
        );
        assert_eq!(resp.status(), StatusCode::CONFLICT);
        let body: Json = test::read_body_json(resp).await;
        assert!(
            body["message"].as_str().unwrap().contains("acl_file"),
            "{body}"
        );
    }

    #[actix_web::test]
    async fn keys_are_listed_and_generated() {
        let dir = TempDir::new("list");
        let st = writable_state(&dir.0);
        let app = app!(st);

        let listed: Json =
            test::read_body_json(get!(app, "/_management/api/keys", Some(ADMIN))).await;
        let entries = listed.as_array().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["key"], ADMIN);
        assert_eq!(entries[0]["admin"], true);

        let generated: Json =
            test::read_body_json(get!(app, "/_management/api/keys/generate", Some(ADMIN))).await;
        let suggestion = generated["key"].as_str().unwrap();
        assert_eq!(suggestion.len(), 40);
        assert!(crate::acl::validate_key(suggestion).is_ok());
    }

    #[actix_web::test]
    async fn key_management_needs_an_admin_key() {
        let dir = TempDir::new("keyauth");
        let st = writable_state(&dir.0);
        let app = app!(st);

        assert_eq!(
            get!(app, "/_management/api/keys", NO_KEY).status(),
            StatusCode::UNAUTHORIZED
        );
        let resp = post_key!(
            app,
            json!({"key": "x", "admin": true, "read": [""], "write": [""]}),
            "not-a-key"
        );
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[actix_web::test]
    async fn echarts_is_served_from_the_binary() {
        let st = state();
        let app = app!(st);

        let resp = get!(app, "/_management/echarts.min.js", NO_KEY);
        assert_eq!(resp.status(), StatusCode::OK);
        let body = test::read_body(resp).await;
        assert!(body.len() > 100_000, "expected the real library");
    }
}
