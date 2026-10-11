//! The admin interface served at `/_management/`.
//!
//! This is a browser over the database — namespaces as folders, the values
//! inside them, and what each value has been seen doing — plus a view of what
//! the server is configured to do. Namespaces can be created and values added
//! from it; the configuration itself is read-only, since it comes from a file
//! read at startup.
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
/// The logo, compiled in for the same reason: an interface that fetches its own
/// branding from somewhere else does not work on an air-gapped host. 64px, for
/// a header that shows it at about a third of that.
const LOGO: &[u8] = include_bytes!("../../doc/sightingdb-logo3_64.png");

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

/// Which rejections to list.
#[derive(Debug, Deserialize)]
pub struct RejectionsQuery {
    /// Only rejections under this namespace, matched as a subtree the way an
    /// ACL grant is. Absent lists every namespace the key may read.
    namespace: Option<String>,
    limit: Option<usize>,
}

impl RejectionsQuery {
    fn limit(&self) -> usize {
        self.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT)
    }
}

/// A page of rejections, and how many are held in total.
#[derive(Debug, Serialize)]
pub struct RejectionPage {
    rejections: Vec<crate::rejections::Rejection>,
    /// Everything currently kept, not just this page, so the interface can say
    /// "showing 50 of 1000".
    total: usize,
    /// The cap. Once `total` reaches it, the oldest rejections are being lost.
    capacity: usize,
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

/// One level of the namespace tree, as the browser walks it.
#[derive(Debug, Deserialize)]
pub struct TreeQuery {
    /// The folder being opened. Empty is the root.
    #[serde(default)]
    path: String,
    /// Substring filter over the child names at this level, case-insensitive.
    #[serde(default)]
    q: String,
    #[serde(default)]
    offset: usize,
    limit: Option<usize>,
}

impl TreeQuery {
    fn limit(&self) -> usize {
        self.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT)
    }
}

/// A namespace to create, which may name a whole path at once.
#[derive(Debug, Deserialize)]
pub struct NewNamespace {
    namespace: String,
}

/// Values to record, one namespace at a time.
///
/// A single value and a bulk paste are the same request with a list of one:
/// the interface has one code path, and so does this.
#[derive(Debug, Deserialize)]
pub struct NewValues {
    namespace: String,
    values: Vec<String>,
    /// Unix seconds. Absent means "now", as on the write API.
    #[serde(default)]
    timestamp: Option<i64>,
    /// Absent leaves whatever TTL an existing value had; 0 clears it.
    #[serde(default)]
    ttl: Option<u64>,
    /// Comma-separated tags applied to every value in this request, merged
    /// with whatever each already carried.
    #[serde(default)]
    tags: String,
}

/// What a create or an add did, per value, so a paste of a thousand lines can
/// report the eight that were rejected without losing the rest.
#[derive(Debug, Serialize)]
pub struct WriteReport {
    namespace: String,
    written: usize,
    /// Each value that was recorded, with its running total afterwards.
    ///
    /// The count comes back from the write itself, taken under the lock that
    /// incremented it, so reporting it costs nothing and saves the interface a
    /// read to find out what a paste actually did.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    counts: Vec<ValueCount>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    errors: Vec<ValueError>,
}

/// One recorded value and how often it has now been seen.
#[derive(Debug, Serialize)]
pub struct ValueCount {
    value: String,
    count: u64,
    /// Whether this was the first sighting of the value in this namespace.
    new: bool,
}

#[derive(Debug, Serialize)]
pub struct ValueError {
    value: String,
    error: String,
}

/// A value's tags, replaced outright.
#[derive(Debug, Deserialize)]
pub struct TagChange {
    namespace: String,
    value: String,
    /// The whole set, comma-separated. Empty clears it.
    tags: String,
}

/// A storage change from the interface or an automation.
///
/// Name any namespace: the setting lands on its top-level namespace, which is
/// the unit that is paged in and out, and so covers everything under it. Both
/// halves are optional, and `"default"` (or null) on either means "stop saying
/// anything here and take the configured default".
#[derive(Debug, Deserialize)]
pub struct TierChange {
    /// Any namespace in the shard to change. `shard` is the older spelling.
    #[serde(default, alias = "shard")]
    namespace: String,
    #[serde(default)]
    tier: Option<String>,
    /// Seconds a warm shard may sit untouched. Accepts a number or a string,
    /// since a form field hands over text.
    #[serde(default)]
    warm_idle: Option<serde_json::Value>,
}

impl TierChange {
    /// The settings to store, or an explanation of what was unreadable.
    fn entry(&self) -> Result<crate::tier::Entry, String> {
        let tier = match self.tier.as_deref().map(str::trim) {
            None | Some("") | Some("default") | Some("inherit") => None,
            Some(tier) => Some(crate::tier::Tier::parse(tier).map_err(|e| e.to_string())?),
        };

        let warm_idle = match &self.warm_idle {
            None | Some(serde_json::Value::Null) => None,
            Some(serde_json::Value::Number(number)) => match number.as_u64() {
                Some(seconds) => Some(seconds),
                None => return Err("warm_idle cannot be negative".to_string()),
            },
            Some(serde_json::Value::String(text)) => {
                let text = text.trim();
                match text {
                    "" | "default" | "inherit" => None,
                    _ => Some(
                        text.parse::<u64>()
                            .map_err(|_| format!("'{text}' is not a number of seconds"))?,
                    ),
                }
            }
            Some(other) => return Err(format!("warm_idle should be a number, found {other}")),
        };

        Ok(crate::tier::Entry { tier, warm_idle })
    }
}

#[derive(Debug, Deserialize)]
pub struct ValueQuery {
    namespace: String,
    value: String,
}

/// Where one value has been seen, for the relationship graph.
#[derive(Debug, Deserialize)]
pub struct SightingsQuery {
    value: String,
    limit: Option<usize>,
}

impl SightingsQuery {
    /// A graph is read by eye, so the cap is what stays legible rather than
    /// what the server could serialize.
    fn limit(&self) -> usize {
        self.limit.unwrap_or(200).clamp(1, MAX_LIMIT)
    }
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
    /// Where the HTTP API listens, as `host:port`. Shown in the configuration
    /// view, and used to notice a peer being added that is this server itself.
    pub listen: String,
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
    /// What this server stores and who it knows about: the two things that
    /// decide its place in a galaxy.
    pub role: RoleInfo,
    /// When this server's TLS certificate runs out. `None` when it serves
    /// plain HTTP, or when the certificate cannot be read.
    pub tls: Option<crate::tls::Expiry>,
    /// Days of certificate life below which the interface calls it urgent, so
    /// the page and the log agree on what "soon" means.
    pub expiring_soon_days: i64,
}

/// This server's place in a galaxy.
///
/// Derived from `[storage] namespaces` and `[galaxy]`, and reported so that a
/// topology can be described from the outside — which is what a cluster view
/// has to read.
#[derive(Debug, Clone, Serialize)]
pub struct RoleInfo {
    /// `"node"`, `"router"`, or `"both"`.
    ///
    /// A node stores namespaces and forwards nothing; a router stores none of
    /// its own and exists to forward; both does each. The words describe a
    /// configuration rather than a type — any server can be any of them.
    pub kind: &'static str,
    /// Whether this server stores every namespace. A full mirror.
    pub mirrors_everything: bool,
    /// The namespace prefixes stored, when it is not everything. Empty on a
    /// router, which stores none.
    pub namespaces: Vec<String>,
    /// Peers, without their keys — a key is a credential and does not belong
    /// in a response the interface renders.
    pub peers: Vec<String>,
    pub max_hops: u8,
}

impl Default for RoleInfo {
    /// A server that stores everything and knows no peers, which is what every
    /// release before galaxies was.
    fn default() -> Self {
        RoleInfo {
            kind: "node",
            mirrors_everything: true,
            namespaces: Vec::new(),
            peers: Vec::new(),
            max_hops: 0,
        }
    }
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
    pub fn from_grants(key: &str, grants: &[Grant]) -> Self {
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
        log::debug!(
            "Refused {}: no API key, asked for the management interface",
            crate::handlers::peer_of(req)
        );
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
        // Louder than a data refusal: this is someone at the door of the
        // interface that hands out keys.
        log::warn!(
            "{}",
            crate::handlers::refusal(
                &crate::handlers::peer_of(req),
                key,
                state.acl().contains(key),
                "use",
                "the management interface",
            )
        );
        Err(HttpResponse::Forbidden().json(Message::new("That key is not an admin key.")))
    }
}

/// Reaching the interface is not the same as being allowed to read the data in
/// it: an `admin, r:feeds` key browses `feeds/*` and nothing else.
fn require_read(state: &SharedState, key: &str, namespace: &str) -> Result<(), HttpResponse> {
    if state.acl().can_read(key, namespace) {
        Ok(())
    } else {
        log::warn!(
            "{}",
            crate::handlers::refusal("an admin key", key, true, "read", namespace)
        );
        // Same answer as a namespace that does not exist, so browsing cannot
        // be used to enumerate what is out of reach.
        Err(HttpResponse::NotFound().json(Message::new("No such namespace.")))
    }
}

/// The same rule as [`require_read`], for the paths that change data: an
/// `admin, r:feeds` key browses `feeds/*` but does not add to it.
///
/// Unlike the sighting API this does not care whether `authenticate` is off.
/// That setting is about the sighting API; the management interface has always
/// demanded a key, and a key that says what it may write is the only thing
/// that makes an admin grant safe to hand out.
fn require_write(state: &SharedState, key: &str, namespace: &str) -> Result<(), HttpResponse> {
    if state.acl().can_write(key, namespace) {
        Ok(())
    } else {
        log::warn!(
            "{}",
            crate::handlers::refusal("an admin key", key, true, "write", namespace)
        );
        Err(HttpResponse::Forbidden().json(Message::new(format!(
            "That key is not permitted to write to '{namespace}'."
        ))))
    }
}

/// Tidy a namespace typed by a person into the name the database will store.
///
/// Browsing is by path segment, so stray or doubled slashes would otherwise
/// create a namespace that looks like a folder someone already made but sorts
/// and links as something else.
fn clean_namespace(namespace: &str) -> Result<String, HttpResponse> {
    let cleaned = namespace
        .split('/')
        .map(str::trim)
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>()
        .join("/");

    if cleaned.is_empty() {
        return Err(HttpResponse::BadRequest().json(Message::new("A namespace needs a name.")));
    }
    // The same rules as an ACL prefix, so that anything created here can also
    // be granted to a key later.
    if let Err(e) = validate_namespace(&cleaned) {
        return Err(HttpResponse::BadRequest().json(Message::new(e.to_string())));
    }
    Ok(cleaned)
}

pub async fn index() -> impl Responder {
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        // Revalidate every time. The page *is* the application — markup, CSS
        // and script in one file compiled into the binary — so a cached copy
        // means a browser running the previous version's JavaScript against
        // this version's API. With no cache headers at all a browser applies
        // its own heuristics and may not ask, which is how an upgraded server
        // ends up serving an interface nobody can explain.
        //
        // `no-cache` rather than `no-store`: the browser may keep it, it just
        // has to check. The one asset that is genuinely immutable between
        // builds, the charting bundle, keeps its long expiry below.
        .insert_header(("Cache-Control", "no-cache"))
        .body(UI)
}

pub async fn logo() -> impl Responder {
    HttpResponse::Ok()
        .content_type("image/png")
        // Immutable: it only changes when the binary does.
        .insert_header(("Cache-Control", "public, max-age=86400"))
        .body(LOGO)
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

/// `GET /_management/api/galaxy` — this server and the peers it knows.
///
/// What a topology view reads. Reports this server's own role and each peer's
/// health, so the picture can be drawn from one request against whichever
/// server the operator happens to be connected to.
///
/// Peer **keys are never included**: they are credentials, and this response is
/// rendered in a browser.
///
/// Nothing is forwarded to peers yet, so this describes the configured galaxy
/// and whether its members answer — not a traversal of it. A cascade is
/// reported one level deep: each peer appears as a peer, and asking *it* for
/// its own galaxy is how the next level is reached.
pub async fn galaxy(state: State, req: HttpRequest) -> HttpResponse {
    if let Err(resp) = require_admin(&state, &req) {
        return resp;
    }

    let Some(galaxy) = state.galaxy.as_ref() else {
        return HttpResponse::Ok().json(serde_json::json!({
            "self": describe(&state),
            "peers": [],
            "below": {},
        }));
    };

    // One level per hop. Asked for only when this request was not itself a
    // walk that has run out of budget, so a cascade is described all the way
    // down and a cycle still terminates.
    let hops = crate::galaxy::hops_left(&req, galaxy.max_hops()).unwrap_or(0);
    let below: serde_json::Map<String, serde_json::Value> = galaxy
        .walk(hops)
        .await
        .into_iter()
        .collect::<std::collections::BTreeMap<_, _>>()
        .into_iter()
        .collect();

    HttpResponse::Ok().json(serde_json::json!({
        // The server answering, so a view has a root to draw from without
        // being told separately which one it asked.
        "self": describe(&state),
        "peers": peers_with_storage(galaxy),
        // Each peer's own answer, keyed by its url. A peer that is itself a
        // router has peers of its own in here, which is how a cascade is
        // drawn from one request.
        //
        // Empty unless the peer key carries `admin` there, since this is the
        // same endpoint and it requires one. That is a deliberate trade — a
        // peer key should be the narrowest thing that works — and it is why
        // each peer's storage is reported above from *this* server's own
        // configuration rather than only from the peer's answer.
        "below": below,
    }))
}

/// Each peer's health, plus what this server has been told it stores.
///
/// The health alone is not enough to draw a galaxy: a viewer needs to know
/// which peers are full mirrors and which hold a slice. That used to be read
/// only from `below`, each peer's own answer — which is empty whenever the
/// peer key lacks `admin`, so every peer rendered as holding nothing on
/// exactly the galaxies that follow the advice about narrow keys.
///
/// This server knows the answer without asking: it is in its own `[galaxy]`
/// peer list, and it is what routing decisions are already made from. Said to
/// be *declared* rather than observed, because a configuration can disagree
/// with what a peer really holds and the viewer should be able to tell which
/// it is looking at.
fn peers_with_storage(galaxy: &crate::galaxy::Galaxy) -> Vec<serde_json::Value> {
    let declared: std::collections::HashMap<String, crate::db::StoragePolicy> = galaxy
        .peers()
        .into_iter()
        .map(|peer| (peer.url, peer.stores))
        .collect();

    galaxy
        .health()
        .into_iter()
        .map(|health| {
            let mut entry = serde_json::to_value(&health).unwrap_or_default();
            if let (Some(object), Some(stores)) = (entry.as_object_mut(), declared.get(&health.url))
            {
                object.insert(
                    "mirrors_everything".to_string(),
                    serde_json::json!(stores.stores_everything()),
                );
                // Null for a full mirror, which is how the rest of the API
                // reports it too.
                object.insert(
                    "namespaces".to_string(),
                    if stores.stores_everything() {
                        serde_json::Value::Null
                    } else {
                        serde_json::json!(stores.prefixes())
                    },
                );
            }
            entry
        })
        .collect()
}

/// One peer as the interface lists it.
///
/// The key is **not** included. It is a credential this server holds, and a
/// topology view is not a reason to hand it back out; the interface shows that
/// one is set and lets it be replaced, which is all editing needs.
#[derive(Debug, Serialize)]
pub struct PeerRow {
    pub url: String,
    /// What the peer stores: `null` for a full mirror, else the prefixes.
    pub namespaces: Option<Vec<String>>,
    /// Whether this peer came from the configuration file, and so cannot be
    /// changed here.
    pub fixed: bool,
    /// Whether this server will use it. A disabled peer is kept and reached
    /// for nothing: no forwarded request, no catch-up, no health probe.
    pub enabled: bool,
    pub health: crate::galaxy::PeerHealth,
}

#[derive(Debug, Serialize)]
pub struct PeersView {
    pub peers: Vec<PeerRow>,
    /// Whether peers can be added or removed here. False without a
    /// `peers_file`, or with no `[galaxy]` section at all.
    pub editable: bool,
    /// Why not, when they cannot be.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// `GET /_management/api/galaxy/peers` — the peer list, for editing.
///
/// Separate from `/_management/api/galaxy`, which walks the whole cascade to
/// draw it. This is one server's own list and answers without touching the
/// network, so the editor stays responsive while a peer is down.
pub async fn list_peers(state: State, req: HttpRequest) -> HttpResponse {
    if let Err(resp) = require_admin(&state, &req) {
        return resp;
    }

    let Some(galaxy) = state.galaxy.as_ref() else {
        return HttpResponse::Ok().json(PeersView {
            peers: Vec::new(),
            editable: false,
            note: Some(
                "This server has no [galaxy] section, so it has no peers to manage. Add \
                 one with a peers_file and restart; `sightingdb --setup` writes both."
                    .to_string(),
            ),
        });
    };

    let health: std::collections::HashMap<String, crate::galaxy::PeerHealth> = galaxy
        .health()
        .into_iter()
        .map(|known| (known.url.clone(), known))
        .collect();

    // Every peer, disabled ones included: a peer taken out of service still
    // has a row, and hiding it would make "disabled" indistinguishable from
    // "removed" in the one place you would go to put it back.
    let peers = galaxy
        .all_peers()
        .into_iter()
        .map(|peer| PeerRow {
            namespaces: (!peer.stores.stores_everything()).then(|| peer.stores.prefixes().to_vec()),
            fixed: galaxy.is_fixed(&peer.url),
            enabled: peer.enabled,
            health: health
                .get(&peer.url)
                .cloned()
                .unwrap_or_else(|| crate::galaxy::PeerHealth::unprobed(&peer.url)),
            url: peer.url,
        })
        .collect();

    let editable = state.galaxy_peers_file.is_some();
    HttpResponse::Ok().json(PeersView {
        peers,
        editable,
        note: (!editable).then(|| {
            "No peers_file is configured, so peers cannot be edited here. Set \
             peers_file in [galaxy] and restart."
                .to_string()
        }),
    })
}

/// A peer as the interface sends it.
#[derive(Debug, Deserialize)]
pub struct PeerChange {
    url: String,
    key: String,
    /// Absent or empty means a full mirror.
    #[serde(default)]
    namespaces: Option<Vec<String>>,
}

/// Where UI-added peers are written, or why they cannot be.
fn peers_file(state: &SharedState) -> Result<&PathBuf, HttpResponse> {
    if state.galaxy.is_none() {
        return Err(HttpResponse::Conflict().json(Message::new(
            "This server has no [galaxy] section, so it has no galaxy to add to. Add one \
             with a peers_file and restart.",
        )));
    }
    state.galaxy_peers_file.as_ref().ok_or_else(|| {
        HttpResponse::Conflict().json(Message::new(
            "No peers_file is configured, so peers cannot be edited here. Set peers_file \
             in [galaxy] and restart.",
        ))
    })
}

/// Write the peers the interface owns, then answer with the whole list.
///
/// Written after the change is already in effect, so a failed write is
/// reported with the galaxy already using the new peer — which is the right
/// way round: the peer works now and the file is what makes it survive a
/// restart. The message says exactly that rather than implying the change
/// did not happen.
fn save_peers(state: &SharedState) -> Result<(), HttpResponse> {
    let path = peers_file(state)?;
    let Some(galaxy) = state.galaxy.as_ref() else {
        return Ok(());
    };
    let rendered = crate::config::PeersFile::to_toml(&galaxy.editable_peers());

    let write = || -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let temp = path.with_extension("tmp");
        std::fs::write(&temp, rendered)?;
        std::fs::rename(&temp, path)
    };

    if let Err(e) = write() {
        log::error!("Could not write {}: {e}", path.display());
        return Err(
            HttpResponse::InternalServerError().json(Message::new(format!(
                "The galaxy was changed and is in effect now, but {} could not be written, \
             so the change will be lost on restart: {e}",
                path.display()
            ))),
        );
    }
    Ok(())
}

/// `POST /_management/api/galaxy/peers` — add a peer this galaxy does not have.
///
/// Adding and changing are separate verbs on purpose. An upsert would mean
/// that typing an address that already exists silently replaces its key, and
/// the one thing a peer's key does is bound what this server may do there —
/// replacing it by accident is not a mistake to make quietly.
pub async fn add_peer(state: State, body: web::Json<PeerChange>, req: HttpRequest) -> HttpResponse {
    save_peer(state, body, req, false).await
}

/// `PUT /_management/api/galaxy/peers` — change a peer this galaxy has.
pub async fn update_peer(
    state: State,
    body: web::Json<PeerChange>,
    req: HttpRequest,
) -> HttpResponse {
    save_peer(state, body, req, true).await
}

async fn save_peer(
    state: State,
    body: web::Json<PeerChange>,
    req: HttpRequest,
    replacing: bool,
) -> HttpResponse {
    let caller = match require_admin(&state, &req) {
        Ok(key) => key.to_string(),
        Err(resp) => return resp,
    };
    if let Err(resp) = peers_file(&state) {
        return resp;
    }
    let Some(galaxy) = state.galaxy.as_ref() else {
        return HttpResponse::Conflict().json(Message::new("This server has no galaxy."));
    };

    let change = body.into_inner();
    // An empty namespaces list from a form means "everything" rather than
    // "nothing": a peer that holds nothing is not a mirror, and the validator
    // refuses it.
    let namespaces = change
        .namespaces
        .as_ref()
        .filter(|list| !list.is_empty())
        .map(|list| list.as_slice());

    // Added enabled, and an edit keeps whatever it was: a `PUT` that changed
    // the key should not quietly put a peer back into service.
    let enabled = state
        .galaxy
        .as_ref()
        .and_then(|galaxy| {
            galaxy
                .all_peers()
                .into_iter()
                .find(|known| known.url == change.url.trim().trim_end_matches('/'))
        })
        .is_none_or(|known| known.enabled);

    let peer = match crate::config::validated_peer(&change.url, &change.key, namespaces, enabled) {
        Ok(peer) => peer,
        Err(e) => return HttpResponse::BadRequest().json(Message::new(e)),
    };

    if galaxy.is_fixed(&peer.url) {
        return HttpResponse::Conflict().json(Message::new(format!(
            "{} is declared in the configuration file. Change it there, or remove it \
             from [galaxy] peers to manage it here.",
            peer.url
        )));
    }

    let url = peer.url.clone();
    if replacing {
        // Keeps its place in the order, so the list does not reshuffle under
        // someone editing it.
        if galaxy.update_peer(peer).is_none() {
            return HttpResponse::NotFound().json(Message::new(format!(
                "{url} is not in this galaxy. Add it instead."
            )));
        }
    } else if let Err(e) = galaxy.add_peer(peer, &state.info.listen) {
        return match e {
            crate::galaxy::AddPeer::Invalid(message) => {
                HttpResponse::BadRequest().json(Message::new(message))
            }
            crate::galaxy::AddPeer::AlreadyThere(message) => {
                HttpResponse::Conflict().json(Message::new(message))
            }
        };
    }

    if let Err(resp) = save_peers(&state) {
        return resp;
    }
    log::info!(
        "Peer '{url}' {} by '{caller}'",
        if replacing { "changed" } else { "added" }
    );
    list_peers(state, req).await
}

/// `DELETE /_management/api/galaxy/peers?url=...` — drop a peer.
///
/// By query rather than path segment because the value is a URL, which a path
/// would have to encode and middleware is free to normalise.
pub async fn delete_peer(
    state: State,
    query: web::Query<PeerQuery>,
    req: HttpRequest,
) -> HttpResponse {
    let caller = match require_admin(&state, &req) {
        Ok(key) => key.to_string(),
        Err(resp) => return resp,
    };
    if let Err(resp) = peers_file(&state) {
        return resp;
    }
    let Some(galaxy) = state.galaxy.as_ref() else {
        return HttpResponse::Conflict().json(Message::new("This server has no galaxy."));
    };

    if galaxy.is_fixed(&query.url) {
        return HttpResponse::Conflict().json(Message::new(format!(
            "{} is declared in the configuration file, so removing it here would not \
             last: it would come back at the next restart. Remove it from [galaxy] \
             peers instead.",
            query.url
        )));
    }
    if !galaxy.remove_peer(&query.url) {
        return HttpResponse::NotFound().json(Message::new("No such peer."));
    }
    if let Err(resp) = save_peers(&state) {
        return resp;
    }
    log::info!("Peer '{}' removed by '{caller}'", query.url);
    list_peers(state, req).await
}

/// `POST /_management/api/galaxy/peers/enabled` — take a peer out of service,
/// or put it back.
///
/// Its own route rather than a field on `PUT`, because that needs the key —
/// which is never read back, so a toggle would mean retyping a credential to
/// change something unrelated to it.
///
/// Idempotent: setting it to what it already is succeeds and changes nothing,
/// so a button pressed twice, or a script run twice, is not an error.
pub async fn set_peer_enabled(
    state: State,
    body: web::Json<PeerEnabled>,
    req: HttpRequest,
) -> HttpResponse {
    let caller = match require_admin(&state, &req) {
        Ok(key) => key.to_string(),
        Err(resp) => return resp,
    };
    if let Err(resp) = peers_file(&state) {
        return resp;
    }
    let Some(galaxy) = state.galaxy.as_ref() else {
        return HttpResponse::Conflict().json(Message::new("This server has no galaxy."));
    };

    let change = body.into_inner();
    if galaxy.is_fixed(&change.url) {
        return HttpResponse::Conflict().json(Message::new(format!(
            concat!(
                "{} is declared in the configuration file, so disabling it here would ",
                "not last: it would come back at the next restart. Set enabled = false ",
                "on it in [galaxy] peers instead."
            ),
            change.url
        )));
    }
    if galaxy.set_enabled(&change.url, change.enabled).is_none() {
        return HttpResponse::NotFound().json(Message::new("No such peer."));
    }
    if let Err(resp) = save_peers(&state) {
        return resp;
    }

    log::info!(
        "Peer '{}' {} by '{caller}'",
        change.url,
        if change.enabled {
            "put back into service"
        } else {
            "taken out of service"
        }
    );
    list_peers(state, req).await
}

#[derive(Debug, Deserialize)]
pub struct PeerEnabled {
    url: String,
    enabled: bool,
}

#[derive(Debug, Deserialize)]
pub struct PeerQuery {
    url: String,
}

/// This server, as a topology view needs it.
fn describe(state: &SharedState) -> serde_json::Value {
    serde_json::json!({
        "node_id": state.db.node(),
        "version": env!("CARGO_PKG_VERSION"),
        "role": state.info.role.clone(),
        "uptime_seconds": state.started.elapsed().as_secs(),
    })
}

/// `GET /_management/api/rejections` — values that were not written.
///
/// Newest first, because the question is nearly always "what has just started
/// failing?". Every write path feeds this, including the ZMQ ingest, which has
/// no caller of its own to tell.
///
/// Filtered by what the key may *read*: a rejection names a namespace and a
/// value someone tried to put in it, which is not something to hand to a key
/// that could not have read that namespace anyway.
pub async fn rejections(
    state: State,
    query: web::Query<RejectionsQuery>,
    req: HttpRequest,
) -> HttpResponse {
    let key = match require_admin(&state, &req) {
        Ok(key) => key.to_string(),
        Err(resp) => return resp,
    };

    if let Some(namespace) = &query.namespace
        && let Err(resp) = require_read(&state, &key, namespace)
    {
        return resp;
    }

    let acl = state.acl();
    // Over-fetch, then drop what this key may not read, so that filtering does
    // not silently return a short page.
    let mut found: Vec<_> = state
        .rejections
        .recent(query.namespace.as_deref(), MAX_LIMIT)
        .into_iter()
        .filter(|entry| acl.can_read(&key, &entry.namespace))
        .collect();
    drop(acl);
    found.truncate(query.limit());

    HttpResponse::Ok().json(RejectionPage {
        rejections: found,
        total: state.rejections.len(),
        capacity: state.rejections.capacity(),
    })
}

/// `DELETE /_management/api/rejections` — forget them all.
///
/// How an operator marks a feed as dealt with, so that what shows up next is
/// new rather than the same thousand entries they have already read.
pub async fn clear_rejections(state: State, req: HttpRequest) -> HttpResponse {
    let key = match require_admin(&state, &req) {
        Ok(key) => key.to_string(),
        Err(resp) => return resp,
    };

    // Clearing is all-or-nothing, so it takes a key that could read all of it.
    if !state.acl().can_read(&key, "") {
        return HttpResponse::Forbidden().json(Message::new(
            "Clearing the rejection log needs a key with unscoped read access.",
        ));
    }

    let held = state.rejections.len();
    state.rejections.clear();
    log::info!("{held} rejection(s) cleared by '{key}'");
    HttpResponse::Ok().json(Message::new("ok"))
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

/// One level of the namespace tree, so the interface can browse namespaces the
/// way a file manager browses directories.
pub async fn tree(state: State, query: web::Query<TreeQuery>, req: HttpRequest) -> HttpResponse {
    let key = match require_admin(&state, &req) {
        Ok(key) => key.to_string(),
        Err(resp) => return resp,
    };

    let acl = state.acl();
    let page =
        state
            .db
            .namespace_children(&query.path, &query.q, query.offset, query.limit(), |name| {
                acl.can_read(&key, name)
            });
    drop(acl);
    HttpResponse::Ok().json(page)
}

/// Create a namespace that holds nothing yet.
///
/// Nothing else in SightingDB needs this — writing a value brings its namespace
/// into being — but a browser wants somewhere to put things before it has them,
/// and a folder made in advance is how anyone expects that to work.
pub async fn create_namespace(
    state: State,
    body: web::Json<NewNamespace>,
    req: HttpRequest,
) -> HttpResponse {
    let caller = match require_admin(&state, &req) {
        Ok(key) => key.to_string(),
        Err(resp) => return resp,
    };

    let namespace = match clean_namespace(&body.namespace) {
        Ok(namespace) => namespace,
        Err(resp) => return resp,
    };
    if let Err(resp) = require_write(&state, &caller, &namespace) {
        return resp;
    }

    if !state.db.create_namespace(&namespace) {
        return HttpResponse::Conflict()
            .json(Message::new(format!("'{namespace}' already exists.")));
    }

    log::info!("Namespace '{namespace}' created by '{caller}'");
    HttpResponse::Ok().json(serde_json::json!({ "namespace": namespace }))
}

/// Record one value or a pasted list of them, in one namespace.
///
/// The namespace does not have to exist: writing is what creates it, here as
/// everywhere else. Values are counted towards consensus exactly as a `/w/`
/// write would be, so nothing added here is a second class of sighting.
pub async fn add_values(
    state: State,
    body: web::Json<NewValues>,
    req: HttpRequest,
) -> HttpResponse {
    let caller = match require_admin(&state, &req) {
        Ok(key) => key.to_string(),
        Err(resp) => return resp,
    };

    let body = body.into_inner();
    let namespace = match clean_namespace(&body.namespace) {
        Ok(namespace) => namespace,
        Err(resp) => return resp,
    };
    if let Err(resp) = require_write(&state, &caller, &namespace) {
        return resp;
    }

    let when = match body
        .timestamp
        .map(crate::sighting_writer::timestamp_to_instant)
    {
        Some(Ok(when)) => Some(when),
        Some(Err(e)) => return HttpResponse::BadRequest().json(Message::new(e.to_string())),
        None => None,
    };

    // Whitespace-only lines are what a paste ends with, not something someone
    // meant to record.
    let values: Vec<&str> = body
        .values
        .iter()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .collect();
    if values.is_empty() {
        return HttpResponse::BadRequest().json(Message::new("No values to add."));
    }

    let mut report = WriteReport {
        namespace: namespace.clone(),
        written: 0,
        counts: Vec::with_capacity(values.len()),
        errors: Vec::new(),
    };
    for value in values {
        match crate::sighting_writer::write_tagged(
            &state.db, &namespace, value, when, body.ttl, &body.tags,
        ) {
            Ok(written) => {
                report.written += 1;
                report.counts.push(ValueCount {
                    value: value.to_string(),
                    count: written.count,
                    new: written.new,
                });
            }
            Err(e) => {
                state.rejections.record(
                    &namespace,
                    value,
                    &e.to_string(),
                    crate::rejections::Source::Management,
                );
                report.errors.push(ValueError {
                    value: value.to_string(),
                    error: e.to_string(),
                });
            }
        }
    }

    log::info!(
        "{} value(s) added to '{namespace}' by '{caller}'{}",
        report.written,
        if report.errors.is_empty() {
            String::new()
        } else {
            format!(", {} rejected", report.errors.len())
        }
    );

    // Every value failing is a client error; a mix still reports what landed,
    // the same way `/wb` does.
    if report.written == 0 {
        HttpResponse::BadRequest().json(report)
    } else {
        HttpResponse::Ok().json(report)
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

/// Every namespace one value appears in, which is what the graph draws.
///
/// Only namespaces this key may read are returned. The count in `_all` — shown
/// beside the graph as consensus — still reflects every namespace, so a scoped
/// key can tell that it is not seeing all of them without being told their
/// names.
pub async fn sightings(
    state: State,
    query: web::Query<SightingsQuery>,
    req: HttpRequest,
) -> HttpResponse {
    let key = match require_admin(&state, &req) {
        Ok(key) => key.to_string(),
        Err(resp) => return resp,
    };
    if query.value.is_empty() {
        return HttpResponse::BadRequest().json(Message::new("No value to look for."));
    }

    let acl = state.acl();
    let found = state
        .db
        .sightings_of(&query.value, query.limit(), |name| acl.can_read(&key, name));
    drop(acl);

    HttpResponse::Ok().json(serde_json::json!({
        "value": query.value,
        "consensus": state.db.count(crate::db::ALL_NAMESPACE, &query.value),
        "items": found.items,
        "truncated": found.truncated,
        "paged_in": found.paged_in,
    }))
}

/// Replace one value's tags.
///
/// Adding tags is a write like any other and goes through `/w`; this exists for
/// the other direction, since a wrong tag can only come off by replacing the
/// set. It is not a sighting: nothing is counted and no timestamp moves.
pub async fn set_tags(state: State, body: web::Json<TagChange>, req: HttpRequest) -> HttpResponse {
    let caller = match require_admin(&state, &req) {
        Ok(key) => key.to_string(),
        Err(resp) => return resp,
    };

    let change = body.into_inner();
    let namespace = match clean_namespace(&change.namespace) {
        Ok(namespace) => namespace,
        Err(resp) => return resp,
    };
    if let Err(resp) = require_write(&state, &caller, &namespace) {
        return resp;
    }

    // Where the value actually lives decides how the change gets there. A
    // server that holds the namespace changes its own copy; one that does not
    // — a router — has no copy to change, so it asks a mirror for the value
    // and applies the change to *that*, without keeping it.
    //
    // Not keeping it matters: a router stores nothing on purpose, and writing
    // every retagged value into it would leave it accumulating values it has
    // no business holding, which nothing would ever read — reads of those
    // namespaces are forwarded, since what a server holds is its configured
    // policy and not whatever happens to be in memory.
    let held = state.db.holds(&namespace);
    let payload = if held {
        if !state.db.set_tags(&namespace, &change.value, &change.tags) {
            return HttpResponse::NotFound().json(Message::new("No such value."));
        }
        match state.db.merge_payload(&namespace, &change.value) {
            Some(payload) => payload,
            // Written a moment ago, so this cannot happen; reported rather
            // than unwrapped.
            None => {
                return HttpResponse::InternalServerError()
                    .json(Message::new("The value disappeared while being retagged."));
            }
        }
    } else {
        match retagged_elsewhere(&state, &namespace, &change).await {
            Ok(payload) => payload,
            Err(resp) => return resp,
        }
    };

    log::info!(
        "Tags of '{}' in '{namespace}' set by '{caller}'",
        change.value
    );

    // A tag change is not a sighting, so nothing else would ever carry it to
    // the mirrors: without this it would sit here until someone noticed the
    // two copies disagreed. Pushed rather than waited for, because the whole
    // point of editing a tag is that it is wrong *now*.
    let spread = spread_tags(&state, &namespace, &change.value, &payload).await;

    let consensus = state.db.count(crate::db::ALL_NAMESPACE, &change.value);
    // The value as it now stands. From this server when it holds it, and
    // otherwise from the copy that was just pushed — a router has nothing of
    // its own to report, and answering "ok" would leave the interface unable
    // to redraw the row it just changed.
    let view = state
        .db
        .view(&namespace, &change.value, consensus, false)
        .unwrap_or_else(|| view_of(&change.value, &payload, consensus));
    match spread {
        // The common case: nothing to say beyond the value itself, which is
        // the shape every existing client already reads.
        None => HttpResponse::Ok().json(view),
        Some(report) => HttpResponse::Ok().json(TaggedAcross {
            value: view,
            mirrors: report,
        }),
    }
}

/// A tag change, and which mirrors it reached.
#[derive(Debug, Serialize)]
pub struct TaggedAcross {
    #[serde(flatten)]
    value: crate::attribute::AttributeView,
    /// One entry per mirror that holds the namespace. Absent when this server
    /// stands alone, so a lone server's answer is unchanged.
    mirrors: Vec<MirrorOutcome>,
}

#[derive(Debug, Serialize)]
pub struct MirrorOutcome {
    url: String,
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

/// Offer this server's copy of a value to every mirror of its namespace.
///
/// `None` when there is nothing to offer it to. Reported rather than silent,
/// because "the tag is off here but still on a mirror" is precisely the state
/// someone editing tags needs to know about.
async fn spread_tags(
    state: &SharedState,
    namespace: &str,
    value: &str,
    payload: &crate::attribute::Merge,
) -> Option<Vec<MirrorOutcome>> {
    let galaxy = state.galaxy.as_ref()?;
    let outcomes = galaxy
        .push_value(namespace, value, payload, galaxy.max_hops())
        .await;
    if outcomes.is_empty() {
        return None;
    }
    Some(
        outcomes
            .into_iter()
            .map(|(url, outcome)| match outcome {
                Ok(_) => MirrorOutcome {
                    url,
                    ok: true,
                    error: None,
                },
                Err(e) => {
                    log::warn!("Could not send the tag change for '{value}' to {url}: {e}");
                    MirrorOutcome {
                        url,
                        ok: false,
                        error: Some(e),
                    }
                }
            })
            .collect(),
    )
}

/// Retag a value this server does not hold.
///
/// A router keeps no copy of the value, so there is nothing here to set tags
/// on. It fetches the value as a mirror holds it, applies the replacement to
/// that, and writes the result into its own database — from where
/// [`spread_tags`] offers it to every mirror. Writing it here is what makes
/// the local copy the thing that was agreed on; it is held in the router's
/// database like any other merge, and the router's own storage policy decides
/// whether it is kept beyond that.
async fn retagged_elsewhere(
    state: &SharedState,
    namespace: &str,
    change: &TagChange,
) -> Result<crate::attribute::Merge, HttpResponse> {
    let Some(galaxy) = state.galaxy.as_ref() else {
        return Err(HttpResponse::NotFound().json(Message::new("No such value.")));
    };

    let path = format!(
        "/r/{}?val={}&noshadow&for_merge",
        namespace,
        crate::galaxy::urlencoding_of(&change.value)
    );
    let answer = galaxy
        .forward_read(namespace, &change.value, &path, galaxy.max_hops(), "")
        .await
        .map_err(|e| {
            HttpResponse::BadGateway().json(Message::new(format!(
                "Could not reach a mirror holding '{namespace}': {e}"
            )))
        })?;

    if !(200..300).contains(&answer.status) {
        // Relayed, so "no such value" from the mirror reads as it would if the
        // interface had asked the mirror directly.
        return Err(HttpResponse::build(
            actix_web::http::StatusCode::from_u16(answer.status)
                .unwrap_or(actix_web::http::StatusCode::BAD_GATEWAY),
        )
        .content_type("application/json")
        .body(answer.body));
    }

    let mut payload: crate::attribute::Merge =
        serde_json::from_slice(&answer.body).map_err(|e| {
            HttpResponse::BadGateway()
                .json(Message::new(format!("A mirror answered unreadably: {e}")))
        })?;

    payload.tags = change.tags.clone();
    payload.tags_at = chrono::Utc::now().timestamp_millis();
    Ok(payload)
}

/// A value as a merge payload describes it, for a server that holds no copy.
fn view_of(
    value: &str,
    payload: &crate::attribute::Merge,
    consensus: u64,
) -> crate::attribute::AttributeView {
    crate::attribute::AttributeView {
        value: value.to_string(),
        first_seen: payload.first_seen,
        last_seen: payload.last_seen,
        count: payload.counts.values().sum(),
        tags: payload.tags.clone(),
        ttl: payload.ttl,
        consensus,
        stats: None,
    }
}

// ---------------------------------------------------------------------------
// The tag vocabulary
// ---------------------------------------------------------------------------

/// One row of the tags table.
#[derive(Debug, Serialize)]
pub struct TagRow {
    /// The tag, or a family if it ends in `:`.
    pub name: String,
    pub colour: String,
    pub description: String,
    /// Whether this is a family, colouring every tag under it.
    pub family: bool,
    /// How many loaded values carry it. For a family, how many carry a tag
    /// under it. `None` for a tag that is defined but not in use.
    pub used: Option<u64>,
    /// Whether the vocabulary defines it, or it was only found on values.
    pub defined: bool,
}

/// `GET /_management/api/tags` — the vocabulary, and what is actually in use.
///
/// Two things at once, deliberately: the tags someone has given a colour to,
/// and the tags found on values. A feed brings whatever tags it brings, so the
/// second set is not a subset of the first, and seeing an undefined tag in the
/// same table is what makes it one click to adopt rather than something to
/// discover by accident.
#[derive(Debug, Serialize)]
pub struct TagsView {
    pub tags: Vec<TagRow>,
    /// The colour an undefined tag is shown in.
    pub unknown_colour: String,
    /// Whether the vocabulary can be edited here. False without a
    /// `tags_file`.
    pub editable: bool,
    /// Usage was counted over this many namespaces, of this many that exist.
    /// Less than all of them means cold namespaces were not paged in to count
    /// — see [`crate::db::Database::tag_usage`].
    pub counted_namespaces: usize,
    pub total_namespaces: usize,
    /// Why the counts cover less than the galaxy, when they do.
    ///
    /// The counts are of what **this server** holds, and a server in front of
    /// a galaxy holds little or none of it. Without saying so, a router's Tags
    /// page reads as "the galaxy has six tags" when it means "I have six" —
    /// and `counted_namespaces` equal to `total_namespaces` makes that look
    /// complete rather than local.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

pub async fn list_tags(state: State, req: HttpRequest) -> HttpResponse {
    let caller = match require_admin(&state, &req) {
        Ok(key) => key.to_string(),
        Err(resp) => return resp,
    };

    let (usage, counted, total) = state.db.tag_usage();

    // A key that cannot read everything would otherwise learn which tags
    // exist in namespaces it has no access to. Counted over what it may read
    // only — which needs the per-namespace walk, so it is done the simple way
    // here: a scoped key sees the vocabulary but no counts.
    let everywhere = state
        .acl
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .can_read(&caller, "/");
    let usage = if everywhere {
        usage
    } else {
        std::collections::BTreeMap::new()
    };

    let vocabulary = state
        .tags
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner);

    let mut rows: Vec<TagRow> = Vec::new();
    for (name, tag) in vocabulary.entries() {
        let family = name.ends_with(':');
        // A family's count is everything under it, which is the only number
        // that means anything for a name no value carries literally.
        let used: u64 = if family {
            usage
                .iter()
                .filter(|(found, _)| found.starts_with(name.as_str()))
                .map(|(_, count)| *count)
                .sum()
        } else {
            usage.get(name).copied().unwrap_or(0)
        };
        rows.push(TagRow {
            name: name.clone(),
            colour: tag.colour.clone(),
            description: tag.description.clone(),
            family,
            used: (used > 0).then_some(used),
            defined: true,
        });
    }

    // Tags found on values that the vocabulary does not define.
    for (name, count) in &usage {
        if vocabulary.get(name).is_some() {
            continue;
        }
        rows.push(TagRow {
            name: name.clone(),
            // What it is shown in today, so adopting it can start from that
            // rather than from an empty field.
            colour: vocabulary
                .colour_of(name)
                .unwrap_or(crate::tags::UNKNOWN_COLOUR)
                .to_string(),
            description: String::new(),
            family: false,
            used: Some(*count),
            defined: false,
        });
    }

    rows.sort_by(|a, b| a.name.cmp(&b.name));

    // Counts are of what this server holds. Say so when that is not the
    // galaxy — a reader cannot tell from the numbers alone.
    let scope = if !everywhere {
        Some(
            concat!(
                "Counts are hidden because this key cannot read every namespace. ",
                "The vocabulary itself is not scoped.",
            )
            .to_string(),
        )
    } else if state.db.stores().is_router() {
        Some(
            concat!(
                "This server stores nothing of its own, so these counts cover only ",
                "what it has locally — which on a router is next to nothing. The tags ",
                "in use are on the nodes; open a node's interface to count them there.",
            )
            .to_string(),
        )
    } else if !state.db.stores().stores_everything() {
        Some(format!(
            concat!(
                "Counts cover the namespaces this server stores ({}). Tags in ",
                "namespaces held elsewhere in the galaxy are not counted here.",
            ),
            state.db.stores().prefixes().join(", ")
        ))
    } else {
        None
    };

    HttpResponse::Ok().json(TagsView {
        tags: rows,
        unknown_colour: crate::tags::UNKNOWN_COLOUR.to_string(),
        editable: state.tags_file.is_some(),
        counted_namespaces: counted,
        total_namespaces: total,
        scope,
    })
}

/// A tag's presentation, as the interface sends it.
#[derive(Debug, Deserialize)]
pub struct TagDefinition {
    name: String,
    colour: String,
    #[serde(default)]
    description: String,
}

/// Where the vocabulary is written. Without one, colours are read-only: the
/// main configuration is hand-maintained and this does not rewrite it.
fn tags_file(state: &SharedState) -> Result<&PathBuf, HttpResponse> {
    state.tags_file.as_ref().ok_or_else(|| {
        HttpResponse::Conflict().json(Message::new(
            "No tags_file is configured, so tag colours cannot be edited here. Set \
             tags_file in [daemon] and restart.",
        ))
    })
}

/// Persist the vocabulary, then adopt it. Temp file and rename, like the ACL.
fn save_tags(state: &SharedState, vocabulary: crate::tags::Vocabulary) -> Result<(), HttpResponse> {
    let path = tags_file(state)?;

    let write = || -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let temp = path.with_extension("tmp");
        std::fs::write(&temp, vocabulary.to_toml())?;
        std::fs::rename(&temp, path)
    };

    if let Err(e) = write() {
        log::error!("Could not write {}: {e}", path.display());
        return Err(
            HttpResponse::InternalServerError().json(Message::new(format!(
                "Could not write the tag vocabulary: {e}"
            ))),
        );
    }

    *state
        .tags
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = vocabulary;
    Ok(())
}

/// `POST /_management/api/tags/vocabulary` — define or redefine one tag.
pub async fn define_tag(
    state: State,
    body: web::Json<TagDefinition>,
    req: HttpRequest,
) -> HttpResponse {
    let caller = match require_admin(&state, &req) {
        Ok(key) => key.to_string(),
        Err(resp) => return resp,
    };
    if let Err(resp) = tags_file(&state) {
        return resp;
    }

    let definition = body.into_inner();
    let mut vocabulary = state
        .tags
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();

    if let Err(e) = vocabulary.set(
        &definition.name,
        &definition.colour,
        &definition.description,
    ) {
        return HttpResponse::BadRequest().json(Message::new(e));
    }
    if let Err(resp) = save_tags(&state, vocabulary) {
        return resp;
    }

    log::info!("Tag '{}' defined by '{caller}'", definition.name.trim());
    list_tags(state, req).await
}

/// `DELETE /_management/api/tags/vocabulary?tag=...` — forget a tag's colour.
///
/// By query rather than path segment because a tag contains `:` and often `/`,
/// which a path would have to encode and middleware would be free to
/// normalise. **Values keep the tag itself**: this is a presentation setting,
/// and deleting data from a colour picker would be a trap.
pub async fn undefine_tag(
    state: State,
    query: web::Query<TagQuery>,
    req: HttpRequest,
) -> HttpResponse {
    let caller = match require_admin(&state, &req) {
        Ok(key) => key.to_string(),
        Err(resp) => return resp,
    };
    if let Err(resp) = tags_file(&state) {
        return resp;
    }

    let mut vocabulary = state
        .tags
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    if !vocabulary.remove(&query.tag) {
        return HttpResponse::NotFound().json(Message::new("No such tag in the vocabulary."));
    }
    if let Err(resp) = save_tags(&state, vocabulary) {
        return resp;
    }

    log::info!("Tag '{}' undefined by '{caller}'", query.tag);
    list_tags(state, req).await
}

#[derive(Debug, Deserialize)]
pub struct TagQuery {
    tag: String,
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

/// `GET /_management/api/keys/drift` — where this server's keys and its peers'
/// disagree.
///
/// Worth a view of its own because of one deliberate limitation: the periodic
/// offer of keys to peers is *additive*, so a key revoked while a peer was down
/// stays live on that peer. That is a security hole if it is invisible, and
/// merely a chore if it is not — this is what makes it visible.
///
/// Reports, per peer:
///
///   * `revoked_but_present` — keys this server **revoked** and the peer still
///     accepts. A revocation that did not land, and the reason this exists.
///   * `only_on_peer` — keys the peer has that this server never knew about.
///     Ordinary: a peer has its own keys, including the one this server
///     authenticates with. Kept separate so it does not drown the case above.
///   * `missing` — keys this server has and the peer does not. Usually a peer
///     that has not had the periodic offer yet.
///
/// The record of revocations is in memory, so it is lost on restart: after one,
/// a revocation that never landed moves from `revoked_but_present` into
/// `only_on_peer` and stops being flagged. Checking the peer's own key list is
/// then the way to find it.
///
/// Asked through each peer's own management interface, so a peer this server
/// does not administer reports why rather than appearing to agree.
pub async fn key_drift(state: State, req: HttpRequest) -> HttpResponse {
    if let Err(resp) = require_admin(&state, &req) {
        return resp;
    }

    let Some(galaxy) = state.galaxy.as_ref() else {
        return HttpResponse::Ok().json(serde_json::json!({ "peers": [] }));
    };

    let mine: std::collections::BTreeSet<String> = state
        .acl()
        .entries()
        .iter()
        .map(|(key, _)| key.clone())
        .collect();
    let revoked_here: std::collections::BTreeSet<String> =
        state.revoked_keys().into_iter().collect();

    let mut rows = Vec::new();
    for peer in galaxy.peer_keys().await {
        let theirs: std::collections::BTreeSet<String> = peer.keys.iter().cloned().collect();
        let unknown: Vec<&String> = theirs.difference(&mine).collect();

        // The dangerous case: this server revoked it and the peer still takes
        // it. Separated from the rest, because a peer having keys this server
        // never knew about is ordinary — it has its own, including the one
        // this server authenticates with, which would otherwise be reported as
        // stale for ever.
        let (stale, theirs_alone): (Vec<&String>, Vec<&String>) = unknown
            .into_iter()
            .partition(|key| revoked_here.contains(*key));

        let missing: Vec<&String> = mine.difference(&theirs).collect();

        rows.push(serde_json::json!({
            "url": peer.url,
            "readable": peer.readable,
            "error": peer.error,
            "revoked_but_present": stale,
            "only_on_peer": theirs_alone,
            "missing": missing,
            "agrees": peer.readable && stale.is_empty() && missing.is_empty(),
        }));
    }

    HttpResponse::Ok().json(serde_json::json!({ "peers": rows }))
}

/// `PUT /_management/api/keys` — hold exactly these keys and no others.
///
/// What makes a galaxy have one place to manage keys, and the only thing that
/// makes a revocation reach a server that was offline for it: the periodic
/// offer of individual keys is additive and cannot delete.
///
/// **Refused unless this server has said it may be replaced.** `acl_replaceable`
/// in `[galaxy]` is off by default, because a server quietly having its keys
/// rewritten is not a state to arrive at by accident. With it off, the offer
/// falls back to being additive and nothing is lost.
///
/// Two guards, both the same shape as the ones on a single-key change:
///
///   * the set must contain an admin key, or nobody could use the interface
///     again;
///   * it must contain the key making the request, or the server doing the
///     replacing locks itself out of the server it just took over.
///
/// Keys removed are noted as revoked, so this server's own drift view can
/// point out any peer that still holds them.
pub async fn replace_keys(
    state: State,
    body: web::Json<KeyList>,
    req: HttpRequest,
) -> HttpResponse {
    let caller = match require_admin(&state, &req) {
        Ok(key) => key.to_string(),
        Err(resp) => return resp,
    };

    if !state.acl_replaceable {
        return HttpResponse::Forbidden().json(Message::new(concat!(
            "This server does not let another replace its keys. Set ",
            "acl_replaceable in [galaxy] if it should.",
        )));
    }

    let wanted = body.into_inner().keys;
    for entry in &wanted {
        if let Err(e) = entry.validate() {
            return HttpResponse::BadRequest().json(Message::new(e.to_string()));
        }
    }

    let mut acl = crate::acl::Acl::new();
    for entry in &wanted {
        acl.set(&entry.key, entry.to_grants());
    }

    if acl.admin_count() == 0 {
        return HttpResponse::Conflict().json(Message::new(
            "That set has no admin key, and would lock everyone out of this interface.",
        ));
    }
    if !acl.contains(&caller) {
        return HttpResponse::Conflict().json(Message::new(concat!(
            "That set does not include the key making this request, which would ",
            "lock the caller out of the server it is replacing.",
        )));
    }

    // What is going away, before it does, so the drift view can say which
    // peers still take it.
    let going: Vec<String> = state
        .acl()
        .entries()
        .iter()
        .map(|(key, _)| key.clone())
        .filter(|key| !acl.contains(key))
        .collect();

    if let Err(resp) = save_acl(&state, acl) {
        return resp;
    }
    for key in &going {
        state.note_revoked(key);
    }
    for entry in &wanted {
        state.note_unrevoked(&entry.key);
    }

    log::warn!(
        "Key list replaced by '{caller}': {} key(s) held, {} revoked",
        wanted.len(),
        going.len()
    );

    HttpResponse::Ok().json(serde_json::json!({
        "held": wanted.len(),
        "revoked": going,
    }))
}

/// A whole key list, for [`replace_keys`].
#[derive(Debug, Deserialize)]
pub struct KeyList {
    pub keys: Vec<KeyEntry>,
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
    // A key put back is not a stale revocation any more.
    state.note_unrevoked(&entry.key);
    gossip_key(&state, &req, &entry).await;
    HttpResponse::Ok().json(entry)
}

/// Pass a key change on to the peers this server administers.
///
/// After the change has been saved here, so a peer never hears about something
/// this server then failed to keep. Best effort: a peer that is down misses it
/// and picks it up from the periodic offer — see [`crate::galaxy::gossip`].
///
/// A change that *arrived* as gossip is passed along with one hop less, so a
/// cascade propagates and a cycle dies on the budget. A change made by a person
/// here starts with the full budget.
async fn gossip_key(state: &State, req: &HttpRequest, entry: &KeyEntry) {
    let Some(galaxy) = state.galaxy.as_ref() else {
        return;
    };
    let Some(hops) = crate::galaxy::hops_left(req, galaxy.max_hops()) else {
        return;
    };
    let report = galaxy.push_key(&serde_json::json!(entry), hops).await;
    if report.accepted > 0 || report.failed > 0 {
        log::info!(
            "Key '{}' passed to {} peer(s); {} could not take it, {} do not let this \
             server administer them",
            entry.key,
            report.accepted,
            report.failed,
            report.refused
        );
    }
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
    // Noted so the interface can point out a peer that still holds it: the
    // periodic offer never deletes, so a revocation missed while a peer was
    // down is the one thing here that is genuinely dangerous.
    state.note_revoked(&key);

    if let Some(galaxy) = state.galaxy.as_ref()
        && let Some(hops) = crate::galaxy::hops_left(&req, galaxy.max_hops())
    {
        let report = galaxy.push_key_removal(&key, hops).await;
        if report.accepted > 0 || report.failed > 0 {
            log::warn!(
                "Revocation of '{key}' passed to {} peer(s); {} could not take it, {} do \
                 not let this server administer them",
                report.accepted,
                report.failed,
                report.refused
            );
        }
    }

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

/// Change a shard's tier and write it back, so it survives a restart.
/// Set, change or clear the storage settings of the shard a namespace is in.
///
/// The tier decides whether the shard is kept in memory, and `warm_idle` how
/// long a warm one waits before being written out — the second being the thing
/// that could only be changed in the configuration file until now.
///
/// It applies to the whole top-level namespace, and the reply says so: a change
/// made from a row deep in a tree is a change to everything beside it, which is
/// better said than discovered.
pub async fn set_tier(state: State, body: web::Json<TierChange>, req: HttpRequest) -> HttpResponse {
    let caller = match require_admin(&state, &req) {
        Ok(key) => key.to_string(),
        Err(resp) => return resp,
    };

    let change = body.into_inner();
    let namespace = change.namespace.trim().trim_matches('/');
    if namespace.is_empty() {
        return HttpResponse::BadRequest().json(Message::new("Name the namespace to change."));
    }
    if namespace.starts_with('_') {
        return HttpResponse::BadRequest().json(Message::new(
            "Internal namespaces are always hot and cannot be retiered.",
        ));
    }
    let entry = match change.entry() {
        Ok(entry) => entry,
        Err(e) => return HttpResponse::BadRequest().json(Message::new(e)),
    };

    // Changing what a namespace costs to keep is a change to it.
    if let Err(resp) = require_write(&state, &caller, namespace) {
        return resp;
    }

    let Some(path) = state.tiers_file.as_ref() else {
        return HttpResponse::Conflict().json(Message::new(
            "No tiers_file is configured, so tiers cannot be changed here. Set tiers_file in \
             [storage] and restart.",
        ));
    };

    let shard = crate::persistence::shard_of(namespace).to_string();
    state.db.set_policy(&shard, entry);
    if let Err(e) = state.db.tier_policy().save(path) {
        log::error!("Could not write {}: {e:#}", path.display());
        return HttpResponse::InternalServerError()
            .json(Message::new(format!("Could not write the tier file: {e}")));
    }

    let resolved = state.db.resolved_policy(&shard);
    log::info!(
        "Storage of '{shard}' set to {} (warm_idle {}s) by '{caller}'",
        resolved.tier.as_str(),
        resolved.warm_idle,
    );

    // Passed on to the peers this server administers, under the same rule as a
    // key change: the peer's own ACL decides whether to accept it. A tier only
    // ever takes a value — there is no unset — so this needs no deletion to
    // chase, which is the one thing that made keys awkward.
    if let Some(galaxy) = state.galaxy.as_ref()
        && let Some(hops) = crate::galaxy::hops_left(&req, galaxy.max_hops())
    {
        let report = galaxy
            .push_tier(
                &serde_json::json!({
                    "namespace": shard,
                    "tier": resolved.tier.as_str(),
                    "warm_idle": resolved.warm_idle,
                }),
                hops,
            )
            .await;
        if report.accepted > 0 || report.failed > 0 {
            log::info!(
                "Storage of '{shard}' passed to {} peer(s); {} could not take it, {} do \
                 not let this server administer them",
                report.accepted,
                report.failed,
                report.refused
            );
        }
    }

    HttpResponse::Ok().json(serde_json::json!({
        "shard": shard,
        "tier": resolved.tier.as_str(),
        "warm_idle": resolved.warm_idle,
        "own_tier": resolved.own_tier.is_some(),
        "own_warm_idle": resolved.own_warm_idle.is_some(),
        "effect": state.db.shard_effect(&shard),
    }))
}

/// Register the admin routes.
pub fn routes(cfg: &mut web::ServiceConfig) {
    // Order matters: the catch-all must come last or it would swallow the API.
    cfg.route("/_management/echarts.min.js", web::get().to(echarts))
        .route("/_management/logo.png", web::get().to(logo))
        .route("/_management/api/session", web::get().to(session))
        .route("/_management/api/info", web::get().to(info))
        .route("/_management/api/namespaces", web::get().to(namespaces))
        .route(
            "/_management/api/namespaces",
            web::post().to(create_namespace),
        )
        .route("/_management/api/tree", web::get().to(tree))
        .route("/_management/api/galaxy", web::get().to(galaxy))
        .route("/_management/api/galaxy/peers", web::get().to(list_peers))
        .route("/_management/api/galaxy/peers", web::post().to(add_peer))
        .route("/_management/api/galaxy/peers", web::put().to(update_peer))
        .route(
            "/_management/api/galaxy/peers",
            web::delete().to(delete_peer),
        )
        .route(
            "/_management/api/galaxy/peers/enabled",
            web::post().to(set_peer_enabled),
        )
        .route("/_management/api/rejections", web::get().to(rejections))
        .route(
            "/_management/api/rejections",
            web::delete().to(clear_rejections),
        )
        .route("/_management/api/values", web::get().to(values))
        .route("/_management/api/values", web::post().to(add_values))
        .route("/_management/api/tags", web::post().to(set_tags))
        .route("/_management/api/tags", web::get().to(list_tags))
        .route(
            "/_management/api/tags/vocabulary",
            web::post().to(define_tag),
        )
        .route(
            "/_management/api/tags/vocabulary",
            web::delete().to(undefine_tag),
        )
        .route("/_management/api/value", web::get().to(value))
        .route("/_management/api/sightings", web::get().to(sightings))
        .route("/_management/api/keys", web::get().to(list_keys))
        .route("/_management/api/keys", web::post().to(save_key))
        .route("/_management/api/keys", web::put().to(replace_keys))
        .route(
            "/_management/api/keys/generate",
            web::get().to(generate_key),
        )
        // Before the `{key}` route, or "drift" would be taken for a key name.
        .route("/_management/api/keys/drift", web::get().to(key_drift))
        .route("/_management/api/keys/{key}", web::delete().to(delete_key))
        .route("/_management/api/tier", web::post().to(set_tier))
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

    /// The management routes *and* the data routes, for tests that drive a
    /// write and then ask the management interface what it made of it.
    macro_rules! app_with_data {
        ($state:expr) => {
            test::init_service(
                App::new()
                    .app_data($state.clone())
                    .configure(routes)
                    .configure(crate::handlers::routes),
            )
            .await
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

    /// The page must be revalidated, not reused.
    ///
    /// It is the whole application in one file, so a browser holding a cached
    /// copy runs the previous version's JavaScript against this version's
    /// API — which looks like the server being wrong rather than the page
    /// being old. With no cache header at all a browser decides for itself,
    /// and may decide not to ask.
    #[actix_web::test]
    async fn the_interface_is_not_cached_across_upgrades() {
        let st = state();
        let app = app!(st);

        let resp = get!(app, "/_management/", NO_KEY);
        assert_eq!(
            resp.headers()
                .get("Cache-Control")
                .and_then(|v| v.to_str().ok()),
            Some("no-cache"),
            "the management page may be served from a stale cache"
        );

        // The charting bundle does not change between builds and is big, so
        // it keeps its long expiry. If that ever flips, this says so.
        let resp = get!(app, "/_management/echarts.min.js", NO_KEY);
        assert!(
            resp.headers()
                .get("Cache-Control")
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| v.contains("max-age")),
            "the charting bundle lost its cache headers"
        );
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

    /// A paste reports what each value now stands at, so the interface does not
    /// have to read the values back to say what it just did.
    #[actix_web::test]
    async fn adding_values_reports_each_running_count() {
        let st = state();
        let app = app!(st);

        // `1.2.3.4` is already in `feeds/ips` once, from `state()`.
        let resp = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/_management/api/values")
                .insert_header(("Authorization", ADMIN))
                .set_json(serde_json::json!({
                    "namespace": "feeds/ips",
                    "values": ["1.2.3.4", "fresh", "   "],
                }))
                .to_request(),
        )
        .await;

        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value = test::read_body_json(resp).await;

        // The blank line was dropped before anything was tried.
        assert_eq!(body["written"], 2, "{body}");

        let counts = body["counts"].as_array().unwrap();
        assert_eq!(counts.len(), 2, "{body}");
        assert_eq!(counts[0]["value"], "1.2.3.4");
        assert_eq!(counts[0]["count"], 2, "an existing value was not added to");
        assert_eq!(counts[1]["value"], "fresh");
        assert_eq!(counts[1]["count"], 1, "{body}");

        // And the counts are what the database actually holds.
        assert_eq!(st.db.count("feeds/ips", "1.2.3.4"), 2);
        assert_eq!(st.db.count("feeds/ips", "fresh"), 1);
    }

    /// Every write path feeds the rejection log, and the log is what answers
    /// "which values errored" after the response has gone.
    #[actix_web::test]
    async fn rejections_are_listed_newest_first() {
        let st = state();
        let app = app_with_data!(st);

        // A rejection from the single-value route, and two from a bulk write.
        test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/w/feeds/ips?val=x&timestamp=99999999999999")
                .to_request(),
        )
        .await;
        test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/wb")
                .set_json(serde_json::json!({"items": [
                    {"namespace": "feeds/ips", "value": ""},
                    {"namespace": "_config/acl/apikeys/mine", "value": "sneaky"}
                ]}))
                .to_request(),
        )
        .await;

        let resp = get!(app, "/_management/api/rejections", Some(ADMIN));
        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value = test::read_body_json(resp).await;

        let found = body["rejections"].as_array().unwrap();
        assert_eq!(found.len(), 3, "{body}");
        assert_eq!(body["total"], 3, "{body}");
        assert_eq!(
            body["capacity"],
            crate::rejections::DEFAULT_CAPACITY,
            "{body}"
        );

        // Newest first.
        assert_eq!(found[0]["value"], "sneaky", "{body}");
        assert_eq!(found[0]["source"], "bulkwrite", "{body}");
        assert!(
            found[0]["reason"].as_str().unwrap().contains("_config"),
            "{body}"
        );

        // The empty value is kept as itself, which is the whole reason this is
        // not a namespace of sightings.
        assert_eq!(found[1]["value"], "", "{body}");

        assert_eq!(found[2]["value"], "x", "{body}");
        assert_eq!(found[2]["source"], "write", "{body}");
        assert!(found[2]["when"].as_i64().unwrap() > 0, "{body}");
    }

    /// A dry run writes nothing, so it must leave no rejections behind either
    /// — otherwise checking a batch would pollute the record of real failures,
    /// and anyone could flood it without writing a thing.
    #[actix_web::test]
    async fn a_dry_run_records_no_rejections() {
        let st = state();
        let app = app_with_data!(st);

        let resp = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/vwb")
                .set_json(serde_json::json!({"items": [
                    {"namespace": "feeds/ips", "value": ""}
                ]}))
                .to_request(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        assert_eq!(
            st.rejections.len(),
            0,
            "the dry run left a rejection behind"
        );
    }

    /// The management add path guards its namespace before it writes, so it
    /// cannot currently reach a rejection at all.
    ///
    /// Pinned because that is load-bearing for the claim above it: the
    /// recording wired into `add_values` is unreachable today and kept only so
    /// that loosening the guard does not silently lose the value. If this test
    /// starts failing, that path has become live and wants a test of its own.
    #[actix_web::test]
    async fn the_management_add_path_rejects_before_it_writes() {
        let st = state();
        let app = app!(st);

        let resp = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/_management/api/values")
                .insert_header(("Authorization", ADMIN))
                .set_json(serde_json::json!({
                    "namespace": "_config/acl/apikeys/mine",
                    "values": ["sneaky"],
                }))
                .to_request(),
        )
        .await;

        // Turned away by `clean_namespace`, not by the writer.
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(st.rejections.len(), 0, "a rejection was recorded after all");
        assert!(!st.db.namespace_exists("_config/acl/apikeys/mine"));
    }

    /// A rejection names a namespace and what someone tried to put in it, so a
    /// key that could not read that namespace must not see it here.
    #[actix_web::test]
    async fn rejections_are_filtered_by_what_the_key_may_read() {
        let st = state();
        st.rejections
            .record("feeds/ips", "a", "nope", crate::rejections::Source::Ingest);
        st.rejections
            .record("secrets", "b", "nope", crate::rejections::Source::Ingest);

        // An admin key scoped to `feeds` only.
        st.acl
            .write()
            .unwrap()
            .set("scoped", parse_grants("admin, rw:feeds").unwrap());
        let app = app!(st);

        let resp = get!(app, "/_management/api/rejections", Some("scoped"));
        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value = test::read_body_json(resp).await;
        let found = body["rejections"].as_array().unwrap();

        assert_eq!(found.len(), 1, "a scoped key saw another subtree: {body}");
        assert_eq!(found[0]["namespace"], "feeds/ips", "{body}");

        // The full-access key sees both.
        let resp = get!(app, "/_management/api/rejections", Some(ADMIN));
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["rejections"].as_array().unwrap().len(), 2, "{body}");
    }

    /// Asking for one subtree must be authorized like any other read of it —
    /// including the answer, which is `404` rather than `403` throughout the
    /// management interface so that browsing cannot enumerate what is out of
    /// reach. See [`require_read`].
    #[actix_web::test]
    async fn filtering_by_a_namespace_needs_read_access_to_it() {
        let st = state();
        st.acl
            .write()
            .unwrap()
            .set("scoped", parse_grants("admin, rw:feeds").unwrap());
        let app = app!(st);

        let resp = get!(
            app,
            "/_management/api/rejections?namespace=secrets",
            Some("scoped")
        );
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[actix_web::test]
    async fn rejections_can_be_cleared() {
        let st = state();
        st.rejections
            .record("feeds/ips", "a", "nope", crate::rejections::Source::Ingest);
        st.acl
            .write()
            .unwrap()
            .set("scoped", parse_grants("admin, rw:feeds").unwrap());
        let app = app!(st);

        // A scoped key cannot clear what it cannot wholly see.
        let resp = test::call_service(
            &app,
            test::TestRequest::delete()
                .uri("/_management/api/rejections")
                .insert_header(("Authorization", "scoped"))
                .to_request(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert_eq!(st.rejections.len(), 1);

        let resp = test::call_service(
            &app,
            test::TestRequest::delete()
                .uri("/_management/api/rejections")
                .insert_header(("Authorization", ADMIN))
                .to_request(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(st.rejections.len(), 0);
    }

    /// A server that has not opted in keeps its own keys, whoever asks.
    ///
    /// The default, because a server quietly having its key list rewritten is
    /// not a state to arrive at by accident.
    #[actix_web::test]
    async fn keys_cannot_be_replaced_unless_the_server_allows_it() {
        let st = state();
        let app = app!(st);

        let resp = test::call_service(
            &app,
            test::TestRequest::put()
                .uri("/_management/api/keys")
                .insert_header(("Authorization", ADMIN))
                .set_json(serde_json::json!({"keys": [
                    {"key": ADMIN, "admin": true, "read": [""], "write": [""]}
                ]}))
                .to_request(),
        )
        .await;

        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert!(
            body["message"]
                .as_str()
                .unwrap()
                .contains("acl_replaceable"),
            "the refusal does not say how to allow it: {body}"
        );
    }

    /// With it allowed, a replace removes what is not in the set — which is
    /// the whole reason it exists, since offering keys one at a time cannot
    /// delete and so cannot carry a revocation to a server that was offline.
    #[actix_web::test]
    async fn an_allowed_replace_removes_what_is_not_offered() {
        let mut inner = SharedState::new(false);
        inner.acl.get_mut().unwrap().grant_full(ADMIN);
        inner
            .acl
            .get_mut()
            .unwrap()
            .set("doomed", parse_grants("rw:feeds").unwrap());
        let dir = TempDir::new("replace");
        inner.acl_file = Some(dir.0.join("acl.toml"));
        inner.acl_replaceable = true;
        let st: State = web::Data::new(inner);
        let app = app!(st);

        let resp = test::call_service(
            &app,
            test::TestRequest::put()
                .uri("/_management/api/keys")
                .insert_header(("Authorization", ADMIN))
                .set_json(serde_json::json!({"keys": [
                    {"key": ADMIN, "admin": true, "read": [""], "write": [""]},
                    {"key": "kept", "admin": false, "read": ["feeds"], "write": []}
                ]}))
                .to_request(),
        )
        .await;

        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["held"], 2, "{body}");
        assert_eq!(body["revoked"][0], "doomed", "{body}");

        let acl = st.acl();
        assert!(acl.contains("kept"));
        assert!(!acl.contains("doomed"), "the revocation did not land");
        drop(acl);

        // Noted, so this server's drift view can point out a peer that still
        // takes it.
        assert!(st.revoked_keys().contains(&"doomed".to_string()));
    }

    /// A replace that would lock the interface or the caller out is refused,
    /// the same way a single-key change is.
    #[actix_web::test]
    async fn a_replace_cannot_lock_anyone_out() {
        let dir = TempDir::new("lockout");
        let fresh = || {
            let mut inner = SharedState::new(false);
            inner.acl.get_mut().unwrap().grant_full(ADMIN);
            inner.acl_file = Some(dir.0.join("acl.toml"));
            inner.acl_replaceable = true;
            web::Data::new(inner) as State
        };

        // No admin at all.
        let st = fresh();
        let app = app!(st);
        let resp = test::call_service(
            &app,
            test::TestRequest::put()
                .uri("/_management/api/keys")
                .insert_header(("Authorization", ADMIN))
                .set_json(serde_json::json!({"keys": [
                    {"key": "reader", "admin": false, "read": ["feeds"], "write": []}
                ]}))
                .to_request(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CONFLICT);
        assert!(st.acl().contains(ADMIN), "the ACL was replaced anyway");

        // An admin, but not the caller: the server replacing it would lose its
        // own way in.
        let st = fresh();
        let app = app!(st);
        let resp = test::call_service(
            &app,
            test::TestRequest::put()
                .uri("/_management/api/keys")
                .insert_header(("Authorization", ADMIN))
                .set_json(serde_json::json!({"keys": [
                    {"key": "someone-else", "admin": true, "read": [""], "write": [""]}
                ]}))
                .to_request(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CONFLICT);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert!(
            body["message"]
                .as_str()
                .unwrap()
                .contains("making this request"),
            "{body}"
        );
        assert!(st.acl().contains(ADMIN));
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

    // -- galaxy peers -------------------------------------------------------

    /// A router with a peers file and one peer declared in the configuration,
    /// so both the editable and the read-only case are present.
    fn peered_state(dir: &std::path::Path) -> State {
        let mut inner = SharedState::new(true);
        inner.acl.get_mut().unwrap().grant_full(ADMIN);
        inner.info.listen = "127.0.0.1:9999".to_string();
        inner.galaxy_peers_file = Some(dir.join("peers.toml"));
        inner.galaxy = Some(crate::galaxy::Galaxy::new(&crate::config::GalaxySettings {
            peers: vec![crate::config::Peer {
                url: "http://from-the-file:9999".to_string(),
                key: "k".to_string(),
                stores: crate::db::StoragePolicy::everything(),
                enabled: true,
            }],
            peers_file: Some(dir.join("peers.toml")),
            fixed: vec!["http://from-the-file:9999".to_string()],
            max_hops: 4,
            health_interval: 30,
            sync_interval: 0,
            reconcile_interval: 0,
            gossip_interval: 0,
            acl_authority: false,
            acl_replaceable: false,
            verify_tls: true,
        }));
        web::Data::new(inner)
    }

    macro_rules! peer {
        ($app:expr, $method:ident, $body:expr) => {
            test::call_service(
                &$app,
                test::TestRequest::$method()
                    .uri("/_management/api/galaxy/peers")
                    .insert_header(("Authorization", ADMIN))
                    .set_json($body)
                    .to_request(),
            )
            .await
        };
    }

    /// A peer added here is in effect at once and written down, so it survives
    /// a restart. Both halves matter: in effect but unwritten would vanish,
    /// written but not in effect would need a restart.
    #[actix_web::test]
    async fn a_peer_added_here_takes_effect_and_is_written() {
        let dir = TempDir::new("peers-add");
        let st = peered_state(&dir.0);
        let app = app!(st);

        let resp = peer!(
            app,
            post,
            serde_json::json!({"url": "http://added:9999", "key": "secret"})
        );
        assert_eq!(resp.status(), StatusCode::OK);

        // In effect: the galaxy will forward to it now.
        assert!(
            st.galaxy
                .as_ref()
                .unwrap()
                .holders("feeds/ips")
                .iter()
                .any(|peer| peer.url == "http://added:9999"),
            "the new peer is not being used for forwarding"
        );

        // Written down, with its key, which is what a restart needs.
        let written = std::fs::read_to_string(dir.0.join("peers.toml")).expect("the file");
        assert!(written.contains("http://added:9999"), "{written}");
        assert!(written.contains("secret"), "{written}");
        // And *without* the peer the configuration owns, which would otherwise
        // be declared in two files.
        assert!(
            !written.contains("from-the-file"),
            "a configured peer was copied into the machine-owned file: {written}"
        );
    }

    /// Adding and changing are separate verbs: an address typed into the add
    /// form must not silently replace an existing peer's key, which is the one
    /// thing bounding what this server may do there.
    #[actix_web::test]
    async fn adding_a_peer_that_exists_is_refused_rather_than_an_upsert() {
        let dir = TempDir::new("peers-twice");
        let st = peered_state(&dir.0);
        let app = app!(st);

        peer!(
            app,
            post,
            serde_json::json!({"url": "http://added:9999", "key": "first"})
        );
        let resp = peer!(
            app,
            post,
            serde_json::json!({"url": "http://added:9999", "key": "second"})
        );
        assert_eq!(resp.status(), StatusCode::CONFLICT);

        // The original key is intact.
        let written = std::fs::read_to_string(dir.0.join("peers.toml")).unwrap();
        assert!(written.contains("first"), "{written}");
        assert!(!written.contains("second"), "{written}");
    }

    #[actix_web::test]
    async fn changing_a_peer_keeps_one_entry() {
        let dir = TempDir::new("peers-put");
        let st = peered_state(&dir.0);
        let app = app!(st);

        peer!(
            app,
            post,
            serde_json::json!({"url": "http://added:9999", "key": "first"})
        );
        let resp = peer!(
            app,
            put,
            serde_json::json!({"url": "http://added:9999", "key": "second"})
        );
        assert_eq!(resp.status(), StatusCode::OK);

        let body: Json = test::read_body_json(resp).await;
        let urls: Vec<&str> = body["peers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p["url"].as_str().unwrap())
            .collect();
        assert_eq!(urls, vec!["http://from-the-file:9999", "http://added:9999"]);

        let written = std::fs::read_to_string(dir.0.join("peers.toml")).unwrap();
        assert!(written.contains("second"), "{written}");
    }

    #[actix_web::test]
    async fn changing_a_peer_that_is_not_there_is_not_an_add() {
        let dir = TempDir::new("peers-put-missing");
        let st = peered_state(&dir.0);
        let app = app!(st);

        let resp = peer!(
            app,
            put,
            serde_json::json!({"url": "http://nowhere:9999", "key": "k"})
        );
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    /// A peer from the hand-maintained configuration is shown but not
    /// editable: "removing" it here would last until the next restart, which
    /// is worse than refusing.
    #[actix_web::test]
    async fn a_configured_peer_cannot_be_changed_or_removed_here() {
        let dir = TempDir::new("peers-fixed");
        let st = peered_state(&dir.0);
        let app = app!(st);

        let body: Json =
            test::read_body_json(get!(app, "/_management/api/galaxy/peers", Some(ADMIN))).await;
        assert_eq!(body["peers"][0]["fixed"], true);

        let resp = test::call_service(
            &app,
            test::TestRequest::delete()
                .uri("/_management/api/galaxy/peers?url=http://from-the-file:9999")
                .insert_header(("Authorization", ADMIN))
                .to_request(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CONFLICT);
        let body: Json = test::read_body_json(resp).await;
        assert!(
            body["message"].as_str().unwrap().contains("configuration"),
            "the refusal should say where it came from: {body}"
        );

        let resp = peer!(
            app,
            put,
            serde_json::json!({"url": "http://from-the-file:9999", "key": "k"})
        );
        assert_eq!(resp.status(), StatusCode::CONFLICT);
    }

    /// Its own address is refused, because a server mirroring itself is never
    /// what was meant.
    #[actix_web::test]
    async fn a_server_cannot_be_added_to_its_own_galaxy() {
        let dir = TempDir::new("peers-self");
        let st = peered_state(&dir.0);
        let app = app!(st);

        let resp = peer!(
            app,
            post,
            serde_json::json!({"url": "http://127.0.0.1:9999", "key": "k"})
        );
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body: Json = test::read_body_json(resp).await;
        assert!(
            body["message"].as_str().unwrap().contains("own address"),
            "{body}"
        );
    }

    #[actix_web::test]
    async fn a_peer_needs_a_key_and_a_real_url() {
        let dir = TempDir::new("peers-bad");
        let st = peered_state(&dir.0);
        let app = app!(st);

        for body in [
            serde_json::json!({"url": "http://ok:9999", "key": ""}),
            serde_json::json!({"url": "ok:9999", "key": "k"}),
            serde_json::json!({"url": "", "key": "k"}),
        ] {
            let resp = peer!(app, post, body.clone());
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "accepted {body}");
        }
    }

    /// The key is a credential this server holds. A topology view is not a
    /// reason to hand it back out.
    #[actix_web::test]
    async fn a_peers_key_is_never_sent_back() {
        let dir = TempDir::new("peers-secret");
        let st = peered_state(&dir.0);
        let app = app!(st);

        peer!(
            app,
            post,
            serde_json::json!({"url": "http://added:9999", "key": "do-not-leak"})
        );
        let resp = get!(app, "/_management/api/galaxy/peers", Some(ADMIN));
        let body = test::read_body(resp).await;
        let text = String::from_utf8_lossy(&body);
        assert!(
            !text.contains("do-not-leak"),
            "a peer key was returned: {text}"
        );
    }

    /// Without a peers file the list is read-only, and the interface is told
    /// so rather than finding out when a save fails.
    #[actix_web::test]
    async fn peers_are_read_only_without_a_peers_file() {
        let st = state();
        let app = app!(st);

        let body: Json =
            test::read_body_json(get!(app, "/_management/api/galaxy/peers", Some(ADMIN))).await;
        assert_eq!(body["editable"], false);
        assert!(body["note"].as_str().is_some(), "{body}");

        let resp = peer!(
            app,
            post,
            serde_json::json!({"url": "http://x:1", "key": "k"})
        );
        assert_eq!(resp.status(), StatusCode::CONFLICT);
    }

    #[actix_web::test]
    async fn the_peer_list_needs_a_key() {
        let st = state();
        let app = app!(st);
        assert_eq!(
            get!(app, "/_management/api/galaxy/peers", NO_KEY).status(),
            StatusCode::UNAUTHORIZED
        );
    }

    // -- the tag vocabulary -------------------------------------------------

    /// State with a real tags_file and some tagged values, so the table has
    /// something to count.
    fn tagged_state(dir: &std::path::Path) -> State {
        let mut inner = SharedState::new(true);
        inner.acl.get_mut().unwrap().grant_full(ADMIN);
        inner.tags_file = Some(dir.join("tags.toml"));
        inner.db.write_tagged(
            "feeds/ips",
            "1.1.1.1",
            chrono::Utc::now(),
            crate::db::WriteOpts::default(),
            "tlp:green,stix-type:ipv4-addr",
        );
        inner.db.write_tagged(
            "feeds/ips",
            "2.2.2.2",
            chrono::Utc::now(),
            crate::db::WriteOpts::default(),
            "tlp:green,home-grown",
        );
        web::Data::new(inner)
    }

    fn row<'a>(body: &'a Json, name: &str) -> &'a Json {
        body["tags"]
            .as_array()
            .expect("tags")
            .iter()
            .find(|t| t["name"] == name)
            .unwrap_or_else(|| panic!("no row for {name} in {body}"))
    }

    /// The table shows what is defined *and* what turned up on values, because
    /// a feed brings tags nobody defined and those are the ones worth seeing.
    #[actix_web::test]
    async fn the_tags_table_lists_defined_and_merely_seen_tags() {
        let dir = TempDir::new("tags-list");
        let st = tagged_state(&dir.0);
        let app = app!(st);

        let resp = get!(app, "/_management/api/tags", Some(ADMIN));
        assert_eq!(resp.status(), StatusCode::OK);
        let body: Json = test::read_body_json(resp).await;

        // Defined by the seed, and in use.
        assert_eq!(row(&body, "tlp:green")["used"], 2);
        assert_eq!(row(&body, "tlp:green")["defined"], true);
        // On a value, defined by nobody.
        assert_eq!(row(&body, "home-grown")["used"], 1);
        assert_eq!(row(&body, "home-grown")["defined"], false);
        // Defined and unused: still listed, with no count.
        assert_eq!(row(&body, "tlp:amber")["used"], Json::Null);
        assert_eq!(body["editable"], true);
    }

    /// A family's count is everything under it, which is the only number that
    /// means anything for a name no value carries literally.
    #[actix_web::test]
    async fn a_family_counts_the_tags_beneath_it() {
        let dir = TempDir::new("tags-family");
        let st = tagged_state(&dir.0);
        let app = app!(st);

        let body: Json =
            test::read_body_json(get!(app, "/_management/api/tags", Some(ADMIN))).await;
        assert_eq!(row(&body, "stix-type:")["family"], true);
        assert_eq!(row(&body, "stix-type:")["used"], 1);
    }

    /// A definition lands on disk and takes effect at once, like a key.
    #[actix_web::test]
    async fn a_defined_tag_is_written_and_adopted() {
        let dir = TempDir::new("tags-define");
        let st = tagged_state(&dir.0);
        let app = app!(st);

        let resp = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/_management/api/tags/vocabulary")
                .insert_header(("Authorization", ADMIN))
                .set_json(serde_json::json!({
                    "name": "home-grown",
                    "colour": "#AA33CC",
                    "description": "Ours, not from a feed."
                }))
                .to_request(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);

        // Answered with the whole table, so the interface need not refetch.
        let body: Json = test::read_body_json(resp).await;
        assert_eq!(row(&body, "home-grown")["defined"], true);
        assert_eq!(row(&body, "home-grown")["colour"], "#aa33cc");
        assert_eq!(row(&body, "home-grown")["used"], 1, "it was already in use");

        let written = std::fs::read_to_string(dir.0.join("tags.toml")).expect("the file");
        assert!(written.contains("home-grown"), "{written}");
        assert!(written.contains("#aa33cc"), "{written}");
        // In effect without a restart.
        assert_eq!(
            st.tags.read().unwrap().colour_of("home-grown"),
            Some("#aa33cc")
        );
    }

    /// A disabled peer is kept and is sent nothing.
    ///
    /// Both halves matter. Sent nothing, or disabling did not do anything;
    /// kept, or it is just a slower way of removing it — and the point is to
    /// be able to put it back without finding its key again.
    #[actix_web::test]
    async fn a_disabled_peer_is_kept_and_sent_nothing() {
        let dir = TempDir::new("peers-disable");
        let st = peered_state(&dir.0);
        let app = app!(st);

        peer!(
            app,
            post,
            serde_json::json!({"url": "http://added:9999", "key": "secret"})
        );
        let galaxy = st.galaxy.as_ref().unwrap();
        assert!(
            galaxy
                .holders("feeds/ips")
                .iter()
                .any(|p| p.url == "http://added:9999"),
            "it should be a holder before being disabled"
        );

        let resp = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/_management/api/galaxy/peers/enabled")
                .insert_header(("Authorization", ADMIN))
                .set_json(serde_json::json!({"url": "http://added:9999", "enabled": false}))
                .to_request(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);

        // Nothing is routed to it any more.
        assert!(
            !galaxy
                .holders("feeds/ips")
                .iter()
                .any(|p| p.url == "http://added:9999"),
            "a disabled peer is still being forwarded to"
        );
        // And nothing else reaches for it either: catch-up, gossip and the
        // health poller all read `peers()`.
        assert!(
            !galaxy.peers().iter().any(|p| p.url == "http://added:9999"),
            "a disabled peer is still in the list the background tasks use"
        );

        // But it is still there, with its key, and still listed.
        assert!(
            galaxy
                .all_peers()
                .iter()
                .any(|p| p.url == "http://added:9999" && p.key == "secret"),
            "the peer was forgotten rather than disabled"
        );
        let body: Json = test::read_body_json(resp).await;
        let row = body["peers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["url"] == "http://added:9999")
            .expect("still listed");
        assert_eq!(row["enabled"], false);
    }

    /// Disabling it must survive a restart, which means it has to be written
    /// to the peers file — and the peer must still be *in* that file, which is
    /// the trap: the file is rewritten from the editable peers, and leaving
    /// disabled ones out would delete them.
    #[actix_web::test]
    async fn a_disabled_peer_stays_in_the_peers_file() {
        let dir = TempDir::new("peers-disable-file");
        let st = peered_state(&dir.0);
        let app = app!(st);

        peer!(
            app,
            post,
            serde_json::json!({"url": "http://added:9999", "key": "secret"})
        );
        test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/_management/api/galaxy/peers/enabled")
                .insert_header(("Authorization", ADMIN))
                .set_json(serde_json::json!({"url": "http://added:9999", "enabled": false}))
                .to_request(),
        )
        .await;

        let written = std::fs::read_to_string(dir.0.join("peers.toml")).expect("the file");
        assert!(
            written.contains("http://added:9999"),
            "disabling the peer deleted it from the file: {written}"
        );
        assert!(
            written.contains("secret"),
            "its key went with it: {written}"
        );
        assert!(
            written.contains("enabled = false"),
            "it would come back enabled: {written}"
        );

        // And the file reads back as a disabled peer.
        let reloaded: crate::config::PeersFile = toml::from_str(&written).expect("parses");
        let entry = reloaded
            .peers
            .iter()
            .find(|p| p.url == "http://added:9999")
            .expect("in the file");
        assert_eq!(entry.enabled, Some(false));
    }

    /// Enabling it again puts it back, and the toggle is idempotent.
    #[actix_web::test]
    async fn enabling_a_peer_puts_it_back() {
        let dir = TempDir::new("peers-enable");
        let st = peered_state(&dir.0);
        let app = app!(st);

        peer!(
            app,
            post,
            serde_json::json!({"url": "http://added:9999", "key": "secret"})
        );
        let toggle =
            |enabled: bool| serde_json::json!({"url": "http://added:9999", "enabled": enabled});
        let send = |body: serde_json::Value| {
            test::TestRequest::post()
                .uri("/_management/api/galaxy/peers/enabled")
                .insert_header(("Authorization", ADMIN))
                .set_json(body)
                .to_request()
        };

        test::call_service(&app, send(toggle(false))).await;
        // Twice: a button pressed again is not an error.
        let resp = test::call_service(&app, send(toggle(false))).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let resp = test::call_service(&app, send(toggle(true))).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(
            st.galaxy
                .as_ref()
                .unwrap()
                .holders("feeds/ips")
                .iter()
                .any(|p| p.url == "http://added:9999"),
            "enabling it did not put it back into routing"
        );

        let written = std::fs::read_to_string(dir.0.join("peers.toml")).unwrap();
        assert!(
            !written.contains("enabled = false"),
            "it would come back disabled: {written}"
        );
    }

    /// Changing a peer's key must not quietly put a disabled one back into
    /// service: those are two different decisions.
    #[actix_web::test]
    async fn editing_a_disabled_peer_leaves_it_disabled() {
        let dir = TempDir::new("peers-edit-disabled");
        let st = peered_state(&dir.0);
        let app = app!(st);

        peer!(
            app,
            post,
            serde_json::json!({"url": "http://added:9999", "key": "first"})
        );
        test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/_management/api/galaxy/peers/enabled")
                .insert_header(("Authorization", ADMIN))
                .set_json(serde_json::json!({"url": "http://added:9999", "enabled": false}))
                .to_request(),
        )
        .await;

        let resp = peer!(
            app,
            put,
            serde_json::json!({"url": "http://added:9999", "key": "rotated"})
        );
        assert_eq!(resp.status(), StatusCode::OK);

        let body: Json = test::read_body_json(resp).await;
        let row = body["peers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["url"] == "http://added:9999")
            .expect("listed");
        assert_eq!(
            row["enabled"], false,
            "rotating the key put the peer back into service: {body}"
        );
    }

    #[actix_web::test]
    async fn a_configured_peer_cannot_be_disabled_here() {
        let dir = TempDir::new("peers-disable-fixed");
        let st = peered_state(&dir.0);
        let app = app!(st);

        let resp = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/_management/api/galaxy/peers/enabled")
                .insert_header(("Authorization", ADMIN))
                .set_json(serde_json::json!({"url": "http://from-the-file:9999", "enabled": false}))
                .to_request(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CONFLICT);
        let body: Json = test::read_body_json(resp).await;
        assert!(
            body["message"]
                .as_str()
                .unwrap()
                .contains("enabled = false"),
            "the refusal should say how to do it instead: {body}"
        );
    }

    #[actix_web::test]
    async fn disabling_a_peer_that_is_not_there_is_not_found() {
        let dir = TempDir::new("peers-disable-missing");
        let st = peered_state(&dir.0);
        let app = app!(st);

        let resp = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/_management/api/galaxy/peers/enabled")
                .insert_header(("Authorization", ADMIN))
                .set_json(serde_json::json!({"url": "http://nowhere:9999", "enabled": false}))
                .to_request(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    /// Removing a colour must not remove the tag from the values, which would
    /// make a colour picker delete data.
    #[actix_web::test]
    async fn undefining_a_tag_leaves_it_on_the_values() {
        let dir = TempDir::new("tags-undefine");
        let st = tagged_state(&dir.0);
        let app = app!(st);

        let resp = test::call_service(
            &app,
            test::TestRequest::delete()
                .uri("/_management/api/tags/vocabulary?tag=tlp:green")
                .insert_header(("Authorization", ADMIN))
                .to_request(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);

        let body: Json = test::read_body_json(resp).await;
        // Still in the table, because values still carry it -- just undefined.
        assert_eq!(row(&body, "tlp:green")["defined"], false);
        assert_eq!(row(&body, "tlp:green")["used"], 2);

        let view = st.db.view("feeds/ips", "1.1.1.1", 0, false).expect("value");
        assert!(
            view.tags.contains("tlp:green"),
            "the tag was taken off the value: {}",
            view.tags
        );
    }

    #[actix_web::test]
    async fn a_tag_that_was_never_defined_cannot_be_undefined() {
        let dir = TempDir::new("tags-missing");
        let st = tagged_state(&dir.0);
        let app = app!(st);

        let resp = test::call_service(
            &app,
            test::TestRequest::delete()
                .uri("/_management/api/tags/vocabulary?tag=never-existed")
                .insert_header(("Authorization", ADMIN))
                .to_request(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    /// Without a `tags_file` the colours are read-only, and the interface is
    /// told so rather than finding out when a save fails.
    #[actix_web::test]
    async fn colours_are_read_only_without_a_tags_file() {
        let st = state();
        let app = app!(st);

        let body: Json =
            test::read_body_json(get!(app, "/_management/api/tags", Some(ADMIN))).await;
        assert_eq!(body["editable"], false);

        let resp = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/_management/api/tags/vocabulary")
                .insert_header(("Authorization", ADMIN))
                .set_json(serde_json::json!({"name": "x", "colour": "#ffffff"}))
                .to_request(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CONFLICT);
        let body: Json = test::read_body_json(resp).await;
        assert!(
            body["message"].as_str().unwrap().contains("tags_file"),
            "the refusal should name the setting: {body}"
        );
    }

    /// The vocabulary is server-wide, so a key that cannot read everywhere
    /// would learn from the counts which tags exist in namespaces it has no
    /// access to.
    #[actix_web::test]
    async fn a_scoped_key_sees_no_usage_counts() {
        let dir = TempDir::new("tags-scoped");
        let st = tagged_state(&dir.0);
        st.acl
            .write()
            .unwrap()
            .set("scoped", parse_grants("admin, rw:other").unwrap());
        let app = app!(st);

        let body: Json =
            test::read_body_json(get!(app, "/_management/api/tags", Some("scoped"))).await;
        assert_eq!(
            row(&body, "tlp:green")["used"],
            Json::Null,
            "a scoped key was told how many values carry a tag"
        );
        // The vocabulary itself is not a secret.
        assert_eq!(row(&body, "tlp:green")["defined"], true);
    }

    /// A router's Tags page must say that its counts are its own.
    ///
    /// They are of what this server holds, and a router holds nothing — while
    /// `counted_namespaces == total_namespaces` makes that look complete
    /// rather than local. Without a word of explanation the page reads as
    /// "the galaxy has these tags".
    #[actix_web::test]
    async fn a_router_says_its_tag_counts_are_local() {
        let dir = TempDir::new("tags-scope");
        let mut inner = SharedState::new(true);
        inner.acl.get_mut().unwrap().grant_full(ADMIN);
        inner.tags_file = Some(dir.0.join("tags.toml"));
        inner.db = crate::db::Database::with_storage(
            crate::db::DatabasePolicy::default(),
            crate::db::StoragePolicy::from_prefixes(Vec::<&str>::new()),
        );
        let st: State = web::Data::new(inner);
        let app = app!(st);

        let body: Json =
            test::read_body_json(get!(app, "/_management/api/tags", Some(ADMIN))).await;
        let scope = body["scope"].as_str().unwrap_or_default();
        assert!(
            scope.contains("stores nothing of its own"),
            "a router did not say its counts are local: {body}"
        );
    }

    /// A partial mirror says which namespaces its counts cover.
    #[actix_web::test]
    async fn a_partial_mirror_says_which_namespaces_it_counted() {
        let dir = TempDir::new("tags-partial");
        let mut inner = SharedState::new(true);
        inner.acl.get_mut().unwrap().grant_full(ADMIN);
        inner.tags_file = Some(dir.0.join("tags.toml"));
        inner.db = crate::db::Database::with_storage(
            crate::db::DatabasePolicy::default(),
            crate::db::StoragePolicy::from_prefixes(["feeds"]),
        );
        let st: State = web::Data::new(inner);
        let app = app!(st);

        let body: Json =
            test::read_body_json(get!(app, "/_management/api/tags", Some(ADMIN))).await;
        let scope = body["scope"].as_str().unwrap_or_default();
        assert!(scope.contains("feeds"), "{body}");
    }

    /// A server that stores everything has nothing to explain, so it says
    /// nothing — a note on every page would stop being read.
    #[actix_web::test]
    async fn a_full_mirror_has_no_scope_note() {
        let dir = TempDir::new("tags-full");
        let st = tagged_state(&dir.0);
        let app = app!(st);

        let body: Json =
            test::read_body_json(get!(app, "/_management/api/tags", Some(ADMIN))).await;
        assert!(body.get("scope").is_none(), "{body}");
    }

    /// No message this server sends has a run of spaces baked into it.
    ///
    /// A long string written with `\` line continuations reads fine in the
    /// source and then `cargo fmt` joins the lines, keeping the indentation
    /// inside the literal — so the text that reaches a user has twelve spaces
    /// in the middle of a sentence. That has happened three times in this
    /// file alone, and it is invisible in review because the source still
    /// looks right. `concat!` of one-line pieces is the way to write them.
    ///
    /// Scoped to the two modules that produce HTTP messages. `setup.rs` is
    /// excluded on purpose: its output is a column-aligned summary where runs
    /// of spaces are the point.
    // `#[test]` resolves to actix-web's attribute in this module, because
    // `test` is imported above — so this is async like every other test here,
    // even though it touches nothing async.
    #[actix_web::test]
    async fn no_message_has_collapsed_whitespace_in_it() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut found = Vec::new();

        for name in ["src/admin/mod.rs", "src/handlers.rs"] {
            let text = std::fs::read_to_string(root.join(name)).expect(name);
            for (number, line) in text.lines().enumerate() {
                if line.trim_start().starts_with("//") {
                    continue;
                }
                // Every string literal on the line. Odd pieces of a split on
                // the quote are the contents.
                for piece in line.split('"').skip(1).step_by(2) {
                    let chars: Vec<char> = piece.chars().collect();
                    let mut at = 0;
                    while at < chars.len() {
                        if chars[at] != ' ' {
                            at += 1;
                            continue;
                        }
                        // Measure the whole run. A fixed-size window would
                        // only ever catch a run of exactly that size, which
                        // is how the first two versions of this test passed
                        // on the very damage they were written to find — the
                        // real cases are six spaces, not three.
                        let from = at;
                        while at < chars.len() && chars[at] == ' ' {
                            at += 1;
                        }
                        if at - from < 3 {
                            continue;
                        }
                        // Punctuation counts as the end of a word: the
                        // real cases wrap after a full stop.
                        let before = from.checked_sub(1).map(|j| chars[j]);
                        let after = chars.get(at).copied();
                        if before.is_some_and(|c| c.is_alphanumeric() || ".,;:!?)]".contains(c))
                            && after.is_some_and(|c| c.is_alphabetic())
                        {
                            found.push(format!("{name}:{}: {piece}", number + 1));
                            break;
                        }
                    }
                }
            }
        }

        assert!(
            found.is_empty(),
            "these messages have whitespace baked in, almost certainly from a \n\
             line continuation that cargo fmt joined. Write them with concat! of \n\
             one-line pieces instead:\n{}",
            found.join("\n")
        );
    }

    #[actix_web::test]
    async fn the_tags_table_needs_a_key() {
        let st = state();
        let app = app!(st);
        assert_eq!(
            get!(app, "/_management/api/tags", NO_KEY).status(),
            StatusCode::UNAUTHORIZED
        );
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

    // -- tiers -------------------------------------------------------------

    fn tiered_state(dir: &std::path::Path) -> State {
        let mut inner = SharedState::new(true);
        inner.acl.get_mut().unwrap().grant_full(ADMIN);
        inner.tiers_file = Some(dir.join("tiers.toml"));
        inner.db.write(
            "myorg/one",
            "v",
            Utc::now(),
            WriteOpts {
                consensus: true,
                ttl: None,
            },
        );
        web::Data::new(inner)
    }

    macro_rules! post_tier {
        ($app:expr, $body:expr, $key:expr) => {
            test::call_service(
                &$app,
                test::TestRequest::post()
                    .uri("/_management/api/tier")
                    .insert_header(("Authorization", $key))
                    .set_json($body)
                    .to_request(),
            )
            .await
        };
    }

    #[actix_web::test]
    async fn a_namespace_listing_carries_its_tier_and_residency() {
        let dir = TempDir::new("tierlist");
        let st = tiered_state(&dir.0);
        let app = app!(st);

        let body: Json =
            test::read_body_json(get!(app, "/_management/api/namespaces", Some(ADMIN))).await;
        let item = &body["items"][0];

        assert_eq!(item["namespace"], "myorg/one");
        // The tier belongs to the top-level namespace, which the row names so
        // the interface can say what a change will affect.
        assert_eq!(item["shard"], "myorg");
        assert_eq!(item["tier"], "hot");
        assert_eq!(item["resident"], true);
    }

    #[actix_web::test]
    async fn a_tier_change_takes_effect_and_is_written_out() {
        let dir = TempDir::new("tierset");
        let st = tiered_state(&dir.0);
        let app = app!(st);

        let resp = post_tier!(app, json!({"shard": "myorg", "tier": "cold"}), ADMIN);
        assert_eq!(resp.status(), StatusCode::OK);
        let body: Json =
            test::read_body_json(get!(app, "/_management/api/namespaces", Some(ADMIN))).await;
        assert_eq!(body["items"][0]["tier"], "cold");

        let written = std::fs::read_to_string(dir.0.join("tiers.toml")).unwrap();
        assert!(written.contains("\"myorg\" = \"cold\""), "{written}");
    }

    #[actix_web::test]
    async fn the_idle_window_can_be_changed_and_cleared() {
        let dir = TempDir::new("tieridle");
        let st = tiered_state(&dir.0);
        let app = app!(st);

        // The thing that could only be set in the configuration file before.
        let resp = post_tier!(
            app,
            json!({"namespace": "myorg/one", "tier": "warm", "warm_idle": 86400}),
            ADMIN
        );
        assert_eq!(resp.status(), StatusCode::OK);
        let body: Json = test::read_body_json(resp).await;
        // Named a namespace, changed its shard, and said so.
        assert_eq!(body["shard"], "myorg");
        assert_eq!(body["tier"], "warm");
        assert_eq!(body["warm_idle"], 86400);
        assert!(
            body["effect"]
                .as_str()
                .unwrap()
                .contains("everything under it"),
            "{body}"
        );

        let written = std::fs::read_to_string(dir.0.join("tiers.toml")).unwrap();
        assert!(
            written.contains(r#""myorg" = { tier = "warm", warm_idle = 86400 }"#),
            "{written}"
        );

        // A form hands over text, and "default" means stop saying anything.
        let resp = post_tier!(
            app,
            json!({"namespace": "myorg", "tier": "warm", "warm_idle": "default"}),
            ADMIN
        );
        let body: Json = test::read_body_json(resp).await;
        assert_eq!(body["own_warm_idle"], false);
        assert_eq!(body["warm_idle"], 3600, "back to the configured default");

        // Clearing both leaves nothing behind.
        let resp = post_tier!(app, json!({"namespace": "myorg", "tier": "default"}), ADMIN);
        assert_eq!(resp.status(), StatusCode::OK);
        let body: Json = test::read_body_json(resp).await;
        assert_eq!(body["own_tier"], false);
        let written = std::fs::read_to_string(dir.0.join("tiers.toml")).unwrap();
        assert!(!written.contains("myorg"), "{written}");
    }

    #[actix_web::test]
    async fn a_row_reports_the_window_its_shard_is_on() {
        let dir = TempDir::new("tierrow");
        let st = tiered_state(&dir.0);
        let app = app!(st);
        post_tier!(
            app,
            json!({"namespace": "myorg", "tier": "warm", "warm_idle": 900}),
            ADMIN
        );

        for uri in [
            "/_management/api/namespaces",
            "/_management/api/tree?path=myorg",
        ] {
            let body: Json = test::read_body_json(get!(app, uri, Some(ADMIN))).await;
            let item = &body["items"][0];
            assert_eq!(item["tier"], "warm", "{uri}");
            assert_eq!(item["warm_idle"], 900, "{uri}");
            assert_eq!(item["own_tier"], true, "{uri}");
            assert_eq!(item["own_warm_idle"], true, "{uri}");
        }
    }

    #[actix_web::test]
    async fn an_unreadable_idle_window_is_refused() {
        let dir = TempDir::new("tierjunk");
        let st = tiered_state(&dir.0);
        let app = app!(st);

        for body in [
            json!({"namespace": "myorg", "warm_idle": "soon"}),
            json!({"namespace": "myorg", "warm_idle": -5}),
            json!({"namespace": "", "tier": "warm"}),
        ] {
            assert_eq!(
                post_tier!(app, body.clone(), ADMIN).status(),
                StatusCode::BAD_REQUEST,
                "{body}"
            );
        }
        assert!(!dir.0.join("tiers.toml").exists());
    }

    #[actix_web::test]
    async fn an_unknown_tier_is_refused() {
        let dir = TempDir::new("tierbad");
        let st = tiered_state(&dir.0);
        let app = app!(st);

        let resp = post_tier!(app, json!({"shard": "myorg", "tier": "tepid"}), ADMIN);
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(!dir.0.join("tiers.toml").exists());
    }

    /// Consensus and API keys are consulted constantly, so the internal shard
    /// is not something the interface may demote.
    #[actix_web::test]
    async fn internal_namespaces_cannot_be_retiered() {
        let dir = TempDir::new("tierinternal");
        let st = tiered_state(&dir.0);
        let app = app!(st);

        for shard in ["_all", "_config", ""] {
            let resp = post_tier!(app, json!({"shard": shard, "tier": "cold"}), ADMIN);
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{shard:?}");
        }
    }

    #[actix_web::test]
    async fn changing_a_tier_needs_an_admin_key() {
        let dir = TempDir::new("tierauth");
        let st = tiered_state(&dir.0);
        let app = app!(st);

        let resp = post_tier!(app, json!({"shard": "myorg", "tier": "cold"}), "plain");
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    /// Without a file there is nowhere to record the change, and a tier that
    /// silently reverted on restart would be worse than refusing.
    #[actix_web::test]
    async fn changing_a_tier_without_a_file_says_so() {
        let st = state();
        let app = app!(st);

        let resp = post_tier!(app, json!({"shard": "feeds", "tier": "cold"}), ADMIN);
        assert_eq!(resp.status(), StatusCode::CONFLICT);
        let body: Json = test::read_body_json(resp).await;
        assert!(
            body["message"].as_str().unwrap().contains("tiers_file"),
            "{body}"
        );
    }

    // -- browsing, creating and adding ------------------------------------

    macro_rules! post_json {
        ($app:expr, $uri:expr, $body:expr, $key:expr) => {
            test::call_service(
                &$app,
                test::TestRequest::post()
                    .uri($uri)
                    .insert_header(("Authorization", $key))
                    .set_json($body)
                    .to_request(),
            )
            .await
        };
    }

    #[actix_web::test]
    async fn the_tree_walks_one_level_at_a_time() {
        let st = state();
        let app = app!(st);

        // At the root, `feeds` is a folder: it holds `feeds/ips` but nothing
        // of its own.
        let body: Json =
            test::read_body_json(get!(app, "/_management/api/tree", Some(ADMIN))).await;
        assert_eq!(body["total"], 1);
        assert_eq!(body["items"][0]["name"], "feeds");
        assert_eq!(body["items"][0]["path"], "feeds");
        assert_eq!(body["items"][0]["is_namespace"], false);
        assert_eq!(body["items"][0]["descendants"], 1);

        // A level down, `ips` is the namespace holding the values.
        let body: Json =
            test::read_body_json(get!(app, "/_management/api/tree?path=feeds", Some(ADMIN))).await;
        assert_eq!(body["items"][0]["name"], "ips");
        assert_eq!(body["items"][0]["path"], "feeds/ips");
        assert_eq!(body["items"][0]["is_namespace"], true);
        assert_eq!(body["items"][0]["descendants"], 0);

        // And nothing below that.
        let body: Json = test::read_body_json(get!(
            app,
            "/_management/api/tree?path=feeds/ips",
            Some(ADMIN)
        ))
        .await;
        assert_eq!(body["total"], 0);
    }

    /// A key scoped to one subtree must not learn the names of the others,
    /// which for the tree means not even seeing the folder above them.
    #[actix_web::test]
    async fn the_tree_only_shows_what_the_key_may_read() {
        let mut inner = SharedState::new(false);
        inner.acl.get_mut().unwrap().grant_full(ADMIN);
        inner
            .acl
            .get_mut()
            .unwrap()
            .set("scoped", parse_grants("admin, r:feeds").unwrap());
        for namespace in ["feeds/ips", "private/ips"] {
            inner
                .db
                .write(namespace, "1.2.3.4", Utc::now(), WriteOpts::default());
        }
        let st = web::Data::new(inner);
        let app = app!(st);

        let body: Json =
            test::read_body_json(get!(app, "/_management/api/tree", Some("scoped"))).await;
        assert_eq!(body["total"], 1);
        assert_eq!(body["items"][0]["name"], "feeds");
    }

    #[actix_web::test]
    async fn a_created_namespace_is_empty_and_browsable() {
        let st = state();
        let app = app!(st);

        let resp = post_json!(
            app,
            "/_management/api/namespaces",
            json!({"namespace": "feeds/domains"}),
            ADMIN
        );
        assert_eq!(resp.status(), StatusCode::OK);

        // It exists as a folder under `feeds`...
        let body: Json =
            test::read_body_json(get!(app, "/_management/api/tree?path=feeds", Some(ADMIN))).await;
        let names: Vec<&str> = body["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| item["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, ["domains", "ips"]);

        // ...and as a namespace holding nothing yet, rather than a 404.
        let body: Json = test::read_body_json(get!(
            app,
            "/_management/api/values?namespace=feeds/domains",
            Some(ADMIN)
        ))
        .await;
        assert_eq!(body["total"], 0);
    }

    #[actix_web::test]
    async fn creating_a_namespace_twice_is_refused() {
        let st = state();
        let app = app!(st);

        let body = json!({"namespace": "feeds/ips"});
        let resp = post_json!(app, "/_management/api/namespaces", body, ADMIN);
        assert_eq!(resp.status(), StatusCode::CONFLICT);
    }

    /// Slashes are how the interface nests folders, so a name doubling or
    /// trailing them must not create a second namespace beside the first.
    #[actix_web::test]
    async fn a_namespace_name_is_tidied_before_it_is_stored() {
        let st = state();
        let app = app!(st);

        let resp = post_json!(
            app,
            "/_management/api/namespaces",
            json!({"namespace": "/feeds//domains/ "}),
            ADMIN
        );
        assert_eq!(resp.status(), StatusCode::OK);
        let body: Json = test::read_body_json(resp).await;
        assert_eq!(body["namespace"], "feeds/domains");
        assert!(st.db.namespace_exists("feeds/domains"));
    }

    #[actix_web::test]
    async fn internal_and_empty_namespaces_are_refused() {
        let st = state();
        let app = app!(st);

        for name in ["_config/acl/apikeys/mine", "  ", "/", "with space"] {
            let resp = post_json!(
                app,
                "/_management/api/namespaces",
                json!({ "namespace": name }),
                ADMIN
            );
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{name}");
        }
    }

    #[actix_web::test]
    async fn values_can_be_added_one_at_a_time_or_in_bulk() {
        let st = state();
        let app = app!(st);

        let resp = post_json!(
            app,
            "/_management/api/values",
            json!({"namespace": "feeds/domains", "values": ["example.com"]}),
            ADMIN
        );
        assert_eq!(resp.status(), StatusCode::OK);
        let body: Json = test::read_body_json(resp).await;
        assert_eq!(body["written"], 1);
        // Writing is what creates a namespace, here as everywhere else.
        assert!(st.db.namespace_exists("feeds/domains"));

        // A pasted list, blank lines and all, lands as the values in it.
        let resp = post_json!(
            app,
            "/_management/api/values",
            json!({"namespace": "feeds/domains", "values": ["a.example", "", "  ", "b.example"]}),
            ADMIN
        );
        let body: Json = test::read_body_json(resp).await;
        assert_eq!(body["written"], 2);
        assert!(body["errors"].is_null(), "{body}");

        let page = st.db.value_page("feeds/domains", "", 0, 10, false).unwrap();
        assert_eq!(page.total, 3);
        // Counted towards consensus, exactly as a `/w/` write would be.
        assert_eq!(st.db.count(crate::db::ALL_NAMESPACE, "example.com"), 1);
    }

    #[actix_web::test]
    async fn added_values_take_a_ttl_and_a_time() {
        let st = state();
        let app = app!(st);

        // An hour ago with an hour to live: recorded then, and still here now.
        let seen = Utc::now().timestamp() - 60;
        let resp = post_json!(
            app,
            "/_management/api/values",
            json!({
                "namespace": "feeds/domains",
                "values": ["example.com"],
                "ttl": 3600,
                "timestamp": seen,
            }),
            ADMIN
        );
        assert_eq!(resp.status(), StatusCode::OK);

        let view = st
            .db
            .view("feeds/domains", "example.com", 0, false)
            .unwrap();
        assert_eq!(view.first_seen, seen);
        assert_eq!(view.ttl, 3600);

        // A time the calendar cannot hold is a client error, not a panic.
        let resp = post_json!(
            app,
            "/_management/api/values",
            json!({"namespace": "feeds/domains", "values": ["x"], "timestamp": i64::MAX}),
            ADMIN
        );
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[actix_web::test]
    async fn a_request_with_nothing_to_add_is_a_bad_request() {
        let st = state();
        let app = app!(st);

        let resp = post_json!(
            app,
            "/_management/api/values",
            json!({"namespace": "feeds/ips", "values": ["", " "]}),
            ADMIN
        );
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    /// Reaching the interface is not the same as being allowed to change the
    /// data in it: an `admin, r:feeds` key browses but does not write.
    #[actix_web::test]
    async fn writing_needs_a_write_grant_over_the_namespace() {
        let mut inner = SharedState::new(false);
        inner.acl.get_mut().unwrap().grant_full(ADMIN);
        inner
            .acl
            .get_mut()
            .unwrap()
            .set("reader", parse_grants("admin, r").unwrap());
        let st = web::Data::new(inner);
        let app = app!(st);

        for (uri, body) in [
            (
                "/_management/api/namespaces",
                json!({"namespace": "feeds/domains"}),
            ),
            (
                "/_management/api/values",
                json!({"namespace": "feeds/domains", "values": ["example.com"]}),
            ),
        ] {
            assert_eq!(
                post_json!(app, uri, body.clone(), "reader").status(),
                StatusCode::FORBIDDEN,
                "{uri}"
            );
            // A key that is not an admin key at all does not get further.
            assert_eq!(
                post_json!(app, uri, body, "nobody").status(),
                StatusCode::FORBIDDEN,
                "{uri}"
            );
        }
        assert!(!st.db.namespace_exists("feeds/domains"));
    }

    // -- the relationship graph -------------------------------------------

    #[actix_web::test]
    async fn a_value_reports_where_else_it_has_been_seen() {
        let mut inner = SharedState::new(false);
        inner.acl.get_mut().unwrap().grant_full(ADMIN);
        inner
            .acl
            .get_mut()
            .unwrap()
            .set("scoped", parse_grants("admin, r:feeds").unwrap());
        for namespace in ["feeds/misp/ips", "feeds/otx/ips", "private/ips"] {
            inner.db.write(
                namespace,
                "1.2.3.4",
                Utc::now(),
                WriteOpts {
                    consensus: true,
                    ttl: None,
                },
            );
        }
        let st = web::Data::new(inner);
        let app = app!(st);

        let body: Json = test::read_body_json(get!(
            app,
            "/_management/api/sightings?value=1.2.3.4",
            Some(ADMIN)
        ))
        .await;
        let namespaces: Vec<&str> = body["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| item["namespace"].as_str().unwrap())
            .collect();
        assert_eq!(
            namespaces,
            ["feeds/misp/ips", "feeds/otx/ips", "private/ips"]
        );
        assert_eq!(body["items"][0]["shard"], "feeds");
        assert_eq!(body["consensus"], 3);
        assert_eq!(body["truncated"], false);

        // A scoped key sees its own subtree; consensus still says how many
        // namespaces hold the value, so it can tell the graph is not all of it.
        let body: Json = test::read_body_json(get!(
            app,
            "/_management/api/sightings?value=1.2.3.4",
            Some("scoped")
        ))
        .await;
        assert_eq!(body["items"].as_array().unwrap().len(), 2);
        assert_eq!(body["consensus"], 3);
    }

    #[actix_web::test]
    async fn the_graph_needs_an_admin_key_and_a_value() {
        let st = state();
        let app = app!(st);

        assert_eq!(
            get!(app, "/_management/api/sightings?value=1.2.3.4", NO_KEY).status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            get!(
                app,
                "/_management/api/sightings?value=1.2.3.4",
                Some("plain")
            )
            .status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            get!(app, "/_management/api/sightings?value=", Some(ADMIN)).status(),
            StatusCode::BAD_REQUEST
        );
    }

    // -- tags and the STIX export -------------------------------------------

    #[actix_web::test]
    async fn values_can_be_added_with_tags_and_retagged_afterwards() {
        let st = state();
        let app = app!(st);

        let resp = post_json!(
            app,
            "/_management/api/values",
            json!({
                "namespace": "feeds/ips",
                "values": ["8.8.8.8"],
                "tags": "stix-type:ipv4-addr, tlp:green",
            }),
            ADMIN
        );
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            st.db.view("feeds/ips", "8.8.8.8", 0, false).unwrap().tags,
            "stix-type:ipv4-addr,tlp:green"
        );

        // Replacing is how a wrong tag comes off, and it is not a sighting:
        // the count stays where it was.
        let before = st.db.view("feeds/ips", "8.8.8.8", 0, false).unwrap().count;
        let resp = post_json!(
            app,
            "/_management/api/tags",
            json!({"namespace": "feeds/ips", "value": "8.8.8.8", "tags": "stix-type:ipv4-addr"}),
            ADMIN
        );
        assert_eq!(resp.status(), StatusCode::OK);
        let view = st.db.view("feeds/ips", "8.8.8.8", 0, false).unwrap();
        assert_eq!(view.tags, "stix-type:ipv4-addr");
        assert_eq!(view.count, before);
    }

    #[actix_web::test]
    async fn retagging_a_value_that_is_not_there_is_a_not_found() {
        let st = state();
        let app = app!(st);

        let resp = post_json!(
            app,
            "/_management/api/tags",
            json!({"namespace": "feeds/ips", "value": "203.0.113.9", "tags": "tlp:red"}),
            ADMIN
        );
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[actix_web::test]
    async fn tagging_needs_a_write_grant() {
        let mut inner = SharedState::new(false);
        inner.acl.get_mut().unwrap().grant_full(ADMIN);
        inner
            .acl
            .get_mut()
            .unwrap()
            .set("reader", parse_grants("admin, r").unwrap());
        inner
            .db
            .write("feeds/ips", "1.2.3.4", Utc::now(), WriteOpts::default());
        let st = web::Data::new(inner);
        let app = app!(st);

        let resp = post_json!(
            app,
            "/_management/api/tags",
            json!({"namespace": "feeds/ips", "value": "1.2.3.4", "tags": "tlp:red"}),
            "reader"
        );
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert!(
            st.db
                .view("feeds/ips", "1.2.3.4", 0, false)
                .unwrap()
                .tags
                .is_empty()
        );
    }

    #[actix_web::test]
    async fn the_logo_is_served_from_the_binary() {
        let st = state();
        let app = app!(st);

        // No key: the page shows it before anyone has signed in.
        let resp = get!(app, "/_management/logo.png", NO_KEY);
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers().get("content-type").unwrap(), "image/png");

        let body = test::read_body(resp).await;
        assert!(body.starts_with(b"\x89PNG"), "not a PNG");
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
