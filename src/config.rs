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
    pub sweep_interval: u64,
    pub stats_retention: usize,
    pub shadow_ttl: u64,
    /// API keys. `None` means no `[acl]` table and no `acl_file`.
    pub acl: Option<Acl>,
    /// File holding the keys, which the management interface rewrites.
    pub acl_file: Option<PathBuf>,
    pub dns: Option<DnsSettings>,
    pub zmq: Option<ZmqSettings>,
    pub stix: StixSettings,
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
    #[serde(default = "default_sweep_interval")]
    sweep_interval: u64,
    #[serde(default)]
    stats_retention: usize,
    #[serde(default)]
    shadow_ttl: u64,
    acl_file: Option<PathBuf>,
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
fn default_sweep_interval() -> u64 {
    60
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

        let acl_file = daemon.acl_file.map(|file| resolve(base, &file));
        let acl = load_acl(self.acl, acl_file.as_deref(), path)?;

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
            sweep_interval: daemon.sweep_interval,
            stats_retention: daemon.stats_retention,
            shadow_ttl: daemon.shadow_ttl,
            acl,
            acl_file,
            dns,
            zmq,
            stix,
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
        Ok(StixSettings {
            mapping: StixMapping {
                types: type_map(self.types.as_ref(), "stix.types", path)?,
                default_namespace: namespace_option(self.default_namespace, "stix")?,
            },
            ttl: self.ttl,
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
        "cannot locate sightingdb.toml: pass -c, or place one in /etc/sightingdb/ or \
         ~/.sightingdb/"
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
