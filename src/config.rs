use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use ini::Ini;

use crate::acl::{Acl, parse_grants};
use crate::db::DatabasePolicy;
use crate::dns::name::{Encoding, Exposed};
use crate::ingest::misp::Mapping;
use crate::ingest::stix::Mapping as StixMapping;
use crate::ingest::{Format, Settings as ZmqSettings};

/// Fallback body size limit for bulk POSTs, used when the config value cannot
/// be parsed. Matches the historical default.
const DEFAULT_POST_LIMIT: usize = 2_500_000_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsSettings {
    pub cert: PathBuf,
    pub key: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    /// Whether to serve the HTTP API at all. Set `enabled = false` in
    /// `[daemon]` to run a DNS-only instance.
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
    /// Seconds between snapshots; 0 saves only on shutdown.
    pub snapshot_interval: u64,
    /// Seconds between eviction sweeps; 0 disables the sweeper.
    pub sweep_interval: u64,
    /// Hourly statistics buckets kept per attribute; 0 keeps all of them.
    pub stats_retention: usize,
    /// TTL applied to shadow sightings; 0 means they never expire.
    pub shadow_ttl: u64,
    /// API keys and their permissions. `None` means the config declared no
    /// `[acl]` section at all, which is what an un-migrated install looks like.
    pub acl: Option<Acl>,
    /// DNS listener. `None` unless a `[dns]` section turns it on.
    pub dns: Option<DnsSettings>,
    /// ZeroMQ ingest. `None` unless a `[zmq]` section turns it on.
    pub zmq: Option<ZmqSettings>,
    /// How STIX observables map to namespaces, for `--import-stix`.
    pub stix: StixSettings,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StixSettings {
    pub mapping: StixMapping,
    /// TTL applied to imported sightings; 0 leaves them permanent.
    pub ttl: u64,
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

impl Settings {
    pub fn database_policy(&self) -> DatabasePolicy {
        DatabasePolicy {
            stats_retention: self.stats_retention,
            shadow_ttl: self.shadow_ttl,
        }
    }

    pub fn load(path: &Path) -> Result<Self> {
        let ini = Ini::load_from_file(path)
            .with_context(|| format!("reading config file {}", path.display()))?;

        let daemon = ini
            .section(Some("daemon"))
            .ok_or_else(|| anyhow!("no [daemon] section in {}", path.display()))?;

        let required = |key: &str| -> Result<&str> {
            daemon
                .get(key)
                .ok_or_else(|| anyhow!("missing '{key}' in [daemon] of {}", path.display()))
        };

        // Only the literal "false" turns the HTTP API off, matching how the
        // other booleans here behave.
        let http_enabled = daemon.get("enabled") != Some("false");
        let listen = format!("{}:{}", required("listen_ip")?, required("listen_port")?);

        // Historically only the literal "false" disables these, so that a typo
        // fails secure rather than silently opening the server up.
        let authenticate = required("authenticate")? != "false";
        let use_tls = required("ssl")? != "false";
        // Daemonizing, conversely, is strictly opt-in.
        let daemonize = required("daemonize")? == "true";

        // Certificate paths are relative to the config file, not the cwd.
        let base = path.parent().unwrap_or_else(|| Path::new("."));
        let tls = if use_tls {
            Some(TlsSettings {
                cert: resolve(base, required("ssl_cert")?),
                key: resolve(base, required("ssl_key")?),
            })
        } else {
            None
        };

        let post_limit = optional_number(daemon.get("post_limit"), DEFAULT_POST_LIMIT, path);

        // Only consulted when daemonizing, so they are not required otherwise.
        let log_out = PathBuf::from(daemon.get("log_out").unwrap_or("/dev/null"));
        let log_err = PathBuf::from(daemon.get("log_err").unwrap_or("/dev/null"));

        // An absent or blank dbdir means "do not persist", which is what an
        // upgraded install gets until it opts in.
        let dbdir = daemon
            .get("dbdir")
            .map(str::trim)
            .filter(|dir| !dir.is_empty())
            .map(PathBuf::from);

        // Retention defaults keep everything, so upgrading never silently
        // starts discarding data.
        let snapshot_interval = optional_number(daemon.get("snapshot_interval"), 300, path);
        let sweep_interval = optional_number(daemon.get("sweep_interval"), 60, path);
        let stats_retention = optional_number(daemon.get("stats_retention"), 0, path);
        let shadow_ttl = optional_number(daemon.get("shadow_ttl"), 0, path);

        let acl = load_acl(&ini, path)?;
        let dns = load_dns(&ini, path)?;
        let zmq = load_zmq(&ini, path)?;
        let stix = load_stix(&ini, path)?;

        if !http_enabled && dns.is_none() && zmq.is_none() {
            bail!(
                "both the HTTP API and DNS are disabled in {}, so there is nothing to serve",
                path.display()
            );
        }

        Ok(Settings {
            http_enabled,
            listen,
            authenticate,
            daemonize,
            tls,
            post_limit,
            log_out,
            log_err,
            dbdir,
            snapshot_interval,
            sweep_interval,
            stats_retention,
            shadow_ttl,
            acl,
            dns,
            zmq,
            stix,
        })
    }
}

/// Read the optional `[acl]` section, where each entry is
/// `<apikey> = <grants>`. A malformed entry is fatal rather than ignored:
/// quietly dropping a grant would either lock someone out or, worse, leave a
/// key with wider access than intended.
fn load_acl(ini: &Ini, path: &Path) -> Result<Option<Acl>> {
    let Some(section) = ini.section(Some("acl")) else {
        return Ok(None);
    };

    let mut acl = Acl::new();
    for (key, spec) in section.iter() {
        let grants = parse_grants(spec).with_context(|| {
            format!(
                "in the [acl] entry for '{key}' in {}: {spec:?}",
                path.display()
            )
        })?;
        acl.set(key, grants);
    }

    Ok(Some(acl))
}

/// Parse an optional numeric setting, warning and falling back rather than
/// refusing to start over a typo.
fn optional_number<T>(raw: Option<&str>, default: T, path: &Path) -> T
where
    T: std::str::FromStr + std::fmt::Display + Copy,
{
    match raw {
        Some(raw) => raw.trim().parse().unwrap_or_else(|_| {
            log::warn!(
                "could not parse '{raw}' in [daemon] of {}, using {default}",
                path.display()
            );
            default
        }),
        None => default,
    }
}

/// Read the optional `[dns]` section and the `[dns.namespaces]` map that says
/// which namespaces it may reach.
///
/// Nothing is exposed implicitly: DNS bypasses the API-key ACL entirely, so a
/// namespace answers queries only if it is named here.
fn load_dns(ini: &Ini, path: &Path) -> Result<Option<DnsSettings>> {
    let Some(section) = ini.section(Some("dns")) else {
        return Ok(None);
    };
    if section.get("enabled") == Some("false") {
        return Ok(None);
    }

    let required = |key: &str| -> Result<&str> {
        section
            .get(key)
            .ok_or_else(|| anyhow!("missing '{key}' in [dns] of {}", path.display()))
    };

    // Defaults to loopback rather than every interface: an open DNS responder
    // publishes whatever it is given to anyone who can send a packet.
    let listen_ip = section.get("listen_ip").unwrap_or("127.0.0.1");
    let listen_port = section.get("listen_port").unwrap_or("5353");
    let zone = required("zone")?
        .trim()
        .trim_matches('.')
        .to_ascii_lowercase();
    if zone.is_empty() {
        bail!("'zone' in [dns] of {} is empty", path.display());
    }

    let mut exposed = Vec::new();
    if let Some(namespaces) = ini.section(Some("dns.namespaces")) {
        for (label, spec) in namespaces.iter() {
            let (namespace, encoding) = spec.rsplit_once(':').ok_or_else(|| {
                anyhow!(
                    "[dns.namespaces] entry '{label}' in {} should read \
                     <namespace>:<ip|domain|base32>, got {spec:?}",
                    path.display()
                )
            })?;
            let namespace = namespace.trim();
            if namespace.starts_with('_') {
                bail!(
                    "[dns.namespaces] entry '{label}' in {} exposes the internal namespace \
                     '{namespace}'",
                    path.display()
                );
            }
            exposed.push(Exposed {
                label: label.trim().to_ascii_lowercase(),
                namespace: namespace.to_string(),
                encoding: Encoding::parse(encoding).with_context(|| {
                    format!("in [dns.namespaces] entry '{label}' of {}", path.display())
                })?,
            });
        }
    }

    if exposed.is_empty() {
        log::warn!(
            "[dns] is configured in {} but [dns.namespaces] exposes nothing, so every \
             query will be NXDOMAIN",
            path.display()
        );
    }

    Ok(Some(DnsSettings {
        listen: format!("{listen_ip}:{listen_port}"),
        zone,
        ttl: optional_number(section.get("ttl"), 60, path),
        rate_limit: optional_number(section.get("rate_limit"), 100, path),
        threads: optional_number(section.get("threads"), 2, path),
        shadow: section.get("shadow") == Some("true"),
        exposed,
    }))
}

/// Read the optional `[zmq]` section and the `[zmq.types]` map that turns MISP
/// attribute types into namespaces.
fn load_zmq(ini: &Ini, path: &Path) -> Result<Option<ZmqSettings>> {
    let Some(section) = ini.section(Some("zmq")) else {
        return Ok(None);
    };
    if section.get("enabled") == Some("false") {
        return Ok(None);
    }

    let endpoint = section
        .get("endpoint")
        .map(str::trim)
        .filter(|e| !e.is_empty())
        .ok_or_else(|| anyhow!("missing 'endpoint' in [zmq] of {}", path.display()))?
        .to_string();

    let topics: Vec<String> = section
        .get("topics")
        .unwrap_or("")
        .split(',')
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .map(String::from)
        .collect();

    let format = Format::parse(section.get("format").unwrap_or("misp"))
        .with_context(|| format!("in [zmq] of {}", path.display()))?;

    let mut types = std::collections::HashMap::new();
    if let Some(mapped) = ini.section(Some("zmq.types")) {
        for (misp_type, namespace) in mapped.iter() {
            let namespace = namespace.trim();
            if namespace.contains('=') {
                bail!(
                    "[zmq.types] entry '{misp_type}' in {} has '=' in its value; a ':' in the \
                     key would do that, since INI treats it as a key/value separator",
                    path.display()
                );
            }
            if namespace.starts_with('_') {
                bail!(
                    "[zmq.types] entry '{misp_type}' in {} targets the internal namespace \
                     '{namespace}'",
                    path.display()
                );
            }
            types.insert(misp_type.trim().to_string(), namespace.to_string());
        }
    }

    let default_namespace = section
        .get("default_namespace")
        .map(str::trim)
        .filter(|n| !n.is_empty())
        .map(String::from);
    if let Some(namespace) = &default_namespace
        && namespace.starts_with('_')
    {
        bail!(
            "'default_namespace' in [zmq] of {} is the internal namespace '{namespace}'",
            path.display()
        );
    }

    if types.is_empty() && default_namespace.is_none() && format == Format::Misp {
        log::warn!(
            "[zmq] is configured in {} but [zmq.types] maps nothing and no default_namespace \
             is set, so every attribute will be discarded",
            path.display()
        );
    }

    Ok(Some(ZmqSettings {
        endpoint,
        topics,
        format,
        mapping: Mapping {
            types,
            default_namespace,
            require_to_ids: section.get("require_to_ids") == Some("true"),
        },
        ttl: optional_number(section.get("ttl"), 0, path),
        reconnect: optional_number(section.get("reconnect"), 5, path),
    }))
}

/// Read the `[stix]` section and its `[stix.types]` map.
///
/// Unlike the listeners this is not a runtime service, so an absent section is
/// not an error — it just means `--import-stix` has nothing mapped and will say so.
fn load_stix(ini: &Ini, path: &Path) -> Result<StixSettings> {
    let section = ini.section(Some("stix"));

    let mut types = std::collections::HashMap::new();
    if let Some(mapped) = ini.section(Some("stix.types")) {
        for (stix_type, namespace) in mapped.iter() {
            let namespace = namespace.trim();
            // A ':' in the key would have been eaten by the INI parser, leaving
            // the rest of the line in the value. Say so rather than quietly
            // building a mapping that can never match.
            if namespace.contains('=') {
                bail!(
                    "[stix.types] entry '{stix_type}' in {} looks like it used ':' in the key. \
                     INI treats ':' as a key/value separator, so write 'file.MD5' rather than \
                     'file:MD5'",
                    path.display()
                );
            }
            if namespace.starts_with('_') {
                bail!(
                    "[stix.types] entry '{stix_type}' in {} targets the internal namespace \
                     '{namespace}'",
                    path.display()
                );
            }
            types.insert(stix_type.trim().to_string(), namespace.to_string());
        }
    }

    let default_namespace = section
        .and_then(|s| s.get("default_namespace"))
        .map(str::trim)
        .filter(|n| !n.is_empty())
        .map(String::from);
    if let Some(namespace) = &default_namespace
        && namespace.starts_with('_')
    {
        bail!(
            "'default_namespace' in [stix] of {} is the internal namespace '{namespace}'",
            path.display()
        );
    }

    Ok(StixSettings {
        mapping: StixMapping {
            types,
            default_namespace,
        },
        ttl: optional_number(section.and_then(|s| s.get("ttl")), 0, path),
    })
}

fn resolve(base: &Path, value: &str) -> PathBuf {
    let candidate = Path::new(value);
    let joined = if candidate.is_absolute() {
        candidate.to_path_buf()
    } else {
        base.join(candidate)
    };

    // Anchor it to the working directory now, so the path keeps resolving no
    // matter where the process ends up, and so failures name the full location.
    // This is lexical, unlike `canonicalize`, so the file need not exist yet.
    std::path::absolute(&joined).unwrap_or(joined)
}

/// Locate `sightingdb.conf` when `-c` was not supplied: system-wide first, then
/// the user's own copy.
pub fn locate() -> Result<PathBuf> {
    let system = PathBuf::from("/etc/sightingdb/sightingdb.conf");
    if system.exists() {
        return Ok(system);
    }

    if let Some(mut home) = dirs::home_dir() {
        home.push(".sightingdb");
        home.push("sightingdb.conf");
        if home.exists() {
            return Ok(home);
        }
    }

    Err(anyhow!(
        "cannot locate sightingdb.conf: pass -c, or place one in \
         /etc/sightingdb/ or ~/.sightingdb/"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_config(dir: &Path, body: &str) -> PathBuf {
        let path = dir.join("sightingdb.conf");
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(body.as_bytes()).unwrap();
        path
    }

    /// A scratch directory that cleans up after itself.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            let path = std::env::temp_dir().join(format!("sightingdb-test-{tag}"));
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

    const FULL: &str = "\
[daemon]
listen_ip=127.0.0.1
listen_port=9999
authenticate=false
daemonize=false
ssl=true
ssl_cert=ssl/cert.pem
ssl_key=/abs/key.pem
post_limit=1234
log_out=/tmp/out.log
log_err=/tmp/err.log
dbdir=/var/lib/sighting
snapshot_interval=120
sweep_interval=30
stats_retention=720
shadow_ttl=86400
";

    const DNS: &str = "\
[dns]
listen_ip=127.0.0.1
listen_port=5353
zone=sdb.example.com

[dns.namespaces]
malware=malware/ips:ip
domains=malware/domains:domain
";

    #[test]
    fn parses_a_full_config() {
        let dir = TempDir::new("full");
        let path = write_config(&dir.0, FULL);
        let settings = Settings::load(&path).unwrap();

        assert_eq!(settings.listen, "127.0.0.1:9999");
        assert!(!settings.authenticate);
        assert!(!settings.daemonize);
        assert_eq!(settings.post_limit, 1234);
        assert_eq!(settings.dbdir, Some(PathBuf::from("/var/lib/sighting")));
        assert_eq!(settings.snapshot_interval, 120);
        assert_eq!(settings.sweep_interval, 30);
        assert_eq!(
            settings.database_policy(),
            DatabasePolicy {
                stats_retention: 720,
                shadow_ttl: 86400,
            }
        );

        let tls = settings.tls.unwrap();
        // Relative to the config file...
        assert_eq!(tls.cert, dir.0.join("ssl/cert.pem"));
        // ...but absolute paths are left alone.
        assert_eq!(tls.key, PathBuf::from("/abs/key.pem"));
    }

    #[test]
    fn ssl_false_means_no_tls() {
        let dir = TempDir::new("nossl");
        let path = write_config(&dir.0, &FULL.replace("ssl=true", "ssl=false"));

        assert_eq!(Settings::load(&path).unwrap().tls, None);
    }

    #[test]
    fn only_the_literal_false_disables_authentication() {
        let dir = TempDir::new("authtypo");
        let path = write_config(
            &dir.0,
            &FULL.replace("authenticate=false", "authenticate=flase"),
        );

        assert!(Settings::load(&path).unwrap().authenticate);
    }

    #[test]
    fn an_unparseable_post_limit_falls_back() {
        let dir = TempDir::new("postlimit");
        let path = write_config(&dir.0, &FULL.replace("post_limit=1234", "post_limit=lots"));

        assert_eq!(
            Settings::load(&path).unwrap().post_limit,
            DEFAULT_POST_LIMIT
        );
    }

    /// Upgrading an old config must not silently switch persistence or
    /// eviction on.
    #[test]
    fn retention_settings_default_to_keeping_everything() {
        let dir = TempDir::new("defaults");
        let minimal = FULL
            .lines()
            .filter(|line| {
                !line.starts_with("dbdir")
                    && !line.starts_with("snapshot_interval")
                    && !line.starts_with("sweep_interval")
                    && !line.starts_with("stats_retention")
                    && !line.starts_with("shadow_ttl")
            })
            .collect::<Vec<_>>()
            .join("\n");
        let path = write_config(&dir.0, &minimal);

        let settings = Settings::load(&path).unwrap();

        assert_eq!(settings.dbdir, None);
        assert_eq!(settings.database_policy(), DatabasePolicy::default());
    }

    #[test]
    fn a_blank_dbdir_disables_persistence() {
        let dir = TempDir::new("blankdbdir");
        let path = write_config(
            &dir.0,
            &FULL.replace("dbdir=/var/lib/sighting", "dbdir=   "),
        );

        assert_eq!(Settings::load(&path).unwrap().dbdir, None);
    }

    #[test]
    fn an_unparseable_interval_falls_back() {
        let dir = TempDir::new("badinterval");
        let path = write_config(
            &dir.0,
            &FULL.replace("sweep_interval=30", "sweep_interval=often"),
        );

        assert_eq!(Settings::load(&path).unwrap().sweep_interval, 60);
    }

    // -- enabling and disabling listeners ----------------------------------

    #[test]
    fn both_listeners_run_by_default() {
        let dir = TempDir::new("bothdefault");
        let path = write_config(&dir.0, &format!("{FULL}\n{DNS}"));
        let settings = Settings::load(&path).unwrap();

        assert!(settings.http_enabled);
        assert!(settings.dns.is_some());
    }

    #[test]
    fn http_can_be_turned_off_for_a_dns_only_instance() {
        let dir = TempDir::new("dnsonly");
        let path = write_config(
            &dir.0,
            &format!(
                "{}\n{DNS}",
                FULL.replace("[daemon]", "[daemon]\nenabled=false")
            ),
        );
        let settings = Settings::load(&path).unwrap();

        assert!(!settings.http_enabled);
        assert!(settings.dns.is_some());
    }

    #[test]
    fn dns_can_be_turned_off_without_deleting_the_section() {
        let dir = TempDir::new("dnsoff");
        let path = write_config(
            &dir.0,
            &format!("{FULL}\n{}", DNS.replace("[dns]", "[dns]\nenabled=false")),
        );
        let settings = Settings::load(&path).unwrap();

        assert!(settings.http_enabled);
        assert_eq!(settings.dns, None);
    }

    /// Refusing to start beats starting a process that listens on nothing.
    #[test]
    fn disabling_both_is_an_error() {
        let dir = TempDir::new("neither");
        let path = write_config(&dir.0, &FULL.replace("[daemon]", "[daemon]\nenabled=false"));

        let err = Settings::load(&path).unwrap_err().to_string();
        assert!(err.contains("nothing to serve"), "{err}");
    }

    // -- [dns] -------------------------------------------------------------

    #[test]
    fn no_dns_section_means_no_dns() {
        let dir = TempDir::new("nodns");
        let path = write_config(&dir.0, FULL);
        assert_eq!(Settings::load(&path).unwrap().dns, None);
    }

    #[test]
    fn the_dns_section_is_parsed() {
        let dir = TempDir::new("dns");
        let path = write_config(&dir.0, &format!("{FULL}\n{DNS}"));
        let dns = Settings::load(&path).unwrap().dns.unwrap();

        assert_eq!(dns.listen, "127.0.0.1:5353");
        assert_eq!(dns.zone, "sdb.example.com");
        assert_eq!(dns.ttl, 60);
        assert_eq!(dns.rate_limit, 100);
        assert!(!dns.shadow);
        assert_eq!(dns.exposed.len(), 2);
        assert_eq!(dns.exposed[0].namespace, "malware/ips");
        assert_eq!(dns.exposed[0].encoding, Encoding::Ip);
    }

    #[test]
    fn a_trailing_dot_on_the_zone_is_ignored() {
        let dir = TempDir::new("dnsdot");
        let path = write_config(
            &dir.0,
            &format!(
                "{FULL}\n{}",
                DNS.replace("zone=sdb.example.com", "zone=SDB.Example.Com.")
            ),
        );
        assert_eq!(
            Settings::load(&path).unwrap().dns.unwrap().zone,
            "sdb.example.com"
        );
    }

    /// The internal trees hold API keys and search history; publishing them over
    /// an unauthenticated protocol must not be a typo away.
    #[test]
    fn internal_namespaces_cannot_be_exposed() {
        let dir = TempDir::new("dnsinternal");
        let path = write_config(
            &dir.0,
            &format!(
                "{FULL}\n{}",
                DNS.replace("malware=malware/ips:ip", "keys=_config/acl/apikeys:domain")
            ),
        );

        let err = Settings::load(&path).unwrap_err().to_string();
        assert!(err.contains("_config/acl/apikeys"), "{err}");
    }

    #[test]
    fn a_malformed_namespace_mapping_is_fatal() {
        let dir = TempDir::new("dnsbadmap");
        let path = write_config(
            &dir.0,
            &format!(
                "{FULL}\n{}",
                DNS.replace("malware=malware/ips:ip", "malware=malware/ips:rot13")
            ),
        );

        let err = format!("{:#}", Settings::load(&path).unwrap_err());
        assert!(err.contains("unknown DNS encoding"), "{err}");
    }

    // -- [acl] -------------------------------------------------------------

    #[test]
    fn no_acl_section_means_none() {
        let dir = TempDir::new("noacl");
        let path = write_config(&dir.0, FULL);

        assert_eq!(Settings::load(&path).unwrap().acl, None);
    }

    #[test]
    fn the_acl_section_is_parsed() {
        let dir = TempDir::new("acl");
        let path = write_config(
            &dir.0,
            &format!("{FULL}\n[acl]\nadmin = rw\nanalyst = r\nfeed = rw:feeds/misp\n"),
        );

        let acl = Settings::load(&path).unwrap().acl.unwrap();

        assert_eq!(acl.len(), 3);
        assert!(acl.can_write("admin", "anything"));
        assert!(acl.can_read("analyst", "anything"));
        assert!(!acl.can_write("analyst", "anything"));
        assert!(acl.can_write("feed", "feeds/misp/ips"));
        assert!(!acl.can_write("feed", "feeds/other"));
    }

    /// A typo in a grant must stop the server rather than silently leaving a
    /// key with the wrong permissions.
    #[test]
    fn a_malformed_grant_is_fatal_and_names_the_key() {
        let dir = TempDir::new("badacl");
        let path = write_config(&dir.0, &format!("{FULL}\n[acl]\nbroken = admin\n"));

        let err = format!("{:#}", Settings::load(&path).unwrap_err());
        assert!(err.contains("broken"), "{err}");
        assert!(err.contains("unknown permission"), "{err}");
    }

    #[test]
    fn a_missing_key_names_itself() {
        let dir = TempDir::new("missing");
        let path = write_config(&dir.0, &FULL.replace("listen_port=9999\n", ""));

        let err = Settings::load(&path).unwrap_err().to_string();
        assert!(err.contains("listen_port"), "{err}");
    }

    #[test]
    fn a_missing_daemon_section_is_an_error() {
        let dir = TempDir::new("nosection");
        let path = write_config(&dir.0, "[other]\nkey=value\n");

        let err = Settings::load(&path).unwrap_err().to_string();
        assert!(err.contains("[daemon]"), "{err}");
    }

    #[test]
    fn a_missing_file_is_an_error() {
        let err = Settings::load(Path::new("/nonexistent/sightingdb.conf"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("reading config file"), "{err}");
    }
}
