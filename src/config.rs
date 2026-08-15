use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use ini::Ini;

use crate::acl::{Acl, parse_grants};
use crate::db::DatabasePolicy;

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

        Ok(Settings {
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
