mod acl;
mod admin;
mod attribute;
mod config;
mod daemon;
mod db;
mod db_log;
mod dns;
mod error;
mod handlers;
mod ingest;
mod maintenance;
mod persistence;
mod sighting_reader;
mod sighting_writer;

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use actix_web::{App, HttpServer, web};
use anyhow::{Context, Result};
use chrono::Utc;
use clap::Parser;
use openssl::ssl::{SslAcceptor, SslAcceptorBuilder, SslFiletype, SslMethod};

use crate::acl::Acl;
use crate::config::{Settings, TlsSettings};
use crate::db::{DEFAULT_APIKEY, Database};
use crate::dns::answer::Responder;
use crate::handlers::SharedState;
use crate::maintenance::Shutdown;

#[derive(Debug, Parser)]
#[command(
    name = "sightingdb",
    version,
    about = "Sightings Database",
    author = "Sebastien Tricaud <sebastien.tricaud@devo.com>"
)]
struct Cli {
    /// Sets a custom config file
    #[arg(short, long, value_name = "FILE")]
    config: Option<PathBuf>,

    /// log4rs configuration file
    #[arg(
        short = 'l',
        long,
        value_name = "FILE",
        default_value = "etc/log4rs.yml"
    )]
    logging_config: PathBuf,

    /// Set the default API key, replacing the built-in one
    #[arg(short = 'k', long, value_name = "APIKEY")]
    apikey: Option<String>,

    /// Import STIX 2.1 bundles from a file or directory, then exit
    #[arg(long, value_name = "PATH")]
    import_stix: Option<PathBuf>,

    /// Sets the level of verbosity
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    log4rs::init_file(&cli.logging_config, Default::default()).with_context(|| {
        format!(
            "loading logging configuration {}",
            cli.logging_config.display()
        )
    })?;

    create_home_config();

    let config_path = match cli.config {
        Some(path) => path,
        None => config::locate()?,
    };
    log::info!("Using configuration file: {}", config_path.display());
    let settings = Settings::load(&config_path)?;

    // Detach before doing anything expensive, so the launcher does not restore
    // a database it is only going to throw away.
    if settings.daemonize && !daemon::is_child() {
        let pid = daemon::detach(&settings.log_out, &settings.log_err)?;
        log::info!("Running in the background as pid {pid}");
        return Ok(());
    }

    // Persistence is only on when dbdir is set *and* usable; a database that
    // cannot save is still better than one that refuses to start.
    let snapshot = usable_snapshot_path(&settings);
    let db = open_database(&settings, snapshot.as_deref())?;

    let acl = build_acl(&settings, &db, cli.apikey.as_deref());

    // A one-shot import: load, write, save, exit. No listeners start.
    if let Some(path) = &cli.import_stix {
        let imported = import_stix(&db, &settings, path)?;
        log::info!("Imported {imported} sighting(s) from {}", path.display());
        if let Some(snapshot) = snapshot.as_deref() {
            persistence::save(&db, snapshot)
                .with_context(|| format!("saving to {}", snapshot.display()))?;
            log::info!("Saved the database to {}", snapshot.display());
        } else {
            log::warn!("No dbdir configured, so the import was not persisted");
        }
        return Ok(());
    }

    log::info!("Starting Sighting Daemon");
    if !settings.authenticate {
        log::warn!("No authentication used for the database; the ACL is not consulted.");
    }
    if settings.http_enabled && settings.tls.is_none() {
        log::warn!("TLS is disabled; serving plain HTTP.");
    }
    if snapshot.is_none() {
        log::warn!("Persistence is disabled; data will be lost when the process stops.");
    }

    if !settings.daemonize {
        log::info!(
            "Running in the foreground. Set 'daemonize = true' in {} to detach, or run under \
             a service manager (see etc/sightingdb.service).",
            config_path.display()
        );
    }

    let info = server_info(&settings, &config_path, &db, &acl);
    let state = Arc::new(SharedState {
        db,
        authenticate: settings.authenticate,
        acl: std::sync::RwLock::new(acl),
        info,
        acl_file: settings.acl_file.clone(),
    });

    let shutdown = Shutdown::new();
    let mut workers = spawn_workers(&state, &settings, snapshot.as_deref(), &shutdown)?;
    workers.extend(spawn_dns(&state, &settings, &shutdown)?);

    let result = actix_web::rt::System::new().block_on(async {
        if let Some(zmq) = settings.zmq.clone() {
            log::info!(
                "ZMQ ingest subscribing to {} ({} format)",
                zmq.endpoint,
                match zmq.format {
                    ingest::Format::Misp => "MISP",
                    ingest::Format::Native => "native",
                }
            );
            actix_web::rt::spawn(ingest::run(Arc::clone(&state), zmq, Arc::clone(&shutdown)));
        }

        if settings.http_enabled {
            serve(Arc::clone(&state), &settings).await
        } else {
            // DNS-only: the listeners are already running on their own threads,
            // so this future exists purely to hold the process open until asked
            // to stop.
            log::info!("HTTP API disabled; running listeners only");
            wait_for_signal(Arc::clone(&shutdown)).await
        }
    });

    // Stop the background workers before the final save, so nothing is writing
    // a snapshot underneath us.
    shutdown.stop();
    for worker in workers {
        let _ = worker.join();
    }

    if let Some(path) = snapshot.as_deref() {
        log::info!("Saving the database to {}", path.display());
        if let Err(e) = persistence::save(&state.db, path) {
            log::error!("Could not save the database: {e:#}");
        }
    }

    daemon::remove_pid_file();

    result
}

/// Snapshot what this server was configured to do, for the management
/// interface. Taken once at startup because configuration is read from a file
/// and does not change while running.
fn server_info(
    settings: &Settings,
    config_path: &Path,
    db: &Database,
    acl: &Acl,
) -> admin::ServerInfo {
    admin::ServerInfo {
        version: env!("CARGO_PKG_VERSION"),
        authenticate: settings.authenticate,
        http_enabled: settings.http_enabled,
        config_path: config_path.display().to_string(),
        dbdir: settings.dbdir.as_ref().map(|d| d.display().to_string()),
        snapshot_interval: settings.snapshot_interval,
        sweep_interval: settings.sweep_interval,
        stats_retention: settings.stats_retention,
        shadow_ttl: settings.shadow_ttl,
        dns: settings.dns.as_ref().map(|dns| admin::DnsInfo {
            listen: dns.listen.clone(),
            zone: dns.zone.clone(),
            ttl: dns.ttl,
            rate_limit: dns.rate_limit,
            shadow: dns.shadow,
            exposed: dns
                .exposed
                .iter()
                .map(|e| admin::ExposedInfo {
                    label: e.label.clone(),
                    namespace: e.namespace.clone(),
                    encoding: format!("{:?}", e.encoding).to_lowercase(),
                })
                .collect(),
        }),
        zmq: settings.zmq.as_ref().map(|zmq| admin::ZmqInfo {
            endpoint: zmq.endpoint.clone(),
            topics: zmq.topics.clone(),
            format: format!("{:?}", zmq.format).to_lowercase(),
            require_to_ids: zmq.mapping.require_to_ids,
            mapped_types: zmq.mapping.types.len(),
        }),
        namespaces: db.namespace_count(),
        apikeys: acl.len(),
    }
}

/// Read STIX bundles from a file, or from every `.json` in a directory.
///
/// One unreadable bundle does not abort the run: an import of a hundred files
/// should tell you which one was broken and keep the other ninety-nine.
fn import_stix(db: &Database, settings: &Settings, path: &Path) -> Result<u64> {
    let files = stix_files(path)?;
    if files.is_empty() {
        log::warn!("No .json files found at {}", path.display());
        return Ok(0);
    }
    if settings.stix.mapping.types.is_empty() && settings.stix.mapping.default_namespace.is_none() {
        log::warn!("No [stix.types] mapping is configured, so every observable will be discarded");
    }

    let mut total = 0;
    for file in files {
        let body = match fs::read_to_string(&file) {
            Ok(body) => body,
            Err(e) => {
                log::error!("Could not read {}: {e}", file.display());
                continue;
            }
        };

        let sightings = match ingest::stix::parse_bundle(&body, &settings.stix.mapping) {
            Ok(sightings) => sightings,
            Err(e) => {
                log::error!("Could not parse {}: {e}", file.display());
                continue;
            }
        };

        let mut written = 0;
        for sighting in &sightings {
            match ingest::record(db, settings.stix.ttl, sighting) {
                Ok(()) => written += sighting.count.max(1),
                Err(e) => log::warn!(
                    "Skipped {}/{} from {}: {e}",
                    sighting.namespace,
                    sighting.value,
                    file.display()
                ),
            }
        }
        log::info!(
            "{}: {} observable(s), {written} sighting(s)",
            file.display(),
            sightings.len()
        );
        total += written;
    }

    Ok(total)
}

fn stix_files(path: &Path) -> Result<Vec<PathBuf>> {
    let metadata = fs::metadata(path).with_context(|| format!("reading {}", path.display()))?;
    if metadata.is_file() {
        return Ok(vec![path.to_path_buf()]);
    }

    let mut files: Vec<PathBuf> = fs::read_dir(path)
        .with_context(|| format!("listing {}", path.display()))?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|p| {
            p.extension()
                .is_some_and(|e| e.eq_ignore_ascii_case("json"))
        })
        .collect();
    // Deterministic order, so repeated imports log identically.
    files.sort();
    Ok(files)
}

/// Decide which API keys exist and what each may reach.
///
/// The `[acl]` section is authoritative when present. Without one we fall back
/// to the keys an older build stored in the database, granting each of them the
/// unrestricted access it used to have — upgrading must not lock a running
/// deployment out of its own data. `-k` always wins, and replaces the built-in
/// default key exactly as it always did.
fn build_acl(settings: &Settings, db: &Database, cli_apikey: Option<&str>) -> Acl {
    let legacy = db.legacy_apikeys();

    let mut acl = match &settings.acl {
        Some(acl) => {
            if !legacy.is_empty() {
                log::warn!(
                    "Ignoring {} API key(s) stored in the snapshot: the configuration has an \
                     [acl] section, which takes precedence",
                    legacy.len()
                );
            }
            log::info!("Loaded {} API key(s) from the [acl] section", acl.len());
            acl.clone()
        }
        None => {
            let mut acl = Acl::new();
            for key in &legacy {
                acl.grant_full(key);
            }
            if !legacy.is_empty() {
                log::warn!(
                    "Granting full access to {} API key(s) restored from the snapshot. Declare \
                     an [acl] section to scope them to particular namespaces.",
                    legacy.len()
                );
            }
            acl
        }
    };

    if let Some(apikey) = cli_apikey {
        acl.remove(DEFAULT_APIKEY);
        acl.grant_full(apikey);
        log::info!("API key from -k granted full access");
    }

    if acl.is_empty() {
        log::warn!(
            "No API keys configured; seeding '{DEFAULT_APIKEY}' with full access. Add an [acl] \
             section or pass -k."
        );
        acl.grant_full(DEFAULT_APIKEY);
    }

    acl
}

/// Load the database from disk when there is a snapshot, otherwise start fresh.
///
/// A snapshot that exists but cannot be read is fatal: starting empty would
/// look like catastrophic data loss, and the next save would make it real.
fn open_database(settings: &Settings, snapshot: Option<&Path>) -> Result<Database> {
    let policy = settings.database_policy();

    let Some(path) = snapshot else {
        return Ok(Database::with_policy(policy));
    };

    match persistence::load(path)? {
        Some(data) => {
            let db = Database::from_snapshot(data, policy);
            log::info!(
                "Restored {} namespaces from {}",
                db.namespace_count(),
                path.display()
            );
            Ok(db)
        }
        None => {
            log::info!("No snapshot at {}, starting empty", path.display());
            Ok(Database::with_policy(policy))
        }
    }
}

/// Where snapshots go, or `None` if persistence is off or the directory is not
/// usable.
fn usable_snapshot_path(settings: &Settings) -> Option<PathBuf> {
    let dbdir = settings.dbdir.as_ref()?;

    if let Err(e) = fs::create_dir_all(dbdir) {
        log::error!(
            "Cannot use dbdir {}: {e}. Continuing without persistence.",
            dbdir.display()
        );
        return None;
    }

    Some(persistence::snapshot_path(dbdir))
}

fn spawn_workers(
    state: &Arc<SharedState>,
    settings: &Settings,
    snapshot: Option<&Path>,
    shutdown: &Arc<Shutdown>,
) -> Result<Vec<JoinHandle<()>>> {
    let mut workers = Vec::new();

    if settings.sweep_interval > 0 {
        let state = Arc::clone(state);
        workers.push(
            maintenance::spawn_interval(
                "sightingdb-sweeper",
                Duration::from_secs(settings.sweep_interval),
                Arc::clone(shutdown),
                move || {
                    let report = state.db.sweep(Utc::now());
                    if !report.is_empty() {
                        log::info!(
                            "Swept {} expired values and {} empty namespaces",
                            report.values_removed,
                            report.namespaces_removed
                        );
                    }
                },
            )
            .context("starting the sweeper thread")?,
        );
    }

    if let Some(path) = snapshot
        && settings.snapshot_interval > 0
    {
        let state = Arc::clone(state);
        let path = path.to_path_buf();
        workers.push(
            maintenance::spawn_interval(
                "sightingdb-snapshot",
                Duration::from_secs(settings.snapshot_interval),
                Arc::clone(shutdown),
                move || {
                    if let Err(e) = persistence::save(&state.db, &path) {
                        log::error!("Snapshot failed: {e:#}");
                    }
                },
            )
            .context("starting the snapshot thread")?,
        );
    }

    Ok(workers)
}

/// Start the DNS listeners, if a `[dns]` section asked for them.
///
/// DNS has no authentication, so this deliberately answers only for the
/// namespaces named in `[dns.namespaces]` — the API-key ACL does not apply here.
fn spawn_dns(
    state: &Arc<SharedState>,
    settings: &Settings,
    shutdown: &Arc<Shutdown>,
) -> Result<Vec<JoinHandle<()>>> {
    let Some(dns) = &settings.dns else {
        return Ok(Vec::new());
    };

    let zone = hickory_proto::rr::Name::parse(&dns.zone, Some(&hickory_proto::rr::Name::root()))
        .with_context(|| format!("parsing the DNS zone '{}'", dns.zone))?;

    let responder = Arc::new(Responder::new(
        Arc::clone(state),
        zone,
        dns.exposed.clone(),
        dns.ttl,
        dns.shadow,
    ));

    let handles = dns::server::spawn(
        responder,
        &dns.listen,
        dns.threads,
        dns.rate_limit,
        Arc::clone(shutdown),
    )?;

    log::info!(
        "DNS listening on {} for zone {} ({} namespace(s) exposed, {} threads)",
        dns.listen,
        dns.zone,
        dns.exposed.len(),
        dns.threads
    );
    for exposed in &dns.exposed {
        log::info!(
            "  {}.{} -> namespace '{}' ({:?})",
            exposed.label,
            dns.zone,
            exposed.namespace,
            exposed.encoding
        );
    }
    if dns.shadow {
        log::warn!("DNS lookups will raise shadow sightings, an unauthenticated write path");
    }

    Ok(handles)
}

async fn serve(state: Arc<SharedState>, settings: &Settings) -> Result<()> {
    let state = web::Data::from(state);
    let post_limit = settings.post_limit;

    let server = HttpServer::new(move || {
        App::new()
            .app_data(state.clone())
            .app_data(handlers::json_config(post_limit))
            .app_data(handlers::query_config())
            .configure(admin::routes)
            .configure(handlers::routes)
    });

    let server = match &settings.tls {
        Some(tls) => {
            let builder = tls_acceptor(tls)?;
            server
                .bind_openssl(&settings.listen, builder)
                .with_context(|| format!("binding https://{}", settings.listen))?
        }
        None => server
            .bind(&settings.listen)
            .with_context(|| format!("binding http://{}", settings.listen))?,
    };

    let scheme = if settings.tls.is_some() {
        "https"
    } else {
        "http"
    };
    log::info!("Listening on {scheme}://{}", settings.listen);

    server.run().await.context("running the HTTP server")
}

/// Block until the process is asked to stop, for the DNS-only case where no
/// HTTP server is holding the runtime open.
///
/// Both signals feed the same `Shutdown` that the background workers watch,
/// and we poll it rather than awaiting the signals directly: `System::stop()`
/// does not interrupt `block_on`, so a task that only stopped the system would
/// leave this future waiting forever.
async fn wait_for_signal(shutdown: Arc<Shutdown>) -> Result<()> {
    #[cfg(unix)]
    {
        use actix_web::rt::signal::unix::{SignalKind, signal};

        let mut terminate = signal(SignalKind::terminate()).context("listening for SIGTERM")?;
        let shutdown = Arc::clone(&shutdown);
        actix_web::rt::spawn(async move {
            terminate.recv().await;
            log::info!("SIGTERM received, shutting down");
            shutdown.stop();
        });
    }

    {
        let shutdown = Arc::clone(&shutdown);
        actix_web::rt::spawn(async move {
            if actix_web::rt::signal::ctrl_c().await.is_ok() {
                log::info!("Interrupt received, shutting down");
                shutdown.stop();
            }
        });
    }

    while !shutdown.is_stopped() {
        actix_web::rt::time::sleep(Duration::from_millis(200)).await;
    }
    Ok(())
}

fn tls_acceptor(tls: &TlsSettings) -> Result<SslAcceptorBuilder> {
    let mut builder =
        SslAcceptor::mozilla_intermediate(SslMethod::tls()).context("creating the TLS acceptor")?;
    builder
        .set_private_key_file(&tls.key, SslFiletype::PEM)
        .with_context(|| format!("reading TLS key {}", tls.key.display()))?;
    builder
        .set_certificate_chain_file(&tls.cert)
        .with_context(|| format!("reading TLS certificate {}", tls.cert.display()))?;
    Ok(builder)
}

/// Make sure `~/.sightingdb` exists so a user-local config has somewhere to live.
fn create_home_config() {
    let Some(mut home_config) = dirs::home_dir() else {
        log::warn!("Cannot determine the home directory; skipping ~/.sightingdb");
        return;
    };
    home_config.push(".sightingdb");

    if let Err(e) = fs::create_dir_all(&home_config) {
        log::error!(
            "Error creating home configuration {}: {e}",
            home_config.display()
        );
    }
}
