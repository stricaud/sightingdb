mod acl;
mod attribute;
mod config;
mod daemon;
mod db;
mod db_log;
mod error;
mod handlers;
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

    log::info!("Starting Sighting Daemon");
    if !settings.authenticate {
        log::warn!("No authentication used for the database; the ACL is not consulted.");
    }
    if settings.tls.is_none() {
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

    let state = Arc::new(SharedState {
        db,
        authenticate: settings.authenticate,
        acl,
    });

    let shutdown = Shutdown::new();
    let workers = spawn_workers(&state, &settings, snapshot.as_deref(), &shutdown)?;

    let result = actix_web::rt::System::new().block_on(serve(Arc::clone(&state), &settings));

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

async fn serve(state: Arc<SharedState>, settings: &Settings) -> Result<()> {
    let state = web::Data::from(state);
    let post_limit = settings.post_limit;

    let server = HttpServer::new(move || {
        App::new()
            .app_data(state.clone())
            .app_data(handlers::json_config(post_limit))
            .app_data(handlers::query_config())
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
