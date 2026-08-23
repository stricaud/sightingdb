//! `--setup`: get from `cargo install sightingdb` to a running service.
//!
//! The wizard asks a handful of questions, prints exactly what it is going to
//! do, and only then touches anything. Two rules hold throughout:
//!
//! * Nothing existing is overwritten without being asked, one file at a time.
//!   A configuration or certificate already in place is far more likely to be
//!   wanted than a fresh default.
//! * Whatever it does, it says. Creating users and writing into `/etc` deserves
//!   a plan on screen rather than a surprise afterwards.

use std::fmt::Write as _;
use std::fs;
use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};

use crate::acl::Acl;
use crate::config::TlsSettings;

/// Where an installation lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// System-wide, under `/etc` and `/var/lib`, running as its own user.
    System,
    /// Just for the current user, under their home directory.
    User,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    Linux,
    MacOs,
}

impl Platform {
    fn detect() -> Result<Platform> {
        match std::env::consts::OS {
            "linux" => Ok(Platform::Linux),
            "macos" => Ok(Platform::MacOs),
            other => bail!("--setup does not know how to install on {other}"),
        }
    }

    fn service_manager(self) -> &'static str {
        match self {
            Platform::Linux => "systemd",
            Platform::MacOs => "launchd",
        }
    }
}

/// Everything the wizard decided, so it can be shown before it is done.
#[derive(Debug, Clone)]
pub struct Plan {
    pub scope: Scope,
    pub platform: Platform,
    /// The account the service runs as. `None` means the current user.
    pub service_user: Option<String>,
    pub config_dir: PathBuf,
    pub config_path: PathBuf,
    pub acl_path: PathBuf,
    pub tiers_path: PathBuf,
    pub log_config_path: PathBuf,
    pub dbdir: PathBuf,
    pub tls: Option<TlsSettings>,
    pub listen_ip: String,
    pub listen_port: u16,
    pub authenticate: bool,
    pub admin_key: String,
    /// Where the binary should live so the service manager can reach it.
    pub binary: PathBuf,
    pub service_path: PathBuf,
    /// Off in tests, and when the caller only wants files written.
    pub create_user: bool,
    pub install_service: bool,
    pub start_service: bool,
}

impl Plan {
    /// A readable account of what will happen, shown before anything does.
    pub fn describe(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(
            out,
            "SightingDB will be installed {} using {}.\n",
            match self.scope {
                Scope::System => "system-wide",
                Scope::User => "for the current user only",
            },
            self.platform.service_manager()
        );

        if self.create_user
            && let Some(user) = &self.service_user
        {
            let _ = writeln!(out, "  create the system user   {user}");
        }
        let _ = writeln!(
            out,
            "  configuration            {}",
            self.config_path.display()
        );
        let _ = writeln!(
            out,
            "  API keys                 {}",
            self.acl_path.display()
        );
        let _ = writeln!(
            out,
            "  namespace tiers          {}",
            self.tiers_path.display()
        );
        let _ = writeln!(
            out,
            "  logging configuration    {}",
            self.log_config_path.display()
        );
        let _ = writeln!(out, "  database                 {}", self.dbdir.display());
        match &self.tls {
            Some(tls) => {
                let _ = writeln!(out, "  self-signed certificate  {}", tls.cert.display());
                let _ = writeln!(out, "  its private key          {}", tls.key.display());
            }
            None => {
                let _ = writeln!(out, "  TLS                      off (plain HTTP)");
            }
        }
        if self.install_service {
            let _ = writeln!(
                out,
                "  service                  {}",
                self.service_path.display()
            );
            let _ = writeln!(out, "  binary                   {}", self.binary.display());
        }
        let _ = writeln!(
            out,
            "\n  listening on             {}://{}:{}",
            if self.tls.is_some() { "https" } else { "http" },
            self.listen_ip,
            self.listen_port
        );
        let _ = writeln!(
            out,
            "  API authentication       {}",
            if self.authenticate { "on" } else { "off" }
        );
        out
    }

    /// The configuration file this plan produces.
    pub fn config_toml(&self) -> String {
        let mut out = String::from(
            "# Written by `sightingdb --setup`. Edit freely: the program only ever\n\
             # rewrites the acl_file and tiers_file named below.\n\n[daemon]\n",
        );
        let _ = writeln!(out, "listen_ip = \"{}\"", self.listen_ip);
        let _ = writeln!(out, "listen_port = {}", self.listen_port);
        let _ = writeln!(out, "authenticate = {}", self.authenticate);
        let _ = writeln!(out, "daemonize = false");
        match &self.tls {
            Some(tls) => {
                let _ = writeln!(out, "ssl = true");
                let _ = writeln!(out, "ssl_cert = \"{}\"", tls.cert.display());
                let _ = writeln!(out, "ssl_key = \"{}\"", tls.key.display());
            }
            None => {
                let _ = writeln!(out, "ssl = false");
            }
        }
        let _ = writeln!(out, "\ndbdir = \"{}\"", self.dbdir.display());
        let _ = writeln!(out, "snapshot_interval = 300");
        let _ = writeln!(out, "sweep_interval = 60");
        let _ = writeln!(out, "# 30 days of hourly statistics per value.");
        let _ = writeln!(out, "stats_retention = 720");
        let _ = writeln!(out, "shadow_ttl = 2_592_000");
        let _ = writeln!(out, "\nacl_file = \"{}\"", self.acl_path.display());
        let _ = writeln!(out, "\n[storage]");
        let _ = writeln!(out, "default_tier = \"hot\"");
        let _ = writeln!(out, "warm_idle = 3600");
        let _ = writeln!(out, "tiers_file = \"{}\"", self.tiers_path.display());
        out
    }

    fn service_unit(&self) -> String {
        match self.platform {
            Platform::Linux => {
                let user = self
                    .service_user
                    .clone()
                    .unwrap_or_else(|| "%i".to_string());
                format!(
                    "# Written by `sightingdb --setup`.\n\
                     [Unit]\n\
                     Description=SightingDB\n\
                     After=network-online.target\n\
                     Wants=network-online.target\n\n\
                     [Service]\n\
                     Type=exec\n\
                     ExecStart={binary} -c {config} -l {logcfg}\n\
                     # systemd restarts it when it dies, so `kill` does not stop it:\n\
                     # use `systemctl stop sightingdb`, or `sightingdb --stop`.\n\
                     Restart=on-failure\n\
                     RestartSec=5s\n\
                     User={user}\n\
                     KillSignal=SIGTERM\n\
                     # Long enough for the final snapshot to be written.\n\
                     TimeoutStopSec=60s\n\
                     NoNewPrivileges=yes\n\
                     PrivateTmp=yes\n\
                     ProtectSystem=strict\n\
                     ProtectHome=yes\n\
                     ReadWritePaths={dbdir}\n\n\
                     [Install]\n\
                     WantedBy=multi-user.target\n",
                    binary = self.binary.display(),
                    config = self.config_path.display(),
                    logcfg = self.log_config_path.display(),
                    dbdir = self.dbdir.display(),
                    user = user,
                )
            }
            Platform::MacOs => format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
                 <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \
                 \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
                 <plist version=\"1.0\">\n<dict>\n\
                 \x20 <key>Label</key><string>{label}</string>\n\
                 \x20 <key>ProgramArguments</key>\n\x20 <array>\n\
                 \x20   <string>{binary}</string>\n\
                 \x20   <string>-c</string><string>{config}</string>\n\
                 \x20   <string>-l</string><string>{logcfg}</string>\n\
                 \x20 </array>\n\
                 \x20 <key>RunAtLoad</key><true/>\n\
                 \x20 <key>KeepAlive</key><true/>\n\
                 \x20 <key>WorkingDirectory</key><string>{workdir}</string>\n\
                 \x20 <key>StandardOutPath</key><string>{logdir}/sightingdb.log</string>\n\
                 \x20 <key>StandardErrorPath</key><string>{logdir}/sightingdb.err</string>\n\
                 </dict>\n</plist>\n",
                label = LAUNCHD_LABEL,
                binary = self.binary.display(),
                config = self.config_path.display(),
                logcfg = self.log_config_path.display(),
                workdir = self.config_dir.display(),
                logdir = self.dbdir.display(),
            ),
        }
    }
}

const LAUNCHD_LABEL: &str = "com.github.stricaud.sightingdb";
const SERVICE_USER: &str = "sightingdb";
/// Minimal logging configuration, so the service has one without hunting.
const LOG_CONFIG: &str = "refresh_rate: 30 seconds\n\
                          appenders:\n\
                          \x20 stdout:\n\
                          \x20   kind: console\n\
                          root:\n\
                          \x20 level: info\n\
                          \x20 appenders:\n\
                          \x20   - stdout\n";

// ---------------------------------------------------------------------------
// Asking
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Accounting for an installation
// ---------------------------------------------------------------------------

/// One file an installation consists of.
struct Installed {
    what: &'static str,
    path: PathBuf,
    /// Why it is there, or when it appears — shown for anything whose absence
    /// is normal, so a missing file is not read as a broken install.
    note: String,
    /// Holds a secret: say so when anyone but its owner can read it.
    private: bool,
    /// This installation's own file, rather than one it merely uses.
    ///
    /// `--erase` removes only these. A logging configuration found in
    /// `/etc` or a home directory may be shared with another instance — or be
    /// the only one on the machine — and the binary belongs to whoever
    /// installed it, so neither is this installation's to delete.
    owned: bool,
}

/// Every file this installation uses, whether or not it exists yet.
///
/// Answers "what did this put on my disk, and is it all still there" — which
/// `--setup` is otherwise the only record of, and only at the moment it ran.
/// The configuration is the source of truth: these are the paths *this*
/// install actually reads and writes, not the ones a default install would.
pub fn installed_report(config_path: &Path, logging_config: Option<&Path>) -> Result<String> {
    let entries = inventory(config_path, logging_config)?;
    let mut out = render(&entries);

    // The question that follows "what is installed" is usually "how do I stop
    // it", and on both platforms the answer is not what people try first.
    if let Some(service) = entries
        .iter()
        .find(|entry| entry.what == "service" && entry.path.exists())
    {
        let _ = write!(out, "\n{}", stopping(&service.path));
    }
    Ok(out)
}

/// How to stop the thing, which is worth saying because the obvious way does
/// not work: both service managers restart the daemon when it dies, so a
/// `kill -9` is followed by it starting again a moment later.
fn stopping(service: &Path) -> String {
    let stop = service_commands(service, ServiceAction::Stop)
        .first()
        .map(|command| command.join(" "))
        .unwrap_or_default();
    let why = if service.display().to_string().ends_with(".plist") {
        "the plist sets KeepAlive, so launchd starts it again immediately"
    } else {
        "the unit sets Restart=on-failure, so systemd starts it again immediately"
    };
    format!(
        "To stop it:    {stop}\n\
         Or:            sightingdb --stop     (--start and --restart too)\n\
         `kill` will not do it — {why}.\n"
    )
}

/// Every file this installation uses, in the order a person reads them.
fn inventory(config_path: &Path, logging_config: Option<&Path>) -> Result<Vec<Installed>> {
    let settings = crate::config::Settings::load(config_path)?;
    let mut entries = vec![Installed {
        what: "configuration",
        path: config_path.to_path_buf(),
        note: String::new(),
        private: false,
        owned: true,
    }];

    // The one named on the command line, else the one the daemon would find.
    let logging = logging_config
        .map(Path::to_path_buf)
        .or_else(|| crate::logging_candidates().into_iter().find(|p| p.exists()));
    if let Some(logging) = logging {
        // Only ours if it lives with the configuration that names it. One
        // found by looking in the usual places belongs to the machine.
        let ours = logging.parent() == config_path.parent();
        entries.push(Installed {
            what: "logging config",
            path: logging,
            note: if ours {
                String::new()
            } else {
                "not this installation's; --erase leaves it".to_string()
            },
            private: false,
            owned: ours,
        });
    }

    if let Some(acl) = &settings.acl_file {
        entries.push(Installed {
            what: "API keys",
            path: acl.clone(),
            note: "rewritten when a key is saved".to_string(),
            private: true,
            owned: true,
        });
    } else {
        entries.push(Installed {
            what: "API keys",
            path: config_path.to_path_buf(),
            note: "no acl_file: the keys are in the [acl] section of it".to_string(),
            private: true,
            owned: false,
        });
    }

    if let Some(tiers) = &settings.tiers_file {
        entries.push(Installed {
            what: "tiers",
            path: tiers.clone(),
            note: "written when a tier is changed".to_string(),
            private: false,
            owned: true,
        });
    }

    if let Some(tls) = &settings.tls {
        entries.push(Installed {
            what: "TLS certificate",
            path: tls.cert.clone(),
            note: String::new(),
            private: false,
            owned: true,
        });
        entries.push(Installed {
            what: "TLS key",
            path: tls.key.clone(),
            note: String::new(),
            private: true,
            owned: true,
        });
    }

    if let Some(dbdir) = &settings.dbdir {
        entries.push(Installed {
            what: "database",
            path: dbdir.clone(),
            note: String::new(),
            private: false,
            owned: true,
        });
    }

    // Only consulted when the daemon backgrounds itself; under a service
    // manager the logs go to the journal instead.
    if settings.daemonize {
        for (what, path) in [
            ("stdout log", &settings.log_out),
            ("stderr log", &settings.log_err),
        ] {
            if path != Path::new("/dev/null") {
                entries.push(Installed {
                    what,
                    path: path.clone(),
                    note: String::new(),
                    private: false,
                    owned: true,
                });
            }
        }
    }

    if let Ok(binary) = std::env::current_exe() {
        entries.push(Installed {
            what: "binary",
            path: binary,
            // Removing the program you are running, on the strength of a
            // configuration file, is more than was asked for.
            note: "left alone by --erase".to_string(),
            private: false,
            owned: false,
        });
    }

    for path in service_candidates() {
        // Only the one that exists, or the system one to say it does not.
        if path.exists() {
            // A unit that runs *this* configuration is this installation's; a
            // unit for another one is somebody else's service.
            let ours = fs::read_to_string(&path).is_ok_and(|unit| {
                unit.contains(&config_path.display().to_string())
                    || unit.contains(&full(config_path).display().to_string())
            });
            entries.push(Installed {
                what: "service",
                path,
                note: if ours {
                    String::new()
                } else {
                    "runs a different configuration; --erase leaves it".to_string()
                },
                private: false,
                owned: ours,
            });
        }
    }
    if !entries.iter().any(|entry| entry.what == "service")
        && let Some(path) = service_candidates().into_iter().next()
    {
        entries.push(Installed {
            what: "service",
            path,
            note: "not installed; `--setup` can add one".to_string(),
            private: false,
            owned: false,
        });
    }

    // `-c short.toml` is a perfectly good way to start the daemon and a useless
    // thing to be told afterwards, so every path is reported in full.
    for entry in &mut entries {
        entry.path = full(&entry.path);
    }
    Ok(entries)
}

/// A path as somewhere you could paste into another command: symlinks resolved
/// when it exists, and made absolute when it does not.
fn full(path: &Path) -> PathBuf {
    if let Ok(real) = fs::canonicalize(path) {
        return real;
    }

    // A file that does not exist yet cannot be canonicalized, so as much of it
    // as does exist is resolved and the rest appended. Without that, a tiers
    // file that has never been written reads as `/var/…` while the directory
    // holding it reads as `/private/var/…`, and the two look like different
    // places.
    let absolute = std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf());
    let mut missing = Vec::new();
    let mut cursor = absolute.as_path();
    while let Some(parent) = cursor.parent() {
        if let Some(name) = cursor.file_name() {
            missing.push(name.to_os_string());
        }
        if let Ok(real) = fs::canonicalize(parent) {
            let mut resolved = real;
            resolved.extend(missing.iter().rev());
            return resolved;
        }
        cursor = parent;
    }
    absolute
}

/// Where a service unit lands, for this platform, system install first.
fn service_candidates() -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    match Platform::detect() {
        Ok(Platform::Linux) => {
            candidates.push(PathBuf::from("/etc/systemd/system/sightingdb.service"));
            if let Some(home) = dirs::home_dir() {
                candidates.push(home.join(".config/systemd/user/sightingdb.service"));
            }
        }
        Ok(Platform::MacOs) => {
            candidates.push(PathBuf::from(format!(
                "/Library/LaunchDaemons/{LAUNCHD_LABEL}.plist"
            )));
            if let Some(home) = dirs::home_dir() {
                candidates.push(home.join(format!("Library/LaunchAgents/{LAUNCHD_LABEL}.plist")));
            }
        }
        Err(_) => {}
    }
    candidates
}

fn render(entries: &[Installed]) -> String {
    let mut out = format!(
        "SightingDB {} — the files this installation uses\n\n",
        env!("CARGO_PKG_VERSION")
    );

    let widest = entries
        .iter()
        .map(|entry| entry.what.len())
        .max()
        .unwrap_or(0);
    let widest_path = entries
        .iter()
        .map(|entry| entry.path.display().to_string().len())
        .max()
        .unwrap_or(0);

    let mut missing = 0;
    let mut exposed = Vec::new();
    for entry in entries {
        let state = describe(&entry.path);
        if state.is_none() {
            missing += 1;
        }
        if entry.private && state.as_ref().is_some_and(|state| state.others_can_read) {
            exposed.push(entry.path.display().to_string());
        }

        let (mark, detail) = match &state {
            Some(state) => ("present", state.detail.as_str()),
            None => ("missing", ""),
        };
        let note = if entry.note.is_empty() {
            String::new()
        } else {
            format!("  ({})", entry.note)
        };
        let _ = writeln!(
            out,
            "  {mark}  {:<widest$}  {:<widest_path$}  {detail}{note}",
            entry.what,
            entry.path.display(),
        );
    }

    let _ = writeln!(
        out,
        "\n{} of {} present. A missing file is not always a problem: the tiers file is\n\
         written when a tier is first changed, and a service is optional.",
        entries.len() - missing,
        entries.len()
    );

    for path in exposed {
        let _ = writeln!(
            out,
            "\nWARNING: {path} holds a secret and can be read by more than its owner.\n\
             Run: chmod 600 {path}"
        );
    }
    out
}

/// What is at a path.
struct State {
    detail: String,
    /// Unix mode allows group or other to read it.
    others_can_read: bool,
}

/// A size, or a directory's contents, or nothing at all.
fn describe(path: &Path) -> Option<State> {
    let meta = fs::metadata(path).ok()?;

    if meta.is_dir() {
        let mut files = 0;
        let mut bytes = 0;
        if let Ok(entries) = fs::read_dir(path) {
            for entry in entries.flatten() {
                if let Ok(meta) = entry.metadata()
                    && meta.is_file()
                {
                    files += 1;
                    bytes += meta.len();
                }
            }
        }
        return Some(State {
            detail: format!("{files} file(s), {}", human(bytes)),
            others_can_read: false,
        });
    }

    // The mode is shown for every file, because it is what `--setup` sets and
    // seeing it is how you notice it has been widened since.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode() & 0o777;
        Some(State {
            detail: format!("{}, mode {mode:04o}", human(meta.len())),
            others_can_read: mode & 0o044 != 0,
        })
    }
    #[cfg(not(unix))]
    {
        Some(State {
            detail: human(meta.len()),
            others_can_read: false,
        })
    }
}

fn human(bytes: u64) -> String {
    match bytes {
        0..=1023 => format!("{bytes} B"),
        1024..=1_048_575 => format!("{:.1} KB", bytes as f64 / 1024.0),
        1_048_576..=1_073_741_823 => format!("{:.1} MB", bytes as f64 / 1_048_576.0),
        _ => format!("{:.1} GB", bytes as f64 / 1_073_741_824.0),
    }
}

// ---------------------------------------------------------------------------
// Taking an installation away again
// ---------------------------------------------------------------------------

/// The word that has to be typed. Not "y": this removes a database.
const ERASE_WORD: &str = "erase";

/// How the caller confirms. A parameter so the tests can answer without a
/// terminal, and so the prompt is in one place.
pub type Confirm<'a> = &'a dyn Fn(&str) -> Result<bool>;

/// Ask on the terminal, refusing when there is not one: a destructive command
/// with nobody to ask is a destructive command that should not run.
pub fn ask_to_erase(summary: &str) -> Result<bool> {
    if !std::io::stdin().is_terminal() {
        bail!(
            "--erase needs a terminal to confirm on. It removes a database; there is no \
             flag to skip the question."
        );
    }
    print!("{summary}\nType {ERASE_WORD} to remove all of this: ");
    std::io::stdout().flush().ok();
    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    Ok(answer.trim() == ERASE_WORD)
}

/// Stop the daemon and remove everything this installation put on disk.
///
/// The counterpart of [`run`]. It stops the *service* rather than the process,
/// because both service managers restart the daemon when it dies — which is
/// why `kill` appears not to work — and then removes only the paths the
/// configuration names, snapshot by snapshot, so a `dbdir` pointing somewhere
/// shared cannot take the rest of that directory with it.
///
/// The binary is left where it is: removing the program you are running, on
/// the strength of a configuration file, is more than was asked for.
pub fn erase(
    config_path: &Path,
    logging_config: Option<&Path>,
    confirm: Confirm,
) -> Result<String> {
    let entries = inventory(config_path, logging_config)?;
    let service = entries
        .iter()
        .find(|entry| entry.what == "service" && entry.owned && entry.path.exists())
        .map(|entry| entry.path.clone());

    // This installation's own files, and only those.
    let doomed: Vec<&Installed> = entries
        .iter()
        .filter(|entry| entry.owned && entry.path.exists())
        .collect();

    let mut summary = String::from("This removes:\n");
    for entry in &doomed {
        let _ = writeln!(summary, "  {:<16} {}", entry.what, entry.path.display());
    }
    let kept: Vec<&Installed> = entries
        .iter()
        .filter(|entry| !entry.owned && entry.path.exists())
        .collect();
    if !kept.is_empty() {
        let _ = writeln!(summary, "\nLeft alone:");
        for entry in kept {
            let _ = writeln!(summary, "  {:<16} {}", entry.what, entry.path.display());
        }
    }
    let _ = write!(summary, "\nThe data cannot be recovered afterwards.");

    if !confirm(&summary)? {
        return Ok("Nothing was removed.\n".to_string());
    }

    let mut out = String::new();
    if let Some(service) = &service {
        let _ = writeln!(out, "{}", stop_service(service));
    }
    let _ = writeln!(out, "{}", stop_processes(config_path));

    for entry in doomed {
        match remove(&entry.path) {
            Ok(what) => {
                let _ = writeln!(
                    out,
                    "removed  {:<16} {} {what}",
                    entry.what,
                    entry.path.display()
                );
            }
            Err(e) => {
                let _ = writeln!(
                    out,
                    "kept     {:<16} {}: {e}",
                    entry.what,
                    entry.path.display()
                );
            }
        }
    }

    // Directories that only existed to hold what has just gone.
    for dir in tidy_candidates(&entries) {
        if fs::read_dir(&dir).is_ok_and(|mut entries| entries.next().is_none())
            && fs::remove_dir(&dir).is_ok()
        {
            let _ = writeln!(out, "removed  {:<16} {}", "empty directory", dir.display());
        }
    }

    let _ = writeln!(
        out,
        "\nDone. `sightingdb --setup` starts again from nothing."
    );
    Ok(out)
}

/// What to ask the service manager for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceAction {
    Start,
    Stop,
    Restart,
    /// Stop and forget: what `--erase` needs, so nothing starts it again.
    Remove,
}

impl ServiceAction {
    fn parse(raw: &str) -> Result<ServiceAction> {
        match raw {
            "start" => Ok(ServiceAction::Start),
            "stop" => Ok(ServiceAction::Stop),
            "restart" => Ok(ServiceAction::Restart),
            other => bail!("unknown service action '{other}'"),
        }
    }
}

/// Whether a unit belongs to the user rather than the system, told from where
/// it lives — the only thing that distinguishes them for these commands.
fn is_user_service(service: &Path) -> bool {
    let path = service.display().to_string();
    path.contains("/.config/") || path.contains("/Library/LaunchAgents/")
}

/// The commands that carry out an action, in the order to try them.
///
/// Pure, so the shapes can be tested on a machine that has neither service
/// manager. Later entries are fallbacks for older systems; a command that
/// succeeds ends the sequence unless it is one of a pair that both have to run.
fn service_commands(service: &Path, action: ServiceAction) -> Vec<Vec<String>> {
    let path = service.display().to_string();
    let user = is_user_service(service);

    if path.ends_with(".plist") {
        let domain = if user {
            format!("gui/{}", current_uid())
        } else {
            "system".to_string()
        };
        let target = format!("{domain}/{LAUNCHD_LABEL}");
        return match action {
            // launchd has no restart; kickstart -k is how it is spelled.
            ServiceAction::Restart => vec![
                vec!["launchctl".into(), "kickstart".into(), "-k".into(), target],
                vec![
                    "launchctl".into(),
                    "unload".into(),
                    "-w".into(),
                    path.clone(),
                ],
                vec!["launchctl".into(), "load".into(), "-w".into(), path],
            ],
            ServiceAction::Start => vec![
                vec!["launchctl".into(), "bootstrap".into(), domain, path.clone()],
                vec!["launchctl".into(), "load".into(), "-w".into(), path],
            ],
            ServiceAction::Stop | ServiceAction::Remove => vec![
                vec!["launchctl".into(), "bootout".into(), target],
                vec!["launchctl".into(), "unload".into(), "-w".into(), path],
            ],
        };
    }

    let unit = "sightingdb".to_string();
    let systemctl = |verb: &str| {
        let mut command = vec!["systemctl".to_string()];
        if user {
            command.push("--user".to_string());
        }
        command.extend([verb.to_string(), unit.clone()]);
        command
    };
    match action {
        ServiceAction::Start => vec![systemctl("start")],
        ServiceAction::Stop => vec![systemctl("stop")],
        ServiceAction::Restart => vec![systemctl("restart")],
        // Disabling as well, so a reboot does not bring back what was erased.
        ServiceAction::Remove => vec![systemctl("stop"), systemctl("disable")],
    }
}

/// Run an action's commands, reporting what happened.
fn run_service_commands(service: &Path, action: ServiceAction) -> String {
    let commands = service_commands(service, action);
    // A pair that both have to run, rather than a first choice and a fallback.
    let all_of_them = matches!(action, ServiceAction::Remove)
        || (!service.display().to_string().ends_with(".plist"));

    let mut out = String::new();
    for command in commands {
        let line = command.join(" ");
        match Command::new(&command[0]).args(&command[1..]).output() {
            Ok(done) if done.status.success() => {
                let _ = writeln!(out, "ran      {line}");
                if !all_of_them {
                    break;
                }
            }
            Ok(done) => {
                let _ = writeln!(
                    out,
                    "note     {line}: {}",
                    String::from_utf8_lossy(&done.stderr).trim()
                );
            }
            Err(e) => {
                let _ = writeln!(out, "note     {line}: {e}");
            }
        }
    }
    out.trim_end().to_string()
}

fn stop_service(service: &Path) -> String {
    run_service_commands(service, ServiceAction::Remove)
}

/// Start, stop or restart the installed service.
///
/// Exists because the obvious way does not work: both managers restart the
/// daemon when it dies, so `kill` — even `kill -9` — is followed by it coming
/// straight back. Stopping it means telling the manager, and the command for
/// that differs by platform and by whether the service is the system's or the
/// user's.
pub fn service_control(
    config_path: &Path,
    logging_config: Option<&Path>,
    action: &str,
) -> Result<String> {
    let action = ServiceAction::parse(action)?;
    let entries = inventory(config_path, logging_config)?;
    let Some(service) = entries
        .iter()
        .find(|entry| entry.what == "service" && entry.path.exists())
    else {
        bail!(
            "no service is installed for this configuration.\n\
             `sightingdb --setup` can install one, or run the daemon in the foreground \
             with `sightingdb -c {}`.",
            config_path.display()
        );
    };

    let mut out = format!("{:?} {}\n", action, service.path.display());
    let _ = writeln!(out, "{}", run_service_commands(&service.path, action));
    Ok(out)
}

/// Stop anything still running with this configuration./// Stop anything still running with this configuration.
///
/// Matched on the configuration path rather than the program name, so another
/// instance serving a different configuration is left alone.
fn stop_processes(config_path: &Path) -> String {
    let pattern = config_path.display().to_string();
    let Ok(found) = Command::new("pgrep").arg("-f").arg(&pattern).output() else {
        return "note     pgrep is not available, so no process was looked for".to_string();
    };

    let mine = std::process::id();
    let pids: Vec<String> = String::from_utf8_lossy(&found.stdout)
        .lines()
        .filter_map(|line| line.trim().parse::<u32>().ok())
        .filter(|pid| *pid != mine)
        .map(|pid| pid.to_string())
        .collect();

    if pids.is_empty() {
        return "no daemon was running with this configuration".to_string();
    }

    // TERM first: the database is written out on the way down, and killing it
    // outright throws away everything since the last snapshot.
    let _ = Command::new("kill").args(&pids).output();
    std::thread::sleep(std::time::Duration::from_secs(2));
    let still: Vec<&String> = pids
        .iter()
        .filter(|pid| {
            Command::new("kill")
                .args(["-0", pid])
                .output()
                .is_ok_and(|out| out.status.success())
        })
        .collect();
    if !still.is_empty() {
        let _ = Command::new("kill")
            .arg("-9")
            .args(still.iter().map(|pid| pid.as_str()))
            .output();
    }
    format!("stopped  process(es) {}", pids.join(", "))
}

fn current_uid() -> String {
    Command::new("id")
        .arg("-u")
        .output()
        .ok()
        .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_string())
        .unwrap_or_default()
}

/// Remove one path, reporting what went.
///
/// A directory is emptied of the files this program writes there and then
/// removed if that is all it held. Anything else is left, and said so: a
/// `dbdir` sharing a directory with something else is a mistake to report, not
/// one to act on.
fn remove(path: &Path) -> Result<String> {
    let meta = fs::symlink_metadata(path).with_context(|| format!("reading {}", path.display()))?;
    if !meta.is_dir() {
        fs::remove_file(path).with_context(|| format!("removing {}", path.display()))?;
        return Ok(String::new());
    }

    let mut removed = 0;
    let mut left = 0;
    for entry in fs::read_dir(path).with_context(|| format!("reading {}", path.display()))? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        // What persistence writes: one zstd-compressed file per shard, plus the
        // single-file snapshot older builds wrote.
        let ours = name.ends_with(".json.zst") || name.ends_with(".json") || name.ends_with(".tmp");
        if ours && entry.path().is_file() {
            fs::remove_file(entry.path())?;
            removed += 1;
        } else {
            left += 1;
        }
    }

    if left == 0 {
        fs::remove_dir(path).with_context(|| format!("removing {}", path.display()))?;
        return Ok(format!("({removed} snapshot file(s))"));
    }
    Ok(format!(
        "({removed} snapshot file(s); {left} other file(s) left, so the directory stays)"
    ))
}

/// Directories worth removing once their contents have gone.
fn tidy_candidates(entries: &[Installed]) -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = Vec::new();
    for entry in entries {
        // The directory a file lived in, and its parent — an `ssl/` under a
        // config directory is worth taking, and so is the config directory.
        if let Some(parent) = entry.path.parent() {
            for dir in [
                parent.to_path_buf(),
                parent.parent().map(Path::to_path_buf).unwrap_or_default(),
            ] {
                if dir.as_os_str().is_empty() || !safe_to_tidy(&dir) || dirs.contains(&dir) {
                    continue;
                }
                dirs.push(dir);
            }
        }
    }
    // Deepest first, so `etc/ssl` goes before `etc`.
    dirs.sort_by_key(|dir| std::cmp::Reverse(dir.components().count()));
    dirs
}

/// Never tidy away somewhere that was not ours to begin with.
fn safe_to_tidy(dir: &Path) -> bool {
    const NEVER: [&str; 10] = [
        "/",
        "/etc",
        "/var",
        "/usr",
        "/opt",
        "/tmp",
        "/var/lib",
        "/usr/local",
        "/usr/local/etc",
        "/usr/local/var",
    ];
    if NEVER.contains(&dir.display().to_string().as_str()) {
        return false;
    }
    if dirs::home_dir().is_some_and(|home| home == dir) {
        return false;
    }
    // Two components is `/etc`; anything shallower is not an install of ours.
    dir.components().count() > 2
}

fn ask(question: &str, default: &str) -> Result<String> {
    print!("{question} [{default}]: ");
    std::io::stdout().flush().ok();
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .context("reading your answer")?;
    let line = line.trim();
    Ok(if line.is_empty() {
        default.to_string()
    } else {
        line.to_string()
    })
}

/// Ask until the answer parses. Aborting the whole wizard over one typo would
/// throw away every answer given before it.
fn ask_parsed<T: std::str::FromStr>(question: &str, default: &str, what: &str) -> Result<T> {
    loop {
        let answer = ask(question, default)?;
        match answer.trim().parse() {
            Ok(value) => return Ok(value),
            Err(_) => println!("  '{}' is not {what}", answer.trim()),
        }
    }
}

fn ask_yes_no(question: &str, default: bool) -> Result<bool> {
    loop {
        let answer = ask(question, if default { "yes" } else { "no" })?;
        match answer.trim().to_ascii_lowercase().as_str() {
            "y" | "yes" => return Ok(true),
            "n" | "no" => return Ok(false),
            _ => println!("  please answer yes or no"),
        }
    }
}

/// What to do about a file that is already there.
fn ask_replace(path: &Path, what: &str) -> Result<bool> {
    println!("\n  {} already exists at {}", what, path.display());
    ask_yes_no("  replace it?", false)
}

// ---------------------------------------------------------------------------
// The wizard
// ---------------------------------------------------------------------------

pub fn run() -> Result<()> {
    if !std::io::stdin().is_terminal() {
        bail!("--setup asks questions, so it needs a terminal. Run it directly.");
    }

    let platform = Platform::detect()?;
    let root = is_root();

    println!("SightingDB setup\n");
    println!(
        "Detected {} with {}, running as {}.\n",
        match platform {
            Platform::Linux => "Linux",
            Platform::MacOs => "macOS",
        },
        platform.service_manager(),
        if root { "root" } else { "an ordinary user" }
    );

    let scope = choose_scope(platform, root)?;
    let plan = build_plan(platform, scope, root)?;

    println!("\n{}", plan.describe());
    if !ask_yes_no("Go ahead?", true)? {
        println!("Nothing was changed.");
        return Ok(());
    }

    let applied = apply(&plan, &mut |path, what| ask_replace(path, what))?;
    report(&plan, applied);
    Ok(())
}

fn choose_scope(platform: Platform, root: bool) -> Result<Scope> {
    if !root {
        // Everything system-wide needs root, and re-running under sudo is a
        // better answer than failing halfway through.
        println!(
            "Installing for the current user. Run with sudo for a system-wide install\n\
             under /etc and /var/lib with its own service account.\n"
        );
        return Ok(Scope::User);
    }
    if platform == Platform::MacOs {
        // Creating a service account on macOS means hand-picking a UID through
        // dscl, which is not something to do silently on someone's machine.
        println!(
            "Running as root on macOS. This installs system-wide but does not create a\n\
             service account; the daemon runs as root unless you change the plist.\n"
        );
    }
    Ok(Scope::System)
}

fn build_plan(platform: Platform, scope: Scope, root: bool) -> Result<Plan> {
    let (config_dir, dbdir, service_path, binary) = match (scope, platform) {
        (Scope::System, Platform::Linux) => (
            PathBuf::from("/etc/sightingdb"),
            PathBuf::from("/var/lib/sightingdb"),
            PathBuf::from("/etc/systemd/system/sightingdb.service"),
            PathBuf::from("/usr/local/bin/sightingdb"),
        ),
        (Scope::System, Platform::MacOs) => (
            PathBuf::from("/usr/local/etc/sightingdb"),
            PathBuf::from("/usr/local/var/sightingdb"),
            PathBuf::from(format!("/Library/LaunchDaemons/{LAUNCHD_LABEL}.plist")),
            PathBuf::from("/usr/local/bin/sightingdb"),
        ),
        (Scope::User, _) => {
            let home = dirs::home_dir().context("finding your home directory")?;
            let config_dir = home.join(".sightingdb");
            let service_path = match platform {
                Platform::Linux => home.join(".config/systemd/user/sightingdb.service"),
                Platform::MacOs => home.join(format!("Library/LaunchAgents/{LAUNCHD_LABEL}.plist")),
            };
            // A user install runs the binary where cargo put it.
            let binary = std::env::current_exe().context("finding this executable")?;
            (
                config_dir.clone(),
                config_dir.join("db"),
                service_path,
                binary,
            )
        }
    };

    let listen_ip = ask("Listen address", "127.0.0.1")?;
    let listen_port: u16 = ask_parsed("Listen port", "9999", "a port number")?;
    let use_tls = ask_yes_no("Serve HTTPS with a self-signed certificate?", true)?;
    let authenticate = ask_yes_no("Require an API key on the sighting API?", true)?;
    let dbdir = PathBuf::from(ask("Database directory", &dbdir.to_string_lossy())?);

    let tls = use_tls.then(|| TlsSettings {
        cert: config_dir.join("ssl/cert.pem"),
        key: config_dir.join("ssl/key.pem"),
    });

    let install_service = ask_yes_no(
        &format!("Install a {} service?", platform.service_manager()),
        true,
    )?;
    let start_service = install_service && ask_yes_no("Start it now?", true)?;

    Ok(Plan {
        scope,
        platform,
        service_user: (scope == Scope::System && platform == Platform::Linux)
            .then(|| SERVICE_USER.to_string()),
        config_path: config_dir.join("sightingdb.toml"),
        acl_path: config_dir.join("acl.toml"),
        tiers_path: config_dir.join("tiers.toml"),
        log_config_path: config_dir.join("log4rs.yml"),
        config_dir,
        dbdir,
        tls,
        listen_ip,
        listen_port,
        authenticate,
        admin_key: random_key(),
        binary,
        service_path,
        create_user: scope == Scope::System && platform == Platform::Linux && root,
        install_service,
        start_service,
    })
}

// ---------------------------------------------------------------------------
// Doing
// ---------------------------------------------------------------------------

/// Whether an existing file should be replaced.
///
/// Passed in rather than asked for directly so that carrying out a plan is not
/// tied to a terminal — otherwise nothing here could be tested without one.
pub type Decide<'a> = &'a mut dyn FnMut(&Path, &str) -> Result<bool>;

/// Never replace anything already there. Used by the tests, which have no
/// terminal to ask at.
#[cfg(test)]
pub fn keep_existing(_: &Path, _: &str) -> Result<bool> {
    Ok(false)
}

/// What carrying out a plan actually changed.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Applied {
    /// Whether a new admin key was written. On a re-run the existing keys are
    /// kept, and reporting the freshly generated one would hand out a key that
    /// does not work.
    pub wrote_admin_key: bool,
}

/// Carry out a plan. Split from the questions so it can be tested.
pub fn apply(plan: &Plan, decide: Decide) -> Result<Applied> {
    let mut applied = Applied::default();
    if plan.create_user {
        create_service_user()?;
    }

    fs::create_dir_all(&plan.config_dir)
        .with_context(|| format!("creating {}", plan.config_dir.display()))?;
    fs::create_dir_all(&plan.dbdir)
        .with_context(|| format!("creating {}", plan.dbdir.display()))?;

    write_unless_kept(
        &plan.config_path,
        &plan.config_toml(),
        0o640,
        "A configuration",
        decide,
    )?;
    write_unless_kept(
        &plan.log_config_path,
        LOG_CONFIG,
        0o644,
        "A logging configuration",
        decide,
    )?;

    // Only written when absent: replacing it would revoke every existing key.
    if plan.acl_path.exists() {
        println!(
            "\n  Keeping the API keys already in {}",
            plan.acl_path.display()
        );
    } else {
        let mut acl = Acl::new();
        acl.grant_full(&plan.admin_key);
        write_file(&plan.acl_path, &acl.to_toml(), 0o600)?;
        applied.wrote_admin_key = true;
    }

    if let Some(tls) = &plan.tls {
        if tls.cert.exists() || tls.key.exists() {
            println!(
                "\n  Keeping the certificate already in {}",
                tls.cert.display()
            );
        } else {
            crate::tls::install_self_signed(tls)?;
        }
    }

    // The database and the keys are the sensitive parts.
    set_mode(&plan.dbdir, 0o750)?;
    set_mode(&plan.config_dir, 0o750)?;

    if let Some(user) = &plan.service_user
        && plan.create_user
    {
        chown(&plan.dbdir, user)?;
        chown(&plan.config_dir, user)?;
    }

    if plan.install_service {
        install_binary(plan)?;
        write_unless_kept(
            &plan.service_path,
            &plan.service_unit(),
            0o644,
            "A service unit",
            decide,
        )?;
        if plan.start_service {
            start(plan)?;
        }
    }

    Ok(applied)
}

/// Write a file unless something is already there and the caller wants it kept.
fn write_unless_kept(
    path: &Path,
    contents: &str,
    mode: u32,
    what: &str,
    decide: Decide,
) -> Result<()> {
    if path.exists() && !decide(path, what)? {
        println!("  Keeping {}", path.display());
        return Ok(());
    }
    write_file(path, contents, mode)
}

fn write_file(path: &Path, contents: &str, mode: u32) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    fs::write(path, contents).with_context(|| format!("writing {}", path.display()))?;
    set_mode(path, mode)
}

fn set_mode(path: &Path, mode: u32) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
            .with_context(|| format!("setting the mode of {}", path.display()))?;
    }
    #[cfg(not(unix))]
    let _ = (path, mode);
    Ok(())
}

fn chown(path: &Path, user: &str) -> Result<()> {
    run_command(
        "chown",
        &["-R", &format!("{user}:{user}"), &path.to_string_lossy()],
    )
}

fn is_root() -> bool {
    #[cfg(unix)]
    {
        // Cheaper and dependency-free compared with reading the real uid.
        std::env::var("USER").map(|u| u == "root").unwrap_or(false)
            || Command::new("id")
                .arg("-u")
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "0")
                .unwrap_or(false)
    }
    #[cfg(not(unix))]
    false
}

fn create_service_user() -> Result<()> {
    // Already there from an earlier run, which is fine.
    if Command::new("id")
        .arg(SERVICE_USER)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
    {
        println!("  The user {SERVICE_USER} already exists");
        return Ok(());
    }
    run_command(
        "useradd",
        &[
            "--system",
            "--no-create-home",
            "--shell",
            "/usr/sbin/nologin",
            SERVICE_USER,
        ],
    )
}

fn install_binary(plan: &Plan) -> Result<()> {
    let current = std::env::current_exe().context("finding this executable")?;
    if current == plan.binary {
        return Ok(());
    }
    if let Some(parent) = plan.binary.parent() {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    fs::copy(&current, &plan.binary)
        .with_context(|| format!("copying the binary to {}", plan.binary.display()))?;
    set_mode(&plan.binary, 0o755)
}

fn start(plan: &Plan) -> Result<()> {
    match plan.platform {
        Platform::Linux => {
            let user_flag: &[&str] = if plan.scope == Scope::User {
                &["--user"]
            } else {
                &[]
            };
            let mut reload = user_flag.to_vec();
            reload.push("daemon-reload");
            run_command("systemctl", &reload)?;

            let mut enable = user_flag.to_vec();
            enable.extend(["enable", "--now", "sightingdb"]);
            run_command("systemctl", &enable)
        }
        Platform::MacOs => {
            let domain = if plan.scope == Scope::User {
                format!("gui/{}", uid())
            } else {
                "system".to_string()
            };
            // Replaces any earlier registration rather than failing on it.
            let _ = run_command(
                "launchctl",
                &["bootout", &format!("{domain}/{LAUNCHD_LABEL}")],
            );
            run_command(
                "launchctl",
                &["bootstrap", &domain, &plan.service_path.to_string_lossy()],
            )
        }
    }
}

fn uid() -> String {
    Command::new("id")
        .arg("-u")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default()
}

fn run_command(program: &str, args: &[&str]) -> Result<()> {
    let output = Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("running {program}"))?;
    if !output.status.success() {
        bail!(
            "{program} {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

fn random_key() -> String {
    use rand::RngExt;
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut rng = rand::rng();
    (0..40)
        .map(|_| ALPHABET[rng.random_range(0..ALPHABET.len())] as char)
        .collect()
}

fn report(plan: &Plan, applied: Applied) {
    let scheme = if plan.tls.is_some() { "https" } else { "http" };
    println!("\nDone.\n");

    if applied.wrote_admin_key {
        println!("  Admin API key: {}", plan.admin_key);
        println!("  This is the only time it is shown. It is stored in plain text in");
        println!(
            "  {} — keep that file readable only by",
            plan.acl_path.display()
        );
        println!("  the account the service runs as.\n");
    } else {
        println!(
            "  The API keys already in {} were kept.\n",
            plan.acl_path.display()
        );
    }

    println!(
        "  Management interface: {scheme}://{}:{}/_management/",
        plan.listen_ip, plan.listen_port
    );
    if plan.tls.is_some() {
        println!("  The certificate is self-signed, so clients need curl -k or an exception.");
    }

    if plan.install_service && !plan.start_service {
        match plan.platform {
            Platform::Linux if plan.scope == Scope::User => {
                println!("\n  Start it with: systemctl --user start sightingdb")
            }
            Platform::Linux => println!("\n  Start it with: systemctl start sightingdb"),
            Platform::MacOs => println!(
                "\n  Start it with: launchctl bootstrap gui/$(id -u) {}",
                plan.service_path.display()
            ),
        }
    } else if !plan.install_service {
        println!(
            "\n  Run it with: sightingdb -c {}",
            plan.config_path.display()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            let path = std::env::temp_dir().join(format!("sightingdb-setup-{tag}"));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).unwrap();
            TempDir(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// An installation in a directory of its own: a configuration naming an
    /// acl file, a tiers file, a certificate, a key and a database.
    fn installation_in(dir: &Path) -> PathBuf {
        let etc = dir.join("etc");
        let db = dir.join("var");
        fs::create_dir_all(etc.join("ssl")).unwrap();
        fs::create_dir_all(&db).unwrap();

        let config = etc.join("sightingdb.toml");
        fs::write(
            &config,
            format!(
                "[daemon]\nssl = true\nssl_cert = \"ssl/cert.pem\"\nssl_key = \"ssl/key.pem\"\n\
                 dbdir = \"{}\"\nacl_file = \"acl.toml\"\n\n[storage]\ntiers_file = \"tiers.toml\"\n",
                db.display()
            ),
        )
        .unwrap();
        fs::write(
            etc.join("acl.toml"),
            "[acl]\n\"changeme\" = \"rw, admin\"\n",
        )
        .unwrap();
        fs::write(etc.join("ssl/cert.pem"), "certificate").unwrap();
        fs::write(etc.join("ssl/key.pem"), "key").unwrap();
        // As `--setup` leaves them: the secrets readable only by their owner.
        set_mode(&etc.join("acl.toml"), 0o600).unwrap();
        set_mode(&etc.join("ssl/key.pem"), 0o600).unwrap();
        fs::write(db.join("feeds-abc.json.zst"), "snapshot").unwrap();
        fs::write(db.join("sightingdb.json.zst"), "snapshot").unwrap();
        config
    }

    #[test]
    fn the_report_lists_every_file_in_full() {
        let dir = TempDir::new("installed");
        let config = installation_in(&dir.0);

        // Given relatively, because that is how someone runs it and the report
        // is useless if it echoes back "sightingdb.toml".
        let relative = config
            .strip_prefix(std::env::current_dir().unwrap())
            .unwrap_or(&config);
        let report = installed_report(relative, None).unwrap();

        for expected in [
            "configuration",
            "API keys",
            "tiers",
            "TLS certificate",
            "TLS key",
            "database",
        ] {
            assert!(
                report.contains(expected),
                "{expected} is missing:\n{report}"
            );
        }
        // Every path absolute, and the sizes read from disk.
        assert!(
            report.contains(&full(&config).display().to_string()),
            "{report}"
        );
        assert!(
            report.contains("2 file(s)"),
            "the database directory:\n{report}"
        );
        // The tiers file has not been written yet, which is normal.
        assert!(report.contains("missing"), "{report}");
    }

    #[test]
    fn a_secret_anyone_can_read_is_called_out() {
        let dir = TempDir::new("installedmode");
        let config = installation_in(&dir.0);
        let acl = dir.0.join("etc/acl.toml");

        set_mode(&acl, 0o600).unwrap();
        let report = installed_report(&config, None).unwrap();
        assert!(!report.contains("WARNING"), "{report}");

        set_mode(&acl, 0o644).unwrap();
        let report = installed_report(&config, None).unwrap();
        assert!(report.contains("WARNING"), "{report}");
        assert!(report.contains("chmod 600"), "{report}");
    }

    /// The commands differ by platform and by whose service it is, and this is
    /// the part that cannot be tried out on the machine running the tests.
    #[test]
    fn service_commands_match_the_platform() {
        let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("/home/x"));

        let unit = PathBuf::from("/etc/systemd/system/sightingdb.service");
        assert_eq!(
            service_commands(&unit, ServiceAction::Restart),
            [["systemctl", "restart", "sightingdb"]]
        );
        assert_eq!(
            service_commands(&unit, ServiceAction::Stop),
            [["systemctl", "stop", "sightingdb"]]
        );
        // Erasing disables it as well, or a reboot brings back what went.
        assert_eq!(
            service_commands(&unit, ServiceAction::Remove),
            [
                vec!["systemctl", "stop", "sightingdb"],
                vec!["systemctl", "disable", "sightingdb"]
            ]
        );

        let user_unit = home.join(".config/systemd/user/sightingdb.service");
        assert_eq!(
            service_commands(&user_unit, ServiceAction::Restart),
            [["systemctl", "--user", "restart", "sightingdb"]]
        );

        // launchd has no restart verb; kickstart -k is how it is spelled, with
        // an unload/load pair for systems too old to have it.
        let plist = PathBuf::from("/Library/LaunchDaemons/com.github.stricaud.sightingdb.plist");
        let restart = service_commands(&plist, ServiceAction::Restart);
        assert_eq!(
            restart[0],
            [
                "launchctl",
                "kickstart",
                "-k",
                "system/com.github.stricaud.sightingdb"
            ]
        );
        assert_eq!(restart[1][1], "unload");
        assert_eq!(restart[2][1], "load");

        let agent = home.join("Library/LaunchAgents/com.github.stricaud.sightingdb.plist");
        let stop = service_commands(&agent, ServiceAction::Stop);
        assert!(stop[0][2].starts_with("gui/"), "{stop:?}");
        assert!(
            stop[0][2].ends_with("com.github.stricaud.sightingdb"),
            "{stop:?}"
        );
    }

    #[test]
    fn erasing_asks_first_and_removes_nothing_if_refused() {
        let dir = TempDir::new("erasesaid no");
        let config = installation_in(&dir.0);

        let report = erase(&config, None, &|_| Ok(false)).unwrap();

        assert!(report.contains("Nothing was removed"), "{report}");
        assert!(config.exists());
        assert!(dir.0.join("var/feeds-abc.json.zst").exists());
    }

    #[test]
    fn erasing_removes_the_installation_and_says_what_went() {
        let dir = TempDir::new("erase");
        let config = installation_in(&dir.0);
        let summary_shown = std::cell::RefCell::new(String::new());

        let report = erase(&config, None, &|summary| {
            summary_shown.replace(summary.to_string());
            Ok(true)
        })
        .unwrap();
        let summary_shown = summary_shown.into_inner();

        // What it said it would remove is what it removed.
        assert!(
            summary_shown.contains("cannot be recovered"),
            "{summary_shown}"
        );
        // What it will not touch is stated too, the binary among it.
        assert!(summary_shown.contains("Left alone:"), "{summary_shown}");
        assert!(summary_shown.contains("binary"), "{summary_shown}");
        for gone in [
            config.clone(),
            dir.0.join("etc/acl.toml"),
            dir.0.join("etc/ssl/cert.pem"),
            dir.0.join("etc/ssl/key.pem"),
            dir.0.join("var/feeds-abc.json.zst"),
            dir.0.join("var"),
        ] {
            assert!(!gone.exists(), "{} survived:\n{report}", gone.display());
        }
        // And the directories that only held them.
        assert!(!dir.0.join("etc/ssl").exists(), "{report}");
        assert!(!dir.0.join("etc").exists(), "{report}");
        assert!(report.contains("removed"), "{report}");
    }

    /// The invariant behind all of this, stated once: nothing `--erase` would
    /// remove may live outside the installation it was pointed at.
    ///
    /// The lookup for a logging configuration reaches into `/etc` and the home
    /// directory, and marking what it finds as ours is how erasing a temporary
    /// install deleted `~/.sightingdb/log4rs.yml` and then this repository's
    /// `etc/log4rs.yml` — from a test run, twice, before anyone typed the word.
    #[test]
    fn nothing_owned_lives_outside_the_installation() {
        let dir = TempDir::new("ownership");
        let config = installation_in(&dir.0);
        let root = full(&dir.0);

        // No logging configuration given, so the global lookup runs — which is
        // exactly the case that went wrong.
        for entry in inventory(&config, None).unwrap() {
            if entry.owned {
                assert!(
                    entry.path.starts_with(&root),
                    "{} ({}) is outside {} and would be erased",
                    entry.path.display(),
                    entry.what,
                    root.display()
                );
            }
        }
    }

    /// Regression: a logging configuration found in the usual places belongs
    /// to the machine, not to whichever installation happened to be erased.
    /// This removed one out of a home directory while erasing a temporary
    /// install, which is exactly the sort of reach a destructive command must
    /// not have.
    #[test]
    fn erasing_leaves_a_logging_config_that_is_not_ours() {
        let dir = TempDir::new("eraselogging");
        let config = installation_in(&dir.0);

        // Somewhere else entirely, as /etc/log4rs.yml or ~/.sightingdb is.
        let elsewhere = dir.0.join("machine-wide");
        fs::create_dir_all(&elsewhere).unwrap();
        let logging = elsewhere.join("log4rs.yml");
        fs::write(&logging, LOG_CONFIG).unwrap();

        let listed = installed_report(&config, Some(&logging)).unwrap();
        assert!(listed.contains("not this installation's"), "{listed}");

        let report = erase(&config, Some(&logging), &|_| Ok(true)).unwrap();

        assert!(
            logging.exists(),
            "the logging configuration went:\n{report}"
        );
        assert!(!config.exists(), "{report}");
    }

    /// The same rule for a service: a unit that runs a different configuration
    /// is somebody else's, and is neither stopped nor removed.
    #[test]
    fn a_service_for_another_configuration_is_left_alone() {
        let dir = TempDir::new("erasefile");
        let config = installation_in(&dir.0);

        let entries = inventory(&config, None).unwrap();
        let service = entries
            .iter()
            .find(|entry| entry.what == "service")
            .unwrap();
        // Nothing on this machine's service path was written by this test, so
        // whatever is there — usually nothing — is not ours to touch.
        assert!(!service.owned, "{}", service.path.display());
    }

    /// A logging configuration written beside the configuration *is* ours.
    #[test]
    fn a_logging_config_in_the_install_directory_is_erased() {
        let dir = TempDir::new("eraseowned");
        let config = installation_in(&dir.0);
        let logging = dir.0.join("etc/log4rs.yml");
        fs::write(&logging, LOG_CONFIG).unwrap();

        let report = erase(&config, Some(&logging), &|_| Ok(true)).unwrap();

        assert!(!logging.exists(), "{report}");
    }

    /// A database directory shared with something else is a mistake to report,
    /// not one to act on: the snapshots go, the stranger stays, and so does
    /// the directory.
    #[test]
    fn erasing_leaves_files_that_are_not_ours() {
        let dir = TempDir::new("erasestranger");
        let config = installation_in(&dir.0);
        let stranger = dir.0.join("var/notes.txt");
        fs::write(&stranger, "someone else's").unwrap();

        let report = erase(&config, None, &|_| Ok(true)).unwrap();

        assert!(stranger.exists(), "{report}");
        assert!(!dir.0.join("var/feeds-abc.json.zst").exists(), "{report}");
        assert!(dir.0.join("var").exists(), "the directory stays:\n{report}");
        assert!(report.contains("other file(s) left"), "{report}");
    }

    /// Nothing shallow or shared is ever tidied away, whatever a configuration
    /// points at.
    #[test]
    fn common_directories_are_never_tidied() {
        for dir in ["/", "/etc", "/var", "/var/lib", "/usr/local", "/tmp"] {
            assert!(!safe_to_tidy(Path::new(dir)), "{dir}");
        }
        if let Some(home) = dirs::home_dir() {
            assert!(!safe_to_tidy(&home), "the home directory itself");
            assert!(
                safe_to_tidy(&home.join(".sightingdb")),
                "an install of ours"
            );
        }
        assert!(safe_to_tidy(Path::new("/etc/sightingdb")));
    }

    /// A plan that only touches the given directory: no user, no service.
    fn plan_in(dir: &Path, platform: Platform, tls: bool) -> Plan {
        let config_dir = dir.join("etc");
        Plan {
            scope: Scope::User,
            platform,
            service_user: None,
            config_path: config_dir.join("sightingdb.toml"),
            acl_path: config_dir.join("acl.toml"),
            tiers_path: config_dir.join("tiers.toml"),
            log_config_path: config_dir.join("log4rs.yml"),
            dbdir: dir.join("db"),
            tls: tls.then(|| TlsSettings {
                cert: config_dir.join("ssl/cert.pem"),
                key: config_dir.join("ssl/key.pem"),
            }),
            config_dir,
            listen_ip: "127.0.0.1".into(),
            listen_port: 9999,
            authenticate: true,
            admin_key: "test-admin-key".into(),
            binary: dir.join("bin/sightingdb"),
            service_path: dir.join("service"),
            create_user: false,
            install_service: false,
            start_service: false,
        }
    }

    #[test]
    fn a_plan_produces_a_configuration_the_program_can_read() {
        let dir = TempDir::new("config");
        let plan = plan_in(&dir.0, Platform::Linux, true);
        apply(&plan, &mut keep_existing).unwrap();

        // The real test: the config it wrote actually loads.
        let settings = crate::config::Settings::load(&plan.config_path).unwrap();
        assert_eq!(settings.listen, "127.0.0.1:9999");
        assert!(settings.authenticate);
        assert_eq!(settings.dbdir, Some(plan.dbdir.clone()));
        assert_eq!(settings.acl_file, Some(plan.acl_path.clone()));
        assert!(settings.tls.is_some());
    }

    #[test]
    fn the_generated_certificate_matches_the_configuration() {
        let dir = TempDir::new("certs");
        let plan = plan_in(&dir.0, Platform::Linux, true);
        apply(&plan, &mut keep_existing).unwrap();

        let tls = plan.tls.clone().unwrap();
        assert!(tls.cert.exists() && tls.key.exists());
        // Loads as a server identity, which is what the daemon will do.
        crate::tls::acceptor(&tls).unwrap();
    }

    #[test]
    fn without_tls_the_configuration_says_so() {
        let dir = TempDir::new("notls");
        let plan = plan_in(&dir.0, Platform::Linux, false);
        apply(&plan, &mut keep_existing).unwrap();

        let settings = crate::config::Settings::load(&plan.config_path).unwrap();
        assert_eq!(settings.tls, None);
        assert!(!plan.config_dir.join("ssl").exists());
    }

    #[test]
    fn the_admin_key_is_written_and_usable() {
        let dir = TempDir::new("key");
        let plan = plan_in(&dir.0, Platform::Linux, false);
        apply(&plan, &mut keep_existing).unwrap();

        let settings = crate::config::Settings::load(&plan.config_path).unwrap();
        let acl = settings.acl.unwrap();
        assert!(acl.is_admin("test-admin-key"));
        assert!(acl.can_write("test-admin-key", "anything"));
    }

    /// Reporting a key that was never written would hand out one that does
    /// not work.
    #[test]
    fn a_rerun_does_not_claim_to_have_written_a_key() {
        let dir = TempDir::new("rerunkey");
        let plan = plan_in(&dir.0, Platform::Linux, false);

        let first = apply(&plan, &mut keep_existing).unwrap();
        assert!(first.wrote_admin_key);

        let second = apply(&plan, &mut keep_existing).unwrap();
        assert!(!second.wrote_admin_key);
    }

    /// Re-running setup must not revoke every key that already exists.
    #[test]
    fn existing_api_keys_are_never_replaced() {
        let dir = TempDir::new("keepkeys");
        let plan = plan_in(&dir.0, Platform::Linux, false);
        apply(&plan, &mut keep_existing).unwrap();

        let mut second = plan.clone();
        second.admin_key = "a-different-key".into();
        apply(&second, &mut keep_existing).unwrap();

        let acl = crate::config::Settings::load(&plan.config_path)
            .unwrap()
            .acl
            .unwrap();
        assert!(acl.is_admin("test-admin-key"), "the original key was lost");
        assert!(!acl.contains("a-different-key"));
    }

    /// Likewise a certificate: replacing one silently would break every client
    /// that had accepted it.
    #[test]
    fn an_existing_certificate_is_kept() {
        let dir = TempDir::new("keepcert");
        let plan = plan_in(&dir.0, Platform::Linux, true);
        apply(&plan, &mut keep_existing).unwrap();
        let original = fs::read(&plan.tls.clone().unwrap().cert).unwrap();

        apply(&plan, &mut keep_existing).unwrap();

        assert_eq!(fs::read(&plan.tls.unwrap().cert).unwrap(), original);
    }

    #[cfg(unix)]
    #[test]
    fn the_sensitive_files_are_not_world_readable() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new("modes");
        let plan = plan_in(&dir.0, Platform::Linux, true);
        apply(&plan, &mut keep_existing).unwrap();

        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&plan.acl_path), 0o600, "API keys");
        assert_eq!(mode(&plan.tls.clone().unwrap().key), 0o600, "private key");
        assert_eq!(mode(&plan.config_path), 0o640, "configuration");
        assert_eq!(mode(&plan.dbdir), 0o750, "database");
    }

    #[test]
    fn a_systemd_unit_names_the_paths_it_was_given() {
        let dir = TempDir::new("systemd");
        let mut plan = plan_in(&dir.0, Platform::Linux, true);
        plan.service_user = Some("sightingdb".into());
        let unit = plan.service_unit();

        assert!(unit.contains("User=sightingdb"), "{unit}");
        assert!(
            unit.contains(&plan.config_path.display().to_string()),
            "{unit}"
        );
        assert!(unit.contains(&plan.dbdir.display().to_string()), "{unit}");
        // Time for the final snapshot to be written.
        assert!(unit.contains("TimeoutStopSec"), "{unit}");
    }

    #[test]
    fn a_launchd_plist_is_well_formed_enough_to_name_its_paths() {
        let dir = TempDir::new("launchd");
        let plan = plan_in(&dir.0, Platform::MacOs, false);
        let plist = plan.service_unit();

        assert!(plist.starts_with("<?xml"), "{plist}");
        assert!(plist.contains("<key>Label</key>"), "{plist}");
        assert!(plist.contains(LAUNCHD_LABEL), "{plist}");
        assert!(
            plist.contains(&plan.config_path.display().to_string()),
            "{plist}"
        );
        assert_eq!(
            plist.matches("<dict>").count(),
            plist.matches("</dict>").count()
        );
    }

    #[test]
    fn the_plan_says_what_it_will_do_before_doing_it() {
        let dir = TempDir::new("describe");
        let mut plan = plan_in(&dir.0, Platform::Linux, true);
        plan.create_user = true;
        plan.service_user = Some("sightingdb".into());
        plan.install_service = true;

        let described = plan.describe();
        for expected in [
            "create the system user   sightingdb",
            "configuration",
            "self-signed certificate",
            "https://127.0.0.1:9999",
        ] {
            assert!(
                described.contains(expected),
                "missing {expected:?}:\n{described}"
            );
        }
    }

    #[test]
    fn a_generated_key_is_acceptable_as_an_api_key() {
        let key = random_key();
        assert_eq!(key.len(), 40);
        assert!(crate::acl::validate_key(&key).is_ok());
        assert_ne!(key, random_key());
    }
}
