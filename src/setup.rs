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

const LAUNCHD_LABEL: &str = "com.devo.sightingdb";
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
