//! Detaching from the controlling terminal, without a daemonization crate.
//!
//! Instead of the textbook double `fork`, we re-execute ourselves with stdio
//! redirected and our own process group. That costs one extra `exec` at
//! startup and buys two things: no `unsafe` and no FFI, and — more importantly
//! — a daemon that begins life with a clean thread state.
//!
//! `fork` carries over only the calling thread, so anything already running in
//! the background is silently lost in the child. That is not hypothetical here:
//! log4rs spawns a configuration reloader when `refresh_rate` is set, and it
//! would simply stop existing in a forked daemon. Re-executing sidesteps the
//! whole class of problem, and because we never change directory, relative
//! paths in the configuration keep resolving the way they did.

use std::env;
use std::fs;
use std::path::PathBuf;

use anyhow::Result;

/// Set in the re-executed child so that it does not detach a second time.
const CHILD_ENV: &str = "SIGHTINGDB_DAEMON_CHILD";
/// Tells the child which pid file was written on its behalf, so it can clean
/// up after itself on a clean exit.
const PID_FILE_ENV: &str = "SIGHTINGDB_PID_FILE";

/// Whether this process is the detached child rather than the launcher.
pub fn is_child() -> bool {
    env::var_os(CHILD_ENV).is_some()
}

/// The pid file this process is responsible for removing when it stops.
pub fn pid_file() -> Option<PathBuf> {
    env::var_os(PID_FILE_ENV).map(PathBuf::from)
}

/// Remove the pid file, if we were given one.
pub fn remove_pid_file() {
    let Some(path) = pid_file() else {
        return;
    };
    if let Err(e) = fs::remove_file(&path)
        && e.kind() != std::io::ErrorKind::NotFound
    {
        log::warn!("Could not remove the pid file {}: {e}", path.display());
    }
}

/// Locations to try for the pid file, most preferred first.
fn pid_file_candidates() -> Vec<PathBuf> {
    let mut candidates = vec![PathBuf::from("/var/run/sightingdb.pid")];
    if let Some(mut home) = dirs::home_dir() {
        home.push(".sightingdb");
        home.push("sightingdb.pid");
        candidates.push(home);
    }
    candidates.push(PathBuf::from("./sightingdb.pid"));
    candidates
}

/// The first candidate we can actually write to.
fn choose_pid_file() -> Option<PathBuf> {
    for candidate in pid_file_candidates() {
        if fs::write(&candidate, b"").is_ok() {
            return Some(candidate);
        }
    }
    log::warn!("Nowhere writable for a pid file; continuing without one");
    None
}

#[cfg(unix)]
pub fn detach(log_out: &std::path::Path, log_err: &std::path::Path) -> Result<u32> {
    use anyhow::Context;
    use std::fs::File;
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};

    let exe = env::current_exe().context("locating our own executable")?;

    let stdout =
        File::create(log_out).with_context(|| format!("creating {}", log_out.display()))?;
    let stderr =
        File::create(log_err).with_context(|| format!("creating {}", log_err.display()))?;

    let pid_path = choose_pid_file();

    let mut command = Command::new(&exe);
    command
        // Same arguments we were given, so -c/-k/-l carry over.
        .args(env::args_os().skip(1))
        .env(CHILD_ENV, "1")
        .stdin(Stdio::null())
        .stdout(stdout)
        .stderr(stderr)
        // Its own process group, so terminal-generated signals — Ctrl-C, and
        // the SIGHUP sent when the session ends — no longer reach it.
        .process_group(0);

    if let Some(path) = &pid_path {
        command.env(PID_FILE_ENV, path);
    }

    let child = command
        .spawn()
        .with_context(|| format!("re-executing {}", exe.display()))?;

    // The child is reparented to init once we exit; we deliberately do not
    // wait on it.
    let pid = child.id();

    if let Some(path) = &pid_path
        && let Err(e) = fs::write(path, format!("{pid}\n"))
    {
        log::warn!("Could not write the pid file {}: {e}", path.display());
    }

    Ok(pid)
}

#[cfg(not(unix))]
pub fn detach(_log_out: &std::path::Path, _log_err: &std::path::Path) -> Result<u32> {
    anyhow::bail!(
        "daemonize = true is only supported on Unix. Set daemonize = false and run \
         under a service manager instead."
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_launcher_is_not_the_child() {
        // The test process was not started by `detach`.
        assert!(!is_child());
        assert!(pid_file().is_none());
    }

    #[test]
    fn removing_a_pid_file_we_do_not_have_is_harmless() {
        remove_pid_file();
    }

    #[test]
    fn the_candidate_list_always_ends_somewhere_relative() {
        let candidates = pid_file_candidates();

        assert_eq!(
            candidates.first().unwrap(),
            &PathBuf::from("/var/run/sightingdb.pid")
        );
        // A last resort that works even with no home and no privileges.
        assert_eq!(
            candidates.last().unwrap(),
            &PathBuf::from("./sightingdb.pid")
        );
    }
}
