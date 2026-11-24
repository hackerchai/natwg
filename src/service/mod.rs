//! natwg as a system service: a LaunchDaemon on macOS and a systemd unit on
//! Linux. Each runs `natwg daemon` from [`BINARY`], a root-owned copy, so
//! root never runs a binary that a user can replace.

pub mod launchd;
pub mod systemd;

#[cfg(target_os = "macos")]
use launchd as manager;
#[cfg(not(target_os = "macos"))]
use systemd as manager;

use crate::config::{self, Config, Instance};
use crate::{Error, Result, status};
use std::{
    fmt::Write as _,
    fs,
    io::Write as _,
    os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    time::{Duration, Instant},
};

pub const BINARY: &str = "/usr/local/libexec/natwg/natwg";

// The commands run as root, so PATH holds only system directories.
const SYSTEM_PATH: &str = "/usr/sbin:/usr/bin:/sbin:/bin";

// launchd and systemd give a stopping server 15 s before they kill it.
const STOP_WAIT: Duration = Duration::from_secs(20);
const START_WAIT: Duration = Duration::from_secs(15);
const POLL: Duration = Duration::from_millis(250);

/// The server of `instance` as the service manager runs it, reading
/// `config`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Service {
    pub instance: Instance,
    pub config: PathBuf,
}

/// What the service manager knows about a job.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum State {
    /// The manager has no such job.
    Missing,
    /// The job is loaded and has no process, for the reason given.
    Stopped(String),
    Running(u32),
}

/// Copy this natwg to [`BINARY`], write the service definition for the
/// server in `config`, and start it. A part that is already in place stays,
/// so a second run with nothing changed keeps the running server.
pub fn install(config: &Path) -> Result<String> {
    require_root()?;
    // Everything that can refuse the install runs before the host changes.
    let service = load(config)?;
    let text = manager::definition(&service)?;
    let name = manager::name(&service.instance);
    let before = manager::state(&name)?;
    // Only natwg's own directory: the directory of a config elsewhere can
    // hold files that other software needs to read.
    let default_dir = Path::new(config::DEFAULT_PATH)
        .parent()
        .and_then(|dir| fs::canonicalize(dir).ok());
    if let Some(dir) = default_dir.filter(|dir| service.config.parent() == Some(dir)) {
        config::make_private_dir(&dir)?;
    }
    let binary = install_binary()?;
    let definition = manager::definition_path(&service.instance);
    let defined = write_if_changed(&definition, text.as_bytes(), 0o644)?;
    let action = match before {
        State::Missing => {
            manager::load(&service)?;
            "started"
        }
        _ if binary || defined => {
            manager::unload(&name)?;
            manager::load(&service)?;
            "restarted"
        }
        State::Stopped(_) => {
            manager::kick(&name)?;
            "started"
        }
        State::Running(_) => "unchanged",
    };
    let pid = wait_running(&service, None)?;
    let changed = |changed| if changed { "written" } else { "unchanged" };
    let mut report = String::new();
    let _ = writeln!(report, "binary     {BINARY} ({})", changed(binary));
    let _ = writeln!(
        report,
        "definition {} ({})",
        definition.display(),
        changed(defined)
    );
    let _ = writeln!(report, "config     {}", service.config.display());
    let _ = writeln!(report, "log        {}", manager::log(&service.instance));
    let _ = write!(report, "service    {name} running, pid {pid} ({action})");
    Ok(report)
}

/// Stop the service of the server in `config` and remove its definition
/// and its status file. `purge` also deletes the config and, when no other
/// natwg service is left, the binary.
pub fn uninstall(config: &Path, purge: bool) -> Result<String> {
    require_root()?;
    let parsed = Config::load(config)?;
    let server = parsed.server()?;
    let name = manager::name(&server.instance);
    let mut report = String::new();
    let loaded = manager::state(&name)? != State::Missing;
    if loaded {
        manager::unload(&name)?;
        let _ = writeln!(report, "stopped {name}");
    }
    let definition = manager::definition_path(&server.instance);
    let mut removed = Vec::new();
    if remove(&definition)? {
        manager::forget(&name)?;
        removed.push(definition);
    }
    let status = status::path(server);
    if remove(&status)? {
        removed.push(status);
    }
    if purge {
        if remove(config)? {
            removed.push(config.to_owned());
        }
        if manager::installed()?.is_empty() && remove(Path::new(BINARY))? {
            removed.push(BINARY.into());
        }
    }
    if !loaded && removed.is_empty() {
        let _ = writeln!(report, "{name} is not installed");
    }
    for path in &removed {
        let _ = writeln!(report, "removed {}", path.display());
    }
    if !purge {
        let _ = writeln!(
            report,
            "kept {BINARY} and {}; --purge deletes them",
            config.display()
        );
    }
    Ok(report.trim_end().to_owned())
}

/// Restart the service of the server in `config`, which then reads its
/// config again.
pub fn restart(config: &Path) -> Result<String> {
    require_root()?;
    let service = load(config)?;
    let name = manager::name(&service.instance);
    let before = match manager::state(&name)? {
        State::Missing => {
            return Err(Error::new(
                "SERVICE_NOT_INSTALLED",
                format!("{name} is not loaded; run natwg service install"),
            ));
        }
        State::Running(pid) => Some(pid),
        State::Stopped(_) => None,
    };
    manager::restart(&name)?;
    let pid = wait_running(&service, before)?;
    Ok(format!("{name} running, pid {pid} (restarted)"))
}

/// Every natwg service on this host, by its launchd label or systemd unit,
/// and its state. Needs no root.
pub fn status() -> Result<Vec<(String, State)>> {
    let mut services = Vec::new();
    for name in manager::installed()? {
        let state = manager::state(&name)?;
        services.push((name, state));
    }
    Ok(services)
}

impl std::fmt::Display for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Missing => f.write_str("defined but not loaded"),
            Self::Stopped(reason) => write!(f, "not running: {reason}"),
            Self::Running(pid) => write!(f, "running, pid {pid}"),
        }
    }
}

fn load(config: &Path) -> Result<Service> {
    let config = canonical(config)?;
    let instance = Config::load(&config)?.server()?.instance.clone();
    Ok(Service { instance, config })
}

fn canonical(path: &Path) -> Result<PathBuf> {
    fs::canonicalize(path)
        .map_err(|e| Error::new("CONFIG_UNREADABLE", format!("{}: {e}", path.display())))
}

fn require_root() -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(Error::new(
            "NOT_ROOT",
            "natwg service changes a system service; run it as root",
        ));
    }
    Ok(())
}

/// Copy the running natwg to [`BINARY`] unless the same bytes are there.
/// Returns whether it wrote.
fn install_binary() -> Result<bool> {
    let running = std::env::current_exe().map_err(|e| storage(Path::new("natwg"), e))?;
    let bytes = fs::read(&running).map_err(|e| storage(&running, e))?;
    write_if_changed(Path::new(BINARY), &bytes, 0o755)
}

/// Atomically replace `path` with `bytes`, owned by root with `mode`, unless
/// it holds them already with that owner and mode. Returns whether it wrote.
fn write_if_changed(path: &Path, bytes: &[u8], mode: u32) -> Result<bool> {
    let fail = |e| storage(path, e);
    let current = fs::symlink_metadata(path)
        .ok()
        .filter(|meta| meta.is_file() && meta.uid() == 0 && meta.mode() & 0o7777 == mode);
    if current.is_some() && fs::read(path).is_ok_and(|old| old == bytes) {
        return Ok(false);
    }
    let dir = path.parent().expect("a service path has a directory");
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o755)
        .create(dir)
        .map_err(fail)?;
    let mut stage = tempfile::NamedTempFile::new_in(dir).map_err(fail)?;
    stage
        .as_file()
        .set_permissions(fs::Permissions::from_mode(mode))
        .map_err(fail)?;
    stage
        .write_all(bytes)
        .and_then(|()| stage.as_file().sync_all())
        .map_err(fail)?;
    stage.persist(path).map_err(|e| fail(e.error))?;
    Ok(true)
}

/// Remove `path` if it exists. Returns whether it did.
fn remove(path: &Path) -> Result<bool> {
    match fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(storage(path, e)),
    }
}

fn storage(path: &Path, error: std::io::Error) -> Error {
    Error::new("SERVICE_STORAGE", format!("{}: {error}", path.display()))
}

/// Wait until the job runs with a process other than `not`, and return its
/// process ID.
fn wait_running(service: &Service, not: Option<u32>) -> Result<u32> {
    let name = manager::name(&service.instance);
    let deadline = Instant::now() + START_WAIT;
    loop {
        let state = manager::state(&name)?;
        match state {
            State::Running(pid) if Some(pid) != not => return Ok(pid),
            _ if Instant::now() >= deadline => {
                return Err(Error::new(
                    "SERVICE_NOT_RUNNING",
                    format!(
                        "{name} did not run within {} s and is {state}; see {}",
                        START_WAIT.as_secs(),
                        manager::log(&service.instance)
                    ),
                ));
            }
            _ => std::thread::sleep(POLL),
        }
    }
}

/// Wait until the job has no process, or is gone when `gone` is set.
fn wait_stopped(name: &str, gone: bool) -> Result<()> {
    let deadline = Instant::now() + STOP_WAIT;
    loop {
        let state = manager::state(name)?;
        let done = match state {
            State::Missing => true,
            State::Stopped(_) => !gone,
            State::Running(_) => false,
        };
        if done {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(Error::new(
                "SERVICE_STILL_RUNNING",
                format!(
                    "{name} did not stop within {} s and is {state}",
                    STOP_WAIT.as_secs()
                ),
            ));
        }
        std::thread::sleep(POLL);
    }
}

/// Run a command of the service manager and return what it did, whatever
/// its exit status.
fn manage(argv: &[&str]) -> Result<Output> {
    let (program, args) = argv.split_first().expect("a command has a program");
    Command::new(program)
        .args(args)
        .env_clear()
        .env("PATH", SYSTEM_PATH)
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .output()
        .map_err(|e| Error::new("SERVICE_MANAGER", format!("`{}`: {e}", argv.join(" "))))
}

/// Run a command of the service manager and fail unless it exits 0.
fn manage_ok(argv: &[&str]) -> Result<Output> {
    checked(argv, manage(argv)?)
}

fn checked(argv: &[&str], output: Output) -> Result<Output> {
    if !output.status.success() {
        return Err(Error::new(
            "SERVICE_MANAGER",
            format!(
                "`{}`: {}: {}",
                argv.join(" "),
                output.status,
                String::from_utf8_lossy(&output.stderr).trim()
            ),
        ));
    }
    Ok(output)
}

/// A value that may stand in a plist or a unit: UTF-8 with no control
/// character.
fn text(path: &Path) -> Result<&str> {
    path.to_str()
        .filter(|text| !text.chars().any(char::is_control))
        .ok_or_else(|| {
            Error::new(
                "SERVICE_PATH",
                format!(
                    "{}: a service path must be UTF-8 with no control character",
                    path.display()
                ),
            )
        })
}
