//! natwg as a system service: a LaunchDaemon on macOS and a systemd unit on
//! Linux. Each runs `natwg daemon` from [`BINARY`], a root-owned copy, so
//! root never runs a binary that a user can replace.

pub mod launchd;
pub mod systemd;

#[cfg(target_os = "macos")]
use launchd as manager;
#[cfg(not(target_os = "macos"))]
use systemd as manager;

use crate::config::{self, Config, Instance, Role};
use crate::status::{self, Report};
use crate::{Error, Result};
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
// A server whose first start fails, as when the old one still holds the
// port, gets one more start 10 s later within this time.
const SERVE_WAIT: Duration = Duration::from_secs(30);
const POLL: Duration = Duration::from_millis(250);
const LOG_LINES: usize = 8;

/// The server of `instance`, or the client when `instance` is
/// [`Instance::client`], as the service manager runs it, reading `config`.
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
    /// The job runs the process `pid`, and the manager started it `runs`
    /// times since it loaded the job.
    Running { pid: u32, runs: u32 },
}

/// Copy this natwg to [`BINARY`], write the service definition for the
/// server or the client in `config`, and start it. A part that is already in place stays,
/// so a second run with nothing changed keeps the running server.
pub fn install(config: &Path) -> Result<String> {
    install_service(config, false)
}

/// Init wrote new keys. A running service must load them even when its
/// binary and unit already match, as when --force also changed the port.
pub fn install_new_config(config: &Path) -> Result<String> {
    install_service(config, true)
}

fn install_service(config: &Path, config_changed: bool) -> Result<String> {
    require_root()?;
    // Everything that can refuse the install runs before the host changes.
    let (service, status) = load(config)?;
    let text = manager::definition(&service)?;
    let binary_dir = Path::new(BINARY).parent().expect("BINARY has a directory");
    for dir in std::iter::once(binary_dir).chain(manager::log_dir()) {
        require_root_only(dir)?;
    }
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
        State::Running { .. } if config_changed => {
            manager::restart(&name)?;
            "restarted"
        }
        State::Running { .. } => "unchanged",
    };
    let old_pid = match before {
        State::Running { pid, .. } if action == "restarted" => Some(pid),
        _ => None,
    };
    let pid = wait_serving(&service, &status, old_pid)?;
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

/// Stop the service of the server or the client in `config` and remove its
/// definition and its status file. `purge` also deletes the config and, when
/// no other natwg service is left, the binary.
pub fn uninstall(config: &Path, purge: bool) -> Result<String> {
    require_root()?;
    let (instance, status) = identify(&Config::load(config)?);
    let files = Files {
        config,
        status,
        purge,
    };
    remove_service(&instance, Some(files))
}

/// Stop the service of `instance` and remove its definition without a
/// config, as when the config is broken or gone. The status file stays,
/// because only the config says where it is.
pub fn uninstall_instance(instance: &Instance) -> Result<String> {
    require_root()?;
    remove_service(instance, None)
}

/// The files of a service that only its config names.
struct Files<'a> {
    config: &'a Path,
    status: PathBuf,
    purge: bool,
}

fn remove_service(instance: &Instance, files: Option<Files>) -> Result<String> {
    let name = manager::name(instance);
    let mut report = String::new();
    let loaded = manager::state(&name)? != State::Missing;
    if loaded {
        manager::unload(&name)?;
        let _ = writeln!(report, "stopped {name}");
    }
    let definition = manager::definition_path(instance);
    let mut removed = Vec::new();
    if remove(&definition)? {
        manager::forget(&name)?;
        removed.push(definition);
    }
    if let Some(files) = &files {
        if remove(&files.status)? {
            removed.push(files.status.clone());
        }
        if files.purge {
            if remove(files.config)? {
                removed.push(files.config.to_owned());
            }
            if manager::installed()?.is_empty() {
                // The last natwg service is gone: so go its binary, the
                // binary that the last natwg update replaced, and the update
                // check that the services shared.
                let previous = crate::update::backup_path(Path::new(BINARY));
                let cache = Path::new(crate::update::CHECK_CACHE);
                for path in [Path::new(BINARY), &previous, cache] {
                    if remove(path)? {
                        removed.push(path.to_owned());
                    }
                }
                if let Some(dir) = Path::new(BINARY).parent()
                    && fs::remove_dir(dir).is_ok()
                {
                    removed.push(dir.to_owned());
                }
            }
        }
    }
    if !loaded && removed.is_empty() {
        let _ = writeln!(report, "{name} is not installed");
    }
    for path in &removed {
        let _ = writeln!(report, "removed {}", path.display());
    }
    match files {
        Some(files) if !files.purge => {
            let config = files.config.display();
            let _ = writeln!(report, "kept {BINARY} and {config}; --purge deletes them");
        }
        Some(_) => {}
        None => {
            let _ = writeln!(report, "kept {BINARY}, the config and the status file");
        }
    }
    Ok(report.trim_end().to_owned())
}

/// Restart the service of the server or the client in `config`, which then
/// reads its config again.
pub fn restart(config: &Path) -> Result<String> {
    require_root()?;
    let (service, status) = load(config)?;
    let name = manager::name(&service.instance);
    if manager::state(&name)? == State::Missing {
        return Err(Error::new(
            "SERVICE_NOT_INSTALLED",
            format!("{name} is not loaded; run natwg service install"),
        ));
    }
    let job = Job {
        name,
        service,
        status,
    };
    let pid = restart_job(&job)?;
    Ok(format!("{job} running, pid {pid} (restarted)"))
}

/// A natwg service as its definition names it, which `natwg update`
/// restarts.
pub struct Job {
    name: String,
    service: Service,
    status: PathBuf,
}

impl std::fmt::Display for Job {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.name)
    }
}

/// Every natwg service that runs a process now, with the config that its
/// definition names. Needs root, because only root reads the configs. A
/// config that no longer loads, or now names another service, fails.
pub fn running() -> Result<Vec<Job>> {
    let mut jobs = Vec::new();
    for name in manager::installed()? {
        if !matches!(manager::state(&name)?, State::Running { .. }) {
            continue;
        }
        let definition = manager::definition_of(&name);
        let text = fs::read_to_string(&definition).map_err(|e| storage(&definition, e))?;
        let config = manager::config_of(&text).ok_or_else(|| {
            Error::new(
                "SERVICE_DEFINITION",
                format!(
                    "{} names no --config; run natwg service install again",
                    definition.display()
                ),
            )
        })?;
        let (service, status) = load(&config)?;
        let named = manager::name(&service.instance);
        if named != name {
            return Err(Error::new(
                "SERVICE_DEFINITION",
                format!(
                    "{name} runs {}, which now belongs to {named}; run natwg service install with that config",
                    config.display()
                ),
            ));
        }
        jobs.push(Job {
            name,
            service,
            status,
        });
    }
    Ok(jobs)
}

/// Restart `job` and wait until a process other than the one that ran
/// before brings its tunnel up. Returns its process ID.
pub fn restart_job(job: &Job) -> Result<u32> {
    let before = match manager::state(&job.name)? {
        State::Running { pid, .. } => Some(pid),
        _ => None,
    };
    manager::restart(&job.name)?;
    wait_serving(&job.service, &job.status, before)
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
            Self::Running { pid, .. } => write!(f, "running, pid {pid}"),
        }
    }
}

/// The service of the server or the client in `config`, and where it
/// writes its status.
fn load(config: &Path) -> Result<(Service, PathBuf)> {
    let config = canonical(config)?;
    let (instance, status) = identify(&Config::load(&config)?);
    Ok((Service { instance, config }, status))
}

/// The instance that names the service of `config`, and its status file. A
/// client takes the instance `client`, which no server can have.
fn identify(config: &Config) -> (Instance, PathBuf) {
    match &config.role {
        Role::Server(server) => (server.instance.clone(), status::path(server)),
        Role::Client(client) => (Instance::client(), status::client_path(client)),
    }
}

/// Refuse `dir` unless root owns it and every directory above it, and no
/// group or other user can write any of them. Whoever can write one of
/// them can swap the binary that root runs, or point the log that launchd
/// opens as root at another file. The part of `dir` that does not exist yet
/// passes, because install creates it as root with mode 0755.
pub fn require_root_only(dir: &Path) -> Result<()> {
    let existing = dir
        .ancestors()
        .find(|dir| dir.exists())
        .unwrap_or(Path::new("/"));
    let real = fs::canonicalize(existing).map_err(|e| storage(existing, e))?;
    for dir in existing.ancestors().chain(real.ancestors()) {
        let meta = fs::metadata(dir).map_err(|e| storage(dir, e))?;
        if meta.uid() != 0 || meta.mode() & 0o022 != 0 {
            return Err(Error::new(
                "SERVICE_PATH_UNSAFE",
                format!(
                    "{}: owner uid {} and mode {:04o}; natwg installs only under directories that root owns and that no group or other user can write",
                    dir.display(),
                    meta.uid(),
                    meta.mode() & 0o7777
                ),
            ));
        }
    }
    Ok(())
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

/// Wait until the job runs a process other than `not` that wrote a running
/// tunnel to `status`, and return its process ID. A process ID alone proves
/// nothing, because launchd and systemd show one for every start of a
/// server that then exits, as on UDP_BIND.
fn wait_serving(service: &Service, status: &Path, not: Option<u32>) -> Result<u32> {
    let name = manager::name(&service.instance);
    let log = || manager::recent_log(&service.instance, LOG_LINES);
    until_serving(
        &name,
        || manager::state(&name),
        status,
        not,
        SERVE_WAIT,
        log,
    )
}

/// [`wait_serving`] with the job state from `state` and the end of the log
/// from `log`. The state must not change while natwg reads the status file,
/// so a status of a process that the manager replaced meanwhile does not
/// count.
fn until_serving(
    name: &str,
    mut state: impl FnMut() -> Result<State>,
    status: &Path,
    not: Option<u32>,
    wait: Duration,
    log: impl FnOnce() -> String,
) -> Result<u32> {
    let deadline = Instant::now() + wait;
    let wrote_a_tunnel = |pid| {
        Report::read(status).is_ok_and(|written| written.pid() == pid && written.has_tunnel())
    };
    loop {
        let before = state()?;
        if let State::Running { pid, .. } = before
            && Some(pid) != not
            && wrote_a_tunnel(pid)
            && state()? == before
        {
            return Ok(pid);
        }
        if Instant::now() >= deadline {
            return Err(Error::new(
                "SERVICE_NOT_STABLE",
                format!(
                    "{name} did not bring its tunnel up within {} s and is {before}. It stays installed, and its service manager keeps starting it. The log ends with:\n{}",
                    wait.as_secs(),
                    log()
                ),
            ));
        }
        std::thread::sleep(POLL);
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
            State::Running { .. } => false,
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

/// The last `count` lines of `text`.
fn last_lines(text: &str, count: usize) -> String {
    let lines: Vec<&str> = text.trim_end().lines().collect();
    lines[lines.len().saturating_sub(count)..].join("\n")
}

#[cfg(test)]
mod tests {
    use super::{State, until_serving};
    use crate::status::Status;
    use std::{path::Path, time::Duration};

    const NAME: &str = "com.hackerchai.natwg.natwg_test";
    const LOG: &str = "UDP_BIND: en6 udp/51839: Address already in use (os error 48)";
    const WAIT: Duration = Duration::from_millis(600);

    fn running(pid: u32, runs: u32) -> State {
        State::Running { pid, runs }
    }

    /// A status file in `dir` that the server `pid` wrote, with a running
    /// tunnel when `tun` is set.
    fn written(dir: &Path, pid: u32, tun: bool) -> std::path::PathBuf {
        let status: Status = serde_json::from_value(serde_json::json!({
            "updated": 1, "pid": pid, "iface": "en6", "listen_port": 51839,
            "tun": tun.then_some("utun13"), "mapping": null, "mapping_since": null,
            "last_stun_ok": null, "stun_misses": 0, "published": null,
            "published_at": null, "publish_error": null, "upnp_ok": null,
            "upnp_at": null, "nat_ok": null, "rebuilds": 0, "peers": [],
        }))
        .unwrap();
        let path = dir.join("status.json");
        status.write(&path).unwrap();
        path
    }

    fn wait(states: impl Fn(u32) -> State, status: &Path, not: Option<u32>) -> crate::Result<u32> {
        let mut calls = 0;
        let state = || {
            calls += 1;
            Ok(states(calls))
        };
        until_serving(NAME, state, status, not, WAIT, || LOG.to_owned())
    }

    #[test]
    fn the_process_that_wrote_a_running_tunnel_is_serving() {
        let dir = tempfile::tempdir().unwrap();
        let status = written(dir.path(), 200, true);
        assert_eq!(wait(|_| running(200, 3), &status, None).unwrap(), 200);
    }

    #[test]
    fn a_server_that_keeps_exiting_is_not_stable_and_the_error_quotes_the_log() {
        let dir = tempfile::tempdir().unwrap();
        let status = dir.path().join("status.json");
        let crash_loop = |call| match call % 3 {
            0 => State::Stopped("spawn scheduled, last exit code 1".into()),
            _ => running(100 + call, call),
        };
        let error = wait(crash_loop, &status, None).unwrap_err();
        assert_eq!(error.code, "SERVICE_NOT_STABLE");
        assert!(error.message.starts_with(NAME), "{}", error.message);
        assert!(error.message.ends_with(LOG), "{}", error.message);
    }

    #[test]
    fn a_status_that_another_process_wrote_does_not_count() {
        let dir = tempfile::tempdir().unwrap();
        let status = written(dir.path(), 199, true);
        let error = wait(|_| running(200, 3), &status, None).unwrap_err();
        assert_eq!(error.code, "SERVICE_NOT_STABLE");
    }

    #[test]
    fn a_status_without_a_tunnel_does_not_count() {
        let dir = tempfile::tempdir().unwrap();
        let status = written(dir.path(), 200, false);
        let error = wait(|_| running(200, 3), &status, None).unwrap_err();
        assert_eq!(error.code, "SERVICE_NOT_STABLE");
    }

    #[test]
    fn a_restart_waits_for_a_process_other_than_the_old_one() {
        let dir = tempfile::tempdir().unwrap();
        let status = written(dir.path(), 200, true);
        let error = wait(|_| running(200, 3), &status, Some(200)).unwrap_err();
        assert_eq!(error.code, "SERVICE_NOT_STABLE");
    }

    #[test]
    fn a_process_replaced_while_natwg_read_its_status_does_not_count() {
        let dir = tempfile::tempdir().unwrap();
        let status = written(dir.path(), 200, true);
        let replaced = |call| match call {
            1 => running(200, 3),
            _ => running(200 + call, 3 + call),
        };
        let error = wait(replaced, &status, None).unwrap_err();
        assert_eq!(error.code, "SERVICE_NOT_STABLE");
    }
}
