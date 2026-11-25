//! The macOS service: a LaunchDaemon in the system domain, labeled
//! `com.hackerchai.natwg` for the instance `natwg` and
//! `com.hackerchai.natwg.<instance>` for any other.

use super::{BINARY, Service, State, checked, manage, manage_ok, text, wait_stopped};
use crate::Result;
use crate::config::Instance;
use std::{
    fs,
    os::unix::fs::DirBuilderExt,
    path::{Path, PathBuf},
};

const PREFIX: &str = "com.hackerchai.natwg";
const DAEMONS: &str = "/Library/LaunchDaemons";
const LOG_DIR: &str = "/usr/local/var/log";

// launchctl exits with this status for a job that is not loaded.
const NO_SUCH_JOB: i32 = 113;

pub fn name(instance: &Instance) -> String {
    match instance.as_str() {
        "natwg" => PREFIX.to_owned(),
        other => format!("{PREFIX}.{other}"),
    }
}

pub fn definition_path(instance: &Instance) -> PathBuf {
    definition_of(&name(instance))
}

/// The plist of the job `name`.
pub fn definition_of(name: &str) -> PathBuf {
    Path::new(DAEMONS).join(format!("{name}.plist"))
}

/// The config that a plist of [`definition`] passes to `natwg daemon`.
pub fn config_of(plist: &str) -> Option<PathBuf> {
    let arguments = plist
        .split_once("<key>ProgramArguments</key>")?
        .1
        .split_once("</array>")?
        .0;
    let words: Vec<String> = arguments
        .split("<string>")
        .skip(1)
        .map(|word| Some(unxml(word.split_once("</string>")?.0)))
        .collect::<Option<_>>()?;
    let at = words.iter().position(|word| word == "--config")?;
    words.get(at + 1).map(PathBuf::from)
}

/// The directory of the logs, which launchd opens as root.
pub fn log_dir() -> Option<&'static Path> {
    Some(Path::new(LOG_DIR))
}

/// Where launchd writes what the server prints.
pub fn log(instance: &Instance) -> String {
    let file = match instance.as_str() {
        "natwg" => "natwg.log".to_owned(),
        other => format!("natwg-{other}.log"),
    };
    format!("{LOG_DIR}/{file}")
}

/// The plist. A first build that fails ends the server, as when the uplink
/// is not up yet at boot, so launchd starts it again, at most every 10 s.
/// launchd sends SIGTERM on stop, and the server then removes its utun,
/// route and NAT rule within the 15 s before launchd kills it.
pub fn definition(service: &Service) -> Result<String> {
    let log = xml(&log(&service.instance));
    let arguments = [BINARY, "--config", text(&service.config)?, "daemon"]
        .map(|argument| format!("    <string>{}</string>\n", xml(argument)))
        .concat();
    Ok(format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>{label}</string>
  <key>ProgramArguments</key>
  <array>
{arguments}  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ThrottleInterval</key><integer>10</integer>
  <key>ExitTimeOut</key><integer>15</integer>
  <key>StandardOutPath</key><string>{log}</string>
  <key>StandardErrorPath</key><string>{log}</string>
</dict>
</plist>
"#,
        label = name(&service.instance),
    ))
}

fn xml(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn unxml(value: &str) -> String {
    value
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}

fn target(name: &str) -> String {
    format!("system/{name}")
}

pub fn state(name: &str) -> Result<State> {
    let argv = ["launchctl", "print", &target(name)];
    let output = manage(&argv)?;
    if output.status.code() == Some(NO_SUCH_JOB) {
        return Ok(State::Missing);
    }
    let printed = String::from_utf8_lossy(&checked(&argv, output)?.stdout).into_owned();
    let field = |key: &str| {
        printed
            .lines()
            .find_map(|line| line.strip_prefix(&format!("\t{key} = ")))
            .map(str::to_owned)
    };
    let state = field("state").unwrap_or_default();
    let runs = field("runs")
        .and_then(|runs| runs.parse().ok())
        .unwrap_or(0);
    match field("pid").and_then(|pid| pid.parse().ok()) {
        Some(pid) if state == "running" => Ok(State::Running { pid, runs }),
        _ => Ok(State::Stopped(format!(
            "{state}, last exit code {}",
            field("last exit code").unwrap_or_default()
        ))),
    }
}

/// The last `lines` lines that the servers of `instance` printed.
pub fn recent_log(instance: &Instance, lines: usize) -> String {
    let text = fs::read_to_string(log(instance)).unwrap_or_default();
    super::last_lines(&text, lines)
}

/// Load the plist, which starts the server. launchd opens the log before
/// natwg runs, so its directory must exist.
pub fn load(service: &Service) -> Result<()> {
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o755)
        .create(LOG_DIR)
        .map_err(|e| super::storage(Path::new(LOG_DIR), e))?;
    let plist = definition_path(&service.instance);
    manage_ok(&["launchctl", "bootstrap", "system", super::text(&plist)?])?;
    Ok(())
}

/// Stop the server and unload the job. `launchctl bootout` can return
/// before the job is gone, and a bootstrap fails until it is.
pub fn unload(name: &str) -> Result<()> {
    manage(&["launchctl", "bootout", &target(name)])?;
    wait_stopped(name, true)
}

/// Start a loaded job that has no process.
pub fn kick(name: &str) -> Result<()> {
    manage_ok(&["launchctl", "kickstart", &target(name)])?;
    Ok(())
}

pub fn restart(name: &str) -> Result<()> {
    manage_ok(&["launchctl", "kickstart", "-k", &target(name)])?;
    Ok(())
}

/// launchd keeps nothing of a job once it is unloaded.
pub fn forget(_: &str) -> Result<()> {
    Ok(())
}

/// The labels of every natwg plist in the LaunchDaemons directory.
pub fn installed() -> Result<Vec<String>> {
    let entries = fs::read_dir(DAEMONS).map_err(|e| super::storage(Path::new(DAEMONS), e))?;
    let mut names: Vec<String> = entries
        .filter_map(|entry| entry.ok()?.file_name().into_string().ok())
        .filter_map(|file| Some(file.strip_suffix(".plist")?.to_owned()))
        .filter(|name| name == PREFIX || name.starts_with(&format!("{PREFIX}.")))
        .collect();
    names.sort();
    Ok(names)
}
