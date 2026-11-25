//! The Linux service: a systemd unit, `natwg.service` for the instance
//! `natwg` and `natwg-<instance>.service` for any other.

use super::{BINARY, Service, State, manage, manage_ok, text, wait_stopped};
use crate::Result;
use crate::config::Instance;
use std::{
    fs,
    path::{Path, PathBuf},
};

const UNITS: &str = "/etc/systemd/system";

pub fn name(instance: &Instance) -> String {
    match instance.as_str() {
        "natwg" => "natwg.service".to_owned(),
        other => format!("natwg-{other}.service"),
    }
}

pub fn definition_path(instance: &Instance) -> PathBuf {
    definition_of(&name(instance))
}

/// The unit file of the unit `name`.
pub fn definition_of(name: &str) -> PathBuf {
    Path::new(UNITS).join(name)
}

/// The config that a unit of [`definition`] passes to `natwg daemon`.
pub fn config_of(unit: &str) -> Option<PathBuf> {
    let command = unit
        .lines()
        .find_map(|line| line.strip_prefix("ExecStart="))?;
    let words = unquote(command)?;
    let at = words.iter().position(|word| word == "--config")?;
    words.get(at + 1).map(PathBuf::from)
}

/// None, because the journal keeps the logs.
pub fn log_dir() -> Option<&'static Path> {
    None
}

/// Where the server's output goes: the journal.
pub fn log(instance: &Instance) -> String {
    format!("journalctl -u {}", name(instance))
}

/// The unit. A first build that fails ends the server or the client, as
/// when the uplink is not up yet at boot, so systemd starts it again after
/// 10 s. systemd sends SIGTERM on stop, and natwg then removes its TUN,
/// routes and NAT table within the 15 s before systemd kills it.
pub fn definition(service: &Service) -> Result<String> {
    let command = [BINARY, "--config", text(&service.config)?, "daemon"]
        .map(quote)
        .join(" ");
    let role = if service.instance.is_client() {
        "client".to_owned()
    } else {
        format!("server {}", service.instance)
    };
    Ok(format!(
        "[Unit]
Description=natwg WireGuard {role}
Wants=network-online.target
After=network-online.target

[Service]
Type=exec
ExecStart={command}
Restart=always
RestartSec=10
TimeoutStopSec=15

[Install]
WantedBy=multi-user.target
"
    ))
}

// systemd unquotes a quoted word with C escapes, and it expands `%`
// specifiers and `$` variables inside it.
fn quote(word: &str) -> String {
    let escaped = word
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('%', "%%")
        .replace('$', "$$");
    format!("\"{escaped}\"")
}

/// The words of a command line that [`quote`] wrote.
fn unquote(command: &str) -> Option<Vec<String>> {
    let mut words = Vec::new();
    let mut chars = command.trim().chars().peekable();
    while let Some(first) = chars.next() {
        if first == ' ' {
            continue;
        }
        if first != '"' {
            return None;
        }
        let mut word = String::new();
        loop {
            match chars.next()? {
                '"' => break,
                '\\' => word.push(chars.next()?),
                c @ ('%' | '$') => {
                    if chars.next()? != c {
                        return None;
                    }
                    word.push(c);
                }
                c => word.push(c),
            }
        }
        words.push(word);
    }
    Some(words)
}

pub fn state(name: &str) -> Result<State> {
    let shown = manage_ok(&[
        "systemctl",
        "show",
        "--property=LoadState,ActiveState,SubState,MainPID,NRestarts",
        name,
    ])?;
    let shown = String::from_utf8_lossy(&shown.stdout).into_owned();
    let field = |key: &str| {
        shown
            .lines()
            .find_map(|line| line.strip_prefix(key)?.strip_prefix('='))
            .unwrap_or_default()
    };
    if field("LoadState") == "not-found" {
        return Ok(State::Missing);
    }
    let (active, sub) = (field("ActiveState"), field("SubState"));
    let runs = field("NRestarts").parse().unwrap_or(0);
    match field("MainPID").parse() {
        Ok(pid) if active == "active" && pid > 0 => Ok(State::Running { pid, runs }),
        _ => Ok(State::Stopped(format!("{active} ({sub})"))),
    }
}

/// The last `lines` lines that the servers of `instance` printed.
pub fn recent_log(instance: &Instance, lines: usize) -> String {
    let lines = lines.to_string();
    let unit = name(instance);
    let argv = [
        "journalctl",
        "-u",
        &unit,
        "-n",
        &lines,
        "--no-pager",
        "-o",
        "cat",
    ];
    manage(&argv).map_or_else(
        |error| error.to_string(),
        |output| {
            String::from_utf8_lossy(&output.stdout)
                .trim_end()
                .to_owned()
        },
    )
}

/// Load the unit, enable it for boot and start it.
pub fn load(service: &Service) -> Result<()> {
    manage_ok(&["systemctl", "daemon-reload"])?;
    manage_ok(&["systemctl", "enable", "--now", &name(&service.instance)])?;
    Ok(())
}

pub fn unload(name: &str) -> Result<()> {
    manage_ok(&["systemctl", "disable", "--now", name])?;
    wait_stopped(name, false)
}

/// Start a loaded unit that has no process.
pub fn kick(name: &str) -> Result<()> {
    manage_ok(&["systemctl", "start", name])?;
    Ok(())
}

pub fn restart(name: &str) -> Result<()> {
    manage_ok(&["systemctl", "restart", name])?;
    Ok(())
}

/// Drop a removed unit from systemd's memory, and a failed state with it.
pub fn forget(name: &str) -> Result<()> {
    manage_ok(&["systemctl", "daemon-reload"])?;
    manage(&["systemctl", "reset-failed", name])?;
    Ok(())
}

/// The units of every natwg service in the system unit directory.
pub fn installed() -> Result<Vec<String>> {
    let entries = fs::read_dir(UNITS).map_err(|e| super::storage(Path::new(UNITS), e))?;
    let mut names: Vec<String> = entries
        .filter_map(|entry| entry.ok()?.file_name().into_string().ok())
        .filter(|file| {
            file == "natwg.service"
                || file
                    .strip_prefix("natwg-")
                    .is_some_and(|rest| rest.ends_with(".service"))
        })
        .collect();
    names.sort();
    Ok(names)
}
