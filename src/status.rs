//! The status file that `natwg server` writes every 10 s and `natwg status`
//! reads without root. Anyone can read it, so it holds no secret. Every time
//! in it is in Unix seconds.

use crate::config::ServerConfig;
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::{
    fmt::Write as _,
    io::Write as _,
    net::{SocketAddr, SocketAddrV4},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

#[cfg(target_os = "macos")]
pub const DEFAULT_PATH: &str = "/usr/local/var/natwg/status.json";
#[cfg(not(target_os = "macos"))]
pub const DEFAULT_PATH: &str = "/run/natwg/status.json";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Status {
    pub updated: u64,
    /// The process ID of the server that wrote the status.
    pub pid: u32,
    pub iface: String,
    pub listen_port: u16,
    /// The TUN of the running tunnel, or none while natwg rebuilds it.
    pub tun: Option<String>,
    pub mapping: Option<SocketAddrV4>,
    pub mapping_since: Option<u64>,
    pub last_stun_ok: Option<u64>,
    /// STUN requests in a row that got no answer.
    pub stun_misses: u32,
    /// What the TXT record holds since natwg last wrote it.
    pub published: Option<SocketAddrV4>,
    pub published_at: Option<u64>,
    pub publish_error: Option<String>,
    /// None when the config has no UPnP section or the first lease is pending.
    pub upnp_ok: Option<bool>,
    pub upnp_at: Option<u64>,
    /// None while no tunnel runs.
    pub nat_ok: Option<bool>,
    /// How many times natwg rebuilt a tunnel that died.
    pub rebuilds: u32,
    pub peers: Vec<PeerStatus>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerStatus {
    /// The first characters of the public key in base64.
    pub key: String,
    pub endpoint: Option<SocketAddr>,
    pub last_handshake: Option<u64>,
    pub rx: u64,
    pub tx: u64,
}

/// Where the server writes its status: `role.server.status_file`, or
/// [`DEFAULT_PATH`] for the instance `natwg` and `<instance>.status.json`
/// beside it for any other, so two servers never share one file.
pub fn path(server: &ServerConfig) -> PathBuf {
    if let Some(path) = &server.status_file {
        return path.clone();
    }
    match server.instance.as_str() {
        "natwg" => PathBuf::from(DEFAULT_PATH),
        other => Path::new(DEFAULT_PATH).with_file_name(format!("{other}.status.json")),
    }
}

pub fn unix(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

impl Status {
    /// Atomically replace `path` with this status, readable by everyone.
    pub fn write(&self, path: &Path) -> Result<()> {
        let storage =
            |e: std::io::Error| Error::new("STATUS_STORAGE", format!("{}: {e}", path.display()));
        let mut text = serde_json::to_string_pretty(self).expect("a status always serializes");
        text.push('\n');
        let dir = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        std::fs::create_dir_all(dir).map_err(storage)?;
        let mut stage = tempfile::NamedTempFile::new_in(dir).map_err(storage)?;
        stage
            .as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o644))
            .map_err(storage)?;
        stage.write_all(text.as_bytes()).map_err(storage)?;
        stage.persist(path).map_err(|e| storage(e.error))?;
        Ok(())
    }

    pub fn read(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path).map_err(|e| {
            Error::new(
                "STATUS_UNREADABLE",
                format!("{}: {e}; is natwg server running?", path.display()),
            )
        })?;
        serde_json::from_str(&text)
            .map_err(|e| Error::new("STATUS_INVALID", format!("{}: {e}", path.display())))
    }

    /// The status for people to read, with times as their age at `now`.
    pub fn render(&self, now: u64) -> String {
        let age = |time: Option<u64>| match time {
            Some(time) => format!("{}s ago", now.saturating_sub(time)),
            None => "never".to_owned(),
        };
        let or_none = |value: Option<String>| value.unwrap_or_else(|| "none".to_owned());
        let health = |ok: Option<bool>| match ok {
            Some(true) => "ok",
            Some(false) => "failed",
            None => "off",
        };
        let error = self
            .publish_error
            .as_ref()
            .map(|error| format!("  ERROR: {error}"))
            .unwrap_or_default();
        let mut text = String::new();
        let lines = [
            format!(
                "public endpoint : {} (since {})",
                or_none(self.mapping.map(|m| m.to_string())),
                age(self.mapping_since)
            ),
            format!(
                "published TXT   : {} ({}){error}",
                or_none(self.published.map(|p| p.to_string())),
                age(self.published_at)
            ),
            format!(
                "last STUN reply : {}, misses={}",
                age(self.last_stun_ok),
                self.stun_misses
            ),
            format!(
                "upnp/nat        : {} / {}",
                health(self.upnp_ok),
                health(self.nat_ok)
            ),
            format!(
                "tunnel          : {} on {} udp/{}, rebuilds={}",
                or_none(self.tun.clone()),
                self.iface,
                self.listen_port,
                self.rebuilds
            ),
        ];
        for line in lines {
            let _ = writeln!(text, "{line}");
        }
        for peer in &self.peers {
            let _ = writeln!(
                text,
                "peer {} endpoint={} handshake={} rx={} tx={}",
                peer.key,
                or_none(peer.endpoint.map(|e| e.to_string())),
                age(peer.last_handshake),
                peer.rx,
                peer.tx
            );
        }
        let _ = writeln!(text, "status written  : {}", age(Some(self.updated)));
        text
    }
}
