//! The status file that `natwg server` and `natwg client` write every 10 s
//! and `natwg status` reads without root. Anyone can read it, so it holds no
//! secret. Every time in it is in Unix seconds.

use crate::config::{ClientConfig, Instance, ServerConfig};
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::{
    fmt::Write as _,
    io::Write as _,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
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
    /// What the TXT record holds, as natwg last wrote or found it.
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
    match &server.status_file {
        Some(path) => path.clone(),
        None => instance_path(&server.instance),
    }
}

/// Where the client writes its status: `role.client.status_file`, or
/// `client.status.json` beside [`DEFAULT_PATH`], a name no server takes.
pub fn client_path(client: &ClientConfig) -> PathBuf {
    match &client.status_file {
        Some(path) => path.clone(),
        None => instance_path(&Instance::client()),
    }
}

fn instance_path(instance: &Instance) -> PathBuf {
    match instance.as_str() {
        "natwg" => PathBuf::from(DEFAULT_PATH),
        other => Path::new(DEFAULT_PATH).with_file_name(format!("{other}.status.json")),
    }
}

/// The status file `natwg status` reads when it is given none: the one of
/// the server `natwg`, else the client's when only that one exists.
pub fn default_path() -> PathBuf {
    let server = PathBuf::from(DEFAULT_PATH);
    let client = instance_path(&Instance::client());
    if !server.exists() && client.exists() {
        return client;
    }
    server
}

/// A status older than this many seconds means the server stopped writing
/// it, which it does every 10 s.
pub const STALE_AFTER: u64 = 60;

/// A WireGuard session lives 180 s. A client that only sends keepalives
/// does not renew it before then, and starts the next handshake with the
/// first keepalive after it expired, so with a keepalive every `keepalive`
/// seconds and 30 s for retries, an older handshake means the server does
/// not answer.
pub fn handshake_stale_after(keepalive: u16) -> u64 {
    180 + u64::from(keepalive) + 30
}

pub fn unix(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

/// Atomically replace `path` with `status`, readable by everyone.
fn write_public(path: &Path, status: &impl Serialize) -> Result<()> {
    let storage =
        |e: std::io::Error| Error::new("STATUS_STORAGE", format!("{}: {e}", path.display()));
    let mut text = serde_json::to_string_pretty(status).expect("a status always serializes");
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

fn read_text(path: &Path) -> Result<String> {
    std::fs::read_to_string(path).map_err(|e| {
        Error::new(
            "STATUS_UNREADABLE",
            format!("{}: {e}; is natwg running?", path.display()),
        )
    })
}

fn invalid(path: &Path, error: serde_json::Error) -> Error {
    Error::new("STATUS_INVALID", format!("{}: {error}", path.display()))
}

fn age(now: u64, time: Option<u64>) -> String {
    match time {
        Some(time) => format!("{}s ago", now.saturating_sub(time)),
        None => "never".to_owned(),
    }
}

fn or_none(value: Option<String>) -> String {
    value.unwrap_or_else(|| "none".to_owned())
}

impl Status {
    /// Atomically replace `path` with this status, readable by everyone.
    pub fn write(&self, path: &Path) -> Result<()> {
        write_public(path, self)
    }

    pub fn read(path: &Path) -> Result<Self> {
        serde_json::from_str(&read_text(path)?).map_err(|e| invalid(path, e))
    }

    /// What this status shows to be wrong at `now`, for people to read.
    /// None of it holds while the server serves: the status is fresh, a
    /// tunnel runs with its NAT rule, there is a public mapping, the last TXT
    /// publish worked, and UPnP did not fail. UPnP that is off is fine.
    pub fn problems(&self, now: u64) -> Vec<String> {
        let age = now.saturating_sub(self.updated);
        let tunnel = self.tun.is_some();
        [
            (age > STALE_AFTER, format!("the status is {age}s old")),
            (!tunnel, "no tunnel runs".to_owned()),
            (
                tunnel && self.nat_ok != Some(true),
                "NAT is not ok".to_owned(),
            ),
            (self.mapping.is_none(), "no public mapping".to_owned()),
            (
                self.publish_error.is_some(),
                "the TXT publish failed".to_owned(),
            ),
            (self.upnp_ok == Some(false), "UPnP failed".to_owned()),
        ]
        .into_iter()
        .filter_map(|(wrong, problem)| wrong.then_some(problem))
        .collect()
    }

    /// The status for people to read, with times as their age at `now`.
    pub fn render(&self, now: u64) -> String {
        let age = |time| age(now, time);
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

/// The tag that tells a client status from a server status, which has none.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientRole {
    Client,
}

/// What `natwg client` reports about its tunnel to the server.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientStatus {
    pub role: ClientRole,
    pub updated: u64,
    /// The process ID of the client that wrote the status.
    pub pid: u32,
    /// The interface the WireGuard and DNS traffic leaves through.
    pub uplink: Option<String>,
    pub uplink_address: Option<Ipv4Addr>,
    /// The TUN of the running tunnel, or none while natwg rebuilds it.
    pub tun: Option<String>,
    /// The TXT record that names the server's endpoint, if the config has one.
    pub record: Option<String>,
    /// Where natwg points the server peer.
    pub endpoint: Option<SocketAddrV4>,
    pub endpoint_since: Option<u64>,
    /// When the TXT record last gave a well-formed endpoint.
    pub looked_up: Option<u64>,
    /// Why the last TXT lookup failed, until one works.
    pub lookup_error: Option<String>,
    /// The persistent keepalive in seconds, 0 when it is off.
    pub keepalive: u16,
    /// How many times natwg rebuilt a tunnel that died or lost its uplink.
    pub rebuilds: u32,
    pub server: Option<PeerStatus>,
}

impl ClientStatus {
    /// Atomically replace `path` with this status, readable by everyone.
    pub fn write(&self, path: &Path) -> Result<()> {
        write_public(path, self)
    }

    /// What this status shows to be wrong at `now`. None of it holds while
    /// the client reaches the server: the status is fresh, a tunnel runs,
    /// natwg knows an endpoint, the last TXT lookup worked, and, with a
    /// keepalive, the last handshake is younger than a session.
    pub fn problems(&self, now: u64) -> Vec<String> {
        let age = now.saturating_sub(self.updated);
        let handshake = self
            .server
            .as_ref()
            .and_then(|server| server.last_handshake)
            .map(|at| now.saturating_sub(at));
        let tunnel = self.tun.is_some();
        let handshake_problem = match handshake {
            _ if !tunnel || self.keepalive == 0 => None,
            None => Some("no handshake yet".to_owned()),
            Some(ago) if ago > handshake_stale_after(self.keepalive) => {
                Some(format!("the last handshake is {ago}s old"))
            }
            Some(_) => None,
        };
        [
            (age > STALE_AFTER).then(|| format!("the status is {age}s old")),
            (!tunnel).then(|| "no tunnel runs".to_owned()),
            self.endpoint
                .is_none()
                .then(|| "no server endpoint".to_owned()),
            self.lookup_error
                .is_some()
                .then(|| "the TXT lookup failed".to_owned()),
            handshake_problem,
        ]
        .into_iter()
        .flatten()
        .collect()
    }

    /// The status for people to read, with times as their age at `now`.
    pub fn render(&self, now: u64) -> String {
        let age = |time| age(now, time);
        let source = match &self.record {
            Some(record) => format!("TXT {record}"),
            None => "config".to_owned(),
        };
        let lookup = match (&self.record, &self.lookup_error) {
            (None, _) => "off".to_owned(),
            (Some(_), None) => age(self.looked_up),
            (Some(_), Some(error)) => format!("{}  ERROR: {error}", age(self.looked_up)),
        };
        let uplink = match (&self.uplink, self.uplink_address) {
            (Some(name), Some(address)) => format!("{name} ({address})"),
            (Some(name), None) => format!("{name} (no IPv4 address)"),
            (None, _) => "none".to_owned(),
        };
        let handshake = match &self.server {
            Some(server) => format!(
                "{}, peer {} endpoint={} rx={} tx={}",
                age(server.last_handshake),
                server.key,
                or_none(server.endpoint.map(|e| e.to_string())),
                server.rx,
                server.tx
            ),
            None => "never".to_owned(),
        };
        let keepalive = match self.keepalive {
            0 => "keepalive off".to_owned(),
            secs => format!("keepalive {secs}s"),
        };
        let lines = [
            format!(
                "server endpoint : {} from {source} (since {})",
                or_none(self.endpoint.map(|e| e.to_string())),
                age(self.endpoint_since)
            ),
            format!("TXT lookup      : {lookup}"),
            format!("handshake       : {handshake}, {keepalive}"),
            format!(
                "tunnel          : {} via {uplink}, rebuilds={}",
                or_none(self.tun.clone()),
                self.rebuilds
            ),
            format!("status written  : {}", age(Some(self.updated))),
        ];
        let mut text = String::new();
        for line in lines {
            let _ = writeln!(text, "{line}");
        }
        text
    }
}

/// A status file of either role.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum Report {
    Server(Status),
    Client(ClientStatus),
}

impl Report {
    /// Read the status at `path`. A status with `"role": "client"` is the
    /// client's, and any other the server's.
    pub fn read(path: &Path) -> Result<Self> {
        let value: serde_json::Value =
            serde_json::from_str(&read_text(path)?).map_err(|e| invalid(path, e))?;
        let parsed = match value.get("role").and_then(|role| role.as_str()) {
            Some("client") => serde_json::from_value(value).map(Self::Client),
            _ => serde_json::from_value(value).map(Self::Server),
        };
        parsed.map_err(|e| invalid(path, e))
    }

    pub fn pid(&self) -> u32 {
        match self {
            Self::Server(status) => status.pid,
            Self::Client(status) => status.pid,
        }
    }

    /// Whether a tunnel ran when the status was written.
    pub fn has_tunnel(&self) -> bool {
        match self {
            Self::Server(status) => status.tun.is_some(),
            Self::Client(status) => status.tun.is_some(),
        }
    }

    pub fn problems(&self, now: u64) -> Vec<String> {
        match self {
            Self::Server(status) => status.problems(now),
            Self::Client(status) => status.problems(now),
        }
    }

    pub fn render(&self, now: u64) -> String {
        match self {
            Self::Server(status) => status.render(now),
            Self::Client(status) => status.render(now),
        }
    }

    /// The error code of a status that shows a problem.
    pub fn unhealthy(&self) -> &'static str {
        match self {
            Self::Server(_) => "SERVER_UNHEALTHY",
            Self::Client(_) => "CLIENT_UNHEALTHY",
        }
    }
}
