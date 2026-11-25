//! The status file that `natwg server` and `natwg client` write every 10 s
//! and `natwg status` reads without root. Anyone can read it, so it holds no
//! secret. Every time in it is in Unix seconds.

use crate::config::{ClientConfig, Instance, PublishMode, ServerConfig};
use crate::detect::PublicBy;
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
    /// The natwg version of that server.
    #[serde(default)]
    pub version: Option<String>,
    /// The newest release that its automatic update check found, if any.
    #[serde(default)]
    pub latest_version: Option<String>,
    pub iface: String,
    pub listen_port: u16,
    /// The TUN of the running tunnel, or none while natwg rebuilds it.
    pub tun: Option<String>,
    pub mapping: Option<SocketAddrV4>,
    pub mapping_since: Option<u64>,
    /// Whether the server runs the STUN keepalive. Only publish `a` on a
    /// public uplink goes without. A status of natwg 0.3.0 has none, and ran
    /// it.
    #[serde(default = "on")]
    pub stun: bool,
    pub last_stun_ok: Option<u64>,
    /// STUN requests in a row that got no answer.
    pub stun_misses: u32,
    /// What the server publishes: `txt`, the mapping in a TXT record, or
    /// `a`, the public IP in an A record. A status of natwg 0.3.0 has none,
    /// and published TXT.
    #[serde(default)]
    pub publish: PublishMode,
    /// The name of the Cloudflare record.
    #[serde(default)]
    pub record: Option<String>,
    /// What the TXT record holds, as natwg last wrote or found it.
    pub published: Option<SocketAddrV4>,
    /// What the A record holds, as natwg last wrote or found it.
    #[serde(default)]
    pub published_ip: Option<Ipv4Addr>,
    pub published_at: Option<u64>,
    pub publish_error: Option<String>,
    /// With publish `a`: the public IP that natwg keeps in the A record.
    #[serde(default)]
    pub public_ip: Option<Ipv4Addr>,
    /// Where `public_ip` comes from: `address`, the uplink's own; or `upnp`,
    /// a router's, confirmed by a working UPnP lease of the listen port, the
    /// gateway's WAN address and a STUN mapping that keeps the port.
    #[serde(default)]
    pub public_by: Option<PublicBy>,
    /// With publish `a`: why there is no public IP, as for a mapping that
    /// does not keep the listen port, or that no UPnP gateway confirms. The A
    /// record then stays as it was.
    #[serde(default)]
    pub public_error: Option<String>,
    /// With publish `a`: the other records of the name that clients may
    /// dial, more A records or an AAAA record, which the operator must
    /// delete. natwg never deletes them.
    #[serde(default)]
    pub record_problem: Option<String>,
    /// None when the config has no UPnP section or the first lease is pending.
    pub upnp_ok: Option<bool>,
    pub upnp_at: Option<u64>,
    /// None while no tunnel runs, and for a server without a LAN, which
    /// loads no NAT rule.
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

fn on() -> bool {
    true
}

/// `name = value`, or the value alone when the name is unknown.
fn named(name: Option<&str>, value: String) -> String {
    match name {
        Some(name) => format!("{name} = {value}"),
        None => value,
    }
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
    /// tunnel runs, its NAT rule works, there is a public mapping (with
    /// publish `a`, a public IP), the last publish worked, and UPnP did not
    /// fail. UPnP that is off is fine, and so is NAT that is off because the
    /// server has no LAN.
    pub fn problems(&self, now: u64) -> Vec<String> {
        let age = now.saturating_sub(self.updated);
        let tunnel = self.tun.is_some();
        let a = self.publish == PublishMode::A;
        [
            (age > STALE_AFTER, format!("the status is {age}s old")),
            (!tunnel, "no tunnel runs".to_owned()),
            (
                tunnel && self.nat_ok == Some(false),
                "NAT is not ok".to_owned(),
            ),
            (!a && self.mapping.is_none(), "no public mapping".to_owned()),
            (a && self.public_ip.is_none(), "no public IP".to_owned()),
            (
                self.record_problem.is_some(),
                self.record_problem.clone().unwrap_or_default(),
            ),
            (
                self.publish_error.is_some(),
                format!("the {} publish failed", self.publish.record_type()),
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
        let error = |error: Option<&String>| {
            error
                .map(|error| format!("  ERROR: {error}"))
                .unwrap_or_default()
        };
        let publish_error = error(self.publish_error.as_ref());
        let record = self.record.as_deref();
        let mut lines = Vec::new();
        let mapping = format!(
            "public endpoint : {} (since {})",
            or_none(self.mapping.map(|m| m.to_string())),
            age(self.mapping_since)
        );
        let stun = format!(
            "last STUN reply : {}, misses={}",
            age(self.last_stun_ok),
            self.stun_misses
        );
        match self.publish {
            PublishMode::Txt => {
                lines.push(mapping);
                lines.push(format!(
                    "published TXT   : {} ({}){publish_error}",
                    named(record, or_none(self.published.map(|p| p.to_string()))),
                    age(self.published_at)
                ));
                lines.push(stun);
                // mapping_since also starts anew after a daemon restart.
                if let Some(since) = self.mapping_since
                    && self.mapping.is_some()
                    && now.checked_sub(since).is_some_and(|age| age < 24 * 60 * 60)
                    && let Some(time) =
                        UNIX_EPOCH.checked_add(std::time::Duration::from_secs(since))
                    && since < 253_402_300_800
                // RFC 3339 ends in year 9999
                {
                    let at = humantime::format_rfc3339_seconds(time);
                    lines.push(format!("Surge/Clash configs exported before {at} may point at an old endpoint; export them again."));
                }
            }
            PublishMode::A => {
                let public = match (self.public_ip, self.public_by) {
                    (Some(ip), Some(by)) => format!("{ip} by {by}"),
                    (Some(ip), None) => ip.to_string(),
                    (None, _) if self.public_error.is_none() => "none (not known yet)".to_owned(),
                    (None, _) => "none".to_owned(),
                };
                lines.push(format!(
                    "public IP       : {public}{}",
                    error(self.public_error.as_ref())
                ));
                let dial = record
                    .map(|record| format!(", clients dial {record}:{}", self.listen_port))
                    .unwrap_or_default();
                lines.push(format!(
                    "published A     : {} ({}){dial}{publish_error}",
                    named(record, or_none(self.published_ip.map(|p| p.to_string()))),
                    age(self.published_at)
                ));
                if let Some(problem) = &self.record_problem {
                    lines.push(format!("other records   : ERROR: {problem}"));
                }
                if self.stun {
                    lines.push(mapping);
                    lines.push(stun);
                } else {
                    lines.push("last STUN reply : off (no role.server.stun)".to_owned());
                }
            }
        }
        let mut text = String::new();
        lines.extend([
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
        ]);
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
    /// The natwg version of that client.
    #[serde(default)]
    pub version: Option<String>,
    /// The newest release that its automatic update check found, if any.
    #[serde(default)]
    pub latest_version: Option<String>,
    /// The interface the WireGuard and DNS traffic leaves through.
    pub uplink: Option<String>,
    pub uplink_address: Option<Ipv4Addr>,
    /// The TUN of the running tunnel, or none while natwg rebuilds it.
    pub tun: Option<String>,
    /// The record the client looks up, if the config has one: the TXT record
    /// that holds the server's endpoint, or the name of role.client.server.
    pub record: Option<String>,
    /// What `record` is: `txt`, or `a` for role.client.server. A status of
    /// natwg 0.3.0 has none, and a TXT record.
    #[serde(default)]
    pub record_type: Option<PublishMode>,
    /// Where natwg points the server peer.
    pub endpoint: Option<SocketAddrV4>,
    pub endpoint_since: Option<u64>,
    /// When the record last gave a well-formed endpoint.
    pub looked_up: Option<u64>,
    /// Why the last lookup failed, until one works.
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

    /// The record type the client looks up: `TXT` or `A`.
    fn record_type(&self) -> &'static str {
        self.record_type.unwrap_or_default().record_type()
    }

    /// What this status shows to be wrong at `now`. None of it holds while
    /// the client reaches the server: the status is fresh, a tunnel runs,
    /// natwg knows an endpoint, the last lookup worked, and, with a
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
                .then(|| format!("the {} lookup failed", self.record_type())),
            handshake_problem,
        ]
        .into_iter()
        .flatten()
        .collect()
    }

    /// The status for people to read, with times as their age at `now`.
    pub fn render(&self, now: u64) -> String {
        let age = |time| age(now, time);
        let kind = self.record_type();
        let source = match &self.record {
            Some(record) => format!("{kind} {record}"),
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
            format!("{:<16}: {lookup}", format!("{kind} lookup")),
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

    /// "Update available: …" when the automatic check of the process that
    /// wrote the status found a release newer than that process.
    pub fn update_notice(&self) -> Option<String> {
        let (version, latest) = match self {
            Self::Server(status) => (&status.version, &status.latest_version),
            Self::Client(status) => (&status.version, &status.latest_version),
        };
        crate::update::notice(version.as_deref(), latest.as_deref()?)
    }

    /// The error code of a status that shows a problem.
    pub fn unhealthy(&self) -> &'static str {
        match self {
            Self::Server(_) => "SERVER_UNHEALTHY",
            Self::Client(_) => "CLIENT_UNHEALTHY",
        }
    }
}
