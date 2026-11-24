//! The natwg configuration is one JSON file, readable only by its owner, that holds
//! the keys, the peers, and either the server or the client role.

use crate::keys::{self, Key, PublicKey, Secret};
use crate::{Error, Result};
use ipnetwork::Ipv4Network;
use serde::{Deserialize, Serialize};
use std::{
    fmt,
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddrV4},
    num::NonZeroU64,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
    str::FromStr,
};

#[cfg(target_os = "macos")]
pub const DEFAULT_PATH: &str = "/usr/local/etc/natwg/config.json";
#[cfg(not(target_os = "macos"))]
pub const DEFAULT_PATH: &str = "/etc/natwg/config.json";

pub const DEFAULT_MTU: u16 = 1380;

// Every IPv4 host accepts a packet of 576 bytes, and 9000 bytes is a jumbo
// frame.
const MTU: std::ops::RangeInclusive<u16> = 576..=9000;

// The server routes the whole subnet of its tunnel address into the tunnel.
const SHORTEST_PREFIX: u8 = 16;

// The longest interface name that Linux and macOS accept.
const IFACE_NAME_MAX: usize = 15;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub version: Version1,
    pub private_key: Key,
    pub interface: Interface,
    pub peers: Vec<PeerConfig>,
    pub role: Role,
}

/// The only config format version, written as `1`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "u64", into = "u64")]
pub struct Version1;

impl TryFrom<u64> for Version1 {
    type Error = String;

    fn try_from(version: u64) -> std::result::Result<Self, Self::Error> {
        if version != 1 {
            return Err(format!(
                "config version {version} is not supported; this natwg reads version 1"
            ));
        }
        Ok(Self)
    }
}

impl From<Version1> for u64 {
    fn from(_: Version1) -> Self {
        1
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Interface {
    pub address: Ipv4Network,
    #[serde(default = "default_mtu")]
    pub mtu: u16,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerConfig {
    pub name: String,
    pub public_key: PublicKey,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preshared_key: Option<Key>,
    pub allowed_ips: Vec<Ipv4Network>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<SocketAddrV4>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keepalive: Option<u16>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[allow(
    clippy::large_enum_variant,
    reason = "a process loads one Config, so the size of the server variant costs nothing"
)]
pub enum Role {
    Server(ServerConfig),
    Client(ClientConfig),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    #[serde(default)]
    pub instance: Instance,
    pub iface: String,
    pub listen_port: u16,
    pub lan: Ipv4Network,
    pub stun: StunConfig,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upnp: Option<UpnpConfig>,
    pub cloudflare: CloudflareConfig,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub doctor: Option<DoctorConfig>,
}

/// The name of one natwg server on a host. It names the pf anchor, the nftables
/// table and the Linux TUN device, so two servers with different names can run
/// side by side.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Instance(String);

impl Instance {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for Instance {
    fn default() -> Self {
        Self("natwg".to_owned())
    }
}

impl TryFrom<String> for Instance {
    type Error = &'static str;

    fn try_from(name: String) -> std::result::Result<Self, Self::Error> {
        // A Linux interface name holds 15 bytes, and the Linux TUN takes this name.
        let valid = (1..=15).contains(&name.len())
            && name
                .bytes()
                .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'_'));
        if !valid {
            return Err("expected an instance name of 1 to 15 characters from a-z, 0-9 and _");
        }
        Ok(Self(name))
    }
}

impl FromStr for Instance {
    type Err = &'static str;

    fn from_str(name: &str) -> std::result::Result<Self, Self::Err> {
        name.to_owned().try_into()
    }
}

impl From<Instance> for String {
    fn from(instance: Instance) -> Self {
        instance.0
    }
}

impl fmt::Display for Instance {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StunConfig {
    /// `host:port` entries, resolved through `dns_server`.
    pub servers: Vec<String>,
    pub fallback: Vec<SocketAddrV4>,
    #[serde(default = "default_stun_interval")]
    pub interval_secs: NonZeroU64,
    pub dns_server: Ipv4Addr,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpnpConfig {
    pub control_url: String,
    pub lease_secs: u32,
    pub refresh_secs: NonZeroU64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudflareConfig {
    pub zone: String,
    pub record: String,
    pub token: Secret,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientConfig {
    pub record: String,
    pub resolvers: Vec<Ipv4Addr>,
}

/// A client identity the server also loads as a peer, so `natwg doctor` can
/// test the server the way a real client would.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DoctorConfig {
    pub private_key: Key,
    pub address: Ipv4Addr,
}

impl Config {
    /// Read a config file. The file must belong to the effective user and grant
    /// no group or other permissions, so a root daemon only trusts a root file.
    pub fn load(path: &Path) -> Result<Self> {
        let unreadable =
            |e: std::io::Error| Error::new("CONFIG_UNREADABLE", format!("{}: {e}", path.display()));
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(path)
            .map_err(unreadable)?;
        let meta = file.metadata().map_err(unreadable)?;
        let euid = unsafe { libc::geteuid() };
        if !meta.is_file() || meta.uid() != euid || meta.mode() & 0o077 != 0 {
            return Err(Error::new(
                "CONFIG_UNSAFE",
                format!(
                    "{}: owner uid {} and mode {:04o}; natwg reads only a regular file owned by uid {euid} with no group or other permissions",
                    path.display(),
                    meta.uid(),
                    meta.mode() & 0o7777,
                ),
            ));
        }
        let mut text = String::new();
        file.read_to_string(&mut text).map_err(unreadable)?;
        let invalid = |e: String| Error::new("CONFIG_INVALID", format!("{}: {e}", path.display()));
        let config: Self = serde_json::from_str(&text).map_err(|e| invalid(e.to_string()))?;
        config.validate().map_err(invalid)?;
        Ok(config)
    }

    /// Reject values that would make natwg take routes or rules that are not
    /// its own, and name the field at fault. [`Config::load`] runs this, so
    /// the rest of natwg trusts a loaded config.
    pub fn validate(&self) -> std::result::Result<(), String> {
        let Interface { address, mtu } = self.interface;
        if address.prefix() < SHORTEST_PREFIX {
            return Err(format!(
                "interface.address {address} has a prefix shorter than /{SHORTEST_PREFIX}, and natwg routes the whole subnet of the address into the tunnel"
            ));
        }
        if !MTU.contains(&mtu) {
            return Err(format!(
                "interface.mtu {mtu} is not between {} and {}",
                MTU.start(),
                MTU.end()
            ));
        }
        let Role::Server(server) = &self.role else {
            return Ok(());
        };
        if !is_iface_name(&server.iface) {
            return Err(format!(
                "role.server.iface {:?} is not an interface name of 1 to {IFACE_NAME_MAX} characters from A-Z, a-z, 0-9, '.', '_' and '-'",
                server.iface
            ));
        }
        if address.overlaps(server.lan) {
            return Err(format!(
                "interface.address {address} and role.server.lan {} overlap, so the tunnel and the LAN would claim the same addresses",
                server.lan
            ));
        }
        let Some(doctor) = server.doctor.as_ref().map(|doctor| doctor.address) else {
            return Ok(());
        };
        if !address.contains(doctor) {
            return Err(format!(
                "role.server.doctor.address {doctor} is outside the tunnel subnet of interface.address {address}"
            ));
        }
        if doctor == address.ip() {
            return Err(format!(
                "role.server.doctor.address {doctor} is the tunnel address of the server"
            ));
        }
        let taken = self.peers.iter().find_map(|peer| {
            let allowed = peer.allowed_ips.iter().find(|net| net.contains(doctor))?;
            Some((peer, allowed))
        });
        if let Some((peer, allowed)) = taken {
            return Err(format!(
                "role.server.doctor.address {doctor} is inside allowed_ips {allowed} of peer {:?}, and the doctor needs an address no peer uses",
                peer.name
            ));
        }
        Ok(())
    }

    /// Atomically replace `path` with this config, readable only by its owner.
    pub fn save(&self, path: &Path) -> Result<()> {
        let storage =
            |e: std::io::Error| Error::new("CONFIG_STORAGE", format!("{}: {e}", path.display()));
        let mut text = keys::exposing(|| serde_json::to_string_pretty(self))
            .expect("a config always serializes");
        text.push('\n');
        let dir = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        std::fs::create_dir_all(dir).map_err(storage)?;
        let mut stage = tempfile::NamedTempFile::new_in(dir).map_err(storage)?;
        stage
            .as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(storage)?;
        stage
            .write_all(text.as_bytes())
            .and_then(|()| stage.as_file().sync_all())
            .map_err(storage)?;
        stage.persist(path).map_err(|e| storage(e.error))?;
        Ok(())
    }

    /// The server role, which the server and the doctor commands need.
    pub fn server(&self) -> Result<&ServerConfig> {
        match &self.role {
            Role::Server(server) => Ok(server),
            Role::Client(_) => Err(Error::new(
                "ROLE_MISMATCH",
                "the config has the client role, and this command needs the server role",
            )),
        }
    }

    /// The config as JSON for people to read. Every secret reads `"<redacted>"`,
    /// and `public_key` holds the public half of `private_key`.
    pub fn redacted(&self) -> String {
        #[derive(Serialize)]
        struct View<'a> {
            public_key: PublicKey,
            #[serde(flatten)]
            config: &'a Config,
        }
        let view = View {
            public_key: self.private_key.public_key(),
            config: self,
        };
        serde_json::to_string_pretty(&view).expect("a config always serializes")
    }
}

// The name goes into the pf and the nftables rule as text, so a character
// outside this set could end the rule and start another.
fn is_iface_name(name: &str) -> bool {
    (1..=IFACE_NAME_MAX).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

fn default_mtu() -> u16 {
    DEFAULT_MTU
}

fn default_stun_interval() -> NonZeroU64 {
    NonZeroU64::new(25).unwrap()
}
