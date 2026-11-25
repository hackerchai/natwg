//! The natwg configuration is one JSON file, readable only by its owner, that holds
//! the keys, the peers, and either the server or the client role.

pub mod set;

use crate::keys::{self, Key, PublicKey, Secret};
use crate::wire::dns::{self, RecordKind};
use crate::{Error, Result};
use ipnetwork::Ipv4Network;
use serde::{Deserialize, Serialize};
use std::{
    fmt,
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddrV4},
    num::NonZeroU64,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
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

impl Interface {
    /// The tunnel subnet: the network that `address` names, as
    /// 10.66.66.0/24 for 10.66.66.1/24.
    pub fn subnet(&self) -> Ipv4Network {
        Ipv4Network::new(self.address.network(), self.address.prefix())
            .expect("the prefix of a network is a valid prefix")
    }
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
    /// The networks behind `iface` that clients reach through the tunnel.
    /// natwg NATs the tunnel subnet into each of them. With none, the server
    /// serves the tunnel only. A file may hold one network as a string, the
    /// form natwg 0.2 wrote.
    #[serde(default, deserialize_with = "lans")]
    pub lan: Vec<Ipv4Network>,
    pub stun: StunConfig,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upnp: Option<UpnpConfig>,
    pub cloudflare: CloudflareConfig,
    /// Where the server writes its status (default: `status::path`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_file: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub doctor: Option<DoctorConfig>,
}

/// The name of one natwg server on a host. It names the pf anchor, the nftables
/// table, the Linux TUN device, the service and the status file, so two
/// servers with different names can run side by side. The client takes the
/// name `client` for its service and status file, and no server may take it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Instance(String);

const CLIENT: &str = "client";

impl Instance {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The name of the client's service and status file.
    pub fn client() -> Self {
        Self(CLIENT.to_owned())
    }

    pub fn is_client(&self) -> bool {
        self.0 == CLIENT
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
        if name == CLIENT {
            return Err("the instance name client belongs to natwg client");
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

/// The client of one natwg server, the only peer of its config. It finds the
/// server through the TXT `record`, or at the peer's `endpoint` when there is
/// no record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientConfig {
    /// The TXT record that holds the server's endpoint as `"ip:port"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record: Option<String>,
    /// The DNS servers asked for `record`, in order (default:
    /// `client::resolve::DEFAULT_RESOLVERS`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resolvers: Vec<Ipv4Addr>,
    /// The uplink the WireGuard and DNS traffic leaves through (default: the
    /// physical interface of the default route, followed as it changes).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iface: Option<String>,
    /// Where the client writes its status (default: `status::client_path`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_file: Option<PathBuf>,
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
        if acl::present(&file).map_err(unreadable)? {
            return Err(Error::new(
                "CONFIG_UNSAFE",
                format!(
                    "{}: the file carries an ACL, which can grant access that its mode does not show; remove it with chmod -N",
                    path.display()
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
        let server = match &self.role {
            Role::Server(server) => server,
            Role::Client(client) => return self.validate_client(client),
        };
        if !is_iface_name(&server.iface) {
            return Err(format!(
                "role.server.iface {:?} is not an interface name of 1 to {IFACE_NAME_MAX} characters from A-Z, a-z, 0-9, '.', '_' and '-'",
                server.iface
            ));
        }
        for (index, &lan) in server.lan.iter().enumerate() {
            if lan.prefix() == 0 {
                return Err(format!(
                    "role.server.lan[{index}] {lan} is a default route; name the LAN networks the clients reach"
                ));
            }
            if address.overlaps(lan) {
                return Err(format!(
                    "interface.address {address} and role.server.lan[{index}] {lan} overlap, so the tunnel and the LAN would claim the same addresses"
                ));
            }
            if let Some((earlier, other)) = server.lan[..index]
                .iter()
                .enumerate()
                .find(|(_, other)| other.overlaps(lan))
            {
                return Err(format!(
                    "role.server.lan[{index}] {lan} overlaps role.server.lan[{earlier}] {other}; list each LAN network once"
                ));
            }
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

    fn validate_client(&self, client: &ClientConfig) -> std::result::Result<(), String> {
        let [server] = &self.peers[..] else {
            return Err(format!(
                "a client config has exactly one peer, the server, and this one has {}",
                self.peers.len()
            ));
        };
        if server.allowed_ips.is_empty() {
            return Err(
                "peers[0].allowed_ips is empty, so nothing would go through the tunnel".to_owned(),
            );
        }
        if let Some(net) = server.allowed_ips.iter().find(|net| net.prefix() == 0) {
            return Err(format!(
                "peers[0].allowed_ips {net} is a default route, which natwg client does not take; name the networks to reach"
            ));
        }
        if client.record.is_none() && server.endpoint.is_none() {
            return Err(
                "the client needs role.client.record or peers[0].endpoint to find the server"
                    .to_owned(),
            );
        }
        if let Some(record) = &client.record
            && !is_dns_name(record)
        {
            return Err(format!("role.client.record {record:?} is not a DNS name"));
        }
        if let Some(iface) = &client.iface
            && !is_iface_name(iface)
        {
            return Err(format!(
                "role.client.iface {iface:?} is not an interface name of 1 to {IFACE_NAME_MAX} characters from A-Z, a-z, 0-9, '.', '_' and '-'"
            ));
        }
        Ok(())
    }

    /// Atomically replace `path` with this config, readable only by its owner.
    /// A directory that `path` needs is created readable only by its owner.
    pub fn save(&self, path: &Path) -> Result<()> {
        self.write(path, true)
    }

    /// Write this config as [`Config::save`] does, but refuse a `path` that
    /// exists.
    pub fn create(&self, path: &Path) -> Result<()> {
        self.write(path, false)
    }

    fn write(&self, path: &Path, replace: bool) -> Result<()> {
        let storage =
            |e: std::io::Error| Error::new("CONFIG_STORAGE", format!("{}: {e}", path.display()));
        let mut text = self.exposed();
        text.push('\n');
        let dir = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .map_err(storage)?;
        let mut stage = tempfile::NamedTempFile::new_in(dir).map_err(storage)?;
        stage
            .as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(storage)?;
        stage
            .write_all(text.as_bytes())
            .and_then(|()| stage.as_file().sync_all())
            .map_err(storage)?;
        let persisted = if replace {
            stage.persist(path)
        } else {
            stage.persist_noclobber(path)
        };
        persisted.map_err(|e| match e.error.kind() {
            std::io::ErrorKind::AlreadyExists => Error::new(
                "CONFIG_EXISTS",
                format!("{} exists already; --force replaces it", path.display()),
            ),
            _ => storage(e.error),
        })?;
        Ok(())
    }

    /// Give the server a doctor with a fresh key, at the highest host of the
    /// tunnel subnet that is neither the server's address nor inside a
    /// peer's allowed IPs. A doctor that is there already stays unless
    /// `replace` is set.
    pub fn add_doctor(&mut self, replace: bool) -> Result<DoctorConfig> {
        if self.server()?.doctor.is_some() && !replace {
            return Err(Error::new(
                "DOCTOR_EXISTS",
                "role.server.doctor exists already; --force replaces it",
            ));
        }
        let address = self.free_host().ok_or_else(|| {
            Error::new(
                "DOCTOR_NO_ADDRESS",
                format!(
                    "every host of the tunnel subnet of interface.address {} is the server's or a peer's",
                    self.interface.address
                ),
            )
        })?;
        let doctor = DoctorConfig {
            private_key: Key::generate()?,
            address,
        };
        if let Role::Server(server) = &mut self.role {
            server.doctor = Some(doctor.clone());
        }
        Ok(doctor)
    }

    fn free_host(&self) -> Option<Ipv4Addr> {
        let address = self.interface.address;
        let first = u32::from(address.network()) + 1;
        let last = u32::from(address.broadcast()).checked_sub(1)?;
        let taken = |host| {
            host == address.ip()
                || self
                    .peers
                    .iter()
                    .any(|peer| peer.allowed_ips.iter().any(|net| net.contains(host)))
        };
        (first..=last)
            .rev()
            .map(Ipv4Addr::from)
            .find(|&host| !taken(host))
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

    /// The client role and its one peer, the server, which the client needs.
    pub fn client(&self) -> Result<(&ClientConfig, &PeerConfig)> {
        match (&self.role, &self.peers[..]) {
            (Role::Client(client), [server]) => Ok((client, server)),
            (Role::Client(_), _) => Err(Error::new(
                "CONFIG_INVALID",
                "a client config has exactly one peer, the server",
            )),
            (Role::Server(_), _) => Err(Error::new(
                "ROLE_MISMATCH",
                "the config has the server role, and this command needs the client role",
            )),
        }
    }

    /// The config as the JSON of its file, secrets and all.
    pub fn exposed(&self) -> String {
        keys::exposing(|| serde_json::to_string_pretty(self)).expect("a config always serializes")
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

/// A name of labels from A-Z, a-z, 0-9, '-' and '_' that fits a DNS query.
fn is_dns_name(name: &str) -> bool {
    let plain = name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'));
    plain && dns::query(0, name, RecordKind::Txt).is_ok()
}

// The name goes into the pf and the nftables rule as text, so a character
// outside this set could end the rule and start another.
fn is_iface_name(name: &str) -> bool {
    (1..=IFACE_NAME_MAX).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// Make `dir` a directory that only the effective user can use: create it
/// if it is missing, then set mode 0700 and remove its ACL, whose
/// inheritable entries a config written into it would get.
pub fn make_private_dir(dir: &Path) -> Result<()> {
    let storage =
        |e: std::io::Error| Error::new("CONFIG_STORAGE", format!("{}: {e}", dir.display()));
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(storage)?;
    let handle = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(dir)
        .map_err(storage)?;
    let owner = handle.metadata().map_err(storage)?.uid();
    let euid = unsafe { libc::geteuid() };
    if owner != euid {
        return Err(Error::new(
            "CONFIG_UNSAFE",
            format!(
                "{}: owner uid {owner}; natwg keeps a config only in a directory owned by uid {euid}",
                dir.display()
            ),
        ));
    }
    handle
        .set_permissions(std::fs::Permissions::from_mode(0o700))
        .map_err(storage)?;
    acl::remove(&handle).map_err(storage)
}

/// The extended ACL of a file. A macOS ACL entry can grant access that the
/// mode bits do not show.
#[cfg(target_os = "macos")]
mod acl {
    use std::{
        fs::File,
        io,
        os::fd::AsRawFd,
        os::raw::{c_int, c_void},
    };

    const ACL_TYPE_EXTENDED: c_int = 0x100;
    const ACL_FIRST_ENTRY: c_int = 0;

    unsafe extern "C" {
        fn acl_init(count: c_int) -> *mut c_void;
        fn acl_get_fd_np(fd: c_int, kind: c_int) -> *mut c_void;
        fn acl_set_fd_np(fd: c_int, acl: *mut c_void, kind: c_int) -> c_int;
        fn acl_get_entry(acl: *mut c_void, entry_id: c_int, entry: *mut *mut c_void) -> c_int;
        fn acl_free(object: *mut c_void) -> c_int;
    }

    pub fn present(file: &File) -> io::Result<bool> {
        let acl = unsafe { acl_get_fd_np(file.as_raw_fd(), ACL_TYPE_EXTENDED) };
        if acl.is_null() {
            let error = io::Error::last_os_error();
            return match error.raw_os_error() {
                Some(libc::ENOENT) => Ok(false),
                _ => Err(error),
            };
        }
        let mut entry = std::ptr::null_mut();
        let found = unsafe { acl_get_entry(acl, ACL_FIRST_ENTRY, &mut entry) } == 0;
        unsafe { acl_free(acl) };
        Ok(found)
    }

    pub fn remove(file: &File) -> io::Result<()> {
        let empty = unsafe { acl_init(0) };
        if empty.is_null() {
            return Err(io::Error::last_os_error());
        }
        let set = unsafe { acl_set_fd_np(file.as_raw_fd(), empty, ACL_TYPE_EXTENDED) };
        let error = io::Error::last_os_error();
        unsafe { acl_free(empty) };
        if set == 0 { Ok(()) } else { Err(error) }
    }
}

/// A Linux ACL entry takes effect only through the ACL mask, and the mode
/// shows the mask as the group bits, so the mode check and the chmod to
/// 0700 already cover it.
#[cfg(not(target_os = "macos"))]
mod acl {
    use std::{fs::File, io};

    pub fn present(_: &File) -> io::Result<bool> {
        Ok(false)
    }

    pub fn remove(_: &File) -> io::Result<()> {
        Ok(())
    }
}

fn default_mtu() -> u16 {
    DEFAULT_MTU
}

/// `role.server.lan` as a list of networks, or as the one network that
/// natwg 0.2 wrote as a string.
fn lans<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Vec<Ipv4Network>, D::Error> {
    struct Lans;

    impl<'de> serde::de::Visitor<'de> for Lans {
        type Value = Vec<Ipv4Network>;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a list of IPv4 networks such as [\"10.24.0.0/24\"]")
        }

        fn visit_str<E: serde::de::Error>(self, lan: &str) -> std::result::Result<Self::Value, E> {
            lan.parse().map(|lan| vec![lan]).map_err(E::custom)
        }

        fn visit_seq<A: serde::de::SeqAccess<'de>>(
            self,
            mut seq: A,
        ) -> std::result::Result<Self::Value, A::Error> {
            let mut lans = Vec::new();
            while let Some(lan) = seq.next_element()? {
                lans.push(lan);
            }
            Ok(lans)
        }
    }

    deserializer.deserialize_any(Lans)
}

fn default_stun_interval() -> NonZeroU64 {
    NonZeroU64::new(25).unwrap()
}
