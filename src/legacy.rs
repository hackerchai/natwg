//! Import of the Python natwg install: `natwg.json`, the wg-quick server config
//! it names in `wg_conf`, and the Cloudflare token file it names in
//! `cf_token_file`. The import only reads and never generates keys, so the same
//! install always produces the same config.

use crate::config::{
    CloudflareConfig, Config, DEFAULT_MTU, Interface, PeerConfig, Role, ServerConfig, StunConfig,
    UpnpConfig, Version1,
};
use crate::keys::{Key, PublicKey, Secret};
use crate::{Error, Result};
use ipnetwork::Ipv4Network;
use serde::Deserialize;
use std::{
    fmt::Display,
    net::{Ipv4Addr, SocketAddrV4},
    num::NonZeroU64,
    path::{Path, PathBuf},
};

pub const DEFAULT_NATWG_JSON: &str = "/usr/local/etc/natwg/natwg.json";

#[derive(Deserialize)]
struct NatwgJson {
    iface: String,
    listen_port: u16,
    wg_conf: PathBuf,
    wg_subnet: Ipv4Network,
    lan_subnet: Ipv4Network,
    stun_servers: Vec<String>,
    stun_fallback: Vec<SocketAddrV4>,
    dns_server: Ipv4Addr,
    keepalive: NonZeroU64,
    upnp_control_url: String,
    upnp_refresh: NonZeroU64,
    upnp_lease: u32,
    cf_zone: String,
    cf_record: String,
    cf_token_file: PathBuf,
}

/// Build a server config from a legacy install. `wg_conf` and `cf_token`
/// default to the paths that `natwg.json` names.
pub fn import(
    natwg_json: &Path,
    wg_conf: Option<&Path>,
    cf_token: Option<&Path>,
) -> Result<Config> {
    let legacy: NatwgJson =
        serde_json::from_str(&read(natwg_json)?).map_err(|e| invalid(natwg_json, e))?;
    let wg_conf = wg_conf.unwrap_or(&legacy.wg_conf);
    let server = parse_wg_conf(&read(wg_conf)?).map_err(|e| invalid(wg_conf, e))?;
    let address = server.interface.address;
    if address.network() != legacy.wg_subnet.network()
        || address.prefix() != legacy.wg_subnet.prefix()
    {
        return Err(invalid(
            natwg_json,
            format!(
                "wg_subnet {} is not the network of Address {address} in {}",
                legacy.wg_subnet,
                wg_conf.display()
            ),
        ));
    }
    let cf_token = cf_token.unwrap_or(&legacy.cf_token_file);
    let token: Secret = read(cf_token)?
        .trim()
        .parse()
        .map_err(|e| invalid(cf_token, e))?;
    Ok(Config {
        version: Version1,
        private_key: server.private_key,
        interface: server.interface,
        peers: server.peers,
        role: Role::Server(ServerConfig {
            iface: legacy.iface,
            listen_port: legacy.listen_port,
            lan: legacy.lan_subnet,
            stun: StunConfig {
                servers: legacy.stun_servers,
                fallback: legacy.stun_fallback,
                interval_secs: legacy.keepalive,
                dns_server: legacy.dns_server,
            },
            upnp: (!legacy.upnp_control_url.is_empty()).then_some(UpnpConfig {
                control_url: legacy.upnp_control_url,
                lease_secs: legacy.upnp_lease,
                refresh_secs: legacy.upnp_refresh,
            }),
            cloudflare: CloudflareConfig {
                zone: legacy.cf_zone,
                record: legacy.cf_record,
                token,
            },
            doctor: None,
        }),
    })
}

struct WgServer {
    private_key: Key,
    interface: Interface,
    peers: Vec<PeerConfig>,
}

#[derive(Default)]
struct PeerDraft {
    name: Option<String>,
    public_key: Option<PublicKey>,
    preshared_key: Option<Key>,
    allowed_ips: Vec<Ipv4Network>,
    endpoint: Option<SocketAddrV4>,
    keepalive: Option<u16>,
}

enum Section {
    Preamble,
    Interface,
    Peer,
}

// "PersistentKeepalive" is the longest wg-quick key, and a 44-character
// base64 key can be all letters, so a longer name is never echoed.
const MAX_KEY_NAME: usize = 19;

fn parse_wg_conf(text: &str) -> std::result::Result<WgServer, String> {
    let mut section = Section::Preamble;
    let mut private_key = None;
    let mut address = None;
    let mut mtu = None;
    let mut peers: Vec<PeerDraft> = Vec::new();
    let mut comment = None;
    for (index, line) in text.lines().enumerate() {
        let at = |message: &dyn Display| format!("line {}: {message}", index + 1);
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(note) = line.strip_prefix('#') {
            comment = Some(note.trim().to_owned()).filter(|note| !note.is_empty());
            continue;
        }
        let note = comment.take();
        if line.eq_ignore_ascii_case("[Interface]") {
            section = Section::Interface;
            continue;
        }
        if line.eq_ignore_ascii_case("[Peer]") {
            section = Section::Peer;
            peers.push(PeerDraft {
                name: note,
                ..PeerDraft::default()
            });
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| at(&"expected a section header or Key = Value"))?;
        let key = key.trim();
        if key.is_empty()
            || key.len() > MAX_KEY_NAME
            || !key.bytes().all(|b| b.is_ascii_alphabetic())
        {
            return Err(at(&"expected a section header or Key = Value"));
        }
        let key = key.to_ascii_lowercase();
        let value = value.trim();
        match (&section, key.as_str()) {
            (Section::Interface, "privatekey") => {
                private_key = Some(value.parse::<Key>().map_err(|e| at(&e))?)
            }
            (Section::Interface, "address") => {
                let mut addresses = value.split(',').map(str::trim);
                address = match (addresses.next(), addresses.next()) {
                    (Some(one), None) => Some(one.parse::<Ipv4Network>().map_err(|e| at(&e))?),
                    _ => return Err(at(&"natwg supports exactly one IPv4 Address")),
                };
            }
            (Section::Interface, "mtu") => mtu = Some(value.parse::<u16>().map_err(|e| at(&e))?),
            (Section::Interface, "listenport") => {}
            (Section::Peer, _) => {
                let peer = peers.last_mut().expect("a [Peer] line starts a draft");
                if peer.name.is_none() {
                    peer.name = note;
                }
                match key.as_str() {
                    "publickey" => peer.public_key = Some(value.parse().map_err(|e| at(&e))?),
                    "presharedkey" => peer.preshared_key = Some(value.parse().map_err(|e| at(&e))?),
                    "allowedips" => {
                        for ip in value.split(',').map(str::trim) {
                            peer.allowed_ips.push(ip.parse().map_err(|e| at(&e))?);
                        }
                    }
                    "endpoint" => peer.endpoint = Some(value.parse().map_err(|e| at(&e))?),
                    "persistentkeepalive" => {
                        peer.keepalive = Some(value.parse().map_err(|e| at(&e))?)
                    }
                    _ => return Err(at(&format!("unsupported key {key:?}"))),
                }
            }
            _ => return Err(at(&format!("unsupported key {key:?}"))),
        }
    }
    let peers = peers
        .into_iter()
        .enumerate()
        .map(|(index, peer)| {
            let name = peer.name.unwrap_or_else(|| format!("peer{}", index + 1));
            Ok(PeerConfig {
                public_key: peer
                    .public_key
                    .ok_or_else(|| format!("[Peer] {name} has no PublicKey"))?,
                name,
                preshared_key: peer.preshared_key,
                allowed_ips: peer.allowed_ips,
                endpoint: peer.endpoint,
                keepalive: peer.keepalive,
            })
        })
        .collect::<std::result::Result<_, String>>()?;
    Ok(WgServer {
        private_key: private_key.ok_or("[Interface] has no PrivateKey")?,
        interface: Interface {
            address: address.ok_or("[Interface] has no Address")?,
            mtu: mtu.unwrap_or(DEFAULT_MTU),
        },
        peers,
    })
}

fn read(path: &Path) -> Result<String> {
    std::fs::read_to_string(path)
        .map_err(|e| Error::new("LEGACY_UNREADABLE", format!("{}: {e}", path.display())))
}

fn invalid(path: &Path, error: impl Display) -> Error {
    Error::new("LEGACY_INVALID", format!("{}: {error}", path.display()))
}
