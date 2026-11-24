//! Import of a wg-quick client config, so a client keeps its keys and its
//! tunnel address when it moves to natwg. An error names the line and the
//! key, never a value, because a value can be a private key.

use crate::client::resolve::DEFAULT_RESOLVERS;
use crate::config::{ClientConfig, Config, DEFAULT_MTU, Interface, PeerConfig, Role, Version1};
use crate::keys::{Key, PublicKey};
use crate::{Error, Result};
use ipnetwork::Ipv4Network;
use std::{
    net::{Ipv4Addr, SocketAddrV4},
    path::Path,
};

/// The name of the client's one peer in the config natwg writes.
pub const SERVER_PEER: &str = "server";

// "PersistentKeepalive" is the longest wg-quick key, and a 44-character
// base64 key can be all letters, so a longer name is never echoed.
const MAX_KEY_NAME: usize = 19;

/// Build a client config from the wg-quick config at `path`. The client finds
/// the server through the TXT `record` when it is given, and otherwise at the
/// peer's Endpoint. wg-quick's `Endpoint = 0.0.0.0:0` placeholder counts as
/// none.
pub fn import(path: &Path, record: Option<String>, resolvers: Vec<Ipv4Addr>) -> Result<Config> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| Error::new("WG_QUICK_UNREADABLE", format!("{}: {e}", path.display())))?;
    let invalid = |e: String| Error::new("WG_QUICK_INVALID", format!("{}: {e}", path.display()));
    let parsed = parse(&text).map_err(invalid)?;
    let resolvers = match (&record, resolvers.is_empty()) {
        (Some(_), true) => DEFAULT_RESOLVERS.to_vec(),
        _ => resolvers,
    };
    let config = Config {
        version: Version1,
        private_key: parsed.private_key,
        interface: parsed.interface,
        peers: vec![parsed.server],
        role: Role::Client(ClientConfig {
            record,
            resolvers,
            iface: None,
            status_file: None,
        }),
    };
    config.validate().map_err(invalid)?;
    Ok(config)
}

struct Parsed {
    private_key: Key,
    interface: Interface,
    server: PeerConfig,
}

#[derive(Default)]
struct PeerDraft {
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

fn parse(text: &str) -> std::result::Result<Parsed, String> {
    let mut section = Section::Preamble;
    let mut private_key = None;
    let mut address = None;
    let mut mtu = None;
    let mut peers: Vec<PeerDraft> = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let at = |message: &str| format!("line {}: {message}", index + 1);
        // wg-quick ends a line at `#`, and base64 has no `#`.
        let line = line.split('#').next().unwrap_or_default().trim();
        if line.is_empty() {
            continue;
        }
        if line.eq_ignore_ascii_case("[Interface]") {
            section = Section::Interface;
            continue;
        }
        if line.eq_ignore_ascii_case("[Peer]") {
            section = Section::Peer;
            peers.push(PeerDraft::default());
            continue;
        }
        let malformed = || at("expected a section header or Key = Value");
        let (key, value) = line.split_once('=').ok_or_else(malformed)?;
        let key = key.trim();
        if key.is_empty()
            || key.len() > MAX_KEY_NAME
            || !key.bytes().all(|b| b.is_ascii_alphabetic())
        {
            return Err(malformed());
        }
        let value = value.trim();
        let name = key.to_ascii_lowercase();
        match (&section, name.as_str()) {
            (Section::Interface, "privatekey") => {
                private_key = Some(
                    value
                        .parse::<Key>()
                        .map_err(|_| at("PrivateKey is not a 32-byte key in base64"))?,
                );
            }
            (Section::Interface, "address") => {
                let mut addresses = value.split(',').map(str::trim);
                let one = match (addresses.next(), addresses.next()) {
                    (Some(one), None) => one.parse::<Ipv4Network>().ok(),
                    _ => None,
                };
                address = Some(one.ok_or_else(|| {
                    at("Address must be one IPv4 address with its prefix, as in 10.66.66.2/32")
                })?);
            }
            (Section::Interface, "mtu") => {
                mtu = Some(
                    value
                        .parse::<u16>()
                        .map_err(|_| at("MTU is not a number"))?,
                );
            }
            // natwg client picks a free port, as a roaming client should.
            (Section::Interface, "listenport") => {}
            (Section::Peer, _) => {
                let peer = peers.last_mut().expect("a [Peer] line starts a draft");
                peer_key(peer, &name, value).map_err(|message| at(&message))?;
            }
            (Section::Preamble, _) => return Err(at(&format!("{key} is outside a section"))),
            (Section::Interface, _) => {
                return Err(at(&format!(
                    "natwg client does not support the [Interface] key {key}; remove it"
                )));
            }
        }
    }
    let server = match <[PeerDraft; 1]>::try_from(peers) {
        Ok([server]) => server,
        Err(peers) => {
            return Err(format!(
                "natwg client takes a wg-quick config with exactly one [Peer], the server, and this one has {}",
                peers.len()
            ));
        }
    };
    Ok(Parsed {
        private_key: private_key.ok_or("[Interface] has no PrivateKey")?,
        interface: Interface {
            address: address.ok_or("[Interface] has no Address")?,
            mtu: mtu.unwrap_or(DEFAULT_MTU),
        },
        server: PeerConfig {
            name: SERVER_PEER.to_owned(),
            public_key: server.public_key.ok_or("[Peer] has no PublicKey")?,
            preshared_key: server.preshared_key,
            allowed_ips: server.allowed_ips,
            endpoint: server.endpoint,
            keepalive: server.keepalive,
        },
    })
}

fn peer_key(peer: &mut PeerDraft, name: &str, value: &str) -> std::result::Result<(), String> {
    match name {
        "publickey" => {
            peer.public_key = Some(
                value
                    .parse()
                    .map_err(|_| "PublicKey is not a 32-byte key in base64")?,
            );
        }
        "presharedkey" => {
            peer.preshared_key = Some(
                value
                    .parse()
                    .map_err(|_| "PresharedKey is not a 32-byte key in base64")?,
            );
        }
        "allowedips" => {
            for net in value.split(',').map(str::trim) {
                let net = net.parse().map_err(|_| {
                    "AllowedIPs must be IPv4 networks, as in 10.66.66.0/24, and natwg client routes no IPv6"
                })?;
                peer.allowed_ips.push(net);
            }
        }
        "endpoint" => {
            let endpoint: SocketAddrV4 = value.parse().map_err(|_| {
                "Endpoint must be an IPv4 address and a port; natwg finds a server by name through --record"
            })?;
            // wg-quick needs an Endpoint line, so a TXT updater's config
            // holds this placeholder.
            let placeholder = endpoint.ip().is_unspecified() && endpoint.port() == 0;
            peer.endpoint = (!placeholder).then_some(endpoint);
        }
        "persistentkeepalive" => {
            let keepalive = match value {
                "off" => 0,
                value => value
                    .parse()
                    .map_err(|_| "PersistentKeepalive is not a number of seconds or off")?,
            };
            peer.keepalive = Some(keepalive);
        }
        _ => {
            return Err(format!(
                "natwg client does not support the [Peer] key {name}; remove it"
            ));
        }
    }
    Ok(())
}
