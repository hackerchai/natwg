//! The peers of a server config. `add` gives a new client fresh keys and the
//! next free tunnel address, and returns the config that client runs.

use crate::client::{resolve::DEFAULT_RESOLVERS, wg_quick::SERVER_PEER};
use crate::config::{
    ClientConfig, Config, HostPort, Interface, PeerConfig, PublishMode, Role, Version1,
};
use crate::keys::Key;
use crate::tunnel::CLIENT_KEEPALIVE;
use crate::{Error, Result};
use ipnetwork::Ipv4Network;
use std::{fmt::Write as _, net::Ipv4Addr};

const NAME_MAX: usize = 32;

/// Add the client `name` to the server `config`: a fresh key pair and
/// preshared key, and the lowest host of the tunnel subnet that is not the
/// server's, the doctor's or inside a peer's allowed IPs. Returns the config
/// of the new client, which finds the server through what it publishes (the
/// TXT record, or with publish `a` the A record at the listen port) and
/// routes the tunnel subnet and every LAN to it.
pub fn add(config: &mut Config, name: &str) -> Result<Config> {
    let server = config.server()?;
    validate_name(name)?;
    if config.peers.iter().any(|peer| peer.name == name) {
        return Err(Error::new(
            "PEER_EXISTS",
            format!("the server has a peer named {name} already"),
        ));
    }
    let address = next_address(config).ok_or_else(|| {
        Error::new(
            "PEER_NO_ADDRESS",
            format!(
                "every host of the tunnel subnet of interface.address {} is the server's, the doctor's or a peer's",
                config.interface.address
            ),
        )
    })?;
    let key = Key::generate()?;
    let preshared = Key::generate()?;
    let record = server.cloudflare.record.clone();
    let (record, dial) = match server.publish {
        PublishMode::Txt => (Some(record), None),
        PublishMode::A => {
            let dial = HostPort {
                host: record,
                port: server.listen_port,
            };
            (None, Some(dial))
        }
    };
    let client = Config {
        version: Version1,
        private_key: key.clone(),
        interface: Interface {
            address: Ipv4Network::from(address),
            mtu: config.interface.mtu,
        },
        peers: vec![PeerConfig {
            name: SERVER_PEER.to_owned(),
            public_key: config.private_key.public_key(),
            preshared_key: Some(preshared.clone()),
            allowed_ips: std::iter::once(config.interface.subnet())
                .chain(server.lan.iter().copied())
                .collect(),
            endpoint: None,
            keepalive: Some(CLIENT_KEEPALIVE),
        }],
        role: Role::Client(ClientConfig {
            record,
            server: dial,
            resolvers: DEFAULT_RESOLVERS.to_vec(),
            iface: None,
            status_file: None,
        }),
        update: None,
    };
    config.peers.push(PeerConfig {
        name: name.to_owned(),
        public_key: key.public_key(),
        preshared_key: Some(preshared),
        allowed_ips: vec![Ipv4Network::from(address)],
        endpoint: None,
        keepalive: None,
    });
    let invalid = |e: String| Error::new("CONFIG_INVALID", e);
    config.validate().map_err(invalid)?;
    client.validate().map_err(invalid)?;
    Ok(client)
}

/// Remove the peer `name` from the server `config` and return it.
pub fn remove(config: &mut Config, name: &str) -> Result<PeerConfig> {
    config.server()?;
    let at = config
        .peers
        .iter()
        .position(|peer| peer.name == name)
        .ok_or_else(|| {
            Error::new(
                "PEER_NOT_FOUND",
                format!("the server has no peer named {name:?}"),
            )
        })?;
    Ok(config.peers.remove(at))
}

/// One line per peer of the server `config`, and one for its doctor: the
/// name, the allowed IPs and the public key.
pub fn list(config: &Config) -> Result<String> {
    let server = config.server()?;
    let mut text = String::new();
    for peer in &config.peers {
        let allowed: Vec<String> = peer.allowed_ips.iter().map(ToString::to_string).collect();
        let _ = writeln!(
            text,
            "{} {} {}",
            peer.name,
            allowed.join(","),
            peer.public_key
        );
    }
    if let Some(doctor) = &server.doctor {
        let _ = writeln!(
            text,
            "(doctor) {}/32 {}",
            doctor.address,
            doctor.private_key.public_key()
        );
    }
    Ok(text)
}

/// The lowest host of the tunnel subnet that neither the server, the doctor
/// nor a peer's allowed IPs hold.
fn next_address(config: &Config) -> Option<Ipv4Addr> {
    let net = config.interface.address;
    let doctor = config
        .server()
        .ok()?
        .doctor
        .as_ref()
        .map(|doctor| doctor.address);
    let first = u32::from(net.network()).checked_add(1)?;
    let last = u32::from(net.broadcast()).checked_sub(1)?;
    (first..=last).map(Ipv4Addr::from).find(|&host| {
        host != net.ip()
            && Some(host) != doctor
            && !config.peers.iter().any(|peer| {
                peer.allowed_ips
                    .iter()
                    .any(|allowed| allowed.contains(host))
            })
    })
}

pub(crate) fn validate_name(name: &str) -> Result<()> {
    if (1..=NAME_MAX).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        Ok(())
    } else {
        Err(Error::new(
            "PEER_NAME_INVALID",
            format!(
                "expected a peer name of 1 to {NAME_MAX} characters from A-Z, a-z, 0-9, '.', '_' and '-'"
            ),
        ))
    }
}
