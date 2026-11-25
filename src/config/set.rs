//! `natwg config set`: change one setting of a config in place. A server
//! that moves to another tunnel subnet takes its peers and its doctor along,
//! each at the same host offset.

use super::{Config, Role};
use crate::{Error, Result};
use ipnetwork::Ipv4Network;
use std::net::Ipv4Addr;

/// A setting that `natwg config set` changes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Setting {
    /// `interface.address`: the tunnel address of this host, whose prefix
    /// sets the tunnel subnet. Both roles.
    Address(Ipv4Network),
    /// `role.server.lan`: the LAN networks of a server. None is allowed.
    Lan(Vec<Ipv4Network>),
    /// `peers[0].allowed_ips`: the networks a client routes into the tunnel.
    AllowedIps(Vec<Ipv4Network>),
}

impl Setting {
    /// The key that names the setting on the command line.
    pub fn key(&self) -> &'static str {
        match self {
            Self::Address(_) => "address",
            Self::Lan(_) => "lan",
            Self::AllowedIps(_) => "allowed-ips",
        }
    }
}

/// What [`apply`] changed, for people to read.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Change {
    /// One line per value that changed, as `<field> <old> -> <new>`. Empty
    /// when the config held the setting already.
    pub changed: Vec<String>,
    /// What has to change elsewhere, such as on the clients.
    pub notes: Vec<String>,
}

/// Give `config` the `setting`, then validate it. A setting that does not
/// fit the role of the config, or that leaves it invalid, is an error, and
/// `config` stays as it was.
pub fn apply(config: &mut Config, setting: &Setting) -> Result<Change> {
    let mut next = config.clone();
    let change = match setting {
        Setting::Address(address) => set_address(&mut next, *address)?,
        Setting::Lan(lans) => set_lan(&mut next, lans)?,
        Setting::AllowedIps(networks) => set_allowed_ips(&mut next, networks)?,
    };
    next.validate()
        .map_err(|e| Error::new("CONFIG_INVALID", e))?;
    *config = next;
    Ok(change)
}

fn set_address(config: &mut Config, address: Ipv4Network) -> Result<Change> {
    let old = config.interface.address;
    let mut change = Change::default();
    if address == old {
        return Ok(change);
    }
    let from = config.interface.subnet();
    config.interface.address = address;
    let to = config.interface.subnet();
    change
        .changed
        .push(format!("interface.address {old} -> {address}"));
    if let Role::Client(_) = config.role {
        let ip = address.ip();
        change.notes.push(format!(
            "The server must list {ip}/32 in the allowed_ips of this client, as natwg config set address on the server does when it moves to a new subnet"
        ));
        let routed = config.peers.iter().flat_map(|peer| &peer.allowed_ips);
        if !routed.clone().any(|net| net.contains(ip)) {
            let routed: Vec<Ipv4Network> = routed.copied().collect();
            change.notes.push(format!(
                "peers[0].allowed_ips {} leaves out {ip}; route the new tunnel subnet with natwg config set allowed-ips",
                listed(&routed)
            ));
        }
        return Ok(change);
    }
    if to != from {
        renumber(config, from, to, &mut change)?;
    }
    if let Some(holder) = holder_of(config, address.ip()) {
        return Err(Error::new(
            "ADDRESS_TAKEN",
            format!(
                "the new server address {} would be {holder}; pick another address",
                address.ip()
            ),
        ));
    }
    Ok(change)
}

/// Move every peer network inside `from` and the doctor to the same host
/// offset in `to`, and say so in `change`.
fn renumber(
    config: &mut Config,
    from: Ipv4Network,
    to: Ipv4Network,
    change: &mut Change,
) -> Result<()> {
    let mut moved_peers = false;
    for peer in &mut config.peers {
        for net in &mut peer.allowed_ips {
            if net.prefix() < from.prefix() || !from.contains(net.network()) {
                continue;
            }
            let moved = moved(*net, from, to)
                .ok_or_else(|| no_room(format!("peer {:?} at {net}", peer.name), *net, from, to))?;
            if moved != *net {
                change
                    .changed
                    .push(format!("peer {} {net} -> {moved}", peer.name));
                *net = moved;
                moved_peers = true;
            }
        }
    }
    if let Role::Server(server) = &mut config.role
        && let Some(doctor) = &mut server.doctor
    {
        let at = Ipv4Network::from(doctor.address);
        let moved = moved(at, from, to).ok_or_else(|| {
            no_room(
                format!("role.server.doctor.address {}", doctor.address),
                at,
                from,
                to,
            )
        })?;
        if moved.ip() != doctor.address {
            change.changed.push(format!(
                "role.server.doctor.address {} -> {}",
                doctor.address,
                moved.ip()
            ));
            doctor.address = moved.ip();
        }
    }
    let lans = match &config.role {
        Role::Server(server) => server.lan.iter().map(|lan| format!(" {lan}")).collect(),
        Role::Client(_) => String::new(),
    };
    if moved_peers {
        change.notes.push(format!(
            "Each moved client must take its new address and route {to} instead of {from}: on the client, natwg config set address <new address> and natwg config set allowed-ips {to}{lans}"
        ));
    } else {
        change.notes.push(format!(
            "Clients must route {to} instead of {from}: on each, natwg config set allowed-ips {to}{lans}"
        ));
    }
    Ok(())
}

/// `net`, a network inside `from`, at the same offset in `to`. None when it
/// does not fit in `to`, or when a single address would land on the network
/// or the broadcast address of `to`.
fn moved(net: Ipv4Network, from: Ipv4Network, to: Ipv4Network) -> Option<Ipv4Network> {
    let base = u32::from(from.network());
    let offset = u32::from(net.network()) - base;
    if u64::from(offset) + u64::from(net.size()) > u64::from(to.size()) {
        return None;
    }
    let last = to.size() - 1;
    if net.prefix() == 32 && to.prefix() <= 30 && (offset == 0 || offset == last) {
        return None;
    }
    let ip = Ipv4Addr::from(u32::from(to.network()) + (u32::from(net.ip()) - base));
    Ipv4Network::new(ip, net.prefix()).ok()
}

fn no_room(what: String, net: Ipv4Network, from: Ipv4Network, to: Ipv4Network) -> Error {
    let offset = u32::from(net.network()) - u32::from(from.network());
    Error::new(
        "RENUMBER_NO_ROOM",
        format!(
            "{what} sits at offset {offset} of the tunnel subnet {from}, which is no host of {to}; pick a larger subnet or move it first"
        ),
    )
}

/// The peer or the doctor whose allowed IPs or address hold `ip`, for
/// people to read.
fn holder_of(config: &Config, ip: Ipv4Addr) -> Option<String> {
    let peer = config.peers.iter().find_map(|peer| {
        let net = peer.allowed_ips.iter().find(|net| net.contains(ip))?;
        Some(format!("inside {net} of peer {:?}", peer.name))
    });
    let doctor = || match &config.role {
        Role::Server(server) => server
            .doctor
            .as_ref()
            .filter(|doctor| doctor.address == ip)
            .map(|_| "role.server.doctor.address".to_owned()),
        Role::Client(_) => None,
    };
    peer.or_else(doctor)
}

fn set_lan(config: &mut Config, lans: &[Ipv4Network]) -> Result<Change> {
    let subnet = config.interface.subnet();
    let Role::Server(server) = &mut config.role else {
        return Err(role_mismatch("lan", "server", "client"));
    };
    let mut change = Change::default();
    if server.lan == lans {
        return Ok(change);
    }
    change.changed.push(format!(
        "role.server.lan {} -> {}",
        listed(&server.lan),
        listed(lans)
    ));
    server.lan = lans.to_vec();
    let routes: String = std::iter::once(subnet)
        .chain(lans.iter().copied())
        .map(|net| format!(" {net}"))
        .collect();
    if lans.is_empty() {
        change.notes.push(
            "With no LAN, the server loads no NAT rule and serves the tunnel only".to_owned(),
        );
    }
    change.notes.push(format!(
        "A client routes only its own allowed_ips: on each, natwg config set allowed-ips{routes}"
    ));
    Ok(change)
}

fn set_allowed_ips(config: &mut Config, networks: &[Ipv4Network]) -> Result<Change> {
    if let Role::Server(_) = config.role {
        return Err(role_mismatch("allowed-ips", "client", "server"));
    }
    let [server] = &mut config.peers[..] else {
        return Err(Error::new(
            "CONFIG_INVALID",
            "a client config has exactly one peer, the server",
        ));
    };
    let mut change = Change::default();
    if server.allowed_ips == networks {
        return Ok(change);
    }
    change.changed.push(format!(
        "peers[0].allowed_ips {} -> {}",
        listed(&server.allowed_ips),
        listed(networks)
    ));
    server.allowed_ips = networks.to_vec();
    Ok(change)
}

fn role_mismatch(key: &str, needs: &str, has: &str) -> Error {
    Error::new(
        "ROLE_MISMATCH",
        format!(
            "natwg config set {key} changes a {needs} config, and this config has the {has} role"
        ),
    )
}

fn listed(nets: &[Ipv4Network]) -> String {
    let nets: Vec<String> = nets.iter().map(ToString::to_string).collect();
    format!("[{}]", nets.join(", "))
}
