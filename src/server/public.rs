//! What the server publishes. With publish `txt` it is the STUN mapping.
//! With publish `a` it is a public IP that clients reach at the listen port,
//! and natwg takes only two kinds as one:
//! - `address`: the uplink's own address is public;
//! - `upnp`: a router holds the public IP and forwards the listen port, which
//!   natwg confirms itself: the UPnP lease of the port works, the gateway's
//!   WAN address is the IP that STUN sees, and the mapping keeps the port.
//!
//! Anything else, a mapping that merely keeps the port among them, is no
//! public IP. A carrier NAT that keeps the port can change it later, and the
//! name would then point at the wrong port. natwg then leaves the A record as
//! it is and reports why; it never falls back to TXT.

use crate::config::{PublishMode, ServerConfig};
use crate::detect::{PublicBy, is_public};
use crate::netcfg;
use crate::server::cloudflare::Content;
use crate::server::keepalive::Mapping;
use crate::server::upnp::Lease;
use std::{
    convert::Infallible,
    net::{Ipv4Addr, SocketAddrV4},
    time::{Duration, SystemTime},
};
use tokio::{
    sync::{Notify, watch},
    time::{Instant, MissedTickBehavior},
};

/// How often publish `a` reads the uplink's addresses.
pub const ADDRESS_EVERY: Duration = Duration::from_secs(10);

/// How long publish `a` waits for the gateway to answer a recheck before it
/// judges with what it has. A renewal takes at most two requests of 6 s.
pub const RECHECK_LIMIT: Duration = Duration::from_secs(30);

/// The public IP that publish `a` keeps in the A record.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum Public {
    /// Not known yet: STUN or the first UPnP lease has not answered.
    #[default]
    Unknown,
    Known {
        ip: Ipv4Addr,
        by: PublicBy,
    },
    /// Why there is no public IP that clients reach at the listen port.
    Missing(String),
}

impl Public {
    pub fn ip(&self) -> Option<Ipv4Addr> {
        match self {
            Self::Known { ip, .. } => Some(*ip),
            Self::Unknown | Self::Missing(_) => None,
        }
    }

    pub fn by(&self) -> Option<PublicBy> {
        match self {
            Self::Known { by, .. } => Some(*by),
            Self::Unknown | Self::Missing(_) => None,
        }
    }

    pub fn error(&self) -> Option<&str> {
        match self {
            Self::Missing(error) => Some(error),
            Self::Unknown | Self::Known { .. } => None,
        }
    }
}

/// What the server sees of its uplink, its mapping and its UPnP lease.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Seen<'a> {
    pub iface: &'a str,
    pub listen_port: u16,
    /// The uplink's IPv4 addresses, in the order the system lists them.
    pub addresses: &'a [Ipv4Addr],
    /// Whether the server runs the STUN keepalive.
    pub stun: bool,
    pub mapping: Option<SocketAddrV4>,
    /// Whether the server keeps a UPnP lease of the listen port.
    pub upnp: bool,
    /// The last renewal of that lease, if one finished.
    pub lease: Option<Lease>,
}

/// The public IP for publish `a`: the uplink's first public address, else
/// the IP of a STUN mapping that a UPnP gateway confirms (see the module).
pub fn public(seen: &Seen) -> Public {
    let port = seen.listen_port;
    if let Some(&ip) = seen.addresses.iter().find(|&&ip| is_public(ip)) {
        return Public::Known {
            ip,
            by: PublicBy::Address,
        };
    }
    let uplink = match seen.addresses.first() {
        Some(address) => format!("the address {address} of {}", seen.iface),
        None => format!("{}, which has no IPv4 address,", seen.iface),
    };
    let Some(mapping) = seen.mapping else {
        if seen.stun {
            return Public::Unknown;
        }
        return Public::Missing(format!(
            "{uplink} is not public, and without role.server.stun natwg cannot learn the public IP"
        ));
    };
    let missing = |why: String| Public::Missing(format!("{why}; publish txt instead"));
    if !is_public(*mapping.ip()) {
        return missing(format!(
            "{uplink} is not public, and STUN sees {mapping}, which is not public either"
        ));
    }
    if mapping.port() != port {
        return missing(format!(
            "STUN sees {mapping}, which does not keep the listen port {port}, so the A record would send clients to the wrong port"
        ));
    }
    if !seen.upnp {
        return missing(format!(
            "STUN sees {mapping}, which keeps the listen port, but without role.server.upnp natwg cannot confirm that a router forwards udp/{port}; a carrier NAT that keeps the port can change it later"
        ));
    }
    let Some(lease) = seen.lease else {
        return Public::Unknown;
    };
    if !lease.ok {
        return missing(format!(
            "the UPnP lease of udp/{port} failed, so natwg cannot confirm that the router forwards it"
        ));
    }
    let ip = *mapping.ip();
    match lease.external_ip {
        None => missing(
            "the UPnP gateway did not report its WAN address, so natwg cannot confirm that it holds the public IP"
                .to_owned(),
        ),
        Some(external) if external != ip => missing(format!(
            "the UPnP gateway's WAN address {external} is not {ip}, which STUN sees, so another NAT sits between the router and the internet"
        )),
        Some(_) => Public::Known {
            ip,
            by: PublicBy::Upnp,
        },
    }
}

/// The IPv4 addresses of `iface`, or none when it is gone.
fn addresses(iface: &str) -> Vec<Ipv4Addr> {
    netcfg::ipv4_addresses()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|(name, address)| (name == iface).then_some(address))
        .collect()
}

/// Keep `wanted`, the value the publisher writes, current. With publish
/// `txt` that is the STUN mapping. With publish `a` it is the public IP,
/// judged again every [`ADDRESS_EVERY`] and on each new mapping or lease,
/// and none while no IP is confirmed, so the publisher never writes an IP
/// that natwg does not confirm now. `public` tells the status where the IP
/// came from, or why there is none.
///
/// A mapping that moves away from the gateway's WAN address notifies
/// `recheck`, which renews the lease and asks that address again at once.
/// Until a renewal that began after the notice answers, or
/// [`RECHECK_LIMIT`] passes, nothing is confirmed and the status keeps its
/// verdict.
pub async fn run(
    server: &ServerConfig,
    mut mapping: watch::Receiver<Option<Mapping>>,
    mut lease: watch::Receiver<Option<Lease>>,
    wanted: watch::Sender<Option<Content>>,
    public: watch::Sender<Public>,
    recheck: &Notify,
) -> Infallible {
    if server.publish == PublishMode::Txt {
        loop {
            let value = mapping.borrow_and_update().map(|m| Content::Txt(m.addr));
            wanted.send_if_modified(|wanted| std::mem::replace(wanted, value) != value);
            if mapping.changed().await.is_err() {
                std::future::pending::<()>().await;
            }
        }
    }
    let set = |value: Option<Content>| {
        wanted.send_if_modified(|wanted| std::mem::replace(wanted, value) != value);
    };
    let mut tick = tokio::time::interval(ADDRESS_EVERY);
    tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
    // The mapping judged last, so a move is told by value, whichever
    // change woke the loop.
    let mut judged: Option<SocketAddrV4> = None;
    // When the gateway was asked again, and until when to wait for it.
    let mut asked: Option<(SystemTime, Instant)> = None;
    loop {
        tokio::select! {
            _ = tick.tick() => {}
            Ok(()) = mapping.changed() => {}
            Ok(()) = lease.changed() => {}
        }
        let addresses = addresses(&server.iface);
        let seen = Seen {
            iface: &server.iface,
            listen_port: server.listen_port,
            addresses: &addresses,
            stun: server.stun.is_some(),
            mapping: mapping.borrow_and_update().map(|m| m.addr),
            upnp: server.upnp.is_some(),
            lease: *lease.borrow_and_update(),
        };
        let moved = seen.mapping != std::mem::replace(&mut judged, seen.mapping);
        if let Some((at, until)) = asked
            && (seen.lease.is_some_and(|lease| lease.at >= at) || Instant::now() >= until)
        {
            asked = None;
        }
        // Only a new mapping asks again, so a gateway that disagrees for
        // good is not asked in a loop.
        let external = seen.lease.and_then(|lease| lease.external_ip);
        if moved
            && seen.addresses.iter().all(|&ip| !is_public(ip))
            && let (Some(mapping), Some(external)) = (seen.mapping, external)
            && *mapping.ip() != external
        {
            recheck.notify_one();
            asked = Some((SystemTime::now(), Instant::now() + RECHECK_LIMIT));
        }
        if asked.is_some() {
            set(None);
            continue;
        }
        let now = self::public(&seen);
        let before = public.send_replace(now.clone());
        if before != now {
            report(&now);
        }
        set(now.ip().map(Content::A));
    }
}

fn report(now: &Public) {
    match now {
        Public::Known { ip, by } => tracing::info!("public IP {ip} by {by}"),
        Public::Missing(error) => {
            tracing::warn!("no public IP to publish, and the A record stays as it is: {error}");
        }
        Public::Unknown => {}
    }
}
