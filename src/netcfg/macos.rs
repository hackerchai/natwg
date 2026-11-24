//! On macOS, `ifconfig` sets the address and the MTU, and `route` adds the
//! routes. A utun is point to point, so the kernel adds no route for the
//! subnet of its address.

use super::{Step, read};
use crate::{Error, Result};
use ipnetwork::Ipv4Network;
use std::net::Ipv4Addr;

/// Refuse the start while a route through a utun covers a peer's allowed
/// IPs, as the routes of a tunnel that `wg-quick down` left behind do.
/// natwg routes only the tunnel subnet, so the kernel would prefer the
/// narrower route and send that peer's traffic to the other utun. natwg's
/// own utun does not exist yet when this runs.
pub fn require_free_routes(allowed: &[Ipv4Network]) -> Result<()> {
    let listing = read(&["netstat", "-rn", "-f", "inet"])?;
    let Some((route, utun, net)) = utun_route_within(&listing, allowed) else {
        return Ok(());
    };
    Err(Error::new(
        "ROUTE_IN_USE",
        format!(
            "the route {route} through {utun} lies within the allowed IPs {net} of a peer, and the kernel would send that peer's traffic to {utun}; take {utun} down or delete the route"
        ),
    ))
}

/// The first route in what `netstat -rn -f inet` prints that leaves through
/// a utun and lies within one of `allowed`, with its utun and that network.
/// A route the kernel cloned from a wider one, flagged `W`, does not count,
/// because Surge clones one through its utun for every host it reaches.
pub fn utun_route_within<'a>(
    listing: &'a str,
    allowed: &[Ipv4Network],
) -> Option<(Ipv4Network, &'a str, Ipv4Network)> {
    listing.lines().find_map(|line| {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let [destination, _, flags, utun, ..] = fields[..] else {
            return None;
        };
        if !utun.starts_with("utun") || flags.contains('W') {
            return None;
        }
        let route = netstat_destination(destination, flags.contains('H'))?;
        let net = allowed
            .iter()
            .find(|net| net.contains(route.network()) && route.prefix() >= net.prefix())?;
        Some((route, utun, *net))
    })
}

/// A destination as netstat prints it. A host has the `H` flag. A network
/// leaves off its trailing zero octets, and its prefix when that is the
/// classful one, as in `10.66.75/24` and `127`. `default` is none of these.
fn netstat_destination(text: &str, host: bool) -> Option<Ipv4Network> {
    let (address, prefix) = match text.split_once('/') {
        Some((address, prefix)) => (address, Some(prefix.parse().ok()?)),
        None => (text, None),
    };
    let mut given = address.split('.');
    let mut octets = [0u8; 4];
    for octet in &mut octets {
        if let Some(text) = given.next() {
            *octet = text.parse().ok()?;
        }
    }
    if given.next().is_some() {
        return None;
    }
    let prefix = prefix.unwrap_or(match (host, octets[0]) {
        (true, _) => 32,
        (false, 0..=127) => 8,
        (false, 128..=191) => 16,
        (false, _) => 24,
    });
    Ipv4Network::new(Ipv4Addr::from(octets), prefix).ok()
}

pub fn plan(tun: &str, address: Ipv4Network, mtu: u16, routes: &[Ipv4Network]) -> Vec<Step> {
    let ip = address.ip().to_string();
    let netmask = address.mask().to_string();
    let mtu = mtu.to_string();
    let configure = Step::new(&[
        "ifconfig", tun, "inet", &ip, &ip, "netmask", &netmask, "mtu", &mtu, "up",
    ]);
    let routes = routes.iter().map(|route| {
        let route = format!("{}/{}", route.network(), route.prefix());
        Step::new(&[
            "route",
            "-q",
            "-n",
            "add",
            "-inet",
            &route,
            "-interface",
            tun,
        ])
        .done_when(
            &["route", "-n", "get", "-inet", &route],
            format!("interface: {tun}\n"),
        )
    });
    std::iter::once(configure).chain(routes).collect()
}
