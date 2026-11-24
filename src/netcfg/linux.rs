//! On Linux, iproute2 sets the address, the MTU and the routes. The kernel
//! adds the route for the subnet of the address by itself.

use super::{Step, read};
use crate::{Error, Result};
use ipnetwork::Ipv4Network;

/// Refuse a tunnel subnet that another device routes already. The kernel
/// would keep both routes and send the traffic for the tunnel peers to the
/// other device.
pub fn require_free_route(tun: &str, subnet: Ipv4Network) -> Result<()> {
    let listing = read(&["ip", "-4", "route", "show", "exact", &subnet.to_string()])?;
    let Some(route) = foreign_route(&listing, tun) else {
        return Ok(());
    };
    Err(Error::new(
        "ROUTE_IN_USE",
        format!(
            "the tunnel subnet {subnet} already has the route {route:?}, and a second route for it through {tun} would not carry the traffic; remove that route or change interface.address"
        ),
    ))
}

/// The first route in what `ip -4 route show exact <subnet>` prints that
/// does not leave through `tun`.
pub fn foreign_route<'a>(listing: &'a str, tun: &str) -> Option<&'a str> {
    listing
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .find(|line| {
            let mut words = line.split_whitespace();
            !(words.any(|word| word == "dev") && words.next() == Some(tun))
        })
}

pub fn plan(tun: &str, address: Ipv4Network, mtu: u16, routes: &[Ipv4Network]) -> Vec<Step> {
    let network = |net: &Ipv4Network| (net.network(), net.prefix());
    let cidr = address.to_string();
    let mtu = mtu.to_string();
    let configure = [
        Step::new(&["ip", "addr", "replace", &cidr, "dev", tun]),
        Step::new(&["ip", "link", "set", "dev", tun, "mtu", &mtu, "up"]),
    ];
    let routes = routes
        .iter()
        .filter(|route| network(route) != network(&address))
        .map(|route| {
            let route = format!("{}/{}", route.network(), route.prefix());
            Step::new(&["ip", "route", "replace", &route, "dev", tun])
        });
    configure.into_iter().chain(routes).collect()
}
