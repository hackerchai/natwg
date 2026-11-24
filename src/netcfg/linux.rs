//! On Linux, iproute2 sets the address, the MTU and the routes. The kernel
//! adds the route for the subnet of the address by itself.

use super::Step;
use ipnetwork::Ipv4Network;

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
