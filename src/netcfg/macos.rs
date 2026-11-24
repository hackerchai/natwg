//! On macOS, `ifconfig` sets the address and the MTU, and `route` adds the
//! routes. A utun is point to point, so the kernel adds no route for the
//! subnet of its address.

use super::Step;
use ipnetwork::Ipv4Network;

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
