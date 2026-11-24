//! The uplink: the physical interface that the client's WireGuard and DNS
//! traffic leaves through. Binding to it keeps that traffic out of a VPN
//! app's TUN, such as Surge's, which owns the default route.

use crate::wire::transport::BoundInterface;
use crate::{Error, Result, netcfg};
use std::{fmt, net::Ipv4Addr};

// Interfaces that carry another tunnel or never reach the internet on their
// own. A name that starts with one of these is never picked as the uplink.
const VIRTUAL: [&str; 21] = [
    "lo",
    "utun",
    "tun",
    "tap",
    "ipsec",
    "ppp",
    "gif",
    "stf",
    "awdl",
    "llw",
    "anpi",
    "bridge",
    "vmenet",
    "feth",
    "wg",
    "natwg",
    "tailscale",
    "zt",
    "docker",
    "veth",
    "virbr",
];

/// The uplink as it was when it was looked up.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Uplink {
    pub iface: BoundInterface,
    /// Its first IPv4 address, if it has one.
    pub address: Option<Ipv4Addr>,
}

impl fmt::Display for Uplink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.address {
            Some(address) => write!(f, "{} ({address})", self.iface),
            None => write!(f, "{} (no IPv4 address)", self.iface),
        }
    }
}

/// The interface named `configured`, or else the physical interface with
/// the highest-priority default route that has an IPv4 address.
pub fn find(configured: Option<&str>) -> Result<Uplink> {
    let addresses =
        netcfg::ipv4_addresses().map_err(|e| Error::new("INTERFACES_UNREADABLE", e.to_string()))?;
    let address_of = |name: &str| {
        addresses
            .iter()
            .find(|(holder, _)| holder == name)
            .map(|(_, address)| *address)
    };
    let name = match configured {
        Some(name) => name.to_owned(),
        None => default_routes()?
            .into_iter()
            .find(|name| !is_virtual(name) && address_of(name).is_some())
            .ok_or_else(|| {
                Error::new(
                    "UPLINK_NOT_FOUND",
                    "no physical interface with an IPv4 address has a default route; connect to a network or set role.client.iface",
                )
            })?,
    };
    Ok(Uplink {
        iface: BoundInterface::lookup(&name)?,
        address: address_of(&name),
    })
}

/// Whether `name` is a tunnel or another interface that is never an uplink.
pub fn is_virtual(name: &str) -> bool {
    VIRTUAL.iter().any(|prefix| name.starts_with(prefix)) || name.starts_with("br-")
}

/// The interfaces with a default route, the preferred one first.
#[cfg(target_os = "macos")]
fn default_routes() -> Result<Vec<String>> {
    let listing = netcfg::read(&["scutil", "--nwi"])?;
    Ok(service_order(&listing)
        .into_iter()
        .map(str::to_owned)
        .collect())
}

#[cfg(not(target_os = "macos"))]
fn default_routes() -> Result<Vec<String>> {
    let listing = netcfg::read(&["ip", "-4", "route", "show", "default"])?;
    Ok(by_metric(&listing).into_iter().map(str::to_owned).collect())
}

/// The interfaces of `scutil --nwi` in the order macOS prefers them. A VPN
/// app that owns the default route comes first, so the caller skips it.
pub fn service_order(nwi: &str) -> Vec<&str> {
    nwi.lines()
        .find_map(|line| line.trim().strip_prefix("Network interfaces:"))
        .map(|names| names.split_whitespace().collect())
        .unwrap_or_default()
}

/// The devices of the default routes in what `ip -4 route show default`
/// prints, the lowest metric first.
pub fn by_metric(listing: &str) -> Vec<&str> {
    let mut routes: Vec<(u32, &str)> = listing
        .lines()
        .filter_map(|line| {
            let words: Vec<&str> = line.split_whitespace().collect();
            let after = |key: &str| {
                let at = words.iter().position(|word| *word == key)?;
                words.get(at + 1).copied()
            };
            let device = after("dev")?;
            let metric = after("metric").and_then(|m| m.parse().ok()).unwrap_or(0);
            Some((metric, device))
        })
        .collect();
    routes.sort_by_key(|(metric, _)| *metric);
    routes.into_iter().map(|(_, device)| device).collect()
}
