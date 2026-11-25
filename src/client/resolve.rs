//! The server's endpoint from its TXT record, or from the A record of its
//! name, asked of several DNS servers through the uplink, past any resolver
//! a VPN app hijacks on the default route.

use crate::config::{ClientConfig, HostPort, PublishMode};
use crate::detect::is_public;
use crate::wire::dns::{self, Record, RecordKind};
use crate::wire::transport::BoundInterface;
use crate::{Error, Result};
use std::{
    net::{Ipv4Addr, SocketAddrV4},
    time::Duration,
};

/// The DNS servers a client asks when its config names none, the ones the
/// bash updater asked.
pub const DEFAULT_RESOLVERS: [Ipv4Addr; 4] = [
    Ipv4Addr::new(223, 5, 5, 5),
    Ipv4Addr::new(119, 29, 29, 29),
    Ipv4Addr::new(1, 1, 1, 1),
    Ipv4Addr::new(8, 8, 8, 8),
];

// A TXT value is quoted in an error only up to this length.
const SHOWN: usize = 64;

/// What the client looks up to find the server.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lookup<'a> {
    /// A TXT record that holds the endpoint as `"ip:port"`.
    Txt(&'a str),
    /// The A record of `host`, dialed at `port`.
    A(&'a HostPort),
}

impl<'a> Lookup<'a> {
    /// What `client` looks up, if anything: its TXT `record`, or the A record
    /// of its `server`.
    pub fn of(client: &'a ClientConfig) -> Option<Self> {
        match (&client.record, &client.server) {
            (Some(record), _) => Some(Self::Txt(record)),
            (None, Some(server)) => Some(Self::A(server)),
            (None, None) => None,
        }
    }

    /// The name asked of the DNS servers.
    pub fn name(self) -> &'a str {
        match self {
            Self::Txt(record) => record,
            Self::A(server) => &server.host,
        }
    }

    pub fn mode(self) -> PublishMode {
        match self {
            Self::Txt(_) => PublishMode::Txt,
            Self::A(_) => PublishMode::A,
        }
    }

    /// Ask each of `resolvers` in turn through `iface`, and return the
    /// endpoint the first good answer names and the resolver that gave it.
    pub async fn endpoint(
        self,
        iface: &BoundInterface,
        resolvers: &[SocketAddrV4],
        timeout: Duration,
    ) -> Result<(SocketAddrV4, SocketAddrV4)> {
        match self {
            Self::Txt(record) => lookup(iface, resolvers, record, timeout).await,
            Self::A(server) => lookup_a(iface, resolvers, server, timeout).await,
        }
    }
}

/// The endpoint a TXT value names: `ip:port`, with optional quotes and
/// whitespace around it. A port of 0 and an address no server can have are
/// not endpoints.
pub fn parse_endpoint(text: &str) -> Option<SocketAddrV4> {
    let text = text.trim().trim_matches('"').trim();
    let endpoint: SocketAddrV4 = text.parse().ok()?;
    (endpoint.port() != 0 && usable(*endpoint.ip())).then_some(endpoint)
}

/// Whether a server can have `ip`: not the unspecified, broadcast or a
/// multicast address.
fn usable(ip: Ipv4Addr) -> bool {
    !(ip.is_unspecified() || ip.is_broadcast() || ip.is_multicast())
}

/// The first public address among the A records of one answer. The server
/// publishes only public IPs, so a private, loopback or carrier-grade NAT
/// address, or one of 198.18.0.0/15 that the fake-IP DNS of Surge and Clash
/// hands out, is never the server's.
pub fn first_address(records: &[Record]) -> Option<Ipv4Addr> {
    addresses(records).into_iter().find(|&ip| is_public(ip))
}

fn addresses(records: &[Record]) -> Vec<Ipv4Addr> {
    records
        .iter()
        .filter_map(|record| match record {
            Record::A(ip) => Some(*ip),
            Record::Txt(_) => None,
        })
        .collect()
}

/// The first well-formed endpoint among the TXT records of one answer.
pub fn first_endpoint(records: &[Record]) -> Option<SocketAddrV4> {
    records.iter().find_map(|record| match record {
        Record::Txt(text) => parse_endpoint(text),
        Record::A(_) => None,
    })
}

/// Ask each of `resolvers` in turn for the TXT records of `record` through
/// `iface`, and return the first well-formed endpoint and the resolver that
/// gave it. A resolver that fails or answers with no endpoint is skipped.
pub async fn lookup(
    iface: &BoundInterface,
    resolvers: &[SocketAddrV4],
    record: &str,
    timeout: Duration,
) -> Result<(SocketAddrV4, SocketAddrV4)> {
    let mut failures = Vec::new();
    for &resolver in resolvers {
        match dns::resolve(iface, resolver, record, RecordKind::Txt, timeout).await {
            Ok(records) => match first_endpoint(&records) {
                Some(endpoint) => return Ok((endpoint, resolver)),
                None => failures.push(format!(
                    "{resolver} answered {}",
                    shown(&records).unwrap_or_else(|| "no TXT".to_owned())
                )),
            },
            Err(error) => failures.push(error.to_string()),
        }
    }
    if failures.is_empty() {
        return Err(Error::new("TXT_NO_RESOLVER", "no DNS server to ask"));
    }
    Err(Error::new(
        "TXT_NO_ENDPOINT",
        format!(
            "no DNS server gave an ip:port TXT for {record}: {}",
            failures.join("; ")
        ),
    ))
}

/// Ask each of `resolvers` in turn for the A records of `server.host`
/// through `iface`, and return the first public address at `server.port`,
/// and the resolver that gave it. A resolver that fails or answers with no
/// public address is skipped.
pub async fn lookup_a(
    iface: &BoundInterface,
    resolvers: &[SocketAddrV4],
    server: &HostPort,
    timeout: Duration,
) -> Result<(SocketAddrV4, SocketAddrV4)> {
    let name = &server.host;
    let mut failures = Vec::new();
    for &resolver in resolvers {
        match dns::resolve(iface, resolver, name, RecordKind::A, timeout).await {
            Ok(records) => match first_address(&records) {
                Some(ip) => return Ok((SocketAddrV4::new(ip, server.port), resolver)),
                None => {
                    let shown: Vec<String> = addresses(&records)
                        .iter()
                        .map(ToString::to_string)
                        .collect();
                    failures.push(format!(
                        "{name} answered {} at {resolver}, not a public address (a fake-IP DNS?)",
                        shown.join(", ")
                    ));
                }
            },
            Err(error) => failures.push(error.to_string()),
        }
    }
    if failures.is_empty() {
        return Err(Error::new("A_NO_RESOLVER", "no DNS server to ask"));
    }
    Err(Error::new(
        "A_NO_ADDRESS",
        format!(
            "no DNS server gave a public A record for {name}: {}",
            failures.join("; ")
        ),
    ))
}

/// The TXT values of an answer that has no endpoint, for an error.
fn shown(records: &[Record]) -> Option<String> {
    let values: Vec<String> = records
        .iter()
        .filter_map(|record| match record {
            Record::Txt(text) => Some(format!(
                "{:?}",
                text.chars().take(SHOWN).collect::<String>()
            )),
            Record::A(_) => None,
        })
        .collect();
    (!values.is_empty()).then(|| values.join(", "))
}
