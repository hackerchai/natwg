//! The server's endpoint from its TXT record, asked of several DNS servers
//! through the uplink, past any resolver a VPN app hijacks on the default
//! route.

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

/// The endpoint a TXT value names: `ip:port`, with optional quotes and
/// whitespace around it. A port of 0 and an address no server can have are
/// not endpoints.
pub fn parse_endpoint(text: &str) -> Option<SocketAddrV4> {
    let text = text.trim().trim_matches('"').trim();
    let endpoint: SocketAddrV4 = text.parse().ok()?;
    let ip = endpoint.ip();
    let unusable =
        endpoint.port() == 0 || ip.is_unspecified() || ip.is_broadcast() || ip.is_multicast();
    (!unusable).then_some(endpoint)
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
