//! The verdict of `natwg detect` as a pure function of what the tests saw,
//! so every combination is testable without a network.

use serde::{Deserialize, Serialize};
use std::{
    fmt,
    net::{Ipv4Addr, SocketAddrV4},
};

/// Whether this network can host a natwg server.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// A client whose address is unknown in advance reaches the server.
    Supported,
    /// Nothing rules the network out, but one test could not be run or
    /// its answers disagree. A first client will tell.
    Likely,
    /// The tests could not see the public side of the network: every STUN
    /// server that answered sits inside a NAT with the host. Nothing is
    /// known; `natwg init` refuses it.
    Inconclusive,
    /// A client cannot reach the server.
    Unsupported,
}

impl Verdict {
    /// The exit status of `natwg detect`. An error is 3.
    pub fn exit_code(self) -> i32 {
        match self {
            Self::Supported => 0,
            Self::Unsupported => 1,
            Self::Likely | Self::Inconclusive => 2,
        }
    }
}

/// How a supported network reaches the server.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    /// A public IPv4 address with the listen port, held by the host or by a
    /// router that forwards the port.
    Public,
    /// A full-cone NAT: endpoint-independent mapping and filtering.
    Nat1,
}

/// How natwg established that a supported network is public. The server's
/// status file names the source of the IP that publish `a` keeps with it too.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicBy {
    /// The uplink holds the public address that STUN sees.
    Address,
    /// The UPnP gateway forwards the tested port, and its WAN address is the
    /// one STUN sees.
    Upnp,
    /// STUN sees a public address with the tested port, and anyone gets in,
    /// but no gateway confirmed a forward: a full-cone NAT that keeps the
    /// port looks the same, and its mapping lives only while traffic flows.
    PortKept,
}

impl fmt::Display for PublicBy {
    /// The name `--json` and the status file use.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Address => "address",
            Self::Upnp => "upnp",
            Self::PortKept => "port_kept",
        })
    }
}

/// How the NAT picks the public address of a socket (RFC 4787).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Mapping {
    /// STUN sees the host's own address and port.
    NoNat,
    /// Every destination sees the same public address and port.
    EndpointIndependent,
    /// Destinations see different public ports or addresses (NAT4).
    EndpointDependent,
    /// Fewer than two server addresses answered.
    Unknown,
}

/// Which senders the NAT lets in through a mapping (RFC 4787).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Filtering {
    /// Anyone (NAT1, full cone).
    EndpointIndependent,
    /// Only addresses the host has sent to (NAT2, restricted cone).
    AddressDependent,
    /// Only addresses and ports the host has sent to (NAT3, port-restricted).
    AddressAndPortDependent,
    /// No RFC 5780 server ran the change tests.
    Unknown,
}

/// What became of one CHANGE-REQUEST. In JSON it is always
/// `{"result": "answered" | "silent" | "not_run", "from": "ip:port" | null}`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(into = "ProbeRecord")]
pub enum Probe {
    /// An answer arrived from this address.
    Answered(SocketAddrV4),
    /// No answer arrived.
    Silent,
    /// The test was not run, as when the server has a single IP.
    NotRun,
}

#[derive(Serialize)]
struct ProbeRecord {
    result: &'static str,
    from: Option<SocketAddrV4>,
}

impl From<Probe> for ProbeRecord {
    fn from(probe: Probe) -> Self {
        let (result, from) = match probe {
            Probe::Answered(from) => ("answered", Some(from)),
            Probe::Silent => ("silent", None),
            Probe::NotRun => ("not_run", None),
        };
        Self { result, from }
    }
}

/// The change tests of RFC 5780 against one server.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct ChangeTest {
    pub server: SocketAddrV4,
    /// The OTHER-ADDRESS (or CHANGED-ADDRESS) the server reported.
    pub other: SocketAddrV4,
    /// Answer from the other IP and port: only a NAT that lets anyone in
    /// passes it.
    pub ip_and_port: Probe,
    /// Answer from the same IP and the other port: a NAT that filters by
    /// port drops it.
    pub port: Probe,
}

/// A STUN server and the mapping it reported.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Answer {
    pub server: SocketAddrV4,
    pub mapped: SocketAddrV4,
}

/// Whether a datagram from a second socket of the host, sent to the mapping,
/// arrived at the tested socket.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SelfTest {
    Received,
    /// Inconclusive: the carrier may not hairpin.
    NotReceived,
    /// Not run: no mapping, or nothing to learn from one.
    Skipped,
}

/// What the tests saw.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Observations {
    /// The uplink's address and the tested port.
    pub local: SocketAddrV4,
    pub answers: Vec<Answer>,
    pub change_tests: Vec<ChangeTest>,
    pub self_test: SelfTest,
    /// The WAN address of the UPnP gateway, when one answered.
    pub gateway_ip: Option<Ipv4Addr>,
    /// Whether that gateway forwards the tested port to this host: natwg
    /// leased it for the test, or the lease existed.
    pub upnp_forwarded: bool,
}

/// The verdict and the reasons for it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Assessment {
    pub verdict: Verdict,
    pub kind: Option<Kind>,
    /// For a supported public network.
    pub public_by: Option<PublicBy>,
    pub mapping: Mapping,
    pub filtering: Filtering,
    /// One line on why the network is not supported, or only likely.
    pub reason: Option<String>,
    /// What would fix an unsupported network, or settle a likely one.
    pub fix: Option<String>,
}

// Ranges that are not reachable from the internet: RFC 6890 and the IANA
// special-purpose registry.
const NOT_PUBLIC: [(Ipv4Addr, u32); 15] = [
    (Ipv4Addr::new(0, 0, 0, 0), 8),
    (Ipv4Addr::new(10, 0, 0, 0), 8),
    (Ipv4Addr::new(100, 64, 0, 0), 10),
    (Ipv4Addr::new(127, 0, 0, 0), 8),
    (Ipv4Addr::new(169, 254, 0, 0), 16),
    (Ipv4Addr::new(172, 16, 0, 0), 12),
    (Ipv4Addr::new(192, 0, 0, 0), 24),
    (Ipv4Addr::new(192, 0, 2, 0), 24),
    (Ipv4Addr::new(192, 88, 99, 0), 24),
    (Ipv4Addr::new(192, 168, 0, 0), 16),
    (Ipv4Addr::new(198, 18, 0, 0), 15),
    (Ipv4Addr::new(198, 51, 100, 0), 24),
    (Ipv4Addr::new(203, 0, 113, 0), 24),
    (Ipv4Addr::new(224, 0, 0, 0), 4),
    (Ipv4Addr::new(240, 0, 0, 0), 4),
];

/// Whether `address` is a public unicast IPv4 address. Private (RFC 1918),
/// carrier-grade NAT (100.64.0.0/10), loopback, link-local, documentation,
/// benchmarking, multicast and reserved addresses are not.
pub fn is_public(address: Ipv4Addr) -> bool {
    !NOT_PUBLIC.iter().any(|(network, prefix)| {
        let mask = u32::MAX << (32 - prefix);
        address.to_bits() & mask == network.to_bits()
    })
}

/// Whether a server sits inside a NAT with the host, as one on its LAN
/// does: it saw a private address, which says nothing of the public side.
fn inside(answer: &Answer) -> bool {
    !is_public(*answer.mapped.ip())
}

/// The mapping behaviour the answers of servers outside the NAT show. One
/// distinct mapping from two server IPs or more is endpoint-independent; two
/// distinct mappings are endpoint-dependent, however few servers answered.
/// The host's own public address and port is no NAT.
pub fn mapping(local: SocketAddrV4, answers: &[Answer]) -> Mapping {
    let outside: Vec<&Answer> = answers.iter().filter(|answer| !inside(answer)).collect();
    let mut mapped: Vec<SocketAddrV4> = outside.iter().map(|answer| answer.mapped).collect();
    mapped.sort();
    mapped.dedup();
    let mut servers: Vec<Ipv4Addr> = outside.iter().map(|answer| *answer.server.ip()).collect();
    servers.sort();
    servers.dedup();
    match mapped[..] {
        [] => Mapping::Unknown,
        [_, _, ..] => Mapping::EndpointDependent,
        // Only a public address passes the filter above.
        [only] if only == local => Mapping::NoNat,
        [_] if servers.len() >= 2 => Mapping::EndpointIndependent,
        [_] => Mapping::Unknown,
    }
}

/// Whether one server's change tests contradict each other: an answer from
/// its other IP and port got in, but none from its other port alone. No
/// endpoint-independent filter does that; a NAT that opens for some senders
/// only does.
pub fn inconsistent(test: &ChangeTest) -> bool {
    matches!(test.ip_and_port, Probe::Answered(_)) && test.port == Probe::Silent
}

/// The filtering behaviour the change tests show. A NAT cannot forge an
/// answer, so an answer outweighs another server's silence: one server's
/// consistent answer from another IP proves endpoint-independent filtering.
/// A server whose own tests contradict each other proves nothing either way.
pub fn filtering(tests: &[ChangeTest]) -> Filtering {
    let consistent: Vec<&ChangeTest> = tests.iter().filter(|test| !inconsistent(test)).collect();
    let any = |pick: fn(&ChangeTest) -> Probe, wanted: fn(Probe) -> bool| {
        consistent.iter().any(|test| wanted(pick(test)))
    };
    let answered = |probe: Probe| matches!(probe, Probe::Answered(_));
    let ip_answered = any(|test| test.ip_and_port, answered);
    let ip_silent = any(|test| test.ip_and_port, |probe| probe == Probe::Silent);
    let port_answered = any(|test| test.port, answered);
    let port_silent = any(|test| test.port, |probe| probe == Probe::Silent);
    if ip_answered {
        Filtering::EndpointIndependent
    } else if consistent.len() < tests.len() {
        // Some sender the host never sent to got in, so this is no NAT2 or
        // NAT3 either.
        Filtering::Unknown
    } else if port_answered && ip_silent {
        Filtering::AddressDependent
    } else if port_answered {
        // A new port got in, but no server could change its IP: NAT1 or NAT2.
        Filtering::Unknown
    } else if port_silent {
        Filtering::AddressAndPortDependent
    } else if ip_silent {
        // Another IP and port did not get in, and the port alone was not
        // tested: NAT2 at least.
        Filtering::AddressDependent
    } else {
        Filtering::Unknown
    }
}

/// The verdict on `seen`.
pub fn classify(seen: &Observations) -> Assessment {
    let port = seen.local.port();
    let mapping = mapping(seen.local, &seen.answers);
    // A change test against a server inside the NAT says nothing of it.
    let tests: Vec<ChangeTest> = seen
        .change_tests
        .iter()
        .filter(|test| {
            !seen
                .answers
                .iter()
                .any(|answer| answer.server == test.server && inside(answer))
        })
        .copied()
        .collect();
    let filtering = filtering(&tests);
    let assessment =
        |verdict, kind, public_by, reason: Option<String>, fix: Option<String>| Assessment {
            verdict,
            kind,
            public_by,
            mapping,
            filtering,
            reason,
            fix,
        };
    let cannot = |why: &str| Some(format!("This network cannot host natwg: {why}."));
    let nat_fix = Some(format!(
        "A public IPv4 address, NAT1 (full cone) from the carrier, or a router that forwards udp/{port} to this host would fix it."
    ));
    if seen.answers.is_empty() {
        return assessment(
            Verdict::Unsupported,
            None,
            None,
            cannot("no STUN server answered, so UDP to the internet is blocked"),
            Some("Allowing outbound UDP, or another network, would fix it.".to_owned()),
        );
    }
    if seen.answers.iter().all(inside) {
        let seen_as: Vec<String> = seen.answers.iter().map(|a| a.mapped.to_string()).collect();
        return assessment(
            Verdict::Inconclusive,
            None,
            None,
            Some(format!(
                "Every STUN server that answered sits inside a NAT with this host (each saw a private address: {}), so natwg could not test the public side: neither the mapping nor the filtering is known.",
                seen_as.join(", ")
            )),
            Some(
                "Pass --server with STUN servers on the internet, or leave --server out to use the built-in ones."
                    .to_owned(),
            ),
        );
    }
    let filtered = match filtering {
        Filtering::AddressDependent => Some((
            "addresses",
            "address-dependent filtering, NAT2, restricted cone",
        )),
        Filtering::AddressAndPortDependent => Some((
            "addresses and ports",
            "address-and-port-dependent filtering, NAT3, port-restricted cone",
        )),
        Filtering::EndpointIndependent | Filtering::Unknown => None,
    };
    let contradiction = tests.iter().find(|test| inconsistent(test)).map(|test| {
        format!(
            "{} answered from its other IP and port but not from its other port, so the NAT lets in some senders the host has not sent to and drops others",
            test.server
        )
    });
    let untested = || {
        contradiction
            .clone()
            .unwrap_or_else(|| "no RFC 5780 STUN server ran the filtering test".to_owned())
    };
    let settle = || {
        Some(
            "A first client will tell, or pass --server with an RFC 5780 STUN server that answers from here."
                .to_owned(),
        )
    };
    match (mapping, filtered) {
        (Mapping::EndpointDependent, _) => assessment(
            Verdict::Unsupported,
            None,
            None,
            cannot(
                "the NAT gives each destination its own public port (endpoint-dependent mapping, NAT4, symmetric), so a client never reaches the port STUN reports",
            ),
            nat_fix,
        ),
        (Mapping::NoNat, Some((senders, _))) => assessment(
            Verdict::Unsupported,
            None,
            None,
            cannot(&format!(
                "the host has a public address, but a firewall drops UDP to udp/{port} from {senders} the host has not sent to"
            )),
            Some(format!(
                "Letting udp/{port} in from any address in the firewall would fix it."
            )),
        ),
        (Mapping::NoNat, None) if filtering == Filtering::EndpointIndependent => assessment(
            Verdict::Supported,
            Some(Kind::Public),
            Some(PublicBy::Address),
            None,
            None,
        ),
        (Mapping::NoNat, None) => assessment(
            Verdict::Likely,
            None,
            None,
            Some(format!(
                "The host has a public address, but {}, so a firewall that drops UDP from senders the host has not sent to cannot be ruled out.",
                untested()
            )),
            Some(format!(
                "Pass --server with an RFC 5780 STUN server that answers from here, or make sure the firewall lets udp/{port} in from any address."
            )),
        ),
        (_, Some((senders, name))) => assessment(
            Verdict::Unsupported,
            None,
            None,
            cannot(&format!(
                "the NAT drops UDP from {senders} the host has not sent to ({name})"
            )),
            nat_fix,
        ),
        (Mapping::EndpointIndependent, None) if filtering == Filtering::EndpointIndependent => {
            match public_by(seen) {
                Some(by) => {
                    assessment(Verdict::Supported, Some(Kind::Public), Some(by), None, None)
                }
                None => assessment(Verdict::Supported, Some(Kind::Nat1), None, None, None),
            }
        }
        (Mapping::EndpointIndependent, None) => assessment(
            Verdict::Likely,
            None,
            None,
            Some(format!(
                "The mapping is endpoint-independent, but {}, so natwg cannot tell whether a client it has not sent to gets in{}.",
                untested(),
                match seen.self_test {
                    SelfTest::Received => "; the self test got in through the mapping",
                    SelfTest::NotReceived =>
                        "; the self test did not get in, which proves nothing where the carrier does not hairpin",
                    SelfTest::Skipped => "",
                }
            )),
            settle(),
        ),
        (_, None) => assessment(
            Verdict::Likely,
            None,
            None,
            Some(format!(
                "Only one STUN server address on the internet answered, so natwg cannot tell whether the mapping is endpoint-independent{}.",
                match filtering {
                    Filtering::EndpointIndependent =>
                        "; the filtering is endpoint-independent".to_owned(),
                    _ => format!("; and {}", untested()),
                }
            )),
            Some(
                "A first client will tell, or pass more --server addresses that answer from here."
                    .to_owned(),
            ),
        ),
    }
}

/// How the endpoint of an endpoint-independent, unfiltered NAT counts as
/// public, if it does: a public address that keeps the tested port. With a
/// UPnP gateway that forwards the port and owns that address, the forward is
/// confirmed. A gateway whose WAN address is another one sits behind carrier
/// NAT, which only happened to keep the port. Without a gateway, a router
/// that forwards the port and a full-cone NAT that keeps it look the same.
fn public_by(seen: &Observations) -> Option<PublicBy> {
    let first = seen.answers.iter().find(|answer| !inside(answer))?;
    let ip = *first.mapped.ip();
    if first.mapped.port() != seen.local.port() || !is_public(ip) {
        return None;
    }
    match seen.gateway_ip {
        Some(gateway) if gateway != ip => None,
        Some(_) if seen.upnp_forwarded => Some(PublicBy::Upnp),
        _ => Some(PublicBy::PortKept),
    }
}
