//! `natwg detect`: the verdict as a pure function of the observations, and
//! the socket flow against fake STUN servers on loopback that answer the
//! way each kind of NAT would let their answers through.

use natwg::detect::{
    self, Answer, ChangeTest, Filtering, Kind, Mapping, Observations, Probe, Request, SelfTest,
    UpnpMode, Verdict, classify, is_public,
};
use std::{
    collections::HashSet,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::net::UdpSocket;

#[cfg(target_os = "macos")]
const LOOPBACK: &str = "lo0";
#[cfg(target_os = "linux")]
const LOOPBACK: &str = "lo";

fn addr(text: &str) -> SocketAddrV4 {
    text.parse().unwrap()
}

const LOCAL: &str = "10.73.0.4:51830";
const MAPPED: &str = "45.77.0.9:7136";

fn answers(pairs: &[(&str, &str)]) -> Vec<Answer> {
    pairs
        .iter()
        .map(|(server, mapped)| Answer {
            server: addr(server),
            mapped: addr(mapped),
        })
        .collect()
}

/// Two servers on different IPs that report `mapped`.
fn agreeing(mapped: &str) -> Vec<Answer> {
    answers(&[
        ("111.206.174.3:3478", mapped),
        ("111.206.174.2:3479", mapped),
    ])
}

fn test_with(ip_and_port: Probe, port: Probe) -> ChangeTest {
    ChangeTest {
        server: addr("111.206.174.3:3478"),
        other: addr("111.206.174.2:3479"),
        ip_and_port,
        port,
    }
}

fn answered(from: &str) -> Probe {
    Probe::Answered(addr(from))
}

fn eif() -> ChangeTest {
    test_with(
        answered("111.206.174.2:3479"),
        answered("111.206.174.3:3479"),
    )
}

fn seen(answers: Vec<Answer>, tests: Vec<ChangeTest>, self_test: SelfTest) -> Observations {
    Observations {
        local: addr(LOCAL),
        answers,
        change_tests: tests,
        self_test,
        gateway_ip: None,
    }
}

#[test]
fn special_ranges_are_not_public() {
    for ip in [
        "0.1.2.3",
        "10.73.0.4",
        "100.64.0.1",
        "100.64.0.42",
        "100.127.255.254",
        "127.0.0.1",
        "169.254.1.1",
        "172.16.0.1",
        "172.31.255.255",
        "192.0.0.8",
        "192.0.2.1",
        "192.88.99.1",
        "192.168.139.19",
        "198.18.0.1",
        "198.19.255.255",
        "198.51.100.7",
        "203.0.113.9",
        "224.0.0.251",
        "239.255.255.250",
        "240.0.0.1",
        "255.255.255.255",
    ] {
        assert!(!is_public(ip.parse().unwrap()), "{ip}");
    }
    for ip in [
        "1.1.1.1",
        "45.77.0.9",
        "100.63.255.255",
        "100.128.0.0",
        "172.15.255.255",
        "172.32.0.0",
        "9.9.9.9",
        "198.17.255.255",
        "198.20.0.0",
        "223.5.5.5",
    ] {
        assert!(is_public(ip.parse().unwrap()), "{ip}");
    }
}

#[test]
fn one_mapping_from_two_server_ips_is_endpoint_independent() {
    let local = addr(LOCAL);
    assert_eq!(
        detect::classify::mapping(local, &agreeing(MAPPED)),
        Mapping::EndpointIndependent
    );
    let same_ip = answers(&[("1.1.1.1:3478", MAPPED), ("1.1.1.1:3479", MAPPED)]);
    assert_eq!(detect::classify::mapping(local, &same_ip), Mapping::Unknown);
    assert_eq!(detect::classify::mapping(local, &[]), Mapping::Unknown);
}

#[test]
fn two_mappings_are_endpoint_dependent_even_from_one_ip() {
    let differing = answers(&[("1.1.1.1:3478", MAPPED), ("1.1.1.1:3479", "45.77.0.9:7137")]);
    assert_eq!(
        detect::classify::mapping(addr(LOCAL), &differing),
        Mapping::EndpointDependent
    );
}

#[test]
fn the_local_address_as_the_mapping_is_no_nat() {
    let local = "45.77.0.10:51830";
    assert_eq!(
        detect::classify::mapping(addr(local), &agreeing(local)),
        Mapping::NoNat
    );
}

#[test]
fn filtering_follows_rfc_5780() {
    use Probe::{NotRun, Silent};
    let other_port = || answered("111.206.174.3:3479");
    let cases = [
        (vec![], Filtering::Unknown),
        (vec![eif()], Filtering::EndpointIndependent),
        (
            vec![test_with(Silent, other_port())],
            Filtering::AddressDependent,
        ),
        (
            vec![test_with(Silent, Silent)],
            Filtering::AddressAndPortDependent,
        ),
        // A single-IP server: a new port gets in, so NAT1 or NAT2.
        (vec![test_with(NotRun, other_port())], Filtering::Unknown),
        (
            vec![test_with(NotRun, Silent)],
            Filtering::AddressAndPortDependent,
        ),
        (vec![test_with(Silent, NotRun)], Filtering::AddressDependent),
        (vec![test_with(NotRun, NotRun)], Filtering::Unknown),
        // An answer outweighs another server's silence.
        (
            vec![test_with(Silent, Silent), eif()],
            Filtering::EndpointIndependent,
        ),
        (
            vec![test_with(Silent, Silent), test_with(Silent, other_port())],
            Filtering::AddressDependent,
        ),
        (
            vec![test_with(Silent, Silent), test_with(NotRun, other_port())],
            Filtering::AddressDependent,
        ),
    ];
    for (tests, expected) in cases {
        assert_eq!(detect::classify::filtering(&tests), expected, "{tests:?}");
    }
}

#[test]
fn nat1_is_supported_with_kind_nat1() {
    let assessment = classify(&seen(agreeing(MAPPED), vec![eif()], SelfTest::Received));
    assert_eq!(assessment.verdict, Verdict::Supported);
    assert_eq!(assessment.kind, Some(Kind::Nat1));
    assert_eq!((assessment.reason, assessment.fix), (None, None));
}

#[test]
fn nat1_does_not_need_the_self_test() {
    let assessment = classify(&seen(agreeing(MAPPED), vec![eif()], SelfTest::NotReceived));
    assert_eq!(assessment.verdict, Verdict::Supported);
    assert_eq!(assessment.kind, Some(Kind::Nat1));
}

#[test]
fn a_host_with_its_public_address_is_supported_public() {
    let mut observed = seen(agreeing("45.77.0.10:51830"), vec![eif()], SelfTest::Skipped);
    observed.local = addr("45.77.0.10:51830");
    let assessment = classify(&observed);
    assert_eq!(assessment.verdict, Verdict::Supported);
    assert_eq!(assessment.kind, Some(Kind::Public));
    assert_eq!(assessment.mapping, Mapping::NoNat);
    // With filtering untested, a public address still counts.
    observed.change_tests.clear();
    assert_eq!(classify(&observed).kind, Some(Kind::Public));
}

#[test]
fn a_public_address_behind_a_filtering_firewall_is_unsupported() {
    let mut observed = seen(
        agreeing("45.77.0.10:51830"),
        vec![test_with(Probe::Silent, Probe::Silent)],
        SelfTest::Skipped,
    );
    observed.local = addr("45.77.0.10:51830");
    let assessment = classify(&observed);
    assert_eq!(assessment.verdict, Verdict::Unsupported);
    let reason = assessment.reason.unwrap();
    assert!(
        reason.starts_with("This network cannot host natwg: "),
        "{reason}"
    );
    assert!(reason.contains("firewall"), "{reason}");
    assert!(assessment.fix.unwrap().contains("udp/51830"));
}

#[test]
fn a_forwarded_port_on_a_public_address_is_supported_public() {
    // A router that owns 45.77.0.9 forwards udp/51830 to the host.
    let observed = seen(
        agreeing("45.77.0.9:51830"),
        vec![eif()],
        SelfTest::NotReceived,
    );
    let assessment = classify(&observed);
    assert_eq!(assessment.verdict, Verdict::Supported);
    assert_eq!(assessment.kind, Some(Kind::Public));
    // The gateway agrees on its WAN address.
    let gateway = Observations {
        gateway_ip: Some("45.77.0.9".parse().unwrap()),
        ..observed.clone()
    };
    assert_eq!(classify(&gateway).kind, Some(Kind::Public));
}

#[test]
fn a_kept_port_behind_carrier_nat_is_nat1() {
    // The gateway's WAN address is carrier NAT, which only kept the port.
    let observed = Observations {
        gateway_ip: Some("100.64.0.42".parse().unwrap()),
        ..seen(agreeing("45.77.0.9:51830"), vec![eif()], SelfTest::Received)
    };
    assert_eq!(classify(&observed).kind, Some(Kind::Nat1));
    // A kept port on a private address is no public endpoint either.
    let private = seen(agreeing("10.1.0.1:51830"), vec![eif()], SelfTest::Received);
    assert_eq!(classify(&private).kind, Some(Kind::Nat1));
}

#[test]
fn nat2_nat3_and_nat4_are_unsupported_with_a_reason_and_a_fix() {
    use Probe::Silent;
    let cases = [
        (
            seen(
                agreeing(MAPPED),
                vec![test_with(Silent, answered("111.206.174.3:3479"))],
                SelfTest::NotReceived,
            ),
            "NAT2",
        ),
        (
            seen(
                agreeing(MAPPED),
                vec![test_with(Silent, Silent)],
                SelfTest::NotReceived,
            ),
            "NAT3",
        ),
        (
            seen(
                answers(&[
                    ("111.206.174.3:3478", MAPPED),
                    ("111.206.174.2:3479", "45.77.0.9:7137"),
                ]),
                vec![eif()],
                SelfTest::Skipped,
            ),
            "NAT4",
        ),
        // Endpoint-dependent mapping wins over unknown filtering.
        (
            seen(
                answers(&[("1.1.1.1:3478", MAPPED), ("8.8.8.8:3478", "45.77.0.9:9")]),
                vec![],
                SelfTest::Skipped,
            ),
            "NAT4",
        ),
    ];
    for (observed, nat) in cases {
        let assessment = classify(&observed);
        assert_eq!(assessment.verdict, Verdict::Unsupported, "{nat}");
        assert_eq!(assessment.kind, None, "{nat}");
        let reason = assessment.reason.unwrap();
        assert!(
            reason.starts_with("This network cannot host natwg: "),
            "{reason}"
        );
        assert!(reason.contains(nat), "{reason}");
        assert!(!reason.contains('\n'), "{reason}");
        let fix = assessment.fix.unwrap();
        assert!(fix.contains("public IPv4 address"), "{fix}");
        assert!(fix.contains("NAT1"), "{fix}");
        assert!(fix.contains("forwards udp/51830"), "{fix}");
    }
}

#[test]
fn no_answer_at_all_is_udp_blocked() {
    let assessment = classify(&seen(vec![], vec![], SelfTest::Skipped));
    assert_eq!(assessment.verdict, Verdict::Unsupported);
    assert!(assessment.reason.unwrap().contains("UDP"));
}

#[test]
fn unknown_filtering_with_independent_mapping_is_likely() {
    for self_test in [SelfTest::Received, SelfTest::NotReceived] {
        let assessment = classify(&seen(agreeing(MAPPED), vec![], self_test));
        assert_eq!(assessment.verdict, Verdict::Likely, "{self_test:?}");
        assert_eq!(assessment.verdict.exit_code(), 2);
        assert!(assessment.reason.unwrap().contains("RFC 5780"));
        assert!(assessment.fix.unwrap().contains("first client"));
    }
}

#[test]
fn one_answering_server_ip_is_at_best_likely() {
    let one = answers(&[("1.1.1.1:3478", MAPPED)]);
    for tests in [vec![], vec![eif()]] {
        let assessment = classify(&seen(one.clone(), tests, SelfTest::Received));
        assert_eq!(assessment.verdict, Verdict::Likely);
        assert_eq!(assessment.mapping, Mapping::Unknown);
    }
    // Filtering alone can rule the network out.
    let filtered = seen(
        one,
        vec![test_with(Probe::Silent, Probe::Silent)],
        SelfTest::Received,
    );
    assert_eq!(classify(&filtered).verdict, Verdict::Unsupported);
}

#[test]
fn exit_codes_match_the_verdicts() {
    assert_eq!(Verdict::Supported.exit_code(), 0);
    assert_eq!(Verdict::Unsupported.exit_code(), 1);
    assert_eq!(Verdict::Likely.exit_code(), 2);
}

// --- The socket flow against fake STUN servers on loopback. ---

/// How the fake network treats the host's traffic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Nat {
    /// No NAT: the servers see the socket's own address.
    None,
    /// NAT1.
    FullCone,
    /// NAT2: answers only from IPs the host has sent to.
    Restricted,
    /// NAT3: answers only from addresses the host has sent to.
    PortRestricted,
    /// NAT4: each server sees its own port.
    Symmetric,
}

/// How the fake RFC 5780 server speaks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Dialect {
    Rfc5780,
    Rfc3489,
    /// Reports OTHER-ADDRESS, but answers every request where it was asked.
    IgnoresChange,
}

struct FakeNet {
    /// The RFC 5780 server's primary address and its other address.
    primary: SocketAddrV4,
    other: SocketAddrV4,
    /// A plain STUN server on a third IP.
    plain: SocketAddrV4,
}

const PUBLIC_MAPPING: &str = "45.77.0.9:40000";

fn mapped_for(nat: Nat, client: SocketAddrV4, server: usize) -> SocketAddrV4 {
    let public = addr(PUBLIC_MAPPING);
    match nat {
        Nat::None => client,
        Nat::Symmetric => SocketAddrV4::new(*public.ip(), public.port() + server as u16),
        _ => public,
    }
}

/// The answer to the request whose header is `header`.
fn response(
    header: &[u8],
    mapped: SocketAddrV4,
    origin: SocketAddrV4,
    other: Option<SocketAddrV4>,
    dialect: Dialect,
) -> Vec<u8> {
    let cookie = 0x2112_A442u32;
    let address = |kind: u16, address: SocketAddrV4, xor: bool| {
        let (ip, port) = if xor {
            (
                address.ip().to_bits() ^ cookie,
                address.port() ^ (cookie >> 16) as u16,
            )
        } else {
            (address.ip().to_bits(), address.port())
        };
        let mut attribute = kind.to_be_bytes().to_vec();
        attribute.extend([0, 8, 0, 1]);
        attribute.extend(port.to_be_bytes());
        attribute.extend(ip.to_be_bytes());
        attribute
    };
    let mut body = Vec::new();
    match dialect {
        Dialect::Rfc3489 => {
            body.extend(address(0x0001, mapped, false));
            body.extend(address(0x0004, origin, false));
            if let Some(other) = other {
                body.extend(address(0x0005, other, false));
            }
        }
        _ => {
            body.extend(address(0x0020, mapped, true));
            body.extend(address(0x802B, origin, false));
            if let Some(other) = other {
                body.extend(address(0x802C, other, false));
            }
        }
    }
    let mut message = vec![0x01, 0x01];
    message.extend((body.len() as u16).to_be_bytes());
    message.extend(&header[4..20]);
    message.extend(body);
    message
}

/// Where a server answers from: `here`, or with `change`, the one of
/// `primary` and `other` that is not `here`.
fn flip<T: PartialEq>(change: bool, here: T, primary: T, other: T) -> T {
    match change {
        false => here,
        true if here == primary => other,
        true => primary,
    }
}

/// The CHANGE-REQUEST flags of a request: (change IP, change port).
fn change_flags(request: &[u8]) -> (bool, bool) {
    match request.get(20..28) {
        Some([0x00, 0x03, 0x00, 0x04, _, _, _, flags]) => (flags & 4 != 0, flags & 2 != 0),
        _ => (false, false),
    }
}

fn v4(address: SocketAddr) -> SocketAddrV4 {
    match address {
        SocketAddr::V4(address) => address,
        SocketAddr::V6(address) => panic!("expected IPv4, got {address}"),
    }
}

/// Spawn the fake network: an RFC 5780 server on `ips[0]` and `ips[1]`, each
/// on two ports, and a plain server on `ips[2]`. The server sees every
/// datagram the host sends, so it knows which answers the NAT lets in.
async fn fake_net(nat: Nat, dialect: Dialect, ips: [Ipv4Addr; 3]) -> FakeNet {
    let a1 = UdpSocket::bind((ips[0], 0)).await.unwrap();
    let p1 = a1.local_addr().unwrap().port();
    let a2 = UdpSocket::bind((ips[0], 0)).await.unwrap();
    let p2 = a2.local_addr().unwrap().port();
    // With one IP, the "other IP" sockets are the same as the first ones.
    let mut sockets = vec![Arc::new(a1), Arc::new(a2)];
    if ips[1] != ips[0] {
        sockets.push(Arc::new(UdpSocket::bind((ips[1], p1)).await.unwrap()));
        sockets.push(Arc::new(UdpSocket::bind((ips[1], p2)).await.unwrap()));
    }
    let plain = Arc::new(UdpSocket::bind((ips[2], 0)).await.unwrap());
    let addresses: Vec<SocketAddrV4> = sockets
        .iter()
        .map(|socket| v4(socket.local_addr().unwrap()))
        .collect();
    let (primary, other) = (addresses[0], *addresses.last().unwrap());
    let contacted: Arc<Mutex<HashSet<SocketAddrV4>>> = Arc::default();
    for (index, socket) in sockets.iter().enumerate() {
        let (sockets, addresses, contacted) =
            (sockets.clone(), addresses.clone(), contacted.clone());
        let socket = socket.clone();
        tokio::spawn(async move {
            let mut request = [0; 1500];
            loop {
                let (len, client) = socket.recv_from(&mut request).await.unwrap();
                let client = v4(client);
                let here = addresses[index];
                contacted.lock().unwrap().insert(here);
                if len < 20 || request[..2] != [0x00, 0x01] {
                    continue;
                }
                let (change_ip, change_port) = match dialect {
                    Dialect::IgnoresChange => (false, false),
                    _ => change_flags(&request[..len]),
                };
                let ip = flip(change_ip, *here.ip(), *primary.ip(), *other.ip());
                let port = flip(change_port, here.port(), primary.port(), other.port());
                let from = SocketAddrV4::new(ip, port);
                let Some(sender) = addresses.iter().position(|address| *address == from) else {
                    continue;
                };
                let lets_in = {
                    let seen = contacted.lock().unwrap();
                    match nat {
                        Nat::None | Nat::FullCone | Nat::Symmetric => true,
                        Nat::Restricted => seen.iter().any(|to| to.ip() == from.ip()),
                        Nat::PortRestricted => seen.contains(&from),
                    }
                };
                if !lets_in {
                    continue;
                }
                let mapped = mapped_for(nat, client, index);
                let answer = response(&request[..20], mapped, from, Some(other), dialect);
                sockets[sender].send_to(&answer, client).await.unwrap();
            }
        });
    }
    let plain_address = v4(plain.local_addr().unwrap());
    tokio::spawn(async move {
        let mut request = [0; 1500];
        loop {
            let (len, client) = plain.recv_from(&mut request).await.unwrap();
            if len < 20 || request[..2] != [0x00, 0x01] {
                continue;
            }
            let mapped = mapped_for(nat, v4(client), 9);
            let answer = response(
                &request[..20],
                mapped,
                plain_address,
                None,
                Dialect::Rfc5780,
            );
            plain.send_to(&answer, client).await.unwrap();
        }
    });
    FakeNet {
        primary,
        other,
        plain: plain_address,
    }
}

fn request(servers: &[SocketAddrV4]) -> Request {
    Request {
        iface: Some(LOOPBACK.to_owned()),
        port: Some(0),
        servers: servers
            .iter()
            .map(|server| (server.ip().to_string(), server.port()))
            .collect(),
        upnp: UpnpMode::Off,
        timeout: Duration::from_millis(150),
        ..Request::default()
    }
}

async fn detect_on(net: &FakeNet) -> detect::Detection {
    detect::run(&request(&[net.primary, net.plain]))
        .await
        .unwrap()
}

#[cfg(target_os = "linux")]
const IPS: [Ipv4Addr; 3] = [
    Ipv4Addr::new(127, 0, 0, 1),
    Ipv4Addr::new(127, 0, 0, 2),
    Ipv4Addr::new(127, 0, 0, 3),
];

#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_full_cone_nat_is_supported_nat1() {
    let net = fake_net(Nat::FullCone, Dialect::Rfc5780, IPS).await;
    let detection = detect_on(&net).await;
    assert_eq!(
        detection.verdict,
        Verdict::Supported,
        "{}",
        detection.render()
    );
    assert_eq!(detection.kind, Some(Kind::Nat1));
    assert_eq!(detection.summary, "supported (NAT1)");
    assert_eq!(detection.exit_code(), 0);
    assert_eq!(detection.mapping.endpoint, Some(addr(PUBLIC_MAPPING)));
    let test = detection.filtering.tests[0];
    assert_eq!(test.ip_and_port, Probe::Answered(net.other));
    assert_eq!(
        test.port,
        Probe::Answered(SocketAddrV4::new(*net.primary.ip(), net.other.port()))
    );
    // The mapping test asked the other IP at the first port, and the plain
    // server.
    let servers: Vec<SocketAddrV4> = detection.mapping.answers.iter().map(|a| a.server).collect();
    let other_ip = SocketAddrV4::new(*net.other.ip(), net.primary.port());
    assert_eq!(servers, [net.primary, other_ip, net.plain]);
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn an_rfc_3489_server_runs_the_same_tests() {
    let net = fake_net(Nat::FullCone, Dialect::Rfc3489, IPS).await;
    let detection = detect_on(&net).await;
    assert_eq!(
        detection.summary,
        "supported (NAT1)",
        "{}",
        detection.render()
    );
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn restricted_and_port_restricted_nats_are_unsupported() {
    for (nat, filtering) in [
        (Nat::Restricted, Filtering::AddressDependent),
        (Nat::PortRestricted, Filtering::AddressAndPortDependent),
    ] {
        let net = fake_net(nat, Dialect::Rfc5780, IPS).await;
        let detection = detect_on(&net).await;
        assert_eq!(
            detection.verdict,
            Verdict::Unsupported,
            "{nat:?}: {}",
            detection.render()
        );
        assert_eq!(detection.filtering.behaviour, filtering, "{nat:?}");
        assert_eq!(
            detection.mapping.behaviour,
            Mapping::EndpointIndependent,
            "{nat:?}"
        );
        assert_eq!(detection.exit_code(), 1);
    }
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_symmetric_nat_is_unsupported() {
    let net = fake_net(Nat::Symmetric, Dialect::Rfc5780, IPS).await;
    let detection = detect_on(&net).await;
    assert_eq!(
        detection.mapping.behaviour,
        Mapping::EndpointDependent,
        "{}",
        detection.render()
    );
    assert_eq!(detection.verdict, Verdict::Unsupported);
    assert!(detection.reason.unwrap().contains("NAT4"));
    assert_eq!(detection.mapping.endpoint, None);
    assert_eq!(detection.self_test, SelfTest::Skipped);
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn no_nat_is_supported_public() {
    let net = fake_net(Nat::None, Dialect::Rfc5780, IPS).await;
    let detection = detect_on(&net).await;
    // lo's address is not public, but the mapping is the socket itself.
    assert_eq!(
        detection.mapping.behaviour,
        Mapping::NoNat,
        "{}",
        detection.render()
    );
    assert_eq!(detection.summary, "supported (public)");
    assert_eq!(detection.self_test, SelfTest::Skipped);
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_server_that_ignores_change_requests_leaves_filtering_unknown() {
    let net = fake_net(Nat::FullCone, Dialect::IgnoresChange, IPS).await;
    let detection = detect_on(&net).await;
    assert!(
        detection.filtering.tests.is_empty(),
        "{}",
        detection.render()
    );
    assert_eq!(detection.filtering.behaviour, Filtering::Unknown);
    assert_eq!(detection.verdict, Verdict::Likely);
    assert_eq!(detection.exit_code(), 2);
    assert!(
        detection
            .notes
            .iter()
            .any(|note| note.contains("ignores CHANGE-REQUEST"))
    );
}

#[tokio::test]
async fn a_single_ip_server_tests_only_the_port() {
    let one = [Ipv4Addr::LOCALHOST; 3];
    let full = fake_net(Nat::FullCone, Dialect::Rfc5780, one).await;
    let detection = detect_on(&full).await;
    let test = detection.filtering.tests[0];
    assert_eq!(test.other, full.other, "{}", detection.render());
    assert_eq!(test.ip_and_port, Probe::NotRun);
    assert_eq!(test.port, Probe::Answered(full.other));
    assert_eq!(detection.filtering.behaviour, Filtering::Unknown);
    assert_eq!(detection.verdict, Verdict::Likely);
}

#[tokio::test]
async fn every_nat_against_single_ip_servers() {
    // Loopback on macOS has one address, so these run everywhere.
    let one = [Ipv4Addr::LOCALHOST; 3];
    for (nat, dialect, summary) in [
        (Nat::None, Dialect::Rfc5780, "supported (public)"),
        (Nat::FullCone, Dialect::Rfc3489, "likely"),
        (Nat::FullCone, Dialect::IgnoresChange, "likely"),
        (Nat::Restricted, Dialect::Rfc5780, "likely"),
        (Nat::PortRestricted, Dialect::Rfc5780, "unsupported"),
        (Nat::Symmetric, Dialect::Rfc5780, "unsupported"),
    ] {
        let net = fake_net(nat, dialect, one).await;
        let detection = detect_on(&net).await;
        assert_eq!(
            detection.summary,
            summary,
            "{nat:?} {dialect:?}: {}",
            detection.render()
        );
    }
}

#[tokio::test]
async fn no_answer_is_unsupported_and_says_udp_is_blocked() {
    let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let detection = detect::run(&request(&[v4(silent.local_addr().unwrap())]))
        .await
        .unwrap();
    assert_eq!(detection.verdict, Verdict::Unsupported);
    assert_eq!(detection.mapping.answers, []);
    assert!(
        detection
            .render()
            .contains("This network cannot host natwg: no STUN server answered")
    );
}

#[tokio::test]
async fn a_held_port_gives_way_to_a_free_one() {
    let held = natwg::wire::transport::bound_udp_socket(
        &natwg::wire::transport::BoundInterface::lookup(LOOPBACK).unwrap(),
        0,
    )
    .unwrap();
    let port = held.local_addr().unwrap().port();
    let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut asked = request(&[v4(silent.local_addr().unwrap())]);
    asked.port = Some(port);
    let detection = detect::run(&asked).await.unwrap();
    assert!(detection.port.held);
    assert_eq!(detection.port.wanted, port);
    assert_ne!(detection.port.tested, port);
    assert!(
        detection
            .render()
            .contains(&format!("udp/{port} is in use"))
    );
}

#[tokio::test]
async fn the_json_names_every_part_init_reads() {
    let net = fake_net(Nat::FullCone, Dialect::Rfc5780, [Ipv4Addr::LOCALHOST; 3]).await;
    let detection = detect_on(&net).await;
    let json = serde_json::to_value(&detection).unwrap();
    for key in [
        "verdict",
        "kind",
        "summary",
        "reason",
        "fix",
        "uplink",
        "port",
        "upnp",
        "mapping",
        "filtering",
        "self_test",
        "notes",
    ] {
        assert!(json.get(key).is_some(), "{key} missing from {json}");
    }
    assert_eq!(json["verdict"], "likely");
    assert_eq!(json["upnp"]["state"], "off");
    assert_eq!(json["upnp"]["mode"], "off");
    assert_eq!(json["uplink"]["iface"], LOOPBACK);
    assert_eq!(json["uplink"]["public"], false);
    assert_eq!(json["mapping"]["endpoint"], PUBLIC_MAPPING);
    assert_eq!(json["filtering"]["tests"][0]["ip_and_port"], "not_run");
}
