use gotatun::packet::PacketBufPool;
use gotatun::udp::{UdpRecv, UdpSend, UdpTransportFactory, UdpTransportFactoryParams};
use natwg::wire::dns::{self, Record, RecordKind};
use natwg::wire::stun::{
    TransactionId, binding_request, is_stun_binding_success, parse_binding_success,
};
use natwg::wire::transport::{BoundInterface, BoundUdp, StunPort};
use std::{
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    time::Duration,
};
use tokio::net::UdpSocket;

#[cfg(target_os = "macos")]
const LOOPBACK: &str = "lo0";
#[cfg(target_os = "linux")]
const LOOPBACK: &str = "lo";

const COOKIE: [u8; 4] = [0x21, 0x12, 0xA4, 0x42];
const MAPPED_ADDRESS: u16 = 0x0001;
const XOR_MAPPED_ADDRESS: u16 = 0x0020;

// Responses from 223.5.5.5 to queries with id 0x4e57, captured through en6 on
// 2026-11-24 with natwg's own query encoder.
const A_STUN_MIWIFI: &str = "4e5781800001000200000000047374756e066d697769666903636f6d0000010001c00c000100010000010000046fceae03c00c000100010000010000046fceae02";
const A_WWW_BAIDU: &str = "4e57818000010003000000000377777705626169647503636f6d0000010001c00c000500010000011700120377777701610673686966656e03636f6d00c02b000100010000001a000424982c84c02b000100010000001a000424982c5d";
const TXT_YAHOO_DKIM: &str = "4e57818000010001000000000573323034380a5f646f6d61696e6b6579057961686f6f03636f6d0000100001c00c0010000100000e1001967a6b3d7273613b20703d4d494942496a414e42676b71686b6947397730424151454641414f43415138414d49494243674b4341514541756f5775666762577735384d637a5547624d76313736526178645a474f4d6b516d6e384f4f4a2f48476f513664616c534d57694c616a38494d634843316375624a7832677a7f694150514856507446596179794c413461794a55534e6b31302f75716642796955387169504345344a5346727078666c684d494b563462742b673175487737774c7a677543663459416f52365878554b5273416f48756f46374d2b7636624d5a2f5831472b766957486b426c345566674a51364f384631636b4b4b6f5a354b7f71556b4a4835704461716267732b46335070796941555166423645457a4f41314b4d5052574a47707a6750744b6f756b446351754b5577394741756c376b5349794563697a71726261554b4e4c47416d7a30656c6b71526e7a497356707a366a6454312f59563552693659554f5135734e3562714e7a5a3854786f516c6b621a56527936654b4f6a556e6f5353546d534168774944415141423b";
const NXDOMAIN_INVALID: &str = "4e5781830001000000010000056e6174776707696e76616c69640000010001c01a0006000100000258004001610c726f6f742d73657276657273036e657400056e73746c640c766572697369676e2d67727303636f6d0078c4052e000007080000038400093a8000015180";
const CAPTURE_ID: u16 = 0x4e57;

fn hex(text: &str) -> Vec<u8> {
    let digits: Vec<u8> = text.bytes().filter(u8::is_ascii_hexdigit).collect();
    digits
        .chunks(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn stun_response(id: [u8; 12], attributes: &[(u16, Vec<u8>)]) -> Vec<u8> {
    let mut body = Vec::new();
    for (kind, value) in attributes {
        body.extend(kind.to_be_bytes());
        body.extend((value.len() as u16).to_be_bytes());
        body.extend(value);
        body.resize(body.len().next_multiple_of(4), 0);
    }
    let mut message = vec![0x01, 0x01];
    message.extend((body.len() as u16).to_be_bytes());
    message.extend(COOKIE);
    message.extend(id);
    message.extend(body);
    message
}

fn mapped(address: SocketAddrV4) -> Vec<u8> {
    let mut value = vec![0, 1];
    value.extend(address.port().to_be_bytes());
    value.extend(address.ip().octets());
    value
}

fn xor_mapped(address: SocketAddrV4) -> Vec<u8> {
    let cookie = u32::from_be_bytes(COOKIE);
    mapped(SocketAddrV4::new(
        Ipv4Addr::from_bits(address.ip().to_bits() ^ cookie),
        address.port() ^ (cookie >> 16) as u16,
    ))
}

fn addr(text: &str) -> SocketAddrV4 {
    text.parse().unwrap()
}

#[test]
fn the_rfc_5769_ipv4_response_yields_its_mapping() {
    let vector = hex("0101003c 2112a442 b7e7a701 bc34d686 fa87dfae
         8022000b 74657374 20766563 746f7220
         00200008 0001a147 e112a643
         00080014 2b91f599 fd9e90c3 8c7489f9 2af9ba53 f06be7d7
         80280004 c07d4c96");
    let id = TransactionId(hex("b7e7a701bc34d686fa87dfae").try_into().unwrap());
    assert!(is_stun_binding_success(&vector));
    assert_eq!(
        parse_binding_success(&vector),
        Some((id, addr("192.0.2.1:32853")))
    );
}

#[test]
fn a_plain_mapped_address_is_read_without_xor() {
    let id = [7; 12];
    let response = stun_response(id, &[(MAPPED_ADDRESS, mapped(addr("203.0.113.9:7007")))]);
    assert_eq!(
        parse_binding_success(&response),
        Some((TransactionId(id), addr("203.0.113.9:7007")))
    );
}

#[test]
fn xor_mapped_address_wins_over_a_mapped_address_before_it() {
    let response = stun_response(
        [1; 12],
        &[
            (MAPPED_ADDRESS, mapped(addr("198.51.100.1:1111"))),
            (XOR_MAPPED_ADDRESS, xor_mapped(addr("203.0.113.9:7007"))),
        ],
    );
    assert_eq!(
        parse_binding_success(&response).map(|(_, mapping)| mapping),
        Some(addr("203.0.113.9:7007"))
    );
}

#[test]
fn unknown_attributes_are_skipped_with_their_padding() {
    let response = stun_response(
        [2; 12],
        &[
            (0x8022, b"natwg".to_vec()),
            (0x0004, vec![0xFF; 3]),
            (XOR_MAPPED_ADDRESS, xor_mapped(addr("203.0.113.9:7007"))),
        ],
    );
    assert_eq!(
        parse_binding_success(&response).map(|(_, mapping)| mapping),
        Some(addr("203.0.113.9:7007"))
    );
}

#[test]
fn a_wrong_magic_cookie_is_not_a_stun_response() {
    let mut response = stun_response(
        [3; 12],
        &[(XOR_MAPPED_ADDRESS, xor_mapped(addr("203.0.113.9:7007")))],
    );
    response[4] ^= 0xFF;
    assert!(!is_stun_binding_success(&response));
    assert_eq!(parse_binding_success(&response), None);
}

#[test]
fn an_attribute_longer_than_the_message_rejects_the_response() {
    let mut response = stun_response(
        [4; 12],
        &[(XOR_MAPPED_ADDRESS, xor_mapped(addr("203.0.113.9:7007")))],
    );
    response[22..24].copy_from_slice(&12u16.to_be_bytes());
    assert_eq!(parse_binding_success(&response), None);
}

#[test]
fn a_message_shorter_than_its_length_field_is_rejected() {
    let response = stun_response(
        [5; 12],
        &[(XOR_MAPPED_ADDRESS, xor_mapped(addr("203.0.113.9:7007")))],
    );
    assert_eq!(parse_binding_success(&response[..response.len() - 1]), None);
}

#[test]
fn a_response_without_an_ipv4_mapping_yields_nothing() {
    let mut ipv6 = vec![0, 2, 0x1B, 0x5F];
    ipv6.extend([0; 16]);
    let response = stun_response([6; 12], &[(XOR_MAPPED_ADDRESS, ipv6)]);
    assert!(is_stun_binding_success(&response));
    assert_eq!(parse_binding_success(&response), None);
}

#[test]
fn a_binding_request_is_a_bare_header_with_the_id() {
    let id = TransactionId(*b"natwg-txid-1");
    let mut expected = vec![0x00, 0x01, 0x00, 0x00];
    expected.extend(COOKIE);
    expected.extend(b"natwg-txid-1");
    assert_eq!(binding_request(id).to_vec(), expected);
    assert!(!is_stun_binding_success(&binding_request(id)));
}

#[test]
fn no_wireguard_message_passes_the_stun_demux() {
    for (kind, len) in [(1, 148), (2, 92), (3, 64), (4, 32)] {
        let mut message = vec![0; len];
        message[0] = kind;
        message[4..8].copy_from_slice(&COOKIE);
        assert!(!is_stun_binding_success(&message), "WireGuard type {kind}");
    }
}

fn loopback() -> BoundInterface {
    BoundInterface::lookup(LOOPBACK).unwrap()
}

fn params(port: u16) -> UdpTransportFactoryParams {
    UdpTransportFactoryParams {
        addr: None,
        port,
        #[cfg(target_os = "linux")]
        fwmark: None,
    }
}

fn v4(address: SocketAddr) -> SocketAddrV4 {
    match address {
        SocketAddr::V4(address) => address,
        SocketAddr::V6(address) => panic!("expected IPv4, got {address}"),
    }
}

async fn fake_stun_server() -> (UdpSocket, SocketAddrV4) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = v4(socket.local_addr().unwrap());
    (socket, address)
}

async fn next_request(server: &UdpSocket) -> ([u8; 12], SocketAddr) {
    let mut request = [0; 64];
    let (len, client) = server.recv_from(&mut request).await.unwrap();
    assert_eq!(len, 20, "a Binding request is a bare header");
    (request[8..20].try_into().unwrap(), client)
}

fn answer(id: [u8; 12], mapping: &str) -> Vec<u8> {
    stun_response(id, &[(XOR_MAPPED_ADDRESS, xor_mapped(addr(mapping)))])
}

fn wireguard(kind: u8, len: usize) -> Vec<u8> {
    let mut message = vec![0x5A; len];
    message[..4].copy_from_slice(&[kind, 0, 0, 0]);
    message
}

#[test]
fn an_unknown_interface_is_iface_not_found() {
    for name in ["natwg-none0", "en\0"] {
        assert_eq!(
            BoundInterface::lookup(name).unwrap_err().code,
            "IFACE_NOT_FOUND"
        );
    }
}

#[tokio::test]
async fn the_shared_socket_gives_stun_answers_to_the_stun_port_and_the_rest_to_gotatun() {
    let (mut udp, mut stun) = BoundUdp::new(loopback());
    let (_send, mut recv) = udp.bind(&params(0)).await.unwrap();
    let (server, server_address) = fake_stun_server().await;
    let others = vec![
        wireguard(1, 148),
        wireguard(2, 92),
        wireguard(3, 64),
        wireguard(4, 32),
        b"not stun".to_vec(),
    ];
    let serve = async {
        let (id, client) = next_request(&server).await;
        let stale = answer([9; 12], "198.51.100.1:1111");
        let right = answer(id, "203.0.113.9:7007");
        for datagram in [
            &others[0], &stale, &others[1], &others[2], &right, &others[3], &others[4],
        ] {
            server.send_to(datagram, client).await.unwrap();
        }
    };
    let gotatun = async {
        let mut pool = PacketBufPool::new(4);
        let mut seen = Vec::new();
        for _ in 0..others.len() {
            seen.push(recv.recv_from(&mut pool).await.unwrap().0.to_vec());
        }
        seen
    };
    let (mapping, (), seen) = tokio::join!(
        stun.binding(server_address, Duration::from_secs(2)),
        serve,
        gotatun
    );
    assert_eq!(mapping.unwrap(), addr("203.0.113.9:7007"));
    assert_eq!(seen, others);
}

#[tokio::test]
async fn binding_ignores_a_stale_answer_and_times_out() {
    let mut stun = StunPort::bind(loopback(), 0).await.unwrap();
    let (server, server_address) = fake_stun_server().await;
    let serve = async {
        let (_, client) = next_request(&server).await;
        let stale = answer([9; 12], "198.51.100.1:1111");
        server.send_to(&stale, client).await.unwrap();
    };
    let (mapping, ()) = tokio::join!(
        stun.binding(server_address, Duration::from_millis(300)),
        serve
    );
    assert_eq!(mapping.unwrap_err().code, "STUN_TIMEOUT");
}

#[tokio::test]
async fn gotatun_can_rebind_the_same_port_while_stun_waits() {
    let (mut udp, mut stun) = BoundUdp::new(loopback());
    let (server, server_address) = fake_stun_server().await;
    let unbound = stun.binding(server_address, Duration::from_millis(100));
    assert_eq!(unbound.await.unwrap_err().code, "STUN_NO_SOCKET");

    let (send, recv) = udp.bind(&params(0)).await.unwrap();
    let port = send.local_addr().unwrap().unwrap().port();
    let rebind = async {
        next_request(&server).await;
        drop((send, recv));
        udp.bind(&params(port)).await
    };
    let (unanswered, rebound) = tokio::join!(
        stun.binding(server_address, Duration::from_millis(300)),
        rebind
    );
    assert_eq!(unanswered.unwrap_err().code, "STUN_TIMEOUT");
    let (send, mut recv) = rebound.expect("the old socket released its port");
    assert_eq!(send.local_addr().unwrap().unwrap().port(), port);

    let serve = async {
        let (id, client) = next_request(&server).await;
        assert_eq!(client.port(), port);
        server
            .send_to(&answer(id, "203.0.113.9:7007"), client)
            .await
            .unwrap();
        server.send_to(&wireguard(4, 32), client).await.unwrap();
    };
    let gotatun = async { recv.recv_from(&mut PacketBufPool::new(1)).await.unwrap() };
    let (mapping, (), _) = tokio::join!(
        stun.binding(server_address, Duration::from_secs(2)),
        serve,
        gotatun
    );
    assert_eq!(mapping.unwrap(), addr("203.0.113.9:7007"));
}

fn a(text: &str) -> Record {
    Record::A(text.parse().unwrap())
}

#[test]
fn compressed_a_answers_parse() {
    assert_eq!(
        dns::parse_response(&hex(A_STUN_MIWIFI), CAPTURE_ID).unwrap(),
        [a("111.206.174.3"), a("111.206.174.2")]
    );
}

#[test]
fn a_cname_before_the_a_answers_is_skipped() {
    assert_eq!(
        dns::parse_response(&hex(A_WWW_BAIDU), CAPTURE_ID).unwrap(),
        [a("36.152.44.132"), a("36.152.44.93")]
    );
}

#[test]
fn txt_character_strings_join_into_one_value() {
    let records = dns::parse_response(&hex(TXT_YAHOO_DKIM), CAPTURE_ID).unwrap();
    let [Record::Txt(text)] = records.as_slice() else {
        panic!("expected one TXT record, got {records:?}");
    };
    let key = text
        .strip_prefix("k=rsa; p=")
        .and_then(|rest| rest.strip_suffix(';'))
        .unwrap();
    let der = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, key).unwrap();
    assert_eq!(der.len(), 294, "a 2048-bit RSA public key");
}

#[test]
fn nxdomain_is_an_error() {
    let error = dns::parse_response(&hex(NXDOMAIN_INVALID), CAPTURE_ID).unwrap_err();
    assert_eq!(error.code, "DNS_NXDOMAIN");
}

#[test]
fn other_error_rcodes_are_errors() {
    let mut response = hex(NXDOMAIN_INVALID);
    response[3] = 0x82;
    let error = dns::parse_response(&response, CAPTURE_ID).unwrap_err();
    assert_eq!(error.code, "DNS_RCODE");
}

#[test]
fn a_response_to_another_query_id_is_rejected() {
    let error = dns::parse_response(&hex(A_STUN_MIWIFI), CAPTURE_ID + 1).unwrap_err();
    assert_eq!(error.code, "DNS_ID_MISMATCH");
}

#[test]
fn a_truncated_response_is_malformed() {
    let response = hex(A_STUN_MIWIFI);
    for len in [5, 40, response.len() - 1] {
        let error = dns::parse_response(&response[..len], CAPTURE_ID).unwrap_err();
        assert_eq!(error.code, "DNS_MALFORMED", "cut to {len} bytes");
    }
}

#[test]
fn queries_carry_the_question_the_server_echoed() {
    for (name, kind, response) in [
        ("stun.miwifi.com", RecordKind::A, A_STUN_MIWIFI),
        (
            "s2048._domainkey.yahoo.com.",
            RecordKind::Txt,
            TXT_YAHOO_DKIM,
        ),
    ] {
        let query = dns::query(CAPTURE_ID, name, kind).unwrap();
        let mut header = CAPTURE_ID.to_be_bytes().to_vec();
        header.extend([0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
        assert_eq!(query[..12], header, "{name}");
        assert_eq!(query[12..], hex(response)[12..query.len()], "{name}");
    }
}

#[test]
fn names_dns_cannot_carry_are_rejected() {
    let long_label = format!("{}.com", "a".repeat(64));
    let long_name = ["a".repeat(63).as_str(); 4].join(".");
    for name in ["", ".", "a..b", &long_label, &long_name] {
        let error = dns::query(1, name, RecordKind::A).unwrap_err();
        assert_eq!(error.code, "DNS_NAME_INVALID", "{name:?}");
    }
}

#[test]
fn xor_mapped_address_wins_when_it_follows_mapped_and_unknown_attributes() {
    let id = [3; 12];
    let message = stun_response(
        id,
        &[
            (MAPPED_ADDRESS, mapped(addr("192.0.2.10:1111"))),
            (0x802b, vec![0; 8]),
            (0x802c, vec![0; 8]),
            (XOR_MAPPED_ADDRESS, xor_mapped(addr("198.51.100.7:4242"))),
        ],
    );
    assert_eq!(
        parse_binding_success(&message),
        Some((TransactionId(id), addr("198.51.100.7:4242")))
    );
}

#[test]
fn a_truncated_dns_response_is_an_error() {
    let mut response = hex(A_STUN_MIWIFI);
    response[2] |= 0x02;
    assert_eq!(
        dns::parse_response(&response, CAPTURE_ID).unwrap_err().code,
        "DNS_TRUNCATED"
    );
}

fn with_id(mut response: Vec<u8>, id: [u8; 2]) -> Vec<u8> {
    response[..2].copy_from_slice(&id);
    response
}

async fn dns_server(reply: impl FnOnce([u8; 2]) -> Vec<Vec<u8>> + Send + 'static) -> SocketAddrV4 {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = v4(socket.local_addr().unwrap());
    tokio::spawn(async move {
        let mut query = [0; 512];
        let (_, client) = socket.recv_from(&mut query).await.unwrap();
        for datagram in reply([query[0], query[1]]) {
            socket.send_to(&datagram, client).await.unwrap();
        }
    });
    address
}

async fn resolve_miwifi(server: SocketAddrV4) -> natwg::Result<Vec<Record>> {
    dns::resolve(
        &loopback(),
        server,
        "stun.miwifi.com",
        RecordKind::A,
        Duration::from_secs(2),
    )
    .await
}

#[tokio::test]
async fn resolve_skips_datagrams_shorter_than_a_dns_header() {
    let server = dns_server(|id| vec![vec![0xff, 0xff], with_id(hex(A_STUN_MIWIFI), id)]).await;
    assert_eq!(
        resolve_miwifi(server).await.unwrap(),
        vec![
            Record::A("111.206.174.3".parse().unwrap()),
            Record::A("111.206.174.2".parse().unwrap()),
        ]
    );
}

#[tokio::test]
async fn resolve_without_a_matching_record_names_the_server_and_the_name() {
    let server = dns_server(|id| {
        let mut response = with_id(hex(A_STUN_MIWIFI), id);
        response[7] = 0;
        response.truncate(33);
        vec![response]
    })
    .await;
    let error = resolve_miwifi(server).await.unwrap_err();
    assert_eq!(error.code, "DNS_NO_ANSWER");
    assert!(
        error.message.contains("stun.miwifi.com"),
        "{}",
        error.message
    );
    assert!(
        error.message.contains(&server.to_string()),
        "{}",
        error.message
    );
}

#[tokio::test]
async fn resolve_errors_name_the_server_and_the_name() {
    let server = dns_server(|id| {
        let mut response = with_id(hex(A_STUN_MIWIFI), id);
        response[3] = (response[3] & 0xF0) | 3;
        vec![response]
    })
    .await;
    let error = resolve_miwifi(server).await.unwrap_err();
    assert_eq!(error.code, "DNS_NXDOMAIN");
    assert!(
        error.message.contains("stun.miwifi.com"),
        "{}",
        error.message
    );
    assert!(
        error.message.contains(&server.to_string()),
        "{}",
        error.message
    );
}

#[tokio::test]
async fn a_rebind_waits_for_the_previous_socket_to_free_the_port() {
    let holder = natwg::wire::transport::bound_udp_socket(&loopback(), 0).unwrap();
    let port = holder.local_addr().unwrap().port();
    let release = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(30)).await;
        drop(holder);
    });
    let (mut udp, _stun) = BoundUdp::new(loopback());
    let bound = udp.bind(&params(port)).await;
    release.await.unwrap();
    assert!(bound.is_ok(), "{:?}", bound.err());
}
