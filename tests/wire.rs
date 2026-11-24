use natwg::wire::stun::{
    TransactionId, binding_request, is_stun_binding_success, parse_binding_success,
};
use std::net::{Ipv4Addr, SocketAddrV4};

const COOKIE: [u8; 4] = [0x21, 0x12, 0xA4, 0x42];
const MAPPED_ADDRESS: u16 = 0x0001;
const XOR_MAPPED_ADDRESS: u16 = 0x0020;

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
