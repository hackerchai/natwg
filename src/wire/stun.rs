//! STUN Binding requests and responses (RFC 5389), IPv4 only, enough to learn
//! the public mapping of a UDP socket.

use std::net::{Ipv4Addr, SocketAddrV4};

const HEADER_LEN: usize = 20;
const BINDING_REQUEST: [u8; 2] = [0x00, 0x01];
const BINDING_SUCCESS: [u8; 2] = [0x01, 0x01];
const MAGIC_COOKIE: u32 = 0x2112_A442;
const MAPPED_ADDRESS: u16 = 0x0001;
const XOR_MAPPED_ADDRESS: u16 = 0x0020;
const FAMILY_IPV4: u8 = 0x01;

/// The STUN servers natwg asks when none are configured: the same list the
/// Python relay shipped with.
pub const DEFAULT_SERVERS: [(&str, u16); 4] = [
    ("stun.miwifi.com", 3478),
    ("stun.chat.bilibili.com", 3478),
    ("stun.hitv.com", 3478),
    ("stun.cloudflare.com", 3478),
];

/// STUN server addresses tried after [`DEFAULT_SERVERS`], for when DNS fails.
pub const DEFAULT_FALLBACKS: [SocketAddrV4; 2] = [
    SocketAddrV4::new(Ipv4Addr::new(111, 206, 174, 3), 3478),
    SocketAddrV4::new(Ipv4Addr::new(111, 206, 174, 2), 3478),
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransactionId(pub [u8; 12]);

pub fn binding_request(id: TransactionId) -> [u8; HEADER_LEN] {
    let mut message = [0; HEADER_LEN];
    message[..2].copy_from_slice(&BINDING_REQUEST);
    message[4..8].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
    message[8..].copy_from_slice(&id.0);
    message
}

pub fn is_stun_binding_success(bytes: &[u8]) -> bool {
    // A WireGuard message starts with its type, 1 to 4, and three zero bytes,
    // so it never starts with 01 01.
    bytes.len() >= HEADER_LEN
        && bytes[..2] == BINDING_SUCCESS
        && bytes[4..8] == MAGIC_COOKIE.to_be_bytes()
}

/// The transaction id and the public IPv4 mapping in a Binding success response.
/// XOR-MAPPED-ADDRESS wins over MAPPED-ADDRESS, and other attributes are skipped.
pub fn parse_binding_success(bytes: &[u8]) -> Option<(TransactionId, SocketAddrV4)> {
    if !is_stun_binding_success(bytes) {
        return None;
    }
    let id = TransactionId(bytes[8..HEADER_LEN].try_into().ok()?);
    let len = usize::from(u16::from_be_bytes([bytes[2], bytes[3]]));
    let mut attributes = bytes.get(HEADER_LEN..HEADER_LEN + len)?;
    let (mut xor_mapped, mut mapped) = (None, None);
    while let [t0, t1, l0, l1, rest @ ..] = attributes {
        let len = usize::from(u16::from_be_bytes([*l0, *l1]));
        let value = rest.get(..len)?;
        match u16::from_be_bytes([*t0, *t1]) {
            XOR_MAPPED_ADDRESS => xor_mapped = xor_mapped.or(ipv4(value).map(unxor)),
            MAPPED_ADDRESS => mapped = mapped.or(ipv4(value)),
            _ => {}
        }
        attributes = rest.get(len.next_multiple_of(4)..).unwrap_or_default();
    }
    Some((id, xor_mapped.or(mapped)?))
}

fn ipv4(value: &[u8]) -> Option<SocketAddrV4> {
    match *value {
        [_, FAMILY_IPV4, p0, p1, a, b, c, d] => Some(SocketAddrV4::new(
            Ipv4Addr::new(a, b, c, d),
            u16::from_be_bytes([p0, p1]),
        )),
        _ => None,
    }
}

fn unxor(address: SocketAddrV4) -> SocketAddrV4 {
    SocketAddrV4::new(
        Ipv4Addr::from_bits(address.ip().to_bits() ^ MAGIC_COOKIE),
        address.port() ^ (MAGIC_COOKIE >> 16) as u16,
    )
}
