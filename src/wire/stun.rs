//! STUN Binding requests and responses (RFC 5389), IPv4 only, enough to learn
//! the public mapping of a UDP socket, and the NAT behaviour tests of RFC 5780
//! (CHANGE-REQUEST, OTHER-ADDRESS, RESPONSE-ORIGIN) with their RFC 3489
//! forms (CHANGED-ADDRESS, SOURCE-ADDRESS).

use std::net::{Ipv4Addr, SocketAddrV4};

const HEADER_LEN: usize = 20;
const BINDING_REQUEST: [u8; 2] = [0x00, 0x01];
const BINDING_SUCCESS: [u8; 2] = [0x01, 0x01];
const MAGIC_COOKIE: u32 = 0x2112_A442;
const MAPPED_ADDRESS: u16 = 0x0001;
const CHANGE_REQUEST: u16 = 0x0003;
const SOURCE_ADDRESS: u16 = 0x0004;
const CHANGED_ADDRESS: u16 = 0x0005;
const XOR_MAPPED_ADDRESS: u16 = 0x0020;
const RESPONSE_ORIGIN: u16 = 0x802B;
const OTHER_ADDRESS: u16 = 0x802C;
const FAMILY_IPV4: u8 = 0x01;
const CHANGE_IP: u32 = 0x04;
const CHANGE_PORT: u32 = 0x02;

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

/// STUN servers that run the NAT behaviour tests of RFC 5780: each reports
/// an OTHER-ADDRESS on another IP and port, and answers a CHANGE-REQUEST from
/// it. Each answered both change tests through en6 of a China Mobile line in
/// Shanghai on 2026-11-25. `natwg detect` asks them in order; Xiaomi's
/// stun.miwifi.com answers within 40 ms there, the others within 200 ms.
pub const RFC5780_SERVERS: [(&str, u16); 6] = [
    ("stun.miwifi.com", 3478),
    ("stun.easybell.de", 3478),
    ("stun.voipia.net", 3478),
    ("stun.m-online.net", 3478),
    ("stun.vozelia.com", 3478),
    ("stun.voipbuster.com", 3478),
];

/// A STUN server as `host:port`, the form the config and the command line use.
pub fn host_port(text: &str) -> Result<(String, u16), String> {
    let (host, port) = text.rsplit_once(':').ok_or("expected HOST:PORT")?;
    let port = port
        .parse()
        .map_err(|_| format!("{port:?} is not a port number"))?;
    Ok((host.to_owned(), port))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransactionId(pub [u8; 12]);

pub fn binding_request(id: TransactionId) -> [u8; HEADER_LEN] {
    let mut message = [0; HEADER_LEN];
    message[..2].copy_from_slice(&BINDING_REQUEST);
    message[4..8].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
    message[8..].copy_from_slice(&id.0);
    message
}

/// What a CHANGE-REQUEST asks the server to change before it answers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Change {
    /// Answer from the other IP and the other port.
    IpAndPort,
    /// Answer from the same IP and the other port.
    Port,
}

impl Change {
    fn flags(self) -> u32 {
        match self {
            Self::IpAndPort => CHANGE_IP | CHANGE_PORT,
            Self::Port => CHANGE_PORT,
        }
    }
}

/// A Binding request that carries a CHANGE-REQUEST (RFC 5780 section 7.2).
pub fn change_request(id: TransactionId, change: Change) -> [u8; HEADER_LEN + 8] {
    let mut message = [0; HEADER_LEN + 8];
    message[..HEADER_LEN].copy_from_slice(&binding_request(id));
    message[2..4].copy_from_slice(&8u16.to_be_bytes());
    message[HEADER_LEN..HEADER_LEN + 2].copy_from_slice(&CHANGE_REQUEST.to_be_bytes());
    message[HEADER_LEN + 2..HEADER_LEN + 4].copy_from_slice(&4u16.to_be_bytes());
    message[HEADER_LEN + 4..].copy_from_slice(&change.flags().to_be_bytes());
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
    parse_binding_response(bytes).map(|response| (response.id, response.mapped))
}

/// What natwg reads from a Binding success response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BindingResponse {
    pub id: TransactionId,
    /// XOR-MAPPED-ADDRESS, else MAPPED-ADDRESS.
    pub mapped: SocketAddrV4,
    /// The address the server would answer a CHANGE-REQUEST from:
    /// OTHER-ADDRESS (RFC 5780), else CHANGED-ADDRESS (RFC 3489).
    pub other: Option<SocketAddrV4>,
    /// The address the server sent the response from, as it says:
    /// RESPONSE-ORIGIN (RFC 5780), else SOURCE-ADDRESS (RFC 3489).
    pub origin: Option<SocketAddrV4>,
}

/// A Binding success response with an IPv4 mapping. The first of each
/// attribute counts, and unknown attributes are skipped.
pub fn parse_binding_response(bytes: &[u8]) -> Option<BindingResponse> {
    if !is_stun_binding_success(bytes) {
        return None;
    }
    let id = TransactionId(bytes[8..HEADER_LEN].try_into().ok()?);
    let [
        mut xor_mapped,
        mut mapped,
        mut other,
        mut changed,
        mut origin,
        mut source,
    ] = [None; 6];
    for_each_attribute(bytes, |kind, value| {
        let slot = match kind {
            XOR_MAPPED_ADDRESS => &mut xor_mapped,
            MAPPED_ADDRESS => &mut mapped,
            OTHER_ADDRESS => &mut other,
            CHANGED_ADDRESS => &mut changed,
            RESPONSE_ORIGIN => &mut origin,
            SOURCE_ADDRESS => &mut source,
            _ => return,
        };
        let address = ipv4(value).map(|address| match kind {
            XOR_MAPPED_ADDRESS => unxor(address),
            _ => address,
        });
        *slot = slot.or(address);
    })?;
    Some(BindingResponse {
        id,
        mapped: xor_mapped.or(mapped)?,
        other: other.or(changed),
        origin: origin.or(source),
    })
}

/// Call `visit` with the type and value of each attribute of a STUN message
/// of at least [`HEADER_LEN`] bytes. None when an attribute runs past the
/// message or the message is shorter than its length field.
fn for_each_attribute(bytes: &[u8], mut visit: impl FnMut(u16, &[u8])) -> Option<()> {
    let len = usize::from(u16::from_be_bytes([bytes[2], bytes[3]]));
    let mut attributes = bytes.get(HEADER_LEN..HEADER_LEN + len)?;
    while let [t0, t1, l0, l1, rest @ ..] = attributes {
        let len = usize::from(u16::from_be_bytes([*l0, *l1]));
        visit(u16::from_be_bytes([*t0, *t1]), rest.get(..len)?);
        attributes = rest.get(len.next_multiple_of(4)..).unwrap_or_default();
    }
    Some(())
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
