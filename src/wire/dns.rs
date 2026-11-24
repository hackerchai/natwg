//! DNS A and TXT lookups sent straight to one server through the uplink
//! interface, past any resolver a VPN app hijacks on the default route.

use crate::wire::transport::{BoundInterface, bound_udp_socket};
use crate::{Error, Result};
use std::{fmt, io, net::Ipv4Addr, time::Duration};
use tokio::net::UdpSocket;

const HEADER_LEN: usize = 12;
const MAX_UDP_MESSAGE: usize = 512;
const RECURSION_DESIRED: u16 = 0x0100;
const CLASS_IN: u16 = 1;
const TYPE_A: u16 = 1;
const TYPE_TXT: u16 = 16;
const NXDOMAIN: u16 = 3;
const ID_MISMATCH: &str = "DNS_ID_MISMATCH";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordKind {
    A,
    Txt,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Record {
    A(Ipv4Addr),
    /// The record's character-strings joined with nothing between them.
    Txt(String),
}

impl fmt::Display for Record {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::A(address) => address.fmt(f),
            Self::Txt(text) => f.write_str(text),
        }
    }
}

pub fn query(id: u16, name: &str, kind: RecordKind) -> Result<Vec<u8>> {
    let invalid = || Error::new("DNS_NAME_INVALID", format!("{name:?} is not a DNS name"));
    let mut message = Vec::with_capacity(HEADER_LEN + name.len() + 6);
    for field in [id, RECURSION_DESIRED, 1, 0, 0, 0] {
        message.extend(field.to_be_bytes());
    }
    for label in name.strip_suffix('.').unwrap_or(name).split('.') {
        let len = u8::try_from(label.len())
            .ok()
            .filter(|len| (1..=63).contains(len))
            .ok_or_else(invalid)?;
        message.push(len);
        message.extend(label.as_bytes());
    }
    message.push(0);
    if message.len() - HEADER_LEN > 255 {
        return Err(invalid());
    }
    let kind = match kind {
        RecordKind::A => TYPE_A,
        RecordKind::Txt => TYPE_TXT,
    };
    message.extend(kind.to_be_bytes());
    message.extend(CLASS_IN.to_be_bytes());
    Ok(message)
}

/// The A and TXT answers in a response to the query with `id`. Other record
/// types, such as the CNAMEs that lead to the answers, are skipped.
pub fn parse_response(bytes: &[u8], id: u16) -> Result<Vec<Record>> {
    let malformed = || {
        Error::new(
            "DNS_MALFORMED",
            "the DNS response is truncated or malformed",
        )
    };
    let header = bytes.get(..HEADER_LEN).ok_or_else(malformed)?;
    let field = |i: usize| u16::from_be_bytes([header[2 * i], header[2 * i + 1]]);
    if field(0) != id {
        return Err(Error::new(
            ID_MISMATCH,
            "the DNS response answers another query",
        ));
    }
    match field(1) & 0x000F {
        0 => {}
        NXDOMAIN => return Err(Error::new("DNS_NXDOMAIN", "the name does not exist")),
        rcode => {
            return Err(Error::new(
                "DNS_RCODE",
                format!("the DNS server answered with rcode {rcode}"),
            ));
        }
    }
    let mut reader = Reader {
        bytes,
        at: HEADER_LEN,
    };
    reader.records(field(2), field(3)).ok_or_else(malformed)
}

/// Ask `server` for the `kind` records of `name` through a fresh socket bound to
/// `iface`. Responses to other queries are ignored.
pub async fn resolve(
    iface: &BoundInterface,
    server: Ipv4Addr,
    name: &str,
    kind: RecordKind,
    timeout: Duration,
) -> Result<Vec<Record>> {
    let id = u16::from_be_bytes(super::random()?);
    let message = query(id, name, kind)?;
    let failed = |e: io::Error| Error::new("DNS_IO", format!("{server}: {e}"));
    let socket =
        bound_udp_socket(iface, 0).map_err(|e| Error::new("UDP_BIND", format!("{iface}: {e}")))?;
    let socket = UdpSocket::from_std(socket).map_err(failed)?;
    let exchange = async {
        socket.connect((server, 53)).await.map_err(failed)?;
        socket.send(&message).await.map_err(failed)?;
        let mut response = [0; MAX_UDP_MESSAGE];
        loop {
            let len = socket.recv(&mut response).await.map_err(failed)?;
            match parse_response(&response[..len], id) {
                Err(e) if e.code == ID_MISMATCH => continue,
                records => return records,
            }
        }
    };
    tokio::time::timeout(timeout, exchange)
        .await
        .unwrap_or_else(|_| {
            Err(Error::new(
                "DNS_TIMEOUT",
                format!(
                    "no answer from {server} for {name} within {} ms",
                    timeout.as_millis()
                ),
            ))
        })
}

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, len: usize) -> Option<&'a [u8]> {
        let taken = self.bytes.get(self.at..self.at.checked_add(len)?)?;
        self.at += len;
        Some(taken)
    }

    fn skip(&mut self, len: usize) -> Option<()> {
        self.take(len).map(drop)
    }

    fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|b| u16::from_be_bytes([b[0], b[1]]))
    }

    fn skip_name(&mut self) -> Option<()> {
        loop {
            match self.take(1)?[0] {
                0 => return Some(()),
                len @ 1..=63 => self.skip(usize::from(len))?,
                0xC0.. => return self.skip(1),
                _ => return None,
            }
        }
    }

    fn records(&mut self, questions: u16, answers: u16) -> Option<Vec<Record>> {
        for _ in 0..questions {
            self.skip_name()?;
            self.skip(4)?;
        }
        let mut records = Vec::new();
        for _ in 0..answers {
            self.skip_name()?;
            let kind = self.u16()?;
            self.skip(6)?;
            let len = self.u16()?;
            let data = self.take(usize::from(len))?;
            match kind {
                TYPE_A => records.push(Record::A(<[u8; 4]>::try_from(data).ok()?.into())),
                TYPE_TXT => records.push(Record::Txt(txt(data)?)),
                _ => {}
            }
        }
        Some(records)
    }
}

fn txt(mut data: &[u8]) -> Option<String> {
    let mut text = Vec::new();
    while let [len, rest @ ..] = data {
        text.extend(rest.get(..usize::from(*len))?);
        data = &rest[usize::from(*len)..];
    }
    Some(String::from_utf8_lossy(&text).into_owned())
}
