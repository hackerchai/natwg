//! The checks behind `natwg doctor`, which use the server the way a client
//! does.

use crate::config::Config;
use crate::tunnel::Detached;
use crate::{Error, Result};
use std::{
    net::{Ipv4Addr, SocketAddrV4},
    time::{Duration, Instant},
};

/// How many echo requests `natwg doctor loopback` sends to a target that
/// stays silent, one per second.
pub const ATTEMPTS: u16 = 8;

const INTERVAL: Duration = Duration::from_secs(1);
const IP_HEADER: usize = 20;
const ICMP_HEADER: usize = 8;
const PROTOCOL_ICMP: u8 = 1;
const ECHO_REQUEST: u8 = 8;
const ECHO_REPLY: u8 = 0;
const DONT_FRAGMENT: u8 = 0x40;
const MORE_FRAGMENTS_AND_OFFSET: u16 = 0x3FFF;
const PAYLOAD: &[u8] = b"natwg doctor";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EchoKind {
    Request,
    Reply,
}

/// An ICMP echo message in an IPv4 packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Echo {
    pub kind: EchoKind,
    pub source: Ipv4Addr,
    pub destination: Ipv4Addr,
    pub id: u16,
    pub seq: u16,
}

impl Echo {
    /// The whole IPv4 packet, with both checksums filled in.
    pub fn encode(&self) -> Vec<u8> {
        let kind = match self.kind {
            EchoKind::Request => ECHO_REQUEST,
            EchoKind::Reply => ECHO_REPLY,
        };
        let total = (IP_HEADER + ICMP_HEADER + PAYLOAD.len()) as u16;
        let mut packet = vec![0x45, 0];
        packet.extend(total.to_be_bytes());
        packet.extend([0, 0, DONT_FRAGMENT, 0, 64, PROTOCOL_ICMP, 0, 0]);
        packet.extend(self.source.octets());
        packet.extend(self.destination.octets());
        let header = checksum(&packet);
        packet[10..12].copy_from_slice(&header.to_be_bytes());
        packet.extend([kind, 0, 0, 0]);
        packet.extend(self.id.to_be_bytes());
        packet.extend(self.seq.to_be_bytes());
        packet.extend(PAYLOAD);
        let message = checksum(&packet[IP_HEADER..]);
        packet[IP_HEADER + 2..IP_HEADER + 4].copy_from_slice(&message.to_be_bytes());
        packet
    }

    /// The echo message in an IPv4 packet that is not a fragment. Checksums
    /// are not verified, because macOS leaves the header checksum of a
    /// loopback packet at zero.
    pub fn decode(packet: &[u8]) -> Option<Self> {
        let header_len = usize::from(packet.first()? & 0x0F) * 4;
        if packet[0] >> 4 != 4 || header_len < IP_HEADER {
            return None;
        }
        let header = packet.get(..header_len)?;
        let total = usize::from(u16::from_be_bytes([header[2], header[3]]));
        let fragment = u16::from_be_bytes([header[6], header[7]]) & MORE_FRAGMENTS_AND_OFFSET;
        if header[9] != PROTOCOL_ICMP || fragment != 0 {
            return None;
        }
        let [kind, 0, _, _, id0, id1, seq0, seq1, ..] = *packet.get(header_len..total)? else {
            return None;
        };
        let kind = match kind {
            ECHO_REQUEST => EchoKind::Request,
            ECHO_REPLY => EchoKind::Reply,
            _ => return None,
        };
        Some(Self {
            kind,
            source: Ipv4Addr::new(header[12], header[13], header[14], header[15]),
            destination: Ipv4Addr::new(header[16], header[17], header[18], header[19]),
            id: u16::from_be_bytes([id0, id1]),
            seq: u16::from_be_bytes([seq0, seq1]),
        })
    }
}

// The Internet checksum of RFC 1071.
fn checksum(bytes: &[u8]) -> u16 {
    let mut sum: u32 = bytes
        .chunks(2)
        .map(|pair| u32::from(u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)])))
        .sum();
    while sum > 0xFFFF {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// One address the doctor pinged, and how long the first reply took. The
/// first echo also starts the WireGuard handshake, so its reply time includes
/// the handshake.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Probe {
    pub target: Ipv4Addr,
    pub reply: Option<Duration>,
}

/// Ping the server's tunnel address and the first host of its LAN from a
/// client that runs in this process and dials `endpoint` through `iface`, or
/// through the server's interface. Each target gets one echo request a second
/// until it replies, `attempts` at most. A reply from the LAN proves that the
/// server forwards and translates tunnel traffic.
pub async fn loopback(
    config: &Config,
    iface: Option<&str>,
    endpoint: SocketAddrV4,
    attempts: u16,
) -> Result<Vec<Probe>> {
    let server = config.server()?;
    let doctor = server.doctor.as_ref().ok_or_else(|| {
        Error::new(
            "DOCTOR_NOT_CONFIGURED",
            "the server config has no doctor section with a private key and a tunnel address",
        )
    })?;
    let lan_host = server.lan.nth(1).unwrap_or(server.lan.network());
    let mut probes = [config.interface.address.ip(), lan_host].map(|target| Probe {
        target,
        reply: None,
    });
    let mut client = Detached::doctor(config, doctor, iface, endpoint).await?;
    let id = std::process::id() as u16;
    let mut sent = Vec::new();
    for seq in 0..attempts {
        if probes.iter().all(|probe| probe.reply.is_some()) {
            break;
        }
        let now = Instant::now();
        sent.push(now);
        for probe in probes.iter().filter(|probe| probe.reply.is_none()) {
            let request = Echo {
                kind: EchoKind::Request,
                source: doctor.address,
                destination: probe.target,
                id,
                seq,
            };
            client.send(&request.encode()).await?;
        }
        let next_send = tokio::time::Instant::from_std(now + INTERVAL);
        while probes.iter().any(|probe| probe.reply.is_none()) {
            let Ok(packet) = tokio::time::timeout_at(next_send, client.recv()).await else {
                break;
            };
            let Some(echo) = Echo::decode(&packet?) else {
                continue;
            };
            let ours =
                echo.kind == EchoKind::Reply && echo.id == id && echo.destination == doctor.address;
            let asked = sent.get(usize::from(echo.seq));
            let waiting = probes
                .iter_mut()
                .find(|probe| probe.target == echo.source && probe.reply.is_none());
            if let (true, Some(asked), Some(probe)) = (ours, asked, waiting) {
                probe.reply = Some(asked.elapsed());
            }
        }
    }
    Ok(probes.to_vec())
}
