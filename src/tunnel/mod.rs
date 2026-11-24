//! The embedded WireGuard device. gotatun runs the protocol on the UDP socket
//! that STUN shares. Only this module and `wire::transport` use gotatun types.

mod channel;

use crate::config::{Config, DoctorConfig, Instance, PeerConfig, ServerConfig};
use crate::keys::{Key, PublicKey};
use crate::nat::{Nat, Rule};
use crate::netcfg;
use crate::wire::transport::{BoundInterface, BoundUdp, StunPort};
use crate::{Error, Result};
use channel::{ChannelRecv, ChannelSend};
use gotatun::device::{Device, DeviceBuilder, DeviceTransports, Peer};
use gotatun::packet::{Ip, Packet};
use gotatun::tun::tun_async_device::TunDevice;
use gotatun::tun::{IpRecv, IpSend, tun};
use gotatun::x25519;
use ipnetwork::{IpNetwork, Ipv4Network};
use std::collections::HashMap;
use std::net::{SocketAddr, SocketAddrV4};
use std::os::fd::AsRawFd;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

const PACKET_QUEUE: usize = 64;

/// The server's WireGuard device on a kernel TUN, with the address, the route
/// and the NAT rules that let its peers reach the LAN.
pub struct Tunnel {
    // Fields drop in this order, so a panic removes the NAT rules before it
    // reaches the device.
    nat: Nat,
    rule: Rule,
    device: Device<(BoundUdp, TunDevice, TunDevice)>,
    tun_name: String,
    handshakes: Handshakes,
}

/// What a WireGuard device knows about one of its peers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerStats {
    pub public_key: PublicKey,
    pub endpoint: Option<SocketAddr>,
    /// How long ago the last handshake completed, as [`Handshakes`] dates it.
    pub last_handshake: Option<Duration>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

impl Tunnel {
    /// Start the server that `config` describes, and STUN on its socket. The
    /// checks that can refuse the start run before anything on the host
    /// changes. A start that fails later removes the TUN, the route and the
    /// NAT rule that it made.
    pub async fn start(config: &Config) -> Result<(Self, StunPort)> {
        let server = config.server()?;
        let subnet = subnet(config.interface.address);
        let rule = Rule::new(&server.instance, &server.iface, subnet, server.lan);
        let nat = rule.clone().check()?;
        // macOS needs no such check. The route step of its plan fails with
        // COMMAND_NO_EFFECT for a subnet that has a route.
        #[cfg(not(target_os = "macos"))]
        netcfg::linux::require_free_route(server.instance.as_str(), subnet)?;
        let peers = server_peers(config, server)?;
        let iface = BoundInterface::lookup(&server.iface)?;
        let tun = open_tun(&server.instance)?;
        let tun_name = tun.name().map_err(tun_unavailable)?;
        let (device, stun) = device(
            &config.private_key,
            iface,
            server.listen_port,
            peers,
            tun.clone(),
            tun,
        )
        .await?;
        let plan = netcfg::plan(
            &tun_name,
            config.interface.address,
            config.interface.mtu,
            &[subnet],
        );
        let nat = netcfg::apply(&plan).and_then(|()| nat.load());
        match nat {
            Ok(nat) => {
                let tunnel = Self {
                    nat,
                    rule,
                    device,
                    tun_name,
                    handshakes: Handshakes::default(),
                };
                Ok((tunnel, stun))
            }
            Err(error) => {
                device.stop().await;
                Err(error)
            }
        }
    }

    /// The name of the TUN, which the kernel chooses on macOS.
    pub fn tun_name(&self) -> &str {
        &self.tun_name
    }

    /// Wait until the device can carry no more traffic, which happens when
    /// its TUN or its UDP socket fails.
    pub async fn failed(&mut self) {
        self.device.wait().await;
    }

    pub async fn peers(&self) -> Vec<PeerStats> {
        peer_stats(&self.device, &self.handshakes).await
    }

    /// Load the NAT rule again if it no longer takes effect. Returns whether
    /// it had to.
    pub fn ensure_nat(&mut self) -> Result<bool> {
        self.nat.ensure(&self.rule)
    }

    /// Remove the NAT rules and stop the device. The TUN closes with the
    /// device, and the kernel then removes its address and its routes.
    pub async fn stop(self) -> Result<()> {
        let nat = self.nat.stop();
        self.device.stop().await;
        nat
    }
}

/// A WireGuard device with no TUN. The caller writes the IP packets that go
/// into the tunnel and reads the ones that come out of it.
pub struct Detached {
    device: Device<(BoundUdp, ChannelSend, ChannelRecv)>,
    outbound: mpsc::Sender<Packet<Ip>>,
    inbound: mpsc::Receiver<Packet<Ip>>,
    handshakes: Handshakes,
}

impl Detached {
    /// The device of [`Tunnel::start`] without its TUN, its route and its
    /// NAT, and STUN on its socket.
    pub async fn server(config: &Config) -> Result<(Self, StunPort)> {
        let server = config.server()?;
        let iface = BoundInterface::lookup(&server.iface)?;
        let peers = server_peers(config, server)?;
        let (key, port, mtu) = (
            &config.private_key,
            server.listen_port,
            config.interface.mtu,
        );
        Self::start(key, iface, port, peers, mtu).await
    }

    /// A client with the doctor's identity, on a free port of `iface` or of
    /// the server's interface. Its only peer is the server at `endpoint`, and
    /// it sends the tunnel subnet and the LAN to that peer.
    pub async fn doctor(
        config: &Config,
        doctor: &DoctorConfig,
        iface: Option<&str>,
        endpoint: SocketAddrV4,
    ) -> Result<Self> {
        let server = config.server()?;
        let iface = BoundInterface::lookup(iface.unwrap_or(&server.iface))?;
        let routed = [subnet(config.interface.address), server.lan];
        let peer = Peer::new(public(config.private_key.public_key()))
            .with_endpoint(endpoint.into())
            .with_allowed_ips(routed.map(IpNetwork::V4));
        let (client, _) = Self::start(
            &doctor.private_key,
            iface,
            0,
            vec![peer],
            config.interface.mtu,
        )
        .await?;
        Ok(client)
    }

    async fn start(
        key: &Key,
        iface: BoundInterface,
        port: u16,
        peers: Vec<Peer>,
        mtu: u16,
    ) -> Result<(Self, StunPort)> {
        let (outbound, from_caller) = mpsc::channel(PACKET_QUEUE);
        let (to_caller, inbound) = mpsc::channel(PACKET_QUEUE);
        let tun_rx = ChannelRecv {
            packets: from_caller,
            mtu,
        };
        let (device, stun) =
            device(key, iface, port, peers, ChannelSend(to_caller), tun_rx).await?;
        let detached = Self {
            device,
            outbound,
            inbound,
            handshakes: Handshakes::default(),
        };
        Ok((detached, stun))
    }

    /// Wait until the device can carry no more traffic, which happens when
    /// its UDP socket fails.
    pub async fn failed(&mut self) {
        self.device.wait().await;
    }

    pub async fn peers(&self) -> Vec<PeerStats> {
        peer_stats(&self.device, &self.handshakes).await
    }

    pub async fn stop(self) {
        self.device.stop().await;
    }

    /// The UDP port the device listens on. The kernel chose it when the
    /// device asked for port 0.
    pub async fn listen_port(&self) -> u16 {
        self.device.read(async |device| device.listen_port()).await
    }

    /// Send one IP packet into the tunnel. The device drops a packet whose
    /// destination no peer's allowed IPs cover.
    pub async fn send(&self, packet: &[u8]) -> Result<()> {
        let packet = Packet::copy_from(packet)
            .try_into_ip()
            .map_err(|e| Error::new("PACKET_INVALID", e.to_string()))?;
        self.outbound.send(packet).await.map_err(|_| stopped())
    }

    /// The next IP packet that came out of the tunnel.
    pub async fn recv(&mut self) -> Result<Vec<u8>> {
        let packet = self.inbound.recv().await.ok_or_else(stopped)?;
        Ok(packet.into_bytes().to_vec())
    }
}

async fn peer_stats<T: DeviceTransports>(
    device: &Device<T>,
    handshakes: &Handshakes,
) -> Vec<PeerStats> {
    let peers = device.read(async |device| device.peers().await).await;
    let now = Instant::now();
    peers
        .into_iter()
        .map(|peer| {
            let key = peer.peer.public_key.to_bytes();
            PeerStats {
                public_key: PublicKey::from(key),
                endpoint: peer.peer.endpoint,
                last_handshake: handshakes.date(key, peer.stats.last_handshake, now),
                rx_bytes: peer.stats.rx_bytes as u64,
                tx_bytes: peer.stats.tx_bytes as u64,
            }
        })
        .collect()
}

/// When each peer of a device last completed a handshake. gotatun 0.10.3 is
/// wrong in two cases. Its timer loop skips a peer that has no endpoint, so
/// it dates the first handshake of a peer without a configured endpoint
/// from the start of the device. And it reports no handshake once the
/// session expires. So a handshake is never dated before the last look at
/// the peers that saw it without a session, and it outlives its session.
#[derive(Default)]
struct Handshakes(Mutex<HashMap<[u8; 32], Handshake>>);

#[derive(Default)]
struct Handshake {
    at: Option<Instant>,
    /// The last look that saw the peer without a session.
    idle: Option<Instant>,
}

impl Handshakes {
    /// How long ago the peer `key` completed its last handshake, given what
    /// gotatun `reported` at `now`.
    fn date(&self, key: [u8; 32], reported: Option<Duration>, now: Instant) -> Option<Duration> {
        let mut peers = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let seen = peers.entry(key).or_default();
        match reported.and_then(|ago| now.checked_sub(ago)) {
            None => seen.idle = Some(now),
            Some(at) => seen.at = seen.at.max(seen.idle.max(Some(at))),
        }
        seen.at.map(|at| now.saturating_duration_since(at))
    }
}

fn stopped() -> Error {
    Error::new("TUNNEL_STOPPED", "the WireGuard device stopped")
}

/// The TUN of `instance`, opened as gotatun's `TunDevice::from_name` opens
/// it. The tun crate opens the macOS utun control socket without
/// FD_CLOEXEC, so every command natwg runs would inherit the socket and could
/// keep the utun alive after natwg exits.
fn open_tun(instance: &Instance) -> Result<TunDevice> {
    let tun = tun::create_as_async(&tun_config(instance)).map_err(tun_unavailable)?;
    if unsafe { libc::fcntl(tun.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } == -1 {
        return Err(tun_unavailable(std::io::Error::last_os_error()));
    }
    TunDevice::from_tun_device(tun).map_err(tun_unavailable)
}

// macOS names a utun itself.
#[cfg(target_os = "macos")]
fn tun_config(_: &Instance) -> tun::Configuration {
    let mut config = tun::Configuration::default();
    config.platform_config(|platform| {
        platform.enable_routing(false);
    });
    config
}

#[cfg(not(target_os = "macos"))]
fn tun_config(instance: &Instance) -> tun::Configuration {
    let mut config = tun::Configuration::default();
    config.tun_name(instance.as_str());
    config
}

fn tun_unavailable(error: impl std::fmt::Display) -> Error {
    Error::new("TUN_UNAVAILABLE", error.to_string())
}

/// Every configured peer, and the doctor as a peer that owns only its
/// address. Two of them with one public key are an error that names both.
fn server_peers(config: &Config, server: &ServerConfig) -> Result<Vec<Peer>> {
    let duplicate = |message: String| Error::new("PEER_DUPLICATE", message);
    for (index, peer) in config.peers.iter().enumerate() {
        let earlier = &config.peers[..index];
        if let Some(first) = earlier.iter().find(|p| p.public_key == peer.public_key) {
            return Err(duplicate(format!(
                "peers {:?} and {:?} have the same public key",
                first.name, peer.name
            )));
        }
    }
    let doctor = server
        .doctor
        .as_ref()
        .map(|doctor| (doctor.private_key.public_key(), doctor.address));
    if let Some((key, _)) = doctor
        && let Some(peer) = config.peers.iter().find(|peer| peer.public_key == key)
    {
        return Err(duplicate(format!(
            "peer {:?} has the public key of role.server.doctor.private_key, and the doctor counts as a peer",
            peer.name
        )));
    }
    let doctor = doctor.map(|(key, address)| {
        Peer::new(public(key)).with_allowed_ip(Ipv4Network::from(address).into())
    });
    Ok(config.peers.iter().map(peer).chain(doctor).collect())
}

fn peer(config: &PeerConfig) -> Peer {
    let allowed = config.allowed_ips.iter().copied().map(IpNetwork::V4);
    let mut peer = Peer::new(public(config.public_key)).with_allowed_ips(allowed);
    peer.endpoint = config.endpoint.map(Into::into);
    peer.preshared_key = config.preshared_key.as_ref().map(Key::to_bytes);
    peer.keepalive = config.keepalive;
    peer
}

fn public(key: PublicKey) -> x25519::PublicKey {
    x25519::PublicKey::from(key.to_bytes())
}

fn subnet(address: Ipv4Network) -> Ipv4Network {
    Ipv4Network::new(address.network(), address.prefix())
        .expect("the prefix of a network is a valid prefix")
}

async fn device<Tx: IpSend, Rx: IpRecv>(
    key: &Key,
    iface: BoundInterface,
    port: u16,
    peers: Vec<Peer>,
    tun_tx: Tx,
    tun_rx: Rx,
) -> Result<(Device<(BoundUdp, Tx, Rx)>, StunPort)> {
    // gotatun binds its socket only when it has a peer, and STUN needs that socket.
    if peers.is_empty() {
        return Err(Error::new(
            "TUNNEL_NO_PEERS",
            "the config has no peer and no doctor, so the tunnel would serve nobody",
        ));
    }
    let name = iface.to_string();
    let (udp, stun) = BoundUdp::new(iface);
    let device = DeviceBuilder::new()
        .with_private_key(x25519::StaticSecret::from(key.to_bytes()))
        .with_ip_pair(tun_tx, tun_rx)
        .with_udp(udp)
        .with_listen_port(port)
        .with_peers(peers)
        .build()
        .await
        .map_err(|error| match error {
            gotatun::device::Error::Bind(error, _) => {
                Error::new("UDP_BIND", format!("{name} udp/{port}: {error}"))
            }
            error => Error::new("TUNNEL_FAILED", error.to_string()),
        })?;
    Ok((device, stun))
}

#[cfg(test)]
mod tests {
    use super::Handshakes;
    use std::time::{Duration, Instant};

    const PEER: [u8; 32] = [7; 32];

    fn secs(secs: u64) -> Duration {
        Duration::from_secs(secs)
    }

    #[test]
    fn a_first_handshake_is_dated_no_earlier_than_the_last_look_without_a_session() {
        let handshakes = Handshakes::default();
        let start = Instant::now();
        assert_eq!(handshakes.date(PEER, None, start + secs(3590)), None);
        let device_age = secs(3600);
        let ago = handshakes.date(PEER, Some(device_age), start + device_age);
        assert_eq!(ago, Some(secs(10)));
    }

    #[test]
    fn a_handshake_that_gotatun_dates_right_keeps_its_date() {
        let handshakes = Handshakes::default();
        let start = Instant::now();
        assert_eq!(handshakes.date(PEER, None, start), None);
        assert_eq!(
            handshakes.date(PEER, Some(secs(3)), start + secs(10)),
            Some(secs(3))
        );
        assert_eq!(
            handshakes.date(PEER, Some(secs(13)), start + secs(20)),
            Some(secs(13))
        );
    }

    #[test]
    fn a_handshake_outlives_its_session() {
        let handshakes = Handshakes::default();
        let start = Instant::now();
        handshakes.date(PEER, Some(secs(5)), start + secs(10));
        assert_eq!(
            handshakes.date(PEER, None, start + secs(400)),
            Some(secs(395))
        );
        assert_eq!(
            handshakes.date(PEER, Some(secs(1)), start + secs(500)),
            Some(secs(1)),
            "a later handshake replaces it"
        );
    }
}
