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
use std::net::{SocketAddr, SocketAddrV4};
use std::os::fd::AsRawFd;
use std::time::Duration;
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
}

/// What a WireGuard device knows about one of its peers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerStats {
    pub public_key: PublicKey,
    pub endpoint: Option<SocketAddr>,
    /// How long ago the last handshake completed.
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
        peer_stats(&self.device).await
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
        };
        Ok((detached, stun))
    }

    /// Wait until the device can carry no more traffic, which happens when
    /// its UDP socket fails.
    pub async fn failed(&mut self) {
        self.device.wait().await;
    }

    pub async fn peers(&self) -> Vec<PeerStats> {
        peer_stats(&self.device).await
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

async fn peer_stats<T: DeviceTransports>(device: &Device<T>) -> Vec<PeerStats> {
    let peers = device.read(async |device| device.peers().await).await;
    peers
        .into_iter()
        .map(|peer| PeerStats {
            public_key: PublicKey::from(peer.peer.public_key.to_bytes()),
            endpoint: peer.peer.endpoint,
            last_handshake: peer.stats.last_handshake,
            rx_bytes: peer.stats.rx_bytes as u64,
            tx_bytes: peer.stats.tx_bytes as u64,
        })
        .collect()
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
