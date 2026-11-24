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
use gotatun::device::{Device, DeviceBuilder, Peer};
use gotatun::packet::{Ip, Packet};
use gotatun::tun::tun_async_device::TunDevice;
use gotatun::tun::{IpRecv, IpSend};
use gotatun::x25519;
use ipnetwork::{IpNetwork, Ipv4Network};
use std::net::SocketAddrV4;
use tokio::sync::mpsc;

const PACKET_QUEUE: usize = 64;

/// The server's WireGuard device on a kernel TUN, with the address, the route
/// and the NAT rules that let its peers reach the LAN.
pub struct Tunnel {
    // Fields drop in this order, so a panic removes the NAT rules before it
    // reaches the device.
    nat: Nat,
    device: Device<(BoundUdp, TunDevice, TunDevice)>,
    stun: StunPort,
    tun_name: String,
}

impl Tunnel {
    /// Start the server that `config` describes. The checks that can refuse
    /// the start run before anything on the host changes. A start that fails
    /// later removes the TUN, the route and the NAT rule that it made.
    pub async fn start(config: &Config) -> Result<Self> {
        let server = config.server()?;
        let subnet = subnet(config.interface.address);
        let nat = Rule::new(&server.instance, &server.iface, subnet, server.lan).check()?;
        // macOS needs no such check. The route step of its plan fails with
        // COMMAND_NO_EFFECT for a subnet that has a route.
        #[cfg(not(target_os = "macos"))]
        netcfg::linux::require_free_route(requested_tun(&server.instance), subnet)?;
        let iface = BoundInterface::lookup(&server.iface)?;
        let unavailable =
            |e: gotatun::tun::tun_async_device::Error| Error::new("TUN_UNAVAILABLE", e.to_string());
        let tun = TunDevice::from_name(requested_tun(&server.instance)).map_err(unavailable)?;
        let tun_name = tun.name().map_err(unavailable)?;
        let (device, stun) = device(
            &config.private_key,
            iface,
            server.listen_port,
            server_peers(config, server),
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
            Ok(nat) => Ok(Self {
                nat,
                device,
                stun,
                tun_name,
            }),
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

    /// STUN on the socket the device listens on.
    pub fn stun(&mut self) -> &mut StunPort {
        &mut self.stun
    }

    /// Wait until the device can carry no more traffic, which happens when
    /// its TUN or its UDP socket fails.
    pub async fn failed(&mut self) {
        self.device.wait().await;
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
    /// The device of [`Tunnel::start`] without its TUN, its route and its NAT.
    pub async fn server(config: &Config) -> Result<Self> {
        let server = config.server()?;
        let iface = BoundInterface::lookup(&server.iface)?;
        let peers = server_peers(config, server);
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
        Self::start(
            &doctor.private_key,
            iface,
            0,
            vec![peer],
            config.interface.mtu,
        )
        .await
    }

    async fn start(
        key: &Key,
        iface: BoundInterface,
        port: u16,
        peers: Vec<Peer>,
        mtu: u16,
    ) -> Result<Self> {
        let (outbound, from_caller) = mpsc::channel(PACKET_QUEUE);
        let (to_caller, inbound) = mpsc::channel(PACKET_QUEUE);
        let tun_rx = ChannelRecv {
            packets: from_caller,
            mtu,
        };
        let (device, _) = device(key, iface, port, peers, ChannelSend(to_caller), tun_rx).await?;
        Ok(Self {
            device,
            outbound,
            inbound,
        })
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

fn stopped() -> Error {
    Error::new("TUNNEL_STOPPED", "the WireGuard device stopped")
}

// gotatun opens a kernel-chosen utun for the name "utun".
#[cfg(target_os = "macos")]
fn requested_tun(_: &Instance) -> &str {
    "utun"
}

#[cfg(not(target_os = "macos"))]
fn requested_tun(instance: &Instance) -> &str {
    instance.as_str()
}

/// Every configured peer, and the doctor as a peer that owns only its address.
fn server_peers(config: &Config, server: &ServerConfig) -> Vec<Peer> {
    let doctor = server.doctor.as_ref().map(|doctor| {
        Peer::new(public(doctor.private_key.public_key()))
            .with_allowed_ip(Ipv4Network::from(doctor.address).into())
    });
    config.peers.iter().map(peer).chain(doctor).collect()
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
            gotatun::device::Error::DuplicatePeer => Error::new(
                "PEER_DUPLICATE",
                "two peers have the same public key, and the doctor counts as a peer",
            ),
            error => Error::new("TUNNEL_FAILED", error.to_string()),
        })?;
    Ok((device, stun))
}
