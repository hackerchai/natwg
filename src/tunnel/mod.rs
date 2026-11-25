//! The embedded WireGuard device. gotatun runs the protocol on the UDP socket
//! that STUN shares. Only this module and `wire::transport` use gotatun types.

mod activity;
mod channel;

use crate::config::{Config, DoctorConfig, PeerConfig, ServerConfig};
use crate::keys::{Key, PublicKey};
use crate::nat::{self, Nat, Rule};
use crate::netcfg;
use crate::wire::transport::{BoundInterface, BoundUdp, Initiation, StunPort};
use crate::{Error, Result};
use activity::{Activity, ClientTun};
use channel::{ChannelRecv, ChannelSend};
use gotatun::device::configure::PeerMut;
use gotatun::device::{Device, DeviceBuilder, DeviceTransports, Peer};
use gotatun::packet::{Ip, Packet};
use gotatun::tun::tun_async_device::TunDevice;
use gotatun::tun::{IpRecv, IpSend, tun};
use gotatun::x25519;
use ipnetwork::{IpNetwork, Ipv4Network};
use std::collections::HashMap;
use std::net::{SocketAddr, SocketAddrV4};
use std::os::fd::AsRawFd;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, watch};

const PACKET_QUEUE: usize = 64;

/// The server's WireGuard device on a kernel TUN, with the address, the route
/// and the NAT rules that let its peers reach the LANs.
pub struct Tunnel {
    // Fields drop in this order, so a panic removes the NAT rules before it
    // reaches the device.
    /// The loaded NAT rules and the rule they load, none without a LAN.
    nat: Option<(Nat, Rule)>,
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
        netcfg::require_free_address(config.interface.address.ip())?;
        #[cfg(target_os = "macos")]
        netcfg::macos::require_free_routes(&allowed_ips(config, server))?;
        let subnet = subnet(config.interface.address);
        let rule = Rule::new(&server.instance, &server.iface, subnet, &server.lan);
        let nat = rule.clone().map(Rule::check).transpose()?;
        if rule.is_none() {
            // A server killed while it served a LAN leaves its rule behind,
            // and a server without a LAN would never remove it.
            nat::require_empty(&server.instance)?;
        }
        // macOS needs no such check. The route step of its plan fails with
        // COMMAND_NO_EFFECT for a subnet that has a route.
        #[cfg(not(target_os = "macos"))]
        netcfg::linux::require_free_route(server.instance.as_str(), subnet)?;
        let peers = server_peers(config, server)?;
        let iface = BoundInterface::lookup(&server.iface)?;
        let tun = open_tun(&tun_config(server.instance.as_str()))?;
        let tun_name = tun.name().map_err(tun_unavailable)?;
        let (udp, stun) = BoundUdp::new(iface);
        let device = device(
            &config.private_key,
            udp,
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
        let nat = netcfg::apply(&plan).and_then(|()| match nat {
            Some(nat) => nat.load().map(Some),
            // Peers reach each other through the TUN, which takes IP
            // forwarding just as a LAN does.
            None => nat::forward().map(|()| None),
        });
        match nat {
            Ok(nat) => {
                let tunnel = Self {
                    nat: nat.zip(rule),
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
    /// it had to, or none for a server without a LAN, which has no NAT rule.
    pub fn ensure_nat(&mut self) -> Option<Result<bool>> {
        let (nat, rule) = self.nat.as_mut()?;
        Some(nat.ensure(rule))
    }

    /// Remove the NAT rules and stop the device. The TUN closes with the
    /// device, and the kernel then removes its address and its routes.
    pub async fn stop(self) -> Result<()> {
        let nat = self.nat.map_or(Ok(()), |(nat, _)| nat.stop());
        self.device.stop().await;
        nat
    }
}

/// The client's WireGuard device on a kernel TUN. Its one peer is the server,
/// and the TUN has a route for each of the server's allowed IPs. Its UDP
/// socket and port are its own, on the uplink it was started with.
pub struct Client {
    device: Device<(BoundUdp, ClientTun, ClientTun)>,
    traffic: Option<Arc<Activity>>,
    initiations: Option<watch::Receiver<Option<Initiation>>>,
    tun_name: String,
    server: x25519::PublicKey,
    handshakes: Handshakes,
}

/// The name of the client's TUN on Linux. No server takes it, because an
/// instance name has no `-`.
#[cfg(not(target_os = "macos"))]
const CLIENT_TUN: &str = "natwg-client";
#[cfg(target_os = "macos")]
const CLIENT_TUN: &str = "";

impl Client {
    /// Start the client that `config` describes on `uplink`, pointed at
    /// `endpoint`. The checks that can refuse the start run before anything
    /// on the host changes. The kernel removes the address and the routes
    /// with the TUN, when the client stops or exits.
    pub async fn start(
        config: &Config,
        uplink: &BoundInterface,
        endpoint: Option<SocketAddrV4>,
    ) -> Result<Self> {
        let (client, server) = config.client()?;
        let mut routes: Vec<Ipv4Network> = server.allowed_ips.iter().copied().map(subnet).collect();
        let local = netcfg::host_local_networks(&routes)?;
        for network in &local {
            tracing::info!("leaving {network} out of the tunnel while this host is on it");
        }
        routes.retain(|route| !local.contains(route));
        netcfg::require_free_address(config.interface.address.ip())?;
        #[cfg(target_os = "macos")]
        netcfg::macos::require_free_routes(&routes)?;
        #[cfg(not(target_os = "macos"))]
        for route in &routes {
            netcfg::linux::require_free_route(CLIENT_TUN, *route)?;
        }
        let tun = open_tun(&tun_config(CLIENT_TUN))?;
        let tun_name = tun.name().map_err(tun_unavailable)?;
        let peer = client_peer(server, endpoint);
        let (mut udp, _) = BoundUdp::new(uplink.clone());
        let initiations = client.record.as_ref().map(|_| udp.observe_initiations());
        let traffic = client
            .idle_pause_minutes
            .map(|_| Arc::new(Activity::new(&server.allowed_ips)));
        let tun = ClientTun {
            tun,
            traffic: traffic.clone(),
        };
        let device = device(&config.private_key, udp, 0, vec![peer], tun.clone(), tun).await?;
        let plan = netcfg::plan(
            &tun_name,
            config.interface.address,
            config.interface.mtu,
            &routes,
        );
        if let Err(error) = netcfg::apply(&plan) {
            device.stop().await;
            return Err(error);
        }
        Ok(Self {
            device,
            tun_name,
            server: public(server.public_key),
            traffic,
            initiations,
            handshakes: Handshakes::default(),
        })
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

    /// What the device knows about the server.
    pub async fn server(&self) -> Option<PeerStats> {
        peer_stats(&self.device, &self.handshakes).await.pop()
    }

    pub fn initiations(&self) -> Option<watch::Receiver<Option<Initiation>>> {
        self.initiations.clone()
    }

    pub fn take_traffic(&self) -> bool {
        self.traffic.as_ref().is_some_and(|traffic| traffic.take())
    }

    pub async fn set_keepalive(&self, seconds: u16) -> Result<()> {
        self.device
            .write(async |device| {
                device
                    .modify_peer(&self.server, |peer| peer.set_keepalive(Some(seconds)))
                    .await
            })
            .await
            .map_err(|e| Error::new("TUNNEL_FAILED", e.to_string()))?
            .then_some(())
            .ok_or_else(|| Error::new("TUNNEL_FAILED", "the device lost its peer"))
    }

    /// Preserve a pending handshake and its queued user packets when a retry
    /// discovers the move. Otherwise start with a fresh peer on the same socket.
    pub async fn point(&self, endpoint: SocketAddrV4) -> Result<()> {
        let last = self.initiations.as_ref().and_then(|rx| *rx.borrow());
        self.device
            .write(async |device| {
                let Some(stats) = device.peers().await.pop() else {
                    return false;
                };
                let mut peer = stats.peer;
                let retrying = last.is_some_and(|i| {
                    i.retry
                        && Some(i.destination) == peer.endpoint
                        && i.at.elapsed() < Initiation::RETRY_WINDOW
                });
                if peer.endpoint.is_none() || retrying {
                    device
                        .modify_peer(&self.server, |peer| {
                            peer.set_endpoint(Some(endpoint.into()))
                        })
                        .await
                } else {
                    device.remove_peer(&self.server).await;
                    peer.endpoint = Some(endpoint.into());
                    device.add_peer(peer)
                }
            })
            .await
            .map_err(|e| Error::new("TUNNEL_FAILED", e.to_string()))?
            .then_some(())
            .ok_or_else(|| Error::new("TUNNEL_FAILED", "the device lost its peer"))
    }

    /// Bind the UDP socket again on the same interface and port, and start
    /// a fresh handshake, as after the uplink's address changed.
    pub async fn rebind(&self) -> Result<()> {
        rebind(&self.device).await
    }

    /// Stop the device. The TUN closes with it, and the kernel then removes
    /// its address and its routes.
    pub async fn stop(self) {
        self.device.stop().await;
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
    /// it sends the tunnel subnet and every LAN to that peer.
    pub async fn doctor(
        config: &Config,
        doctor: &DoctorConfig,
        iface: Option<&str>,
        endpoint: SocketAddrV4,
    ) -> Result<Self> {
        let server = config.server()?;
        let iface = BoundInterface::lookup(iface.unwrap_or(&server.iface))?;
        let routed = std::iter::once(subnet(config.interface.address)).chain(server.lan.clone());
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

    /// The device of [`Client::start`] without its TUN and its routes, on a
    /// free port of `iface`.
    pub async fn client(
        config: &Config,
        iface: BoundInterface,
        endpoint: Option<SocketAddrV4>,
    ) -> Result<Self> {
        let (_, server) = config.client()?;
        let peer = client_peer(server, endpoint);
        let (key, mtu) = (&config.private_key, config.interface.mtu);
        let (client, _) = Self::start(key, iface, 0, vec![peer], mtu).await?;
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
        let (udp, stun) = BoundUdp::new(iface);
        let device = device(key, udp, port, peers, ChannelSend(to_caller), tun_rx).await?;
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

    /// Send the traffic of the peer `key` to `endpoint` from now on, with a
    /// fresh handshake.
    pub async fn point(&self, key: PublicKey, endpoint: SocketAddrV4) -> Result<()> {
        point(&self.device, &public(key), endpoint).await
    }

    /// Bind the UDP socket again and start a fresh handshake with every peer.
    pub async fn rebind(&self) -> Result<()> {
        rebind(&self.device).await
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

async fn point<T: DeviceTransports>(
    device: &Device<T>,
    key: &x25519::PublicKey,
    endpoint: SocketAddrV4,
) -> Result<()> {
    let set = |peer: &mut PeerMut| peer.set_endpoint(Some(endpoint.into()));
    let found = device
        .write(async |device| device.modify_peer(key, set).await)
        .await
        .map_err(|e| Error::new("TUNNEL_FAILED", e.to_string()))?;
    if !found {
        return Err(Error::new("TUNNEL_FAILED", "the device lost its peer"));
    }
    // The session with the old endpoint stays valid for minutes, and data
    // sent on it to the new endpoint goes nowhere until it expires.
    rebind(device).await
}

/// gotatun drops every session when it resumes, so a peer with a persistent
/// keepalive starts a handshake at once.
async fn rebind<T: DeviceTransports>(device: &Device<T>) -> Result<()> {
    device.suspend().await;
    device
        .resume()
        .await
        .map_err(|e| Error::new("TUNNEL_FAILED", format!("rebinding the UDP socket: {e}")))
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

/// A TUN opened as gotatun's `TunDevice::from_name` opens it. The tun crate
/// opens the macOS utun control socket without FD_CLOEXEC, so every command
/// natwg runs would inherit the socket and could keep the utun alive after
/// natwg exits.
fn open_tun(config: &tun::Configuration) -> Result<TunDevice> {
    let tun = tun::create_as_async(config).map_err(tun_unavailable)?;
    if unsafe { libc::fcntl(tun.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } == -1 {
        return Err(tun_unavailable(std::io::Error::last_os_error()));
    }
    TunDevice::from_tun_device(tun).map_err(tun_unavailable)
}

// macOS names a utun itself.
#[cfg(target_os = "macos")]
fn tun_config(_: &str) -> tun::Configuration {
    let mut config = tun::Configuration::default();
    config.platform_config(|platform| {
        platform.enable_routing(false);
    });
    config
}

#[cfg(not(target_os = "macos"))]
fn tun_config(name: &str) -> tun::Configuration {
    let mut config = tun::Configuration::default();
    config.tun_name(name);
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

/// The allowed IPs of every peer, the doctor's address among them.
#[cfg(target_os = "macos")]
fn allowed_ips(config: &Config, server: &ServerConfig) -> Vec<Ipv4Network> {
    let doctor = server.doctor.iter().map(|doctor| doctor.address.into());
    let peers = config
        .peers
        .iter()
        .flat_map(|peer| peer.allowed_ips.clone());
    peers.chain(doctor).collect()
}

/// The client's one peer, the server, at `endpoint`. A client keeps its
/// session alive every [`CLIENT_KEEPALIVE`] seconds unless its config says
/// otherwise, so the server can reach it behind its NAT.
fn client_peer(server: &PeerConfig, endpoint: Option<SocketAddrV4>) -> Peer {
    let mut peer = peer(server);
    peer.endpoint = endpoint.map(Into::into);
    peer.keepalive = Some(client_keepalive(server));
    peer
}

/// The keepalive of a client's session in seconds: 0 turns it off.
pub const CLIENT_KEEPALIVE: u16 = 25;

pub fn client_keepalive(server: &PeerConfig) -> u16 {
    server.keepalive.unwrap_or(CLIENT_KEEPALIVE)
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
    udp: BoundUdp,
    port: u16,
    peers: Vec<Peer>,
    tun_tx: Tx,
    tun_rx: Rx,
) -> Result<Device<(BoundUdp, Tx, Rx)>> {
    // gotatun binds its socket only when it has a peer, and STUN needs that socket.
    if peers.is_empty() {
        return Err(Error::new(
            "TUNNEL_NO_PEERS",
            "the config has no peer and no doctor, so the tunnel would serve nobody",
        ));
    }
    let name = udp.interface().to_string();
    DeviceBuilder::new()
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
        })
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
