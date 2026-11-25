//! The UDP socket that STUN and WireGuard share. It is bound to the uplink
//! interface, so a VPN app's TUN routes never carry it and the public mapping
//! STUN reports is the one peers reach.

use crate::wire::stun::{self, TransactionId};
use crate::{Error, Result};
use gotatun::packet::{Packet, PacketBufPool};
use gotatun::udp::{UdpRecv, UdpSend, UdpTransportFactory, UdpTransportFactoryParams};
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    ffi::CString,
    fmt, io,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    num::NonZeroU32,
    sync::{Arc, Mutex, MutexGuard, PoisonError, Weak},
    time::Duration,
};
use tokio::time::Instant;
use tokio::{
    net::UdpSocket,
    sync::{oneshot, watch},
};

const REBIND_ATTEMPTS: u32 = 40;
const REBIND_PAUSE: Duration = Duration::from_millis(5);

/// The Binding request that the [`StunPort`] waits for. Only the answer with
/// its transaction id, from its server, reaches `reply`.
struct Pending {
    id: TransactionId,
    server: SocketAddrV4,
    reply: oneshot::Sender<SocketAddrV4>,
}

#[derive(Clone, Default)]
struct Slot(Arc<Mutex<Option<Pending>>>);

impl Slot {
    fn lock(&self) -> MutexGuard<'_, Option<Pending>> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn answer(&self, id: TransactionId, source: SocketAddr, mapping: SocketAddrV4) {
        let asked = |pending: &mut Pending| pending.id == id && source == pending.server.into();
        if let Some(pending) = self.lock().take_if(asked) {
            let _ = pending.reply.send(mapping);
        }
    }
}

/// A network interface that existed when it was looked up.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BoundInterface {
    name: String,
    index: NonZeroU32,
}

impl BoundInterface {
    pub fn lookup(name: &str) -> Result<Self> {
        let not_found = || {
            Error::new(
                "IFACE_NOT_FOUND",
                format!("no network interface named {name:?}"),
            )
        };
        let c_name = CString::new(name).map_err(|_| not_found())?;
        let index = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
        Ok(Self {
            name: name.to_owned(),
            index: NonZeroU32::new(index).ok_or_else(not_found)?,
        })
    }
}

impl fmt::Display for BoundInterface {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.name)
    }
}

/// A nonblocking IPv4 UDP socket on `0.0.0.0:port` that sends and receives only
/// through `iface` (`IP_BOUND_IF` on macOS, `SO_BINDTOIFINDEX` on Linux).
pub fn bound_udp_socket(iface: &BoundInterface, port: u16) -> io::Result<std::net::UdpSocket> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.bind_device_by_index_v4(Some(iface.index))?;
    socket.set_nonblocking(true)?;
    socket.bind(&SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port).into())?;
    Ok(socket.into())
}

/// A blocking TCP connection to `address` through `iface`, for a request
/// that cannot wait for a runtime, such as a cleanup while a panic unwinds.
pub fn bound_tcp_connect(
    iface: &BoundInterface,
    address: SocketAddrV4,
    timeout: Duration,
) -> io::Result<std::net::TcpStream> {
    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
    socket.bind_device_by_index_v4(Some(iface.index))?;
    socket.connect_timeout(&address.into(), timeout)?;
    socket.set_read_timeout(Some(timeout))?;
    socket.set_write_timeout(Some(timeout))?;
    Ok(socket.into())
}

/// gotatun's UDP transport on one interface. Every socket it binds also carries
/// STUN. The answer to the pending Binding request goes to the [`StunPort`],
/// other Binding success responses are dropped, and everything else goes to
/// gotatun.
pub struct BoundUdp {
    iface: BoundInterface,
    observation: Option<watch::Sender<Option<watch::Receiver<HandshakeFlight>>>>,
    socket: watch::Sender<Weak<UdpSocket>>,
    pending: Slot,
}

/// Sends STUN Binding requests on the socket [`BoundUdp`] bound last.
pub struct StunPort {
    socket: watch::Receiver<Weak<UdpSocket>>,
    pending: Slot,
}

impl BoundUdp {
    pub fn new(iface: BoundInterface) -> (Self, StunPort) {
        let (socket_tx, socket_rx) = watch::channel(Weak::new());
        let pending = Slot::default();
        let udp = Self {
            iface,
            observation: None,
            socket: socket_tx,
            pending: pending.clone(),
        };
        let stun = StunPort {
            socket: socket_rx,
            pending,
        };
        (udp, stun)
    }
}

/// A locally generated WireGuard initiation. A second one to the same
/// endpoint within the retry window is evidence of an unanswered attempt.
#[derive(Clone, Copy, Debug)]
pub struct Initiation {
    pub at: Instant,
    pub destination: SocketAddr,
    pub retry: bool,
}

impl Initiation {
    // WireGuard retries in 5 s plus jitter. A new healthy session normally
    // rekeys after at least 120 s.
    pub(crate) const RETRY_WINDOW: Duration = Duration::from_secs(15);
}

/// Observations from one binding of the client socket. A new bind starts an
/// independent flight, even while a send task on the old socket is unwinding.
#[derive(Clone, Copy, Debug, Default)]
pub struct HandshakeFlight {
    pub pending: Option<Initiation>,
    pub confirmed: Option<Instant>,
}

impl HandshakeFlight {
    fn initiated(&mut self, at: Instant, destination: SocketAddr) {
        let retry = self.pending.is_some_and(|i| {
            i.destination == destination && at.duration_since(i.at) < Initiation::RETRY_WINDOW
        });
        self.pending = Some(Initiation {
            at,
            destination,
            retry,
        });
    }
}

pub(crate) type SocketFlights = watch::Receiver<Option<watch::Receiver<HandshakeFlight>>>;

impl BoundUdp {
    pub(crate) fn interface(&self) -> &BoundInterface {
        &self.iface
    }

    pub(crate) fn observe_handshakes(&mut self) -> SocketFlights {
        let (tx, rx) = watch::channel(None);
        self.observation = Some(tx);
        rx
    }
}

impl UdpTransportFactory for BoundUdp {
    type Send = BoundSend;
    type Recv = BoundRecv;

    async fn bind(
        &mut self,
        params: &UdpTransportFactoryParams,
    ) -> io::Result<(BoundSend, BoundRecv)> {
        let socket = bind_retrying(&self.iface, params.port).await?;
        let socket = Arc::new(UdpSocket::from_std(socket)?);
        self.socket.send_replace(Arc::downgrade(&socket));
        let recv = BoundRecv {
            socket: socket.clone(),
            pending: self.pending.clone(),
        };
        Ok((
            BoundSend {
                socket,
                flight: self.observation.as_ref().map(|observation| {
                    let (tx, rx) = watch::channel(HandshakeFlight::default());
                    observation.send_replace(Some(rx));
                    tx
                }),
            },
            recv,
        ))
    }
}

// gotatun aborts the tasks that hold its previous socket without awaiting them,
// so on a multi-threaded runtime that socket can still own the port for a few
// milliseconds after gotatun asks for the same port again.
async fn bind_retrying(iface: &BoundInterface, port: u16) -> io::Result<std::net::UdpSocket> {
    let mut attempts = 0;
    loop {
        match bound_udp_socket(iface, port) {
            Err(e)
                if e.kind() == io::ErrorKind::AddrInUse
                    && port != 0
                    && attempts < REBIND_ATTEMPTS =>
            {
                attempts += 1;
                tokio::time::sleep(REBIND_PAUSE).await;
            }
            result => return result,
        }
    }
}

#[derive(Clone)]
pub struct BoundSend {
    socket: Arc<UdpSocket>,
    flight: Option<watch::Sender<HandshakeFlight>>,
}

impl UdpSend for BoundSend {
    type SendManyBuf = ();

    async fn send_to(&self, packet: Packet, destination: SocketAddr) -> io::Result<()> {
        if let Some(flight) = &self.flight {
            if packet.starts_with(&1u32.to_le_bytes()) {
                flight.send_modify(|f| f.initiated(Instant::now(), destination));
            } else if packet.len() == 32
                && packet.starts_with(&4u32.to_le_bytes())
                && packet[8..16] == [0; 8]
            {
                // gotatun confirms an authenticated handshake response with
                // the new session's empty transport packet, counter zero.
                // Later persistent keepalives use increasing counters.
                flight.send_modify(|f| {
                    f.pending = None;
                    f.confirmed = Some(Instant::now());
                });
            }
        }
        self.socket.send_to(&packet, destination).await.map(drop)
    }

    fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
        self.socket.local_addr().map(Some)
    }
}

pub struct BoundRecv {
    socket: Arc<UdpSocket>,
    pending: Slot,
}

impl UdpRecv for BoundRecv {
    type RecvManyBuf = ();

    async fn recv_from(&mut self, pool: &mut PacketBufPool) -> io::Result<(Packet, SocketAddr)> {
        loop {
            let mut packet = pool.get();
            let (len, source) = self.socket.recv_from(&mut packet).await?;
            packet.truncate(len);
            if !stun::is_stun_binding_success(&packet) {
                return Ok((packet, source));
            }
            if let Some((id, mapping)) = stun::parse_binding_success(&packet) {
                self.pending.answer(id, source, mapping);
            }
        }
    }
}

impl StunPort {
    /// Bind `port` on `iface` through [`BoundUdp`] with no WireGuard device behind
    /// it, and drop every datagram that is not a STUN answer. The socket stays
    /// open until the tokio runtime stops.
    pub async fn bind(iface: BoundInterface, port: u16) -> Result<Self> {
        let name = iface.to_string();
        let (mut udp, stun) = BoundUdp::new(iface);
        let params = UdpTransportFactoryParams {
            addr: None,
            port,
            #[cfg(target_os = "linux")]
            fwmark: None,
        };
        let (_, mut recv) = udp
            .bind(&params)
            .await
            .map_err(|e| Error::new("UDP_BIND", format!("{name} udp/{port}: {e}")))?;
        tokio::spawn(async move {
            let mut pool = PacketBufPool::new(1);
            while recv.recv_from(&mut pool).await.is_ok() {}
        });
        Ok(stun)
    }

    /// Wait until the shared socket is bound. gotatun binds it when the
    /// device starts and again when it rebinds.
    pub async fn wait_bound(&mut self) -> Result<()> {
        self.socket
            .wait_for(|socket| socket.strong_count() > 0)
            .await
            .map(drop)
            .map_err(|_| Error::new("STUN_NO_SOCKET", "the WireGuard device stopped"))
    }

    /// Ask `server` for the public mapping of the shared socket. Answers to
    /// earlier requests, and answers from any other address, are ignored.
    pub async fn binding(
        &mut self,
        server: SocketAddrV4,
        timeout: Duration,
    ) -> Result<SocketAddrV4> {
        let id = TransactionId(super::random()?);
        let socket =
            self.socket.borrow().upgrade().ok_or_else(|| {
                Error::new("STUN_NO_SOCKET", "the shared UDP socket is not bound")
            })?;
        let (reply, answer) = oneshot::channel();
        *self.pending.lock() = Some(Pending { id, server, reply });
        let sent = socket.send_to(&stun::binding_request(id), server).await;
        // Holding the socket while waiting would stop gotatun from rebinding its port.
        drop(socket);
        let mapping = match sent {
            Ok(_) => tokio::time::timeout(timeout, answer).await,
            Err(e) => {
                self.pending.lock().take();
                return Err(Error::new("STUN_SEND", format!("{server}: {e}")));
            }
        };
        self.pending.lock().take();
        mapping.ok().and_then(|reply| reply.ok()).ok_or_else(|| {
            Error::new(
                "STUN_TIMEOUT",
                format!("no answer from {server} within {} ms", timeout.as_millis()),
            )
        })
    }
}
