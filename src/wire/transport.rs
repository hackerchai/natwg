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
    sync::{Arc, Weak},
    time::Duration,
};
use tokio::{
    net::UdpSocket,
    sync::{mpsc, watch},
};

const ANSWER_QUEUE: usize = 16;
const REBIND_ATTEMPTS: u32 = 40;
const REBIND_PAUSE: Duration = Duration::from_millis(5);

type Answer = (TransactionId, SocketAddrV4);

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

/// gotatun's UDP transport on one interface. Every socket it binds also carries
/// STUN. Binding success responses go to the [`StunPort`] and everything else
/// to gotatun.
pub struct BoundUdp {
    iface: BoundInterface,
    socket: watch::Sender<Weak<UdpSocket>>,
    answers: mpsc::Sender<Answer>,
}

/// Sends STUN Binding requests on the socket [`BoundUdp`] bound last.
pub struct StunPort {
    socket: watch::Receiver<Weak<UdpSocket>>,
    answers: mpsc::Receiver<Answer>,
}

impl BoundUdp {
    pub fn new(iface: BoundInterface) -> (Self, StunPort) {
        let (socket_tx, socket_rx) = watch::channel(Weak::new());
        let (answers_tx, answers_rx) = mpsc::channel(ANSWER_QUEUE);
        let udp = Self {
            iface,
            socket: socket_tx,
            answers: answers_tx,
        };
        let stun = StunPort {
            socket: socket_rx,
            answers: answers_rx,
        };
        (udp, stun)
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
            answers: self.answers.clone(),
        };
        Ok((BoundSend(socket), recv))
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
pub struct BoundSend(Arc<UdpSocket>);

impl UdpSend for BoundSend {
    type SendManyBuf = ();

    async fn send_to(&self, packet: Packet, destination: SocketAddr) -> io::Result<()> {
        self.0.send_to(&packet, destination).await.map(drop)
    }

    fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
        self.0.local_addr().map(Some)
    }
}

pub struct BoundRecv {
    socket: Arc<UdpSocket>,
    answers: mpsc::Sender<Answer>,
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
            if let Some(answer) = stun::parse_binding_success(&packet) {
                let _ = self.answers.try_send(answer);
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

    /// Ask `server` for the public mapping of the shared socket. Answers to
    /// earlier requests are ignored.
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
        socket
            .send_to(&stun::binding_request(id), server)
            .await
            .map_err(|e| Error::new("STUN_SEND", format!("{server}: {e}")))?;
        // Holding the socket while waiting would stop gotatun from rebinding its port.
        drop(socket);
        let answer = async {
            while let Some((answer, mapping)) = self.answers.recv().await {
                if answer == id {
                    return Some(mapping);
                }
            }
            None
        };
        tokio::time::timeout(timeout, answer)
            .await
            .ok()
            .flatten()
            .ok_or_else(|| {
                Error::new(
                    "STUN_TIMEOUT",
                    format!("no answer from {server} within {} ms", timeout.as_millis()),
                )
            })
    }
}
