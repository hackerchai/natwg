//! Observe only inner IP packets. WireGuard never delivers its keepalives,
//! handshakes or retries to this interface.
use gotatun::packet::{Ip, Packet, PacketBufPool};
use gotatun::tun::{IpRecv, IpSend, MtuWatcher, tun_async_device::TunDevice};
use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

#[derive(Clone)]
pub(super) struct ClientTun {
    pub tun: TunDevice,
    pub traffic: Option<Arc<AtomicBool>>,
}

impl IpSend for ClientTun {
    async fn send(&mut self, packet: Packet<Ip>) -> io::Result<()> {
        self.tun.send(packet).await?;
        if let Some(traffic) = &self.traffic {
            traffic.store(true, Ordering::Relaxed);
        }
        Ok(())
    }
}

impl IpRecv for ClientTun {
    async fn recv<'a>(
        &'a mut self,
        pool: &mut PacketBufPool,
    ) -> io::Result<impl Iterator<Item = Packet<Ip>> + 'a> {
        let packets = self.tun.recv(pool).await?;
        if let Some(traffic) = &self.traffic {
            traffic.store(true, Ordering::Relaxed);
        }
        Ok(packets)
    }

    fn mtu(&self) -> MtuWatcher {
        self.tun.mtu()
    }
}
