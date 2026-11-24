//! A TUN made of two in-memory queues, for a device whose IP packets belong
//! to the caller and not to the kernel.

use gotatun::packet::{Ip, Packet, PacketBufPool};
use gotatun::tun::{IpRecv, IpSend, MtuWatcher};
use std::io;
use tokio::sync::mpsc;

/// Packets the device decrypted, on their way to the caller.
pub(super) struct ChannelSend(pub mpsc::Sender<Packet<Ip>>);

/// Packets the caller wants encrypted.
pub(super) struct ChannelRecv {
    pub packets: mpsc::Receiver<Packet<Ip>>,
    pub mtu: u16,
}

impl IpSend for ChannelSend {
    async fn send(&mut self, packet: Packet<Ip>) -> io::Result<()> {
        // A full queue drops the packet, as a TUN does. Waiting for the
        // caller here would stop the device for every peer.
        let _ = self.0.try_send(packet);
        Ok(())
    }
}

impl IpRecv for ChannelRecv {
    async fn recv<'a>(
        &'a mut self,
        _pool: &mut PacketBufPool,
    ) -> io::Result<impl Iterator<Item = Packet<Ip>> + Send + 'a> {
        let packet = self.packets.recv().await.ok_or_else(|| {
            io::Error::new(io::ErrorKind::UnexpectedEof, "the packet queue closed")
        })?;
        Ok(std::iter::once(packet))
    }

    fn mtu(&self) -> MtuWatcher {
        MtuWatcher::new(self.mtu)
    }
}
