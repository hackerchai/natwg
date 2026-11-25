//! Observe only inner IP packets. WireGuard never delivers its keepalives,
//! handshakes or retries to this interface.
use gotatun::packet::{Ip, Packet, PacketBufPool};
use gotatun::tun::{IpRecv, IpSend, MtuWatcher, tun_async_device::TunDevice};
use ipnetwork::Ipv4Network;
use std::{
    io,
    net::IpAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

pub(super) struct Activity {
    seen: AtomicBool,
    allowed: Vec<Ipv4Network>,
}

impl Activity {
    pub fn new(allowed: &[Ipv4Network]) -> Self {
        Self {
            seen: AtomicBool::new(false),
            allowed: allowed.to_vec(),
        }
    }

    pub fn take(&self) -> bool {
        self.seen.swap(false, Ordering::Relaxed)
    }

    fn outbound(&self, destination: Option<IpAddr>) {
        // Linux can put IPv6 router solicitations on an otherwise idle TUN.
        // Count only IP traffic this WireGuard peer can actually carry.
        if let Some(IpAddr::V4(addr)) = destination
            && self.allowed.iter().any(|net| net.contains(addr))
        {
            self.seen.store(true, Ordering::Relaxed);
        }
    }
}

#[derive(Clone)]
pub(super) struct ClientTun {
    pub tun: TunDevice,
    pub traffic: Option<Arc<Activity>>,
}

impl IpSend for ClientTun {
    async fn send(&mut self, packet: Packet<Ip>) -> io::Result<()> {
        self.tun.send(packet).await?;
        if let Some(traffic) = &self.traffic {
            traffic.seen.store(true, Ordering::Relaxed);
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
        Ok(packets.inspect(|packet| {
            if let Some(traffic) = &self.traffic {
                traffic.outbound(packet.destination());
            }
        }))
    }

    fn mtu(&self) -> MtuWatcher {
        self.tun.mtu()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_outbound_destinations_owned_by_the_peer_count_as_demand() {
        let traffic = Activity::new(&["10.77.0.0/24".parse().unwrap()]);
        for dst in ["ff02::2", "224.0.0.1", "192.0.2.1"] {
            traffic.outbound(Some(dst.parse().unwrap()));
            assert!(!traffic.take());
        }
        traffic.outbound(Some("10.77.0.1".parse().unwrap()));
        assert!(traffic.take());
        assert!(!traffic.take());
    }
}
