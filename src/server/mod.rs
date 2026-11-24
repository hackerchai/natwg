//! The long-running server. It builds the tunnel and runs the STUN keepalive,
//! the TXT publisher, the UPnP lease, the NAT re-check and the status file
//! beside it. A tunnel that dies is torn down and built again.

pub mod cloudflare;
pub mod keepalive;
pub mod upnp;

use crate::Result;
use crate::config::{Config, ServerConfig};
use crate::status::{self, PeerStatus, Status};
use crate::tunnel::{PeerStats, Tunnel};
use crate::wire::transport::{BoundInterface, StunPort};
use cloudflare::{Publish, Publisher};
use keepalive::{Health, Mapping};
use std::{
    convert::Infallible,
    future::Future,
    pin::{Pin, pin},
    time::{Duration, SystemTime},
};
use tokio::{
    sync::watch,
    time::{Instant, MissedTickBehavior},
};
use upnp::{Lease, Upnp};

/// A run of this many unanswered STUN requests counts as a dead tunnel. The
/// socket of a tunnel that outlived its uplink keeps the old interface index,
/// and its send errors never reach gotatun.
pub const DEAD_AFTER_MISSES: u32 = 10;

const STATUS_EVERY: Duration = Duration::from_secs(10);
const NAT_EVERY: Duration = Duration::from_secs(30);
const FIRST_BACKOFF: Duration = Duration::from_secs(1);
const MAX_BACKOFF: Duration = Duration::from_secs(60);

/// What the supervisor needs of a WireGuard device. natwg runs a [`Tunnel`],
/// and tests run a device without a TUN.
pub trait Device {
    /// Resolve when the device can carry no more traffic.
    fn failed(&mut self) -> impl Future<Output = ()>;

    fn peers(&self) -> impl Future<Output = Vec<PeerStats>>;

    /// The TUN the device reads and writes, if it has one.
    fn tun(&self) -> Option<&str>;

    /// Load the NAT rule again if it stopped taking effect, and say whether
    /// it had to. None for a device without NAT.
    fn ensure_nat(&mut self) -> Option<Result<bool>>;

    fn stop(self) -> impl Future<Output = Result<()>>;
}

impl Device for Tunnel {
    async fn failed(&mut self) {
        Tunnel::failed(self).await;
    }

    async fn peers(&self) -> Vec<PeerStats> {
        Tunnel::peers(self).await
    }

    fn tun(&self) -> Option<&str> {
        Some(self.tun_name())
    }

    fn ensure_nat(&mut self) -> Option<Result<bool>> {
        Some(Tunnel::ensure_nat(self))
    }

    async fn stop(self) -> Result<()> {
        Tunnel::stop(self).await
    }
}

/// Serve `config` until `stop` resolves. `build` starts the device and STUN
/// on its socket. When the device dies, it runs again with a fresh lookup of
/// the interface, after a pause that doubles from 1 s up to 60 s while
/// rebuilds keep failing or dying young. Only a failure of the first build
/// ends the server. The Cloudflare API is `cloudflare_api`, which is
/// [`cloudflare::API`] outside of tests.
pub async fn run<D: Device>(
    config: &Config,
    cloudflare_api: &str,
    build: impl AsyncFn(&Config) -> Result<(D, StunPort)>,
    stop: impl Future<Output = ()>,
) -> Result<()> {
    let server = config.server()?;
    let (mapping, mapping_rx) = watch::channel(None);
    let (publish_tx, publish) = watch::channel(Publish::Idle);
    let (lease_tx, lease) = watch::channel(None);
    let publisher = Publisher::new(&server.cloudflare, cloudflare_api)?;
    let upnp = Upnp::new(server)?;
    let supervisor = Supervisor {
        config,
        server,
        mapping,
        health: watch::Sender::new(Health::default()),
        publish,
        lease,
        rebuilds: 0,
    };
    tokio::select! {
        served = supervisor.run(build, stop) => served,
        never = publisher.run(mapping_rx, publish_tx) => match never {},
        never = renew(upnp, lease_tx) => match never {},
    }
}

async fn renew(upnp: Option<Upnp>, lease: watch::Sender<Option<Lease>>) -> Infallible {
    match upnp {
        Some(upnp) => upnp.run(lease).await,
        None => std::future::pending().await,
    }
}

struct Supervisor<'a> {
    config: &'a Config,
    server: &'a ServerConfig,
    mapping: watch::Sender<Option<Mapping>>,
    health: watch::Sender<Health>,
    publish: watch::Receiver<Publish>,
    lease: watch::Receiver<Option<Lease>>,
    rebuilds: u32,
}

enum Exit {
    Stopped,
    Died(String),
}

impl Supervisor<'_> {
    async fn run<D: Device>(
        mut self,
        build: impl AsyncFn(&Config) -> Result<(D, StunPort)>,
        stop: impl Future<Output = ()>,
    ) -> Result<()> {
        let mut stop = pin!(stop);
        let (mut device, mut stun) = tokio::select! {
            built = build(self.config) => built?,
            () = stop.as_mut() => return Ok(()),
        };
        let mut backoff = FIRST_BACKOFF;
        loop {
            let started = Instant::now();
            let exit = self.serve(&mut device, stun, stop.as_mut()).await;
            if let Err(error) = device.stop().await {
                tracing::warn!("{error}");
            }
            let Exit::Died(reason) = exit else {
                tracing::info!("stopped");
                return Ok(());
            };
            tracing::warn!("{reason}");
            if started.elapsed() >= MAX_BACKOFF {
                backoff = FIRST_BACKOFF;
            }
            (device, stun) = loop {
                self.write_status(None, Vec::new(), None);
                tracing::info!("rebuilding the tunnel in {} s", backoff.as_secs());
                tokio::select! {
                    () = tokio::time::sleep(backoff) => {}
                    () = stop.as_mut() => return Ok(()),
                }
                backoff = (backoff * 2).min(MAX_BACKOFF);
                let built = tokio::select! {
                    built = build(self.config) => built,
                    () = stop.as_mut() => return Ok(()),
                };
                match built {
                    Ok(built) => break built,
                    Err(error) => tracing::warn!("{error}"),
                }
            };
            self.rebuilds += 1;
        }
    }

    /// Run one tunnel until it dies or `stop` resolves.
    async fn serve<D: Device>(
        &self,
        device: &mut D,
        stun: StunPort,
        mut stop: Pin<&mut impl Future<Output = ()>>,
    ) -> Exit {
        // The misses of the tunnel before this one must not count against it.
        self.health.send_modify(|health| health.misses = 0);
        let mut health = self.health.subscribe();
        let server = self.server;
        let keepalive = keepalive::run(
            stun,
            &server.iface,
            &server.stun,
            &self.mapping,
            &self.health,
        );
        let mut keepalive = pin!(keepalive);
        let mut status_tick = tokio::time::interval(STATUS_EVERY);
        let mut nat_tick = tokio::time::interval(NAT_EVERY);
        for tick in [&mut status_tick, &mut nat_tick] {
            tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
        }
        let mut nat_ok = None;
        let tun = device.tun().unwrap_or("no TUN").to_owned();
        tracing::info!("tunnel up on {tun}, udp/{}", server.listen_port);
        loop {
            tokio::select! {
                () = device.failed() => {
                    return Exit::Died(format!("the WireGuard device on {tun} stopped, because its TUN or its UDP socket failed"));
                }
                _ = health.wait_for(|health| health.misses >= DEAD_AFTER_MISSES) => {
                    return Exit::Died(format!("{DEAD_AFTER_MISSES} STUN requests in a row got no answer"));
                }
                () = stop.as_mut() => return Exit::Stopped,
                never = &mut keepalive => match never {},
                _ = nat_tick.tick() => nat_ok = self.check_nat(device, nat_ok),
                _ = status_tick.tick() => {
                    if let Some(tun) = device.tun()
                        && BoundInterface::lookup(tun).is_err()
                    {
                        return Exit::Died(format!("the TUN {tun} is gone"));
                    }
                    self.write_status(device.tun(), device.peers().await, nat_ok);
                }
            }
        }
    }

    fn check_nat<D: Device>(&self, device: &mut D, before: Option<bool>) -> Option<bool> {
        let instance = &self.server.instance;
        let ok = match device.ensure_nat()? {
            Ok(restored) => {
                if restored {
                    tracing::warn!(
                        "the NAT rule of {instance} had stopped taking effect; loaded it again"
                    );
                } else if before == Some(false) {
                    tracing::info!("the NAT rule of {instance} works again");
                }
                true
            }
            Err(error) => {
                if before != Some(false) {
                    tracing::warn!("NAT check failed: {error}");
                }
                false
            }
        };
        Some(ok)
    }

    fn write_status(&self, tun: Option<&str>, peers: Vec<PeerStats>, nat_ok: Option<bool>) {
        let now = SystemTime::now();
        let mapping = *self.mapping.borrow();
        let health = *self.health.borrow();
        let lease = *self.lease.borrow();
        let publish = self.publish.borrow();
        let record = publish.record();
        let status = Status {
            updated: status::unix(now),
            pid: std::process::id(),
            iface: self.server.iface.clone(),
            listen_port: self.server.listen_port,
            tun: tun.map(str::to_owned),
            mapping: mapping.map(|mapping| mapping.addr),
            mapping_since: mapping.map(|mapping| status::unix(mapping.since)),
            last_stun_ok: health.last_ok.map(status::unix),
            stun_misses: health.misses,
            published: record.map(|record| record.value),
            published_at: record.map(|record| status::unix(record.at)),
            publish_error: publish.error().map(str::to_owned),
            upnp_ok: lease.map(|lease| lease.ok),
            upnp_at: lease.map(|lease| status::unix(lease.at)),
            nat_ok,
            rebuilds: self.rebuilds,
            peers: peers
                .into_iter()
                .map(|peer| peer_status(peer, now))
                .collect(),
        };
        drop(publish);
        if let Err(error) = status.write(&status::path(self.server)) {
            tracing::warn!("{error}");
        }
    }
}

fn peer_status(peer: PeerStats, now: SystemTime) -> PeerStatus {
    let key = peer.public_key.to_string();
    PeerStatus {
        key: format!("{}…", &key[..10]),
        endpoint: peer.endpoint,
        last_handshake: peer
            .last_handshake
            .and_then(|ago| now.checked_sub(ago))
            .map(status::unix),
        rx: peer.rx_bytes,
        tx: peer.tx_bytes,
    }
}

/// An error with the errors that caused it, such as the refused connection
/// behind reqwest's "error sending request".
fn error_chain(error: &dyn std::error::Error) -> String {
    let mut text = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        text.push_str(": ");
        text.push_str(&cause.to_string());
        source = cause.source();
    }
    text
}
