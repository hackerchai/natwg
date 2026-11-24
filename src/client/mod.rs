//! The long-running client. It keeps a tunnel to the server up on the
//! current uplink, points it at the endpoint that the TXT record names, and
//! writes the status file. A tunnel that dies or loses its uplink is torn
//! down and built again.

pub mod resolve;
pub mod uplink;

use crate::Result;
use crate::config::{ClientConfig, Config};
use crate::server::peer_status;
use crate::status::{self, ClientRole, ClientStatus};
use crate::tunnel::{self, PeerStats};
use crate::wire::transport::BoundInterface;
use std::{
    future::Future,
    net::SocketAddrV4,
    path::PathBuf,
    pin::{Pin, pin},
    time::{Duration, SystemTime},
};
use tokio::time::{Instant, MissedTickBehavior};
use uplink::Uplink;

const FIRST_BACKOFF: Duration = Duration::from_secs(1);
const MAX_BACKOFF: Duration = Duration::from_secs(60);
const HANDSHAKE_CHECK: Duration = Duration::from_secs(1);
const HANDSHAKE_STALE: Duration = Duration::from_secs(status::HANDSHAKE_STALE_AFTER);
// A wall clock that ran this much further than the monotonic clock between
// two looks at the uplink means the host slept, and the monotonic clock,
// which WireGuard's timers run on, stood still meanwhile.
const SLEPT_AFTER: Duration = Duration::from_secs(20);

/// What the supervisor needs of the client's WireGuard device. natwg runs a
/// [`tunnel::Client`], and tests run a device without a TUN.
pub trait Device {
    /// Resolve when the device can carry no more traffic.
    fn failed(&mut self) -> impl Future<Output = ()>;

    /// The TUN the device reads and writes, if it has one.
    fn tun(&self) -> Option<&str>;

    /// What the device knows about the server.
    fn server(&self) -> impl Future<Output = Option<PeerStats>>;

    /// Send the server's traffic to `endpoint` with a fresh handshake.
    fn point(&self, endpoint: SocketAddrV4) -> impl Future<Output = Result<()>>;

    /// Bind the UDP socket again and start a fresh handshake.
    fn rebind(&self) -> impl Future<Output = Result<()>>;

    fn stop(self) -> impl Future<Output = ()>;
}

impl Device for tunnel::Client {
    async fn failed(&mut self) {
        tunnel::Client::failed(self).await;
    }

    fn tun(&self) -> Option<&str> {
        Some(self.tun_name())
    }

    async fn server(&self) -> Option<PeerStats> {
        tunnel::Client::server(self).await
    }

    async fn point(&self, endpoint: SocketAddrV4) -> Result<()> {
        tunnel::Client::point(self, endpoint).await
    }

    async fn rebind(&self) -> Result<()> {
        tunnel::Client::rebind(self).await
    }

    async fn stop(self) {
        tunnel::Client::stop(self).await;
    }
}

/// How often the client does what, and the DNS port it asks. Tests make them
/// short.
#[derive(Clone, Debug)]
pub struct Options {
    pub dns_port: u16,
    /// How long one DNS server may take to answer.
    pub dns_timeout: Duration,
    /// How often the TXT record is looked up once there is an endpoint.
    pub lookup_every: Duration,
    /// How soon the TXT record is looked up again while there is no
    /// endpoint. The pause doubles up to `lookup_every`.
    pub retry_every: Duration,
    /// How often the uplink is looked up.
    pub watch_every: Duration,
    pub status_every: Duration,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            dns_port: 53,
            dns_timeout: Duration::from_secs(2),
            lookup_every: Duration::from_secs(60),
            retry_every: Duration::from_secs(5),
            watch_every: Duration::from_secs(5),
            status_every: Duration::from_secs(10),
        }
    }
}

/// Serve the client of `config` until `stop` resolves. `find_uplink` looks
/// up the configured interface, or the physical one of the default route,
/// and `build` starts the device on it, pointed at the endpoint known so far.
/// When the device dies or its uplink changes, it runs again after a pause
/// that doubles from 1 s up to 60 s while rebuilds keep failing or dying
/// young, and that ends early when the uplink changes. Only a failure of the
/// first build ends the client.
pub async fn run<D: Device>(
    config: &Config,
    options: &Options,
    find_uplink: impl Fn(Option<&str>) -> Result<Uplink>,
    build: impl AsyncFn(&Config, &Uplink, Option<SocketAddrV4>) -> Result<D>,
    stop: impl Future<Output = ()>,
) -> Result<()> {
    let (client, server) = config.client()?;
    let resolvers = match &client.resolvers[..] {
        [] => &resolve::DEFAULT_RESOLVERS[..],
        configured => configured,
    };
    let supervisor = Supervisor {
        config,
        client,
        options,
        find_uplink,
        resolvers: resolvers
            .iter()
            .map(|&ip| SocketAddrV4::new(ip, options.dns_port))
            .collect(),
        keepalive: tunnel::client_keepalive(server),
        endpoint: server.endpoint.map(|addr| Endpoint {
            addr,
            since: SystemTime::now(),
        }),
        looked_up: None,
        lookup_error: None,
        rebuilds: 0,
        status: status::client_path(client),
    };
    supervisor.run(build, stop).await
}

struct Endpoint {
    addr: SocketAddrV4,
    since: SystemTime,
}

struct Supervisor<'a, F> {
    config: &'a Config,
    client: &'a ClientConfig,
    options: &'a Options,
    find_uplink: F,
    resolvers: Vec<SocketAddrV4>,
    keepalive: u16,
    endpoint: Option<Endpoint>,
    looked_up: Option<SystemTime>,
    lookup_error: Option<String>,
    rebuilds: u32,
    status: PathBuf,
}

enum Exit {
    Stopped,
    Died(String),
}

impl<F: Fn(Option<&str>) -> Result<Uplink>> Supervisor<'_, F> {
    fn uplink(&self) -> Result<Uplink> {
        (self.find_uplink)(self.client.iface.as_deref())
    }

    fn endpoint(&self) -> Option<SocketAddrV4> {
        self.endpoint.as_ref().map(|endpoint| endpoint.addr)
    }

    async fn run<D: Device>(
        mut self,
        build: impl AsyncFn(&Config, &Uplink, Option<SocketAddrV4>) -> Result<D>,
        stop: impl Future<Output = ()>,
    ) -> Result<()> {
        let mut stop = pin!(stop);
        let mut uplink = self.uplink()?;
        let mut building = Instant::now();
        let mut device = tokio::select! {
            built = build(self.config, &uplink, self.endpoint()) => built?,
            () = stop.as_mut() => return Ok(()),
        };
        let mut backoff = FIRST_BACKOFF;
        loop {
            let started = Instant::now();
            let exit = self
                .serve(&mut device, &mut uplink, building, stop.as_mut())
                .await;
            device.stop().await;
            let Exit::Died(reason) = exit else {
                tracing::info!("stopped");
                return Ok(());
            };
            tracing::warn!("{reason}");
            if started.elapsed() >= MAX_BACKOFF {
                backoff = FIRST_BACKOFF;
            }
            (device, uplink) = loop {
                self.write_status(None, None, None);
                let seen = self.uplink().ok();
                tracing::info!(
                    "rebuilding the tunnel in {} s, or once the uplink changes",
                    backoff.as_secs()
                );
                tokio::select! {
                    () = tokio::time::sleep(backoff) => {}
                    () = self.uplink_changes(seen.as_ref()) => {}
                    () = stop.as_mut() => return Ok(()),
                }
                backoff = (backoff * 2).min(MAX_BACKOFF);
                let uplink = match self.uplink() {
                    Ok(uplink) => uplink,
                    Err(error) => {
                        tracing::warn!("{error}");
                        continue;
                    }
                };
                building = Instant::now();
                let built = tokio::select! {
                    built = build(self.config, &uplink, self.endpoint()) => built,
                    () = stop.as_mut() => return Ok(()),
                };
                match built {
                    Ok(device) => break (device, uplink),
                    Err(error) => tracing::warn!("{error}"),
                }
            };
            self.rebuilds += 1;
        }
    }

    /// Resolve once the uplink differs from `seen`.
    async fn uplink_changes(&self, seen: Option<&Uplink>) {
        loop {
            tokio::time::sleep(self.options.watch_every).await;
            if self.uplink().ok().as_ref() != seen {
                return;
            }
        }
    }

    /// Run one tunnel, whose build began at `building`, until it dies, its
    /// uplink changes, or `stop` resolves. A new address on the same uplink,
    /// or a wake from sleep, only binds the socket again.
    async fn serve<D: Device>(
        &mut self,
        device: &mut D,
        uplink: &mut Uplink,
        building: Instant,
        mut stop: Pin<&mut impl Future<Output = ()>>,
    ) -> Exit {
        let options = self.options;
        let tun = device.tun().unwrap_or("no TUN").to_owned();
        tracing::info!("tunnel up on {tun} via {uplink}");
        let mut lookup_at = Instant::now();
        let mut watch =
            tokio::time::interval_at(Instant::now() + options.watch_every, options.watch_every);
        let mut status_tick = tokio::time::interval(options.status_every);
        let mut handshake_tick = tokio::time::interval(HANDSHAKE_CHECK);
        for tick in [&mut watch, &mut status_tick, &mut handshake_tick] {
            tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
        }
        let mut clock = Clock::now();
        // Since when the device waits for a handshake, and whether it was
        // reported. A handshake can complete before the device's build or
        // the change of its endpoint returns.
        let mut pointed_at = building;
        let mut greeted = false;
        let mut retry = options.retry_every;
        loop {
            tokio::select! {
                () = device.failed() => {
                    return Exit::Died(format!("the WireGuard device on {tun} stopped, because its TUN or its UDP socket failed"));
                }
                () = stop.as_mut() => return Exit::Stopped,
                () = tokio::time::sleep_until(lookup_at), if self.client.record.is_some() => {
                    let found = tokio::select! {
                        found = self.lookup(&uplink.iface) => found,
                        () = stop.as_mut() => return Exit::Stopped,
                    };
                    if let Some(endpoint) = found {
                        (pointed_at, greeted) = (Instant::now(), false);
                        if let Err(error) = device.point(endpoint).await {
                            return Exit::Died(error.to_string());
                        }
                        status_tick.reset_immediately();
                    }
                    // Without an endpoint the client asks again soon, then
                    // less often while the record stays missing.
                    let every = match self.endpoint {
                        Some(_) => options.lookup_every,
                        None => {
                            let next = (retry * 2).min(options.lookup_every);
                            std::mem::replace(&mut retry, next)
                        }
                    };
                    lookup_at = Instant::now() + every;
                }
                _ = watch.tick() => {
                    let now = match self.uplink() {
                        Ok(now) => now,
                        Err(error) => return Exit::Died(format!("lost the uplink {uplink}: {error}")),
                    };
                    if now.iface != uplink.iface {
                        return Exit::Died(format!("the uplink moved from {uplink} to {now}"));
                    }
                    let why = match clock.slept() {
                        Some(gap) => format!("woke after about {} s asleep", gap.as_secs()),
                        None if now.address != uplink.address => format!("the uplink is now {now}"),
                        None => continue,
                    };
                    tracing::info!("{why}; binding the UDP socket again");
                    (pointed_at, greeted) = (Instant::now(), false);
                    if let Err(error) = device.rebind().await {
                        return Exit::Died(error.to_string());
                    }
                    *uplink = now;
                    lookup_at = Instant::now();
                    status_tick.reset_immediately();
                }
                _ = handshake_tick.tick(), if !greeted => {
                    let since = pointed_at.elapsed();
                    let shook = device.server().await.and_then(|server| server.last_handshake);
                    if shook.is_some_and(|ago| ago <= since) {
                        let endpoint = self.endpoint().map_or("no endpoint".to_owned(), |e| e.to_string());
                        tracing::info!("handshake ok with the server at {endpoint}");
                        greeted = true;
                        status_tick.reset_immediately();
                    }
                }
                _ = status_tick.tick() => {
                    if let Some(tun) = device.tun()
                        && BoundInterface::lookup(tun).is_err()
                    {
                        return Exit::Died(format!("the TUN {tun} is gone"));
                    }
                    let server = device.server().await;
                    let ago = server.as_ref().and_then(|server| server.last_handshake);
                    let stale = self.keepalive > 0
                        && ago.unwrap_or(pointed_at.elapsed()) > HANDSHAKE_STALE;
                    if stale && greeted {
                        let endpoint = self.endpoint().map_or("no endpoint".to_owned(), |e| e.to_string());
                        tracing::warn!("no handshake with the server at {endpoint} for {} s", HANDSHAKE_STALE.as_secs());
                        greeted = false;
                    }
                    self.write_status(device.tun(), Some(uplink), server);
                }
            }
        }
    }

    /// Ask the resolvers for the TXT record, and return the endpoint it names
    /// when that is a new one. A failed lookup keeps the endpoint.
    async fn lookup(&mut self, iface: &BoundInterface) -> Option<SocketAddrV4> {
        let record = self.client.record.as_deref()?;
        let timeout = self.options.dns_timeout;
        match resolve::lookup(iface, &self.resolvers, record, timeout).await {
            Err(error) => {
                let kept = match self.endpoint() {
                    Some(endpoint) => format!("keeping {endpoint}"),
                    None => "no endpoint yet".to_owned(),
                };
                tracing::warn!("{error}; {kept}");
                self.lookup_error = Some(error.to_string());
                None
            }
            Ok((addr, resolver)) => {
                let now = SystemTime::now();
                self.looked_up = Some(now);
                if self.lookup_error.take().is_some() {
                    tracing::info!("the TXT lookup works again");
                }
                if self.endpoint() == Some(addr) {
                    return None;
                }
                let old = self
                    .endpoint()
                    .map_or("none".to_owned(), |endpoint| endpoint.to_string());
                tracing::info!("endpoint {old} -> {addr} from {record} via {resolver}");
                self.endpoint = Some(Endpoint { addr, since: now });
                Some(addr)
            }
        }
    }

    fn write_status(&self, tun: Option<&str>, uplink: Option<&Uplink>, server: Option<PeerStats>) {
        let now = SystemTime::now();
        let status = ClientStatus {
            role: ClientRole::Client,
            updated: status::unix(now),
            pid: std::process::id(),
            uplink: uplink.map(|uplink| uplink.iface.to_string()),
            uplink_address: uplink.and_then(|uplink| uplink.address),
            tun: tun.map(str::to_owned),
            record: self.client.record.clone(),
            endpoint: self.endpoint(),
            endpoint_since: self
                .endpoint
                .as_ref()
                .map(|endpoint| status::unix(endpoint.since)),
            looked_up: self.looked_up.map(status::unix),
            lookup_error: self.lookup_error.clone(),
            keepalive: self.keepalive,
            rebuilds: self.rebuilds,
            server: server.map(|server| peer_status(server, now)),
        };
        if let Err(error) = status.write(&self.status) {
            tracing::warn!("{error}");
        }
    }
}

/// The wall clock and the monotonic clock at one look.
struct Clock {
    wall: SystemTime,
    monotonic: std::time::Instant,
}

impl Clock {
    fn now() -> Self {
        Self {
            wall: SystemTime::now(),
            monotonic: std::time::Instant::now(),
        }
    }

    /// How much further the wall clock ran than the monotonic clock since
    /// the last look, when that much means the host slept.
    fn slept(&mut self) -> Option<Duration> {
        let now = Self::now();
        let wall = now.wall.duration_since(self.wall).unwrap_or_default();
        let monotonic = now.monotonic.duration_since(self.monotonic);
        *self = now;
        wall.checked_sub(monotonic)
            .filter(|gap| *gap >= SLEPT_AFTER)
    }
}
