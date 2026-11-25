//! The long-running client. It keeps a tunnel to the server up on the
//! current uplink, points it at the endpoint that the TXT record names, or
//! at the A record of the server's name, and writes the status file. A
//! tunnel that dies or loses its uplink is torn down and built again.

pub mod resolve;
mod routes;
mod schedule;
pub mod uplink;
pub mod wg_quick;

use crate::Result;
use crate::config::{ClientConfig, Config};
use crate::netcfg;
use crate::server::peer_status;
use crate::status::{self, ClientRole, ClientStatus, PeerStatus};
use crate::tunnel::{self, PeerStats};
use crate::wire::transport::{BoundInterface, HandshakeFlight};
use ipnetwork::Ipv4Network;
use resolve::Lookup;
use schedule::{Handshake, Keepalive, Lookups};
use std::{
    borrow::Cow,
    future::Future,
    net::SocketAddrV4,
    path::PathBuf,
    pin::{Pin, pin},
    time::{Duration, SystemTime},
};
use tokio::sync::watch;
use tokio::time::Instant;
use uplink::Uplink;

const FIRST_BACKOFF: Duration = Duration::from_secs(1);
const MAX_BACKOFF: Duration = Duration::from_secs(60);
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

    /// Locally observed handshake attempts and authenticated completions on this binding.
    fn flights(&self) -> Option<watch::Receiver<HandshakeFlight>> {
        None
    }
    /// Whether an inner IP packet crossed the TUN since the last sample.
    fn take_traffic(&self) -> bool {
        false
    }
    /// Apply the effective keepalive without interrupting the session.
    fn set_keepalive(&self, _seconds: u16) -> impl Future<Output = Result<()>> {
        std::future::ready(Err(crate::Error::new(
            "TUNNEL_FAILED",
            "the device cannot change keepalive at runtime",
        )))
    }

    /// Send the server's traffic to `endpoint` with a fresh handshake.
    fn point(&self, endpoint: SocketAddrV4) -> impl Future<Output = Result<()>>;

    /// Reconcile a failed, roamed session with an unchanged TXT answer.
    fn restore(
        &self,
        endpoint: SocketAddrV4,
        _since: Instant,
    ) -> impl Future<Output = Result<bool>> {
        async move {
            if self
                .server()
                .await
                .is_some_and(|peer| peer.endpoint != Some(endpoint.into()))
            {
                self.point(endpoint).await?;
                return Ok(true);
            }
            Ok(false)
        }
    }

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

    fn flights(&self) -> Option<watch::Receiver<HandshakeFlight>> {
        self.flights()
    }

    fn take_traffic(&self) -> bool {
        self.take_traffic()
    }

    async fn set_keepalive(&self, seconds: u16) -> Result<()> {
        self.set_keepalive(seconds).await
    }

    async fn point(&self, endpoint: SocketAddrV4) -> Result<()> {
        tunnel::Client::point(self, endpoint).await
    }

    async fn restore(&self, endpoint: SocketAddrV4, since: Instant) -> Result<bool> {
        self.apply_endpoint(endpoint, Some(since)).await
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
    /// Healthy TXT refresh.
    pub txt_every: Duration,
    /// Hostname (A) refresh.
    pub lookup_every: Duration,
    /// How soon the record is looked up again while there is no endpoint.
    /// The pause doubles up to 60 seconds.
    pub retry_every: Duration,
    /// Fallback when the kernel sends no uplink event.
    pub watch_every: Duration,
    pub status_every: Duration,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            dns_port: 53,
            dns_timeout: Duration::from_secs(2),
            txt_every: Duration::from_secs(600),
            lookup_every: Duration::from_secs(60),
            retry_every: Duration::from_secs(5),
            watch_every: Duration::from_secs(60),
            status_every: Duration::from_secs(30),
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
    let supervisor = Supervisor {
        config,
        client,
        options,
        find_uplink,
        keepalive: Keepalive::new(
            tunnel::client_keepalive(server),
            client
                .idle_pause_minutes
                .map(|n| Duration::from_secs(u64::from(n.get()) * 60)),
        ),
        last_status: None,
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
    keepalive: Keepalive,
    last_status: Option<(Instant, ClientStatus)>,
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

    /// The server's networks that this host sits on, which the client
    /// leaves out of its routes. A change means the routes need a rebuild.
    fn local_networks(&self) -> Option<Vec<Ipv4Network>> {
        let (_, server) = self.config.client().ok()?;
        let routes: Vec<Ipv4Network> = server
            .allowed_ips
            .iter()
            .filter_map(|net| Ipv4Network::new(net.network(), net.prefix()).ok())
            .collect();
        netcfg::host_local_networks(&routes).ok()
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
        let mut routes = routes::Monitor::new(self.options.watch_every);
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
                .serve(
                    &mut device,
                    &mut uplink,
                    &mut routes,
                    building,
                    stop.as_mut(),
                )
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
                self.write_status(None, None, None, false);
                let seen = self.uplink().ok();
                tracing::info!(
                    "rebuilding the tunnel in {} s, or once the uplink changes",
                    backoff.as_secs()
                );
                let rebuild_at = Instant::now() + backoff;
                loop {
                    tokio::select! {
                        () = tokio::time::sleep_until(rebuild_at) => break,
                        () = routes.changed() => {
                            if self.uplink().ok() != seen { break; }
                        }
                        () = tokio::time::sleep_until(self.status_deadline()) => {
                            self.write_status(None, None, None, false);
                        }
                        () = stop.as_mut() => return Ok(()),
                    }
                }
                backoff = (backoff * 2).min(MAX_BACKOFF);
                let uplink = match self.uplink() {
                    Ok(uplink) => uplink,
                    Err(error) => {
                        tracing::warn!("{error}");
                        continue;
                    }
                };
                // A rebuild while paused must start with keepalives disabled.
                let mut config = Cow::Borrowed(self.config);
                self.keepalive.update(Instant::now(), false);
                if self.keepalive.effective != self.keepalive.configured {
                    config.to_mut().peers[0].keepalive = Some(self.keepalive.effective);
                }
                building = Instant::now();
                let built = tokio::select! {
                    built = build(&config, &uplink, self.endpoint()) => built,
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

    /// Run one device, using kernel events as hints to re-read the physical uplink.
    async fn serve<D: Device>(
        &mut self,
        device: &mut D,
        uplink: &mut Uplink,
        routes: &mut routes::Monitor,
        building: Instant,
        mut stop: Pin<&mut impl Future<Output = ()>>,
    ) -> Exit {
        let tun = device.tun().unwrap_or("no TUN").to_owned();
        tracing::info!("tunnel up on {tun} via {uplink}");
        let local = self.local_networks();
        let lookup = Lookup::of(self.client);
        let mut dns = Lookups::new(matches!(lookup, Some(Lookup::Txt(_))), self.options);
        let resolvers = resolve::resolvers(self.client, self.options.dns_port);
        let mut query = None;
        let mut flights = device.flights();
        let mut handshake = Handshake::new(building);
        let mut check_at = Instant::now();
        let mut server = None;
        let mut clock = Clock::now();
        let mut slept = None;
        loop {
            tokio::select! {
                () = device.failed() => {
                    return Exit::Died(format!("the WireGuard device on {tun} stopped, because its TUN or its UDP socket failed"));
                }
                () = stop.as_mut() => return Exit::Stopped,
                () = tokio::time::sleep_until(dns.at), if lookup.is_some() && query.is_none() => {
                    let iface = uplink.iface.clone();
                    let timeout = self.options.dns_timeout;
                    let resolvers = &resolvers;
                    query = lookup.map(|lookup| Box::pin(async move {
                        (lookup, lookup.endpoint(&iface, resolvers, timeout).await)
                    }));
                    continue;
                }
                (lookup, answer) = async { query.as_mut().unwrap().await }, if query.is_some() => {
                    query = None;
                    let old = self.endpoint();
                    if let Some(endpoint) = self.accept_answer(lookup, answer) {
                        let now = Instant::now();
                        let applied = if old != Some(endpoint) {
                            device.point(endpoint).await.map(|()| true)
                        } else if let Some(since) = dns.failure {
                            device.restore(endpoint, since).await
                        } else {
                            Ok(false)
                        };
                        match applied {
                            Err(error) => return Exit::Died(error.to_string()),
                            Ok(true) => {
                                if old.is_some() {
                                    handshake.moved(now);
                                }
                                dns.recovered(now);
                                server = None;
                            }
                            Ok(false) => {}
                        }
                    }
                    dns.looked_up(Instant::now(), self.endpoint.is_some(), self.lookup_error.is_none());
                }
                () = routes.changed() => {
                    let now = match self.uplink() {
                        Ok(now) => now,
                        Err(error) => return Exit::Died(format!("lost the uplink {uplink}: {error}")),
                    };
                    if now.iface != uplink.iface {
                        return Exit::Died(format!("the uplink moved from {uplink} to {now}"));
                    }
                    if let (Some(was), Some(now)) = (&local, self.local_networks())
                        && *was != now {
                        return Exit::Died("this host joined or left a network that the server routes; rebuilding the routes".to_owned());
                    }
                    let why = match slept.take().or_else(|| clock.slept(Clock::now())) {
                        Some(gap) => format!("woke after about {} s asleep", gap.as_secs()),
                        None if now.address != uplink.address => format!("the uplink is now {now}"),
                        None => continue,
                    };
                    tracing::info!("{why}; binding the UDP socket again");
                    handshake.moved(Instant::now());
                    if let Err(error) = device.rebind().await {
                        return Exit::Died(error.to_string());
                    }
                    flights = device.flights();
                    *uplink = now;
                    query = None;
                    dns = Lookups::new(matches!(lookup, Some(Lookup::Txt(_))), self.options);
                    server = None;
                }
                flight = next_flight(&mut flights) => {
                    handshake.observed(flight, &mut dns);
                }
                () = tokio::time::sleep_until(check_at) => {
                    if let Some(gap) = clock.slept(Clock::now()) {
                        slept = Some(gap);
                        routes.refresh();
                    }
                    if let Some(tun) = device.tun() && BoundInterface::lookup(tun).is_err() {
                        return Exit::Died(format!("the TUN {tun} is gone"));
                    }
                    if let Some(seconds) = self.keepalive.update(Instant::now(), device.take_traffic()) {
                        if let Err(error) = device.set_keepalive(seconds).await {
                            return Exit::Died(error.to_string());
                        }
                        tracing::info!("persistent keepalive is now {seconds}s");
                    }
                    let sample = device.server().await;
                    let ago = sample.as_ref().and_then(|s| s.last_handshake);
                    server = sample.map(|s| peer_status(s, SystemTime::now()));
                    let now = Instant::now();
                    if let Some(endpoint) = self.endpoint()
                        && handshake.sample(now, ago, self.keepalive.effective, &mut dns) {
                        tracing::info!("handshake ok with the server at {endpoint}");
                    }
                    check_at = now + handshake.interval();
                }
                () = tokio::time::sleep_until(self.status_deadline()) => {}
            }
            self.write_status(
                device.tun(),
                Some(uplink),
                server.as_ref(),
                dns.failure.is_some(),
            );
        }
    }

    /// Remember the last usable advertised endpoint across failed lookups.
    fn accept_answer(
        &mut self,
        lookup: Lookup<'_>,
        answer: Result<(SocketAddrV4, SocketAddrV4)>,
    ) -> Option<SocketAddrV4> {
        let (kind, record) = (lookup.mode().record_type(), lookup.name());
        match answer {
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
                    tracing::info!("the {kind} lookup works again");
                }
                if self.endpoint() == Some(addr) {
                    return Some(addr);
                }
                let old = self
                    .endpoint()
                    .map_or("none".to_owned(), |endpoint| endpoint.to_string());
                tracing::info!("endpoint {old} -> {addr} from {kind} {record} via {resolver}");
                self.endpoint = Some(Endpoint { addr, since: now });
                Some(addr)
            }
        }
    }

    fn status_deadline(&self) -> Instant {
        self.last_status
            .as_ref()
            .map_or_else(Instant::now, |(at, _)| *at + self.options.status_every)
    }

    fn write_status(
        &mut self,
        tun: Option<&str>,
        uplink: Option<&Uplink>,
        server: Option<&PeerStatus>,
        retrying: bool,
    ) {
        let now = SystemTime::now();
        let lookup = Lookup::of(self.client);
        let status = ClientStatus {
            role: ClientRole::Client,
            updated: status::unix(now),
            pid: std::process::id(),
            version: Some(env!("CARGO_PKG_VERSION").to_owned()),
            latest_version: crate::update::latest(),
            uplink: uplink.map(|uplink| uplink.iface.to_string()),
            uplink_address: uplink.and_then(|uplink| uplink.address),
            tun: tun.map(str::to_owned),
            record: lookup.map(|lookup| lookup.name().to_owned()),
            record_type: lookup.map(Lookup::mode),
            endpoint: self.endpoint(),
            endpoint_since: self
                .endpoint
                .as_ref()
                .map(|endpoint| status::unix(endpoint.since)),
            looked_up: self.looked_up.map(status::unix),
            lookup_error: self.lookup_error.clone(),
            keepalive: self.keepalive.effective,
            handshake_retrying: retrying,
            rebuilds: self.rebuilds,
            server: server.cloned(),
        };
        let now = Instant::now();
        if let Some((at, old)) = &self.last_status
            && now - *at < self.options.status_every
            && old.same_client_state(&status)
        {
            return;
        }
        if let Err(error) = status.write(&self.status) {
            tracing::warn!("{error}");
        }
        self.last_status = Some((now, status));
    }
}

async fn next_flight(events: &mut Option<watch::Receiver<HandshakeFlight>>) -> HandshakeFlight {
    if let Some(rx) = events
        && rx.changed().await.is_ok()
    {
        return *rx.borrow_and_update();
    }
    std::future::pending().await
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
    fn slept(&mut self, now: Self) -> Option<Duration> {
        let wall = now.wall.duration_since(self.wall).unwrap_or_default();
        let monotonic = now.monotonic.duration_since(self.monotonic);
        *self = now;
        wall.checked_sub(monotonic)
            .filter(|gap| *gap >= SLEPT_AFTER)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sleep_requires_a_new_wall_clock_gap_and_is_reported_once() {
        let start = Clock::now();
        let after = |wall, mono| Clock {
            wall: start.wall + Duration::from_secs(wall),
            monotonic: start.monotonic + Duration::from_secs(mono),
        };
        let mut clock = after(0, 0);
        assert_eq!(clock.slept(after(60, 60)), None);
        assert_eq!(clock.slept(after(95, 65)), Some(Duration::from_secs(30)));
        assert_eq!(clock.slept(after(105, 75)), None);
        assert_eq!(clock.slept(after(80, 85)), None);
    }
}
