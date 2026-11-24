//! The STUN keepalive. A Binding request every `interval_secs` through the
//! shared socket keeps the carrier's mapping alive and reports where it
//! points, the way natwg.py does.

use crate::config::StunConfig;
use crate::wire::dns::{self, Record, RecordKind};
use crate::wire::stun;
use crate::wire::transport::{BoundInterface, StunPort};
use std::{
    convert::Infallible,
    net::SocketAddrV4,
    time::{Duration, SystemTime},
};
use tokio::{
    sync::watch,
    time::{Instant, MissedTickBehavior},
};

/// How long a Binding request may wait for its answer before it counts as a
/// miss.
pub const TIMEOUT: Duration = Duration::from_secs(5);

const RESOLVE_EVERY: Duration = Duration::from_secs(3600);
const DNS_TIMEOUT: Duration = Duration::from_secs(2);
const DNS_PORT: u16 = 53;
const ADDRESSES_PER_HOST: usize = 2;

/// The public address the carrier maps the shared socket to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mapping {
    pub addr: SocketAddrV4,
    /// When the keepalive first saw this address.
    pub since: SystemTime,
}

/// How the STUN servers answered lately.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Health {
    /// Binding requests in a row that got no answer.
    pub misses: u32,
    pub last_ok: Option<SystemTime>,
}

/// The STUN server addresses that the keepalive asks in turn, without end.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Targets {
    addresses: Vec<SocketAddrV4>,
    next: usize,
}

impl Targets {
    /// The first two addresses of each host, then the fallbacks, each address
    /// once, in random order.
    pub fn new(
        hosts: impl IntoIterator<Item = Vec<SocketAddrV4>>,
        fallback: &[SocketAddrV4],
    ) -> Self {
        let mut addresses = Vec::new();
        let candidates = hosts
            .into_iter()
            .flat_map(|host| host.into_iter().take(ADDRESSES_PER_HOST))
            .chain(fallback.iter().copied());
        for address in candidates {
            if !addresses.contains(&address) {
                addresses.push(address);
            }
        }
        shuffle(&mut addresses);
        Self { addresses, next: 0 }
    }

    pub fn is_empty(&self) -> bool {
        self.addresses.is_empty()
    }
}

impl Iterator for Targets {
    type Item = SocketAddrV4;

    fn next(&mut self) -> Option<SocketAddrV4> {
        let address = *self
            .addresses
            .get(self.next % self.addresses.len().max(1))?;
        self.next += 1;
        Some(address)
    }
}

fn shuffle(items: &mut [SocketAddrV4]) {
    for i in (1..items.len()).rev() {
        let Ok(random) = getrandom::u32() else {
            return;
        };
        items.swap(i, random as usize % (i + 1));
    }
}

/// Ask the next STUN server for the mapping of the shared socket every
/// `interval_secs`, starting now. A new address goes to `mapping`, and every
/// answer or miss to `health`.
pub async fn run(
    mut stun: StunPort,
    iface: &str,
    config: &StunConfig,
    mapping: &watch::Sender<Option<Mapping>>,
    health: &watch::Sender<Health>,
) -> Infallible {
    let mut targets = Targets::default();
    let mut resolved_at: Option<Instant> = None;
    let mut tick = tokio::time::interval(Duration::from_secs(config.interval_secs.get()));
    tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        if targets.is_empty() || resolved_at.is_none_or(|at| at.elapsed() >= RESOLVE_EVERY) {
            let resolved = resolve(config, iface).await;
            if !resolved.is_empty() {
                targets = resolved;
                resolved_at = Some(Instant::now());
            }
        }
        let Some(server) = targets.next() else {
            continue;
        };
        let answer = tokio::time::timeout(TIMEOUT, async {
            stun.wait_bound().await?;
            stun.binding(server, TIMEOUT).await
        })
        .await;
        match answer {
            Ok(Ok(addr)) => answered(addr, mapping, health),
            Ok(Err(error)) => missed(server, &error.to_string(), health),
            Err(_) => missed(server, "the shared UDP socket was not bound", health),
        }
    }
}

fn answered(
    addr: SocketAddrV4,
    mapping: &watch::Sender<Option<Mapping>>,
    health: &watch::Sender<Health>,
) {
    let now = SystemTime::now();
    let before = health.send_replace(Health {
        misses: 0,
        last_ok: Some(now),
    });
    if before.misses >= 3 {
        tracing::info!("STUN answers again after {} misses", before.misses);
    }
    mapping.send_if_modified(|current| {
        if current.is_some_and(|current| current.addr == addr) {
            return false;
        }
        let old = current.map_or("none".to_owned(), |current| current.addr.to_string());
        tracing::info!("public endpoint {old} -> {addr}");
        *current = Some(Mapping { addr, since: now });
        true
    });
}

fn missed(server: SocketAddrV4, error: &str, health: &watch::Sender<Health>) {
    let mut misses = 0;
    health.send_modify(|health| {
        health.misses += 1;
        misses = health.misses;
    });
    if misses == 3 || misses == 10 || misses % 50 == 0 {
        tracing::warn!(
            "{misses} STUN requests in a row got no answer, the last from {server}: {error}"
        );
    }
}

/// Resolve the configured STUN hosts through the interface, past any VPN app
/// that answers DNS on the default route. With no server and no fallback in
/// the config, the built-in list stands in.
async fn resolve(config: &StunConfig, iface: &str) -> Targets {
    let (servers, fallback) = if config.servers.is_empty() && config.fallback.is_empty() {
        let servers = stun::DEFAULT_SERVERS.map(|(host, port)| (host.to_owned(), port));
        (servers.to_vec(), stun::DEFAULT_FALLBACKS.to_vec())
    } else {
        let servers = config
            .servers
            .iter()
            .filter_map(|entry| match stun::host_port(entry) {
                Ok(server) => Some(server),
                Err(error) => {
                    tracing::warn!("STUN_SERVER_INVALID: {entry:?}: {error}");
                    None
                }
            });
        (servers.collect(), config.fallback.clone())
    };
    let mut hosts = Vec::new();
    match BoundInterface::lookup(iface) {
        Ok(iface) => {
            let dns = SocketAddrV4::new(config.dns_server, DNS_PORT);
            for (host, port) in servers {
                match dns::resolve(&iface, dns, &host, RecordKind::A, DNS_TIMEOUT).await {
                    Ok(records) => hosts.push(
                        records
                            .into_iter()
                            .filter_map(|record| match record {
                                Record::A(ip) => Some(SocketAddrV4::new(ip, port)),
                                Record::Txt(_) => None,
                            })
                            .collect(),
                    ),
                    Err(error) => tracing::warn!("{error}; skipping {host}:{port}"),
                }
            }
        }
        Err(error) => tracing::warn!("{error}; asking only the fallback STUN servers"),
    }
    Targets::new(hosts, &fallback)
}
