use natwg::config::StunConfig;
use natwg::server::keepalive::{self, Health, Mapping, Targets};
use natwg::wire::transport::{BoundInterface, StunPort};
use std::{
    collections::BTreeSet,
    net::{SocketAddr, SocketAddrV4},
    num::NonZeroU64,
    time::Duration,
};
use tokio::sync::{mpsc, watch};

#[cfg(target_os = "macos")]
const LOOPBACK: &str = "lo0";
#[cfg(target_os = "linux")]
const LOOPBACK: &str = "lo";

const XOR_MAPPED_ADDRESS: u16 = 0x0020;
const COOKIE: u32 = 0x2112_A442;

fn addr(text: &str) -> SocketAddrV4 {
    text.parse().unwrap()
}

fn v4(address: SocketAddr) -> SocketAddrV4 {
    match address {
        SocketAddr::V4(address) => address,
        SocketAddr::V6(address) => panic!("expected IPv4, got {address}"),
    }
}

/// A Binding success response with one XOR-MAPPED-ADDRESS.
fn answer(id: [u8; 12], mapping: SocketAddrV4) -> Vec<u8> {
    let port = mapping.port() ^ (COOKIE >> 16) as u16;
    let ip = mapping.ip().to_bits() ^ COOKIE;
    let mut message = vec![0x01, 0x01, 0, 12];
    message.extend(COOKIE.to_be_bytes());
    message.extend(id);
    message.extend(XOR_MAPPED_ADDRESS.to_be_bytes());
    message.extend(8u16.to_be_bytes());
    message.extend([0, 1]);
    message.extend(port.to_be_bytes());
    message.extend(ip.to_be_bytes());
    message
}

#[test]
fn targets_take_two_addresses_of_each_host_then_the_fallbacks_each_once() {
    let hosts = vec![
        vec![
            addr("111.206.174.3:3478"),
            addr("111.206.174.2:3478"),
            addr("111.206.174.9:3478"),
        ],
        vec![addr("1.1.1.1:3478")],
        vec![addr("111.206.174.3:3478")],
    ];
    let fallback = [addr("111.206.174.3:3478"), addr("9.9.9.9:3478")];
    let rotation: Vec<_> = Targets::new(hosts, &fallback).take(12).collect();
    let once: BTreeSet<_> = rotation[..4].iter().copied().collect();
    let expected = BTreeSet::from([
        addr("111.206.174.3:3478"),
        addr("111.206.174.2:3478"),
        addr("1.1.1.1:3478"),
        addr("9.9.9.9:3478"),
    ]);
    assert_eq!(once, expected);
    assert_eq!(rotation[..4], rotation[4..8], "the rotation repeats");
    assert_eq!(rotation[4..8], rotation[8..12], "the rotation repeats");
}

#[test]
fn targets_without_an_address_yield_nothing() {
    let mut targets = Targets::new(Vec::<Vec<SocketAddrV4>>::new(), &[]);
    assert!(targets.is_empty());
    assert_eq!(targets.next(), None);
}

#[test]
fn targets_come_in_random_order() {
    let hosts: Vec<Vec<_>> = (1..=6)
        .map(|n| vec![addr(&format!("192.0.2.{n}:3478"))])
        .collect();
    let orders: BTreeSet<Vec<_>> = (0..20)
        .map(|_| Targets::new(hosts.clone(), &[]).take(6).collect())
        .collect();
    assert!(orders.len() > 1, "20 rotations had the same order");
}

/// A STUN server on a blocking thread. It reads one request for each entry
/// of `replies`, reports it on the returned channel, and answers it with the
/// entry's mapping, or stays silent. A running blocking task stops tokio's
/// paused clock from jumping ahead while a datagram is on its way.
fn blocking_stun_server(
    replies: Vec<Option<SocketAddrV4>>,
) -> (SocketAddrV4, mpsc::UnboundedReceiver<()>) {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let address = v4(socket.local_addr().unwrap());
    let (seen_tx, seen) = mpsc::unbounded_channel();
    tokio::task::spawn_blocking(move || {
        for reply in replies {
            let mut request = [0; 64];
            let Ok((20, client)) = socket.recv_from(&mut request) else {
                return;
            };
            let _ = seen_tx.send(());
            if let Some(mapping) = reply {
                let id = request[8..20].try_into().unwrap();
                socket.send_to(&answer(id, mapping), client).unwrap();
            }
        }
    });
    (address, seen)
}

fn stun_config(fallback: SocketAddrV4, interval_secs: u64) -> StunConfig {
    StunConfig {
        servers: vec![],
        fallback: vec![fallback],
        interval_secs: NonZeroU64::new(interval_secs).unwrap(),
        dns_server: "127.0.0.1".parse().unwrap(),
    }
}

#[tokio::test(start_paused = true)]
async fn the_keepalive_counts_misses_and_reports_each_new_mapping() {
    let first = addr("203.0.113.9:7007");
    let second = addr("203.0.113.9:7008");
    let (server, mut seen) =
        blocking_stun_server(vec![None, Some(first), Some(second), Some(second)]);
    let stun = StunPort::bind(BoundInterface::lookup(LOOPBACK).unwrap(), 0)
        .await
        .unwrap();
    let config = stun_config(server, 25);
    let (mapping_tx, mut mapping) = watch::channel(None::<Mapping>);
    let earlier_run = Health {
        misses: 7,
        last_ok: None,
    };
    let (health_tx, mut health) = watch::channel(earlier_run);
    let keepalive = keepalive::run(stun, LOOPBACK, &config, &mapping_tx, &health_tx);
    let check = async {
        seen.recv().await.unwrap();
        assert_eq!(health.borrow().misses, 0, "a run starts with no miss");
        tokio::time::advance(keepalive::TIMEOUT).await;
        health.wait_for(|health| health.misses == 1).await.unwrap();
        assert_eq!(*mapping.borrow(), None);

        tokio::time::advance(Duration::from_secs(20)).await;
        seen.recv().await.unwrap();
        let reported = *mapping.wait_for(Option::is_some).await.unwrap();
        let reported = reported.unwrap();
        assert_eq!(reported.addr, first);
        let after_answer = *health.borrow();
        assert_eq!(after_answer.misses, 0);
        assert!(after_answer.last_ok.is_some());

        tokio::time::advance(Duration::from_secs(25)).await;
        seen.recv().await.unwrap();
        mapping
            .wait_for(|now| now.is_some_and(|now| now.addr == second))
            .await
            .unwrap();
        let moved = mapping.borrow_and_update().unwrap();
        assert!(moved.since >= reported.since);

        let last_ok = health.borrow().last_ok;
        tokio::time::advance(Duration::from_secs(25)).await;
        seen.recv().await.unwrap();
        health
            .wait_for(|health| health.last_ok != last_ok)
            .await
            .unwrap();
        tokio::task::yield_now().await;
        assert!(
            !mapping.has_changed().unwrap(),
            "the same address again is no change"
        );
    };
    tokio::select! {
        never = keepalive => match never {},
        () = check => {}
    }
}
