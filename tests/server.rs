use natwg::Result;
use natwg::config::{CloudflareConfig, Config, PublishMode, ServerConfig, StunConfig};
use natwg::detect::PublicBy;
use natwg::keys::Key;
use natwg::server::cloudflare::{self, Content, Publish, Publisher, Record};
use natwg::server::keepalive::{self, Health, Mapping, Targets};
use natwg::server::public::{self, Public, Seen};
use natwg::server::upnp::{self, Upnp};
use natwg::server::{self, Device};
use natwg::status::Status;
use natwg::tunnel::{Detached, PeerStats};
use natwg::wire::transport::{BoundInterface, StunPort};
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    io::{BufRead, BufReader, Read, Write},
    net::Ipv4Addr,
    net::{SocketAddr, SocketAddrV4, TcpStream},
    num::NonZeroU64,
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU32, Ordering},
    },
    time::Duration,
};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::time::Instant;

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
    let (health_tx, mut health) = watch::channel(Health::default());
    let keepalive = keepalive::run(stun, LOOPBACK, &config, &mapping_tx, &health_tx);
    let check = async {
        seen.recv().await.unwrap();
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

#[derive(Debug, PartialEq)]
struct Request {
    method: String,
    target: String,
    authorization: Option<String>,
    body: Option<Value>,
}

/// An HTTP/1.1 server on a blocking thread that answers each request with
/// the status and JSON body of `reply`, and reports the request. It stops
/// when the value drops.
struct MockApi {
    url: String,
    requests: mpsc::UnboundedReceiver<Request>,
    stop: Arc<AtomicBool>,
}

impl Drop for MockApi {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

impl MockApi {
    fn start(reply: impl Fn(&Request) -> (u16, Value) + Send + 'static) -> Self {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}/client/v4", listener.local_addr().unwrap());
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let (seen, requests) = mpsc::unbounded_channel();
        tokio::task::spawn_blocking(move || {
            while !stopped.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _)) => serve(stream, &reply, &seen),
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    Err(e) => panic!("accept: {e}"),
                }
            }
        });
        Self {
            url,
            requests,
            stop,
        }
    }

    /// The requests that arrived so far.
    fn taken(&mut self) -> Vec<Request> {
        std::iter::from_fn(|| self.requests.try_recv().ok()).collect()
    }
}

fn serve(
    mut stream: TcpStream,
    reply: &impl Fn(&Request) -> (u16, Value),
    seen: &mpsc::UnboundedSender<Request>,
) {
    stream.set_nonblocking(false).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    let mut words = line.split_whitespace().map(str::to_owned);
    let (method, target) = (words.next().unwrap(), words.next().unwrap());
    let (mut length, mut authorization) = (0, None);
    loop {
        line.clear();
        reader.read_line(&mut line).unwrap();
        let Some((name, value)) = line.trim_end().split_once(':') else {
            break;
        };
        match name.to_ascii_lowercase().as_str() {
            "content-length" => length = value.trim().parse().unwrap(),
            "authorization" => authorization = Some(value.trim().to_owned()),
            _ => {}
        }
    }
    let mut body = vec![0; length];
    reader.read_exact(&mut body).unwrap();
    let request = Request {
        method,
        target,
        authorization,
        body: (length > 0).then(|| serde_json::from_slice(&body).unwrap()),
    };
    let (status, answer) = reply(&request);
    let _ = seen.send(request);
    let answer = answer.to_string();
    let head = format!(
        "HTTP/1.1 {status} Mock\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        answer.len()
    );
    let _ = stream.write_all(format!("{head}{answer}").as_bytes());
}

const TOKEN: &str = "cf-test-token-7Hq2";
const ZONES: &str = "/client/v4/zones?name=example.com";
const RECORDS: &str = "/client/v4/zones/zone1/dns_records";
const LOOKUP: &str = "/client/v4/zones/zone1/dns_records?type=TXT&name=_wg.example.com";
const RECORD: &str = "/client/v4/zones/zone1/dns_records/rec1";

fn ok(result: Value) -> (u16, Value) {
    (
        200,
        json!({"success": true, "errors": [], "result": result}),
    )
}

fn unknown() -> (u16, Value) {
    (
        404,
        json!({"success": false, "errors": [{"code": 7003, "message": "no route"}]}),
    )
}

fn cloudflare_config() -> CloudflareConfig {
    CloudflareConfig {
        zone: "example.com".into(),
        record: "_wg.example.com".into(),
        token: TOKEN.parse().unwrap(),
    }
}

/// The TXT value the publisher should write for the mapping `text`.
fn mapping(text: &str) -> Option<Content> {
    Some(Content::Txt(addr(text)))
}

/// The body natwg.py sends, as its `json.dumps` prints it.
fn python_body(value: &str) -> Value {
    let printed = format!(
        r#"{{"type": "TXT", "name": "_wg.example.com", "content": "\"{value}\"", "ttl": 60, "comment": "natwg: WireGuard public endpoint, auto-updated"}}"#
    );
    serde_json::from_str(&printed).unwrap()
}

fn put(value: &str) -> Request {
    Request {
        method: "PUT".into(),
        target: RECORD.into(),
        authorization: Some(format!("Bearer {TOKEN}")),
        body: Some(python_body(value)),
    }
}

fn get(target: &str) -> Request {
    Request {
        method: "GET".into(),
        target: target.into(),
        authorization: Some(format!("Bearer {TOKEN}")),
        body: None,
    }
}

/// Let 200 ms of real time pass while tokio's paused clock stands still, so
/// a request that the code under test sends now reaches the mock.
async fn real_pause() {
    tokio::task::spawn_blocking(|| std::thread::sleep(Duration::from_millis(200)))
        .await
        .unwrap();
}

async fn published(state: &mut watch::Receiver<Publish>, value: &str) -> Record {
    let value = Content::Txt(addr(value));
    let state = state
        .wait_for(|state| matches!(state, Publish::Published(record) if record.value == value))
        .await
        .unwrap();
    state.record().unwrap()
}

async fn failed(state: &mut watch::Receiver<Publish>) -> (String, tokio::time::Instant) {
    match &*state
        .wait_for(|state| matches!(state, Publish::Failed { .. }))
        .await
        .unwrap()
    {
        Publish::Failed {
            error, retry_at, ..
        } => (error.clone(), *retry_at),
        _ => unreachable!(),
    }
}

#[tokio::test]
async fn a_missing_record_is_created_with_the_body_natwg_py_sends() {
    let mut api =
        MockApi::start(
            |request| match (request.method.as_str(), request.target.as_str()) {
                ("GET", ZONES) => ok(json!([{"id": "zone1"}])),
                ("GET", LOOKUP) => ok(json!([])),
                ("POST", RECORDS) => ok(json!({"id": "rec1"})),
                _ => unknown(),
            },
        );
    let (_mapping_tx, mapping_rx) = watch::channel(mapping("203.0.113.9:7007"));
    let (state_tx, mut state) = watch::channel(Publish::Idle);
    let publisher = Publisher::new(&cloudflare_config(), PublishMode::Txt, &api.url).unwrap();
    let check = async {
        published(&mut state, "203.0.113.9:7007").await;
        let create = Request {
            method: "POST".into(),
            target: RECORDS.into(),
            authorization: Some(format!("Bearer {TOKEN}")),
            body: Some(python_body("203.0.113.9:7007")),
        };
        assert_eq!(api.taken(), [get(ZONES), get(LOOKUP), create]);
    };
    tokio::select! {
        never = publisher.run(mapping_rx, state_tx) => match never {},
        () = check => {}
    }
}

#[tokio::test]
async fn an_existing_record_is_updated_and_a_value_already_published_is_skipped() {
    let mut api =
        MockApi::start(
            |request| match (request.method.as_str(), request.target.as_str()) {
                ("GET", ZONES) => ok(json!([{"id": "zone1"}])),
                ("GET", LOOKUP) => ok(json!([{"id": "rec1"}])),
                ("PUT", RECORD) => ok(json!({"id": "rec1"})),
                _ => unknown(),
            },
        );
    let (mapping_tx, mapping_rx) = watch::channel(mapping("203.0.113.9:7007"));
    let (state_tx, mut state) = watch::channel(Publish::Idle);
    let publisher = Publisher::new(&cloudflare_config(), PublishMode::Txt, &api.url).unwrap();
    let check = async {
        let first = published(&mut state, "203.0.113.9:7007").await;
        assert_eq!(
            api.taken(),
            [get(ZONES), get(LOOKUP), put("203.0.113.9:7007")]
        );

        mapping_tx.send_replace(mapping("203.0.113.9:7008"));
        let second = published(&mut state, "203.0.113.9:7008").await;
        assert!(second.at >= first.at);
        assert_eq!(api.taken(), [put("203.0.113.9:7008")], "ids are cached");

        mapping_tx.send_replace(mapping("203.0.113.9:7008"));
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(api.taken(), [], "the record holds 7008 already");
        mapping_tx.send_replace(mapping("203.0.113.9:7009"));
        published(&mut state, "203.0.113.9:7009").await;
        assert_eq!(api.taken(), [put("203.0.113.9:7009")]);
    };
    tokio::select! {
        never = publisher.run(mapping_rx, state_tx) => match never {},
        () = check => {}
    }
}

#[tokio::test]
async fn a_record_that_holds_the_mapping_already_is_published_without_a_write() {
    let mut api =
        MockApi::start(
            |request| match (request.method.as_str(), request.target.as_str()) {
                ("GET", ZONES) => ok(json!([{"id": "zone1"}])),
                ("GET", LOOKUP) => ok(json!([{"id": "rec1", "content": "\"203.0.113.9:7007\""}])),
                ("PUT", RECORD) => ok(json!({"id": "rec1"})),
                _ => unknown(),
            },
        );
    let (mapping_tx, mapping_rx) = watch::channel(mapping("203.0.113.9:7007"));
    let (state_tx, mut state) = watch::channel(Publish::Idle);
    let publisher = Publisher::new(&cloudflare_config(), PublishMode::Txt, &api.url).unwrap();
    let check = async {
        published(&mut state, "203.0.113.9:7007").await;
        assert_eq!(api.taken(), [get(ZONES), get(LOOKUP)]);

        mapping_tx.send_replace(mapping("203.0.113.9:7008"));
        published(&mut state, "203.0.113.9:7008").await;
        assert_eq!(api.taken(), [put("203.0.113.9:7008")], "the ID is cached");
    };
    tokio::select! {
        never = publisher.run(mapping_rx, state_tx) => match never {},
        () = check => {}
    }
}

#[tokio::test(start_paused = true)]
async fn an_api_error_is_reported_without_the_token_and_tried_again_after_60_s() {
    let mut api = MockApi::start(|_| {
        let message = format!("Invalid access token {TOKEN}");
        (
            403,
            json!({"success": false, "errors": [{"code": 9109, "message": message}]}),
        )
    });
    let (_mapping_tx, mapping_rx) = watch::channel(mapping("203.0.113.9:7007"));
    let (state_tx, mut state) = watch::channel(Publish::Idle);
    let publisher = Publisher::new(&cloudflare_config(), PublishMode::Txt, &api.url).unwrap();
    let check = async {
        assert_eq!(api.requests.recv().await.unwrap(), get(ZONES));
        let (error, retry_at) = failed(&mut state).await;
        let failed_at = tokio::time::Instant::now();
        assert!(error.starts_with("CLOUDFLARE_API: HTTP 403"), "{error}");
        assert!(error.contains("9109"), "{error}");
        assert!(!error.contains(TOKEN), "the token leaked into {error:?}");
        assert_eq!(retry_at, failed_at + cloudflare::RETRY);

        tokio::time::advance(cloudflare::RETRY - Duration::from_secs(1)).await;
        real_pause().await;
        assert_eq!(api.taken(), [], "no retry before 60 s");
        tokio::time::advance(Duration::from_secs(1)).await;
        assert_eq!(api.requests.recv().await.unwrap(), get(ZONES));
        assert_eq!(tokio::time::Instant::now() - failed_at, cloudflare::RETRY);
    };
    tokio::select! {
        never = publisher.run(mapping_rx, state_tx) => match never {},
        () = check => {}
    }
}

#[tokio::test]
async fn a_zone_the_token_cannot_see_is_an_error() {
    let api = MockApi::start(|request| match request.target.as_str() {
        ZONES => ok(json!([])),
        _ => unknown(),
    });
    let (_mapping_tx, mapping_rx) = watch::channel(mapping("203.0.113.9:7007"));
    let (state_tx, mut state) = watch::channel(Publish::Idle);
    let publisher = Publisher::new(&cloudflare_config(), PublishMode::Txt, &api.url).unwrap();
    let check = async {
        let (error, _) = failed(&mut state).await;
        assert_eq!(
            error,
            "CLOUDFLARE_ZONE: the zone example.com is not visible to the token"
        );
        assert_eq!(state.borrow().record(), None);
    };
    tokio::select! {
        never = publisher.run(mapping_rx, state_tx) => match never {},
        () = check => {}
    }
}

const A_LOOKUP: &str = "/client/v4/zones/zone1/dns_records?name=home.example.com";

fn a_config() -> CloudflareConfig {
    CloudflareConfig {
        record: "home.example.com".into(),
        ..cloudflare_config()
    }
}

fn ip(text: &str) -> Ipv4Addr {
    text.parse().unwrap()
}

/// The body that makes home.example.com an A record of `ip`.
fn a_body(ip: &str) -> Value {
    json!({
        "type": "A",
        "name": "home.example.com",
        "content": ip,
        "ttl": 60,
        "proxied": false,
        "comment": "natwg: WireGuard public IP, auto-updated",
    })
}

fn a_write(method: &str, target: &str, ip: &str) -> Request {
    Request {
        method: method.into(),
        target: target.into(),
        authorization: Some(format!("Bearer {TOKEN}")),
        body: Some(a_body(ip)),
    }
}

/// A record of home.example.com as the Cloudflare API lists it.
fn listed(id: &str, kind: &str, content: &str, proxied: bool, ttl: u32) -> Value {
    json!({"id": id, "type": kind, "name": "home.example.com", "content": content, "proxied": proxied, "ttl": ttl})
}

/// A fake API whose zone lists `records` for home.example.com, and that
/// takes every write. A PUT fails while `failing` is above zero, which each
/// PUT counts down.
fn zone_with(records: Value, failing: u32) -> MockApi {
    let failing = AtomicU32::new(failing);
    MockApi::start(
        move |request| match (request.method.as_str(), request.target.as_str()) {
            ("GET", ZONES) => ok(json!([{"id": "zone1"}])),
            ("GET", A_LOOKUP) => ok(records.clone()),
            ("POST", RECORDS) => ok(json!({"id": "rec1"})),
            ("PUT", target) if target.starts_with(RECORDS) => {
                let left = failing.load(Ordering::SeqCst);
                if left > 0 {
                    failing.store(left - 1, Ordering::SeqCst);
                    return (
                        500,
                        json!({"success": false, "errors": [{"code": 1, "message": "boom"}]}),
                    );
                }
                ok(json!({"id": "rec1"}))
            }
            _ => unknown(),
        },
    )
}

fn writes(requests: Vec<Request>) -> Vec<Request> {
    requests
        .into_iter()
        .filter(|request| request.method != "GET")
        .collect()
}

fn a_publisher(api: &MockApi) -> Publisher {
    Publisher::new(&a_config(), PublishMode::A, &api.url).unwrap()
}

async fn published_a(state: &mut watch::Receiver<Publish>, value: &str) -> Record {
    let value = Content::A(ip(value));
    let state = state
        .wait_for(|state| matches!(state, Publish::Published(record) if record.value == value))
        .await
        .unwrap();
    state.record().unwrap()
}

#[tokio::test]
async fn an_a_record_is_created_never_proxied_with_natwgs_ttl_and_then_kept_current() {
    let mut api = zone_with(json!([]), 0);
    let (wanted_tx, wanted) = watch::channel(Some(Content::A(ip("45.77.0.10"))));
    let (state_tx, mut state) = watch::channel(Publish::Idle);
    let publisher = a_publisher(&api);
    let check = async {
        published_a(&mut state, "45.77.0.10").await;
        assert_eq!(
            api.taken(),
            [
                get(ZONES),
                get(A_LOOKUP),
                a_write("POST", RECORDS, "45.77.0.10")
            ]
        );

        wanted_tx.send_replace(Some(Content::A(ip("45.77.0.11"))));
        published_a(&mut state, "45.77.0.11").await;
        assert_eq!(
            api.taken(),
            [a_write("PUT", RECORD, "45.77.0.11")],
            "ids are cached"
        );

        wanted_tx.send_replace(Some(Content::A(ip("45.77.0.11"))));
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(api.taken(), [], "the record holds 45.77.0.11 already");
    };
    tokio::select! {
        never = publisher.run(wanted, state_tx) => match never {},
        () = check => {}
    }
}

#[tokio::test]
async fn an_a_record_that_holds_the_ip_as_natwg_writes_it_is_published_without_a_write() {
    let mut api = zone_with(json!([listed("rec1", "A", "45.77.0.10", false, 60)]), 0);
    let (_wanted_tx, wanted) = watch::channel(Some(Content::A(ip("45.77.0.10"))));
    let (state_tx, mut state) = watch::channel(Publish::Idle);
    let publisher = a_publisher(&api);
    let check = async {
        published_a(&mut state, "45.77.0.10").await;
        real_pause().await;
        assert_eq!(api.taken(), [get(ZONES), get(A_LOOKUP)]);
    };
    tokio::select! {
        never = publisher.run(wanted, state_tx) => match never {},
        () = check => {}
    }
}

#[tokio::test]
async fn a_proxied_record_or_one_with_another_ttl_is_written_again() {
    // The dashboard creates an A record proxied with an automatic TTL (1),
    // and Cloudflare's proxy carries no WireGuard.
    for (proxied, ttl) in [(true, 1), (true, 60), (false, 1), (false, 300)] {
        let mut api = zone_with(json!([listed("rec1", "A", "45.77.0.10", proxied, ttl)]), 0);
        let (_wanted_tx, wanted) = watch::channel(Some(Content::A(ip("45.77.0.10"))));
        let (state_tx, mut state) = watch::channel(Publish::Idle);
        let publisher = a_publisher(&api);
        let check = async {
            published_a(&mut state, "45.77.0.10").await;
            assert_eq!(
                writes(api.taken()),
                [a_write("PUT", RECORD, "45.77.0.10")],
                "proxied {proxied}, ttl {ttl}"
            );
        };
        tokio::select! {
            never = publisher.run(wanted, state_tx) => match never {},
            () = check => {}
        }
    }
}

#[tokio::test]
async fn more_a_records_and_an_aaaa_record_are_named_and_left_to_the_operator() {
    let mut api = zone_with(
        json!([
            listed("rec1", "A", "45.77.0.10", false, 60),
            listed("rec2", "A", "45.77.0.99", false, 60),
            listed("rec3", "AAAA", "2001:db8::1", false, 60),
            listed("rec4", "TXT", "\"v=spf1 -all\"", false, 60),
        ]),
        0,
    );
    let (_wanted_tx, wanted) = watch::channel(Some(Content::A(ip("45.77.0.10"))));
    let (state_tx, mut state) = watch::channel(Publish::Idle);
    let publisher = a_publisher(&api);
    let mut strays = publisher.strays();
    let check = async {
        published_a(&mut state, "45.77.0.10").await;
        let stray = strays
            .wait_for(Option::is_some)
            .await
            .unwrap()
            .clone()
            .unwrap();
        assert!(
            stray.starts_with("home.example.com also has A 45.77.0.99, AAAA 2001:db8::1; delete them in Cloudflare"),
            "{stray}"
        );
        real_pause().await;
        assert_eq!(writes(api.taken()), [], "natwg deletes nothing");
    };
    tokio::select! {
        never = publisher.run(wanted, state_tx) => match never {},
        () = check => {}
    }
}

#[tokio::test]
async fn with_nothing_confirmed_the_record_is_read_and_never_written() {
    let mut api = zone_with(json!([listed("rec1", "A", "45.77.0.99", true, 1)]), 0);
    let (_wanted_tx, wanted) = watch::channel(None);
    let (state_tx, mut state) = watch::channel(Publish::Idle);
    let publisher = a_publisher(&api);
    let check = async {
        let record = published_a(&mut state, "45.77.0.99").await;
        assert_eq!(record.value, Content::A(ip("45.77.0.99")));
        assert_eq!(state.borrow().error(), None);
        real_pause().await;
        assert_eq!(
            api.taken(),
            [get(ZONES), get(A_LOOKUP)],
            "a read and no write"
        );
    };
    tokio::select! {
        never = publisher.run(wanted, state_tx) => match never {},
        () = check => {}
    }
}

#[tokio::test(start_paused = true)]
async fn a_failed_write_is_not_tried_again_once_nothing_is_confirmed() {
    let mut api = zone_with(json!([listed("rec1", "A", "45.77.0.99", false, 60)]), 1);
    let (wanted_tx, wanted) = watch::channel(Some(Content::A(ip("45.77.0.2"))));
    let (state_tx, mut state) = watch::channel(Publish::Idle);
    let publisher = a_publisher(&api);
    let check = async {
        let (error, _) = failed(&mut state).await;
        assert!(error.contains("HTTP 500"), "{error}");
        wanted_tx.send_replace(None);
        published_a(&mut state, "45.77.0.99").await;
        assert_eq!(state.borrow().error(), None, "no write is pending");
        tokio::time::advance(cloudflare::RETRY * 2).await;
        real_pause().await;
        assert_eq!(
            writes(api.taken()),
            [a_write("PUT", RECORD, "45.77.0.2")],
            "only the one write while 45.77.0.2 was confirmed"
        );
    };
    tokio::select! {
        never = publisher.run(wanted, state_tx) => match never {},
        () = check => {}
    }
}

fn seen<'a>(addresses: &'a [Ipv4Addr], mapping: Option<&str>) -> Seen<'a> {
    Seen {
        iface: "eth0",
        listen_port: 51830,
        addresses,
        stun: true,
        mapping: mapping.map(addr),
        upnp: false,
        lease: None,
    }
}

/// A UPnP lease that worked, on a gateway whose WAN address is `wan`.
fn lease(wan: Option<&str>) -> Option<upnp::Lease> {
    Some(upnp::Lease {
        ok: true,
        at: std::time::SystemTime::now(),
        external_ip: wan.map(ip),
    })
}

#[test]
fn publish_a_takes_the_first_public_address_of_the_uplink_over_any_mapping() {
    let addresses = [ip("10.88.0.1"), ip("45.77.0.10"), ip("45.77.0.11")];
    let known = Public::Known {
        ip: ip("45.77.0.10"),
        by: PublicBy::Address,
    };
    assert_eq!(
        public::public(&seen(&addresses, Some("45.77.0.2:7105"))),
        known
    );
    let without_stun = Seen {
        stun: false,
        ..seen(&addresses, None)
    };
    assert_eq!(public::public(&without_stun), known);
}

#[test]
fn publish_a_takes_a_mapping_only_when_a_upnp_gateway_confirms_it() {
    let private = [ip("192.168.77.2")];
    let confirmed = Seen {
        upnp: true,
        lease: lease(Some("45.77.0.2")),
        ..seen(&private, Some("45.77.0.2:51830"))
    };
    assert_eq!(
        public::public(&confirmed),
        Public::Known {
            ip: ip("45.77.0.2"),
            by: PublicBy::Upnp
        }
    );
    let pending = Seen {
        lease: None,
        ..confirmed
    };
    assert_eq!(
        public::public(&pending),
        Public::Unknown,
        "the first lease is pending"
    );
    assert_eq!(
        public::public(&seen(&private, None)),
        Public::Unknown,
        "STUN has not answered yet"
    );
}

#[test]
fn publish_a_never_publishes_an_ip_that_natwg_cannot_confirm() {
    let private = [ip("192.168.77.2")];
    let upnp = |wan: Option<&str>, mapping: &'static str| Seen {
        upnp: true,
        lease: lease(wan),
        ..seen(&[], Some(mapping))
    };
    let failed = Seen {
        lease: Some(upnp::Lease {
            ok: false,
            at: std::time::SystemTime::now(),
            external_ip: None,
        }),
        ..upnp(None, "45.77.0.2:51830")
    };
    let cases = [
        (
            seen(&private, Some("45.77.0.2:51830")),
            "STUN sees 45.77.0.2:51830, which keeps the listen port, but without role.server.upnp natwg cannot confirm that a router forwards udp/51830",
        ),
        (
            seen(&private, Some("45.77.0.2:52830")),
            "STUN sees 45.77.0.2:52830, which does not keep the listen port 51830, so the A record would send clients to the wrong port; publish txt instead",
        ),
        (
            upnp(Some("45.77.0.2"), "45.77.0.2:52830"),
            "STUN sees 45.77.0.2:52830, which does not keep the listen port 51830",
        ),
        (
            seen(&private, Some("100.87.0.9:51830")),
            "the address 192.168.77.2 of eth0 is not public, and STUN sees 100.87.0.9:51830, which is not public either",
        ),
        (
            failed,
            "the UPnP lease of udp/51830 failed, so natwg cannot confirm that the router forwards it",
        ),
        (
            upnp(None, "45.77.0.2:51830"),
            "the UPnP gateway did not report its WAN address",
        ),
        (
            upnp(Some("100.87.0.9"), "45.77.0.2:51830"),
            "the UPnP gateway's WAN address 100.87.0.9 is not 45.77.0.2, which STUN sees, so another NAT sits between the router and the internet; publish txt instead",
        ),
        (
            Seen {
                stun: false,
                ..seen(&private, None)
            },
            "the address 192.168.77.2 of eth0 is not public, and without role.server.stun natwg cannot learn the public IP",
        ),
        (
            Seen {
                stun: false,
                ..seen(&[], None)
            },
            "eth0, which has no IPv4 address, is not public",
        ),
    ];
    for (seen, expected) in cases {
        match public::public(&seen) {
            Public::Missing(error) => assert!(error.starts_with(expected), "{error}"),
            other => panic!("{seen:?}: {other:?}"),
        }
    }
}

#[test]
fn the_upnp_request_is_the_one_natwg_py_sends_with_the_instance_as_description() {
    let body = upnp::add_port_mapping(
        51831,
        "10.73.0.2".parse().unwrap(),
        &"natwg_next".parse().unwrap(),
        3600,
    );
    let python = concat!(
        r#"<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body><u:AddPortMapping xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">"#,
        "<NewRemoteHost></NewRemoteHost><NewExternalPort>51831</NewExternalPort><NewProtocol>UDP</NewProtocol><NewInternalPort>51831</NewInternalPort><NewInternalClient>10.73.0.2</NewInternalClient><NewEnabled>1</NewEnabled><NewPortMappingDescription>natwg</NewPortMappingDescription><NewLeaseDuration>3600</NewLeaseDuration>",
        "</u:AddPortMapping></s:Body></s:Envelope>",
    );
    let python = python.replace(
        "<NewPortMappingDescription>natwg<",
        "<NewPortMappingDescription>natwg_next<",
    );
    assert_eq!(body, python);
}

fn server_config(upnp: Option<Value>) -> ServerConfig {
    let mut server = json!({
        "instance": "natwg_next",
        "iface": LOOPBACK,
        "listen_port": 51831,
        "lan": "10.73.0.0/24",
        "stun": {"servers": [], "fallback": [], "dns_server": "127.0.0.1"},
        "cloudflare": {"zone": "example.com", "record": "_wg.example.com", "token": TOKEN},
    });
    if let Some(upnp) = upnp {
        server["upnp"] = upnp;
    }
    serde_json::from_value(server).unwrap()
}

#[test]
fn upnp_stays_off_without_a_upnp_section() {
    assert!(Upnp::new(&server_config(None)).unwrap().is_none());
    let upnp = json!({"control_url": "http://10.73.0.1:1900/ipc", "lease_secs": 3600, "refresh_secs": 300});
    assert!(Upnp::new(&server_config(Some(upnp))).unwrap().is_some());
}

/// A device without a TUN that the test can kill: generation `n` fails once
/// `kills` exceeds `n`.
struct Killable {
    device: Detached,
    kills: watch::Receiver<u32>,
    generation: u32,
}

impl Device for Killable {
    async fn failed(&mut self) {
        let generation = self.generation;
        tokio::select! {
            () = self.device.failed() => {}
            _ = self.kills.wait_for(|kills| *kills > generation) => {}
        }
    }

    async fn peers(&self) -> Vec<PeerStats> {
        self.device.peers().await
    }

    fn tun(&self) -> Option<&str> {
        None
    }

    fn ensure_nat(&mut self) -> Option<Result<bool>> {
        None
    }

    async fn stop(self) -> Result<()> {
        self.device.stop().await;
        Ok(())
    }
}

const NO_API: &str = "http://127.0.0.1:9/client/v4";

struct Secrets {
    private_key: String,
    doctor_key: String,
}

/// A server on the loopback interface whose only STUN server never answers.
fn supervised(
    status_file: &Path,
    stun_server: SocketAddrV4,
    interval_secs: u64,
) -> (Config, Secrets) {
    let secrets = Secrets {
        private_key: Key::generate().unwrap().to_base64(),
        doctor_key: Key::generate().unwrap().to_base64(),
    };
    let config = json!({
        "version": 1,
        "private_key": secrets.private_key,
        "interface": {"address": "10.66.67.1/24"},
        "peers": [],
        "role": {"server": {
            "instance": "natwg_test",
            "iface": LOOPBACK,
            "listen_port": 0,
            "lan": "10.73.0.0/24",
            "stun": {
                "servers": [],
                "fallback": [stun_server.to_string()],
                "interval_secs": interval_secs,
                "dns_server": "127.0.0.1",
            },
            "cloudflare": {"zone": "example.com", "record": "_wg.example.com", "token": TOKEN},
            "status_file": status_file,
            "doctor": {"private_key": secrets.doctor_key, "address": "10.66.67.254"},
        }},
    });
    (serde_json::from_value(config).unwrap(), secrets)
}

fn silent_stun_server() -> (std::net::UdpSocket, SocketAddrV4) {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let address = v4(socket.local_addr().unwrap());
    (socket, address)
}

/// The first status that `done` accepts, polled once a second for up to 10
/// minutes of tokio's clock.
async fn status_until(path: &Path, done: impl Fn(&Status) -> bool) -> Status {
    for _ in 0..600 {
        if let Ok(status) = Status::read(path)
            && done(&status)
        {
            return status;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    panic!("no status matched; the last is {:?}", Status::read(path));
}

#[tokio::test(start_paused = true)]
async fn a_device_that_fails_is_rebuilt_and_the_rebuild_is_counted() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("status.json");
    let (_stun, stun_server) = silent_stun_server();
    let (config, secrets) = supervised(&path, stun_server, 25);
    let (kill, kills) = watch::channel(0);
    let builds = AtomicU32::new(0);
    let build = async |config: &Config| {
        let generation = builds.fetch_add(1, Ordering::SeqCst);
        let (device, stun) = Detached::server(config).await?;
        let kills = kills.clone();
        let device = Killable {
            device,
            kills,
            generation,
        };
        Ok((device, stun))
    };
    let (stop, stopped) = oneshot::channel::<()>();
    let check = async {
        let first = status_until(&path, |_| true).await;
        assert_eq!(first.rebuilds, 0);
        assert_eq!(first.peers.len(), 1, "the doctor is a peer");
        let text = std::fs::read_to_string(&path).unwrap();
        for secret in [TOKEN, &secrets.private_key, &secrets.doctor_key] {
            assert!(!text.contains(secret), "the status file holds a secret");
        }

        kill.send_replace(1);
        let killed_at = Instant::now();
        let rebuilt = status_until(&path, |status| status.rebuilds == 1).await;
        assert!(killed_at.elapsed() < Duration::from_secs(5));
        assert!(rebuilt.stun_misses < server::DEAD_AFTER_MISSES);
        assert_eq!(builds.load(Ordering::SeqCst), 2);
        stop.send(()).unwrap();
    };
    let stop = async {
        let _ = stopped.await;
    };
    let (served, ()) = tokio::join!(server::run(&config, NO_API, build, stop), check);
    served.unwrap();
}

#[tokio::test(start_paused = true)]
async fn a_run_of_unanswered_stun_requests_rebuilds_the_tunnel() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("status.json");
    let (_stun, stun_server) = silent_stun_server();
    let (config, _) = supervised(&path, stun_server, 1);
    let (_kill, kills) = watch::channel(0);
    let build = async |config: &Config| {
        let (device, stun) = Detached::server(config).await?;
        let kills = kills.clone();
        let device = Killable {
            device,
            kills,
            generation: 0,
        };
        Ok((device, stun))
    };
    let (stop, stopped) = oneshot::channel::<()>();
    let check = async {
        let serving = |status: &Status, rebuilds| {
            (6..server::DEAD_AFTER_MISSES).contains(&status.stun_misses)
                && status.rebuilds == rebuilds
        };
        let started = Instant::now();
        status_until(&path, |status| serving(status, 0)).await;
        status_until(&path, |status| status.rebuilds == 1).await;
        let ten_misses = keepalive::TIMEOUT * server::DEAD_AFTER_MISSES;
        assert!(started.elapsed() >= ten_misses, "{:?}", started.elapsed());
        status_until(&path, |status| serving(status, 1)).await;
        stop.send(()).unwrap();
    };
    let stop = async {
        let _ = stopped.await;
    };
    let (served, ()) = tokio::join!(server::run(&config, NO_API, build, stop), check);
    served.unwrap();
}

#[tokio::test(start_paused = true)]
async fn a_new_mapping_reaches_the_status_before_the_next_tick() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("status.json");
    let (stun_server, _seen) = blocking_stun_server(vec![Some(addr("203.0.113.5:6785"))]);
    let (config, _) = supervised(&path, stun_server, 25);
    let (_kill, kills) = watch::channel(0);
    let build = async |config: &Config| {
        let (device, stun) = Detached::server(config).await?;
        let kills = kills.clone();
        let device = Killable {
            device,
            kills,
            generation: 0,
        };
        Ok((device, stun))
    };
    let (stop, stopped) = oneshot::channel::<()>();
    let check = async {
        status_until(&path, |_| true).await;
        let first_written = Instant::now();
        let written = status_until(&path, |status| status.mapping.is_some()).await;
        assert_eq!(written.mapping, Some(addr("203.0.113.5:6785")));
        let waited = first_written.elapsed();
        assert!(
            waited < Duration::from_secs(5),
            "{waited:?}: the mapping waited for the 10 s tick"
        );
        stop.send(()).unwrap();
    };
    let stop = async {
        let _ = stopped.await;
    };
    let (served, ()) = tokio::join!(server::run(&config, NO_API, build, stop), check);
    served.unwrap();
}

#[tokio::test(start_paused = true)]
async fn rebuilds_that_fail_wait_twice_as_long_each_time_up_to_60_s() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("status.json");
    let (_stun, stun_server) = silent_stun_server();
    let (config, _) = supervised(&path, stun_server, 25);
    let (kill, kills) = watch::channel(0);
    let attempts = Mutex::new(Vec::new());
    let build = async |config: &Config| {
        let attempt = {
            let mut attempts = attempts.lock().unwrap();
            attempts.push(Instant::now());
            attempts.len()
        };
        if (2..=8).contains(&attempt) {
            return Err(natwg::Error::new("TUN_UNAVAILABLE", "test"));
        }
        let (device, stun) = Detached::server(config).await?;
        let kills = kills.clone();
        let device = Killable {
            device,
            kills,
            generation: 0,
        };
        Ok((device, stun))
    };
    let (stop, stopped) = oneshot::channel::<()>();
    let check = async {
        status_until(&path, |_| true).await;
        kill.send_replace(1);
        let killed_at = Instant::now();
        status_until(&path, |status| status.rebuilds == 1).await;
        let attempts = attempts.lock().unwrap().clone();
        let waits: Vec<u64> = std::iter::once(killed_at)
            .chain(attempts[1..].iter().copied())
            .zip(&attempts[1..])
            .map(|(before, attempt)| (*attempt - before).as_secs())
            .collect();
        assert_eq!(waits, [1, 2, 4, 8, 16, 32, 60, 60]);
        stop.send(()).unwrap();
    };
    let stop = async {
        let _ = stopped.await;
    };
    let (served, ()) = tokio::join!(server::run(&config, NO_API, build, stop), check);
    served.unwrap();
}

#[tokio::test]
async fn a_first_build_that_fails_ends_the_server() {
    let dir = tempfile::tempdir().unwrap();
    let (_stun, stun_server) = silent_stun_server();
    let (config, _) = supervised(&dir.path().join("status.json"), stun_server, 25);
    let build = async |_: &Config| -> Result<(Killable, StunPort)> {
        Err(natwg::Error::new("UDP_BIND", "test"))
    };
    let served = server::run(&config, NO_API, build, std::future::pending()).await;
    assert_eq!(served.unwrap_err().code, "UDP_BIND");
}

/// A free UDP port on loopback, for a server whose clients dial its listen
/// port.
fn free_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A server with publish a on loopback at `listen_port`, with `stun_server`
/// as its only STUN server, or without STUN, and with a UPnP lease on the
/// gateway at `control_url`, if one is given.
fn publishing_a(
    status_file: &Path,
    listen_port: u16,
    stun_server: Option<SocketAddrV4>,
    control_url: Option<&str>,
) -> Config {
    let mut config = json!({
        "version": 1,
        "private_key": Key::generate().unwrap().to_base64(),
        "interface": {"address": "10.66.67.1/24"},
        "peers": [],
        "role": {"server": {
            "instance": "natwg_test",
            "iface": LOOPBACK,
            "listen_port": listen_port,
            "lan": [],
            "publish": "a",
            "cloudflare": {"zone": "example.com", "record": "home.example.com", "token": TOKEN},
            "status_file": status_file,
            "doctor": {"private_key": Key::generate().unwrap().to_base64(), "address": "10.66.67.254"},
        }},
    });
    let server = &mut config["role"]["server"];
    if let Some(stun_server) = stun_server {
        server["stun"] = json!({
            "servers": [],
            "fallback": [stun_server.to_string()],
            "dns_server": "127.0.0.1",
        });
    }
    if let Some(control_url) = control_url {
        server["upnp"] =
            json!({"control_url": control_url, "lease_secs": 3600, "refresh_secs": 300});
    }
    let config: Config = serde_json::from_value(config).unwrap();
    config.validate().unwrap();
    config
}

/// A UPnP gateway on loopback that takes every lease and reports `wan` as
/// its WAN address. It returns its control URL and the SOAP actions it got.
async fn fake_gateway(wan: &'static str) -> (String, Arc<Mutex<Vec<String>>>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/ctl", listener.local_addr().unwrap());
    let calls = Arc::new(Mutex::new(Vec::new()));
    let seen = calls.clone();
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut buffer = [0; 4096];
            let head = loop {
                let len = stream.read(&mut buffer).await.unwrap();
                request.extend(&buffer[..len]);
                let text = String::from_utf8_lossy(&request).into_owned();
                let Some((head, body)) = text.split_once("\r\n\r\n") else {
                    continue;
                };
                let length = head
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().ok())?
                    })
                    .unwrap_or(0);
                if len == 0 || body.len() >= length {
                    break head.to_owned();
                }
            };
            let action = head
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("soapaction").then_some(value)
                })
                .unwrap_or_default()
                .trim()
                .trim_matches('"')
                .rsplit('#')
                .next()
                .unwrap_or_default()
                .to_owned();
            let fields = match action.as_str() {
                "GetExternalIPAddress" => {
                    format!("<NewExternalIPAddress>{wan}</NewExternalIPAddress>")
                }
                _ => String::new(),
            };
            let answer = format!(
                r#"<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><u:{action}Response xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">{fields}</u:{action}Response></s:Body></s:Envelope>"#
            );
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{answer}",
                answer.len()
            );
            seen.lock().unwrap().push(action);
            let _ = stream.write_all(response.as_bytes()).await;
        }
    });
    (url, calls)
}

/// Serve `config` until `check` returns, with a device that never dies.
async fn serving(config: &Config, api: &str, check: impl Future<Output = ()>) {
    let (_kill, kills) = watch::channel(0);
    let build = async |config: &Config| {
        let (device, stun) = Detached::server(config).await?;
        let kills = kills.clone();
        let device = Killable {
            device,
            kills,
            generation: 0,
        };
        Ok((device, stun))
    };
    let (stop, stopped) = oneshot::channel::<()>();
    let served = server::run(config, api, build, async {
        let _ = stopped.await;
    });
    let mut served = std::pin::pin!(served);
    tokio::select! {
        early = &mut served => panic!("the server ended early: {early:?}"),
        () = check => {}
    }
    stop.send(()).unwrap();
    served.await.unwrap();
}

/// The first status that `done` accepts, polled every 50 ms for 10 s.
async fn status_soon(path: &Path, done: impl Fn(&Status) -> bool) -> Status {
    for _ in 0..200 {
        if let Ok(status) = Status::read(path)
            && done(&status)
        {
            return status;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("no status matched; the last is {:?}", Status::read(path));
}

fn a_api() -> MockApi {
    MockApi::start(
        |request| match (request.method.as_str(), request.target.as_str()) {
            ("GET", ZONES) => ok(json!([{"id": "zone1"}])),
            ("GET", A_LOOKUP) => ok(json!([])),
            ("POST", RECORDS) => ok(json!({"id": "rec1"})),
            _ => unknown(),
        },
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn publish_a_publishes_a_mapping_that_the_upnp_gateway_confirms() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("status.json");
    let port = free_port();
    let mapped = SocketAddrV4::new(ip("45.77.0.2"), port);
    let (stun_server, _seen) = blocking_stun_server(vec![Some(mapped)]);
    let (control_url, calls) = fake_gateway("45.77.0.2").await;
    let config = publishing_a(&path, port, Some(stun_server), Some(&control_url));
    let mut api = a_api();
    let url = api.url.clone();
    serving(&config, &url, async {
        let status = status_soon(&path, |status| status.published_ip.is_some()).await;
        assert_eq!(status.publish, natwg::config::PublishMode::A);
        assert_eq!(status.record.as_deref(), Some("home.example.com"));
        assert_eq!(status.mapping, Some(mapped));
        assert_eq!(status.public_ip, Some(ip("45.77.0.2")));
        assert_eq!(status.public_by, Some(PublicBy::Upnp));
        assert_eq!(status.published_ip, Some(ip("45.77.0.2")));
        assert_eq!(status.published, None);
        assert_eq!(status.upnp_ok, Some(true));
        assert_eq!(
            status.problems(status.updated),
            ["no tunnel runs"],
            "only the detached device's missing TUN: {status:?}"
        );
        assert_eq!(
            api.taken().last(),
            Some(&a_write("POST", RECORDS, "45.77.0.2"))
        );
        let calls = calls.lock().unwrap().clone();
        assert_eq!(calls[..2], ["AddPortMapping", "GetExternalIPAddress"]);
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn publish_a_leaves_the_record_alone_when_the_gateway_is_behind_another_nat() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("status.json");
    let port = free_port();
    let mapped = SocketAddrV4::new(ip("45.77.0.2"), port);
    let (stun_server, _seen) = blocking_stun_server(vec![Some(mapped)]);
    let (control_url, _calls) = fake_gateway("100.87.0.9").await;
    let config = publishing_a(&path, port, Some(stun_server), Some(&control_url));
    let mut api = a_api();
    let url = api.url.clone();
    serving(&config, &url, async {
        let status = status_soon(&path, |status| status.public_error.is_some()).await;
        let error = status.public_error.clone().unwrap();
        assert!(
            error.contains("the UPnP gateway's WAN address 100.87.0.9 is not 45.77.0.2"),
            "{error}"
        );
        assert_eq!(status.public_ip, None);
        assert!(
            status
                .problems(status.updated)
                .contains(&"no public IP".to_owned())
        );
        real_pause().await;
        assert_eq!(writes(api.taken()), [], "nothing is published");
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn publish_a_refuses_a_mapping_that_only_keeps_the_port() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("status.json");
    let port = free_port();
    let mapped = SocketAddrV4::new(ip("45.77.0.2"), port);
    let (stun_server, _seen) = blocking_stun_server(vec![Some(mapped)]);
    let config = publishing_a(&path, port, Some(stun_server), None);
    let mut api = a_api();
    let url = api.url.clone();
    serving(&config, &url, async {
        let status = status_soon(&path, |status| status.public_error.is_some()).await;
        let error = status.public_error.clone().unwrap();
        assert!(
            error.contains(
                "keeps the listen port, but without role.server.upnp natwg cannot confirm"
            ),
            "{error}"
        );
        assert_eq!(status.mapping, Some(mapped));
        assert_eq!(status.public_ip, None);
        real_pause().await;
        assert_eq!(writes(api.taken()), [], "nothing is published");
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn publish_a_without_stun_names_an_uplink_that_is_not_public() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("status.json");
    let config = publishing_a(&path, free_port(), None, None);
    let mut api = a_api();
    let url = api.url.clone();
    serving(&config, &url, async {
        let status = status_soon(&path, |status| status.public_error.is_some()).await;
        let error = status.public_error.clone().unwrap();
        assert!(
            error.ends_with(
                "is not public, and without role.server.stun natwg cannot learn the public IP"
            ),
            "{error}"
        );
        assert!(!status.stun);
        assert_eq!((status.mapping, status.last_stun_ok), (None, None));
        real_pause().await;
        assert_eq!(writes(api.taken()), [], "nothing is published");
    })
    .await;
}

/// The tracker of publish `a` on loopback (127.0.0.1, not public), with
/// STUN and UPnP, fed by hand.
struct Tracker {
    mapping: watch::Sender<Option<Mapping>>,
    lease: watch::Sender<Option<upnp::Lease>>,
    wanted: watch::Receiver<Option<Content>>,
    public: watch::Receiver<Public>,
    recheck: &'static tokio::sync::Notify,
    /// Every value `wanted` took.
    history: Arc<Mutex<Vec<Option<Content>>>>,
}

fn at_mapping(text: &str) -> Option<Mapping> {
    Some(Mapping {
        addr: addr(text),
        since: std::time::SystemTime::now(),
    })
}

/// A lease renewal that began now: `ok`, on a gateway whose WAN is `wan`.
fn renewal(ok: bool, wan: Option<&str>) -> Option<upnp::Lease> {
    Some(upnp::Lease {
        ok,
        at: std::time::SystemTime::now(),
        external_ip: wan.map(ip),
    })
}

fn track(first_mapping: &str, first_wan: &str) -> Tracker {
    let server: &'static ServerConfig = Box::leak(Box::new(
        serde_json::from_value(json!({
            "iface": LOOPBACK,
            "listen_port": 51830,
            "lan": [],
            "publish": "a",
            "stun": {"servers": [], "fallback": [], "dns_server": "127.0.0.1"},
            "upnp": {"control_url": "http://127.0.0.1:9/ctl", "lease_secs": 600, "refresh_secs": 300},
            "cloudflare": {"zone": "example.com", "record": "home.example.com", "token": TOKEN},
        }))
        .unwrap(),
    ));
    let (mapping_tx, mapping_rx) = watch::channel(at_mapping(first_mapping));
    let (lease_tx, lease_rx) = watch::channel(renewal(true, Some(first_wan)));
    let (wanted_tx, wanted) = watch::channel(None);
    let (public_tx, public) = watch::channel(Public::default());
    let recheck: &'static tokio::sync::Notify = Box::leak(Box::default());
    let history = Arc::new(Mutex::new(Vec::new()));
    let (mut watcher, seen) = (wanted.clone(), history.clone());
    tokio::spawn(async move {
        while watcher.changed().await.is_ok() {
            seen.lock().unwrap().push(*watcher.borrow_and_update());
        }
    });
    tokio::spawn(async move {
        let never = public::run(server, mapping_rx, lease_rx, wanted_tx, public_tx, recheck).await;
        match never {}
    });
    Tracker {
        mapping: mapping_tx,
        lease: lease_tx,
        wanted,
        public,
        recheck,
        history,
    }
}

impl Tracker {
    async fn confirmed(&mut self, value: &str) {
        let value = ip(value);
        self.public
            .wait_for(|public| public.ip() == Some(value))
            .await
            .unwrap();
        self.wanted
            .wait_for(|wanted| *wanted == Some(Content::A(value)))
            .await
            .unwrap();
    }

    fn ever_wanted(&self, value: &str) -> bool {
        self.history
            .lock()
            .unwrap()
            .contains(&Some(Content::A(ip(value))))
    }
}

async fn settle() {
    for _ in 0..20 {
        tokio::task::yield_now().await;
    }
}

async fn asked_again(recheck: &tokio::sync::Notify) -> bool {
    tokio::time::timeout(Duration::from_millis(50), recheck.notified())
        .await
        .is_ok()
}

#[tokio::test(start_paused = true)]
async fn losing_the_confirmation_leaves_the_publisher_nothing_to_write() {
    let mut t = track("45.77.0.2:51830", "45.77.0.2");
    t.confirmed("45.77.0.2").await;
    t.lease.send_replace(renewal(false, None));
    t.public.wait_for(|p| p.error().is_some()).await.unwrap();
    t.wanted.wait_for(Option::is_none).await.unwrap();
    // The router reconnects as .3 while UPnP is down; the port is kept.
    t.mapping.send_replace(at_mapping("45.77.0.3:51830"));
    tokio::time::sleep(Duration::from_secs(35)).await;
    assert!(t.public.borrow().ip().is_none());
    assert_eq!(*t.wanted.borrow(), None);
    assert!(!t.ever_wanted("45.77.0.3"));
}

#[tokio::test(start_paused = true)]
async fn a_mapping_on_another_port_is_never_published_after_the_gateway_answers() {
    let mut t = track("45.77.0.2:51830", "45.77.0.2");
    t.confirmed("45.77.0.2").await;
    t.mapping.send_replace(at_mapping("45.77.0.3:52830"));
    settle().await;
    assert!(
        asked_again(t.recheck).await,
        "a mismatch asks the gateway again"
    );
    t.lease.send_replace(renewal(true, Some("45.77.0.3")));
    let error = t
        .public
        .wait_for(|p| p.error().is_some())
        .await
        .unwrap()
        .error()
        .unwrap()
        .to_owned();
    assert!(
        error.contains("does not keep the listen port 51830"),
        "{error}"
    );
    tokio::time::sleep(Duration::from_secs(35)).await;
    assert_eq!(*t.wanted.borrow(), None);
    assert!(!t.ever_wanted("45.77.0.3"));
}

/// A new mapping and an ordinary renewal that began before it reach the
/// tracker in the same poll: whichever change wakes it, the gateway is
/// asked again, nothing is confirmed meanwhile, and the status keeps its
/// verdict until the answer.
#[tokio::test(start_paused = true)]
async fn a_new_mapping_asks_the_gateway_again_whichever_change_wakes_the_tracker() {
    for run in 0..200 {
        let mut t = track("45.77.0.2:51830", "45.77.0.2");
        t.confirmed("45.77.0.2").await;
        t.mapping.send_replace(at_mapping("45.77.0.3:51830"));
        t.lease.send_replace(renewal(true, Some("45.77.0.2")));
        settle().await;
        assert!(asked_again(t.recheck).await, "run {run}: no recheck");
        assert_eq!(*t.wanted.borrow(), None, "run {run}");
        assert_eq!(
            t.public.borrow().ip(),
            Some(ip("45.77.0.2")),
            "run {run}: no false reason while the gateway is asked"
        );
        t.lease.send_replace(renewal(true, Some("45.77.0.3")));
        t.confirmed("45.77.0.3").await;
        assert_eq!(t.public.borrow().by(), Some(PublicBy::Upnp));
    }
}

#[tokio::test(start_paused = true)]
async fn a_recheck_that_gets_no_answer_ends_after_its_limit() {
    let mut t = track("45.77.0.2:51830", "45.77.0.2");
    t.confirmed("45.77.0.2").await;
    t.mapping.send_replace(at_mapping("45.77.0.3:51830"));
    settle().await;
    assert!(asked_again(t.recheck).await);
    tokio::time::sleep(public::RECHECK_LIMIT + public::ADDRESS_EVERY).await;
    let error = t.public.borrow().error().unwrap_or_default().to_owned();
    assert!(
        error.contains("WAN address 45.77.0.2 is not 45.77.0.3"),
        "{error}"
    );
    assert_eq!(*t.wanted.borrow(), None);
}

/// The first write of a confirmed IP fails; then the confirmation is lost.
/// The publisher must not write the old IP when its retry comes.
#[tokio::test(start_paused = true)]
async fn a_retry_never_writes_an_ip_that_is_no_longer_confirmed() {
    let mut api = zone_with(json!([listed("rec1", "A", "45.77.0.99", false, 60)]), 3);
    let mut t = track("45.77.0.2:51830", "45.77.0.2");
    let (state_tx, mut state) = watch::channel(Publish::Idle);
    let publisher = a_publisher(&api);
    let wanted = t.wanted.clone();
    tokio::spawn(async move {
        let never = publisher.run(wanted, state_tx).await;
        match never {}
    });
    t.confirmed("45.77.0.2").await;
    failed(&mut state).await;
    t.lease.send_replace(renewal(false, None));
    t.public.wait_for(|p| p.error().is_some()).await.unwrap();
    let before = writes(api.taken());
    assert_eq!(before, [a_write("PUT", RECORD, "45.77.0.2")]);
    tokio::time::advance(cloudflare::RETRY + Duration::from_secs(1)).await;
    real_pause().await;
    assert_eq!(
        writes(api.taken()),
        [],
        "no write while nothing is confirmed"
    );
}
