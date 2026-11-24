use natwg::config::{CloudflareConfig, ServerConfig, StunConfig};
use natwg::server::cloudflare::{self, Publish, Publisher, Record};
use natwg::server::keepalive::{self, Health, Mapping, Targets};
use natwg::server::upnp::{self, Upnp};
use natwg::wire::transport::{BoundInterface, StunPort};
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    io::{BufRead, BufReader, Read, Write},
    net::{SocketAddr, SocketAddrV4, TcpStream},
    num::NonZeroU64,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, SystemTime},
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

fn mapping(text: &str) -> Option<Mapping> {
    Some(Mapping {
        addr: addr(text),
        since: SystemTime::now(),
    })
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
    let value = addr(value);
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
    let publisher = Publisher::new(&cloudflare_config(), &api.url).unwrap();
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
    let publisher = Publisher::new(&cloudflare_config(), &api.url).unwrap();
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
    let publisher = Publisher::new(&cloudflare_config(), &api.url).unwrap();
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
    let publisher = Publisher::new(&cloudflare_config(), &api.url).unwrap();
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
