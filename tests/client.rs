//! The client: its TXT lookup, its uplink, and a client and a server in
//! memory over loopback UDP while the server moves.

use natwg::client::uplink::{self, Uplink};
use natwg::client::{self, Device, Options, resolve};
use natwg::config::Config;
use natwg::keys::{Key, PublicKey};
use natwg::status::{ClientStatus, Report};
use natwg::tunnel::{Detached, PeerStats};
use natwg::wire::dns::Record;
use natwg::wire::transport::BoundInterface;
use serde_json::json;
use std::{
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    path::Path,
    process::Command,
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
    time::Duration,
};
use tokio::{net::UdpSocket, sync::Mutex};

#[cfg(target_os = "macos")]
const LOOPBACK: &str = "lo0";
#[cfg(target_os = "linux")]
const LOOPBACK: &str = "lo";

const RECORD: &str = "_wg-home.example.com";
const SERVER: Ipv4Addr = Ipv4Addr::new(10, 66, 67, 1);
const CLIENT: Ipv4Addr = Ipv4Addr::new(10, 66, 67, 2);

fn addr(text: &str) -> SocketAddrV4 {
    text.parse().unwrap()
}

fn loopback() -> BoundInterface {
    BoundInterface::lookup(LOOPBACK).unwrap()
}

#[test]
fn an_endpoint_is_an_ipv4_address_and_a_port_quoted_or_not() {
    for (text, endpoint) in [
        ("183.192.36.226:7105", "183.192.36.226:7105"),
        ("\"183.192.36.226:7105\"", "183.192.36.226:7105"),
        ("  183.192.36.226:7105\n", "183.192.36.226:7105"),
        ("127.0.0.1:51830", "127.0.0.1:51830"),
    ] {
        assert_eq!(
            resolve::parse_endpoint(text),
            Some(addr(endpoint)),
            "{text:?}"
        );
    }
    for text in [
        "",
        "183.192.36.226",
        "183.192.36.226:0",
        "183.192.36.226:65536",
        "0.0.0.0:51830",
        "255.255.255.255:51830",
        "224.0.0.1:51830",
        "home.example.com:51830",
        "[::1]:51830",
        "183.192.036.226:7105",
        "v=spf1 -all",
        "183.192.36.226:7105 183.192.36.227:7105",
    ] {
        assert_eq!(resolve::parse_endpoint(text), None, "{text:?}");
    }
}

#[test]
fn the_first_well_formed_txt_of_an_answer_wins() {
    let records = [
        Record::A(Ipv4Addr::new(192, 0, 2, 1)),
        Record::Txt("v=spf1 -all".into()),
        Record::Txt("192.0.2.7:7000".into()),
        Record::Txt("192.0.2.8:8000".into()),
    ];
    assert_eq!(
        resolve::first_endpoint(&records),
        Some(addr("192.0.2.7:7000"))
    );
    assert_eq!(resolve::first_endpoint(&records[..2]), None);
}

/// A DNS response to `query` with one TXT answer per value.
fn txt_answer(query: &[u8], values: &[String]) -> Vec<u8> {
    let mut message = query[..2].to_vec();
    message.extend([0x81, 0x80, 0, 1]);
    message.extend((values.len() as u16).to_be_bytes());
    message.extend([0, 0, 0, 0]);
    message.extend(&query[12..]);
    for value in values {
        message.extend([0xC0, 0x0C, 0, 16, 0, 1, 0, 0, 0, 60]);
        message.extend((value.len() as u16 + 1).to_be_bytes());
        message.push(value.len() as u8);
        message.extend(value.as_bytes());
    }
    message
}

/// A DNS server on loopback that answers every TXT query with the values
/// `answer` holds at the time, and that counts the queries.
async fn dns_server(answer: Arc<std::sync::Mutex<Vec<String>>>) -> (SocketAddrV4, Arc<AtomicU32>) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let SocketAddr::V4(address) = socket.local_addr().unwrap() else {
        unreachable!()
    };
    let queries = Arc::new(AtomicU32::new(0));
    let counted = queries.clone();
    tokio::spawn(async move {
        let mut query = [0; 512];
        while let Ok((len, from)) = socket.recv_from(&mut query).await {
            counted.fetch_add(1, Ordering::SeqCst);
            let values = answer.lock().unwrap().clone();
            let _ = socket
                .send_to(&txt_answer(&query[..len], &values), from)
                .await;
        }
    });
    (address, queries)
}

fn answering(values: &[&str]) -> Arc<std::sync::Mutex<Vec<String>>> {
    Arc::new(std::sync::Mutex::new(
        values.iter().map(|value| value.to_string()).collect(),
    ))
}

/// A UDP port that takes queries and never answers.
async fn silent_server() -> (SocketAddrV4, UdpSocket) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let SocketAddr::V4(address) = socket.local_addr().unwrap() else {
        unreachable!()
    };
    (address, socket)
}

const DNS_TIMEOUT: Duration = Duration::from_millis(300);

#[tokio::test]
async fn the_first_resolver_with_a_well_formed_answer_wins() {
    let (silent, _held) = silent_server().await;
    let (garbage, _) = dns_server(answering(&["not an endpoint", "1.2.3.4"])).await;
    let (good, good_queries) = dns_server(answering(&["\"192.0.2.7:7000\""])).await;
    let (other, other_queries) = dns_server(answering(&["192.0.2.8:8000"])).await;
    let resolvers = [silent, garbage, good, other];
    let (endpoint, by) = resolve::lookup(&loopback(), &resolvers, RECORD, DNS_TIMEOUT)
        .await
        .unwrap();
    assert_eq!((endpoint, by), (addr("192.0.2.7:7000"), good));
    assert_eq!(good_queries.load(Ordering::SeqCst), 1);
    assert_eq!(
        other_queries.load(Ordering::SeqCst),
        0,
        "a resolver after the first good answer is never asked"
    );
}

#[tokio::test]
async fn a_lookup_that_finds_no_endpoint_names_each_resolver_and_what_it_said() {
    let (silent, _held) = silent_server().await;
    let (garbage, _) = dns_server(answering(&["v=spf1 -all"])).await;
    let (empty, _) = dns_server(answering(&[])).await;
    let error = resolve::lookup(&loopback(), &[silent, garbage, empty], RECORD, DNS_TIMEOUT)
        .await
        .unwrap_err();
    assert_eq!(error.code, "TXT_NO_ENDPOINT");
    for part in [
        format!("DNS_TIMEOUT: no answer from {silent}"),
        format!("{garbage} answered \"v=spf1 -all\""),
        format!("{empty} has no Txt record"),
    ] {
        assert!(
            error.message.contains(&part),
            "{part:?} in {}",
            error.message
        );
    }
}

#[test]
fn macos_lists_the_interfaces_of_its_default_routes_in_service_order() {
    let nwi = "Network information\n\nIPv4 network interface information\n   utun8 : flags      : 0x5 (IPv4,DNS)\n     en6 : flags      : 0x5 (IPv4,DNS)\n\n   REACH : flags 0x00000003 (Reachable,Transient Connection)\n\nNetwork interfaces: utun8 en6 en0\n";
    assert_eq!(uplink::service_order(nwi), ["utun8", "en6", "en0"]);
    assert!(uplink::service_order("No network information\n").is_empty());
}

#[test]
fn linux_lists_the_devices_of_its_default_routes_lowest_metric_first() {
    let listing = "default via 10.0.0.1 dev wlan0 proto dhcp src 10.0.0.5 metric 600\ndefault dev wg0 scope link\ndefault via 192.168.139.1 dev eth0 proto dhcp src 192.168.139.19 metric 100\n";
    assert_eq!(uplink::by_metric(listing), ["wg0", "eth0", "wlan0"]);
}

#[test]
fn tunnels_and_bridges_are_never_the_uplink() {
    for name in [
        "utun8",
        "utun11",
        "ipsec0",
        "ppp0",
        "lo0",
        "lo",
        "bridge101",
        "awdl0",
        "llw0",
        "wg0",
        "tun0",
        "tailscale0",
        "docker0",
        "br-1a2b",
        "veth12",
        "natwg-client",
        "vmenet0",
    ] {
        assert!(uplink::is_virtual(name), "{name}");
    }
    for name in ["en0", "en6", "eth0", "wlan0", "enp3s0", "wlp2s0", "usb0"] {
        assert!(!uplink::is_virtual(name), "{name}");
    }
}

#[test]
fn a_configured_uplink_is_looked_up_with_its_address() {
    let found = uplink::find(Some(LOOPBACK)).unwrap();
    assert_eq!(found.iface, loopback());
    assert_eq!(found.address, Some(Ipv4Addr::LOCALHOST));
    let error = uplink::find(Some("natwg_none0")).unwrap_err();
    assert_eq!(error.code, "IFACE_NOT_FOUND");
}

fn key() -> Key {
    Key::generate().unwrap()
}

fn natwg() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_natwg"));
    command.env_remove("NATWG_CONFIG");
    command
}

/// A server and its one client, which finds it through the TXT record at the
/// resolver on loopback, with a preshared key.
fn pair(status_file: &Path) -> (Config, Config) {
    let (server_key, client_key, preshared) = (key(), key(), key());
    let server = json!({
        "version": 1,
        "private_key": server_key.to_base64(),
        "interface": { "address": "10.66.67.1/24" },
        "peers": [{
            "name": "laptop",
            "public_key": client_key.public_key(),
            "preshared_key": preshared.to_base64(),
            "allowed_ips": ["10.66.67.2/32"]
        }],
        "role": { "server": {
            "instance": "natwg_test",
            "iface": LOOPBACK,
            "listen_port": 0,
            "lan": "10.24.0.0/24",
            "stun": { "servers": [], "fallback": [], "dns_server": "127.0.0.1" },
            "cloudflare": { "zone": "example.com", "record": RECORD, "token": "t" }
        }}
    });
    let client = json!({
        "version": 1,
        "private_key": client_key.to_base64(),
        "interface": { "address": "10.66.67.2/32" },
        "peers": [{
            "name": "server",
            "public_key": server_key.public_key(),
            "preshared_key": preshared.to_base64(),
            "allowed_ips": ["10.66.67.0/24"],
            "keepalive": 1
        }],
        "role": { "client": {
            "record": RECORD,
            "resolvers": ["127.0.0.1"],
            "status_file": status_file
        }}
    });
    let parse = |value| -> Config {
        let config: Config = serde_json::from_value(value).unwrap();
        config.validate().unwrap();
        config
    };
    (parse(server), parse(client))
}

/// A client device the test shares with the supervisor, so the test can
/// send through it while the supervisor points it.
struct Shared {
    device: Arc<Mutex<Detached>>,
    server: PublicKey,
}

impl Device for Shared {
    async fn failed(&mut self) {
        std::future::pending().await
    }

    /// An interface that exists, so the supervisor finds its TUN.
    fn tun(&self) -> Option<&str> {
        Some(LOOPBACK)
    }

    async fn server(&self) -> Option<PeerStats> {
        self.device.lock().await.peers().await.pop()
    }

    async fn point(&self, endpoint: SocketAddrV4) -> natwg::Result<()> {
        self.device.lock().await.point(self.server, endpoint).await
    }

    async fn rebind(&self) -> natwg::Result<()> {
        self.device.lock().await.rebind().await
    }

    async fn stop(self) {}
}

fn packet(source: Ipv4Addr, destination: Ipv4Addr, payload: &[u8]) -> Vec<u8> {
    let mut packet = vec![0x45, 0];
    packet.extend((20 + payload.len() as u16).to_be_bytes());
    packet.extend([0, 0, 0, 0, 64, 253, 0, 0]);
    packet.extend(source.octets());
    packet.extend(destination.octets());
    packet.extend(payload);
    packet
}

/// Send `payload` from the client to the server's tunnel address once a
/// second until `server` takes it, for at most `within`.
async fn reaches(
    client: &Mutex<Detached>,
    server: &mut Detached,
    payload: &[u8],
    within: Duration,
) -> bool {
    let sent = packet(CLIENT, SERVER, payload);
    let deadline = tokio::time::Instant::now() + within;
    while tokio::time::Instant::now() < deadline {
        client.lock().await.send(&sent).await.unwrap();
        let wait = tokio::time::timeout(Duration::from_millis(500), async {
            loop {
                if server.recv().await.unwrap() == sent {
                    return;
                }
            }
        });
        if wait.await.is_ok() {
            return true;
        }
    }
    false
}

fn client_status(path: &Path) -> ClientStatus {
    match Report::read(path).unwrap() {
        Report::Client(status) => status,
        Report::Server(_) => panic!("the client wrote a server status"),
    }
}

fn options(dns: SocketAddrV4) -> Options {
    Options {
        dns_port: dns.port(),
        dns_timeout: Duration::from_millis(300),
        lookup_every: Duration::from_millis(300),
        retry_every: Duration::from_millis(100),
        watch_every: Duration::from_millis(100),
        status_every: Duration::from_millis(100),
    }
}

fn loopback_uplink(address: Ipv4Addr) -> Uplink {
    Uplink {
        iface: loopback(),
        address: Some(address),
    }
}

const WITHIN: Duration = Duration::from_secs(10);

#[tokio::test(flavor = "multi_thread")]
async fn the_client_follows_the_txt_record_when_the_server_moves() {
    let dir = tempfile::tempdir().unwrap();
    let status_file = dir.path().join("client.status.json");
    let (server_config, client_config) = pair(&status_file);
    let mut first = Detached::server(&server_config).await.unwrap().0;
    let first_at = addr(&format!("127.0.0.1:{}", first.listen_port().await));
    let answer = answering(&[&first_at.to_string()]);
    let (dns, _) = dns_server(answer.clone()).await;
    let options = options(dns);
    let (handle_tx, mut handle) = tokio::sync::mpsc::unbounded_channel();
    let server_key = client_config.peers[0].public_key;
    let build = async |config: &Config, uplink: &Uplink, endpoint| {
        let device = Detached::client(config, uplink.iface.clone(), endpoint).await?;
        let device = Arc::new(Mutex::new(device));
        handle_tx.send(device.clone()).unwrap();
        Ok(Shared {
            device,
            server: server_key,
        })
    };
    let (stop_tx, stop) = tokio::sync::oneshot::channel::<()>();
    let stop = async move {
        let _ = stop.await;
    };
    let running = client::run(
        &client_config,
        &options,
        |_| Ok(loopback_uplink(Ipv4Addr::LOCALHOST)),
        build,
        stop,
    );
    let check = async {
        let device = handle.recv().await.unwrap();
        assert!(
            reaches(&device, &mut first, b"to the first server", WITHIN).await,
            "the client reaches the server that the TXT record names"
        );
        let status = client_status(&status_file);
        assert_eq!(status.endpoint, Some(first_at));
        assert_eq!(status.record.as_deref(), Some(RECORD));

        *answer.lock().unwrap() = vec!["not an endpoint".into()];
        tokio::time::sleep(Duration::from_millis(800)).await;
        let status = client_status(&status_file);
        assert!(status.lookup_error.is_some(), "{status:?}");
        assert_eq!(
            status.endpoint,
            Some(first_at),
            "a failed lookup keeps the endpoint"
        );
        assert!(reaches(&device, &mut first, b"still there", WITHIN).await);

        let mut second = Detached::server(&server_config).await.unwrap().0;
        let second_at = addr(&format!("127.0.0.1:{}", second.listen_port().await));
        assert_ne!(first_at, second_at);
        first.stop().await;
        *answer.lock().unwrap() = vec![second_at.to_string()];
        assert!(
            reaches(&device, &mut second, b"to the second server", WITHIN).await,
            "the client follows the TXT record to the second server"
        );
        let status = client_status(&status_file);
        assert_eq!(status.endpoint, Some(second_at));
        assert_eq!(status.lookup_error, None);
        assert_eq!(status.rebuilds, 0);
        assert!(status.server.unwrap().last_handshake.is_some());
        stop_tx.send(()).unwrap();
    };
    let (ran, ()) = tokio::join!(running, check);
    ran.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn the_client_rebinds_on_a_new_address_and_rebuilds_when_the_uplink_returns() {
    let dir = tempfile::tempdir().unwrap();
    let status_file = dir.path().join("client.status.json");
    let (server_config, client_config) = pair(&status_file);
    let mut server = Detached::server(&server_config).await.unwrap().0;
    let server_at = addr(&format!("127.0.0.1:{}", server.listen_port().await));
    let (dns, _) = dns_server(answering(&[&server_at.to_string()])).await;
    let options = options(dns);
    // 0: the uplink is up, 1: it has a new address, 2: it is gone, 3: back.
    let phase = AtomicU32::new(0);
    let find = |_: Option<&str>| match phase.load(Ordering::SeqCst) {
        0 => Ok(loopback_uplink(Ipv4Addr::LOCALHOST)),
        2 => Err(natwg::Error::new("IFACE_NOT_FOUND", "gone")),
        _ => Ok(loopback_uplink(Ipv4Addr::new(127, 0, 0, 2))),
    };
    let builds = AtomicU32::new(0);
    let (handle_tx, mut handle) = tokio::sync::mpsc::unbounded_channel();
    let server_key = client_config.peers[0].public_key;
    let build = async |config: &Config, uplink: &Uplink, endpoint| {
        builds.fetch_add(1, Ordering::SeqCst);
        let device = Detached::client(config, uplink.iface.clone(), endpoint).await?;
        let device = Arc::new(Mutex::new(device));
        handle_tx.send(device.clone()).unwrap();
        Ok(Shared {
            device,
            server: server_key,
        })
    };
    let (stop_tx, stop) = tokio::sync::oneshot::channel::<()>();
    let stop = async move {
        let _ = stop.await;
    };
    let running = client::run(&client_config, &options, find, build, stop);
    let check = async {
        let device = handle.recv().await.unwrap();
        assert!(reaches(&device, &mut server, b"first", WITHIN).await);

        phase.store(1, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(500)).await;
        let status = client_status(&status_file);
        assert_eq!(status.uplink_address, Some(Ipv4Addr::new(127, 0, 0, 2)));
        assert_eq!(
            builds.load(Ordering::SeqCst),
            1,
            "a new address only rebinds"
        );
        assert!(reaches(&device, &mut server, b"after the rebind", WITHIN).await);

        phase.store(2, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(500)).await;
        let status = client_status(&status_file);
        assert_eq!(status.tun, None);
        assert!(
            Report::Client(status)
                .problems(natwg::status::unix(std::time::SystemTime::now()))
                .contains(&"no tunnel runs".to_owned())
        );

        phase.store(3, Ordering::SeqCst);
        let device = tokio::time::timeout(Duration::from_secs(5), handle.recv())
            .await
            .expect("the uplink coming back rebuilds before the backoff ends")
            .unwrap();
        assert!(reaches(&device, &mut server, b"after the rebuild", WITHIN).await);
        assert_eq!(builds.load(Ordering::SeqCst), 2);
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(client_status(&status_file).rebuilds, 1);
        stop_tx.send(()).unwrap();
    };
    let (ran, ()) = tokio::join!(running, check);
    ran.unwrap();
}

#[tokio::test]
async fn a_client_whose_first_build_fails_ends_with_the_error() {
    let dir = tempfile::tempdir().unwrap();
    let (_, client_config) = pair(&dir.path().join("status.json"));
    let options = Options::default();
    let build = async |_: &Config, _: &Uplink, _| -> natwg::Result<Shared> {
        Err(natwg::Error::new("ROUTE_IN_USE", "taken"))
    };
    let find = |_: Option<&str>| Ok(loopback_uplink(Ipv4Addr::LOCALHOST));
    let error = client::run(
        &client_config,
        &options,
        find,
        build,
        std::future::pending(),
    )
    .await
    .unwrap_err();
    assert_eq!(error.code, "ROUTE_IN_USE");
}

#[test]
fn natwg_client_and_server_need_their_own_role() {
    let dir = tempfile::tempdir().unwrap();
    let (server, client) = pair(&dir.path().join("status.json"));
    for (config, command, other) in [(&server, "client", "server"), (&client, "server", "client")] {
        let path = dir.path().join(format!("{other}.json"));
        config.save(&path).unwrap();
        let output = natwg()
            .args(["--config", path.to_str().unwrap(), command, "--foreground"])
            .output()
            .unwrap();
        assert!(!output.status.success());
        let stderr = String::from_utf8(output.stderr).unwrap();
        let root = unsafe { libc::geteuid() } == 0;
        let expected = if root {
            "ROLE_MISMATCH: "
        } else {
            "NOT_ROOT: "
        };
        assert!(stderr.starts_with(expected), "{command}: {stderr}");
    }
}
