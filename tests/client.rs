//! The client: its TXT lookup, its uplink, the wg-quick import, and a client
//! and a server in memory over loopback UDP while the server moves.

use natwg::client::uplink::{self, Uplink};
use natwg::client::{self, Device, Options, resolve, wg_quick};
use natwg::config::{Config, Role};
use natwg::keys::{Key, PublicKey};
use natwg::status::{ClientStatus, Report};
use natwg::tunnel::{Detached, PeerStats};
use natwg::wire::dns::Record;
use natwg::wire::transport::BoundInterface;
use serde_json::{Value, json};
use std::{
    fs,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    path::Path,
    process::{Command, Output},
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
        ("203.0.113.7:52830", "203.0.113.7:52830"),
        ("\"203.0.113.7:52830\"", "203.0.113.7:52830"),
        ("  203.0.113.7:52830\n", "203.0.113.7:52830"),
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
        "203.0.113.7",
        "203.0.113.7:0",
        "203.0.113.7:65536",
        "0.0.0.0:51830",
        "255.255.255.255:51830",
        "224.0.0.1:51830",
        "home.example.com:51830",
        "[::1]:51830",
        "183.192.036.226:7105",
        "v=spf1 -all",
        "203.0.113.7:52830 203.0.113.8:52830",
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

/// A DNS response to `query` with one A answer per address.
fn a_answer(query: &[u8], addresses: &[Ipv4Addr]) -> Vec<u8> {
    let mut message = query[..2].to_vec();
    message.extend([0x81, 0x80, 0, 1]);
    message.extend((addresses.len() as u16).to_be_bytes());
    message.extend([0, 0, 0, 0]);
    message.extend(&query[12..]);
    for address in addresses {
        message.extend([0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
        message.extend(address.octets());
    }
    message
}

type Addresses = Arc<std::sync::Mutex<Vec<Ipv4Addr>>>;

/// A DNS server on loopback that answers every A query with the addresses
/// `answer` holds at the time, and that counts the queries.
async fn a_dns_server(answer: Addresses) -> (SocketAddrV4, Arc<AtomicU32>) {
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
            let addresses = answer.lock().unwrap().clone();
            let _ = socket
                .send_to(&a_answer(&query[..len], &addresses), from)
                .await;
        }
    });
    (address, queries)
}

fn holding(addresses: &[&str]) -> Addresses {
    Arc::new(std::sync::Mutex::new(
        addresses
            .iter()
            .map(|address| address.parse().unwrap())
            .collect(),
    ))
}

const HOME: &str = "home.example.com";

#[test]
fn only_a_public_address_of_an_a_answer_can_be_the_server() {
    for private in [
        "127.0.0.1",
        "10.0.0.5",
        "172.16.0.1",
        "192.168.1.1",
        "100.64.1.1",
        "169.254.0.1",
        "198.18.0.5",
        "198.19.255.1",
        "0.0.0.0",
        "224.0.0.1",
        "255.255.255.255",
    ] {
        let records = [Record::A(private.parse().unwrap())];
        assert_eq!(resolve::first_address(&records), None, "{private}");
    }
    let records = [
        Record::A("198.18.0.5".parse().unwrap()),
        Record::Txt("45.77.0.9".into()),
        Record::A("45.77.0.10".parse().unwrap()),
    ];
    assert_eq!(
        resolve::first_address(&records),
        Some("45.77.0.10".parse().unwrap())
    );
}

#[tokio::test]
async fn the_first_resolver_with_a_public_a_record_gives_the_ip_at_the_servers_port() {
    let (silent, _held) = silent_server().await;
    let (private, _) = a_dns_server(holding(&["127.0.0.1", "10.0.0.5", "100.64.1.1"])).await;
    let (good, good_queries) = a_dns_server(holding(&["198.18.0.5", "45.77.0.10"])).await;
    let (other, other_queries) = a_dns_server(holding(&["45.77.0.12"])).await;
    let server = format!("{HOME}:51830").parse().unwrap();
    let resolvers = [silent, private, good, other];
    let found = resolve::lookup_a(&loopback(), &resolvers, &server, DNS_TIMEOUT).await;
    assert_eq!(found.unwrap(), (addr("45.77.0.10:51830"), good));
    assert_eq!(good_queries.load(Ordering::SeqCst), 1);
    assert_eq!(other_queries.load(Ordering::SeqCst), 0);

    let (fake_ip, _) = a_dns_server(holding(&["198.18.0.5"])).await;
    let error = resolve::lookup_a(&loopback(), &[silent, fake_ip], &server, DNS_TIMEOUT)
        .await
        .unwrap_err();
    assert_eq!(error.code, "A_NO_ADDRESS");
    for part in [
        format!("no DNS server gave a public A record for {HOME}: "),
        format!("DNS_TIMEOUT: no answer from {silent}"),
        format!("{HOME} answered 198.18.0.5 at {fake_ip}, not a public address (a fake-IP DNS?)"),
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

struct WgQuick {
    client: Key,
    server: PublicKey,
    preshared: Key,
}

impl WgQuick {
    fn new() -> Self {
        Self {
            client: key(),
            server: key().public_key(),
            preshared: key(),
        }
    }

    /// A client config as the Python natwg install wrote it.
    fn text(&self) -> String {
        format!(
            "# natwg client config. Endpoint is kept current by natwg-client-update.sh\n\
             # (it reads the TXT record _wg-home.example.com).\n\
             [Interface]\n\
             PrivateKey = {}\n\
             Address = 10.66.66.2/32\n\
             MTU = 1420\n\
             \n\
             [Peer]\n\
             PublicKey = {}\n\
             PresharedKey = {}\n\
             AllowedIPs = 10.66.66.0/24, 10.24.0.0/24\n\
             Endpoint = 0.0.0.0:0\n\
             PersistentKeepalive = 25\n",
            self.client.to_base64(),
            self.server,
            self.preshared.to_base64()
        )
    }

    fn secrets(&self) -> [String; 2] {
        [self.client.to_base64(), self.preshared.to_base64()]
    }
}

fn write(dir: &Path, text: &str) -> std::path::PathBuf {
    let path = dir.join("wg-home.conf");
    fs::write(&path, text).unwrap();
    path
}

#[test]
fn a_wg_quick_client_keeps_its_keys_address_and_routes() {
    let dir = tempfile::tempdir().unwrap();
    let conf = WgQuick::new();
    let path = write(dir.path(), &conf.text());
    let config = wg_quick::import(&path, Some(RECORD.into()), vec![]).unwrap();
    let expected: Config = serde_json::from_value(json!({
        "version": 1,
        "private_key": conf.client.to_base64(),
        "interface": { "address": "10.66.66.2/32", "mtu": 1420 },
        "peers": [{
            "name": "server",
            "public_key": conf.server,
            "preshared_key": conf.preshared.to_base64(),
            "allowed_ips": ["10.66.66.0/24", "10.24.0.0/24"],
            "keepalive": 25
        }],
        "role": { "client": {
            "record": RECORD,
            "resolvers": ["223.5.5.5", "119.29.29.29", "1.1.1.1", "8.8.8.8"]
        }}
    }))
    .unwrap();
    assert_eq!(config, expected, "Endpoint = 0.0.0.0:0 is no endpoint");
    config.validate().unwrap();
}

#[test]
fn a_wg_quick_endpoint_stands_in_for_a_record() {
    let dir = tempfile::tempdir().unwrap();
    let text = WgQuick::new()
        .text()
        .replace("0.0.0.0:0", "192.0.2.7:51830");
    let path = write(dir.path(), &text);
    let resolvers = vec![Ipv4Addr::new(9, 9, 9, 9)];
    let config = wg_quick::import(&path, None, resolvers).unwrap();
    assert_eq!(config.peers[0].endpoint, Some(addr("192.0.2.7:51830")));
    let Role::Client(client) = &config.role else {
        panic!("a wg-quick import is a client config")
    };
    assert_eq!(client.record, None);

    let path = write(dir.path(), &WgQuick::new().text());
    let error = wg_quick::import(&path, None, vec![]).unwrap_err();
    assert_eq!(error.code, "WG_QUICK_INVALID");
    assert!(
        error
            .message
            .contains("role.client.record, role.client.server or peers[0].endpoint"),
        "{}",
        error.message
    );
}

#[test]
fn a_wg_quick_config_that_natwg_cannot_run_is_refused_by_line_and_key() {
    let dir = tempfile::tempdir().unwrap();
    let base = WgQuick::new().text();
    let second_peer = format!(
        "{base}\n[Peer]\nPublicKey = {}\nAllowedIPs = 10.9.0.0/24\n",
        key().public_key()
    );
    for (text, expected) in [
        (
            base.replace("MTU = 1420", "DNS = 10.24.0.1"),
            "line 6: natwg client does not support the [Interface] key DNS",
        ),
        (
            base.replace("MTU = 1420", "PostUp = true"),
            "line 6: natwg client does not support the [Interface] key PostUp",
        ),
        (
            base.replace(
                "Address = 10.66.66.2/32",
                "Address = 10.66.66.2/32, fd00::2/128",
            ),
            "line 5: Address must be one IPv4 address",
        ),
        (
            base.replace("10.24.0.0/24", "::/0"),
            "line 11: AllowedIPs must be IPv4 networks",
        ),
        (
            base.replace("0.0.0.0:0", "home.example.com:51830"),
            "line 12: Endpoint must be an IPv4 address",
        ),
        (
            base.replace("0.0.0.0:0", "0.0.0.0:0\nTable = off"),
            "natwg client does not support the [Peer] key table",
        ),
        (
            second_peer,
            "exactly one [Peer], the server, and this one has 2",
        ),
        (
            base.replace("10.66.66.0/24, 10.24.0.0/24", "0.0.0.0/0"),
            "default route",
        ),
    ] {
        let path = write(dir.path(), &text);
        let error = wg_quick::import(&path, Some(RECORD.into()), vec![]).unwrap_err();
        assert_eq!(error.code, "WG_QUICK_INVALID");
        assert!(
            error.message.contains(expected),
            "{expected:?} in {}",
            error.message
        );
    }
}

fn natwg() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_natwg"));
    command.env_remove("NATWG_CONFIG");
    command
}

fn import(path: &Path, extra: &[&str]) -> Output {
    natwg()
        .args(["config", "import-wg-quick"])
        .arg(path)
        .args(extra)
        .output()
        .unwrap()
}

#[test]
fn a_malformed_wg_quick_line_never_echoes_a_key() {
    let dir = tempfile::tempdir().unwrap();
    let conf = WgQuick::new();
    let text = conf.text();
    let private = conf.client.to_base64();
    let private_line = format!("PrivateKey = {private}");
    let letters = "QWErtyUIOPasdfghJKLzxcvbnmQWERTYUIOPasdfghA=";
    let cases = [
        format!("PrivateKey: {private}"),
        format!("PrivateKey{letters}"),
        letters.to_owned(),
        format!("PrivateKey = {}", &private[..40]),
        format!("Address = {private}"),
        format!("MTU = {private}"),
        format!("{letters} = 1"),
        format!("[{private}]"),
    ];
    for line in cases {
        let path = write(dir.path(), &text.replace(&private_line, &line));
        let output = import(&path, &["--dry-run", "--record", RECORD]);
        assert!(!output.status.success(), "{line}");
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(stderr.starts_with("WG_QUICK_INVALID: "), "{stderr}");
        let lower = stderr.to_lowercase();
        for secret in conf.secrets().iter().map(String::as_str).chain([letters]) {
            assert!(
                !lower.contains(&secret[..16].to_lowercase()),
                "{line}: {stderr}"
            );
        }
    }
    for (key, text) in [
        (
            "PublicKey",
            text.replace(&conf.server.to_string(), &private),
        ),
        (
            "PresharedKey",
            text.replace(&conf.preshared.to_base64(), &format!("{private}x")),
        ),
    ] {
        let path = write(dir.path(), &text);
        let output = import(&path, &["--dry-run", "--record", RECORD]);
        let stderr = String::from_utf8(output.stderr).unwrap();
        if key == "PresharedKey" {
            assert!(
                stderr.contains("PresharedKey is not a 32-byte key"),
                "{stderr}"
            );
        }
        assert!(!stderr.contains(&private[..16]), "{key}: {stderr}");
    }
}

#[test]
fn import_wg_quick_prints_the_redacted_config_and_writes_it_only_once() {
    let dir = tempfile::tempdir().unwrap();
    let conf = WgQuick::new();
    let path = write(dir.path(), &conf.text());
    let out = dir.path().join("etc/natwg/config.json");
    let out_arg = out.to_str().unwrap();

    let output = import(
        &path,
        &[
            "--record",
            RECORD,
            "--resolver",
            "1.1.1.1",
            "--out",
            out_arg,
        ],
    );
    assert!(output.status.success(), "{output:?}");
    let shown: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(shown["public_key"], conf.client.public_key().to_string());
    assert_eq!(shown["private_key"], "<redacted>");
    assert_eq!(shown["role"]["client"]["resolvers"], json!(["1.1.1.1"]));
    let printed =
        String::from_utf8(output.stdout).unwrap() + &String::from_utf8(output.stderr).unwrap();
    for secret in conf.secrets() {
        assert!(!printed.contains(&secret), "{secret} printed");
    }
    let saved = Config::load(&out).unwrap();
    assert_eq!(saved.private_key, conf.client);
    let mode = fs::metadata(&out).unwrap().permissions();
    assert_eq!(
        std::os::unix::fs::PermissionsExt::mode(&mode) & 0o777,
        0o600
    );

    let again = import(&path, &["--record", RECORD, "--out", out_arg]);
    assert!(!again.status.success());
    let stderr = String::from_utf8(again.stderr).unwrap();
    assert!(stderr.starts_with("CONFIG_EXISTS: "), "{stderr}");
    let forced = import(&path, &["--record", RECORD, "--out", out_arg, "--force"]);
    assert!(forced.status.success(), "{forced:?}");
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
        txt_every: Duration::from_millis(300),
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
        let status = client_status_until(&status_file, |state| {
            state.endpoint == Some(second_at)
                && state.server.as_ref().is_some_and(|s| {
                    s.endpoint == Some(second_at.into()) && s.last_handshake.is_some()
                })
        })
        .await;
        assert_eq!(status.endpoint, Some(second_at));
        assert_eq!(status.lookup_error, None);
        assert_eq!(status.rebuilds, 0);
        assert!(status.server.unwrap().last_handshake.is_some());
        stop_tx.send(()).unwrap();
    };
    let (ran, ()) = tokio::join!(running, check);
    ran.unwrap();
}

/// The client status once `done` accepts it, polled for one steady handshake check plus scheduling slack.
async fn client_status_until(path: &Path, done: impl Fn(&ClientStatus) -> bool) -> ClientStatus {
    for _ in 0..250 {
        if let Ok(Report::Client(status)) = Report::read(path)
            && done(&status)
        {
            return status;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!(
        "no client status matched; the last is {:?}",
        Report::read(path)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_client_follows_the_a_record_to_public_addresses_only_and_keeps_the_last() {
    let dir = tempfile::tempdir().unwrap();
    let status_file = dir.path().join("client.status.json");
    let (_, mut client_config) = pair(&status_file);
    let Role::Client(role) = &mut client_config.role else {
        unreachable!()
    };
    role.record = None;
    role.server = Some(format!("{HOME}:51830").parse().unwrap());
    client_config.validate().unwrap();
    let answer = holding(&[]);
    let (dns, _) = a_dns_server(answer.clone()).await;
    let options = options(dns);
    let server_key = client_config.peers[0].public_key;
    let build = async |config: &Config, uplink: &Uplink, endpoint| {
        let device = Detached::client(config, uplink.iface.clone(), endpoint).await?;
        Ok(Shared {
            device: Arc::new(Mutex::new(device)),
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
        let status = client_status_until(&status_file, |s| s.lookup_error.is_some()).await;
        assert_eq!(status.record.as_deref(), Some(HOME));
        assert_eq!(status.record_type, Some(natwg::config::PublishMode::A));
        assert_eq!(status.endpoint, None, "no A record yet");

        *answer.lock().unwrap() = vec!["198.18.0.5".parse().unwrap()];
        let status = client_status_until(&status_file, |s| {
            s.lookup_error
                .as_deref()
                .is_some_and(|e| e.contains("198.18.0.5"))
        })
        .await;
        let error = status.lookup_error.unwrap();
        assert!(
            error.contains(&format!(
                "{HOME} answered 198.18.0.5 at {dns}, not a public address (a fake-IP DNS?)"
            )),
            "{error}"
        );
        assert_eq!(
            status.endpoint, None,
            "a fake-IP answer is never the server"
        );

        *answer.lock().unwrap() = vec!["45.77.0.10".parse().unwrap()];
        let at = addr("45.77.0.10:51830");
        let status = client_status_until(&status_file, |s| s.endpoint == Some(at)).await;
        assert_eq!(status.lookup_error, None);

        *answer.lock().unwrap() = vec![Ipv4Addr::LOCALHOST];
        let status = client_status_until(&status_file, |s| s.lookup_error.is_some()).await;
        assert!(
            status
                .lookup_error
                .unwrap()
                .contains("not a public address"),
            "a loopback answer is refused"
        );
        assert_eq!(
            status.endpoint,
            Some(at),
            "a refused answer keeps the endpoint"
        );
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

#[tokio::test(start_paused = true)]
async fn fixed_endpoint_writes_status_on_first_handshake_then_heartbeat_despite_byte_changes() {
    use std::os::unix::fs::MetadataExt;

    struct Idle {
        server: PublicKey,
        shook: std::time::SystemTime,
        samples: Arc<AtomicU32>,
    }

    impl Device for Idle {
        async fn failed(&mut self) {
            std::future::pending().await
        }
        fn tun(&self) -> Option<&str> {
            Some(LOOPBACK)
        }
        async fn server(&self) -> Option<PeerStats> {
            let sample = self.samples.fetch_add(1, Ordering::Relaxed);
            Some(PeerStats {
                public_key: self.server,
                endpoint: Some(addr("127.0.0.1:51830").into()),
                last_handshake: (sample > 0).then(|| self.shook.elapsed().unwrap()),
                rx_bytes: u64::from(sample) * 32,
                tx_bytes: u64::from(sample) * 32,
            })
        }
        async fn point(&self, _: SocketAddrV4) -> natwg::Result<()> {
            panic!("fixed endpoint was replaced")
        }
        async fn rebind(&self) -> natwg::Result<()> {
            panic!("unchanged uplink was rebound")
        }
        async fn stop(self) {}
    }

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("status.json");
    let (_, mut config) = pair(&path);
    let Role::Client(role) = &mut config.role else {
        unreachable!()
    };
    role.record = None;
    config.peers[0].endpoint = Some(addr("127.0.0.1:51830"));
    let key = config.peers[0].public_key;
    let samples = Arc::new(AtomicU32::new(0));
    let build = async |_: &Config, _: &Uplink, _| {
        Ok(Idle {
            server: key,
            shook: std::time::SystemTime::now(),
            samples: samples.clone(),
        })
    };
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
    let options = Options::default();
    let running = client::run(
        &config,
        &options,
        |_| Ok(loopback_uplink(Ipv4Addr::LOCALHOST)),
        build,
        async { stop_rx.await.unwrap() },
    );
    let check = async {
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(samples.load(Ordering::Relaxed), 1);
        let initial = fs::metadata(&path).unwrap().ino();
        tokio::time::sleep(Duration::from_millis(1100)).await;
        let first = fs::metadata(&path).unwrap().ino();
        assert_ne!(first, initial, "first handshake publishes immediately");
        assert_eq!(samples.load(Ordering::Relaxed), 2);
        tokio::time::sleep(Duration::from_secs(9)).await;
        assert_eq!(samples.load(Ordering::Relaxed), 2);
        let held = fs::File::open(&path).unwrap();
        tokio::time::sleep(Duration::from_secs(20)).await;
        assert_eq!(samples.load(Ordering::Relaxed), 4);
        assert_eq!(
            fs::metadata(&path).unwrap().ino(),
            first,
            "byte totals alone do not write"
        );
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert_ne!(
            fs::metadata(&path).unwrap().ino(),
            held.metadata().unwrap().ino()
        );
        assert!(client_status(&path).server.unwrap().rx >= 96);
        stop_tx.send(()).unwrap();
    };
    let (result, ()) = tokio::join!(running, check);
    result.unwrap();
}

#[test]
fn idle_pause_is_opt_in_and_does_not_override_a_configured_zero_keepalive() {
    let dir = tempfile::tempdir().unwrap();
    let (_, client) = pair(&dir.path().join("status.json"));
    let path = dir.path().join("client.json");
    client.save(&path).unwrap();
    let mut value: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    assert!(value["role"]["client"].get("idle_pause_minutes").is_none());
    value["peers"][0]
        .as_object_mut()
        .unwrap()
        .remove("keepalive");
    let default: Config = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(natwg::tunnel::client_keepalive(&default.peers[0]), 25);
    value["role"]["client"]["idle_pause_minutes"] = json!(3);
    value["peers"][0]["keepalive"] = json!(0);
    let configured: Config = serde_json::from_value(value.clone()).unwrap();
    configured.validate().unwrap();
    assert_eq!(natwg::tunnel::client_keepalive(&configured.peers[0]), 0);
    assert_eq!(
        serde_json::to_value(configured).unwrap()["role"],
        value["role"]
    );
    value["role"]["client"]["idle_pause_minutes"] = json!(0);
    assert!(serde_json::from_value::<Config>(value).is_err());
}
