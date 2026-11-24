//! The WireGuard device and the doctor, run in memory over loopback UDP.

use natwg::config::Config;
use natwg::doctor::{self, Echo, EchoKind, Probe};
use natwg::keys::Key;
use natwg::tunnel::Detached;
use serde_json::{Value, json};
use std::{
    net::{Ipv4Addr, SocketAddrV4},
    num::NonZeroU16,
    process::{Command, Output},
    time::Duration,
};

#[cfg(target_os = "macos")]
const LOOPBACK: &str = "lo0";
#[cfg(target_os = "linux")]
const LOOPBACK: &str = "lo";

const SERVER: Ipv4Addr = Ipv4Addr::new(10, 66, 67, 1);
const DOCTOR: Ipv4Addr = Ipv4Addr::new(10, 66, 67, 254);
const LAN_HOST: Ipv4Addr = Ipv4Addr::new(10, 24, 0, 1);

fn key() -> String {
    Key::generate().unwrap().to_base64()
}

fn public(private: &str) -> String {
    private.parse::<Key>().unwrap().public_key().to_string()
}

fn server_json(private: &str) -> Value {
    json!({
        "version": 1,
        "private_key": private,
        "interface": { "address": "10.66.67.1/24" },
        "peers": [],
        "role": { "server": {
            "instance": "natwg_test",
            "iface": LOOPBACK,
            "listen_port": 0,
            "lan": "10.24.0.0/24",
            "stun": { "servers": [], "fallback": [], "dns_server": "127.0.0.1" },
            "cloudflare": { "zone": "example.com", "record": "_wg.example.com", "token": "t" }
        }}
    })
}

fn config(value: Value) -> Config {
    serde_json::from_value(value).unwrap()
}

fn with_doctor() -> Config {
    let mut value = server_json(&key());
    value["role"]["server"]["doctor"] = json!({ "private_key": key(), "address": DOCTOR });
    config(value)
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

async fn endpoint(device: &Detached) -> SocketAddrV4 {
    SocketAddrV4::new(Ipv4Addr::LOCALHOST, device.listen_port().await)
}

async fn dial_as_doctor(config: &Config, server: &Detached) -> Detached {
    let doctor = config.server().unwrap().doctor.as_ref().unwrap();
    Detached::doctor(config, doctor, None, endpoint(server).await)
        .await
        .unwrap()
}

async fn next(device: &mut Detached) -> Vec<u8> {
    tokio::time::timeout(Duration::from_secs(5), device.recv())
        .await
        .expect("a packet crosses the tunnel within 5 s")
        .unwrap()
}

async fn nothing_more(device: &mut Detached) {
    let arrived = tokio::time::timeout(Duration::from_millis(300), device.recv()).await;
    assert!(
        arrived.is_err(),
        "an unexpected packet arrived: {arrived:?}"
    );
}

#[tokio::test]
async fn the_doctor_reaches_the_server_and_the_server_answers() {
    let config = with_doctor();
    let mut server = Detached::server(&config).await.unwrap();
    let mut doctor = dial_as_doctor(&config, &server).await;

    let request = packet(DOCTOR, SERVER, b"to the tunnel address");
    doctor.send(&request).await.unwrap();
    assert_eq!(next(&mut server).await, request);

    let reply = packet(SERVER, DOCTOR, b"back to the doctor");
    server.send(&reply).await.unwrap();
    assert_eq!(next(&mut doctor).await, reply);
}

#[tokio::test]
async fn the_doctor_sends_the_lan_through_the_tunnel_and_nothing_else() {
    let config = with_doctor();
    let mut server = Detached::server(&config).await.unwrap();
    let doctor = dial_as_doctor(&config, &server).await;

    let outside = packet(DOCTOR, Ipv4Addr::new(192, 0, 2, 1), b"not routed");
    let lan = packet(DOCTOR, LAN_HOST, b"to the LAN");
    doctor.send(&outside).await.unwrap();
    doctor.send(&lan).await.unwrap();
    assert_eq!(next(&mut server).await, lan);
    nothing_more(&mut server).await;
}

#[tokio::test]
async fn the_server_accepts_only_the_doctors_own_address_from_the_doctor() {
    let config = with_doctor();
    let mut server = Detached::server(&config).await.unwrap();
    let doctor = dial_as_doctor(&config, &server).await;

    let spoofed = packet(Ipv4Addr::new(10, 66, 67, 9), SERVER, b"spoofed source");
    let honest = packet(DOCTOR, SERVER, b"honest source");
    doctor.send(&spoofed).await.unwrap();
    doctor.send(&honest).await.unwrap();
    assert_eq!(next(&mut server).await, honest);
    nothing_more(&mut server).await;
}

fn pair(server_psk: &str, client_psk: &str) -> (Config, Config, Ipv4Addr) {
    let (server_key, client_key) = (key(), key());
    let client = Ipv4Addr::new(10, 66, 67, 2);
    let mut server = server_json(&server_key);
    server["peers"] = json!([{
        "name": "laptop",
        "public_key": public(&client_key),
        "preshared_key": server_psk,
        "allowed_ips": ["10.66.67.2/32"]
    }]);
    let mut dialer = server_json(&client_key);
    dialer["interface"]["address"] = json!("10.66.67.2/32");
    dialer["peers"] = json!([{
        "name": "home",
        "public_key": public(&server_key),
        "preshared_key": client_psk,
        "allowed_ips": ["10.66.67.0/24"]
    }]);
    (config(server), config(dialer), client)
}

async fn dial(server: &Detached, mut dialer: Config) -> Detached {
    dialer.peers[0].endpoint = Some(endpoint(server).await);
    Detached::server(&dialer).await.unwrap()
}

#[tokio::test]
async fn a_configured_peer_with_the_same_preshared_key_exchanges_packets() {
    let psk = key();
    let (server, dialer, client) = pair(&psk, &psk);
    let mut server = Detached::server(&server).await.unwrap();
    let mut dialer = dial(&server, dialer).await;

    let request = packet(client, SERVER, b"from the laptop");
    dialer.send(&request).await.unwrap();
    assert_eq!(next(&mut server).await, request);

    let reply = packet(SERVER, client, b"from home");
    server.send(&reply).await.unwrap();
    assert_eq!(next(&mut dialer).await, reply);
}

#[tokio::test]
async fn peers_with_different_preshared_keys_exchange_nothing() {
    let (server, dialer, client) = pair(&key(), &key());
    let mut server = Detached::server(&server).await.unwrap();
    let dialer = dial(&server, dialer).await;

    dialer
        .send(&packet(client, SERVER, b"wrong key"))
        .await
        .unwrap();
    nothing_more(&mut server).await;
}

#[tokio::test]
async fn a_server_without_a_peer_or_a_doctor_does_not_start() {
    let config = config(server_json(&key()));
    let error = Detached::server(&config).await.err().unwrap();
    assert_eq!(error.code, "TUNNEL_NO_PEERS");
}

#[tokio::test]
async fn a_client_config_is_not_a_server() {
    let mut value = server_json(&key());
    value["role"] = json!({ "client": { "record": "_wg.example.com", "resolvers": ["1.1.1.1"] } });
    let error = Detached::server(&config(value)).await.err().unwrap();
    assert_eq!(error.code, "ROLE_MISMATCH");
}

#[tokio::test]
async fn a_doctor_on_a_missing_interface_reports_the_interface() {
    let config = with_doctor();
    let doctor = config.server().unwrap().doctor.as_ref().unwrap();
    let endpoint = "127.0.0.1:9".parse().unwrap();
    let error = Detached::doctor(&config, doctor, Some("natwg-none0"), endpoint)
        .await
        .err()
        .unwrap();
    assert_eq!(error.code, "IFACE_NOT_FOUND");
}

// An echo request and its reply as the macOS kernel wrote them, captured on
// lo0 with `tcpdump -x` during `ping -c 1 -s 24 127.0.0.1`.
const KERNEL_REQUEST: &str = "4500 0034 282e 0000 4001 0000 7f00 0001 7f00 0001
    0800 4898 6d96 0000 6b05 27da 0000 3671 0809 0a0b 0c0d 0e0f 1011 1213 1415 1617";
const KERNEL_REPLY: &str = "4500 0034 7d50 0000 4001 0000 7f00 0001 7f00 0001
    0000 5098 6d96 0000 6b05 27da 0000 3671 0809 0a0b 0c0d 0e0f 1011 1213 1415 1617";

fn hex(text: &str) -> Vec<u8> {
    let digits: Vec<u8> = text.bytes().filter(u8::is_ascii_hexdigit).collect();
    digits
        .chunks(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn ones_complement_sum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    for pair in bytes.chunks(2) {
        sum += u32::from(pair[0]) << 8 | u32::from(*pair.get(1).unwrap_or(&0));
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    sum as u16
}

fn request() -> Echo {
    Echo {
        kind: EchoKind::Request,
        source: DOCTOR,
        destination: SERVER,
        id: 0x1234,
        seq: 7,
    }
}

fn pong(request: Echo) -> Echo {
    Echo {
        kind: EchoKind::Reply,
        source: request.destination,
        destination: request.source,
        ..request
    }
}

#[test]
fn an_echo_request_is_an_ipv4_icmp_packet_with_valid_checksums() {
    let packet = request().encode();
    assert_eq!(packet[0], 0x45, "IPv4 with a 20-byte header");
    assert_eq!(
        usize::from(u16::from_be_bytes([packet[2], packet[3]])),
        packet.len()
    );
    assert_eq!(packet[9], 1, "protocol ICMP");
    assert_eq!(packet[12..16], DOCTOR.octets());
    assert_eq!(packet[16..20], SERVER.octets());
    assert_eq!(packet[20..22], [8, 0], "echo request, code 0");
    assert_eq!(packet[24..28], [0x12, 0x34, 0x00, 0x07], "id then sequence");
    assert_eq!(ones_complement_sum(&packet[..20]), 0xFFFF, "IP header");
    assert_eq!(ones_complement_sum(&packet[20..]), 0xFFFF, "ICMP message");

    let reply = pong(request()).encode();
    assert_eq!(reply[20..22], [0, 0], "echo reply, code 0");
    assert_eq!(ones_complement_sum(&reply[20..]), 0xFFFF, "ICMP message");
}

#[test]
fn echo_messages_from_the_kernel_decode() {
    let localhost = Ipv4Addr::LOCALHOST;
    let expected = Echo {
        kind: EchoKind::Request,
        source: localhost,
        destination: localhost,
        id: 0x6d96,
        seq: 0,
    };
    assert_eq!(Echo::decode(&hex(KERNEL_REQUEST)), Some(expected));
    let expected = Echo {
        kind: EchoKind::Reply,
        ..expected
    };
    assert_eq!(Echo::decode(&hex(KERNEL_REPLY)), Some(expected));
}

#[test]
fn an_encoded_echo_decodes_to_itself() {
    for echo in [request(), pong(request())] {
        assert_eq!(Echo::decode(&echo.encode()), Some(echo));
    }
}

#[test]
fn an_echo_behind_ip_options_decodes() {
    let mut packet = hex(KERNEL_REPLY);
    packet[0] = 0x46;
    packet[3] += 4;
    packet.splice(20..20, [1, 1, 1, 1]);
    let echo = Echo::decode(&packet).expect("a 24-byte header is valid");
    assert_eq!((echo.kind, echo.id, echo.seq), (EchoKind::Reply, 0x6d96, 0));
}

#[test]
fn packets_that_are_not_a_whole_echo_message_decode_to_nothing() {
    let reply = hex(KERNEL_REPLY);
    for len in 0..28 {
        assert_eq!(Echo::decode(&reply[..len]), None, "cut at {len} bytes");
    }
    let change = |at: usize, value: u8| {
        let mut packet = reply.clone();
        packet[at] = value;
        packet
    };
    for (what, packet) in [
        ("IPv6", change(0, 0x65)),
        ("a header shorter than 20 bytes", change(0, 0x44)),
        ("UDP", change(9, 17)),
        ("the first fragment", change(6, 0x20)),
        ("a later fragment", change(7, 3)),
        ("destination unreachable", change(20, 3)),
        ("a non-zero code", change(21, 1)),
        ("a total length past the end", change(3, 0x35)),
        ("a total length inside the ICMP header", change(3, 27)),
    ] {
        assert_eq!(Echo::decode(&packet), None, "{what}");
    }
    assert!(
        Echo::decode(&change(6, 0x40)).is_some(),
        "the don't-fragment flag alone is not a fragment"
    );
}

/// Run `server` as the kernel behind a tunnel would. Each echo request gets
/// the replies that `replies` makes of it.
fn answering(mut server: Detached, replies: impl Fn(Echo) -> Vec<Echo> + Send + 'static) {
    tokio::spawn(async move {
        while let Ok(packet) = server.recv().await {
            let request = Echo::decode(&packet).filter(|echo| echo.kind == EchoKind::Request);
            for reply in request.map(&replies).unwrap_or_default() {
                server.send(&reply.encode()).await.unwrap();
            }
        }
    });
}

async fn doctor_run(
    replies: impl Fn(Echo) -> Vec<Echo> + Send + 'static,
    attempts: u16,
) -> Vec<Probe> {
    let config = with_doctor();
    let server = Detached::server(&config).await.unwrap();
    let endpoint = endpoint(&server).await;
    answering(server, replies);
    let attempts = NonZeroU16::new(attempts).unwrap();
    doctor::loopback(&config, None, endpoint, attempts)
        .await
        .unwrap()
}

#[tokio::test]
async fn the_doctor_gets_replies_from_the_tunnel_address_and_the_first_lan_host() {
    let probes = doctor_run(|request| vec![pong(request)], 3).await;
    let targets: Vec<Ipv4Addr> = probes.iter().map(|probe| probe.target).collect();
    assert_eq!(targets, [SERVER, LAN_HOST]);
    assert!(
        probes.iter().all(|probe| probe.reply.is_some()),
        "{probes:?}"
    );
}

#[tokio::test]
async fn a_target_that_stays_silent_has_no_reply() {
    let probes = doctor_run(
        |request| {
            if request.destination == SERVER {
                vec![pong(request)]
            } else {
                vec![]
            }
        },
        2,
    )
    .await;
    assert!(probes[0].reply.is_some(), "{probes:?}");
    assert_eq!(
        probes[1],
        Probe {
            target: LAN_HOST,
            reply: None
        }
    );
}

#[tokio::test]
async fn only_a_reply_with_the_id_and_a_sequence_of_a_request_counts() {
    let probes = doctor_run(
        |request| {
            let reply = pong(request);
            vec![
                Echo {
                    id: reply.id ^ 1,
                    ..reply
                },
                Echo {
                    seq: reply.seq + 100,
                    ..reply
                },
                Echo {
                    source: Ipv4Addr::new(10, 66, 67, 9),
                    ..reply
                },
                Echo {
                    kind: EchoKind::Request,
                    ..reply
                },
            ]
        },
        1,
    )
    .await;
    assert!(
        probes.iter().all(|probe| probe.reply.is_none()),
        "{probes:?}"
    );
}

#[tokio::test]
async fn a_lost_first_request_is_sent_again_and_the_reply_time_is_that_of_its_own_request() {
    let probes = doctor_run(
        |request| {
            if request.seq == 0 {
                vec![]
            } else {
                vec![pong(request)]
            }
        },
        3,
    )
    .await;
    for probe in probes {
        let reply = probe.reply.expect("the second request gets a reply");
        assert!(reply < Duration::from_millis(900), "{reply:?}");
    }
}

#[tokio::test]
async fn the_doctor_needs_a_doctor_section() {
    let mut value = server_json(&key());
    value["peers"] = json!([{ "name": "laptop", "public_key": public(&key()), "allowed_ips": ["10.66.67.2/32"] }]);
    let endpoint = "127.0.0.1:9".parse().unwrap();
    let error = doctor::loopback(&config(value), None, endpoint, NonZeroU16::MIN)
        .await
        .unwrap_err();
    assert_eq!(error.code, "DOCTOR_NOT_CONFIGURED");
}

fn natwg(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_natwg"))
        .args(args)
        .env_remove("NATWG_CONFIG")
        .output()
        .unwrap()
}

/// Run `natwg doctor loopback` against a server in this process.
async fn natwg_doctor(
    replies: impl Fn(Echo) -> Vec<Echo> + Send + 'static,
    extra: &'static [&'static str],
) -> Output {
    let config = with_doctor();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.json");
    config.save(&path).unwrap();
    let server = Detached::server(&config).await.unwrap();
    let endpoint = endpoint(&server).await.to_string();
    answering(server, replies);
    tokio::task::spawn_blocking(move || {
        let path = path.to_str().unwrap();
        let mut args = vec!["doctor", "loopback", "--config", path];
        args.extend(["--endpoint", &endpoint]);
        args.extend(extra);
        natwg(&args)
    })
    .await
    .unwrap()
}

fn reply_time(line: &str, target: &str) -> f64 {
    line.strip_prefix(target)
        .and_then(|rest| rest.strip_prefix(" reply "))
        .and_then(|rest| rest.strip_suffix(" ms"))
        .and_then(|ms| ms.parse().ok())
        .unwrap_or_else(|| panic!("expected `{target} reply <ms> ms`, got {line:?}"))
}

#[tokio::test(flavor = "multi_thread")]
async fn natwg_doctor_loopback_prints_one_reply_line_for_each_target_and_exits_0() {
    let output = natwg_doctor(|request| vec![pong(request)], &[]).await;
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stderr}");
    let stdout = String::from_utf8(output.stdout).unwrap();
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 2, "{stdout}");
    for (line, target) in lines.iter().zip(["10.66.67.1", "10.24.0.1"]) {
        let ms = reply_time(line, target);
        assert!((0.0..1000.0).contains(&ms), "{line}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn natwg_doctor_loopback_exits_1_and_names_the_target_that_stayed_silent() {
    let only_the_tunnel_address = |request: Echo| {
        if request.destination == SERVER {
            vec![pong(request)]
        } else {
            vec![]
        }
    };
    let output = natwg_doctor(only_the_tunnel_address, &["--attempts", "2"]).await;
    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8(output.stdout).unwrap();
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 2, "{stdout}");
    reply_time(lines[0], "10.66.67.1");
    assert_eq!(lines[1], "10.24.0.1 no reply");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.starts_with("DOCTOR_NO_REPLY"), "{stderr}");
    assert!(stderr.contains("10.24.0.1"), "{stderr}");
    assert!(!stderr.contains("10.66.67.1"), "{stderr}");
}

#[test]
fn natwg_doctor_loopback_needs_an_endpoint() {
    let output = natwg(&["doctor", "loopback"]);
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("--endpoint"), "{stderr}");
}

#[test]
fn natwg_doctor_loopback_refuses_zero_attempts_before_it_reads_the_config() {
    let endpoint = ["--endpoint", "127.0.0.1:9", "--config", "/natwg-none.json"];
    let output = natwg(&[&["doctor", "loopback", "--attempts", "0"], &endpoint[..]].concat());
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("--attempts"), "{stderr}");

    let output = natwg(&[&["doctor", "loopback", "--attempts", "1"], &endpoint[..]].concat());
    assert_eq!(output.status.code(), Some(1));
    assert!(
        output.stderr.starts_with(b"CONFIG_UNREADABLE"),
        "{output:?}"
    );
}

#[test]
fn natwg_server_needs_the_foreground_flag() {
    let output = natwg(&["server"]);
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("--foreground"), "{stderr}");
}

#[test]
fn natwg_server_without_root_exits_with_not_root() {
    // Root passes this check and would go on to start a server.
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    let output = natwg(&["server", "--foreground", "--config", "/natwg-none.json"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stderr.starts_with(b"NOT_ROOT"), "{output:?}");
}
