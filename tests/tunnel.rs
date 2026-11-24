use natwg::config::Config;
use natwg::keys::Key;
use natwg::tunnel::Detached;
use serde_json::{Value, json};
use std::{
    net::{Ipv4Addr, SocketAddrV4},
    time::Duration,
};

#[cfg(target_os = "macos")]
const LOOPBACK: &str = "lo0";
#[cfg(target_os = "linux")]
const LOOPBACK: &str = "lo";

const SERVER: Ipv4Addr = Ipv4Addr::new(10, 66, 67, 1);
const DOCTOR: Ipv4Addr = Ipv4Addr::new(10, 66, 67, 254);
const LAN_HOST: Ipv4Addr = Ipv4Addr::new(10, 73, 0, 1);

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
            "lan": "10.73.0.0/24",
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
