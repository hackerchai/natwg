//! natwg peer: adding a client to a server config, listing and removing it.

use natwg::config::{Config, Role};
use natwg::keys::Key;
use natwg::peer;
use serde_json::{Value, json};
use std::{fs, os::unix::fs::PermissionsExt, path::Path, process::Command};

fn key() -> String {
    Key::generate().unwrap().to_base64()
}

fn public() -> String {
    Key::generate().unwrap().public_key().to_string()
}

/// A server on 10.66.67.1/24 with a laptop at .2, a phone holding .3 and .4,
/// and the doctor at .5.
fn server_json() -> Value {
    json!({
        "version": 1,
        "private_key": key(),
        "interface": { "address": "10.66.67.1/24", "mtu": 1400 },
        "peers": [
            { "name": "laptop", "public_key": public(), "allowed_ips": ["10.66.67.2/32"] },
            { "name": "phone", "public_key": public(), "allowed_ips": ["10.66.67.4/31"] }
        ],
        "role": { "server": {
            "instance": "natwg_next",
            "iface": "en6",
            "listen_port": 51831,
            "lan": "10.73.0.0/24",
            "stun": { "servers": [], "fallback": [], "dns_server": "223.5.5.5" },
            "cloudflare": { "zone": "example.com", "record": "_wg-home-next.example.com", "token": "t" },
            "doctor": { "private_key": key(), "address": "10.66.67.3" }
        }}
    })
}

fn config(value: Value) -> Config {
    let config: Config = serde_json::from_value(value).unwrap();
    config.validate().unwrap();
    config
}

fn address_of(config: &Config) -> String {
    config.interface.address.to_string()
}

#[test]
fn a_new_peer_takes_the_lowest_host_nobody_holds() {
    let mut server = config(server_json());
    let first = peer::add(&mut server, "tablet").unwrap();
    assert_eq!(
        address_of(&first),
        "10.66.67.6/32",
        "skips .1 server, .2 laptop, .3 doctor, .4-.5 phone"
    );
    let second = peer::add(&mut server, "desktop").unwrap();
    assert_eq!(address_of(&second), "10.66.67.7/32");

    let added = server
        .peers
        .iter()
        .find(|peer| peer.name == "tablet")
        .unwrap();
    assert_eq!(added.allowed_ips, ["10.66.67.6/32".parse().unwrap()]);
    assert_eq!(added.public_key, first.private_key.public_key());
    assert_eq!(added.preshared_key, first.peers[0].preshared_key);
    assert!(added.preshared_key.is_some());

    peer::remove(&mut server, "laptop").unwrap();
    let third = peer::add(&mut server, "laptop2").unwrap();
    assert_eq!(
        address_of(&third),
        "10.66.67.2/32",
        "a removed peer frees its address"
    );
}

#[test]
fn the_client_config_reaches_the_tunnel_and_the_lan_through_the_record() {
    let mut server = config(server_json());
    let client = peer::add(&mut server, "tablet").unwrap();
    client.validate().unwrap();
    let [home] = &client.peers[..] else {
        panic!("a client has one peer")
    };
    assert_eq!(home.public_key, server.private_key.public_key());
    assert_eq!(
        home.allowed_ips,
        [
            "10.66.67.0/24".parse().unwrap(),
            "10.73.0.0/24".parse().unwrap()
        ]
    );
    assert_eq!(home.endpoint, None);
    assert_eq!(home.keepalive, Some(25));
    assert_eq!(
        client.interface.mtu, 1400,
        "the client takes the server's MTU"
    );
    let Role::Client(role) = &client.role else {
        panic!("peer add returns a client config")
    };
    assert_eq!(role.record.as_deref(), Some("_wg-home-next.example.com"));
    assert_eq!(role.resolvers.len(), 4);
    assert_ne!(client.private_key, server.private_key);
}

#[test]
fn the_client_config_routes_the_tunnel_subnet_and_every_lan() {
    let routed = |lan: Value| {
        let mut value = server_json();
        value["role"]["server"]["lan"] = lan;
        let client = peer::add(&mut config(value), "tablet").unwrap();
        client.validate().unwrap();
        let routed: Vec<String> = client.peers[0]
            .allowed_ips
            .iter()
            .map(ToString::to_string)
            .collect();
        routed
    };
    assert_eq!(
        routed(json!(["10.73.0.0/24", "192.168.50.0/24", "172.20.0.0/16"])),
        [
            "10.66.67.0/24",
            "10.73.0.0/24",
            "192.168.50.0/24",
            "172.20.0.0/16"
        ]
    );
    assert_eq!(
        routed(json!([])),
        ["10.66.67.0/24"],
        "a server without a LAN gives its clients the tunnel only"
    );
}

#[test]
fn a_peer_name_is_unique_and_plain() {
    let mut server = config(server_json());
    assert_eq!(
        peer::add(&mut server, "laptop").unwrap_err().code,
        "PEER_EXISTS"
    );
    let long = "a".repeat(33);
    for name in ["", "a b", "a/b", "x\n", &long] {
        assert_eq!(
            peer::add(&mut server, name).unwrap_err().code,
            "PEER_NAME_INVALID",
            "{name:?}"
        );
    }
    assert_eq!(server.peers.len(), 2, "a refused add changes nothing");
    assert_eq!(
        peer::remove(&mut server, "nobody").unwrap_err().code,
        "PEER_NOT_FOUND"
    );
}

#[test]
fn a_full_subnet_has_no_address_for_a_new_peer() {
    let mut value = server_json();
    value["interface"]["address"] = json!("10.66.67.1/29");
    value["peers"][1]["allowed_ips"] = json!(["10.66.67.4/30"]);
    value["role"]["server"]["doctor"]["address"] = json!("10.66.67.3");
    let mut server = config(value);
    assert_eq!(
        peer::add(&mut server, "tablet").unwrap_err().code,
        "PEER_NO_ADDRESS"
    );
}

#[test]
fn peers_are_added_only_to_a_server_config() {
    let mut client = config(json!({
        "version": 1,
        "private_key": key(),
        "interface": { "address": "10.66.67.2/32" },
        "peers": [{ "name": "server", "public_key": public(), "allowed_ips": ["10.66.67.0/24"],
                    "endpoint": "192.0.2.7:51831" }],
        "role": { "client": {} }
    }));
    for error in [
        peer::add(&mut client, "tablet").unwrap_err(),
        peer::remove(&mut client, "server").unwrap_err(),
        peer::list(&client).unwrap_err(),
    ] {
        assert_eq!(error.code, "ROLE_MISMATCH");
    }
}

fn natwg(config: &Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_natwg"))
        .arg("--config")
        .arg(config)
        .arg("peer")
        .args(args)
        .output()
        .unwrap()
}

fn mode(path: &Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}

#[test]
fn natwg_peer_adds_lists_and_removes_and_saves_the_server_config() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.json");
    config(server_json()).save(&path).unwrap();

    let added = natwg(&path, &["add", "tablet"]);
    assert!(added.status.success(), "{added:?}");
    let stderr = String::from_utf8(added.stderr).unwrap();
    assert!(
        stderr.contains("Added peer tablet at 10.66.67.6/32"),
        "{stderr}"
    );
    assert!(stderr.contains("natwg service restart"), "{stderr}");
    let client: Config = serde_json::from_slice(&added.stdout).unwrap();
    client.validate().unwrap();
    let server = Config::load(&path).unwrap();
    assert_eq!(mode(&path), 0o600);
    let tablet = server
        .peers
        .iter()
        .find(|peer| peer.name == "tablet")
        .unwrap();
    assert_eq!(tablet.public_key, client.private_key.public_key());

    let out = dir.path().join("tablet/config.json");
    let written = natwg(&path, &["add", "desktop", "--out", out.to_str().unwrap()]);
    assert!(written.status.success(), "{written:?}");
    assert!(
        written.stdout.is_empty(),
        "--out keeps the private key off the terminal"
    );
    assert_eq!(mode(&out), 0o600);
    assert_eq!(address_of(&Config::load(&out).unwrap()), "10.66.67.7/32");

    let refused = natwg(&path, &["add", "watch", "--out", out.to_str().unwrap()]);
    assert!(!refused.status.success());
    assert!(
        String::from_utf8(refused.stderr)
            .unwrap()
            .starts_with("CONFIG_EXISTS: ")
    );
    let unchanged = Config::load(&path).unwrap();
    assert!(
        !unchanged.peers.iter().any(|peer| peer.name == "watch"),
        "a refused --out leaves the server config as it was"
    );

    let listed = natwg(&path, &["list"]);
    assert!(listed.status.success(), "{listed:?}");
    let listed = String::from_utf8(listed.stdout).unwrap();
    for line in [
        format!("tablet 10.66.67.6/32 {}", tablet.public_key),
        "laptop 10.66.67.2/32 ".to_owned(),
        "(doctor) 10.66.67.3/32 ".to_owned(),
    ] {
        assert!(listed.contains(&line), "{line:?} in {listed}");
    }
    assert!(!listed.contains(&client.private_key.to_base64()));

    let removed = natwg(&path, &["remove", "tablet"]);
    assert!(removed.status.success(), "{removed:?}");
    let server = Config::load(&path).unwrap();
    assert!(!server.peers.iter().any(|peer| peer.name == "tablet"));
    assert_eq!(server.peers.len(), 3);
    let left: Vec<_> = fs::read_dir(dir.path()).unwrap().collect();
    assert_eq!(left.len(), 2, "no temporary file stays beside the config");
}
