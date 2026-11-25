//! natwg config set: the tunnel address with the renumbering of a server's
//! peers, the LANs of a server, and the allowed IPs of a client.

use ipnetwork::Ipv4Network;
use natwg::config::set::{self, Setting};
use natwg::config::{Config, Role};
use serde_json::{Value, json};
use std::{fs, os::unix::fs::PermissionsExt, path::Path, process::Command};

const SERVER_PRIVATE: &str = "OBVOyBiR+AQljDndwhkOOOvLPVQUogKaqG9unoAN+nw=";
const SERVER_PUBLIC: &str = "y8ocWNQCQNyN5iT1HmIcsFMbw7Khqm3029s2xAGJjDQ=";
const LAPTOP_PUBLIC: &str = "CXOTAEiTQggjsjWB6iD0+iahmCU4DI/YZBWeRK+TVRk=";
const PHONE_PUBLIC: &str = "ILtVQIifKCtTfqceUpcqerlPKtnu6WzgeDQY0SWkbig=";
const PRESHARED: &str = "joXuSVtd81G0ce6cm8K2oryfVmS//fa+NhOUXJHCRc4=";
const DOCTOR_PRIVATE: &str = "cPXIkbJn1Y1Q9hOersIfKG70D6iHQ2ie9iCdb+zUY1Y=";
const TOKEN: &str = "fixture-cf-token-hWBiBe3RXo3KGxecH3tNIrFUGJTy";
const SECRETS: [&str; 4] = [SERVER_PRIVATE, PRESHARED, DOCTOR_PRIVATE, TOKEN];

/// A server on 10.66.66.1/24 with the LAN 10.24.0.0/24 in the single-string
/// form of natwg 0.2, a laptop at .2 that also routes a network of its own,
/// a phone holding .4 and .5, and the doctor at .254.
fn server_json() -> Value {
    json!({
        "version": 1,
        "private_key": SERVER_PRIVATE,
        "interface": { "address": "10.66.66.1/24", "mtu": 1380 },
        "peers": [
            {
                "name": "laptop",
                "public_key": LAPTOP_PUBLIC,
                "preshared_key": PRESHARED,
                "allowed_ips": ["10.66.66.2/32", "192.168.9.0/24"]
            },
            { "name": "phone", "public_key": PHONE_PUBLIC, "allowed_ips": ["10.66.66.4/31"] }
        ],
        "role": { "server": {
            "iface": "en6",
            "listen_port": 51830,
            "lan": "10.24.0.0/24",
            "stun": { "servers": [], "fallback": [], "dns_server": "223.5.5.5" },
            "cloudflare": { "zone": "example.com", "record": "_wg-home.example.com", "token": TOKEN },
            "doctor": { "private_key": DOCTOR_PRIVATE, "address": "10.66.66.254" }
        }}
    })
}

fn client_json() -> Value {
    json!({
        "version": 1,
        "private_key": DOCTOR_PRIVATE,
        "interface": { "address": "10.66.66.2/32" },
        "peers": [{
            "name": "server",
            "public_key": SERVER_PUBLIC,
            "allowed_ips": ["10.66.66.0/24", "10.24.0.0/24"]
        }],
        "role": { "client": { "record": "_wg-home.example.com" } }
    })
}

fn config(value: Value) -> Config {
    let config: Config = serde_json::from_value(value).unwrap();
    config.validate().unwrap();
    config
}

fn net(text: &str) -> Ipv4Network {
    text.parse().unwrap()
}

fn nets(texts: &[&str]) -> Vec<Ipv4Network> {
    texts.iter().map(|text| net(text)).collect()
}

fn address(text: &str) -> Setting {
    Setting::Address(net(text))
}

fn allowed_of<'a>(config: &'a Config, name: &str) -> &'a [Ipv4Network] {
    let peer = config.peers.iter().find(|peer| peer.name == name).unwrap();
    &peer.allowed_ips
}

fn doctor_of(config: &Config) -> String {
    let Role::Server(server) = &config.role else {
        panic!("a server config")
    };
    server.doctor.as_ref().unwrap().address.to_string()
}

fn lans_of(config: &Config) -> &[Ipv4Network] {
    let Role::Server(server) = &config.role else {
        panic!("a server config")
    };
    &server.lan
}

/// `setting` on `value` must fail with `code` and a message that holds
/// `needle`, and leave the config as it was.
fn refused(value: Value, setting: Setting, code: &str, needle: &str) {
    let before = config(value);
    let mut after = before.clone();
    let error = set::apply(&mut after, &setting).unwrap_err();
    assert_eq!(error.code, code, "{setting:?}: {error}");
    assert!(error.message.contains(needle), "{setting:?}: {error}");
    assert_eq!(after, before, "a refused setting changes nothing");
}

#[test]
fn a_server_that_moves_to_another_subnet_takes_its_peers_and_its_doctor_along() {
    let mut server = config(server_json());
    let change = set::apply(&mut server, &address("10.66.70.1/24")).unwrap();
    assert_eq!(server.interface.address, net("10.66.70.1/24"));
    assert_eq!(
        allowed_of(&server, "laptop"),
        nets(&["10.66.70.2/32", "192.168.9.0/24"]),
        "a network outside the tunnel subnet stays"
    );
    assert_eq!(allowed_of(&server, "phone"), nets(&["10.66.70.4/31"]));
    assert_eq!(doctor_of(&server), "10.66.70.254");
    assert_eq!(lans_of(&server), nets(&["10.24.0.0/24"]));
    assert_eq!(
        change.changed,
        [
            "interface.address 10.66.66.1/24 -> 10.66.70.1/24",
            "peer laptop 10.66.66.2/32 -> 10.66.70.2/32",
            "peer phone 10.66.66.4/31 -> 10.66.70.4/31",
            "role.server.doctor.address 10.66.66.254 -> 10.66.70.254",
        ]
    );
    let notes = change.notes.join("\n");
    for needle in [
        "new address",
        "route 10.66.70.0/24 instead of 10.66.66.0/24",
        "natwg config set allowed-ips 10.66.70.0/24 10.24.0.0/24",
    ] {
        assert!(notes.contains(needle), "{needle:?} in {notes}");
    }
}

#[test]
fn a_server_can_move_to_a_larger_or_a_smaller_subnet_when_everyone_fits() {
    let mut server = config(server_json());
    set::apply(&mut server, &address("172.31.4.1/22")).unwrap();
    assert_eq!(allowed_of(&server, "laptop")[0], net("172.31.4.2/32"));
    assert_eq!(allowed_of(&server, "phone"), nets(&["172.31.4.4/31"]));
    assert_eq!(doctor_of(&server), "172.31.4.254");

    let mut value = server_json();
    value["role"]["server"]["doctor"]["address"] = json!("10.66.66.100");
    let mut server = config(value);
    set::apply(&mut server, &address("10.66.70.129/25")).unwrap();
    assert_eq!(
        allowed_of(&server, "laptop")[0],
        net("10.66.70.130/32"),
        "offset 2 of 10.66.70.128/25"
    );
    assert_eq!(allowed_of(&server, "phone"), nets(&["10.66.70.132/31"]));
    assert_eq!(doctor_of(&server), "10.66.70.228");
}

#[test]
fn growing_the_subnet_in_place_moves_nobody() {
    let mut server = config(server_json());
    let change = set::apply(&mut server, &address("10.66.66.1/23")).unwrap();
    assert_eq!(
        change.changed,
        ["interface.address 10.66.66.1/24 -> 10.66.66.1/23"]
    );
    assert_eq!(allowed_of(&server, "laptop")[0], net("10.66.66.2/32"));
    assert_eq!(doctor_of(&server), "10.66.66.254");
    assert!(
        change.notes.join("\n").contains("route 10.66.66.0/23"),
        "{:?}",
        change.notes
    );
}

#[test]
fn a_subnet_that_holds_the_old_one_keeps_everyone_where_they_are() {
    let mut server = config(server_json());
    let change = set::apply(&mut server, &address("10.66.66.1/16")).unwrap();
    assert_eq!(
        change.changed,
        ["interface.address 10.66.66.1/24 -> 10.66.66.1/16"]
    );
    assert_eq!(
        allowed_of(&server, "laptop"),
        nets(&["10.66.66.2/32", "192.168.9.0/24"])
    );
    assert_eq!(allowed_of(&server, "phone"), nets(&["10.66.66.4/31"]));
    assert_eq!(doctor_of(&server), "10.66.66.254");
    let notes = change.notes.join("\n");
    assert!(
        notes.contains("route 10.66.0.0/16 instead of 10.66.66.0/24"),
        "{notes}"
    );
    assert!(!notes.contains("new address"), "{notes}");
}

#[test]
fn a_subnet_inside_the_old_one_keeps_those_inside_and_refuses_the_rest() {
    let mut value = server_json();
    value["peers"][0]["allowed_ips"] = json!(["10.66.66.130/32"]);
    value["peers"][1]["allowed_ips"] = json!(["10.66.66.132/31"]);
    value["role"]["server"]["doctor"]["address"] = json!("10.66.66.200");
    let mut server = config(value.clone());
    let change = set::apply(&mut server, &address("10.66.66.129/25")).unwrap();
    assert_eq!(
        change.changed,
        ["interface.address 10.66.66.1/24 -> 10.66.66.129/25"]
    );
    assert_eq!(allowed_of(&server, "laptop"), nets(&["10.66.66.130/32"]));
    assert_eq!(allowed_of(&server, "phone"), nets(&["10.66.66.132/31"]));
    assert_eq!(doctor_of(&server), "10.66.66.200");

    refused(
        server_json(),
        address("10.66.66.129/25"),
        "RENUMBER_NO_ROOM",
        "peer \"laptop\" at 10.66.66.2/32 is no host of 10.66.66.128/25",
    );
    value["role"]["server"]["doctor"]["address"] = json!("10.66.66.255");
    refused(
        value,
        address("10.66.66.129/25"),
        "RENUMBER_NO_ROOM",
        "role.server.doctor.address 10.66.66.255 is no host",
    );
}

#[test]
fn a_new_subnet_may_not_take_a_network_that_a_peer_routes() {
    let mut value = server_json();
    value["peers"][1]["allowed_ips"] = json!(["10.66.66.4/31", "10.66.70.0/29"]);
    refused(
        value.clone(),
        address("10.66.70.9/24"),
        "ADDRESS_TAKEN",
        "peer \"phone\" routes 10.66.70.0/29",
    );
    refused(
        value,
        address("10.66.66.1/16"),
        "ADDRESS_TAKEN",
        "overlaps the new tunnel subnet 10.66.0.0/16",
    );
}

#[test]
fn a_server_address_may_not_be_the_network_or_the_broadcast_address() {
    for edge in ["10.77.0.0/24", "10.77.0.255/24"] {
        refused(
            server_json(),
            address(edge),
            "CONFIG_INVALID",
            "network or broadcast address of 10.77.0.0/24",
        );
    }
}

#[test]
fn lans_and_routes_are_written_at_their_network_address() {
    let mut server = config(server_json());
    set::apply(&mut server, &Setting::Lan(nets(&["10.24.0.5/24"]))).unwrap();
    assert_eq!(lans_of(&server), nets(&["10.24.0.0/24"]));
    let mut client = config(client_json());
    set::apply(
        &mut client,
        &Setting::AllowedIps(nets(&["10.66.66.9/24", "10.24.0.1/24"])),
    )
    .unwrap();
    assert_eq!(
        client.peers[0].allowed_ips,
        nets(&["10.66.66.0/24", "10.24.0.0/24"])
    );
}

#[test]
fn a_new_server_address_in_the_same_subnet_moves_nobody() {
    let mut server = config(server_json());
    let change = set::apply(&mut server, &address("10.66.66.100/24")).unwrap();
    assert_eq!(
        change.changed,
        ["interface.address 10.66.66.1/24 -> 10.66.66.100/24"]
    );
    assert!(change.notes.is_empty(), "{:?}", change.notes);
    assert_eq!(allowed_of(&server, "laptop")[0], net("10.66.66.2/32"));
}

#[test]
fn a_move_is_refused_when_a_peer_or_the_doctor_does_not_fit() {
    refused(
        server_json(),
        address("10.66.70.1/25"),
        "RENUMBER_NO_ROOM",
        "role.server.doctor.address 10.66.66.254 sits at offset 254",
    );
    let mut value = server_json();
    value["peers"][1]["allowed_ips"] = json!(["10.66.66.200/32"]);
    value["role"]["server"]["doctor"]["address"] = json!("10.66.66.3");
    refused(
        value,
        address("10.66.70.1/25"),
        "RENUMBER_NO_ROOM",
        "peer \"phone\" at 10.66.66.200/32 sits at offset 200",
    );
    let mut value = server_json();
    value["peers"][1]["allowed_ips"] = json!(["10.66.66.127/32"]);
    value["role"]["server"]["doctor"]["address"] = json!("10.66.66.3");
    refused(
        value,
        address("10.66.70.1/25"),
        "RENUMBER_NO_ROOM",
        "no host of 10.66.70.0/25",
    );
}

#[test]
fn a_move_is_refused_when_a_peer_or_the_doctor_would_take_the_server_address() {
    refused(
        server_json(),
        address("10.66.70.2/24"),
        "ADDRESS_TAKEN",
        "10.66.70.2 would be inside 10.66.70.2/32 of peer \"laptop\"",
    );
    refused(
        server_json(),
        address("10.66.70.5/24"),
        "ADDRESS_TAKEN",
        "inside 10.66.70.4/31 of peer \"phone\"",
    );
    refused(
        server_json(),
        address("10.66.70.254/24"),
        "ADDRESS_TAKEN",
        "role.server.doctor.address",
    );
    refused(
        server_json(),
        address("10.66.66.2/24"),
        "ADDRESS_TAKEN",
        "peer \"laptop\"",
    );
}

#[test]
fn a_new_subnet_that_overlaps_a_lan_or_is_too_wide_is_invalid() {
    refused(
        server_json(),
        address("10.24.0.1/16"),
        "CONFIG_INVALID",
        "role.server.lan[0] 10.24.0.0/24 overlap",
    );
    refused(
        server_json(),
        address("10.66.66.1/15"),
        "CONFIG_INVALID",
        "interface.address",
    );
}

#[test]
fn a_client_takes_a_new_address_and_hears_what_else_must_change() {
    let mut client = config(client_json());
    let change = set::apply(&mut client, &address("10.66.70.2/32")).unwrap();
    assert_eq!(client.interface.address, net("10.66.70.2/32"));
    assert_eq!(
        client.peers[0].allowed_ips,
        nets(&["10.66.66.0/24", "10.24.0.0/24"]),
        "the routes stay as they were"
    );
    assert_eq!(
        change.changed,
        ["interface.address 10.66.66.2/32 -> 10.66.70.2/32"]
    );
    let notes = change.notes.join("\n");
    assert!(
        notes.contains("10.66.70.2/32 in the allowed_ips"),
        "{notes}"
    );
    assert!(notes.contains("leaves out 10.66.70.2"), "{notes}");
}

#[test]
fn a_server_takes_any_number_of_lans_and_none() {
    let mut server = config(server_json());
    let lans = nets(&["10.24.0.0/24", "192.168.50.0/24"]);
    let change = set::apply(&mut server, &Setting::Lan(lans.clone())).unwrap();
    assert_eq!(lans_of(&server), lans);
    assert_eq!(
        change.changed,
        ["role.server.lan [10.24.0.0/24] -> [10.24.0.0/24, 192.168.50.0/24]"]
    );
    assert!(
        change
            .notes
            .join("\n")
            .contains("natwg config set allowed-ips 10.66.66.0/24 10.24.0.0/24 192.168.50.0/24"),
        "{:?}",
        change.notes
    );

    let unchanged = set::apply(&mut server, &Setting::Lan(lans)).unwrap();
    assert_eq!(unchanged, set::Change::default());

    let change = set::apply(&mut server, &Setting::Lan(vec![])).unwrap();
    assert!(lans_of(&server).is_empty());
    assert_eq!(
        change.changed,
        ["role.server.lan [10.24.0.0/24, 192.168.50.0/24] -> []"]
    );
    assert!(change.notes.join("\n").contains("serves the tunnel only"));
}

#[test]
fn lans_that_overlap_the_tunnel_or_each_other_are_refused() {
    for (lans, needle) in [
        (
            &["10.66.66.0/25"][..],
            "role.server.lan[0] 10.66.66.0/25 overlap",
        ),
        (
            &["10.24.0.0/16", "10.24.9.0/24"],
            "role.server.lan[1] 10.24.9.0/24 overlaps role.server.lan[0]",
        ),
        (&["0.0.0.0/0"], "default route"),
    ] {
        refused(
            server_json(),
            Setting::Lan(nets(lans)),
            "CONFIG_INVALID",
            needle,
        );
    }
}

#[test]
fn a_client_sets_the_networks_it_routes() {
    let mut client = config(client_json());
    let routed = nets(&["10.66.66.0/24", "10.24.0.0/24", "192.168.50.0/24"]);
    let change = set::apply(&mut client, &Setting::AllowedIps(routed.clone())).unwrap();
    assert_eq!(client.peers[0].allowed_ips, routed);
    assert_eq!(
        change.changed,
        [
            "peers[0].allowed_ips [10.66.66.0/24, 10.24.0.0/24] -> [10.66.66.0/24, 10.24.0.0/24, 192.168.50.0/24]"
        ]
    );
    refused(
        client_json(),
        Setting::AllowedIps(vec![]),
        "CONFIG_INVALID",
        "peers[0].allowed_ips is empty",
    );
    refused(
        client_json(),
        Setting::AllowedIps(nets(&["10.66.66.0/24", "0.0.0.0/0"])),
        "CONFIG_INVALID",
        "default route",
    );
}

#[test]
fn each_key_refuses_the_role_it_does_not_belong_to() {
    refused(
        client_json(),
        Setting::Lan(nets(&["10.24.0.0/24"])),
        "ROLE_MISMATCH",
        "natwg config set lan changes a server config",
    );
    refused(
        server_json(),
        Setting::AllowedIps(nets(&["10.66.66.0/24"])),
        "ROLE_MISMATCH",
        "natwg config set allowed-ips changes a client config",
    );
}

fn write_private(path: &Path, value: &Value) {
    fs::write(path, value.to_string()).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

fn natwg_set(path: &Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_natwg"))
        .env_remove("NATWG_CONFIG")
        .arg("--config")
        .arg(path)
        .args(["config", "set"])
        .args(args)
        .output()
        .unwrap()
}

fn mode(path: &Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o7777
}

#[test]
fn natwg_config_set_replaces_the_config_and_says_to_restart() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.json");
    write_private(&path, &server_json());

    let output = natwg_set(&path, &["address", "10.66.70.1/24"]);
    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_eq!(
        stdout,
        "interface.address 10.66.66.1/24 -> 10.66.70.1/24
peer laptop 10.66.66.2/32 -> 10.66.70.2/32
peer phone 10.66.66.4/31 -> 10.66.70.4/31
role.server.doctor.address 10.66.66.254 -> 10.66.70.254
"
    );
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("must take its new address"), "{stderr}");
    assert!(
        stderr.contains("run sudo natwg service restart"),
        "{stderr}"
    );
    assert_eq!(mode(&path), 0o600);
    let saved = Config::load(&path).unwrap();
    assert_eq!(saved.interface.address, net("10.66.70.1/24"));
    assert_eq!(doctor_of(&saved), "10.66.70.254");
    let text = fs::read_to_string(&path).unwrap();
    for secret in SECRETS {
        assert!(text.contains(secret), "the file keeps {secret}");
    }

    let output = natwg_set(&path, &["lan", "10.24.0.0/24", "192.168.50.0/24"]);
    assert!(output.status.success(), "{output:?}");
    let saved: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(
        saved["role"]["server"]["lan"],
        json!(["10.24.0.0/24", "192.168.50.0/24"])
    );
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("natwg config set allowed-ips"), "{stderr}");

    let output = natwg_set(&path, &["lan"]);
    assert!(output.status.success(), "{output:?}");
    let saved: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(saved["role"]["server"]["lan"], json!([]));

    let left: Vec<_> = fs::read_dir(dir.path()).unwrap().collect();
    assert_eq!(left.len(), 1, "no temporary file stays beside the config");
}

#[test]
fn natwg_config_set_writes_nothing_when_it_refuses_or_nothing_changes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.json");
    write_private(&path, &server_json());
    let before = fs::read(&path).unwrap();
    for (args, code) in [
        (&["address", "10.66.70.1/25"][..], "RENUMBER_NO_ROOM: "),
        (&["address", "10.66.70.2/24"], "ADDRESS_TAKEN: "),
        (&["lan", "10.66.66.0/24"], "CONFIG_INVALID: "),
        (&["allowed-ips", "10.66.66.0/24"], "ROLE_MISMATCH: "),
    ] {
        let output = natwg_set(&path, args);
        assert_eq!(output.status.code(), Some(1), "{args:?}: {output:?}");
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(stderr.starts_with(code), "{args:?}: {stderr}");
        assert_eq!(fs::read(&path).unwrap(), before, "{args:?} wrote");
    }

    let output = natwg_set(&path, &["address", "10.66.66.1/24"]);
    assert!(output.status.success(), "{output:?}");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("nothing to write"), "{stderr}");
    assert_eq!(fs::read(&path).unwrap(), before);

    let client = dir.path().join("client.json");
    write_private(&client, &client_json());
    let output = natwg_set(&client, &["lan", "10.24.0.0/24"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stderr.starts_with(b"ROLE_MISMATCH: "), "{output:?}");
    let output = natwg_set(&client, &["allowed-ips"]);
    assert_eq!(output.status.code(), Some(2), "allowed-ips needs a network");
    let output = natwg_set(&client, &["address", "10.66.66.0/33"]);
    assert_eq!(output.status.code(), Some(2), "{output:?}");
}

#[test]
fn natwg_config_set_dry_run_prints_the_redacted_result_and_writes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.json");
    write_private(&path, &server_json());
    let before = fs::read(&path).unwrap();

    for args in [
        &["--dry-run", "address", "10.66.70.1/24"][..],
        &["address", "10.66.70.1/24", "--dry-run"],
    ] {
        let output = natwg_set(&path, args);
        assert!(output.status.success(), "{args:?}: {output:?}");
        assert_eq!(fs::read(&path).unwrap(), before, "{args:?} wrote");
        let stdout = String::from_utf8(output.stdout).unwrap();
        for secret in SECRETS {
            assert!(!stdout.contains(secret), "{secret} leaked into {stdout}");
        }
        let shown: Value = serde_json::from_str(&stdout).unwrap();
        assert_eq!(shown["public_key"], SERVER_PUBLIC);
        assert_eq!(shown["private_key"], "<redacted>");
        assert_eq!(shown["interface"]["address"], "10.66.70.1/24");
        assert_eq!(shown["peers"][0]["allowed_ips"][0], "10.66.70.2/32");
        assert_eq!(shown["role"]["server"]["doctor"]["address"], "10.66.70.254");
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(
            stderr.contains("peer laptop 10.66.66.2/32 -> 10.66.70.2/32"),
            "{stderr}"
        );
        assert!(stderr.contains("Dry run"), "{stderr}");
        assert!(!stderr.contains("Wrote"), "{stderr}");
    }

    let client = dir.path().join("client.json");
    write_private(&client, &client_json());
    let before = fs::read(&client).unwrap();
    let output = natwg_set(&client, &["allowed-ips", "10.66.66.0/24", "--dry-run"]);
    assert!(output.status.success(), "{output:?}");
    let shown: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(shown["peers"][0]["allowed_ips"], json!(["10.66.66.0/24"]));
    assert_eq!(fs::read(&client).unwrap(), before);
}
