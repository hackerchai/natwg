use natwg::config::{Config, DoctorConfig, HostPort, PublishMode, Role};
use natwg::keys::Key;
use serde_json::{Value, json};
use std::{fs, os::unix::fs::PermissionsExt, path::Path, process::Command};

const SERVER_PRIVATE: &str = "OBVOyBiR+AQljDndwhkOOOvLPVQUogKaqG9unoAN+nw=";
const SERVER_PUBLIC: &str = "y8ocWNQCQNyN5iT1HmIcsFMbw7Khqm3029s2xAGJjDQ=";
const LAPTOP_PUBLIC: &str = "CXOTAEiTQggjsjWB6iD0+iahmCU4DI/YZBWeRK+TVRk=";
const PRESHARED: &str = "joXuSVtd81G0ce6cm8K2oryfVmS//fa+NhOUXJHCRc4=";
const DOCTOR_PRIVATE: &str = "cPXIkbJn1Y1Q9hOersIfKG70D6iHQ2ie9iCdb+zUY1Y=";
const DOCTOR_PUBLIC: &str = "ILtVQIifKCtTfqceUpcqerlPKtnu6WzgeDQY0SWkbig=";
const TOKEN: &str = "fixture-cf-token-hWBiBe3RXo3KGxecH3tNIrFUGJTy";
const SECRETS: [&str; 4] = [SERVER_PRIVATE, PRESHARED, DOCTOR_PRIVATE, TOKEN];

fn server_json() -> Value {
    json!({
        "version": 1,
        "private_key": SERVER_PRIVATE,
        "interface": { "address": "10.66.66.1/24", "mtu": 1380 },
        "peers": [{
            "name": "laptop",
            "public_key": LAPTOP_PUBLIC,
            "preshared_key": PRESHARED,
            "allowed_ips": ["10.66.66.2/32"],
            "endpoint": "203.0.113.7:51830",
            "keepalive": 25
        }],
        "role": { "server": {
            "iface": "en6",
            "listen_port": 51830,
            "lan": "10.73.0.0/24",
            "stun": {
                "servers": ["stun.example.com:3478"],
                "fallback": ["192.0.2.1:3478"],
                "interval_secs": 25,
                "dns_server": "223.5.5.5"
            },
            "upnp": { "control_url": "http://10.73.0.1:1900/ipc", "lease_secs": 3600, "refresh_secs": 300 },
            "cloudflare": { "zone": "example.com", "record": "_wg-home.example.com", "token": TOKEN },
            "doctor": { "private_key": DOCTOR_PRIVATE, "address": "10.66.66.3" }
        }}
    })
}

fn client_json() -> Value {
    json!({
        "version": 1,
        "private_key": DOCTOR_PRIVATE,
        "interface": { "address": "10.66.66.2/32" },
        "peers": [{
            "name": "home",
            "public_key": SERVER_PUBLIC,
            "allowed_ips": ["10.66.66.0/24", "10.73.0.0/24"]
        }],
        "role": { "client": { "record": "_wg-home.example.com", "resolvers": ["223.5.5.5", "1.1.1.1"] } }
    })
}

fn write_private(path: &Path, text: &str) {
    fs::write(path, text).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

fn load_value(value: &Value) -> natwg::Result<Config> {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.json");
    write_private(&path, &value.to_string());
    Config::load(&path)
}

fn natwg() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_natwg"));
    command.env_remove("NATWG_CONFIG");
    command
}

fn mode(path: &Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o7777
}

#[test]
fn saved_configs_load_back_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    for value in [server_json(), client_json()] {
        let config = load_value(&value).unwrap();
        let path = dir.path().join("saved.json");
        config.save(&path).unwrap();
        assert_eq!(mode(&path), 0o600, "save writes an owner-only file");
        assert_eq!(Config::load(&path).unwrap(), config);
    }
    let client = load_value(&client_json()).unwrap();
    assert_eq!(client.interface.mtu, 1380, "mtu defaults to 1380");
}

fn instance_of(config: &Config) -> &str {
    let Role::Server(server) = &config.role else {
        panic!("expected a server config")
    };
    server.instance.as_str()
}

#[test]
fn the_instance_defaults_to_natwg_and_a_chosen_name_survives_a_save() {
    let mut value = server_json();
    assert_eq!(instance_of(&load_value(&value).unwrap()), "natwg");

    value["role"]["server"]["instance"] = json!("natwg_next");
    let config = load_value(&value).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("saved.json");
    config.save(&path).unwrap();
    let saved = Config::load(&path).unwrap();
    assert_eq!(saved, config);
    assert_eq!(instance_of(&saved), "natwg_next");
}

#[test]
fn an_instance_name_must_be_1_to_15_characters_from_a_z_0_9_and_underscore() {
    for name in ["a", "natwg_next", "wg0", "a23456789012345"] {
        let mut value = server_json();
        value["role"]["server"]["instance"] = json!(name);
        assert_eq!(instance_of(&load_value(&value).unwrap()), name);
    }
    for name in [
        "",
        "Natwg",
        "natwg-next",
        "natwg next",
        "natwg/next",
        "natwg\"",
        "a234567890123456",
        "client",
    ] {
        let mut value = server_json();
        value["role"]["server"]["instance"] = json!(name);
        let error = load_value(&value).unwrap_err();
        assert_eq!(error.code, "CONFIG_INVALID", "{name:?}");
    }
}

/// What `Config::validate` says about `server_json` after `change`.
fn validated(change: impl FnOnce(&mut Value)) -> Result<(), String> {
    let mut value = server_json();
    change(&mut value);
    serde_json::from_value::<Config>(value).unwrap().validate()
}

fn refused(field: &str, change: impl FnOnce(&mut Value)) {
    let error = validated(change).unwrap_err();
    assert!(error.starts_with(field), "expected {field}, got {error}");
}

#[test]
fn the_uplink_interface_must_be_a_plain_interface_name() {
    for name in ["en6", "eth0", "bridge101", "wlan-0.1_X", "a23456789012345"] {
        validated(|config| config["role"]["server"]["iface"] = json!(name)).unwrap();
    }
    for name in [
        "",
        "a234567890123456",
        "en 6",
        "en6\n",
        "en6) pass all",
        "eth0\"",
        "en6;",
        "en6/",
        "\u{e9}n6",
    ] {
        refused("role.server.iface", |config| {
            config["role"]["server"]["iface"] = json!(name)
        });
    }
}

fn with_address(address: &str, lan: &str) -> impl FnOnce(&mut Value) {
    let (address, lan) = (json!(address), json!(lan));
    move |config| {
        config["interface"]["address"] = address;
        config["role"]["server"]["lan"] = lan;
        config["role"]["server"]["doctor"] = Value::Null;
        config["peers"] = json!([]);
    }
}

#[test]
fn the_tunnel_address_needs_a_prefix_of_16_bits_or_more() {
    for address in ["10.66.0.1/16", "10.66.66.1/24", "10.66.66.1/32"] {
        validated(with_address(address, "10.73.0.0/24")).unwrap();
    }
    for address in ["10.66.0.1/15", "10.0.0.1/8", "0.0.0.1/0"] {
        refused("interface.address", with_address(address, "192.168.0.0/24"));
    }
}

#[test]
fn the_tunnel_subnet_and_the_lan_must_not_overlap() {
    validated(with_address("10.73.1.1/24", "10.73.0.0/24")).unwrap();
    for (address, lan) in [
        ("10.73.0.200/24", "10.73.0.0/24"),
        ("10.73.1.1/24", "10.73.0.0/16"),
        ("10.73.0.1/16", "10.73.5.0/24"),
        ("10.73.0.9/32", "10.73.0.0/24"),
    ] {
        refused("interface.address", with_address(address, lan));
    }
}

fn lans_of(config: &Config) -> Vec<String> {
    let Role::Server(server) = &config.role else {
        panic!("expected a server config")
    };
    server.lan.iter().map(ToString::to_string).collect()
}

#[test]
fn the_lan_loads_from_a_list_or_from_the_one_string_that_natwg_0_2_wrote() {
    let with_lan = |lan: Option<Value>| {
        let mut value = server_json();
        let server = value["role"]["server"].as_object_mut().unwrap();
        match lan {
            Some(lan) => server.insert("lan".to_owned(), lan),
            None => server.remove("lan"),
        };
        load_value(&value)
    };
    for (lan, expected) in [
        (Some(json!("10.73.0.0/24")), &["10.73.0.0/24"][..]),
        (Some(json!(["10.73.0.0/24"])), &["10.73.0.0/24"]),
        (
            Some(json!(["10.73.0.0/24", "192.168.50.0/24"])),
            &["10.73.0.0/24", "192.168.50.0/24"],
        ),
        (Some(json!([])), &[]),
        (None, &[]),
    ] {
        let config = with_lan(lan.clone()).unwrap();
        assert_eq!(lans_of(&config), expected, "{lan:?}");
    }
    for lan in [
        json!("10.73.0.0/33"),
        json!(["10.73.0.0/24", "lan"]),
        json!(24),
        json!({ "lan": "10.73.0.0/24" }),
    ] {
        assert_eq!(
            with_lan(Some(lan.clone())).unwrap_err().code,
            "CONFIG_INVALID",
            "{lan}"
        );
    }

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.json");
    let config = load_value(&server_json()).unwrap();
    config.save(&path).unwrap();
    let saved: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(
        saved["role"]["server"]["lan"],
        json!(["10.73.0.0/24"]),
        "natwg writes the list form"
    );
    assert_eq!(Config::load(&path).unwrap(), config);
}

fn with_lans(lans: &[&str]) -> impl FnOnce(&mut Value) {
    let lans = json!(lans);
    move |config| config["role"]["server"]["lan"] = lans
}

#[test]
fn every_lan_lies_outside_the_tunnel_subnet_and_apart_from_the_others() {
    for lans in [
        &[][..],
        &["10.73.0.0/24", "192.168.50.0/24", "172.16.0.0/12"],
        &["10.73.0.0/24", "10.73.1.0/24"],
        &["10.66.67.0/24"],
    ] {
        validated(with_lans(lans)).unwrap_or_else(|e| panic!("{lans:?}: {e}"));
    }
    for (lans, field, why) in [
        (
            &["10.73.0.0/24", "10.66.66.128/25"][..],
            "interface.address",
            "role.server.lan[1] 10.66.66.128/25 overlap",
        ),
        (
            &["10.0.0.0/8"],
            "interface.address",
            "role.server.lan[0] 10.0.0.0/8 overlap",
        ),
        (
            &["10.73.0.0/24", "10.73.0.0/24"],
            "role.server.lan[1]",
            "overlaps role.server.lan[0] 10.73.0.0/24",
        ),
        (
            &["192.168.50.0/24", "10.73.0.0/16", "10.73.5.0/24"],
            "role.server.lan[2]",
            "overlaps role.server.lan[1] 10.73.0.0/16",
        ),
        (
            &["10.73.0.0/24", "0.0.0.0/0"],
            "role.server.lan[1]",
            "default route",
        ),
    ] {
        let error = validated(with_lans(lans)).unwrap_err();
        assert!(
            error.starts_with(field) && error.contains(why),
            "{lans:?}: {error}"
        );
    }
}

#[test]
fn the_mtu_must_be_between_576_and_9000() {
    for mtu in [576, 1380, 9000] {
        validated(|config| config["interface"]["mtu"] = json!(mtu)).unwrap();
    }
    for mtu in [0, 575, 9001, 65535] {
        refused("interface.mtu", |config| {
            config["interface"]["mtu"] = json!(mtu)
        });
    }
}

#[test]
fn the_doctor_needs_a_tunnel_address_that_nobody_else_has() {
    let doctor_at = |address: &'static str| {
        move |config: &mut Value| config["role"]["server"]["doctor"]["address"] = json!(address)
    };
    validated(doctor_at("10.66.66.254")).unwrap();
    for (address, why) in [
        ("10.66.67.3", "outside the tunnel subnet"),
        ("10.73.0.9", "outside the tunnel subnet"),
        ("10.66.66.1", "the tunnel address of the server"),
        ("10.66.66.2", "allowed_ips 10.66.66.2/32 of peer \"laptop\""),
    ] {
        let error = validated(doctor_at(address)).unwrap_err();
        assert!(
            error.starts_with("role.server.doctor.address") && error.contains(why),
            "{address}: {error}"
        );
    }
    refused("role.server.doctor.address", |config| {
        config["peers"][0]["allowed_ips"] = json!(["192.168.9.0/24", "10.66.66.0/24"])
    });
}

#[test]
fn a_client_config_needs_a_valid_address_and_mtu_too() {
    let client = |change: fn(&mut Value)| {
        let mut value = client_json();
        change(&mut value);
        serde_json::from_value::<Config>(value).unwrap().validate()
    };
    client(|_| {}).unwrap();
    assert!(client(|config| config["interface"]["mtu"] = json!(100)).is_err());
    assert!(client(|config| config["interface"]["address"] = json!("10.0.0.2/8")).is_err());
}

/// What `Config::validate` says about `client_json` after `change`.
fn client_validated(change: impl FnOnce(&mut Value)) -> Result<(), String> {
    let mut value = client_json();
    change(&mut value);
    serde_json::from_value::<Config>(value).unwrap().validate()
}

fn client_refused(needle: &str, change: impl FnOnce(&mut Value)) {
    let error = client_validated(change).unwrap_err();
    assert!(error.contains(needle), "expected {needle:?} in {error}");
}

#[test]
fn a_client_has_exactly_one_peer_the_server() {
    client_refused("exactly one peer", |config| config["peers"] = json!([]));
    client_refused("exactly one peer", |config| {
        let server = config["peers"][0].clone();
        config["peers"] = json!([server.clone(), server]);
    });
    client_refused("peers[0].allowed_ips is empty", |config| {
        config["peers"][0]["allowed_ips"] = json!([]);
    });
    client_refused("default route", |config| {
        config["peers"][0]["allowed_ips"] = json!(["10.66.66.0/24", "0.0.0.0/0"]);
    });
}

#[test]
fn a_client_finds_the_server_by_its_record_or_at_its_endpoint() {
    client_refused(
        "role.client.record, role.client.server or peers[0].endpoint",
        |config| config["role"]["client"] = json!({}),
    );
    client_validated(|config| {
        config["role"]["client"] = json!({});
        config["peers"][0]["endpoint"] = json!("192.0.2.7:51830");
    })
    .unwrap();
    client_validated(|config| config["role"]["client"] = json!({ "record": "_wg.example.com" }))
        .unwrap();
    for record in ["", "a..b", "white space.example.com\n"] {
        client_refused("role.client.record", |config| {
            config["role"]["client"]["record"] = json!(record);
        });
    }
}

#[test]
fn a_client_names_the_server_by_a_txt_record_or_by_name_and_port_never_both() {
    let with_server = |server: Value| {
        move |config: &mut Value| config["role"]["client"] = json!({ "server": server })
    };
    client_validated(with_server(json!("home.example.com:51830"))).unwrap();
    let mut value = client_json();
    with_server(json!("home.example.com:51830"))(&mut value);
    let config: Config = serde_json::from_value(value).unwrap();
    let Role::Client(client) = &config.role else {
        panic!("a client config")
    };
    let server = client.server.as_ref().unwrap();
    assert_eq!(
        (server.host.as_str(), server.port),
        ("home.example.com", 51830)
    );
    assert_eq!(
        serde_json::to_value(&config).unwrap()["role"]["client"],
        json!({ "server": "home.example.com:51830" })
    );
    client_refused("role.client.record and role.client.server both", |config| {
        config["role"]["client"]["server"] = json!("home.example.com:51830");
    });
}

#[test]
fn a_server_name_is_an_rfc_1123_host_name_and_its_port_plain_digits() {
    for good in [
        "home.example.com:51830",
        "a.b:1",
        "HOME-1.Example.COM:65535",
        "x1.example.co:443",
    ] {
        let parsed: HostPort = good.parse().unwrap_or_else(|e| panic!("{good}: {e}"));
        assert_eq!(parsed.to_string(), good);
    }
    let long = format!("{}.example.com:51830", "a".repeat(64));
    let too_long = format!("{}.com:51830", vec!["a".repeat(63); 4].join("."));
    for (text, why) in [
        (
            "home.example.com:+51830",
            "no port from 1 to 65535 of plain digits",
        ),
        (
            "home.example.com:051830",
            "no port from 1 to 65535 of plain digits",
        ),
        (
            "home.example.com:0",
            "no port from 1 to 65535 of plain digits",
        ),
        (
            "home.example.com:65536",
            "no port from 1 to 65535 of plain digits",
        ),
        (
            "home.example.com: 51830",
            "no port from 1 to 65535 of plain digits",
        ),
        ("home.example.com", "is not \"name:port\""),
        (":51830", "the name is empty"),
        (
            "1.2.3.4:51830",
            "names an address; dial it with peers[0].endpoint \"1.2.3.4:51830\"",
        ),
        ("1.2.3:51830", "ends with an all-digit label"),
        ("home.example.com.:51830", "ends with a dot; leave it out"),
        ("-home.example.com:51830", "has the label \"-home\""),
        ("home-.example.com:51830", "has the label \"home-\""),
        ("home..example.com:51830", "has the label \"\""),
        ("_wg.example.com:51830", "has the label \"_wg\""),
        (
            "white space.example.com:51830",
            "has the label \"white space\"",
        ),
        ("localhost:51830", "is a single label"),
        ("[::1]:51830", "has the label \"[::1]\""),
        (&long, "has the label"),
        (&too_long, "is longer than 253 characters"),
    ] {
        let error = text.parse::<HostPort>().unwrap_err();
        assert!(error.contains(why), "{text}: {error}");
        let mut value = client_json();
        value["role"]["client"] = json!({ "server": text });
        let error = serde_json::from_value::<Config>(value)
            .unwrap_err()
            .to_string();
        assert!(error.contains(why), "{text}: {error}");
    }
}

#[test]
fn a_server_publishes_txt_unless_it_says_a() {
    let config = load_value(&server_json()).unwrap();
    let server = config.server().unwrap();
    assert_eq!(server.publish, PublishMode::Txt);
    assert!(
        serde_json::to_value(&config).unwrap()["role"]["server"]
            .get("publish")
            .is_none(),
        "a config without publish saves without it"
    );
    let mut value = server_json();
    value["role"]["server"]["publish"] = json!("a");
    value["role"]["server"]["cloudflare"]["record"] = json!("home.example.com");
    let config = load_value(&value).unwrap();
    assert_eq!(config.server().unwrap().publish, PublishMode::A);
    assert_eq!(
        serde_json::to_value(&config).unwrap()["role"]["server"]["publish"],
        "a"
    );
    value["role"]["server"]["publish"] = json!("aaaa");
    assert_eq!(load_value(&value).unwrap_err().code, "CONFIG_INVALID");
}

#[test]
fn publish_txt_needs_stun_and_publish_a_does_not() {
    refused(
        "role.server.stun is missing, and publish txt needs it",
        |config| {
            config["role"]["server"]
                .as_object_mut()
                .unwrap()
                .remove("stun");
        },
    );
    validated(|config| {
        config["role"]["server"]["cloudflare"]["record"] = json!("home.example.com");
        let server = config["role"]["server"].as_object_mut().unwrap();
        server.remove("stun");
        server.insert("publish".into(), json!("a"));
    })
    .unwrap();
}

#[test]
fn publish_a_needs_a_record_that_clients_can_dial_and_a_listen_port() {
    for (record, why) in [
        ("_wg-home.example.com", "has the label \"_wg-home\""),
        ("home", "is a single label"),
        ("home.example.com.", "ends with a dot"),
    ] {
        let error = validated(|config| {
            config["role"]["server"]["publish"] = json!("a");
            config["role"]["server"]["cloudflare"]["record"] = json!(record);
        })
        .unwrap_err();
        assert!(
            error.starts_with(
                "cloudflare.record is not a host name that clients can dial, which publish a needs"
            ),
            "{error}"
        );
        assert!(error.contains(why), "{record}: {error}");
    }
    validated(|config| {
        config["role"]["server"]["cloudflare"]["record"] = json!("_wg-home.example.com");
    })
    .unwrap();
    refused("role.server.listen_port is 0", |config| {
        config["role"]["server"]["publish"] = json!("a");
        config["role"]["server"]["cloudflare"]["record"] = json!("home.example.com");
        config["role"]["server"]["listen_port"] = json!(0);
    });
}

#[test]
fn a_client_uplink_must_be_a_plain_interface_name() {
    client_validated(|config| config["role"]["client"]["iface"] = json!("en0")).unwrap();
    for name in ["", "en 0", "en0;", "a234567890123456"] {
        client_refused("role.client.iface", |config| {
            config["role"]["client"]["iface"] = json!(name);
        });
    }
}

#[test]
fn a_client_config_rejects_unknown_fields_and_the_server_fields() {
    for (key, value) in [
        ("listen_port", json!(51830)),
        ("instance", json!("natwg")),
        ("endpoint", json!("192.0.2.7:51830")),
    ] {
        let mut config = client_json();
        config["role"]["client"][key] = value;
        assert_eq!(load_value(&config).unwrap_err().code, "CONFIG_INVALID");
    }
}

#[test]
fn load_refuses_a_config_that_is_not_valid_and_names_the_file_and_the_field() {
    let mut value = server_json();
    value["role"]["server"]["iface"] = json!("en6) pass all");
    let error = load_value(&value).unwrap_err();
    assert_eq!(error.code, "CONFIG_INVALID");
    assert!(error.message.contains("config.json"), "{}", error.message);
    assert!(
        error.message.contains("role.server.iface"),
        "{}",
        error.message
    );
}

#[test]
fn the_update_settings_are_optional_and_survive_a_save() {
    let config = load_value(&server_json()).unwrap();
    assert_eq!(config.update, None);
    assert!(
        !config.exposed().contains("update"),
        "no update object is written"
    );
    for value in [server_json(), client_json()] {
        let mut value = value;
        value["update"] = json!({
            "url": "https://mirror.example.org",
            "repository": "me/natwg",
            "check": "6h"
        });
        let config = load_value(&value).unwrap();
        let update = config.update.clone().unwrap();
        assert_eq!(update.url.as_deref(), Some("https://mirror.example.org"));
        assert_eq!(update.repository.as_deref(), Some("me/natwg"));
        assert_eq!(update.check.as_deref(), Some("6h"));
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        config.save(&path).unwrap();
        assert_eq!(Config::load(&path).unwrap(), config);
    }
    let mut off = client_json();
    off["update"] = json!({ "check": "off" });
    assert_eq!(
        load_value(&off).unwrap().update.unwrap().check.as_deref(),
        Some("off")
    );
}

#[test]
fn bad_update_settings_are_refused_by_name() {
    for (update, field) in [
        (json!({ "url": "http://mirror.example.org" }), "update.url"),
        (
            json!({ "url": "https://mirror.example.org/natwg" }),
            "update.url",
        ),
        (json!({ "repository": "natwg" }), "update.repository"),
        (json!({ "check": "30m" }), "update.check"),
        (json!({ "check": "daily" }), "update.check"),
    ] {
        refused(field, |value| value["update"] = update.clone());
        client_refused(field, |value| value["update"] = update);
    }
    let mut unknown = server_json();
    unknown["update"] = json!({ "channel": "beta" });
    assert_eq!(load_value(&unknown).unwrap_err().code, "CONFIG_INVALID");
}

#[test]
fn unknown_fields_are_rejected_at_any_depth() {
    let mut top = server_json();
    top["extra"] = json!(1);
    let mut nested = server_json();
    nested["role"]["server"]["stun"]["extra"] = json!(1);
    for value in [top, nested] {
        assert_eq!(load_value(&value).unwrap_err().code, "CONFIG_INVALID");
    }
}

#[test]
fn a_config_with_both_roles_is_rejected() {
    let mut value = server_json();
    value["role"]["client"] = client_json()["role"]["client"].clone();
    assert_eq!(load_value(&value).unwrap_err().code, "CONFIG_INVALID");
}

#[test]
fn only_version_1_loads() {
    let mut value = server_json();
    value["version"] = json!(2);
    assert_eq!(load_value(&value).unwrap_err().code, "CONFIG_INVALID");
}

#[test]
fn group_or_other_permissions_are_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.json");
    write_private(&path, &server_json().to_string());
    assert!(Config::load(&path).is_ok());
    for mode in [0o640, 0o604, 0o644, 0o610] {
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
        let error = Config::load(&path).unwrap_err();
        assert_eq!(error.code, "CONFIG_UNSAFE", "mode {mode:o}");
    }
}

#[test]
fn show_and_debug_never_print_a_secret() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.json");
    let config = load_value(&server_json()).unwrap();

    let debug = format!("{config:?}");
    let redacted = config.redacted();
    config.save(&path).unwrap();
    let saved = fs::read_to_string(&path).unwrap();
    let output = natwg()
        .args(["config", "show", "--config"])
        .arg(&path)
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let shown = String::from_utf8(output.stdout).unwrap();
    for secret in SECRETS {
        assert!(saved.contains(secret), "the saved file keeps {secret}");
        for text in [&debug, &redacted, &shown] {
            assert!(!text.contains(secret), "{secret} leaked into {text}");
        }
    }

    let shown: Value = serde_json::from_str(&shown).unwrap();
    assert_eq!(shown["public_key"], SERVER_PUBLIC);
    assert_eq!(shown["private_key"], "<redacted>");
    assert_eq!(shown["peers"][0]["preshared_key"], "<redacted>");
    assert_eq!(shown["role"]["server"]["cloudflare"]["token"], "<redacted>");
    assert_eq!(
        shown["role"]["server"]["doctor"]["private_key"],
        "<redacted>"
    );
    let doctor: Key = DOCTOR_PRIVATE.parse().unwrap();
    assert_eq!(doctor.public_key().to_string(), DOCTOR_PUBLIC);
}

#[test]
fn keys_gen_prints_a_fresh_matching_pair() {
    let generate = || -> Value {
        let output = natwg().args(["keys", "gen"]).output().unwrap();
        assert!(output.status.success(), "{output:?}");
        serde_json::from_slice(&output.stdout).unwrap()
    };
    let first = generate();
    assert_ne!(first["private_key"], generate()["private_key"]);
    let private: Key = first["private_key"].as_str().unwrap().parse().unwrap();
    assert_eq!(first["public_key"], private.public_key().to_string());
}

#[test]
fn natwg_prints_into_a_closed_pipe_without_a_panic() {
    let closed_pipe = || {
        let (reader, writer) = std::io::pipe().unwrap();
        drop(reader);
        writer
    };
    let output = natwg()
        .args(["keys", "gen"])
        .stdout(closed_pipe())
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(0), "{stderr}");
    assert_eq!(stderr, "");

    let output = natwg()
        .args(["config", "show", "--config", "/natwg-none.json"])
        .stderr(closed_pipe())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1), "CONFIG_UNREADABLE exits 1");
}

#[test]
fn secrets_serialize_redacted_outside_the_config_file() {
    let config = load_value(&server_json()).unwrap();
    let text = serde_json::to_string(&config).unwrap();
    for secret in SECRETS {
        assert!(!text.contains(secret), "{secret} leaked into {text}");
    }
}

#[test]
fn a_client_config_cannot_carry_a_doctor() {
    let mut value = client_json();
    value["role"]["client"]["doctor"] =
        json!({ "private_key": DOCTOR_PRIVATE, "address": "10.66.66.3" });
    assert_eq!(load_value(&value).unwrap_err().code, "CONFIG_INVALID");
}

#[test]
fn a_fifo_at_the_config_path_is_refused_without_blocking() {
    let dir = tempfile::tempdir().unwrap();
    let fifo = dir.path().join("config.json");
    assert!(
        Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success()
    );
    fs::set_permissions(&fifo, fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(Config::load(&fifo).unwrap_err().code, "CONFIG_UNSAFE");
}

#[test]
fn save_creates_missing_directories_readable_only_by_their_owner() {
    let dir = tempfile::tempdir().unwrap();
    let nested = dir.path().join("etc/natwg");
    let config = load_value(&server_json()).unwrap();
    config.save(&nested.join("config.json")).unwrap();
    assert_eq!(mode(&dir.path().join("etc")), 0o700);
    assert_eq!(mode(&nested), 0o700);
}

#[cfg(target_os = "macos")]
#[test]
fn a_config_that_carries_an_acl_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.json");
    load_value(&server_json()).unwrap().save(&path).unwrap();
    let chmod = |args: &[&str]| {
        let status = Command::new("/bin/chmod")
            .args(args)
            .arg(&path)
            .status()
            .unwrap();
        assert!(status.success(), "chmod {args:?}");
    };

    chmod(&["+a", "everyone allow read"]);
    assert_eq!(mode(&path), 0o600, "the ACL leaves the mode as it was");
    let error = Config::load(&path).unwrap_err();
    assert_eq!(error.code, "CONFIG_UNSAFE");
    assert!(error.message.contains("ACL"), "{}", error.message);

    chmod(&["-N"]);
    Config::load(&path).unwrap();
}

fn doctor_of(path: &Path) -> Option<DoctorConfig> {
    let Role::Server(server) = Config::load(path).unwrap().role else {
        panic!("a server config")
    };
    server.doctor
}

#[test]
fn config_doctor_adds_a_doctor_at_the_highest_free_host_and_replaces_it_only_with_force() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.json");
    let mut value = server_json();
    value["role"]["server"]
        .as_object_mut()
        .unwrap()
        .remove("doctor");
    value["peers"].as_array_mut().unwrap().push(json!({
        "name": "phone", "public_key": DOCTOR_PUBLIC, "allowed_ips": ["10.66.66.252/30"]
    }));
    write_private(&path, &value.to_string());
    let doctor = |extra: &[&str]| {
        natwg()
            .arg("--config")
            .arg(&path)
            .args(["config", "doctor"])
            .args(extra)
            .output()
            .unwrap()
    };

    let output = doctor(&[]);
    assert!(output.status.success(), "{output:?}");
    let first = doctor_of(&path).unwrap();
    let expected: std::net::Ipv4Addr = "10.66.66.251".parse().unwrap();
    assert_eq!(first.address, expected, ".252 to .255 belong to the phone");
    assert_eq!(mode(&path), 0o600);
    let stdout = String::from_utf8(output.stdout).unwrap();
    let public = first.private_key.public_key().to_string();
    assert_eq!(stdout, format!("doctor {expected} public key {public}\n"));

    let before = fs::read(&path).unwrap();
    let output = doctor(&[]);
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.starts_with("DOCTOR_EXISTS: "), "{stderr}");
    assert_eq!(
        fs::read(&path).unwrap(),
        before,
        "a refused run writes nothing"
    );

    let output = doctor(&["--force"]);
    assert!(output.status.success(), "{output:?}");
    let second = doctor_of(&path).unwrap();
    assert_eq!(second.address, expected);
    assert_ne!(second.private_key, first.private_key, "a fresh key");
    let left: Vec<_> = fs::read_dir(dir.path()).unwrap().collect();
    assert_eq!(left.len(), 1, "the write leaves no temporary file");
}

#[test]
fn the_doctor_never_takes_the_address_of_the_server() {
    let mut value = server_json();
    value["role"]["server"]
        .as_object_mut()
        .unwrap()
        .remove("doctor");
    value["interface"]["address"] = json!("10.66.66.254/24");
    let mut config = load_value(&value).unwrap();
    let doctor = config.add_doctor(false).unwrap();
    assert_eq!(
        doctor.address,
        "10.66.66.253".parse::<std::net::Ipv4Addr>().unwrap()
    );
    config.validate().unwrap();
}
