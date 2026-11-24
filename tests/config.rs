use natwg::config::{
    CloudflareConfig, Config, DoctorConfig, Instance, Interface, PeerConfig, Role, ServerConfig,
    StunConfig, UpnpConfig, Version1,
};
use natwg::keys::Key;
use serde_json::{Value, json};
use std::{
    fs,
    num::NonZeroU64,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Output},
};

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

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/legacy")
        .join(name)
}

fn natwg() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_natwg"));
    command.env_remove("NATWG_CONFIG");
    command
}

fn import_fixture(out: &Path, extra: &[&str]) -> Output {
    natwg()
        .args(["config", "import-legacy", "--natwg-json"])
        .arg(fixture("natwg.json"))
        .arg("--wg-conf")
        .arg(fixture("wg-home.conf"))
        .arg("--cf-token")
        .arg(fixture("cf_token"))
        .arg("--out")
        .arg(out)
        .args(extra)
        .output()
        .unwrap()
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
fn legacy_import_maps_every_field() {
    let config = natwg::legacy::import(
        &fixture("natwg.json"),
        Some(&fixture("wg-home.conf")),
        Some(&fixture("cf_token")),
    )
    .unwrap();
    let expected = Config {
        version: Version1,
        private_key: SERVER_PRIVATE.parse().unwrap(),
        interface: Interface {
            address: "10.66.66.1/24".parse().unwrap(),
            mtu: 1420,
        },
        peers: vec![PeerConfig {
            name: "laptop".into(),
            public_key: LAPTOP_PUBLIC.parse().unwrap(),
            preshared_key: Some(PRESHARED.parse().unwrap()),
            allowed_ips: vec!["10.66.66.2/32".parse().unwrap()],
            endpoint: None,
            keepalive: None,
        }],
        role: Role::Server(ServerConfig {
            instance: Instance::default(),
            iface: "en6".into(),
            listen_port: 51830,
            lan: "10.73.0.0/24".parse().unwrap(),
            stun: StunConfig {
                servers: vec![
                    "stun.miwifi.com:3478".into(),
                    "stun.chat.bilibili.com:3478".into(),
                    "stun.hitv.com:3478".into(),
                    "stun.cloudflare.com:3478".into(),
                ],
                fallback: vec![
                    "111.206.174.3:3478".parse().unwrap(),
                    "111.206.174.2:3478".parse().unwrap(),
                ],
                interval_secs: NonZeroU64::new(17).unwrap(),
                dns_server: "223.5.5.5".parse().unwrap(),
            },
            upnp: Some(UpnpConfig {
                control_url: "http://10.73.0.1:1900/ipc".into(),
                lease_secs: 3600,
                refresh_secs: NonZeroU64::new(300).unwrap(),
            }),
            cloudflare: CloudflareConfig {
                zone: "example.com".into(),
                record: "_wg-home.example.com".into(),
                token: TOKEN.parse().unwrap(),
            },
            doctor: None,
        }),
    };
    assert_eq!(config, expected);
    assert_eq!(config.private_key.public_key().to_string(), SERVER_PUBLIC);
}

#[test]
fn legacy_import_twice_writes_identical_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("config.json");
    let mut runs = Vec::new();
    for _ in 0..2 {
        let output = import_fixture(&out, &[]);
        assert!(output.status.success(), "{output:?}");
        runs.push(fs::read(&out).unwrap());
    }
    assert_eq!(runs[0], runs[1]);
    assert_eq!(mode(&out), 0o600);
    let Role::Server(server) = Config::load(&out).unwrap().role else {
        panic!("legacy import is a server config")
    };
    assert_eq!(server.doctor, None);
}

#[test]
fn legacy_import_without_cf_token_writes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let token = dir.path().join("cf_token");
    let mut legacy: Value =
        serde_json::from_str(&fs::read_to_string(fixture("natwg.json")).unwrap()).unwrap();
    legacy["wg_conf"] = json!(fixture("wg-home.conf"));
    legacy["cf_token_file"] = json!(token);
    let natwg_json = dir.path().join("natwg.json");
    fs::write(&natwg_json, legacy.to_string()).unwrap();
    let out = dir.path().join("config.json");
    let import = || {
        natwg()
            .args(["config", "import-legacy", "--natwg-json"])
            .arg(&natwg_json)
            .arg("--out")
            .arg(&out)
            .output()
            .unwrap()
    };

    let output = import();
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains(&token.display().to_string()), "{stderr}");
    assert!(!out.exists(), "a failed import writes no config");

    fs::copy(fixture("cf_token"), &token).unwrap();
    let output = import();
    assert!(output.status.success(), "{output:?}");
    assert!(out.exists(), "paths default to the ones natwg.json names");
}

#[test]
fn dry_run_prints_the_server_public_key_and_writes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("config.json");
    let output = import_fixture(&out, &["--dry-run"]);
    assert!(output.status.success(), "{output:?}");
    let shown: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(shown["public_key"], SERVER_PUBLIC);
    assert!(!out.exists());
}

#[test]
fn show_and_debug_never_print_a_secret() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.json");
    let mut config = natwg::legacy::import(
        &fixture("natwg.json"),
        Some(&fixture("wg-home.conf")),
        Some(&fixture("cf_token")),
    )
    .unwrap();
    let Role::Server(server) = &mut config.role else {
        panic!("legacy import is a server config")
    };
    server.doctor = Some(DoctorConfig {
        private_key: DOCTOR_PRIVATE.parse().unwrap(),
        address: "10.66.66.3".parse().unwrap(),
    });

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
fn a_malformed_legacy_key_line_never_echoes_the_key() {
    let dir = tempfile::tempdir().unwrap();
    let fixture_conf = fs::read_to_string(fixture("wg-home.conf")).unwrap();
    let private_line = format!("PrivateKey = {SERVER_PRIVATE}");
    assert!(fixture_conf.contains(&private_line));
    let letters_key = "QWErtyUIOPasdfghJKLzxcvbnmQWERTYUIOPasdfghA=";
    for (line, key) in [
        (format!("PrivateKey: {SERVER_PRIVATE}"), SERVER_PRIVATE),
        (format!("PrivateKey{letters_key}"), letters_key),
        (letters_key.to_owned(), letters_key),
    ] {
        let wg_conf = dir.path().join("wg-home.conf");
        fs::write(&wg_conf, fixture_conf.replace(&private_line, &line)).unwrap();
        let output = natwg()
            .args(["config", "import-legacy", "--dry-run", "--natwg-json"])
            .arg(fixture("natwg.json"))
            .arg("--wg-conf")
            .arg(&wg_conf)
            .arg("--cf-token")
            .arg(fixture("cf_token"))
            .output()
            .unwrap();
        assert!(!output.status.success(), "{line}");
        let stderr = String::from_utf8(output.stderr).unwrap().to_lowercase();
        assert!(stderr.contains("legacy_invalid"), "{stderr}");
        assert!(!stderr.contains(&key[..16].to_lowercase()), "{stderr}");
    }
}

#[test]
fn an_empty_upnp_control_url_imports_as_upnp_off() {
    let dir = tempfile::tempdir().unwrap();
    let mut legacy: Value =
        serde_json::from_str(&fs::read_to_string(fixture("natwg.json")).unwrap()).unwrap();
    legacy["upnp_control_url"] = json!("");
    let natwg_json = dir.path().join("natwg.json");
    fs::write(&natwg_json, legacy.to_string()).unwrap();
    let config = natwg::legacy::import(
        &natwg_json,
        Some(&fixture("wg-home.conf")),
        Some(&fixture("cf_token")),
    )
    .unwrap();
    let Role::Server(server) = config.role else {
        panic!("legacy import is a server config")
    };
    assert_eq!(server.upnp, None);
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
