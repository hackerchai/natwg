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
fn a_client_of_a_server_with_publish_a_dials_the_name_at_the_listen_port() {
    let mut value = server_json();
    value["role"]["server"]["publish"] = json!("a");
    value["role"]["server"]["cloudflare"]["record"] = json!("home-next.example.com");
    let mut server = config(value);
    let client = peer::add(&mut server, "tablet").unwrap();
    client.validate().unwrap();
    let Role::Client(role) = &client.role else {
        panic!("peer add returns a client config")
    };
    assert_eq!(role.record, None);
    assert_eq!(
        role.server.as_ref().map(ToString::to_string).as_deref(),
        Some("home-next.example.com:51831")
    );
    assert_eq!(role.resolvers.len(), 4);
    let printed: Value = serde_json::from_str(&client.exposed()).unwrap();
    assert_eq!(
        printed["role"]["client"]["server"],
        "home-next.example.com:51831"
    );
    assert!(printed["role"]["client"].get("record").is_none());
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

fn public_server(path: &Path) -> Config {
    let mut cfg = server_json();
    cfg["role"]["server"]["publish"] = json!("a");
    cfg["role"]["server"]["cloudflare"]["record"] = json!("wg.example.net");
    cfg["role"]["server"]["lan"] = json!(["10.73.0.0/24", "192.168.20.0/24"]);
    let server = config(cfg);
    server.save(path).unwrap();
    server
}

fn export(input: &Path, format: &str, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_natwg"))
        .arg("--config")
        .arg(input)
        .args(["config", "export", "--format", format])
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn formats_preserve_the_devices_keys_mtu_keepalive_and_split_routes() {
    let dir = tempfile::tempdir().unwrap();
    let server = dir.path().join("server.json");
    let initial = public_server(&server);
    let client = dir.path().join("client.json");
    let added = natwg(
        &server,
        &["add", "laptop2", "--out", client.to_str().unwrap()],
    );
    assert!(added.status.success());
    let json = export(&client, "natwg", &[]);
    assert!(json.status.success());
    let identity = Config::load(&client).unwrap();
    assert_eq!(
        serde_json::from_slice::<Config>(&json.stdout).unwrap(),
        identity
    );
    for (format, snippets) in [
        (
            "wg-quick",
            vec![
                "Address = 10.66.67.6/32",
                "MTU = 1400",
                "PersistentKeepalive = 25",
                "Endpoint = wg.example.net:51831",
                "AllowedIPs = 10.66.67.0/24, 10.73.0.0/24, 192.168.20.0/24",
            ],
        ),
        (
            "surge",
            vec![
                "self-ip = 10.66.67.6\n",
                "mtu = 1400",
                "keepalive = 25)",
                "endpoint = wg.example.net:51831",
                "allowed-ips = \"10.66.67.0/24, 10.73.0.0/24, 192.168.20.0/24\"",
                "IP-CIDR,192.168.20.0/24,natwg,no-resolve",
                "FINAL,DIRECT",
            ],
        ),
        (
            "clash",
            vec![
                "ip: 10.66.67.6\n",
                "mtu: 1400",
                "persistent-keepalive: 25",
                "server: \"wg.example.net\"",
                "port: 51831",
                "IP-CIDR,10.73.0.0/24,natwg,no-resolve",
                "IP-CIDR,192.168.20.0/24,natwg,no-resolve",
                "udp: true",
            ],
        ),
    ] {
        let result = export(&client, format, &[]);
        assert!(result.status.success());
        let text = String::from_utf8(result.stdout).unwrap();
        for snippet in snippets {
            assert!(text.contains(snippet), "{format} missing {snippet}");
        }
        assert!(text.contains(&identity.private_key.to_base64()));
        assert!(
            text.contains(
                &identity.peers[0]
                    .preshared_key
                    .as_ref()
                    .unwrap()
                    .to_base64()
            )
        );
        assert!(text.contains(&initial.private_key.public_key().to_string()));
        assert!(!text.contains("snapshot"));
    }

    let profile = dir.path().join("phone.conf");
    fs::write(&profile, "previous").unwrap();
    fs::set_permissions(&profile, fs::Permissions::from_mode(0o644)).unwrap();
    let issued = natwg(
        &server,
        &[
            "add",
            "DIRECT",
            "--format",
            "surge",
            "--out",
            profile.to_str().unwrap(),
            "--force",
        ],
    );
    assert!(issued.status.success());
    assert!(issued.stdout.is_empty());
    assert_eq!(mode(&profile), 0o600);
    assert!(
        fs::read_to_string(profile)
            .unwrap()
            .contains("natwg-DIRECT = wireguard, section-name = natwg-DIRECT")
    );

    let server_export = export(&server, "wg-quick", &[]);
    assert!(server_export.status.success());
    let text = String::from_utf8(server_export.stdout).unwrap();
    assert_eq!(text.matches("[Peer]").count(), initial.peers.len() + 3);
    assert!(text.contains(&initial.private_key.to_base64()));
    assert!(text.contains("ListenPort = 51831"));
    assert!(text.contains("PostUp = "));
    assert!(text.contains("PostDown = "));
    assert!(text.contains(&identity.private_key.public_key().to_string()));
    assert!(!text.contains(&identity.private_key.to_base64()));
    assert!(
        !text.contains(
            &initial
                .server()
                .unwrap()
                .doctor
                .as_ref()
                .unwrap()
                .private_key
                .to_base64()
        )
    );
    for format in ["natwg", "surge", "clash"] {
        let result = export(&server, format, &[]);
        assert!(!result.status.success());
        assert!(result.stdout.is_empty());
    }
}

#[test]
fn a_refused_or_broken_output_never_commits_a_new_peer() {
    use std::{io::pipe, os::unix::fs::symlink};
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("server.json");
    let original = public_server(&input);
    let alias = dir.path().join("alias.json");
    symlink(&input, &alias).unwrap();
    let hardlink = dir.path().join("hard.json");
    fs::hard_link(&input, &hardlink).unwrap();
    for out in [&input, &alias, &hardlink] {
        let args = ["--out", out.to_str().unwrap(), "--force"];
        assert!(!export(&input, "wg-quick", &args).status.success());
        let mut add = vec!["add", "device"];
        add.extend(args);
        assert!(!natwg(&input, &add).status.success());
        assert_eq!(Config::load(out).unwrap(), original);
        assert_eq!(Config::load(&input).unwrap(), original);
    }
    let (read, write) = pipe().unwrap();
    drop(read);
    let broken = Command::new(env!("CARGO_BIN_EXE_natwg"))
        .arg("--config")
        .arg(&input)
        .args(["peer", "add", "device"])
        .stdout(write)
        .output()
        .unwrap();
    assert!(!broken.status.success());
    assert_eq!(Config::load(&input).unwrap(), original);

    let mut config = original;
    config.interface.mtu = 1500;
    config.save(&input).unwrap();
    let out = dir.path().join("phone.conf");
    let refused = natwg(
        &input,
        &[
            "add",
            "phone2",
            "--format",
            "surge",
            "--out",
            out.to_str().unwrap(),
        ],
    );
    assert!(!refused.status.success());
    assert!(
        String::from_utf8(refused.stderr)
            .unwrap()
            .contains("SURGE_MTU")
    );
    assert!(!out.exists());
    assert_eq!(Config::load(&input).unwrap(), config);
}

#[test]
fn a_failed_txt_snapshot_cannot_silently_fall_back_to_a_stale_endpoint() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("server.json");
    let mut server = config(server_json());
    let Role::Server(role) = &mut server.role else {
        unreachable!()
    };
    role.iface = "absent_natwg9".into();
    server.save(&input).unwrap();
    let bad = natwg(&input, &["add", "tablet", "--format", "clash"]);
    assert!(!bad.status.success());
    assert!(bad.stdout.is_empty());
    assert_eq!(Config::load(&input).unwrap(), server);
    assert!(!export(&input, "wg-quick", &[]).status.success());

    let mut client = peer::add(&mut server, "tablet").unwrap();
    client.peers[0].endpoint = Some("192.0.2.9:12345".parse().unwrap());
    let Role::Client(role) = &mut client.role else {
        unreachable!()
    };
    role.iface = Some("absent_natwg9".into());
    let path = dir.path().join("client.json");
    client.save(&path).unwrap();
    assert!(export(&path, "natwg", &[]).status.success());
    assert!(!export(&path, "wg-quick", &[]).status.success());
    let Role::Client(role) = &mut client.role else {
        unreachable!()
    };
    role.record = None;
    client.peers[0].preshared_key = None;
    client.peers[0].keepalive = Some(0);
    client.save(&path).unwrap();
    let result = export(&path, "surge", &[]);
    assert!(result.status.success());
    let profile = String::from_utf8(result.stdout).unwrap();
    assert!(profile.contains("endpoint = 192.0.2.9:12345, keepalive = 0)"));
    assert!(!profile.contains("preshared-key"));
    assert!(!profile.contains("snapshot"));
}

#[test]
fn peer_edits_follow_a_symlink_and_keep_the_daemon_config_in_sync() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("server.json");
    let original = public_server(&path);
    let aliases = dir.path().join("aliases");
    fs::create_dir(&aliases).unwrap();
    let alias = aliases.join("active.json");
    std::os::unix::fs::symlink("../server.json", &alias).unwrap();
    let new = natwg(&alias, &["add", "watch"]);
    assert!(new.status.success());
    let client: Config = serde_json::from_slice(&new.stdout).unwrap();
    let enrolled = Config::load(&path).unwrap();
    assert_eq!(
        enrolled.peers.last().unwrap().public_key,
        client.private_key.public_key()
    );
    assert!(alias.is_symlink());
    assert!(natwg(&alias, &["remove", "watch"]).status.success());
    assert!(alias.is_symlink());
    assert_eq!(Config::load(&path).unwrap(), original);
}

#[test]
fn failed_server_save_preserves_the_previous_client_profile_under_force() {
    // Root bypasses the directory permissions used for this failure.
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let server_dir = dir.path().join("server");
    fs::create_dir(&server_dir).unwrap();
    let path = server_dir.join("server.json");
    public_server(&path);
    let out = dir.path().join("device.conf");
    let out_args = [
        "--out",
        out.to_str().unwrap(),
        "--format",
        "wg-quick",
        "--force",
    ];
    assert!(
        natwg(&path, &[&["add", "old"][..], &out_args].concat())
            .status
            .success()
    );
    let old_server = fs::read(&path).unwrap();
    let old_profile = fs::read(&out).unwrap();
    fs::set_permissions(&server_dir, fs::Permissions::from_mode(0o500)).unwrap();
    let failed = natwg(&path, &[&["add", "new"][..], &out_args].concat());
    fs::set_permissions(&server_dir, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(!failed.status.success());
    assert!(String::from_utf8_lossy(&failed.stderr).contains("CONFIG_STORAGE"));
    assert!(fs::read(&out).unwrap() == old_profile);
    assert!(fs::read(&path).unwrap() == old_server);
}

#[cfg(target_os = "macos")]
#[test]
fn an_immutable_profile_rolls_back_enrollment_after_the_server_saves() {
    let dir = tempfile::tempdir().unwrap();
    let server = dir.path().join("server.json");
    let original = public_server(&server);
    let out = dir.path().join("device.conf");
    fs::write(&out, "existing private profile").unwrap();
    let immutable = |flag| {
        Command::new("chflags")
            .arg(flag)
            .arg(&out)
            .status()
            .unwrap()
            .success()
    };
    assert!(immutable("uchg"));
    let result = natwg(
        &server,
        &["add", "watch", "--out", out.to_str().unwrap(), "--force"],
    );
    assert!(immutable("nouchg"));
    assert!(!result.status.success());
    assert_eq!(Config::load(&server).unwrap(), original);
    assert_eq!(fs::read_to_string(out).unwrap(), "existing private profile");
}

#[test]
fn concurrent_enrollments_persist_both_device_identities() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("server.json");
    public_server(&path);
    let issued: Vec<_> = std::thread::scope(|scope| {
        let children: Vec<_> = ["desk", "watch"]
            .into_iter()
            .map(|name| {
                let path = &path;
                scope.spawn(move || natwg(path, &["add", name]))
            })
            .collect();
        children
            .into_iter()
            .map(|child| child.join().unwrap())
            .collect()
    });
    let stored = Config::load(&path).unwrap();
    for output in issued {
        assert!(output.status.success());
        let client: Config = serde_json::from_slice(&output.stdout).unwrap();
        assert!(
            stored
                .peers
                .iter()
                .any(|p| p.public_key == client.private_key.public_key()
                    && p.allowed_ips == [client.interface.address])
        );
    }
}

#[cfg(target_os = "macos")]
#[test]
fn exported_pf_hooks_refuse_collisions_and_return_their_enable_reference() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("server.json");
    let mut server = public_server(&input);
    if let Role::Server(role) = &mut server.role {
        role.iface = "lo0".into();
    }
    server.save(&input).unwrap();
    let export = export(&input, "wg-quick", &[]);
    assert!(export.status.success());
    let config = String::from_utf8(export.stdout).unwrap();
    let stub = dir.path().join("pfctl");
    fs::write(
        &stub,
        r#"#!/bin/bash
set -eu
case "$*" in
    '-s nat') echo 'nat-anchor "com.apple/*" all' ;;
    '-a com.apple/natwg_next -s nat') cat nat ;;
    '-E') echo "Token : 123" >&2; touch enabled ;;
    '-a com.apple/natwg_next -N -f -') test -e enabled; cat > nat ;;
    '-a com.apple/natwg_next -F nat') : > nat ;;
    '-X 123') rm enabled ;;
    *) exit 2 ;;
esac
"#,
    )
    .unwrap();
    fs::set_permissions(&stub, fs::Permissions::from_mode(0o700)).unwrap();
    let sysctl = dir.path().join("sysctl");
    fs::write(
        &sysctl,
        r#"#!/bin/bash
case "$1" in
    -w) test ! -e fail_forward && echo 1 > forwarding ;;
    -n) cat forwarding ;;
esac
"#,
    )
    .unwrap();
    fs::set_permissions(&sysctl, fs::Permissions::from_mode(0o700)).unwrap();
    let forwarding = dir.path().join("forwarding");
    fs::write(&forwarding, "0").unwrap();
    let run = |phase: &str| {
        for line in config.lines().filter_map(|l| l.strip_prefix(phase)) {
            let hook = line.replace("/var/run/natwg-wg-quick-natwg_next", "./lease");
            let result = Command::new("/bin/bash")
                .args(["-e", "-o", "pipefail", "-c", &hook])
                .env("PATH", format!("{}:/usr/bin:/bin", dir.path().display()))
                .current_dir(dir.path())
                .output()
                .unwrap();
            if !result.status.success() {
                return false;
            }
        }
        true
    };
    let rules = dir.path().join("nat");
    fs::write(&rules, "foreign NAT rule\n").unwrap();
    assert!(!run("PostUp = "));
    assert_eq!(fs::read_to_string(&rules).unwrap(), "foreign NAT rule\n");
    assert_eq!(fs::read_to_string(&forwarding).unwrap(), "0");
    fs::write(&rules, "").unwrap();
    fs::write(dir.path().join("fail_forward"), "").unwrap();
    assert!(!run("PostUp = "));
    assert!(!dir.path().join("enabled").exists());
    assert!(!dir.path().join("lease").exists());
    assert_eq!(fs::read_to_string(&rules).unwrap(), "");
    fs::remove_file(dir.path().join("fail_forward")).unwrap();
    assert!(run("PostUp = "));
    assert_eq!(fs::read_to_string(&forwarding).unwrap().trim(), "1");
    let own = fs::read_to_string(&rules).unwrap();
    assert_eq!(own.lines().count(), 2);
    // Parse exactly the generated translation rules, without loading them.
    let parsed = Command::new("/sbin/pfctl")
        .args(["-n", "-N", "-a", "com.apple/natwg_next", "-f"])
        .arg(&rules)
        .output()
        .unwrap();
    assert!(
        parsed.status.success(),
        "{}",
        String::from_utf8_lossy(&parsed.stderr)
    );
    assert!(dir.path().join("enabled").exists());
    fs::write(&rules, format!("{own}foreign NAT rule\n")).unwrap();
    assert!(!run("PostDown = "));
    assert!(
        fs::read_to_string(&rules)
            .unwrap()
            .contains("foreign NAT rule")
    );
    fs::write(&rules, own.replace(")\n", ") round-robin\n")).unwrap();
    assert!(run("PostDown = "));
    assert_eq!(fs::read_to_string(&rules).unwrap(), "");
    assert!(!dir.path().join("enabled").exists());
    assert!(!dir.path().join("lease").exists());
}
