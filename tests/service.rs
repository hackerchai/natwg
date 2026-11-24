//! The service definitions natwg writes, and the commands that need root.

use natwg::config::{Instance, make_private_dir};
use natwg::service::{self, BINARY, Service, launchd, systemd};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command,
};

fn service(instance: &str, config: &str) -> Service {
    Service {
        instance: instance.parse().unwrap(),
        config: PathBuf::from(config),
    }
}

fn instance(name: &str) -> Instance {
    name.parse().unwrap()
}

#[test]
fn the_instance_natwg_keeps_the_plain_names_and_another_instance_adds_its_own() {
    let (natwg, next) = (instance("natwg"), instance("natwg_next"));
    assert_eq!(launchd::name(&natwg), "com.hackerchai.natwg");
    assert_eq!(launchd::name(&next), "com.hackerchai.natwg.natwg_next");
    assert_eq!(
        launchd::definition_path(&natwg),
        Path::new("/Library/LaunchDaemons/com.hackerchai.natwg.plist")
    );
    assert_eq!(
        launchd::definition_path(&next),
        Path::new("/Library/LaunchDaemons/com.hackerchai.natwg.natwg_next.plist")
    );
    assert_eq!(launchd::log(&natwg), "/usr/local/var/log/natwg.log");
    assert_eq!(
        launchd::log(&next),
        "/usr/local/var/log/natwg-natwg_next.log"
    );

    assert_eq!(systemd::name(&natwg), "natwg.service");
    assert_eq!(systemd::name(&next), "natwg-natwg_next.service");
    assert_eq!(
        systemd::definition_path(&natwg),
        Path::new("/etc/systemd/system/natwg.service")
    );
    assert_eq!(
        systemd::definition_path(&next),
        Path::new("/etc/systemd/system/natwg-natwg_next.service")
    );
}

#[test]
fn the_client_service_has_names_no_server_can_take() {
    let client = Instance::client();
    assert!(
        "client".parse::<Instance>().is_err(),
        "no server is named client"
    );
    assert_eq!(launchd::name(&client), "com.hackerchai.natwg.client");
    assert_eq!(
        launchd::definition_path(&client),
        Path::new("/Library/LaunchDaemons/com.hackerchai.natwg.client.plist")
    );
    assert_eq!(launchd::log(&client), "/usr/local/var/log/natwg-client.log");
    assert_eq!(systemd::name(&client), "natwg-client.service");
    for server in ["natwg", "natwg_next", "client0", "natwg_client"] {
        let server = instance(server);
        assert_ne!(launchd::name(&server), launchd::name(&client));
        assert_ne!(systemd::name(&server), systemd::name(&client));
    }
    let service = Service {
        instance: client,
        config: PathBuf::from("/etc/natwg/config.json"),
    };
    let unit = systemd::definition(&service).unwrap();
    assert!(
        unit.contains("Description=natwg WireGuard client\n"),
        "{unit}"
    );
    let plist = launchd::definition(&service).unwrap();
    assert!(
        plist.contains("<string>com.hackerchai.natwg.client</string>"),
        "{plist}"
    );
    assert!(plist.contains("<string>daemon</string>"), "{plist}");
}

#[test]
fn the_plist_runs_the_installed_binary_and_restarts_it_every_10_s() {
    let plist = launchd::definition(&service("natwg", "/usr/local/etc/natwg/config.json")).unwrap();
    assert_eq!(
        plist,
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.hackerchai.natwg</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/local/libexec/natwg/natwg</string>
    <string>--config</string>
    <string>/usr/local/etc/natwg/config.json</string>
    <string>daemon</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ThrottleInterval</key><integer>10</integer>
  <key>ExitTimeOut</key><integer>15</integer>
  <key>StandardOutPath</key><string>/usr/local/var/log/natwg.log</string>
  <key>StandardErrorPath</key><string>/usr/local/var/log/natwg.log</string>
</dict>
</plist>
"#
    );
    let next =
        launchd::definition(&service("natwg_next", "/private/tmp/natwg-p5/config.json")).unwrap();
    assert_eq!(
        next,
        plist
            .replace("com.hackerchai.natwg<", "com.hackerchai.natwg.natwg_next<")
            .replace(
                "/usr/local/etc/natwg/config.json",
                "/private/tmp/natwg-p5/config.json"
            )
            .replace("natwg.log", "natwg-natwg_next.log")
    );
}

#[test]
fn the_unit_runs_the_installed_binary_and_restarts_it_every_10_s() {
    let unit = systemd::definition(&service("natwg", "/etc/natwg/config.json")).unwrap();
    assert_eq!(
        unit,
        r#"[Unit]
Description=natwg WireGuard server natwg
Wants=network-online.target
After=network-online.target

[Service]
Type=exec
ExecStart="/usr/local/libexec/natwg/natwg" "--config" "/etc/natwg/config.json" "daemon"
Restart=always
RestartSec=10
TimeoutStopSec=15

[Install]
WantedBy=multi-user.target
"#
    );
    let next = systemd::definition(&service("natwg_next", "/tmp/natwg-p5/config.json")).unwrap();
    assert_eq!(
        next,
        unit.replace("server natwg\n", "server natwg_next\n")
            .replace("/etc/natwg/config.json", "/tmp/natwg-p5/config.json")
    );
}

#[test]
fn a_config_path_with_special_characters_reaches_the_server_unchanged() {
    let path = r#"/srv/a b&<c>"d'\e%f$g/config.json"#;
    let unit = systemd::definition(&service("natwg", path)).unwrap();
    let exec = unit
        .lines()
        .find_map(|line| line.strip_prefix("ExecStart="))
        .unwrap();
    assert_eq!(
        exec,
        r#""/usr/local/libexec/natwg/natwg" "--config" "/srv/a b&<c>\"d'\\e%%f$$g/config.json" "daemon""#
    );
    if cfg!(target_os = "macos") {
        let plist = launchd::definition(&service("natwg", path)).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("natwg.plist");
        fs::write(&file, plist).unwrap();
        let output = Command::new("/usr/bin/plutil")
            .args(["-extract", "ProgramArguments.2", "raw", "-o", "-"])
            .arg(&file)
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        assert_eq!(String::from_utf8(output.stdout).unwrap().trim_end(), path);
    }
}

#[test]
fn a_config_path_with_a_control_character_is_refused() {
    for definition in [launchd::definition, systemd::definition] {
        let error = definition(&service("natwg", "/etc/natwg\n/config.json")).unwrap_err();
        assert_eq!(error.code, "SERVICE_PATH");
    }
}

fn mode(path: &Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o7777
}

#[test]
fn the_config_directory_is_created_private() {
    let dir = tempfile::tempdir().unwrap();
    let nested = dir.path().join("etc/natwg");
    make_private_dir(&nested).unwrap();
    assert_eq!(mode(&nested), 0o700);
    make_private_dir(&nested).unwrap();
    assert_eq!(mode(&nested), 0o700, "a second run converges");
}

#[cfg(target_os = "macos")]
#[test]
fn an_open_config_directory_becomes_private_and_passes_no_acl_to_a_new_config() {
    use natwg::config::Config;
    let dir = tempfile::tempdir().unwrap();
    let natwg = dir.path().join("natwg");
    fs::create_dir(&natwg).unwrap();
    fs::set_permissions(&natwg, fs::Permissions::from_mode(0o755)).unwrap();
    let status = Command::new("/bin/chmod")
        .args([
            "+a",
            "everyone allow list,search,read,file_inherit,directory_inherit",
        ])
        .arg(&natwg)
        .status()
        .unwrap();
    assert!(status.success());
    let config: Config = serde_json::from_value(serde_json::json!({
        "version": 1,
        "private_key": natwg::keys::Key::generate().unwrap().to_base64(),
        "interface": { "address": "10.66.67.2/32" },
        "peers": [{
            "name": "server",
            "public_key": natwg::keys::Key::generate().unwrap().public_key(),
            "allowed_ips": ["10.66.67.0/24"]
        }],
        "role": { "client": { "record": "_wg.example.com", "resolvers": ["223.5.5.5"] } }
    }))
    .unwrap();
    let inherited = natwg.join("inherited.json");
    config.save(&inherited).unwrap();
    assert_eq!(
        Config::load(&inherited).unwrap_err().code,
        "CONFIG_UNSAFE",
        "a config written into the open directory inherits its ACL"
    );

    make_private_dir(&natwg).unwrap();
    assert_eq!(mode(&natwg), 0o700);
    let fresh = natwg.join("config.json");
    config.save(&fresh).unwrap();
    assert_eq!(Config::load(&fresh).unwrap(), config);
}

#[test]
fn service_commands_that_change_the_host_need_root() {
    if is_root() {
        return;
    }
    for action in [
        &["install"][..],
        &["uninstall"],
        &["uninstall", "--instance", "natwg_gone"],
        &["uninstall", "--instance", "client"],
        &["restart"],
    ] {
        let output = natwg_service(action);
        assert!(!output.status.success(), "{action:?}");
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(stderr.starts_with("NOT_ROOT: "), "{action:?}: {stderr}");
    }
}

fn natwg_service(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_natwg"))
        .args(["--config", "/nonexistent/config.json", "service"])
        .args(args)
        .env_remove("NATWG_CONFIG")
        .output()
        .unwrap()
}

#[test]
fn uninstall_by_instance_takes_a_valid_name_and_never_purges() {
    let output = natwg_service(&["uninstall", "--instance", "Natwg-1"]);
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("expected an instance name"), "{stderr}");
    let output = natwg_service(&["uninstall", "--instance", "natwg_gone", "--purge"]);
    assert_eq!(output.status.code(), Some(2), "--purge needs the config");
}

fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

/// A server config for the instance `natwg_odd` at `path`, private to its
/// owner.
fn write_server_config(path: &Path) {
    let config = serde_json::json!({
        "version": 1,
        "private_key": natwg::keys::Key::generate().unwrap().to_base64(),
        "interface": { "address": "10.66.79.1/24" },
        "peers": [],
        "role": { "server": {
            "instance": "natwg_odd",
            "iface": "lo",
            "listen_port": 51899,
            "lan": "10.24.0.0/24",
            "stun": { "servers": [], "fallback": [], "dns_server": "127.0.0.1" },
            "cloudflare": { "zone": "example.com", "record": "_wg.example.com", "token": "t" }
        }}
    });
    fs::write(path, config.to_string()).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

/// Needs root, so it runs only where the tests run as root, as in the
/// Linux VM.
#[test]
fn an_install_that_cannot_write_its_definition_changes_nothing() {
    if !is_root() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let odd = dir.path().join("a\nb");
    fs::create_dir(&odd).unwrap();
    let config = odd.join("config.json");
    write_server_config(&config);
    let binary = fs::read(BINARY).ok();
    let output = Command::new(env!("CARGO_BIN_EXE_natwg"))
        .arg("--config")
        .arg(&config)
        .args(["service", "install"])
        .env_remove("NATWG_CONFIG")
        .output()
        .unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.starts_with("SERVICE_PATH: "), "{stderr}");
    assert_eq!(fs::read(BINARY).ok(), binary, "{BINARY} changed");
    let odd_instance = instance("natwg_odd");
    for definition in [
        launchd::definition_path(&odd_instance),
        systemd::definition_path(&odd_instance),
    ] {
        assert!(!definition.exists(), "{} exists", definition.display());
    }
}

#[test]
fn install_takes_only_directories_that_root_owns_and_nobody_else_can_write() {
    service::require_root_only(Path::new("/usr/bin")).unwrap();
    service::require_root_only(Path::new("/usr/bin/natwg-missing/libexec")).unwrap();
    let error = service::require_root_only(Path::new("/tmp/natwg-missing")).unwrap_err();
    assert_eq!(error.code, "SERVICE_PATH_UNSAFE");
    assert!(error.message.starts_with("/tmp: "), "{}", error.message);
    if !is_root() {
        let mine = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
        let error = service::require_root_only(mine.path()).unwrap_err();
        assert_eq!(error.code, "SERVICE_PATH_UNSAFE");
    }
}

/// Needs root, so it runs only where the tests run as root, as in the
/// Linux VM.
#[test]
fn a_symlink_in_the_chain_is_followed_to_where_it_points() {
    if !is_root() {
        return;
    }
    let target = tempfile::tempdir().unwrap();
    let real = target.path().join("real");
    fs::create_dir(&real).unwrap();
    fs::set_permissions(&real, fs::Permissions::from_mode(0o755)).unwrap();
    let link = Path::new("/usr/local/natwg-chain-test");
    let _ = fs::remove_file(link);
    std::os::unix::fs::symlink(&real, link).unwrap();
    let checked = service::require_root_only(&link.join("libexec"));
    fs::remove_file(link).unwrap();
    assert_eq!(checked.unwrap_err().code, "SERVICE_PATH_UNSAFE");
}
