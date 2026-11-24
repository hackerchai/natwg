use natwg::status::{ClientRole, ClientStatus, PeerStatus, Report, Status};
use serde_json::json;
use std::{
    os::unix::fs::PermissionsExt,
    process::{Command, Output},
    time::SystemTime,
};

fn fixture(updated: u64) -> Status {
    Status {
        updated,
        pid: 4242,
        iface: "en6".into(),
        listen_port: 51831,
        tun: Some("utun12".into()),
        mapping: Some("183.192.36.226:7105".parse().unwrap()),
        mapping_since: Some(updated - 300),
        last_stun_ok: Some(updated - 5),
        stun_misses: 0,
        published: Some("183.192.36.226:7105".parse().unwrap()),
        published_at: Some(updated - 290),
        publish_error: None,
        upnp_ok: Some(true),
        upnp_at: Some(updated - 100),
        nat_ok: Some(true),
        rebuilds: 1,
        peers: vec![PeerStatus {
            key: "paDfvm0HLq…".into(),
            endpoint: Some("10.24.0.9:51820".parse().unwrap()),
            last_handshake: Some(updated - 12),
            rx: 1024,
            tx: 2048,
        }],
    }
}

#[test]
fn the_status_file_has_the_documented_fields() {
    let status = fixture(1_000_000);
    let expected = json!({
        "updated": 1_000_000,
        "pid": 4242,
        "iface": "en6",
        "listen_port": 51831,
        "tun": "utun12",
        "mapping": "183.192.36.226:7105",
        "mapping_since": 999_700,
        "last_stun_ok": 999_995,
        "stun_misses": 0,
        "published": "183.192.36.226:7105",
        "published_at": 999_710,
        "publish_error": null,
        "upnp_ok": true,
        "upnp_at": 999_900,
        "nat_ok": true,
        "rebuilds": 1,
        "peers": [{
            "key": "paDfvm0HLq…",
            "endpoint": "10.24.0.9:51820",
            "last_handshake": 999_988,
            "rx": 1024,
            "tx": 2048,
        }],
    });
    assert_eq!(serde_json::to_value(&status).unwrap(), expected);
}

#[test]
fn a_written_status_reads_back_and_everyone_can_read_it() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("natwg").join("status.json");
    let status = fixture(1_000_000);
    status.write(&path).unwrap();
    let mode = std::fs::metadata(&path).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o644);
    assert_eq!(Status::read(&path).unwrap(), status);

    let mut changed = status.clone();
    changed.stun_misses = 3;
    changed.write(&path).unwrap();
    assert_eq!(Status::read(&path).unwrap(), changed);
}

#[test]
fn the_human_view_shows_each_part_with_its_age() {
    let now = 1_000_004;
    let text = fixture(1_000_000).render(now);
    let expected = "\
public endpoint : 183.192.36.226:7105 (since 304s ago)
published TXT   : 183.192.36.226:7105 (294s ago)
last STUN reply : 9s ago, misses=0
upnp/nat        : ok / ok
tunnel          : utun12 on en6 udp/51831, rebuilds=1
peer paDfvm0HLq… endpoint=10.24.0.9:51820 handshake=16s ago rx=1024 tx=2048
status written  : 4s ago
";
    assert_eq!(text, expected);
}

#[test]
fn the_human_view_names_what_is_missing_and_the_publish_error() {
    let mut status = fixture(1_000_000);
    status.tun = None;
    status.mapping = None;
    status.mapping_since = None;
    status.published = None;
    status.published_at = None;
    status.publish_error = Some("CLOUDFLARE_API: Authentication error".into());
    status.upnp_ok = None;
    status.nat_ok = Some(false);
    status.peers[0].last_handshake = None;
    let text = status.render(1_000_000);
    for line in [
        "public endpoint : none (since never)",
        "published TXT   : none (never)  ERROR: CLOUDFLARE_API: Authentication error",
        "upnp/nat        : off / failed",
        "tunnel          : none on en6 udp/51831, rebuilds=1",
        "handshake=never",
    ] {
        assert!(text.contains(line), "{line:?} is missing from\n{text}");
    }
}

fn natwg_status(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_natwg"))
        .arg("status")
        .args(args)
        .output()
        .unwrap()
}

fn now() -> u64 {
    natwg::status::unix(SystemTime::now())
}

#[test]
fn natwg_status_prints_the_status_file_for_people() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("status.json");
    fixture(now()).write(&path).unwrap();
    let output = natwg_status(&["--status-file", path.to_str().unwrap()]);
    assert!(output.status.success(), "{output:?}");
    let text = String::from_utf8(output.stdout).unwrap();
    for line in [
        "public endpoint : 183.192.36.226:7105 (since 30",
        "published TXT   : 183.192.36.226:7105 (29",
        "upnp/nat        : ok / ok",
        "peer paDfvm0HLq… endpoint=10.24.0.9:51820",
        "status written  : ",
    ] {
        assert!(text.contains(line), "{line:?} is missing from\n{text}");
    }
}

#[test]
fn natwg_status_json_prints_the_status_file_as_json() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("status.json");
    let status = fixture(now());
    status.write(&path).unwrap();
    let output = natwg_status(&["--json", "--status-file", path.to_str().unwrap()]);
    assert!(output.status.success(), "{output:?}");
    let printed: Status = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(printed, status);
}

#[test]
fn natwg_status_without_a_status_file_exits_1_and_names_the_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("missing.json");
    let output = natwg_status(&["--status-file", path.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(1));
    let error = String::from_utf8(output.stderr).unwrap();
    assert!(error.starts_with("STATUS_UNREADABLE: "), "{error}");
    assert!(error.contains("missing.json"), "{error}");
}

fn server(instance: &str, status_file: Option<&str>) -> natwg::config::ServerConfig {
    serde_json::from_value(json!({
        "instance": instance,
        "iface": "en6",
        "listen_port": 51831,
        "lan": "10.24.0.0/24",
        "stun": {"servers": [], "fallback": [], "dns_server": "223.5.5.5"},
        "cloudflare": {"zone": "example.com", "record": "_wg.example.com", "token": "t"},
        "status_file": status_file,
    }))
    .unwrap()
}

#[test]
fn each_instance_has_its_own_default_status_file() {
    let default = std::path::Path::new(natwg::status::DEFAULT_PATH);
    assert_eq!(natwg::status::path(&server("natwg", None)), default);
    assert_eq!(
        natwg::status::path(&server("natwg_fix5", None)),
        default.with_file_name("natwg_fix5.status.json")
    );
    assert_eq!(
        natwg::status::path(&server("natwg_fix5", Some("/srv/natwg/status.json"))),
        std::path::Path::new("/srv/natwg/status.json"),
        "a status_file in the config wins"
    );
}

type Change = fn(&mut Status);

#[test]
fn natwg_status_exits_1_and_names_each_problem_it_shows() {
    let cases: [(&str, Change); 6] = [
        ("the status is ", |status| status.updated -= 120),
        ("no tunnel runs", |status| {
            status.tun = None;
            status.nat_ok = None;
        }),
        ("NAT is not ok", |status| status.nat_ok = Some(false)),
        ("no public mapping", |status| status.mapping = None),
        ("the TXT publish failed", |status| {
            status.publish_error = Some("CLOUDFLARE_HTTP: connection refused".into());
        }),
        ("UPnP failed", |status| status.upnp_ok = Some(false)),
    ];
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("status.json");
    for (problem, change) in cases {
        let mut status = fixture(now());
        change(&mut status);
        status.write(&path).unwrap();
        for format in [&[][..], &["--json"]] {
            let mut args = format.to_vec();
            args.extend(["--status-file", path.to_str().unwrap()]);
            let output = natwg_status(&args);
            assert_eq!(output.status.code(), Some(1), "{problem}: {output:?}");
            assert!(
                !output.stdout.is_empty(),
                "{problem}: the status still prints"
            );
            let stderr = String::from_utf8(output.stderr).unwrap();
            let expected = format!("SERVER_UNHEALTHY: {problem}");
            assert!(stderr.starts_with(&expected), "{problem}: {stderr}");
        }
    }
}

#[test]
fn natwg_status_exits_0_when_upnp_is_off() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("status.json");
    let mut status = fixture(now());
    status.upnp_ok = None;
    status.upnp_at = None;
    status.write(&path).unwrap();
    let output = natwg_status(&["--status-file", path.to_str().unwrap()]);
    assert!(output.status.success(), "{output:?}");
}

fn client_fixture(updated: u64) -> ClientStatus {
    ClientStatus {
        role: ClientRole::Client,
        updated,
        pid: 4343,
        uplink: Some("en0".into()),
        uplink_address: Some("10.16.0.105".parse().unwrap()),
        tun: Some("utun13".into()),
        record: Some("_wg-home.example.com".into()),
        endpoint: Some("183.192.36.226:7105".parse().unwrap()),
        endpoint_since: Some(updated - 300),
        looked_up: Some(updated - 20),
        lookup_error: None,
        keepalive: 25,
        rebuilds: 0,
        server: Some(PeerStatus {
            key: "paDfvm0HLq…".into(),
            endpoint: Some("183.192.36.226:7105".parse().unwrap()),
            last_handshake: Some(updated - 40),
            rx: 4096,
            tx: 8192,
        }),
    }
}

#[test]
fn the_client_status_file_is_tagged_with_its_role() {
    let status = client_fixture(1_000_000);
    let value = serde_json::to_value(&status).unwrap();
    assert_eq!(value["role"], "client");
    assert_eq!(value["endpoint"], "183.192.36.226:7105");
    assert_eq!(value["server"]["last_handshake"], 1_000_000 - 40);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("client.status.json");
    status.write(&path).unwrap();
    assert_eq!(Report::read(&path).unwrap(), Report::Client(status));
    let server = fixture(1_000_000);
    server.write(&path).unwrap();
    assert_eq!(Report::read(&path).unwrap(), Report::Server(server));
}

#[test]
fn the_client_human_view_shows_the_endpoint_handshake_and_traffic() {
    let now = 1_000_000;
    let text = client_fixture(now).render(now + 3);
    for line in [
        "server endpoint : 183.192.36.226:7105 from TXT _wg-home.example.com (since 303s ago)",
        "TXT lookup      : 23s ago",
        "handshake       : 43s ago, peer paDfvm0HLq… endpoint=183.192.36.226:7105 rx=4096 tx=8192, keepalive 25s",
        "tunnel          : utun13 via en0 (10.16.0.105), rebuilds=0",
        "status written  : 3s ago",
    ] {
        assert!(text.contains(line), "{line:?} is missing from\n{text}");
    }
    let mut status = client_fixture(now);
    status.record = None;
    status.lookup_error = Some("TXT_NO_ENDPOINT: nothing".into());
    let text = status.render(now);
    assert!(text.contains("from config"), "{text}");
    assert!(text.contains("TXT lookup      : off"), "{text}");
}

#[test]
fn the_client_status_file_sits_beside_the_server_one() {
    let client: natwg::config::ClientConfig = serde_json::from_value(json!({})).unwrap();
    let default = std::path::Path::new(natwg::status::DEFAULT_PATH);
    assert_eq!(
        natwg::status::client_path(&client),
        default.with_file_name("client.status.json")
    );
    let client: natwg::config::ClientConfig =
        serde_json::from_value(json!({ "status_file": "/tmp/natwg-lane-a/status.json" })).unwrap();
    assert_eq!(
        natwg::status::client_path(&client),
        std::path::Path::new("/tmp/natwg-lane-a/status.json")
    );
}

type ClientChange = fn(&mut ClientStatus);

#[test]
fn natwg_status_of_a_client_exits_1_and_names_each_problem() {
    let cases: [(&str, ClientChange); 6] = [
        ("the status is ", |status| status.updated -= 120),
        ("no tunnel runs", |status| status.tun = None),
        ("no server endpoint", |status| status.endpoint = None),
        ("the TXT lookup failed", |status| {
            status.lookup_error = Some("TXT_NO_ENDPOINT: 223.5.5.5 timed out".into());
        }),
        ("no handshake yet", |status| {
            status.server.as_mut().unwrap().last_handshake = None;
        }),
        ("the last handshake is 240s old", |status| {
            status.server.as_mut().unwrap().last_handshake = Some(status.updated - 240);
        }),
    ];
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("client.status.json");
    for (problem, change) in cases {
        let mut status = client_fixture(now());
        change(&mut status);
        status.write(&path).unwrap();
        let output = natwg_status(&["--status-file", path.to_str().unwrap()]);
        assert_eq!(output.status.code(), Some(1), "{problem}: {output:?}");
        assert!(
            !output.stdout.is_empty(),
            "{problem}: the status still prints"
        );
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(
            stderr.starts_with(&format!("CLIENT_UNHEALTHY: {problem}")),
            "{problem}: {stderr}"
        );
    }
}

#[test]
fn natwg_status_of_a_healthy_client_exits_0_and_prints_json_as_written() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("client.status.json");
    let status = client_fixture(now());
    status.write(&path).unwrap();
    let output = natwg_status(&["--status-file", path.to_str().unwrap()]);
    assert!(output.status.success(), "{output:?}");
    let output = natwg_status(&["--json", "--status-file", path.to_str().unwrap()]);
    assert!(output.status.success(), "{output:?}");
    let printed: ClientStatus = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(printed, status);

    // A session that only keepalives use expires after 180 s, and the next
    // keepalive, up to 25 s later, renews it.
    let mut renewing = client_fixture(now());
    renewing.server.as_mut().unwrap().last_handshake = Some(renewing.updated - 205);
    renewing.write(&path).unwrap();
    let output = natwg_status(&["--status-file", path.to_str().unwrap()]);
    assert!(output.status.success(), "{output:?}");

    let mut idle = client_fixture(now());
    idle.keepalive = 0;
    idle.server.as_mut().unwrap().last_handshake = Some(idle.updated - 900);
    idle.write(&path).unwrap();
    let output = natwg_status(&["--status-file", path.to_str().unwrap()]);
    assert!(
        output.status.success(),
        "without a keepalive an old handshake is no problem: {output:?}"
    );
}
