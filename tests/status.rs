use natwg::status::{PeerStatus, Status};
use serde_json::json;
use std::{
    os::unix::fs::PermissionsExt,
    process::{Command, Output},
    time::SystemTime,
};

fn fixture(updated: u64) -> Status {
    Status {
        updated,
        iface: "en6".into(),
        listen_port: 51831,
        tun: Some("utun12".into()),
        mapping: Some("203.0.113.7:52830".parse().unwrap()),
        mapping_since: Some(updated - 300),
        last_stun_ok: Some(updated - 5),
        stun_misses: 0,
        published: Some("203.0.113.7:52830".parse().unwrap()),
        published_at: Some(updated - 290),
        publish_error: None,
        upnp_ok: Some(true),
        upnp_at: Some(updated - 100),
        nat_ok: Some(true),
        rebuilds: 1,
        peers: vec![PeerStatus {
            key: "paDfvm0HLq…".into(),
            endpoint: Some("10.73.0.9:51820".parse().unwrap()),
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
        "iface": "en6",
        "listen_port": 51831,
        "tun": "utun12",
        "mapping": "203.0.113.7:52830",
        "mapping_since": 999_700,
        "last_stun_ok": 999_995,
        "stun_misses": 0,
        "published": "203.0.113.7:52830",
        "published_at": 999_710,
        "publish_error": null,
        "upnp_ok": true,
        "upnp_at": 999_900,
        "nat_ok": true,
        "rebuilds": 1,
        "peers": [{
            "key": "paDfvm0HLq…",
            "endpoint": "10.73.0.9:51820",
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
public endpoint : 203.0.113.7:52830 (since 304s ago)
published TXT   : 203.0.113.7:52830 (294s ago)
last STUN reply : 9s ago, misses=0
upnp/nat        : ok / ok
tunnel          : utun12 on en6 udp/51831, rebuilds=1
peer paDfvm0HLq… endpoint=10.73.0.9:51820 handshake=16s ago rx=1024 tx=2048
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
        "public endpoint : 203.0.113.7:52830 (since 30",
        "published TXT   : 203.0.113.7:52830 (29",
        "upnp/nat        : ok / ok",
        "peer paDfvm0HLq… endpoint=10.73.0.9:51820",
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
