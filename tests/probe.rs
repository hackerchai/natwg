//! Tests that spawn natwg live apart from tests/wire.rs. A child holds copies of
//! the test process's sockets from fork until exec, which fails a parallel
//! same-port rebind with EADDRINUSE.

use std::{
    net::{SocketAddrV4, UdpSocket},
    process::{Command, Output},
    time::Duration,
};

#[cfg(target_os = "macos")]
const LOOPBACK: &str = "lo0";
#[cfg(target_os = "linux")]
const LOOPBACK: &str = "lo";

fn natwg_probe(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_natwg"))
        .arg("probe")
        .args(args)
        .output()
        .unwrap()
}

fn answer(id: &[u8], mapped: SocketAddrV4) -> Vec<u8> {
    let mut message = vec![0x01, 0x01, 0x00, 0x0C, 0x21, 0x12, 0xA4, 0x42];
    message.extend(id);
    message.extend([0x00, 0x01, 0x00, 0x08, 0x00, 0x01]);
    message.extend(mapped.port().to_be_bytes());
    message.extend(mapped.ip().octets());
    message
}

#[test]
fn probe_stun_falls_back_when_dns_fails_and_prints_the_mapping() {
    let server = UdpSocket::bind("127.0.0.1:0").unwrap();
    server
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let fallback = server.local_addr().unwrap().to_string();
    let serve = std::thread::spawn(move || {
        let mut request = [0; 64];
        let (_, client) = server.recv_from(&mut request).unwrap();
        let mapped = "203.0.113.9:7007".parse().unwrap();
        server
            .send_to(&answer(&request[8..20], mapped), client)
            .unwrap();
    });
    let output = natwg_probe(&[
        "stun",
        "--iface",
        LOOPBACK,
        "--dns",
        "127.0.0.1",
        "--timeout-ms",
        "1000",
        "--server",
        "natwg.invalid:3478",
        "--fallback",
        &fallback,
    ]);
    serve.join().unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stderr}");
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        format!("203.0.113.9:7007 via {fallback}\n")
    );
    assert!(stderr.contains("natwg.invalid"), "{stderr}");
}

#[test]
fn probe_stun_on_a_missing_interface_exits_with_iface_not_found() {
    let output = natwg_probe(&[
        "stun",
        "--iface",
        "natwg-none0",
        "--fallback",
        "192.0.2.1:3478",
    ]);
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stderr.starts_with(b"IFACE_NOT_FOUND"));
}
