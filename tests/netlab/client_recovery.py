#!/usr/bin/env python3
"""Move a WireGuard server and its authoritative TXT answer in two private namespaces.

Run as root on the disposable Linux VM with BINARY KEEPALIVE [--active].
Each invocation owns unique namespaces and can run beside another comparison.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
from contextlib import ExitStack

LAB = Path(__file__).resolve().parent
WIRE = "192.0.2.1"
NAME = "_wg.example.net"
TUNNEL = "10.77.0.1"
PORT = 51830


def run(*cmd, **kw):
    return subprocess.run(cmd, text=True, check=True, capture_output=True, **kw).stdout.strip()


def experiment(args, work, cleanup):
    client, server = (f"p5-{os.getpid()}-{side}" for side in ("c", "s"))

    def ns(namespace, *cmd):
        return ["ip", "netns", "exec", namespace, *cmd]

    def start(*cmd, log, env=None):
        output = cleanup.enter_context(open(work / log, "w"))
        child = subprocess.Popen(cmd, stdout=output, stderr=subprocess.STDOUT, env=env)

        def stop():
            child.terminate()
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()

        cleanup.callback(stop)
        return child

    for namespace in (client, server):
        run("ip", "netns", "add", namespace)
        cleanup.callback(run, "ip", "netns", "del", namespace)
        run(*ns(namespace, "ip", "link", "set", "lo", "up"))
    run("ip", "link", "add", "eth0", "netns", client, "type", "veth", "peer",
        "name", "eth0", "netns", server)
    for namespace, addr in ((server, WIRE), (client, "192.0.2.2")):
        run(*ns(namespace, "ip", "addr", "add", addr + "/24", "dev", "eth0"))
        run(*ns(namespace, "ip", "link", "set", "eth0", "up"))
    run(*ns(client, "ip", "route", "add", "default", "via", WIRE))

    # During a baseline rebuild the physical default route still exists.
    # Count only encrypted echoes, including when the TUN briefly disappears.
    run(*ns(server, "nft", "-f", "-"), input=f"""table ip recovery {{
        chain input {{ type filter hook input priority 0; iifname "eth0" ip daddr {TUNNEL} drop; }}
    }}""")

    server_key = work / "key"
    server_key.write_text(run("wg", "genkey") + "\n")
    client_key = run("wg", "genkey")
    client_pub = run("wg", "pubkey", input=client_key)
    server_pub = run("wg", "pubkey", input=server_key.read_text())

    def listen(port):
        run(*ns(server, "ip", "link", "add", "wg0", "type", "wireguard"))
        run(*ns(server, "wg", "set", "wg0", "private-key", str(server_key), "listen-port",
                str(port), "peer", client_pub, "allowed-ips", "10.77.0.2/32"))
        run(*ns(server, "ip", "addr", "add", TUNNEL + "/24", "dev", "wg0"))
        run(*ns(server, "ip", "link", "set", "wg0", "up"))

    listen(PORT)
    dnslog = work / "dns.log"
    start(*ns(server, "python3", str(LAB / "cloudflare.py"), "--api", WIRE + ":80",
              "--dns", WIRE + ":53", "--zone", "example.net", "--token", "lab", "--log",
              str(dnslog), "--record", f"{NAME}=TXT:{WIRE}:{PORT}"), log="dns.out")
    for _ in range(100):
        if subprocess.run(ns(server, "curl", "-s", "-o", "/dev/null", "http://" + WIRE),
                          capture_output=True).returncode == 0:
            break
        time.sleep(.05)
    status = work / "status.json"
    role = {"record": NAME, "resolvers": [WIRE], "status_file": str(status)}
    if args.routes:
        del role["record"]
    if args.pause:
        role["idle_pause_minutes"] = 1
    config = {"version": 1, "private_key": client_key, "interface": {"address": "10.77.0.2/32"},
              "peers": [{"name": "server", "public_key": server_pub, "keepalive": args.keepalive,
                         "allowed_ips": ["10.77.0.0/24"]}], "role": {"client": role},
              "update": {"check": "off"}}
    if args.routes:
        config["peers"][0]["endpoint"] = f"{WIRE}:{PORT}"
    profile = work / "client.json"
    profile.write_text(json.dumps(config))
    # natwg uses a fixed system PATH. Interpose ip only inside the daemon's
    # private mount namespace, forwarding every command to an identical copy.
    real_ip = Path(shutil.which("ip")).resolve()
    shutil.copy2(real_ip, work / "real-ip")
    ip = work / "ip"
    ip.write_text(f'#!/bin/sh\nif [ "$*" = "-4 route show default" ]; then echo poll >> "{work}/polls"; fi\n'
                  f'exec "{work}/real-ip" "$@"\n')
    ip.chmod(0o700)
    daemon = start(*ns(client, "unshare", "--mount", "--propagation", "private", "sh", "-ec",
                       'mount --bind "$1" "$2"; shift 2; exec "$@"', "lab", str(ip), str(real_ip),
                       args.binary, "--config", str(profile), "client", "--foreground"), log="client.log")

    def ping():
        return subprocess.run(ns(client, "ping", "-I", "natwg-client", "-n", "-q", "-c1", "-W1", TUNNEL),
                              capture_output=True).returncode == 0

    def handshake():
        return int(run(*ns(server, "wg", "show", "wg0", "latest-handshakes")).split()[-1])

    start_time = time.monotonic()
    while not (daemon.poll() is None and status.exists() and ping() and handshake()):
        if time.monotonic() - start_time > 15 or daemon.poll() is not None:
            raise RuntimeError((work / "client.log").read_text())
        time.sleep(.1)
    origin = time.monotonic()
    if args.routes:
        def wait_for(**fields):
            deadline = time.monotonic() + 8
            while time.monotonic() < deadline:
                state = json.loads(status.read_text())
                if all(state.get(k) == v for k, v in fields.items()):
                    return
                time.sleep(.05)
            raise RuntimeError((work / "client.log").read_text())

        for _ in range(5):
            for action in ("add", "del"):
                run(*ns(client, "ip", "route", action, "198.18.0.0/24", "dev", "eth0"))
        time.sleep(1)
        wait_for(uplink="eth0", rebuilds=0)
        run("ip", "link", "add", "eth1", "netns", client, "type", "veth", "peer",
            "name", "eth1", "netns", server)
        for namespace, addr in ((server, "198.51.100.1"), (client, "198.51.100.2")):
            run(*ns(namespace, "ip", "addr", "add", addr + "/24", "dev", "eth1"))
            run(*ns(namespace, "ip", "link", "set", "eth1", "up"))
        switched = time.monotonic()
        run(*ns(client, "ip", "route", "replace", "default", "via", "198.51.100.1"))
        wait_for(uplink="eth1", rebuilds=1)
        switch_time = time.monotonic() - switched
        assert ping()
        run(*ns(client, "sysctl", "-qw", "net.ipv4.conf.eth1.promote_secondaries=1"))
        run(*ns(client, "ip", "addr", "add", "198.51.100.3/24", "dev", "eth1"))
        run(*ns(client, "ip", "addr", "del", "198.51.100.2/24", "dev", "eth1"))
        wait_for(uplink_address="198.51.100.3", rebuilds=1)
        assert ping()
        assert not dnslog.exists() or "DNS " not in dnslog.read_text()
        return {"default_route_switch_s": round(switch_time, 2), "rebuilds": 1,
                "duplicate_route_changes": 10, "static_dns_queries": 0,
                "new_address_echo": True}
    # Both variants get the same endpoint age and polling phase. At 187 s an
    # idle client may have exhausted its 180 s session. At 7 s it is fresh.
    delay = args.move_after if args.move_after is not None else (7 if args.active else 187)
    if args.active:
        start(*ns(client, "ping", "-I", "natwg-client", "-n", "-i", "1", TUNNEL), log="active.log")
    last_mtime = status.stat().st_mtime_ns
    writes = 0
    idle_start = None
    capture = None

    def counts():
        return (len((work / "polls").read_text().splitlines()),
                sum(line.startswith("DNS TXT") for line in dnslog.read_text().splitlines()))

    while time.monotonic() - origin < delay:
        now = time.monotonic() - origin
        if not args.active and now >= 100 and capture is None:
            # Sample only already-generated client WireGuard datagrams after
            # a one-minute pause policy has had time to settle.
            capture = start(*ns(client, "tcpdump", "-p", "-n", "-l", "-i", "eth0",
                                f"src host 192.0.2.2 and udp dst port {PORT}"), log="wire.log")
        mtime = status.stat().st_mtime_ns
        if not args.active and now >= 15 and idle_start is None:
            idle_start = counts()
        elif idle_start and last_mtime != mtime:
            writes += 1
        last_mtime = mtime
        time.sleep(.05)
    report = {"keepalive": args.keepalive, "move_after_s": delay, "active": args.active}
    if capture:
        capture.terminate()
        capture.wait(timeout=5)
        wire = (work / "wire.log").read_text().splitlines()
        assert any("listening on" in line for line in wire)
        report.update(wire_window_s=delay-100,
                      empty_transport_packets=sum(line.endswith("UDP, length 32") for line in wire),
                      initiations=sum(line.endswith("UDP, length 148") for line in wire))
    if idle_start:
        polls, lookups = (n - old for n, old in zip(counts(), idle_start))
        report.update(idle_window_s=delay-15, route_commands=polls, txt_queries=lookups,
                      status_replacements=writes, effective_keepalive=json.loads(status.read_text())["keepalive"])
    # Discard the server session as well as the old listener. A successful
    # echo on the new port now requires a new authenticated handshake.
    moved = time.monotonic()
    run(*ns(server, "ip", "link", "del", "wg0"))
    listen(PORT + 1)
    run(*ns(server, "curl", "--fail", "-sS", "-X", "PUT", "-H", "Authorization: Bearer lab",
            "-d", json.dumps({"name": NAME, "type": "TXT", "content": f"{WIRE}:{PORT+1}", "ttl": 60}),
            f"http://{WIRE}/client/v4/zones/zone1/dns_records/rec1"))
    if not args.active:
        time.sleep(max(0, moved + 5 - time.monotonic()))
    first = time.monotonic()
    while not ping():
        if time.monotonic() - first > 100:
            raise RuntimeError("no echo after move\n" + (work / "client.log").read_text())
        time.sleep(.15)
    echoed = time.monotonic()
    assert handshake() > 0, "fresh server has no authenticated session"
    assert f"DNS TXT {NAME} {WIRE}:{PORT+1}" in dnslog.read_text()
    report.update(move_to_echo_s=round(echoed-moved, 2), demand_to_echo_s=round(echoed-first, 2),
                  new_server_handshake=handshake())
    if args.pause:
        deadline = time.monotonic() + 15
        while json.loads(status.read_text())["keepalive"] != args.keepalive:
            if time.monotonic() >= deadline:
                raise RuntimeError("keepalive did not resume")
            time.sleep(.1)
        assert report["effective_keepalive"] == 0, report
        # An initial data packet can still arm WireGuard's normal session
        # rekey. Its key confirmation is also an empty transport packet.
        assert report["empty_transport_packets"] <= report["initiations"] + 1, report
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=lambda p: str(Path(p).resolve(strict=True)))
    parser.add_argument("keepalive", type=int)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--active", action="store_true")
    parser.add_argument("--move-after", type=int, metavar="SECONDS",
                        help="change the move phase relative to the initial working echo")
    mode.add_argument("--routes", action="store_true", help="test physical route and address changes with a fixed endpoint")
    mode.add_argument("--pause", action="store_true")
    args = parser.parse_args()
    if args.move_after is not None and args.move_after <= 0:
        parser.error("--move-after must be positive")
    if args.pause and (args.keepalive <= 0 or (args.move_after or 187) < 180):
        parser.error("--pause needs an enabled keepalive and at least 180 seconds to measure idle traffic")
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix="natwg-recovery-") as directory, ExitStack() as cleanup:
        print(json.dumps(experiment(args, Path(directory), cleanup), sort_keys=True), flush=True)
