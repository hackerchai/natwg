#!/usr/bin/env python3
"""Move a WireGuard server and its authoritative TXT answer in two private namespaces.

Run as root on the disposable Linux VM with BINARY KEEPALIVE and a scenario flag.
Each invocation owns unique namespaces and can run beside another comparison.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import time
from contextlib import ExitStack
from dataclasses import dataclass

LAB = Path(__file__).resolve().parent
WIRE = "192.0.2.1"
NAME = "_wg.example.net"
TUNNEL = "10.77.0.1"
PORT = 51830
LAN = "10.88.0.2"


def run(*cmd, **kw):
    return subprocess.run(cmd, text=True, check=True, capture_output=True, **kw).stdout.strip()


def ns(namespace, *cmd):
    return ["ip", "netns", "exec", namespace, *cmd]

@dataclass
class ClientLab:
    binary: str
    client: str
    server: str
    work: Path
    daemon: subprocess.Popen
    dns: subprocess.Popen

    @property
    def status(self):
        return self.work / "status.json"

    def packets(self, counter):
        result = json.loads(run(*ns(self.server, "nft", "-j", "list", "counter", "ip", "recovery", counter)))
        return next(o["counter"]["packets"] for o in result["nftables"] if "counter" in o)

    def ping(self, target=TUNNEL, timeout=1):
        return subprocess.run(ns(self.client, "ping", "-I", "natwg-client", "-n", "-q", "-c1", f"-W{timeout}", target),
                              capture_output=True).returncode == 0

    def handshake(self):
        return int(run(*ns(self.server, "wg", "show", "wg0", "latest-handshakes")).split()[-1])

    def wait(self, predicate, timeout, description):
        until = time.monotonic() + timeout
        while True:
            if self.daemon.poll() is not None:
                raise RuntimeError((self.work / "client.log").read_text())
            if self.dns.poll() is not None:
                raise RuntimeError((self.work / "dns.out").read_text())
            if predicate():
                return time.monotonic()
            if time.monotonic() > until:
                log = (self.work / "client.log").read_text() + (self.status.read_text() if self.status.exists() else "")
                raise AssertionError(f"timed out waiting for {description}\n{log}")
            time.sleep(.1)

    def txt(self):
        log = self.work / "dns.log"
        lines = log.read_text().splitlines() if log.exists() else []
        return [line for line in lines if line.startswith(f"DNS TXT {NAME} ")]

    def state(self):
        return json.loads(self.status.read_text()) if self.status.exists() else {}

    def healthy(self):
        return subprocess.run([self.binary, "status", "--status-file", str(self.status)],
                              capture_output=True).returncode == 0

    def publish(self, port, create=False):
        url = f"http://{WIRE}/client/v4/zones/zone1/dns_records"
        run(*ns(self.server, "curl", "--fail", "-sS", "-X", "POST" if create else "PUT",
                "-H", "Authorization: Bearer lab", "-d",
                json.dumps({"name": NAME, "type": "TXT", "content": f"{WIRE}:{port}", "ttl": 60}),
                url if create else url + "/rec1"))

    def delayed_first_txt(self, keepalive):
        first = self.wait(lambda: self.txt() and "NXDOMAIN" in self.txt()[0], 10, "initial NXDOMAIN")
        time.sleep(541)
        self.publish(PORT, create=True)
        answered = self.wait(lambda: f"DNS TXT {NAME} {WIRE}:{PORT}" in self.txt(), 70, "first usable TXT")
        assert answered - first > 540
        if keepalive:
            ready = self.wait(self.handshake, 10, "receive-first authenticated session")
            run(*ns(self.server, "ping", "-I", "wg0", "-n", "-c1", "-W2", "10.77.0.2"))
        else:
            time.sleep(15)
            assert self.packets("wire") == 0 and not self.handshake(), "disabled keepalive initiated traffic"
            assert self.ping(timeout=10), "the single first demand packet was lost"
            ready = self.wait(self.handshake, 2, "first demand handshake")
        return {"keepalive": keepalive, "first_usable_txt_s": round(answered-first, 2),
                "txt_to_authenticated_s": round(ready-answered, 2), "receive_first": bool(keepalive),
                "client_initiations": self.packets("init"), "dns_queries": len(self.txt())}

    def successful_retry(self):
        first = self.wait(lambda: self.packets("init") >= 1, 10, "first WireGuard initiation")
        time.sleep(2)
        run(*ns(self.server, "wg", "set", "wg0", "listen-port", str(PORT)))
        authenticated = self.wait(self.handshake, 13, "authentication on retry")
        assert self.packets("init") >= 2 and self.ping()
        self.wait(self.healthy, 12, "healthy CLI after successful retry")

        def quiet():
            queries = len(self.txt())
            time.sleep(45)
            extra = len(self.txt()) - queries
            assert extra == 0 and self.healthy() and self.ping()
            return extra

        first_extra = quiet()
        # Create an unanswered initiation, then rebind again before its retry.
        # The old binding's pending flight must never mark the new one failed.
        run(*ns(self.server, "wg", "set", "wg0", "listen-port", str(PORT + 1)))
        run(*ns(self.client, "sysctl", "-qw", "net.ipv4.conf.eth0.promote_secondaries=1"))

        def readdress(old, new):
            queries, attempts = len(self.txt()), self.packets("init")
            run(*ns(self.client, "ip", "addr", "add", new + "/24", "dev", "eth0"))
            run(*ns(self.client, "ip", "addr", "del", old + "/24", "dev", "eth0"))
            self.wait(lambda: (self.packets("init") > attempts and len(self.txt()) > queries
                               and self.state()["uplink_address"] == new), 4, "new socket initiation and TXT")
            time.sleep(.25)
            assert not self.state()["handshake_retrying"] and self.state()["rebuilds"] == 0
            assert len(self.txt()) == queries + 1, self.txt()
            return queries + 1

        readdress("192.0.2.2", "192.0.2.3")
        rebound = time.monotonic()
        queries = readdress("192.0.2.3", "192.0.2.4")
        # The new binding's genuine retry must now trigger failure-driven DNS.
        self.wait(lambda: self.state()["handshake_retrying"] and len(self.txt()) > queries, 10, "later genuine failure")
        assert not self.healthy()
        # An unrelated UDP datagram cannot confirm the local handshake.
        sockets = run(*ns(self.client, "ss", "-Hunlp")).splitlines()
        (local,) = [s.split()[3] for s in sockets if f"pid={self.daemon.pid}," in s]
        run(*ns(self.server, "python3", "-c",
                "import socket,sys; socket.socket(2,2).sendto(bytes(92), ('192.0.2.4', int(sys.argv[1])))",
                local.rsplit(":", 1)[1]))
        time.sleep(1)
        assert self.state()["handshake_retrying"] and not self.healthy()
        run(*ns(self.server, "wg", "set", "wg0", "listen-port", str(PORT)))
        self.wait(lambda: self.ping() and self.healthy(), 18, "rebound authenticated traffic and healthy CLI")
        recovered = time.monotonic()
        rebind_extra = quiet()
        return {"first_retry_authenticated_s": round(authenticated-first, 2),
                "rebind_to_recovery_s": round(recovered-rebound, 2), "healthy_quiet_s_after_each_recovery": 45,
                "txt_queries_after_first_recovery": first_extra, "txt_queries_after_rebind": rebind_extra, "rebuilds": self.state()["rebuilds"]}

    def inbound_while_paused(self, configured, peer, start):
        self.wait(lambda: self.state()["keepalive"] == 0, 82, "idle pause")
        run(*ns(self.server, "nft", "-f", "-"), input=f"""add counter ip recovery empty
add chain ip recovery out {{ type filter hook output priority 0; }}
add rule ip recovery out udp sport {PORT} udp length 40 counter name empty
""")
        run(*ns(self.server, "wg", "set", "wg0", "peer", peer, "persistent-keepalive", "1"))
        endpoint = run(*ns(self.server, "wg", "show", "wg0", "endpoints")).split()[-1]
        run(*ns(self.server, "python3", "-c",
                "import socket,sys; socket.socket(2,2).sendto(b'hello', ('192.0.2.2', int(sys.argv[1])))",
                endpoint.rsplit(":", 1)[1]))
        time.sleep(12)
        empty = self.packets("empty")
        assert empty > 0 and self.state()["keepalive"] == 0

        # Receive an application datagram without eliciting a client reply.
        listener = start(*ns(self.client, "python3", "-u", "-c",
                             "import socket; s=socket.socket(2,2); s.bind(('10.77.0.2',6060)); "
                             "print('ready'); assert s.recv(32)==b'inner'"), log="listener.log")
        self.wait(lambda: "ready" in (self.work / "listener.log").read_text(), 3, "UDP listener")
        run(*ns(self.server, "python3", "-c",
                "import socket; socket.socket(2,2).sendto(b'inner', ('10.77.0.2',6060))"))
        assert listener.wait(timeout=5) == 0
        self.wait(lambda: self.state()["keepalive"] == configured, 15, "inbound application resume")
        return {"authenticated_empty_packets": empty, "paused_keepalive": 0,
                "inbound_application_datagrams": 1, "resumed_keepalive": configured}

    def queued_after_move(self, listen, start):
        # Let the established session age past WireGuard's 180 s reject time.
        time.sleep(187)
        run(*ns(self.server, "ip", "link", "del", "wg0"))
        listen(PORT + 1)
        self.publish(PORT + 1)
        before = self.packets("wire")
        time.sleep(15)
        idle_datagrams = self.packets("wire") - before
        assert idle_datagrams == 0 and not self.handshake()
        demand = time.monotonic()
        assert self.ping(timeout=30), "the sole queued application packet did not arrive"
        assert self.handshake() and f"DNS TXT {NAME} {WIRE}:{PORT+1}" in self.txt()
        sole_echo = time.monotonic() - demand
        # Repeat with DNS answering *before* the second initiation. A socket
        # rebind drops the session and asks for TXT immediately. Hold that
        # answer until the TUN has queued exactly one packet on the old port.
        run(*ns(self.server, "ip", "link", "del", "wg0"))
        listen(PORT)
        self.publish(PORT)
        self.dns.send_signal(signal.SIGSTOP)
        try:
            run(*ns(self.client, "sysctl", "-qw", "net.ipv4.conf.eth0.promote_secondaries=1"))
            run(*ns(self.client, "ip", "addr", "add", "192.0.2.3/24", "dev", "eth0"))
            run(*ns(self.client, "ip", "addr", "del", "192.0.2.2/24", "dev", "eth0"))
            self.wait(lambda: self.state()["uplink_address"] == "192.0.2.3", 4, "rebind")
            previous = self.packets("init")
            demand = time.monotonic()
            echo = start(*ns(self.client, "ping", "-I", "natwg-client", "-n", "-c1", "-W20", TUNNEL),
                         log="sole-echo.log")
            self.wait(lambda: self.packets("init") == previous + 1, 2, "first unanswered initiation")
        finally:
            self.dns.send_signal(signal.SIGCONT)
        self.wait(lambda: self.state()["endpoint"] == f"{WIRE}:{PORT}", 4, "answer during first flight")
        assert self.packets("init") == previous + 1
        assert echo.wait(timeout=22) == 0 and self.handshake()
        return {"idle_after_move_s": 15, "idle_datagrams": idle_datagrams,
                "queued_through_retry_echo_s": round(sole_echo, 2),
                "queued_before_retry_echo_s": round(time.monotonic()-demand, 2),
                "fresh_server_handshake": self.handshake()}

    def roam_after_refresh(self, origin, listen, start):
        run(*ns(self.server, "wg", "set", "wg0", "listen-port", str(PORT + 1)))
        sender = start(*ns(self.server, "ping", "-I", "wg0", "-n", "-i", "2", "10.77.0.2"), log="roam.log")

        def live(port):
            return (self.state().get("server") or {}).get("endpoint") == f"{WIRE}:{port}"

        self.wait(lambda: live(PORT + 1) and self.healthy(), 20, "authenticated roam")
        assert self.ping() and self.ping(LAN)
        queries = len(self.txt())
        periodic = self.wait(lambda: len(self.txt()) > queries, 615, "healthy ten-minute TXT refresh")
        assert periodic - origin > 580, self.txt()
        time.sleep(12)  # allow a status sample after the answer
        assert live(PORT + 1) and self.healthy() and self.ping(LAN)
        sender.terminate()
        sender.wait(timeout=5)
        assert self.state()["endpoint"] == f"{WIRE}:{PORT}"
        old_queries = len(self.txt())
        moved = time.monotonic()
        run(*ns(self.server, "ip", "link", "del", "wg0"))
        listen(PORT)
        restored = self.wait(self.ping, 210, "echo after same-key restart at advertised endpoint")
        assert self.handshake() and self.ping(LAN)
        self.wait(lambda: live(PORT) and self.healthy(), 20, "restored healthy status")
        assert len(self.txt()) > old_queries and self.state()["rebuilds"] == 0
        return {"healthy_refresh_s": round(periodic-origin, 2), "retained_authenticated_port": PORT+1,
                "restart_to_echo_s": round(restored-moved, 2), "fresh_server_handshake": self.handshake(),
                "restored_port": PORT, "routed_lan_echo": True, "rebuilds": 0}


def experiment(args, work, cleanup):
    client, server = (f"p5-{os.getpid()}-{side}" for side in ("c", "s"))

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

    if args.roam:
        # Route a separate LAN host through the WG router. Only packets that
        # entered wg0 may reach it from the client.
        lan = f"p5-{os.getpid()}-lan"
        run("ip", "netns", "add", lan)
        cleanup.callback(run, "ip", "netns", "del", lan)
        run("ip", "link", "add", "lan0", "netns", server, "type", "veth",
            "peer", "name", "lan0", "netns", lan)
        for namespace, addr in ((server, "10.88.0.1"), (lan, LAN)):
            run(*ns(namespace, "ip", "addr", "add", addr + "/24", "dev", "lan0"))
            run(*ns(namespace, "ip", "link", "set", "lan0", "up"))
        run(*ns(lan, "ip", "route", "add", "10.77.0.0/24", "via", "10.88.0.1"))
        run(*ns(server, "sysctl", "-qw", "net.ipv4.ip_forward=1"))
        run(*ns(server, "nft", "-f", "-"), input="""add chain ip recovery forward { type filter hook forward priority 0; }
add rule ip recovery forward iifname "eth0" oifname "lan0" drop
""")

    if args.late_dns or args.retry or args.queued:
        # Count passive observations in this namespace before starting the client.
        run(*ns(server, "nft", "-f", "-"), input=f"""add counter ip recovery wire
add counter ip recovery init
add rule ip recovery input iifname "eth0" udp dport {{ {PORT}, {PORT+1} }} counter name wire
add rule ip recovery input iifname "eth0" udp dport {{ {PORT}, {PORT+1} }} udp length 156 counter name init
""")
    listen(PORT + 1 if args.retry else PORT)
    # The legacy e2e harness stops services by the shared script path.
    # Give this invocation its own DNS process identity and lifetime.
    dns_script = work / "dns-server.py"
    shutil.copyfile(LAB / "cloudflare.py", dns_script)
    dnslog = work / "dns.log"
    records = [] if args.late_dns else ["--record", f"{NAME}=TXT:{WIRE}:{PORT}"]
    dns = start(*ns(server, "python3", str(dns_script), "--api", WIRE + ":80",
                    "--dns", WIRE + ":53", "--zone", "example.net", "--token", "lab",
                    "--log", str(dnslog), *records), log="dns.out")
    for _ in range(100):
        if subprocess.run(ns(server, "curl", "-s", "-o", "/dev/null", "http://" + WIRE),
                          capture_output=True).returncode == 0:
            break
        time.sleep(.05)
    status = work / "status.json"
    role = {"record": NAME, "resolvers": [WIRE], "status_file": str(status)}
    if args.routes:
        del role["record"]
    if args.pause or args.pause_inbound:
        role["idle_pause_minutes"] = 1
    config = {"version": 1, "private_key": client_key, "interface": {"address": "10.77.0.2/32"},
              "peers": [{"name": "server", "public_key": server_pub, "keepalive": args.keepalive,
                         "allowed_ips": ["10.77.0.0/24"]}], "role": {"client": role},
              "update": {"check": "off"}}
    if args.routes:
        config["peers"][0]["endpoint"] = f"{WIRE}:{PORT}"
    if args.roam:
        config["peers"][0]["allowed_ips"].append("10.88.0.0/24")
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

    lab = ClientLab(args.binary, client, server, work, daemon, dns)
    if args.late_dns:
        return lab.delayed_first_txt(args.keepalive)
    if args.retry:
        return lab.successful_retry()
    ping, handshake = lab.ping, lab.handshake
    origin = lab.wait(lambda: status.exists() and ping() and handshake(), 15, "initial tunnel echo")
    if args.pause_inbound:
        return lab.inbound_while_paused(args.keepalive, client_pub, start)
    if args.queued:
        return lab.queued_after_move(listen, start)
    if args.roam:
        return lab.roam_after_refresh(origin, listen, start)
    if args.routes:
        def wait_for(**fields):
            lab.wait(lambda: all(lab.state().get(k) == v for k, v in fields.items()), 8, str(fields))

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
    lab.publish(PORT + 1)
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
    mode.add_argument("--pause-inbound", action="store_true", help="exercise idle pause with inbound traffic")
    mode.add_argument("--queued", action="store_true", help="send a single demand packet after an idle endpoint move")
    mode.add_argument("--late-dns", action="store_true", help="withhold first TXT beyond peer expiry")
    mode.add_argument("--roam", action="store_true", help="keep a healthy roam through refresh, then restart")
    mode.add_argument("--retry", action="store_true", help="bring server online during first retry")
    mode.add_argument("--active", action="store_true")
    parser.add_argument("--move-after", type=int, metavar="SECONDS",
                        help="change the move phase relative to the initial working echo")
    mode.add_argument("--routes", action="store_true", help="test physical route and address changes with a fixed endpoint")
    mode.add_argument("--pause", action="store_true")
    args = parser.parse_args()
    if args.queued and args.keepalive != 0:
        parser.error("--queued needs keepalive 0")
    if (args.retry or args.roam or args.pause_inbound) and args.keepalive <= 0:
        parser.error("--retry, --roam and --pause-inbound need enabled keepalive")
    if args.move_after is not None and args.move_after <= 0:
        parser.error("--move-after must be positive")
    if args.pause and (args.keepalive <= 0 or (args.move_after or 187) < 180):
        parser.error("--pause needs an enabled keepalive and at least 180 seconds to measure idle traffic")
    signal.signal(signal.SIGTERM, lambda *_: exit(143))
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix="natwg-recovery-") as directory, ExitStack() as cleanup:
        print(json.dumps(experiment(args, Path(directory), cleanup), sort_keys=True), flush=True)
