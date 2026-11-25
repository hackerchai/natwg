#!/usr/bin/env bash
# End-to-end tests of natwg's public mode (publish "a") in the network lab.
# A real natwg server keeps an A record at a fake Cloudflare API. A real
# natwg client finds the server through that zone's DNS server, handshakes,
# pings the tunnel and a LAN host, and follows the server to a new IP. Where
# natwg cannot confirm a public IP, the server must refuse to publish and
# leave the record as it was. See tests/netlab/README.md.
#
#   sudo NATWG=target/debug/natwg tests/netlab/e2e.sh [test] [SCENARIO...]
#   tests/netlab/e2e.sh list
set -euo pipefail

# shellcheck source-path=SCRIPTDIR
# shellcheck source=run.sh
. "$(dirname "${BASH_SOURCE[0]}")/run.sh"

API=45.78.0.80
DNS=45.78.0.53
ZONE=example.net
NAME=home.example.net
TOKEN=netlab-token
# What the record holds before natwg runs where it must refuse to publish.
STALE=45.77.0.99
NEW_PUBLIC_HOST=45.77.0.11
NEW_ROUTER_WAN=45.77.0.3
# The LAN behind the public host, on the host's own link.
LAN_NET=10.88.0.0/24
HOST_ON_LAN=10.88.0.1
LAN_HOST=10.88.0.2
TUNNEL_IP=10.66.66.1
E2E=(public upnp public-forward nat1)
# The client looks the name up every 60 s, then handshakes.
FOLLOW_LIMIT=100
RESULT=""
# The server calls the fake API, never the real one.
export NATWG_CLOUDFLARE_API="http://$API/client/v4"

e2e_describe() {
	case $1 in
	public) echo "the host owns $PUBLIC_HOST, no STUN; it moves to $NEW_PUBLIC_HOST" ;;
	upnp) echo "a UPnP router owns $ROUTER_WAN; it moves to $NEW_ROUTER_WAN" ;;
	public-forward) echo "a router forwards udp/$PORT and keeps it, no UPnP: refuse" ;;
	nat1) echo "NAT1 maps udp/$PORT to :$NAT_PORT: refuse" ;;
	*) return 1 ;;
	esac
}

# The fake Cloudflare API and DNS server on the internet, and for `public` a
# LAN host on the host's link that the internet cannot route to.
extras() {
	local seed=()
	ns inet ip addr add "$API/32" dev lo
	ns inet ip addr add "$DNS/32" dev lo
	case $1 in
	public-forward | nat1) seed=(--record "$NAME=A:$STALE") ;;
	esac
	start inet cloudflare "Cloudflare API on" "$LAB/cloudflare.py" --api "$API:80" \
		--dns "$DNS:53" --zone "$ZONE" --token "$TOKEN" --log "$WORK/cloudflare.log" "${seed[@]}"
	[ "$1" = public ] || return 0
	ns inet ip link add "$P-sw" type bridge
	ns inet ip link set "$P-sw" up
	ns inet ip addr del "$INET_GW/24" dev "$P-i0"
	ns inet ip link set "$P-i0" master "$P-sw"
	ns inet ip addr add "$INET_GW/24" dev "$P-sw"
	ip netns add "$P-lan"
	ns lan ip link set lo up
	ip link add "$P-l0" netns "$P-lan" type veth peer name "$P-i2" netns "$P-inet"
	ns lan ip addr add "$LAN_HOST/24" dev "$P-l0"
	ns lan ip link set "$P-l0" up
	ns inet ip link set "$P-i2" master "$P-sw"
	ns inet ip link set "$P-i2" up
	ns host ip addr add "$HOST_ON_LAN/24" dev "$P-h0"
}

# The server config of SCENARIO: publish a, with STUN and UPnP as the
# network needs, a fresh key, and no peer yet.
server_config() {
	"$NATWG" keys gen >"$WORK/keys.json"
	python3 -c '
import json, os, sys
scenario, work, iface, port, zone, name, token, dns, stun, plain, router, lan = sys.argv[1:13]
server = {
    "iface": iface,
    "listen_port": int(port),
    "lan": {"public": [lan], "nat1": []}.get(scenario, [router.rsplit(".", 1)[0] + ".0/24"]),
    "publish": "a",
    "cloudflare": {"zone": zone, "record": name, "token": token},
    "status_file": work + "/server.status.json",
}
if scenario != "public":
    server["stun"] = {
        "servers": [],
        "fallback": [stun + ":3478", plain + ":3478"],
        "interval_secs": 5,
        "dns_server": dns,
    }
if scenario == "upnp":
    server["upnp"] = {
        "control_url": "http://%s:5000/ctl" % router,
        "lease_secs": 600,
        "refresh_secs": 300,
    }
config = {
    "version": 1,
    "private_key": json.load(open(work + "/keys.json"))["private_key"],
    "interface": {"address": "10.66.66.1/24"},
    "peers": [],
    "role": {"server": server},
    "update": {"check": "off"},
}
os.umask(0o077)
json.dump(config, open(work + "/server.json", "w"), indent=2)
' "$1" "$WORK" "$P-h0" "$PORT" "$ZONE" "$NAME" "$TOKEN" "$DNS" "$STUN_A" "$PLAIN_A" \
		"$ROUTER_LAN" "$LAN_NET"
}

# natwg peer add on the server config, then the client config it printed,
# pointed at the lab's DNS server and uplink.
add_client() {
	"$NATWG" --config "$WORK/server.json" peer add laptop --out "$WORK/client.json" \
		2>>"$WORK/peer.log"
	check "peer add hands the client server $NAME:$PORT" \
		is_field client.json role.client.server "$NAME:$PORT" &&
		check "and no TXT record" is_field client.json role.client.record "" || return 1
	python3 -c '
import json, os, sys
path, iface, dns, work = sys.argv[1:5]
config = json.load(open(path))
config["role"]["client"].update(resolvers=[dns], iface=iface, status_file=work + "/client.status.json")
config["update"] = {"check": "off"}
os.umask(0o077)
json.dump(config, open(path + ".new", "w"), indent=2)
os.replace(path + ".new", path)
' "$WORK/client.json" "$P-p0" "$DNS" "$WORK"
}

# Start natwg ROLE, server or client, in namespace WHERE; it logs to
# WORK/ROLE.log.
daemon() {
	local where=$1 role=$2
	ns "$where" "$NATWG" --config "$WORK/$role.json" "$role" --foreground >"$WORK/$role.log" 2>&1 &
	PIDS+=("$!")
}

# Stop the natwg server and client with SIGTERM, and wait for them to remove
# their TUN, routes and NAT rules.
stop_daemons() {
	local tries=50
	[ -n "$WORK" ] || return 0
	pkill -TERM -f -- "--config $WORK/" 2>/dev/null || true
	while pgrep -f -- "--config $WORK/" >/dev/null && [ "$tries" -gt 0 ]; do
		sleep 0.1
		tries=$((tries - 1))
	done
}

# Run CMD... once a second until it succeeds, for at most LIMIT seconds.
wait_until() {
	local limit=$1 deadline
	shift
	deadline=$(($(date +%s) + limit))
	until "$@"; do
		[ "$(date +%s)" -lt "$deadline" ] || return 1
		sleep 1
	done
}

is_field() { [ "$(field "$WORK/$1" "$2")" = "$3" ]; }
status_is() { is_field "$1.status.json" "$2" "$3"; }
api_logged() { grep -Eq "$1" "$WORK/cloudflare.log" 2>/dev/null; }
nothing_written() { ! api_logged "^(POST|PUT) "; }
pings() { ns peer ping -c 2 -W 2 "$1" >/dev/null; }
healthy() { "$NATWG" status --status-file "$WORK/$1.status.json" >/dev/null 2>&1; }

# Whether the zone's DNS server answers the name with ADDRESS alone, asked
# from the peer as the client asks it.
dns_answers() {
	[ "$(ns peer "$NATWG" probe dns "$NAME" --iface "$P-p0" --dns "$DNS" --timeout-ms 1000 2>/dev/null)" = "$1" ]
}

# Whether the client's last handshake happened at or after the Unix time AT.
handshake_since() {
	local at
	at=$(field "$WORK/client.status.json" server.last_handshake)
	[ -n "$at" ] && [ "$at" -ge "$1" ]
}

follows() { status_is client endpoint "$1:$PORT" && handshake_since "$2"; }

# Whether natwg status of the server exits 1 and names PROBLEM.
unhealthy() {
	local code=0 said
	said=$("$NATWG" status --status-file "$WORK/server.status.json" 2>&1 >/dev/null) || code=$?
	[ "$code" -eq 1 ] && grep -qF "$1" <<<"$said"
}

says() { field "$WORK/server.status.json" public_error | grep -qF "$1"; }

# Give the server's public IP a new address, as an ISP does.
readdress() {
	case $SCENARIO in
	public)
		ns host sysctl -qw "net.ipv4.conf.$P-h0.promote_secondaries=1"
		ns host ip addr add "$NEW_PUBLIC_HOST/24" dev "$P-h0"
		ns host ip addr del "$PUBLIC_HOST/24" dev "$P-h0"
		ns host ip route replace default via "$INET_GW"
		;;
	upnp)
		# The router reconnects with a new WAN address and an empty UPnP
		# table, and its old NAT bindings go with the old address.
		ns rtr sysctl -qw "net.ipv4.conf.$P-r0.promote_secondaries=1"
		ns rtr ip addr add "$NEW_ROUTER_WAN/24" dev "$P-r0"
		ns rtr ip addr del "$ROUTER_WAN/24" dev "$P-r0"
		ns rtr ip route replace default via "$INET_GW"
		pkill -f "$LAB/igd\.py" || true
		ns rtr nft flush chain ip "$P" upnp_pre
		ns rtr nft flush chain ip "$P" upnp_post
		ns rtr python3 "$LAB/conntrack.py" >/dev/null
		start rtr igd-new "IGD on" "$LAB/igd.py" --lan-ip "$ROUTER_LAN" \
			--wan-ip "$NEW_ROUTER_WAN" --wan-if "$P-r0" --table "$P" --log "$WORK/igd.log"
		;;
	esac
}

# A server whose public IP natwg confirms publishes it, a client reaches it
# and a LAN host behind it, and both follow the IP when it moves.
publishing() {
	local old new by lan_host started changed
	case $SCENARIO in
	public) old=$PUBLIC_HOST new=$NEW_PUBLIC_HOST by=address lan_host=$LAN_HOST ;;
	upnp) old=$ROUTER_WAN new=$NEW_ROUTER_WAN by=upnp lan_host=$ROUTER_LAN ;;
	esac
	daemon host server
	check "the A record holds $old" wait_until 30 status_is server published_ip "$old" &&
		check "public by $by" status_is server public_by "$by" &&
		check "created through the API" api_logged "^POST A $NAME $old$" &&
		check "DNS answers $old" dns_answers "$old" &&
		check "natwg status of the server exits 0" wait_until 15 healthy server || return 1
	started=$(date +%s)
	daemon peer client
	check "a handshake" wait_until 30 handshake_since "$started" &&
		check "the client looks up A $NAME" status_is client record_type a &&
		check "the client dials $old:$PORT" status_is client endpoint "$old:$PORT" &&
		check "ping $TUNNEL_IP through the tunnel" pings "$TUNNEL_IP" &&
		check "ping the LAN host $lan_host" pings "$lan_host" &&
		check "natwg status of the client exits 0" healthy client || return 1
	changed=$(date +%s)
	readdress
	check "the A record follows to $new" wait_until 60 status_is server published_ip "$new" &&
		check "updated through the API" api_logged "^PUT A $NAME $new$" &&
		check "DNS answers $new" dns_answers "$new" &&
		check "the client follows within ${FOLLOW_LIMIT}s" \
			wait_until "$FOLLOW_LIMIT" follows "$new" "$changed" || return 1
	RESULT="by $by, $old to $new; the client followed in $(($(date +%s) - changed))s"
	check "ping $TUNNEL_IP after the move" pings "$TUNNEL_IP" &&
		check "ping $lan_host after the move" pings "$lan_host" &&
		check "public by $by after the move" status_is server public_by "$by" &&
		check "natwg status of the server exits 0" healthy server &&
		check "natwg status of the client exits 0" healthy client
}

# A server whose public IP natwg cannot confirm publishes nothing, says why,
# and leaves the record as it was.
refusing() {
	local reason
	case $SCENARIO in
	public-forward) reason="cannot confirm that a router forwards udp/$PORT" ;;
	nat1) reason="does not keep the listen port $PORT" ;;
	esac
	daemon host server
	check "the status says: $reason" wait_until 30 says "$reason" &&
		check "natwg status exits 1: no public IP" unhealthy "no public IP" || return 1
	# Two more STUN rounds and an address check, then nothing may have changed.
	sleep 11
	check "nothing written through the API" nothing_written &&
		check "DNS still answers $STALE" dns_answers "$STALE" &&
		check "still no public IP" status_is server public_ip "" &&
		check "natwg status still exits 1" unhealthy "no public IP" || return 1
	RESULT="refused, $NAME stays $STALE: $(field "$WORK/server.status.json" public_error)"
}

run_scenario() {
	case $SCENARIO in
	public | upnp) publishing ;;
	*) refusing ;;
	esac
}

show_logs() {
	local log
	for log in server.log client.log cloudflare.log server.status.json client.status.json; do
		[ -f "$WORK/$log" ] || continue
		echo "--- $log" >&2
		tail -n 40 "$WORK/$log" >&2
	done
}

e2e_tests() {
	local failed=0 rows=() outcome started
	[ "$#" -gt 0 ] || set -- "${E2E[@]}"
	for SCENARIO in "$@"; do
		e2e_describe "$SCENARIO" >/dev/null || die "no e2e scenario $SCENARIO"
	done
	for SCENARIO in "$@"; do
		up "$SCENARIO"
		rm -f "$WORK"/*.json
		extras "$SCENARIO"
		RESULT=""
		started=$(date +%s)
		server_config "$SCENARIO"
		if add_client && run_scenario; then
			outcome=ok
			echo "ok   $SCENARIO: $RESULT ($(($(date +%s) - started))s)" >&2
		else
			outcome=FAIL
			failed=1
			show_logs
		fi
		rows+=("| $SCENARIO | $(e2e_describe "$SCENARIO") | $outcome | $RESULT |")
		stop_daemons
		teardown
	done
	echo "| scenario | network | result | details |"
	echo "|---|---|---|---|"
	printf '%s\n' "${rows[@]}"
	return "$failed"
}

e2e_main() {
	local command=${1:-test} scenario
	case $command in
	list)
		for scenario in "${E2E[@]}"; do
			printf '%-16s %s\n' "$scenario" "$(e2e_describe "$scenario")"
		done
		return
		;;
	-h | --help | help) usage ;;
	esac
	[ "$(id -u)" -eq 0 ] || die "run it as root: sudo $0 $*"
	command -v nft >/dev/null || die "nft is missing"
	command -v "$NATWG" >/dev/null || [ -x "$NATWG" ] || die "no natwg at $NATWG; set NATWG"
	if [ "$command" = test ] && [ "$#" -gt 0 ]; then
		shift
	fi
	down
	WORK=$(mktemp -d "${TMPDIR:-/tmp}/$P.XXXXXX")
	echo "$WORK" >"$STATE"
	trap 'stop_daemons; down' EXIT
	e2e_tests "$@"
}

e2e_main "$@"
