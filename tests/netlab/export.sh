#!/usr/bin/env bash
# Exercise the exported configs with native WireGuard in isolated namespaces.
# sudo NATWG=/path/to/debug/natwg [MIHOMO=/path/to/mihomo] tests/netlab/export.sh
set -euo pipefail
# shellcheck source-path=SCRIPTDIR
# shellcheck source=e2e.sh
. "$(dirname "${BASH_SOURCE[0]}")/e2e.sh"

export_client() {
	ns peer "$NATWG" config export --config "$WORK/client.json" --format "$1" --out "$2"
}

issue() {
	ns host "$NATWG" peer add "$1" --config "$WORK/server.json" --format "$2" --out "$3"
}

# Isolate wg-quick's libc resolver as well as its network. The mount only
# lives for this one command, and the namespace has no real internet route.
client_up() {
	printf 'nameserver %s\n' "$DNS" >"$WORK/resolv.conf"
	# The inner bash expands its two positional arguments after unshare.
	# shellcheck disable=SC2016
	ns peer unshare -m --propagation private bash -ec '
		mount --bind "$1" /etc/resolv.conf
		exec wg-quick up "$2"
	' _ "$WORK/resolv.conf" "$WORK/mobile.conf"
}

traffic() {
	local lan=$1 endpoint=$2 since=$3 handshake
	pings "$TUNNEL_IP"
	pings "$lan"
	handshake=$(ns peer wg show mobile latest-handshakes | awk '{print $2}')
	[[ $handshake -ge $since ]]
	ns peer wg show mobile endpoints | awk '{print $2}' | grep -Fx "$endpoint"
	echo "$SCENARIO: handshake at $handshake; two pings each to tunnel $TUNNEL_IP and LAN $lan"
}

proxies() {
	issue surge-phone surge "$WORK/phone.conf"
	issue clash-tablet clash "$WORK/tablet.yaml"
	for f in "$WORK/phone.conf" "$WORK/tablet.yaml"; do
		[[ $(stat -c %a "$f") = 600 ]]
	done
	if [[ -n ${MIHOMO:-} ]]; then
		ns peer "$MIHOMO" -t -d "$WORK/mihomo" -f "$WORK/tablet.yaml"
	fi
	# Optional offline parser handoff for Surge on macOS. Only synthetic
	# fixtures from this script are copied, into a fresh private directory.
	if [[ -n ${SURGE_FIXTURES:-} ]]; then
		install -m 600 "$WORK/phone.conf" "$SURGE_FIXTURES/$SCENARIO.conf"
	fi
}

public_exports() {
	local started instance table=natwg_wgquick_natwg
	extras public --record "$NAME=A:$PUBLIC_HOST"
	server_config public
	issue laptop natwg "$WORK/client.json"
	export_client wg-quick "$WORK/mobile.conf"
	proxies
	grep -Fx "Endpoint = $NAME:$PORT" "$WORK/mobile.conf"
	grep -Fq "endpoint = $NAME:$PORT" "$WORK/phone.conf"
	grep -Fq "server: \"$NAME\"" "$WORK/tablet.yaml"
	ns host "$NATWG" config export --config "$WORK/server.json" --format wg-quick --out "$WORK/home.conf"
	[[ $(stat -c %a "$WORK/home.conf") = 600 ]]
	[[ $(grep -Fc '[Peer]' "$WORK/home.conf") = 3 ]]

	ns host sysctl -qw net.ipv4.ip_forward=0
	ns host nft add table inet "$table"
	ns host nft add chain inet "$table" existing
	if ns host wg-quick up "$WORK/home.conf" >"$WORK/collision.log" 2>&1; then
		die "wg-quick took an occupied table"
	fi
	[[ $(ns host sysctl -n net.ipv4.ip_forward) = 0 ]]
	ns host nft list chain inet "$table" existing >/dev/null
	ns host nft delete table inet "$table"
	ns host wg-quick up "$WORK/home.conf"
	started=$(date +%s)
	client_up
	traffic "$LAN_HOST" "$PUBLIC_HOST:$PORT" "$started"
	api_logged "^DNS A $NAME $PUBLIC_HOST"
	ns peer wg-quick down "$WORK/mobile.conf"
	ns host wg-quick down "$WORK/home.conf"
	if ns host nft list table inet "$table" >/dev/null 2>&1; then
		die "wg-quick left its table behind"
	fi
	ns host wg-quick up "$WORK/home.conf"
	ns host nft add chain inet "$table" added_later
	if ns host wg-quick down "$WORK/home.conf" >"$WORK/changed.log" 2>&1; then
		die "wg-quick removed a changed table"
	fi
	ns host nft list chain inet "$table" added_later >/dev/null
	for instance in 2026 10home ip; do
		python3 - "$WORK/server.json" "$instance" <<'PYTHON'
import json, sys
path, instance = sys.argv[1:]
with open(path) as f:
    config = json.load(f)
config["role"]["server"]["instance"] = instance
with open(path, "w") as f:
    json.dump(config, f)
PYTHON
		ns host "$NATWG" config export --config "$WORK/server.json" --format wg-quick --out "$WORK/home.conf" --force
		ns host wg-quick up "$WORK/home.conf"
		ns host nft list table inet "natwg_wgquick_$instance" >/dev/null
		ns host wg-quick down "$WORK/home.conf"
		if ns host nft list table inet "natwg_wgquick_$instance" >/dev/null 2>&1; then
			die "wg-quick left the table for $instance behind"
		fi
	done
	echo "public: wg-quick removed its own table and preserved both foreign chains in collision tests"
}

nat1_exports() {
	local started new_port=52831
	extras nat1
	server_config nat1
	python3 - "$WORK/server.json" "$ROUTER_LAN" <<'PY'
import json, sys
path, router = sys.argv[1:]
config = json.load(open(path))
server = config["role"]["server"]
server["publish"] = "txt"
server["lan"] = [router.rsplit(".", 1)[0] + ".0/24"]
server["cloudflare"]["record"] = "_wg.example.net"
with open(path, "w") as f:
    json.dump(config, f)
PY
	issue laptop natwg "$WORK/client.json"
	daemon host server
	wait_until 30 status_is server published "$ROUTER_WAN:$NAT_PORT"
	python3 - "$WORK/client.json" "$P-p0" "$DNS" <<'PY'
import json, sys
path, iface, dns = sys.argv[1:]
config = json.load(open(path))
config["role"]["client"].update(iface=iface, resolvers=[dns])
with open(path, "w") as f:
    json.dump(config, f)
PY
	export_client wg-quick "$WORK/mobile.conf"
	proxies
	grep -Fx "Endpoint = $ROUTER_WAN:$NAT_PORT" "$WORK/mobile.conf"
	grep -Fq "endpoint = $ROUTER_WAN:$NAT_PORT" "$WORK/phone.conf"
	grep -Fq "server: \"$ROUTER_WAN\"" "$WORK/tablet.yaml"
	grep -Fq "port: $NAT_PORT" "$WORK/tablet.yaml"
	for f in mobile.conf phone.conf tablet.yaml; do
		grep -Fxq '# TXT record _wg.example.net' "$WORK/$f"
		grep -Eq '^# Snapshot at [0-9T:Z-]+\. Export again when the mapping changes\.$' "$WORK/$f"
	done
	"$NATWG" status --status-file "$WORK/server.status.json" | grep -F 'Surge/Clash configs exported before'
	started=$(date +%s)
	client_up
	traffic "$ROUTER_LAN" "$ROUTER_WAN:$NAT_PORT" "$started"
	ns peer wg-quick down "$WORK/mobile.conf"
	# Rotate the mapping and flush the old bindings in the isolated NAT box.
	{
		echo "delete table ip $P"
		NAT_PORT=$new_port rules nat1
	} | ns rtr nft -f -
	ns rtr python3 "$LAB/conntrack.py"
	wait_until 35 status_is server published "$ROUTER_WAN:$new_port"
	grep -Fx "Endpoint = $ROUTER_WAN:$NAT_PORT" "$WORK/mobile.conf"
	cp "$WORK/mobile.conf" "$WORK/first.conf"
	ns peer "$NATWG" config export --config "$WORK/client.json" --format wg-quick --out "$WORK/mobile.conf" --force
	grep -Fx "Endpoint = $ROUTER_WAN:$new_port" "$WORK/mobile.conf"
	cmp <(grep -Ev '^(#|Endpoint)' "$WORK/first.conf") <(grep -Ev '^(#|Endpoint)' "$WORK/mobile.conf")
	started=$(date +%s)
	client_up
	traffic "$ROUTER_LAN" "$ROUTER_WAN:$new_port" "$started"
	ns peer wg-quick down "$WORK/mobile.conf"
	# A recipient keeping only the native profile can read its record, resolve
	# the new port and reconnect using the original client identity.
	local record answer
	record=$(awk '$1 == "#" && $2 == "TXT" && $3 == "record" {print $4}' "$WORK/first.conf")
	answer=$(ns peer "$NATWG" probe txt "$record" --iface "$P-p0" --dns "$DNS")
	[[ $answer = "$ROUTER_WAN:$new_port" ]]
	sed "s/^Endpoint = .*/Endpoint = $answer/" "$WORK/first.conf" >"$WORK/mobile.conf"
	started=$(date +%s)
	client_up
	traffic "$ROUTER_LAN" "$answer" "$started"
	ns peer wg-quick down "$WORK/mobile.conf"
	stop_daemons
}

# init.sh reuses client_up and traffic on its generated native files.
if [[ "${BASH_SOURCE[0]}" != "$0" ]]; then
	return 0
fi

[[ $(id -u) = 0 ]] || die "run as root"
command -v wg-quick >/dev/null || die "install wireguard-tools"
umask 077
if [[ -n ${SURGE_FIXTURES:-} ]]; then
	mkdir -m 700 "$SURGE_FIXTURES"
fi
down
WORK=$(mktemp -d "${TMPDIR:-/tmp}/$P.XXXXXX")
echo "$WORK" >"$STATE"
trap 'stop_daemons; down' EXIT
for SCENARIO in public nat1; do
	up "$SCENARIO"
	mkdir "$WORK/$SCENARIO"
	parent=$WORK
	WORK=$parent/$SCENARIO
	"${SCENARIO}_exports"
	WORK=$parent
done
