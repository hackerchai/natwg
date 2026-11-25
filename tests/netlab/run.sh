#!/usr/bin/env bash
# The natwg network lab: isolated network namespaces that put a natwg host
# behind each kind of NAT, an "internet" with STUN servers, and a peer on it.
# See tests/netlab/README.md.
#
#   sudo NATWG=target/debug/natwg tests/netlab/run.sh [test] [SCENARIO...]
#   sudo tests/netlab/run.sh up SCENARIO     # build it and leave it up
#   sudo tests/netlab/run.sh down            # remove what up left
#   tests/netlab/run.sh list
set -euo pipefail

LAB=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
NATWG=${NATWG:-natwg}
# Every namespace, interface and nftables table of the lab starts with this.
P=nwl
# Where `up` records its work directory for `down`.
STATE=${TMPDIR:-/tmp}/$P-netlab.work
PORT=51830
NAT_PORT=52830
INET_GW=45.77.0.1
ROUTER_WAN=45.77.0.2
PUBLIC_HOST=45.77.0.10
ROUTER_LAN=192.168.77.1
HOST_LAN=192.168.77.2
OTHER_LAN_HOST=192.168.77.99
STUN_A=45.78.0.1
STUN_B=45.78.0.2
PLAIN_A=45.78.0.3
PLAIN_B=45.78.0.4
# No host answers here.
SILENT=45.78.0.99
PEER_GW=45.79.0.1
PEER=45.79.0.2
NAMESPACES=(host rtr inet peer)
SCENARIOS=(
	public public-firewall public-firewall-plain public-forward
	nat1 nat2 nat3 nat4 blocked likely ignores-change inconsistent lan-stun
	upnp upnp-existing upnp-conflict upnp-permanent upnp-rogue upnp-slow upnp-sigterm
)
# natwg detect must finish upnp-slow within this many seconds.
SLOW_LIMIT=12
PIDS=()
WORK=""

usage() {
	sed -n '2,10s/^# \{0,1\}//p' "$0"
	exit 2
}

die() {
	echo "netlab: $*" >&2
	exit 1
}

ns() {
	local name=$1
	shift
	ip netns exec "$P-$name" "$@"
}

describe() {
	case $1 in
	public) echo "the host owns public $PUBLIC_HOST" ;;
	public-firewall) echo "public, behind a stateful firewall that drops new UDP" ;;
	public-firewall-plain) echo "public-firewall, with plain STUN servers only" ;;
	public-forward) echo "a router forwards udp/$PORT and keeps the port, hairpin" ;;
	nat1) echo "static SNAT to :$NAT_PORT, DNAT from anyone, hairpin" ;;
	nat2) echo "static SNAT, DNAT only from IPs the host sent to" ;;
	nat3) echo "masquerade" ;;
	nat4) echo "masquerade fully-random" ;;
	blocked) echo "the router drops UDP" ;;
	likely) echo "nat1, with plain STUN servers only" ;;
	ignores-change) echo "nat1, the RFC 5780 server ignores CHANGE-REQUEST" ;;
	inconsistent) echo "masquerade, DNAT from $STUN_B only" ;;
	lan-stun) echo "masquerade, only a STUN server on the LAN" ;;
	upnp) echo "masquerade, a UPnP gateway that forwards leases, hairpin" ;;
	upnp-existing) echo "upnp, the gateway forwards udp/$PORT to the host already" ;;
	upnp-conflict) echo "upnp, the gateway forwards udp/$PORT to $OTHER_LAN_HOST" ;;
	upnp-permanent) echo "upnp, the gateway takes only permanent leases (725)" ;;
	upnp-rogue) echo "upnp, and a LAN responder that points at $PLAIN_A" ;;
	upnp-slow) echo "masquerade, 10 SSDP answers whose descriptions never come" ;;
	upnp-sigterm) echo "upnp, SIGTERM while natwg holds the lease" ;;
	*) return 1 ;;
	esac
}

# The verdict and exit status natwg detect must give.
expect() {
	case $1 in
	public | public-forward | upnp | upnp-existing | upnp-rogue) echo "supported (public)|0" ;;
	nat1) echo "supported (NAT1)|0" ;;
	public-firewall | nat2 | nat3 | nat4 | blocked | upnp-conflict | upnp-permanent | upnp-slow)
		echo "unsupported|1"
		;;
	public-firewall-plain | likely | ignores-change | inconsistent) echo "likely|2" ;;
	lan-stun) echo "inconclusive|2" ;;
	upnp-sigterm) echo "error INTERRUPTED|3" ;;
	esac
}

# The STUN servers natwg detect asks in SCENARIO.
servers() {
	case $1 in
	likely | public-firewall-plain) echo "$PLAIN_A:3478 $PLAIN_B:3478" ;;
	lan-stun) echo "$ROUTER_LAN:3478" ;;
	upnp-sigterm) echo "$SILENT:3478" ;;
	*) echo "$STUN_A:3478 $PLAIN_A:3478" ;;
	esac
}

# Stop what an earlier `up` left running and remove its work directory.
down() {
	local old
	teardown
	pkill -f "$LAB/(stun_server|igd|rogue)\.py" 2>/dev/null || true
	if [ -f "$STATE" ]; then
		old=$(cat "$STATE")
		case $old in
		"${TMPDIR:-/tmp}/$P".*) rm -rf "$old" ;;
		esac
		rm -f "$STATE"
	fi
}

teardown() {
	local pid name
	for pid in "${PIDS[@]}"; do
		kill "$pid" 2>/dev/null || true
	done
	PIDS=()
	for name in "${NAMESPACES[@]}"; do
		if ip netns list | grep -qw "$P-$name"; then
			ip netns del "$P-$name"
		fi
	done
}

# The nftables ruleset of the router in SCENARIO.
rules() {
	local masquerade="add rule ip $P nat_post oifname \"$P-r0\" masquerade"
	local static_snat="add rule ip $P nat_post oifname \"$P-r0\" ip saddr $HOST_LAN udp sport $PORT snat to $ROUTER_WAN:$NAT_PORT"
	# Hairpin: a LAN host that sends to the router's public address comes
	# back from the router, as on a home router; its own address as the
	# source would be dropped as a martian.
	local hairpin="add rule ip $P nat_post oifname \"$P-r1\" ip saddr $HOST_LAN/24 ct status dnat masquerade"
	cat <<-EOF
		table ip $P {
			set sent { type ipv4_addr; flags dynamic,timeout; timeout 5m; }
			chain upnp_pre { }
			chain upnp_post { }
			chain nat_pre { type nat hook prerouting priority dstnat; policy accept; jump upnp_pre; }
			chain nat_post { type nat hook postrouting priority srcnat; policy accept; jump upnp_post; }
			chain forward_filter { type filter hook forward priority filter; policy accept; }
		}
	EOF
	case $1 in
	public-forward)
		echo "add rule ip $P nat_pre ip daddr $ROUTER_WAN udp dport $PORT dnat to $HOST_LAN:$PORT"
		echo "add rule ip $P nat_post oifname \"$P-r0\" ip saddr $HOST_LAN udp sport $PORT snat to $ROUTER_WAN:$PORT"
		echo "$masquerade"
		echo "$hairpin"
		;;
	nat1 | likely | ignores-change)
		echo "add rule ip $P nat_pre ip daddr $ROUTER_WAN udp dport $NAT_PORT dnat to $HOST_LAN:$PORT"
		echo "$static_snat"
		echo "$masquerade"
		echo "$hairpin"
		;;
	nat2)
		echo "add rule ip $P forward_filter iifname \"$P-r1\" oifname \"$P-r0\" update @sent { ip daddr }"
		echo "add rule ip $P nat_pre iifname \"$P-r0\" ip daddr $ROUTER_WAN udp dport $NAT_PORT ip saddr @sent dnat to $HOST_LAN:$PORT"
		echo "$static_snat"
		echo "$masquerade"
		;;
	nat3 | lan-stun | upnp-slow) echo "$masquerade" ;;
	inconsistent)
		echo "add rule ip $P nat_pre iifname \"$P-r0\" ip saddr $STUN_B udp dport $PORT dnat to $HOST_LAN:$PORT"
		echo "$masquerade"
		;;
	upnp*)
		echo "$masquerade"
		echo "$hairpin"
		;;
	nat4) echo "add rule ip $P nat_post oifname \"$P-r0\" masquerade fully-random" ;;
	blocked)
		echo "add rule ip $P forward_filter meta l4proto udp drop"
		echo "$masquerade"
		;;
	esac
}

# A host firewall that lets in only replies, as a cloud security group does.
host_firewall() {
	cat <<-EOF
		table inet ${P}_fw {
			chain input {
				type filter hook input priority filter; policy accept;
				ct state established,related accept
				meta l4proto udp drop
			}
		}
	EOF
}

# A veth pair with one end in each namespace, each end with its address.
link() {
	local a=$1 a_if=$2 a_ip=$3 b=$4 b_if=$5 b_ip=$6
	ip link add "$a_if" netns "$P-$a" type veth peer name "$b_if" netns "$P-$b"
	ns "$a" ip addr add "$a_ip" dev "$a_if"
	ns "$a" ip link set "$a_if" up
	ns "$b" ip addr add "$b_ip" dev "$b_if"
	ns "$b" ip link set "$b_if" up
}

wait_for() {
	local file=$1 text=$2 tries=${3:-50}
	until grep -q "$text" "$file" 2>/dev/null; do
		tries=$((tries - 1))
		[ "$tries" -gt 0 ] || die "timed out waiting for \"$text\" in $file"
		sleep 0.1
	done
}

# Start a lab process in a namespace; it logs to WORK/NAME.out.
start() {
	local where=$1 name=$2 ready=$3
	shift 3
	ns "$where" python3 "$@" >"$WORK/$name.out" 2>&1 &
	PIDS+=("$!")
	wait_for "$WORK/$name.out" "$ready"
}

# Build SCENARIO: the internet with its STUN servers and the peer, and the
# host, behind the router unless the scenario gives it a public address.
up() {
	local scenario=$1 name direct=false stun=()
	case $scenario in
	public*) [ "$scenario" = public-forward ] || direct=true ;;
	esac
	teardown
	# Each scenario starts with fresh logs.
	rm -f "${WORK:?}"/*.log "${WORK:?}"/*.out
	for name in "${NAMESPACES[@]}"; do
		if [ "$name" = rtr ] && $direct; then
			continue
		fi
		ip netns add "$P-$name"
		ns "$name" ip link set lo up
	done
	ns inet sysctl -qw net.ipv4.ip_forward=1
	for name in "$STUN_A" "$STUN_B" "$PLAIN_A" "$PLAIN_B"; do
		ns inet ip addr add "$name/32" dev lo
	done
	link peer "$P-p0" "$PEER/24" inet "$P-i1" "$PEER_GW/24"
	ns peer ip route add default via "$PEER_GW"
	stun=(--rfc5780 "$STUN_A" "$STUN_B" --plain "$PLAIN_A" --plain "$PLAIN_B")
	[ "$scenario" != ignores-change ] || stun+=(--ignore-change)
	start inet stun listening "$LAB/stun_server.py" "${stun[@]}"
	if $direct; then
		link host "$P-h0" "$PUBLIC_HOST/24" inet "$P-i0" "$INET_GW/24"
		ns host ip route add default via "$INET_GW"
		if [ "$scenario" != public ]; then
			host_firewall | ns host nft -f -
		fi
		return
	fi
	link rtr "$P-r0" "$ROUTER_WAN/24" inet "$P-i0" "$INET_GW/24"
	link host "$P-h0" "$HOST_LAN/24" rtr "$P-r1" "$ROUTER_LAN/24"
	ns rtr ip route add default via "$INET_GW"
	ns host ip route add default via "$ROUTER_LAN"
	ns rtr sysctl -qw net.ipv4.ip_forward=1
	rules "$scenario" | ns rtr nft -f -
	local igd=(--lan-ip "$ROUTER_LAN" --wan-ip "$ROUTER_WAN" --wan-if "$P-r0" --table "$P" --log "$WORK/igd.log")
	case $scenario in
	lan-stun) start rtr lan-stun listening "$LAB/stun_server.py" --plain "$ROUTER_LAN" ;;
	upnp | upnp-sigterm) start rtr igd "IGD on" "$LAB/igd.py" "${igd[@]}" ;;
	upnp-existing) start rtr igd "IGD on" "$LAB/igd.py" "${igd[@]}" --preset "$PORT:$HOST_LAN" ;;
	upnp-conflict) start rtr igd "IGD on" "$LAB/igd.py" "${igd[@]}" --preset "$PORT:$OTHER_LAN_HOST" ;;
	upnp-permanent) start rtr igd "IGD on" "$LAB/igd.py" "${igd[@]}" --permanent-only ;;
	upnp-rogue)
		start rtr igd "IGD on" "$LAB/igd.py" "${igd[@]}"
		start rtr rogue "rogue SSDP" "$LAB/rogue.py" --lan-ip "$ROUTER_LAN" \
			--location "http://$PLAIN_A:5000/igd.xml"
		# What natwg must never reach: a gateway on the internet.
		start inet evil "IGD on" "$LAB/igd.py" --lan-ip "$PLAIN_A" --no-ssdp --log "$WORK/evil.log"
		;;
	upnp-slow)
		start rtr rogue "rogue SSDP" "$LAB/rogue.py" --lan-ip "$ROUTER_LAN" --answers 10 \
			--location "http://$ROUTER_LAN:5001/d{n}.xml" --stall "$ROUTER_LAN:5001"
		;;
	esac
}

# natwg detect in the host namespace, as the user who ran sudo: it needs no
# root on Linux.
detect() {
	local scenario=$1 server args=()
	local as_user=()
	if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != root ]; then
		as_user=(runuser -u "$SUDO_USER" --)
	fi
	for server in $(servers "$scenario"); do
		args+=(--server "$server")
	done
	case $scenario in
	upnp*) args+=(--upnp auto) ;;
	*) args+=(--upnp off) ;;
	esac
	case $scenario in
	upnp-sigterm) args+=(--timeout-ms 3000) ;;
	*) args+=(--timeout-ms 300) ;;
	esac
	ns host "${as_user[@]}" "$NATWG" detect --config /nonexistent/config.json \
		--iface "$P-h0" --port "$PORT" --json "${args[@]}"
}

# natwg detect, stopped with SIGTERM once the gateway holds its lease.
detect_sigterm() {
	local pid code=0
	detect upnp-sigterm &
	pid=$!
	wait_for "$WORK/igd.log" "^AddPortMapping $PORT" 100
	sleep 0.5
	pkill -TERM -f "^$NATWG detect" || true
	wait "$pid" || code=$?
	return "$code"
}

# A field of the JSON natwg detect printed, such as upnp.state.
field() {
	python3 -c '
import json, sys
value = json.load(open(sys.argv[1]))
for key in sys.argv[2].split("."):
    value = value.get(key) if isinstance(value, dict) else None
print("" if value is None else value)
' "$@" 2>/dev/null || true
}

# The summary of the JSON natwg detect printed, or its error.
summary() {
	local code
	code=$(field "$1" error.code)
	if [ -n "$code" ]; then
		echo "error $code"
	else
		field "$1" summary
	fi
}

check() {
	local what=$1
	shift
	if ! "$@"; then
		echo "FAIL $SCENARIO: $what" >&2
		[ ! -f "$WORK/igd.log" ] || sed 's/^/  igd: /' "$WORK/igd.log" >&2
		return 1
	fi
}

logged() { grep -q "$1" "$WORK/igd.log" 2>/dev/null; }
not_logged() { ! logged "$1"; }
forwards() { ns rtr nft list chain ip "$P" upnp_pre | grep -q "dnat to $1"; }
forwards_nothing() { ! ns rtr nft list chain ip "$P" upnp_pre | grep -q dnat; }
is() { [ "$(field "$JSON" "$1")" = "$2" ]; }

# What SCENARIO must show beyond its verdict.
checks() {
	case $SCENARIO in
	public) check "public by address" is public_by address ;;
	public-forward) check "public by port_kept" is public_by port_kept ;;
	upnp)
		check "a 120 s lease" logged "^AddPortMapping $PORT lease=120$" &&
			check "the lease deleted" logged "^DeletePortMapping $PORT$" &&
			check "no mapping left" forwards_nothing &&
			check "state leased" is upnp.state leased &&
			check "public by upnp" is public_by upnp
		;;
	upnp-existing)
		check "no lease taken" not_logged "PortMapping $PORT lease" &&
			check "no lease deleted" not_logged "^DeletePortMapping" &&
			check "the existing mapping stays" forwards "$HOST_LAN:$PORT" &&
			check "state existing" is upnp.state existing &&
			check "public by upnp" is public_by upnp
		;;
	upnp-conflict)
		check "no lease taken" not_logged "PortMapping $PORT lease" &&
			check "no lease deleted" not_logged "^DeletePortMapping" &&
			check "the other host's mapping stays" forwards "$OTHER_LAN_HOST:$PORT" &&
			check "state conflict" is upnp.state conflict
		;;
	upnp-permanent)
		check "refused with 725" logged "^AddPortMapping $PORT lease=120 refused=725$" &&
			check "no permanent lease asked" not_logged "lease=0" &&
			check "no mapping" forwards_nothing &&
			check "state permanent_only" is upnp.state permanent_only
		;;
	upnp-rogue)
		check "nothing reached the internet gateway" test ! -s "$WORK/evil.log" &&
			check "the LAN gateway used" is upnp.gateway.control_url "http://$ROUTER_LAN:5000/ctl" &&
			check "its WAN address" is upnp.external_ip "$ROUTER_WAN" &&
			check "the lease deleted" logged "^DeletePortMapping $PORT$"
		;;
	upnp-slow)
		check "done within $SLOW_LIMIT s (took ${ELAPSED}s)" test "$ELAPSED" -lt "$SLOW_LIMIT" &&
			check "state failed" is upnp.state failed
		;;
	upnp-sigterm)
		check "the lease deleted" logged "^DeletePortMapping $PORT$" &&
			check "no mapping left" forwards_nothing
		;;
	esac
}

# One row of the results table from the JSON of natwg detect.
row() {
	python3 -c '
import json, sys
scenario, description, code, path = sys.argv[1:5]
try:
    d = json.load(open(path))
except Exception:
    d = {}
if "error" in d or not d:
    error = d.get("error", {}).get("code", "no JSON")
    print("| %s | %s | error %s | %s | | | | | |" % (scenario, description, error, code))
    sys.exit()
answers = d["mapping"]["answers"]
endpoint = d["mapping"]["endpoint"] or ("(several)" if answers else "-")
print("| %s | %s | %s | %s | %s %s | %s | %s | %s | %s |" % (
    scenario, description, d["summary"], code, d["mapping"]["behaviour"], endpoint,
    d["filtering"]["behaviour"], d["self_test"], d["upnp"]["state"], d["public_by"] or ""))
' "$@"
}

run_tests() {
	local code failed=0 want got rows=() started
	[ "$#" -gt 0 ] || set -- "${SCENARIOS[@]}"
	command -v "$NATWG" >/dev/null || [ -x "$NATWG" ] || die "no natwg at $NATWG; set NATWG"
	for SCENARIO in "$@"; do
		describe "$SCENARIO" >/dev/null || die "no scenario $SCENARIO"
		up "$SCENARIO"
		JSON=$WORK/$SCENARIO.json
		code=0
		started=$(date +%s)
		if [ "$SCENARIO" = upnp-sigterm ]; then
			detect_sigterm >"$JSON" || code=$?
		else
			detect "$SCENARIO" >"$JSON" || code=$?
		fi
		ELAPSED=$(($(date +%s) - started))
		want=$(expect "$SCENARIO")
		got=$(summary "$JSON")
		if [ "$got|$code" != "$want" ]; then
			echo "FAIL $SCENARIO: got ${got:-no JSON}, exit $code; want ${want%|*}, exit ${want#*|}" >&2
			cat "$JSON" >&2 || true
			failed=1
		elif ! checks; then
			failed=1
		else
			echo "ok   $SCENARIO: $got, exit $code, ${ELAPSED}s" >&2
		fi
		rows+=("$(row "$SCENARIO" "$(describe "$SCENARIO")" "$code" "$JSON")")
		teardown
	done
	echo "| scenario | network | verdict | exit | mapping | filtering | self test | UPnP | public by |"
	echo "|---|---|---|---|---|---|---|---|---|"
	printf '%s\n' "${rows[@]}"
	return "$failed"
}

main() {
	local command=${1:-test}
	case $command in
	list)
		for command in "${SCENARIOS[@]}"; do
			printf '%-22s %s\n' "$command" "$(describe "$command")"
		done
		return
		;;
	-h | --help | help) usage ;;
	esac
	[ "$(id -u)" -eq 0 ] || die "run it as root: sudo $0 $*"
	command -v nft >/dev/null || die "nft is missing"
	case $command in
	down)
		down
		return
		;;
	up)
		[ "$#" -eq 2 ] || usage
		describe "$2" >/dev/null || die "no scenario $2"
		down
		WORK=$(mktemp -d "${TMPDIR:-/tmp}/$P.XXXXXX")
		echo "$WORK" >"$STATE"
		up "$2"
		# The processes keep running after this script exits; down stops them.
		PIDS=()
		echo "scenario $2 is up; logs in $WORK; run commands with ip netns exec $P-host ..." >&2
		return
		;;
	test) [ "$#" -eq 0 ] || shift ;;
	esac
	down
	WORK=$(mktemp -d "${TMPDIR:-/tmp}/$P.XXXXXX")
	trap 'teardown; rm -rf "$WORK"' EXIT
	run_tests "$@"
}

main "$@"
