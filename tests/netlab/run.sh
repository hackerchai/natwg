#!/usr/bin/env bash
# The natwg network lab: isolated network namespaces that put a natwg host
# behind each kind of NAT, an "internet" with STUN servers, and a peer on it.
# See tests/netlab/README.md.
#
#   sudo NATWG=target/debug/natwg tests/netlab/run.sh [test] [SCENARIO...]
#   sudo tests/netlab/run.sh up SCENARIO     # build it and leave it up
#   sudo tests/netlab/run.sh down            # remove whatever the lab left
#   tests/netlab/run.sh list
set -euo pipefail

LAB=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
NATWG=${NATWG:-natwg}
# Every namespace, interface and nftables table of the lab starts with this.
P=nwl
PORT=51830
NAT_PORT=52830
INET_GW=45.77.0.1
ROUTER_WAN=45.77.0.2
PUBLIC_HOST=45.77.0.10
ROUTER_LAN=192.168.77.1
HOST_LAN=192.168.77.2
STUN_A=45.78.0.1
STUN_B=45.78.0.2
PLAIN_A=45.78.0.3
PLAIN_B=45.78.0.4
PEER_GW=45.79.0.1
PEER=45.79.0.2
NAMESPACES=(host rtr inet peer)
SCENARIOS=(public public-forward nat1 nat2 nat3 nat4 blocked likely upnp)
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
	public-forward) echo "a router forwards udp/$PORT and keeps the port, hairpin" ;;
	nat1) echo "static SNAT to :$NAT_PORT, DNAT from anyone, hairpin" ;;
	nat2) echo "static SNAT, DNAT only from IPs the host sent to" ;;
	nat3) echo "masquerade" ;;
	nat4) echo "masquerade fully-random" ;;
	blocked) echo "the router drops UDP" ;;
	likely) echo "nat1, with plain STUN servers only" ;;
	upnp) echo "masquerade, and a UPnP gateway that forwards leases, hairpin" ;;
	*) return 1 ;;
	esac
}

# The verdict and exit status natwg detect must give.
expect() {
	case $1 in
	public | public-forward | upnp) echo "supported (public)|0" ;;
	nat1) echo "supported (NAT1)|0" ;;
	nat2 | nat3 | nat4 | blocked) echo "unsupported|1" ;;
	likely) echo "likely|2" ;;
	esac
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
	nat1 | likely)
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
	nat3) echo "$masquerade" ;;
	upnp)
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
	local file=$1 text=$2 tries=50
	until grep -q "$text" "$file" 2>/dev/null; do
		tries=$((tries - 1))
		[ "$tries" -gt 0 ] || die "timed out waiting for \"$text\" in $file"
		sleep 0.1
	done
}

# Build SCENARIO: the internet with its STUN servers and the peer, and the
# host, behind the router unless the scenario gives it a public address.
up() {
	local scenario=$1 name
	teardown
	for name in "${NAMESPACES[@]}"; do
		if [ "$name" = rtr ] && [ "$scenario" = public ]; then
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
	ns inet python3 "$LAB/stun_server.py" --rfc5780 "$STUN_A" "$STUN_B" \
		--plain "$PLAIN_A" --plain "$PLAIN_B" >"$WORK/stun.log" 2>&1 &
	PIDS+=("$!")
	wait_for "$WORK/stun.log" listening
	if [ "$scenario" = public ]; then
		link host "$P-h0" "$PUBLIC_HOST/24" inet "$P-i0" "$INET_GW/24"
		ns host ip route add default via "$INET_GW"
		return
	fi
	link rtr "$P-r0" "$ROUTER_WAN/24" inet "$P-i0" "$INET_GW/24"
	link host "$P-h0" "$HOST_LAN/24" rtr "$P-r1" "$ROUTER_LAN/24"
	ns rtr ip route add default via "$INET_GW"
	ns host ip route add default via "$ROUTER_LAN"
	ns rtr sysctl -qw net.ipv4.ip_forward=1
	rules "$scenario" | ns rtr nft -f -
	if [ "$scenario" = upnp ]; then
		ns rtr python3 "$LAB/igd.py" --lan-ip "$ROUTER_LAN" --wan-ip "$ROUTER_WAN" \
			--wan-if "$P-r0" --table "$P" --log "$WORK/igd.log" >"$WORK/igd.out" 2>&1 &
		PIDS+=("$!")
		wait_for "$WORK/igd.out" "IGD on"
	fi
}

# natwg detect in the host namespace, as the user who ran sudo: it needs no
# root on Linux.
detect() {
	local scenario=$1 servers=()
	local as_user=()
	if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != root ]; then
		as_user=(runuser -u "$SUDO_USER" --)
	fi
	case $scenario in
	likely) servers=(--server "$PLAIN_A:3478" --server "$PLAIN_B:3478") ;;
	*) servers=(--server "$STUN_A:3478" --server "$PLAIN_A:3478") ;;
	esac
	local upnp=off
	[ "$scenario" = upnp ] && upnp=auto
	ns host "${as_user[@]}" "$NATWG" detect --config /nonexistent/config.json \
		--iface "$P-h0" --port "$PORT" --upnp "$upnp" --timeout-ms 300 --json "${servers[@]}"
}

# One row of the results table from the JSON of natwg detect.
row() {
	python3 -c '
import json, sys
scenario, description, code, path = sys.argv[1:5]
d = json.load(open(path))
answers = d["mapping"]["answers"]
endpoint = d["mapping"]["endpoint"] or ("(several)" if answers else "-")
print("| %s | %s | %s | %s | %s %s | %s | %s | %s |" % (
    scenario, description, d["summary"], code, d["mapping"]["behaviour"], endpoint,
    d["filtering"]["behaviour"], d["self_test"], d["upnp"]["state"]))
' "$@"
}

run_tests() {
	local scenario code failed=0 want summary rows=()
	[ "$#" -gt 0 ] || set -- "${SCENARIOS[@]}"
	command -v "$NATWG" >/dev/null || [ -x "$NATWG" ] || die "no natwg at $NATWG; set NATWG"
	for scenario in "$@"; do
		describe "$scenario" >/dev/null || die "no scenario $scenario"
		up "$scenario"
		code=0
		detect "$scenario" >"$WORK/$scenario.json" || code=$?
		want=$(expect "$scenario")
		summary=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["summary"])' \
			"$WORK/$scenario.json" 2>/dev/null || echo "no JSON")
		if [ "$summary|$code" != "$want" ]; then
			echo "FAIL $scenario: got $summary, exit $code; want ${want%|*}, exit ${want#*|}" >&2
			cat "$WORK/$scenario.json" >&2 || true
			failed=1
		elif [ "$scenario" = upnp ] && ! check_lease_gone; then
			failed=1
		else
			echo "ok   $scenario: $summary, exit $code" >&2
		fi
		rows+=("$(row "$scenario" "$(describe "$scenario")" "$code" "$WORK/$scenario.json" 2>/dev/null ||
			echo "| $scenario | $(describe "$scenario") | no JSON | $code | | | | |")")
		teardown
	done
	echo "| scenario | network | verdict | exit | mapping | filtering | self test | UPnP |"
	echo "|---|---|---|---|---|---|---|---|"
	printf '%s\n' "${rows[@]}"
	return "$failed"
}

# natwg leased the port on the gateway and deleted the lease afterwards.
check_lease_gone() {
	local log=$WORK/igd.log
	if ! grep -q "^AddPortMapping $PORT$" "$log" || ! grep -q "^DeletePortMapping $PORT$" "$log"; then
		echo "FAIL upnp: natwg did not lease and release udp/$PORT:" >&2
		cat "$log" >&2
		return 1
	fi
	if ns rtr nft list chain ip "$P" upnp_pre | grep -q dnat; then
		echo "FAIL upnp: the gateway still forwards a port after natwg detect" >&2
		return 1
	fi
}

main() {
	local command=${1:-test}
	case $command in
	list)
		for command in "${SCENARIOS[@]}"; do
			printf '%-15s %s\n' "$command" "$(describe "$command")"
		done
		return
		;;
	-h | --help | help) usage ;;
	esac
	[ "$(id -u)" -eq 0 ] || die "run it as root: sudo $0 $*"
	command -v nft >/dev/null || die "nft is missing"
	WORK=$(mktemp -d "${TMPDIR:-/tmp}/$P.XXXXXX")
	case $command in
	up)
		[ "$#" -eq 2 ] || usage
		describe "$2" >/dev/null || die "no scenario $2"
		up "$2"
		# The processes keep running after this script exits.
		PIDS=()
		echo "scenario $2 is up; logs in $WORK; run commands with ip netns exec $P-host ..." >&2
		;;
	down)
		teardown
		pkill -f "$LAB/stun_server.py" 2>/dev/null || true
		pkill -f "$LAB/igd.py" 2>/dev/null || true
		rm -rf "$WORK"
		;;
	test)
		# With no arguments, "test" is only the default.
		[ "$#" -eq 0 ] || shift
		trap 'teardown; rm -rf "$WORK"' EXIT
		run_tests "$@"
		;;
	*)
		trap 'teardown; rm -rf "$WORK"' EXIT
		run_tests "$@"
		;;
	esac
}

main "$@"
