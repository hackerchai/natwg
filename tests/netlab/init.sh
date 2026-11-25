#!/usr/bin/env bash
# Run the first-time setup CLI against isolated STUN, DNS, Cloudflare and UPnP.
# sudo NATWG=/absolute/path/to/debug/natwg tests/netlab/init.sh [SCENARIO...]
set -euo pipefail
# shellcheck source-path=SCRIPTDIR
# shellcheck source=export.sh
. "$(dirname "${BASH_SOURCE[0]}")/export.sh"

# A private mount namespace for every invocation keeps the real OS paths and
# service-manager socket out of the test, including on an unexpected install.
isolated() {
	local where=$1
	shift
	# The inner shell expands its own positional arguments after unshare.
	# shellcheck disable=SC2016
	ns "$where" unshare -m --propagation private bash -ec '
		work=$1; shift
		mount -t tmpfs -o mode=0755 tmpfs /run
		mkdir /run/natwg
		mount --bind "$work/runtime" /run/natwg
		mount --bind "$work/platform-wg" /etc/wireguard
		mount -t tmpfs -o mode=0755 tmpfs /etc/systemd/system
		mount -t tmpfs -o mode=0755 tmpfs /usr/local
		mount --bind "$work/systemctl" /usr/bin/systemctl
		exec "$@"
	' _ "$WORK" "$@"
}

initialize() {
	local args=() target
	for target in $(servers "$SCENARIO"); do
		args+=(--server "$target")
	done
	isolated host "$NATWG" init --config "$WORK/server.json" --yes --iface "$P-h0" \
		--dns "$DNS" --zone "$ZONE" --record "$NAME" --token-file "$WORK/token" "${args[@]}" "$@" \
		</dev/null >"$WORK/stdout" 2>"$WORK/init.log"
}

refused() {
	local reason=$1
	shift
	if initialize "$@"; then die "unexpected init success ($reason)"; fi
	grep -qF -- "$reason" "$WORK/init.log"
}

private() {
	local f
	for f in "$@"; do [[ $(stat -c '%u:%a' "$f") = 0:600 ]]; done
}

run_daemon() {
	local where=$1 role=$2
	isolated "$where" "$NATWG" --config "$WORK/$role.json" "$role" --foreground >"$WORK/$role.log" 2>&1 &
	PIDS+=("$!")
}

client_traffic() {
	local endpoint=$1 lan=$2 started
	started=$(date +%s)
	run_daemon peer client
	wait_until 35 handshake_since "$started"
	status_is client endpoint "$endpoint"
	pings "$TUNNEL_IP"
	pings "$lan"
	echo "$SCENARIO: handshake $(field "$WORK/client.status.json" server.last_handshake), tunnel $TUNNEL_IP and LAN $lan via $endpoint"
}

daemon_init() {
	local mode=txt ip=$ROUTER_WAN port=$NAT_PORT lan=$ROUTER_LAN args=()
	case $SCENARIO in
	public) mode=a ip=$PUBLIC_HOST port=$PORT lan=$LAN_HOST; args+=(--lan "$LAN_NET") ;;
	upnp) mode=a port=$PORT ;;
	public-forward) port=$PORT ;;
	esac
	extras "$SCENARIO"
	if [[ $mode = txt ]]; then
		refused 'needs a confirmed public IP' --mode wireguard --wg-dir "$WORK/wg"
		[[ ! -e $WORK/server.json && ! -e $WORK/wg ]]
	fi
	if [[ $SCENARIO = nat1 ]]; then
		# Fresh install. There is no TXT to snapshot until the new server runs.
		refused INIT_PEER_RECOVERY --peer laptop --format surge --out "$WORK/surge.conf"
		local recovery
		recovery=$(sed -n 's/^First peer recovery file \(.*\) (0600).*/\1/p' "$WORK/init.log")
		private "$WORK/server.json" "$recovery"
		[[ ! -e $WORK/surge.conf ]]
		mv "$recovery" "$WORK/client.json"
	else
		initialize --peer laptop --out "$WORK/client.json" "${args[@]}"
		[[ -z $(find "$WORK" -name '.natwg-pending-*' -print -quit) ]]
	fi
	private "$WORK/server.json" "$WORK/client.json"
	"$NATWG" config show --config "$WORK/server.json" >"$WORK/redacted"
	! grep -qF "$TOKEN" "$WORK/redacted" "$WORK/init.log" "$WORK/stdout" || die "token leaked"
	[[ ! -s $WORK/stdout && ! -e $WORK/systemctl.called ]]
	local publish
	publish=$(field "$WORK/server.json" role.server.publish)
	[[ ${publish:-txt} = "$mode" ]]
	if [[ $mode = txt ]]; then
		is_field client.json role.client.record "$NAME"
	else
		is_field client.json role.client.server "$NAME:$PORT"
	fi
	if [[ $SCENARIO = upnp ]]; then
		is_field server.json role.server.upnp.control_url "http://$ROUTER_LAN:5000/ctl"
	fi
	if [[ $SCENARIO = likely ]]; then grep -qF 'Connect a first client' "$WORK/init.log"; fi
	run_daemon host server
	if [[ $mode = a ]]; then
		wait_until 35 api_logged "^POST A $NAME $ip$"
	else
		wait_until 35 api_logged "^POST TXT $NAME .*$ip:$port" # fake API logs TXT with quotes
	fi
	client_traffic "$ip:$port" "$lan"
	if [[ $SCENARIO = nat1 ]]; then
		isolated peer "$NATWG" config export --config "$WORK/client.json" --format surge --out "$WORK/surge.conf"
		private "$WORK/surge.conf"
		grep -Fq "endpoint = $ip:$port" "$WORK/surge.conf"
	fi
}

native_init() {
	local lan=$LAN_HOST ip=$PUBLIC_HOST wg=$WORK/platform-wg args=(--lan "$LAN_NET")
	if [[ $SCENARIO = upnp ]]; then ip=$ROUTER_WAN lan=$ROUTER_LAN wg=$WORK/wg; args=(--wg-dir "$wg"); fi
	extras "$SCENARIO" --record "$NAME=A:$ip"
	initialize --mode wireguard --peer mobile --format clash --out "$WORK/mobile.yaml" "${args[@]}"
	private "$WORK/server.json" "$wg/natwg.conf" "$wg/natwg-client.conf" "$WORK/mobile.yaml"
	grep -Fq "server: \"$NAME\"" "$WORK/mobile.yaml"
	grep -qF 'DNS-only A record' "$WORK/init.log"
	if [[ $SCENARIO = upnp ]]; then
		grep -qF 'independent UPnP lease renewer' "$WORK/init.log"
		# Native WireGuard relies on an independently maintained router forward.
		ns rtr nft add rule ip "$P" upnp_pre udp dport "$PORT" dnat to "$HOST_LAN:$PORT"
		ns rtr nft add rule ip "$P" upnp_post ip saddr "$HOST_LAN" udp sport "$PORT" snat to "$ROUTER_WAN:$PORT"
	fi
	[[ ! -e $WORK/systemctl.called ]]
	ln "$wg/natwg-client.conf" "$WORK/mobile.conf"
	ns host wg-quick up "$wg/natwg.conf"
	local started
	started=$(date +%s)
	client_up
	traffic "$lan" "$ip:$PORT" "$started"
	ns peer wg-quick down "$WORK/mobile.conf"
	ns host wg-quick down "$wg/natwg.conf"
	nothing_written
}

# A stand-in for systemctl inside the masked OS paths starts the installed
# binary in the server namespace. The unit, binary, PID and logs are private.
service_init() {
	# This name still holds an old endpoint when the installer starts.
	extras upnp --record "$NAME=TXT:$ROUTER_WAN:55555"
	cat >"$WORK/systemctl" <<'MANAGER'
#!/bin/sh
set -eu
run=/run/natwg
printf '%s\n' "$*" >>"$run/systemctl.called"
case $1 in
show)
	if [ -s "$run/pid" ]; then
		printf 'LoadState=loaded\nActiveState=active\nMainPID=%s\n' "$(cat "$run/pid")"
	else
		echo LoadState=not-found
	fi ;;
daemon-reload) ;;
enable)
	config=$(cat "$run/config-path")
	grep -Fq "$config" /etc/systemd/system/natwg.service
	NATWG_UPDATE_CHECK=off NATWG_CLOUDFLARE_API=http://45.78.0.80/client/v4 \
		/usr/local/libexec/natwg/natwg --config "$config" daemon </dev/null >"$run/daemon.log" 2>&1 &
	echo "$!" >"$run/pid" ;;
*) exit 1 ;;
esac
MANAGER
	printf '%s\n' "$WORK/server.json" >"$WORK/runtime/config-path"
	initialize --install-service --peer mobile --format wg-quick --out "$WORK/mobile.conf"
	grep -Fxq 'enable --now natwg.service' "$WORK/runtime/systemctl.called"
	grep -Fq "Endpoint = $ROUTER_WAN:$NAT_PORT" "$WORK/mobile.conf"
	private "$WORK/server.json" "$WORK/mobile.conf"
	local started
	started=$(date +%s)
	client_up
	traffic "$ROUTER_LAN" "$ROUTER_WAN:$NAT_PORT" "$started"
	ns peer wg-quick down "$WORK/mobile.conf"
}

cli_checks() {
	isolated host python3 "$LAB/init_tty.py" "$NATWG" "$WORK"
	private "$WORK/server.json"
	[[ ! -e $WORK/systemctl.called ]]
	# Existing and aliased outputs, missing credentials, and an unsafe
	# credential file must leave the prior server identity intact.
	local before
	before=$(sha256sum "$WORK/server.json")
	refused CONFIG_EXISTS
	refused 'overlaps another' --force --peer test --out "$WORK/server.json"
	chmod 644 "$WORK/token"
	refused CONFIG_UNSAFE --force
	chmod 600 "$WORK/token"
	[[ $(sha256sum "$WORK/server.json") = "$before" ]]
	if isolated host "$NATWG" init --config "$WORK/new/server.json" --iface "$P-h0" \
		--server "$STUN_A:3478" --zone "$ZONE" --record "$NAME" </dev/null \
		>"$WORK/stdout" 2>"$WORK/init.log"; then die "accepted missing token"; fi
	grep -Fq -- 'missing --token-file' "$WORK/init.log"
	[[ ! -e $WORK/new ]]
	initialize --force --no-lan
	[[ $(sha256sum "$WORK/server.json") != "$before" ]]
	is_field server.json role.server.lan '[]'
	echo "TTY defaults, hidden token, Ctrl-C, multiple LANs, no-TTY input errors, --force and file permissions passed"
}

negative() {
	case $SCENARIO in
	blocked) refused 'unsupported' --force --peer unused ;;
	lan-stun) refused 'inconclusive' --force ;;
	public)
		ns host python3 -c 'import socket,time,sys; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(("",int(sys.argv[1]))); print("bound",flush=True); time.sleep(120)' "$PORT" >"$WORK/holder.log" &
		PIDS+=("$!")
		wait_for "$WORK/holder.log" bound 50
		refused INIT_PORT_IN_USE --force
		;;
	esac
	[[ ! -s $WORK/stdout && ! -e $WORK/server.json && ! -e $WORK/systemctl.called ]]
	[[ -z $(find "$WORK" -name '.natwg-pending-*' -print -quit) ]]
	echo "$SCENARIO: refused before writing or installing"
}

[[ $(id -u) = 0 ]] || die "run as root in the disposable Linux VM"
NATWG=$(realpath "$NATWG")
export NATWG_UPDATE_CHECK=off
umask 077
down
base=$(mktemp -d "${TMPDIR:-/tmp}/$P.XXXXXX")
echo "$base" >"$STATE"
# The service installer copies its current executable. Keep that inode
# available if the operator also runs cargo test in the shared target.
install -m 755 "$NATWG" "$base/natwg"
NATWG=$base/natwg
cleanup() {
	local code=$?
	if [[ $code != 0 ]]; then
		echo "FAIL ${scenario:-setup}" >&2
		tail -n 12 "$WORK/init.log" "$WORK/runtime/daemon.log" >&2 2>/dev/null || true
	fi
	stop_daemons
	down
}
trap cleanup EXIT
[[ $# -gt 0 ]] || set -- public upnp nat1 public-forward likely native-public native-upnp service cli blocked lan-stun occupied
for scenario in "$@"; do
	WORK=$base/$scenario
	mkdir -p "$WORK/runtime" "$WORK/platform-wg"
	ln -s "$WORK/runtime/client.status.json" "$WORK/client.status.json"
	printf '%s\n' "$TOKEN" >"$WORK/token"
	printf '#!/bin/sh\necho called >>"%s/systemctl.called"\nexit 1\n' "$WORK" >"$WORK/systemctl"
	chmod 700 "$WORK/systemctl"
	SCENARIO=${scenario#native-}
	case $scenario in occupied | cli) SCENARIO=public ;; service) SCENARIO=nat1 ;; esac
	up "$SCENARIO"
	case $scenario in
	native-*) native_init ;;
	service) service_init ;;
	cli) cli_checks ;;
	blocked | lan-stun | occupied) negative ;;
	*) daemon_init ;;
	esac
	stop_daemons
	echo "PASS $scenario"
done
