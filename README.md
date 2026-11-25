# natwg

natwg runs a WireGuard server on a host that sits behind carrier-grade NAT, so a
laptop elsewhere can reach the home LAN. It needs no relay and no port on a VPS.

The server keeps one UDP socket on the WAN interface. The socket carries both
STUN and WireGuard, so the public mapping that STUN reports is the one that
WireGuard peers reach. natwg then:

- refreshes that mapping with a STUN keepalive every 25 seconds;
- publishes it as a Cloudflare DNS TXT record (`"ip:port"`), which the client
  reads to find the server, or, on a network with a public IP, publishes that
  IP as an A record ([public mode](#public-mode-an-a-record));
- leases the port on the home router through UPnP;
- routes the tunnel subnet and NATs it to each LAN (pf on macOS, nftables on
  Linux);
- writes a status file, and rebuilds the tunnel when STUN stops answering.

The same binary is the client. `natwg client` keeps a tunnel to the server,
reads the TXT record (or the A record) every 60 seconds and follows the
server when its endpoint changes.

WireGuard runs inside the process through
[gotatun](https://crates.io/crates/gotatun), so it needs no wireguard-go or
wg-quick. natwg supports macOS and Linux.

## Install

```sh
curl -fsSL https://natwg-dl.hackerchai.com/install.sh | bash
```

The installer reads the newest release from the download site, downloads the
archive for this OS and CPU, checks it against the SHA-256 in the release
manifest, checks that the binary runs and reports that version, and puts it
at `/usr/local/bin/natwg`, through sudo when that directory is not writable.
It is [`scripts/install-latest.sh`](scripts/install-latest.sh); read it first
if you like (`curl -fsSL https://natwg-dl.hackerchai.com/install.sh | less`).
Three variables change what it does:

```sh
curl -fsSL https://natwg-dl.hackerchai.com/install.sh | NATWG_VERSION=0.3.0 bash     # this version
curl -fsSL https://natwg-dl.hackerchai.com/install.sh | NATWG_INSTALL_DIR=$HOME/.local/bin bash
curl -fsSL https://natwg-dl.hackerchai.com/install.sh | NATWG_DOWNLOAD_URL=https://mirror.example bash
```

Running it again installs the newest release over the old one. For a natwg
that runs as a service, `sudo natwg update` (see [Update](#update)) also
updates the service's own copy and restarts it.

Each release has a binary archive for macOS (Apple silicon and Intel) and for
Linux (arm64 and x86_64, static musl builds) on the download site
`https://natwg-dl.hackerchai.com`. To install one by hand:

```sh
site=https://natwg-dl.hackerchai.com
version=$(curl -fsSL "$site/latest/natwg-update.json" | sed -n 's/.*"version": "\([^"]*\)".*/\1/p')
target=aarch64-apple-darwin   # x86_64-apple-darwin, aarch64-unknown-linux-musl, x86_64-unknown-linux-musl
curl -fLO "$site/v$version/natwg-$version-$target.tar.gz"
curl -fLO "$site/v$version/natwg-$version-$target.tar.gz.sha256"
shasum -a 256 -c "natwg-$version-$target.tar.gz.sha256"   # sha256sum -c on Linux
tar -xzf "natwg-$version-$target.tar.gz"
sudo "./natwg-$version-$target/install.sh"
```

`latest/natwg-update.json` names the newest version and the SHA-256 of each
of its archives, and the files under `v<version>/` never change. The
archive's own `install.sh` checks the files of the archive against its `SHA256SUMS` and copies `natwg`
to `/usr/local/bin`; `NATWG_INSTALL_DIR` picks another directory. The GitHub
Releases of `hackerchai/natwg` carry the same archives.

With Rust 1.99 or newer, cargo builds natwg from crates.io instead:

```sh
cargo install natwg --locked
```

## Check the network

natwg works only where a client whose address it cannot know in advance
reaches the server's UDP port. Two kinds of network allow that:

- **Public:** the host holds a public IPv4 address, or a router that holds
  one forwards the port to the host (by UPnP or by hand), and the port stays
  the listen port.
- **NAT1 (full cone):** the NAT gives the socket one public address and port
  whatever the destination (endpoint-independent mapping), and lets anyone in
  through it (endpoint-independent filtering). the carrier's carrier-grade
  NAT does.

A restricted cone NAT (NAT2), a port-restricted cone NAT (NAT3), a symmetric
NAT (NAT4) and a network that blocks UDP cannot host natwg. `natwg detect`
tells them apart. It needs no root.

```sh
natwg detect          # the verdict and the evidence
natwg detect --json   # everything it found, for scripts
```

```text
uplink    : en6 10.73.0.4 (private)
port      : udp/51830 is in use, perhaps by a running natwg; tested udp/60408 instead, so the result leaves out any router lease of udp/51830
upnp      : leased udp/60408 on http://10.73.0.1:1900/ipc (WAN 100.64.0.42) for the test, deleted after it
mapping   : endpoint-independent, 203.0.113.7:6918 (3 answers)
filtering : endpoint-independent: 111.206.174.3:3478 (other 111.206.174.2:3479): change IP and port answered from 111.206.174.2:3479, change port answered from 111.206.174.3:3479
self test : a second socket got in through the mapping
verdict   : supported (NAT1)
```

| Verdict | Meaning | Exit |
|---|---|---|
| `supported (public)` | The endpoint is a public address with the tested port: the host's own address, or a router's that forwards the port. | 0 |
| `supported (NAT1)` | A full-cone NAT: one public endpoint for every destination, open to anyone. | 0 |
| `likely` | Nothing rules the network out, but a test could not run or its answers disagree. Either no RFC 5780 server answered the filtering test, so a firewall in front of a public address or a filtering NAT cannot be ruled out; or only one STUN server address answered; or one server's change answers contradict each other. A first client will tell. | 2 |
| `inconclusive` | Every STUN server that answered sits inside a NAT with the host (on its LAN, say) and saw a private address, so nothing about the public side is known. Use STUN servers on the internet. | 2 |
| `unsupported` | One line says why (`This network cannot host natwg: …`), and the next what would fix it: a public IPv4 address, NAT1 from the carrier, or a router that forwards the port. | 1 |

An error, such as a missing uplink, a port natwg cannot bind, or a signal,
exits 3.

`--json` prints the whole result, version 1 (`"schema": 1`), which
`natwg init` reads. An error prints `{"schema": 1, "error": {"code": …,
"message": …}}` instead. For a public network, `public_by` says how natwg
knows:

- `address`: the uplink holds the public address that STUN sees.
- `upnp`: the UPnP gateway forwards the tested port to this host and owns
  the address that STUN sees.
- `port_kept`: only STUN says so. It sees a public address that keeps the
  port, and anyone gets in, but no gateway confirmed a forward. A full-cone
  NAT that keeps the port looks the same, and its mapping lives only while
  traffic flows.

`natwg init` offers plain WireGuard mode, which needs a fixed endpoint, only
for `address` and `upnp`, and the server publishes an A record
([public mode](#public-mode-an-a-record)) only in those two cases too.

natwg runs every test through one UDP socket on the uplink, as the server
does:

- **The socket.** `--iface` picks the uplink (default: `role.server.iface` of
  the config when natwg can read it, else the interface `natwg client`
  would pick), and `--port` the port (default: `listen_port`, else 51830).
  A running natwg holds its port, so natwg detect then tests a free port and
  says so: the result leaves out the router's lease of the real port, and
  `natwg status` covers that one.
- **UPnP.** On an uplink with a private address, `--upnp auto` (the default)
  finds the router by SSDP and has it forward the tested port to this host
  for 120 s, as the server's lease would, then deletes that lease.
  - natwg follows only an SSDP answer from a host on the uplink's subnet
    that points at a device description on that same host, the default
    gateway first. The control URL must be on that host too. natwg follows
    no redirect and reads at most 64 KiB from the gateway.
  - Discovery takes at most about five seconds: two for SSDP answers, three
    for at most three device descriptions.
  - A mapping of the tested port that exists already stays as it is. So
    does any mapping when the gateway's answer about the port is unclear.
  - A gateway that takes only permanent leases is not used for the test.
  - SIGINT, SIGTERM and SIGHUP stop the tests and delete the lease first. A
    panic deletes it too. A process killed outright leaves the lease to
    expire after 120 s on a gateway that honours lease durations.
  - `--upnp off` skips all of this, as for a port forwarded by hand.
- **Filtering** (RFC 5780). An RFC 5780 STUN server reports its other IP and
  port (OTHER-ADDRESS, or CHANGED-ADDRESS from RFC 3489 servers), and natwg
  asks it to answer from there (CHANGE-REQUEST), then from its other port
  alone. An answer from the other IP means anyone gets in (NAT1); one from
  the other port alone, only addresses the host has sent to (NAT2); neither,
  only the exact addresses (NAT3). An answer from the other IP and port with
  none from the other port alone contradicts itself, and leaves the
  filtering unknown. These tests run first, because sending to an address
  opens a filtering NAT to it. A second server is asked when the first one
  shows filtering, since a server may not honour the request.
- **Mapping.** The RFC 5780 server's other IP and more STUN servers report
  the public endpoint of the socket. Two different endpoints mean NAT4. The
  host's own address and port means no NAT, when that address is public. A
  server that sees a private address sits inside a NAT with the host, and
  natwg leaves its answers out.
- **Self test.** A second socket sends to the endpoint, and the first waits.
  It gets in where the carrier hairpins and the NAT lets anyone in; when it
  does not get in, that proves nothing.

The built-in RFC 5780 servers answered both change tests from a the carrier
line in the test location in November 2026: `stun.miwifi.com` (Xiaomi, within 40 ms),
then `stun.easybell.de`, `stun.voipia.net`, `stun.m-online.net`,
`stun.vozelia.com` and `stun.voipbuster.com` (within 200 ms). The mapping
test also asks the servers that `natwg probe stun` uses. `--server HOST:PORT`
(repeatable) replaces both lists, `--dns` picks the resolver for their names,
and `--timeout-ms` how long each request waits before it is sent again.

- **macOS:** macOS Local Network privacy keeps a program off the LAN unless
  it runs from Terminal, over SSH or as root, or the app that runs it has
  Local Network access (System Settings > Privacy & Security > Local
  Network). Without it, the UPnP step fails with "No route to host", and
  natwg detect says so.
- **Linux:** natwg binds its sockets to the uplink with `SO_BINDTOIFINDEX`.
  Linux 5.7 and newer need no root for that. Linux 5.0 to 5.6 need root
  (CAP_NET_RAW). Older kernels lack it and fail even as root.

`tests/netlab` proves each verdict in Linux network namespaces: a public
host with and without a firewall, a forwarded port, NAT1 to NAT4, blocked
UDP, a STUN server on the LAN, servers that misbehave, and UPnP gateways
that forward, refuse, lie or stall. See [its README](tests/netlab/README.md).

## Run the server

Write a server config to `/usr/local/etc/natwg/config.json` (`/etc/natwg/config.json`
on Linux), owned by root with mode 0600. `natwg keys gen` prints a key pair, and
`natwg config show` prints the loaded config with its secrets redacted.

```sh
sudo natwg service install   # a LaunchDaemon on macOS, a systemd unit on Linux
natwg status                 # the mapping, the TXT or A record, NAT and UPnP
natwg service status
sudo natwg doctor loopback   # ping the tunnel and the LAN through a test peer
```

`natwg server --foreground` runs the same server in the terminal.
`natwg probe stun|dns|txt|uplink` asks STUN and DNS servers through one
interface without the server, and prints the uplink a client would pick.
Run `natwg detect` first (see [Check the network](#check-the-network)).

### Public mode: an A record

On a network with a public IPv4 address, the server can publish that address
as a Cloudflare A record instead of a TXT record. Clients, Surge and Clash
then dial `name:listen_port`, as with any dynamic DNS name. Set
`role.server.publish` to `"a"`, and `cloudflare.record` names the A record:

```json
"role": { "server": {
  "iface": "eth0",
  "listen_port": 51830,
  "lan": ["10.73.0.0/24"],
  "publish": "a",
  "cloudflare": { "zone": "example.com", "record": "home.example.com", "token": "<token>" }
}}
```

`publish` defaults to `"txt"`, the TXT record of the mapping, and a config
without it works as before. With `"a"`, `cloudflare.record` must be a host
name that clients can dial: letters, digits and hyphens, two labels or more,
and no trailing dot (so no `_wg-home…`). Use public mode only where `natwg detect` says
`supported (public)` with `public_by` `address` or `upnp`. natwg publishes an
IP only when it confirms the IP itself, which it can do in two cases:

- **`address`:** the uplink's own address is public. natwg reads it every 10
  seconds and needs no STUN for it, so `role.server.stun` may go.
- **`upnp`:** a router holds the public IP and forwards the listen port, and
  natwg confirms all of it: the UPnP lease of the listen port
  (`role.server.upnp`) works, the router's WAN address (GetExternalIPAddress)
  is the IP that STUN sees, and the STUN mapping keeps the listen port. This
  needs `stun` and `upnp`.

Every other network uses TXT. natwg publishes no A record for:

- **`port_kept`:** STUN sees a public IP that keeps the listen port, but no
  UPnP gateway confirms a router. A carrier NAT that keeps the port looks the
  same, and it can hand out another port later, which would leave the name
  pointing at the wrong port. A port forwarded by hand looks the same too:
  forward it through UPnP, or publish TXT.
- a mapping whose port is not the listen port, as on a NAT1 network;
- a router whose WAN address is not the IP that STUN sees, because another
  NAT sits in front of it;
- a private uplink without STUN.

When natwg cannot confirm the IP, at start or later (when the ISP takes the
public address away, say), it leaves the A record as it is. It never writes
an IP it cannot confirm, not even one it confirmed a moment before and failed
to write, and it does not fall back to TXT. `natwg status` shows what the
record holds, says why natwg leaves it, and exits 1 with `no public IP`. To move such a server to TXT,
remove `publish` (or set `"txt"`), give it `stun`, and give each client a
`record` in place of its `server`.

`natwg status` shows the mode, the name and the IP:

```text
public IP       : 45.77.0.10 by address
published A     : home.example.com = 45.77.0.10 (3s ago), clients dial home.example.com:51830
last STUN reply : off (no role.server.stun)
upnp/nat        : off / ok
```

The A record has a TTL of 60 seconds, and natwg never has Cloudflare proxy
it: Cloudflare's proxy carries no WireGuard. natwg reads every record of the
name at start and every 5 minutes.

- An A record that holds the IP but is proxied, or has another TTL, natwg
  writes again. The Cloudflare dashboard creates A records proxied.
- More A records than the one natwg keeps, or an AAAA record, are a problem
  that `natwg status` names, with exit 1: clients may dial them, and natwg is
  IPv4-only. Delete them in Cloudflare; natwg never deletes a record.

`natwg peer add` gives a client of such a server
`"server": "home.example.com:51830"` in place of a `record`.

`NATWG_CLOUDFLARE_API` is for tests only. It sends the server's Cloudflare
calls, token and all, to another API base URL, and only a debug build
honours it; a release build ignores it and logs a warning. The network lab
points it at its fake API.

### Add a client

```sh
sudo natwg peer add phone --out phone.json   # fresh keys, the next free address
sudo natwg peer list
sudo natwg peer remove phone
sudo natwg service restart                   # the running server loads the change
```

`peer add` writes the server config in one step and prints the new client's
config, or writes it to `--out` readable only by its owner. That file holds the
client's private key, so move it to the client privately. The new client routes
the tunnel subnet and every LAN of the server.

### Export WireGuard, Surge and Clash clients

Give **each device or app its own peer**. A natwg laptop, a phone running
Surge and a tablet running Clash each need a different private key and
tunnel address. Reusing one identity on two devices makes the server send
traffic to whichever device handshook last.

```sh
sudo natwg peer add laptop --out laptop.json
sudo natwg peer add phone --format surge --out phone.conf
sudo natwg peer add tablet --format clash --out tablet.yaml
sudo natwg peer add travel --format wg-quick --out travel.conf
sudo natwg service restart
```

The default format, `natwg`, is the client JSON with DNS discovery intact.
`peer add` is the one time the server can deliver the new device's private
key. Use `--out` to write a mode **0600** file and transfer it privately.
Without `--out`, the private key goes to stdout. Shell redirection uses your
shell's file permissions. Existing files require `--force`.

To refresh or convert the same device later, keep its natwg client JSON in
private storage. For example, issue a phone as JSON and export its Surge
profile from that file:

```sh
sudo natwg peer add roaming-phone --out roaming-phone.json
sudo natwg config export --config roaming-phone.json --format surge --out roaming-phone.conf
# After the server's NAT mapping changes:
sudo natwg config export --config roaming-phone.json --format surge --out roaming-phone.conf --force
```

- **Public mode** keeps the configured hostname and port, such as
  `home.example.com:51830`. A client with only a static endpoint keeps its
  IPv4 address and port.
- **NAT1** needs a running natwg server to maintain and publish the mapping.
  wg-quick, Surge and mihomo receive a timestamped snapshot of the current
  TXT answer. Re-export the device's client JSON when the mapping changes.
  A direct `peer add --format surge|clash|wg-quick` also takes a snapshot.
  If that exported profile is your only copy, retain its keys and update
  the endpoint from the TXT name in its first comment. Run
  `dig +short TXT <record-name>` and use the returned `IPv4:port` for
  wg-quick’s `Endpoint` or Surge’s peer `endpoint`. In mihomo, put the IPv4
  address in `server` and the number in `port`. Reload the profile.
  For 24 hours after first seeing
  a mapping, `natwg status` shows the UTC cutoff for older snapshots. A
  server restart starts that observation period again.
- **Surge and Clash (mihomo)** route the tunnel subnet and configured LANs
  to WireGuard. Other traffic uses the final direct rule. To add the export
  to an existing profile, merge the proxy and WireGuard settings and place
  the exported IP-CIDR rules before broader rules. Keep your existing final
  rule. Surge accepts tunnel MTUs from 576 to 1420. See the
  [Surge WireGuard manual](https://manual.nssurge.com/policies/wireguard.html)
  and [mihomo WireGuard reference](https://wiki.metacubex.one/en/config/proxies/wg/).

### Export a plain WireGuard server

On the intended server OS, export a public-mode server config
(`role.server.publish = "a"`) after adding its devices:

```sh
sudo natwg config export --config server.json --format wg-quick --out home.conf
sudo wg-quick up ./home.conf
sudo wg-quick down ./home.conf
```

Use a reachable fixed UDP port. Arrange DNS and any router port forwarding
separately while running plain WireGuard. Stop any natwg instance serving
this port and subnet before bringing up wg-quick. The export contains the
server's private key and the public identity of every configured peer,
including the doctor if configured. Re-export after changing the peer list.

The hooks enable IPv4 forwarding and apply source NAT to the listed LANs
through the configured uplink. Linux needs nftables and creates the
`inet natwg_wgquick_<instance>` table. macOS uses the `com.apple/<instance>` pf anchor and
holds a pf enable reference while the tunnel is up. Teardown removes the
exported rules and leaves system IP forwarding enabled. An occupied
nftables table or an occupied pf NAT anchor stops setup. If someone changes
its rules while the tunnel is up, teardown reports the conflict.

### Choose the tunnel subnet and the LANs

The server's `interface.address` is its tunnel address, and the prefix sets the
tunnel subnet: `10.66.66.1/24` serves 10.66.66.0/24. `role.server.lan` lists
the networks behind `role.server.iface` that clients reach:

```json
"interface": { "address": "10.66.66.1/24", "mtu": 1380 },
"role": { "server": {
  "iface": "en6",
  "lan": ["10.73.0.0/24", "192.168.50.0/24"],
  ...
}}
```

- natwg NATs the tunnel subnet into each LAN out of `role.server.iface`, so LAN
  hosts answer clients without a route back to the tunnel.
- A LAN may not overlap the tunnel subnet or another LAN, and `0.0.0.0/0` is
  not a LAN.
- An empty list (`"lan": []`) serves the tunnel only. natwg then loads no NAT
  rule, `natwg status` shows NAT as off, and `doctor loopback` pings only the
  server's tunnel address. With LANs, the doctor also pings the first host of
  the first LAN. natwg turns IP forwarding on either way, so clients reach each
  other through the server.
- A server without a LAN refuses to start while its pf anchor or nftables
  table still holds a rule, such as one a killed server left behind for a LAN
  that is gone. Empty it first (`pfctl -a com.apple/<instance> -F all`, or
  `nft delete table inet <instance>`).
- natwg 0.2 wrote one LAN as a string (`"lan": "10.73.0.0/24"`). That form
  still loads, and natwg writes the list form from then on, which natwg 0.2
  cannot read: going back to 0.2 takes the LAN back to a single string by
  hand.

`natwg config set` changes these settings in `--config`. It validates the
result, replaces the file in one step, readable only by its owner, and prints
what changed. `--dry-run` prints the redacted result and writes nothing.

```sh
sudo natwg config set lan 10.73.0.0/24 192.168.50.0/24   # server; no network clears the list
sudo natwg config set address 10.66.70.1/24              # server or client
sudo natwg config set allowed-ips 10.66.70.0/24 10.73.0.0/24 192.168.50.0/24   # client
sudo natwg service restart                               # load the change
```

A server whose new subnet holds the old one, or sits inside it, keeps every
peer and its doctor where they are: growing 10.66.66.1/24 to 10.66.66.1/16
moves nobody, and shrinking it to 10.66.66.129/25 keeps 10.66.66.130. A server
that moves to a subnet apart from the old one moves its peers and its doctor
along. Each keeps its host offset, so 10.66.66.2 becomes 10.66.70.2, and natwg
prints each old and new address. Each moved client must then take its new
address and route the new subnet: on the client, run
`natwg config set address 10.66.70.2/32` and `natwg config set allowed-ips`
with the new subnet and the LANs.

natwg refuses the change and writes nothing when a peer or the doctor does not
fit in the new subnet, when one would land on the server's new address, when
a network that a peer routes beyond the tunnel overlaps the new subnet, or
when the server address is the network or broadcast address of its subnet.

A client routes only its own `allowed_ips`. After `config set lan` on the
server, give each client the new set with `config set allowed-ips`.

## Run the client

The client config has the client role and exactly one peer, the server:

```json
{
  "version": 1,
  "private_key": "<client private key>",
  "interface": { "address": "10.66.66.2/32", "mtu": 1380 },
  "peers": [{
    "name": "server",
    "public_key": "<server public key>",
    "preshared_key": "<preshared key>",
    "allowed_ips": ["10.66.66.0/24", "10.73.0.0/24"],
    "keepalive": 25
  }],
  "role": { "client": {
    "record": "_wg-home.example.com",
    "resolvers": ["223.5.5.5", "119.29.29.29", "1.1.1.1", "8.8.8.8"]
  }}
}
```

- `record` is the TXT record the server publishes. The client asks the
  `resolvers` in order and takes the first well-formed `"ip:port"`. It keeps the
  last endpoint when no resolver gives one. `resolvers` defaults to the list
  above.
- `server` (`"home.example.com:51830"`) takes the place of `record` for a
  server in [public mode](#public-mode-an-a-record). The client asks the
  `resolvers` for the A record of the name, the same way and as often, dials
  the first public address at the port, and keeps the last endpoint when no
  resolver gives one. A config has `record` or `server`, not both.
  - The name is a host name of two labels or more from letters, digits and
    hyphens, without a trailing dot, and the port has plain digits from 1 to
    65535.
  - The server publishes only public IPs, so the client takes only a public
    address. A private, loopback or carrier-grade NAT address, or one of
    198.18.0.0/15, which the fake-IP DNS of Surge and Clash hands out, counts
    as a failed lookup, and `natwg status` says which address came back.
- Without either, the client dials `peers[0].endpoint` (`"ip:port"`).
- The client routes each of `allowed_ips` into its tunnel and refuses to start
  when another interface holds the tunnel address or one of those routes. A
  default route (`0.0.0.0/0`) is not supported.
- The WireGuard and DNS traffic leaves through the physical interface of the
  default route, past a VPN app such as Surge that owns the default route.
  `role.client.iface` pins an interface instead. The client follows a new
  uplink (Wi-Fi, a hotspot) and a wake from sleep within seconds.
- `keepalive` defaults to 25 seconds for a client; 0 turns it off.
- `role.client.status_file` moves the status file.

```sh
sudo natwg client --foreground   # in the terminal
sudo natwg service install       # com.hackerchai.natwg.client / natwg-client.service
natwg status                     # endpoint, handshake age, traffic
```

`natwg status` exits 1 when the client has no tunnel, no endpoint, a failing
TXT or A lookup, or no handshake for longer than a session can live, 235
seconds with the default keepalive.

### Move a wg-quick client to natwg

The client keeps its keys and its tunnel address, so the server needs no
change.

The wg-quick config is `/opt/homebrew/etc/wireguard/wg-home.conf` with
Homebrew on macOS, and `/etc/wireguard/wg-home.conf` on Linux.

```sh
conf=/opt/homebrew/etc/wireguard/wg-home.conf
sudo natwg config import-wg-quick "$conf" \
  --record _wg-home.example.com --dry-run          # check the redacted result
sudo natwg config import-wg-quick "$conf" \
  --record _wg-home.example.com                    # writes --config
# wg-quick down frees the address and the routes. If the install refuses,
# wg-quick comes back up.
sudo wg-quick down "$conf" && { sudo natwg service install || sudo wg-quick up "$conf"; }
natwg status
```

A client on one of the server's networks, such as a laptop at home on the
LAN that the server routes, leaves that network out of its routes and reaches
it directly. It routes the network again once the host leaves it.

The import takes one `[Peer]`, reads wg-quick's `Endpoint = 0.0.0.0:0`
placeholder as no endpoint, and refuses keys natwg does not run, such as `DNS`
or `PostUp`. Once `natwg status` shows a recent handshake, remove the TXT
updater job and the wg-quick config.

## Update

```sh
natwg update --check   # the installed and the latest version; needs no root
sudo natwg update      # install the latest release and restart the services
```

`natwg update` downloads the archive of this platform from the download site,
and from the GitHub Releases of `hackerchai/natwg` when the site fails. It
checks the archive against the SHA-256 that the release's manifest names and
runs the new binary's `--version` before it replaces anything. Then it:

- replaces the service binary `/usr/local/libexec/natwg/natwg` and the natwg
  you ran, such as `/usr/local/bin/natwg` or `~/.cargo/bin/natwg`, each in one
  step with its owner and mode, so a `sudo natwg update` of a cargo install
  leaves it yours. The file it replaced stays beside it as `.natwg.previous`;
- restarts each natwg service that runs, server instances and the client, one
  at a time, and waits until each brings its tunnel up again. When one does
  not, natwg puts every previous binary back, restarts the services again and
  fails. A stopped service stays stopped and runs the new binary when it
  starts.

natwg never downgrades a binary. When the natwg you ran is up to date but the
service binary is older, as after a `cargo install` without a
`natwg service install`, `sudo natwg update` brings the service binary to the
latest release and restarts the services. A natwg that Homebrew or Nix owns is
upgraded with that package manager instead. Two updates never run at once.

The GitHub repository is private, so the fallback needs a token with
Contents: read: natwg takes `GH_TOKEN` or `GITHUB_TOKEN`, else asks
`gh auth token`, run under sudo as the user who ran sudo. sudo drops the
environment, so to pass a token on, export it and name it, which keeps it off
the command line:

```sh
export GH_TOKEN=...            # or: export GH_TOKEN="$(gh auth token)"
sudo --preserve-env=GH_TOKEN natwg update
```

`--download-url ORIGIN` (or `NATWG_UPDATE_URL`) picks another download site
with the same layout, an exact `https://` origin. `--repository OWNER/REPO`
(or `NATWG_UPDATE_REPOSITORY`) skips the download site and uses the GitHub
Releases of that repository alone. The `update` object of the config sets
them as well; see below.

### Automatic update check

A running server or client looks for a newer release a minute after it
starts, then at most once a day. The check runs in the background with a
20-second limit, so it never holds up or fails the tunnel, and every natwg
service on the host shares its answer
(`/usr/local/var/natwg/update-check.json` on macOS,
`/var/lib/natwg/update-check.json` on Linux). It never installs anything:
the service writes the newest version into its status file, and
`natwg status` then prints

```text
Update available: 0.2.0 → 0.3.0. Run sudo natwg update.
```

The optional `update` object of the config sets the interval, or turns the
check off, and the sources:

```json
"update": {
  "check": "6h",
  "url": "https://natwg-dl.hackerchai.com"
}
```

- `check` is `off`, or an interval of at least an hour such as `6h` or `2d`
  (default `1d`). `NATWG_UPDATE_CHECK` overrides it.
- `url` and `repository` work as `--download-url` and `--repository` do, for
  the check and for `natwg update`. A `repository` skips the download site,
  and a root service has no GitHub token, so leave it out unless the service
  can reach that repository.
- A check that fails is logged once, until one succeeds again.

Restart the service to load a change: `sudo natwg service restart`.

## License

MIT
