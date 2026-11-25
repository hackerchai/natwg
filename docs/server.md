# Set up and run a server

Run `sudo natwg init` on the server. The wizard tests the uplink and listen
port, then asks for the tunnel address, LANs, Cloudflare zone and record, and
the API token with echo disabled. Use a token with Zone Read and DNS Edit
permissions for that zone. The default listen port is 51830, the tunnel address
is `10.66.66.1/24`, and the default LAN is the uplink's IPv4 subnet when it excludes the public endpoint.
On a directly public uplink, the default routes only the tunnel. Supply
`--lan` for each network, or `--no-lan` for the tunnel alone.

For example, this creates a server and saves the first device's private config
to `laptop.json`:

```sh
sudo natwg init --yes --zone example.com --record home.example.com \
	--token-file /etc/natwg/cloudflare-token --peer laptop --out laptop.json
```

With `--yes` or without a terminal, supply `--zone`, `--record` and
`--token-file`. Use an owner-only token file belonging to root or the user invoking sudo.
Put the token on a single line. The interactive service prompt defaults to no. Pass
`--install-service` to install and start the service from a script.

| What detection finds | What init configures |
|---|---|
| Supported public IP on the uplink or confirmed by UPnP | A record with the fixed listen port, or `--mode wireguard` |
| NAT1, an unconfirmed port-preserving mapping, or likely reachability | natwg daemon with TXT discovery. For a likely verdict, connect the first client to confirm reachability. |
| Unsupported, inconclusive, or the requested port was occupied | Stops before writing files. Free an occupied port or select another with `--port`. |

Init creates fresh server and doctor keys in the validated, root-owned config
(mode 0600). `--config PATH` changes its destination. Existing files require
`--force`, which replaces the keys and peer list. Back up profiles before
reinitializing a server that has devices enrolled. When you defer service installation
after `--force`, the printed `service install --reload-config` command starts a
missing service or restarts an existing one with the new keys and port.

## Deliver the first client profile

Use `--peer NAME --format natwg|wg-quick|surge|clash` for a first device.
`--out PATH` writes its profile with mode 0600. Without it, stdout carries
only the private profile and stderr carries the wizard and verdict. Use
`umask 077` before redirecting stdout. The first native-format export on a TXT
server requires the TXT answer to match the mapping seen on the selected port.
For a wg-quick, Surge, or Clash export, init waits for DNS to match the
published endpoint when it starts the daemon. The natwg JSON keeps TXT
discovery and needs no endpoint snapshot.
If DNS, service startup or delivery fails
after enrollment, init prints the path to the peer's private JSON. Start the
server, wait for its TXT record, then run the printed `config export` command.
Move the recovery file to its device or remove it after successful delivery.

## Initialize plain WireGuard

In `--mode wireguard`, init also writes `natwg.conf` and, for an enrolled
device, `natwg-client.conf` with mode 0600. The directory is `/etc/wireguard`
on Linux or `$(brew --prefix)/etc/wireguard` on macOS. Set `--wg-dir DIR`
to choose another location. Set the DNS-only A record to the reported public IP
and maintain it if the IP changes. Behind UPnP, arrange a static UDP forward
or keep the lease renewed independently. Detection's lease is temporary.
Run the printed `wg-quick up` command on the server.

## Run the server

The server carries STUN and WireGuard over the same UDP socket on the uplink.
STUN therefore reports the mapping that clients can reach. A keepalive
refreshes it every 25 seconds by default. The server rebuilds the tunnel
when STUN stops answering and writes its current state to the status file.

For a hand-written config, use the [configuration reference](configuration.md).
Save the server config to `/usr/local/etc/natwg/config.json` (`/etc/natwg/config.json`
on Linux), owned by root with mode 0600. `natwg keys gen` prints a key pair, and
`sudo natwg config show` prints the loaded config with its secrets redacted.

```sh
sudo natwg service install   # a LaunchDaemon on macOS, a systemd unit on Linux
natwg status                 # the mapping, the TXT or A record, NAT and UPnP
natwg service status
sudo natwg doctor loopback   # ping the tunnel and the LAN through a test peer
```

`sudo natwg server --foreground` runs the same server in the terminal.
`natwg probe stun|dns|txt|uplink` asks STUN and DNS servers through one
interface without the server, and prints the uplink a client would pick.
Run `natwg detect` first (see [Check the network](network-detection.md)).

## Public mode: an A record

On a network with a public IPv4 address, the server can publish that address
as a Cloudflare A record instead of a TXT record. Clients, Surge and Clash
then dial `name:listen_port`, as with any dynamic DNS name. Set
`role.server.publish` to `"a"`. `cloudflare.record` names the A record.

See the [public A-record configuration variant](configuration.md#public-a-record-variant)
for the server and client changes.

`publish` defaults to `"txt"`, the TXT record of the mapping, and a config
without it works as before. With `"a"`, `cloudflare.record` must be a host
name that clients can dial: letters, digits and hyphens, two labels or more,
and no trailing dot. A name such as `_wg-home.example.com` is not a hostname. Use public mode only where `natwg detect` says
`supported (public)` with `public_by` `address` or `upnp`. natwg publishes an
IP only when it confirms the IP itself, which it can do in two cases:

- **`address`:** the uplink's own address is public. natwg reads it every 10
  seconds and needs no STUN for it, so `role.server.stun` may go.
- **`upnp`:** a router holds the public IP and forwards the listen port, and
  natwg confirms all of it: the UPnP lease of the listen port
  (`role.server.upnp`) works, the router's WAN address (GetExternalIPAddress)
  is the IP that STUN sees, and the STUN mapping keeps the listen port. This
  needs `stun` and `upnp`.

### Confirm public reachability

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

### Check DNS publication

`natwg status` shows the mode, the name and the IP. This example uses a
documentation-only address:

```text
public IP       : 203.0.113.7 by address
published A     : home.example.com = 203.0.113.7 (3s ago), clients dial home.example.com:51830
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

## Export a plain WireGuard server

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

See [Add and run clients](clients.md) for enrollment and native app exports,
and [Change tunnel addresses and LAN routes](configure.md) for network changes.
