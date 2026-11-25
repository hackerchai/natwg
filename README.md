# natwg

natwg runs a WireGuard server on a host that sits behind carrier-grade NAT, so a
laptop elsewhere can reach the home LAN. It needs no relay and no port on a VPS.

The server keeps one UDP socket on the WAN interface. The socket carries both
STUN and WireGuard, so the public mapping that STUN reports is the one that
WireGuard peers reach. natwg then:

- refreshes that mapping with a STUN keepalive every 25 seconds;
- publishes it as a Cloudflare DNS TXT record (`"ip:port"`), which the client
  reads to find the server;
- leases the port on the home router through UPnP;
- routes the tunnel subnet and NATs it to each LAN (pf on macOS, nftables on
  Linux);
- writes a status file, and rebuilds the tunnel when STUN stops answering.

The same binary is the client. `natwg client` keeps a tunnel to the server,
reads the TXT record every 60 seconds and follows the server when its mapping
changes.

WireGuard runs inside the process through
[gotatun](https://crates.io/crates/gotatun), so it needs no wireguard-go or
wg-quick. natwg supports macOS and Linux.

## Install

```sh
cargo install natwg --locked
```

## Run the server

Write a server config to `/usr/local/etc/natwg/config.json` (`/etc/natwg/config.json`
on Linux), owned by root with mode 0600. `natwg keys gen` prints a key pair, and
`natwg config show` prints the loaded config with its secrets redacted.

```sh
sudo natwg service install   # a LaunchDaemon on macOS, a systemd unit on Linux
natwg status                 # the mapping, the TXT record, NAT and UPnP
natwg service status
sudo natwg doctor loopback   # ping the tunnel and the LAN through a test peer
```

`natwg server --foreground` runs the same server in the terminal.
`natwg probe stun|dns|txt|uplink` asks STUN and DNS servers through one
interface without the server, and prints the uplink a client would pick.

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

### Choose the tunnel subnet and the LANs

The server's `interface.address` is its tunnel address, and the prefix sets the
tunnel subnet: `10.66.66.1/24` serves 10.66.66.0/24. `role.server.lan` lists
the networks behind `role.server.iface` that clients reach:

```json
"interface": { "address": "10.66.66.1/24", "mtu": 1380 },
"role": { "server": {
  "iface": "en6",
  "lan": ["10.24.0.0/24", "192.168.50.0/24"],
  ...
}}
```

- natwg NATs the tunnel subnet into each LAN out of `role.server.iface`, so LAN
  hosts answer clients without a route back to the tunnel.
- A LAN may not overlap the tunnel subnet or another LAN, and `0.0.0.0/0` is
  not a LAN.
- An empty list (`"lan": []`) serves the tunnel only. natwg then loads no NAT
  rule and leaves IP forwarding as it is, `natwg status` shows NAT as off, and
  `doctor loopback` pings only the server's tunnel address. With LANs, the
  doctor also pings the first host of the first LAN.
- natwg 0.2 wrote one LAN as a string (`"lan": "10.24.0.0/24"`). That form
  still loads, and natwg writes the list form from then on.

A client routes only its own `allowed_ips`, so give each client the tunnel
subnet and every LAN.

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
    "allowed_ips": ["10.66.66.0/24", "10.24.0.0/24"],
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
- Without a `record`, the client dials `peers[0].endpoint` (`"ip:port"`).
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
TXT lookup, or no handshake for longer than a session can live, 235 seconds
with the default keepalive.

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

## License

MIT
