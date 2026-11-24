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
- routes the tunnel subnet and NATs it to the LAN (pf on macOS, nftables on
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
client's private key, so move it to the client privately.

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
TXT lookup, or no handshake within 180 seconds.

### Move a wg-quick client to natwg

The client keeps its keys and its tunnel address, so the server needs no
change.

```sh
sudo natwg config import-wg-quick /etc/wireguard/wg-home.conf \
  --record _wg-home.example.com --dry-run          # check the redacted result
sudo natwg config import-wg-quick /etc/wireguard/wg-home.conf \
  --record _wg-home.example.com                    # writes --config
sudo wg-quick down wg-home                         # frees the address and routes
sudo natwg service install
natwg status
```

The import takes one `[Peer]`, reads wg-quick's `Endpoint = 0.0.0.0:0`
placeholder as no endpoint, and refuses keys natwg does not run, such as `DNS`
or `PostUp`. Once `natwg status` shows a recent handshake, remove the TXT
updater job and the wg-quick config.

## License

MIT
