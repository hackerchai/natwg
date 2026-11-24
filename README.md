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

WireGuard runs inside the process through
[gotatun](https://crates.io/crates/gotatun), so it needs no wireguard-go or
wg-quick. natwg supports macOS and Linux.

## Install

```sh
cargo install natwg --locked
```

## Run the server

Write a server config to `/usr/local/etc/natwg/config.json`, owned by root
with mode 0600. `natwg keys gen` prints a key pair, and `natwg config show`
prints the loaded config with its secrets redacted.

```sh
sudo natwg service install   # a LaunchDaemon on macOS, a systemd unit on Linux
natwg status                 # the mapping, the TXT record, NAT and UPnP
natwg service status
sudo natwg doctor loopback   # ping the tunnel and the LAN through a test peer
```

`natwg server --foreground` runs the same server in the terminal.
`natwg probe stun|dns|txt` asks STUN and DNS servers through one interface
without the server.

## License

MIT
