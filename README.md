# natwg

[English](README.md) | [简体中文](README.zh-CN.md)

Reach your home LAN over WireGuard, even behind carrier-grade NAT.
natwg keeps a public UDP mapping alive and publishes it in DNS so clients
can follow endpoint changes. No relay or VPS is needed.

The same binary runs the server and client on macOS and Linux. WireGuard runs
in the process through [gotatun](https://crates.io/crates/gotatun), with no
separate daemon. The server manages LAN routing, NAT, and UPnP leases.

## Network requirements

The server needs a reachable public IPv4 endpoint or full-cone NAT (NAT1).
Restricted NAT (NAT2 or NAT3), symmetric NAT (NAT4), and blocked UDP cannot
host natwg. `natwg detect` checks your network without root.

A-record publication and plain WireGuard mode require a public address on
the host (`public_by: address`) or a forward confirmed by UPnP (`public_by: upnp`).
Every other supported case uses TXT, including a mapping that keeps the listen port.

## Install

Run on both devices:

```sh
curl -fsSL https://natwg-dl.hackerchai.com/install.sh | bash
```

The installer verifies the archive checksum and binary version, then installs
to `/usr/local/bin/natwg`. Builds cover Apple silicon and Intel Macs, plus
arm64 and x86_64 Linux. With Rust 1.99 or newer, `cargo install natwg --locked`
is another option.

## Connect your first device

On a fresh server, prepare a Cloudflare zone and an API token with Zone Read
and DNS Edit permissions for that zone. The wizard tests the network, asks
for your LAN and DNS settings, enrolls the laptop, and starts the service:

```sh
sudo natwg init --mode natwg --peer laptop \
	--out /etc/natwg/clients/laptop.json --install-service
natwg status
```

Wait until status shows the tunnel and a published TXT endpoint or A record.
Transfer `/etc/natwg/clients/laptop.json` privately to the client as
`./laptop.json`. It contains the client's private key. On the client:

```sh
sudo install -d -o root -m 700 /etc/natwg
sudo test -e /etc/natwg/client.json || \
	sudo install -o root -m 600 ./laptop.json /etc/natwg/client.json
sudo natwg --config /etc/natwg/client.json service install
natwg status
ping -c 3 10.66.66.1
```

The copy creates a root-owned 0600 config and keeps an existing file unchanged.
Use your server's tunnel address if you changed the default. A recent handshake
and ping replies confirm the connection. Keep the JSON privately for later
exports, and remove transfer copies. Give each device or app its own peer.

## Guides

| Task | Guide |
| --- | --- |
| Install manually or select a version | [Installation](docs/installation.md) |
| Interpret detection results and network limits | [Network detection](docs/network-detection.md) |
| Set up a server or use plain WireGuard | [Server setup](docs/server.md) |
| Write JSON or change tunnel and LAN routes | [Configuration reference](docs/configuration.md) · [Network changes](docs/configure.md) |
| Add clients, tune keepalives, or export to Surge, mihomo, and wg-quick | [Clients](docs/clients.md) |
| Upgrade natwg or publish a release | [Updates](docs/updates.md) · [Release process](docs/releasing.md) |

## License

[MIT](LICENSE)
