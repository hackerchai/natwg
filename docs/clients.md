# Add and run clients

## Enroll a device

```sh
sudo natwg peer add phone --out phone.json   # fresh keys, the next free address
sudo natwg peer list
sudo natwg service restart                   # the running server loads the change
```

`peer add` writes the server config in one step and prints the new client's
config, or writes it to `--out` readable only by its owner. That file holds the
client's private key, so move it to the client privately. The new client routes
the tunnel subnet and every LAN of the server.

To revoke this device later, run these commands on the server:

```sh
sudo natwg peer remove phone
sudo natwg service restart
```

## Export WireGuard, Surge and Clash clients

Give **each device or app its own peer**. A natwg laptop, a phone running
Surge and a tablet running Clash each need a different private key and
tunnel address. Reusing one identity on two devices makes the server send
traffic to whichever device handshook last.

Choose unused peer names for these examples:

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
  wg-quick's `Endpoint` or Surge's peer `endpoint`. In mihomo, put the IPv4
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

## Run the client

The [client configuration](configuration.md#client-template) has one peer,
the server. Use the protected file and explicit
`--config /etc/natwg/client.json` from the [quick start](../README.md#connect-your-first-device).

### Discover the server endpoint

- `record` is the TXT record the server publishes. The client asks the
  `resolvers` in order and takes the first well-formed `"ip:port"`. It keeps the
  last endpoint when no resolver gives one. The default resolvers are
  `223.5.5.5`, `119.29.29.29`, `1.1.1.1`, and `8.8.8.8`. With a known endpoint,
  the client refreshes TXT every 10 minutes.
  An outgoing WireGuard handshake retry to the same endpoint (typically
  about 5 seconds after initiation), or an overdue handshake with persistent
  keepalive enabled, triggers an immediate lookup. While the failure lasts,
  retries start at 5 seconds and double to a maximum of 60 seconds. Recovery
  also depends on when the resolver serves the new answer. An unchanged TXT
  answer leaves a healthy WireGuard roam in place. If the roamed session
  fails, the client uses that answer to return to the advertised endpoint.
- `server` (`"home.example.com:51830"`) takes the place of `record` for a
  server in [public mode](server.md#public-mode-an-a-record). The client asks the
  `resolvers` for the A record of the name every 60 seconds, dials
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

### Follow routes and the uplink

- The client routes each of `allowed_ips` into its tunnel and refuses to start
  when another interface holds the tunnel address or one of those routes. A
  default route (`0.0.0.0/0`) is not supported.
- The WireGuard and DNS traffic leaves through the physical interface of the
  default route, past a VPN app such as Surge that owns the default route.
  `role.client.iface` pins an interface instead. The client follows a new
  uplink through macOS routing socket or Linux rtnetlink notifications. It
  also checks the route every 60 seconds and rebinds its UDP socket on wake.

### Tune keepalives and idle behavior

- `peers[0].keepalive` defaults to 25 seconds, a good choice for a laptop
  on Wi-Fi that should remain reachable. When tethered to a phone, set it to
  0 to disable persistent keepalives, or try 120 to send them less often.
  With keepalive enabled, even a late first TXT answer starts a handshake so
  the server can send the first application packet. With keepalive off, the
  laptop may need to send traffic first to establish or refresh its NAT mapping.
- To pause keepalives automatically, set `role.client.idle_pause_minutes`
  to a positive whole number. Omit it to keep the configured interval.
  The client samples inner traffic received from the peer or addressed to
  its allowed networks, including background application traffic. WireGuard
  handshakes and empty keepalives travel outside the TUN. After the idle
  interval it sets the peer's keepalive to 0. On the next sample with traffic
  it restores the configured value. Normal WireGuard session rekeys and replies
  can still occur while persistent keepalives are paused.
- With keepalives off or paused, an old handshake alone is normal. New
  traffic can use an existing session until WireGuard needs a handshake.
  The client observes actual initiation retries and sends no test packets.
  When it sees a pending handshake, the client updates its endpoint in place
  so WireGuard can deliver queued packets. Traffic sent before the first
  endpoint is known, or encrypted for the old address, can still require
  retransmission.
  The 10-minute TXT refresh still runs while idle.

### Inspect client status

The client checks the handshake every second until the first success on a
new device, then every 10 seconds. `role.client.status_file` selects the
file. Reachability, endpoint, keepalive, and handshake changes update it.
A 30-second heartbeat refreshes byte totals. Status becomes stale after
60 seconds.

Start the background service and inspect its status:

```sh
sudo natwg --config /etc/natwg/client.json service install
natwg status
```

The service is `com.hackerchai.natwg.client` on macOS or
`natwg-client.service` on Linux. To run in a terminal instead, stop the
service with `sudo natwg --config /etc/natwg/client.json service uninstall`
and run `sudo natwg --config /etc/natwg/client.json client --foreground`.
Uninstalling without `--purge` retains the config.

`natwg status` exits 1 when the client has no tunnel, no endpoint, a failing
TXT or A lookup, or is retrying TXT after a handshake failure. With an active
keepalive it also reports a missing or overdue handshake (235 seconds with
the default keepalive). The status file reports the effective keepalive,
including 0 while paused.

## Move a wg-quick client to natwg

The client keeps its keys and its tunnel address, so the server needs no
change.

The wg-quick config is `/opt/homebrew/etc/wireguard/wg-home.conf` with
Homebrew on macOS, and `/etc/wireguard/wg-home.conf` on Linux.

```sh
conf=/opt/homebrew/etc/wireguard/wg-home.conf
sudo natwg --config /etc/natwg/client.json config import-wg-quick "$conf" \
	--record _wg-home.example.com --dry-run          # check the redacted result
sudo natwg --config /etc/natwg/client.json config import-wg-quick "$conf" \
	--record _wg-home.example.com                    # writes --config
# wg-quick down frees the address and the routes. If the install refuses,
# wg-quick comes back up.
sudo wg-quick down "$conf" && { sudo natwg --config /etc/natwg/client.json service install || sudo wg-quick up "$conf"; }
natwg status
```

A client on one of the server's networks, such as a laptop at home on the
LAN that the server routes, leaves that network out of its routes and reaches
it directly. It routes the network again once the host leaves it.

The import takes one `[Peer]`, reads wg-quick's `Endpoint = 0.0.0.0:0`
placeholder as no endpoint, and refuses keys natwg does not run, such as `DNS`
or `PostUp`. Once `natwg status` shows a recent handshake, remove the TXT
updater job and the wg-quick config.
