# Check whether a network can host natwg

natwg works only where a client whose address it cannot know in advance
reaches the server's UDP port. Two kinds of network allow that:

- **Public:** the host holds a public IPv4 address, or a router that holds
  one forwards the port to the host (by UPnP or by hand), and the port stays
  the listen port.
- **NAT1 (full cone):** the NAT gives the socket one public address and port
  whatever the destination (endpoint-independent mapping), and lets anyone in
  through it (endpoint-independent filtering). Some carrier networks provide
  this behavior. Test your own line.

A restricted cone NAT (NAT2), a port-restricted cone NAT (NAT3), a symmetric
NAT (NAT4) and a network that blocks UDP cannot host natwg. `natwg detect`
tells them apart. It needs no root.

```sh
natwg detect          # the verdict and the evidence
natwg detect --json   # everything it found, for scripts
```

Example output with documentation addresses:

```text
uplink    : en6 10.24.0.4 (private)
port      : udp/51830 is in use, perhaps by a running natwg; tested udp/60408 instead, so the result leaves out any router lease of udp/51830
upnp      : leased udp/60408 on http://10.24.0.1:1900/ipc (WAN 100.64.0.42) for the test, deleted after it
mapping   : endpoint-independent, 203.0.113.7:6918 (3 answers)
filtering : endpoint-independent: 198.51.100.3:3478 (other 198.51.100.2:3479): change IP and port answered from 198.51.100.2:3479, change port answered from 198.51.100.3:3479
self test : a second socket got in through the mapping
verdict   : supported (NAT1)
```

## Interpret the result

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
([public mode](server.md#public-mode-an-a-record)) only in those two cases too.

## What detection tests

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

The built-in RFC 5780 list includes `stun.miwifi.com`, `stun.easybell.de`,
`stun.voipia.net`, `stun.m-online.net`, `stun.vozelia.com`, and
`stun.voipbuster.com`. Server availability can change. The mapping
test also asks the servers that `natwg probe stun` uses. `--server HOST:PORT`
(repeatable) replaces both lists, `--dns` picks the resolver for their names,
and `--timeout-ms` how long each request waits before it is sent again.

## Platform limits

- **macOS:** macOS Local Network privacy keeps a program off the LAN unless
  it runs from Terminal, over SSH or as root, or the app that runs it has
  Local Network access (System Settings > Privacy & Security > Local
  Network). Without it, the UPnP step fails with "No route to host", and
  natwg detect says so.
- **Linux:** natwg binds its sockets to the uplink with `SO_BINDTOIFINDEX`.
  Linux 5.7 and newer need no root for that. Linux 5.0 to 5.6 need root
  (CAP_NET_RAW). Older kernels lack it and fail even as root.

## Network lab

`tests/netlab` proves each verdict in Linux network namespaces: a public
host with and without a firewall, a forwarded port, NAT1 to NAT4, blocked
UDP, a STUN server on the LAN, servers that misbehave, and UPnP gateways
that forward, refuse, lie or stall. See [its README](https://github.com/hackerchai/natwg/blob/main/tests/netlab/README.md).
