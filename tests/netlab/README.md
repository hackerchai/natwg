# natwg network lab

The lab puts a natwg host behind each kind of network natwg must tell apart,
on one Linux machine, with no traffic leaving it. It runs in network
namespaces, so the machine's own interfaces, routes, nftables ruleset and
`ip_forward` stay as they are.

```sh
cargo build
sudo NATWG=target/debug/natwg tests/netlab/run.sh            # every scenario
sudo NATWG=target/debug/natwg tests/netlab/run.sh nat2 upnp  # some of them
tests/netlab/run.sh list                                    # the scenarios
```

It needs root, `ip` (iproute2), `nft` and `python3`. With sudo, natwg itself
runs as the user who ran sudo, since `natwg detect` needs no root on Linux.
`run.sh` exits 1 when a verdict or exit status differs from the expected one,
and prints a Markdown table of the results.

## Topology

```text
   nwl-peer 45.79.0.2 ── 45.79.0.1 ┐
                                    nwl-inet  STUN: 45.78.0.1, 45.78.0.2 (RFC 5780, ports 3478 and 3479)
                                    │               45.78.0.3, 45.78.0.4 (plain, port 3478)
                         45.77.0.1 ─┤
                                    │
   nwl-rtr  WAN nwl-r0 45.77.0.2 ───┘     (public, public-firewall* have no router:
            LAN nwl-r1 192.168.77.1        the host is 45.77.0.10 on nwl-inet)
              │
   nwl-host  nwl-h0 192.168.77.2, natwg tests udp/51830
```

- `nwl-inet` is the internet. It routes between made-up public networks:
  45.77.0.0/24 (routers and public hosts), 45.78.0.0/24 (STUN servers on its
  loopback) and 45.79.0.0/24 (the peer). They are real, routable ranges on
  purpose: natwg treats TEST-NET and the other special ranges as not public.
  The namespaces never reach the real internet.
- `stun_server.py` is a STUN server with the RFC 5780 attributes. It answers
  on 45.78.0.1 and 45.78.0.2, each on ports 3478 and 3479, and honours
  CHANGE-REQUEST. 45.78.0.3 and 45.78.0.4 are plain servers.
- `nwl-rtr` is the NAT, an nftables table `ip nwl` with chains `nat_pre`,
  `nat_post` and `forward_filter`.
- `nwl-peer` is a host on the internet, for tests that need a client there.
- `igd.py` is a UPnP gateway on the router's LAN side (SSDP, and SOAP on
  `http://192.168.77.1:5000/ctl`). Each lease becomes a DNAT rule in chain
  `upnp_pre` and a port-keeping SNAT rule in `upnp_post`, and ends after its
  duration. It can hold a mapping from the start (`--preset`), or refuse
  leases with a duration (`--permanent-only`, error 725). It logs every call.
- `rogue.py` is a hostile SSDP responder: its answers point elsewhere, or at
  a listener that never answers (`--stall`).

## Scenarios

| Scenario | The network | `natwg detect` must say | Exit |
|---|---|---|---|
| `public` | no router: the host owns 45.77.0.10 | supported (public), by `address` | 0 |
| `public-firewall` | public, with a host firewall that lets in only replies | unsupported (a firewall) | 1 |
| `public-firewall-plain` | the same, but natwg asks only the plain servers | likely: a firewall cannot be ruled out | 2 |
| `public-forward` | the router forwards udp/51830 to the host and keeps the port | supported (public), by `port_kept` | 0 |
| `nat1` | static SNAT of udp/51830 to :52830, DNAT from anyone | supported (NAT1) | 0 |
| `nat2` | the same SNAT, DNAT only from IPs the host has sent to (an nft dynamic set) | unsupported | 1 |
| `nat3` | `masquerade` | unsupported | 1 |
| `nat4` | `masquerade fully-random` | unsupported | 1 |
| `blocked` | drops all forwarded UDP | unsupported | 1 |
| `likely` | as `nat1`, but natwg asks only the plain servers | likely | 2 |
| `ignores-change` | as `nat1`, but the RFC 5780 server ignores CHANGE-REQUEST | likely | 2 |
| `inconsistent` | `masquerade`, and DNAT only from 45.78.0.2: the other IP gets in, the other port does not | likely | 2 |
| `lan-stun` | `masquerade`, and natwg asks only a STUN server on the router's LAN side | inconclusive | 2 |
| `upnp` | `masquerade`, and a UPnP gateway; natwg leases udp/51830 for 120 s and deletes it | supported (public), by `upnp` | 0 |
| `upnp-existing` | the gateway forwards udp/51830 to the host already; natwg leaves it | supported (public), by `upnp` | 0 |
| `upnp-conflict` | the gateway forwards udp/51830 to 192.168.77.99; natwg leaves it | unsupported | 1 |
| `upnp-permanent` | the gateway takes only permanent leases; natwg takes none | unsupported | 1 |
| `upnp-rogue` | a second LAN responder points at a gateway on the internet, which natwg must never reach | supported (public) | 0 |
| `upnp-slow` | ten SSDP answers point at descriptions that never come; natwg must finish within 12 s | unsupported | 1 |
| `upnp-sigterm` | natwg gets SIGTERM while it holds its lease, and must delete it | error `INTERRUPTED` | 3 |

The UPnP scenarios also check the gateway's log and rules: which leases
natwg asked for, for how long, and that none is left afterwards. The
routers of `public-forward`, `nat1`, `likely`, `ignores-change` and the UPnP
scenarios hairpin: a datagram from the LAN to the router's public address
comes back to the LAN from the router, so natwg's self test gets in.

## Public mode end to end

`e2e.sh` runs a real natwg server and a real natwg client in the lab, as
root, with publish `a`:

```sh
cargo build
sudo NATWG=target/debug/natwg tests/netlab/e2e.sh          # every scenario
sudo NATWG=target/debug/natwg tests/netlab/e2e.sh upnp     # some of them
tests/netlab/e2e.sh list
```

- `cloudflare.py`, on the internet, is a fake Cloudflare API on
  `http://45.78.0.80/client/v4`, which natwg calls through
  `NATWG_CLOUDFLARE_API` (only a debug build such as `target/debug/natwg`
  honours it), and the authoritative DNS server of its zone on
  45.78.0.53, which answers what the API holds. It logs every write and every
  DNS answer.
- The server runs in `nwl-host` and keeps the A record `home.example.net`.
  `natwg peer add` writes the client's config, which must name the server as
  `home.example.net:51830`. The client runs in `nwl-peer` with 45.78.0.53 as
  its only resolver.
- `conntrack.py` flushes a router's conntrack table after its WAN address
  changes, as a reconnect does.

| Scenario | The network | What must happen |
|---|---|---|
| `public` | the host owns 45.77.0.10, with no STUN; a LAN host, 10.88.0.2, shares the host's link through a bridge on the internet side that the internet does not route | A record 45.77.0.10 by `address`; a handshake; pings to 10.66.66.1 and 10.88.0.2. The host moves to 45.77.0.11: the record and the client follow, and the pings pass again. |
| `upnp` | `masquerade` and the UPnP gateway; the router owns 45.77.0.2 | A record 45.77.0.2 by `upnp`: the lease works, GetExternalIPAddress agrees with STUN, and the port is kept. A handshake; pings to 10.66.66.1 and the router, 192.168.77.1, on the LAN. The router reconnects as 45.77.0.3 with an empty UPnP table: the record and the client follow. |
| `public-forward` | the router forwards udp/51830 and keeps the port, without UPnP | No write: the record keeps 45.77.0.99, which `natwg status` shows; it exits 1 with `no public IP` and says natwg cannot confirm a router. |
| `nat1` | NAT1 maps udp/51830 to :52830 | No write, as above: the port is not kept. |
| `strays` | as `public`; the name holds 45.77.0.10 proxied (as the dashboard makes it), another A record, 45.77.0.98, and an AAAA record | natwg writes 45.77.0.10 again, not proxied with a TTL of 60. `natwg status` exits 1 and names the other A and the AAAA record. natwg deletes no record. |

`e2e.sh` exits 1 when a check fails, prints the logs, and prints a Markdown
table of the results. A run takes a few minutes, most of it waiting for the
client's lookup, which comes every 60 s.

## Reuse it

`run.sh up SCENARIO` builds one scenario and leaves it running, with its
logs in a work directory it names. `run.sh down` stops its processes, and
the natwg daemons and fake API of an interrupted `e2e.sh`, removes every
`nwl-` namespace and that directory. In between, run anything in a namespace:

```sh
sudo tests/netlab/run.sh up nat1
sudo ip netns exec nwl-host target/debug/natwg detect --iface nwl-h0 --upnp off \
  --server 45.78.0.1:3478 --server 45.78.0.3:3478
sudo ip netns exec nwl-peer ping -c1 45.77.0.2
sudo tests/netlab/run.sh down
```

To add a scenario, add its name to `SCENARIOS`, a line to `describe` and
`expect`, its router rules to `rules`, its servers to `servers`, and any
further checks to `checks` in `run.sh`. A test of the server
or the client can put a natwg server in `nwl-host` and a client in
`nwl-peer`, which reaches the host only through the router's NAT, the way a
laptop on the internet does.
