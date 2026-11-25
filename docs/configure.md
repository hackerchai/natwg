# Change tunnel addresses and LAN routes

The server's `interface.address` is its tunnel address, and the prefix sets the
tunnel subnet: `10.66.66.1/24` serves 10.66.66.0/24. `role.server.lan` lists
the networks behind `role.server.iface` that clients reach. See the complete
[server template](configuration.md#server-template).

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
- natwg 0.2 wrote one LAN as a string (`"lan": "10.24.0.0/24"`). That form
  still loads, and natwg writes the list form from then on, which natwg 0.2
  cannot read: going back to 0.2 takes the LAN back to a single string by
  hand.

## Change the server networks

`natwg config set` changes these settings in `--config`. It validates the
result, replaces the file in one step, readable only by its owner, and prints
what changed. `--dry-run` prints the redacted result and writes nothing.

```sh
sudo natwg config set lan 10.24.0.0/24 192.168.50.0/24   # server; no network clears the list
sudo natwg config set address 10.66.70.1/24
sudo natwg service restart                               # load the change
```

A server whose new subnet holds the old one, or sits inside it, keeps every
peer and its doctor where they are: growing 10.66.66.1/24 to 10.66.66.1/16
moves nobody, and shrinking it to 10.66.66.129/25 keeps 10.66.66.130. A server
that moves to a subnet apart from the old one moves its peers and its doctor
along. Each keeps its host offset, so 10.66.66.2 becomes 10.66.70.2, and natwg
prints each old and new address. Each moved client must then take its new
address and route the new subnet.

natwg refuses the change and writes nothing when a peer or the doctor does not
fit in the new subnet, when one would land on the server's new address, when
a network that a peer routes beyond the tunnel overlaps the new subnet, or
when the server address is the network or broadcast address of its subnet.

## Update the clients

A client routes only its own `allowed_ips`. After a server network change,
update each client with its assigned address and the new route list:

```sh
sudo natwg --config /etc/natwg/client.json config set address 10.66.70.2/32
sudo natwg --config /etc/natwg/client.json config set allowed-ips 10.66.70.0/24 10.24.0.0/24 192.168.50.0/24
sudo natwg --config /etc/natwg/client.json service restart
```

If only the LAN list changed, skip the address change. Use a distinct tunnel
address for each client.
