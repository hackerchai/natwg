# Changelog

## [0.4.0](https://github.com/hackerchai/natwg/compare/v0.3.0...v0.4.0) (2026-11-25)


### Features

* add natwg detect to tell whether the network can host natwg
* export WireGuard, Surge and mihomo configurations
* export WireGuard, Surge and mihomo configurations
* follow uplink events and recover TXT endpoints on handshake failure
* follow uplink events and recover TXT endpoints on handshake failure
* initialize WireGuard servers from network detection
* initialize WireGuard servers from network detection
* natwg detect tells whether the network can host natwg
* publish the public IP as an A record in public mode
* publish the public IP as an A record in public mode


### Bug Fixes

* **client:** recover TXT peers across retries and roaming
* **client:** start handshake grace at first TXT discovery
* ignore unrouted traffic when pausing client keepalives
* make natwg detect claim only what it saw, and keep UPnP safe
* preserve peer keys and recover native endpoint snapshots
* prove the review fixes of public mode in the network lab
* prove the review's cases in the network lab
* verify first-peer endpoints and reload the initialized server
* write only an exact A record of an IP confirmed now

## [0.3.0](https://github.com/hackerchai/natwg/compare/v0.2.0...v0.3.0) (2026-11-25)


### Features

* add natwg config set for the subnet, the LANs and the routes
* choose the tunnel subnet and any number of LANs, with natwg config set
* let a server serve any number of LANs
* self-update from the R2 download site with GitHub Releases fallback
* self-update from the R2 download site with GitHub Releases fallback


### Bug Fixes

* keep addresses in place when the new subnet overlaps the old one
* **update:** review findings on self-update

## [0.2.0](https://github.com/hackerchai/natwg/compare/v0.1.0...v0.2.0) (2026-11-24)


### ⚠ BREAKING CHANGES

* **config:** `natwg config import-legacy` is gone. Write the config by hand or keep using the one the cutover produced.

### Features

* **client:** run natwg as a WireGuard client that follows the TXT record
* **config:** import a wg-quick client config with its keys
* **peer:** add, list and remove the clients of a server
* **service:** install natwg client as its own service


### Bug Fixes

* **client:** judge a stale handshake by the session lifetime and keepalive
* **client:** leave the LAN the host sits on out of the tunnel routes


### Code Refactoring

* **config:** remove config import-legacy

## 0.1.0 (2026-11-24)


### Features

* **cli:** add a hidden natwg daemon command for service managers
* **cli:** add natwg probe stun, dns and txt
* **cli:** add natwg server --foreground and natwg doctor loopback
* **config:** add natwg config doctor for an imported config
* **config:** add the natwg crate, config model and legacy import
* **config:** add the natwg crate, config model and legacy import
* **config:** name the server instance that owns the NAT rules
* **doctor:** dial the mapping in the status file by default
* **doctor:** ping the tunnel address and the LAN through a client in process
* land the wire layer and the embedded tunnel on main, with the P3 safety fixes
* **nat:** plan LAN NAT as a pf anchor and an nftables table
* **netcfg:** plan the tunnel address, MTU and routes as commands
* **server:** keep the carrier mapping alive with a STUN keepalive
* **server:** keep the mapping alive, publish it, and supervise the tunnel
* **server:** publish the mapping as the Cloudflare TXT record
* **server:** renew the UPnP lease on the home router
* **server:** supervise the tunnel and rebuild it when it dies
* **service:** install natwg as a system service
* **service:** install natwg as a system service
* **service:** uninstall a service by its instance name
* **status:** add the status file and natwg status
* **tunnel:** hand out the STUN port, peer stats and a NAT re-check
* **tunnel:** run gotatun with the config's peers on a TUN or in memory
* **wire:** add the STUN Binding codec
* **wire:** resolve A and TXT records through the uplink interface
* **wire:** share one interface-bound socket between STUN and WireGuard


### Bug Fixes

* **cli:** keep running when nobody reads the output
* **cli:** stop the server on SIGHUP
* **config:** close the review findings on secrets and the legacy import
* **config:** guard the real config before the cutover writes it
* **config:** never echo a legacy key name longer than 19 characters
* **config:** refuse values that take routes or rules natwg does not own
* **doctor:** refuse --attempts 0 when the command line is parsed
* **nat:** check that Linux turned IP forwarding on
* **nat:** refuse an anchor or a table that holds rules of someone else
* **nat:** remove the rules when the server panics
* **netcfg:** refuse a tunnel subnet that another Linux device routes
* **server:** count a TXT that holds the mapping as published
* **server:** delay a missed status or NAT tick instead of bursting it
* **server:** write the status as soon as the mapping or the TXT changes
* **service:** install only under directories that only root can write
* **service:** report a started service only once its tunnel is up
* **service:** validate the install before it changes the host
* **status:** exit 1 when the status shows the server is not serving
* **status:** give each instance its own default status file
* **tunnel:** keep the utun control socket out of child processes
* **tunnel:** name the peers that share a key in PEER_DUPLICATE
* **tunnel:** refuse a peer route that another utun holds on macOS
* **tunnel:** refuse a tunnel address that another interface holds
* **tunnel:** stop reporting a handshake as old as the device
* **wire:** close the P2 review findings on probes, DNS and rebinding
* **wire:** deliver only the answer to the pending STUN request
* **wire:** name the query in every DNS error and pin the buffer and default list
