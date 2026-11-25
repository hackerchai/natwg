# Configuration reference

natwg reads one JSON file containing the local identity, tunnel interface,
peers, and exactly one role: `server` or `client`. The schema is defined in
[`src/config.rs`](https://github.com/hackerchai/natwg/blob/main/src/config.rs). Unknown fields are rejected.

For guided setup, use [the server wizard](server.md). For changing an existing
subnet or LAN list, see [network configuration](configure.md).

## File paths and permissions

| Setting | Value |
| --- | --- |
| Default config on macOS | `/usr/local/etc/natwg/config.json` |
| Default config on Linux | `/etc/natwg/config.json` |
| Override | `--config PATH`, then `NATWG_CONFIG`, then the platform default |
| Owner | The effective user reading the file. A root service requires a root-owned file. |
| Permissions | A regular file with no group or other permissions, normally 0600, and no extended ACL |

The README uses `/etc/natwg/client.json` explicitly on both platforms so the
client service keeps reading the same file after the transfer copy is removed.
The `--config` option is global and works with every config-dependent command.
For example, this validates a client file and prints a redacted view:

```sh
sudo natwg --config /etc/natwg/client.json config show
```

The redacted output includes the derived public key. It is a display format,
not an importable replacement for the config. `config show` does not check
network reachability, DNS credentials, or router settings.

## Server template

This complete TXT-mode template includes a laptop peer and the optional doctor
and UPnP settings. Angle-bracket strings are placeholders, not valid keys or
credentials. Replace them before validation. The interface, LAN, domain names,
and UPnP control URL must match the deployment. `natwg detect --json` reports
the discovered gateway URL. If no UPnP gateway is used, omit `upnp`.

```json
{
	"version": 1,
	"private_key": "<SERVER_PRIVATE_KEY>",
	"interface": {
		"address": "10.66.66.1/24",
		"mtu": 1380
	},
	"peers": [
		{
			"name": "laptop",
			"public_key": "<CLIENT_PUBLIC_KEY>",
			"preshared_key": "<SHARED_PRESHARED_KEY>",
			"allowed_ips": ["10.66.66.2/32"]
		}
	],
	"role": {
		"server": {
			"instance": "natwg",
			"iface": "eth0",
			"listen_port": 51830,
			"lan": ["192.168.50.0/24"],
			"publish": "txt",
			"stun": {
				"servers": [],
				"fallback": [],
				"interval_secs": 25,
				"dns_server": "1.1.1.1"
			},
			"upnp": {
				"control_url": "http://192.168.50.1:1900/control/WANIPConn1",
				"lease_secs": 3600,
				"refresh_secs": 300
			},
			"cloudflare": {
				"zone": "example.com",
				"record": "_wg-home.example.com",
				"token": "<CLOUDFLARE_API_TOKEN>"
			},
			"doctor": {
				"private_key": "<DOCTOR_PRIVATE_KEY>",
				"address": "10.66.66.254"
			}
		}
	},
	"update": {
		"check": "1d"
	}
}
```

Each private key has its own public key. `natwg keys gen` prints a fresh pair.
The server's `peers[0].public_key` is the client's public key, and the client's
peer holds the server's public key. Both sides use the same preshared key,
or both omit it. A fresh generated private-key value can serve as the
preshared key. The doctor has a separate private key and an unused address.
Keys are base64-encoded 32-byte values. Treat key-generator output as secret.

The empty STUN lists select natwg's built-in targets. A manually supplied
`servers` list contains `host:port` entries; `fallback` contains literal
`IPv4:port` entries. These fields are required when `stun` is present.

## Client template

This template matches the server above. The client routes the tunnel subnet
and the server's LAN. Its own tunnel address is a single-host `/32`.

```json
{
	"version": 1,
	"private_key": "<CLIENT_PRIVATE_KEY>",
	"interface": {
		"address": "10.66.66.2/32",
		"mtu": 1380
	},
	"peers": [
		{
			"name": "server",
			"public_key": "<SERVER_PUBLIC_KEY>",
			"preshared_key": "<SHARED_PRESHARED_KEY>",
			"allowed_ips": ["10.66.66.0/24", "192.168.50.0/24"],
			"keepalive": 25
		}
	],
	"role": {
		"client": {
			"record": "_wg-home.example.com",
			"resolvers": ["223.5.5.5", "119.29.29.29", "1.1.1.1", "8.8.8.8"]
		}
	},
	"update": {
		"check": "1d"
	}
}
```

`peer add` generates a matching client and registers its public identity on
the server. A manually written client also needs the corresponding server
peer. After enrollment or a peer change, the server must restart to load it.

## Common fields

| Field | Requirement or default |
| --- | --- |
| `version` | Required. Exactly `1`. |
| `private_key` | Required. This host's WireGuard private key. |
| `interface.address` | Required IPv4 address with prefix, from `/16` through `/32`. The server prefix defines the tunnel subnet. |
| `interface.mtu` | Optional. Default `1380`, accepted range `576` through `9000`. Surge exports accept at most `1420`. |
| `peers` | Required array. A server can have no peers. A client has exactly one. |
| `role` | Required. Exactly one object, `{"server": {...}}` or `{"client": {...}}`. |
| `update` | Optional release source and check interval. See [update settings](#update-settings). |

Each peer has these fields:

| Field | Requirement or default |
| --- | --- |
| `name` | Required string. Enrollment and client exports accept 1 to 32 letters, digits, `.`, `_`, or `-`. |
| `public_key` | Required public key of the remote peer. |
| `preshared_key` | Optional shared key, identical on both sides. |
| `allowed_ips` | Required IPv4 CIDR list. On the server, normally the client's tunnel `/32`. On the client, the networks reachable through the server. |
| `endpoint` | Optional literal `IPv4:port`. Required for a client without DNS discovery. A server normally learns the client's endpoint from WireGuard. |
| `keepalive` | Optional integer from `0` through `65535` seconds. A client defaults to `25`; a server peer defaults to `0`. Zero disables persistent keepalives. |

A client's `allowed_ips` must be nonempty and cannot contain `0.0.0.0/0`.
natwg supports IPv4 split routes, not a full-tunnel default route.

## Server role

All fields below belong to `role.server`.

| Field | Requirement or default |
| --- | --- |
| `instance` | Default `natwg`. 1 to 15 lowercase letters, digits, or `_`. `client` is reserved. Names the service, Linux TUN, firewall rules, and status file. |
| `iface` | Required uplink name, such as `eth0` or `en0`. 1 to 15 letters, digits, `.`, `_`, or `-`. |
| `listen_port` | Required UDP port. Use a fixed nonzero port, normally `51830`. A-record publication rejects `0`. |
| `lan` | Default `[]`, for tunnel-only access. IPv4 CIDR array. No default route or overlap with the tunnel or another LAN. The old single-string form still loads. |
| `publish` | Default `"txt"`. Either `"txt"` for the public `IPv4:port`, or `"a"` for a confirmed public IP at the listen port. |
| `stun` | Required for TXT. Also needed for A publication behind a UPnP router. Optional on a directly public uplink. |
| `upnp` | Optional router lease. Omission disables UPnP. |
| `cloudflare` | Required publication credentials and record. |
| `doctor` | Optional loopback-test identity. `init` creates one. |
| `status_file` | Optional path. The default instance uses `/usr/local/var/natwg/status.json` on macOS or `/run/natwg/status.json` on Linux. Other instances use `<instance>.status.json` beside it. |

Nested objects have these fields:

| Object | Fields |
| --- | --- |
| `stun` | Required `servers` array, `fallback` array, and `dns_server` IPv4 address. `interval_secs` defaults to `25` and must be a positive integer. |
| `upnp` | Required `control_url`, `lease_secs`, and `refresh_secs`. The refresh interval is a positive integer in seconds. `init` uses a 3600-second lease and refreshes every 300 seconds. |
| `cloudflare` | Required `zone` name, full `record` name, and `token`. The token needs Zone Read and DNS Edit for that zone. |
| `doctor` | Required `private_key` and IPv4 `address`. The address must be inside the tunnel subnet, differ from the server's address, and be outside every peer's `allowed_ips`. |

### Public A-record variant

Only `natwg detect` results confirmed by `public_by: address` or
`public_by: upnp` qualify. A `port_kept` result alone does not. All other
supported networks use TXT.

For the server template, `publish` becomes `"a"`, and
`cloudflare.record` becomes `"home.example.com"`. For the client template,
`role.client.server` becomes `"home.example.com:51830"` and `record` is
removed. On a directly public uplink, `stun` and `upnp` can be omitted.
Behind a public UPnP router, both are needed to confirm the IP and port.

The A-record name must be a hostname with at least two labels containing
letters, digits, and hyphens. Labels cannot begin or end with a hyphen.
Underscores, a trailing dot, and an all-numeric top-level label are invalid.
natwg publishes a DNS-only A record with TTL 60. Extra A or AAAA records
cause a status error. natwg does not delete them.

If public confirmation fails, natwg leaves the existing A record untouched
and reports the problem. It does not switch to TXT automatically. See
[public mode behavior](server.md#public-mode-an-a-record).

## Client role

All fields below belong to `role.client`.

| Field | Requirement or default |
| --- | --- |
| `record` | Optional TXT name, for example `_wg-home.example.com`. Mutually exclusive with `server`. |
| `server` | Optional A-record hostname and fixed port, for example `home.example.com:51830`. Hostname rules match the public server's record. The port is 1 through 65535 without a leading zero. |
| `resolvers` | Optional IPv4 array in query order. Omitted or empty uses `223.5.5.5`, `119.29.29.29`, `1.1.1.1`, and `8.8.8.8`. |
| `iface` | Optional pinned uplink. Otherwise natwg follows the physical interface of the default route. Same name constraints as the server uplink. |
| `idle_pause_minutes` | Optional positive whole number. Pauses persistent keepalives after this many minutes without inner IP traffic. Omission leaves them active at the configured interval. |
| `status_file` | Optional path. Default `client.status.json` beside the platform's server status file. |

A client uses one of three discovery forms:

| Mode | Client settings |
| --- | --- |
| TXT | `role.client.record` names the server's published TXT record. |
| Public A record | `role.client.server` names the host and port. Only public IPv4 answers are accepted. |
| Static endpoint | Both `record` and `server` are absent, and `peers[0].endpoint` contains the literal `IPv4:port`. |

For a static template, remove `record` from the client example and add
`"endpoint": "203.0.113.7:51830"` to its peer. That documentation address
must be replaced by the reachable server address. The `role.client` object
may be empty for a static endpoint with default settings.

TXT refreshes every ten minutes and on handshake failure. A records refresh
every 60 seconds. Failed lookups retain the last endpoint. See the
[client guide](clients.md#run-the-client) for retry timing, roaming, route
conflicts, keepalive behavior, and status checks.

## Update settings

All fields in the optional top-level `update` object are optional:

| Field | Default and meaning |
| --- | --- |
| `check` | `"1d"`. Either `"off"` or an interval of at least one hour, such as `"6h"`. Checks notify but never install. |
| `url` | `"https://natwg-dl.hackerchai.com"`. An exact HTTPS origin with the same download layout. |
| `repository` | No override. An `owner/repository` value uses GitHub Releases alone and skips the download site. |

`NATWG_UPDATE_CHECK`, `NATWG_UPDATE_URL`, and `NATWG_UPDATE_REPOSITORY`
override the matching config fields. `natwg update` also accepts
`--download-url` and `--repository`. A root service does not inherit an
interactive user's GitHub credentials. In natwg 0.4.0 the GitHub path
requires a token even for a public repository; the download site is anonymous.
See [the update guide](updates.md) for credentials, service restarts, and
rollback behavior.
