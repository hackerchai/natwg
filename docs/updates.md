# Update natwg

```sh
natwg update --check   # the installed and the latest version; needs no root
sudo natwg update      # install the latest release and restart the services
```

`natwg update` downloads the archive of this platform from the download site,
and from the GitHub Releases of `hackerchai/natwg` when the site fails. It
checks the archive against the SHA-256 that the release's manifest names and
runs the new binary's `--version` before it replaces anything. Then it:

- replaces the service binary `/usr/local/libexec/natwg/natwg` and the natwg
  you ran, such as `/usr/local/bin/natwg` or `~/.cargo/bin/natwg`, each in one
  step with its owner and mode, so a `sudo natwg update` of a cargo install
  leaves it yours. The file it replaced stays beside it as `.natwg.previous`;
- restarts each natwg service that runs, server instances and the client, one
  at a time, and waits until each brings its tunnel up again. When one does
  not, natwg puts every previous binary back, restarts the services again and
  fails. A stopped service stays stopped and runs the new binary when it
  starts.

natwg never downgrades a binary. When the natwg you ran is up to date but the
service binary is older, as after a `cargo install` without a
`natwg service install`, `sudo natwg update` brings the service binary to the
latest release and restarts the services. A natwg that Homebrew or Nix owns is
upgraded with that package manager instead. Two updates never run at once.

## GitHub fallback and other sources

In natwg 0.4.0, the GitHub fallback requires a token even when the repository
is public. The download site works without authentication. For a private
repository, the token needs Contents: read. natwg takes `GH_TOKEN` or `GITHUB_TOKEN`, else asks
`gh auth token`, run under sudo as the user who ran sudo. sudo drops the
environment, so to pass a token on, export it and name it, which keeps it off
the command line:

```sh
export GH_TOKEN="$(gh auth token)"
sudo --preserve-env=GH_TOKEN natwg update
```

`--download-url ORIGIN` (or `NATWG_UPDATE_URL`) picks another download site
with the same layout, an exact `https://` origin. `--repository OWNER/REPO`
(or `NATWG_UPDATE_REPOSITORY`) skips the download site and uses the GitHub
Releases of that repository alone. The `update` object of the config sets
them as well; see the [configuration reference](configuration.md#update-settings).

## Automatic update check

By default, a running server or client checks for a newer release a minute
after it starts, then at most once a day. The check runs in the background with a
20-second limit, so it never holds up or fails the tunnel, and every natwg
service on the host shares its answer
(`/usr/local/var/natwg/update-check.json` on macOS,
`/var/lib/natwg/update-check.json` on Linux). It never installs anything:
the service writes the newest version into its status file, and
`natwg status` then prints

```text
Update available: 0.3.0 -> 0.4.0. Run sudo natwg update.
```

The optional `update` object of the config sets the interval, or turns the
check off, and the sources. This fragment belongs at the top level of the full config:

```json
{
	"update": {
		"check": "6h",
		"url": "https://natwg-dl.hackerchai.com"
	}
}
```

- `check` is `off`, or an interval of at least an hour such as `6h` or `2d`
  (default `1d`). `NATWG_UPDATE_CHECK` overrides it.
- `url` and `repository` work as `--download-url` and `--repository` do, for
  the check and for `natwg update`. A `repository` skips the download site,
  and a root service has no GitHub token, so leave it out unless the service
  can reach that repository.
- A check that fails is logged once, until one succeeds again.

Restart the service to load a change. For a default server, run
`sudo natwg service restart`. For the client path used in the README, run
`sudo natwg --config /etc/natwg/client.json service restart`.
