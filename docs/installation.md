# Install natwg

```sh
curl -fsSL https://natwg-dl.hackerchai.com/install.sh | bash
```

The installer reads the newest release from the download site, downloads the
archive for this OS and CPU, checks it against the SHA-256 in the release
manifest, checks that the binary runs and reports that version, and puts it
at `/usr/local/bin/natwg`, through sudo when that directory is not writable.
It is [`scripts/install-latest.sh`](https://github.com/hackerchai/natwg/blob/main/scripts/install-latest.sh); read it first
if you like (`curl -fsSL https://natwg-dl.hackerchai.com/install.sh | less`).
Three variables change what it does:

```sh
curl -fsSL https://natwg-dl.hackerchai.com/install.sh | NATWG_VERSION=0.4.0 bash     # this version
curl -fsSL https://natwg-dl.hackerchai.com/install.sh | NATWG_INSTALL_DIR=$HOME/.local/bin bash
curl -fsSL https://natwg-dl.hackerchai.com/install.sh | NATWG_DOWNLOAD_URL=https://mirror.example bash
```

Running it again installs the newest release over the old one. For a natwg
that runs as a service, `sudo natwg update` (see [Update natwg](updates.md)) also
updates the service's own copy and restarts it.

Each release has a binary archive for macOS (Apple silicon and Intel) and for
Linux (arm64 and x86_64, static musl builds) on the download site
`https://natwg-dl.hackerchai.com`. To install one by hand:

```sh
site=https://natwg-dl.hackerchai.com
version=$(curl -fsSL "$site/latest/natwg-update.json" | sed -n 's/.*"version": "\([^"]*\)".*/\1/p')
target=aarch64-apple-darwin   # x86_64-apple-darwin, aarch64-unknown-linux-musl, x86_64-unknown-linux-musl
curl -fLO "$site/v$version/natwg-$version-$target.tar.gz"
curl -fLO "$site/v$version/natwg-$version-$target.tar.gz.sha256"
shasum -a 256 -c "natwg-$version-$target.tar.gz.sha256"   # sha256sum -c on Linux
tar -xzf "natwg-$version-$target.tar.gz"
sudo "./natwg-$version-$target/install.sh"
```

`latest/natwg-update.json` names the newest version and the SHA-256 of each
of its archives, and the files under `v<version>/` never change. The
archive's own `install.sh` checks the files of the archive against its `SHA256SUMS` and copies `natwg`
to `/usr/local/bin`; `NATWG_INSTALL_DIR` picks another directory. The GitHub
Releases of `hackerchai/natwg` carry the same archives.

With Rust 1.99 or newer, cargo builds natwg from crates.io instead:

```sh
cargo install natwg --locked
```
