#!/usr/bin/env bash
# Install the newest natwg release from the natwg download site:
#
#   curl -fsSL https://natwg-dl.hackerchai.com/install.sh | bash
#
# It reads latest/natwg-update.json, downloads the archive for this OS and
# CPU, checks it against the SHA-256 that the manifest names, checks that the
# binary runs and reports its version, and puts it at /usr/local/bin/natwg,
# through sudo when that directory is not writable. Every release uploads this
# script to the download site, as install.sh and v<version>/install.sh.
#
#   NATWG_VERSION       install this version instead of the newest, e.g. 0.3.0
#   NATWG_INSTALL_DIR   install into this absolute path instead of /usr/local/bin
#   NATWG_DOWNLOAD_URL  another download site with the same layout
#
# Everything runs inside main, so a download cut short runs nothing.
set -euo pipefail

say() { printf '%s\n' "$*"; }
fail() {
  printf 'natwg install: %s\n' "$*" >&2
  exit 1
}

# The release target of this host. A shell translated by Rosetta still gets
# the native Apple silicon build.
detect_target() {
  local os arch
  os=$(uname -s)
  arch=$(uname -m)
  if [ "$os" = Darwin ] && [ "$arch" = x86_64 ] &&
    [ "$(sysctl -n sysctl.proc_translated 2>/dev/null || true)" = 1 ]; then
    arch=arm64
  fi
  case "$os:$arch" in
    Darwin:arm64) echo aarch64-apple-darwin ;;
    Darwin:x86_64) echo x86_64-apple-darwin ;;
    Linux:aarch64 | Linux:arm64) echo aarch64-unknown-linux-musl ;;
    Linux:x86_64 | Linux:amd64) echo x86_64-unknown-linux-musl ;;
    *) fail "no natwg release is built for $os on $arch" ;;
  esac
}

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d ' ' -f 1
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | cut -d ' ' -f 1
  else
    fail 'neither sha256sum nor shasum is installed'
  fi
}

# The value of the string field `name` in one line of compact JSON.
field() {
  sed -n "s/.*\"$1\":\"\\([^\"]*\\)\".*/\\1/p" | head -n 1
}

main() {
  local site=${NATWG_DOWNLOAD_URL:-https://natwg-dl.hackerchai.com}
  local install_dir=${NATWG_INSTALL_DIR:-/usr/local/bin}
  local pinned=${NATWG_VERSION:-}
  site=${site%/}

  command -v curl >/dev/null 2>&1 || fail 'curl is required'
  command -v tar >/dev/null 2>&1 || fail 'tar is required'
  # An exact https:// origin, or loopback http:// for tests.
  local proto
  if [[ $site =~ ^https://[A-Za-z0-9.-]+(:[0-9]+)?$ ]]; then
    proto='=https'
  elif [[ $site =~ ^http://127\.0\.0\.1(:[0-9]+)?$ ]]; then
    proto='=http'
  else
    fail "NATWG_DOWNLOAD_URL must be an https:// origin such as https://natwg-dl.hackerchai.com, not $site"
  fi
  case "$install_dir" in
    /*) ;;
    *) fail "NATWG_INSTALL_DIR must be an absolute path, not $install_dir" ;;
  esac
  if [ -n "$pinned" ] && ! [[ $pinned =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    fail "NATWG_VERSION must look like 0.3.0, not $pinned"
  fi

  local target
  target=$(detect_target)
  local work
  work=$(mktemp -d 2>/dev/null || mktemp -d -t natwg)
  # shellcheck disable=SC2064 # expand $work now: it is local to main
  trap "rm -rf '$work'" EXIT
  fetch() {
    curl --proto "$proto" --fail --silent --show-error --location \
      --retry 3 --connect-timeout 10 --max-time 300 -o "$2" "$site/$1"
  }

  local manifest_path=latest/natwg-update.json
  [ -n "$pinned" ] && manifest_path="v$pinned/natwg-update.json"
  say "Reading $site/$manifest_path"
  fetch "$manifest_path" "$work/manifest.json" ||
    fail "could not read $site/$manifest_path"
  local manifest version entry asset sha256
  manifest=$(tr -d ' \t\r\n' <"$work/manifest.json")
  [[ $manifest == *'"schema":1,'* || $manifest == *'"schema":1}'* ]] ||
    fail 'the update manifest has an unknown schema; install natwg by hand, see the README'
  version=$(printf '%s' "$manifest" | field version)
  [[ $version =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail 'the update manifest names no version'
  if [ -n "$pinned" ] && [ "$version" != "$pinned" ]; then
    fail "the manifest of $pinned names version $version"
  fi
  # One artifact per line, then the one of this target.
  entry=$(printf '%s' "$manifest" | tr '}' '\n' | grep -F "\"target\":\"$target\"" | head -n 1 || true)
  [ -n "$entry" ] || fail "natwg $version has no archive for $target"
  asset=$(printf '%s' "$entry" | field asset)
  sha256=$(printf '%s' "$entry" | field sha256)
  [ "$asset" = "natwg-$version-$target.tar.gz" ] || fail "unexpected archive name $asset"
  [[ $sha256 =~ ^[0-9a-f]{64}$ ]] || fail "the manifest has no SHA-256 for $asset"

  say "Downloading natwg $version for $target"
  fetch "v$version/$asset" "$work/$asset" || fail "could not download $site/v$version/$asset"
  [ "$(sha256_of "$work/$asset")" = "$sha256" ] ||
    fail "$asset does not match the SHA-256 in the manifest; nothing was installed"

  local prefix="natwg-$version-$target"
  tar -xzf "$work/$asset" -C "$work" "$prefix/bin/natwg" "$prefix/TARGET" ||
    fail "$asset does not hold $prefix/bin/natwg"
  [ "$(cat "$work/$prefix/TARGET")" = "$target" ] || fail "$asset is not built for $target"
  local binary="$work/$prefix/bin/natwg"
  if [ ! -f "$binary" ] || [ -L "$binary" ]; then
    fail "$prefix/bin/natwg is not a regular file"
  fi
  chmod 755 "$binary"
  local reported
  reported=$("$binary" --version 2>/dev/null || true)
  [ "$reported" = "natwg $version" ] ||
    fail "the downloaded natwg reports '$reported', not 'natwg $version'; nothing was installed"

  local sudo=
  if ! { mkdir -p "$install_dir" 2>/dev/null && [ -w "$install_dir" ]; }; then
    if [ "$(id -u)" != 0 ] && command -v sudo >/dev/null 2>&1; then
      say "Installing into $install_dir needs root; asking sudo"
      sudo=sudo
      $sudo mkdir -p "$install_dir"
    else
      fail "cannot write $install_dir; set NATWG_INSTALL_DIR to a directory you can write"
    fi
  fi
  [ ! -d "$install_dir/natwg" ] || fail "$install_dir/natwg is a directory; refusing to replace it"
  # Copy beside the target, then rename, so natwg is never half written.
  local stage="$install_dir/.natwg.new.$$"
  $sudo cp "$binary" "$stage"
  $sudo chmod 755 "$stage"
  $sudo mv -f "$stage" "$install_dir/natwg"
  say "Installed $install_dir/natwg ($("$install_dir/natwg" --version))"

  case ":$PATH:" in
    *":$install_dir:"*) ;;
    *) say "$install_dir is not on PATH; add it, or run $install_dir/natwg" ;;
  esac
  local service=/usr/local/libexec/natwg/natwg
  if [ -e "$service" ]; then
    if [ "$("$service" --version 2>/dev/null || true)" != "natwg $version" ]; then
      say "The natwg service runs its own copy at $service; bring it to $version with: sudo natwg update"
    fi
  else
    say 'Next: write the config, then run sudo natwg service install.'
    say 'See https://crates.io/crates/natwg for the README.'
  fi
}

main "$@"
