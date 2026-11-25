#!/bin/sh
# Install natwg from this archive. Check the archive against its checksum,
# from a source you trust, before you run this.
set -eu
umask 022
package_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
install_dir=${NATWG_INSTALL_DIR:-/usr/local/bin}
case "$install_dir" in /*) ;; *) echo 'NATWG_INSTALL_DIR must be an absolute path' >&2; exit 1 ;; esac
case "$(uname -s):$(uname -m):$(cat "$package_dir/TARGET")" in
  Darwin:arm64:aarch64-apple-darwin|Darwin:x86_64:x86_64-apple-darwin|Linux:aarch64:aarch64-unknown-linux-musl|Linux:arm64:aarch64-unknown-linux-musl|Linux:x86_64:x86_64-unknown-linux-musl) ;;
  *) echo 'This archive is for another OS or architecture' >&2; exit 1 ;;
esac
(cd "$package_dir" && if command -v sha256sum >/dev/null 2>&1; then sha256sum -c SHA256SUMS; else shasum -a 256 -c SHA256SUMS; fi)
if ! mkdir -p "$install_dir" 2>/dev/null || [ ! -w "$install_dir" ]; then
  echo "Cannot write $install_dir; run sudo ./install.sh, or set NATWG_INSTALL_DIR to a directory you can write" >&2
  exit 1
fi
if [ -d "$install_dir/natwg" ]; then
  echo "Refusing to replace the directory $install_dir/natwg" >&2
  exit 1
fi
install_tmp=$(mktemp "$install_dir/.natwg.XXXXXXXX")
trap 'test -z "${install_tmp:-}" || rm -f "$install_tmp"' EXIT HUP INT TERM
cp "$package_dir/bin/natwg" "$install_tmp"
chmod 755 "$install_tmp"
mv -f "$install_tmp" "$install_dir/natwg"
install_tmp=''
printf 'Installed %s/natwg (%s)\n' "$install_dir" "$("$install_dir/natwg" --version)"
printf 'Next: write the config, then run sudo natwg service install. README.md has the steps.\n'
