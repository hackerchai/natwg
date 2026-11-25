#!/bin/sh
# Build the release archive of natwg for one target into target/packages.
# Publication is a separate CI step.
set -eu
repo_dir=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_dir"
package_target=${1:?usage: scripts/package.sh TARGET}
case "$package_target" in
  aarch64-apple-darwin|x86_64-apple-darwin|aarch64-unknown-linux-musl|x86_64-unknown-linux-musl) ;;
  *) echo 'Unsupported package target' >&2; exit 1 ;;
esac
package_version=$(cargo metadata --format-version 1 --no-deps --locked | python3 -c 'import json,sys; print(json.load(sys.stdin)["packages"][0]["version"])')
package_name="natwg-$package_version-$package_target"
package_dir="$repo_dir/target/packages/$package_name"
build_dir=${CARGO_TARGET_DIR:-"$repo_dir/target"}
rm -rf "$package_dir"
mkdir -p "$package_dir/bin"
# Hash the build inputs before building and check them afterwards, so an edit
# during the build cannot produce an archive that describes other sources.
{
  printf '%s\n' Cargo.toml Cargo.lock LICENSE README.md
  find src tests scripts .github -type f ! -name '*.pyc' ! -path '*/__pycache__/*'
} | LC_ALL=C sort | while IFS= read -r package_input; do
  shasum -a 256 "$package_input"
done > "$package_dir/SOURCE-MANIFEST.sha256"
cargo build --release --locked --target "$package_target"
if ! shasum -a 256 -c "$package_dir/SOURCE-MANIFEST.sha256" > /dev/null; then
  echo 'Build inputs changed during packaging; build this archive again.' >&2
  exit 1
fi
{
  printf 'version=%s\ntarget=%s\nbuilt_utc=%s\n' "$package_version" "$package_target" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf 'source_manifest_sha256=%s\n' "$(shasum -a 256 "$package_dir/SOURCE-MANIFEST.sha256" | cut -d ' ' -f 1)"
  printf 'git_commit=%s\n' "$(git rev-parse --verify HEAD 2>/dev/null || printf 'uncommitted-source-snapshot')"
  rustc -Vv
  cargo -V
  uname -srm
} > "$package_dir/BUILD-INFO.txt"
cp "$build_dir/$package_target/release/natwg" "$package_dir/bin/natwg"
chmod 755 "$package_dir/bin/natwg"
cp scripts/install.sh "$package_dir/install.sh"
chmod 755 "$package_dir/install.sh"
cp README.md "$package_dir/README.md"
cp LICENSE "$package_dir/LICENSE"
printf '%s\n' "$package_target" > "$package_dir/TARGET"
(cd "$package_dir" && shasum -a 256 bin/natwg install.sh README.md LICENSE TARGET SOURCE-MANIFEST.sha256 BUILD-INFO.txt > SHA256SUMS)
(cd "$repo_dir/target/packages" && tar -czf "$package_name.tar.gz" "$package_name" && shasum -a 256 "$package_name.tar.gz" > "$package_name.tar.gz.sha256")
printf '%s\n' "$repo_dir/target/packages/$package_name.tar.gz"
