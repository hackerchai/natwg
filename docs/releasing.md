# Releasing natwg

Every push, pull request and merge queue commit runs CI: Rust formatting,
Clippy with warnings denied, the tests and crate packaging on Linux and macOS,
and the offline checks of the download site upload
(`scripts/test-download-site.py`).

## Versions

Conventional commits feed Release Please after a successful CI run on `main`.
While natwg is before 1.0, a feature commit raises the minor version and a fix
the patch version. Its pull request updates `Cargo.toml`, `Cargo.lock`, the
changelog and `.release-please-manifest.json` together. GitHub runs no
workflow for events that `GITHUB_TOKEN` creates, so the release workflow
dispatches CI on the release pull request itself.

Merging the release pull request creates the tag `vX.Y.Z` and a draft release,
then calls the `Publish` workflow in the same run.

## Publish

`Publish` checks that the tag names a commit on `main` whose versions match
the tag, and runs CI again on that commit. Then it builds a release archive
for each platform with `scripts/package.sh`:

| Target | Runner |
| --- | --- |
| `aarch64-apple-darwin` | `macos-15` |
| `x86_64-apple-darwin` | `macos-15-intel` |
| `x86_64-unknown-linux-musl` | `ubuntu-24.04` with `musl-tools` |
| `aarch64-unknown-linux-musl` | `ubuntu-24.04-arm` with `musl-tools` |

Each archive `natwg-X.Y.Z-TARGET.tar.gz` holds `bin/natwg`, `install.sh`,
`README.md`, `README.zh-CN.md`, the `docs/` guides, `LICENSE`, `TARGET`,
`BUILD-INFO.txt` (toolchain, build host
and commit), `SOURCE-MANIFEST.sha256` (the build inputs) and `SHA256SUMS`, and
has a `.sha256` file beside it.

The publish job then runs these steps in order. Each must pass before the
next one starts:

1. Write `preflight/check.txt` (`Cache-Control: no-store`) to the R2 bucket,
   which proves that the credentials can publish before anything is
   published.
2. Attach the archives, their checksums and a source archive to the draft
   release.
3. Publish the crate to crates.io (`scripts/publish-crate.py`).
4. Write the update manifest `natwg-update.json` (`scripts/update-manifest.py`)
   after checking each archive against its checksum and its `TARGET`.
5. Attach the manifest and publish the release as the latest.
6. Upload to the download site (`scripts/publish-download-site.py`).

`natwg update` installs only a release whose manifest is in place. GitHub
locks the assets of a published release, so the manifest goes up last there,
and the latest manifest goes up last on the download site.

## Download site

The R2 bucket `natwg-dl` of the Cloudflare account serves
`https://natwg-dl.hackerchai.com`:

| Key | Cache-Control |
| --- | --- |
| `v{version}/natwg-{version}-{target}.tar.gz` and `.sha256` | `public, max-age=31536000, immutable` |
| `v{version}/natwg-update.json` | `public, max-age=31536000, immutable` |
| `v{version}/install.sh` | `public, max-age=31536000, immutable` |
| `install.sh` | `public, max-age=300` |
| `latest/natwg-update.json` | `public, max-age=300`, uploaded last |
| `preflight/check.txt` | `no-store` |

`install.sh` is `scripts/install-latest.sh`, the installer behind
`curl -fsSL https://natwg-dl.hackerchai.com/install.sh | bash`. Every release
uploads it with the archives. A change to it on `main` needs no release: the
`Installer` workflow (`.github/workflows/installer.yml`) runs its tests,
uploads only `install.sh` (`scripts/publish-download-site.py --installer`),
then installs the latest release with the hosted copy. Run that workflow by
hand to upload it again.

`scripts/publish-download-site.py` checks each archive against the manifest
and its `.sha256` file before it uploads anything. It writes through the S3
API of R2 (`https://<account>.r2.cloudflarestorage.com/natwg-dl/<key>`, region
`auto`) with AWS Signature Version 4. The credentials come from the
environment and never reach a command line. Requests that fail with HTTP 5xx,
429 or a network error are retried three times.

The manifest names the version and, for each of the four targets, the archive
and its SHA-256:

```json
{
  "schema": 1,
  "version": "0.3.0",
  "artifacts": [
    {
      "target": "aarch64-apple-darwin",
      "asset": "natwg-0.3.0-aarch64-apple-darwin.tar.gz",
      "sha256": "…"
    }
  ]
}
```

The GitHub Releases of `hackerchai/natwg` carry the same archives and
manifest. `natwg update` falls back to them when the download site fails;
in natwg 0.4.0, that path requires a GitHub token even for a public repository.
The download site requires no authentication.

## Secrets

| Name | Use |
| --- | --- |
| `CARGO_REGISTRY_TOKEN` | Publish `natwg` to crates.io |
| `R2_ACCESS_KEY_ID` | S3 access key of the R2 API token, scoped to the objects of `natwg-dl` |
| `R2_SECRET_ACCESS_KEY` | Its secret |
| `CLOUDFLARE_ACCOUNT_ID` | The account of the bucket, which names the S3 endpoint |

The release workflow passes them to `Publish` with `secrets: inherit`.

## Retry

Run the `Publish` workflow by hand with the existing tag. A step that passed
before passes again:

- The bucket check writes the same marker again.
- While the release is a draft, its assets are uploaded again. Once it is
  published, the retry downloads its locked assets, checks their checksums,
  and builds the manifest again to compare it with the published one byte for
  byte. A release that was published before its manifest was attached needs a
  new version.
- crates.io accepts an existing version only when its checksum matches the
  crate exactly. A crate cannot be overwritten; a different one needs a new
  version.
- The download site gets the same bytes again, the latest manifest last.

## Recovery

A published crate cannot be overwritten: release a fix as a new version, or
yank a broken version after review. To withdraw a release from `natwg update`,
upload the manifest of the previous version to `latest/natwg-update.json`;
the updater never downgrades an installed binary, so this only stops new
updates. On a host, `natwg update` keeps the binary it replaced beside it as
`.natwg.previous`; `sudo natwg update` restores it on its own when a service
does not come back.
