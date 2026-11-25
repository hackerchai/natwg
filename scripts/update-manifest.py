#!/usr/bin/env python3
"""Write the update manifest after checking every release archive.

The manifest is the updater's readiness marker: CI writes it only after all
release gates have passed, and publishes it after the archives it names.
"""
import hashlib
import json
from pathlib import Path
import tarfile
import tomllib

TARGETS = (
    'aarch64-apple-darwin', 'x86_64-apple-darwin',
    'aarch64-unknown-linux-musl', 'x86_64-unknown-linux-musl',
)


def manifest(directory, version):
    artifacts = []
    for target in TARGETS:
        prefix = f'natwg-{version}-{target}'
        archive = directory / f'{prefix}.tar.gz'
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        if archive.with_name(archive.name + '.sha256').read_text().split()[0] != digest:
            raise SystemExit(f'{archive.name} does not match its .sha256 file')
        with tarfile.open(archive) as bundle:
            if bundle.extractfile(f'{prefix}/TARGET').read().decode().strip() != target:
                raise SystemExit(f'{archive.name} holds another target')
            if not bundle.getmember(f'{prefix}/bin/natwg').isfile():
                raise SystemExit(f'{archive.name} has no bin/natwg')
        artifacts.append({'target': target, 'asset': archive.name, 'sha256': digest})
    return {'schema': 1, 'version': version, 'artifacts': artifacts}


def main():
    version = tomllib.loads(Path('Cargo.toml').read_text())['package']['version']
    directory = Path('target/packages')
    (directory / 'natwg-update.json').write_text(
        json.dumps(manifest(directory, version), indent=2) + '\n')


if __name__ == '__main__':
    main()
