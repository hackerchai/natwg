#!/usr/bin/env python3
"""Upload the natwg archives and the update manifest to the R2 download site.

Run after the GitHub Release is final. Versioned files go up first and
`latest/natwg-update.json` last, so the updater never sees a version whose
archives are missing. A retry uploads the same bytes again. `--check` writes a
small marker object and nothing else, proving that the credentials can publish
before anything else is published.

Uploads go through the S3 API of R2, signed with AWS Signature Version 4:
R2_ACCESS_KEY_ID and R2_SECRET_ACCESS_KEY (scoped to the objects of the bucket)
and CLOUDFLARE_ACCOUNT_ID come from the environment and never reach argv.
"""
import datetime
import hashlib
import hmac
import json
import os
from pathlib import Path
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

BUCKET = 'natwg-dl'
MANIFEST = 'natwg-update.json'
IMMUTABLE = 'public, max-age=31536000, immutable'
LATEST = 'public, max-age=300'
NO_STORE = 'no-store'
CHECK_KEY = 'preflight/check.txt'
TARGETS = ('aarch64-apple-darwin', 'x86_64-apple-darwin',
           'aarch64-unknown-linux-musl', 'x86_64-unknown-linux-musl')
ATTEMPTS = 4


def plan(directory):
    """(key, file, cache-control) in upload order, after checking every archive."""
    manifest = json.loads((directory / MANIFEST).read_text())
    version = manifest.get('version')
    artifacts = manifest.get('artifacts', [])
    if (manifest.get('schema') != 1 or not isinstance(version, str)
            or sorted(a.get('target') for a in artifacts) != sorted(TARGETS)):
        raise SystemExit('Unexpected update manifest; download site not updated.')
    uploads = []
    for artifact in artifacts:
        name = f"natwg-{version}-{artifact['target']}.tar.gz"
        if artifact.get('asset') != name:
            raise SystemExit(f'Unexpected asset {artifact.get("asset")!r}; download site not updated.')
        archive = directory / name
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        if digest != artifact['sha256']:
            raise SystemExit(f'Checksum mismatch for {name}; download site not updated.')
        checksum = archive.with_name(name + '.sha256')
        if checksum.read_text().split() != [digest, name]:
            raise SystemExit(f'{checksum.name} does not match {name}; download site not updated.')
        uploads += [(f'v{version}/{name}', archive, IMMUTABLE),
                    (f'v{version}/{checksum.name}', checksum, IMMUTABLE)]
    uploads.append((f'v{version}/{MANIFEST}', directory / MANIFEST, IMMUTABLE))
    uploads.append((f'latest/{MANIFEST}', directory / MANIFEST, LATEST))
    return uploads


def content_type(key):
    if key.endswith('.json'):
        return 'application/json'
    if key.endswith('.tar.gz'):
        return 'application/gzip'
    return 'text/plain; charset=utf-8'


def _hmac(key, text):
    return hmac.new(key, text.encode(), hashlib.sha256).digest()


def sign(method, url, headers, payload_sha256, access_key, secret_key, now,
         region='auto', service='s3'):
    """The headers of a SigV4 request: `headers` plus host, x-amz-date,
    x-amz-content-sha256 and Authorization, every one of them signed."""
    parts = urllib.parse.urlsplit(url)
    amz_date = now.strftime('%Y%m%dT%H%M%SZ')
    day = amz_date[:8]
    signed = {name.lower(): ' '.join(str(value).split()) for name, value in headers.items()}
    signed.update({'host': parts.netloc, 'x-amz-content-sha256': payload_sha256,
                   'x-amz-date': amz_date})
    names = sorted(signed)
    query = '&'.join(sorted(
        f"{urllib.parse.quote(k, safe='-_.~')}={urllib.parse.quote(v, safe='-_.~')}"
        for k, v in urllib.parse.parse_qsl(parts.query, keep_blank_values=True)))
    canonical = '\n'.join([
        method,
        urllib.parse.quote(parts.path or '/', safe='/-_.~'),
        query,
        ''.join(f'{name}:{signed[name]}\n' for name in names),
        ';'.join(names),
        payload_sha256,
    ])
    scope = f'{day}/{region}/{service}/aws4_request'
    to_sign = '\n'.join(['AWS4-HMAC-SHA256', amz_date, scope,
                         hashlib.sha256(canonical.encode()).hexdigest()])
    key = _hmac(('AWS4' + secret_key).encode(), day)
    for part in (region, service, 'aws4_request'):
        key = _hmac(key, part)
    signature = hmac.new(key, to_sign.encode(), hashlib.sha256).hexdigest()
    signed['authorization'] = (f'AWS4-HMAC-SHA256 Credential={access_key}/{scope}, '
                               f"SignedHeaders={';'.join(names)}, Signature={signature}")
    return signed


def put(endpoint, credentials, key, body, cache_control, now=None):
    """PUT `body` at `key` of the bucket, retrying a failure that may pass."""
    url = f'{endpoint}/{BUCKET}/{urllib.parse.quote(key, safe="/-_.~")}'
    payload = hashlib.sha256(body).hexdigest()
    for attempt in range(1, ATTEMPTS + 1):
        headers = sign('PUT', url, {'Content-Type': content_type(key),
                                    'Cache-Control': cache_control},
                       payload, *credentials,
                       now or datetime.datetime.now(datetime.timezone.utc))
        request = urllib.request.Request(url, data=body, method='PUT', headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=120) as response:
                response.read()
            return
        except urllib.error.HTTPError as error:
            with error:
                detail = error.read()[:500].decode(errors='replace')
            if error.code < 500 and error.code != 429 or attempt == ATTEMPTS:
                raise SystemExit(f'Uploading {key} failed: HTTP {error.code} {detail}') from None
        except (urllib.error.URLError, TimeoutError, ConnectionError) as error:
            if attempt == ATTEMPTS:
                raise SystemExit(f'Uploading {key} failed: {error}') from None
        time.sleep(2 ** attempt)


def publish(directory, endpoint, credentials):
    for key, path, cache in plan(directory):
        put(endpoint, credentials, key, path.read_bytes(), cache)
        print('Uploaded', key)


def check(endpoint, credentials):
    put(endpoint, credentials, CHECK_KEY, b'publish check\n', NO_STORE)
    print('The download site is writable')


def environment():
    names = ('CLOUDFLARE_ACCOUNT_ID', 'R2_ACCESS_KEY_ID', 'R2_SECRET_ACCESS_KEY')
    missing = [name for name in names if not os.environ.get(name)]
    if missing:
        raise SystemExit(f"Set {', '.join(missing)}; download site not updated.")
    account = os.environ['CLOUDFLARE_ACCOUNT_ID']
    if not account.isalnum():
        raise SystemExit('CLOUDFLARE_ACCOUNT_ID is not an account ID.')
    endpoint = f'https://{account}.r2.cloudflarestorage.com'
    return endpoint, (os.environ['R2_ACCESS_KEY_ID'], os.environ['R2_SECRET_ACCESS_KEY'])


def main():
    if sys.argv[1:] == ['--check']:
        check(*environment())
        return
    directory = Path(sys.argv[1] if len(sys.argv) > 1 else 'target/packages')
    plan(directory)  # Refuse a broken set before touching the bucket.
    publish(directory, *environment())


if __name__ == '__main__':
    main()
