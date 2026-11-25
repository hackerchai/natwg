#!/usr/bin/env python3
"""Offline checks of the download site: the upload plan, the SigV4 signature
and the requests against a stub S3 endpoint on this host, and the installer
against a download site on this host."""
import datetime
import functools
import hashlib
import http.server
import importlib.util
import io
import json
import os
from pathlib import Path
import platform
import subprocess
import tarfile
import tempfile
import threading
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('site', Path(__file__).with_name('publish-download-site.py'))
site = importlib.util.module_from_spec(spec)
spec.loader.exec_module(site)

# The examples of the Amazon S3 documentation for Signature Version 4.
EXAMPLE_KEYS = ('AKIAIOSFODNN7EXAMPLE', 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY')
EXAMPLE_DATE = datetime.datetime(2013, 5, 24, tzinfo=datetime.timezone.utc)


class Release(unittest.TestCase):
    """A directory with the archives and the manifest of natwg 1.2.3."""
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        artifacts = []
        for target in site.TARGETS:
            name = f'natwg-1.2.3-{target}.tar.gz'
            data = target.encode()
            digest = hashlib.sha256(data).hexdigest()
            (self.directory / name).write_bytes(data)
            (self.directory / f'{name}.sha256').write_text(f'{digest}  {name}\n')
            artifacts.append({'target': target, 'asset': name, 'sha256': digest})
        self.manifest = {'schema': 1, 'version': '1.2.3', 'artifacts': artifacts}
        self.write_manifest()

    def write_manifest(self):
        (self.directory / site.MANIFEST).write_text(json.dumps(self.manifest))


class PlanTests(Release):
    def test_archives_first_and_the_latest_manifest_last(self):
        (self.directory / 'natwg-1.2.3-source.tar.gz').write_bytes(b'source')
        plan = site.plan(self.directory)
        keys = [key for key, _, _ in plan]
        self.assertEqual(keys[-1], 'latest/natwg-update.json')
        self.assertEqual(keys[-2], 'install.sh')
        self.assertEqual(keys[-3], 'v1.2.3/natwg-update.json')
        self.assertEqual(keys[-4], 'v1.2.3/install.sh')
        self.assertEqual(len(keys), 12)
        self.assertFalse(any('source' in key for key in keys))
        for key, _, cache in plan[:-2]:
            self.assertTrue(key.startswith('v1.2.3/'), key)
            self.assertEqual(cache, 'public, max-age=31536000, immutable')
        for _, path, cache in plan[-2:]:
            self.assertEqual(cache, 'public, max-age=300')
        self.assertEqual(plan[-2][1], site.INSTALLER)

    def test_a_checksum_mismatch_stops_the_upload(self):
        name = f'natwg-1.2.3-{site.TARGETS[0]}.tar.gz'
        (self.directory / name).write_bytes(b'tampered')
        with self.assertRaises(SystemExit):
            site.plan(self.directory)

    def test_a_checksum_file_for_other_bytes_stops_the_upload(self):
        name = f'natwg-1.2.3-{site.TARGETS[1]}.tar.gz'
        (self.directory / f'{name}.sha256').write_text(f'{"0" * 64}  {name}\n')
        with self.assertRaises(SystemExit):
            site.plan(self.directory)

    def test_a_manifest_without_every_target_stops_the_upload(self):
        self.manifest['artifacts'].pop()
        self.write_manifest()
        with self.assertRaises(SystemExit):
            site.plan(self.directory)

    def test_an_asset_of_another_version_stops_the_upload(self):
        self.manifest['artifacts'][0]['asset'] = f'natwg-1.2.2-{site.TARGETS[0]}.tar.gz'
        self.write_manifest()
        with self.assertRaises(SystemExit):
            site.plan(self.directory)


class SignatureTests(unittest.TestCase):
    def test_the_get_object_example(self):
        headers = site.sign('GET', 'https://examplebucket.s3.amazonaws.com/test.txt',
                            {'Range': 'bytes=0-9'}, hashlib.sha256(b'').hexdigest(),
                            *EXAMPLE_KEYS, EXAMPLE_DATE, region='us-east-1')
        self.assertEqual(
            headers['authorization'],
            'AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, '
            'SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, '
            'Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41')

    def test_the_put_object_example(self):
        # The path arrives encoded, as put() sends it, and is signed once.
        body = b'Welcome to Amazon S3.'
        headers = site.sign('PUT', 'https://examplebucket.s3.amazonaws.com/test%24file.text',
                            {'Date': 'Fri, 24 May 2013 00:00:00 GMT',
                             'x-amz-storage-class': 'REDUCED_REDUNDANCY'},
                            hashlib.sha256(body).hexdigest(), *EXAMPLE_KEYS, EXAMPLE_DATE,
                            region='us-east-1')
        self.assertTrue(headers['authorization'].endswith(
            'Signature=98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd'))


class Stub(http.server.BaseHTTPRequestHandler):
    """An S3 endpoint that records each PUT and answers `statuses` in turn."""
    def do_PUT(self):
        body = self.rfile.read(int(self.headers['Content-Length']))
        self.server.puts.append((self.path, self.headers, body))
        status = self.server.statuses.pop(0) if self.server.statuses else 200
        self.send_response(status)
        self.send_header('Content-Length', '0')
        self.end_headers()

    def log_message(self, *args):
        pass


class UploadTests(Release):
    def setUp(self):
        super().setUp()
        self.server = http.server.HTTPServer(('127.0.0.1', 0), Stub)
        self.server.puts, self.server.statuses = [], []
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.endpoint = f'http://127.0.0.1:{self.server.server_address[1]}'
        self.credentials = ('AKIDTEST', 'secret-that-never-travels')
        patch = mock.patch.object(site.time, 'sleep')
        patch.start()
        self.addCleanup(patch.stop)

    def test_every_file_goes_to_the_bucket_with_its_type_and_caching(self):
        site.publish(self.directory, self.endpoint, self.credentials)
        puts = self.server.puts
        self.assertEqual([path for path, _, _ in puts],
                         [f'/natwg-dl/{key}' for key, _, _ in site.plan(self.directory)])
        for (path, headers, body), (_, file, cache) in zip(puts, site.plan(self.directory)):
            self.assertEqual(body, file.read_bytes())
            self.assertEqual(headers['x-amz-content-sha256'], hashlib.sha256(body).hexdigest())
            self.assertEqual(headers['Cache-Control'], cache)
            self.assertTrue(headers['Authorization'].startswith('AWS4-HMAC-SHA256 Credential=AKIDTEST/'))
            self.assertIn('/auto/s3/aws4_request', headers['Authorization'])
            self.assertIn('cache-control;content-type;host', headers['Authorization'])
            self.assertNotIn('secret-that-never-travels', str(headers))
        types = {path.rsplit('.', 1)[-1]: headers['Content-Type'] for path, headers, _ in puts}
        self.assertEqual(types, {'gz': 'application/gzip', 'sha256': 'text/plain; charset=utf-8',
                                 'sh': 'text/plain; charset=utf-8', 'json': 'application/json'})

    def test_the_installer_alone_goes_up_with_short_caching(self):
        site.installer(self.endpoint, self.credentials)
        [(path, headers, body)] = self.server.puts
        self.assertEqual(path, '/natwg-dl/install.sh')
        self.assertEqual(body, site.INSTALLER.read_bytes())
        self.assertEqual(headers['Cache-Control'], 'public, max-age=300')

    def test_the_check_writes_only_its_marker_uncached(self):
        site.check(self.endpoint, self.credentials)
        [(path, headers, body)] = self.server.puts
        self.assertEqual(path, '/natwg-dl/preflight/check.txt')
        self.assertEqual(body, b'publish check\n')
        self.assertEqual(headers['Cache-Control'], 'no-store')

    def test_a_server_error_is_retried_and_a_refusal_is_not(self):
        self.server.statuses = [503, 500]
        site.check(self.endpoint, self.credentials)
        self.assertEqual(len(self.server.puts), 3)
        self.server.puts.clear()
        self.server.statuses = [403]
        with self.assertRaises(SystemExit):
            site.check(self.endpoint, self.credentials)
        self.assertEqual(len(self.server.puts), 1)



def host_target():
    """The release target that the installer picks on this host."""
    return {
        ('Darwin', 'arm64'): 'aarch64-apple-darwin',
        ('Darwin', 'x86_64'): 'x86_64-apple-darwin',
        ('Linux', 'aarch64'): 'aarch64-unknown-linux-musl',
        ('Linux', 'arm64'): 'aarch64-unknown-linux-musl',
        ('Linux', 'x86_64'): 'x86_64-unknown-linux-musl',
    }[(platform.system(), platform.machine())]


class Quiet(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass


class InstallerTests(unittest.TestCase):
    """scripts/install-latest.sh against a download site on this host. Each
    natwg in it is a shell script that prints a version."""
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name) / 'site'
        self.bin = Path(temp.name) / 'bin'
        self.target = host_target()
        server = http.server.HTTPServer(
            ('127.0.0.1', 0), functools.partial(Quiet, directory=str(self.root)))
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        self.url = f'http://127.0.0.1:{server.server_address[1]}'
        self.release('1.2.2')
        self.release('1.2.3', latest=True)

    def release(self, version, latest=False, reports=None):
        """Put natwg `version` on the site, a natwg that reports `reports`."""
        directory = self.root / f'v{version}'
        directory.mkdir(parents=True, exist_ok=True)
        artifacts = []
        for target in site.TARGETS:
            prefix = f'natwg-{version}-{target}'
            data = io.BytesIO()
            with tarfile.open(fileobj=data, mode='w:gz') as archive:
                for name, body, mode in [
                    (f'{prefix}/bin/natwg', f'#!/bin/sh\necho "natwg {reports or version}"\n', 0o755),
                    (f'{prefix}/TARGET', f'{target}\n', 0o644),
                ]:
                    member = tarfile.TarInfo(name)
                    member.size, member.mode = len(body), mode
                    archive.addfile(member, io.BytesIO(body.encode()))
            (directory / f'{prefix}.tar.gz').write_bytes(data.getvalue())
            artifacts.append({'target': target, 'asset': f'{prefix}.tar.gz',
                              'sha256': hashlib.sha256(data.getvalue()).hexdigest()})
        manifest = json.dumps({'schema': 1, 'version': version, 'artifacts': artifacts}, indent=2)
        (directory / site.MANIFEST).write_text(manifest)
        if latest:
            (self.root / 'latest').mkdir(exist_ok=True)
            (self.root / 'latest' / site.MANIFEST).write_text(manifest)

    def install(self, piped=False, **env):
        environment = {'PATH': os.environ['PATH'], 'HOME': os.environ.get('HOME', '/'),
                       'NATWG_DOWNLOAD_URL': self.url, 'NATWG_INSTALL_DIR': str(self.bin), **env}
        script = site.INSTALLER.read_text()
        # `curl … | bash` hands bash the script on stdin.
        command, stdin = (['bash'], script) if piped else (['bash', str(site.INSTALLER)], '')
        return subprocess.run(command, input=stdin, env=environment, capture_output=True,
                              text=True, timeout=60)

    def installed(self):
        natwg = self.bin / 'natwg'
        if not natwg.exists():
            return None
        return subprocess.run([str(natwg), '--version'], capture_output=True, text=True).stdout.strip()

    def test_the_newest_release_is_installed_from_a_pipe(self):
        run = self.install(piped=True)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(self.installed(), 'natwg 1.2.3')
        self.assertIn(f'Downloading natwg 1.2.3 for {self.target}', run.stdout)
        self.assertIn(f'Installed {self.bin}/natwg (natwg 1.2.3)', run.stdout)
        self.assertEqual([p.name for p in self.bin.iterdir()], ['natwg'])

    def test_a_pinned_version_is_installed_and_replaces_another(self):
        self.assertEqual(self.install().returncode, 0)
        run = self.install(NATWG_VERSION='1.2.2')
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(self.installed(), 'natwg 1.2.2')

    def test_an_archive_that_does_not_match_the_manifest_installs_nothing(self):
        archive = self.root / 'v1.2.3' / f'natwg-1.2.3-{self.target}.tar.gz'
        archive.write_bytes(archive.read_bytes() + b'tampered')
        run = self.install()
        self.assertNotEqual(run.returncode, 0)
        self.assertIn('does not match the SHA-256 in the manifest', run.stderr)
        self.assertIsNone(self.installed())

    def test_a_binary_that_reports_another_version_installs_nothing(self):
        self.release('1.2.3', latest=True, reports='9.9.9')
        run = self.install()
        self.assertNotEqual(run.returncode, 0)
        self.assertIn("reports 'natwg 9.9.9'", run.stderr)
        self.assertIsNone(self.installed())

    def test_a_missing_version_and_a_plain_http_site_are_refused(self):
        run = self.install(NATWG_VERSION='1.0.0')
        self.assertNotEqual(run.returncode, 0)
        self.assertIn('could not read', run.stderr)
        for url in ('http://example.com', 'https://example.com/path', 'ftp://127.0.0.1'):
            run = self.install(NATWG_DOWNLOAD_URL=url)
            self.assertNotEqual(run.returncode, 0, url)
            self.assertIn('must be an https:// origin', run.stderr)
        run = self.install(NATWG_VERSION='latest')
        self.assertIn('NATWG_VERSION must look like 0.3.0', run.stderr)
        run = self.install(NATWG_INSTALL_DIR='relative/bin')
        self.assertIn('must be an absolute path', run.stderr)
        self.assertIsNone(self.installed())


if __name__ == '__main__':
    unittest.main()
