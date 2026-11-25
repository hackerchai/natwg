#!/usr/bin/env python3
"""Offline checks of the download site upload: the plan, the SigV4 signature
and the requests, against a stub S3 endpoint on this host."""
import datetime
import hashlib
import http.server
import importlib.util
import json
from pathlib import Path
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
        self.assertEqual(keys[-2], 'v1.2.3/natwg-update.json')
        self.assertEqual(len(keys), 10)
        self.assertFalse(any('source' in key for key in keys))
        for key, _, cache in plan[:-1]:
            self.assertTrue(key.startswith('v1.2.3/'), key)
            self.assertEqual(cache, 'public, max-age=31536000, immutable')
        self.assertEqual(plan[-1][2], 'public, max-age=300')

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
        body = b'Welcome to Amazon S3.'
        headers = site.sign('PUT', 'https://examplebucket.s3.amazonaws.com/test$file.text',
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
                                 'json': 'application/json'})

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


if __name__ == '__main__':
    unittest.main()
