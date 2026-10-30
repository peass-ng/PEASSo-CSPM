"""Portable native Pod and OCI fixtures, loaded only from this isolated candidate."""
import base64
from copy import deepcopy
import gzip
import hashlib
import io
import json
from pathlib import Path
import socket
import tarfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


from peaso import container_image_archive_20261020 as archive
from peaso.auth import secrets
from peaso.collectors import k8s_selected_registry_image_20261021 as registry_module
from peaso.collectors import k8s as k8s_module
from peaso.checks import k8s_selected_registry_image_review_20261021 as review_module
namespace = vars(registry_module)
review = vars(review_module)


def digest(raw):
    return 'sha256:' + hashlib.sha256(raw).hexdigest()


def fixture(file_bytes=b'mode=ready\n', *, wrong_diff=False):
    layer_stream = io.BytesIO()
    with tarfile.open(fileobj=layer_stream, mode='w') as tar:
        member = tarfile.TarInfo('app/settings.txt')
        member.size = len(file_bytes)
        tar.addfile(member, io.BytesIO(file_bytes))
    raw_tar = layer_stream.getvalue()
    compressed = gzip.compress(raw_tar, mtime=0)
    config = json.dumps({'os': 'linux', 'architecture': 'amd64',
                         'rootfs': {'type': 'layers', 'diff_ids': ['sha256:' + '0' * 64 if wrong_diff else digest(raw_tar)]}}, separators=(',', ':')).encode()
    manifest = json.dumps({'schemaVersion': 2, 'mediaType': archive.OCI,
                           'config': {'mediaType': 'application/vnd.oci.image.config.v1+json',
                                      'digest': digest(config), 'size': len(config)},
                           'layers': [{'mediaType': 'application/vnd.oci.image.layer.v1.tar+gzip',
                                      'digest': digest(compressed), 'size': len(compressed)}]}, separators=(',', ':')).encode()
    image = 'ghcr.io/owned/demo@' + digest(manifest)
    target = dict(cluster_id='cluster.example', namespace='default', pod='pod-a', uid='abc123',
                  resource_version='42', container_type='regular', container_name='app', image=image)
    pod = {'apiVersion': 'v1', 'kind': 'Pod',
           'metadata': {'namespace': 'default', 'name': 'pod-a', 'uid': 'abc123', 'resourceVersion': '42'},
           'spec': {'containers': [{'name': 'app', 'image': image}]},
           'status': {'containerStatuses': [{'name': 'app', 'image': image,
                'imageID': 'docker-pullable://' + image, 'state': {'running': {
                    'startedAt': '2026-10-21T10:00:00Z', 'containerID': 'containerd://abc123'}},
                'containerID': 'containerd://abc123', 'restartCount': 0, 'ready': True}]}}
    blobs = {('manifests', digest(manifest)): manifest, ('blobs', digest(config)): config,
             ('blobs', digest(compressed)): compressed}
    return target, pod, blobs


class Response:
    def __init__(self, payload, *, status=200, declared=None):
        self.status = status
        self.payload = io.BytesIO(payload)
        self.headers = {'Content-Length': str(len(payload) if declared is None else declared),
                        'Content-Encoding': 'identity', 'Content-Type': archive.OCI}
        self.closed = False
    def read(self, n): return self.payload.read(n)
    def close(self): self.closed = True


class Connection:
    def __init__(self): self.closed = False
    def close(self): self.closed = True


class FakeWire:
    def __init__(self, blobs, fault=None, expected_authorization=None):
        self.blobs, self.fault, self.calls, self.responses = blobs, fault, [], []
        self.expected_authorization = expected_authorization
    def __call__(self, host, path, headers, timeout):
        assert host == 'ghcr.io' and path.startswith('/v2/owned/demo/')
        assert headers['Accept-Encoding'] == 'identity'
        if self.expected_authorization is None: assert 'Authorization' not in headers
        else: assert headers.get('Authorization') == self.expected_authorization
        _, category, requested = path.rsplit('/', 2)
        payload = self.blobs[(category, requested)]
        response = Response(payload)
        if self.fault == 'denied': response.status = 403
        if self.fault == 'truncated' and category == 'blobs': response.headers['Content-Length'] = str(len(payload) + 1)
        if self.fault == 'redirect': response.status = 307
        self.calls.append((category, requested))
        self.responses.append(response)
        return Connection(), response


def scanner(payload, path, source, check, leaks, parts, *, redact_values=None):
    check()
    complete = True
    parts.append({'part': path, 'bytes': len(payload), 'complete': complete,
                  'engines': [{'engine': 'kingfisher', 'version': '1.4.0', 'status': 'complete'},
                              {'engine': 'trufflehog', 'version': '3.92.5', 'status': 'complete'}]})
    if b'mode=ready' in payload and scanner.hit:
        leaks.append({'fingerprint': 'a' * 64, 'locations': [{'path': path}],
                      'detectors': [{'engine': 'kingfisher', 'rule': 'fixture'}]})
scanner.hit = False


class RegistryTests(unittest.TestCase):
    def setUp(self):
        self.target, self.pod, self.blobs = fixture()
        scanner.hit = False

    def test_private_auth_exact_origin_and_redaction(self):
        for method in ('basic', 'bearer'):
            with self.subTest(method=method):
                entry = {'host': 'ghcr.io', 'repository': 'owned/demo', 'method': method}
                if method == 'basic':
                    entry.update(username='private-user', password='private-password')
                    expected = 'Basic ' + base64.b64encode(b'private-user:private-password').decode()
                else:
                    entry['token'] = 'private-token-123'
                    expected = 'Bearer private-token-123'
                auth = {'registry_auth': [entry]}
                credentials = namespace['registry_credentials'](auth, [self.target], ['ghcr.io'])
                wire = FakeWire(self.blobs, expected_authorization=expected)
                result = namespace['inspect'](self.target, lambda _: deepcopy(self.pod),
                    allowed_hosts=['ghcr.io'], credentials=credentials,
                    registry_factory=lambda h, r, c, **kw: namespace['RegistryReader'](h, r, c, open_https=wire, **kw),
                    scanner=scanner)
                self.assertEqual(result['status'], 'PASS')
                self.assertEqual(result['auth_mode'], method)
                self.assertEqual(len(wire.calls), 3)
                output = json.dumps(result)
                for secret in ('private-user', 'private-password', 'private-token-123', expected):
                    self.assertNotIn(secret, output)
                self.assertNotIn('registry_auth', output)
                self.assertNotIn('registry_auth', json.dumps({namespace['OPTION']: [self.target]}))
                public_options = secrets.redact({'selected_registry_hosts': ['ghcr.io'],
                    namespace['OPTION']: [self.target]}, tuple(secrets.credential_values(auth)))
                self.assertNotIn('private-token-123', json.dumps(public_options))
                self.assertNotIn('private-password', json.dumps(public_options))
                self.assertIn(entry.get('token', entry.get('password')), list(secrets.credential_values(auth)))
                for foreign in ({**entry, 'host': 'other.example.com'},
                                {**entry, 'repository': 'other/repo'}):
                    with self.assertRaises(namespace['Incomplete']):
                        namespace['registry_credentials']({'registry_auth': [foreign]}, [self.target], ['ghcr.io'])
                with self.assertRaises(namespace['Incomplete']):
                    namespace['selected_targets']({namespace['OPTION']: [self.target],
                        namespace['ALLOWLIST']: ['ghcr.io'], 'registry_auth': [entry]}, ['default'])
                redirected = FakeWire(self.blobs, fault='redirect', expected_authorization=expected)
                result = namespace['inspect'](self.target, lambda _: deepcopy(self.pod),
                    allowed_hosts=['ghcr.io'], credentials=credentials,
                    registry_factory=lambda h, r, c, **kw: namespace['RegistryReader'](h, r, c, open_https=redirected, **kw),
                    scanner=scanner)
                self.assertEqual(result['status'], 'UNKNOWN')
                self.assertEqual(len(redirected.calls), 1)

    def test_hosted_auth_keeps_separate_encrypted_document(self):
        private = {'registry_auth': [{'host': 'ghcr.io', 'repository': 'owned/demo',
                   'method': 'bearer', 'token': 'private-token-123'}]}
        resolved = k8s_module.hosted_auth({'method': 'direct', 'server': 'https://k8s.example.com',
                    'token': 'kubernetes-only-token', **private})
        self.assertEqual(resolved['registry_auth'], private['registry_auth'])
        self.assertEqual(resolved['token'], 'kubernetes-only-token')
        self.assertNotEqual(resolved['token'], private['registry_auth'][0]['token'])


    def test_default_off_zero_io_and_allowlist(self):
        self.assertEqual(namespace['selected_targets']({}, ['default']), [])
        self.assertEqual(namespace['collect'](object(), None, {}, ['default'], 'cluster.example', {}), ({}, set()))
        with self.assertRaises(namespace['Incomplete']):
            namespace['selected_targets']({namespace['OPTION']: [self.target], namespace['ALLOWLIST']: ['localhost']}, ['default'])
        options = {namespace['OPTION']: [self.target], namespace['ALLOWLIST']: ['ghcr.io'],
                   'content_secret_scans': True}
        self.assertEqual(namespace['selected_targets'](options, ['default'], [namespace['SECRET_CHECK']]), [self.target])
        wire = FakeWire(self.blobs)
        result = namespace['inspect'](self.target, lambda _: self.pod, registry_factory=lambda h, r, c, **kw:
            namespace['RegistryReader'](h, r, c, open_https=wire, **kw), scanner=scanner)
        self.assertEqual(result['status'], 'UNKNOWN')
        self.assertEqual(wire.calls, [])
        with patch.object(socket, 'getaddrinfo', return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('127.0.0.1', 443))]), \
             patch.object(socket, 'create_connection') as connect:
            with self.assertRaises(namespace['Incomplete']):
                namespace['_open_https']('ghcr.io', '/v2/owned/demo/manifests/' + self.target['image'].split('@')[1], {}, 1)
            connect.assert_not_called()

    def test_native_clean_and_positive(self):
        for hit, expected in ((False, 'PASS'), (True, 'FAIL')):
            with self.subTest(hit=hit):
                scanner.hit = hit
                wire = FakeWire(self.blobs)
                result = namespace['inspect'](self.target, lambda _: deepcopy(self.pod), allowed_hosts=['ghcr.io'],
                    registry_factory=lambda h, r, c, **kw: namespace['RegistryReader'](h, r, c, open_https=wire, **kw), scanner=scanner)
                self.assertEqual(result['status'], expected)
                self.assertEqual([r['status'] for r in result['registry_receipts']], ['collected'] * 3)
                self.assertEqual(len(wire.calls), 3)
                self.assertTrue(all(r.closed for r in wire.responses))

    def test_foreign_denied_truncated_drift_and_cancel(self):
        for fault in ('denied', 'truncated', 'redirect'):
            with self.subTest(fault=fault):
                wire = FakeWire(self.blobs, fault)
                result = namespace['inspect'](self.target, lambda _: self.pod, allowed_hosts=['ghcr.io'],
                    registry_factory=lambda h, r, c, **kw: namespace['RegistryReader'](h, r, c, open_https=wire, **kw), scanner=scanner)
                self.assertEqual(result['status'], 'UNKNOWN')
                if fault == 'denied':
                    self.assertEqual(result['registry_receipts'][0]['status'], 'denied')
        foreign = deepcopy(self.pod)
        foreign['metadata']['uid'] = 'foreign'
        wire = FakeWire(self.blobs)
        result = namespace['inspect'](self.target, lambda _: foreign, allowed_hosts=['ghcr.io'],
            registry_factory=lambda h, r, c, **kw: namespace['RegistryReader'](h, r, c, open_https=wire, **kw), scanner=scanner)
        self.assertEqual(result['status'], 'UNKNOWN')
        self.assertEqual(wire.calls, [])
        calls = [0]
        def pod_get(_):
            calls[0] += 1
            pod = deepcopy(self.pod)
            if calls[0] > 1: pod['metadata']['resourceVersion'] = '43'
            return pod
        result = namespace['inspect'](self.target, pod_get, allowed_hosts=['ghcr.io'],
            registry_factory=lambda h, r, c, **kw: namespace['RegistryReader'](h, r, c, open_https=FakeWire(self.blobs), **kw), scanner=scanner)
        self.assertEqual(result['status'], 'UNKNOWN')
        def cancelled(): raise namespace['Incomplete']('cancelled')
        result = namespace['inspect'](self.target, lambda _: self.pod, allowed_hosts=['ghcr.io'], cancel=cancelled,
            registry_factory=lambda h, r, c, **kw: namespace['RegistryReader'](h, r, c, open_https=FakeWire(self.blobs), **kw), scanner=scanner)
        self.assertEqual(result['status'], 'UNKNOWN')

    def test_partial_positive_survives_later_denial(self):
        scanner.hit = True
        class LateDeny(FakeWire):
            def __call__(self, host, path, headers, timeout):
                conn, response = super().__call__(host, path, headers, timeout)
                if '/blobs/' in path and len(self.calls) == 3: response.status = 403
                return conn, response
        # Config is scanned only after layer capture, so a denied layer cannot
        # establish a content finding. A detector gap after a verified file can.
        wire = FakeWire(self.blobs)
        def partial_scanner(payload, path, source, check, leaks, parts):
            scanner(payload, path, source, check, leaks, parts)
            if b'mode=ready' in payload: raise namespace['Incomplete']('detectors_incomplete')
        result = namespace['inspect'](self.target, lambda _: self.pod, allowed_hosts=['ghcr.io'],
            registry_factory=lambda h, r, c, **kw: namespace['RegistryReader'](h, r, c, open_https=wire, **kw), scanner=partial_scanner)
        self.assertEqual(result['status'], 'FAIL')
        self.assertFalse(result['complete'])
        self.assertTrue(result['leaks'])

    def test_binary_nested_and_rootfs_gap_are_unknown(self):
        for file_bytes, wrong_diff in ((b'\x00binary', False), (b'PK\x03\x04nested', False),
                                       (b'mode=ready\n', True)):
            with self.subTest(file_bytes=file_bytes, wrong_diff=wrong_diff):
                target, pod, blobs = fixture(file_bytes, wrong_diff=wrong_diff)
                result = namespace['inspect'](target, lambda _: pod, allowed_hosts=['ghcr.io'],
                    registry_factory=lambda h, r, c, **kw: namespace['RegistryReader'](h, r, c,
                        open_https=FakeWire(blobs), **kw), scanner=scanner)
                self.assertEqual(result['status'], 'UNKNOWN')
                self.assertFalse(result['complete'])

    def test_optional_trivy_and_evidence_projection(self):
        scanner.hit = True
        finding = {'severity': 'HIGH', 'image_digest': self.target['image'].rsplit('@', 1)[1],
                   'vulnerability_id': 'CVE-2026-1001', 'package': 'pkg', 'version': '1'}
        def runner(identity, manifest, config, layers, **kwargs):
            self.assertEqual(kwargs['native_verifier'](), identity)
            self.assertEqual(kwargs['archive_format'], 'docker')
            return {'status': 'FAIL', 'complete': False, 'findings': [finding]}
        result = namespace['inspect'](self.target, lambda _: deepcopy(self.pod), allowed_hosts=['ghcr.io'],
            registry_factory=lambda h, r, c, **kw: namespace['RegistryReader'](h, r, c, open_https=FakeWire(self.blobs), **kw),
            scanner=scanner, trivy_enabled=True, trivy_runner=runner)
        item = {'id': namespace['identity'](self.target), 'name': namespace['identity'](self.target),
                'SelectedRegistryImage': result}
        def evaluate(kind):
            envelope = {'scope': 'default', 'status': 'collected', 'items': [item]}
            index = {'context': {'provider': 'k8s', 'scope': 'default', 'metadata': {
                kind + '_authorized': True, namespace['OPTION']: [self.target]}},
                'collections': {kind: [envelope]}}
            return review['evaluate'](item, index, kind)[0]
        self.assertEqual(evaluate(namespace['SECRET_KIND']), 'FAIL')
        self.assertEqual(evaluate(namespace['VULN_KIND']), 'FAIL')
        self.assertEqual(result['vulnerability']['findings'], [finding])

    def test_frozen_incomplete_positive_reaches_image_rows_without_clean_coverage(self):
        from peaso.image_findings import build_report
        from peaso.selected_image_observations_20261021 import metadata_for_report
        from peaso.snapshot import digest as snapshot_digest, freeze, resource_id

        target, pod, blobs = fixture(b'\x00binary image file')
        image_digest = target['image'].rsplit('@', 1)[1]
        finding = {'vulnerability_id': 'CVE-2026-1001', 'severity': 'HIGH',
            'package_types': ['debian'], 'package': 'openssl', 'version': '1.0',
            'fixed_in': ['1.1'], 'fix_status': 'fixed', 'classes': ['os-pkgs'],
            'image_digest': image_digest}
        def runner(image, manifest, config, layers, **kwargs):
            self.assertEqual(kwargs['native_verifier'](), image)
            return {'image': image, 'status': 'FAIL', 'complete': False,
                'scan_complete': False, 'coverage_status': 'UNKNOWN',
                'database': {'fresh': True}, 'findings': [finding]}
        marker = namespace['inspect'](target, lambda _: deepcopy(pod), allowed_hosts=['ghcr.io'],
            registry_factory=lambda h, r, c, **kw: namespace['RegistryReader'](h, r, c,
                open_https=FakeWire(blobs), **kw), scanner=scanner,
            trivy_enabled=True, trivy_runner=runner)
        self.assertEqual(marker['reason'], 'binary_file_uninspected')
        kind, check = namespace['VULN_KIND'], namespace['VULN_CHECK']
        plain_item = {'id': namespace['identity'](target), 'name': namespace['identity'](target),
            'SelectedRegistryImage': marker}
        item = freeze(plain_item)
        collection = {'type': kind, 'scope': 'default', 'status': 'partial', 'items': [item]}
        context = {'provider': 'k8s', 'scope': 'default', 'metadata': freeze({
            kind + '_authorized': True, namespace['OPTION']: [target]})}
        self.assertEqual(review['evaluate'](item,
            {'context': context, 'collections': {kind: [collection]}}, kind)[0], 'FAIL')
        native_id = resource_id('k8s', kind, 'default', item)
        report_id = snapshot_digest(['k8s', 'default', kind, native_id])
        report = {'provider': 'k8s', 'findings': [
            {'provider': 'k8s', 'check_id': check, 'scope': 'default',
             'resource_id': report_id, 'status': 'FAIL'},
            {'provider': 'k8s', 'check_id': check, 'scope': 'default',
             'resource_id': 'inventory:' + kind, 'status': 'UNKNOWN'}]}
        snapshot = {'provider': 'k8s', 'scopes': ['default'], 'collections': [collection],
                    'metadata': {}}
        image = build_report(metadata_for_report(snapshot, report)['observations'], selected=True)
        self.assertEqual((len(image['rows']), image['coverage'], image['invalid_observations']),
                         (1, 'UNKNOWN', 1))
        self.assertEqual(image['rows'][0]['vulnerability_id'], finding['vulnerability_id'])
        self.assertEqual(image['rows'][0]['affected_assets'][0]['resource_id'], report_id)
        self.assertEqual(image['rows'][0]['coverage'], 'UNKNOWN')

        # Native drift cannot become a positive check; a forged evaluated FAIL
        # still cannot pass the adapter's child image identity validator.
        drifted = deepcopy(plain_item)
        drifted['SelectedRegistryImage']['native_after']['uid'] = 'foreign-uid'
        self.assertEqual(review['evaluate'](freeze(drifted),
            {'context': context, 'collections': {kind: [{**collection, 'items': [freeze(drifted)]}]}}, kind)[0],
            'UNKNOWN')
        foreign = deepcopy(plain_item)
        foreign['SelectedRegistryImage']['child_vulnerability_scans'][0]['image']['manifest_digest'] = 'sha256:' + 'f' * 64
        foreign_collection = {**collection, 'items': [freeze(foreign)]}
        withheld = build_report(metadata_for_report({**snapshot, 'collections': [foreign_collection]}, report)['observations'], selected=True)
        self.assertEqual((len(withheld['rows']), withheld['invalid_observations']), (0, 2))


if __name__ == '__main__': unittest.main()
