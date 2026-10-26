"""Offline native-shaped selected ECR index producer/consumer regression."""
import hashlib
import importlib.util
import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from peaso import aws_image_selection_20261021 as selection
from peaso import oci_index_20261021 as index
from peaso.collectors import aws_package_content_indicators as content
from peaso.collectors import aws_image_vulnerability_native_20261021 as native
from peaso.collectors import aws_workload_image_secret_native_20261021 as secret
from peaso.checks import aws_workload_image_secret_review_20261021 as secret_check
from peaso.checks import aws_image_vulnerabilities_20261021 as cve_check


ACCOUNT = '123456789012'
REGION = 'us-east-1'
REPO = 'samples/image'
SCOPE = ACCOUNT + '/' + REGION
ASSET = f'arn:aws:ecs:{REGION}:{ACCOUNT}:task-definition/demo:7'


def wire(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def sha(raw):
    return 'sha256:' + hashlib.sha256(raw).hexdigest()


def fixture():
    leaves = {}
    for arch in ('amd64', 'arm64'):
        conf = wire({'architecture': arch, 'os': 'linux', 'rootfs': {'type': 'layers', 'diff_ids': [sha(b'diff')]}})
        layer = b'layer-' + arch.encode()
        leaf = wire({'schemaVersion': 2, 'mediaType': content.OCI,
            'config': {'mediaType': 'application/vnd.oci.image.config.v1+json', 'digest': sha(conf), 'size': len(conf)},
            'layers': [{'mediaType': 'application/vnd.oci.image.layer.v1.tar+gzip',
                        'digest': sha(layer), 'size': len(layer)}]})
        leaves[arch] = (sha(leaf), leaf, conf, layer)
    parent = wire({'schemaVersion': 2, 'mediaType': index.OCI_INDEX,
        'manifests': [{'mediaType': content.OCI, 'digest': leaves[arch][0],
                       'size': len(leaves[arch][1]), 'platform': {'os': 'linux', 'architecture': arch}}
                      for arch in leaves]})
    return sha(parent), parent, leaves


def target(parent):
    return {'scope': SCOPE, 'task_definition_arn': ASSET, 'container_name': 'app',
            'repository_name': REPO, 'image_digest': parent}


def binding(parent):
    return {'asset_arn': ASSET, 'revision': 7, 'container': 'app', 'profile': 'ecs_container',
            'image_uri': f'{ACCOUNT}.dkr.ecr.{REGION}.amazonaws.com/{REPO}@{parent}'}


def response(digest, raw, media):
    return {'images': [{'registryId': ACCOUNT, 'repositoryName': REPO,
        'imageId': {'imageDigest': digest}, 'imageManifest': raw.decode(),
        'imageManifestMediaType': media}], 'failures': []}


class FakeReader:
    parent = b''
    leaves = {}
    bad_child = None
    def __init__(self, requests, session, account, region, *, target_count=1):
        assert account == ACCOUNT and region == REGION
        self.calls = []
    def caller(self):
        self.calls.append('caller')
    def manifest(self, repo, digest, *, allow_index=False):
        assert repo == REPO
        self.calls.append((digest, allow_index))
        if digest == sha(self.parent):
            assert allow_index
            return self.parent, json.loads(self.parent)
        if digest == self.bad_child:
            raise ValueError('child denied')
        for item in self.leaves.values():
            if digest == item[0]:
                assert not allow_index
                return item[1], json.loads(item[1])
        raise AssertionError('foreign child')
    def check(self):
        pass
    def blob(self, repo, descriptor, *, image_digest=None):
        assert repo == REPO
        for item in self.leaves.values():
            if sha(item[2]) == descriptor['digest'] and image_digest in (None, item[0]):
                return item[2]
        raise AssertionError('foreign config')
    def close(self):
        return True


class Projection:
    def __init__(self, parent, leaves, *, hit=False, denied=False, binary=False):
        self.parent = parent
        self.leaves = leaves
        self.hit = hit
        self.denied = denied
        self.binary = binary
        self.requests = []
    def detail(self, session, service, region, operation, **kwargs):
        assert (service, region, operation) == ('ecr', REGION, 'batch_get_image')
        assert kwargs['registryId'] == ACCOUNT and kwargs['repositoryName'] == REPO
        assert kwargs['acceptedMediaTypes'] == [content.OCI, content.DOCKER]
        digest = kwargs['imageIds'][0]['imageDigest']
        assert digest != self.parent
        self.requests.append(digest)
        if self.denied and digest == self.leaves['arm64'][0]:
            raise ValueError('denied')
        refs = []
        if self.hit and digest == self.leaves['amd64'][0]:
            refs = [{'File': 'app.env', 'Categories': ['secret'],
                'LayerDigest': sha(self.leaves['amd64'][3])}]
        ident = f'arn:aws:ecr:{REGION}:{ACCOUNT}:repository/{REPO}@{digest}'
        return {'ImageDigest': digest, 'PackageSecretIndicators': content.marker(
            ident, ACCOUNT, REGION, 'ecr:batch_get_image', refs)}


def project(monkeypatch, *, hit=False, denied=False):
    parent, raw, leaves = fixture()
    FakeReader.parent, FakeReader.leaves = raw, leaves
    FakeReader.bad_child = None
    monkeypatch.setattr(native, 'Reader', FakeReader)
    monkeypatch.setattr(content, 'reuse_image_layer', lambda *args, **kwargs: None)
    sdk = Projection(parent, leaves, hit=hit, denied=denied)
    output = content._image(response(parent, raw, index.OCI_INDEX),
        {'registryId': ACCOUNT, 'repositoryName': REPO, 'imageIds': [{'imageDigest': parent}]},
        sdk, object(), REGION)
    return parent, raw, leaves, sdk, output


def row(parent, source, *, drift=False):
    before = binding(parent)
    return {'selection': target(parent), 'image': {'repository_name': REPO, 'image_digest': parent},
        'binding_before': before, 'binding_after': None if drift else before,
        'source': {'ImageDigest': parent, 'collection_status':
            source['PackageSecretIndicators']['collection_status'], **source},
        'complete': not drift and source['PackageSecretIndicators']['NativeResponseComplete']}


def test_secret_parent_index_clean_and_positive(monkeypatch):
    parent, raw, leaves, sdk, clean = project(monkeypatch)
    assert len(sdk.requests) == 2
    assert clean['PackageSecretIndicators']['IndexGraph']['complete']
    assert secret_check.evaluate(row(parent, clean))[0] == 'PASS'
    parent, raw, leaves, sdk, positive = project(monkeypatch, hit=True)
    assert secret_check.evaluate(row(parent, positive))[0] == 'FAIL'
    assert positive['PackageSecretIndicators']['References'][0]['ChildManifestDigest'] == leaves['amd64'][0]
    assert secret_check.evaluate(row(parent, positive, drift=True))[0] == 'UNKNOWN'


def test_later_child_denied_keeps_bound_positive(monkeypatch):
    parent, raw, leaves, sdk, partial = project(monkeypatch, hit=True, denied=True)
    marker = partial['PackageSecretIndicators']
    assert marker['IndexGraph']['complete'] is False
    assert marker['NativeResponseComplete'] is False
    assert secret_check.evaluate(row(parent, partial))[0] == 'FAIL'
    parent, raw, leaves, sdk, partial_clean = project(monkeypatch, denied=True)
    assert secret_check.evaluate(row(parent, partial_clean))[0] == 'UNKNOWN'


def test_foreign_child_and_bad_parent_rejected(monkeypatch):
    parent, raw, leaves, sdk, positive = project(monkeypatch, hit=True)
    bad = row(parent, positive)
    bad['source']['PackageSecretIndicators']['References'][0]['ChildManifestDigest'] = sha(b'foreign')
    assert secret_check.evaluate(bad)[0] == 'UNKNOWN'
    foreign = response(sha(b'foreign'), raw, index.OCI_INDEX)
    with pytest.raises(ValueError):
        content._image(foreign, {'registryId': ACCOUNT, 'repositoryName': REPO,
            'imageIds': [{'imageDigest': parent}]}, sdk, object(), REGION)


class SDK:
    def __init__(self, parent, raw, leaves, *, deny=None, drift=False):
        import threading
        self.parent, self.raw, self.leaves = parent, raw, leaves
        self.deny, self.drift = deny, drift
        self.calls, self.max_calls, self.deadline, self.timeout = 0, 128, None, 5
        self._lock = threading.Lock()
        self.parent_reads = 0
        self.ecs_reads = 0
        self.requests = []
    def check_deadline(self):
        return None
    def client(self, service, *, region_name, config):
        assert region_name == REGION
        sdk = self
        class Client:
            def close(self):
                pass
            def get_caller_identity(self):
                return {'ResponseMetadata': {'HTTPStatusCode': 200}, 'Account': ACCOUNT,
                    'Arn': f'arn:aws:sts::{ACCOUNT}:assumed-role/test/runner'}
            def describe_task_definition(self, **kw):
                assert kw == {'taskDefinition': ASSET}
                sdk.ecs_reads += 1
                image = f'{ACCOUNT}.dkr.ecr.{REGION}.amazonaws.com/{REPO}@{sdk.parent}'
                if sdk.drift and sdk.ecs_reads > 1:
                    image = image[:-1] + ('0' if image[-1] != '0' else '1')
                return {'ResponseMetadata': {'HTTPStatusCode': 200, 'RequestId': 'req-123'},
                    'taskDefinition': {'taskDefinitionArn': ASSET, 'family': 'demo',
                        'revision': 7, 'status': 'ACTIVE',
                        'containerDefinitions': [{'name': 'app', 'image': image}]}}
            def batch_get_image(self, **kw):
                assert kw['registryId'] == ACCOUNT and kw['repositoryName'] == REPO
                digest = kw['imageIds'][0]['imageDigest']
                sdk.requests.append((digest, kw.get('acceptedMediaTypes')))
                if digest == sdk.parent:
                    assert 'acceptedMediaTypes' not in kw
                    sdk.parent_reads += 1
                    return {'ResponseMetadata': {'HTTPStatusCode': 200}, **response(digest, sdk.raw, index.OCI_INDEX)}
                assert kw['acceptedMediaTypes'] == [content.OCI, content.DOCKER]
                if digest == sdk.deny:
                    return {'ResponseMetadata': {'HTTPStatusCode': 200}, 'images': [],
                        'failures': [{'imageId': {'imageDigest': digest}, 'failureCode': 'Missing'}]}
                for item in sdk.leaves.values():
                    if item[0] == digest:
                        return {'ResponseMetadata': {'HTTPStatusCode': 200}, **response(digest, item[1], content.OCI)}
                raise AssertionError('foreign digest')
        assert service in ('sts', 'ecs', 'ecr')
        return Client()


def vulnerability(digest):
    return {'vulnerability_id': 'CVE-2025-12345', 'severity': 'HIGH',
        'package_types': ['apk'], 'package': 'testpkg', 'version': '1.0',
        'fixed_in': ['1.1'], 'fix_status': 'fixed', 'classes': ['os-pkgs'],
        'image_digest': digest}


def cve_capture(monkeypatch, *, hit=False, deny=False, drift=False, cancel=False):
    parent, raw, leaves = fixture()
    sdk = SDK(parent, raw, leaves, deny=leaves['arm64'][0] if deny else None, drift=drift)
    if cancel:
        class Cancelled(Exception):
            code = 'collection_cancelled'
        def check_deadline():
            if len(sdk.requests) >= 3:
                raise Cancelled('cancelled')
        sdk.check_deadline = check_deadline
    def leaf_scan(reader, selected, repo, digest, reference, binding, manifest, document,
                  cache, runner, cli, scratch, *, platform=None):
        assert repo == REPO and binding is None and platform['os'] == 'linux'
        assert any(digest == item[0] and manifest == item[1] for item in leaves.values())
        image = {'provider': 'aws', 'scope': SCOPE, 'immutable_reference': reference,
            'manifest_digest': digest, 'config_digest': document['config']['digest']}
        findings = [vulnerability(digest)] if hit and digest == leaves['amd64'][0] else []
        scan = {'image': image, 'status': 'FAIL' if findings else 'PASS', 'complete': True,
            'scan_complete': True, 'coverage_status': 'COMPLETE', 'database': {'fresh': True},
            'findings': findings}
        return image, scan
    monkeypatch.setattr(native, '_scan_bound', leaf_scan)
    captured = native.collect_native(sdk, sdk, ACCOUNT, REGION, [target(parent)], enabled=True)
    item = {'id': ASSET + '#container=app', 'ImageVulnerabilityReview': captured['rows'][0]}
    envelope = {'context': {'provider': 'aws', 'scope': SCOPE,
        'metadata': {cve_check.OPTION: [target(parent)]}},
        'collections': {cve_check.KIND: [{'scope': SCOPE, 'status': 'collected' if captured['complete'] else 'partial',
            'items': [item]}]}}
    return sdk, captured, cve_check.evaluate(item, envelope)


def test_cve_native_parent_child_graph_and_consumer(monkeypatch):
    sdk, result, (status, evidence) = cve_capture(monkeypatch)
    assert status == 'PASS'
    assert len(result['rows'][0]['index_graph']['children']) == 2
    assert sdk.parent_reads == 2
    sdk, result, (status, evidence) = cve_capture(monkeypatch, hit=True)
    assert status == 'FAIL'
    assert evidence['Vulnerabilities'][0]['image_digest'] == result['rows'][0]['index_graph']['children'][0]['digest']


def test_cve_later_denied_retains_positive_and_clean_unknown(monkeypatch):
    sdk, result, (status, evidence) = cve_capture(monkeypatch, hit=True, deny=True)
    if status != 'FAIL':
        try:
            cve_check._evaluate_index(result['rows'][0], target(result['rows'][0]['selection']['image_digest']),
                {'id': ASSET + '#container=app'})
        except Exception as exc:
            pytest.fail(f'index consumer rejected retained child: {exc!r}; row={result["rows"][0]!r}')
    assert status == 'FAIL' and result['rows'][0]['index_graph']['complete'] is False, (status, result, evidence)
    sdk, result, (status, evidence) = cve_capture(monkeypatch, deny=True)
    assert status == 'UNKNOWN'
    sdk, result, (status, evidence) = cve_capture(monkeypatch, hit=True, drift=True)
    assert status == 'UNKNOWN'


def test_cancellation_propagates_after_first_child(monkeypatch):
    with pytest.raises(Exception) as exc:
        cve_capture(monkeypatch, hit=True, cancel=True)
    assert getattr(exc.value, 'code', None) == 'collection_cancelled'


def test_selected_secret_collector_omits_parent_media_filter_and_default_off(monkeypatch):
    parent, raw, leaves = fixture()
    selected = target(parent)
    untouched = SimpleNamespace(content_secret_scans=False)
    monkeypatch.setattr(secret, 'Reader', lambda *args: pytest.fail('default off used credentials'))
    assert secret.collect_scope(untouched, object(), ACCOUNT, REGION, [selected], named=[secret.CHECK]) == []
    class BoundReader:
        def __init__(self, requests, session, account, region):
            self.config = object()
        def caller(self):
            pass
        def reference(self, target):
            return REPO, parent, binding(parent)['image_uri'], binding(parent)
        def close(self):
            return True
    monkeypatch.setattr(secret, 'Reader', BoundReader)
    class Requests:
        content_secret_scans = True
        def detail(self, session, service, region, operation, **kwargs):
            assert service == 'ecr' and operation == 'batch_get_image'
            assert 'acceptedMediaTypes' not in kwargs
            assert kwargs['imageIds'] == [{'imageDigest': parent}]
            ident = f'arn:aws:ecr:{REGION}:{ACCOUNT}:repository/{REPO}@{parent}'
            marker = content.marker(ident, ACCOUNT, REGION, 'ecr:batch_get_image', [])
            return {'collection_status': 'collected', 'ImageDigest': parent, 'PackageSecretIndicators': marker}
    rows = secret.collect_scope(Requests(), object(), ACCOUNT, REGION, [selected], named=[secret.CHECK])
    assert len(rows) == 1 and rows[0]['complete']


def test_binary_first_does_not_hide_later_supported_file(monkeypatch):
    import io
    calls = []
    def scan(raw, name, requests):
        calls.append(name)
        return [{'File': name, 'Categories': ['secret'], 'Leaks': []}]
    monkeypatch.setattr(content, '_scan', scan)
    requests = SimpleNamespace(check_deadline=lambda: None)
    budget = [1024]
    assert content._scan_reader(io.BytesIO(b'\x00opaque'), 7, 'bin.dat', requests, budget) == ([], False)
    refs, covered = content._scan_reader(io.BytesIO(b'key=value'), 9, 'app.env', requests, budget)
    assert covered and len(refs) == 1 and calls == ['app.env']
    assert not all((False, covered))  # clean image with a binary remains incomplete


def test_default_off_image_reader_has_zero_io():
    assert native.collect_native(None, None, ACCOUNT, REGION, None, enabled=False) == {
        'status': 'UNKNOWN', 'complete': False, 'rows': [], 'observations': []}


def test_child_config_platform_mismatch_withholds_clean_pass(monkeypatch):
    parent, raw, leaves = fixture()
    document = json.loads(raw)
    document['manifests'][0]['platform']['architecture'] = 'arm64'
    raw = wire(document)
    parent = sha(raw)
    FakeReader.parent, FakeReader.leaves = raw, leaves
    FakeReader.bad_child = None
    monkeypatch.setattr(native, 'Reader', FakeReader)
    monkeypatch.setattr(content, 'reuse_image_layer', lambda *args, **kwargs: None)
    sdk = Projection(parent, leaves)
    result = content._image(response(parent, raw, index.OCI_INDEX),
        {'registryId': ACCOUNT, 'repositoryName': REPO, 'imageIds': [{'imageDigest': parent}]},
        sdk, object(), REGION)
    assert not result['PackageSecretIndicators']['NativeResponseComplete']
    assert secret_check.evaluate(row(parent, result))[0] == 'UNKNOWN'
