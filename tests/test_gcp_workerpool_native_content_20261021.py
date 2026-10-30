"""Offline native GET -> immutable OCI bytes -> normal consumer proof."""
import hashlib
import io
import json
from pathlib import Path
import tarfile
import threading
import types

from peaso.collectors import gcp_workerpool_image_native_20261021 as source
from peaso.collectors import gcp_workerpool_image_runtime_20261021 as runtime
from peaso.checks import gcp_workerpool_image_secret_review_20261021 as consumer

ROOT = Path(__file__).resolve().parents[1]
SCOPE = 'projects/example-project'
POOL = SCOPE + '/locations/europe-west1/workerPools/pool-one'
REV = POOL + '/revisions/revision-one'
REPO = SCOPE + '/locations/europe-west1/repositories/example-repo'
PUID = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
RUID = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'


def sha(raw): return 'sha256:' + hashlib.sha256(raw).hexdigest()


def fixture(secret=False, extra_layer=False, config_secret=False):
    filedata = b'TESTSECRET' if secret else b'ordinary harmless bytes'
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode='w') as tf:
        info = tarfile.TarInfo('app/config.txt')
        info.size = len(filedata)
        tf.addfile(info, io.BytesIO(filedata))
    layer = buf.getvalue()
    layers = [layer]
    if extra_layer:
        second = io.BytesIO()
        with tarfile.open(fileobj=second, mode='w') as tf:
            info = tarfile.TarInfo('app/other.txt'); info.size = 5; tf.addfile(info, io.BytesIO(b'other'))
        layers.append(second.getvalue())
    config = json.dumps({'os': 'linux', 'architecture': 'amd64', 'rootfs': {'type': 'layers', 'diff_ids': [sha(x) for x in layers]}, **({'config': {'Env': ['KEY=TESTSECRET']}} if config_secret else {})}, separators=(',', ':')).encode()
    manifest = json.dumps({'schemaVersion': 2, 'mediaType': 'application/vnd.oci.image.manifest.v1+json', 'config': {'mediaType': 'application/vnd.oci.image.config.v1+json', 'size': len(config), 'digest': sha(config)}, 'layers': [{'mediaType': 'application/vnd.oci.image.layer.v1.tar', 'size': len(x), 'digest': sha(x)} for x in layers]}, separators=(',', ':')).encode()
    image = 'europe-west1-docker.pkg.dev/example-project/example-repo/example-image@' + sha(manifest)
    uri, _, _, image_name = source.native.parse_image_uri(image)
    selection = {'pool_name': POOL, 'pool_uid': PUID, 'revision_name': REV, 'revision_uid': RUID, 'container_index': 0, 'immutable_reference': image}
    bodies = [
        {'name': POOL, 'uid': PUID, 'generation': '1', 'observedGeneration': '1', 'reconciling': False, 'terminalCondition': {'state': 'CONDITION_SUCCEEDED'}, 'latestReadyRevision': REV, 'latestCreatedRevision': REV, 'instanceSplitStatuses': [{'type': 'INSTANCE_SPLIT_ALLOCATION_TYPE_LATEST', 'revision': REV, 'percent': 100}]},
        {'name': REV, 'uid': RUID, 'service': POOL, 'generation': '1', 'observedGeneration': '1', 'reconciling': False, 'conditions': [{'type': 'Ready', 'state': 'CONDITION_SUCCEEDED'}], 'containers': [{'image': image}]},
        {'name': 'projects/123456789', 'projectId': 'example-project', 'state': 'ACTIVE'},
        {'name': REPO, 'format': 'DOCKER', 'mode': 'STANDARD_REPOSITORY'},
        {'name': REPO + '/dockerImages/' + image_name, 'uri': image, 'mediaType': 'application/vnd.oci.image.manifest.v1+json'},
    ]
    return selection, bodies, {sha(manifest): manifest, sha(config): config, **{sha(x): x for x in layers}}


class Response:
    def __init__(self, url, payload, status=200, override_url=None, length=None):
        self.url = override_url or url
        self.status_code = status
        self.history = []
        self.headers = {'Content-Length': str(len(payload) if length is None else length)}
        self.payload = payload
        self.closed = False
    def iter_content(self, chunk_size):
        for start in range(0, len(self.payload), chunk_size): yield self.payload[start:start+chunk_size]
    def close(self): self.closed = True


class Session:
    def __init__(self, selection, bodies, blobs, *, mutate=None, denied=None, foreign=None, truncated=None):
        self.calls = []
        self.routes = {url: json.dumps(body, separators=(',', ':')).encode() for (url, _), body in zip(source.requests_for(selection, SCOPE), bodies)}
        self.blobs = blobs
        self.mutate, self.denied, self.foreign, self.truncated = mutate, denied, foreign, truncated
        self.cookies = types.SimpleNamespace(clear=lambda: None)
        self.closed = False
    def request(self, method, url, **kwargs):
        assert method == 'GET' and kwargs['allow_redirects'] is False and kwargs['stream'] is True
        assert kwargs['headers']['Authorization'].startswith(('Bearer ', 'Basic '))
        self.calls.append(url)
        if 'params' in kwargs:
            import requests
            expected = requests.Request('GET', url, params=kwargs['params']).prepare().url
            payload = self.routes[url]
            if self.mutate and len(self.calls) > 5 and self.mutate in url:
                body = json.loads(payload)
                body['uid'] = 'cccccccc-cccc-cccc-cccc-cccccccccccc'
                payload = json.dumps(body, separators=(',', ':')).encode()
        else:
            expected = url
            payload = self.blobs[url.rsplit('/', 1)[-1]]
        return Response(expected, payload, status=403 if self.denied and self.denied in url else 200,
            override_url='https://foreign.example.invalid/steal' if self.foreign and self.foreign in url else None,
            length=len(payload)+1 if self.truncated and self.truncated in url else None)
    def close(self): self.closed = True


class Transport:
    def __init__(self, cancelled=False):
        self.lock = threading.RLock(); self.calls = 0; self.max_calls = 64; self.timeout = 10; self.evidence = []
        self.credentials = types.SimpleNamespace(headers=lambda: {'Authorization': 'Bearer synthetic-offline-token'})
        self.cancelled = cancelled
    def check_cancelled(self):
        if self.cancelled: raise RuntimeError('cancelled')


def fake_engine(payload, path, timeout):
    return [('TESTSECRET', 'offline', 1)] if b'TESTSECRET' in payload else []


def collect_case(monkeypatch, secret=False, **changes):
    from peaso import secret_scanning
    monkeypatch.setattr(secret_scanning, '_scan_kingfisher', fake_engine)
    monkeypatch.setattr(secret_scanning, '_scan_trufflehog', fake_engine)
    selection, bodies, blobs = fixture(secret, extra_layer=changes.pop('extra_layer', False), config_secret=changes.pop('config_secret', False))
    body_change = changes.pop('body_change', None)
    if body_change: body_change(bodies)
    meta = Session(selection, bodies, blobs, **changes)
    image = Session(selection, bodies, blobs, **changes)
    transport = Transport()
    result = source.collect_native(transport, scope=SCOPE, selectors=[selection], enabled=True, metadata_session=meta, image_session=image)
    assert meta.closed and image.closed
    assert 'synthetic-offline-token' not in repr(result)
    return result, transport


def evaluate_result(result):
    row = result['rows'][0]
    selection = row['selection']
    identity = selection['revision_name'] + '#container=' + str(selection['container_index'])
    ids = row['source_requests']
    item = {'name': identity, '_resource_id': identity, 'native_id': identity,
        runtime.MARKER: {'scope': SCOPE, 'row': row, 'source_requests': ids,
            'association_kind': 'immutable_revision_container_declaration', 'runtime_image_proven': False},
        '_provenance': {'scope': SCOPE, 'source_requests': ids}}
    index = {'context': {'provider': 'gcp', 'scope': SCOPE, 'metadata': {runtime.OPTION: [selection], 'source_requests': result['source_requests']}},
        'collections': {runtime.KIND: [{'scope': SCOPE, 'items': [item]}]}}
    return consumer.evaluate(item, index)


def test_native_positive_and_clean(monkeypatch):
    for secret, expected in ((True, 'FAIL'), (False, 'PASS')):
        result, transport = collect_case(monkeypatch, secret=secret)
        assert result['status'] == expected
        status, evidence = evaluate_result(result)
        assert status == expected, evidence
        assert 'TESTSECRET' not in repr(result) and 'TESTSECRET' not in repr(evidence)
        if secret:
            leaks = evidence['secret_leaks']
            assert len(leaks) == 1 and {d['engine'] for d in leaks[0]['detectors']} == {'kingfisher', 'trufflehog'}
            assert len(leaks[0]['fingerprint']) == 64 and leaks[0]['fingerprint'] != 'TESTSECRET'
        assert any(r['operation'] == 'artifactregistry.registry_content_get' and r['category'] == 'blobs' for r in transport.evidence)


def test_source_drift_denial_foreign_truncated(monkeypatch):
    for changes in ({'mutate': '/workerPools/'}, {'mutate': '/revisions/'}, {'denied': '/workerPools/'},
                    {'foreign': '/workerPools/'}, {'truncated': '/workerPools/'}, {'denied': '/blobs/'},
                    {'foreign': '/blobs/'}, {'truncated': '/blobs/'}):
        result, _ = collect_case(monkeypatch, **changes)
        assert result['status'] == 'UNKNOWN', changes
        assert evaluate_result(result)[0] == 'UNKNOWN'


def test_preflight_foreign_and_disabled_zero_io(monkeypatch):
    selection, bodies, blobs = fixture()
    t = Transport()
    assert source.collect_native(t, scope=SCOPE, selectors=[selection], enabled=False)['status'] == 'UNKNOWN'
    assert t.calls == 0
    for key, value in [('pool_name', 'projects/foreign/locations/europe-west1/workerPools/pool-one'),
                       ('revision_name', POOL + '/revisions/../foreign'), ('container_index', 10),
                       ('immutable_reference', 'other-docker.pkg.dev/foreign/repo/image@sha256:'+'a'*64)]:
        changed = dict(selection, **{key: value})
        try: source.selections([changed], SCOPE)
        except ValueError: pass
        else: raise AssertionError(key)
    assert t.calls == 0


def test_cancelled_before_network(monkeypatch):
    selection, bodies, blobs = fixture()
    meta = Session(selection, bodies, blobs)
    image = Session(selection, bodies, blobs)
    result = source.collect_native(Transport(cancelled=True), scope=SCOPE, selectors=[selection], enabled=True, metadata_session=meta, image_session=image)
    assert result['status'] == 'UNKNOWN' and not meta.calls and not image.calls


def test_partial_positive_retained(monkeypatch):
    selection, bodies, blobs = fixture(True, extra_layer=True)
    second = next(k for k in blobs if k not in (selection['immutable_reference'].rsplit('@', 1)[1],) and len(blobs[k]) > 1000 and b'other' in blobs[k])
    result, _ = collect_case(monkeypatch, secret=True, extra_layer=True, config_secret=True, truncated=second)
    assert result['status'] == 'FAIL'
    assert evaluate_result(result)[0] == 'FAIL'
    assert not result['complete']


def test_wrong_native_owner_and_split(monkeypatch):
    cases = [
        lambda b: b[0].update(uid='cccccccc-cccc-cccc-cccc-cccccccccccc'),
        lambda b: b[0]['instanceSplitStatuses'][0].update(revision=POOL+'/revisions/other'),
        lambda b: b[0]['instanceSplitStatuses'][0].update(percent=50),
        lambda b: b[1].update(uid='cccccccc-cccc-cccc-cccc-cccccccccccc'),
        lambda b: b[1].update(service='projects/foreign/locations/europe-west1/workerPools/other'),
        lambda b: b[1]['containers'][0].update(image='foreign-image@sha256:'+'a'*64),
        lambda b: b[2].update(projectId='foreign'),
        lambda b: b[3].update(name='projects/foreign/locations/europe-west1/repositories/other'),
        lambda b: b[4].update(uri='other-image@sha256:'+'a'*64),
    ]
    for body_change in cases:
        result, transport = collect_case(monkeypatch, body_change=body_change)
        assert result['status'] == 'UNKNOWN'
        assert evaluate_result(result)[0] == 'UNKNOWN'
        assert not any(r['operation'] == 'artifactregistry.registry_content_get' for r in transport.evidence)


def test_cancellation_during_native_read(monkeypatch):
    selection, bodies, blobs = fixture()
    meta = Session(selection, bodies, blobs); image = Session(selection, bodies, blobs)
    transport = Transport()
    def check():
        if transport.calls >= 2: raise RuntimeError('cancelled')
    transport.check_cancelled = check
    result = source.collect_native(transport, scope=SCOPE, selectors=[selection], enabled=True, metadata_session=meta, image_session=image)
    assert result['status'] == 'UNKNOWN' and not image.calls and meta.closed and image.closed


