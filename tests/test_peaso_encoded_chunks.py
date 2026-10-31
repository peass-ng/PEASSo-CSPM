"""Lossless encoded chunks retain legacy boundaries, detail routing and writes."""
from contextlib import nullcontext
import copy
import inspect
import gzip
from io import BytesIO
import json
from unittest.mock import patch

import pytest

from peaso.engine import hydrate_finding
from peaso.storage import artifacts as storage, reports

TENANT, JOB = 'owner', 'a' * 32


class MemoryS3:
    def __init__(self):
        self.objects = {}

    def put_object(self, **request):
        self.objects[request['Key']] = request

    def get_object(self, Bucket, Key):
        return {'Body': BytesIO(self.objects[Key]['Body'])}


def decoded(request):
    body = request['Body']
    return gzip.decompress(body) if request.get('ContentEncoding') == 'gzip' else body


@pytest.mark.parametrize('maximum', [1, 80, 4096, 2 * 1024 * 1024])
def test_identical_chunk_boundaries_and_exact_serialized_bytes(monkeypatch, maximum):
    monkeypatch.setattr(reports, 'CHUNK_BYTES', maximum)
    rows = [{'id': i, 'unicode': '· 数据 😀', 'controls': '\n\t\\"',
             'nested': [None, True, False, -0.0, {'value': i / 7}]} for i in range(503)]
    original = copy.deepcopy(rows)
    writer = storage.S3Artifacts('private', client=MemoryS3())
    expected = list(reports.chunks(rows))
    actual = list(reports._artifact_chunks(writer, rows))
    assert [group for group, _ in actual] == expected
    for group, body in actual:
        assert body == json.dumps({'items': group}, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()
        assert json.loads(body) == {'items': group}
    assert rows == original


def test_custom_and_local_stores_keep_ordinary_json_puts(tmp_path):
    writer = storage.FileArtifacts(tmp_path)
    rows = [{'id': 'one', 'native': '数据'}, {'id': 'two'}]
    for group, body in reports._artifact_chunks(writer, rows):
        assert body is None
        reference = reports._put_chunk(writer, TENANT, JOB, 'coverage', group, body)
        assert writer.get(TENANT, reference) == {'items': group}


@pytest.mark.parametrize('parallel', [False, True])
def test_findings_are_encoded_once_and_retain_compression_and_kms(parallel):
    client = MemoryS3()
    store = storage.S3Artifacts('private', client=client, kms_key='fixture-kms')
    rows = [{'id': f'{i:04d}', 'check_id': 'fixture', 'evidence': {'value': '数据' * 50}} for i in range(200)]
    with store.batch() if parallel else nullcontext(store) as writer:
        with patch.object(reports.json, 'dumps', wraps=json.dumps) as encode:
            prepared = reports._prepared_findings(writer, TENANT, JOB, rows)
            for group, body in reports._artifact_chunks(writer, prepared, preencoded=True):
                reference = reports._put_chunk(writer, TENANT, JOB, 'findings', group, body)
            assert encode.call_count == len(rows)
        writer._put_json_bytes(TENANT, JOB, 'manifest', reports._json_bytes({'reference': reference}))
    assert store.get(TENANT, reference) == {'items': rows}
    stored = client.objects['artifacts/' + reference]
    assert stored['ContentType'] == 'application/json' and stored['ContentEncoding'] == 'gzip'
    assert stored['ServerSideEncryption'] == 'aws:kms' and stored['SSEKMSKeyId'] == 'fixture-kms'


@pytest.mark.parametrize('text', ['x' * 600, '数' * 90, '😀' * 45, '\n' * 300])
def test_legacy_oversized_finding_decision_and_hydrated_detail_are_preserved(monkeypatch, text):
    monkeypatch.setattr(reports, 'CHUNK_BYTES', 500)
    rows = [{'id': f'{i:03d}', 'check_id': 'fixture', 'evidence': {'native': value}}
            for i, value in enumerate(('small', text))]
    metadata = {'fixture': {'category': 'hardening', 'title': 'Recorded fixture'}}
    client = MemoryS3()
    writer = storage.S3Artifacts('private', client=client)
    prepared = list(reports._prepared_findings(writer, TENANT, JOB, rows,
        check_frameworks={'fixture': ['fixture']}, check_meta=metadata))
    for (actual, body), original in zip(prepared, rows, strict=True):
        assert body == reports._json_bytes(actual)
        oversized = len(json.dumps(original).encode()) > reports.CHUNK_BYTES
        assert ('_detail_reference' in actual) == oversized
        if oversized:
            assert writer.get(TENANT, actual['_detail_reference']) == hydrate_finding(
                original, {'fixture': ['fixture']}, metadata)
        else:
            assert actual == original


def test_unicode_detail_routing_uses_legacy_ascii_size_not_compact_utf8_size():
    row = {'id': 'large', 'check_id': 'fixture', 'evidence': {'native': '数' * 350000}}
    assert len(reports._json_bytes(row)) < reports.CHUNK_BYTES < len(json.dumps(row).encode())
    client = MemoryS3()
    writer = storage.S3Artifacts('private', client=client)
    [(summary, _)] = reports._prepared_findings(writer, TENANT, JOB, [row])
    assert writer.get(TENANT, summary['_detail_reference'])['evidence'] == row['evidence']


@pytest.mark.parametrize('bad', [float('nan'), float('inf'), float('-inf')])
def test_nonfinite_values_fail_without_publishing_manifest(bad):
    client = MemoryS3()
    store = storage.S3Artifacts('private', client=client)
    with pytest.raises(ValueError):
        with store.batch() as writer:
            for group, body in reports._artifact_chunks(writer, [{'native': bad}]):
                reports._put_chunk(writer, TENANT, JOB, 'findings', group, body)
            writer.put(TENANT, JOB, 'manifest', {})
    assert not any('/manifest-' in key for key in client.objects)


@pytest.mark.parametrize('parallel', [False, True])
def test_raw_json_reuses_reference_policy_and_rejects_mutable_bytes(parallel):
    store = storage.S3Artifacts('private', client=MemoryS3())
    with store.batch() if parallel else nullcontext(store) as writer:
        with pytest.raises(ValueError):
            writer._put_json_bytes('other-tenant', 'invalid-job', 'findings', b'{}')
        with pytest.raises(TypeError):
            writer._put_json_bytes(TENANT, JOB, 'findings', bytearray(b'{}'))


def test_raw_json_failure_is_sticky_and_prevents_manifest():
    class FailingS3(MemoryS3):
        def put_object(self, **request):
            if '/findings-' in request['Key']:
                raise OSError('fixture failure')
            super().put_object(**request)

    client = FailingS3()
    store = storage.S3Artifacts('private', client=client)
    with pytest.raises(OSError):
        with store.batch() as writer:
            writer._put_json_bytes(TENANT, JOB, 'findings', b'{"items":[]}')
            with pytest.raises(OSError):
                writer.flush()
            writer._put_json_bytes(TENANT, JOB, 'manifest', b'{}')
    assert not any('/manifest-' in key for key in client.objects)


def test_complete_finding_chunk_and_detail_publication_matches_previous_path(monkeypatch):
    from tests.synthetic.benchmark_peaso_publication import content_digest

    monkeypatch.setattr(reports, 'CHUNK_BYTES', 1024)
    rows = [{'id': f'{i:03d}', 'check_id': 'fixture', 'evidence': {
        'native': '数' * 180 if i in (30, 70) else 'fixture data' * 10}} for i in range(100)]
    original = copy.deepcopy(rows)

    def publish(encoded):
        client = MemoryS3()
        store = storage.S3Artifacts('private', client=client, kms_key='fixture-kms')
        with store.batch() as writer:
            if encoded:
                prepared = reports._prepared_findings(writer, TENANT, JOB, rows)
                groups = reports._artifact_chunks(writer, prepared, preencoded=True)
            else:
                # Previous implementation: prepare every oversized detail
                # before sizing and serializing all finding chunks.
                prepared = []
                for row in sorted(rows, key=lambda row: row['id']):
                    if len(json.dumps(row).encode()) > reports.CHUNK_BYTES:
                        reference = writer.put(TENANT, JOB, 'detail', hydrate_finding(row))
                        row = dict(reports.finding_summary(row), _detail_reference=reference)
                    prepared.append(row)
                groups = ((group, None) for group in reports.chunks(prepared))
            chunks = []
            for group, body in groups:
                detail = reports._put_chunk(writer, TENANT, JOB, 'findings', group, body)
                summary = writer.put(TENANT, JOB, 'finding-index', {'items': [reports.finding_summary(row) for row in group]})
                chunks.append({'reference': detail, 'index_reference': summary,
                               'first_id': group[0]['id'], 'last_id': group[-1]['id'], 'count': len(group)})
            writer.put(TENANT, JOB, 'manifest', {'finding_chunks': chunks})
        assert sum('/detail-' in key for key in client.objects) == 2
        return len(client.objects), content_digest(client.objects)

    assert publish(True) == publish(False)
    assert rows == original


@pytest.mark.parametrize('compact', [False, True])
def test_complete_publisher_retains_native_artifacts_and_private_output_boundaries(monkeypatch, compact):
    from tests.synthetic.benchmark_peaso_publication import SimulatedS3
    from tests.synthetic.benchmark_peaso_report_publication import fixture

    monkeypatch.setattr(reports, 'CHUNK_BYTES', 1024)
    report, snapshot = fixture(12, compact)
    canary = 'synthetic-private-publisher-canary'
    report['findings'][0]['evidence']['native'] = '数' * 400
    report['findings'][0]['secret_evidence'] = {'value': canary}
    report['snapshot_metadata'] = {'image_vulnerability_scan': {'credentials': canary}}
    report['ai'] = {'status': 'not_requested', 'reason': 'fixture'}
    before = copy.deepcopy((report, snapshot))
    # Uploads overlap but never exceed the batch's configured worker bound.
    workers = inspect.signature(storage.S3Artifacts.batch).parameters['workers'].default
    client = SimulatedS3(0)
    store = storage.S3Artifacts('private', client=client, kms_key='fixture-kms')
    reference = reports.publish_report(store, TENANT, JOB, report, snapshot)
    assert list(client.objects)[-1] == 'artifacts/' + reference
    assert client.peak <= workers
    assert any('/detail-' in key for key in client.objects)
    assert all(canary.encode() not in decoded(request) for request in client.objects.values())
    manifest = json.loads(decoded(client.objects['artifacts/' + reference]))
    assert bool(manifest.get('resource_chunks')) == compact
    assert manifest['finding_count'] == 12
    # Every finding is retained exactly once across the published chunks.
    published = [row['id'] for key, request in client.objects.items()
                 if key.rsplit('/', 1)[-1].startswith('findings-') for row in json.loads(decoded(request))['items']]
    assert sorted(published) == sorted(finding['id'] for finding in report['findings'])
    assert (report, snapshot) == before
