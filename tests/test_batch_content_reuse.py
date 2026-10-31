"""Exact-content reuse keeps every original path and private source binding."""
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace

import pytest
from peaso import secret_scanning as scanning, secret_evidence as evidence

spec = importlib.util.spec_from_file_location('peaso._batch_content_test',
    Path(__file__).resolve().parents[1]/'peaso/secret_scanning_batch.py')
batch = importlib.util.module_from_spec(spec)
spec.loader.exec_module(batch)
PRIMARY = 'synthetic-primary'
FULL = PRIMARY+':'+'A'*40


@pytest.fixture
def prepared(monkeypatch, tmp_path):
    calls = {'sizes': [], 'files': [], 'serial': 0}
    temporary = tempfile.TemporaryDirectory
    monkeypatch.setattr(batch, 'tempfile', SimpleNamespace(TemporaryDirectory=
        lambda **kwargs: temporary(prefix='synthetic-only-', dir=tmp_path)))
    monkeypatch.setattr(batch, '_volatile_shm_available',
        lambda size: calls['sizes'].append(size) or True)
    monkeypatch.setattr(batch, '_staging_root', lambda size: str(tmp_path))
    monkeypatch.setattr(scanning, '_prepared_trufflehog_output', batch.prepared_output)
    monkeypatch.setattr(scanning, '_trufflehog', lambda: '/synthetic-trufflehog')
    monkeypatch.setattr(scanning, '_scan_kingfisher', lambda *a: [])

    def row(payload, source=None):
        if PRIMARY.encode() not in payload:
            return b''
        value = dict(Raw=PRIMARY, RawV2=FULL, DetectorName='AWS', Verified=False)
        if source is not None:
            value['SourceMetadata'] = {'Data': {'Filesystem': {'file': source}}}
        return json.dumps(value).encode()

    def run(argv, payload, timeout):
        if 'filesystem' not in argv:
            calls['serial'] += 1
            return row(payload)
        paths = [Path(value) for value in argv if str(tmp_path) in value]
        assert all(path.parent.stat().st_mode & 0o777 == 0o700 for path in paths)
        assert all(path.stat().st_mode & 0o777 == 0o600 for path in paths)
        calls['files'].append(paths)
        return b'\n'.join(value for path in paths
            if (value := row(path.read_bytes(), str(path))))

    monkeypatch.setattr(scanning, '_run', run)
    scanning._RESULTS.clear()
    yield calls
    scanning._RESULTS.clear()


def test_unique_content_staged_once_and_clean_results_keep_all_keys(prepared):
    payload = FULL.encode()
    items = [(payload, 'one'), (b'clean', 'clean'), (payload, 'two'), (payload, 'one')]
    with batch.prepared_content_batch(items):
        shared = batch._PREPARED_BATCH.get()
        assert len(shared) == 3
        assert batch.prepared_output(payload, 'one') is batch.prepared_output(payload, 'two')
        assert batch.prepared_output(b'clean', 'clean') == b''
        assert batch.prepared_output(b'other', 'clean') is None
        assert all(not path.exists() for paths in prepared['files'] for path in paths)
    assert prepared['sizes'] == [len(payload)+len(b'clean')]
    assert [len(paths) for paths in prepared['files']] == [2]
    assert not shared and batch._PREPARED_BATCH.get() is None


def test_128_identical_payloads_keep_full_private_native_locations(prepared):
    payload = FULL.encode()
    items = [(payload, f'original/{i}') for i in range(128)]
    cipher = evidence.EphemeralCipher()
    with evidence.capture(cipher, tenant='fixture', scan_id='a'*32) as sink:
        with batch.prepared_content_batch(items):
            for i, (body, path) in enumerate(items):
                with evidence.source_context(resource_id=f'resource/{i}', scope='native', path=path):
                    outcome = scanning.scan_content(body, path)
                    assert outcome['complete'] and outcome['leaks']
        for value in (PRIMARY, FULL):
            record = cipher.decrypt(sink.records[scanning._fingerprint(value)])
            assert {loc['path'] for loc in record['locations']} == {path for _, path in items}
            assert {loc['resource_id'] for loc in record['locations']} == {f'resource/{i}' for i in range(128)}
            assert all(loc['scope'] == 'native' for loc in record['locations'])
        assert not sink.incomplete
    assert [len(paths) for paths in prepared['files']] == [1]
    assert prepared['serial'] == 0 and batch._PREPARED_BATCH.get() is None


def test_byte_different_content_remains_separate(prepared):
    payload = FULL.encode()
    items = [(payload, 'one'), (payload+b'\n', 'two')]
    with batch.prepared_content_batch(items):
        assert batch.prepared_output(*items[0]) != batch.prepared_output(*items[1])
    assert [len(paths) for paths in prepared['files']] == [2]
    assert prepared['sizes'] == [2*len(payload)+1]


def test_logical_input_byte_bound_is_not_reduced_by_deduplication(prepared, monkeypatch):
    monkeypatch.setattr(batch, 'MAX_BATCH_BYTES', 16)
    with pytest.raises(ValueError, match='content batch bound'):
        with batch.prepared_content_batch([(b'x'*10, 'one'), (b'x'*10, 'two')]):
            pytest.fail('logical input bound widened')
    assert not prepared['files'] and not prepared['sizes']


def test_unbound_engine_source_falls_back_for_every_original_source(prepared, monkeypatch):
    original = scanning._run
    def run(argv, payload, timeout):
        if 'filesystem' in argv:
            original(argv, payload, timeout)
            return json.dumps(dict(Raw=PRIMARY, Verified=False,
                SourceMetadata={'Data': {'Filesystem': {'file': '/not-staged'}}})).encode()
        return original(argv, payload, timeout)
    monkeypatch.setattr(scanning, '_run', run)
    items = [(FULL.encode(), f'original/{i}') for i in range(8)]
    cipher = evidence.EphemeralCipher()
    with evidence.capture(cipher, tenant='fixture', scan_id='a'*32) as sink:
        with batch.prepared_content_batch(items):
            assert batch._PREPARED_BATCH.get() is None
            for payload, path in items:
                with evidence.source_context(path=path, resource_id=path):
                    assert scanning.scan_content(payload, path)['complete']
        record = cipher.decrypt(sink.records[scanning._fingerprint(FULL)])
        assert {loc['path'] for loc in record['locations']} == {path for _, path in items}
    assert prepared['serial'] == len(items)


def test_nested_preparation_restores_parent_context(prepared):
    first = [(FULL.encode(), 'parent/one'), (FULL.encode(), 'parent/two')]
    second = [(b'clean', 'child/one'), (b'clean', 'child/two')]
    with batch.prepared_content_batch(first):
        parent = batch._PREPARED_BATCH.get()
        with batch.prepared_content_batch(second):
            assert batch._PREPARED_BATCH.get() is not parent
        assert batch._PREPARED_BATCH.get() is parent and parent
    assert not parent and batch._PREPARED_BATCH.get() is None


@pytest.mark.parametrize('failure', ['invalid_json', 'truncated_json', 'verified', 'empty_raw', 'non_object', 'timeout'])
def test_invalid_or_partial_preparation_never_becomes_clean(prepared, monkeypatch, failure):
    original = scanning._run
    def run(argv, payload, timeout):
        if 'filesystem' not in argv:
            return original(argv, payload, timeout)
        valid = original(argv, payload, timeout)
        if failure == 'timeout':
            raise TimeoutError('synthetic bounded timeout')
        if failure == 'invalid_json': return b'not json'
        if failure == 'truncated_json': return valid+b'\n{"Raw":'
        if failure == 'non_object': return b'[]'
        row = json.loads(valid)
        if failure == 'verified': row['Verified'] = True
        if failure == 'empty_raw': row['Raw'] = ''
        return json.dumps(row).encode()
    monkeypatch.setattr(scanning, '_run', run)
    items = [(FULL.encode(), 'first'), (FULL.encode(), 'second')]
    with batch.prepared_content_batch(items):
        assert batch._PREPARED_BATCH.get() is None
        for payload, path in items:
            outcome = scanning.scan_content(payload, path)
            assert outcome['complete'] and outcome['leaks']
    assert prepared['serial'] == 2
    assert all(not path.exists() for paths in prepared['files'] for path in paths)
