"""Larger prepared batches preserve every source and its detected value."""
import json
from pathlib import Path

import pytest

from peaso import secret_scanning as scanning
from peaso import secret_scanning_batch as batch


def _row(value, path=None):
    result = {'Raw': value, 'RawV2': value, 'Verified': False,
              'DetectorName': 'Github'}
    if path is not None:
        result['SourceMetadata'] = {'Data': {'Filesystem': {'file': path}}}
    return json.dumps(result, separators=(',', ':')).encode()


@pytest.fixture
def scanner(monkeypatch, tmp_path):
    original = batch.tempfile.TemporaryDirectory
    monkeypatch.setattr(batch.tempfile, 'TemporaryDirectory',
                        lambda **kw: original(prefix='adaptive-', dir=tmp_path))
    monkeypatch.setattr(batch, '_volatile_shm_available', lambda total: True)
    monkeypatch.setattr(batch, '_DENSE_SAMPLE_ITEMS', 2)
    monkeypatch.setattr(batch, '_DENSE_SAMPLE_OUTPUT', 1000)
    monkeypatch.setattr(scanning, '_trufflehog', lambda: '/synthetic/trufflehog')
    monkeypatch.setattr(scanning, '_scan_kingfisher', lambda *args: [])
    calls = []

    def run(argv, payload, timeout):
        assert 0 < timeout <= 60
        if argv[1] == 'stdin':
            value = payload.decode().split('=', 1)[1]
            return _row(value)
        assert argv[1] == 'filesystem'
        paths = [Path(value) for value in argv if str(tmp_path) in value]
        calls.append(len(paths))
        # Simulate the pinned tool's fixed 4 MiB output ceiling: a later,
        # unexpectedly dense group must split without losing its detections.
        if len(paths) > 2 and any(b'dense' in path.read_bytes() for path in paths):
            raise ValueError('scanner output bound')
        return b'\n'.join(_row(path.read_text().split('=', 1)[1], str(path)) for path in paths)

    monkeypatch.setattr(scanning, '_run', run)
    scanning._RESULTS.clear()
    yield calls, tmp_path
    scanning._RESULTS.clear()
    assert not list(tmp_path.iterdir())


def test_sparse_sources_share_two_processes_and_keep_each_detection(scanner):
    calls, _ = scanner
    items = [(f'key=ghp_{i:036d}'.encode(), f'original/{i}.cfg') for i in range(6)]
    with batch.prepared_content_batch(items):
        outcomes = [scanning.scan_content(payload, path) for payload, path in items]
    assert calls == [2, 4]
    assert all(row['complete'] for row in outcomes)
    assert [row['leaks'][0]['locations'][0]['path'] for row in outcomes] == [path for _, path in items]
    assert [len(row['leaks']) for row in outcomes] == [1] * len(items)


def test_unexpected_dense_group_splits_and_matches_serial_results(scanner):
    calls, _ = scanner
    items = [(f'key=ghp_{i:036d}-dense'.encode(), f'original/{i}.cfg')
             for i in range(6)]
    # The first two are sparse enough to admit a four-source remainder.
    items[:2] = [(payload.replace(b'-dense', b''), path) for payload, path in items[:2]]
    with batch.prepared_content_batch(items):
        prepared = [scanning.scan_content(payload, path) for payload, path in items]
    serial = [scanning.scan_content(payload, path) for payload, path in items]
    assert calls == [2, 4, 2, 2]
    assert prepared == serial
    assert all(row['complete'] and len(row['leaks']) == 1 for row in prepared)


def test_dense_sample_keeps_original_group_size(scanner, monkeypatch):
    calls, _ = scanner
    monkeypatch.setattr(batch, '_DENSE_SAMPLE_OUTPUT', 100)
    items = [(f'key=ghp_{i:036d}'.encode(), f'original/{i}.cfg') for i in range(6)]
    with batch.prepared_content_batch(items):
        outcomes = [scanning.scan_content(payload, path) for payload, path in items]
    assert calls == [2, 2, 2]
    assert all(row['complete'] and len(row['leaks']) == 1 for row in outcomes)


def test_more_than_2048_items_is_rejected_before_preparation(monkeypatch):
    monkeypatch.setattr(batch, '_prepare_trufflehog_batch',
                        lambda *args: pytest.fail('unbounded input reached scanner'))
    with pytest.raises(ValueError, match='content batch bound'):
        with batch.prepared_content_batch([(b'x', 'path')] * 2049):
            pass
