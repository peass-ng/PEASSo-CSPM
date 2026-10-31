"""A bounded batch still batches when volatile scratch is smaller than input."""
import json
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from peaso import secret_scanning as scanning, secret_scanning_batch as batch

MIB = 1024 * 1024


@pytest.fixture
def bounded_tmpfs(monkeypatch, tmp_path):
    original = tempfile.TemporaryDirectory
    monkeypatch.setattr(batch.tempfile, 'TemporaryDirectory',
        lambda **kw: original(prefix='synthetic-capacity-', dir=tmp_path))
    monkeypatch.setattr(batch, '_volatile_shm_available', lambda size: size <= 2 * MIB)
    monkeypatch.setattr(batch, '_staging_root', lambda size: str(tmp_path))
    monkeypatch.setattr(scanning, '_trufflehog', lambda: '/synthetic-tool')
    calls = []
    def run(argv, payload, timeout):
        paths = [Path(x) for x in argv if str(tmp_path) in x]
        assert paths and 'filesystem' in argv and payload == b''
        assert 0 < timeout <= 60
        assert sum(p.stat().st_size for p in paths) <= 2 * MIB
        calls.append((paths, timeout))
        return b'\n'.join(json.dumps({
            'Raw': 'synthetic-primary', 'RawV2': 'synthetic-primary',
            'Verified': False, 'DetectorName': 'Synthetic',
            'SourceMetadata': {'Data': {'Filesystem': {'file': str(path)}}},
        }).encode() for path in paths if b'synthetic-primary' in path.read_bytes())
    monkeypatch.setattr(scanning, '_run', run)
    yield calls
    assert not list(tmp_path.iterdir())
    assert batch._PREPARED_BATCH.get() is None


def items():
    return [(('synthetic-primary\n' + str(n)).encode().ljust(MIB, b'.'),
             'native/source-' + str(n)) for n in range(3)]


def test_capacity_split_preserves_every_source_and_detection(bounded_tmpfs):
    selected = items()
    with batch.prepared_content_batch(selected):
        assert len(batch._PREPARED_BATCH.get()) == 3
        for payload, path in selected:
            rows = batch.prepared_output(payload, path)
            assert json.loads(rows)['Raw'] == 'synthetic-primary'
        assert all(not path.exists() for paths, _ in bounded_tmpfs for path in paths)
    assert [len(paths) for paths, _ in bounded_tmpfs] == [2, 1]
    assert bounded_tmpfs[1][1] <= bounded_tmpfs[0][1]


def test_later_group_failure_discards_preparation_for_serial_fallback(monkeypatch, bounded_tmpfs):
    original = scanning._run
    def run(*args):
        if bounded_tmpfs:
            raise RuntimeError('synthetic second-group failure')
        return original(*args)
    monkeypatch.setattr(scanning, '_run', run)
    with batch.prepared_content_batch(items()):
        assert all(batch.prepared_output(payload, path) is None for payload, path in items())
    assert len(bounded_tmpfs) == 1


def test_unsplittable_payload_keeps_serial_fallback(bounded_tmpfs):
    selected = [(b'a' * (3 * MIB), 'large'), (b'b', 'small')]
    with batch.prepared_content_batch(selected):
        assert all(batch.prepared_output(payload, path) is None for payload, path in selected)
    assert not bounded_tmpfs


def test_capacity_groups_share_one_deadline(monkeypatch, bounded_tmpfs):
    clock = iter([100.0, 161.0])
    monkeypatch.setattr(batch, 'time', SimpleNamespace(monotonic=lambda: next(clock)))
    with batch.prepared_content_batch(items(), timeout=60):
        assert batch._PREPARED_BATCH.get() is None
    assert not bounded_tmpfs


def test_capacity_groups_share_output_bound(monkeypatch, bounded_tmpfs):
    monkeypatch.setattr(scanning, 'MAX_OUTPUT', 1)
    with batch.prepared_content_batch(items()):
        assert batch._PREPARED_BATCH.get() is None
    assert len(bounded_tmpfs) == 1
