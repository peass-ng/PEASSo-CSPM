from concurrent.futures import ThreadPoolExecutor
import json
import logging
import threading
import time
import tomllib
from pathlib import Path

import pytest

from peaso import collection_job_metrics as jobs
from peaso import runtime_metrics as metrics
from scripts.decode_collection_job_metrics import MARKER, decode


@pytest.fixture(autouse=True)
def close_recorders():
    metrics.close()
    yield
    metrics.close()


def test_nested_and_concurrent_job_identity_is_hashed_bounded_and_run_local():
    frames = []
    metrics.configure(frames.append, role='collector', interval_seconds=60)
    state = jobs._state
    key_hex = state.key.hex()
    marker = '123456789012/us-east-1/resource/PRIVATE-NATIVE-VALUE'
    barrier = threading.Barrier(2, timeout=5)
    def read():
        with metrics.span('collection.job', job_kind='vpc', job_scope=marker):
            barrier.wait()
            return {'native': marker}
    with metrics.span('collection.job', job_kind='vpc', job_scope=marker):
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(read) for _ in range(2)]
            assert [f.result() for f in futures] == [{'native': marker}] * 2
        with metrics.span('collection.job', job_kind='subnet', job_scope=marker):
            pass
    events = [event for tag, event in frames if tag == '__collection_job_metrics__']
    assert len(events) == 4 and all(jobs.validate(e) for e in events)
    assert len({e['job'] for e in events}) == 4
    assert len({e['scope_hmac_sha256'] for e in events}) == 1
    parent = next(e for e in events if e['job'] == 1)
    child = next(e for e in events if e['kind_sha256'] == jobs.kind_digest('subnet'))
    assert child['parent'] == parent['job']
    assert child['start_ms'] >= parent['start_ms'] and child['end_ms'] <= parent['end_ms']
    assert all(e['parent'] == 0 for e in events if e['job'] not in (1, child['job']))
    text = json.dumps(events)
    assert key_hex not in text
    for raw in ('123456789012', 'us-east-1', 'PRIVATE', 'resource/', 'vpc', 'subnet'):
        assert raw not in text
    assert max(len(json.dumps(e)) for e in events) < 450
    metrics.close()
    assert state.key == b''
    metrics.configure(frames.append, role='collector', interval_seconds=60)
    with metrics.span('collection.job', job_kind='vpc', job_scope=marker):
        pass
    again = [e for tag, e in frames if tag == '__collection_job_metrics__' and 'job' in e][-1]
    assert again['kind_sha256'] == jobs.kind_digest('vpc')
    assert again['scope_hmac_sha256'] != parent['scope_hmac_sha256']


def test_disabled_metrics_and_unsupported_identity_preserve_body(monkeypatch):
    jobs.close()
    def forbidden():
        raise AssertionError('disabled diagnostics read a clock')
    monkeypatch.setattr(jobs.time, 'monotonic', forbidden)
    with jobs.span('vpc', '123456789012'):
        value = 3
    assert value == 3


def test_failed_inventory_and_failed_delivery_do_not_change_exception_or_result():
    frames = []
    jobs.configure(frames.append, started=time.monotonic())
    original = ValueError('PRIVATE-EXCEPTION')
    with pytest.raises(ValueError) as error:
        with jobs.span('vpc', 'PRIVATE-SCOPE'):
            raise original
    assert error.value is original
    assert frames[0][1]['failed'] == 1
    def broken(_):
        raise RuntimeError('PRIVATE-DELIVERY')
    jobs.configure(broken, started=time.monotonic())
    with jobs.span('vpc', 'PRIVATE-SCOPE'):
        value = {'same': ['output']}
    assert value == {'same': ['output']}
    assert 'PRIVATE' not in json.dumps(frames)
    jobs.close()


def test_supervisor_rejects_unknown_fields_raw_hashes_and_unsafe_numeric_values(caplog):
    frames = []
    jobs.configure(frames.append, started=time.monotonic())
    with jobs.span('vpc', 'PRIVATE-SCOPE'):
        pass
    valid = frames[0][1]
    logger = logging.getLogger('job-metric-test')
    for changed in ({**valid, 'secret': 'PRIVATE'}, {**valid, 'kind_sha256': 'PRIVATE'},
                    {**valid, 'failed': True}, {**valid, 'job': 0},
                    {**valid, 'parent': valid['job']}, {**valid, 'end_ms': 2**64}):
        assert jobs.record(changed, logger) is False
    with caplog.at_level(logging.INFO, logger='job-metric-test'):
        assert jobs.record(valid, logger)
    assert 'peaso collection job metrics:' in caplog.text
    assert 'PRIVATE' not in caplog.text
    decoded = decode([{'message': MARKER + json.dumps(valid)}])
    assert decoded['longest_jobs'][0]['inventory_kind'] == 'vpc'
    assert decoded['captured_job_count'] == 1
    jobs.close()


def test_event_cap_retains_late_longest_and_exports_validated_summary(monkeypatch):
    frames = []
    monkeypatch.setattr(jobs, 'MAX_STREAMED_JOBS', 2)
    monkeypatch.setattr(jobs, 'MAX_RETAINED_JOBS', 1)
    clock = iter((1, 2, 3, 4, 5, 10))
    monkeypatch.setattr(jobs.time, 'monotonic', lambda: next(clock))
    jobs.configure(frames.append, started=0)
    for _ in range(3):
        with jobs.span('vpc', 'PRIVATE-SCOPE'):
            pass
    jobs.close()
    assert len(frames) == 3  # two streamed rows plus one bounded final summary
    summary = frames[-1][1]
    assert jobs.validate(summary)
    assert summary['started_jobs'] == summary['completed_jobs'] == 3
    assert summary['streamed_jobs'] == 2 and summary['suppressed_jobs'] == 1
    assert summary['longest_jobs'][0]['job'] == 3
    decoded = decode([{'message': MARKER + json.dumps(e)} for _, e in frames])
    assert decoded['captured_job_count'] == 3
    assert decoded['longest_jobs'][0]['job'] == 3
    assert decoded['roster_sha256'] == jobs.ROSTER_SHA256


def test_unknown_kind_never_reaches_log():
    frames = []
    jobs.configure(frames.append, started=time.monotonic())
    with jobs.span('private_arbitrary_label', 'PRIVATE-SCOPE'):
        pass
    jobs.close()
    assert len(frames) == 1 and frames[0][1]['rejected_jobs'] == 1
    assert frames[0][1]['longest_jobs'] == []


def test_reviewed_roster_is_in_wheel_package_data():
    root = Path(__file__).resolve().parents[1]
    config = tomllib.loads((root / 'pyproject.toml').read_text())
    assert 'collection_job_kinds_20261029.json' in config['tool']['setuptools']['package-data']['peaso']
    assert jobs.roster()
