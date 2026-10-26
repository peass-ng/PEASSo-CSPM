"""Leak scan scheduling, exact locations and complete redacted correlation."""
import copy
import json
import threading

import pytest

from peaso import secret_scanning as scanning
from peaso.secret_findings import deduplicate_secret_findings


@pytest.fixture(autouse=True)
def isolated_cache():
    scanning._RESULTS.clear()
    yield
    scanning._RESULTS.clear()


def test_both_detectors_overlap_and_union_redaction_before_return(monkeypatch):
    barrier = threading.Barrier(2, timeout=2)
    values = ("synthetic-first-value", "synthetic-second-value")

    def detector(value):
        def scan(payload, path, timeout):
            barrier.wait()
            return [(value, 'synthetic', 1)]
        return scan

    monkeypatch.setattr(scanning, '_scan_kingfisher', detector(values[0]))
    monkeypatch.setattr(scanning, '_scan_trufflehog', detector(values[1]))
    callbacks = []
    result = scanning.scan_content(b'synthetic', '/'.join(values), _redact_values=callbacks.append)
    assert result['complete'] and len(result['leaks']) == 2
    assert [engine['engine'] for engine in result['engines']] == ['kingfisher', 'trufflehog']
    # Found values stay visible in the exact path; the callback has nothing to redact.
    assert callbacks == [frozenset()]
    assert {loc['path'] for leak in result['leaks'] for loc in leak['locations']} == {'/'.join(values)}
    assert all(value not in repr(scanning._RESULTS) for value in values)
    assert not any(t.name.startswith('peaso-secret') for t in threading.enumerate())


def test_worker_start_failure_falls_back_to_both_detectors(monkeypatch):
    def unavailable(*args, **kwargs):
        raise RuntimeError('cannot start worker')

    monkeypatch.setattr(scanning.ThreadPoolExecutor, 'submit', unavailable)
    monkeypatch.setattr(scanning, '_scan_kingfisher', lambda *args: [('synthetic', 'first', 1)])
    monkeypatch.setattr(scanning, '_scan_trufflehog', lambda *args: [('synthetic', 'second', 1)])
    outcome = scanning.scan_content(b'synthetic')
    assert outcome['complete'] and len(outcome['leaks']) == 1
    assert {d['engine'] for d in outcome['leaks'][0]['detectors']} == {'kingfisher', 'trufflehog'}


@pytest.mark.parametrize('value,payload,lines', [
    ('secret', b'secret\nxx secret\nsecret', [1, 2, 3]),
    ('multi\nline', b'multi\nline\nmulti\nline', [1, 3]),
    ('\n', b'\n\n\n', [1, 2, 3]),
    ('aaa', b'aaaaaa\naaa', [1, 1, 2]),
    ('caf\u00e9', 'caf\u00e9\nother caf\u00e9'.encode(), [1, 2]),
    ('decoded-only', b'encoded representation', [None]),
])
def test_exact_line_recovery_and_repeated_detector_rows(monkeypatch, value, payload, lines):
    output = b'\n'.join(json.dumps({'Raw': value, 'Verified': False, 'DetectorName': name}).encode()
                        for name in ('first', 'second'))
    monkeypatch.setattr(scanning, '_trufflehog', lambda: '/synthetic/trufflehog')
    monkeypatch.setattr(scanning, '_run', lambda *args: output)
    assert scanning._scan_trufflehog(payload, 'file', 1) == [
        (value, name, line) for name in ('first', 'second') for line in lines]


@pytest.mark.parametrize('rows', [1, 2])
def test_location_bound_includes_reused_positions(monkeypatch, rows):
    monkeypatch.setattr(scanning, 'MAX_FINDINGS', 5)
    monkeypatch.setattr(scanning, '_trufflehog', lambda: '/synthetic/trufflehog')
    output = b'\n'.join([b'{"Raw":"value","Verified":false}'] * rows)
    monkeypatch.setattr(scanning, '_run', lambda *args: output)
    with pytest.raises(ValueError, match='finding bound'):
        scanning._scan_trufflehog(b'value\n' * (6 if rows == 1 else 3), 'file', 1)


def leak(number=0):
    return {'fingerprint': 'a' * 64,
            'detectors': [{'engine': 'kingfisher', 'rule': 'synthetic'}],
            'locations': [{'path': 'synthetic.log', 'line': number + 1}]}


def test_large_merge_preserves_all_locations_and_existing_sort_order():
    rows = [leak(i) for i in range(5000)]
    original = copy.deepcopy(rows)
    merged = scanning.merge_leaks(rows + rows[::-1])
    assert rows == original
    assert len(merged) == 1
    assert merged[0]['detectors'] == rows[0]['detectors']
    assert merged[0]['locations'] == sorted([row['locations'][0] for row in rows],
                                           key=lambda loc: json.dumps(loc, sort_keys=True))


def test_grouping_preserves_all_sources_and_incomplete_coverage():
    sources = [{'provider': 'aws', 'check_id': f'check-{i % 3}', 'scope': f'scope-{i % 7}',
                'resource_id': f'asset-{i}', 'native_resource_id': f'native-{i}',
                'status': 'FAIL', 'frameworks': [f'framework-{i % 2}'],
                'evidence': {'secret_leaks': [leak()], 'complete': i != 123}}
               for i in range(1000)]
    original = copy.deepcopy(sources)
    grouped = deduplicate_secret_findings(sources)
    assert sources == original and len(grouped) == 1
    result = grouped[0]
    assert result['frameworks'] == ['framework-0', 'framework-1']
    assert result['linked_check_ids'] == ['check-0', 'check-1', 'check-2']
    assert result['evidence']['complete'] is False
    assert result['evidence_summary'].endswith('Coverage is incomplete.')
    assert {loc['resource_id'] for loc in result['evidence']['secret_leaks'][0]['locations']} == {
        f'native-{i}' for i in range(1000)}


def test_positive_cache_never_skips_metadata_redaction_callback(monkeypatch):
    calls, callbacks = [], []
    for engine in ('kingfisher', 'trufflehog'):
        def scan(*args, name=engine):
            calls.append(name)
            return [('synthetic-value', 'synthetic', 1)]
        monkeypatch.setattr(scanning, '_scan_' + engine, scan)
    for _ in range(2):
        result = scanning.scan_content(b'synthetic-value', _redact_values=callbacks.append)
        assert result['complete']
    assert len(calls) == 4
    assert callbacks == [frozenset()] * 2


@pytest.mark.parametrize('malformed', [
    {'locations': [{'path': 'file', 'line': True}]},
    {'locations': [{'path': 'file', 'line': 0}]},
    {'detectors': [{'engine': 'unknown', 'rule': 'synthetic'}]},
    {'locations': [{'path': 'file', 'extra': 'untrusted'}]},
])
def test_invalid_leak_evidence_is_still_rejected(malformed):
    with pytest.raises(ValueError):
        scanning.merge_leaks([dict(leak(), **malformed)])


def test_parallel_detectors_preserve_prepared_batch_and_private_source_context(monkeypatch):
    from peaso import secret_scanning_batch as batch, secret_evidence as evidence
    payload, path = b'synthetic-primary', 'artifact/config.txt'
    output = json.dumps({'Raw': 'synthetic-primary', 'RawV2': 'synthetic-primary:component',
                         'Verified': False, 'DetectorName': 'Synthetic'}).encode()
    monkeypatch.setattr(batch, '_prepare_trufflehog_batch',
                        lambda items, timeout: {item: output if item == (payload, path) else b'' for item in items})
    monkeypatch.setattr(scanning, '_scan_kingfisher', lambda *args: [])
    def must_not_spawn(*args):
        raise AssertionError('Prepared TruffleHog output must stay available on caller context')
    monkeypatch.setattr(scanning, '_run', must_not_spawn)
    observed, caller = [], threading.get_ident()
    monkeypatch.setattr(evidence, 'remember_full_match', lambda *args, **kwargs:
                        observed.append((threading.get_ident(), dict(evidence._source.fields))))
    original = getattr(evidence._source, 'fields', {})
    evidence._source.fields = {'resource_id': 'synthetic-workload', 'scope': 'synthetic-scope'}
    try:
        with batch.prepared_content_batch([(payload, path), (b'clean', 'artifact/other.txt')]):
            result = scanning.scan_content(payload, path)
    finally:
        evidence._source.fields = original
    assert result['complete'] is True
    assert len(result['leaks']) == 1
    assert observed == [(caller, {'resource_id': 'synthetic-workload', 'scope': 'synthetic-scope'})]
