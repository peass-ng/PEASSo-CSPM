"""Independent adversarial review; proposal implementations are never patched.

Only fake native HTTP harnesses and detector failure boundaries are injected.
Regression assertions describe required behavior and intentionally remain red
when the immutable reviewed proposal violates its capture-consumer contract.
"""
from copy import deepcopy
import gzip
import importlib.util
import io
import json
from pathlib import Path
import socket
import tarfile
import pytest

from peaso import secret_scanning as scanning
from peaso.collectors import gcp


def load_harness(name):
    path = Path(__file__).with_name('gcp_' + name + '_referenced_source_20261020_test.py')
    spec = importlib.util.spec_from_file_location('independent_' + name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


dataflow = load_harness('dataflow')
workbench = load_harness('workbench')


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def blocked(*args, **kwargs): pytest.fail('Live cloud, authentication or network is forbidden')
    for name in ('connect', 'connect_ex', 'sendto'): monkeypatch.setattr(socket.socket, name, blocked)
    for name in ('create_connection', 'getaddrinfo', 'gethostbyname', 'gethostbyname_ex'):
        monkeypatch.setattr(socket, name, blocked)
    monkeypatch.setattr(gcp, 'Credentials', blocked)
    monkeypatch.setattr(gcp.Transport, 'request', blocked)
    scanning._RESULTS.clear()
    yield
    scanning._RESULTS.clear()


@pytest.mark.parametrize('hit', [False, True], ids=['clean_sibling_invalid', 'trusted_hit_sibling_invalid'])
def test_workbench_invalid_sibling_cannot_establish_complete_capture(monkeypatch, hit):
    """Actual two-target capture, then one malformed sibling engine receipt.

    This tests a selective consumer-contract corruption, not fabricated native
    identity or a claim of protection against wholly forged snapshots.
    """
    targets = [workbench.target(), {**workbench.target(), 'resource': workbench.target()['resource'] + '-second'}]
    snapshot, initial, trace = workbench.capture(monkeypatch, targets=targets,
        payload=('token=' + workbench.TOKEN).encode() if hit else b'echo ready\n', real=True)
    assert {r[0] for r in initial} == {'FAIL' if hit else 'PASS'} and len(trace.calls) == 18
    envelope = snapshot['collections'][0]
    first, second = envelope['items']
    second[workbench.source.MARKER]['parts'][0]['engines'][0]['version'] = '0.0.0'
    index = deepcopy(trace.index)
    index['collections'][workbench.KIND] = [envelope]
    assert workbench.consumer.referenced_source(second, index)[0] == 'UNKNOWN'
    status, details = workbench.consumer.referenced_source(first, index)
    assert status == ('FAIL' if hit else 'UNKNOWN') and details['complete'] is False, (
        'An independently invalid selected sibling must prevent a clean or complete batch result', status, details['complete'])


def test_dataflow_closing_request_must_bind_opening_request(monkeypatch):
    """Real capture's closing job receipt changed to another opaque route hash."""
    capture, initial, calls, _ = dataflow.capture(monkeypatch)
    assert initial[0][0] == 'PASS' and len(calls) == 9
    opening = next(r for r in capture['receipts'] if r['operation'] == 'reference_before')
    closing = next(r for r in capture['receipts'] if r['operation'] == 'reference_after')
    assert opening['request'] == closing['request']
    closing['request'] = '0' * 64 if opening['request'] != '0' * 64 else '1' * 64
    status, _ = dataflow.consumer.evaluate(capture['items'][0], capture)
    assert status == 'UNKNOWN', 'Closing native reference receipt no longer identifies the opening request'


@pytest.mark.parametrize('hit', [False, True], ids=['clean_before_link', 'trusted_hit_before_link'])
def test_dataflow_tar_hardlink_is_incomplete_without_losing_trusted_prior_hit(monkeypatch, hit):
    """Regular file then disallowed hardlink: no extraction and fail-only prefix."""
    output = io.BytesIO()
    raw = ('token=' + dataflow.TOKEN).encode() if hit else b'echo ready\n'
    with tarfile.open(fileobj=output, mode='w', format=tarfile.USTAR_FORMAT) as archive:
        info = tarfile.TarInfo('first.py'); info.size = len(raw)
        archive.addfile(info, io.BytesIO(raw))
        link = tarfile.TarInfo('linked.py'); link.type = tarfile.LNKTYPE; link.linkname = 'first.py'
        archive.addfile(link)
    capture, rows, _, _ = dataflow.capture(monkeypatch, output.getvalue(), targets=[dataflow.target('tar')])
    assert rows[0][0] == ('FAIL' if hit else 'UNKNOWN') and rows[0][1]['complete'] is False
    assert capture['items'][0]['native_complete'] is True
    assert dataflow.TOKEN not in json.dumps(capture)
    if hit:
        assert len(rows[0][1]['secret_leaks']) == 1
        assert {d['engine'] for d in rows[0][1]['secret_leaks'][0]['detectors']} == {'kingfisher', 'trufflehog'}


def test_dataflow_concatenated_gzip_members_are_not_a_clean_package(monkeypatch):
    """A valid first tar must not hide a second gzip member from completeness."""
    first = dataflow.archive_payload('tar', [('first.py', b'echo ready\n')])
    second = dataflow.archive_payload('tar', [('second.py', ('token=' + dataflow.TOKEN).encode())])
    payload = gzip.compress(first, mtime=0) + gzip.compress(second, mtime=0)
    capture, rows, _, _ = dataflow.capture(monkeypatch, payload, targets=[dataflow.target('tar.gz')])
    assert capture['items'][0]['native_complete'] is True
    assert rows[0][0] == 'UNKNOWN' and rows[0][1]['complete'] is False
    assert dataflow.TOKEN not in json.dumps(capture)


def test_workbench_partial_failed_engine_match_is_scrubbed_but_not_trusted(monkeypatch):
    """An engine can reveal a value before a malformed later observation fails."""
    def partial_failed(*args): return [(workbench.TOKEN, 'Synthetic', 1), (None, 'Synthetic', 1)]
    def completed_clean(*args): return []
    monkeypatch.setattr(scanning, '_scan_kingfisher', partial_failed)
    monkeypatch.setattr(scanning, '_scan_trufflehog', completed_clean)
    def repeat(snapshot, collector):
        snapshot['metadata']['synthetic'] = workbench.TOKEN
        collector.transport.cache['synthetic'] = workbench.TOKEN
        collector.transport.evidence.append({'synthetic': workbench.TOKEN})
    snapshot, rows, trace = workbench.capture(monkeypatch, real=True,
        payload=('token=' + workbench.TOKEN).encode(), mutate_snapshot=repeat)
    assert rows[0][0] == 'UNKNOWN'
    marker = snapshot['collections'][0]['items'][0][workbench.source.MARKER]
    assert marker['leaks'] == []
    # Found values stay visible (73706ae8): seeded copies are not scrubbed.
    assert workbench.TOKEN in json.dumps([snapshot, trace.collector.transport.cache, trace.collector.transport.evidence])
    assert not hasattr(trace.collector.transport, '_workbench_source_state')


def test_workbench_sealing_exception_still_clears_match_state(monkeypatch):
    """The final snapshot boundary must release transient secrets on failure."""
    import peaso.snapshot
    saved = {}
    def repeat(snapshot, collector):
        saved['collector'] = collector
        collector.transport.cache['synthetic'] = workbench.TOKEN
    def failed_seal(*args): raise RuntimeError('synthetic seal failure')
    monkeypatch.setattr(peaso.snapshot, 'seal', failed_seal)
    with pytest.raises(RuntimeError, match='synthetic seal failure'):
        workbench.capture(monkeypatch, real=True, payload=('token=' + workbench.TOKEN).encode(), mutate_snapshot=repeat)
    collector = saved['collector']
    assert not hasattr(collector.transport, '_workbench_source_state')
    # Found values stay visible (73706ae8); only transient match state is released.
    assert workbench.TOKEN in json.dumps(collector.transport.cache)
    assert workbench.TOKEN not in json.dumps([collector.transport.evidence, collector.options])


def test_dataflow_unselected_graph_url_changes_do_not_expand_source_scope(monkeypatch):
    """Full native metadata may contain graph locations; only chosen package IO."""
    def irrelevant_graph(op, data, response):
        if op.startswith('reference_'):
            data['stepsLocation'] = 'https://never-follow.invalid/' + op
            raw = json.dumps(data).encode(); response.stream = io.BytesIO(raw)
            response.headers['Content-Length'] = str(len(raw))
    capture, rows, calls, _ = dataflow.capture(monkeypatch, fault=irrelevant_graph)
    assert rows[0][0] == 'PASS' and len(calls) == 9
    assert all('never-follow.invalid' not in call[2] for call in calls)
    assert rows[0][1]['executed_bytes_proven'] is False
    assert 'never-follow.invalid' not in json.dumps(capture)
