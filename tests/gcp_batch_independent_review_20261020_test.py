"""Independent bounded Batch proof; sealed proposal and harness stay unchanged.

Run only this file. Real pinned scanners receive bytes through the existing
offline native HTTP harness; assertions preserve any discovered red proof.
"""
from copy import deepcopy
import base64
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest

_spec = importlib.util.spec_from_file_location('batch_independent_harness',
    Path(__file__).with_name('gcp_batch_referenced_source_20261020_test.py'))
batch = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(batch)
source, consumer = batch.source, batch.consumer
offline = batch.offline
ROOT = Path(__file__).resolve().parents[1]


def record(case, evidence, rows, trace):
    """Optional durable native capture, with no raw source or auth in output."""
    if path := os.environ.get('BATCH_INDEPENDENT_PROOF_JSONL'):
        row = dict(case=case, evidence=evidence, actual=[r[0] for r in rows],
            complete=[r[1]['complete'] for r in rows], operations=[c[0] for c in trace.calls],
            all_responses_closed=all(r.closed for r in trace.responses),
            auth_calls=len(trace.auth), scanner_matches_cleared=not hasattr(trace.transport, '_batch_source_redactions'))
        with open(path, 'a') as handle:
            handle.write(json.dumps(row, sort_keys=True) + '\n')


def capture(monkeypatch, case, **kwargs):
    saved, rows, trace = batch.capture(monkeypatch, **kwargs)
    record(case, saved['evidence'], rows, trace)
    assert all(r.closed for r in trace.responses)
    return saved, rows, trace


def test_supported_native_offsets_and_opaque_incarnation(monkeypatch):
    job = json.loads(batch.NATIVE.read_text())
    job['uid'] = 'opaque-native-incarnation:NOT-A-UUID'
    spec = job['taskGroups'][0]['taskSpec']
    spec['runnables'].insert(0, {'script': {'text': 'unselected inline source'}})
    spec['volumes'].insert(0, {'deviceName': 'disk0', 'mountPath': '/mnt/disjoint'})
    spec['volumes'][1]['gcs']['remotePath'] = 'review-source'
    spec['runnables'][1]['script']['path'] = '/mnt/source/code/scripts/main.sh'
    saved, rows, trace = capture(monkeypatch, 'native_offsets_opaque_uid_bucket_root', job=job,
        targets=[{**batch.target(), 'volume': 1, 'runnable': 1}])
    assert batch.statuses(rows) == {'PASS'} and len(trace.calls) == 9
    marker = saved['evidence']['items'][0][source.MARKER]
    assert marker['executed_bytes_proven'] is False
    assert marker['parts'][0]['engines'] == [
        dict(engine='kingfisher', version='1.4.0', status='complete'),
        dict(engine='trufflehog', version='3.92.5', status='complete')]


@pytest.mark.parametrize('case', ['prefix_collision', 'duplicate_identical', 'ancestor', 'disjoint_prefix'])
def test_mount_boundary_matrix(monkeypatch, case):
    job = json.loads(batch.NATIVE.read_text()); spec = job['taskGroups'][0]['taskSpec']
    if case == 'prefix_collision':
        spec['runnables'][0]['script']['path'] = '/mnt/source-other/scripts/main.sh'
    elif case == 'duplicate_identical':
        spec['volumes'].append(deepcopy(spec['volumes'][0]))
    else:
        spec['volumes'].append({'deviceName': 'disk0',
            'mountPath': '/mnt' if case == 'ancestor' else '/mnt/source-other'})
    saved, rows, trace = capture(monkeypatch, case, job=job)
    expected = 'PASS' if case == 'disjoint_prefix' else 'UNKNOWN'
    assert batch.statuses(rows) == {expected}
    assert [c[0] for c in trace.calls] == (['project', 'reference'] if expected == 'UNKNOWN'
        else ['project', 'reference', 'bucket', 'latest', 'content', 'latest', 'reference', 'bucket', 'project'])


@pytest.mark.parametrize('case', ['uid_after', 'generation_before', 'generation_after',
                                'bucket_owner_before', 'bucket_owner_after'])
def test_native_identity_and_current_generation_brackets(monkeypatch, case):
    def fault(op, n, data, response, transport):
        if n != (1 if case.endswith('_before') else 2):
            return
        if case == 'uid_after' and op == 'reference': data['uid'] = 'another-incarnation'
        elif case.startswith('generation_') and op == 'latest': data['generation'] = '12346'
        elif case.startswith('bucket_owner_') and op == 'bucket': data['projectNumber'] = '10002'
        else: return
        raw = json.dumps(data).encode(); response.stream = io.BytesIO(raw)
        response.headers['Content-Length'] = str(len(raw))
    saved, rows, trace = capture(monkeypatch, case, fault=fault)
    assert batch.statuses(rows) == {'UNKNOWN'}
    assert saved['evidence']['items'][0][source.MARKER]['native_complete'] is False
    assert sum(c[0] == 'content' for c in trace.calls) == (0 if case.endswith('_before') else 1)


@pytest.mark.parametrize('hit', [False, True], ids=['clean', 'trusted_hit'])
@pytest.mark.parametrize('shape', ['bad_engine_version', 'null_marker'])
def test_malformed_selected_sibling_cannot_erase_trusted_own_hit(monkeypatch, hit, shape):
    targets = [batch.target(), {**batch.target(), 'resource': batch.target()['resource'] + '-second'}]
    saved, initial, trace = batch.capture(monkeypatch, targets=targets,
        payload=('token=' + batch.TOKEN).encode() if hit else b'echo ready\n')
    assert batch.statuses(initial) == {'FAIL' if hit else 'PASS'} and len(trace.calls) == 18
    evidence = saved['evidence']; first, sibling = evidence['items']
    if shape == 'bad_engine_version':
        sibling[source.MARKER]['parts'][0]['engines'][0]['version'] = '0.0.0'
    else:
        sibling[source.MARKER] = None
    rows = [consumer.evaluate(item, evidence, batch.SCOPE) for item in evidence['items']]
    record(shape + ('_hit' if hit else '_clean'), evidence, rows, trace)
    assert rows[1][0] == 'UNKNOWN'
    assert rows[0][0] == ('FAIL' if hit else 'UNKNOWN') and rows[0][1]['complete'] is False, (
        'Malformed sibling must prevent complete clean PASS while preserving a trustworthy own hit', rows[0])


@pytest.mark.parametrize('case', ['missing_named', 'missing_flag', 'missing_selector', 'invalid_selector'])
def test_prerequisites_precede_private_auth_and_http(monkeypatch, case):
    def forbidden(*args, **kwargs): pytest.fail('Private auth or HTTP before prerequisites')
    monkeypatch.setattr(source.reads.git, '_session', forbidden)
    options = {source.OPTION: [batch.target()], 'content_secret_scans': True}
    named = [source.CHECK]
    if case == 'missing_named': named = []
    elif case == 'missing_flag': options.pop('content_secret_scans')
    elif case == 'missing_selector': options.pop(source.OPTION)
    else: options[source.OPTION][0]['volume'] = True
    transport = batch.gcp.Transport(SimpleNamespace(headers=forbidden), options)
    if case in ('missing_selector', 'invalid_selector'):
        with pytest.raises(source.Incomplete): source.collect(transport, options, [batch.SCOPE], named=named)
    else:
        evidence = source.collect(transport, options, [batch.SCOPE], named=named)
        assert evidence['authorized'] is False and evidence['items'] == []
    assert transport.calls == 0


def test_actual_scanners_never_execute_script_and_raw_values_stay_private(monkeypatch, tmp_path, capsys):
    sentinel = tmp_path / 'script-executed'
    payload = ('#!/bin/sh\ntouch ' + str(sentinel) + '\n# token=' + batch.TOKEN + '\n').encode()
    original = subprocess.Popen; commands = []
    def guarded(argv, *args, **kwargs):
        commands.append(argv)
        assert isinstance(argv, list) and Path(argv[0]).name == 'trufflehog'
        assert argv[1] in ('--version', 'stdin') and not kwargs.get('shell')
        if argv[1] == 'stdin':
            assert '--no-verification' in argv and '--no-update' in argv
        return original(argv, *args, **kwargs)
    monkeypatch.setattr(subprocess, 'Popen', guarded)
    encoded = base64.b64encode(batch.TOKEN.encode()).decode()
    saved, rows, trace = capture(monkeypatch, 'script_not_executed_raw_privacy', payload=payload,
        export_metadata={'raw': batch.TOKEN, 'encoded': encoded})
    assert batch.statuses(rows) == {'FAIL'} and not sentinel.exists() and commands
    raw = json.dumps([saved, rows, trace.transport.cache, trace.transport.evidence, trace.transport.options])
    assert batch.TOKEN in raw  # found values stay visible
    for private in (batch.AUTH, '/mnt/source', 'review-source', 'batch-opaque-native-uid'):
        assert private not in raw
    assert not hasattr(trace.transport, '_batch_source_redactions')
    output = capsys.readouterr(); assert not output.out and not output.err
