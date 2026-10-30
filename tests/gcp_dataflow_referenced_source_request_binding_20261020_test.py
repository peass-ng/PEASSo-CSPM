"""Actual native offline captures prove a narrow Dataflow red -> green successor."""
from copy import deepcopy
import gzip
import importlib.util
import json
from pathlib import Path
import socket
import pytest
from peaso import secret_scanning as scanning
from peaso.collectors import gcp
from peaso.checks import gcp_dataflow_referenced_source_request_binding_20261020 as successor

spec = importlib.util.spec_from_file_location('dataflow_successor_native_harness',
    Path(__file__).with_name('gcp_dataflow_referenced_source_20261020_test.py'))
harness = importlib.util.module_from_spec(spec)
spec.loader.exec_module(harness)


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def blocked(*args, **kwargs): pytest.fail('Live cloud, credentials and network are forbidden')
    for name in ('connect', 'connect_ex', 'sendto'): monkeypatch.setattr(socket.socket, name, blocked)
    for name in ('create_connection', 'getaddrinfo', 'gethostbyname', 'gethostbyname_ex'):
        monkeypatch.setattr(socket, name, blocked)
    monkeypatch.setattr(gcp, 'Credentials', blocked)
    monkeypatch.setattr(gcp.Transport, 'request', blocked)
    scanning._RESULTS.clear()
    yield
    scanning._RESULTS.clear()


@pytest.mark.parametrize('family', ['project', 'reference', 'bucket', 'latest'])
def test_each_closing_request_mismatch_red_to_green(monkeypatch, family):
    capture, baseline, calls, _ = harness.capture(monkeypatch)
    item = capture['items'][0]
    assert baseline[0][0] == 'PASS' and len(calls) == 9
    opening = next(r for r in capture['receipts'] if r['operation'] == family + '_before')
    closing = next(r for r in capture['receipts'] if r['operation'] == family + '_after')
    assert opening['request'] == closing['request']
    closing['request'] = '0' * 64 if opening['request'] != '0' * 64 else '1' * 64
    assert successor.predecessor.evaluate(item, capture)[0] == 'PASS'
    assert successor.evaluate(item, capture)[0] == 'UNKNOWN'


@pytest.mark.parametrize('family', ['project', 'reference', 'bucket', 'latest'])
def test_each_closing_operation_tamper_stays_unknown(monkeypatch, family):
    capture, baseline, _, _ = harness.capture(monkeypatch)
    assert baseline[0][0] == 'PASS'
    closing = next(r for r in capture['receipts'] if r['operation'] == family + '_after')
    closing['operation'] = family + '_before'
    assert successor.evaluate(capture['items'][0], capture)[0] == 'UNKNOWN'


@pytest.mark.parametrize('hit', [False, True])
def test_real_native_results_remain_exactly_equal_and_inputs_unchanged(monkeypatch, hit):
    capture, baseline, calls, _ = harness.capture(monkeypatch,
        ('token=' + harness.TOKEN).encode() if hit else b'echo ready\n')
    before = deepcopy(capture)
    assert baseline[0][0] == ('FAIL' if hit else 'PASS')
    assert successor.evaluate(capture['items'][0], capture) == baseline[0]
    assert capture == before and len(calls) == 9
    assert harness.TOKEN not in json.dumps(capture)


@pytest.mark.parametrize('failed', ['kingfisher', 'trufflehog'])
@pytest.mark.parametrize('hit', [False, True])
def test_actual_surviving_engine_partial_semantics_preserved(monkeypatch, failed, hit):
    def unavailable(*args): raise RuntimeError('synthetic detector unavailable')
    monkeypatch.setattr(scanning, '_scan_' + failed, unavailable)
    capture, baseline, _, _ = harness.capture(monkeypatch,
        ('token=' + harness.TOKEN).encode() if hit else b'echo ready\n')
    expected = 'FAIL' if hit else 'UNKNOWN'
    assert baseline[0][0] == expected
    assert successor.evaluate(capture['items'][0], capture) == baseline[0]
    assert baseline[0][1]['complete'] is False


@pytest.mark.parametrize('hit', [False, True])
def test_bad_other_closing_request_prevents_clean_but_keeps_trusted_hit(monkeypatch, hit):
    targets = [harness.target(), {**harness.target(), 'resource': harness.target()['resource'] + '2'}]
    capture, baseline, calls, _ = harness.capture(monkeypatch,
        ('token=' + harness.TOKEN).encode() if hit else b'echo ready\n', targets=targets)
    assert {r[0] for r in baseline} == {'FAIL' if hit else 'PASS'} and len(calls) == 18
    second_id = capture['items'][1]['identity']
    closing = next(r for r in capture['receipts'] if r['identity'] == second_id and r['operation'] == 'reference_after')
    closing['request'] = '0' * 64 if closing['request'] != '0' * 64 else '1' * 64
    assert successor.evaluate(capture['items'][1], capture)[0] == 'UNKNOWN'
    status, evidence = successor.evaluate(capture['items'][0], capture)
    assert status == ('FAIL' if hit else 'UNKNOWN') and evidence['complete'] is False


def test_trusted_partial_archive_hit_unchanged(monkeypatch):
    payload = harness.archive_payload('tar', [('first.py', ('token=' + harness.TOKEN).encode()), ('second.bin', b'\x00binary')])
    capture, baseline, _, _ = harness.capture(monkeypatch, payload, targets=[harness.target('tar')])
    assert baseline[0][0] == 'FAIL' and baseline[0][1]['complete'] is False
    assert successor.evaluate(capture['items'][0], capture) == baseline[0]


def test_evaluation_has_no_filesystem_access(monkeypatch):
    capture, baseline, _, _ = harness.capture(monkeypatch)
    def forbidden(*args, **kwargs): pytest.fail('Pure evaluation must not read files')
    monkeypatch.setattr(Path, 'read_bytes', forbidden)
    monkeypatch.setattr(Path, 'read_text', forbidden)
    assert successor.evaluate(capture['items'][0], capture) == baseline[0]


def test_source_successor_attestation_and_packaged_original_bytes():
    from tests.gcp_referenced_source_historical_compatibility_20261020 import reviewed_epoch
    root = Path(__file__).resolve().parents[1]
    # Sealed files are read through the reviewed source epoch: a later reviewed
    # edit (b7134a7d) must rebuild the signed bytes exactly.
    with reviewed_epoch(json.loads(Path(successor.__file__).with_suffix('.json').read_bytes())['files']):
        receipt = successor.validate_successor()
        baseline = json.loads(gzip.decompress((root / receipt['predecessor']).read_bytes()))
        sealed = {name: (root / name).read_bytes() for name in baseline['sources']}
    assert receipt['registration'] == 'unregistered_consumer_successor_only'
    assert baseline['red_receipt']['failed'] == 3 and baseline['red_receipt']['passed'] == 6
    for name, entry in baseline['sources'].items():
        assert sealed[name] == entry['content'].encode('utf-8')


@pytest.mark.parametrize('tamper', ['successor_source', 'packaged_original'])
def test_attestation_rejects_source_and_packaged_predecessor_drift(monkeypatch, tamper):
    if tamper == 'successor_source':
        original = Path.read_bytes
        own = Path(successor.__file__).resolve()
        monkeypatch.setattr(Path, 'read_bytes', lambda p: b'changed source' if p.resolve() == own else original(p))
    else:
        original = gzip.decompress
        def changed(raw):
            baseline = json.loads(original(raw))
            name = 'peaso/checks/gcp_dataflow_referenced_source_20261020.py'
            baseline['sources'][name]['content'] += '# drift\n'
            return json.dumps(baseline).encode()
        monkeypatch.setattr(gzip, 'decompress', changed)
    with pytest.raises(ValueError): successor.validate_successor()
