"""Isolate a fresh detector outage in the sealed Dataflow/Batch review."""
from __future__ import annotations

import hashlib
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
TEST = 'tests/test_gcp_dataflow_batch_source_runtime_20261020.py'
SEALED = {
    TEST: '23ae6d0d6299871e0412f4b70dd173591d555c6098918560016efeaac5b2dd16',
    'docs/gcp-review/recheck-20261020/dataflow-batch-source-runtime-admission-review-20261020.json':
        'b659b2bcfd7a63e28d9848a54dd5184c959e2ca4dc55d475e86bdbb772a75c3c',
    'docs/gcp-review/recheck-20261020/dataflow-batch-source-runtime-public-findings-20261020.json':
        '0ecb312351eade87d1720a5949b2dff6c7efd908253e5a47c518c321f45bd87f',
    'docs/gcp-review/recheck-20261020/dataflow-batch-source-runtime-native-proof-20261020.json.gz':
        '047576a09471bd8db6c608426769d6a2a4c2f3a2505e26e9c2311873d4c424a9',
}


@pytest.fixture(autouse=True)
def _fresh_detector_outage(request):
    if (Path(getattr(request.module, '__file__', '')).name != Path(TEST).name
            or request.function.__name__ != 'test_detector_unavailable_partial_hit'):
        yield
        return
    assert Path(request.module.__file__).resolve() == ROOT / TEST
    for relative, expected in SEALED.items():
        assert hashlib.sha256((ROOT / relative).read_bytes()).hexdigest() == expected

    # The dated fixture already clears the combined-result cache. Its
    # independent TruffleHog clean-byte memo survives between parameter cases,
    # and would replay a prior completed scan after the fake hides the binary.
    # Force this outage test through the detector instead of memo replay.
    from peaso import secret_scan_clean
    secret_scan_clean._CLEAN.clear()
    if request.node.callspec.params['hit'] is False:
        monkeypatch = request.getfixturevalue('monkeypatch')
        module = request.module
        original = module.capture

        def capture_current(patch, profile='dataflow', **kwargs):
            snapshot, findings, trace = original(patch, profile, **kwargs)
            absent = kwargs['absent']
            own, index = module.native_index(snapshot, profile)
            p = module.runtime.PROFILES[profile]
            native = own['items'][0][p['marker']]
            marker = native if profile == 'dataflow' else native[module.bt.source.MARKER]
            assert marker['complete'] is False
            assert marker['parts'][0]['complete'] is False
            assert {e['engine']: e['status'] for e in marker['parts'][0]['engines']}[absent] == 'unavailable'
            assert {row['status'] for row in findings} == {'UNKNOWN'}
            status, evidence = getattr(module.consumer, profile + '_source')(own['items'][0], index)
            assert status == 'UNKNOWN' and evidence['complete'] is False
            return snapshot, findings, trace

        monkeypatch.setattr(module, 'capture', capture_current)
    yield
    secret_scan_clean._CLEAN.clear()
