"""Isolate a fresh detector outage in the sealed Dataflow/Batch review."""
from __future__ import annotations

from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
TEST = 'tests/test_gcp_dataflow_batch_source_runtime_20261020.py'

@pytest.fixture(autouse=True)
def _fresh_detector_outage(request):
    if (Path(getattr(request.module, '__file__', '')).name != Path(TEST).name
            or request.function.__name__ != 'test_detector_unavailable_partial_hit'):
        yield
        return
    assert Path(request.module.__file__).resolve() == ROOT / TEST

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
