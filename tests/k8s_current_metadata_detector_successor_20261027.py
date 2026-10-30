"""Give the sealed K8s detector-outage case a fresh clean-byte memo."""
from __future__ import annotations

import hashlib
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
TEST = ROOT / 'tests/test_k8s_selected_metadata_production_20261020.py'
SEALED_SHA256 = '16904f90c856d65dd452006c792dfc0f6ba60d4f7dffea95d10a5aa9fbfb3b8f'


@pytest.fixture(autouse=True)
def _fresh_metadata_detector_outage(request):
    if (Path(getattr(request.module, '__file__', '')).name != TEST.name
            or request.function.__name__ != 'test_actual_unavailable_engine_cannot_clean_and_trusted_peer_hit_survives'
            or request.node.callspec.params != {'engine': 'trufflehog', 'positive': False}):
        yield
        return

    assert Path(request.module.__file__).resolve() == TEST
    assert hashlib.sha256(TEST.read_bytes()).hexdigest() == SEALED_SHA256

    # The dated fixture clears combined results but leaves the separate
    # completed clean-byte proof. This case must exercise the unavailable
    # detector rather than replay a prior clean scan of identical bytes.
    from peaso import secret_scan_clean
    secret_scan_clean._CLEAN.clear()
    monkeypatch = request.getfixturevalue('monkeypatch')
    module = request.module
    original = module.capture

    def capture_current(patch, **kwargs):
        result, trace, item, index = original(patch, **kwargs)
        status, evidence = result
        assert status == 'UNKNOWN'
        marker = item[module.source.MARKER]
        assert marker['complete'] is False
        assert marker['parts'][0]['complete'] is False
        assert {row['engine']: row['status'] for row in marker['parts'][0]['engines']}['trufflehog'] == 'unavailable'
        assert evidence['observed'].startswith('Selected object metadata was unavailable')
        assert {row['status'] for row in trace.findings} == {'UNKNOWN'}
        return result, trace, item, index

    monkeypatch.setattr(module, 'capture', capture_current)
    yield
    secret_scan_clean._CLEAN.clear()
