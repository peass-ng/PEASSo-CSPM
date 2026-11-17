"""An incomplete package-content scan names why a secret engine was unavailable."""
from types import SimpleNamespace

import pytest

from peaso import secret_scanning
from peaso.collectors import aws_package_content_indicators as p

REQUESTS = SimpleNamespace(check_deadline=lambda: None)


@pytest.fixture(autouse=True)
def clean_results():
    secret_scanning._RESULTS.clear()
    yield
    secret_scanning._RESULTS.clear()


def test_unavailable_engine_reason_reaches_the_incomplete_causes(monkeypatch):
    def rejected(*args):
        raise ValueError('invalid offline detector result')
    monkeypatch.setattr(secret_scanning, '_scan_kingfisher', lambda *args: [])
    monkeypatch.setattr(secret_scanning, '_scan_trufflehog', rejected)
    with pytest.raises(p.PartialArchive) as partial:
        p._scan(b'ready=true', 'config.py', REQUESTS)
    assert partial.value.causes == ('trufflehog_valueerror_invalid_offline_detector_result',)
    reason = p.incomplete_reason('image_content_incomplete', {'engine_incomplete', *partial.value.causes})
    assert reason.endswith('engine_incomplete, trufflehog_valueerror_invalid_offline_detector_result')


def test_engine_messages_outside_the_fixed_vocabulary_are_not_reported(monkeypatch):
    def leaky(*args):
        raise RuntimeError('Synthetic9342 value at /tmp/x')
    monkeypatch.setattr(secret_scanning, '_scan_kingfisher', leaky)
    monkeypatch.setattr(secret_scanning, '_scan_trufflehog', lambda *args: [])
    with pytest.raises(p.PartialArchive) as partial:
        p._scan(b'ready=true', 'config.py', REQUESTS)
    assert partial.value.causes == ('kingfisher_runtimeerror',)


def test_complete_scans_report_no_engine_reason(monkeypatch):
    monkeypatch.setattr(secret_scanning, '_scan_kingfisher', lambda *args: [])
    monkeypatch.setattr(secret_scanning, '_scan_trufflehog', lambda *args: [])
    assert p._scan(b'ready=true', 'config.py', REQUESTS) == []
    assert secret_scanning.UNAVAILABLE_REASONS.get() == ()
