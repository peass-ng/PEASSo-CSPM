"""Image content scans finish on a busy collector instead of missing deadlines.

A two-vCPU collector scanning many images at once started a TruffleHog process
for every window and config at the same moment. Each wall-clock deadline (and
its longer retry) then measured the CPU queue, so small images were reported
UNKNOWN with ``trufflehog_timeouterror_scanner_deadline``.
"""
import subprocess
import sys
import threading
import time

import pytest

from peaso import secret_scanning
from peaso.collectors import aws_package_content_indicators as p
from tests.test_aws_package_content_review_20261019 import (
    FUNCTIONS, REGION, index, sdk, isolated_detector_dependencies)  # noqa: F401 (autouse: offline detectors)

QUICK = [sys.executable, '-I', '-S', '-c', 'import time; time.sleep(0.15)']


def _ecr(monkeypatch, scan_trufflehog):
    monkeypatch.setattr(secret_scanning, '_scan_trufflehog', scan_trufflehog)
    requests, session, item, *_ = sdk(monkeypatch, 'ecr_repository', False)
    result = p.ENRICHERS['ecr_repository'](requests, session, REGION, [item])[0]
    status, _ = FUNCTIONS['ecr_repository'](result, index('ecr_repository', result))
    return status, result['PackageContentSource']['PackageSecretIndicators']


def test_an_image_whose_scans_miss_the_first_deadline_completes_on_the_retry(monkeypatch):
    attempts = {}
    def slow_once(payload, path, timeout):
        attempts.setdefault(payload, []).append(timeout)
        if len(attempts[payload]) == 1:
            raise TimeoutError('scanner deadline')
        return []
    status, indicators = _ecr(monkeypatch, slow_once)
    assert indicators['NativeResponseComplete'] is True, indicators.get('Reason')
    assert status == 'PASS'
    # The image config and the layer file each got one longer attempt.
    assert len(attempts) >= 2
    assert all(len(seen) == 2 and seen[0] < seen[1] for seen in attempts.values())


def test_an_image_whose_scans_keep_timing_out_stays_unknown_with_the_reason(monkeypatch):
    def slow(payload, path, timeout):
        raise TimeoutError('scanner deadline')
    status, indicators = _ecr(monkeypatch, slow)
    assert indicators['NativeResponseComplete'] is False
    assert 'trufflehog_timeouterror_scanner_deadline' in indicators['Reason']
    assert status == 'UNKNOWN'


def test_an_expired_collection_lease_is_not_retried(monkeypatch):
    calls = []
    def expired(payload, path, timeout):
        calls.append(payload)
        raise TimeoutError('collection lease expired')
    status, indicators = _ecr(monkeypatch, expired)
    assert status == 'UNKNOWN'
    assert len(calls) == len(set(calls))


def test_concurrent_scanner_processes_never_exceed_the_slots(monkeypatch):
    monkeypatch.setattr(secret_scanning, '_SLOTS', threading.BoundedSemaphore(2))
    lock, live, peak = threading.Lock(), [0], [0]
    class Counting(subprocess.Popen):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.counted = True
            with lock:
                live[0] += 1
                peak[0] = max(peak[0], live[0])
        def wait(self, timeout=None):
            code = super().wait(timeout)
            with lock:
                if self.counted:
                    self.counted = False
                    live[0] -= 1
            return code
    monkeypatch.setattr(secret_scanning.subprocess, 'Popen', Counting)
    errors = []
    def run():
        try:
            secret_scanning._run(QUICK, b'', 10)
        except Exception as exc:  # pragma: no cover - reported below
            errors.append(exc)
    threads = [threading.Thread(target=run) for _ in range(5)]
    for thread in threads: thread.start()
    for thread in threads: thread.join()
    assert errors == []
    assert peak[0] == 2


def test_waiting_for_a_slot_does_not_consume_the_scanner_deadline(monkeypatch):
    monkeypatch.setattr(secret_scanning, '_SLOTS', threading.BoundedSemaphore(1))
    held, release = threading.Event(), threading.Event()
    def busy():
        with secret_scanning._scanner_slot():
            held.set()
            release.wait(5)
    holder = threading.Thread(target=busy)
    holder.start()
    held.wait(5)
    timer = threading.Timer(1.2, release.set)
    timer.start()
    started = time.monotonic()
    try:
        # Queued longer than its own one-second deadline, yet it completes.
        assert secret_scanning._run(QUICK, b'', 1) == b''
    finally:
        release.set(); timer.cancel(); holder.join()
    assert time.monotonic() - started >= 1.2


def test_a_queued_scan_still_ends_with_the_collection_lease(monkeypatch):
    from peaso import collection_lease
    monkeypatch.setattr(secret_scanning, '_SLOTS', threading.BoundedSemaphore(1))
    monkeypatch.setattr(collection_lease, 'effective_deadline', lambda requests: time.monotonic() + 0.3)
    with secret_scanning._scanner_slot():
        with pytest.raises(TimeoutError, match='collection lease expired'):
            secret_scanning._run(QUICK, b'', 10)
