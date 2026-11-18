"""A slow first TruffleHog start no longer leaves image secret scans UNKNOWN.

On a busy collector the first start of the large TruffleHog binary took longer
than its version check allowed. That check failed the same way on the longer
retry, and the image config is the first thing scanned, so whole images ended
UNKNOWN with ``trufflehog_timeouterror_scanner_deadline`` and no layer read.
"""
import shutil
import sys
import threading

import pytest

from peaso import secret_scanning as scanning
from peaso.collectors import aws_package_content_indicators as p
from tests.test_aws_package_content_review_20261019 import (
    FUNCTIONS, REGION, SECRET, index, sdk, isolated_detector_dependencies)  # noqa: F401 (autouse: offline detectors)

# The autouse fixture replaces the engine; these cases run the real one.
SCAN_TRUFFLEHOG = scanning._scan_trufflehog


@pytest.fixture
def slow_start_trufflehog(tmp_path, monkeypatch):
    """A synthetic TruffleHog whose version check takes ``start`` seconds."""
    log = tmp_path / 'calls.log'
    binary = tmp_path / 'trufflehog'
    def make(start):
        binary.write_text(
            '#!' + sys.executable + '\n'
            'import sys, time\n'
            'open(' + repr(str(log)) + ', "a").write(sys.argv[1] + "\\n")\n'
            'if sys.argv[1] == "--version":\n'
            '    time.sleep(' + repr(start) + ')\n'
            '    print("trufflehog ' + scanning.TRUFFLEHOG_VERSION + '")\n'
            'else:\n'
            '    sys.stdin.buffer.read()\n')
        binary.chmod(0o755)
        return log
    real_which = shutil.which
    monkeypatch.setattr(shutil, 'which',
                        lambda name, *a, **kw: str(binary) if name == 'trufflehog' else real_which(name, *a, **kw))
    monkeypatch.setattr(scanning, '_scan_trufflehog', SCAN_TRUFFLEHOG)
    scanning._trufflehog.cache_clear()
    yield make
    scanning._trufflehog.cache_clear()


def test_an_image_scanned_by_a_binary_slow_to_start_completes(slow_start_trufflehog, monkeypatch):
    slow_start_trufflehog(5.5)
    requests, session, item, *_ = sdk(monkeypatch, 'ecr_repository', False)
    result = p.ENRICHERS['ecr_repository'](requests, session, REGION, [item])[0]
    indicators = result['PackageContentSource']['PackageSecretIndicators']
    status, _ = FUNCTIONS['ecr_repository'](result, index('ecr_repository', result))
    assert indicators['NativeResponseComplete'] is True, indicators.get('Reason')
    assert status == 'PASS'


def test_concurrent_first_scans_start_the_binary_for_its_version_once(slow_start_trufflehog):
    log = slow_start_trufflehog(0.3)
    errors = []
    def scan():
        try:
            assert scanning._scan_trufflehog(b'synthetic item', 'item', 15) == []
        except Exception as exc:  # pragma: no cover - reported below
            errors.append(exc)
    threads = [threading.Thread(target=scan) for _ in range(4)]
    for thread in threads: thread.start()
    for thread in threads: thread.join()
    assert errors == []
    calls = log.read_text().split()
    assert calls.count('--version') == 1 and calls.count('stdin') == 4


def test_an_image_whose_config_scan_fails_still_scans_and_reports_its_layers(monkeypatch):
    def config_times_out(payload, path, timeout):
        if path == 'image-config':
            raise TimeoutError('scanner deadline')
        return [(SECRET, 'synthetic', 1)] if SECRET.encode() in payload else []
    monkeypatch.setattr(scanning, '_scan_trufflehog', config_times_out)
    requests, session, item, *_ = sdk(monkeypatch, 'ecr_repository', True)
    result = p.ENRICHERS['ecr_repository'](requests, session, REGION, [item])[0]
    indicators = result['PackageContentSource']['PackageSecretIndicators']
    status, _ = FUNCTIONS['ecr_repository'](result, index('ecr_repository', result))
    # The layer secret is found although the config stayed unscanned.
    assert [ref['File'] for ref in indicators['References']] == ['config.py']
    assert status == 'FAIL'
    assert indicators['NativeResponseComplete'] is False
    assert 'trufflehog_timeouterror_scanner_deadline' in indicators['Reason']
    assert [row['File'] for row in indicators['UncoveredFiles']] == ['image-config']
