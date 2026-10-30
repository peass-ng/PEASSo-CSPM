"""Bounded offline TruffleHog preparation; all tokens here are synthetic."""
import json
import os
import shutil
import stat
import sys

import pytest

from peaso import secret_scanning as scanning
from peaso import secret_scanning_batch as batch


TOKEN_A = 'ghp_' + '7mQ2zR9wL4cV8nK1sF6aH3jP5uD0xB2yE9rT'
TOKEN_B = 'ghp_' + '2Yt9Ec5Zp0Ru6Wq1Aa8Kd3Vx7Mn4Bs5Hj9Lf'


@pytest.fixture(autouse=True)
def clear_redacted_cache():
    scanning._RESULTS.clear()
    yield
    scanning._RESULTS.clear()


def _row(value, *, full='', file=None):
    row = {'Raw': value, 'RawV2': full, 'DetectorName': 'AWS' if full else 'Github',
           'Verified': False}
    if file is not None:
        row['SourceMetadata'] = {'Data': {'Filesystem': {'file': file}}}
    return row


def test_context_keeps_original_source_and_decoded_pair(monkeypatch):
    from peaso import secret_evidence

    payload = b'encoded-only representation'
    path = 'original/source/part'
    pair = TOKEN_A + ':' + 'A' * 40
    calls = []
    monkeypatch.setattr(batch, '_prepare_trufflehog_batch',
                        lambda items, timeout: {(payload, path): json.dumps(_row(TOKEN_A, full=pair)).encode(),
                                                (b'other', 'other/path'): b''})
    monkeypatch.setattr(scanning, '_scan_kingfisher',
                        lambda *args: (_ for _ in ()).throw(RuntimeError('unavailable')))
    monkeypatch.setattr(secret_evidence, 'remember_full_match',
                        lambda *args, **kwargs: calls.append((args, kwargs)))
    monkeypatch.setattr(scanning, '_run',
                        lambda *args: pytest.fail('prepared result must not launch serial scanner'))

    with scanning.prepared_content_batch([(payload, path), (b'other', 'other/path')]):
        outcome = scanning.scan_content(payload, path)
        assert scanning._scan_trufflehog(b'other', 'other/path', 1) == []

    assert not outcome['complete'] and len(outcome['leaks']) == 1
    assert outcome['engines'][0]['status'] == 'unavailable'
    assert outcome['engines'][1]['status'] == 'complete'
    assert outcome['leaks'][0]['locations'] == [{'path': path}]
    assert calls == [((TOKEN_A, pair), {'payload': payload, 'path': path,
                                       'engine': 'trufflehog', 'rule': 'AWS'})]
    assert TOKEN_A not in json.dumps(outcome)


def test_failed_batch_and_expired_context_use_serial_scanner(monkeypatch):
    calls = []
    monkeypatch.setattr(batch, '_prepare_trufflehog_batch',
                        lambda *args: (_ for _ in ()).throw(TimeoutError('batch failed')))
    monkeypatch.setattr(scanning, '_trufflehog', lambda: '/synthetic/trufflehog')
    monkeypatch.setattr(scanning, '_run', lambda argv, payload, timeout:
                        calls.append((argv, payload, timeout)) or
                        json.dumps(_row(TOKEN_A)).encode())
    payload = TOKEN_A.encode()
    with scanning.prepared_content_batch([(payload, 'first'), (b'other', 'second')]):
        assert scanning._scan_trufflehog(payload, 'first', 2)[0][0] == TOKEN_A
    assert scanning._scan_trufflehog(payload, 'first', 2)[0][0] == TOKEN_A
    assert len(calls) == 2 and all('stdin' in argv for argv, _, _ in calls)


def test_serial_error_after_failed_batch_retains_other_engine_positive(monkeypatch):
    monkeypatch.setattr(batch, '_prepare_trufflehog_batch',
                        lambda *args: (_ for _ in ()).throw(ValueError('batch failed')))
    monkeypatch.setattr(scanning, '_scan_kingfisher',
                        lambda *args: [(TOKEN_A, 'synthetic', 1)])
    monkeypatch.setattr(scanning, '_trufflehog', lambda: '/synthetic/trufflehog')
    monkeypatch.setattr(scanning, '_run',
                        lambda *args: (_ for _ in ()).throw(RuntimeError('serial unavailable')))
    with scanning.prepared_content_batch([(TOKEN_A.encode(), 'first'), (b'other', 'second')]):
        outcome = scanning.scan_content(TOKEN_A.encode(), 'first')
    assert not outcome['complete'] and len(outcome['leaks']) == 1
    assert {row['engine']: row['status'] for row in outcome['engines']} == {
        'kingfisher': 'complete', 'trufflehog': 'unavailable'}


def test_context_rejects_unbounded_input_before_preparation(monkeypatch):
    monkeypatch.setattr(batch, '_prepare_trufflehog_batch',
                        lambda *args: pytest.fail('invalid batch reached preparation'))
    with pytest.raises(ValueError, match='content batch bound'):
        with scanning.prepared_content_batch([(b'x', 'p')] * (batch.MAX_BATCH_ITEMS + 1)):
            pass
    assert batch.MAX_BATCH_BYTES == 64 * 1024 * 1024
    monkeypatch.setattr(batch, 'MAX_BATCH_BYTES', 5)
    with pytest.raises(ValueError, match='content batch bound'):
        with scanning.prepared_content_batch([(b'xxx', 'a'), (b'xxx', 'b')]):
            pass


def _pinned_linux():
    if sys.platform != 'linux':
        pytest.skip('Linux tmpfs required')
    if shutil.which('trufflehog') is None:
        pytest.skip('pinned TruffleHog unavailable')
    try:
        scanning._trufflehog()
    except RuntimeError:
        pytest.skip('pinned TruffleHog unavailable')
    assert batch._volatile_shm_available(1024), 'verified volatile tmpfs required by Linux gate'


def test_pinned_linux_batch_preserves_repeated_sources_and_windows(monkeypatch):
    _pinned_linux()
    original_run = scanning._run
    calls = []
    modes = []

    def observed_run(argv, payload, timeout):
        calls.append((argv, payload, timeout))
        if argv[1] == 'filesystem':
            modes.append(stat.S_IMODE(os.stat(os.path.dirname(argv[-1])).st_mode))
            modes.extend(stat.S_IMODE(os.stat(path).st_mode) for path in argv[-len(items):])
        return original_run(argv, payload, timeout)

    monkeypatch.setattr(scanning, '_run', observed_run)
    first = (f'token={TOKEN_A}\nrepeat={TOKEN_A}\n').encode()
    second = (f'token={TOKEN_B}\n').encode()
    third = (f'token={TOKEN_A}\n').encode()
    fourth = (f'window=next\ntoken={TOKEN_B}\n').encode()
    items = [(first, 'original/first.py'), (second, 'original/second.py'),
             (third, 'original/third.py'), (fourth, 'original/first.py')]
    with scanning.prepared_content_batch(items, timeout=15):
        batch_argv, batch_payload, batch_timeout = calls[0]
        assert batch_argv[1] == 'filesystem' and batch_payload == b'' and batch_timeout == 15
        assert {'--json', '--no-verification', '--no-update', '--no-verification-cache',
                '--force-skip-archives', '--fail-on-scan-errors'} <= set(batch_argv)
        staged = batch_argv[-len(items):]
        assert len(set(staged)) == len(items)
        assert all(path.startswith('/dev/shm/peaso-scan-') and not os.path.exists(path)
                   for path in staged)
        one = scanning._scan_trufflehog(*items[0], 15)
        two = scanning._scan_trufflehog(*items[1], 15)
        three = scanning._scan_trufflehog(*items[2], 15)
        four = scanning._scan_trufflehog(*items[3], 15)
        assert {match[2] for match in one} == {1, 2}
        assert {match[0] for match in one} == {TOKEN_A}
        assert {match[0] for match in two} == {TOKEN_B}
        assert {match[0] for match in three} == {TOKEN_A}
        assert {match[0] for match in four} == {TOKEN_B}
        assert len(calls) == 1
    assert modes == [0o700, 0o600, 0o600, 0o600, 0o600]
    assert batch._PREPARED_BATCH.get() is None


def test_unrecognized_filesystem_source_falls_back_to_serial(monkeypatch):
    if sys.platform != 'linux':
        pytest.skip('Linux tmpfs required')
    assert batch._volatile_shm_available(1024)
    calls = []

    def run(argv, payload, timeout):
        calls.append(argv)
        if argv[1] == 'filesystem':
            return json.dumps(_row(TOKEN_A, file='/foreign/source')).encode()
        return b''

    monkeypatch.setattr(scanning, '_trufflehog', lambda: '/synthetic/trufflehog')
    monkeypatch.setattr(scanning, '_run', run)
    with scanning.prepared_content_batch([(b'one', 'first'), (b'two', 'second')]):
        assert batch._PREPARED_BATCH.get() is None
        assert scanning._scan_trufflehog(b'one', 'first', 1) == []
    assert [argv[1] for argv in calls] == ['filesystem', 'stdin']
    assert all(not os.path.exists(path) for path in calls[0][-2:])


@pytest.mark.parametrize('behavior', ['deadline', 'output'])
def test_batch_process_failure_reaps_child_and_falls_back(monkeypatch, tmp_path, behavior):
    _pinned_linux()
    script = tmp_path / 'fake-scanner'
    if behavior == 'deadline':
        script.write_text(f'#!{sys.executable}\nimport time\ntime.sleep(10)\n')
    else:
        script.write_text(f'#!{sys.executable}\nimport sys,time\nsys.stdout.write("x"*2048)\nsys.stdout.flush()\ntime.sleep(10)\n')
    script.chmod(0o700)
    children = []
    paths = []
    errors = []
    popen = scanning.subprocess.Popen
    run = scanning._run

    def observed_popen(*args, **kwargs):
        process = popen(*args, **kwargs)
        children.append(process)
        paths.extend(args[0][-2:])
        return process

    def observed_run(*args):
        try:
            return run(*args)
        except Exception as exc:
            errors.append(type(exc))
            raise

    monkeypatch.setattr(scanning, '_trufflehog', lambda: str(script))
    monkeypatch.setattr(scanning.subprocess, 'Popen', observed_popen)
    monkeypatch.setattr(scanning, '_run', observed_run)
    if behavior == 'output':
        monkeypatch.setattr(scanning, 'MAX_OUTPUT', 1024)
    with scanning.prepared_content_batch([(b'one', 'one'), (b'two', 'two')],
                                         timeout=2 if behavior == 'output' else .1):
        assert batch._PREPARED_BATCH.get() is None
    assert len(children) == 1 and children[0].returncode is not None
    assert children[0].stdout.closed and children[0].stdin.closed
    assert all(not os.path.exists(path) for path in paths)
    assert len(errors) == 1 and issubclass(errors[0], ValueError if behavior == 'output' else TimeoutError)
