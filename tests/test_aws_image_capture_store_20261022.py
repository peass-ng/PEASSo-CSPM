"""Isolated file-store tests; no provider/check initializer or admission bypass.

The authority adapter is an explicit stub in this pure store unit boundary.
Real pinned-session authority and scanner integration are in the sibling suite,
which must run with the current admitted runtime epoch.
"""
from concurrent.futures import ThreadPoolExecutor
import importlib.util
from pathlib import Path
import threading
from types import SimpleNamespace

import pytest

_spec = importlib.util.spec_from_file_location(
    '_image_capture_store_unit', Path(__file__).resolve().parents[1] /
    'peaso/collectors/aws_image_capture_20261022.py')
capture = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(capture)
ACCOUNT, REGION = '123456789012', 'us-east-1'


@pytest.fixture(autouse=True)
def isolated_authority_adapter(monkeypatch):
    monkeypatch.setattr(capture, '_authority', lambda session: session)


def test_concurrent_success_has_one_owner_and_scope_ends_after_consumers():
    requests = SimpleNamespace(_lock=threading.RLock(), check_deadline=lambda: None)
    session, start = object(), threading.Barrier(8)
    loads, paths = [], []
    def load(path):
        loads.append(path)
        path.write_bytes(b'abc')
        return path
    def consume():
        start.wait(timeout=5)
        path = capture.shared_blob(requests, session, ACCOUNT, REGION,
            'repo', 'image', 'blob', 3, load, None)
        assert path.read_bytes() == b'abc'
        return path
    with capture.capture_scope(requests) as store, ThreadPoolExecutor(8) as pool:
        paths = [future.result(timeout=5) for future in [pool.submit(consume) for _ in range(8)]]
        assert len(loads) == 1 and len(set(paths)) == 1
        assert store.reserved == 3
    assert not store.root.exists() and not paths[0].exists()


def test_cancelled_waiter_does_not_remove_active_owner_payload():
    entered, finish, cancelled = threading.Event(), threading.Event(), threading.Event()
    def check():
        if threading.current_thread().name == 'waiter' and cancelled.is_set():
            raise RuntimeError('cancelled_waiter')
    requests = SimpleNamespace(_lock=threading.RLock(), check_deadline=lambda: None)
    session, outcomes = object(), []
    def load(path):
        path.write_bytes(b'abc')
        entered.set()
        assert finish.wait(5)
        return path
    def consume():
        try:
            outcomes.append(capture.shared_blob(requests, session, ACCOUNT, REGION,
                'repo', 'image', 'blob', 3, load, None, check=check))
        except RuntimeError as exc:
            outcomes.append(str(exc))
    with capture.capture_scope(requests) as store:
        owner = threading.Thread(target=consume, name='owner')
        owner.start()
        assert entered.wait(5)
        waiter = threading.Thread(target=consume, name='waiter')
        cancelled.set()
        waiter.start()
        waiter.join(timeout=5)
        assert not waiter.is_alive() and outcomes == ['cancelled_waiter']
        assert len(list(store.root.iterdir())) == 1
        finish.set()
        owner.join(timeout=5)
        assert not owner.is_alive() and outcomes[-1].read_bytes() == b'abc'
    assert not store.root.exists()


def test_failed_cleanup_is_retried_and_removes_payloads(monkeypatch):
    requests = SimpleNamespace(_lock=threading.RLock(), check_deadline=lambda: None)
    with capture.capture_scope(requests) as store:
        (store.root / 'blob-0').write_bytes(b'payload')
        def fail():
            raise OSError('synthetic cleanup error')
        monkeypatch.setattr(store.temporary, 'cleanup', fail)
    assert not hasattr(requests, '_ecr_image_capture')
    assert not store.root.exists()


def test_cleanup_error_propagates_when_payloads_remain_and_detaches_scope(monkeypatch):
    requests = SimpleNamespace(_lock=threading.RLock(), check_deadline=lambda: None)
    with pytest.raises(OSError, match='synthetic cleanup error'):
        with capture.capture_scope(requests) as store:
            cleanup = store.temporary.cleanup
            def fail():
                raise OSError('synthetic cleanup error')
            monkeypatch.setattr(store.temporary, 'cleanup', fail)
            monkeypatch.setattr(capture.shutil, 'rmtree', lambda *a, **k: None)
    assert not hasattr(requests, '_ecr_image_capture')
    monkeypatch.undo()
    cleanup()
    assert not store.root.exists()


def test_capacity_uses_actual_available_disk_with_scanner_headroom(monkeypatch):
    requests = SimpleNamespace(_lock=threading.RLock(), check_deadline=lambda: None)
    monkeypatch.setattr(capture.shutil, 'disk_usage', lambda path:
        SimpleNamespace(free=capture.FREE_RESERVE_BYTES + 20))
    with capture.capture_scope(requests) as store:
        assert store.capacity == 10
        with pytest.raises(ValueError, match='capture_bound'):
            capture.shared_blob(requests, object(), ACCOUNT, REGION, 'repo',
                'image', 'blob', 11, lambda path: pytest.fail('Must not download'), None)
        assert store.reserved == 0 and not list(store.root.iterdir())


@pytest.mark.parametrize('changed', ['account', 'region', 'repository', 'session'])
def test_exact_capture_boundary(monkeypatch, changed):
    requests = SimpleNamespace(_lock=threading.RLock(), check_deadline=lambda: None)
    session = object()
    params = dict(requests=requests, session=session, account=ACCOUNT, region=REGION,
                  repo='example', image_digest='sha256:' + 'a' * 64,
                  digest='sha256:' + 'b' * 64, size=3, fallback=None)
    loads = []
    def load(path):
        loads.append(path)
        path.write_bytes(b'abc')
        path.chmod(0o600)
        return path
    with capture.capture_scope(requests):
        first = capture.shared_blob(**params, load=load)
        assert capture.shared_blob(**params, load=load) == first
        # Another image of the same repository listing this blob reuses it.
        assert capture.shared_blob(**{**params, 'image_digest': 'sha256:' + 'c' * 64},
                                   load=load) == first
        updated = dict(params)
        key = {'account': 'account', 'region': 'region', 'repository': 'repo',
               'image': 'image_digest', 'session': 'session'}[changed]
        updated[key] = object() if key == 'session' else 'different'
        assert capture.shared_blob(**updated, load=load) != first
    assert len(loads) == 2 and all(not path.exists() for path in loads)


def test_failed_capture_wakes_waiters_without_retry_or_partial_files():
    requests = SimpleNamespace(_lock=threading.RLock(), check_deadline=lambda: None)
    entered, release = threading.Event(), threading.Event()
    loads = []
    def fail(path):
        loads.append(path)
        path.write_bytes(b'partial')
        entered.set()
        assert release.wait(5)
        raise ValueError('synthetic_transport_failure')
    def consume(session):
        with pytest.raises(ValueError):
            capture.shared_blob(requests, session, ACCOUNT, REGION, 'repo',
                                'image', 'blob', 10, fail, None)
    session = object()
    with capture.capture_scope(requests) as store:
        with ThreadPoolExecutor(2) as pool:
            first = pool.submit(consume, session)
            assert entered.wait(5)
            second = pool.submit(consume, session)
            release.set()
            first.result(timeout=5)
            second.result(timeout=5)
        consume(session)
        assert len(loads) == 1 and not list(store.root.iterdir())
    assert not store.root.exists()


def test_capture_bounds_size_conflicts_and_exception_cleanup(monkeypatch):
    requests = SimpleNamespace(_lock=threading.RLock(), check_deadline=lambda: None)
    session = object()
    monkeypatch.setattr(capture, 'MAX_CAPTURE_BYTES', 3)
    def load(path):
        path.write_bytes(b'abc')
        return path
    with pytest.raises(RuntimeError, match='consumer failed'):
        with capture.capture_scope(requests) as store:
            params = (requests, session, ACCOUNT, REGION, 'repo', 'image', 'blob')
            path = capture.shared_blob(*params, 3, load, None)
            with pytest.raises(ValueError, match='descriptor_changed'):
                capture.shared_blob(*params, 2, load, None)
            with pytest.raises(ValueError, match='capture_bound'):
                capture.shared_blob(*params[:-1], 'another', 1, load, None)
            raise RuntimeError('consumer failed')
    assert not path.exists() and not store.root.exists()
    assert not hasattr(requests, '_ecr_image_capture')
