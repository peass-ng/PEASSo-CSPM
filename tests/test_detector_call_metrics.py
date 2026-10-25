import importlib.util,time,threading
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
import pytest
spec=importlib.util.spec_from_file_location('candidate_detector_metrics',Path(__file__).resolve().parents[1]/'peaso/detector_call_metrics.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

@contextmanager
def broken(label):
    raise RuntimeError('diagnostic failed')
    yield

def test_diagnostic_failure_preserves_results_errors_and_lock():
    lock=threading.Lock();proxy=m.TimedLock(lock,broken)
    assert proxy.acquire(False) is True
    assert proxy.acquire(False) is False
    assert proxy.locked() is True
    proxy.release()
    with proxy as actual:
        assert actual is True and lock.locked()
    assert not lock.locked()
    with pytest.raises(ValueError,match='business'):
        with m._span(broken,'secret.kingfisher.native'):
            raise ValueError('business')
    with pytest.raises(KeyboardInterrupt):
        with m._span(broken,'secret.kingfisher.native'):
            raise KeyboardInterrupt()

def test_contention_uses_exact_original_mutex_and_measures_wait():
    rows=[]
    @contextmanager
    def span(label):
        wall,cpu=time.perf_counter(),time.thread_time()
        try:yield
        finally:rows.append((label,time.perf_counter()-wall,time.thread_time()-cpu))
    original=threading.Lock();proxy=m.TimedLock(original,span);entered=threading.Event()
    original.acquire()
    def wait():
        entered.set()
        with proxy:pass
    t=threading.Thread(target=wait);t.start();entered.wait();time.sleep(.04);original.release();t.join(timeout=2)
    assert not t.is_alive() and not original.locked()
    assert rows[0][0]=='secret.kingfisher.lock_wait' and rows[0][1]>=.03
    assert rows[0][2]<rows[0][1]

def test_sdk_wrapper_preserves_identity_results_and_errors_and_restores_only_owner():
    rows=[]
    @contextmanager
    def span(label):
        rows.append(label);yield
    class Scanner:
        def scan_input(self,value):
            if value=='error':raise ValueError('business')
            return value
    source=SimpleNamespace(_LOCK=threading.Lock());lock=source._LOCK;method=Scanner.scan_input
    handle=m.Installation(span,source,Scanner)
    sentinel=object()
    try:
        assert Scanner().scan_input(sentinel) is sentinel
        with pytest.raises(ValueError,match='business'):Scanner().scan_input('error')
        assert rows==['secret.kingfisher.native']*2
    finally:handle.close();handle.close()
    assert source._LOCK is lock and Scanner.scan_input is method
    handle=m.Installation(span,source,Scanner)
    replacement=threading.Lock();source._LOCK=replacement
    later=lambda self,value:value;Scanner.scan_input=later
    handle.close()
    assert source._LOCK is replacement and Scanner.scan_input is later

def test_install_close_idempotent_and_no_scanner_producer_rebinding():
    from peaso import secret_scanning as s
    from kingfisher_sdk import Scanner
    original=(s._LOCK,Scanner.scan_input,s._scan_kingfisher,s._scan_trufflehog,s.scan_content)
    handle=m.install(broken)
    try:
        assert m.install(broken) is handle
        assert (s._scan_kingfisher,s._scan_trufflehog,s.scan_content)==original[2:]
        assert s._scan_kingfisher(b'ordinary synthetic configuration','synthetic',15)==[]
    finally:handle.close();handle.close()
    assert (s._LOCK,Scanner.scan_input)==original[:2]

def test_actual_offline_positive_detector_output_is_unchanged():
    import hashlib,json
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    from peaso import secret_scanning as s
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048).private_bytes(
        serialization.Encoding.PEM,serialization.PrivateFormat.TraditionalOpenSSL,serialization.NoEncryption())
    before=s._scan_kingfisher(key,'synthetic-generated-key',15)
    assert bool(before)
    handle=m.install(broken)
    try:after=s._scan_kingfisher(key,'synthetic-generated-key',15)
    finally:handle.close()
    assert hashlib.sha256(json.dumps(before).encode()).digest()==hashlib.sha256(json.dumps(after).encode()).digest()
