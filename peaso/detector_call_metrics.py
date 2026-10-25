"""Explicit worker-owned Kingfisher timing; no payload, path or result retained."""
from contextlib import contextmanager
import functools
import threading

_active = None
_install_lock = threading.RLock()


@contextmanager
def _span(factory, label):
    cm = None
    try:
        cm = factory(label)
        cm.__enter__()
    except Exception:
        cm = None
    error = (None, None, None)
    try:
        yield
    except BaseException as exc:
        error = (type(exc), exc, exc.__traceback__)
        raise
    finally:
        if cm is not None:
            try:
                cm.__exit__(*error)
            except Exception:
                pass


class TimedLock:
    """Keep the original mutex and exact acquire/release behavior."""
    def __init__(self, original, span):
        self.original, self.span = original, span
    def acquire(self, *args, **kwargs):
        with _span(self.span, 'secret.kingfisher.lock_wait'):
            return self.original.acquire(*args, **kwargs)
    def __enter__(self):
        with _span(self.span, 'secret.kingfisher.lock_wait'):
            return self.original.__enter__()
    def __exit__(self, *args):
        return self.original.__exit__(*args)
    def release(self):
        return self.original.release()
    def locked(self):
        return self.original.locked()


class Installation:
    def __init__(self, span, scanning, scanner_class):
        self.span, self.scanning, self.scanner_class = span, scanning, scanner_class
        self.original_lock, self.original_scan = scanning._LOCK, scanner_class.scan_input
        self.lock = TimedLock(self.original_lock, span)
        owner = self
        @functools.wraps(self.original_scan)
        def scan(instance, *args, **kwargs):
            with _span(span, 'secret.kingfisher.native'):
                return owner.original_scan(instance, *args, **kwargs)
        self.scan = scan
        scanning._LOCK = self.lock
        scanner_class.scan_input = scan
    def close(self):
        global _active
        with _install_lock:
            # Never overwrite a later owner or alter the original mutex.
            if self.scanning._LOCK is self.lock:
                self.scanning._LOCK = self.original_lock
            if self.scanner_class.scan_input is self.scan:
                self.scanner_class.scan_input = self.original_scan
            if _active is self:
                _active = None


def install(span):
    """Install once in the owned collector; close after tools have settled.

    Runtime stage spans supply wall/thread CPU and periodic numeric-only IPC.
    The original source and producer function bindings remain unchanged.
    No stdlib or TruffleHog/scanner producer callable is patched.
    """
    global _active
    with _install_lock:
        if _active is not None:
            return _active
        from peaso import secret_scanning
        from kingfisher_sdk import Scanner
        _active = Installation(span, secret_scanning, Scanner)
        return _active
