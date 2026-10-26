"""Defer full (oldest-generation) garbage collections while one K8s scan builds its snapshot.

A scan allocates hundreds of thousands of long-lived, acyclic native objects. Every few
young collections CPython then rescans the whole heap for cycles; on a 5k-pod cluster
those full passes cost about a quarter of the collector's CPU. Young collections keep
running, so short-lived cycles (sockets, responses, tracebacks) are still reclaimed
promptly. The previous thresholds are restored when the last concurrent scan ends, and a
setting changed by someone else in the meantime is left alone.
"""
import gc
import threading
from contextlib import contextmanager

_DEFERRED = 1 << 30
_lock = threading.Lock()
_depth = 0
_saved = None


class Pause:
    """One scan's hold on deferred full collections; close() is idempotent."""

    __slots__ = ("_open",)

    def __init__(self):
        global _depth, _saved
        with _lock:
            if _depth == 0:
                current = gc.get_threshold()
                # threshold0 == 0 means automatic collection is off; nothing to defer.
                _saved = current if current[0] and current[2] < _DEFERRED else None
                if _saved is not None:
                    gc.set_threshold(current[0], current[1], _DEFERRED)
            _depth += 1
        self._open = True

    def close(self):
        global _depth, _saved
        with _lock:
            if not self._open:
                return
            self._open = False
            _depth -= 1
            if _depth == 0 and _saved is not None:
                if gc.get_threshold() == (_saved[0], _saved[1], _DEFERRED):
                    gc.set_threshold(*_saved)
                _saved = None


def pause():
    return Pause()


@contextmanager
def paused():
    hold = Pause()
    try:
        yield
    finally:
        hold.close()
