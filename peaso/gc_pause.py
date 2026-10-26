"""Pause the cyclic garbage collector around bulk acyclic data work.

Snapshot copies, freezes, JSON decoding and redaction each allocate millions
of JSON-like containers next to an already large live heap. Those containers
never form reference cycles, so the cyclic collector cannot reclaim any of
them, yet every few hundred thousand allocations it rescans the whole heap.
At real scan scale (hundreds of MB of native JSON) those full rescans cost
more than the copy itself. Reference counting still frees everything at once;
only cycle detection is deferred until the outermost pause ends.

Nested and concurrent pauses are counted, so a thread leaving its pause never
re-enables collection while another thread's pause is still active, and a
collector that was disabled before the first pause stays disabled.
"""
import gc
import threading

_lock = threading.Lock()
_depth = 0
_restore = False


class _Pause:
    """Shared reentrant pause; a plain class avoids a generator per use.

    Called millions of times on small values (digests, freezes), the
    generator-based context manager cost more than the work it wrapped.
    """
    __slots__ = ()

    def __enter__(self):
        global _depth, _restore
        with _lock:
            if _depth == 0:
                _restore = gc.isenabled()
                gc.disable()
            _depth += 1
        return None

    def __exit__(self, kind, value, traceback):
        global _depth
        with _lock:
            _depth -= 1
            if _depth == 0 and _restore:
                gc.enable()
        return False


_PAUSE = _Pause()


def gc_paused():
    return _PAUSE
