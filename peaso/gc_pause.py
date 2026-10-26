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
from contextlib import contextmanager
import gc
import threading

_lock = threading.Lock()
_depth = 0
_restore = False


@contextmanager
def gc_paused():
    global _depth, _restore
    with _lock:
        if _depth == 0:
            _restore = gc.isenabled()
            gc.disable()
        _depth += 1
    try:
        yield
    finally:
        with _lock:
            _depth -= 1
            if _depth == 0 and _restore:
                gc.enable()
