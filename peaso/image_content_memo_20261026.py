"""Process-local, bounded memo of facts proven for immutable image content.

Entries are written only after a full local proof succeeded. Keys are built from
sha256 content digests, so an entry can be reused only after the caller has
re-verified that its current bytes hash to those same digests. Nothing here is
persisted, shared across processes or derived from connector options.
Staged scratch holds already-verified private files for one later consumer,
which re-verifies them against the same digests before any use.
"""
import atexit
from collections import OrderedDict
from contextlib import contextmanager
import shutil
import threading
import time


class BoundedMemo:
    """Thread-safe LRU with an entry cap and an optional total weight cap."""

    def __init__(self, entries, weight=None):
        self._entries, self._weight_cap = entries, weight
        self._items = OrderedDict()
        self._weight = 0
        self._lock = threading.Lock()
        self._inflight = {}

    def get(self, key):
        with self._lock:
            item = self._items.get(key)
            if item is None:
                return None
            self._items.move_to_end(key)
            return item[0]

    def put(self, key, value, weight=0):
        if self._weight_cap is not None and weight > self._weight_cap:
            return
        with self._lock:
            old = self._items.pop(key, None)
            if old is not None:
                self._weight -= old[1]
            self._items[key] = (value, weight)
            self._weight += weight
            while self._items and (len(self._items) > self._entries or (
                    self._weight_cap is not None and self._weight > self._weight_cap)):
                _, (_, dropped) = self._items.popitem(last=False)
                self._weight -= dropped

    def clear(self):
        with self._lock:
            self._items.clear()
            self._weight = 0

    @contextmanager
    def single_flight(self, key, check=lambda: None):
        """Let one thread compute a key while equal requests wait, honouring check()."""
        with self._lock:
            entry = self._inflight.get(key)
            if entry is None:
                entry = self._inflight[key] = [threading.Lock(), 0]
            entry[1] += 1
        try:
            while not entry[0].acquire(timeout=0.2):
                check()
            try:
                yield
            finally:
                entry[0].release()
        finally:
            with self._lock:
                entry[1] -= 1
                if not entry[1]:
                    self._inflight.pop(key, None)


class StagedScratch:
    """Bounded hand-off of private scratch directories between two local steps.

    A producer parks a directory under a content key; at most one consumer
    takes it, and the consumer owns its removal. Entries past the byte cap or
    age limit are removed eagerly, and anything left is removed at exit.
    """

    def __init__(self, max_bytes, max_seconds):
        self._max_bytes, self._max_seconds = max_bytes, max_seconds
        self._items = OrderedDict()
        self._lock = threading.Lock()
        atexit.register(self.clear)

    def _expire(self, now):
        doomed = []
        while self._items:
            key, (born, scratch, value, size) = next(iter(self._items.items()))
            if now - born <= self._max_seconds and sum(i[3] for i in self._items.values()) <= self._max_bytes:
                break
            self._items.popitem(last=False)
            doomed.append(scratch)
        return doomed

    def park(self, key, scratch, value, size):
        doomed = []
        with self._lock:
            old = self._items.pop(key, None)
            if old is not None:
                doomed.append(old[1])
            if size > self._max_bytes:
                doomed.append(scratch)
            else:
                self._items[key] = (time.monotonic(), scratch, value, size)
                doomed += self._expire(time.monotonic())
        for path in doomed:
            shutil.rmtree(path, ignore_errors=True)

    def take(self, key):
        """Return (scratch, value) now owned by the caller, or None."""
        with self._lock:
            doomed = self._expire(time.monotonic())
            item = self._items.pop(key, None)
        for path in doomed:
            shutil.rmtree(path, ignore_errors=True)
        return None if item is None else (item[1], item[2])

    def clear(self):
        with self._lock:
            doomed = [item[1] for item in self._items.values()]
            self._items.clear()
        for path in doomed:
            shutil.rmtree(path, ignore_errors=True)
