"""Per-scan response caches for provider read transports.

One cache belongs to one transport object, and a transport serves exactly one
scan with one credential. The cache therefore never crosses scans, tenants or
identities, and it is dropped with its transport when the scan ends.

``BoundedEntries`` keeps the GCP transport's existing single-flight entries
(``{"event", "data"|"error", "id"}``) while bounding the bytes held by settled
entries. ``RawResponseCache`` is a single-flight cache of complete raw response
bodies, used by the Azure transport. Both evict least-recently-used settled
entries once the per-scan byte budget is exceeded, never keep one oversized
body, and are reset in a forked child, where the owner threads of in-flight
entries do not exist.

Only successful reads and deterministic provider answers are kept. Throttling,
5xx, transport failures, cancellation and budget stops are transient: callers
already waiting on that flight share its outcome, later callers read again.
"""

import os
import threading
import weakref
from collections import OrderedDict

# Budgets are approximate retained bytes per scan. Parsed JSON entries are
# charged PARSED_OBJECT_FACTOR times their wire size; raw bodies at face value.
DEFAULT_MAX_BYTES = 512 * 1024 * 1024
DEFAULT_MAX_ENTRY_BYTES = 64 * 1024 * 1024
RAW_MAX_BYTES = 128 * 1024 * 1024
RAW_MAX_ENTRY_BYTES = 16 * 1024 * 1024
PARSED_OBJECT_FACTOR = 4
ERROR_ENTRY_BYTES = 512

# ReadError codes that describe this attempt, not the resource.
GCP_TRANSIENT_CODES = frozenset((
    "network_error", "read_failed", "call_limit", "cancelled", "execution_deadline",
    "retry_after_exceeds_budget", "retry_wait_exceeds_deadline",
))
GCP_THROTTLE_REASONS = frozenset(("RATE_LIMIT_EXCEEDED", "RESOURCE_EXHAUSTED", "QUOTA_EXCEEDED"))
TRANSIENT_HTTP = frozenset((408, 429))


def budget(options, name, default):
    """A positive integer byte budget from scan options, else the default."""
    value = (options or {}).get(name, default) if isinstance(options, dict) else default
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return default
    return value


def gcp_error_is_transient(error):
    detail = getattr(error, "error", None)
    if not isinstance(detail, dict):
        return True
    status = detail.get("http_status")
    if isinstance(status, int) and (status in TRANSIENT_HTTP or status >= 500):
        return True
    return detail.get("code") in GCP_TRANSIENT_CODES or detail.get("reason") in GCP_THROTTLE_REASONS


def http_status_is_transient(status):
    return not isinstance(status, int) or status in TRANSIENT_HTTP or status >= 500


_LIVE = weakref.WeakValueDictionary()


def _track(cache):
    _LIVE[id(cache)] = cache


def _reset_in_child():
    for cache in list(_LIVE.values()):
        try:
            cache._reset_after_fork()
        except Exception:
            pass


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_reset_in_child)


class BoundedEntries(OrderedDict):
    """Insertion/recency-ordered GCP transport entries with a settled-byte budget.

    Every mutation happens under the owning transport's lock. ``admit`` is
    called when an entry settles; in-flight entries are never evicted.
    """

    def __init__(self, max_bytes=DEFAULT_MAX_BYTES, max_entry_bytes=DEFAULT_MAX_ENTRY_BYTES, owner=None):
        super().__init__()
        self.max_bytes = max_bytes
        self.max_entry_bytes = max_entry_bytes
        self.sizes = {}
        self.bytes = 0
        self.evictions = 0
        self.owner = weakref.ref(owner) if owner is not None else None
        _track(self)

    def touch(self, key):
        if key in self.sizes:
            self.move_to_end(key)

    def admit(self, key, entry, size):
        """Account one settled entry; drop it when it cannot be retained."""
        if self.get(key) is not entry:
            return
        if size > self.max_entry_bytes or size > self.max_bytes:
            super().__delitem__(key)
            self.evictions += 1
            return
        self.sizes[key] = size
        self.bytes += size
        self.move_to_end(key)
        while self.bytes > self.max_bytes and self.sizes:
            # Least recently used settled entry; in-flight entries stay.
            oldest = next(candidate for candidate in self if candidate in self.sizes)
            self.pop(oldest)
            self.evictions += 1

    def discard(self, key, entry):
        """Forget a settled transient outcome so a later caller reads again."""
        if self.get(key) is entry:
            self.pop(key)

    def __delitem__(self, key):
        super().__delitem__(key)
        self.bytes -= self.sizes.pop(key, 0)

    def pop(self, key, *default):
        if key in self:
            value = super().__getitem__(key)
            self.__delitem__(key)
            return value
        if default:
            return default[0]
        raise KeyError(key)

    def clear(self):
        super().clear()
        self.sizes.clear()
        self.bytes = 0

    def _reset_after_fork(self):
        OrderedDict.clear(self)
        self.sizes = {}
        self.bytes = 0
        owner = self.owner() if self.owner is not None else None
        if owner is not None and hasattr(owner, "lock"):
            owner.lock = threading.Lock()


class _Flight:
    __slots__ = ("event", "value", "error")

    def __init__(self):
        self.event = threading.Event()
        self.value = None
        self.error = None


class RawResponseCache:
    """Single-flight cache of complete raw read bodies (bytes)."""

    def __init__(self, max_bytes=RAW_MAX_BYTES, max_entry_bytes=RAW_MAX_ENTRY_BYTES):
        self.max_bytes = max_bytes
        self.max_entry_bytes = max_entry_bytes
        self.lock = threading.Lock()
        self.entries = OrderedDict()
        self.flights = {}
        self.bytes = 0
        self.hits = self.misses = self.coalesced = self.evictions = 0
        _track(self)

    def fetch(self, key, loader, wait=None):
        """Return ``loader()``'s bytes once per key; concurrent callers share one call.

        A loader exception is shared with callers already waiting on that flight
        and is never retained, so the next caller reads again.
        """
        with self.lock:
            value = self.entries.get(key)
            if value is not None:
                self.entries.move_to_end(key)
                self.hits += 1
                return value
            flight = self.flights.get(key)
            owner = flight is None
            if owner:
                flight = self.flights[key] = _Flight()
                self.misses += 1
            else:
                self.coalesced += 1
        if not owner:
            if wait is None:
                flight.event.wait()
            else:
                wait(flight.event)
            if flight.error is not None:
                raise flight.error
            return flight.value
        try:
            value = loader()
            if not isinstance(value, (bytes, bytearray)):
                raise TypeError("raw response cache stores bytes")
            value = bytes(value)
            flight.value = value
        except BaseException as exc:
            flight.error = exc
            raise
        finally:
            with self.lock:
                if self.flights.get(key) is flight:
                    del self.flights[key]
                if flight.error is None:
                    self._admit(key, flight.value)
            flight.event.set()
        return value

    def _admit(self, key, value):
        size = len(value)
        if size > self.max_entry_bytes or size > self.max_bytes:
            return
        previous = self.entries.pop(key, None)
        if previous is not None:
            self.bytes -= len(previous)
        self.entries[key] = value
        self.bytes += size
        while self.bytes > self.max_bytes and self.entries:
            _, dropped = self.entries.popitem(last=False)
            self.bytes -= len(dropped)
            self.evictions += 1

    def clear(self):
        with self.lock:
            self.entries.clear()
            self.bytes = 0

    def stats(self):
        with self.lock:
            return {"hits": self.hits, "misses": self.misses, "coalesced": self.coalesced,
                    "evictions": self.evictions, "entries": len(self.entries), "bytes": self.bytes}

    def _reset_after_fork(self):
        self.lock = threading.Lock()
        self.entries = OrderedDict()
        self.flights = {}
        self.bytes = 0
