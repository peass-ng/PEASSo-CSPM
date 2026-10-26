"""Per-scan, read-only Kubernetes response cache at the bounded transport.

``install`` gives one ``collect`` call's bounded transport (one API client,
one credential) a fresh cache; ``uninstall`` clears it and restores the
original pool when that scan ends, so it is never shared across scans or tenants.

Only GET responses are retained, and only after the caller consumed the whole
body: a caller that stops early (byte budgets, representation checks, deadlines)
leaves nothing behind, so streaming guards behave exactly as without a cache.
Throttling, server errors and any status other than 2xx/403/404 are never kept.
Identical concurrent requests are single-flight: followers wait for the leader's
complete body instead of issuing the same request again.

``warm`` lets a caller that is about to perform a known series of reads one by
one (for example one Secret Table per namespace) start them concurrently on this
scan's bounded worker pool. The caller still performs, validates and orders each
read itself; a warmed read only lets its request reach the cache earlier.
"""
from __future__ import annotations

import hashlib
import io
import threading
from concurrent.futures import ThreadPoolExecutor
from collections import OrderedDict
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

CACHEABLE_STATUS = frozenset(range(200, 300)) | {403, 404}
MAX_ENTRY_BYTES = 8 * 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024
FOLLOWER_WAIT_SECONDS = 60.0
WARM_WORKERS = 8
# Request headers that do not change a GET response from the API server.
_IGNORED_HEADERS = frozenset(("user-agent", "content-type"))
# Defaults that are equivalent to the header being absent.
_DEFAULT_HEADERS = {"accept": "application/json", "accept-encoding": "identity"}


def request_key(method, url, kwargs):
    """Normalized identity of a read: URL, sorted query and response-shaping headers."""
    if method != "GET" or kwargs.get("body") is not None:
        return None
    target = urlsplit(url)
    query = parse_qsl(target.query, keep_blank_values=True)
    fields = kwargs.get("fields") or {}
    query += list(fields.items()) if isinstance(fields, dict) else list(fields)
    normalized = urlencode(sorted((str(k), str(v)) for k, v in query))
    headers = []
    for name, value in (kwargs.get("headers") or {}).items():
        lowered = str(name).lower()
        if lowered in _IGNORED_HEADERS or _DEFAULT_HEADERS.get(lowered) == value:
            continue
        headers.append((lowered, str(value)))
    # Credentials only scope the key; the digest avoids keeping another token copy.
    digest = hashlib.sha256(repr(sorted(headers)).encode()).hexdigest()
    return urlunsplit((target.scheme, target.netloc.lower(), target.path, normalized, "")), digest


class _Entry:
    __slots__ = ("status", "reason", "headers", "body", "version")

    def __init__(self, status, reason, headers, body, version):
        self.status, self.reason, self.headers, self.body, self.version = status, reason, headers, body, version


class _Recording:
    """Forward a live response while keeping its bytes until the caller reaches EOF."""
    _response = None
    _done = True

    def __init__(self, response, cache, key, preload):
        self._response, self._cache, self._key = response, cache, key
        self._chunks, self._size, self._done = [], 0, False
        if preload:
            self._finish(response.data or b"")

    def __getattr__(self, name):
        return getattr(self._response, name)

    def _finish(self, body):
        if not self._done:
            self._done = True
            self._cache._complete(self._key, self._response, body)

    def _abandon(self):
        if not self._done:
            self._done = True
            self._chunks = []
            self._cache._abandon(self._key)

    def _record(self, chunk):
        if self._done or not isinstance(chunk, bytes):
            return
        self._size += len(chunk)
        if self._size > MAX_ENTRY_BYTES:
            self._abandon()
        else:
            self._chunks.append(chunk)

    @property
    def data(self):
        data = self._response.data
        if not self._done:
            self._finish(b"".join(self._chunks) + (data or b""))
        return data

    def read(self, amt=None, *args, **kwargs):
        try:
            chunk = self._response.read(amt, *args, **kwargs)
        except BaseException:
            self._abandon()
            raise
        self._record(chunk)
        if not self._done and (amt is None or (amt and not chunk)):
            self._finish(b"".join(self._chunks))
        return chunk

    def stream(self, amt=2 ** 16, decode_content=None):
        while True:
            chunk = self.read(amt, decode_content=decode_content)
            if not chunk:
                return
            yield chunk

    def close(self):
        self._abandon()
        return self._response.close()

    def release_conn(self):
        self._abandon()
        return self._response.release_conn()

    def __del__(self):
        try:
            self._abandon()
        except Exception:
            pass


class ScanResponseCache:
    """Thread-safe, memory-bounded LRU of complete GET responses for one scan."""

    def __init__(self, max_entry_bytes=MAX_ENTRY_BYTES, max_total_bytes=MAX_TOTAL_BYTES):
        self.max_entry_bytes, self.max_total_bytes = max_entry_bytes, max_total_bytes
        self._lock = threading.Lock()
        self._entries = OrderedDict()
        self._inflight = {}
        self._bytes = 0
        self.stats = {"requests": 0, "hits": 0, "misses": 0, "stored": 0, "waited": 0, "bypassed": 0}

    def request(self, perform, method, url, kwargs):
        key = request_key(method, url, kwargs)
        if key is None:
            return perform()
        preload = kwargs.get("preload_content", True)
        decode = kwargs.get("decode_content", True)
        me = threading.get_ident()
        with self._lock:
            self.stats["requests"] += 1
        while True:
            with self._lock:
                entry = self._entries.get(key)
                if entry is not None:
                    self._entries.move_to_end(key)
                    self.stats["hits"] += 1
                    return self._replay(entry, url, preload, decode)
                flight = self._inflight.get(key)
                if flight is None:
                    self._inflight[key] = (threading.Event(), me)
                    self.stats["misses"] += 1
                    break
                if flight[1] == me:
                    # The leader re-requested before finishing its own body.
                    self.stats["bypassed"] += 1
                    return perform()
                self.stats["waited"] += 1
            if not flight[0].wait(FOLLOWER_WAIT_SECONDS):
                with self._lock:
                    self.stats["bypassed"] += 1
                return perform()
            with self._lock:
                if key not in self._entries:
                    # Leader failed or stopped early: perform independently.
                    self.stats["bypassed"] += 1
                    return perform()
        try:
            response = perform()
        except BaseException:
            self._abandon(key)
            raise
        status = getattr(response, "status", None)
        encoding = str(getattr(response, "headers", {}).get("Content-Encoding", "identity") or "identity").lower()
        if status not in CACHEABLE_STATUS or encoding != "identity":
            self._abandon(key)
            return response
        return _Recording(response, self, key, preload)

    def _replay(self, entry, url, preload, decode):
        from urllib3 import HTTPResponse
        from urllib3._collections import HTTPHeaderDict
        return HTTPResponse(body=io.BytesIO(entry.body), headers=HTTPHeaderDict(entry.headers), status=entry.status,
                            reason=entry.reason, version=entry.version, preload_content=preload,
                            decode_content=decode, request_method="GET", request_url=url)

    def _complete(self, key, response, body):
        headers = list(getattr(response, "headers", {}).items())
        length = dict((k.lower(), v) for k, v in headers).get("content-length")
        complete = isinstance(body, bytes) and (length is None or (str(length).isdecimal() and int(length) == len(body)))
        with self._lock:
            flight = self._inflight.pop(key, None)
            # A flight cleared at scan end is never stored into a later scan.
            if flight is not None and complete and len(body) <= self.max_entry_bytes:
                self._entries[key] = _Entry(response.status, getattr(response, "reason", None), headers, body,
                                            getattr(response, "version", 11))
                self._bytes += len(body)
                self.stats["stored"] += 1
                while self._bytes > self.max_total_bytes and self._entries:
                    _, old = self._entries.popitem(last=False)
                    self._bytes -= len(old.body)
        if flight:
            flight[0].set()

    def _abandon(self, key):
        with self._lock:
            flight = self._inflight.pop(key, None)
        if flight:
            flight[0].set()

    def clear(self):
        """Discard every retained body and pending flight at scan end."""
        with self._lock:
            self._entries.clear()
            self._bytes = 0
            flights = list(self._inflight.values())
            self._inflight.clear()
        for flight in flights:
            flight[0].set()


class CachingPool:
    """Inner pool of the bounded transport: replays identical complete reads.

    The bounded transport validates every request first and then calls this
    pool. Selected content readers re-read exact objects on purpose to prove
    they did not change, so their paths always reach the server.
    """

    def __init__(self, pool, bounded, cache=None):
        self.pool, self.bounded = pool, bounded
        self.response_cache = cache if cache is not None else ScanResponseCache()
        self._warmer = None
        self._warmer_lock = threading.Lock()
        self._closed = False

    def _executor(self):
        with self._warmer_lock:
            if self._warmer is None and not self._closed:
                self._warmer = ThreadPoolExecutor(WARM_WORKERS, thread_name_prefix="k8s-warm")
            return self._warmer

    def close(self):
        """Stop warming at scan end: queued reads are dropped, running ones finish."""
        with self._warmer_lock:
            self._closed = True
            warmer, self._warmer = self._warmer, None
        if warmer is not None:
            warmer.shutdown(wait=True, cancel_futures=True)

    def _selected_path(self, url):
        path = urlsplit(url).path
        server = getattr(self.bounded, "server", None)
        base = server.path.rstrip("/") if server is not None else ""
        if base and path.startswith(base + "/"):
            path = path[len(base):]
        return path in getattr(self.bounded, "literal_paths", ())

    def request(self, method, url, **kwargs):
        if method != "GET" or self._selected_path(url):
            return self.pool.request(method, url, **kwargs)
        return self.response_cache.request(lambda: self.pool.request(method, url, **kwargs), method, url, kwargs)

    def __getattr__(self, name):
        return getattr(self.pool, name)


def _quiet(read, slots=None):
    try:
        if slots is None:
            read()
        else:
            with slots:
                read()
    except Exception:
        pass  # Warm-up only; the caller performs and reports its own request.


def warm(api, reads, reader=None):
    """Start reads the caller will perform next, in order, so they land in this scan's cache.

    Each read is a zero-argument callable issuing exactly the GET the caller is about to
    make. Nothing is started without an installed cache, for a serial reader, or when the
    reader's call budget could not also cover these reads. Warm reads share the reader's
    nested fan-out slots, so they never exceed its configured concurrency.
    Returns how many reads were started.
    """
    bounded = _bounded(api)
    pool = bounded.__dict__["pool"] if bounded is not None else None
    if not isinstance(pool, CachingPool):
        return 0
    reads = list(reads)
    slots = None
    if reader is not None:
        workers = getattr(reader, "workers", 1)
        if not (type(workers) is int and workers > 1):
            return 0
        budget = getattr(reader, "budget", None)
        limit = getattr(budget, "max_calls", None)
        if limit is not None and getattr(budget, "calls", 0) + len(reads) > limit:
            return 0
        from .azure import _fanout_slots
        slots = _fanout_slots(reader)
    executor = pool._executor() if reads else None
    started = 0
    for read in reads if executor is not None else ():
        try:
            executor.submit(_quiet, read, slots)
        except RuntimeError:
            break  # Scan ended.
        started += 1
    return started


def _bounded(api):
    client = getattr(getattr(api, "api", api), "api_client", None)
    bounded = getattr(getattr(client, "rest_client", None), "pool_manager", None)
    # Only the collector's bounded, read-only transport gets a cache.
    if bounded is None or not hasattr(bounded, "literal_paths") or "pool" not in getattr(bounded, "__dict__", {}):
        return None
    return bounded


def install(api):
    """Give this scan's bounded transport a fresh response cache; returns it or None."""
    bounded = _bounded(api)
    if bounded is None:
        return None
    inner = bounded.__dict__["pool"]
    if isinstance(inner, CachingPool):
        inner.response_cache.clear()
        return inner.response_cache
    bounded.pool = CachingPool(inner, bounded)
    return bounded.pool.response_cache


def uninstall(api):
    """Discard the scan's cache at scan end and restore the original pool; returns its stats."""
    bounded = _bounded(api)
    inner = bounded.__dict__["pool"] if bounded is not None else None
    if not isinstance(inner, CachingPool):
        return None
    inner.close()
    inner.response_cache.clear()
    bounded.pool = inner.pool
    return dict(inner.response_cache.stats)
