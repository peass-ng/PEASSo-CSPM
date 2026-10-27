"""Graph JSON $batch first-page prefetch for per-object directory reads.

Each per-object read (owners, administrative unit members, federated
credentials, app role assignments, group members) still runs as its own
collection job through the shared reader. This module only answers that job's
first GET with the exact 200 body returned for the same relative URL inside a
read-only $batch of at most 20 GETs. Any other outcome (batch failure,
non-200 or malformed sub-response, cancellation) falls through to the caller's
normal request path, so errors, retries,
continuations and budgets are produced exactly as without batching.
"""
import copy
import math
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor

GRAPH = "https://graph.microsoft.com"
PREFIX = GRAPH + "/v1.0"
BATCH_URL = PREFIX + "/$batch"
MAX_REQUESTS = 20
_OBJECT = r"[A-Za-z0-9-]{1,64}"
ROUTES = tuple(re.compile(pattern) for pattern in (
    r"/(?:applications|servicePrincipals|groups)/" + _OBJECT + r"/owners\?\$select=id",
    r"/directory/administrativeUnits/" + _OBJECT + r"/members\?\$select=id",
    r"/applications/" + _OBJECT + r"/federatedIdentityCredentials\?\$select=id,name,issuer,subject,audiences",
    r"/servicePrincipals/" + _OBJECT + r"/appRoleAssignments",
    r"/groups/" + _OBJECT + r"/members\?\$select=id",
))
_MISSING = object()


def relative(url):
    """The reviewed relative batch URL for an absolute read, or None."""
    if not isinstance(url, str) or not url.startswith(PREFIX + "/"):
        return None
    path = url[len(PREFIX):]
    return path if any(route.fullmatch(path) for route in ROUTES) else None


def valid_body(body):
    """A $batch body that contains only reviewed directory GETs."""
    if not isinstance(body, dict) or set(body) != {"requests"}:
        return False
    requests = body["requests"]
    if not isinstance(requests, list) or not 1 <= len(requests) <= MAX_REQUESTS:
        return False
    seen = set()
    for row in requests:
        if (not isinstance(row, dict) or set(row) != {"id", "method", "url"} or row["method"] != "GET"
                or not isinstance(row["id"], str) or not re.fullmatch(r"[0-9]{1,2}", row["id"]) or row["id"] in seen
                or not isinstance(row["url"], str) or not any(route.fullmatch(row["url"]) for route in ROUTES)):
            return False
        seen.add(row["id"])
    return True


def _retry_after(headers):
    value = headers.get("Retry-After") if isinstance(headers, dict) else None
    if isinstance(value, str) and re.fullmatch(r"[0-9]{1,4}", value.strip()):
        return float(value.strip())
    return 2.0


class FirstPages:
    """Order-preserving, bounded-lookahead $batch prefetch for one reader.run."""

    def __init__(self, reader, transport, fallback, urls, *, rounds=3):
        self.reader, self.transport, self.fallback, self.rounds = reader, transport, fallback, rounds
        unique = list(dict.fromkeys(url for url in urls if relative(url)))
        self.chunks = [unique[offset:offset + MAX_REQUESTS] for offset in range(0, len(unique), MAX_REQUESTS)]
        self.chunk_of = {url: number for number, chunk in enumerate(self.chunks) for url in chunk}
        self.workers = max(1, reader.workers)
        # One shared bound for batch POSTs and fall-through reads keeps wire
        # concurrency at the reader's configured worker count.
        self.slots = threading.BoundedSemaphore(self.workers)
        self.lock = threading.Lock()
        self.futures = {}
        self.submitted = 0
        self.closed = False
        self.pool = ThreadPoolExecutor(max_workers=min(self.workers, len(self.chunks))) if self.chunks else None
        self.posts = 0
        self._advance(-1)

    def _advance(self, consumed):
        # Hold at most `workers` chunks ahead of the latest consumer.
        with self.lock:
            while not self.closed and self.submitted < len(self.chunks) and self.submitted <= consumed + self.workers:
                self.futures[self.submitted] = self.pool.submit(self._fetch, self.chunks[self.submitted])
                self.submitted += 1

    def _post(self, urls):
        body = {"requests": [{"id": str(number), "method": "GET", "url": relative(url)}
                             for number, url in enumerate(urls)]}
        with self.slots:
            self.reader.check_cancelled()
            with self.lock:
                self.posts += 1
            return self.transport.request(BATCH_URL, body=body, audience=GRAPH)

    def _fetch(self, chunk):
        values, pending = {}, list(chunk)
        for attempt in range(self.rounds):
            if not pending:
                break
            try:
                response = self._post(pending)
            except Exception:
                break
            rows = response.get("responses") if isinstance(response, dict) else None
            if not isinstance(rows, list):
                break
            row_ids = [row.get("id") for row in rows if isinstance(row, dict)]
            if (len(row_ids) != len(rows) or len(set(row_ids)) != len(rows)
                    or any(not isinstance(identifier, str) or not identifier.isdigit()
                           or int(identifier) >= len(pending) for identifier in row_ids)):
                break
            throttled, delay = [], 0.0
            for row in rows:
                position = int(row["id"])
                url, status = pending[position], row.get("status")
                if status == 200 and isinstance(row.get("body"), dict):
                    values.setdefault(url, row["body"])
                elif status == 429:
                    throttled.append(url)
                    delay = max(delay, _retry_after(row.get("headers")))
            pending = [url for url in throttled if url not in values]
            if not pending or attempt + 1 >= self.rounds:
                break
            deadline = self.reader.deadline
            if (not math.isfinite(delay) or delay > 30
                    or deadline is not None and time.monotonic() + delay >= deadline):
                break
            time.sleep(delay)
        return values

    def request(self, url, *, body=None, audience=None):
        number = self.chunk_of.get(url) if body is None and audience == GRAPH else None
        if number is not None:
            self._advance(number)
            future = self.futures.get(number)
            try:
                values = future.result() if future is not None else {}
            except Exception:
                values = {}
            with self.lock:
                value = values.get(url, _MISSING)
            if value is not _MISSING:
                # A later read of the same URL must reuse this scan's first
                # successful response, just as AzureTransport's GET cache does.
                return copy.deepcopy(value)
        with self.slots:
            return self.fallback(url, body=body, audience=audience)

    def close(self):
        with self.lock:
            self.closed = True
        if self.pool is not None:
            self.pool.shutdown(wait=True, cancel_futures=True)

    def __enter__(self):
        return self.request

    def __exit__(self, *exc):
        self.close()
        return False


def first_pages(reader, transport, fallback, urls, *, enabled):
    """Context manager yielding the request callable for one batch of jobs."""
    if not enabled:
        return _Direct(fallback)
    return FirstPages(reader, transport, fallback, urls)


class _Direct:
    def __init__(self, fallback):
        self.fallback = fallback

    def __enter__(self):
        return self.fallback

    def __exit__(self, *exc):
        return False
