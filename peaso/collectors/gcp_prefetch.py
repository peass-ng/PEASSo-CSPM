"""Bounded read-ahead for two serial GCP read loops in ``GCPCollector.scope_jobs``.

``scope_jobs`` is source-pinned, so its serial loops stay as written:

* ``iam_deny_policy`` hydrates one deny policy detail GET after another for
  every listed policy that has no inline ``rules``;
* ``org_policy_effective`` issues one ``getEffectivePolicy`` per entry of
  ``ORG_POLICY_CONSTRAINTS`` for a project, one after another.

The transport sees the request that starts each loop (the deny-policy list
page, and the first constraint's ``getEffectivePolicy``) and issues the exact
requests the loop will issue next — same method, URL, params, body and scope —
on a small bounded pool into the per-scan response cache. The loop then finds
a settled entry or joins the in-flight request (single-flight), so it still
reads the same requests in the same order and only the wall time changes.

A prefetched read that ends in a transient error (429, 5xx, transport error)
is not cached; its error is kept for the loop's own request instead, so the
loop still sees exactly one failed read and no request is sent twice.
"""

import json
import re
import threading
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout

from .scan_cache import _track

DEFAULT_WORKERS = 8
_DENY_LIST = re.compile(
    r"https://iam\.googleapis\.com/v2/policies/cloudresourcemanager\.googleapis\.com%2F"
    r"(projects|folders|organizations)%2F([^/%]+)/denypolicies")
_EFFECTIVE = re.compile(r"https://orgpolicy\.googleapis\.com/v2/(projects/[^/]+)/policies/([^/:]+):getEffectivePolicy")


def cache_key(method, url, params, body):
    """The transport's single-flight key (absent and empty params are one request)."""
    return json.dumps([method, url, params or {}, body], sort_keys=True)


class _State:
    def __init__(self, transport):
        options = transport.options if isinstance(transport.options, dict) else {}
        value = options.get("prefetch_workers", DEFAULT_WORKERS)
        if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 32:
            value = DEFAULT_WORKERS
        self.workers = value
        self.lock = threading.Lock()
        self.local = threading.local()
        self.pool = None
        self.planned = set()
        self.futures = {}
        self.retained = {}
        self.closed = False
        _track(self)

    def executor(self):
        if self.closed or not self.workers:
            return None
        if self.pool is None:
            self.pool = ThreadPoolExecutor(max_workers=self.workers, thread_name_prefix="gcp-prefetch")
        return self.pool

    def _reset_after_fork(self):
        # Worker threads do not exist in a forked child; neither do their flights.
        self.lock = threading.Lock()
        self.local = threading.local()
        self.pool = None
        self.planned = set()
        self.futures = {}
        self.retained = {}


def _state(transport):
    state = transport.__dict__.get("_prefetch_state")
    if state is None:
        with transport.lock:
            state = transport.__dict__.get("_prefetch_state")
            if state is None:
                state = transport.__dict__["_prefetch_state"] = _State(transport)
    return state


def _schedule(transport, scope, reads):
    """Queue (url, params) GETs exactly as the loop will issue them, once per scan."""
    state = _state(transport)
    for url, params in reads:
        key = cache_key("GET", url, params, None)
        with transport.lock:
            settled_or_flying = key in transport.cache
        with state.lock:
            if key in state.planned or settled_or_flying:
                continue
            pool = state.executor()
            if pool is None:
                return
            state.planned.add(key)
            try:
                state.futures[key] = pool.submit(_prefetch, transport, state, scope, url, params, key)
            except RuntimeError:  # pool shut down by close()
                return


def _prefetch(transport, state, scope, url, params, key):
    state.local.active = True
    try:
        type(transport).request(transport, "GET", url, params=params, body=None, scope=scope, operation=None)
    except Exception as exc:
        with transport.lock:
            settled = key in transport.cache
        if not settled:
            # Transient outcomes are not cached; keep this one for the loop's
            # own read so it sees one failed request, not a second attempt.
            with state.lock:
                state.retained[key] = exc
    finally:
        state.local.active = False


def _await(transport, future):
    """Wait for a read-ahead like a single-flight follower, honouring cancellation."""
    options = transport.options if isinstance(transport.options, dict) else {}
    interruptible = (options.get("cancel_event") is not None or callable(options.get("_cancel_check"))
                     or transport.deadline is not None or transport.deadline_seconds is not None)
    while True:
        try:
            future.result(timeout=0.1 if interruptible else None)
            return
        except FutureTimeout:
            transport.check_cancelled()
        except Exception:  # cancelled at close(); the loop reads for itself
            return


def before_read(transport, key, method, url, params, body, scope, operation):
    """Settle a pending read-ahead first; start a project's constraint read-ahead."""
    state = transport.__dict__.get("_prefetch_state")
    if state is not None and not getattr(state.local, "active", False):
        with state.lock:
            future = state.futures.pop(key, None)
        if future is not None:
            _await(transport, future)
            with state.lock:
                error = state.retained.pop(key, None)
            if error is not None:
                raise error
    if method != "GET" or body is not None or params or operation is not None:
        return
    match = _EFFECTIVE.fullmatch(url)
    if not match or match.group(1) != scope:
        return
    from .gcp import ORG_POLICY_CONSTRAINTS
    constraints = tuple(ORG_POLICY_CONSTRAINTS)
    if len(constraints) < 2 or match.group(2) != constraints[0]:
        return
    # pages(single=True) sends empty params for each constraint.
    _schedule(transport, scope, [(f"https://orgpolicy.googleapis.com/v2/{scope}/policies/{constraint}:getEffectivePolicy", {})
                                 for constraint in constraints[1:]])


def after_read(transport, method, url, params, body, scope, operation, data):
    """After a deny-policy list page, read ahead the details the loop will hydrate."""
    if method != "GET" or body is not None or operation is not None or not isinstance(data, dict):
        return
    match = _DENY_LIST.fullmatch(url)
    if not match or f"{match.group(1)}/{match.group(2)}" != scope:
        return
    items = data.get("policies", [])
    # pages() rejects a malformed list before the loop hydrates anything.
    if not isinstance(items, list) or any(not isinstance(item, dict) for item in items):
        return
    # hydrate() reads each detail without params.
    reads = [(f"https://iam.googleapis.com/v2/{item['name']}", None) for item in items
             if "rules" not in item and isinstance(item.get("name"), str) and item["name"]]
    if reads:
        _schedule(transport, scope, reads)


def close(transport):
    state = transport.__dict__.get("_prefetch_state")
    if state is None:
        return
    with state.lock:
        state.closed = True
        pool, state.pool = state.pool, None
    if pool is not None:
        pool.shutdown(wait=True, cancel_futures=True)
    with state.lock:
        state.futures.clear()
        state.retained.clear()
