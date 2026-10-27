"""Scan-local sharing of native AWS reads below the projection layer.

``Requests.call`` already single-flights projected responses per session
namespace. Network metadata modules wrap the same SDK session in their own
projecting session (``MetadataSession``), so one native read could be sent
once per namespace and once per wrapper instance, each through a freshly built
botocore client. This module removes both costs without changing projections:

* ``RawReadCache`` sits on the SDK client's ``_make_api_call``. It is active
  only inside ``Requests.call`` (``shared_reads``); direct client use such as
  readiness polling always reaches AWS. Entries are keyed by the root session,
  endpoint URL, operation and normalized parameters, so the same account
  credentials, endpoint and request share one response for the scan. Global
  endpoints (IAM, Organizations, CloudFront, Route 53) resolve to one URL from
  every Region and are therefore read once.
* Only read-named, non-streaming operations are eligible. Credential, token,
  password, secret, session and presigned-download style operations, STS and
  SSO are never retained. Requests with a refresh, credential-exchange or
  content profile run with sharing disabled.
* Concurrent identical reads wait for one owner (single flight). Successes and
  definitive client errors (for example access denied) are shared; throttling,
  5xx, 429 and transport failures are never stored, so a waiter retries.
* Memory is bounded by an approximate payload size per entry and in total
  (least recently used entries are dropped). The cache lives on one
  ``Requests`` object and is discarded with it at scan end.
* Clients carrying a botocore ``Stubber`` bypass sharing so ordered stub
  queues keep their exact semantics.
"""

from __future__ import annotations

import contextlib
import contextvars
import json
import threading
import time
from collections import OrderedDict
from datetime import date, datetime

_SHARED = contextvars.ContextVar("peaso_aws_shared_reads", default=False)

READ_PREFIXES = ("Get", "List", "Describe", "BatchGet", "BatchDescribe", "Search")
NEVER_SERVICES = frozenset({"sts", "sso", "sso-oidc", "cognito-identity", "secretsmanager", "signin"})
NEVER_WORDS = ("Credential", "Token", "Password", "Secret", "Login", "Session", "Url", "URL",
               "Download", "Content", "LogEvents", "QueryResults")
# Ordinary metadata reads whose names contain a word above.
ALLOW_OPERATIONS = frozenset()
NEVER_OPERATIONS = frozenset({("lambda", "GetFunction"), ("lambda", "GetLayerVersion"),
                              ("lambda", "GetLayerVersionByArn"), ("cloudtrail", "LookupEvents"),
                              ("codecommit", "GetFile"), ("codecommit", "GetFolder"), ("codecommit", "GetBlob"),
                              ("codecommit", "GetDifferences"), ("ssm", "GetParameter"), ("ssm", "GetParameters"),
                              ("ssm", "GetParametersByPath"), ("ssm", "GetParameterHistory"),
                              ("iam", "GetCredentialReport")})
TRANSIENT_CODES = frozenset({"Throttling", "ThrottlingException", "TooManyRequestsException",
                             "RequestLimitExceeded", "SlowDown", "ServiceUnavailable",
                             "ServiceUnavailableException", "InternalError", "InternalServerError",
                             "InternalServerException", "RequestThrottled", "RequestThrottledException",
                             "ProvisionedThroughputExceededException", "PriorRequestNotComplete",
                             "BandwidthLimitExceeded", "LimitExceededException", "EC2ThrottledException",
                             "RequestTimeout", "RequestTimeoutException"})


# Waits before the 2nd and 3rd attempt of a read whose TLS session failed.
TLS_RETRY_DELAYS = (0.2, 0.5)


def tls_failure(exc):
    """A botocore TLS transport failure (handshake/verify/EOF), no API answer."""
    try:
        from botocore.exceptions import SSLError
    except Exception:
        return False
    return isinstance(exc, SSLError)


# Callers whose native response is read through the plain pooled client and
# only projected afterwards (metadata-only operations). Content, credential
# exchange and source profiles never share native reads.
SHARED_PROFILES = frozenset({None, 'bedrock-agent-reasoning-metadata-v1', 'fms-managed-web-acl-metadata-v1',
                             'securityhub-workflow-history-metadata-v1', 'securityhub-findings-metadata-v1',
                             'bedrock-security-role-metadata-v1', 'aws-cloudtrail-s3-delivery-metadata-v1'})


@contextlib.contextmanager
def shared_reads(enabled=True):
    """Enable native read sharing for SDK calls made in this context."""
    token = _SHARED.set(bool(enabled))
    try:
        yield
    finally:
        _SHARED.reset(token)


def fast_copy(value):
    """Copy JSON-like SDK data; return ``(copy, approximate_bytes)``.

    Timestamps, numbers and strings are immutable and shared. Any other
    object is returned as-is (botocore parsed output holds no mutable leaf).
    """
    size = [0]

    def walk(item):
        kind = type(item)
        if kind is dict:
            size[0] += 64
            return {key: walk(child) for key, child in item.items()}
        if kind is list:
            size[0] += 32 + 8 * len(item)
            return [walk(child) for child in item]
        if kind is str or kind is bytes:
            size[0] += 50 + len(item)
            return item
        if kind is tuple:
            size[0] += 32
            return tuple(walk(child) for child in item)
        size[0] += 32
        return item
    copied = walk(value)
    return copied, size[0]


def _copy(value):
    return fast_copy(value)[0]


def _normal(value):
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, (bytes, bytearray)):
        return "b:" + bytes(value).hex()
    raise TypeError("unshareable")


def stubbed(client):
    events = getattr(getattr(client, "meta", None), "events", None)
    emitter = getattr(events, "_emitter", events)
    handlers = getattr(emitter, "_unique_id_handlers", None)
    return isinstance(handlers, dict) and "boto_stubber" in handlers


def eligible(service, operation, model):
    if service in NEVER_SERVICES or (service, operation) in NEVER_OPERATIONS:
        return False
    if not operation.startswith(READ_PREFIXES):
        return False
    if (service, operation) not in ALLOW_OPERATIONS and any(word in operation for word in NEVER_WORDS):
        return False
    try:
        return not (model.has_streaming_output or model.has_event_stream_output)
    except Exception:
        return False


class RawReadCache:
    """Thread-safe, size-bounded single-flight cache for one scan."""

    def __init__(self, *, max_bytes=96 * 1024 * 1024, max_entry_bytes=8 * 1024 * 1024):
        self.max_bytes, self.max_entry_bytes = max_bytes, max_entry_bytes
        self._lock = threading.Lock()
        self._entries = OrderedDict()
        self._inflight = {}
        self._bytes = 0
        self.hits = self.waits = self.stored = self.evicted = self.oversized = self.seeded = 0
        self.tls_retries = self.gateway_retries = 0
        self.limiter = AdaptiveLimiter()
        # Load each client's CA bundle once instead of on every new TLS
        # connection (a shared-store race under concurrent handshakes).
        from .aws_tls_context import install as install_tls_context
        install_tls_context()

    def install(self, client, root):
        """Share eligible reads of ``client`` (an SDK client) for ``root``."""
        if getattr(client, "_peaso_shared_reads", None) is self:
            return client
        original = getattr(client, "_make_api_call", None)
        meta = getattr(client, "meta", None)
        if original is None or meta is None:
            return client
        root_id = id(root)
        limiter = self.limiter

        def limited(operation_name, api_params):
            # A TLS failure is a transport fault of this one connection. Read
            # operations get a short bounded retry outside the endpoint slot;
            # ``Requests.call`` keeps its own attempt budget for API errors.
            retries = TLS_RETRY_DELAYS if operation_name.startswith(READ_PREFIXES) else ()
            tag_compliance = (getattr(meta.service_model, "service_name", None) == "resourcegroupstaggingapi"
                              and operation_name == "GetResources"
                              and api_params.get("IncludeComplianceDetails") is True)
            for attempt in range(len(retries) + 1):
                try:
                    with limiter.slot((root_id, getattr(meta, "endpoint_url", None))):
                        return original(operation_name, api_params)
                except Exception as exc:
                    response = getattr(exc, "response", None)
                    metadata = response.get("ResponseMetadata", {}) if isinstance(response, dict) else {}
                    gateway_timeout = (tag_compliance and isinstance(metadata, dict)
                                       and metadata.get("HTTPStatusCode") == 504)
                    tls = tls_failure(exc)
                    if attempt == len(retries) or not (tls or gateway_timeout):
                        raise
                with self._lock:
                    if tls:
                        self.tls_retries += 1
                    else:
                        self.gateway_retries += 1
                time.sleep(retries[attempt])
                if gateway_timeout:
                    owner = getattr(self, "owner", None)
                    if owner is not None:
                        owner.check_deadline()
                        with owner._lock:
                            if owner.max_calls is not None and owner.calls >= owner.max_calls:
                                from .aws import ReadFailure
                                raise ReadFailure("not_collected", "call_limit")
                            owner.calls += 1

        def make_api_call(operation_name, api_params):
            if not _SHARED.get():
                return limited(operation_name, api_params)
            key = self._key(client, root_id, operation_name, api_params)
            if key is None:
                return limited(operation_name, api_params)
            return self._read(key, lambda: limited(operation_name, api_params))
        try:
            client._make_api_call = make_api_call
            client._peaso_native_call = limited
            client._peaso_shared_reads = self
        except Exception:
            pass
        return client

    def admit(self, client, root, check_deadline):
        """Admit a content-profile wire attempt at its native endpoint.

        Content clients cannot use native response sharing because their raw
        payloads may contain secrets. They still share the endpoint budget.
        """
        return self.limiter.slot((id(root), client.meta.endpoint_url), check=check_deadline)

    def _key(self, client, root_id, operation_name, api_params):
        try:
            model = client.meta.service_model
            service = model.service_name
            if not eligible(service, operation_name, model.operation_model(operation_name)) or stubbed(client):
                return None
            arguments = json.dumps(api_params, sort_keys=True, default=_normal)
            return (root_id, client.meta.endpoint_url, service, operation_name, arguments)
        except Exception:
            return None

    def _read(self, key, send):
        while True:
            with self._lock:
                entry = self._entries.get(key)
                if entry is not None:
                    self._entries.move_to_end(key)
                    self.hits += 1
                    return self._replay(entry)
                waiter = self._inflight.get(key)
                if waiter is None:
                    waiter = self._inflight[key] = threading.Event()
                    break
                self.waits += 1
            waiter.wait()
        try:
            try:
                response = send()
            except Exception as exc:
                self._store_error(key, exc)
                raise
            self._store(key, ("ok", response))
            return response
        finally:
            with self._lock:
                self._inflight.pop(key, None)
            waiter.set()

    def _replay(self, entry):
        kind, payload, _size = entry[0], entry[1], entry[2]
        if kind == "ok":
            return _copy(payload)
        error_class, response, operation_name = payload
        raise error_class(_copy(response), operation_name)

    def _store_error(self, key, exc):
        response = getattr(exc, "response", None)
        operation_name = getattr(exc, "operation_name", None)
        if not isinstance(response, dict) or not isinstance(operation_name, str):
            return  # transport failures are never shared
        meta = response.get("ResponseMetadata") or {}
        status = meta.get("HTTPStatusCode") if isinstance(meta, dict) else None
        code = (response.get("Error") or {}).get("Code") if isinstance(response.get("Error"), dict) else None
        if not isinstance(status, int) or status >= 500 or status == 429 or code in TRANSIENT_CODES:
            return
        try:
            type(exc)(_copy(response), operation_name)
        except Exception:
            return
        self._store(key, ("error", (type(exc), response, operation_name)))

    def _store(self, key, value):
        kind, payload = value
        copied, size = fast_copy(payload if kind == "ok" else payload[1])
        if kind == "error":
            copied = (payload[0], copied, payload[2])
        with self._lock:
            if size > self.max_entry_bytes:
                self.oversized += 1
                return
            previous = self._entries.pop(key, None)
            if previous is not None:
                self._bytes -= previous[2]
            self._entries[key] = (kind, copied, size)
            self._bytes += size
            self.stored += 1
            while self._bytes > self.max_bytes and self._entries:
                _, dropped = self._entries.popitem(last=False)
                self._bytes -= dropped[2]
                self.evicted += 1

    def seed(self, key, response):
        """Store a known native answer unless one is cached or in flight."""
        with self._lock:
            if key in self._entries or key in self._inflight:
                return False
        self._store(key, ("ok", response))
        with self._lock:
            self.seeded += 1
        return True

    def stats(self):
        with self._lock:
            return {"entries": len(self._entries), "bytes": self._bytes, "hits": self.hits,
                    "waits": self.waits, "stored": self.stored, "evicted": self.evicted,
                    "oversized": self.oversized, "seeded": self.seeded, "tls_retries": self.tls_retries,
                    "gateway_retries": self.gateway_retries,
                    "throttles": self.limiter.throttles, "limit_waits": self.limiter.waits}


WRAPPER_MODULES = frozenset({"peaso.collectors.aws_network_inventory", "peaso.collectors.aws_network_catalog"})


def wrapper_root(session):
    """Return the SDK session a known metadata wrapper projects, else None."""
    if type(session).__name__ == "MetadataSession" and type(session).__module__ in WRAPPER_MODULES:
        native = getattr(session, "native", None)
        if isinstance(native, PooledRoot):
            return native.root
        return native
    return None


class PooledRoot:
    """Session facade whose clients are the scan's pooled SDK clients."""

    def __init__(self, requests, root):
        self.requests, self.root = requests, root

    def client(self, service, *, region_name=None, **_ignored):
        return self.requests.client(self.root, service, region_name)

    def __getattr__(self, name):
        return getattr(self.root, name)


def canonical_wrapper(requests, session):
    """One metadata wrapper per (wrapper type, root) for the scan.

    Its SDK clients are the root's pooled clients, so a wrapper job neither
    builds new botocore clients nor opens new connection pools.
    """
    # Keep native retries within the scan's physical call and deadline budget.
    requests.raw_reads.owner = requests
    root = wrapper_root(session)
    if root is None:
        return session
    key = (type(session), id(root))
    with requests._lock:
        wrappers = getattr(requests, "_canonical_wrappers", None)
        if wrappers is None:
            wrappers = requests._canonical_wrappers = {}
        found = wrappers.get(key)
        if found is not None:
            return found[0]
    try:
        canonical = type(session)(PooledRoot(requests, root))
    except Exception:
        return session
    with requests._lock:
        # Keep the root alive so its id cannot be reused during the scan.
        return requests._canonical_wrappers.setdefault(key, (canonical, root))[0]


# --------------------------------------------------------------------------- adaptive per-endpoint concurrency

THROTTLE_CODES = frozenset({"Throttling", "ThrottlingException", "TooManyRequestsException",
                            "RequestLimitExceeded", "SlowDown", "RequestThrottled",
                            "RequestThrottledException", "EC2ThrottledException",
                            "ProvisionedThroughputExceededException", "BandwidthLimitExceeded"})


def throttled(exc):
    response = getattr(exc, "response", None)
    if not isinstance(response, dict):
        return False
    error = response.get("Error") if isinstance(response.get("Error"), dict) else {}
    meta = response.get("ResponseMetadata") if isinstance(response.get("ResponseMetadata"), dict) else {}
    return error.get("Code") in THROTTLE_CODES or meta.get("HTTPStatusCode") == 429


class AdaptiveLimiter:
    """AIMD in-flight limit per (credentials root, endpoint).

    Each endpoint starts at ``initial`` concurrent requests. A throttling
    answer halves its limit (never below one); successes grow it additively
    up to ``maximum``. Waiting happens before a request is sent, so a
    throttled endpoint slows down instead of exhausting retry attempts.
    A throttling answer also pauses new requests to that endpoint for
    ``cooldown`` seconds, so a quota shared with the customer's own
    workloads gets room to refill before the next request is sent.
    """

    def __init__(self, initial=8, maximum=16, cooldown=1.0, clock=time.monotonic):
        self.initial, self.maximum, self.cooldown, self._clock = initial, maximum, cooldown, clock
        self._condition = threading.Condition()
        self._state = {}
        self._paused = {}
        self.throttles = 0
        self.waits = 0

    @contextlib.contextmanager
    def slot(self, key, *, check=None):
        with self._condition:
            state = self._state.get(key)
            if state is None:
                state = self._state[key] = [float(self.initial), 0]
            waited = False
            while True:
                if check is not None:
                    check()
                pause = self._paused.get(key, 0.0) - self._clock()
                if state[1] < int(state[0]) and pause <= 0:
                    break
                if not waited:
                    self.waits += 1
                    waited = True
                timeout = min(pause, 0.1) if check is not None and pause > 0 else (
                    0.1 if check is not None else pause if pause > 0 else None)
                self._condition.wait(timeout)
            state[1] += 1
        ok = False
        try:
            yield state
            ok = True
        except Exception as exc:
            if throttled(exc):
                with self._condition:
                    state[0] = max(1.0, state[0] / 2)
                    self._paused[key] = max(self._paused.get(key, 0.0), self._clock() + self.cooldown)
                    self.throttles += 1
            else:
                ok = True
            raise
        finally:
            with self._condition:
                state[1] -= 1
                if ok:
                    state[0] = min(float(self.maximum), state[0] + 1.0 / max(1.0, state[0]))
                self._condition.notify_all()


# --------------------------------------------------------------------------- ordered helper work

_HELPER = threading.local()


def _helpers(requests):
    with requests._lock:
        pool = getattr(requests, "_item_helpers", None)
        if pool is None:
            import weakref
            from concurrent.futures import ThreadPoolExecutor
            pool = requests._item_helpers = ThreadPoolExecutor(
                max_workers=max(1, requests.workers), thread_name_prefix="aws-item")
            weakref.finalize(requests, pool.shutdown, wait=False)
        return pool


def parallel_enabled(requests):
    return (getattr(requests, "max_calls", None) is None and getattr(requests, "workers", 1) > 1
            and not getattr(_HELPER, "active", False) and hasattr(requests, "_lock"))


def run_all(requests, tasks, *, stop_on_error=False):
    """Run independent zero-argument ``tasks`` with caller-runs helpers.

    Returns ``[(ok, value_or_exception), ...]`` in task order. The caller
    thread works through the same queue, so progress never depends on a free
    helper; helper threads never start nested helper work.
    """
    tasks = list(tasks)
    results = [None] * len(tasks)
    if len(tasks) < 2 or not parallel_enabled(requests):
        for index, task in enumerate(tasks):
            try:
                results[index] = (True, task())
            except Exception as exc:
                results[index] = (False, exc)
                if stop_on_error:
                    return results[:index + 1]
        return results
    lock = threading.Lock()
    done = threading.Condition(lock)
    state = {"next": 0, "active": 0}

    def drain(helper):
        if helper:
            _HELPER.active = True
        try:
            while True:
                with lock:
                    index = state["next"]
                    if index >= len(tasks):
                        return
                    state["next"] += 1
                    state["active"] += 1
                try:
                    results[index] = (True, tasks[index]())
                except Exception as exc:
                    results[index] = (False, exc)
                finally:
                    with lock:
                        state["active"] -= 1
                        done.notify_all()
        finally:
            if helper:
                _HELPER.active = False
    pool = _helpers(requests)
    from contextvars import copy_context
    for _ in range(min(len(tasks) - 1, max(1, requests.workers) - 1)):
        context = copy_context()
        pool.submit(context.run, drain, True)
    drain(False)
    with lock:
        while state["active"] or state["next"] < len(tasks):
            done.wait()
    return results


def ordered_map(requests, items, function):
    """``[function(item) for item in items]`` with concurrent item work.

    Results keep input order. The first failing item (in input order) raises
    its exception, exactly where the serial comprehension would have stopped.
    """
    outcomes = run_all(requests, [lambda item=item: function(item) for item in items], stop_on_error=True)
    output = []
    for ok, value in outcomes:
        if not ok:
            raise value
        output.append(value)
    return output


def warm(requests, tasks):
    """Run read-only tasks concurrently only to fill the scan read caches."""
    if len(tasks) < 2 or not parallel_enabled(requests):
        return
    run_all(requests, tasks)


# --------------------------------------------------------------------------- batch detail seeding

# Single-identifier detail reads that AWS also answers in batches of 100.
# (service, operation): (argument, list member, not-found member)
BATCH_DETAILS = {
    ("codebuild", "batch_get_builds"): ("ids", "builds", "buildsNotFound"),
    ("codebuild", "batch_get_build_batches"): ("ids", "buildBatches", "buildBatchesNotFound"),
    ("codebuild", "batch_get_sandboxes"): ("ids", "sandboxes", "sandboxesNotFound"),
    ("codebuild", "batch_get_fleets"): ("names", "fleets", "fleetsNotFound"),
}
BATCH_SIZE = 100


def seed_batch_details(requests, session, service, region, operation, values):
    """Read single-identifier batch details in chunks of 100 and seed the
    native read cache with the exact per-identifier answers.

    Each later ``operation(argument=[value])`` read finds its own response:
    the one matching row (or the not-found marker), as a single-identifier
    request would have returned it. Identifiers without one unambiguous
    answer, and any failed chunk, are left for the ordinary per-item read.
    """
    spec = BATCH_DETAILS.get((service, operation))
    if spec is None or getattr(requests, "max_calls", None) is not None:
        return 0
    argument, member, missing = spec
    values = list(dict.fromkeys(v for v in values if isinstance(v, str) and v))
    if len(values) < 2:
        return 0
    root = wrapper_root(session) or session
    cache = getattr(requests, "raw_reads", None)
    try:
        client = requests.client(root, service, region)
    except Exception:
        return 0
    native = getattr(client, "_peaso_native_call", None)
    if cache is None or native is None or getattr(client, "_peaso_shared_reads", None) is not cache or stubbed(client):
        return 0
    model = client.meta.service_model
    from botocore import xform_name
    api_name = next((name for name in model.operation_names if xform_name(name) == operation), None)
    if api_name is None:
        return 0
    seeded = 0
    for offset in range(0, len(values), BATCH_SIZE):
        chunk = values[offset:offset + BATCH_SIZE]
        try:
            requests.check_deadline()
            with requests._lock:
                requests.calls += 1
            # Batch prefetch bypasses Requests.call, so share its exact native
            # read through the same scan-local, bounded single-flight cache.
            # The cache never retains throttles, 429s or server errors.
            batch_args = {argument: chunk}
            key = cache._key(client, id(root), api_name, batch_args)
            response = cache._read(key, lambda: native(api_name, batch_args)) if key is not None else native(api_name, batch_args)
        except Exception:
            return seeded
        rows = response.get(member) if isinstance(response, dict) else None
        absent = response.get(missing) if isinstance(response, dict) else None
        if not isinstance(rows, list) or (absent is not None and not isinstance(absent, list)):
            return seeded
        absent = set(v for v in (absent or []) if isinstance(v, str))
        metadata = response.get("ResponseMetadata")
        for value in chunk:
            matches = [row for row in rows if isinstance(row, dict)
                       and value in (row.get("id"), row.get("arn"), row.get("name"))]
            if len(matches) == 1 and value not in absent:
                single = {member: [matches[0]], missing: []}
            elif not matches and value in absent:
                single = {member: [], missing: [value]}
            else:
                continue
            if metadata is not None:
                single["ResponseMetadata"] = metadata
            key = (id(root), client.meta.endpoint_url, model.service_name, api_name,
                   json.dumps({argument: [value]}, sort_keys=True, default=_normal))
            if cache.seed(key, single):
                seeded += 1
    return seeded


ACTIVITY_READERS = 4


def ordered_reads(requests, names, read, workers=ACTIVITY_READERS):
    """``[read(name) for name in names]`` on a few dedicated threads.

    For long, rate-limited chains (CloudTrail LookupEvents is paced at 2 TPS
    per account and Region inside ``Requests.call``). A handful of readers
    keeps that budget busy while each request waits on network latency.
    Dedicated threads keep minutes-long chains off the shared helper pool.
    A global call cap keeps the serial admission order.
    """
    names = list(names)
    if len(names) < 2 or getattr(requests, "max_calls", None) is not None or workers <= 1:
        return [read(name) for name in names]
    from concurrent.futures import ThreadPoolExecutor
    from contextvars import copy_context
    with ThreadPoolExecutor(max_workers=min(workers, len(names)), thread_name_prefix="aws-activity-read") as pool:
        futures = [pool.submit(copy_context().run, read, name) for name in names]
        return [future.result() for future in futures]


def prefetch_details(requests, session, service, region, plan, context, listed, arguments_for, details):
    """Fill the scan caches for a network plan's per-resource detail reads.

    Batch-capable single-identifier details are read 100 identifiers at a
    time; other details are read concurrently. The plan's own serial loop
    then reads every detail exactly as before, from the caches.
    """
    detail = plan['detail']
    calls = []
    for item in listed:
        if isinstance(item, str) and item:
            item = {'Item': item}
        if not isinstance(item, dict) or any(item.get(key) != value for key, value in plan.get('match', {}).items()):
            continue
        try:
            calls.append(arguments_for(detail, context | item))
        except ValueError:
            continue
    if len(calls) < 2 or not parallel_enabled(requests):
        return
    spec = BATCH_DETAILS.get((service, detail['operation']))
    if spec is not None and not detail.get('tokens') and all(
            set(call) == {spec[0]} and isinstance(call[spec[0]], list) and len(call[spec[0]]) == 1 for call in calls):
        seed_batch_details(requests, session, service, region, detail['operation'], [call[spec[0]][0] for call in calls])
    warm(requests, [lambda call=call: details(requests, session, service, region, detail, call) for call in calls])


# --------------------------------------------------------------------------- item-wise extension enrichers

# Extension enrichers reviewed to be item-wise: each output row depends only
# on its own input row, so ``enrich(items) == sum(enrich([item]) ...)``. The
# factories build one per-row loop (or comprehension) per kind.
ITEM_WISE = frozenset({
    ("peaso.collectors.aws_facts_swc", "_each.<locals>.enrich"),
    ("peaso.collectors.aws_b_services", "_enricher.<locals>.enrich"),
    ("peaso.collectors.aws_facts_cb_ca", "_container_enricher.<locals>.enrich"),
    ("peaso.collectors.aws_facts_cb_ca", "_merge_enricher.<locals>.enrich"),
    ("peaso.collectors.aws_facts_cb_ca", "_bucket_website"),
    ("peaso.collectors.aws_network_catalog", "detail_enricher.<locals>.enrich"),
    ("peaso.collectors.aws_network_inventory", "enrich_network_detail.<locals>.enrich"),
    ("peaso.collectors.aws_facts_compute_edge", "_lambda_variable_count"),
    ("peaso.collectors.aws_facts_ext", "_lambda_function"),
    ("peaso.collectors.aws_s3_object_acl_review_20261019", "enrich"),
})


def item_wise(module_name, enricher):
    """Run a reviewed item-wise enricher concurrently per resource."""
    if (module_name, getattr(enricher, "__qualname__", None)) not in ITEM_WISE \
            or getattr(enricher, "__module__", None) != module_name:
        return enricher

    def enrich(requests, session, region, items):
        if not isinstance(items, list) or len(items) < 2:
            return enricher(requests, session, region, items)
        # Always one row per call, also when serial, so the output never
        # depends on the concurrency mode. (The network catalog detail
        # enricher reuses its identity-field name as an inner loop variable;
        # one row per call keeps every row reading its own identity field.)
        parts = ordered_map(requests, items, lambda item: enricher(requests, session, region, [item]))
        return [row for part in parts for row in part]
    enrich.item_wise_enricher = enricher
    return enrich
