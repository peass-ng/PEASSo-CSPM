"""Complete IAM service use evidence with the scan's own authenticated contexts."""
from contextlib import contextmanager
from contextvars import ContextVar, copy_context
from concurrent.futures import ThreadPoolExecutor
import copy
import time
import threading

from peaso.snapshot import make_snapshot

_active = ContextVar("aws_iam_usage_contexts", default=None)
_IAM_KINDS = frozenset({"iam_user", "iam_group", "iam_role", "iam_policy"})


class _UsageContexts(dict):
    """Own at most two account jobs until every IAM consumer has joined."""
    def __init__(self):
        super().__init__()
        self.lock = threading.RLock()
        self.pool = None
        self.futures = {}
        self.late_retried = set()
        self.closed = False

    def close(self):
        with self.lock:
            self.closed = True
            pool, self.pool = self.pool, None
        if pool is not None:
            pool.shutdown(wait=True, cancel_futures=True)
        self.futures.clear()


def _overlap_allowed(contexts):
    if not isinstance(contexts, _UsageContexts) or not contexts:
        return False
    return (len({id(session) for _, session, _ in contexts.values()}) == len(contexts)
        and all(getattr(requests, name, None) is None
                for requests, _, _ in contexts.values()
                for name in ("max_calls", "max_pages", "max_items")))


def start_account_usage(requests, session, identity, region, seed):
    """Start only from a completed native IAM future under captured authority.

    The caller registers all authenticated account contexts before scheduling.
    Explicit global limits and shared sessions keep the original serial path.
    """
    contexts = _active.get()
    account = identity.get("Account") if isinstance(identity, dict) else None
    if (not _overlap_allowed(contexts) or account not in contexts
            or contexts[account] != (requests, session, region)):
        return False
    from .aws import _safe
    collections = [{"type": kind, "scope": account + "/global", "service": "iam",
                    "status": read.status, "items": _safe(read.items)}
                   for kind, read in seed.items() if kind in _IAM_KINDS]
    if not any(c["items"] and c["status"] in {"collected", "partial"} for c in collections):
        return False
    def run():
        snapshot = make_snapshot("aws", [account + "/global"], collections,
            created_at=requests.observed_at.isoformat())
        return enrich_snapshot(snapshot, {account: (requests, session, region)}, retry_pending=True)
    with contexts.lock:
        if contexts.closed or account in contexts.futures:
            return False
        if contexts.pool is None:
            contexts.pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix="aws-iam-early")
        contexts.futures[account] = contexts.pool.submit(copy_context().run, run)
    return True


def join_account_usage(collections):
    """Merge only proven report fields into the same native scope and ARN.

    Final snapshot assembly still owns validation, privacy and publication.
    Joining all futures before propagating errors prevents background IAM work
    escaping collector cleanup, cancellation or an unsuccessful account.
    """
    contexts = _active.get()
    if not isinstance(contexts, _UsageContexts):
        return
    with contexts.lock:
        futures = list(contexts.futures.items())
    completed, error = [], None
    for account, future in futures:
        try:
            completed.append((account, future.result()))
        except BaseException as exc:
            if error is None:
                error = exc
    if error is not None:
        raise error
    reports = {}
    for account, snapshot in completed:
        for collection in snapshot["collections"]:
            if collection["scope"] != account + "/global" or collection["type"] not in _IAM_KINDS:
                continue
            for item in collection["items"]:
                arn = item.get("Arn")
                if isinstance(arn, str) and arn.split(":")[4:5] == [account]:
                    reports[(collection["type"], collection["scope"], arn)] = item
    for collection in collections:
        for item in collection.get("items", []) if collection.get("type") in _IAM_KINDS else ():
            source = reports.get((collection["type"], collection["scope"], item.get("Arn")))
            if source is None:
                continue
            for name in ("ServicesLastAccessed", "ServicesLastAccessedStatus"):
                if name in source:
                    item[name] = copy.deepcopy(source[name])
    with contexts.lock:
        for account, future in futures:
            if contexts.futures.get(account) is future:
                del contexts.futures[account]


def _refresh_request_counters(metadata, contexts):
    """Include report jobs completed after the provider assembled its metadata."""
    if not contexts:
        return
    requests = {id(value[0]): value[0] for value in contexts.values()}.values()
    for name in ("calls", "cache_hits"):
        if all(hasattr(value, name) for value in requests):
            metadata[name] = sum(getattr(value, name) for value in requests)
    generations = metadata.get("authorized_evidence_generation")
    if isinstance(generations, dict):
        for key, attribute in (("iam_credential_report", "iam_credential_report_generation_requested"),
                               ("iam_service_last_accessed_report", "iam_service_access_reports_requested")):
            if all(hasattr(value, attribute) for value in requests):
                generations[key] = any(getattr(value, attribute) for value in requests)
        for key, attribute in (("generation_requests", "evidence_generations"),
                               ("service_last_accessed_generation_requests", "service_last_accessed_generations")):
            if all(hasattr(value, attribute) for value in requests):
                generations[key] = sum(getattr(value, attribute) for value in requests)


@contextmanager
def capture_contexts(enabled=True):
    contexts = _UsageContexts() if enabled else None
    token = _active.set(contexts)
    try:
        yield contexts
    finally:
        try:
            if contexts is not None:
                contexts.close()
        finally:
            _active.reset(token)


def register_context(requests, session, identity, regions):
    contexts = _active.get()
    account = identity.get("Account") if isinstance(identity, dict) else None
    if contexts is not None and account and regions:
        contexts.setdefault(account, (requests, session, regions[0]))
        requests.iam_usage_scan = True
    return contexts is not None


def _pending_report(requests, session, region, arn, state):
    """Only retry a native pending job, never denial, FAILED or malformed data."""
    if (state.get("collection_status") not in {"timeout", "unknown"}
            or state.get("granularity") != "ACTION_LEVEL"
            or state.get("principal_arn") != arn):
        return False
    code = (state.get("error") or {}).get("code")
    if code == "service_report_batch_timeout":
        # This exact native branch occurs before any generation attempt.
        return True
    if code not in {"service_report_poll_timeout", "service_report_poll_limit",
                    "service_report_page_timeout", "read_failed", "Throttling",
                    "ThrottlingException", "TooManyRequestsException",
                    "RequestLimitExceeded", "ServiceUnavailable", "ServiceUnavailableException",
                    "InternalError", "InternalServerError", "InternalServerException"}:
        return False
    with requests._lock:
        job = getattr(requests, "_sla_principal_jobs", {}).get(
            (id(session), region, "ACTION_LEVEL", arn))
        return job is not None and getattr(requests, "_sla_job_bindings", {}).get(
            (id(session), region, job)) == arn


def enrich_snapshot(snapshot, contexts, *, retry_pending=False):
    from .aws_iam_report_native import service_reports

    if contexts is None:
        return snapshot
    collections = [copy.deepcopy(collection) if collection.get("type") in _IAM_KINDS else collection
                   for collection in snapshot["collections"]]
    by_account = {}
    for collection in collections:
        if collection.get("type") not in {"iam_user", "iam_group", "iam_role", "iam_policy"}:
            continue
        if collection.get("status") not in {"collected", "partial"}:
            continue
        for item in collection.get("items", []):
            arn = item.get("Arn") if isinstance(item, dict) else None
            if not isinstance(arn, str) or ":iam::" not in arn:
                continue
            account = arn.split(":")[4]
            if account not in contexts:
                continue
            if collection["type"] == "iam_policy" and not item.get("AttachmentCount", 0):
                continue
            state = item.get("ServicesLastAccessedStatus", {})
            deferred = state.get("reason") == "identity_policies_cannot_allow_namespaces" or (
                state.get("error") or {}).get("code") == "service_last_accessed_generation_disabled"
            recover = False
            if state and (retry_pending or isinstance(contexts, _UsageContexts)):
                requests, session, region = contexts[account]
                key = (id(session), region, arn)
                spent = isinstance(contexts, _UsageContexts) and key in contexts.late_retried
                recover = not spent and _pending_report(requests, session, region, arn, state)
                if recover and isinstance(contexts, _UsageContexts):
                    contexts.late_retried.add(key)
            if state and not deferred and not recover and not (
                    state.get("collection_status") == "collected"
                    and state.get("granularity") != "ACTION_LEVEL"):
                continue
            by_account.setdefault(account, {}).setdefault(arn, []).append(item)
    def report_for(account, items):
        requests, session, region = contexts[account]
        requests.iam_report_generation_requested = True
        requests.iam_service_access_reports_requested = True
        requests.service_last_accessed_wait = max(requests.service_last_accessed_wait, 600)
        requests.service_last_accessed_workers = max(requests.service_last_accessed_workers, 8)
        with requests._lock:
            deadlines = getattr(requests, "_sla_batch_deadlines", None)
            if deadlines is None:
                deadlines = requests._sla_batch_deadlines = {}
            deadlines[(id(session), region)] = time.monotonic() + requests.service_last_accessed_wait
        return service_reports(requests, session, region, items.keys(), granularity="ACTION_LEVEL")

    accounts = list(by_account)
    # Requests keeps global call/page/resource limits, while its IAM report
    # pacing and job bindings are keyed by session. Preserve admission order
    # whenever a limit is explicit or two accounts share a session.
    independent = (len(accounts) > 1
        and len({id(contexts[account][1]) for account in accounts}) == len(accounts)
        and all(getattr(contexts[account][0], limit, None) is None
                for account in accounts for limit in ("max_calls", "max_pages", "max_items")))

    def apply_reports(account, account_reports):
        items = by_account[account]
        for arn, (rows, status) in account_reports.items():
            for item in items[arn]:
                if rows is not None:
                    item["ServicesLastAccessed"] = rows
                item["ServicesLastAccessedStatus"] = status

    if independent:
        with ThreadPoolExecutor(max_workers=2, thread_name_prefix="aws-iam-usage") as pool:
            futures = [pool.submit(copy_context().run, report_for, account, by_account[account])
                       for account in accounts]
            # Apply in stable account order and release each large report once
            # used. Executor exit joins every account even if one raises.
            for index, account in enumerate(accounts):
                apply_reports(account, futures[index].result())
                futures[index] = None
    else:
        for account in accounts:
            apply_reports(account, report_for(account, by_account[account]))
    metadata = copy.deepcopy(snapshot.get("metadata", {}))
    _refresh_request_counters(metadata, contexts)
    if not by_account and metadata == snapshot.get("metadata", {}):
        return snapshot
    return make_snapshot(snapshot["provider"], snapshot["scopes"], collections,
                         created_at=snapshot["created_at"], metadata=metadata)
