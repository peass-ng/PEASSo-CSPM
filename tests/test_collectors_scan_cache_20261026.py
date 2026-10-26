"""Per-scan response cache for the GCP and Azure read transports."""
import copy
import io
import json
import threading
import time
from types import SimpleNamespace
from urllib.error import HTTPError

import pytest

from peaso.collectors import azure, gcp, scan_cache


# --- generic cache -----------------------------------------------------------

def test_raw_cache_single_flight_shares_one_load_between_concurrent_callers():
    cache = scan_cache.RawResponseCache()
    gate, calls = threading.Event(), []

    def load():
        calls.append(1)
        gate.wait(5)
        return b'{"value": []}'

    results = []
    threads = [threading.Thread(target=lambda: results.append(cache.fetch("k", load))) for _ in range(8)]
    for thread in threads:
        thread.start()
    deadline = time.monotonic() + 5
    while cache.stats()["coalesced"] < 7 and time.monotonic() < deadline:
        time.sleep(0.01)
    gate.set()
    for thread in threads:
        thread.join(5)
    assert calls == [1]
    assert results == [b'{"value": []}'] * 8
    assert cache.fetch("k", lambda: pytest.fail("cached")) == b'{"value": []}'


def test_raw_cache_never_retains_a_failure():
    cache = scan_cache.RawResponseCache()
    attempts = []

    def failing():
        attempts.append(1)
        raise HTTPError("https://management.azure.com/x", 429, "throttled", {}, None)

    for _ in range(2):
        with pytest.raises(HTTPError):
            cache.fetch("k", failing)
    assert len(attempts) == 2
    assert cache.fetch("k", lambda: b"{}") == b"{}"


def test_raw_cache_is_memory_bounded_least_recently_used_first():
    cache = scan_cache.RawResponseCache(max_bytes=10, max_entry_bytes=6)
    cache.fetch("a", lambda: b"aaaa")
    cache.fetch("b", lambda: b"bbbb")
    cache.fetch("a", lambda: pytest.fail("a is cached"))  # refresh a
    cache.fetch("c", lambda: b"cccc")  # evicts b, the least recently used
    assert set(cache.entries) == {"a", "c"} and cache.bytes == 8
    cache.fetch("big", lambda: b"x" * 7)  # larger than one entry may be
    assert "big" not in cache.entries and cache.bytes == 8


def test_caches_reset_in_forked_child():
    raw = scan_cache.RawResponseCache()
    raw.fetch("k", lambda: b"{}")
    class Owner:
        lock = None
    owner = Owner()
    owner.lock = threading.Lock()
    entries = scan_cache.BoundedEntries(owner=owner)
    entry = {"event": threading.Event(), "data": {}}
    entries["k"] = entry
    entries.admit("k", entry, 10)
    held = owner.lock
    held.acquire()
    scan_cache._reset_in_child()
    assert not raw.entries and raw.bytes == 0 and not raw.flights
    assert not entries and entries.bytes == 0
    assert owner.lock is not held and owner.lock.acquire(blocking=False)


def test_bounded_entries_never_evict_in_flight_entries():
    entries = scan_cache.BoundedEntries(max_bytes=10, max_entry_bytes=10)
    pending = {"event": threading.Event()}
    entries["pending"] = pending
    for name in ("a", "b", "c"):
        entry = {"event": threading.Event(), "data": {}}
        entries[name] = entry
        entries.admit(name, entry, 4)
    assert "pending" in entries and list(entries.sizes) == ["b", "c"] and entries.bytes == 8
    del entries["b"]
    assert entries.bytes == 4


# --- GCP transport -------------------------------------------------------------

class Response:
    def __init__(self, status=200, data=None):
        self.status_code = status
        self.data = data if data is not None else {"items": []}
        self.content = json.dumps(self.data).encode()
        self.headers = {}

    def json(self):
        return copy.deepcopy(self.data)


def gcp_transport(monkeypatch, responses, **options):
    calls = []

    def request(method, url, **kwargs):
        calls.append({"method": method, "url": url, **kwargs})
        value = responses[min(len(calls) - 1, len(responses) - 1)]
        if isinstance(value, Exception):
            raise value
        return value
    session = SimpleNamespace(request=request, close=lambda: None)
    transport = gcp.Transport(SimpleNamespace(headers=lambda: {"Authorization": "Bearer t"}, close=lambda: None),
                              options, sleep=lambda _: None)
    monkeypatch.setattr(transport, "_session", lambda: session)
    return transport, calls


URL = "https://cloudasset.googleapis.com/v1/projects/p-one/assets"


def test_gcp_absent_and_empty_params_share_one_wire_read(monkeypatch):
    transport, calls = gcp_transport(monkeypatch, [Response(200, {"items": [{"name": "a"}]})])
    first = transport.request("GET", URL, scope="projects/p-one")
    second = transport.request("GET", URL, params={}, scope="projects/p-one")
    assert first == second and len(calls) == 1


@pytest.mark.parametrize("status", [429, 500, 503])
def test_gcp_throttling_and_server_errors_are_not_cached(monkeypatch, status):
    transport, calls = gcp_transport(monkeypatch, [Response(status, {}), Response(200, {"items": []})], retries=0)
    with pytest.raises(gcp.ReadError):
        transport.request("GET", URL, scope="projects/p-one")
    value, _ = transport.request("GET", URL, scope="projects/p-one")
    assert value == {"items": []} and len(calls) == 2


def test_gcp_transport_errors_are_not_cached(monkeypatch):
    transport, calls = gcp_transport(monkeypatch, [OSError("reset"), Response(200, {"items": []})], retries=0)
    with pytest.raises(gcp.ReadError) as caught:
        transport.request("GET", URL, scope="projects/p-one")
    assert caught.value.error["code"] == "network_error"
    assert transport.request("GET", URL, scope="projects/p-one")[0] == {"items": []}
    assert len(calls) == 2


@pytest.mark.parametrize("status", [403, 404])
def test_gcp_deterministic_denials_are_cached_for_the_scan(monkeypatch, status):
    transport, calls = gcp_transport(monkeypatch, [Response(status, {}), Response(200, {"items": []})], retries=0)
    for _ in range(2):
        with pytest.raises(gcp.ReadError) as caught:
            transport.request("GET", URL, scope="projects/p-one")
        assert caught.value.error["http_status"] == status
    assert len(calls) == 1


def test_gcp_cache_is_bounded_and_rereads_evicted_pages(monkeypatch):
    big = {"items": [{"name": "x" * 200}]}
    entry = len(Response(200, big).content) * scan_cache.PARSED_OBJECT_FACTOR
    limit = entry * 2 + entry // 2  # two settled pages fit, a third evicts the oldest
    transport, calls = gcp_transport(monkeypatch, [Response(200, big)], response_cache_max_bytes=limit)
    for page in ("a", "b", "c"):
        transport.request("GET", URL, params={"pageToken": page}, scope="projects/p-one")
    assert len(calls) == 3
    assert transport.cache.bytes <= limit and transport.cache.evictions == 1
    transport.request("GET", URL, params={"pageToken": "a"}, scope="projects/p-one")  # evicted, read again
    transport.request("GET", URL, params={"pageToken": "c"}, scope="projects/p-one")  # still cached
    assert len(calls) == 4


def test_gcp_transport_caches_are_per_transport(monkeypatch):
    first, first_calls = gcp_transport(monkeypatch, [Response(200, {"items": []})])
    second, second_calls = gcp_transport(monkeypatch, [Response(200, {"items": []})])
    first.request("GET", URL, scope="projects/p-one")
    second.request("GET", URL, scope="projects/p-one")
    assert len(first_calls) == 1 and len(second_calls) == 1


# --- Azure transport -----------------------------------------------------------

class AzureResponse(io.BytesIO):
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def azure_transport(monkeypatch, responder):
    calls = []

    class Opener:
        def open(self, request, timeout=None):
            calls.append((request.get_method(), request.full_url, request.data))
            value = responder(len(calls), request)
            if isinstance(value, Exception):
                raise value
            return AzureResponse(json.dumps(value).encode())
    monkeypatch.setattr(azure, "build_opener", lambda *handlers: Opener())
    transport = azure.AzureTransport({"method": "token", "arm_token": "x", "graph_token": "x"})
    return transport, calls


ARM_URL = azure.ARM + "/subscriptions/00000000-0000-0000-0000-000000000001?api-version=2022-12-01"


def test_azure_identical_reads_hit_the_wire_once_and_return_independent_values(monkeypatch):
    transport, calls = azure_transport(monkeypatch, lambda n, r: {"id": "/subscriptions/x", "tags": {"a": "b"}})
    first = transport.request(ARM_URL)
    first["tags"]["a"] = "mutated"
    second = transport.request(ARM_URL)
    assert second == {"id": "/subscriptions/x", "tags": {"a": "b"}}
    assert len(calls) == 1
    transport.request(azure.GRAPH + "/v1.0/organization", audience=azure.GRAPH)
    assert len(calls) == 2


def test_azure_resource_graph_query_post_is_cached_by_body(monkeypatch):
    transport, calls = azure_transport(monkeypatch, lambda n, r: {"data": [], "count": 0})
    url = azure.ARM + "/providers/Microsoft.ResourceGraph/resources?api-version=2022-10-01"
    body = {"subscriptions": ["00000000-0000-0000-0000-000000000001"], "query": "Resources | project id"}
    transport.request(url, body=body)
    transport.request(url, body=dict(body))
    transport.request(url, body={**body, "query": "Resources | project name"})
    assert len(calls) == 2


@pytest.mark.parametrize("status", [429, 500, 503])
def test_azure_throttling_and_server_errors_are_not_cached(monkeypatch, status):
    def responder(n, request):
        return HTTPError(request.full_url, status, "x", {}, None) if n == 1 else {"id": "x"}
    transport, calls = azure_transport(monkeypatch, responder)
    with pytest.raises(HTTPError):
        transport.request(ARM_URL)
    assert transport.request(ARM_URL) == {"id": "x"}
    assert len(calls) == 2


def test_azure_cached_body_still_honours_a_caller_byte_limit(monkeypatch):
    transport, calls = azure_transport(monkeypatch, lambda n, r: {"value": ["x" * 100]})
    transport.request(ARM_URL)
    with pytest.raises(azure.AzureReadError) as caught:
        transport.request(ARM_URL, max_response_bytes=10)
    assert caught.value.code == "response_too_large" and len(calls) == 1


def test_azure_subject_capture_reads_bypass_the_cache(monkeypatch):
    transport, calls = azure_transport(monkeypatch, lambda n, r: {"id": "x"})
    monkeypatch.setattr("peaso.collectors.azure_disclosure_native.accepted_subject", lambda token, audience: "s")
    transport.request(ARM_URL)
    transport.request(ARM_URL, capture_subject=True)
    assert len(calls) == 2 and transport.disclosure_accepted_subjects == {azure.ARM: "s"}


def test_azure_cache_is_dropped_when_the_scan_transport_closes(monkeypatch):
    transport, calls = azure_transport(monkeypatch, lambda n, r: {"id": "x"})
    transport.request(ARM_URL)
    transport.close()
    transport.request(ARM_URL)
    assert len(calls) == 2


def test_azure_shared_privileged_role_definition_read_is_one_wire_request(monkeypatch):
    # azure_sw18_mfa_native and azure_identity_enforcement_review_20261020 both read this URL.
    transport, calls = azure_transport(monkeypatch, lambda n, r: {"value": [{"id": "x", "isPrivileged": True}]})
    url = azure.GRAPH + "/beta/roleManagement/directory/roleDefinitions?$select=id,isPrivileged"
    first = transport.request(url, audience=azure.GRAPH)
    second = transport.request(url, audience=azure.GRAPH)
    assert first == second and len(calls) == 1


# --- GCP read-ahead for the serial scope_jobs loops ----------------------------------

class RoutedSession:
    """Thread-safe fake session: answers by URL, records every wire request."""

    def __init__(self, latency=0.0, fail=None):
        self.latency, self.fail = latency, fail or {}
        self.lock = threading.Lock()
        self.calls, self.active, self.peak = [], 0, 0

    def request(self, method, url, params=None, json=None, **kwargs):
        with self.lock:
            self.calls.append((method, url, dict(params or {})))
            self.active += 1
            self.peak = max(self.peak, self.active)
        try:
            time.sleep(self.latency)
            if url in self.fail:
                return Response(self.fail[url], {"error": {"code": self.fail[url]}})
            path = url.split("googleapis.com", 1)[1]
            if path.endswith("/denypolicies"):
                attachment = path.split("/")[3]
                return Response(200, {"policies": [{"name": f"policies/{attachment}/denypolicies/d{i}"} for i in range(6)]
                                      + [{"name": f"policies/{attachment}/denypolicies/inline", "rules": []}]})
            if "/denypolicies/" in path:
                return Response(200, {"name": path[len("/v2/"):], "rules": [{"denyRule": {}}]})
            if path.endswith(":getEffectivePolicy"):
                return Response(200, {"name": path[len("/v2/"):].split(":")[0], "spec": {}})
            return Response(404, {})
        finally:
            with self.lock:
                self.active -= 1

    def close(self):
        pass


def routed_transport(monkeypatch, session, **options):
    transport = gcp.Transport(SimpleNamespace(headers=lambda: {"Authorization": "Bearer t"}, close=lambda: None),
                              {"retries": 0, **options}, sleep=lambda _: None)
    monkeypatch.setattr(transport, "_session", lambda: session)
    return transport


def effective_url(scope, constraint):
    return f"https://orgpolicy.googleapis.com/v2/{scope}/policies/{constraint}:getEffectivePolicy"


def serial_effective_loop(transport, scope):
    """The org_policy_effective loop's exact reads: pages(single=True) sends {} params."""
    results = []
    for constraint in gcp.ORG_POLICY_CONSTRAINTS:
        try:
            results.append(transport.request("GET", effective_url(scope, constraint), params={}, scope=scope)[0])
        except gcp.ReadError as exc:
            results.append(("error", exc.error.get("http_status"), bool(getattr(exc, "request_id", None))))
    return results


def test_effective_policy_read_ahead_keeps_requests_and_results_and_overlaps_them(monkeypatch):
    scope = "projects/p-one"
    serial_session, ahead_session = RoutedSession(0.03), RoutedSession(0.03)
    serial = routed_transport(monkeypatch, serial_session, prefetch_workers=0)
    started = time.monotonic()
    expected = serial_effective_loop(serial, scope)
    serial_time = time.monotonic() - started
    ahead = routed_transport(monkeypatch, ahead_session)
    started = time.monotonic()
    observed = serial_effective_loop(ahead, scope)
    ahead_time = time.monotonic() - started
    ahead.close()
    assert observed == expected
    assert sorted(ahead_session.calls) == sorted(serial_session.calls)
    assert len(ahead_session.calls) == len(gcp.ORG_POLICY_CONSTRAINTS)
    assert ahead_session.peak > 1 and serial_session.peak == 1
    assert ahead_time < serial_time * 0.6
    assert sorted(e["url"] for e in ahead.evidence) == sorted(e["url"] for e in serial.evidence)


def test_effective_policy_read_ahead_hands_a_transient_failure_to_the_loop_once(monkeypatch):
    scope = "projects/p-one"
    failing = effective_url(scope, gcp.ORG_POLICY_CONSTRAINTS[5])
    session = RoutedSession(0.01, fail={failing: 503})
    transport = routed_transport(monkeypatch, session)
    results = serial_effective_loop(transport, scope)
    assert results[5] == ("error", 503, True)
    assert [call[1] for call in session.calls].count(failing) == 1
    # Not cached for the scan: a later read goes to the wire again.
    with pytest.raises(gcp.ReadError):
        transport.request("GET", failing, params={}, scope=scope)
    assert [call[1] for call in session.calls].count(failing) == 2
    transport.close()


def test_effective_policy_read_ahead_needs_the_loop_start_on_the_same_project(monkeypatch):
    session = RoutedSession()
    transport = routed_transport(monkeypatch, session)
    transport.request("GET", effective_url("projects/p-one", gcp.ORG_POLICY_CONSTRAINTS[3]), params={}, scope="projects/p-one")
    transport.request("GET", effective_url("projects/p-two", gcp.ORG_POLICY_CONSTRAINTS[0]), params={}, scope="projects/other")
    transport.close()
    assert len(session.calls) == 2


def test_deny_policy_read_ahead_reads_each_detail_once_concurrently(monkeypatch):
    scope = "projects/p-one"
    attachment = "cloudresourcemanager.googleapis.com%2Fprojects%2Fp-one"
    session = RoutedSession(0.03)
    transport = routed_transport(monkeypatch, session)
    listing, _ = transport.request("GET", f"https://iam.googleapis.com/v2/policies/{attachment}/denypolicies",
                                   params={"pageSize": 1000}, scope=scope)
    details = [transport.request("GET", f"https://iam.googleapis.com/v2/{item['name']}", scope=scope)[0]
               for item in listing["policies"] if "rules" not in item]
    transport.close()
    urls = [call[1] for call in session.calls]
    assert len(details) == 6 and len(urls) == 7 and len(set(urls)) == 7
    assert not any(url.endswith("/inline") for url in urls)  # inline rules are never hydrated
    assert session.peak > 1


def _collection_shape(result, kind):
    import re as _re
    rows = [c for c in result["collections"] if c["type"] == kind]
    return _re.sub(r"request-[0-9]+|[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.+]+", "X", json.dumps(
        sorted(rows, key=lambda c: c["scope"]), sort_keys=True))


@pytest.mark.parametrize("kind", ["iam_deny_policy", "org_policy_effective"])
def test_read_ahead_leaves_collector_output_identical(monkeypatch, kind):
    shapes, wires = [], []
    for workers in (0, 8):
        session = RoutedSession(0.005, fail={effective_url("projects/p-one", gcp.ORG_POLICY_CONSTRAINTS[2]): 503})
        options = {"inventories": [kind], "retries": 0, "prefetch_workers": workers}
        transport = routed_transport(monkeypatch, session, **options)
        collector = gcp.GCPCollector({"provider": "gcp", "scopes": ["projects/p-one", "projects/p-two"], "options": options},
                                     transport=transport)
        shapes.append(_collection_shape(collector.collect(), kind))
        transport.close()
        wires.append(sorted(session.calls))
    assert shapes[0] == shapes[1]
    assert wires[0] == wires[1]


@pytest.mark.parametrize("limit", [0, True, -1, 20000001, 1.5])
def test_azure_cached_body_still_rejects_an_invalid_byte_limit(monkeypatch, limit):
    transport, calls = azure_transport(monkeypatch, lambda n, r: {"id": "x"})
    transport.request(ARM_URL)
    with pytest.raises(ValueError, match="invalid response byte limit"):
        transport.request(ARM_URL, max_response_bytes=limit)
    assert len(calls) == 1
