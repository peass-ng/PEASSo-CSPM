"""Azure pooled-transport isolation and parallel-collector parity.

Qualifies the keep-alive pool and bounded fan-out of the Azure native reads:
per-request bearer isolation on one pooled host, proxy CONNECT pool separation
per proxy and proxy credentials, the shared effective-route query budget under
concurrency (same rows as the serial read, cancellation stops workers) and
the parallel identity collectors' denied/partial/unknown and tenant binding.
"""
from __future__ import annotations

import base64
import json
import random
import select
import socket
import threading
import time
from copy import deepcopy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit
from urllib.request import Request

import pytest

from peaso.collectors import azure, azure_effective_routes_native, azure_nsg_ingress_native
from tests.test_azure_collector_keepalive_parallel_20261025 import _Handler, server  # noqa: F401  (fixture)

pytest.importorskip("cryptography")

_SLEEP = time.sleep
SUB = "11111111-1111-1111-1111-111111111111"
SCOPE = "/subscriptions/" + SUB


# --------------------------------------------------------------------------
# Bearer isolation on one pooled host
# --------------------------------------------------------------------------

def _echo_authorization(handler):
    body = json.dumps({"path": handler.path, "authorization": handler.headers.get("Authorization"),
                       "proxy_authorization": handler.headers.get("Proxy-Authorization")}).encode()
    with handler.server.lock:
        handler.server.seen.append((handler.path, dict(handler.headers)))
    time.sleep(random.random() * 0.003)
    handler._send(200, body)


@pytest.fixture
def echo(server, monkeypatch):  # noqa: F811
    monkeypatch.setattr(_Handler, "do_GET", _echo_authorization)
    return server


def _read(base, path, token, timeout=5):
    request = Request(base + path, headers={"Authorization": "Bearer " + token, "Accept": "application/json"}, method="GET")
    with azure._native_open(request, timeout) as response:
        return json.loads(response.read())


def test_two_bearers_interleaved_on_one_pooled_connection_never_mix(echo):
    for index in range(10):
        token = ("tenant-a-token", "tenant-b-token")[index % 2]
        body = _read(echo.base, "/%s/%d" % (token, index), token)
        assert body["authorization"] == "Bearer " + token and body["path"] == "/%s/%d" % (token, index)
    # Both credentials really shared one pooled TLS connection.
    assert echo.connections == 1 and echo.pool.reused == 9
    for path, headers in echo.seen:
        assert headers["Authorization"] == "Bearer " + path.split("/")[1]
        assert list(headers).count("Authorization") == 1


def test_two_bearers_under_concurrency_keep_request_and_response_paired(echo):
    errors = []
    def worker(token, number):
        try:
            for index in range(15):
                path = "/%s/%d/%d" % (token, number, index)
                body = _read(echo.base, path, token)
                # A cross-wired pooled response would carry another request's path or token.
                assert body == {"path": path, "authorization": "Bearer " + token, "proxy_authorization": None}
        except Exception as exc:  # pragma: no cover - reported below
            errors.append(exc)
    threads = [threading.Thread(target=worker, args=(token, n)) for n in range(3) for token in ("tok-a", "tok-b")]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert not errors
    assert len(echo.seen) == 90
    assert all(headers["Authorization"] == "Bearer " + path.split("/")[1] for path, headers in echo.seen)
    assert echo.connections <= 6 and echo.pool.reused >= 84


def test_failed_request_does_not_leave_its_bearer_on_the_pooled_connection(echo, monkeypatch):
    assert _read(echo.base, "/tok-a/1", "tok-a")["authorization"] == "Bearer tok-a"
    request = Request(echo.base + "/tok-b/2", headers={"Authorization": "Bearer tok-b"}, method="GET")
    with azure._native_open(request, 5) as response:
        response.read(4)  # abandoned partial body: never reused
    assert _read(echo.base, "/tok-a/3", "tok-a")["authorization"] == "Bearer tok-a"
    assert [headers["Authorization"] for _, headers in echo.seen] == ["Bearer tok-a", "Bearer tok-b", "Bearer tok-a"]
    assert echo.connections == 2


# --------------------------------------------------------------------------
# Proxy CONNECT pool separation
# --------------------------------------------------------------------------

class _ConnectProxy(threading.Thread):
    """Minimal recording CONNECT proxy that tunnels to one local origin."""
    def __init__(self, origin_port):
        super().__init__(daemon=True)
        self.origin_port = origin_port
        self.listener = socket.create_server(("127.0.0.1", 0))
        self.port = self.listener.getsockname()[1]
        self.connects, self.lock, self.stopped = [], threading.Lock(), False

    def run(self):
        while not self.stopped:
            try:
                client, _ = self.listener.accept()
            except OSError:
                return
            threading.Thread(target=self.tunnel, args=(client,), daemon=True).start()

    def tunnel(self, client):
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = client.recv(4096)
            if not chunk:
                client.close()
                return
            data += chunk
        head = data.split(b"\r\n\r\n", 1)[0].decode("latin-1").split("\r\n")
        headers = dict(line.split(": ", 1) for line in head[1:] if ": " in line)
        with self.lock:
            self.connects.append((head[0], headers.get("Proxy-Authorization")))
        if not head[0].startswith("CONNECT localhost:%d " % self.origin_port):
            client.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
            client.close()
            return
        upstream = socket.create_connection(("127.0.0.1", self.origin_port))
        client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        sockets = [client, upstream]
        try:
            while True:
                readable, _, _ = select.select(sockets, [], [], 5)
                if not readable:
                    return
                for sock in readable:
                    chunk = sock.recv(65536)
                    if not chunk:
                        return
                    (upstream if sock is client else client).sendall(chunk)
        except OSError:
            return
        finally:
            client.close()
            upstream.close()

    def stop(self):
        self.stopped = True
        self.listener.close()


@pytest.fixture
def proxies(echo, monkeypatch):
    for name in ("NO_PROXY", "no_proxy", "HTTP_PROXY", "http_proxy"):
        monkeypatch.delenv(name, raising=False)
    port = int(echo.base.rsplit(":", 1)[1])
    started = [_ConnectProxy(port), _ConnectProxy(port)]
    for proxy in started:
        proxy.start()
    yield started
    for proxy in started:
        proxy.stop()


def _basic(user, password):
    return "Basic " + base64.b64encode(("%s:%s" % (user, password)).encode()).decode()


def test_proxy_connect_pools_are_separated_per_proxy_and_proxy_credentials(echo, proxies, monkeypatch):
    one, two = proxies
    def via(proxy, credentials, path, token="tok"):
        monkeypatch.setenv("HTTPS_PROXY", "http://%s127.0.0.1:%d" % (credentials + "@" if credentials else "", proxy.port))
        return _read(echo.base, path, token)

    # Proxy credentials go to the proxy CONNECT only, never to the origin.
    assert via(one, "alice:pw1", "/p1/a")["proxy_authorization"] is None
    assert via(one, "alice:pw1", "/p1/b")["proxy_authorization"] is None
    assert one.connects == [("CONNECT localhost:%d HTTP/1.1" % int(echo.base.rsplit(":", 1)[1]), _basic("alice", "pw1"))]
    # Different proxy credentials on the same proxy never reuse alice's tunnel.
    via(one, "bob:pw2", "/p1/c")
    via(one, "bob:pw2", "/p1/d")
    assert [auth for _, auth in one.connects] == [_basic("alice", "pw1"), _basic("bob", "pw2")]
    # Back to alice: her idle tunnel is reused, no new CONNECT.
    via(one, "alice:pw1", "/p1/e")
    assert len(one.connects) == 2
    # A different proxy endpoint with the same credentials is its own pool.
    via(two, "alice:pw1", "/p2/a")
    assert [auth for _, auth in two.connects] == [_basic("alice", "pw1")]
    # An unauthenticated tunnel through proxy one is separate from both.
    via(one, "", "/p1/f")
    assert [auth for _, auth in one.connects] == [_basic("alice", "pw1"), _basic("bob", "pw2"), None]
    # A direct read never borrows a proxied tunnel.
    monkeypatch.delenv("HTTPS_PROXY")
    monkeypatch.setenv("NO_PROXY", "*")
    _read(echo.base, "/direct", "tok")
    assert echo.connections == 5
    keys = set(echo.pool.idle)
    origin = "localhost:%d" % int(echo.base.rsplit(":", 1)[1])
    assert keys == {("127.0.0.1:%d" % one.port, origin, _basic("alice", "pw1")),
                    ("127.0.0.1:%d" % one.port, origin, _basic("bob", "pw2")),
                    ("127.0.0.1:%d" % one.port, origin, None),
                    ("127.0.0.1:%d" % two.port, origin, _basic("alice", "pw1")),
                    (origin, None, None)}
    assert all("Proxy-Authorization" not in headers for _, headers in echo.seen)


# --------------------------------------------------------------------------
# Effective-route shared budget under concurrency
# --------------------------------------------------------------------------

NIC = SCOPE + "/resourceGroups/rg/providers/Microsoft.Network/networkInterfaces/nic%02d"
ROUTES = azure_nsg_ingress_native.ARM + "%s/effectiveRouteTable?api-version=" + azure_nsg_ingress_native.VERSION


class _RouteWire:
    """Fake ARM: each NIC answers ``pages`` route pages, one call per page."""
    def __init__(self, pages, *, body_bytes=0, jitter=0.004, fail=None, on_call=None):
        self.pages, self.body_bytes, self.jitter, self.fail, self.on_call = pages, body_bytes, jitter, fail or {}, on_call
        self.lock, self.calls, self.active, self.peak = threading.Lock(), [], 0, 0

    def __call__(self, *handlers):
        return self

    def open(self, request, timeout):
        parts = urlsplit(request.full_url)
        nic = parts.path.rsplit("/effectiveRouteTable", 1)[0]
        page = int(parse_qs(parts.query).get("$skiptoken", ["0"])[0])
        assert request.get_header("Authorization") == "Bearer route-token"
        with self.lock:
            self.calls.append((nic, page))
            self.active += 1
            self.peak = max(self.peak, self.active)
            count = len(self.calls)
        if self.on_call is not None:
            self.on_call(count)
        try:
            time.sleep(random.random() * self.jitter)
            failure = self.fail.get((nic, page))
            if failure is not None:
                raise failure
            value = {"value": [{"name": "%s/p%d" % (nic.rsplit("/", 1)[1], page),
                                "pad": "x" * self.body_bytes}]}
            if page + 1 < self.pages.get(nic, 1):
                value["nextLink"] = (ROUTES % nic) + "&$skiptoken=%d" % (page + 1)
            return _Response(json.dumps(value).encode())
        finally:
            with self.lock:
                self.active -= 1


class _Response:
    status = 200
    headers = {}

    def __init__(self, raw):
        self.raw = raw

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self, limit=-1):
        return self.raw if limit is None or limit < 0 else self.raw[:limit]


class _Token:
    def token(self, audience):
        assert audience == azure.ARM
        return "route-token"


def _routes(monkeypatch, wire, nics, *, concurrency, cancel=None):
    monkeypatch.setattr(azure_nsg_ingress_native, "build_opener", wire)
    options = {"concurrency": concurrency, "retries": 0}
    if cancel is not None:
        options["_cancel_check"] = cancel
    reader = azure._Reader(options)
    reader.collections.append({"type": "nic", "scope": SCOPE, "status": "collected", "items": [{"id": nic} for nic in nics]})
    azure_effective_routes_native.collect(reader, _Token(), [SCOPE], {"effective_route"})
    envelope = next(c for c in reader.collections if c["type"] == "effective_route")
    return {"status": envelope["status"], "error": (envelope.get("error") or {}).get("code"),
            "rows": [(row["id"], row["nic_id"], row["route"]["name"]) for row in envelope["items"]],
            "proofs": [(proof["resource_id"], proof["response_sha256"]) for proof in envelope["source_evidence"]]}


@pytest.mark.parametrize("layout", ["uniform", "skewed"])
def test_call_budget_exhaustion_matches_the_serial_read_under_concurrency(monkeypatch, layout):
    nics = [NIC % n for n in range(40)]
    if layout == "uniform":
        pages = {nic: 9 for nic in nics}            # 360 calls > 300: nic33 is cut after 3 pages
    else:
        pages = {nic: (31 if n % 5 == 3 else 2) for n, nic in enumerate(nics)}   # 312 calls
    serial_wire = _RouteWire(pages, jitter=0)
    serial = _routes(monkeypatch, serial_wire, nics, concurrency=1)
    assert serial["status"] == "partial" and serial["error"] == "network_query_budget"
    assert len(serial_wire.calls) == 300
    for _ in range(4):
        wire = _RouteWire(pages)
        parallel = _routes(monkeypatch, wire, nics, concurrency=8)
        assert wire.peak > 1
        assert parallel == serial
        # Only parents that found the shared total spent rerun; the overshoot
        # is bounded by the reads in flight when the budget ran out.
        assert 300 <= len(wire.calls) <= 300 + 8 * 31


def test_two_exhausted_subscriptions_share_fanout_slots_without_stalling(monkeypatch):
    other = "/subscriptions/22222222-2222-2222-2222-222222222222"
    scopes = {SCOPE: [NIC % n for n in range(40)],
              other: [other + "/resourceGroups/rg/providers/Microsoft.Network/networkInterfaces/nic%02d" % n for n in range(40)]}
    pages = {nic: 9 for nics in scopes.values() for nic in nics}
    def run(concurrency, jitter):
        wire = _RouteWire(pages, jitter=jitter)
        monkeypatch.setattr(azure_nsg_ingress_native, "build_opener", wire)
        reader = azure._Reader({"concurrency": concurrency, "retries": 0})
        for scope, nics in scopes.items():
            reader.collections.append({"type": "nic", "scope": scope, "status": "collected", "items": [{"id": nic} for nic in nics]})
        started = time.monotonic()
        azure_effective_routes_native.collect(reader, _Token(), list(scopes), {"effective_route"})
        elapsed = time.monotonic() - started
        envelopes = {c["scope"]: (c["status"], (c.get("error") or {}).get("code"), [row["id"] for row in c["items"]])
                     for c in reader.collections if c["type"] == "effective_route"}
        return envelopes, elapsed
    serial, _ = run(1, 0)
    assert all(status == "partial" and code == "network_query_budget" for status, code, _ in serial.values())
    # Four shared fan-out slots for two exhausted ledgers: no parent waits while holding one.
    parallel, elapsed = run(4, 0.002)
    assert parallel == serial
    assert elapsed < 30


def test_body_budget_exhaustion_matches_the_serial_read_under_concurrency(monkeypatch):
    nics = [NIC % n for n in range(14)]
    pages = {nic: 1 for nic in nics}
    size = 3_800_000                                   # the 9th response crosses 32 MB
    serial = _routes(monkeypatch, _RouteWire(pages, body_bytes=size, jitter=0), nics, concurrency=1)
    assert serial["status"] == "partial" and serial["error"] == "network_query_body_budget"
    assert len(serial["rows"]) == 8
    for _ in range(3):
        wire = _RouteWire(pages, body_bytes=size, jitter=0.01)
        assert _routes(monkeypatch, wire, nics, concurrency=8) == serial
        assert wire.peak > 1


def test_denied_parent_matches_the_serial_read_under_concurrency(monkeypatch):
    nics = [NIC % n for n in range(20)]
    pages = {nic: 3 for nic in nics}
    fail = {(nics[11], 1): azure.AzureReadError("forbidden", 403), (nics[15], 0): azure.AzureReadError("forbidden", 403)}
    serial = _routes(monkeypatch, _RouteWire(pages, jitter=0, fail=fail), nics, concurrency=1)
    assert serial["status"] == "partial" and serial["error"] == "403"
    assert serial["rows"][-1][2] == "nic11/p0"
    for _ in range(3):
        assert _routes(monkeypatch, _RouteWire(pages, fail=fail), nics, concurrency=8) == serial


def test_denied_first_parent_is_denied_not_partial_under_concurrency(monkeypatch):
    nics = [NIC % n for n in range(6)]
    fail = {(nics[0], 0): azure.AzureReadError("forbidden", 403)}
    serial = _routes(monkeypatch, _RouteWire({}, jitter=0, fail=fail), nics, concurrency=1)
    parallel = _routes(monkeypatch, _RouteWire({}, fail=fail), nics, concurrency=8)
    assert serial["status"] == "denied" and serial["rows"] == []
    assert parallel == serial


def test_cancellation_stops_parallel_route_workers(monkeypatch):
    nics = [NIC % n for n in range(40)]
    pages = {nic: 6 for nic in nics}
    cancelled = threading.Event()
    def on_call(count):
        if count == 20:
            cancelled.set()
    wire = _RouteWire(pages, jitter=0.005, on_call=on_call)
    result = _routes(monkeypatch, wire, nics, concurrency=8, cancel=cancelled.is_set)
    assert cancelled.is_set()
    # At most the reads already in flight when cancellation was observed finish.
    assert len(wire.calls) <= 20 + 8
    assert result["error"] == "collection_cancelled"
    assert result["status"] in ("partial", "unknown", "not_collected", "denied", "error") or result["rows"] == []


# --------------------------------------------------------------------------
# Parallel identity collectors keep denied/partial/unknown and tenant binding
# --------------------------------------------------------------------------

def _normalise(value):
    if isinstance(value, dict):
        return {key: _normalise(item) for key, item in value.items()
                if key not in ("observed_at", "captured_at", "collected_at", "started_at", "finished_at",
                               "duration_ms", "elapsed_seconds", "generated_at",
                               "credential_context_id", "customer_context_id")}
    if isinstance(value, list):
        return [_normalise(item) for item in value]
    return value


def _identity_capture(monkeypatch, cid, data, *, concurrency, verified_tenant, jitter):
    from peaso import engine
    from tests import test_azure_identity_enforcement_native_20261020 as fixtures
    wire = fixtures.Wire(data)
    original = wire.open
    active, peak, lock = [0], [0], threading.Lock()
    def open_(request, timeout):
        with lock:
            active[0] += 1
            peak[0] = max(peak[0], active[0])
        try:
            if jitter:
                _SLEEP(random.random() * jitter)
            return original(request, timeout)
        finally:
            with lock:
                active[0] -= 1
    wire.open = open_
    monkeypatch.setattr(azure, "build_opener", lambda *args: wire)
    transport = object.__new__(fixtures.REAL_TRANSPORT)
    transport.tenant = fixtures.TENANT
    transport.verified_tenant = verified_tenant
    transport.owned = False
    transport.credential = None
    transport.token = lambda audience: "offline-native-fixture"
    monkeypatch.setattr(azure, "AzureTransport", lambda auth: transport)
    monkeypatch.setattr(azure, "AzureTransportExposure", lambda auth: transport)
    snapshot = engine.collect_snapshot({"connector": {"provider": "azure", "scopes": [fixtures.SUB], "auth": {"tenant_id": fixtures.TENANT},
                                                      "options": {"retries": 0, "concurrency": concurrency}}, "checks": [cid]})
    findings = engine.evaluate_snapshot(snapshot, checks=[cid])["findings"]
    rows = [c for c in snapshot["collections"] if c["type"] == fixtures.native.KIND]
    return ({(f["resource_id"], f["status"]) for f in findings}, _normalise(rows), peak[0])


def _identity_modes():
    from tests import test_azure_identity_enforcement_native_20261020 as fixtures
    def denied(data):
        data[("graph", "/v1.0/identity/conditionalAccess/policies")] = azure.AzureReadError("forbidden", 403)
    def partial(data):
        key = ("graph", "/v1.0/users")
        initial = deepcopy(data[key])
        data[key] = lambda q: azure.AzureReadError("forbidden", 403) if "$skiptoken" in q else {
            **initial, "@odata.nextLink": azure.GRAPH + "/v1.0/users?$skiptoken=next"}
    def denied_pim(data):
        data[("graph", "/v1.0/roleManagement/directory/roleEligibilityScheduleInstances")] = azure.AzureReadError("forbidden", 403)
    assignments = ("arm", "/providers/Microsoft.Authorization/roleAssignments")
    def denied_binding(data):
        # A returned direct ARM grant forces a native parent read of its scope.
        data[assignments] = {"value": [fixtures.direct_assignment()]}
        data[("arm", fixtures.SCOPE)] = azure.AzureReadError("forbidden", 403)
    def foreign_binding(data):
        data[assignments] = {"value": [fixtures.direct_assignment()]}
        data[("arm", fixtures.SCOPE)] = {**data[("arm", fixtures.SCOPE)], "tenantId": fixtures.OTHER}
    return {"ok": lambda data: None, "denied": denied, "partial": partial, "denied_pim": denied_pim,
            "denied_binding": denied_binding, "foreign_binding": foreign_binding,
            "foreign_tenant": lambda data: None}


@pytest.mark.parametrize("mode", sorted(_identity_modes()))
def test_identity_enforcement_parallel_matches_serial(monkeypatch, mode):
    from tests import test_azure_identity_enforcement_native_20261020 as fixtures
    tenant = fixtures.OTHER if mode == "foreign_tenant" else fixtures.TENANT
    for cid in fixtures.IDS:
        def data():
            # Fresh fixture state (including stateful routes) per capture.
            value = fixtures.baseline(cid)
            _identity_modes()[mode](value)
            return value
        serial = _identity_capture(monkeypatch, cid, data(), concurrency=1, verified_tenant=tenant, jitter=0)
        parallel = _identity_capture(monkeypatch, cid, data(), concurrency=8, verified_tenant=tenant, jitter=0.004)
        assert parallel[:2] == serial[:2], (cid, mode)
        if mode == "foreign_tenant":
            # An unverified token tenant never yields a collected projection.
            assert all(row["status"] != "collected" for row in serial[1]), (cid, serial[1])
            assert {status for _, status in serial[0]} <= {"UNKNOWN", "NOT_APPLICABLE"}, (cid, serial[0])
            continue
        assert parallel[2] > 1, (cid, mode)
        sources = {source["name"]: source for row in serial[1] for item in row["items"] for source in item["sources"]}
        natives = [c["status"] for row in serial[1] for item in row["items"] for c in item["native_collections"]]
        statuses = [source["status"] for source in sources.values()] + natives
        if mode in ("denied", "denied_pim"):
            assert "denied" in statuses, (cid, mode, statuses)
        if mode == "partial":
            assert "partial" in statuses, (cid, mode, statuses)
        binding = [source for name, source in sources.items() if name.startswith("binding:")]
        if mode == "denied_binding":
            assert [source["status"] for source in binding] == ["denied"], (cid, binding)
        if mode == "foreign_binding":
            assert [source["items"][0]["tenantId"] for source in binding] == [fixtures.OTHER], (cid, binding)
        if mode in ("denied_binding", "foreign_binding"):
            # An unauthenticated parent never lets the direct grant prove a compliant state.
            assert "PASS" not in {status for _, status in serial[0]} or "FAIL" not in {s for _, s in serial[0]}, (cid, serial[0])


def _mfa_run(monkeypatch, mode, concurrency, users):
    from tests import test_peaso_azure_nonprivileged_mfa_native as fixtures
    from peaso.engine import evaluate_snapshot
    ids = ["%08d-3333-3333-3333-333333333333" % n for n in range(users)]
    state = {"active": 0, "peak": 0}
    lock = threading.Lock()
    class Transport:
        tenant = verified_tenant = fixtures.TENANT
        def close(self):
            pass
        def request(self, url, *, body=None, audience=azure.ARM):
            path = urlsplit(url).path
            if audience == azure.GRAPH and path == "/v1.0/users":
                return {"value": [{"id": uid, "accountEnabled": True} for uid in ids]}
            if audience == azure.GRAPH and path.endswith("/authentication/requirements"):
                uid = path.split("/")[3]
                with lock:
                    state["active"] += 1
                    state["peak"] = max(state["peak"], state["active"])
                try:
                    time.sleep(random.random() * 0.004)
                    index = ids.index(uid)
                    if mode == "denied_some" and index % 4 == 1:
                        raise fixtures.Denied()
                    if mode == "foreign_some" and index % 5 == 2:
                        return {"id": ids[(index + 1) % users], "perUserMfaState": "enforced"}
                    return {"perUserMfaState": ("disabled", "enabled", "enforced")[index % 3]}
                finally:
                    with lock:
                        state["active"] -= 1
            if audience == azure.GRAPH and path == "/v1.0/reports/authenticationMethods/userRegistrationDetails":
                return {"value": [{"id": uid, "isMfaCapable": True, "isMfaRegistered": True} for uid in ids]}
            if audience == azure.GRAPH:
                return {"value": []}
            if path.casefold() == fixtures.SUB.casefold():
                if mode == "subscription_denied":
                    raise fixtures.Denied()
                return {"id": fixtures.SUB, "subscriptionId": fixtures.SUB.rsplit("/", 1)[-1],
                        "tenantId": fixtures.GROUP if mode == "foreign_subscription" else fixtures.TENANT}
            return {"value": []}
    monkeypatch.setattr(azure, "AzureTransport", lambda auth: Transport())
    monkeypatch.setattr(azure, "AzureTransportExposure", lambda auth: Transport())
    connector = {"provider": "azure", "scopes": [fixtures.SUB],
                 "auth": {"method": "token", "arm_token": "mock", "graph_token": "mock"},
                 "options": {"retries": 0, "concurrency": concurrency}}
    snapshot = azure.collect(connector, ["directory_user", "azure_sw18_evidence"])
    findings = evaluate_snapshot(snapshot, checks=[fixtures.USER_MFA_ID])["findings"]
    rows = [c for c in snapshot["collections"] if c["type"] == "azure_sw18_evidence"]
    return sorted((f["resource_id"], f["status"]) for f in findings), _normalise(rows), state["peak"]


@pytest.mark.parametrize("mode", ["ok", "denied_some", "foreign_some", "subscription_denied", "foreign_subscription"])
def test_mfa_requirement_prefetch_parallel_matches_serial(monkeypatch, mode):
    serial = _mfa_run(monkeypatch, mode, 1, 24)
    parallel = _mfa_run(monkeypatch, mode, 8, 24)
    assert parallel[:2] == serial[:2]
    statuses = {status for _, status in serial[0]}
    if mode in ("denied_some", "foreign_some"):
        assert "UNKNOWN" in statuses and parallel[2] > 1
    if mode == "ok":
        assert parallel[2] > 1


def _unused_reader(concurrency, fail):
    from tests import test_unused_iam_azure as fixtures
    reader = azure._Reader({"retries": 0, "concurrency": concurrency})
    groups = ["%08d-4444-4444-4444-444444444444" % n for n in range(10)]
    reader.collections.extend([
        fixtures.native("directory_group", [fixtures.identity("directory_group", id=g) for g in groups])] + [
        fixtures.native("directory_membership", scope=fixtures.SCOPE + "/groups/" + g) for g in groups])
    def request(url, *, audience, body=None):
        assert body is None
        time.sleep(random.random() * 0.004)
        for marker, error in fail.items():
            if marker in url:
                raise error
        if "/beta/groups/" in url:
            group = url.split("/beta/groups/")[1].split("/")[0]
            return {"value": [{"id": fixtures.OTHER, "@odata.type": "#microsoft.graph.servicePrincipal"}]
                    if int(group[:8]) % 3 == 0 else []}
        if "servicePrincipalSignInActivities" in url:
            return {"value": [fixtures.principal_record()]}
        return {"value": [fixtures.credential_record()]}
    return reader, request, fixtures


@pytest.mark.parametrize("fail", ["none", "report_denied", "membership_denied", "foreign_tenant"])
def test_unused_iam_parallel_reports_and_membership_match_serial(fail):
    from types import SimpleNamespace
    class Denied(Exception):
        status_code = 403
    failures = {"none": {}, "foreign_tenant": {},
                "report_denied": {"servicePrincipalSignInActivities": Denied("report")},
                "membership_denied": {"/beta/groups/00000004": Denied("member"), "/beta/groups/00000007": Denied("member")}}[fail]
    outputs = []
    for concurrency in (1, 8):
        reader, request, fixtures = _unused_reader(concurrency, failures)
        verified = fixtures.OTHER if fail == "foreign_tenant" else fixtures.TENANT
        transport = SimpleNamespace(tenant=fixtures.TENANT, verified_tenant=verified)
        from peaso.collectors import azure_unused_iam_20261021 as producer
        producer.collect(reader, request, [], {producer.KIND}, transport, "capture-one", "customer-one")
        outputs.append(_normalise([c for c in reader.collections if c["type"] == producer.KIND]))
    assert outputs[0] == outputs[1]
    record = outputs[0][-1]
    if fail == "foreign_tenant":
        assert record["status"] != "collected"
        return
    item = record["items"][0]
    memberships = {c["scope"].rsplit("/", 1)[1][:8]: c["status"] for c in item["native_collections"] if c["type"] == "directory_membership"}
    if fail == "membership_denied":
        assert memberships["00000004"] == memberships["00000007"] == "denied"
    if fail == "report_denied":
        assert item["reports"][0]["status"] == "denied"
