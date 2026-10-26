"""Azure native transport keep-alive and bounded, order-preserving fan-out."""
from __future__ import annotations

import datetime as dt
import ipaddress
import random
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.request import Request

import pytest

from peaso.collectors import azure, azure_effective_routes_native

cryptography = pytest.importorskip("cryptography")


def _certificate(tmp_path):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(minutes=5))
            .not_valid_after(now + dt.timedelta(hours=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost"),
                                                         x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    cert_path, key_path = tmp_path / "cert.pem", tmp_path / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
    return cert_path, key_path


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def setup(self):
        super().setup()
        with self.server.lock:
            self.server.connections += 1

    def log_message(self, *args):
        pass

    def _send(self, status, body=b'{"value": []}', headers=()):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for key, value in headers:
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        with self.server.lock:
            self.server.seen.append((self.path, dict(self.headers)))
        if self.path == "/throttle":
            self._send(429, b'{"error":{}}', [("Retry-After", "7")])
        elif self.path == "/redirect":
            self._send(302, b"", [("Location", "https://example.invalid/")])
        elif self.path == "/drop":
            # Server forgets the idle connection without announcing it.
            self._send(200)
            self.close_connection = True
        elif self.path == "/large":
            self._send(200, b'{"value": [' + b'1,' * 5000 + b'1]}')
        else:
            self._send(200, ('{"path": "%s"}' % self.path).encode())

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        with self.server.lock:
            self.server.seen.append((self.path, dict(self.headers), body))
        self._send(200, body)


@pytest.fixture
def server(tmp_path, monkeypatch):
    cert, key = _certificate(tmp_path)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    httpd.daemon_threads = True
    httpd.lock, httpd.connections, httpd.seen = threading.Lock(), 0, []
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    client = ssl.create_default_context(cafile=str(cert))
    client.set_alpn_protocols(["http/1.1"])
    monkeypatch.setattr(azure, "_HTTPS_CONTEXT", client)
    pool = azure._KeepAlivePool()
    monkeypatch.setattr(azure, "_KEEPALIVE_POOL", pool)
    for name in ("HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("NO_PROXY", "*")
    httpd.base, httpd.pool = "https://localhost:%d" % httpd.server_address[1], pool
    yield httpd
    pool.clear()
    httpd.shutdown()
    httpd.server_close()


def _get(server, path, *, read=None, timeout=5):
    request = Request(server.base + path, headers={"Authorization": "Bearer t", "Accept": "application/json"}, method="GET")
    with azure._native_open(request, timeout) as response:
        return response.status, (response.read() if read is None else response.read(read))


def test_sequential_reads_reuse_one_tls_connection(server):
    for index in range(6):
        status, body = _get(server, "/item/%d" % index)
        assert status == 200 and body == ('{"path": "/item/%d"}' % index).encode()
    assert server.connections == 1
    assert server.pool.created == 1 and server.pool.reused == 5
    # Request headers are unchanged except for the dropped one-shot Connection: close.
    headers = server.seen[-1][1]
    assert headers["Authorization"] == "Bearer t" and headers["Accept"] == "application/json"
    assert "close" not in headers.get("Connection", "").lower()


def test_post_body_and_headers_survive_reuse(server):
    _get(server, "/warm")
    request = Request(server.base + "/query", data=b'{"query":"x"}', method="POST",
                      headers={"Authorization": "Bearer t", "Content-Type": "application/json"})
    with azure._native_open(request, 5) as response:
        assert response.read() == b'{"query":"x"}'
    assert server.seen[-1][2] == b'{"query":"x"}' and server.connections == 1


def test_threads_share_a_bounded_pool(server):
    errors = []
    def worker(number):
        try:
            for index in range(5):
                assert _get(server, "/t%d/%d" % (number, index))[0] == 200
        except Exception as exc:  # pragma: no cover - surfaced below
            errors.append(exc)
    threads = [threading.Thread(target=worker, args=(n,)) for n in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert not errors
    assert server.connections <= 4
    assert server.pool.created + server.pool.reused == 20


def test_http_error_retry_after_and_redirect_parity(server):
    with pytest.raises(HTTPError) as caught:
        _get(server, "/throttle")
    assert azure._status_code(caught.value) == 429
    assert azure._retry_after(caught.value) == 7.0
    caught.value.close()
    with pytest.raises(azure.AzureReadError) as redirect:
        _get(server, "/redirect")
    assert redirect.value.code == "redirect_rejected"
    assert _get(server, "/after")[0] == 200


def test_stale_idle_connection_is_replayed_once_on_a_fresh_connection(server):
    assert _get(server, "/drop")[0] == 200
    time.sleep(0.05)
    assert _get(server, "/after-drop") == (200, b'{"path": "/after-drop"}')
    assert server.connections == 2


def test_partially_read_body_is_never_reused(server):
    status, head = _get(server, "/large", read=16)
    assert status == 200 and len(head) == 16
    assert _get(server, "/next")[0] == 200
    assert server.connections == 2 and server.pool.reused == 0


def test_injected_opener_keeps_single_policy_seam(monkeypatch):
    calls = []
    class Response:
        status = 200
        def __enter__(self): return self
        def __exit__(self, *args): return False
        def read(self, *args): return b'{"value": []}'
    class Opener:
        def open(self, request, timeout):
            calls.append((request.full_url, timeout))
            return Response()
    def factory(*handlers):
        assert len(handlers) == 1 and isinstance(handlers[0], azure._NoRedirect)
        return Opener()
    monkeypatch.setattr(azure, "build_opener", factory)
    transport = azure.AzureTransport({"method": "token", "arm_token": "a.e30.c"})
    monkeypatch.setattr(transport, "token", lambda audience: "token")
    assert transport.request(azure.ARM + "/subscriptions?api-version=2022-12-01") == {"value": []}
    assert calls == [(azure.ARM + "/subscriptions?api-version=2022-12-01", 20)]


class _Reader:
    def __init__(self, workers):
        import threading as _threading
        self.workers = workers
        self.fanout_slots = _threading.BoundedSemaphore(workers)


def test_ordered_parallel_preserves_order_errors_and_bound():
    active, peak, lock = [0], [0], threading.Lock()
    def work(value):
        with lock:
            active[0] += 1
            peak[0] = max(peak[0], active[0])
        time.sleep(random.random() * 0.01)
        with lock:
            active[0] -= 1
        if value % 5 == 0:
            raise ValueError(value)
        return value * 2
    results = azure.ordered_parallel(_Reader(3), work, range(30))
    assert [ok for ok, _ in results] == [value % 5 != 0 for value in range(30)]
    assert [value for ok, value in results if ok] == [v * 2 for v in range(30) if v % 5]
    assert [value.args[0] for ok, value in results if not ok] == [0, 5, 10, 15, 20, 25]
    assert peak[0] <= 3
    # Readers without a worker bound stay serial.
    assert azure.ordered_parallel(object(), lambda v: v, [1, 2]) == [(True, 1), (True, 2)]


def test_reader_exposes_shared_fanout_slots():
    reader = azure._Reader({"concurrency": 5})
    assert reader.workers == 5
    slots = azure._fanout_slots(reader)
    assert azure._fanout_slots(reader) is slots
    assert all(slots.acquire(blocking=False) for _ in range(5))
    assert not slots.acquire(blocking=False)


def test_transport_opener_binding_reuses_connections(server):
    """AzureTransport passes the stdlib build_opener; it is upgraded to pooling."""
    for index in range(3):
        request = Request(server.base + "/t/%d" % index, headers={"Authorization": "Bearer t"}, method="GET")
        with azure._native_open(request, 5, azure.build_opener) as response:
            assert response.read() == ('{"path": "/t/%d"}' % index).encode()
    assert server.connections == 1 and server.pool.reused == 2


def test_full_get_details_settle_in_list_order_with_last_error():
    from tests.test_peaso_azure_bulk_native import BASE, SCOPE, SUB, Transport, parent
    routes, items = {}, []
    for index in range(12):
        rid = BASE + "Microsoft.Network/networkSecurityGroups/nsg%02d" % index
        value = parent(rid, "Microsoft.Network/networkSecurityGroups", {"securityRules": [], "defaultSecurityRules": []})
        items.append(value)
        def detail(query, value=value, index=index):
            time.sleep(random.random() * 0.02)
            if index in (3, 7):
                raise azure.AzureReadError("detail_%d" % index)
            return value
        routes[rid] = detail
    routes[SCOPE + "/providers/Microsoft.Network/networkSecurityGroups"] = {"value": items}
    api = Transport(routes)
    result = azure.collect({"scopes": [SUB], "options": {"retries": 0, "concurrency": 8}}, ["nsg"], transport=api)
    envelope = next(c for c in result["collections"] if c["type"] == "nsg" and c["scope"] == SCOPE)
    assert [row["id"] for row in envelope["items"]] == [item["id"] for item in items]
    assert [i for i, row in enumerate(envelope["items"]) if "detail" in row] == [3, 7]
    assert envelope["status"] == "partial" and envelope["error"]["code"] == "detail_7"


def test_effective_route_parents_keep_inventory_and_proof_order(monkeypatch):
    class Queries:
        def __init__(self, reader, transport, scope):
            self.proofs = []
        def pages(self, kind, parent, *, nsg_ids=(), proof_sink=None):
            for page in range(2):
                time.sleep(random.random() * 0.01)
                if parent.endswith("nic4") and page == 1:
                    raise azure.AzureReadError("network_query_budget")
                proof_sink.append({"resource_id": parent, "page": page})
                yield [{"name": parent + "/r%d" % page}]
    monkeypatch.setattr(azure_effective_routes_native, "NetworkQueries", Queries)
    # Treat the fake like the native query class so the parallel path runs.
    monkeypatch.setattr(azure_effective_routes_native, "_NATIVE_PAGES", Queries.pages)
    scope = "/subscriptions/11111111-1111-1111-1111-111111111111"
    nics = [scope + "/resourceGroups/rg/providers/Microsoft.Network/networkInterfaces/nic%d" % n for n in range(7)]
    reader = azure._Reader({"concurrency": 6, "retries": 0})
    reader.collections.append({"type": "nic", "scope": scope, "status": "collected", "items": [{"id": nic} for nic in nics]})
    azure_effective_routes_native.collect(reader, None, [scope], {"effective_route"})
    envelope = next(c for c in reader.collections if c["type"] == "effective_route")
    expected = [nic + "/r%d" % page for nic in nics[:4] for page in range(2)] + [nics[4] + "/r0"]
    assert [row["route"]["name"] for row in envelope["items"]] == expected
    assert envelope["status"] == "partial"
    assert envelope["source_evidence"] == [{"resource_id": nic, "page": page} for nic in nics[:4] for page in range(2)] + [
        {"resource_id": nics[4], "page": 0}]


def test_graph_directory_lists_request_documented_page_maxima():
    assert azure.DIRECTORY["directory_user"].endswith("signInActivity&$top=500")
    assert azure.DIRECTORY["directory_group"].endswith("&$top=999")
    assert azure.DIRECTORY["directory_application"].endswith("&$top=999")
    # servicePrincipals documents 100 as both default and maximum page size.
    assert "$top" not in azure.DIRECTORY["directory_service_principal"]
    assert "$top" not in azure.DIRECTORY["directory_role"]


def test_user_fallback_without_sign_in_activity_uses_full_page_size():
    seen = []
    class Graph:
        tenant = verified_tenant = "22222222-2222-2222-2222-222222222222"
        def request(self, url, *, body=None, audience=azure.ARM):
            seen.append(url)
            if "signInActivity" in url:
                raise azure.AzureReadError("premium_required", 403)
            return {"value": [{"id": "33333333-3333-3333-3333-333333333333"}]}
    result = azure.collect({"scopes": ["11111111-1111-1111-1111-111111111111"], "options": {"retries": 0}},
                           ["directory_user"], transport=Graph())
    envelope = next(c for c in result["collections"] if c["type"] == "directory_user")
    assert envelope["status"] == "collected"
    assert seen[0].endswith("signInActivity&$top=500")
    assert seen[1].endswith("onPremisesImmutableId&$top=999")


def test_forked_child_never_reuses_parent_connections():
    import os
    if not hasattr(os, "fork"):
        pytest.skip("fork unavailable")
    sentinel = object()
    class Connection:
        sock = sentinel
        def close(self):
            raise AssertionError("child must not close a parent's connection")
    key = ("parent.example", None, None)
    azure._KEEPALIVE_POOL.release(key, Connection(), True)
    try:
        read, write = os.pipe()
        pid = os.fork()
        if pid == 0:
            os.close(read)
            try:
                ok = azure._KEEPALIVE_POOL.acquire(key) is None and azure._KEEPALIVE_POOL.idle == {}
            except BaseException:
                ok = False
            os.write(write, b"1" if ok else b"0")
            os._exit(0)
        os.close(write)
        assert os.read(read, 1) == b"1"
        os.close(read)
        os.waitpid(pid, 0)
        assert azure._KEEPALIVE_POOL.acquire(key) is not None
    finally:
        azure._KEEPALIVE_POOL.idle.pop(key, None)
