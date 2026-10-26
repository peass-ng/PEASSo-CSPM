"""Per-scan Kubernetes response cache at the bounded transport."""
import io
import threading

from urllib3 import HTTPResponse

from peaso.collectors import k8s_response_cache as rc

URL = "https://api.example:443/api/v1/pods"
AUTH = {"headers": {"Authorization": "Bearer one", "Accept": "application/json"}, "preload_content": False}


def _server(status=200, body=b'{"items":[]}', headers=None, calls=None, gate=None):
    def perform():
        if calls is not None:
            calls.append(1)
        if gate is not None:
            gate.wait(5)
        return HTTPResponse(body=io.BytesIO(body), status=status, preload_content=False,
                            headers=dict({"Content-Length": str(len(body))}, **(headers or {})))
    return perform


def test_complete_read_is_replayed_without_a_second_request():
    cache, calls = rc.ScanResponseCache(), []
    first = cache.request(_server(calls=calls), "GET", URL + "?limit=500", dict(AUTH, fields={"continue": "x"}))
    assert first.read() == b'{"items":[]}'
    # Same query in a different order is the same read.
    second = cache.request(_server(calls=calls), "GET", URL + "?continue=x&limit=500", dict(AUTH))
    assert second.read() == b'{"items":[]}' and second.status == 200
    assert len(calls) == 1 and cache.stats["hits"] == 1


def test_credentials_query_and_method_scope_the_key():
    cache, calls = rc.ScanResponseCache(), []
    cache.request(_server(calls=calls), "GET", URL, dict(AUTH)).read()
    cache.request(_server(calls=calls), "GET", URL, dict(AUTH, headers={"Authorization": "Bearer two"})).read()
    cache.request(_server(calls=calls), "GET", URL + "?limit=1", dict(AUTH)).read()
    cache.request(_server(calls=calls), "GET", URL, dict(AUTH, headers={"Authorization": "Bearer one",
                                                                          "Accept": "application/json;as=Table"})).read()
    cache.request(_server(calls=calls), "POST", URL, dict(AUTH)).read()
    cache.request(_server(calls=calls), "POST", URL, dict(AUTH)).read()
    assert len(calls) == 6


def test_throttling_and_server_errors_are_never_kept():
    for status in (429, 500, 503):
        cache, calls = rc.ScanResponseCache(), []
        for _ in range(2):
            cache.request(_server(status=status, calls=calls), "GET", URL, dict(AUTH)).read()
        assert len(calls) == 2 and cache.stats["stored"] == 0


def test_early_close_or_partial_read_keeps_nothing():
    cache, calls = rc.ScanResponseCache(), []
    response = cache.request(_server(body=b"x" * 100, calls=calls), "GET", URL, dict(AUTH))
    assert response.read(10) == b"x" * 10
    response.release_conn()
    cache.request(_server(body=b"x" * 100, calls=calls), "GET", URL, dict(AUTH)).read()
    assert len(calls) == 2


def test_truncated_body_is_not_kept():
    cache, calls = rc.ScanResponseCache(), []
    perform = _server(body=b"abc", headers={"Content-Length": "10"}, calls=calls)
    response = cache.request(perform, "GET", URL, dict(AUTH))
    try:
        response.read()
    except Exception:
        pass
    assert cache.stats["stored"] == 0


def test_oversized_bodies_are_not_kept():
    cache, calls = rc.ScanResponseCache(max_entry_bytes=4), []
    for _ in range(2):
        cache.request(_server(body=b"0123456789", calls=calls), "GET", URL, dict(AUTH)).read()
    assert len(calls) == 2


def test_concurrent_identical_reads_are_single_flight():
    cache, calls, gate = rc.ScanResponseCache(), [], threading.Event()
    bodies = []

    def worker():
        bodies.append(cache.request(_server(calls=calls, gate=gate), "GET", URL, dict(AUTH)).read())

    threads = [threading.Thread(target=worker) for _ in range(6)]
    for thread in threads:
        thread.start()
    while cache.stats["requests"] < 6:
        pass
    gate.set()
    for thread in threads:
        thread.join(10)
    assert bodies == [b'{"items":[]}'] * 6 and len(calls) == 1


def test_clear_discards_everything_at_scan_end():
    cache, calls = rc.ScanResponseCache(), []
    cache.request(_server(calls=calls), "GET", URL, dict(AUTH)).read()
    pending = cache.request(_server(calls=calls), "GET", URL + "?x=1", dict(AUTH))
    cache.clear()
    pending.read()  # Completes after scan end: must not be stored.
    cache.request(_server(calls=calls), "GET", URL, dict(AUTH)).read()
    cache.request(_server(calls=calls), "GET", URL + "?x=1", dict(AUTH)).read()
    assert len(calls) == 4


class _Inner:
    def __init__(self):
        self.calls = []
        self.connection_pool_kw = {}

    def request(self, method, url, **kwargs):
        self.calls.append(url)
        return _server()()


def _api(pool):
    from types import SimpleNamespace
    return SimpleNamespace(api_client=SimpleNamespace(rest_client=SimpleNamespace(pool_manager=pool)))


def test_bounded_transport_caches_inventory_reads_for_one_scan_only():
    from peaso.collectors import k8s
    inner = _Inner()
    pool = k8s._BoundedPool(inner, "https://api.example:443")
    api = _api(pool)
    cache = rc.install(api)
    assert isinstance(pool.pool, rc.CachingPool) and pool.pool.connection_pool_kw == {}
    for _ in range(3):
        pool.request("GET", URL, fields={"limit": "500"}, preload_content=False).read()
    assert len(inner.calls) == 1 and cache.stats["hits"] == 2
    # Selected content readers re-read exact objects to prove they did not change.
    pool.literal_paths = frozenset({"/api/v1/namespaces/a/configmaps/b"})
    for _ in range(2):
        pool.request("GET", "https://api.example:443/api/v1/namespaces/a/configmaps/b", preload_content=False).read()
    assert len(inner.calls) == 3
    stats = rc.uninstall(api)
    assert stats["hits"] == 2 and pool.pool is inner
    # The next scan starts empty.
    rc.install(api)
    pool.request("GET", URL, fields={"limit": "500"}, preload_content=False).read()
    assert len(inner.calls) == 4
    rc.uninstall(api)


def test_install_ignores_transports_that_are_not_bounded():
    assert rc.install(_api(_Inner())) is None and rc.uninstall(_api(_Inner())) is None


def test_empty_detected_value_union_scrub_is_an_exact_copy():
    # collect() skips the union scrub when no reader detected a value; that is
    # only valid because the scrub of an empty union returns equal output.
    from peaso.collectors import k8s_selected_metadata_runtime_20261020 as runtime
    collections = [{"type": "pod", "scope": "*", "items": [{"metadata": {"name": "p", "annotations": {"a": "b"}},
                    "spec": {"env": [{"name": "X", "value": "secret-looking-AKIA"}]}, "_coverage": {"x": {"status": "ok"}},
                    "n": 1, "f": 1.5, "t": True, "z": None}]}]
    metadata = {"k": ["v", {"w": 2}]}
    import copy
    expected = copy.deepcopy((["*"], collections, metadata))
    assert runtime.finalize(["*"], collections, metadata, set(), set()) == expected
