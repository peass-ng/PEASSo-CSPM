import threading
import time
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest

from peaso.collectors.gcp import GCPCollector, ReadError, endpoint_page_size
from peaso.collectors.gcp_fanout import POOL_PREFIX, fanout_pages, location_fanout


@pytest.fixture
def collector():
    pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix=POOL_PREFIX)
    try:
        yield SimpleNamespace(location_pool=pool)
    finally:
        pool.shutdown(wait=True, cancel_futures=True)


def reader(plan, calls):
    """plan: location -> (pages, error, delay)."""
    lock = threading.Lock()

    def fetch(location):
        with lock:
            calls.append(location)
        pages, error, delay = plan[location]
        time.sleep(delay)
        yield from pages
        if error is not None:
            raise error
    return fetch


def test_replays_pages_and_errors_in_location_order(collector):
    failure = ReadError("denied", "permission_denied", http_status=403)
    plan = {
        "a": ([["a1"], ["a2"]], None, 0.0),
        "b": ([["b1"]], failure, 0.05),  # slowest finishes last but replays second
        "c": ([["c1"]], None, 0.0),
    }
    calls = []
    out = list(location_fanout(collector, ["a", "b", "c"], reader(plan, calls)))
    assert out == [("a", [["a1"], ["a2"]], None), ("b", [["b1"]], failure), ("c", [["c1"]], None)]
    assert sorted(calls) == ["a", "b", "c"] and calls[0] == "a"


def test_matches_serial_loop_without_pool():
    failure = ReadError("unavailable", "read_failed", http_status=500)
    plan = {"a": ([["a1"]], None, 0.0), "b": ([], failure, 0.0), "c": ([["c1"]], None, 0.0)}
    serial = list(location_fanout(SimpleNamespace(location_pool=None), list(plan), reader(plan, [])))
    pool = ThreadPoolExecutor(max_workers=3, thread_name_prefix=POOL_PREFIX)
    try:
        fanned = list(location_fanout(SimpleNamespace(location_pool=pool), list(plan), reader(plan, [])))
    finally:
        pool.shutdown(wait=True)
    assert serial == fanned


def test_disabled_service_probe_short_circuits_before_other_reads(collector):
    disabled = ReadError("not_enabled", "permission_denied", http_status=403, reason="SERVICE_DISABLED")
    plan = {"a": ([], disabled, 0.0), "b": ([["b1"]], None, 0.0), "c": ([["c1"]], None, 0.0)}
    calls = []
    for location, _pages, error in location_fanout(collector, ["a", "b", "c"], reader(plan, calls)):
        assert location == "a" and error is disabled
        break  # call sites stop on a disabled service
    collector.location_pool.shutdown(wait=True)
    assert calls == ["a"]


def test_fanout_pages_raises_first_failure_after_its_pages(collector):
    first = ReadError("denied", "permission_denied", http_status=403)
    later = ReadError("unavailable", "read_failed", http_status=500)
    plan = {"a": ([["a1"]], None, 0.0), "b": ([["b1"]], first, 0.02), "c": ([["c1"]], later, 0.0)}
    seen = []
    with pytest.raises(ReadError) as raised:
        for page in fanout_pages(collector, ["a", "b", "c"], reader(plan, [])):
            seen.append(page)
    assert raised.value is first
    assert seen == [["a1"], ["b1"]]


def test_other_exceptions_raise_at_their_serial_position(collector):
    plan = {"a": ([["a1"]], None, 0.0), "b": ([["b1"]], ValueError("bad identity"), 0.0), "c": ([["c1"]], None, 0.0)}
    seen = []
    with pytest.raises(ValueError, match="bad identity"):
        for location, pages, error in location_fanout(collector, ["a", "b", "c"], reader(plan, [])):
            seen.append((location, pages, error))
    assert seen == [("a", [["a1"]], None), ("b", [["b1"]], None)]


def test_nested_fanout_from_pool_thread_runs_serially(collector):
    plan = {"x": ([["x1"]], None, 0.0), "y": ([["y1"]], None, 0.0)}
    threads = []

    def inner(location):
        threads.append(threading.current_thread().name)
        yield from plan[location][0]

    def outer(location):
        yield list(fanout_pages(collector, ["x", "y"], inner)) + [location]

    out = list(fanout_pages(collector, ["o1", "o2", "o3"], outer))
    assert out == [[["x1"], ["y1"], "o1"], [["x1"], ["y1"], "o2"], [["x1"], ["y1"], "o3"]]
    # Inner reads issued from pool workers stay on that worker (no self-wait).
    assert len(threads) == 6


@pytest.mark.parametrize(("url", "method", "expected"), [
    ("https://cloudasset.googleapis.com/v1/organizations/1:searchAllResources", "GET", 500),
    ("https://cloudasset.googleapis.com/v1/projects/p:searchAllIamPolicies", "GET", 500),
    ("https://cloudasset.googleapis.com/v1/projects/p/assets", "GET", 1000),
    ("https://cloudasset.googleapis.com/v1/folders/1/assets", "GET", 1000),
    ("https://cloudasset.googleapis.com/v1/projects/p/feeds", "GET", None),
    ("https://compute.googleapis.com/compute/v1/projects/p/aggregated/instances", "GET", 500),
    ("https://storage.googleapis.com/storage/v1/b", "GET", 1000),
    ("https://run.googleapis.com/v2/projects/p/locations/-/services", "GET", None),
])
def test_endpoint_page_size(url, method, expected):
    assert endpoint_page_size(url, method) == expected


def test_default_page_size_uses_endpoint_maximum_only_when_unset():
    unset = SimpleNamespace(options={}, page_size=100)
    assert GCPCollector.default_page_size(unset, "https://storage.googleapis.com/storage/v1/b") == 1000
    assert GCPCollector.default_page_size(unset, "https://compute.googleapis.com/compute/v1/x") == 500
    assert GCPCollector.default_page_size(unset, "https://run.googleapis.com/v2/x") == 100
    explicit = SimpleNamespace(options={"page_size": 200}, page_size=200)
    assert GCPCollector.default_page_size(explicit, "https://storage.googleapis.com/storage/v1/b") == 200
    assert GCPCollector.default_page_size(explicit, "https://run.googleapis.com/v2/x") == 200
    big = SimpleNamespace(options={"page_size": 1000}, page_size=1000)
    assert GCPCollector.default_page_size(big, "https://compute.googleapis.com/compute/v1/x") == 500


def test_read_raises_only_the_seeded_default_page_size():
    seen = []
    class Transport:
        def request(self, method, url, *, params=None, body=None, scope=None, operation=None):
            seen.append(dict(params))
            return {}
    storage = "https://storage.googleapis.com/storage/v1/b"
    unset = SimpleNamespace(options={}, page_size=100, transport=Transport())
    for name in ("default_page_size", "_bulk_page_params"):
        setattr(unset, name, getattr(GCPCollector, name).__get__(unset))
    original = {"pageSize": 100, "pageToken": "t"}
    GCPCollector.read(unset, storage, "projects/p", params=original)
    GCPCollector.read(unset, storage, "projects/p", params={"pageSize": 50})
    GCPCollector.read(unset, "https://run.googleapis.com/v2/x", "projects/p", params={"pageSize": 100})
    explicit = SimpleNamespace(options={"page_size": 100}, page_size=100, transport=Transport())
    for name in ("default_page_size", "_bulk_page_params"):
        setattr(explicit, name, getattr(GCPCollector, name).__get__(explicit))
    GCPCollector.read(explicit, storage, "projects/p", params={"pageSize": 100})
    assert seen == [{"pageSize": 1000, "pageToken": "t"}, {"pageSize": 50},
                    {"pageSize": 100}, {"pageSize": 100}]
    assert original == {"pageSize": 100, "pageToken": "t"}
