"""A late Service Usage quota response cannot silently lose the next pages."""

import json
import random
from types import SimpleNamespace

import pytest

from peaso.collectors import gcp


SCOPE = "projects/p-one"
URL = "https://serviceusage.googleapis.com/v1/" + SCOPE + "/services"


class Clock:
    def __init__(self):
        self.now = 100.0
        self.waits = []

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.waits.append(seconds)
        self.now += seconds


class Response:
    def __init__(self, status, payload):
        self.status_code = status
        self.payload = payload
        self.headers = {}
        self.content = json.dumps(payload).encode()

    def json(self):
        return self.payload


def page(start, count, token=None):
    data = {"services": [{"name": f"{SCOPE}/services/svc-{i}.googleapis.com"}
                         for i in range(start, start + count)]}
    if token:
        data["nextPageToken"] = token
    return Response(200, data)


def throttled():
    return Response(429, {"error": {"details": [{"reason": "RATE_LIMIT_EXCEEDED"}]}})


def unavailable():
    return Response(503, {"error": {"message": "service temporarily unavailable"}})


def reader(monkeypatch, responses, options=None):
    clock = Clock()
    monkeypatch.setattr(gcp.time, "monotonic", clock.monotonic)
    monkeypatch.setattr(random, "random", lambda: 0.0)
    transport = gcp.Transport(SimpleNamespace(headers=lambda: {}, close=lambda: None),
                              options or {}, sleep=clock.sleep)
    calls = []

    def request(*args, **kwargs):
        calls.append((args, dict(kwargs.get("params") or {})))
        return responses.pop(0)

    monkeypatch.setattr(transport, "_session", lambda: SimpleNamespace(request=request))
    return transport, clock, calls


def pages(transport):
    pager = SimpleNamespace(page_size=200, max_pages=None,
                            read=lambda url, scope, **kw: transport.request(
                                kw.pop("method", "GET"), url, scope=scope, **kw))
    return gcp.GCPCollector.pages(pager, URL, SCOPE, key="services", params={"pageSize": 200})


def test_late_quota_recovers_full_ordered_service_usage_pages(monkeypatch):
    responses = [page(0, 200, "second"), *[throttled() for _ in range(5)],
                 page(200, 200, "third"), page(400, 168)]
    transport, clock, calls = reader(monkeypatch, responses)
    groups = list(pages(transport))
    names = [item["name"] for items, _ in groups for item in items]
    assert len(names) == len(set(names)) == 568
    assert names[0].endswith("svc-0.googleapis.com")
    assert names[-1].endswith("svc-567.googleapis.com")
    assert len(calls) == 8 and [row[1].get("pageToken") for row in calls] == [
        None, "second", "second", "second", "second", "second", "second", "third"]
    assert [row["attempts"] for row in transport.evidence] == [1, 6, 1]
    assert clock.waits == [0.5, 1, 2, 4, 8]


def test_complete_pages_do_not_add_calls_or_waits(monkeypatch):
    transport, clock, calls = reader(monkeypatch,
        [page(0, 200, "second"), page(200, 168)])
    names = [item["name"] for items, _ in pages(transport) for item in items]
    assert len(names) == 368 and len(set(names)) == 368
    assert len(calls) == 2 and clock.waits == []
    assert [row["attempts"] for row in transport.evidence] == [1, 1]


def test_late_service_usage_503_uses_same_bounded_extra_attempts(monkeypatch):
    transport, clock, calls = reader(monkeypatch,
        [page(0, 200, "second"), *[unavailable() for _ in range(5)],
         page(200, 168)])
    names = [item["name"] for items, _ in pages(transport) for item in items]
    assert len(names) == 368 and len(set(names)) == 368
    assert len(calls) == 7 and len(clock.waits) == 5
    assert [row["attempts"] for row in transport.evidence] == [1, 6]


def test_persistent_quota_remains_incomplete_after_two_extra_attempts(monkeypatch):
    transport, clock, calls = reader(monkeypatch,
        [page(0, 200, "second"), *[throttled() for _ in range(7)]])
    stream = pages(transport)
    assert len(next(stream)[0]) == 200
    with pytest.raises(gcp.ReadError) as caught:
        next(stream)
    assert caught.value.status == "unavailable"
    assert caught.value.error["http_status"] == 429
    assert len(calls) == 8 and clock.waits == [0.5, 1, 2, 4, 8, 16]
    assert transport.evidence[-1]["attempts"] == 7


def test_extra_quota_wait_has_a_finite_budget(monkeypatch):
    responses = [throttled() for _ in range(7)]
    for response in responses:
        response.headers = {"Retry-After": "60"}
    transport, clock, calls = reader(monkeypatch, responses)
    with pytest.raises(gcp.ReadError) as caught:
        transport.request("GET", URL, scope=SCOPE, params={"pageSize": 200})
    assert caught.value.error["code"] == "quota_retry_wait_budget"
    assert len(calls) == 6 and len(clock.waits) == 5
    assert transport.evidence[-1]["attempts"] == 6


def test_explicit_retry_setting_and_other_routes_keep_existing_limit(monkeypatch):
    for url, options in ((URL, {"retries": 4}),
                         ("https://compute.googleapis.com/compute/v1/projects/p-one/global/networks", {})):
        transport, _, calls = reader(monkeypatch, [throttled() for _ in range(5)], options)
        with pytest.raises(gcp.ReadError) as caught:
            transport.request("GET", url, scope=SCOPE, params={"pageSize": 200})
        assert caught.value.error["http_status"] == 429
        assert len(calls) == 5


def test_service_usage_extra_wait_respects_scan_deadline(monkeypatch):
    transport, clock, calls = reader(monkeypatch, [throttled() for _ in range(7)],
                                     {"deadline_seconds": 3})
    with pytest.raises(gcp.ReadError) as caught:
        transport.request("GET", URL, scope=SCOPE, params={"pageSize": 200})
    assert caught.value.error["code"] == "retry_wait_exceeds_deadline"
    assert len(calls) < 7 and sum(clock.waits) < 3
