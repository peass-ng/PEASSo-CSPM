"""Offline fake-client contracts for the throttle-only retry extension."""
from __future__ import annotations

import pytest

from peaso.collectors import aws


class ProviderError(Exception):
    def __init__(self, code, status=400):
        super().__init__(code)
        self.response = {"Error": {"Code": code}, "ResponseMetadata": {"HTTPStatusCode": status, "HTTPHeaders": {}}}


class FakeClient:
    def __init__(self, results):
        self.results, self.calls = iter(results), 0

    def get_account_summary(self):
        self.calls += 1
        result = next(self.results)
        if isinstance(result, Exception):
            raise result
        return result


def reader(monkeypatch, results, options=None):
    client = FakeClient(results)
    monkeypatch.setattr(aws.Requests, "client", lambda self, session, service, region, **_: client)
    waits = []
    return aws.Requests(dict(options or {}), sleep=waits.append), client, waits


def call(requests):
    return requests.call(object(), "iam", "us-east-1", "get_account_summary")


def test_default_budget_outlasts_a_throttle_burst_with_bounded_jittered_waits(monkeypatch):
    burst = [ProviderError("ThrottlingException")] * 6
    requests, client, waits = reader(monkeypatch, burst + [{"SummaryMap": {"Users": 1}}])
    assert call(requests) == {"SummaryMap": {"Users": 1}}
    assert client.calls == 7 and requests.throttle_retries == 4
    # The first two waits keep the historic schedule; later ones are jittered.
    assert waits[:2] == [0.2, 0.4]
    for wait, ceiling in zip(waits[2:], (2, 4, 8, 16)):
        assert ceiling / 2 <= wait <= ceiling


def test_default_throttle_budget_is_finite(monkeypatch):
    requests, client, waits = reader(monkeypatch, [ProviderError("Throttling")] * 20)
    with pytest.raises(aws.ReadFailure) as caught:
        call(requests)
    assert caught.value.code == "Throttling"
    assert client.calls == aws.THROTTLE_RETRY_ATTEMPTS == 8
    assert max(waits) <= aws.THROTTLE_RETRY_MAX_WAIT


def test_non_throttle_server_errors_keep_three_attempts(monkeypatch):
    requests, client, waits = reader(monkeypatch, [ProviderError("InternalError", 500)] * 5)
    with pytest.raises(aws.ReadFailure):
        call(requests)
    assert client.calls == 3 and waits == [0.2, 0.4]


def test_http_429_with_unmodelled_code_is_throttle(monkeypatch):
    requests, client, _ = reader(monkeypatch, [ProviderError("Custom", 429)] * 4 + [{"SummaryMap": {"Users": 3}}])
    assert call(requests) == {"SummaryMap": {"Users": 3}} and client.calls == 5


def test_explicit_retry_attempts_keeps_its_exact_budget(monkeypatch):
    requests, client, waits = reader(monkeypatch, [ProviderError("ThrottlingException")] * 3, {"retry_attempts": 2})
    with pytest.raises(aws.ReadFailure):
        call(requests)
    assert client.calls == 2 and waits == [0.2]


def test_throttle_extension_is_bounded_by_the_deadline(monkeypatch):
    requests, client, waits = reader(monkeypatch, [ProviderError("ThrottlingException")] * 8, {"deadline_seconds": 0.9})
    with pytest.raises(aws.ReadFailure) as caught:
        call(requests)
    assert caught.value.code == "retry_wait_exceeds_deadline"
    assert client.calls == 3 and waits == [0.2, 0.4]


def test_throttled_failure_is_not_cached_for_a_later_reader(monkeypatch):
    results = [ProviderError("ThrottlingException")] * 8 + [{"SummaryMap": {"Users": 2}}]
    requests, client, _ = reader(monkeypatch, results)
    with pytest.raises(aws.ReadFailure):
        call(requests)
    assert call(requests) == {"SummaryMap": {"Users": 2}} and client.calls == 9


def test_option_validation(monkeypatch):
    with pytest.raises(ValueError):
        aws.Requests({"throttle_retry_attempts": 11})
    assert aws.Requests({"throttle_retry_attempts": 1}).throttle_attempts == 3
