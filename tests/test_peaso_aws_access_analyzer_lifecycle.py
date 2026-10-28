"""Access Analyzer collection only uses previously saved snapshot results."""

import pytest

from peaso.collectors import aws
from peaso.collectors.aws_access_analyzer_lifecycle import AnalyzerLifecycle

ACCOUNT = "123456789012"
IDENTITY = {"Account": ACCOUNT, "Arn": f"arn:aws:iam::{ACCOUNT}:user/scanner"}
REGIONS = ("us-east-1", "eu-west-1")


class NoLiveRequests:
    """Any service request is a test failure, including a read request."""

    def __init__(self):
        self.calls = []

    def _unexpected(self, method):
        self.calls.append(method)
        pytest.fail(f"Access Analyzer attempted live request through {method}")

    def client(self, *args, **kwargs):
        self._unexpected("client")

    def pages(self, *args, **kwargs):
        self._unexpected("pages")

    def call(self, *args, **kwargs):
        self._unexpected("call")


class NoEnrichment:
    def __init__(self):
        self.calls = 0

    def __call__(self, *args, **kwargs):
        self.calls += 1
        pytest.fail("Access Analyzer attempted live finding enrichment")


def test_prepare_and_collect_do_not_make_live_requests():
    requests = NoLiveRequests()
    enrich = NoEnrichment()
    events = []
    with AnalyzerLifecycle(requests, events) as manager:
        manager.prepare(object(), IDENTITY, REGIONS)
        results = [manager.collect(object(), IDENTITY, region, enrich) for region in REGIONS]
    assert requests.calls == []
    assert enrich.calls == 0
    assert events == []
    assert all(isinstance(result, aws.ReadResult) for result in results)
    assert all(result.status == "unknown" and result.items == [] for result in results)
    assert all(result.error == {"code": "access_analyzer_saved_result_unavailable"} for result in results)


def test_cached_result_is_not_mistaken_for_fresh_live_inventory():
    saved = {"arn": f"arn:aws:access-analyzer:{REGIONS[0]}:{ACCOUNT}:analyzer/saved",
             "type": "ACCOUNT", "status": "ACTIVE",
             "Findings": [{"id": "previously-saved"}]}
    requests = NoLiveRequests()
    requests.saved = {REGIONS[0]: aws.ReadResult([saved], "collected")}
    with AnalyzerLifecycle(requests, []) as manager:
        manager.prepare(object(), IDENTITY, REGIONS[:1])
        result = manager.collect(object(), IDENTITY, REGIONS[0], NoEnrichment())
    assert result.status == "unknown"
    assert result.items == []
    assert requests.saved[REGIONS[0]].items == [saved]
    assert requests.calls == []


def test_no_identity_or_region_does_not_trigger_service_client():
    requests = NoLiveRequests()
    events = []
    with AnalyzerLifecycle(requests, events) as manager:
        manager.prepare(object(), {}, ())
        result = manager.collect(object(), {}, "", NoEnrichment())
    assert result.status == "unknown"
    assert result.error == {"code": "access_analyzer_saved_result_unavailable"}
    assert requests.calls == []
    assert events == []
