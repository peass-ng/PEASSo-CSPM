"""Scans only read existing Access Analyzers; they never create or change one."""

import pytest

from peaso.collectors.aws import ReadFailure, ReadResult, Requests
from peaso.collectors.aws_access_analyzer_lifecycle import AnalyzerLifecycle

IDENTITY = {"Account": "111122223333"}
ANALYZER = {"arn": "arn:aws:access-analyzer:us-east-1:111122223333:analyzer/a", "name": "a",
            "type": "ACCOUNT", "status": "ACTIVE"}


class ForbiddenSession:
    def client(self, *args, **kwargs):
        raise AssertionError("AWS client construction is forbidden")


class ListingRequests:
    def __init__(self, analyzers):
        self.analyzers, self.calls = analyzers, []

    def pages(self, session, service, region, operation, expression, **arguments):
        self.calls.append((service, operation))
        return ReadResult(list(self.analyzers), "collected" if self.analyzers else "empty")


@pytest.mark.parametrize("operation", ["create_analyzer", "delete_analyzer", "start_resource_scan",
                                       "update_findings", "create_archive_rule"])
@pytest.mark.parametrize("method", ["call", "pages"])
def test_analyzer_changes_are_refused_before_any_client(method, operation):
    args = (ForbiddenSession(), "accessanalyzer", "us-east-1", operation)
    if method == "pages":
        args += ("analyzers",)
    with pytest.raises(ReadFailure) as error:
        getattr(Requests({}), method)(*args)
    assert error.value.code == "access_analyzer_live_api_banned"


def test_bare_analyzer_client_is_refused():
    with pytest.raises(ReadFailure):
        Requests({}).client(ForbiddenSession(), "accessanalyzer", "us-east-1")


def test_existing_analyzers_are_listed_and_their_findings_read():
    requests, events = ListingRequests([ANALYZER]), []
    enriched = []
    read = AnalyzerLifecycle(requests, events).collect(
        object(), IDENTITY, "us-east-1", lambda r, s, region, items: enriched.extend(items) or items)
    assert read.status == "collected" and read.items == [ANALYZER] and enriched == [ANALYZER]
    assert requests.calls == [("accessanalyzer", "list_analyzers")]


def test_region_without_analyzer_is_complete_and_named():
    events = []
    read = AnalyzerLifecycle(ListingRequests([]), events).collect(
        object(), IDENTITY, "us-east-1", lambda *_: pytest.fail("nothing to enrich"))
    assert read.status == "empty" and read.items == []
    assert events == [{"account_id": "111122223333", "region": "us-east-1",
                       "status": "empty", "reason": "no_existing_access_analyzer"}]
