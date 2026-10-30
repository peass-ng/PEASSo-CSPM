"""New AWS scans must never contact IAM Access Analyzer."""

import pytest

from peaso.collectors.aws import ReadFailure, Requests
from peaso.collectors.aws_access_analyzer_lifecycle import AnalyzerLifecycle


class ForbiddenSession:
    def client(self, *args, **kwargs):
        raise AssertionError("AWS client construction is forbidden")


class ForbiddenRequests:
    def __getattr__(self, name):
        raise AssertionError(f"Unexpected live request: {name}")


def test_new_scan_without_saved_analyzer_facts_is_unknown_and_makes_no_calls():
    events = []
    lifecycle = AnalyzerLifecycle(ForbiddenRequests(), events)
    lifecycle.prepare(ForbiddenSession(), {"Account": "123456789012"}, ["us-east-1"])
    read = lifecycle.collect(ForbiddenSession(), {"Account": "123456789012"},
                             "us-east-1", lambda *_: pytest.fail("Live enrichment called"))
    assert read.items == []
    assert read.status == "unknown"
    assert read.error == {"code": "access_analyzer_saved_result_unavailable"}
    assert events == []


@pytest.mark.parametrize("method", ["client", "call", "pages"])
def test_shared_request_boundary_rejects_all_live_analyzer_calls(method):
    requests = Requests({})
    session = ForbiddenSession()
    args = (session, "accessanalyzer", "us-east-1")
    if method == "call":
        args += ("list_analyzers",)
    elif method == "pages":
        args += ("list_analyzers", "analyzers")
    with pytest.raises(ReadFailure) as error:
        getattr(requests, method)(*args)
    assert error.value.code == "access_analyzer_live_api_banned"
