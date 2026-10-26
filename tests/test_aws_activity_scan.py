"""One unfiltered CloudTrail activity pass versus per-name LookupEvents queries."""
import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from peaso.collectors import aws

REGION = "us-east-1"
NOW = datetime(2026, 10, 10, tzinfo=timezone.utc)
NAMES = aws.activity_event_names(REGION)


def _event(index, name, when, actor=True):
    identity = {"type": "IAMUser", **({"arn": "arn:aws:iam::123456789012:user/u%d" % (index % 7)} if actor else {})}
    return {"EventId": "event-%06d" % index, "EventName": name, "EventTime": when,
            "CloudTrailEvent": json.dumps({"userIdentity": identity, "requestParameters": {"secret": "x"}})}


class FakeCloudTrail:
    """LookupEvents over a fixed event history: newest first, 50 per page."""

    def __init__(self, events, foreign_garbage=False):
        self.foreign_garbage = foreign_garbage
        self.events = sorted(events, key=lambda e: e["EventTime"], reverse=True)
        self.calls = []
        self.meta = SimpleNamespace(endpoint_url="https://cloudtrail.us-east-1.amazonaws.com")

    def can_paginate(self, operation):
        return True

    def get_paginator(self, operation):
        return SimpleNamespace(_pagination_cfg={"input_token": "NextToken", "output_token": "NextToken", "result_key": "Events"})

    def lookup_events(self, **arguments):
        self.calls.append(arguments)
        attributes = arguments.get("LookupAttributes")
        rows = [e for e in self.events if arguments["StartTime"] <= e["EventTime"] <= arguments["EndTime"]
                and (not attributes or e["EventName"] == attributes[0]["AttributeValue"])]
        offset = int(arguments.get("NextToken", "0"))
        response = {"Events": [dict(e) for e in rows[offset:offset + 50]]}
        if not attributes and offset == 0 and self.foreign_garbage:
            response["Events"].append({"EventId": "bad", "EventName": "ForeignUnlistedEvent", "EventTime": "not-a-time"})
        if offset + 50 < len(rows):
            response["NextToken"] = str(offset + 50)
        return response


def _collect(monkeypatch, events, *, scan=True, foreign_garbage=False):
    client = FakeCloudTrail(events, foreign_garbage)
    requests = aws.Requests({}, sleep=lambda _: None)
    requests.observed_at = NOW
    monkeypatch.setattr(requests, "client", lambda *args, **kwargs: client)
    if not scan:
        monkeypatch.setattr(aws, "_activity_scan", lambda *args: None)
    try:
        result = aws._cloudtrail_activity(requests, object(), REGION)
    finally:
        monkeypatch.undo()
    return result, client.calls


def _history(count, span, *, foreign_every=3, start=NOW):
    events = []
    for index in range(count):
        when = start - span * (index + 1) / (count + 1)
        name = "ForeignUnlistedEvent" if index % foreign_every == 0 else NAMES[(index * 7) % len(NAMES)]
        events.append(_event(index, name, when, actor=index % 11 != 0))
    # Boundary events at both window edges, and one just outside.
    events += [_event(900001, "ListUsers", NOW), _event(900002, "AssumeRole", NOW - timedelta(days=1)),
               _event(900003, "ListUsers", NOW - timedelta(days=1, seconds=1))]
    return events


def test_low_activity_account_reads_one_pass_with_identical_events(monkeypatch):
    events = _history(1200, timedelta(hours=23))
    per_name, per_name_calls = _collect(monkeypatch, events, scan=False)
    scanned, scan_calls = _collect(monkeypatch, events)
    assert scanned == per_name
    assert [list(row) for row in scanned.items] == [list(row) for row in per_name.items]
    assert len(per_name_calls) >= len(NAMES) and len(scan_calls) == 25
    assert all("LookupAttributes" not in call for call in scan_calls)
    assert {"event-900001", "event-900002"} <= {row["EventId"] for row in scanned.items}
    assert "event-900003" not in {row["EventId"] for row in scanned.items}
    assert scanned.status == "collected"


def test_busy_account_abandons_the_pass_early_and_keeps_per_name_results(monkeypatch):
    # Thousands of events in the last hour: two pages cover minutes of a day.
    events = _history(20000, timedelta(hours=1), foreign_every=2)
    per_name, per_name_calls = _collect(monkeypatch, events, scan=False)
    scanned, scan_calls = _collect(monkeypatch, events)
    assert scanned == per_name
    unfiltered = [call for call in scan_calls if "LookupAttributes" not in call]
    assert len(unfiltered) == aws.ACTIVITY_SCAN_MIN_PAGES
    assert len(scan_calls) == len(per_name_calls) + aws.ACTIVITY_SCAN_MIN_PAGES


def test_malformed_foreign_event_falls_back_to_per_name_queries(monkeypatch):
    events = _history(300, timedelta(hours=20))
    per_name, per_name_calls = _collect(monkeypatch, events, scan=False, foreign_garbage=True)
    scanned, scan_calls = _collect(monkeypatch, events, foreign_garbage=True)
    assert scanned == per_name and scanned.status == "collected"
    assert len(scan_calls) == len(per_name_calls) + 1


def test_empty_history_needs_one_call(monkeypatch):
    scanned, calls = _collect(monkeypatch, [])
    assert scanned.items == [] and scanned.status == "empty" and len(calls) == 1


def test_per_read_caps_keep_per_name_queries(monkeypatch):
    for option in ({"max_pages": 3}, {"max_resources": 10}):
        requests = aws.Requests(option)
        assert aws._activity_scan(requests, object(), REGION, NOW - timedelta(days=1), NOW, NAMES) is None


@pytest.mark.parametrize("extra", [{"LookupAttributes": []}, {"EventCategory": "insight"}, {"MaxResults": 5}])
def test_unfiltered_pass_accepts_only_the_plain_window_shape(monkeypatch, extra):
    requests = aws.Requests({})
    monkeypatch.setattr(requests, "client", lambda *args: pytest.fail("undeclared query constructed client"))
    with pytest.raises(aws.ReadFailure, match="undeclared_activity_event_query"):
        requests.call(object(), "cloudtrail", REGION, "lookup_events", StartTime=NOW - timedelta(days=1), EndTime=NOW, **extra)


def test_unfiltered_page_projects_only_declared_names():
    page = {"Events": [_event(1, "ListUsers", NOW), _event(2, "ForeignUnlistedEvent", NOW - timedelta(hours=2))], "NextToken": "t"}
    projected = aws._project_activity_scan_response(page)
    assert [row["EventName"] for row in projected["Events"]] == ["ListUsers"]
    assert projected["NextToken"] == "t" and projected["OldestEventTime"] == (NOW - timedelta(hours=2)).isoformat()
    assert "secret" not in json.dumps(projected)
