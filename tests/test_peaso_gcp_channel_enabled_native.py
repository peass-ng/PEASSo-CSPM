"""Native Monitoring channel presence through the real GCP collector and engine."""
from __future__ import annotations

import copy
import threading

import pytest

from peaso.collectors import gcp
from peaso.engine import evaluate_snapshot
from peaso.snapshot import validate
import peaso.checks.claude2_gcp_logging as logging_check


SCOPE = "projects/p"
CID = "gcp.claude2.logging.metric_alert_route_changes"
CHANNEL = SCOPE + "/notificationChannels/c"
METRIC = SCOPE + "/metrics/m"


class FakeTransport:
    def __init__(self, channels, *, deny_channels=False, partial_channels=False):
        self.channels = channels
        self.deny_channels = deny_channels
        self.partial_channels = partial_channels
        self.requests = []
        self.evidence = []
        self.lock = threading.Lock()

    def request(self, method, url, **kwargs):
        with self.lock:
            request_id = f"request-{len(self.requests) + 1}"
            self.requests.append((method, url, copy.deepcopy(kwargs)))
        if url.endswith(":getAncestry"):
            data = {"ancestor": [{"resourceId": {"type": "project", "id": "p"}}]}
        elif url == "https://cloudresourcemanager.googleapis.com/v3/" + SCOPE:
            data = {"name": "projects/123", "projectId": "p", "state": "ACTIVE"}
        elif url.endswith("/metricsScopes:listMetricsScopesByMonitoredProject"):
            data = {"metricsScopes": []}
        elif url.endswith("/metrics"):
            data = {"metrics": [{"name": "m", "filter": logging_check.CIS_FILTERS["route_changes"],
                     "metricDescriptor": {"type": "logging.googleapis.com/user/m", "metricKind": "DELTA",
                                          "valueType": "INT64"}}]}
        elif url.endswith("/alertPolicies"):
            data = {"alertPolicies": [{"name": SCOPE + "/alertPolicies/a", "enabled": True,
                     "notificationChannels": [CHANNEL if row["name"].startswith("projects/foreign/") else row["name"]
                                              for row in self.channels],
                     # The reviewed event contract binds a positive-count DELTA threshold on
                     # the audited resource type (gcp_metric_alert_native, 2026-10-20).
                     "conditions": [{"conditionThreshold": {
                         "filter": 'metric.type="logging.googleapis.com/user/m" resource.type="gce_route"',
                         "comparison": "COMPARISON_GT", "duration": "0s"}}]}]}
        elif url.endswith("/notificationChannels"):
            if self.deny_channels or (self.partial_channels and kwargs.get("params", {}).get("pageToken")):
                error = gcp.ReadError("denied", "PERMISSION_DENIED", http_status=403)
                error.request_id = request_id
                self.evidence.append({"id": request_id, "url": url, "method": method, "status": "denied"})
                raise error
            data = {"notificationChannels": copy.deepcopy(self.channels)}
            if self.partial_channels:
                data["nextPageToken"] = "page-2"
        elif url.endswith("/sinks"):
            data = {"sinks": []}
        else:
            data = {}
        self.evidence.append({"id": request_id, "url": url, "method": method, "status": "collected"})
        return data, request_id


def channel(suffix="c", **fields):
    return {"name": SCOPE + "/notificationChannels/" + suffix, "type": "email", **fields}


def collect(channels, *, deny_channels=False, partial_channels=False):
    transport = FakeTransport(channels, deny_channels=deny_channels, partial_channels=partial_channels)
    connector = {"provider": "gcp", "scopes": [SCOPE], "options": {"inventories": ["project", "logging_metric",
        "monitoring_alert_policy", "monitoring_notification_channel", "log_sink"], "concurrency": 1}}
    snapshot = gcp.GCPCollector(connector, transport=transport).collect()
    assert validate(snapshot) == snapshot
    channel_reads = [r for r in transport.requests if r[1].endswith("/notificationChannels")]
    assert channel_reads and channel_reads[0][0] == "GET"
    assert channel_reads[0][2]["params"]["fields"] == (
        # 16bb81e0 also reads labels, projected to a safe destination summary.
        "notificationChannels(name,type,enabled,verificationStatus,labels),nextPageToken")
    return snapshot


def status(snapshot):
    findings = [f for f in evaluate_snapshot(snapshot, checks=[CID])["findings"] if f["check_id"] == CID]
    assert len(findings) == 1
    return findings[0]["status"]




@pytest.mark.parametrize("name,rows,expected", [
    ("enabled", [channel(enabled=True)], "PASS"),
    ("disabled", [channel(enabled=False)], "FAIL"),
    ("omitted", [channel()], "UNKNOWN"),
    ("null", [channel(enabled=None)], "UNKNOWN"),
    ("malformed", [channel(enabled="true")], "UNKNOWN"),
    ("foreign", [{"name": "projects/foreign/notificationChannels/c", "type": "email", "enabled": True}], "FAIL"),
    ("enabled_with_unread_sibling", [channel("unread"), channel(enabled=True)], "PASS"),
])
def test_projected_channel_field_cases(name, rows, expected):
    snapshot = collect(rows)
    assert status(snapshot) == expected, name


def test_field_denied_and_verified_sibling():
    snapshot = collect([channel("unread"), channel(enabled=True)])
    inventory = next(c for c in snapshot["collections"] if c["type"] == "monitoring_notification_channel")
    unread = next(row for row in inventory["items"] if row["name"].endswith("/unread"))
    unread["_coverage"] = {"enabled": {"status": "denied"}}
    snapshot.pop("snapshot_id")  # Re-seal the intentionally altered field projection.
    assert status(snapshot) == "PASS"
    other = next(row for row in inventory["items"] if row["name"] == CHANNEL)
    other["enabled"] = False
    assert status(snapshot) == "UNKNOWN"


@pytest.mark.parametrize("mode", ["denied", "partial"])
def test_channel_inventory_unavailable(mode):
    snapshot = collect([channel(enabled=True)], deny_channels=mode == "denied", partial_channels=mode == "partial")
    inventory = next(c for c in snapshot["collections"] if c["type"] == "monitoring_notification_channel")
    assert inventory["status"] not in ("collected", "empty")
    assert status(snapshot) == "UNKNOWN"
