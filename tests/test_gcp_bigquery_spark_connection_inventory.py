"""Spark connection identity and policy reads are bound to a dataset location."""

import sys
import types
from pathlib import Path


PROJECT = "projects/p1"
CONNECTION = PROJECT + "/locations/US/connections/spark1"
EMAIL = "bqcx-123@gcp-sa-bigquery-consp.iam.gserviceaccount.com"


def collect(monkeypatch, *, denied_policy=False, bad_identity=False, denied_routines=False):
    package = types.ModuleType("peaso.collectors")
    package.__path__ = [str(Path(__file__).resolve().parents[1] / "peaso" / "collectors")]
    monkeypatch.setitem(sys.modules, "peaso.collectors", package)
    from peaso.collectors import gcp

    class Transport:
        def __init__(self):
            self.calls = []

        def request(self, method, url, **kwargs):
            self.calls.append((method, url, kwargs))
            if url.endswith("/datasets"):
                return {"datasets": [{"id": "p1:private", "datasetReference":
                    {"projectId": "p1", "datasetId": "private"}}]}, "dataset-list"
            if url.endswith("/datasets/private"):
                return {"id": "p1:private", "datasetReference":
                    {"projectId": "p1", "datasetId": "private"}, "location": "US", "access": []}, "dataset-get"
            if url.endswith("/connections"):
                return {"connections": [{"name": CONNECTION}]}, "connection-list"
            if url.endswith("/connections/spark1"):
                return {"name": CONNECTION + "-wrong" if bad_identity else CONNECTION,
                        "spark": {"serviceAccountId": EMAIL}}, "connection-get"
            if url.endswith("/connections/spark1:getIamPolicy"):
                if denied_policy:
                    raise gcp.ReadError("denied", "permission_denied", http_status=403)
                return {"bindings": []}, "connection-policy"
            if url.endswith("/datasets/private/routines"):
                if denied_routines:
                    raise gcp.ReadError("denied", "permission_denied", http_status=403)
                return {"routines": [{"routineReference": {"projectId": "p1",
                    "datasetId": "private", "routineId": "existing_spark"},
                    "routineType": "PROCEDURE", "language": "PYTHON",
                    "definitionBody": "private code must not enter metadata"}]}, "routine-list"
            if url.endswith("/routines/existing_spark:getIamPolicy"):
                # Routine IAM is hydrated for the public-routine join (02d8d6d5).
                return {"bindings": []}, "routine-policy"
            raise AssertionError(url)

    transport = Transport()
    collector = gcp.GCPCollector({"provider": "gcp", "scopes": [PROJECT], "options": {
        "inventories": ["bigquery_connection", "bigquery_routine_metadata"], "include_inherited": False,
        "metrics_scopes": False, "concurrency": 1}}, transport=transport)
    collector._data_project_binding = lambda scope: {"project_id": "p1", "project_number": "111"}
    return collector.collect(), transport


def test_spark_connection_identity_and_policy_are_collected(monkeypatch):
    snap, transport = collect(monkeypatch)
    row = next(c for c in snap["collections"] if c["type"] == "bigquery_connection")
    assert row["status"] == "collected"
    item, = row["items"]
    assert item["name"] == CONNECTION
    assert item["spark"]["serviceAccountId"] == EMAIL
    assert item["_coverage"]["iamPolicy"]["status"] == "collected"
    assert any(method == "POST" and url.endswith(CONNECTION + ":getIamPolicy")
               for method, url, _ in transport.calls)


def test_denied_policy_and_wrong_detail_identity_remain_incomplete(monkeypatch):
    denied, _ = collect(monkeypatch, denied_policy=True)
    row = next(c for c in denied["collections"] if c["type"] == "bigquery_connection")
    assert row["items"][0]["_coverage"]["iamPolicy"]["status"] == "denied"
    bad, _ = collect(monkeypatch, bad_identity=True)
    row = next(c for c in bad["collections"] if c["type"] == "bigquery_connection")
    assert row["items"][0]["_coverage"]["connectionDetails"]["status"] == "malformed"


def test_routine_inventory_keeps_only_bound_metadata(monkeypatch):
    snap, _ = collect(monkeypatch)
    row = next(c for c in snap["collections"] if c["type"] == "bigquery_routine_metadata")
    assert row["status"] == "collected"
    routine, = row["items"]
    assert routine["name"] == PROJECT + "/datasets/private/routines/existing_spark"
    assert routine["routineType"] == "PROCEDURE"
    assert routine["datasetLocation"] == "US"
    assert "definitionBody" not in routine
    assert routine["_coverage"]["iamPolicy"]["status"] == "collected"
    denied, _ = collect(monkeypatch, denied_routines=True)
    row = next(c for c in denied["collections"] if c["type"] == "bigquery_routine_metadata")
    assert row["status"] == "denied"
