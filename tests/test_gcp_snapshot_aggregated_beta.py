"""The saved v1 404 for snapshots must not hide regional or global snapshots."""

from peaso.collectors import gcp


PROJECT = "projects/p1"


def test_snapshot_aggregated_list_uses_documented_beta_route_and_keeps_scopes():
    class Transport:
        def __init__(self):
            self.calls = []

        def request(self, method, url, **kwargs):
            self.calls.append((method, url, kwargs))
            assert method == "GET"
            if url.endswith("/getIamPolicy"):
                return {"bindings": [], "version": 3}, "iam-read"
            assert url == "https://compute.googleapis.com/compute/beta/" + PROJECT + "/aggregated/snapshots"
            return {"items": {
                "global": {"snapshots": [{"name": "global-copy", "selfLink":
                    "https://compute.googleapis.com/compute/v1/" + PROJECT + "/global/snapshots/global-copy"}]},
                "regions/us-central1": {"snapshots": [{"name": "regional-copy", "region":
                    "https://compute.googleapis.com/compute/v1/" + PROJECT + "/regions/us-central1",
                    "selfLink": "https://compute.googleapis.com/compute/beta/" + PROJECT +
                    "/regions/us-central1/snapshots/regional-copy"}]}
            }}, "snapshot-read"

    transport = Transport()
    collector = gcp.GCPCollector({"provider": "gcp", "scopes": [PROJECT], "options": {
        "inventories": ["snapshot"], "include_inherited": False,
        "compute_resource_iam": True, "concurrency": 1}}, transport=transport)
    job, = [row for row in collector.scope_jobs(PROJECT) if row[0] == "snapshot"]
    envelope = collector.envelope(*job[:3], job[3])
    assert envelope["status"] == "collected"
    assert {item["name"] for item in envelope["items"]} == {"global-copy", "regional-copy"}
    assert all(item["iamPolicy"]["bindings"] == [] for item in envelope["items"])
    assert len(transport.calls) == 3
