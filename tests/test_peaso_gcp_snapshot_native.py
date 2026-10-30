"""The Compute snapshot inventory includes global and regional policies."""

from peaso.collectors.gcp import GCPCollector


PROJECT = "projects/p1"
BASE = "https://compute.googleapis.com/compute/v1/" + PROJECT
# The cross-region snapshot aggregatedList exists only in Compute beta (9b483c7d).
LIST = "https://compute.googleapis.com/compute/beta/" + PROJECT + "/aggregated/snapshots"


def test_aggregated_snapshots_read_each_exact_policy():
    collector = GCPCollector({"scopes": [PROJECT], "options": {
        "inventories": ["snapshot"], "concurrency": 1, "hydration_concurrency": 1}},
        ["snapshot"], transport=object())
    collector.discover = lambda: None
    reads = []

    def row(location):
        return {"name": "backup", "selfLink": BASE + f"/{location}/snapshots/backup",
                "status": "READY", **({"region": BASE + "/" + location}
                                    if location.startswith("regions/") else {})}

    def read(url, scope, **kwargs):
        reads.append(url)
        if url == LIST:
            return {"items": {"global": {"snapshots": [row("global")]},
                              "regions/us-central1": {"snapshots": [row("regions/us-central1")]}}}, "list-read"
        if url.endswith("/getIamPolicy"):
            return {"bindings": []}, "policy-read"
        raise AssertionError(url)

    collector.read = read
    result = collector.collect()
    snapshots = next(c for c in result["collections"] if c["type"] == "snapshot")
    assert snapshots["status"] == "collected"
    assert len(snapshots["items"]) == 2
    assert reads == [LIST,
                     BASE + "/global/snapshots/backup/getIamPolicy",
                     BASE + "/regions/us-central1/snapshots/backup/getIamPolicy"]
    assert all(item["_coverage"]["iamPolicy"]["status"] == "collected"
               for item in snapshots["items"])
