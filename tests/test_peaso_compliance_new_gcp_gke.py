"""Semantic fixtures for the signed GKE public-IP endpoint scope check."""
from peaso.checks import CHECKS, evaluate_check


CHECK_ID = "gcp_gke_cluster_endpoint_publicly_accessible_ea8dcc0ec97d"
_registered = [check for check in CHECKS if check.id == CHECK_ID]
if _registered:
    assert len(_registered) == 1
    assert _registered[0].evaluate.__module__ == "peaso.checks.batch_remaining_gcp"
else:
    from peaso.checks import compliance_new_gcp_gke  # noqa: F401: isolated draft registration


def cluster(name, public):
    return {"name": name, "controlPlaneEndpointsConfig": {"ipEndpointsConfig": {"enablePublicEndpoint": public}}}


def scoped(rows, status="collected"):
    return {"collections": {"gke_cluster": [{"scope": "projects/inert", "status": status}]},
            "gke_cluster": [{"data": row} for row in rows]}


def evaluate(rows, status="collected"):
    return evaluate_check(CHECK_ID, {"scope": "projects/inert"}, scoped(rows, status))


def test_public_ip_endpoint_requires_explicit_complete_cluster_facts():
    assert evaluate([cluster("private", False)])[0] == "PASS"
    status, evidence = evaluate([cluster("private", False), cluster("public", True)])
    assert status == "FAIL" and evidence["public_ip_endpoint_clusters"] == ["public"]
    assert evaluate([cluster("private", False), {"name": "missing"}])[0] == "UNKNOWN"
    assert evaluate([cluster("private", False), cluster("public", True)], "partial")[0] == "UNKNOWN"
    assert evaluate([cluster("private", False)], "denied")[0] == "UNKNOWN"
    assert evaluate([{"name": "bad", "controlPlaneEndpointsConfig": {"ipEndpointsConfig": {"enablePublicEndpoint": "false"}}}])[0] == "UNKNOWN"
    assert evaluate([cluster("covered", False) | {"_coverage": {"controlPlaneEndpointsConfig": {"status": "denied"}}}])[0] == "UNKNOWN"
    assert evaluate([], "empty")[0] == "NOT_APPLICABLE"
