"""A K8s snapshot keeps the GKE load-balancer annotations a GCP-side join needs, and nothing else."""
import hashlib

from peaso.analysis.gke_related_workloads import join
from peaso.collectors import gcp_gke_exposure_services as services
from peaso.collectors import k8s
from peaso.snapshot import make_snapshot

SELECTION = "projects/p1/locations/r1/clusters/c1"
EDGE = {"service.kubernetes.io/tcp-forwarding-rule": "a1b2c3",
        "service.kubernetes.io/backend-service": "k8s2-backend",
        "cloud.google.com/load-balancer-type": "Internal"}
SERVICE = {"metadata": {"name": "web", "namespace": "default", "uid": "u1", "resourceVersion": "3",
                        "annotations": {**EDGE, "example.com/db-password-hint": "s3cr3t-value",
                                        "kubectl.kubernetes.io/last-applied-configuration": "{\"secret\":\"x\"}",
                                        "service.kubernetes.io/backend-service-oversized": "x"}},
           "spec": {"type": "LoadBalancer", "ports": [{"port": 80, "protocol": "TCP", "nodePort": 30080}]},
           "status": {"loadBalancer": {"ingress": [{"ip": "34.9.9.9"}]}}}


def test_sanitizer_keeps_only_bounded_cloud_edge_annotations():
    kept = k8s._sanitize(SERVICE)["metadata"]["annotations"]
    assert kept == EDGE
    oversized = {"metadata": {"annotations": {"service.kubernetes.io/backend-service": "x" * 5000}}}
    assert k8s._sanitize(oversized)["metadata"]["annotations"] == {}


def test_joined_gke_service_carries_its_load_balancer_annotations():
    cluster_id = "k8s-cluster:" + hashlib.sha256(b"https://34.1.2.3").hexdigest()
    item = k8s._sanitize(SERVICE)
    related = make_snapshot("k8s", ["*"], [{"type": "service", "scope": "*", "status": "collected", "items": [item]}],
                            metadata={"cluster_id": cluster_id})
    resources = [
        {"id": "cluster", "type": "gke_cluster", "scope": "projects/p1", "provider": "gcp",
         "data": {"name": "c1", "location": "r1", "endpoint": "34.1.2.3"}},
        {"id": "marker", "type": services.KIND, "scope": "projects/p1", "provider": "gcp", "service": "kubernetes",
         "data": {"name": SELECTION + "/serviceInventory", "cluster": SELECTION, "inventoryStatus": "unavailable",
                  "reason": "gke_exposure_services_read_unavailable"}}]
    rows = [r["data"] for r in join(resources, [related]) if r["type"] == services.KIND and r["id"] != "marker"]
    assert [row["annotations"] for row in rows] == [EDGE]
