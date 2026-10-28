"""GKE Exposure Service bridge preserves complete reads and explicit gaps."""

from types import SimpleNamespace
from threading import Lock
import json
import time

import pytest

from peaso.collectors import gcp_gke_exposure_services as services
from peaso.collectors.gcp import ReadError


def test_service_projection_keeps_network_fields_without_arbitrary_annotations():
    binding = {"selection": "projects/p1/locations/r1/clusters/c1", "endpoint": "34.1.2.3",
               "ca_sha256": "abc"}
    reader = services.ServiceReader(SimpleNamespace(transport=None), binding, None, {"resources": 0})
    service = {"apiVersion": "v1", "kind": "Service", "metadata": {
        "name": "web", "namespace": "default", "uid": "service-uid", "resourceVersion": "10",
        "annotations": {"cloud.google.com/load-balancer-type": "External", "private.example/token": "secret"}},
        "spec": {"type": "LoadBalancer", "ports": [{"port": 443, "nodePort": 30443, "protocol": "TCP"}],
                 "loadBalancerSourceRanges": ["0.0.0.0/0"], "selector": {"app": "private"}},
        "status": {"loadBalancer": {"ingress": [{"ip": "34.5.6.7"}]}}}
    projected = reader.project_list({"apiVersion": "v1", "kind": "ServiceList",
        "metadata": {"resourceVersion": "10"}, "items": [service]}, "/api/v1/services")
    row = projected["items"][0]
    assert row["spec"]["type"] == "LoadBalancer"
    assert row["status"]["loadBalancer"]["ingress"] == [{"ip": "34.5.6.7"}]
    assert "selector" not in str(row) and "secret" not in str(row)
    service["spec"]["loadBalancerSourceRanges"] = "not-a-list"
    with pytest.raises(ValueError, match="address/range"):
        reader.project_list({"apiVersion": "v1", "kind": "ServiceList",
            "metadata": {"resourceVersion": "10"}, "items": [service]}, "/api/v1/services")
    service["spec"]["loadBalancerSourceRanges"] = ["0.0.0.0/0"]
    service["spec"]["type"] = "unrecognized"
    with pytest.raises(ValueError, match="Service type"):
        reader.project_list({"apiVersion": "v1", "kind": "ServiceList",
            "metadata": {"resourceVersion": "10"}, "items": [service]}, "/api/v1/services")


def test_all_discovered_clusters_receive_service_inventory_markers(monkeypatch):
    scope = "projects/p1"
    clusters = [{"name": "c1", "location": "r1"}, {"name": "c2", "location": "r1"}]
    collector = SimpleNamespace(needed={services.KIND}, scopes=[scope], transport=None,
        collections={("gke_cluster", scope): {"status": "collected", "coverage_status": "collected",
            "items": clusters, "source_requests": ["cluster-request"]}})
    def binding(_, __, selection):
        if selection.endswith("/c2"):
            raise ReadError("unavailable", "gke_cluster_endpoint_or_ca_unproved")
        return {"selection": selection, "endpoint": "34.1.2.3", "ca_sha256": "abc"}
    monkeypatch.setattr(services, "cluster_binding", binding)
    monkeypatch.setattr(services.ServiceReader, "pages", lambda self: iter([([
        {"name": self.binding["selection"] + "/namespaces/default/services/web"}], "service-request")]))
    jobs = services.dependent_jobs(collector)
    assert len(jobs) == 1
    rows = [row for page, _ in jobs[0][3]() for row in page]
    assert len(rows) == 3
    assert rows[1]["inventoryStatus"] == "collected" and rows[1]["serviceCount"] == 1
    assert rows[2]["inventoryStatus"] == "unavailable"
    assert rows[2]["reason"] == "gke_cluster_endpoint_or_ca_unproved"
    collector.collections[("gke_cluster", scope)]["status"] = "partial"
    incomplete = [row for page, _ in services.dependent_jobs(collector)[0][3]() for row in page]
    assert incomplete == [{"name": scope + "/gkeServiceInventory", "inventoryStatus": "unavailable",
                           "reason": "gke_cluster_inventory_incomplete"}]
    collector.collections[("gke_cluster", scope)].update(status="empty", coverage_status="empty", items=[])
    assert [page for page, _ in services.dependent_jobs(collector)[0][3]()] == [[]]


def test_service_reader_uses_verified_get_and_records_no_bearer(monkeypatch):
    body = json.dumps({"apiVersion": "v1", "kind": "ServiceList", "metadata": {"resourceVersion": "10"},
                       "items": []}).encode()
    calls = []
    class Response:
        status = 200
        chunked = False
        def __init__(self):
            self.remaining = body
        def getheader(self, key, default=None):
            return {"Content-Length": str(len(body))}.get(key, default)
        def read(self, size):
            result, self.remaining = self.remaining[:size], self.remaining[size:]
            return result
        def close(self):
            pass
    class Connection:
        def __init__(self, host, **kwargs):
            assert host == "34.1.2.3" and kwargs["port"] == 443
        def request(self, method, path, headers):
            calls.append((method, path, headers))
        def getresponse(self):
            return Response()
        def close(self):
            pass
    monkeypatch.setattr(services.http.client, "HTTPSConnection", Connection)
    monkeypatch.setattr(services, "existing_bearer", lambda _: "test-token")
    transport = SimpleNamespace(lock=Lock(), calls=0, max_calls=None, evidence=[], check_cancelled=lambda: None)
    binding = {"selection": "projects/p1/locations/r1/clusters/c1", "endpoint": "34.1.2.3",
               "context": object(), "ca_sha256": "abc"}
    budget = {"deadline": time.monotonic() + 10, "calls": 0, "read_bytes": services.MAX_READ_BYTES,
              "resources": 0}
    reader = services.ServiceReader(SimpleNamespace(transport=transport), binding, None, budget)
    assert list(reader.pages()) == [([], "request-1")]
    assert calls[0][0:2] == ("GET", "/api/v1/services?limit=25")
    assert calls[0][2]["Authorization"] == "Bearer test-token"
    assert "test-token" not in str(transport.evidence)
    assert transport.evidence[0]["status"] == "collected"
