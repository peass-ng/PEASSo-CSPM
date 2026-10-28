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
    monkeypatch.setattr(services, "dns_cluster_binding", lambda *_: (_ for _ in ()).throw(
        ReadError("unavailable", "gke_cluster_endpoint_or_ca_unproved")))
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


def test_dns_binding_requires_exact_source_receipt_and_enabled_endpoint():
    scope = "projects/p1"
    selection = scope + "/locations/r1/clusters/c1"
    row = {"name": "c1", "location": "r1", "status": "RUNNING",
        "selfLink": f"https://container.googleapis.com/v1/{selection}",
        "_provenance": {"scope": scope, "source_requests": ["cluster-request"]},
        "controlPlaneEndpointsConfig": {"dnsEndpointConfig": {
            "endpoint": "abc.r1.gke.goog", "allowExternalTraffic": True}}}
    receipt = {"id": "cluster-request", "scope": scope, "method": "GET", "status": "collected",
        "http_status": 200, "query": {},
        "url": f"https://container.googleapis.com/v1/{scope}/locations/-/clusters"}
    collector = SimpleNamespace(collections={("gke_cluster", scope): {"status": "collected",
        "coverage_status": "collected", "items": [row]}}, transport=SimpleNamespace(evidence=[receipt]))
    binding = services.dns_cluster_binding(collector, scope, selection)
    assert binding["endpoint"] == "abc.r1.gke.goog"
    assert binding["context"].check_hostname is True
    assert binding["context"].verify_mode == services.ssl.CERT_REQUIRED
    assert binding["ca_sha256"] is None
    for endpoint in ("abc.r1.gke.goog.evil.test", "https://abc.r1.gke.goog", "ABC.r1.gke.goog"):
        row["controlPlaneEndpointsConfig"]["dnsEndpointConfig"]["endpoint"] = endpoint
        with pytest.raises(ReadError, match="gke_cluster_dns_endpoint_unproved"):
            services.dns_cluster_binding(collector, scope, selection)
    row["controlPlaneEndpointsConfig"]["dnsEndpointConfig"].update(
        endpoint="abc.r1.gke.goog", allowExternalTraffic=False)
    with pytest.raises(ReadError, match="gke_cluster_dns_endpoint_unproved"):
        services.dns_cluster_binding(collector, scope, selection)
    row["controlPlaneEndpointsConfig"]["dnsEndpointConfig"]["allowExternalTraffic"] = True
    receipt["http_status"] = 403
    with pytest.raises(ReadError, match="gke_cluster_source_receipt_unproved"):
        services.dns_cluster_binding(collector, scope, selection)


def test_dns_fallback_publishes_only_complete_read(monkeypatch):
    scope = "projects/p1"
    selection = scope + "/locations/r1/clusters/c1"
    collector = SimpleNamespace(needed={services.KIND}, scopes=[scope], transport=None,
        collections={("gke_cluster", scope): {"status": "collected", "coverage_status": "collected",
            "items": [{"name": "c1", "location": "r1"}], "source_requests": ["cluster-request"]}})
    monkeypatch.setattr(services, "cluster_binding", lambda *_: {"selection": selection,
        "endpoint": "34.1.2.3", "ca_sha256": "abc"})
    monkeypatch.setattr(services, "dns_cluster_binding", lambda *_: {"selection": selection,
        "endpoint": "abc.r1.gke.goog", "ca_sha256": None, "endpointTrust": "public_ca"})
    def pages(reader):
        if reader.binding["endpoint"] == "34.1.2.3":
            yield ([{"name": "partial-ip"}], "ip-request")
            raise ReadError("unavailable", "gke_exposure_services_read_unavailable")
        yield ([{"name": "complete-dns"}], "dns-request")
    monkeypatch.setattr(services.ServiceReader, "pages", pages)
    rows = [row for page, _ in services.dependent_jobs(collector)[0][3]() for row in page]
    assert [row["name"] for row in rows] == ["complete-dns", selection + "/serviceInventory"]
    assert rows[-1]["inventoryStatus"] == "collected" and rows[-1]["serviceCount"] == 1


def test_ingress_projection_and_inventory_marker(monkeypatch):
    scope = "projects/p1"
    selection = scope + "/locations/r1/clusters/c1"
    binding = {"selection": selection, "endpoint": "abc.r1.gke.goog",
               "ca_sha256": None, "endpointTrust": "public_ca"}
    reader = services.IngressReader(SimpleNamespace(transport=None), binding, None, {"resources": 0})
    ingress = {"apiVersion": "networking.k8s.io/v1", "kind": "Ingress",
        "metadata": {"name": "web", "namespace": "default", "uid": "ingress-uid",
                     "annotations": {"private.example/token": "secret"}},
        "spec": {"ingressClassName": "gce", "defaultBackend": {"service": {"name": "private-backend"}},
                 "rules": [{"host": "example.com", "http": {"paths": []}}]},
        "status": {"loadBalancer": {"ingress": [{"ip": "34.1.2.3"}]}}}
    data = {"apiVersion": "networking.k8s.io/v1", "kind": "IngressList",
        "metadata": {"resourceVersion": "12"}, "items": [ingress]}
    row = reader.project_list(data, reader.PATH)["items"][0]
    assert row["hosts"] == ["example.com"] and row["hasDefaultBackend"] is True
    assert row["status"]["loadBalancer"]["ingress"] == [{"ip": "34.1.2.3"}]
    assert "secret" not in str(row) and "private-backend" not in str(row)
    ingress["spec"]["rules"][0]["host"] = "x" * 254
    with pytest.raises(ValueError, match="Ingress rules"):
        reader.project_list(data, reader.PATH)
    ingress["spec"]["rules"][0]["host"] = "example.com"
    collector = SimpleNamespace(needed={services.INGRESS_KIND}, scopes=[scope], transport=None,
        collections={("gke_cluster", scope): {"status": "collected", "coverage_status": "collected",
            "items": [{"name": "c1", "location": "r1"}], "source_requests": ["cluster-request"]}})
    monkeypatch.setattr(services, "cluster_binding", lambda *_: binding)
    monkeypatch.setattr(services.IngressReader, "pages", lambda self: iter([([row], "ingress-request")]))
    rows = [item for page, _ in services.dependent_jobs(collector, services.INGRESS_KIND)[0][3]() for item in page]
    assert len(rows) == 2 and rows[-1]["inventoryStatus"] == "collected"
    assert rows[-1]["ingressCount"] == 1
