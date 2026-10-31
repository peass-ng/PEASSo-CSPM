"""GKE-side workload reads accept real list items and report why an IP-endpoint read failed."""
from types import SimpleNamespace

import pytest

from peaso.collectors import gcp_gke_exposure_services as services
from peaso.collectors.gcp import ReadError

BINDING = {"selection": "projects/p1/locations/r1/clusters/c1", "endpoint": "34.1.2.3", "ca_sha256": "abc"}


@pytest.mark.parametrize("reader,list_kind,item", [
    (services.ServiceReader, "ServiceList", {"metadata": {"name": "web", "namespace": "default", "uid": "u1"},
                                             "spec": {"type": "LoadBalancer", "ports": [{"port": 80, "protocol": "TCP"}]},
                                             "status": {"loadBalancer": {}}}),
    (services.PodReader, "PodList", {"metadata": {"name": "p", "namespace": "default", "uid": "u2"},
                                     "spec": {"containers": [{"name": "c"}]}, "status": {"phase": "Running"}}),
    (services.NodeReader, "NodeList", {"metadata": {"name": "n", "uid": "u3"}, "spec": {}, "status": {"addresses": []}}),
])
def test_typed_list_items_without_kind_are_projected(reader, list_kind, item):
    # The API server omits kind/apiVersion on items of built-in typed lists.
    data = {"apiVersion": "v1", "kind": list_kind, "metadata": {"resourceVersion": "9"}, "items": [item]}
    rows = reader(SimpleNamespace(transport=None), BINDING, None, {"resources": 0}).project_list(data, reader.PATH)["items"]
    assert len(rows) == 1


def test_ip_endpoint_failure_reason_survives_inapplicable_dns_fallback(monkeypatch):
    scope = "projects/p1"
    collector = SimpleNamespace(needed={services.KIND}, scopes=[scope], transport=None,
        collections={("gke_cluster", scope): {"status": "collected", "coverage_status": "collected",
            "items": [{"name": "c1", "location": "r1"}], "source_requests": ["cluster-request"]}})
    monkeypatch.setattr(services, "cluster_binding", lambda *_: dict(BINDING))
    monkeypatch.setattr(services, "dns_cluster_binding", lambda *_: (_ for _ in ()).throw(
        ReadError("unavailable", "gke_cluster_dns_endpoint_external_access_disabled")))
    def pages(reader):
        raise ReadError("denied", "gke_exposure_services_read_unavailable")
        yield
    monkeypatch.setattr(services.ServiceReader, "pages", pages)
    marker = [row for page, _ in services.dependent_jobs(collector)[0][3]() for row in page][-1]
    assert marker["inventoryStatus"] == "unavailable"
    assert marker["reason"] == "gke_exposure_services_read_unavailable"


def reader_with_status(monkeypatch, reader_type, status):
    import time
    from threading import Lock

    class Response:
        chunked = False
        def __init__(self):
            self.status = status
        def getheader(self, key, default=None):
            return {"Content-Length": "2"}.get(key, default)
        def read(self, size):
            return b""
        def close(self):
            pass

    class Connection:
        def __init__(self, host, **kwargs):
            pass
        def request(self, *args, **kwargs):
            pass
        def getresponse(self):
            return Response()
        def close(self):
            pass
    monkeypatch.setattr(services.http.client, "HTTPSConnection", Connection)
    monkeypatch.setattr(services, "existing_bearer", lambda _: "t")
    transport = SimpleNamespace(lock=Lock(), calls=0, max_calls=None, evidence=[], check_cancelled=lambda: None)
    budget = {"deadline": time.monotonic() + 10, "calls": 0, "read_bytes": services.MAX_READ_BYTES, "resources": 0}
    return reader_type(SimpleNamespace(transport=transport), dict(BINDING, context=object()), None, budget)


def test_unserved_gateway_api_is_empty_but_unserved_core_api_is_not(monkeypatch):
    assert [rows for rows, _ in reader_with_status(monkeypatch, services.GatewayReader, 404).pages()] == [[]]
    with pytest.raises(ReadError):
        list(reader_with_status(monkeypatch, services.ServiceReader, 404).pages())


def test_endpointslice_with_null_endpoints_and_ports_is_projected():
    entry = {"addressType": "IPv4", "endpoints": None, "ports": None,
             "metadata": {"name": "web-abc", "namespace": "default", "uid": "u4",
                          "labels": {"kubernetes.io/service-name": "web"}}}
    data = {"apiVersion": "discovery.k8s.io/v1", "kind": "EndpointSliceList", "metadata": {"resourceVersion": "9"},
            "items": [entry]}
    reader = services.EndpointSliceReader(SimpleNamespace(transport=None), BINDING, None, {"resources": 0})
    assert len(reader.project_list(data, reader.PATH)["items"]) == 1


def test_related_k8s_snapshot_fills_unread_gke_service_inventory():
    import hashlib
    from peaso.analysis.gke_related_workloads import join
    from peaso.snapshot import make_snapshot
    selection = BINDING["selection"]
    cluster_id = "k8s-cluster:" + hashlib.sha256(b"https://34.1.2.3").hexdigest()
    service = {"metadata": {"name": "web", "namespace": "default", "uid": "u1", "resourceVersion": "3"},
               "spec": {"type": "LoadBalancer", "ports": [{"port": 80, "protocol": "TCP", "nodePort": 30080}]},
               "status": {"loadBalancer": {"ingress": [{"ip": "34.9.9.9"}]}}}
    related = make_snapshot("k8s", ["*"], [{"type": "service", "scope": "*", "status": "collected", "items": [service]}],
                            metadata={"cluster_id": cluster_id})
    resources = [
        {"id": "cluster", "type": "gke_cluster", "scope": "projects/p1", "provider": "gcp",
         "data": {"name": "c1", "location": "r1", "endpoint": "34.1.2.3"}},
        {"id": "marker", "type": services.KIND, "scope": "projects/p1", "provider": "gcp", "service": "kubernetes",
         "data": {"name": selection + "/serviceInventory", "cluster": selection, "inventoryStatus": "unavailable",
                  "reason": "gke_exposure_services_read_unavailable"}}]
    joined = join(resources, [related])
    marker = next(r for r in joined if r["id"] == "marker")
    assert marker["data"]["inventoryStatus"] == "collected" and marker["data"]["source"] == "related_k8s_snapshot"
    rows = [r["data"] for r in joined if r["type"] == services.KIND and r["id"] != "marker"]
    assert [(r["kubernetesName"], r["spec"]["type"]) for r in rows] == [("web", "LoadBalancer")]
    other = make_snapshot("k8s", ["*"], [{"type": "service", "scope": "*", "status": "collected", "items": [service]}],
                          metadata={"cluster_id": "k8s-cluster:other"})
    assert join(resources, [other]) == resources
