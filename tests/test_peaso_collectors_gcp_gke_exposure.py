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
        "annotations": {"cloud.google.com/load-balancer-type": "External", "private.example/token": "secret",
                        "cloud.google.com/neg": '{"exposed_ports":{"443":{}}}',
                        "cloud.google.com/neg-status": '{"network_endpoint_groups":{"443":"k8s1-neg-web"},"zones":["us-central1-a"]}',
                        "service.kubernetes.io/backend-service": "k8s-be-web",
                        "service.kubernetes.io/tcp-forwarding-rule": "k8s-fw-web",
                        "service.kubernetes.io/l3-forwarding-rule": "k8s-fw-mixed"}},
        "spec": {"type": "LoadBalancer", "ports": [{"port": 443, "nodePort": 30443, "protocol": "TCP"}],
                 "loadBalancerSourceRanges": ["0.0.0.0/0"], "selector": {"app": "private"}},
        "status": {"loadBalancer": {"ingress": [{"ip": "34.5.6.7"}]}}}
    projected = reader.project_list({"apiVersion": "v1", "kind": "ServiceList",
        "metadata": {"resourceVersion": "10"}, "items": [service]}, "/api/v1/services")
    row = projected["items"][0]
    assert row["spec"]["type"] == "LoadBalancer"
    assert row["status"]["loadBalancer"]["ingress"] == [{"ip": "34.5.6.7"}]
    assert row["annotations"]["service.kubernetes.io/backend-service"] == "k8s-be-web"
    assert row["annotations"]["service.kubernetes.io/tcp-forwarding-rule"] == "k8s-fw-web"
    assert row["annotations"]["service.kubernetes.io/l3-forwarding-rule"] == "k8s-fw-mixed"
    assert row["negConfigured"] is True and row["negStatus"] == {
        "networkEndpointGroups": {"443": "k8s1-neg-web"}, "zones": ["us-central1-a"]}
    assert "selector" not in str(row) and "secret" not in str(row)
    assert "cloud.google.com/neg-status" not in str(row)
    service["metadata"]["annotations"]["cloud.google.com/neg-status"] = "{invalid"
    assert reader.project_list({"apiVersion": "v1", "kind": "ServiceList",
        "metadata": {"resourceVersion": "10"}, "items": [service]}, "/api/v1/services")["items"][0]["negStatusUnresolved"] is True
    service["spec"]["loadBalancerSourceRanges"] = "not-a-list"
    with pytest.raises(ValueError, match="address/range"):
        reader.project_list({"apiVersion": "v1", "kind": "ServiceList",
            "metadata": {"resourceVersion": "10"}, "items": [service]}, "/api/v1/services")
    service["spec"]["loadBalancerSourceRanges"] = ["0.0.0.0/0"]
    service["spec"]["type"] = "unrecognized"
    with pytest.raises(ValueError, match="Service type"):
        reader.project_list({"apiVersion": "v1", "kind": "ServiceList",
            "metadata": {"resourceVersion": "10"}, "items": [service]}, "/api/v1/services")
    service["spec"]["type"] = "NodePort"
    service["spec"]["ports"][0]["targetPort"] = {"secret": "private"}
    with pytest.raises(ValueError, match="Service port value"):
        reader.project_list({"apiVersion": "v1", "kind": "ServiceList",
            "metadata": {"resourceVersion": "10"}, "items": [service]}, "/api/v1/services")
    service["spec"]["ports"][0]["targetPort"] = 8080
    service["spec"]["externalTrafficPolicy"] = "unrecognized"
    with pytest.raises(ValueError, match="external traffic policy"):
        reader.project_list({"apiVersion": "v1", "kind": "ServiceList",
            "metadata": {"resourceVersion": "10"}, "items": [service]}, "/api/v1/services")


def test_endpointslice_projection_keeps_ready_nodes_without_endpoint_addresses():
    binding = {"selection": "projects/p1/locations/r1/clusters/c1", "endpoint": "34.1.2.3",
               "ca_sha256": "abc"}
    reader = services.EndpointSliceReader(SimpleNamespace(transport=None), binding, None,
                                          {"resources": 0})
    item = {"apiVersion": "discovery.k8s.io/v1", "kind": "EndpointSlice",
            "metadata": {"name": "web-abc", "namespace": "default", "uid": "slice-uid",
                         "labels": {"kubernetes.io/service-name": "web", "private/token": "secret"}},
            "addressType": "IPv4", "ports": [{"name": "http", "port": 8080, "protocol": "TCP"}],
            "endpoints": [{"addresses": ["10.1.2.3"], "nodeName": "node-a", "conditions": {}},
                          {"addresses": ["10.1.2.4"], "nodeName": "node-b",
                           "conditions": {"ready": False}},
                          {"addresses": ["10.1.2.5"], "nodeName": "node-c",
                           "conditions": {"terminating": True}},
                          {"addresses": ["10.1.2.6"], "nodeName": "node-d",
                           "conditions": {"serving": False}}]}
    data = {"apiVersion": "discovery.k8s.io/v1", "kind": "EndpointSliceList",
            "metadata": {"resourceVersion": "12"}, "items": [item]}
    row = reader.project_list(data, reader.PATH)["items"][0]
    assert row["serviceName"] == "web" and row["readyEndpointCount"] == 1
    assert row["readyNodeNames"] == ["node-a"] and row["ports"][0]["port"] == 8080
    assert "10.1.2" not in str(row) and "secret" not in str(row)
    item["endpoints"][0]["conditions"] = {"ready": "true"}
    with pytest.raises(ValueError, match="conditions"):
        reader.project_list(data, reader.PATH)


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
                     "annotations": {"private.example/token": "secret", "kubernetes.io/ingress.class": "gce",
                                     "ingress.kubernetes.io/forwarding-rule": "k8s-fw-web",
                                     "ingress.kubernetes.io/target-proxy": "k8s-tp-web",
                                     "ingress.kubernetes.io/url-map": "k8s-um-web"}},
        "spec": {"ingressClassName": "gce", "defaultBackend": {"service": {"name": "private-backend"}},
                 "rules": [{"host": "example.com", "http": {"paths": []}}]},
        "status": {"loadBalancer": {"ingress": [{"ip": "34.1.2.3"}]}}}
    data = {"apiVersion": "networking.k8s.io/v1", "kind": "IngressList",
        "metadata": {"resourceVersion": "12"}, "items": [ingress]}
    row = reader.project_list(data, reader.PATH)["items"][0]
    assert row["hosts"] == ["example.com"] and row["hasDefaultBackend"] is True
    assert row["status"]["loadBalancer"]["ingress"] == [{"ip": "34.1.2.3"}]
    assert row["annotations"] == {"kubernetes.io/ingress.class": "gce",
                                  "ingress.kubernetes.io/forwarding-rule": "k8s-fw-web",
                                  "ingress.kubernetes.io/target-proxy": "k8s-tp-web",
                                  "ingress.kubernetes.io/url-map": "k8s-um-web"}
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


def test_multicluster_ingress_projection_and_inventory_marker(monkeypatch):
    scope = "projects/p1"
    selection = scope + "/locations/r1/clusters/c1"
    binding = {"selection": selection, "endpoint": "abc.r1.gke.goog",
               "ca_sha256": None, "endpointTrust": "public_ca"}
    reader = services.MultiClusterIngressReader(SimpleNamespace(transport=None), binding, None, {"resources": 0})
    ingress = {"apiVersion": "networking.gke.io/v1", "kind": "MultiClusterIngress",
        "metadata": {"name": "web", "namespace": "default", "uid": "mci-uid",
                     "annotations": {"private.example/token": "secret"}},
        "spec": {"template": {"spec": {"backend": {"serviceName": "private-backend"}}}},
        "status": {"VIP": "34.1.2.3", "cloudResources": {
            "forwardingRules": ["mci-forward"], "targetProxies": ["mci-proxy"],
            "urlMap": "mci-map", "backendServices": ["mci-backend"]}}}
    data = {"apiVersion": "networking.gke.io/v1", "kind": "MultiClusterIngressList",
        "metadata": {"resourceVersion": "12"}, "items": [ingress]}
    row = reader.project_list(data, reader.PATH)["items"][0]
    assert row["VIP"] == "34.1.2.3" and row["cloudResources"]["urlMap"] == ["mci-map"]
    assert "secret" not in str(row) and "private-backend" not in str(row)
    legacy = services.LegacyMultiClusterIngressReader(SimpleNamespace(transport=None), binding, None, {"resources": 0})
    data["apiVersion"] = ingress["apiVersion"] = "networking.gke.io/v1beta1"
    assert legacy.project_list(data, legacy.PATH)["items"][0]["VIP"] == "34.1.2.3"
    data["apiVersion"] = ingress["apiVersion"] = "networking.gke.io/v1"
    ingress["status"]["cloudResources"]["forwardingRules"] = ["bad/name"]
    with pytest.raises(ValueError, match="cloud resource names"):
        reader.project_list(data, reader.PATH)
    ingress["status"]["cloudResources"]["forwardingRules"] = ["mci-forward"]
    collector = SimpleNamespace(needed={services.MULTICLUSTERINGRESS_KIND}, scopes=[scope], transport=None,
        collections={("gke_cluster", scope): {"status": "collected", "coverage_status": "collected",
            "items": [{"name": "c1", "location": "r1"}], "source_requests": ["cluster-request"]}})
    monkeypatch.setattr(services, "cluster_binding", lambda *_: binding)
    monkeypatch.setattr(services.MultiClusterIngressReader, "pages", lambda self: iter([([row], "mci-request")]))
    rows = [item for page, _ in services.dependent_jobs(collector, services.MULTICLUSTERINGRESS_KIND)[0][3]() for item in page]
    assert len(rows) == 2 and rows[-1]["inventoryStatus"] == "collected"
    assert rows[-1]["multiclusteringressCount"] == 1
    def unavailable(_):
        raise ReadError("unavailable", "v1_unavailable")
    monkeypatch.setattr(services.MultiClusterIngressReader, "pages", unavailable)
    monkeypatch.setattr(services.LegacyMultiClusterIngressReader, "pages",
                        lambda self: iter([([row], "legacy-mci-request")]))
    rows = [item for page, _ in services.dependent_jobs(collector, services.MULTICLUSTERINGRESS_KIND)[0][3]() for item in page]
    assert len(rows) == 2 and rows[-1]["inventoryStatus"] == "collected"


def test_pod_projection_keeps_only_host_network_facts():
    binding = {"selection": "projects/p1/locations/r1/clusters/c1", "endpoint": "34.1.2.3",
               "ca_sha256": "abc"}
    reader = services.PodReader(SimpleNamespace(transport=None), binding, None, {"resources": 0})
    pod = {"apiVersion": "v1", "kind": "Pod", "metadata": {
        "name": "web-1", "namespace": "default", "uid": "pod-uid",
        "annotations": {"private.example/token": "secret"}},
        "spec": {"hostNetwork": True, "nodeName": "node-a", "containers": [{
            "name": "app", "image": "private-image", "env": [{"value": "password"}],
            "ports": [{"containerPort": 8080, "hostPort": 8080, "protocol": "TCP"}]}]},
        "status": {"phase": "Running", "hostIP": "34.1.2.3", "podIP": "10.1.2.3"}}
    data = {"apiVersion": "v1", "kind": "PodList", "metadata": {"resourceVersion": "12"},
            "items": [pod]}
    row = reader.project_list(data, reader.PATH)["items"][0]
    assert row["hostNetwork"] is True and row["hostPorts"] == [{
        "hostPort": 8080, "protocol": "TCP", "containerKind": "containers",
        "portSource": "hostPort", "bindIP": "0.0.0.0"}]
    assert row["hostIP"] == "34.1.2.3" and row["nodeName"] == "node-a"
    for secret in ("secret", "password", "private-image", "10.1.2.3"):
        assert secret not in str(row)
    pod["spec"]["containers"][0]["ports"][0]["hostPort"] = -1
    with pytest.raises(ValueError, match="hostPort"):
        reader.project_list(data, reader.PATH)
    pod["spec"]["containers"][0]["ports"][0]["hostPort"] = 0
    row = reader.project_list(data, reader.PATH)["items"][0]
    assert row["hostPorts"] == [{"hostPort": 8080, "protocol": "TCP",
                                 "containerKind": "containers", "portSource": "hostNetwork",
                                 "bindIP": "0.0.0.0"}]
    pod["spec"]["containers"][0]["ports"][0]["hostIP"] = "127.0.0.1"
    assert reader.project_list(data, reader.PATH)["items"][0]["hostPorts"][0]["bindIP"] == "127.0.0.1"
    pod["spec"]["containers"][0]["ports"][0]["hostIP"] = "invalid"
    with pytest.raises(ValueError, match="bind address"):
        reader.project_list(data, reader.PATH)
    pod["spec"]["containers"][0]["ports"][0].pop("hostIP")
    pod["spec"]["hostNetwork"] = False
    assert reader.project_list(data, reader.PATH)["items"][0]["hostPorts"] == []


def test_node_projection_keeps_provider_and_addresses_only():
    binding = {"selection": "projects/p1/locations/r1/clusters/c1", "endpoint": "34.1.2.3",
               "ca_sha256": "abc"}
    reader = services.NodeReader(SimpleNamespace(transport=None), binding, None, {"resources": 0})
    node = {"apiVersion": "v1", "kind": "Node", "metadata": {
        "name": "gke-node-1", "uid": "node-uid", "annotations": {"private/token": "secret"}},
        "spec": {"providerID": "gce://p1/us-central1-a/gke-node-1", "taints": [{"value": "private"}]},
        "status": {"addresses": [{"type": "ExternalIP", "address": "34.1.2.3"}],
                   "capacity": {"private": "data"}}}
    data = {"apiVersion": "v1", "kind": "NodeList", "metadata": {"resourceVersion": "12"},
            "items": [node]}
    row = reader.project_list(data, reader.PATH)["items"][0]
    assert row["providerID"] == "gce://p1/us-central1-a/gke-node-1"
    assert row["addresses"] == [{"type": "ExternalIP", "address": "34.1.2.3"}]
    assert "secret" not in str(row) and "private" not in str(row)
    pending = {"apiVersion": "v1", "kind": "Node", "metadata": {
        "name": "gke-node-2", "uid": "pending-uid"}, "spec": {}, "status": {"addresses": []}}
    data["items"].append(pending)
    rows = reader.project_list(data, reader.PATH)["items"]
    assert len(rows) == 2 and rows[1]["providerID"] is None
    node["spec"]["providerID"] = "evil://p1/us-central1-a/gke-node-1"
    with pytest.raises(ValueError, match="identity/provider"):
        reader.project_list(data, reader.PATH)


def test_gateway_and_httproute_project_only_network_routing_facts():
    binding = {"selection": "projects/p1/locations/r1/clusters/c1", "endpoint": "34.1.2.3",
               "ca_sha256": "abc"}
    gateway_reader = services.GatewayReader(SimpleNamespace(transport=None), binding, None, {"resources": 0})
    gateway = {"apiVersion": "gateway.networking.k8s.io/v1", "kind": "Gateway",
        "metadata": {"name": "web", "namespace": "default", "uid": "gateway-uid",
                     "annotations": {"private/token": "secret",
                                     "networking.gke.io/forwarding-rules": "gkegw-fr1",
                                     "networking.gke.io/target-proxies": "gkegw-tp1",
                                     "networking.gke.io/url-maps": "gkegw-url-map1"}},
        "spec": {"gatewayClassName": "gke-l7-global-external-managed",
                 "listeners": [{"name": "https", "port": 443, "protocol": "HTTPS",
                                "hostname": "example.com", "tls": {"certificateRefs": [{"name": "secret"}]}}]},
        "status": {"addresses": [{"type": "IPAddress", "value": "34.1.2.3"}],
                   "conditions": [{"message": "private"}]}}
    row = gateway_reader.project_list({"apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "GatewayList", "metadata": {"resourceVersion": "12"}, "items": [gateway]},
        gateway_reader.PATH)["items"][0]
    assert row["listeners"] == [{"name": "https", "port": 443, "protocol": "HTTPS",
                                 "hostname": "example.com"}]
    assert row["addresses"] == [{"type": "IPAddress", "value": "34.1.2.3"}]
    assert row["annotations"] == {"networking.gke.io/forwarding-rules": "gkegw-fr1",
                                  "networking.gke.io/target-proxies": "gkegw-tp1",
                                  "networking.gke.io/url-maps": "gkegw-url-map1"}
    assert "secret" not in str(row) and "private" not in str(row)
    route_reader = services.HTTPRouteReader(SimpleNamespace(transport=None), binding, None, {"resources": 0})
    route = {"apiVersion": "gateway.networking.k8s.io/v1", "kind": "HTTPRoute",
        "metadata": {"name": "web-route", "namespace": "default", "uid": "route-uid", "generation": 3},
        "spec": {"hostnames": ["example.com"], "parentRefs": [{"name": "web", "sectionName": "https"}],
                 "rules": [{"matches": [{"path": {"value": "/private-token"}}],
                            "backendRefs": [{"name": "web-service", "port": 8080}]}]},
        "status": {"parents": [{"controllerName": "networking.gke.io/gateway",
                                "parentRef": {"name": "web", "sectionName": "https"},
                                "conditions": [{"type": "Accepted", "status": "True", "observedGeneration": 3,
                                                "message": "private"},
                                               {"type": "Reconciled", "status": "True", "observedGeneration": 3}]}]}}
    projected = route_reader.project_list({"apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "HTTPRouteList", "metadata": {"resourceVersion": "12"}, "items": [route]},
        route_reader.PATH)["items"][0]
    assert projected["parentRefs"] == [{"name": "web", "sectionName": "https"}]
    assert projected["backendRefs"] == [{"name": "web-service", "port": 8080}]
    assert projected["generation"] == 3 and projected["parentStatus"][0]["conditions"] == [
        {"type": "Accepted", "status": "True", "observedGeneration": 3},
        {"type": "Reconciled", "status": "True", "observedGeneration": 3}]
    assert "/private-token" not in str(projected) and "private" not in str(projected)
    route["spec"]["parentRefs"][0]["port"] = 443
    route["status"]["parents"][0]["parentRef"]["port"] = 443
    projected_port = route_reader.project_list({"apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "HTTPRouteList", "metadata": {"resourceVersion": "12"}, "items": [route]},
        route_reader.PATH)["items"][0]
    assert projected_port["parentRefs"][0]["port"] == 443
    assert projected_port["parentStatus"][0]["parentRef"]["port"] == 443
    class_reader = services.GatewayClassReader(SimpleNamespace(transport=None), binding, None,
                                               {"resources": 0})
    gateway_class = {"apiVersion": "gateway.networking.k8s.io/v1", "kind": "GatewayClass",
                     "metadata": {"name": "gke-l7-global-external-managed", "uid": "class-uid",
                                  "annotations": {"private/token": "secret"}},
                     "spec": {"controllerName": "networking.gke.io/gateway",
                              "parametersRef": {"name": "private"}}}
    projected_class = class_reader.project_list({"apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "GatewayClassList", "metadata": {"resourceVersion": "12"}, "items": [gateway_class]},
        class_reader.PATH)["items"][0]
    assert projected_class["kubernetesName"] == "gke-l7-global-external-managed"
    assert projected_class["controllerName"] == "networking.gke.io/gateway"
    assert "private" not in str(projected_class) and "secret" not in str(projected_class)


def test_gatewayclass_inventory_produces_complete_cluster_marker(monkeypatch):
    scope = "projects/p1"
    selection = scope + "/locations/r1/clusters/c1"
    binding = {"selection": selection, "endpoint": "34.1.2.3", "ca_sha256": "abc"}
    collector = SimpleNamespace(needed={services.GATEWAYCLASS_KIND}, scopes=[scope], transport=None,
        collections={("gke_cluster", scope): {"status": "collected", "coverage_status": "collected",
            "items": [{"name": "c1", "location": "r1"}], "source_requests": ["cluster-request"]}})
    monkeypatch.setattr(services, "cluster_binding", lambda *_: binding)
    class_row = {"name": selection + "/gatewayclasses/gke-l7-global-external-managed",
                 "cluster": selection, "kubernetesName": "gke-l7-global-external-managed",
                 "controllerName": "networking.gke.io/gateway"}
    monkeypatch.setattr(services.GatewayClassReader, "pages", lambda self: iter([([class_row], "class-request")]))
    rows = [item for page, _ in services.dependent_jobs(collector, services.GATEWAYCLASS_KIND)[0][3]()
            for item in page]
    assert rows[0] == class_row
    assert rows[-1]["inventoryStatus"] == "collected" and rows[-1]["gatewayclassCount"] == 1
