"""Read-only, per-cluster GKE Service inventory for Exposure.

Uses a source-proven GKE IP or DNS endpoint and existing Google bearer token.
Unavailable or bounded reads produce an explicit cluster marker; they never
stand in for a complete empty Service list.
"""

import http.client
import ipaddress
import json
import re
import ssl
import time
from urllib.parse import urlencode

from .gcp_gke_literal_secret_indicators import (
    CLUSTER, LOCATION, MAX_CALLS, MAX_HTTP_BYTES, MAX_READ_BYTES, PAGE_SIZE, PROJECT,
    DNS_NAME, SELECTION, cluster_binding, existing_bearer, _failure,
)

KIND = "gke_exposure_service"
INGRESS_KIND = "gke_exposure_ingress"
POD_KIND = "gke_exposure_pod"
NODE_KIND = "gke_exposure_node"
GATEWAY_KIND = "gke_exposure_gateway"
GATEWAYCLASS_KIND = "gke_exposure_gatewayclass"
HTTPROUTE_KIND = "gke_exposure_httproute"
ENDPOINTSLICE_KIND = "gke_exposure_endpointslice"
MAX_SECONDS = 120
MAX_SERVICES = 10000
ANNOTATIONS = frozenset({
    "cloud.google.com/load-balancer-type",
    "networking.gke.io/load-balancer-type",
    "service.beta.kubernetes.io/load-balancer-source-ranges",
    "service.kubernetes.io/backend-service",
    "service.kubernetes.io/tcp-forwarding-rule",
    "service.kubernetes.io/udp-forwarding-rule",
    "service.kubernetes.io/l3-forwarding-rule",
    "service.kubernetes.io/l3-forwarding-rule-ipv6",
})
INGRESS_ANNOTATIONS = frozenset({
    "kubernetes.io/ingress.class", "ingress.kubernetes.io/forwarding-rule",
    "ingress.kubernetes.io/https-forwarding-rule", "ingress.kubernetes.io/target-proxy",
    "ingress.kubernetes.io/https-target-proxy", "ingress.kubernetes.io/url-map",
})
GATEWAY_ANNOTATIONS = frozenset({
    "networking.gke.io/forwarding-rules", "networking.gke.io/target-proxies",
    "networking.gke.io/url-maps",
})
DNS_ENDPOINT = re.compile(r"(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*\.gke\.goog")


def dns_cluster_binding(collector, scope, selection):
    """Bind a GKE DNS endpoint only to its proven cluster-list subject."""
    source = collector.collections.get(("gke_cluster", scope))
    match = SELECTION.fullmatch(selection)
    if (not source or source.get("status") != "collected" or source.get("coverage_status") != "collected"
            or not isinstance(source.get("items"), list) or not match or "projects/" + match[1] != scope):
        raise _failure("gke_cluster_inventory_unproved")
    candidates = [row for row in source["items"] if isinstance(row, dict)
                  and row.get("name") == match[3] and row.get("location") == match[2]]
    if len(candidates) != 1:
        raise _failure("gke_cluster_subject_ambiguous")
    row = candidates[0]
    expected_links = {f"https://container.googleapis.com/v1/{scope}/{segment}/{match[2]}/clusters/{match[3]}"
                      for segment in ("locations", "zones")}
    provenance = row.get("_provenance", {})
    refs = provenance.get("source_requests") if isinstance(provenance, dict) else None
    if (row.get("selfLink") not in expected_links or row.get("status") != "RUNNING"
            or row.get("_coverage") or row.get("collection_status", "collected") != "collected"
            or not isinstance(provenance, dict) or provenance.get("scope") != scope
            or not isinstance(refs, list) or not refs):
        raise _failure("gke_cluster_subject_unproved")
    receipts = {e.get("id"): e for e in collector.transport.evidence if isinstance(e, dict)}
    if any(not isinstance(ref, str) or ref not in receipts or receipts[ref].get("scope") != scope
            or receipts[ref].get("method") != "GET" or receipts[ref].get("status") != "collected"
            or receipts[ref].get("http_status") != 200 or receipts[ref].get("query") != {}
            or receipts[ref].get("url") != f"https://container.googleapis.com/v1/{scope}/locations/-/clusters"
            for ref in refs):
        raise _failure("gke_cluster_source_receipt_unproved")
    config = row.get("controlPlaneEndpointsConfig")
    config = config.get("dnsEndpointConfig") if isinstance(config, dict) else None
    endpoint = config.get("endpoint") if isinstance(config, dict) else None
    if (not isinstance(config, dict) or config.get("allowExternalTraffic") is not True
            or not isinstance(endpoint, str) or not DNS_ENDPOINT.fullmatch(endpoint)):
        raise _failure("gke_cluster_dns_endpoint_unproved")
    context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return {"selection": selection, "endpoint": endpoint, "ca_sha256": None,
            "context": context, "source_requests": refs[:], "endpointTrust": "public_ca"}


class ServiceReader:
    PATH = "/api/v1/services"
    OPERATION = "gke-exposure-services-list"
    def __init__(self, collector, binding, namespaces, budget):
        self.transport = collector.transport
        self.binding, self.budget = binding, budget

    def read(self, path, params):
        if (path != self.PATH or set(params) - {"limit", "continue"}
                or params.get("limit") != PAGE_SIZE or type(params["limit"]) is not int
                or "continue" in params and (not isinstance(params["continue"], str)
                    or not params["continue"] or len(params["continue"].encode()) > 4096)):
            raise _failure("gke_exposure_service_path_prohibited")
        self.transport.check_cancelled()
        bearer = existing_bearer(self.transport)
        response = connection = rid = None
        failure_status = "unavailable"
        try:
            with self.transport.lock:
                if (self.budget["calls"] >= MAX_CALLS or time.monotonic() >= self.budget["deadline"]
                        or self.transport.max_calls is not None and self.transport.calls >= self.transport.max_calls):
                    raise ValueError("call budget")
                self.transport.calls += 1
                self.budget["calls"] += 1
                rid = "request-" + str(len(self.transport.evidence) + 1)
                evidence = {"id": rid, "scope": self.binding["selection"], "method": "GET",
                    "url": "https://" + self.binding["endpoint"] + path, "operation": self.OPERATION,
                    "query": {"limit": PAGE_SIZE}, "status": "incomplete"}
                self.transport.evidence.append(evidence)
            connection = http.client.HTTPSConnection(self.binding["endpoint"], port=443,
                context=self.binding["context"], timeout=max(.01, min(1, self.budget["deadline"] - time.monotonic())))
            connection.request("GET", path + "?" + urlencode(params), headers={
                "Authorization": "Bearer " + bearer, "Accept": "application/json", "Accept-Encoding": "identity"})
            del bearer
            response = connection.getresponse()
            evidence["http_status"] = response.status
            if response.status != 200:
                failure_status = "denied" if response.status in (401, 403) else "unavailable"
                evidence["status"] = failure_status
                raise ValueError("HTTP failure")
            encoding = response.getheader("Content-Encoding", "identity")
            length, transfer = response.getheader("Content-Length"), response.getheader("Transfer-Encoding")
            if not isinstance(encoding, str) or encoding.strip().lower() != "identity":
                raise ValueError("encoding")
            if length is not None:
                if (transfer is not None or not isinstance(length, str) or not re.fullmatch(r"[0-9]{1,9}", length)
                        or int(length) > MAX_HTTP_BYTES):
                    raise ValueError("framing")
                length = int(length)
            elif not isinstance(transfer, str) or transfer.strip().lower() != "chunked" or response.chunked is not True:
                raise ValueError("framing")
            raw = bytearray()
            while True:
                self.transport.check_cancelled()
                if time.monotonic() >= self.budget["deadline"]:
                    raise TimeoutError("read deadline")
                chunk = response.read(16384)
                if not chunk:
                    break
                self.budget["read_bytes"] -= len(chunk)
                if len(raw) + len(chunk) > MAX_HTTP_BYTES or self.budget["read_bytes"] < 0:
                    raise ValueError("read byte bound")
                raw.extend(chunk)
            if length is not None and len(raw) != length:
                raise ValueError("truncated")
            def pairs(values):
                output = {}
                for key, value in values:
                    if key in output:
                        raise ValueError("duplicate key")
                    output[key] = value
                return output
            data = json.loads(raw, object_pairs_hook=pairs,
                parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite")))
            del raw
            safe = self.project_list(data, path)
            del data
            self.transport.check_cancelled()
            if time.monotonic() >= self.budget["deadline"]:
                raise TimeoutError("deadline")
            evidence["status"] = "collected"
            return safe, rid
        except Exception:
            error = _failure("gke_exposure_services_read_unavailable", failure_status)
            if rid is not None:
                error.request_id = rid
            raise error from None
        finally:
            for stream in (response, connection):
                if stream is not None:
                    try:
                        stream.close()
                    except Exception:
                        pass

    def project_list(self, data, path):
        if (not isinstance(data, dict) or data.get("apiVersion") != "v1"
                or data.get("kind") != "ServiceList" or not isinstance(data.get("items"), list)
                or len(data["items"]) > PAGE_SIZE or not isinstance(data.get("metadata"), dict)):
            raise ValueError("GKE Service list shape")
        metadata = data["metadata"]
        version, token = metadata.get("resourceVersion"), metadata.get("continue", "")
        if (not isinstance(version, str) or not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", version)
                or not isinstance(token, str) or len(token.encode()) > 4096):
            raise ValueError("GKE Service list continuity")
        rows = []
        for service in data["items"]:
            if not isinstance(service, dict) or service.get("kind") != "Service" or service.get("apiVersion") != "v1":
                raise ValueError("GKE Service resource shape")
            meta, spec = service.get("metadata"), service.get("spec")
            if not isinstance(meta, dict) or not isinstance(spec, dict):
                raise ValueError("GKE Service metadata/spec")
            if spec.get("type") not in ("ClusterIP", "ExternalName", "LoadBalancer", "NodePort"):
                raise ValueError("GKE Service type")
            namespace, name, uid = meta.get("namespace"), meta.get("name"), meta.get("uid")
            if (not isinstance(namespace, str) or not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}", namespace)
                    or not isinstance(name, str) or not DNS_NAME.fullmatch(name)
                    or not isinstance(uid, str) or not 1 <= len(uid) <= 128):
                raise ValueError("GKE Service identity")
            self.budget["resources"] += 1
            if self.budget["resources"] > MAX_SERVICES:
                raise ValueError("GKE Service count bound")
            ports = spec.get("ports", [])
            if not isinstance(ports, list) or len(ports) > 100:
                raise ValueError("GKE Service ports")
            safe_ports = []
            for port in ports:
                if not isinstance(port, dict):
                    raise ValueError("GKE Service port shape")
                if (type(port.get("port")) is not int or not 1 <= port["port"] <= 65535
                        or "nodePort" in port and (type(port["nodePort"]) is not int or not 1 <= port["nodePort"] <= 65535)
                        or port.get("protocol", "TCP") not in ("TCP", "UDP", "SCTP")
                        or "targetPort" in port and not (type(port["targetPort"]) is int and 1 <= port["targetPort"] <= 65535
                            or isinstance(port["targetPort"], str) and DNS_NAME.fullmatch(port["targetPort"]))
                        or "name" in port and (not isinstance(port["name"], str)
                            or port["name"] and not DNS_NAME.fullmatch(port["name"]))):
                    raise ValueError("GKE Service port value")
                safe_ports.append({key: port[key] for key in ("port", "nodePort", "targetPort", "protocol", "name") if key in port})
            annotations = meta.get("annotations", {})
            if not isinstance(annotations, dict):
                raise ValueError("GKE Service annotations")
            selected_annotations = {key: value for key, value in annotations.items()
                                    if key in ANNOTATIONS and isinstance(value, str) and len(value) <= 4096}
            status = service.get("status", {})
            if not isinstance(status, dict):
                raise ValueError("GKE Service status")
            lb = status.get("loadBalancer", {})
            if not isinstance(lb, dict) or not isinstance(lb.get("ingress", []), list):
                raise ValueError("GKE Service load balancer status")
            if any(not isinstance(item, dict) for item in lb.get("ingress", [])):
                raise ValueError("GKE Service ingress shape")
            ingress = [{key: value for key in ("ip", "hostname") if isinstance(value := item.get(key), str)}
                       for item in lb.get("ingress", [])]
            if len(ingress) > 32:
                raise ValueError("GKE Service ingress bound")
            for field in ("externalIPs", "loadBalancerSourceRanges"):
                value = spec.get(field, [])
                if not isinstance(value, list) or len(value) > 128 or any(not isinstance(item, str) or len(item) > 253 for item in value):
                    raise ValueError("GKE Service address/range shape")
            if spec.get("externalTrafficPolicy", "Cluster") not in ("Cluster", "Local"):
                raise ValueError("GKE Service external traffic policy")
            safe_spec = {key: spec[key] for key in ("type", "externalIPs", "loadBalancerIP",
                         "loadBalancerSourceRanges", "externalTrafficPolicy", "allocateLoadBalancerNodePorts") if key in spec}
            safe_spec["ports"] = safe_ports
            rows.append({"name": f"{self.binding['selection']}/namespaces/{namespace}/services/{name}",
                "cluster": self.binding["selection"], "namespace": namespace, "kubernetesName": name,
                "uid": uid, "resourceVersion": meta.get("resourceVersion"),
                "spec": safe_spec, "status": {"loadBalancer": {"ingress": ingress}},
                "annotations": selected_annotations, "clusterEndpoint": self.binding["endpoint"],
                "clusterCaSha256": self.binding["ca_sha256"],
                "endpointTrust": self.binding.get("endpointTrust", "cluster_ca")})
        return {"items": rows, "continue": token, "resourceVersion": version}

    def pages(self):
        token, version, tokens, identities = None, None, set(), set()
        while True:
            params = {"limit": PAGE_SIZE}
            if token is not None:
                params["continue"] = token
            page, request_id = self.read(self.PATH, params)
            if version is not None and page["resourceVersion"] != version:
                raise _failure("gke_exposure_services_version_changed")
            version = page["resourceVersion"]
            for row in page["items"]:
                if row["name"] in identities:
                    raise _failure("gke_exposure_services_duplicate")
                identities.add(row["name"])
            yield page["items"], request_id
            token = page["continue"]
            if not token:
                return
            if token in tokens:
                raise _failure("gke_exposure_services_token_repeated")
            tokens.add(token)


class IngressReader(ServiceReader):
    PATH = "/apis/networking.k8s.io/v1/ingresses"
    OPERATION = "gke-exposure-ingresses-list"

    def project_list(self, data, path):
        if (not isinstance(data, dict) or data.get("apiVersion") != "networking.k8s.io/v1"
                or data.get("kind") != "IngressList" or not isinstance(data.get("items"), list)
                or len(data["items"]) > PAGE_SIZE or not isinstance(data.get("metadata"), dict)):
            raise ValueError("GKE Ingress list shape")
        version = data["metadata"].get("resourceVersion")
        token = data["metadata"].get("continue", "")
        if (not isinstance(version, str) or not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", version)
                or not isinstance(token, str) or len(token.encode()) > 4096):
            raise ValueError("GKE Ingress list continuity")
        rows = []
        for ingress in data["items"]:
            if (not isinstance(ingress, dict) or ingress.get("apiVersion") != "networking.k8s.io/v1"
                    or ingress.get("kind") != "Ingress"):
                raise ValueError("GKE Ingress resource shape")
            meta, spec, status = ingress.get("metadata"), ingress.get("spec"), ingress.get("status", {})
            if not isinstance(meta, dict) or not isinstance(spec, dict) or not isinstance(status, dict):
                raise ValueError("GKE Ingress metadata/spec/status")
            namespace, name, uid = meta.get("namespace"), meta.get("name"), meta.get("uid")
            if (not isinstance(namespace, str) or not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}", namespace)
                    or not isinstance(name, str) or not DNS_NAME.fullmatch(name)
                    or not isinstance(uid, str) or not 1 <= len(uid) <= 128):
                raise ValueError("GKE Ingress identity")
            self.budget["resources"] += 1
            if self.budget["resources"] > MAX_SERVICES:
                raise ValueError("GKE Ingress count bound")
            ingress_class = spec.get("ingressClassName")
            if ingress_class is not None and (not isinstance(ingress_class, str) or len(ingress_class) > 253):
                raise ValueError("GKE Ingress class")
            rules = spec.get("rules", [])
            if (not isinstance(rules, list) or len(rules) > 128
                    or any(not isinstance(rule, dict) or not isinstance(rule.get("host", ""), str)
                           or len(rule.get("host", "")) > 253 for rule in rules)):
                raise ValueError("GKE Ingress rules")
            load_balancer = status.get("loadBalancer", {})
            if not isinstance(load_balancer, dict) or not isinstance(load_balancer.get("ingress", []), list):
                raise ValueError("GKE Ingress load balancer status")
            addresses = load_balancer.get("ingress", [])
            if len(addresses) > 32 or any(not isinstance(item, dict) for item in addresses):
                raise ValueError("GKE Ingress addresses")
            safe_addresses = [{key: value for key in ("ip", "hostname")
                               if isinstance(value := item.get(key), str) and len(value) <= 253}
                              for item in addresses]
            annotations = meta.get("annotations", {})
            if not isinstance(annotations, dict):
                raise ValueError("GKE Ingress annotations")
            selected_annotations = {key: value for key, value in annotations.items()
                                    if key in INGRESS_ANNOTATIONS and isinstance(value, str)
                                    and len(value) <= 253}
            rows.append({"name": f"{self.binding['selection']}/namespaces/{namespace}/ingresses/{name}",
                "cluster": self.binding["selection"], "namespace": namespace, "kubernetesName": name,
                "uid": uid, "ingressClassName": ingress_class,
                "annotations": selected_annotations,
                "hosts": [rule.get("host", "") for rule in rules],
                "hasDefaultBackend": "defaultBackend" in spec,
                "status": {"loadBalancer": {"ingress": safe_addresses}},
                "clusterEndpoint": self.binding["endpoint"],
                "clusterCaSha256": self.binding["ca_sha256"],
                "endpointTrust": self.binding.get("endpointTrust", "cluster_ca")})
        return {"items": rows, "continue": token, "resourceVersion": version}


class PodReader(ServiceReader):
    PATH = "/api/v1/pods"
    OPERATION = "gke-exposure-pods-list"

    def project_list(self, data, path):
        if (not isinstance(data, dict) or data.get("apiVersion") != "v1"
                or data.get("kind") != "PodList" or not isinstance(data.get("items"), list)
                or len(data["items"]) > PAGE_SIZE or not isinstance(data.get("metadata"), dict)):
            raise ValueError("GKE Pod list shape")
        version = data["metadata"].get("resourceVersion")
        token = data["metadata"].get("continue", "")
        if (not isinstance(version, str) or not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", version)
                or not isinstance(token, str) or len(token.encode()) > 4096):
            raise ValueError("GKE Pod list continuity")
        rows = []
        for pod in data["items"]:
            if not isinstance(pod, dict) or pod.get("apiVersion") != "v1" or pod.get("kind") != "Pod":
                raise ValueError("GKE Pod resource shape")
            meta, spec, status = pod.get("metadata"), pod.get("spec"), pod.get("status", {})
            if not isinstance(meta, dict) or not isinstance(spec, dict) or not isinstance(status, dict):
                raise ValueError("GKE Pod metadata/spec/status")
            namespace, name, uid = meta.get("namespace"), meta.get("name"), meta.get("uid")
            if (not isinstance(namespace, str) or not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}", namespace)
                    or not isinstance(name, str) or not DNS_NAME.fullmatch(name)
                    or not isinstance(uid, str) or not 1 <= len(uid) <= 128):
                raise ValueError("GKE Pod identity")
            self.budget["resources"] += 1
            if self.budget["resources"] > MAX_SERVICES:
                raise ValueError("GKE Pod count bound")
            host_network = spec.get("hostNetwork", False)
            if type(host_network) is not bool:
                raise ValueError("GKE Pod hostNetwork")
            node = spec.get("nodeName")
            if node is not None and (not isinstance(node, str) or len(node) > 253):
                raise ValueError("GKE Pod nodeName")
            phase = status.get("phase")
            if phase is not None and phase not in ("Pending", "Running", "Succeeded", "Failed", "Unknown"):
                raise ValueError("GKE Pod phase")
            host_ip = status.get("hostIP")
            if host_ip is not None and (not isinstance(host_ip, str) or len(host_ip) > 253):
                raise ValueError("GKE Pod hostIP")
            ports = []
            for field in ("containers", "initContainers"):
                containers = spec.get(field, [])
                if not isinstance(containers, list) or len(containers) > 100:
                    raise ValueError("GKE Pod containers")
                for container in containers:
                    if not isinstance(container, dict):
                        raise ValueError("GKE Pod container")
                    declared = container.get("ports", [])
                    if not isinstance(declared, list) or len(declared) > 100:
                        raise ValueError("GKE Pod ports")
                    for port in declared:
                        if not isinstance(port, dict):
                            raise ValueError("GKE Pod port shape")
                        host_port = port.get("hostPort", 0)
                        if type(host_port) is not int or not 0 <= host_port <= 65535:
                            raise ValueError("GKE Pod hostPort")
                        container_port = port.get("containerPort")
                        if container_port is not None and (type(container_port) is not int
                                                           or not 1 <= container_port <= 65535):
                            raise ValueError("GKE Pod containerPort")
                        if host_network and not host_port and container_port is not None:
                            host_port = container_port
                        if host_port:
                            protocol = port.get("protocol", "TCP")
                            if protocol not in ("TCP", "UDP", "SCTP"):
                                raise ValueError("GKE Pod protocol")
                            bind_ip = port.get("hostIP", "0.0.0.0")
                            if not isinstance(bind_ip, str) or len(bind_ip) > 45:
                                raise ValueError("GKE Pod host port bind address")
                            bind_ip = bind_ip or "0.0.0.0"
                            try:
                                ipaddress.ip_address(bind_ip)
                            except ValueError as exc:
                                raise ValueError("GKE Pod host port bind address") from exc
                            ports.append({"hostPort": host_port, "protocol": protocol,
                                          "bindIP": bind_ip,
                                          "containerKind": field,
                                          "portSource": "hostPort" if port.get("hostPort") else "hostNetwork"})
            rows.append({"name": f"{self.binding['selection']}/namespaces/{namespace}/pods/{name}",
                "cluster": self.binding["selection"], "namespace": namespace, "kubernetesName": name,
                "uid": uid, "hostNetwork": host_network, "hostPorts": ports,
                "nodeName": node, "phase": phase, "hostIP": host_ip,
                "clusterEndpoint": self.binding["endpoint"],
                "clusterCaSha256": self.binding["ca_sha256"],
                "endpointTrust": self.binding.get("endpointTrust", "cluster_ca")})
        return {"items": rows, "continue": token, "resourceVersion": version}


class NodeReader(ServiceReader):
    PATH = "/api/v1/nodes"
    OPERATION = "gke-exposure-nodes-list"

    def project_list(self, data, path):
        if (not isinstance(data, dict) or data.get("apiVersion") != "v1"
                or data.get("kind") != "NodeList" or not isinstance(data.get("items"), list)
                or len(data["items"]) > PAGE_SIZE or not isinstance(data.get("metadata"), dict)):
            raise ValueError("GKE Node list shape")
        version = data["metadata"].get("resourceVersion")
        token = data["metadata"].get("continue", "")
        if (not isinstance(version, str) or not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", version)
                or not isinstance(token, str) or len(token.encode()) > 4096):
            raise ValueError("GKE Node list continuity")
        rows = []
        for node in data["items"]:
            if not isinstance(node, dict) or node.get("apiVersion") != "v1" or node.get("kind") != "Node":
                raise ValueError("GKE Node resource shape")
            meta, spec, status = node.get("metadata"), node.get("spec"), node.get("status", {})
            if not isinstance(meta, dict) or not isinstance(spec, dict) or not isinstance(status, dict):
                raise ValueError("GKE Node metadata/spec/status")
            name, uid, provider = meta.get("name"), meta.get("uid"), spec.get("providerID")
            if (not isinstance(name, str) or not DNS_NAME.fullmatch(name)
                    or not isinstance(uid, str) or not 1 <= len(uid) <= 128
                    or provider is not None and (not isinstance(provider, str) or not re.fullmatch(
                        r"gce://[a-z][a-z0-9-]{0,62}/[a-z][a-z0-9-]{0,62}/[a-z][a-z0-9-]{0,62}", provider))):
                raise ValueError("GKE Node identity/provider")
            self.budget["resources"] += 1
            if self.budget["resources"] > MAX_SERVICES:
                raise ValueError("GKE Node count bound")
            addresses = status.get("addresses", [])
            if (not isinstance(addresses, list) or len(addresses) > 32
                    or any(not isinstance(item, dict) or item.get("type") not in
                           ("ExternalIP", "InternalIP", "Hostname", "ExternalDNS", "InternalDNS")
                           or not isinstance(item.get("address"), str) or len(item["address"]) > 253
                           for item in addresses)):
                raise ValueError("GKE Node addresses")
            rows.append({"name": f"{self.binding['selection']}/nodes/{name}",
                "cluster": self.binding["selection"], "kubernetesName": name, "uid": uid,
                "providerID": provider, "addresses": [{"type": item["type"], "address": item["address"]}
                                                      for item in addresses],
                "clusterEndpoint": self.binding["endpoint"],
                "clusterCaSha256": self.binding["ca_sha256"],
                "endpointTrust": self.binding.get("endpointTrust", "cluster_ca")})
        return {"items": rows, "continue": token, "resourceVersion": version}


class GatewayReader(ServiceReader):
    PATH = "/apis/gateway.networking.k8s.io/v1/gateways"
    OPERATION = "gke-exposure-gateways-list"

    def project_list(self, data, path):
        if (not isinstance(data, dict) or data.get("apiVersion") != "gateway.networking.k8s.io/v1"
                or data.get("kind") != "GatewayList" or not isinstance(data.get("items"), list)
                or len(data["items"]) > PAGE_SIZE or not isinstance(data.get("metadata"), dict)):
            raise ValueError("GKE Gateway list shape")
        version, token = data["metadata"].get("resourceVersion"), data["metadata"].get("continue", "")
        if (not isinstance(version, str) or not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", version)
                or not isinstance(token, str) or len(token.encode()) > 4096):
            raise ValueError("GKE Gateway list continuity")
        rows = []
        for gateway in data["items"]:
            if (not isinstance(gateway, dict) or gateway.get("apiVersion") != "gateway.networking.k8s.io/v1"
                    or gateway.get("kind") != "Gateway"):
                raise ValueError("GKE Gateway resource shape")
            meta, spec, status = gateway.get("metadata"), gateway.get("spec"), gateway.get("status", {})
            if not isinstance(meta, dict) or not isinstance(spec, dict) or not isinstance(status, dict):
                raise ValueError("GKE Gateway metadata/spec/status")
            namespace, name, uid = meta.get("namespace"), meta.get("name"), meta.get("uid")
            if (not isinstance(namespace, str) or not DNS_NAME.fullmatch(namespace)
                    or not isinstance(name, str) or not DNS_NAME.fullmatch(name)
                    or not isinstance(uid, str) or not 1 <= len(uid) <= 128):
                raise ValueError("GKE Gateway identity")
            self.budget["resources"] += 1
            if self.budget["resources"] > MAX_SERVICES:
                raise ValueError("GKE Gateway count bound")
            gateway_class = spec.get("gatewayClassName")
            if not isinstance(gateway_class, str) or not DNS_NAME.fullmatch(gateway_class):
                raise ValueError("GKE Gateway class")
            listeners = spec.get("listeners", [])
            if not isinstance(listeners, list) or len(listeners) > 128:
                raise ValueError("GKE Gateway listeners")
            safe_listeners = []
            for listener in listeners:
                if (not isinstance(listener, dict) or type(listener.get("port")) is not int
                        or not 1 <= listener["port"] <= 65535
                        or listener.get("protocol") not in ("HTTP", "HTTPS", "TLS", "TCP", "UDP")
                        or not isinstance(listener.get("name"), str) or len(listener["name"]) > 253):
                    raise ValueError("GKE Gateway listener")
                host = listener.get("hostname")
                if host is not None and (not isinstance(host, str) or len(host) > 253):
                    raise ValueError("GKE Gateway hostname")
                safe_listeners.append({"name": listener["name"], "port": listener["port"],
                                       "protocol": listener["protocol"], "hostname": host})
            addresses = status.get("addresses", [])
            if (not isinstance(addresses, list) or len(addresses) > 32
                    or any(not isinstance(item, dict) or item.get("type", "IPAddress") not in
                           ("IPAddress", "Hostname") or not isinstance(item.get("value"), str)
                           or len(item["value"]) > 253 for item in addresses)):
                raise ValueError("GKE Gateway addresses")
            annotations = meta.get("annotations", {})
            if not isinstance(annotations, dict):
                raise ValueError("GKE Gateway annotations")
            selected_annotations = {key: value for key, value in annotations.items()
                                    if key in GATEWAY_ANNOTATIONS and isinstance(value, str) and len(value) <= 4096}
            rows.append({"name": f"{self.binding['selection']}/namespaces/{namespace}/gateways/{name}",
                "cluster": self.binding["selection"], "namespace": namespace, "kubernetesName": name,
                "uid": uid, "gatewayClassName": gateway_class, "listeners": safe_listeners,
                "annotations": selected_annotations,
                "addresses": [{"type": item.get("type", "IPAddress"), "value": item["value"]}
                              for item in addresses], "clusterEndpoint": self.binding["endpoint"],
                "clusterCaSha256": self.binding["ca_sha256"],
                "endpointTrust": self.binding.get("endpointTrust", "cluster_ca")})
        return {"items": rows, "continue": token, "resourceVersion": version}


class GatewayClassReader(ServiceReader):
    PATH = "/apis/gateway.networking.k8s.io/v1/gatewayclasses"
    OPERATION = "gke-exposure-gatewayclasses-list"

    def project_list(self, data, path):
        if (not isinstance(data, dict) or data.get("apiVersion") != "gateway.networking.k8s.io/v1"
                or data.get("kind") != "GatewayClassList" or not isinstance(data.get("items"), list)
                or len(data["items"]) > PAGE_SIZE or not isinstance(data.get("metadata"), dict)):
            raise ValueError("GKE GatewayClass list shape")
        version, token = data["metadata"].get("resourceVersion"), data["metadata"].get("continue", "")
        if (not isinstance(version, str) or not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", version)
                or not isinstance(token, str) or len(token.encode()) > 4096):
            raise ValueError("GKE GatewayClass list continuity")
        rows = []
        for gateway_class in data["items"]:
            if (not isinstance(gateway_class, dict) or gateway_class.get("apiVersion") != "gateway.networking.k8s.io/v1"
                    or gateway_class.get("kind") != "GatewayClass"
                    or not isinstance(gateway_class.get("metadata"), dict)
                    or not isinstance(gateway_class.get("spec"), dict)):
                raise ValueError("GKE GatewayClass resource shape")
            meta, spec = gateway_class["metadata"], gateway_class["spec"]
            name, uid, controller_name = meta.get("name"), meta.get("uid"), spec.get("controllerName")
            if (not isinstance(name, str) or not DNS_NAME.fullmatch(name)
                    or not isinstance(uid, str) or not 1 <= len(uid) <= 128
                    or not isinstance(controller_name, str) or not 1 <= len(controller_name) <= 253):
                raise ValueError("GKE GatewayClass identity/controller")
            self.budget["resources"] += 1
            if self.budget["resources"] > MAX_SERVICES:
                raise ValueError("GKE GatewayClass count bound")
            rows.append({"name": f"{self.binding['selection']}/gatewayclasses/{name}",
                         "cluster": self.binding["selection"], "kubernetesName": name,
                         "uid": uid, "controllerName": controller_name,
                         "clusterEndpoint": self.binding["endpoint"],
                         "clusterCaSha256": self.binding["ca_sha256"],
                         "endpointTrust": self.binding.get("endpointTrust", "cluster_ca")})
        return {"items": rows, "continue": token, "resourceVersion": version}


class HTTPRouteReader(ServiceReader):
    PATH = "/apis/gateway.networking.k8s.io/v1/httproutes"
    OPERATION = "gke-exposure-httproutes-list"

    def project_list(self, data, path):
        if (not isinstance(data, dict) or data.get("apiVersion") != "gateway.networking.k8s.io/v1"
                or data.get("kind") != "HTTPRouteList" or not isinstance(data.get("items"), list)
                or len(data["items"]) > PAGE_SIZE or not isinstance(data.get("metadata"), dict)):
            raise ValueError("GKE HTTPRoute list shape")
        version, token = data["metadata"].get("resourceVersion"), data["metadata"].get("continue", "")
        if (not isinstance(version, str) or not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", version)
                or not isinstance(token, str) or len(token.encode()) > 4096):
            raise ValueError("GKE HTTPRoute list continuity")
        rows = []
        for route in data["items"]:
            if (not isinstance(route, dict) or route.get("apiVersion") != "gateway.networking.k8s.io/v1"
                    or route.get("kind") != "HTTPRoute"):
                raise ValueError("GKE HTTPRoute resource shape")
            meta, spec, status = route.get("metadata"), route.get("spec"), route.get("status", {})
            if not isinstance(meta, dict) or not isinstance(spec, dict) or not isinstance(status, dict):
                raise ValueError("GKE HTTPRoute metadata/spec/status")
            namespace, name, uid = meta.get("namespace"), meta.get("name"), meta.get("uid")
            if (not isinstance(namespace, str) or not DNS_NAME.fullmatch(namespace)
                    or not isinstance(name, str) or not DNS_NAME.fullmatch(name)
                    or not isinstance(uid, str) or not 1 <= len(uid) <= 128):
                raise ValueError("GKE HTTPRoute identity")
            self.budget["resources"] += 1
            if self.budget["resources"] > MAX_SERVICES:
                raise ValueError("GKE HTTPRoute count bound")
            generation = meta.get("generation")
            if generation is not None and (type(generation) is not int or generation < 1):
                raise ValueError("GKE HTTPRoute generation")
            hosts, parents, rules = (spec.get("hostnames", []), spec.get("parentRefs", []), spec.get("rules", []))
            if (not isinstance(hosts, list) or len(hosts) > 128 or
                    any(not isinstance(host, str) or len(host) > 253 for host in hosts) or
                    not isinstance(parents, list) or len(parents) > 128 or
                    not isinstance(rules, list) or len(rules) > 128):
                raise ValueError("GKE HTTPRoute hosts/parents/rules")
            safe_parents = []
            for parent in parents:
                if not isinstance(parent, dict) or not isinstance(parent.get("name"), str) or not DNS_NAME.fullmatch(parent["name"]):
                    raise ValueError("GKE HTTPRoute parent")
                safe_parents.append({key: value for key in ("group", "kind", "namespace", "name", "sectionName")
                                     if isinstance(value := parent.get(key), str) and len(value) <= 253})
            safe_backends = []
            for rule in rules:
                if not isinstance(rule, dict) or not isinstance(rule.get("backendRefs", []), list) or len(rule.get("backendRefs", [])) > 128:
                    raise ValueError("GKE HTTPRoute backends")
                for backend in rule.get("backendRefs", []):
                    if (not isinstance(backend, dict) or not isinstance(backend.get("name"), str)
                            or not DNS_NAME.fullmatch(backend["name"])):
                        raise ValueError("GKE HTTPRoute backend")
                    safe_backends.append({key: value for key in ("group", "kind", "namespace", "name", "port")
                                          if (isinstance(value := backend.get(key), str) and len(value) <= 253)
                                          or key == "port" and type(value) is int and 1 <= value <= 65535})
            status_parents = status.get("parents", [])
            if not isinstance(status_parents, list) or len(status_parents) > 32:
                raise ValueError("GKE HTTPRoute parent status")
            safe_status = []
            for parent in status_parents:
                if not isinstance(parent, dict) or not isinstance(parent.get("parentRef"), dict):
                    raise ValueError("GKE HTTPRoute parent status")
                ref = parent["parentRef"]
                if not isinstance(ref.get("name"), str) or not DNS_NAME.fullmatch(ref["name"]):
                    raise ValueError("GKE HTTPRoute status parent identity")
                conditions = parent.get("conditions", [])
                if not isinstance(conditions, list) or len(conditions) > 16:
                    raise ValueError("GKE HTTPRoute status conditions")
                safe_conditions = []
                for condition in conditions:
                    if (not isinstance(condition, dict) or not isinstance(condition.get("type"), str)
                            or not isinstance(condition.get("status"), str)
                            or condition["status"] not in ("True", "False", "Unknown")
                            or condition.get("observedGeneration") is not None
                            and type(condition["observedGeneration"]) is not int):
                        raise ValueError("GKE HTTPRoute status condition")
                    if condition["type"] in ("Accepted", "Reconciled", "ResolvedRefs"):
                        safe_conditions.append({"type": condition["type"], "status": condition["status"],
                                                "observedGeneration": condition["observedGeneration"]})
                controller_name = parent.get("controllerName")
                if not isinstance(controller_name, str) or len(controller_name) > 253:
                    raise ValueError("GKE HTTPRoute status controller")
                safe_status.append({"controllerName": controller_name,
                                    "parentRef": {key: value for key in ("group", "kind", "namespace", "name", "sectionName")
                                                  if isinstance(value := ref.get(key), str) and len(value) <= 253},
                                    "conditions": safe_conditions})
            rows.append({"name": f"{self.binding['selection']}/namespaces/{namespace}/httproutes/{name}",
                "cluster": self.binding["selection"], "namespace": namespace, "kubernetesName": name,
                "uid": uid, "generation": generation, "hostnames": hosts[:], "parentRefs": safe_parents,
                "parentStatus": safe_status,
                "backendRefs": safe_backends, "clusterEndpoint": self.binding["endpoint"],
                "clusterCaSha256": self.binding["ca_sha256"],
                "endpointTrust": self.binding.get("endpointTrust", "cluster_ca")})
        return {"items": rows, "continue": token, "resourceVersion": version}


class EndpointSliceReader(ServiceReader):
    PATH = "/apis/discovery.k8s.io/v1/endpointslices"
    OPERATION = "gke-exposure-endpointslices-list"

    def project_list(self, data, path):
        if (not isinstance(data, dict) or data.get("apiVersion") != "discovery.k8s.io/v1"
                or data.get("kind") != "EndpointSliceList" or not isinstance(data.get("items"), list)
                or len(data["items"]) > PAGE_SIZE or not isinstance(data.get("metadata"), dict)):
            raise ValueError("GKE EndpointSlice list shape")
        version, token = data["metadata"].get("resourceVersion"), data["metadata"].get("continue", "")
        if (not isinstance(version, str) or not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", version)
                or not isinstance(token, str) or len(token.encode()) > 4096):
            raise ValueError("GKE EndpointSlice list continuity")
        rows = []
        for entry in data["items"]:
            if (not isinstance(entry, dict) or entry.get("apiVersion") != "discovery.k8s.io/v1"
                    or entry.get("kind") != "EndpointSlice"):
                raise ValueError("GKE EndpointSlice resource shape")
            meta = entry.get("metadata")
            if not isinstance(meta, dict):
                raise ValueError("GKE EndpointSlice metadata")
            namespace, name, uid = meta.get("namespace"), meta.get("name"), meta.get("uid")
            labels = meta.get("labels", {})
            if (not isinstance(namespace, str) or not DNS_NAME.fullmatch(namespace)
                    or not isinstance(name, str) or not DNS_NAME.fullmatch(name)
                    or not isinstance(uid, str) or not 1 <= len(uid) <= 128
                    or not isinstance(labels, dict)):
                raise ValueError("GKE EndpointSlice identity")
            service_name = labels.get("kubernetes.io/service-name")
            if service_name is not None and (not isinstance(service_name, str)
                                             or not DNS_NAME.fullmatch(service_name)):
                raise ValueError("GKE EndpointSlice service label")
            self.budget["resources"] += 1
            if self.budget["resources"] > MAX_SERVICES:
                raise ValueError("GKE EndpointSlice count bound")
            address_type, endpoints, ports = entry.get("addressType"), entry.get("endpoints"), entry.get("ports", [])
            if (address_type not in ("IPv4", "IPv6", "FQDN") or not isinstance(endpoints, list)
                    or len(endpoints) > 1000 or not isinstance(ports, list) or len(ports) > 100):
                raise ValueError("GKE EndpointSlice addresses/ports")
            ready_nodes = []
            ready_count = 0
            for endpoint in endpoints:
                if not isinstance(endpoint, dict) or not isinstance(endpoint.get("addresses"), list) or not 1 <= len(endpoint["addresses"]) <= 100:
                    raise ValueError("GKE EndpointSlice endpoint")
                if any(not isinstance(address, str) or len(address) > 253 for address in endpoint["addresses"]):
                    raise ValueError("GKE EndpointSlice address")
                conditions = endpoint.get("conditions", {})
                if (not isinstance(conditions, dict) or any(key in conditions and conditions[key] is not None
                    and type(conditions[key]) is not bool for key in ("ready", "serving", "terminating"))):
                    raise ValueError("GKE EndpointSlice conditions")
                node = endpoint.get("nodeName")
                if node is not None and (not isinstance(node, str) or not DNS_NAME.fullmatch(node)):
                    raise ValueError("GKE EndpointSlice nodeName")
                if (conditions.get("ready") is not False and conditions.get("serving") is not False
                        and conditions.get("terminating") is not True):
                    ready_count += 1
                    ready_nodes.append(node)
            safe_ports = []
            for port in ports:
                if not isinstance(port, dict):
                    raise ValueError("GKE EndpointSlice port")
                number, protocol, port_name = port.get("port"), port.get("protocol", "TCP"), port.get("name", "")
                if (number is not None and (type(number) is not int or not 1 <= number <= 65535)
                        or protocol not in ("TCP", "UDP", "SCTP")
                        or not isinstance(port_name, str) or len(port_name) > 63):
                    raise ValueError("GKE EndpointSlice port value")
                safe_ports.append({"name": port_name, "port": number, "protocol": protocol})
            rows.append({"name": f"{self.binding['selection']}/namespaces/{namespace}/endpointslices/{name}",
                "cluster": self.binding["selection"], "namespace": namespace,
                "kubernetesName": name, "uid": uid, "serviceName": service_name,
                "addressType": address_type, "ports": safe_ports,
                "readyEndpointCount": ready_count, "readyNodeNames": ready_nodes,
                "clusterEndpoint": self.binding["endpoint"],
                "clusterCaSha256": self.binding["ca_sha256"],
                "endpointTrust": self.binding.get("endpointTrust", "cluster_ca")})
        return {"items": rows, "continue": token, "resourceVersion": version}


def dependent_jobs(collector, kind=KIND):
    if kind not in collector.needed:
        return []
    if kind not in (KIND, INGRESS_KIND, POD_KIND, NODE_KIND, GATEWAY_KIND, GATEWAYCLASS_KIND, HTTPROUTE_KIND, ENDPOINTSLICE_KIND):
        return []
    reader_type = {KIND: ServiceReader, INGRESS_KIND: IngressReader, POD_KIND: PodReader,
                   NODE_KIND: NodeReader, GATEWAY_KIND: GatewayReader, GATEWAYCLASS_KIND: GatewayClassReader,
                   HTTPROUTE_KIND: HTTPRouteReader,
                   ENDPOINTSLICE_KIND: EndpointSliceReader}[kind]
    resource_label = {KIND: "service", INGRESS_KIND: "ingress", POD_KIND: "pod", NODE_KIND: "node",
                      GATEWAY_KIND: "gateway", GATEWAYCLASS_KIND: "gatewayclass", HTTPROUTE_KIND: "httproute",
                      ENDPOINTSLICE_KIND: "endpointslice"}[kind]
    jobs = []
    for scope in collector.scopes:
        if not isinstance(scope, str) or not re.fullmatch(r"projects/" + PROJECT, scope):
            continue

        def fetch(scope=scope):
            from .gcp import ReadError
            parent = collector.collections.get(("gke_cluster", scope))
            if not parent or not isinstance(parent.get("items"), list) or not parent.get("source_requests"):
                raise ReadError("unavailable", "gke_cluster_inventory_incomplete")
            if parent.get("status") == "empty" and parent.get("coverage_status") == "empty":
                yield [], parent["source_requests"][0]
                return
            if parent.get("status") != "collected" or parent.get("coverage_status") != "collected":
                yield [{"name": scope + "/gkeServiceInventory", "inventoryStatus": "unavailable",
                        "reason": "gke_cluster_inventory_incomplete"}], parent["source_requests"][0]
                return
            seen = set()
            for cluster in parent["items"]:
                name, location = cluster.get("name"), cluster.get("location")
                if (not isinstance(name, str) or not re.fullmatch(CLUSTER, name) or
                        not isinstance(location, str) or not re.fullmatch(LOCATION, location)):
                    raise ReadError("malformed", "gke_cluster_identity_unresolved")
                selection = f"{scope}/locations/{location}/clusters/{name}"
                if selection in seen:
                    raise ReadError("malformed", "gke_cluster_identity_duplicate")
                seen.add(selection)
                last_request = parent["source_requests"][0]
                count, state, reason = 0, "unavailable", "gke_cluster_endpoint_unproved"
                budget = {"deadline": time.monotonic() + MAX_SECONDS, "calls": 0,
                          "read_bytes": MAX_READ_BYTES, "resources": 0}
                for bind in (cluster_binding, dns_cluster_binding):
                    try:
                        binding = bind(collector, scope, selection)
                        # Publish only a complete endpoint read. A failed second page
                        # cannot leave first-page rows masquerading as live inventory.
                        pages = list(reader_type(collector, binding, None, budget).pages())
                        count = sum(len(rows) for rows, _ in pages)
                        for rows, request_id in pages:
                            last_request = request_id
                            yield rows, request_id
                        state, reason = "collected", None
                        break
                    except ReadError as exc:
                        reason = exc.error["code"]
                        last_request = getattr(exc, "request_id", None) or last_request
                yield [{"name": selection + "/" + resource_label + "Inventory", "cluster": selection,
                        "inventoryStatus": state, resource_label + "Count": count,
                        **({"reason": reason} if reason else {})}], last_request
        jobs.append((kind, scope, "kubernetes", fetch))
    return jobs
