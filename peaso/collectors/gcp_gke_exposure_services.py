"""Read-only, per-cluster GKE Service inventory for Exposure.

Uses a source-proven GKE IP or DNS endpoint and existing Google bearer token.
Unavailable or bounded reads produce an explicit cluster marker; they never
stand in for a complete empty Service list.
"""

import http.client
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
MAX_SECONDS = 120
MAX_SERVICES = 10000
ANNOTATIONS = frozenset({
    "cloud.google.com/load-balancer-type",
    "networking.gke.io/load-balancer-type",
    "service.beta.kubernetes.io/load-balancer-source-ranges",
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
                        or port.get("protocol", "TCP") not in ("TCP", "UDP", "SCTP")):
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
            rows.append({"name": f"{self.binding['selection']}/namespaces/{namespace}/ingresses/{name}",
                "cluster": self.binding["selection"], "namespace": namespace, "kubernetesName": name,
                "uid": uid, "ingressClassName": ingress_class,
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
                        if host_port:
                            protocol = port.get("protocol", "TCP")
                            if protocol not in ("TCP", "UDP", "SCTP"):
                                raise ValueError("GKE Pod protocol")
                            ports.append({"hostPort": host_port, "protocol": protocol,
                                          "containerKind": field})
            rows.append({"name": f"{self.binding['selection']}/namespaces/{namespace}/pods/{name}",
                "cluster": self.binding["selection"], "namespace": namespace, "kubernetesName": name,
                "uid": uid, "hostNetwork": host_network, "hostPorts": ports,
                "nodeName": node, "phase": phase, "hostIP": host_ip,
                "clusterEndpoint": self.binding["endpoint"],
                "clusterCaSha256": self.binding["ca_sha256"],
                "endpointTrust": self.binding.get("endpointTrust", "cluster_ca")})
        return {"items": rows, "continue": token, "resourceVersion": version}


def dependent_jobs(collector, kind=KIND):
    if kind not in collector.needed:
        return []
    if kind not in (KIND, INGRESS_KIND, POD_KIND):
        return []
    reader_type = {KIND: ServiceReader, INGRESS_KIND: IngressReader, POD_KIND: PodReader}[kind]
    resource_label = {KIND: "service", INGRESS_KIND: "ingress", POD_KIND: "pod"}[kind]
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
