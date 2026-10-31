"""Source-bound Kubernetes compliance checks over observed, read-only facts.

Only IDs listed here are implemented. The signed ledger contains additional
proposals needing operator policy, host coverage, or new collection; importing
this module does not turn those proposals into automatic verdicts.
"""
from __future__ import annotations

from ipaddress import ip_address, ip_network
from datetime import datetime

from . import register, result, unknown
from .facts import Unavailable, complete_items, get, list_of_objects, memoized, optional
from .fixtures import CASES

IDS = []
_PODSPEC = {
    "pod": "spec",
    "deployment": "spec.template.spec",
    "daemonset": "spec.template.spec",
    "statefulset": "spec.template.spec",
    "replicaset": "spec.template.spec",
    "replicationcontroller": "spec.template.spec",
    "job": "spec.template.spec",
    "cronjob": "spec.jobTemplate.spec.template.spec",
}


def _register(check_id, kind, title, evaluate, *, category="hardening", dependencies=None, remediation, passing, failing):
    register(check_id, "k8s", category, kind, title, "medium", "CM-6", remediation,
             dependencies=dependencies or [kind])(evaluate)
    IDS.append(check_id)
    CASES[check_id] = {"pass": passing, "fail": failing, "missing": {}, "malformed": None}


def _runtime_seccomp(item, kind):
    spec = get(item, _PODSPEC[kind], dict)
    os_spec = optional(spec, "os", {}, dict)
    # Kubernetes treats a Pod without spec.os as a Linux Pod.
    os_name = optional(os_spec, "name", "linux")
    if os_name not in ("linux", "windows"):
        return unknown("unrecognized Pod OS", observed_os=os_name)
    if os_name == "windows":
        return "NOT_APPLICABLE", {"reason": "seccomp is a Linux Pod control", "observed_os": os_name}
    pod_context = optional(spec, "securityContext", {}, dict)
    pod_profile = optional(pod_context, "seccompProfile", {}, dict)
    inherited = optional(pod_profile, "type", None)
    if inherited not in (None, "RuntimeDefault", "Localhost", "Unconfined"):
        return unknown("unrecognized Pod seccomp profile", observed_type=inherited)
    # Build our own list before appending init and ephemeral containers so
    # evaluation cannot mutate the native PodSpec evidence.
    containers = list(list_of_objects(get(spec, "containers", list)))
    if not containers:
        raise Unavailable("PodSpec has no regular containers")
    containers += list_of_objects(optional(spec, "initContainers", [], list))
    containers += list_of_objects(optional(spec, "ephemeralContainers", [], list))
    failures, unresolved = [], []
    for row in containers:
        name = get(row, "name", str)
        context = optional(row, "securityContext", {}, dict)
        profile = optional(context, "seccompProfile", {}, dict)
        configured = optional(profile, "type", None)
        if configured not in (None, "RuntimeDefault", "Localhost", "Unconfined"):
            return unknown("unrecognized container seccomp profile", container=name, observed_type=configured)
        effective = configured if configured is not None else inherited
        if effective is None:
            # A kubelet seccompDefault setting can supply RuntimeDefault without
            # materializing a PodSpec field; absence is not proof of Unconfined.
            unresolved.append(name)
        elif effective != "RuntimeDefault":
            failures.append({"container": name, "effective_profile": effective})
    if failures:
        return result(True, non_runtime_default=failures,
                      semantics="Pod/container declaration, not runtime enforcement")
    if unresolved:
        return unknown("no seccompProfile declared and the kubelet seccompDefault setting is not recorded", containers=unresolved)
    return result(False, assessed_containers=len(containers), effective_profile="RuntimeDefault",
                  semantics="Pod/container declaration, not runtime enforcement")


for _kind, _path in _PODSPEC.items():
    _id = f"k8s.cis.{_kind}_effective_runtime_default_seccomp"
    def _evaluate(item, index, kind=_kind):
        return _runtime_seccomp(item, kind)
    _good = {"os": {"name": "linux"}, "securityContext": {"seccompProfile": {"type": "RuntimeDefault"}},
             "containers": [{"name": "main"}], "initContainers": [{"name": "init", "securityContext": {"seccompProfile": {"type": "RuntimeDefault"}}}]}
    _bad = {**_good, "containers": [{"name": "main", "securityContext": {"seccompProfile": {"type": "Unconfined"}}}]}
    from .fixtures import nest as _nest
    _register(_id, _kind, f"{_kind.title()} containers declare effective RuntimeDefault seccomp",
              _evaluate, remediation="Review the workload owner and set the Pod or container seccompProfile.type to RuntimeDefault on Linux after compatibility testing; update the owned manifest and roll out safely.",
              passing=_nest(_path, _good), failing=_nest(_path, _bad))


def _default_allow(item, direction):
    spec = get(item, "spec", dict)
    # A real Kubernetes response may default an omitted selector to {}, but a
    # projected/partial item does not prove that omission. Require the field.
    selector = get(spec, "podSelector", dict)
    _selector_shape(selector)
    labels = optional(selector, "matchLabels", {}, dict)
    expressions = optional(selector, "matchExpressions", [], list)
    if labels or expressions:
        return "NOT_APPLICABLE", {"reason": "Policy does not select all Pods in its namespace"}
    declared_types = get(spec, "policyTypes", list)
    if not declared_types or any(x not in ("Ingress", "Egress") for x in declared_types):
        return unknown("malformed NetworkPolicy policyTypes")
    active_types = set(declared_types)
    if direction not in active_types:
        return "NOT_APPLICABLE", {"reason": f"Policy does not select {direction} traffic"}
    field = direction.lower()
    # The API omits empty rule slices. Only the collector's existing native
    # full-object receipt establishes the documented empty-list default.
    native = item.get("provenance", {}).get("evidence") == "read-only list"
    rules = list_of_objects(optional(spec, field, [], list) if native else get(spec, field, list))
    broad = []
    peer_key = "from" if direction == "Ingress" else "to"
    for number, rule in enumerate(rules):
        peers = optional(rule, peer_key, None)
        if peers is None or peers == []:
            broad.append(number)
        elif not isinstance(peers, list) or any(not isinstance(peer, dict) for peer in peers):
            return unknown("malformed NetworkPolicy peers", direction=direction, rule=number)
        else:
            for peer in peers:
                _peer_shape(peer)
    return result(bool(broad), direction=direction, peer_unrestricted_rules=broad,
                  semantics="Declared per-policy peer restriction only; ports, other policies and CNI enforcement are separate")


def _selector_shape(selector):
    if any(key not in ("matchLabels", "matchExpressions", "_coverage", "_provenance") for key in selector):
        raise Unavailable("unrecognized NetworkPolicy selector field")
    labels = optional(selector, "matchLabels", {}, dict)
    if any(not isinstance(key, str) or not isinstance(value, str) for key, value in labels.items()):
        raise Unavailable("malformed NetworkPolicy selector labels")
    expressions = list_of_objects(optional(selector, "matchExpressions", [], list))
    for row in expressions:
        get(row, "key", str)
        op = get(row, "operator", str)
        if op not in ("In", "NotIn", "Exists", "DoesNotExist"):
            raise Unavailable("unrecognized NetworkPolicy selector operator")
        values = optional(row, "values", [], list)
        if any(not isinstance(value, str) for value in values):
            raise Unavailable("malformed NetworkPolicy selector values")


def _peer_shape(peer):
    if any(key not in ("podSelector", "namespaceSelector", "ipBlock", "_coverage", "_provenance") for key in peer):
        raise Unavailable("unrecognized NetworkPolicy peer field")
    present = {key for key in ("podSelector", "namespaceSelector", "ipBlock") if key in peer or key in peer.get("_coverage", {})}
    if not present or ("ipBlock" in present and len(present) != 1):
        raise Unavailable("ambiguous NetworkPolicy peer selector")
    for key in ("podSelector", "namespaceSelector"):
        if key in peer or key in peer.get("_coverage", {}):
            _selector_shape(get(peer, key, dict))
    if "ipBlock" in peer or "ipBlock" in peer.get("_coverage", {}):
        block = get(peer, "ipBlock", dict)
        try:
            cidr = ip_network(get(block, "cidr", str), strict=False)
            exclusions = optional(block, "except", [], list)
            if any(not isinstance(entry, str) or ip_network(entry, strict=False).version != cidr.version for entry in exclusions):
                raise ValueError("invalid exception CIDR")
        except ValueError as exc:
            raise Unavailable("malformed NetworkPolicy ipBlock") from exc


for _direction in ("Ingress", "Egress"):
    _id = f"k8s.cis.networkpolicy_no_default_allow_{_direction.lower()}"
    def _evaluate(item, index, direction=_direction):
        return _default_allow(item, direction)
    _peer = "from" if _direction == "Ingress" else "to"
    _field = _direction.lower()
    _register(_id, "networkpolicy", f"Namespace-wide NetworkPolicy has no {_direction.lower()} allow rule with omitted peers",
              _evaluate, category="network", remediation=f"Review the policy owner and narrow {_field}[].{_peer} to the intended peer selectors or CIDRs in the owned NetworkPolicy manifest; validate traffic before rollout.",
              passing={"spec": {"podSelector": {}, "policyTypes": [_direction], _field: [{_peer: [{"podSelector": {"matchLabels": {"app": "api"}}}]}]}},
              failing={"spec": {"podSelector": {}, "policyTypes": [_direction], _field: [{}]}})


def _deployment_available(item, index):
    desired = get(item, "spec.replicas", int)
    available = get(item, "status.availableReplicas", int)
    if desired < 0 or available < 0:
        return unknown("negative deployment replica count")
    conditions = list_of_objects(get(item, "status.conditions", list))
    observed = [get(row, "status", str) for row in conditions if get(row, "type", str) == "Available"]
    if not observed or any(value not in ("True", "False", "Unknown") for value in observed) or len(set(observed)) != 1:
        return unknown("Deployment Available condition missing or malformed")
    return result("True" not in observed or available < desired,
                  desired_replicas=desired, available_replicas=available, available_condition=observed,
                  semantics="Observed Deployment status at snapshot time")


_register("k8s_deployment_available_condition", "deployment", "Deployment reports Available with desired replicas",
          _deployment_available, remediation="Inspect Deployment conditions and rollout events, then fix the workload or capacity issue in the owned manifest; verify Available and availableReplicas after rollout.",
          passing={"spec": {"replicas": 2}, "status": {"availableReplicas": 2, "conditions": [{"type": "Available", "status": "True"}]}},
          failing={"spec": {"replicas": 2}, "status": {"availableReplicas": 1, "conditions": [{"type": "Available", "status": "False"}]}})


def _ingress_sni_hosts(item, index):
    spec = get(item, "spec", dict)
    rules = list_of_objects(optional(spec, "rules", [], list))
    tls = list_of_objects(optional(spec, "tls", [], list))  # Absent spec.tls: no host has TLS.
    covered = set()
    for entry in tls:
        secret = optional(entry, "secretName", "", str)
        hosts = optional(entry, "hosts", [], list)
        if any(not isinstance(host, str) for host in hosts):
            return unknown("malformed Ingress TLS hosts")
        if secret.strip():
            covered.update(hosts)
    hosts = [get(rule, "host", str) for rule in rules if "host" in rule]
    missing = sorted({host for host in hosts if host and host not in covered})
    return result(bool(missing), rule_hosts=hosts, hosts_without_tls_secret=missing,
                  semantics="Ingress TLS declaration; certificate validity and controller behavior not tested")


_register("k8s_ingress_sni_hosts", "ingress", "Ingress rule hosts have matching TLS hosts and Secret names",
          _ingress_sni_hosts, category="network", remediation="Add each required rule host to an Ingress spec.tls[].hosts entry with an existing same-namespace TLS Secret name, then verify the controller certificate deployment.",
          passing={"spec": {"rules": [{"host": "app.example.org"}], "tls": [{"hosts": ["app.example.org"], "secretName": "app-tls"}]}},
          failing={"spec": {"rules": [{"host": "app.example.org"}], "tls": [{"hosts": ["other.example.org"], "secretName": "app-tls"}]}})


def _ingress_tls_secret(item, index):
    namespace = get(item, "metadata.namespace", str)
    rules = list_of_objects(optional(get(item, "spec", dict), "rules", [], list))
    tls = list_of_objects(optional(get(item, "spec", dict), "tls", [], list))  # Absent spec.tls: no TLS declared.
    if not namespace:
        return unknown("Ingress namespace absent")
    def secret_names():
        names = {}
        for secret in complete_items(index, "secret_metadata"):
            name = get(secret, "metadata.name", str)
            secret_namespace = get(secret, "metadata.namespace", str)
            kind = get(secret, "type", str)
            key = (secret_namespace, name)
            if key in names:
                raise Unavailable("duplicate Secret metadata identity")
            names[key] = kind
        return names
    names = memoized(index, ("compliance_new_k8s_tls_secret_names",), secret_names)
    if not tls:
        return result(True, reason="Ingress has no TLS declaration")
    covered = set()
    missing = []
    for row in tls:
        secret_name = get(row, "secretName", str)
        hosts = get(row, "hosts", list)
        if any(not isinstance(host, str) or not host.strip() for host in hosts):
            return unknown("malformed Ingress TLS host")
        if not secret_name.strip():
            missing.append({"namespace": namespace, "secret": secret_name, "reason": "TLS Secret name is explicitly empty"})
            continue
        kind = names.get((namespace, secret_name))
        if kind is None:
            missing.append({"namespace": namespace, "secret": secret_name, "reason": "not found in complete scoped Secret metadata"})
        elif kind != "kubernetes.io/tls":
            missing.append({"namespace": namespace, "secret": secret_name, "reason": "not a kubernetes.io/tls Secret"})
        else:
            covered.update(hosts)
    rule_hosts = [get(row, "host", str) for row in rules if "host" in row]
    if any(not host.strip() for host in rule_hosts):
        return unknown("malformed Ingress rule host")
    uncovered = sorted(set(rule_hosts) - covered)
    return result(bool(missing or uncovered), namespace=namespace, missing_tls_secrets=missing,
                  rule_hosts_without_resolved_tls=uncovered,
                  semantics="Same-namespace Secret metadata and Ingress declaration; certificate and controller runtime are not assessed")


_register("k8s_ingress_tls_configured", "ingress", "Ingress TLS hosts resolve to same-namespace TLS Secret metadata",
          _ingress_tls_secret, category="network", dependencies=["ingress", "secret_metadata"],
          remediation="Have the Ingress owner provision a same-namespace kubernetes.io/tls Secret through the approved secret manager, set each TLS host and secretName in the owned Ingress manifest, then verify controller certificate delivery without reading Secret values in this check.",
          passing={"metadata": {"namespace": "apps"}, "spec": {"rules": [{"host": "app.example.org"}], "tls": [{"hosts": ["app.example.org"], "secretName": "app-tls"}]}},
          failing={"metadata": {"namespace": "apps"}, "spec": {"rules": [{"host": "app.example.org"}], "tls": [{"hosts": ["app.example.org"], "secretName": "wrong-tls"}]}})
CASES["k8s_ingress_tls_configured"]["index"] = {
    "collections": {"secret_metadata": [{"status": "collected"}]},
    "secret_metadata": [{"data": {"metadata": {"name": "app-tls", "namespace": "apps"},
                                  "type": "kubernetes.io/tls"}}],
}


def _service_ftp(item, index):
    spec = get(item, "spec", dict)
    service_type = get(spec, "type", str)
    if service_type not in ("ClusterIP", "NodePort", "LoadBalancer", "ExternalName"):
        return unknown("unrecognized Service type", observed_type=service_type)
    if service_type != "ClusterIP":
        return "NOT_APPLICABLE", {"reason": "Source predicate selects ClusterIP Services"}
    ports = list_of_objects(get(spec, "ports", list))
    offending = []
    for row in ports:
        protocol = optional(row, "protocol", "TCP", str)
        if protocol not in ("TCP", "UDP", "SCTP"):
            return unknown("unrecognized Service port protocol", observed_protocol=protocol)
        port = get(row, "port", int)
        if not 1 <= port <= 65535:
            return unknown("invalid Service port")
        if protocol == "TCP" and port == 21:
            offending.append(port)
    return result(bool(offending), declared_tcp_ftp_ports=offending,
                  semantics="Service port declaration; application protocol and access are not probed")


_register("k8s_service_service_uses_ftp_endpoint_connection_e9b0a5f836", "service",
          "ClusterIP Service does not declare TCP port 21", _service_ftp, category="network",
          remediation="Confirm the application protocol with its owner, then remove TCP port 21 or migrate the Service and clients to an approved encrypted protocol in the owned manifest.",
          passing={"spec": {"type": "ClusterIP", "ports": [{"port": 21, "protocol": "UDP"}]}},
          failing={"spec": {"type": "ClusterIP", "ports": [{"port": 21, "protocol": "TCP"}]}})


def _global_addresses(values):
    observed = []
    for value in values:
        if not isinstance(value, str):
            raise Unavailable("malformed IP address")
        try:
            address = ip_address(value)
        except ValueError as exc:
            raise Unavailable("malformed IP address") from exc
        observed.append((value, address.is_global))
    return observed


def _node_external_ip(item, index):
    addresses = list_of_objects(get(item, "status.addresses", list))
    external = [get(row, "address", str) for row in addresses if get(row, "type", str) == "ExternalIP"]
    assessed = _global_addresses(external)
    global_ips = [value for value, is_global in assessed if is_global]
    return result(bool(global_ips), observed_external_ips=external, globally_routable_external_ips=global_ips,
                  semantics="Node address declaration only; no internet reachability is inferred")


_register("k8s_node_nodes_publicly_accessible_rule_non_8250b02a65", "node",
          "Node advertises no globally routable ExternalIP", _node_external_ip, category="network",
          remediation="Inspect the node pool's address assignment and workload dependencies with the infrastructure owner; if private nodes are required, plan a replacement/private pool and migrate workloads before removing public addresses.",
          passing={"status": {"addresses": [{"type": "ExternalIP", "address": "192.0.2.5"}]}},
          failing={"status": {"addresses": [{"type": "ExternalIP", "address": "8.8.8.8"}]}})


def _pod_global_ip(item, index):
    status = get(item, "status", dict)
    addresses = []
    if "podIP" in status:
        value = get(status, "podIP", str)
        if value:
            addresses.append(value)
    if "podIPs" in status:
        rows = list_of_objects(get(status, "podIPs", list))
        addresses.extend(get(row, "ip", str) for row in rows)
    if not addresses:
        return unknown("Pod IP status is not assigned or not collected")
    assessed = _global_addresses(addresses)
    global_ips = sorted({value for value, is_global in assessed if is_global})
    return result(bool(global_ips), observed_pod_ips=sorted(set(addresses)), globally_routable_pod_ips=global_ips,
                  semantics="Assigned Pod IP status only; no internet reachability is inferred")


_register("k8s_pod_direct_internet_access_disabled_pod_0a30afe8f2", "pod",
          "Pod status advertises no globally routable Pod IP", _pod_global_ip, category="network",
          remediation="Review the CNI and assigned Pod IPs with the cluster network owner; if private Pod addresses are required, change the approved network allocation and safely replace affected workloads after testing.",
          passing={"status": {"podIP": "10.1.2.3", "podIPs": [{"ip": "10.1.2.3"}]}},
          failing={"status": {"podIP": "8.8.8.8", "podIPs": [{"ip": "8.8.8.8"}]}})


def _secret_not_deleting(item, index):
    metadata = get(item, "metadata", dict)
    name = get(metadata, "name", str)
    namespace = get(metadata, "namespace", str)
    timestamp = optional(metadata, "deletionTimestamp", None)
    if timestamp is not None:
        if not isinstance(timestamp, str) or not timestamp.strip():
            return unknown("malformed Secret deletion timestamp", name=name, namespace=namespace)
        try:
            parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        except ValueError:
            return unknown("malformed Secret deletion timestamp", name=name, namespace=namespace)
        if parsed.tzinfo is None:
            return unknown("Secret deletion timestamp lacks timezone", name=name, namespace=namespace)
    return result(timestamp is not None, name=name, namespace=namespace, deletion_timestamp=timestamp,
                  semantics="Metadata-only deletion request state; Secret data and dependent workloads are not read")


# The signed proposal names kind `secret`; the collected metadata-only API
# inventory is `secret_metadata`. Registry owner approved this exact alias.
_register("k8s_secret_no_deletion_timestamp", "secret_metadata",
          "Secret metadata has no pending deletion timestamp", _secret_not_deleting,
          remediation="Confirm whether the pending Secret deletion is intentional with its owner; if the Secret remains needed, safely recreate it through the approved secret manager and update dependent workloads, because deletionTimestamp cannot be unset.",
          passing={"metadata": {"name": "app-secret", "namespace": "apps"}},
          failing={"metadata": {"name": "app-secret", "namespace": "apps", "deletionTimestamp": "2026-10-12T01:00:00Z"}})
