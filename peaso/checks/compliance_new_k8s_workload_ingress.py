"""Signed Kubernetes Pod identity and nginx Ingress declaration checks.

These inspect API declarations, not process identity, controller behavior, or
end-to-end TLS. Other Ingress controllers are outside the reviewed predicates.
"""
from __future__ import annotations

from . import register, result, unknown
from .facts import Unavailable, complete_items, get, list_of_objects, optional
from .fixtures import CASES

POD_ID = "k8s_pod_effective_run_as_user_nonzero"
BACKEND_ID = "k8s_ingress_backend_https"
REDIRECT_ID = "k8s_ingress_ingress_redirect_http_traffic_https_12967db1"
IDS = [POD_ID, BACKEND_ID, REDIRECT_ID]


@register(POD_ID, "k8s", "hardening", "pod",
          "Linux Pod declares a nonzero runAsUser for every regular and init container",
          "medium", "CM-6",
          "Review the image USER and workload compatibility; declare a nonzero runAsUser in the owned Pod or container securityContext and roll out safely.",
          dependencies=["pod"])
def pod_run_as_user(item, index):
    spec = get(item, "spec", dict)
    # Kubernetes treats a Pod without spec.os as a Linux Pod.
    os_name = optional(optional(spec, "os", {}, dict), "name", "linux", str)
    if os_name == "windows":
        return "NOT_APPLICABLE", {"reason": "runAsUser is a Linux Pod setting", "observed_os": os_name}
    if os_name != "linux":
        return unknown("unrecognized Pod OS", observed_os=os_name)
    pod_context = optional(spec, "securityContext", {}, dict)
    inherited = optional(pod_context, "runAsUser", None)
    if inherited is not None and (type(inherited) is not int or inherited < 0):
        return unknown("malformed Pod runAsUser declaration")
    regular = list_of_objects(get(spec, "containers", list))
    if not regular:
        return unknown("Pod has no regular containers")
    containers = regular + list_of_objects(optional(spec, "initContainers", [], list))
    root, unresolved, observed = [], [], []
    for container in containers:
        name = get(container, "name", str)
        if not name.strip():
            return unknown("container name is empty")
        context = optional(container, "securityContext", {}, dict)
        uid = optional(context, "runAsUser", inherited)
        if uid is None:
            unresolved.append(name)
            continue
        if type(uid) is not int or uid < 0:
            return unknown("malformed container runAsUser declaration", container=name)
        observed.append({"container": name, "declared_uid": uid})
        if uid == 0:
            root.append(name)
    if root:
        return result(True, explicit_root_containers=root, observed=observed,
                      unresolved_containers=unresolved,
                      semantics="Pod/container declaration only; runtime identity and image USER unobserved")
    if unresolved:
        return unknown("container UID can inherit image USER; runtime identity unobserved",
                       unresolved_containers=unresolved, observed=observed)
    return result(False, observed=observed,
                  semantics="Pod/container declaration only; runtime identity unobserved")


def _nginx_tls(item, index):
    spec = get(item, "spec", dict)
    ingress_class = get(spec, "ingressClassName", str)
    classes = {}
    for row in complete_items(index, "ingressclass"):
        name = get(row, "metadata.name", str)
        if not name or name in classes:
            return unknown("IngressClass identity missing or duplicated", observed_ingress_class=name)
        classes[name] = get(row, "spec.controller", str)
    controller = classes.get(ingress_class)
    if controller is None:
        return unknown("IngressClass not resolved in complete inventory", observed_ingress_class=ingress_class)
    if controller != "k8s.io/ingress-nginx":
        return unknown("IngressClass controller is outside reviewed ingress-nginx identifier",
                       observed_ingress_class=ingress_class, observed_controller=controller)
    tls = list_of_objects(get(spec, "tls", list))
    if not tls:
        return "NOT_APPLICABLE", {"reason": "signed predicate selects Ingresses with a TLS declaration"}
    metadata = get(item, "metadata", dict)
    annotations = optional(metadata, "annotations", {}, dict)
    if any(not isinstance(key, str) or not isinstance(value, str) for key, value in annotations.items()):
        raise Unavailable("malformed Ingress annotations")
    return spec, metadata, annotations


@register(BACKEND_ID, "k8s", "network", "ingress",
          "nginx TLS Ingress declares HTTPS or GRPCS for resolved backend Services",
          "medium", "SC-8",
          "Review backend TLS support with the Service owner and plan migration from retired ingress-nginx to a supported controller; during a reviewed transition, declare HTTPS or GRPCS only after backend TLS is configured and verify the result.",
          dependencies=["ingress", "ingressclass", "service"])
def ingress_backend_protocol(item, index):
    parsed = _nginx_tls(item, index)
    if len(parsed) == 2:
        return parsed
    spec, metadata, annotations = parsed
    namespace = get(metadata, "namespace", str)
    if not namespace:
        return unknown("Ingress namespace is absent")
    services = {}
    for service in complete_items(index, "service"):
        key = (get(service, "metadata.namespace", str), get(service, "metadata.name", str))
        if key in services:
            return unknown("duplicate Service identity in complete inventory", namespace=key[0], name=key[1])
        services[key] = service
    native = item.get("provenance", {}).get("evidence") == "read-only list"
    rules = list_of_objects(optional(spec, "rules", [], list) if native else get(spec, "rules", list))
    targets = []
    if "defaultBackend" in spec:
        backend = get(spec, "defaultBackend", dict)
        if "resource" in backend:
            return unknown("Ingress default resource backend is outside reviewed Service configuration")
        targets.append(get(backend, "service.name", str))
    for rule in rules:
        paths = list_of_objects(get(rule, "http.paths", list))
        for path in paths:
            targets.append(get(path, "backend.service.name", str))
    if not targets:
        return unknown("no rule backend Service was observed")
    unresolved = sorted({name for name in targets if not name or (namespace, name) not in services})
    if unresolved:
        return unknown("Ingress backend Service unresolved in complete same-namespace inventory",
                       unresolved_services=unresolved, namespace=namespace)
    protocol = annotations.get("nginx.ingress.kubernetes.io/backend-protocol")
    if protocol is not None and protocol not in ("HTTPS", "GRPCS", "HTTP", "GRPC", "FCGI", "AUTO_HTTP"):
        return unknown("unrecognized nginx backend protocol annotation", observed_protocol=protocol)
    return result(protocol not in ("HTTPS", "GRPCS"), declared_backend_protocol=protocol,
                  resolved_backend_services=sorted(set(targets)), namespace=namespace,
                  semantics="Ingress annotation and Service identity only; controller adoption and backend TLS runtime unverified")


@register(REDIRECT_ID, "k8s", "network", "ingress",
          "nginx TLS Ingress explicitly declares HTTP-to-HTTPS redirect",
          "medium", "SC-8",
          "Review the controller's redirect policy and plan migration from retired ingress-nginx to a supported controller; during a reviewed transition, set an explicit redirect annotation only when approved and verify behavior.",
          dependencies=["ingress", "ingressclass"])
def ingress_explicit_redirect(item, index):
    parsed = _nginx_tls(item, index)
    if len(parsed) == 2:
        return parsed
    _, _, annotations = parsed
    keys = ("nginx.ingress.kubernetes.io/force-ssl-redirect",
            "nginx.ingress.kubernetes.io/ssl-redirect")
    observed = {key: annotations[key] for key in keys if key in annotations}
    if not observed:
        return unknown("redirect annotation absent; controller default or ConfigMap may govern behavior")
    if any(value not in ("true", "false") for value in observed.values()):
        return unknown("malformed nginx redirect annotation", observed=observed)
    if len(set(observed.values())) > 1:
        return unknown("conflicting nginx redirect annotations", observed=observed)
    return result(not any(value == "true" for value in observed.values()),
                  observed_redirect_annotations=observed,
                  semantics="Explicit Ingress annotation only; controller defaults and actual redirect are unverified")


CASES[POD_ID] = {
    "pass": {"spec": {"os": {"name": "linux"}, "securityContext": {"runAsUser": 1000},
                      "containers": [{"name": "app"}], "initContainers": [{"name": "setup", "securityContext": {"runAsUser": 2000}}]}},
    "fail": {"spec": {"os": {"name": "linux"}, "securityContext": {"runAsUser": 1000},
                      "containers": [{"name": "app", "securityContext": {"runAsUser": 0}}]}},
    "missing": {"spec": {"os": {"name": "linux"}, "containers": [{"name": "app"}]}},
    "malformed": {"spec": {"os": {"name": "linux"}, "containers": [{"name": "app", "securityContext": {"runAsUser": "0"}}]}},
}

_INGRESS = {"metadata": {"namespace": "apps", "annotations": {}},
            "spec": {"ingressClassName": "nginx", "tls": [{"hosts": ["app.example"], "secretName": "tls"}],
                     "rules": [{"http": {"paths": [{"backend": {"service": {"name": "app"}}}]}}]}}
_CLASS_INDEX = {"collections": {"ingressclass": [{"status": "collected"}]},
                "ingressclass": [{"data": {"metadata": {"name": "nginx", "uid": "class-1"},
                                          "spec": {"controller": "k8s.io/ingress-nginx"}}}]}
_SERVICE_INDEX = {"collections": {**_CLASS_INDEX["collections"], "service": [{"status": "collected"}]},
                  "ingressclass": _CLASS_INDEX["ingressclass"],
                  "service": [{"data": {"metadata": {"namespace": "apps", "name": "app"}}}]}
CASES[BACKEND_ID] = {
    "pass": {**_INGRESS, "metadata": {"namespace": "apps", "annotations": {"nginx.ingress.kubernetes.io/backend-protocol": "HTTPS"}}},
    "fail": _INGRESS,
    "missing": {"metadata": {"namespace": "apps"}, "spec": {"ingressClassName": "nginx", "tls": [{}]}},
    "malformed": {**_INGRESS, "metadata": {"namespace": "apps", "annotations": {"nginx.ingress.kubernetes.io/backend-protocol": 42}}},
    "index": _SERVICE_INDEX,
}
CASES[REDIRECT_ID] = {
    "pass": {**_INGRESS, "metadata": {"namespace": "apps", "annotations": {"nginx.ingress.kubernetes.io/force-ssl-redirect": "true"}}},
    "fail": {**_INGRESS, "metadata": {"namespace": "apps", "annotations": {"nginx.ingress.kubernetes.io/force-ssl-redirect": "false"}}},
    "missing": {"spec": {"ingressClassName": "nginx"}},
    "malformed": {**_INGRESS, "metadata": {"namespace": "apps", "annotations": {"nginx.ingress.kubernetes.io/ssl-redirect": 42}}},
    "index": _CLASS_INDEX,
}
