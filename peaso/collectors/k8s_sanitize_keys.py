"""Bounded per-process memo for the K8s collector's key-drop decision.

The decision itself stays in ``peaso.collectors.k8s._sanitize``; this module
only remembers its boolean result for exact ``str`` keys, which repeat across
every object of a scan (metadata, spec, containers, ...). It stores no values.
It also holds the value-free Multus annotation projection used by the sanitizer.
"""
import json


MAX_KEYS = 8192
# Exact scalar types that _sanitize returns unchanged; skipping the call is identical.
LEAVES = frozenset((str, int, float, bool, type(None)))
DROPPED = {}


def remember(key, dropped):
    if type(key) is not str:
        return
    if len(DROPPED) >= MAX_KEYS:
        DROPPED.clear()
    DROPPED[key] = dropped


# GKE load-balancer annotations: provider-written resource names, scheme and
# source-range settings, and NEG status JSON. They identify the cloud edge of a
# Service, Ingress or Gateway and hold no workload literals; values stay bounded.
CLOUD_EDGE_ANNOTATIONS = frozenset({
    "cloud.google.com/load-balancer-type", "networking.gke.io/load-balancer-type",
    "service.beta.kubernetes.io/load-balancer-source-ranges",
    "service.kubernetes.io/backend-service", "service.kubernetes.io/tcp-forwarding-rule",
    "service.kubernetes.io/udp-forwarding-rule", "service.kubernetes.io/l3-forwarding-rule",
    "service.kubernetes.io/l3-forwarding-rule-ipv6",
    "cloud.google.com/neg", "cloud.google.com/neg-status",
    "ingress.kubernetes.io/forwarding-rule", "ingress.kubernetes.io/https-forwarding-rule",
    "ingress.kubernetes.io/target-proxy", "ingress.kubernetes.io/https-target-proxy",
    "ingress.kubernetes.io/url-map",
    "networking.gke.io/forwarding-rules", "networking.gke.io/target-proxies", "networking.gke.io/url-maps",
})
CLOUD_EDGE_MAX = 4096

MULTUS_ANNOTATIONS = ("k8s.v1.cni.cncf.io/networks", "k8s.v1.cni.cncf.io/network-status")
MULTUS_FIELDS = ("name", "namespace", "interface", "ips", "mac", "default", "default-route")


def multus_annotation(text):
    """Keep only Multus attachment identity and address fields; CNI arguments and plugin data can carry credentials."""
    if not text.lstrip().startswith(("[", "{")):
        return text  # Short form: comma-separated namespace/name@interface references.
    try:
        entries = json.loads(text)
    except ValueError:
        return None
    entries = entries if isinstance(entries, list) else [entries]
    kept = [{key: entry[key] for key in MULTUS_FIELDS if key in entry}
            for entry in entries if isinstance(entry, dict)]
    return json.dumps(kept, separators=(",", ":"))
