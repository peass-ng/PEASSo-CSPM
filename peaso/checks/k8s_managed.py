"""Provider- and control-plane-managed Kubernetes object classifier.

A hardening finding on an object the customer cannot change (a GKE add-on in
``kube-system``, the ``cluster-admin`` bootstrap ClusterRole, a kube-controller-manager
ServiceAccount) is not actionable. Native k8s checks keep evaluating such objects,
but a non-passing result is reported as ``NOT_APPLICABLE`` with
``{"provider_managed": true, "managed_reason": ...}`` and the underlying result, the
same convention the AWS checks use for service-linked roles.

Precision first: an object is managed only on positive evidence carried by the
object itself (reserved labels, annotations or names), by its owner chain, or by a
provider-reserved namespace. Living in ``kube-system`` alone is NOT evidence: a
customer workload in ``kube-system`` is still evaluated. A customer-created binding
that references a managed role (for example ``cluster-admin``) is still evaluated.
"""
from __future__ import annotations

import re

# Namespaces the control plane creates. Only objects that are themselves managed
# inside them are exempt.
SYSTEM_NAMESPACES = frozenset(("kube-system", "kube-public", "kube-node-lease"))

# Namespaces wholly reconciled by a provider add-on manager; customers do not
# deploy into them (GKE rejects writes to gke-managed-*).
PROVIDER_NAMESPACES = frozenset((
    "gmp-system", "gke-gmp-system",                  # GKE Managed Service for Prometheus
    "gke-managed-cim", "gke-managed-system",          # also covered by the gke-managed- prefix
    "aks-command",                                    # AKS run-command
    "amazon-guardduty", "amazon-cloudwatch", "amazon-network-flow-monitor",  # documented EKS add-ons
))
PROVIDER_NAMESPACE_PREFIXES = (
    "gke-managed-",   # GKE
    "aks-istio-",     # AKS managed Istio add-on
)

# kube-addon-manager modes (GKE, AKS and kube-up clusters).
ADDON_MODES = frozenset(("Reconcile", "EnsureExists"))
# EKS / AKS ownership labels. eks.amazonaws.com/role-arn and other IRSA keys are
# customer configuration, so only the component label is a managed marker.
EKS_LABELS = frozenset(("eks.amazonaws.com/component",))
AKS_LABELS = frozenset(("kubernetes.azure.com/managedby",))
GKE_COMPONENT_MARKER = "components.gke.io/component-name"

# RBAC object name prefixes reserved by Kubernetes (system:) and EKS (eks:).
RESERVED_RBAC_PREFIXES = ("system:", "eks:")
RBAC_KINDS = frozenset(("role", "clusterrole", "rolebinding", "clusterrolebinding"))

# ServiceAccounts kube-controller-manager / cloud-controller-manager create in
# kube-system for their controllers (--use-service-account-credentials).
CONTROLLER_SERVICE_ACCOUNTS = frozenset((
    "attachdetach-controller", "bootstrap-signer", "certificate-controller", "clusterrole-aggregation-controller",
    "cronjob-controller", "daemon-set-controller", "deployment-controller", "disruption-controller",
    "endpoint-controller", "endpointslice-controller", "endpointslicemirroring-controller",
    "ephemeral-volume-controller", "expand-controller", "generic-garbage-collector", "horizontal-pod-autoscaler",
    "job-controller", "legacy-service-account-token-cleaner", "namespace-controller", "node-controller",
    "persistent-volume-binder", "pod-garbage-collector", "pv-protection-controller", "pvc-protection-controller",
    "replicaset-controller", "replication-controller", "resource-claim-controller", "resourcequota-controller",
    "root-ca-cert-publisher", "route-controller", "service-account-controller", "service-cidrs-controller",
    "service-controller", "statefulset-controller", "token-cleaner", "ttl-after-finished-controller",
    "ttl-controller", "validatingadmissionpolicy-status-controller", "volumeattributesclass-protection-controller",
    "selinux-warning-controller", "device-taint-eviction-controller", "cloud-provider", "gke-service-controller",
))

# Control-plane users that authenticate without the reserved system: prefix.
CONTROL_PLANE_USERS = frozenset(("kube-apiserver", "kube-apiserver-kubelet-client"))
CONTROL_PLANE_USER_PREFIXES = ("eks:",)
UNIVERSAL_GROUPS = frozenset(("system:authenticated", "system:unauthenticated", "system:serviceaccounts"))

# Node labels proving the node (and so its kubelet static manifests) is provider-managed.
MANAGED_NODE_LABELS = ("cloud.google.com/gke-nodepool", "eks.amazonaws.com/nodegroup", "kubernetes.azure.com/agentpool")

OWNER_KINDS = {"ReplicaSet": "replicaset", "Deployment": "deployment", "DaemonSet": "daemonset",
               "StatefulSet": "statefulset", "Job": "job", "CronJob": "cronjob",
               "ReplicationController": "replicationcontroller"}
WORKLOAD_TEMPLATE_KINDS = frozenset(OWNER_KINDS.values()) | {"pod"}


def _mapping(value):
    return value if isinstance(value, dict) else {}


def _metadata(item):
    return _mapping(_mapping(item).get("metadata"))


def marker_reason(metadata):
    """A managed marker carried by the object's own labels or annotations."""
    labels = _mapping(metadata.get("labels"))
    annotations = _mapping(metadata.get("annotations"))
    mode = labels.get("addonmanager.kubernetes.io/mode")
    if isinstance(mode, str) and mode in ADDON_MODES:
        return "label addonmanager.kubernetes.io/mode=" + mode
    if labels.get("kubernetes.io/bootstrapping") == "rbac-defaults":
        return "label kubernetes.io/bootstrapping=rbac-defaults"
    for source, values in (("label", labels), ("annotation", annotations)):
        value = values.get(GKE_COMPONENT_MARKER)
        if isinstance(value, str) and value:
            return source + " " + GKE_COMPONENT_MARKER + "=" + value
    for key in sorted(EKS_LABELS | AKS_LABELS):
        value = labels.get(key)
        if isinstance(value, str) and value:
            return "label " + key + "=" + value
    return None


def _namespace_reason(name):
    if not isinstance(name, str):
        return None
    if name in PROVIDER_NAMESPACES or name.startswith(PROVIDER_NAMESPACE_PREFIXES):
        return "provider-managed namespace " + name
    return None


_LOOKUPS = {}


def _lookup_table(rows):
    """(name, namespace, uid) -> matching row data, built once per index list.

    Equivalent to scanning ``rows`` for each lookup: only rows whose name and uid
    are strings and whose namespace is a string or absent can ever match."""
    cached = _LOOKUPS.get(id(rows))
    if cached is not None and cached[0] is rows and cached[1] == len(rows):
        return cached[2]
    table = {}
    for row in rows:
        data = _mapping(_mapping(row).get("data"))
        metadata = _metadata(data)
        name, namespace, uid = metadata.get("name"), metadata.get("namespace"), metadata.get("uid")
        if type(name) is str and type(uid) is str and (namespace is None or type(namespace) is str):
            table.setdefault((name, namespace, uid), []).append(data)
        elif isinstance(name, str) and isinstance(uid, str) and (namespace is None or isinstance(namespace, str)):
            table = None  # str subclasses: keep the exact linear comparison
            break
    if len(_LOOKUPS) > 64:
        _LOOKUPS.clear()
    _LOOKUPS[id(rows)] = (rows, len(rows), table)
    return table


def _lookup(index, kind, namespace, name, uid):
    if not isinstance(name, str) or not name or not isinstance(uid, str) or not uid:
        return None
    rows = _mapping(index).get(kind)
    if not isinstance(rows, list):
        return None
    table = _lookup_table(rows) if type(name) is str and type(uid) is str and (namespace is None or type(namespace) is str) else None
    if table is not None:
        matches = table.get((name, namespace, uid), ())
        return matches[0] if len(matches) == 1 else None
    matches = []
    for row in rows:
        data = _mapping(_mapping(row).get("data"))
        metadata = _metadata(data)
        if metadata.get("name") != name or metadata.get("namespace") != namespace:
            continue
        if metadata.get("uid") != uid:
            continue
        matches.append(data)
    return matches[0] if len(matches) == 1 else None


def _owner_reason(metadata, index, depth=0):
    if depth > 3:
        return None
    owners = metadata.get("ownerReferences")
    if not isinstance(owners, list):
        return None
    namespace = metadata.get("namespace")
    if not isinstance(namespace, str) or not namespace or not isinstance(metadata.get("uid"), str) or not metadata["uid"]:
        return None
    controllers = [owner for owner in owners if isinstance(owner, dict) and owner.get("controller") is True]
    if len(controllers) != 1:
        return None
    owner = controllers[0]
    kind, name = OWNER_KINDS.get(owner.get("kind")), owner.get("name")
    if kind is None or not isinstance(name, str) or not name:
        return None
    parent = _lookup(index, kind, namespace, name, owner.get("uid"))
    if parent is not None:
        parent_meta = _metadata(parent)
        reason = marker_reason(parent_meta) or _owner_reason(parent_meta, index, depth + 1)
        if reason:
            return "owned by managed " + owner["kind"] + " " + name + " (" + reason + ")"
    return None


def _mirror_pod_reason(item, metadata, index):
    """Kubelet mirror pod in kube-system on a provider-managed node (GKE kube-proxy)."""
    if metadata.get("namespace") != "kube-system" or _mapping(item).get("_static_pod_metadata") is not True:
        return None
    if not isinstance(metadata.get("uid"), str) or not metadata["uid"]:
        return None
    owners = metadata.get("ownerReferences")
    if not isinstance(owners, list):
        return None
    controllers = [owner for owner in owners if isinstance(owner, dict) and owner.get("controller") is True]
    if len(controllers) != 1 or controllers[0].get("kind") != "Node":
        return None
    owner = controllers[0]
    node = _lookup(index, "node", None, owner.get("name"), owner.get("uid"))
    labels = _mapping(_metadata(node).get("labels")) if node else {}
    for key in MANAGED_NODE_LABELS:
        value = labels.get(key)
        if isinstance(value, str) and value:
            return "static pod on provider-managed node (" + key + ")"
    return None


def managed_reason(item, kind, index=None):
    """Why ``item`` (a native object of check ``kind``) is provider/control-plane managed, or None."""
    metadata = _metadata(item)
    if not metadata or not isinstance(metadata.get("name"), str):
        return None
    name, namespace = metadata["name"], metadata.get("namespace")
    index = _mapping(index)
    if kind == "namespace":
        if name in SYSTEM_NAMESPACES:
            return "control-plane namespace " + name
        return _namespace_reason(name) or marker_reason(metadata)
    reason = _namespace_reason(namespace) or marker_reason(metadata)
    if reason:
        return reason
    if kind in RBAC_KINDS and name.startswith(RESERVED_RBAC_PREFIXES):
        return "reserved RBAC name prefix " + name.split(":", 1)[0] + ":"
    if kind == "configmap_metadata" and name == "kube-root-ca.crt":
        return "root-ca-cert-publisher ConfigMap"
    if kind == "service" and namespace == "default" and name == "kubernetes":
        # Only the Service object. Its EndpointSlice carries the API server's real address and port,
        # which cluster-level controls (secure port) still evaluate.
        labels = _mapping(metadata.get("labels"))
        if labels.get("component") == "apiserver" and labels.get("provider") == "kubernetes":
            return "API server Service"
    if namespace in SYSTEM_NAMESPACES:
        if kind == "serviceaccount" and (name == "default" or (namespace == "kube-system" and name in CONTROLLER_SERVICE_ACCOUNTS)):
            return "control-plane ServiceAccount " + namespace + "/" + name
        if kind in WORKLOAD_TEMPLATE_KINDS:
            return _owner_reason(metadata, index) or (_mirror_pod_reason(item, metadata, index) if kind == "pod" else None)
        return None
    if kind in WORKLOAD_TEMPLATE_KINDS:
        return _owner_reason(metadata, index)
    return None


def control_plane_subject(subject):
    """True for reserved control-plane identities (system:*, kube-apiserver, eks:*).

    Groups that cover every caller or every ServiceAccount are never control-plane identities."""
    subject = _mapping(subject)
    kind, name = subject.get("kind"), subject.get("name")
    if kind not in ("User", "Group") or not isinstance(name, str):
        return False
    if name.startswith("system:serviceaccount:"):
        return False
    if kind == "Group":
        return name.startswith("system:") and name not in UNIVERSAL_GROUPS and not name.startswith("system:serviceaccounts:")
    return name.startswith("system:") or name in CONTROL_PLANE_USERS or name.startswith(CONTROL_PLANE_USER_PREFIXES)


ACTIONABLE = frozenset(("FAIL", "MANUAL", "UNKNOWN", "DENIED"))
_CACHE = {}


def apply(kind, item, index, status, evidence):
    """Re-label a non-passing native k8s result on a managed object as NOT_APPLICABLE."""
    if status not in ACTIONABLE:
        return status, evidence
    key = (id(item), id(index), kind)
    cached = _CACHE.get(key)
    if cached is not None and cached[0] is item and cached[1] is index:
        reason = cached[2]
    else:
        reason = managed_reason(item, kind, index)
        if len(_CACHE) > 50000:
            _CACHE.clear()
        _CACHE[key] = (item, index, reason)
    if reason is None:
        return status, evidence
    return "NOT_APPLICABLE", {"reason": "Provider- or control-plane-managed component; the customer cannot change it",
                              "provider_managed": True, "managed_reason": reason,
                              "underlying_status": status, "underlying_evidence": evidence}


__all__ = ["managed_reason", "marker_reason", "control_plane_subject", "apply", "SYSTEM_NAMESPACES",
           "PROVIDER_NAMESPACES", "CONTROLLER_SERVICE_ACCOUNTS", "CONTROL_PLANE_USERS"]
