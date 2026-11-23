"""Shared pure projection helpers. Native evidence is shared read-only or referenced, never rewritten.

Snapshot items are sealed read-only views (peaso.snapshot.FrozenDict), so evidence shares them instead of
deep-copying; graph nodes reference their native resource by ``evidence.native_resource_ref`` (the report
``resources[].id``) rather than embedding a second copy of the snapshot.
"""
from __future__ import annotations

import copy
import hashlib
import json
from json.encoder import encode_basestring_ascii
from contextlib import contextmanager
from contextvars import ContextVar
from functools import lru_cache, wraps

from peaso.snapshot import FrozenDict, FrozenList, digest

FRAMEWORKS = ["HackTricks Cloud Best Practices"]


def frameworks_for(check_id):
    from peaso.presentation_metadata_20261020 import includes_in_hacktricks as includes
    return list(FRAMEWORKS) if includes(check_id) else []


RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_CONTEXT = ContextVar("peaso_analysis_context", default=None)
_JSON_DUMPS = json.dumps


@contextmanager
def analysis_context(snapshot):
    """Bounded, scan-local caches; concurrent evaluations do not share facts."""
    current = _CONTEXT.get()
    if current is not None and current["snapshot"] is snapshot:
        yield current
        return
    value = {"snapshot": snapshot, "collections": {(c["scope"], c["type"]): c for c in snapshot["collections"]},
             "derivations": {}}
    token = _CONTEXT.set(value)
    try:
        yield value
    finally:
        _CONTEXT.reset(token)


def with_analysis_context(function):
    @wraps(function)
    def wrapped(snapshot, *args, **kwargs):
        with analysis_context(snapshot):
            return function(snapshot, *args, **kwargs)
    return wrapped


def derived(resource, kind, compute):
    context = _CONTEXT.get()
    if context is None:
        return compute()
    key = (kind, node_id(resource))
    cache = context["derivations"]
    if key not in cache:
        cache[key] = compute()
    return cache[key]


def stable_id(*parts):
    if json.dumps is _JSON_DUMPS and len(parts) <= 8 and all(type(part) is str for part in parts):
        # IDs overwhelmingly join plain native strings. Use the same JSON
        # string encoder without rebuilding a general object encoder per ID.
        encoded = '[' + ','.join(encode_basestring_ascii(part) for part in parts) + ']'
    else:
        encoded = json.dumps(parts, sort_keys=True, default=str, separators=(",", ":"))
    return "analysis:" + hashlib.sha256(encoded.encode()).hexdigest()[:24]


def gcp_interface_resource_id(instance, index):
    """Selected-flow ID for one interface embedded in a collected GCP VM."""
    native = f"{native_id(instance)}/networkInterfaces/{index}"
    return digest(["gcp", instance["scope"], "instance_interface", native])


def as_list(value):
    return value if isinstance(value, list) else [] if value is None else [value]


def native_id(resource):
    return resource.get("native_id", resource.get("id", resource.get("resource_id", "")))


@lru_cache(maxsize=1 << 17)
def _node_id(provider, scope, kind, native):
    return stable_id(provider, scope, kind, native)


def node_id(resource):
    native = native_id(resource)
    try:
        return _node_id(resource["provider"], resource["scope"], resource["type"], native)
    except TypeError:  # unhashable native identifier
        return stable_id(resource["provider"], resource["scope"], resource["type"], native)


def source(snapshot, resource, path):
    context = _CONTEXT.get()
    if context is not None and context["snapshot"] is snapshot:
        collection = context["collections"].get((resource["scope"], resource["type"]), {})
    else:
        collection = next((c for c in snapshot["collections"]
                           if c["scope"] == resource["scope"] and c["type"] == resource["type"]), {})
    return {"snapshot_id": snapshot.get("snapshot_id"), "resource_id": native_id(resource),
            "resource_type": resource["type"], "scope": resource["scope"], "path": path,
            "collection_status": collection.get("status", "unknown"),
            "request_evidence": _share(resource["data"].get("_evidence", resource["data"].get("_provenance", resource["data"].get("provenance", {})))),
            "native_scope": copy.deepcopy(snapshot.get("metadata", {}).get("cluster_id"))}


def finding(snapshot, resource, category, check, title, severity, evidence, *, status="MANUAL"):
    from peaso.finding_types import type_for
    from peaso.presentation_metadata_20261020 import type_for as presentation_type_for
    from peaso.check_services import service_for
    from .finding_clarity import HOW, ACTION, evidence_summary, network_priority
    if check == "analysis.network_review":
        severity = network_priority(evidence, severity)
    result = {"id": stable_id(category, check, node_id(resource)),
            "category": category, "check_id": check, "title": title,
            "finding_type": presentation_type_for(check) if type(check) is str and check.startswith("analysis.") else type_for(check),
            "provider": resource["provider"], "service": service_for(resource["provider"], resource["type"], resource.get("service")),
            "resource_id": resource.get("id", native_id(resource)), "scope": resource["scope"], "severity": severity,
            "status": status, "frameworks": frameworks_for(check), "evidence": _share(evidence),
            "remediation": ACTION.get(check, "Review the recorded access declaration before changing it.")}
    if status == 'FAIL':
        from peaso.finding_subjects import direct_exposure_subject

        affected = direct_exposure_subject(check, resource)
        if affected:
            result['affected_subjects'] = [affected]
    if check in HOW:
        result["description"] = HOW[check]
    summary = evidence_summary(result)
    if summary:
        result["evidence_summary"] = summary
    return result


def _share(value):
    """Evidence built from sealed snapshot views is shared; anything still mutable is copied once."""
    if isinstance(value, (FrozenDict, FrozenList)) or not isinstance(value, (dict, list, tuple)):
        return value
    if isinstance(value, dict):
        return {key: _share(item) for key, item in value.items()}
    return [_share(item) for item in value]


def _path_prefix(path):
    if not isinstance(path, str) or not path.startswith("/"):
        return None
    parts = [part for part in path.split("/") if part]
    return "/" + parts[0] + "/" if parts else "/"


def facets(resource):
    """Small, provider-native grouping dimensions (account/project, path prefix, namespace) for projections."""
    data, provider = resource["data"], resource["provider"]
    out = {}
    if provider == "aws":
        arn = data.get("Arn")
        if isinstance(arn, str) and arn.count(":") >= 5 and arn.split(":")[4]:
            out["account"] = arn.split(":")[4]
        prefix = _path_prefix(data.get("Path"))
        if prefix:
            out["path_prefix"] = prefix
    elif provider == "gcp":
        email = data.get("email")
        if isinstance(email, str) and "@" in email:
            out["domain"] = email.split("@", 1)[1]
        if isinstance(data.get("projectId"), str):
            out["project"] = data["projectId"]
    elif provider == "azure":
        props = data.get("properties") if isinstance(data.get("properties"), dict) else data
        for key, name in (("userType", "user_type"), ("principalType", "principal_type"), ("servicePrincipalType", "principal_type")):
            if isinstance(data.get(key), str) or isinstance(props.get(key), str):
                out[name] = data.get(key) if isinstance(data.get(key), str) else props[key]
    elif provider == "k8s":
        meta = data.get("metadata")
        if isinstance(meta, dict) and isinstance(meta.get("namespace"), str):
            out["namespace"] = meta["namespace"]
    return out


def node(resource):
    data = resource["data"]
    meta = data.get("metadata", {})
    if not isinstance(meta, dict):
        meta = {}
    label = (data.get("UserName") or data.get("RoleName") or data.get("GroupName")
             or data.get("PolicyName") or data.get("name") or meta.get("name") or native_id(resource))
    resource_ref = resource.get("id", native_id(resource))
    value = {"id": node_id(resource), "resource_id": resource_ref,
            "native_id": native_id(resource), "label": str(label),
            "type": resource["type"], "native_kind": resource["type"],
            "provider_specific": {"native_kind": resource["type"]},
            "provider": resource["provider"], "scope": resource["scope"],
            # Report schema 1.1: a reference to report resources[].id (the native item lives once, in the
            # snapshot); peaso.engine.expand_report() inlines it as evidence.native_resource (schema 1.0).
            "evidence": {"native_resource_ref": resource_ref}, "risk_annotations": []}
    grouping = facets(resource)
    if grouping:
        value["facets"] = grouping
    return value


def relationship(source_id, target_id, kind, evidence, *, layer="structural", confidence="high"):
    path = evidence.get("source", evidence).get("path")
    return {"id": stable_id(source_id, target_id, kind, path), "source": source_id,
            "target": target_id, "type": kind, "layer": layer, "confidence": confidence,
            "evidence": _share(evidence)}


def usage(snapshot, resource):
    return derived(resource, "usage", lambda: _usage(snapshot, resource))


def _usage(snapshot, resource):
    data = resource["data"]
    observed = {k: _share(data[k]) for k in ("Usage", "usage", "LastUsed", "RoleLastUsed",
        "PasswordLastUsed", "AccessKeys", "activity", "signInActivity") if k in data}
    metadata = snapshot.get("metadata", {})
    window = metadata.get("usage_window", metadata.get("activity_window", metadata.get("coverageWindow")))
    completeness = metadata.get("usage_completeness", "unknown")
    detail = data.get("Usage", data.get("usage", {}))
    if isinstance(detail, dict):
        window = detail.get("window", window)
        completeness = detail.get("completeness", completeness)
    return {"observations": observed, "window": copy.deepcopy(window), "completeness": completeness,
            "provider_observation_context": {k: copy.deepcopy(metadata[k]) for k in
                ("usage_evidence", "activity", "activity_window", "activity_coverage", "directory_coverage", "logging_coverage") if k in metadata},
            "inactive_observation": isinstance(detail, dict) and detail.get("activity_count") == 0,
            "safe_to_remove": False,
            "uncertainty": "No observed activity is not evidence that access is unnecessary; telemetry can exclude data events, federation, other regions, or activity outside the window."}


# Google-managed service agents outside the gcp-sa-* naming convention, from
# https://docs.cloud.google.com/iam/docs/service-agents (service-PROJECT_NUMBER@<name>.iam.gserviceaccount.com).
GCP_SERVICE_AGENT_DOMAINS = frozenset((
    "bigquery-encryption", "cloud-filer", "cloud-memcache-sa", "cloud-ml", "cloud-redis", "cloud-tpu",
    "cloudcomposer-accounts", "compute-system", "container-analysis", "container-engine-robot", "containerregistry",
    "dataflow-service-producer-prod", "dataproc-accounts", "dlp-api", "firebase-rules", "gae-api-prod",
    "gcf-admin-robot", "gcp-gae-service", "gcp-ri-aiplatform", "gcp-ri-contactcenterinsights", "gcp-ri-identitypool",
    "gs-project-accounts", "remotebuildexecution", "security-center-api", "serverless-robot-prod",
    "service-consumer-management", "service-networking", "storage-transfer-service"))


def gcp_member(text):
    """Split an IAM member into (type, identifier), dropping the deleted:
    prefix and ?uid= suffix that IAM adds to bindings of deleted principals."""
    text = str(text)
    if text.startswith("deleted:"):
        text = text[len("deleted:"):]
    kind, _, value = text.partition(":") if ":" in text and not text.startswith(("principal://", "principalSet://")) else ("", "", text)
    value = value.split("?uid=", 1)[0]
    return kind, value.lower() if "@" in value else value


def principal_scope(provider, principal):
    import re
    text = str(principal)
    if provider == "aws":
        match = re.search(r"(?:^|:)\d{12}(?=:|$)", text)
        return match.group().strip(":") if match else None
    if provider == "gcp":
        kind, value = gcp_member(text)
        # Basic-role convenience members name their project directly.
        if kind in ("projectOwner", "projectEditor", "projectViewer"):
            return value or None
        # Google service agents are named after the consumer project number:
        # service-NUMBER@<agent>.iam.gserviceaccount.com (documented agents).
        match = re.fullmatch(r"service-([0-9]+)@([a-z0-9-]+)\.iam\.gserviceaccount\.com", value)
        if match and (match.group(2) in GCP_SERVICE_AGENT_DOMAINS or match.group(2).startswith("gcp-sa-")):
            return match.group(1)
        # App Engine standard service agent keeps its legacy dotted domain.
        match = re.fullmatch(r"service-([0-9]+)@gae-api-prod\.google\.com\.iam\.gserviceaccount\.com", value)
        if match:
            return match.group(1)
        # Agent identities live in the organization's agents trust domain.
        match = re.match(r"principal(?:Set)?://agents\.global\.org-([0-9]+)\.system\.id\.goog/", value)
        if match:
            return match.group(1)
        # Default Compute Engine and App Engine service accounts.
        match = re.fullmatch(r"([0-9]+)-compute@developer\.gserviceaccount\.com", value)
        if match:
            return match.group(1)
        match = re.fullmatch(r"([a-z][a-z0-9-]*)@appspot\.gserviceaccount\.com", value)
        if match:
            return match.group(1)
        match = re.search(r"@([^.@]+)\.iam\.gserviceaccount\.com$", value)
        return match.group(1) if match else None
    # An Azure object ID does not establish a tenant. A Kubernetes subject
    # belongs to a cluster, which cannot be inferred from its namespace.
    return None


def externality(snapshot, principal, *, tenant=None):
    """public / everyone_authenticated / allowlisted / external / provider_service / unknown.

    Default trust boundary: scanned accounts/projects/subscriptions/tenant and
    collected organisation members, plus the explicit trusted_scope_ids allowlist
    (see peaso.analysis.trust)."""
    from .trust import classify
    return classify(snapshot, principal, scope=tenant or principal_scope(snapshot["provider"], str(principal)))
