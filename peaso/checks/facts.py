"""Strict, offline accessors. An absent fact is never a safe configuration."""
from __future__ import annotations


class Unavailable(ValueError):
    pass


FIELD_SPECS = {}


def guard(item):
    if not isinstance(item, dict):
        raise Unavailable("native resource is not an object")
    if "collection_status" in item and item["collection_status"] not in ("collected", "empty"):
        raise Unavailable("resource detail unavailable: " + str(item["collection_status"]))
    if "_coverage" in item and not isinstance(item["_coverage"], dict):
        raise Unavailable("malformed resource fact coverage")
    coverage = item.get("_coverage", {})
    if "collection_status" in coverage:
        marker = coverage["collection_status"]
        if not isinstance(marker, dict) or marker.get("status") not in ("collected", "empty"):
            raise Unavailable("resource collection status evidence unavailable")
        # Empty coverage can attest an omitted marker, but cannot authenticate
        # a retained status string. Collected coverage requires the marker.
        if ("collection_status" in item) != (marker["status"] == "collected"):
            raise Unavailable("resource collection status evidence contradictory")


def get(item, path, expected=None):
    guard(item)
    value = item
    parts = path.split(".")
    for position, part in enumerate(parts):
        if not isinstance(value, dict):
            raise Unavailable("malformed parent of " + path)
        guard(value)
        coverage_entries = value.get("_coverage", {})
        coverage = coverage_entries.get(part)
        if part in coverage_entries and (not isinstance(coverage, dict) or coverage.get("status") not in ("collected", "empty")):
            raise Unavailable("fact unavailable or malformed coverage: " + path)
        if part not in value:
            # ARM omits some properties that hold a documented default.
            from .azure_platform_defaults import lookup
            found, selected = lookup(item, ".".join(parts[:position + 1]))
            if not found:
                found, selected = lookup(item, path)
                if not found:
                    raise Unavailable("missing fact: " + path)
                value = selected
                break
            value = selected
            continue
        selected = value[part]
        if selected is None and position == len(parts) - 1:
            from .azure_platform_defaults import lookup
            found, default = lookup(item, path, null=True)
            if found:
                value = default
                break
        if coverage is not None and coverage["status"] == "empty" and not (
            selected is None or selected == "" or selected == [] or selected == {}
        ):
            raise Unavailable("empty coverage contradicts selected fact: " + path)
        value = selected
    if isinstance(value, dict):
        guard(value)
    if expected is not None and (type(value) is not expected if expected in (bool, int) else not isinstance(value, expected)):
        raise Unavailable("malformed fact: " + path)
    return value


def field_check(check_id, provider, kind, path, good, bad, title, *, category="hardening", severity="medium", control="CM-6", expected=bool):
    """Register a strict scalar/list predicate and its independently specified fixture."""
    from . import register, result, unknown
    from .fixtures import CASES, nest
    FIELD_SPECS[check_id] = {"path": path, "good": good, "bad": bad, "expected": expected}
    @register(check_id, provider, category, kind, title, severity, control, "Review the collected setting and configure " + path + " according to the intended security policy.")
    def evaluate(item, index):
        value = get(item, path, expected)
        # Unknown enum variants are not failures or passes.
        if expected is str and value not in set(good if isinstance(good, tuple) else (good,)) | {bad}:
            return unknown("unrecognized setting", field=path, configured=value)
        return result(value not in good if isinstance(good, tuple) else value != good, field=path, configured=value)
    evaluate.__name__ = check_id.replace(".", "_")
    CASES[check_id] = {"pass": nest(path, good[0] if isinstance(good, tuple) else good), "fail": nest(path, bad), "missing": {}, "malformed": nest(path, {"unexpected": True})}


def list_of_objects(value):
    if not isinstance(value, list) or any(not isinstance(x, dict) for x in value):
        raise Unavailable("expected a list of native objects")
    return value


class MemoIndex(dict):
    """The engine's read-only scoped evaluation index, plus a memo of joins derived from it.

    Every check of one evaluation shares the same scoped index, so dependency inventories and
    lookup maps derived from it (complete_items, security-group/ENI joins) are computed once
    per index instead of once per evaluated resource. Ordinary dict indexes (tests, ad-hoc
    callers) are never memoized; the derived values are identical either way."""
    __slots__ = ("memo",)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.memo = {}


def memoized(index, key, compute):
    """compute() once per MemoIndex and key; an Unavailable outcome is replayed as the same error."""
    if type(index) is not MemoIndex:
        return compute()
    hit = index.memo.get(key)
    if hit is None:
        try:
            hit = (True, compute())
        except Unavailable as exc:
            hit = (False, (type(exc), exc.args))
        index.memo[key] = hit
    if not hit[0]:
        kind, args = hit[1]
        raise kind(*args)
    return hit[1]


def complete_items(index, kind):
    """Require complete scoped dependency inventory before absence/cardinality."""
    if type(index) is MemoIndex:
        # A fresh list per call: callers own the returned list (the native items are shared read-only views).
        return list(memoized(index, ("complete_items", kind), lambda: _complete_items(index, kind)))
    return _complete_items(index, kind)


def _complete_items(index, kind):
    envelopes = index.get("collections", {}).get(kind, [])
    if not isinstance(envelopes, list) or not envelopes:
        raise Unavailable("dependency not collected: " + kind)
    if any(not isinstance(row, dict) or row.get("status") not in ("collected", "empty") for row in envelopes):
        raise Unavailable("dependency incomplete or unavailable: " + kind)
    resources = list_of_objects(index.get(kind, []))
    return [get(resource, "data", dict) for resource in resources]


def optional(item, key, default, expected=None):
    """A documented API omission default, while explicit unreadability stays unknown."""
    guard(item)
    if key in item or key in item.get("_coverage", {}):
        return get(item, key, expected)
    return default


def full_representation(item):
    """True only when the collector marked the item as the API's complete
    resource representation (no field mask or partial projection)."""
    guard(item)
    provenance = item.get("_provenance")
    return isinstance(provenance, dict) and provenance.get("representation") == "full"


def omitted(item, path, default, expected=None):
    """Read `path`; an absent field is `default` only on a full representation.

    For APIs that document "omitted when unset" (proto3 JSON). Any explicit
    non-collected coverage, malformed parent or partial projection stays
    Unavailable, so a missing field from a field-masked read remains UNKNOWN.
    """
    complete = full_representation(item)
    value = item
    for part in path.split("."):
        if not isinstance(value, dict):
            raise Unavailable("malformed parent of " + path)
        guard(value)
        coverage_entries = value.get("_coverage", {})
        coverage = coverage_entries.get(part)
        if part in coverage_entries and (not isinstance(coverage, dict) or coverage.get("status") not in ("collected", "empty")):
            raise Unavailable("fact unavailable or malformed coverage: " + path)
        if part not in value:
            if coverage is not None and coverage["status"] == "collected":
                raise Unavailable("collected fact missing from representation: " + path)
            if complete:
                return default
            raise Unavailable("missing fact (partial representation): " + path)
        selected = value[part]
        if coverage is not None and coverage["status"] == "empty" and not (
            selected is None or selected == "" or selected == [] or selected == {}
        ):
            raise Unavailable("empty coverage contradicts selected fact: " + path)
        value = selected
    if isinstance(value, dict):
        guard(value)
    if expected is not None and (type(value) is not expected if expected in (bool, int) else not isinstance(value, expected)):
        raise Unavailable("malformed fact: " + path)
    return value


PRINCIPAL_TRUST_FIELDS = (("user", "trusted_users"), ("group", "trusted_groups"), ("domain", "trusted_domains"),
                          ("serviceAccount", "trusted_service_accounts"))
PUBLIC_PRINCIPALS = ("allUsers", "allAuthenticatedUsers")


def principal_trust_lists(metadata):
    """Operator principal trust lists by member prefix, or None when none was configured.

    The collector records an unset list as null and trusted_domains as [] with
    trusted_domains_explicit=false, so "no configuration" is distinguishable
    from an explicitly empty list. Once any list is configured, unset ones are empty."""
    from collections.abc import Mapping
    if not isinstance(metadata, Mapping):
        raise Unavailable("malformed principal trust policy")
    configured = any(metadata.get(field) is not None for prefix, field in PRINCIPAL_TRUST_FIELDS if field != "trusted_domains")
    configured = configured or metadata.get("trusted_domains_explicit") is True or (
        "trusted_domains_explicit" not in metadata and metadata.get("trusted_domains") is not None)
    if not configured:
        return None
    approved = {}
    for prefix, field in PRINCIPAL_TRUST_FIELDS:
        values = metadata.get(field)
        values = [] if values is None else values
        if not isinstance(values, (list, tuple)) or any(not isinstance(value, str) for value in values):
            raise Unavailable("malformed principal trust policy")
        approved[prefix] = set(values)
    return approved


def unique_join(index, kind, path, value):
    """A complete, exact native-key join. Missing/ambiguous relationships are unknown."""
    rows = [row for row in complete_items(index, kind) if get(row, path) == value]
    if len(rows) != 1:
        raise Unavailable("dependency join missing or ambiguous: " + kind + "." + path)
    return rows[0]


# Reviewed collector fields only: no arbitrary path/URL/file or recursive $ref resolver.
EMBEDDED_FIELDS = {
    "diagnosticSettings": (None, "list"),
    "flowLogs": (("network_watcher",), "list"),
    "backupProtectedItems": (("recovery_vault",), "list"),
    "backupPolicies": (("recovery_vault",), "list"),
    "blobContainers": (("storage_account",), "list"),
    "encryptionScopes": (("storage_account",), "list"),
    "backupLongTermRetentionPolicies": (("sql_database",), "list"),
    "keyVaultKeys": (("vault",), "list"),
    "vulnerabilityAssessment": (("sql_server",), "singleton"),
    "encryptionProtector": (("sql_server",), "singleton"),
    "properties.rotationPolicy": (("key_metadata", "key_vault_key"), "singleton"),
}


def resolve_embedded_fact(item, parents, *, child_status="collected"):
    """Materialize an approved child metadata reference from one canonical parent.

    Caller must provide authorized same-snapshot parent wrappers. No network or
    mutation occurs; missing/partial identity or coverage cannot yield a fact.
    """
    guard(item)
    if "_embedded_ref" not in item:
        return item
    if child_status != "collected":
        raise Unavailable("referenced child inventory incomplete or unavailable")
    ref = get(item, "_embedded_ref", dict)
    parent_id, field = get(ref, "parent_id", str), get(ref, "field", str)
    if get(item, "parent_id", str).casefold() != parent_id.casefold():
        raise Unavailable("embedded reference parent identity mismatch")
    if field not in EMBEDDED_FIELDS:
        raise Unavailable("unreviewed embedded metadata path")
    candidates = [parent for parent in parents if isinstance(parent, dict) and isinstance(parent.get("native_id"), str) and parent["native_id"].casefold() == parent_id.casefold()]
    if len(candidates) != 1:
        raise Unavailable("referenced parent missing or ambiguous")
    parent = candidates[0]
    allowed, shape = EMBEDDED_FIELDS[field]
    if parent.get("provider") != "azure" or allowed is not None and parent.get("type") not in allowed:
        raise Unavailable("embedded reference parent provider/type mismatch")
    data = get(parent, "data", dict)
    value = get(data, field, list if shape == "list" else dict)
    if shape == "list":
        index = get(ref, "index", int)
        if index < 0 or index >= len(value):
            raise Unavailable("embedded reference index out of range")
        value = value[index]
        if not isinstance(value, dict):
            raise Unavailable("embedded child is not native metadata object")
        guard(value)
    elif ref.get("index") is not None:
        raise Unavailable("singleton embedded reference requires index=null")
    child_id = get(item, "id", str)
    provenance = optional(value, "_provenance", {}, dict)
    actual_id = value.get("id") or value.get("kid") or provenance.get("native_id")
    if not isinstance(actual_id, str) or actual_id.casefold() != child_id.casefold():
        raise Unavailable("embedded child native identity missing or mismatched")
    from copy import deepcopy
    return deepcopy(value)


def azure_directory_join_authorized(scope, metadata, collection):
    """Directory visibility requires verified tenant AND capture/customer context."""
    if not isinstance(scope, str) or not scope.lower().startswith("/subscriptions/"):
        return False
    if not isinstance(metadata, dict) or metadata.get("tenant_verified") is not True:
        return False
    tenant = metadata.get("tenant_id")
    capture = metadata.get("credential_context_id")
    customer = metadata.get("customer_context_id")
    if not all(isinstance(value, str) and value for value in (tenant, capture, customer)):
        return False
    subscriptions = metadata.get("subscription_tenants", {})
    subscribed_tenant = subscriptions.get(scope) if isinstance(subscriptions, dict) else None
    if not isinstance(subscribed_tenant, str) or subscribed_tenant.casefold() != tenant.casefold():
        return False
    if not isinstance(collection, dict) or collection.get("service") != "Microsoft.Graph":
        return False
    proof = collection.get("_provenance", {})
    if not isinstance(proof, dict) or proof.get("tenant_verified") is not True:
        return False
    if any(proof.get(key) != metadata[key] for key in ("credential_context_id", "customer_context_id")):
        return False
    if not isinstance(proof.get("tenant_id"), str) or proof["tenant_id"].casefold() != tenant.casefold():
        return False
    tenant_scope = "/tenants/" + tenant.casefold()
    actual_scope = str(collection.get("scope", "")).casefold()
    if actual_scope != tenant_scope and not actual_scope.startswith(tenant_scope + "/"):
        return False
    items = collection.get("items", [])
    if not isinstance(items, list):
        return False
    for item in items:
        identity = item.get("_provenance", {}) if isinstance(item, dict) else {}
        if not isinstance(identity, dict) or identity.get("tenant_verified") is not True or not isinstance(identity.get("tenant_id"), str) or identity["tenant_id"].casefold() != tenant.casefold():
            return False
    return True
