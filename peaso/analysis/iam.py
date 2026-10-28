"""Declared IAM facts and conditional risk review; never an access simulator."""
from __future__ import annotations

import json
import re
from collections import defaultdict
import hashlib
from fnmatch import fnmatchcase
from functools import lru_cache
from heapq import nsmallest
from urllib.parse import unquote
from threading import Lock

from .common import (RANK, _CONTEXT, as_list, derived, externality, finding, native_id, node, node_id,
                     relationship, source, stable_id, usage)
from peaso.snapshot import FrozenDict, FrozenList, freeze

IAM_TYPES = {"iam_user", "iam_group", "iam_role", "iam_policy", "iam_binding", "service_account",
             "iam_role_definition", "directory_user", "directory_group", "directory_service_principal", "directory_application",
             "directory_role_assignment", "directory_role_definition", "directory_membership", "deny_assignment", "iam_deny_policy",
             "role_assignment", "role_definition", "principal", "user", "group", "service_principal",
             "role", "clusterrole", "rolebinding", "clusterrolebinding", "serviceaccount"}


def document(value):
    if isinstance(value, str):
        try:
            value = json.loads(unquote(value))
        except (ValueError, TypeError):
            return None
    return value if isinstance(value, dict) and isinstance(value.get("Statement"), (dict, list)) else None


_DEFAULT_DOCUMENT = document
POLICY_VIEW_LIMIT = 256
POLICY_VIEW_BYTES = 4 * 1024 * 1024
POLICY_VIEW_MISS_LIMIT = 64


def _sealed_policy_document(value):
    """Share identical encoded policy trees only inside one analysis context.

    Parsed facts are sealed before sharing. Public/mutable parsers still return
    independent trees, and exhausted admission falls back to ordinary decoding.
    The byte charge conservatively allows for decoded Python container overhead.
    """
    if type(value) is not str:
        parsed = document(value)
        return parsed if parsed is None or type(parsed) is FrozenDict else _decoded_policy_view(parsed)
    context = _CONTEXT.get()
    eligible = (context is not None and document is _DEFAULT_DOCUMENT
                and 256 <= len(value) <= 32768)
    cache = None
    if eligible:
        cache = context['derivations'].get(('snapshot', 'iam_encoded_policy_views'))
        if cache is None:
            cache = context['derivations'][('snapshot', 'iam_encoded_policy_views')] = {
                'entries': {}, 'bytes': 0, 'lock': Lock(), 'misses': 0, 'enabled': True}
        if not cache['enabled']:
            cache = None
        else:
            cached = cache['entries'].get(value)
            if cached is not None:
                cache['misses'] = 0
                return cached
    parsed = document(value)
    result = parsed if parsed is None or type(parsed) is FrozenDict else _decoded_policy_view(parsed)
    if cache is not None and type(result) is FrozenDict:
        charge = 512 + 128 * len(value)
        with cache['lock']:
            if not cache['enabled']:
                return result
            if value in cache['entries']:
                return cache['entries'][value]
            cache['misses'] += 1
            if cache['misses'] >= POLICY_VIEW_MISS_LIMIT:
                # Unique-policy scans should not keep hashing large strings or
                # paying admission costs after reuse has stopped being useful.
                cache['enabled'] = False
                cache['entries'].clear()
                cache['bytes'] = 0
                return result
            if len(cache['entries']) < POLICY_VIEW_LIMIT and cache['bytes'] + charge <= POLICY_VIEW_BYTES:
                cache['entries'][value] = result
                cache['bytes'] += charge
    return result


def policy_documents(data, *, _parse=None):
    parse = document if _parse is None else _parse
    # DomainStatus.AccessPolicies (OpenSearch describe_domain), Policy.policy.document (CodeArtifact),
    # Identity.Policies {name: document} (SES v2 get_email_identity), policyDocument (Logs resource policy).
    wrappers = {"Policy", "policy", "Attributes", "Domain", "Table", "PolicyDetails", "ResourcePolicy", "AccessPolicy", "AccessPolicies", "policyText",
                "DomainStatus", "Identity", "document", "policyDocument"}
    def nested(value, path, depth):
        if depth > 4 or not isinstance(value, dict):
            return
        for key, current in value.items():
            if key == "Policies" and isinstance(current, dict):
                for name, entry in sorted(current.items()):
                    doc = parse(entry)
                    if doc is not None:
                        yield f"{path}.Policies.{name}", doc
                continue
            if key not in wrappers:
                continue
            doc = parse(current)
            if doc is not None:
                yield f"{path}.{key}", doc
            else:
                yield from nested(current, f"{path}.{key}", depth + 1)
    for key in ("PolicyDocument", "Document", "Policy", "policy", "AssumeRolePolicyDocument"):
        doc = parse(data.get(key))
        if doc is not None:
            yield key, doc
    for key in wrappers:
        value = data.get(key)
        doc = parse(value)
        if doc is None:
            yield from nested(value, key, 0)
        elif key not in {"Policy", "policy"}:
            yield key, doc
    for key in ("UserPolicyList", "GroupPolicyList", "RolePolicyList", "PolicyVersionList", "PolicySources"):
        for i, item in enumerate(as_list(data.get(key))):
            if not isinstance(item, dict):
                continue
            if key == "PolicyVersionList" and item.get("IsDefaultVersion") is not True:
                continue
            doc = parse(item.get("PolicyDocument", item.get("Document", item.get("document"))))
            if doc is not None:
                yield f"{key}[{i}]", doc


_DEFAULT_POLICY_DOCUMENTS = policy_documents
_DEFAULT_SEALED_POLICY_DOCUMENT = _sealed_policy_document
# Exhaustive root fields visited by the policy parser above. Policy-free native
# records do not need a node identifier or an empty per-record cache entry.
_POLICY_SURFACE_KEYS = frozenset({
    'PolicyDocument', 'Document', 'Policy', 'policy', 'AssumeRolePolicyDocument',
    'Attributes', 'Domain', 'Table', 'PolicyDetails', 'ResourcePolicy',
    'AccessPolicy', 'AccessPolicies', 'policyText', 'DomainStatus', 'Identity',
    'document', 'policyDocument', 'UserPolicyList', 'GroupPolicyList',
    'RolePolicyList', 'PolicyVersionList', 'PolicySources',
})


def _decoded_policy_view(doc):
    try:
        return freeze(doc)
    except RecursionError:
        # A decoder can accept more nesting than Python's recursive view
        # conversion. Keep the original complete tree when reuse is unavailable.
        return doc


def _resource_policy_documents(resource):
    data = resource['data']
    if (policy_documents is _DEFAULT_POLICY_DOCUMENTS and document is _DEFAULT_DOCUMENT
            and _sealed_policy_document is _DEFAULT_SEALED_POLICY_DOCUMENT
            and type(data) in (dict, FrozenDict) and _POLICY_SURFACE_KEYS.isdisjoint(data)):
        return ()
    def documents():
        if _CONTEXT.get() is not None and type(resource["data"]) is FrozenDict:
            # Encoded native policies decode into mutable trees. Seal those
            # views once so reviews and graph evidence can share statements.
            if policy_documents is _DEFAULT_POLICY_DOCUMENTS:
                result = tuple(policy_documents(resource["data"], _parse=_sealed_policy_document))
            else:
                result = tuple((path, doc if type(doc) is FrozenDict else _decoded_policy_view(doc))
                               for path, doc in policy_documents(resource["data"]))
            if type(resource['data'].get('AssumeRolePolicyDocument')) is str:
                # Wrappers can be replaced while a context is alive. Trust
                # consumers may share only the exact source decoded here.
                _CONTEXT.get()['derivations'][('iam_policy_documents_source', node_id(resource))] = resource['data']
            return result
        return tuple(policy_documents(resource["data"]))
    return derived(resource, "iam_policy_documents", documents)


def assume_role_document(resource):
    """Reuse an already decoded native trust policy without eagerly parsing other fields."""
    value = resource['data'].get('AssumeRolePolicyDocument')
    if type(value) is not str or type(resource['data']) is not FrozenDict:
        return document(value)
    context = _CONTEXT.get()
    if context is not None:
        identity = node_id(resource)
        cache = context['derivations']
        documents = (cache.get(('iam_policy_documents', identity))
                     if cache.get(('iam_policy_documents_source', identity)) is resource['data'] else None)
        if documents is not None:
            for path, doc in documents:
                if path == 'AssumeRolePolicyDocument':
                    # Mutable or unusually deep decoded trees keep the public
                    # parser's independent ownership and failure behavior.
                    if type(doc) is FrozenDict:
                        return doc
                    break
    return document(value)


@lru_cache(maxsize=4)
def _rulepack_revision(provider):
    if provider not in {"aws", "gcp", "azure"}:
        return None
    try:
        from scripts.cloud_permission_risks import _bundled_rules_path
        # The shared resolver chooses source-checkout or installed package data.
        # Guard the actual file before invoking the classifier's loader.
        path = _bundled_rules_path(provider)
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except (ImportError, OSError, ValueError):
        return None


def permission_severity(provider, permission):
    revision = _rulepack_revision(provider)
    return _permission_severity(provider, permission, revision) if revision else None


_DEFAULT_PERMISSION_SEVERITY = permission_severity
ACTION_PROFILE_LIMIT = 1024
ACTION_PROFILE_BYTES = 2 * 1024 * 1024


def _permission_profile_uncached(provider, permissions, *, force_broad=False):
    levels = [permission_severity(provider, p) for p in permissions if isinstance(p, str)]
    broad = any("*" in p for p in permissions if isinstance(p, str)) or force_broad
    severity = "high" if broad else min((x for x in levels if x), key=RANK.get, default="info")
    state = "unknown" if not levels or all(x is None for x in levels) else "partial" if any(x is None for x in levels) else "rule_based"
    return broad, severity, state


def _permission_profile(provider, permissions, *, force_broad=False):
    """Reuse action classification only; no resources, conditions or grants are cached.

    Admission is bounded and scan-local. Unusual inputs, caller classifiers and
    exhausted budgets use the complete original computation.
    """
    context = _CONTEXT.get()
    if (context is None or permission_severity is not _DEFAULT_PERMISSION_SEVERITY
            or type(permissions) not in (list, FrozenList) or not 8 <= len(permissions) <= 128):
        return _permission_profile_uncached(provider, permissions, force_broad=force_broad)
    signature = tuple(permissions)
    if any(type(p) is not str for p in signature):
        return _permission_profile_uncached(provider, permissions, force_broad=force_broad)
    cache = context['derivations'].get(('snapshot', 'iam_action_profiles'))
    if cache is None:
        cache = context['derivations'][('snapshot', 'iam_action_profiles')] = {'entries': {}, 'bytes': 0, 'lock': Lock()}
    # Bind the summary to the same audited revision as the per-action cache.
    key = provider, _permission_severity, _rulepack_revision(provider), force_broad, signature
    cached = cache['entries'].get(key)
    if cached is not None:
        return cached
    result = _permission_profile_uncached(provider, permissions, force_broad=force_broad)
    if len(cache['entries']) < ACTION_PROFILE_LIMIT and all(len(p) <= 256 for p in signature):
        size = 320 + len(signature) * 16 + sum(len(p) * 4 for p in signature)
        with cache['lock']:
            if key not in cache['entries'] and len(cache['entries']) < ACTION_PROFILE_LIMIT and cache['bytes'] + size <= ACTION_PROFILE_BYTES:
                cache['entries'][key] = result
                cache['bytes'] += size
    return result


@lru_cache(maxsize=16384)
def _permission_severity(provider, permission, revision):
    """Reuse the audited standalone classifier, with no multi-grant combinations.

    Guard bundled data before import so its optional remote fallback is unreachable.
    Missing installations produce unknown, never an invented low severity.
    """
    try:
        from scripts.cloud_permission_risks import classify_permission
        low = classify_permission(provider, permission, unknown_default="low", offline=True)
        high = classify_permission(provider, permission, unknown_default="high", offline=True)
        # The shared API exposes fallback uncertainty through its default.
        # If only changing the fallback changes the classification, no rule
        # recognized this permission and low must not be asserted.
        return low if low == high else None
    except (ImportError, OSError, ValueError):
        return None


def grants(resource):
    return derived(resource, "grants", lambda: _grants(resource))


def _grants(resource):
    """Retain native constraints, not effective permission/target combinations."""
    data, provider = resource["data"], resource["provider"]
    result = []
    if provider == "aws":
        for path, doc in _resource_policy_documents(resource):
            if path == "AssumeRolePolicyDocument":
                continue
            for i, statement in enumerate(as_list(doc.get("Statement"))):
                if not isinstance(statement, dict):
                    continue
                permissions = as_list(statement.get("Action"))
                if type(permissions) in (list, FrozenList) and len(permissions) < 8:
                    # Short declarations cost less to classify directly than to
                    # admit into a shared profile; retain their original path.
                    levels = [permission_severity(provider, p) for p in permissions if isinstance(p, str)]
                    broad = any("*" in p for p in permissions if isinstance(p, str)) or "NotAction" in statement
                    severity = "high" if broad else min((x for x in levels if x), key=RANK.get, default="info")
                    state = "unknown" if not levels or all(x is None for x in levels) else "partial" if any(x is None for x in levels) else "rule_based"
                else:
                    broad, severity, state = _permission_profile(provider, permissions, force_broad="NotAction" in statement)
                result.append({"path": f"{path}.Statement[{i}]", "native_grant": statement,
                    "severity": "high" if broad else severity,
                    "criticality_state": state,
                    "broad": broad, "allowed_declaration": statement.get("Effect") == "Allow",
                    "conditional": bool(statement.get("Condition")), "effective_access": "unknown"})
    elif provider == "gcp":
        policy = data.get("policy", data.get("iamPolicy", data))
        if not isinstance(policy, dict):
            return []
        for i, binding in enumerate(as_list(policy.get("bindings"))):
            if not isinstance(binding, dict):
                continue
            role = binding.get("role", "")
            broad = role in {"roles/owner", "roles/editor"}
            result.append({"path": f"bindings[{i}]", "native_grant": binding,
                "severity": "high" if broad else "info", "broad": broad,
                "allowed_declaration": True, "conditional": bool(binding.get("condition")),
                "effective_access": "unknown", "permission_definition": "not inferred from role name"})
        for i, permission in enumerate(as_list(data.get("includedPermissions"))):
            level = permission_severity(provider, permission)
            result.append({"path": f"includedPermissions[{i}]", "native_grant": permission,
                "severity": level or "info", "broad": "*" in permission,
                "criticality_state": "rule_based" if level else "unknown",
                "allowed_declaration": True, "conditional": False, "effective_access": "unknown"})
    elif provider == "azure":
        props = data.get("properties", data)
        for i, permission in enumerate(as_list(props.get("permissions"))):
            if not isinstance(permission, dict):
                continue
            actions = as_list(permission.get("actions")) + as_list(permission.get("dataActions"))
            if type(actions) in (list, FrozenList) and len(actions) < 8:
                levels = [permission_severity(provider, p) for p in actions if isinstance(p, str)]
                broad = any("*" in p for p in actions if isinstance(p, str))
                severity = "high" if broad else min((x for x in levels if x), key=RANK.get, default="info")
                state = "unknown" if not levels or all(x is None for x in levels) else "partial" if any(x is None for x in levels) else "rule_based"
            else:
                broad, severity, state = _permission_profile(provider, actions)
            result.append({"path": f"properties.permissions[{i}]", "native_grant": permission,
                "severity": "high" if broad else severity,
                "criticality_state": state,
                "broad": broad, "allowed_declaration": True,
                "conditional": bool(permission.get("notActions") or permission.get("notDataActions")),
                "effective_access": "unknown"})
    elif provider == "k8s":
        for i, rule in enumerate(as_list(data.get("rules"))):
            if not isinstance(rule, dict):
                continue
            broad = any("*" in as_list(rule.get(k)) for k in ("verbs", "resources", "apiGroups", "nonResourceURLs"))
            levels = []
            try:
                from bluepeass.k8s_risks import PermissionKey, classify_permission
                # Resource and verb declarations are individually classified;
                # no graph expansion into escalation prerequisites or targets.
                # The classification is a pure function of the key and the canonical rules,
                # so equal keys are classified once per analysis context.
                context = _CONTEXT.get()
                memo = None if context is None else context["derivations"].setdefault(
                    ("snapshot", "k8s_permission_levels", classify_permission), {})
                for verb in as_list(rule.get("verbs")):
                    for group in as_list(rule.get("apiGroups", [""])):
                        for res in as_list(rule.get("resources")):
                            base, _, sub = res.partition("/")
                            key = PermissionKey(verb, group=group, resource=base,
                                subresource=sub, namespace=data.get("metadata", {}).get("namespace", ""))
                            try:
                                level = memo[key] if memo is not None else None
                            except (KeyError, TypeError):
                                level = None
                            if level is None:
                                level, _ = classify_permission(key)
                                if memo is not None:
                                    try:
                                        memo[key] = level
                                    except TypeError:
                                        pass
                            levels.append(level)
            except (ImportError, OSError, ValueError):
                pass
            result.append({"path": f"rules[{i}]", "native_grant": rule,
                "severity": "high" if broad else min(levels, key=RANK.get, default="info"),
                "broad": broad, "allowed_declaration": True,
                "conditional": bool(rule.get("resourceNames")), "effective_access": "unknown"})
    return result


def principals(resource):
    yield from derived(resource, "iam_principals", lambda: tuple(_principals(resource)))


def _principals(resource):
    data = resource["data"]
    if resource["provider"] == "azure" and resource["type"] == "managed_hsm":
        for index, assignment in enumerate(as_list(data.get("localRoleAssignments"))):
            props = assignment.get("properties") if isinstance(assignment, dict) else None
            principal = props.get("principalId") if isinstance(props, dict) else None
            if isinstance(principal, str) and principal:
                yield principal, f"localRoleAssignments[{index}].properties.principalId", {
                    **props, "hsmLocalRbac": True, "roleAssignmentId": assignment.get("id"),
                    "coverage": (data.get("_coverage") or {}).get("localRoleAssignments")}, "HsmLocalRoleAssignment"
    if resource["provider"] == "k8s":
        if resource["type"] in {"kcc_iampolicy", "kcc_iampartialpolicy"}:
            spec, status = data.get("spec") or {}, data.get("status") or {}
            meta = data.get("metadata") or {}
            generation = meta.get("generation")
            observed = isinstance(generation, int) and not isinstance(generation, bool) and \
                status.get("observedGeneration") == generation and isinstance(status.get("allBindings"), list)
            bindings = status["allBindings"] if observed else spec.get("bindings") or []
            base = "status.allBindings" if observed else "spec.bindings"
            for i, binding in enumerate(as_list(bindings)):
                if not isinstance(binding, dict):
                    continue
                for j, member in enumerate(as_list(binding.get("members"))):
                    identity = member.get("member") if isinstance(member, dict) else member
                    if isinstance(identity, str):
                        yield identity, f"{base}[{i}].members[{j}]", binding, "member"
        if resource["type"] == "securitycontextconstraint":
            for field in ("users", "groups"):
                for i, identity in enumerate(as_list(data.get(field))):
                    if isinstance(identity, str):
                        yield identity, f"{field}[{i}]", data, "subject"
    for path, doc in _resource_policy_documents(resource):
        for i, statement in enumerate(as_list(doc.get("Statement"))):
            if not isinstance(statement, dict) or statement.get("Effect") != "Allow":
                continue
            principal = statement.get("Principal", {})
            if isinstance(principal, dict):
                values = [(kind, value) for kind, value in principal.items()]
            else:
                values = [("principal", principal)]
            for kind, value in values:
                for identity in as_list(value):
                    if isinstance(identity, str):
                        yield identity, f"{path}.Statement[{i}].Principal", statement, kind
    policy = data.get("policy", data.get("iamPolicy", data))
    for i, binding in enumerate(as_list(policy.get("bindings")) if isinstance(policy, dict) else []):
        if isinstance(binding, dict):
            for member in as_list(binding.get("members")):
                if isinstance(member, str):
                    yield member, f"bindings[{i}].members", binding, "member"
    if resource["provider"] == "gcp" and resource["type"] == "bigquery_dataset":
        # Dataset ACLs predate IAM and are returned by datasets.get as access[].
        # They can grant public or third-party read without an IAM binding.
        fields = {"userByEmail": "user", "groupByEmail": "group", "domain": "domain",
                  "iamMember": None, "specialGroup": None}
        for i, access in enumerate(as_list(data.get("access"))):
            if not isinstance(access, dict):
                continue
            for field, prefix in fields.items():
                value = access.get(field)
                if field == "specialGroup" and value not in {"allUsers", "allAuthenticatedUsers"}:
                    continue
                if isinstance(value, str) and value:
                    identity = f"{prefix}:{value}" if prefix else value
                    yield identity, f"access[{i}].{field}", access, "member"
    if resource["provider"] == "gcp" and resource["type"] == "bucket" and (
            (data.get("iamConfiguration") or {}).get("uniformBucketLevelAccess") or {}).get("enabled") is False:
        for field in ("bucketAccessControls", "objectAccessControls"):
            envelope = data.get(field)
            if not isinstance(envelope, dict) or envelope.get("status") != "collected" or envelope.get("all_pages") is not True:
                continue
            if field == "objectAccessControls" and (envelope.get("all_objects") is not True or envelope.get("all_versions") is not True):
                continue
            for i, acl in enumerate(as_list(envelope.get("items"))):
                if not isinstance(acl, dict) or acl.get("role") not in {"READER", "OWNER", "WRITER"}:
                    continue
                entity = acl.get("entity")
                if not isinstance(entity, str):
                    continue
                identity = entity
                for tag in ("user", "group", "domain"):
                    if entity.startswith(tag + "-"):
                        identity = tag + ":" + entity[len(tag) + 1:]
                        break
                yield identity, f"{field}.items[{i}].entity", acl, "member"
    for i, subject in enumerate(as_list(data.get("subjects"))):
        if isinstance(subject, dict):
            name = subject.get("name", "")
            identity = f"system:serviceaccount:{subject.get('namespace', data.get('metadata', {}).get('namespace', 'default'))}:{name}" if subject.get("kind") == "ServiceAccount" else name
            yield identity, f"subjects[{i}]", subject, subject.get("kind", "subject")
    props = data.get("properties", data)
    if resource["provider"] == "azure" and props.get("principalId"):
        yield props["principalId"], "properties.principalId", props, props.get("principalType", "principal")


def _azure_role_guid(value):
    text = str(value or "").rstrip("/")
    return text.rsplit("/", 1)[-1].lower()


def _azure_definition_only(resource):
    # Azure role definitions are reviewed through the assignments that grant them
    # (azure_assignment_reviews); an unassigned definition grants nothing.
    return resource["provider"] == "azure" and resource["type"] == "role_definition"


def azure_assignment_reviews(snapshot, resources):
    """Azure grant review per actual assignment of a high-impact role definition.

    The definition is resolved by role GUID (built-ins are collected once at "/",
    custom roles per assignable scope). The same assignment is listed at every
    scope that inherits it, so findings are deduplicated by (principal, role, scope).
    Assignments whose definition was not collected produce no grant claim.
    """
    if snapshot.get("provider") != "azure":
        return []
    definitions = {}
    for resource in resources:
        if resource["type"] == "role_definition":
            definitions.setdefault(_azure_role_guid(resource["data"].get("name") or native_id(resource)), resource)
    output, seen = [], set()
    for resource in resources:
        if resource["type"] != "role_assignment":
            continue
        props = resource["data"].get("properties", resource["data"])
        if not isinstance(props, dict) or not props.get("roleDefinitionId"):
            continue
        guid = _azure_role_guid(props["roleDefinitionId"])
        definition = definitions.get(guid)
        key = (str(props.get("principalId", "")).lower(), guid, str(props.get("scope") or resource["scope"]).lower())
        if definition is None or key in seen:
            continue
        declared = grants(definition)
        high = [g for g in declared if g["allowed_declaration"] and RANK[g["severity"]] <= RANK["high"]]
        uncertain = [g for g in declared if g.get("criticality_state") in {"unknown", "partial"} and not g["broad"] and g["allowed_declaration"]]
        if not high and not uncertain:
            continue
        seen.add(key)
        definition_props = definition["data"].get("properties", definition["data"])
        assignment = {"principalId": props.get("principalId"), "principalType": props.get("principalType"),
                      "scope": props.get("scope") or resource["scope"], "roleDefinitionId": props["roleDefinitionId"],
                      "roleName": definition_props.get("roleName") if isinstance(definition_props, dict) else None,
                      "roleType": definition_props.get("type") if isinstance(definition_props, dict) else None,
                      "condition": props.get("condition")}
        if high:
            severity = min((g["severity"] for g in high), key=RANK.get)
            evidence = {"source": source(snapshot, resource, "properties.roleDefinitionId"), "assignment": assignment,
                "role_definition_source": source(snapshot, definition, "properties.permissions"), "grants": high,
                "usage": usage(snapshot, resource), "risk_state": "conditional", "effective_access": "unknown",
                "missing_context": ["Deny assignments, assignment conditions, PIM activation state and owner-approved business need must be reviewed"],
                "restrictions": {k: v for k, v in (("condition", props.get("condition")),) if v},
                "criticality_source": "Bundled Blue-CloudPEASS standalone HackTricks permission criticality; combinations are not evaluated"}
            output.append(finding(snapshot, resource, "least_privilege", "analysis.grant_review",
                "Review high-impact or broad declared grants", severity, evidence))
        else:
            output.append(finding(snapshot, resource, "least_privilege", "analysis.coverage",
                "Permission criticality context incomplete", "info", {"source": source(snapshot, resource, "properties.roleDefinitionId"),
                    "assignment": assignment, "unclassified_grants": uncertain, "risk_state": "unknown", "reason": "permission_criticality_unknown"}, status="UNKNOWN"))
    return output


def _azure_external_group_members(snapshot, resources):
    """Resolve observed guest/foreign members of assigned Azure RBAC groups."""
    groups = {str(row["data"].get("id", "")).lower() for row in resources
              if row["type"] == "directory_group"}
    links = defaultdict(list)
    for row in resources:
        if row["type"] != "directory_membership" or "/groups/" not in row["scope"].lower():
            continue
        parent = row["scope"].lower().rsplit("/groups/", 1)[-1]
        member = row["data"].get("id")
        if isinstance(member, str) and member:
            links[parent].append((member.lower(), row))
    cache = {}

    def resolve(group_id):
        group_id = str(group_id).lower()
        if group_id not in cache:
            found, seen, pending = {}, set(), [(group_id, (group_id,))]
            while pending:
                current, path = pending.pop()
                if current in seen:
                    continue
                seen.add(current)
                for member, membership in links.get(current, ()):
                    if member in groups or member in links:
                        pending.append((member, (*path, member)))
                    elif externality(snapshot, member) == "external":
                        found.setdefault(member, (path, membership))
            cache[group_id] = found
        return cache[group_id]

    return resolve


def _azure_gallery_rbac_reviews(snapshot, resources, group_members):
    """Report declared image-version read grants to observed outside principals."""
    galleries = [str(native_id(row)).casefold() for row in resources if row["type"] == "compute_gallery"]
    if not galleries:
        return []
    definitions = {_azure_role_guid(row["data"].get("name") or native_id(row)): row
                   for row in resources if row["type"] == "role_definition"}
    action = "microsoft.compute/galleries/images/versions/read"
    output, seen = [], set()
    for assignment in resources:
        if assignment["type"] != "role_assignment":
            continue
        props = assignment["data"].get("properties") or {}
        scope = props.get("scope")
        principal = props.get("principalId")
        if not isinstance(scope, str) or not isinstance(principal, str):
            continue
        scope = scope.casefold().rstrip("/")
        targets = [gallery for gallery in galleries if gallery == scope or gallery.startswith(scope + "/")
                   or re.fullmatch(re.escape(gallery) + r"/images/[^/]+(?:/versions/[^/]+)?", scope)]
        if not targets:
            continue
        definition = definitions.get(_azure_role_guid(props.get("roleDefinitionId")))
        if definition is None:
            continue
        permissions = (definition["data"].get("properties") or {}).get("permissions") or []
        grants_read = any(isinstance(block, dict) and isinstance(block.get("actions"), list)
                          and isinstance(block.get("notActions", []), list)
                          and any(isinstance(pattern, str) and fnmatchcase(action, pattern.casefold())
                                  for pattern in block["actions"])
                          and not any(isinstance(pattern, str) and fnmatchcase(action, pattern.casefold())
                                      for pattern in block.get("notActions", []))
                          for block in permissions)
        if not grants_read:
            continue
        principals = [(principal, None, None)]
        if props.get("principalType") == "Group":
            principals.extend((member, path, membership)
                              for member, (path, membership) in group_members(principal).items())
        for identity, group_path, membership in principals:
            if externality(snapshot, identity) != "external":
                continue
            for gallery in targets:
                key = (str(native_id(assignment)).casefold(), gallery, identity.casefold())
                if key in seen:
                    continue
                seen.add(key)
                condition = props.get("condition")
                evidence = {"source": source(snapshot, assignment, "properties.roleDefinitionId"),
                    "role_definition_source": source(snapshot, definition, "properties.permissions"),
                    "gallery_id": gallery, "assignment_scope": scope, "principal_id": identity,
                    "via_group": principal if group_path else None, "group_path": group_path,
                    "membership_source": source(snapshot, membership, "id") if membership else None,
                    "role_definition_id": props.get("roleDefinitionId"), "action": action,
                    "condition": condition, "effective_access": "unknown",
                    "uncertainty": "Deny assignments, PIM activation, and runtime authorization may narrow declared access."}
                output.append(finding(snapshot, assignment, "exposure", "analysis.azure_gallery_rbac_share",
                    "Review external Azure Compute Gallery image read grant", "medium", evidence,
                    status="MANUAL" if condition else "FAIL"))
    return output


def review_findings(snapshot, resources, *, include_manual_only=True):
    resources = list(resources)
    external_group_members = _azure_external_group_members(snapshot, resources) if snapshot["provider"] == "azure" else None
    output = []
    for resource in resources:
        declared = [] if _azure_definition_only(resource) else grants(resource)
        uncertain = [g for g in declared if g.get("criticality_state") in {"unknown", "partial"} and not g["broad"] and g["allowed_declaration"]]
        if uncertain:
            output.append(finding(snapshot, resource, "least_privilege", "analysis.coverage",
                "Permission criticality context incomplete", "info", {"source": source(snapshot, resource, "grants"),
                    "unclassified_grants": uncertain, "risk_state": "unknown", "reason": "permission_criticality_unknown"}, status="UNKNOWN"))
        high = [g for g in declared if g["allowed_declaration"] and RANK[g["severity"]] <= RANK["high"]] if include_manual_only else []
        if high:
            severity = min((g["severity"] for g in high), key=RANK.get)
            evidence = {"source": source(snapshot, resource, "grants"), "grants": high,
                "usage": usage(snapshot, resource), "risk_state": "conditional", "effective_access": "unknown",
                "missing_context": ["Effective denies, inherited grants, boundaries/SCPs, runtime conditions, and owner-approved business need must be reviewed"],
                "restrictions": {k: v for k, v in resource["data"].items()
                    if k in {"PermissionsBoundary", "DenyPolicies", "PolicySources", "denyAssignments"}},
                "criticality_source": "Bundled Blue-CloudPEASS standalone HackTricks permission criticality; combinations are not evaluated"}
            output.append(finding(snapshot, resource, "least_privilege", "analysis.grant_review",
                "Review high-impact or broad declared grants", severity, evidence))
        telemetry = usage(snapshot, resource) if include_manual_only else None
        if telemetry is not None and resource["type"] in IAM_TYPES and telemetry["inactive_observation"]:
            output.append(finding(snapshot, resource, "least_privilege", "analysis.inactive_identity",
                "Review identity with no activity in the observed window", "low",
                {"source": source(snapshot, resource, "usage"), "usage": telemetry, "risk_state": "unknown"}))
        # Public/external principal triage (peaso.analysis.trust): unconditional public
        # or out-of-boundary principals FAIL, restrictive conditions MANUAL, unattributable UNKNOWN.
        from .trust import principal_exposure
        declarations = [(identity, path, fact, kind, fact.get("tenantId"))
                        for identity, path, fact, kind in principals(resource)]
        if external_group_members and resource["type"] == "role_assignment":
            props = resource["data"].get("properties") or {}
            group_id = props.get("principalId")
            if isinstance(group_id, str) and props.get("principalType") == "Group":
                for member, (group_path, membership) in external_group_members(group_id).items():
                    declarations.append((member, "properties.principalId",
                        {**props, "viaGroup": group_id, "groupPath": group_path,
                         "membershipSource": source(snapshot, membership, "id")},
                        "GroupMember", None))
        verdict = principal_exposure(snapshot, resource, declarations)
        if verdict:
            status, severity, evidence = verdict
            output.append(finding(snapshot, resource, "exposure", "analysis.principal_exposure",
                "Review public or external principal declarations", severity, evidence, status=status))
    if external_group_members:
        output.extend(_azure_gallery_rbac_reviews(snapshot, resources, external_group_members))
    return output


GRANT_SAMPLE = 25  # graph cards inline at most this many grants; the complete list stays in the native resource
MANAGED_SCOPE = "provider_managed"  # node scope of a deduplicated provider-managed definition
PRINCIPAL_SCOPE = "principal_references"  # node scope of an uncollected principal referenced by grants
PRINCIPAL_KINDS = {"principal", "everyone"}
# Principal identifiers that are not scope-relative (members, ARNs, object IDs). Kubernetes subjects are
# cluster-relative and keep their per-scope reference nodes.
PRINCIPAL_GLOBAL_PROVIDERS = {"aws", "gcp", "azure"}


def full_grants(resource, provider=None):
    """The complete declared grant list of a native resource, e.g. the item served by
    GET /api/scans/{id}/resources/{card.detail_ref.resource_ref} (pass the report provider); served complete by
    GET /api/scans/{id}/graphs/iam/grants/{card.detail_ref.resource_ref}.
    Graph cards carry only grant_summary and the GRANT_SAMPLE highest-risk grants."""
    current = resource if provider is None else {**resource, "provider": provider}
    return _grants(current)


def _grant_risk(grant):
    # Highest risk first: allowed, most severe, broad, unconditional; ties keep declaration order.
    return (not grant.get("allowed_declaration"), RANK.get(grant.get("severity"), len(RANK)),
            not grant.get("broad"), bool(grant.get("conditional")))


def grant_summary(declared):
    by_severity, by_state = defaultdict(int), defaultdict(int)
    broad = conditional = allowed = high_risk_allowed = 0
    for g in declared:
        by_severity[g.get("severity")] += 1
        by_state[g.get("criticality_state", "unspecified")] += 1
        broad += bool(g.get("broad"))
        conditional += bool(g.get("conditional"))
        allowed += bool(g.get("allowed_declaration"))
        high_risk_allowed += bool(g.get("allowed_declaration") and RANK.get(g.get("severity"), 9) <= RANK["high"])
    return {"by_severity": {k: by_severity[k] for k in RANK if by_severity.get(k)},
            "by_criticality_state": dict(sorted(by_state.items())),
            "broad": broad, "conditional": conditional, "allowed": allowed,
            "high_risk_allowed": high_risk_allowed}


def grant_card(declared, resource):
    """Bounded grant view for graph cards: complete when small, else the GRANT_SAMPLE highest-risk grants."""
    truncated = len(declared) > GRANT_SAMPLE
    sample = nsmallest(GRANT_SAMPLE, declared, key=_grant_risk) if truncated else declared
    return {"source_grants": sample, "grant_count": len(declared), "source_grants_truncated": truncated,
            "grant_summary": grant_summary(declared),
            "detail_ref": {"resource_ref": resource.get("id", native_id(resource)),
                           "endpoint": "/api/scans/{scan_id}/graphs/iam/grants/{resource_ref}",
                           "derivation": "peaso.analysis.iam.full_grants(resource, provider)"}}


def _attach_card(snapshot, current, resource):
    data = resource["data"]
    declared = grants(resource)
    current["card"] = {**grant_card(declared, resource), "trust": data.get("AssumeRolePolicyDocument"),
                       "usage": usage(snapshot, resource), "effective_access": "unknown",
                       "restrictions": {k: data[k] for k in ("PermissionsBoundary", "denyAssignments", "DenyPolicies", "condition") if k in data}}
    if any(g["allowed_declaration"] and RANK[g["severity"]] <= 1 for g in declared):
        current["risk_annotations"].append({"state": "conditional", "type": "high_risk_grant"})
    if current["card"]["usage"]["inactive_observation"]:
        current["risk_annotations"].append({"state": "observed", "type": "inactive_identity",
            "meaning": "No activity observed within the supplied window; removal remains owner-reviewed"})


_AWS_MANAGED_POLICY = re.compile(r"^arn:aws[a-z-]*:iam::aws:policy/")


def _managed_name(provider, kind, name):
    """Provider-managed definition named by a reference: GCP predefined/basic role, AWS managed policy."""
    name = str(name or "")
    return ((provider == "gcp" and kind == "iam_role" and name.startswith("roles/"))
            or (provider == "aws" and kind == "iam_policy" and bool(_AWS_MANAGED_POLICY.match(name))))


def managed_definition_key(resource):
    """Scope-independent identity of a provider-managed definition, else None.

    GCP predefined/basic roles, AWS managed policies and Azure built-in role definitions are the same
    definition wherever they are collected, so the IAM graph keeps ONE node per definition; the scope a
    grant applies at stays on the binding/attachment/assignment edge evidence."""
    provider, kind, data = resource["provider"], resource["type"], resource["data"]
    if provider == "gcp" and kind == "iam_role":
        name = data.get("name") or native_id(resource)
        return str(name) if _managed_name(provider, kind, name) else None
    if provider == "aws" and kind == "iam_policy":
        arn = data.get("Arn") or native_id(resource)
        return str(arn) if _managed_name(provider, kind, arn) else None
    if provider == "azure" and kind == "role_definition":
        props = data.get("properties", data)
        if isinstance(props, dict) and props.get("type") == "BuiltInRole":
            return _azure_role_guid(data.get("name") or native_id(resource))
    return None


def _definition_digest(resource):
    native = [g["native_grant"] for g in grants(resource)]
    return hashlib.sha256(json.dumps(native, sort_keys=True, default=str).encode()).hexdigest()


def _managed_aliases(snapshot, selected):
    """{per-scope node id: canonical node id} and {canonical id: (canonical resource, merged resources)}.
    Copies whose declared grants differ from the canonical (lowest-scope) copy keep their own node."""
    groups = defaultdict(list)
    for resource in selected:
        key = managed_definition_key(resource)
        if key:
            groups[(resource["type"], key)].append(resource)
    alias, merged = {}, {}
    for (kind, key), members in groups.items():
        members.sort(key=lambda r: (str(r["scope"]), str(r.get("id", ""))))
        target = stable_id(snapshot["provider"], MANAGED_SCOPE, kind, key)
        reference = _definition_digest(members[0]) if len(members) > 1 else None
        same = [members[0]] + [r for r in members[1:] if _definition_digest(r) == reference]
        for resource in same:
            alias[node_id(resource)] = target
        merged[target] = (members[0], same)
    return alias, merged


def build_iam(snapshot, resources, *, defer_types=()):
    """defer_types: native definition types whose cards are built only when the node gets an edge (the
    engine folds edge-less definitions into aggregates, so their cards would be discarded)."""
    selected = [r for r in resources if r["type"] in IAM_TYPES or list(principals(r))
                or (r["type"] == "pod" and r["data"].get("spec", {}).get("serviceAccountName"))]
    alias, merged = _managed_aliases(snapshot, selected)
    # Non-canonical copies of a deduplicated definition: same declared grants, folded into one node.
    folded = {node_id(r) for canonical, same in merged.values() for r in same if r is not canonical}
    nodes = {}
    native_node_ids, canonical_node_ids = [], []
    for r in selected:
        current_id = node_id(r)
        canonical_id = alias.get(current_id, current_id)
        native_node_ids.append(current_id)
        canonical_node_ids.append(canonical_id)
        if current_id in folded:
            continue
        current = nodes[canonical_id] = node(r)
        if canonical_id in merged:
            canonical, same = merged[canonical_id]
            current.update(id=canonical_id, scope=MANAGED_SCOPE, provider_managed=True, native_scope=canonical["scope"],
                           scope_refs={s["scope"]: s.get("id", native_id(s)) for s in same})
    edges = []
    observed_bindings = {}
    lookup = {}
    deferred = {}
    for resource, current_id in zip(selected, canonical_node_ids):  # folded copies resolve to the canonical node
        data = resource["data"]
        meta = data.get("metadata", {})
        names = [native_id(resource), data.get("UserName"), data.get("GroupName"), data.get("RoleName"), data.get("name"), data.get("email"), data.get("id"),
                 f"{meta.get('namespace', '_cluster')}/{meta['name']}" if meta.get("name") else None]
        for name in names:
            if name:
                lookup[(resource["scope"], resource["type"], str(name))] = current_id
    by_kind_name = defaultdict(list)  # (kind, name) -> [(scope, node id)]: O(1) cross-scope resolution
    for (lscope, lkind, lname), value in lookup.items():
        by_kind_name[(lkind, lname)].append((lscope, value))

    principal_scopes = defaultdict(set)

    def reference(resource, kind, rid, *, refscope=None, classification="unknown"):
        scope = refscope or resource["scope"]
        key = (scope, kind, str(rid))
        target = lookup.get(key)
        if target:
            return target
        if kind == "principal":
            raw = str(rid)
            if raw.startswith("system:serviceaccount:"):
                parts = raw.split(":")
                alias = f"{parts[2]}/{parts[3]}" if len(parts) == 4 else raw
                principal_kinds = {"serviceaccount"}
            else:
                alias = raw.split(":", 1)[1] if raw.startswith(("user:", "group:", "serviceAccount:")) else raw
                principal_kinds = {"iam_user", "iam_role", "iam_group", "service_account", "directory_user", "directory_group", "directory_service_principal"}
            candidates = {value for pkind in principal_kinds for _, value in by_kind_name.get((pkind, alias), ())}
            if len(candidates) == 1:
                return candidates.pop()
        if (kind == "iam_policy" and str(rid).startswith("arn:")) or kind in {"role_definition", "iam_role"}:
            candidates = {value for _, value in by_kind_name.get((kind, str(rid)), ())}
            if len(candidates) == 1:
                return candidates.pop()
        if kind == "role_definition" and snapshot["provider"] == "azure" and "/roledefinitions/" in str(rid).lower():
            # Assignments cite a scope-qualified definition ID; built-ins are collected
            # once at "/" and keyed by their GUID name. Prefer a same-scope custom copy.
            found = by_kind_name.get((kind, _azure_role_guid(rid)), ())
            candidates = {value for lscope, value in found if lscope == scope} or {value for _, value in found}
            if len(candidates) == 1:
                return candidates.pop()
        if _managed_name(snapshot["provider"], kind, rid):
            scope = MANAGED_SCOPE  # uncollected provider-managed definition: one reference node, not one per scope
        principal = kind in PRINCIPAL_KINDS and snapshot["provider"] in PRINCIPAL_GLOBAL_PROVIDERS
        if principal:
            # A cloud principal identifier names one identity wherever it is granted: one reference node;
            # the scope of each grant stays on its edge evidence (and in referenced_scopes).
            scope = PRINCIPAL_SCOPE
        target = stable_id(snapshot["provider"], scope, kind, rid)
        annotation = {"state": "unknown" if classification == "unknown" else
                      "observed" if classification == "allowlisted" else "conditional",
                      "classification": classification}
        current = nodes.get(target)
        if current is None:
            nodes[target] = {"id": target, "label": str(rid), "resource_id": str(rid),
                "type": kind, "provider": snapshot["provider"], "scope": scope,
                "evidence": {"inventory_status": "reference_only"}, "risk_annotations": [annotation]}
        elif principal and annotation not in current["risk_annotations"]:
            current["risk_annotations"].append(annotation)  # classification can depend on per-grant tenant facts
        if principal:
            principal_scopes[target].add(str(resource["scope"]))
        return target

    for resource, current_id, src in zip(selected, native_node_ids, canonical_node_ids):
        if current_id in folded:
            continue
        data = resource["data"]
        card = nodes[src]
        if resource["type"] in defer_types:
            deferred[src] = resource
        else:
            _attach_card(snapshot, card, resource)
        for i, group in enumerate(as_list(data.get("GroupList"))):
            dst = reference(resource, "iam_group", group)
            edges.append(relationship(src, dst, "member_of", source(snapshot, resource, f"GroupList[{i}]")))
        for i, member in enumerate(as_list(data.get("members"))):
            if isinstance(member, dict):
                member = member.get("id", member.get("name"))
            if member:
                dst = reference(resource, "principal", member)
                edges.append(relationship(dst, src, "member_of", source(snapshot, resource, f"members[{i}]")))
        for i, policy in enumerate(as_list(data.get("AttachedManagedPolicies"))):
            if isinstance(policy, dict) and policy.get("PolicyArn"):
                dst = reference(resource, "iam_policy", policy["PolicyArn"])
                edges.append(relationship(src, dst, "attached_policy", source(snapshot, resource, f"AttachedManagedPolicies[{i}]")))
        for path, doc in _resource_policy_documents(resource):
            if path == "AssumeRolePolicyDocument" or path in {"Document", "PolicyDocument"}:
                continue
            dst = reference(resource, "policy_document", stable_id(native_id(resource), path))
            # Schema 1.1 references the document inside the native resource (source.resource_id + path);
            # peaso.engine.expand_report() restores evidence.native_document.
            nodes[dst]["evidence"] = {"source": source(snapshot, resource, path), "native_document_ref": path}
            edges.append(relationship(src, dst, "inline_policy", source(snapshot, resource, path)))
        props = data.get("properties", data)
        if resource["type"] == "pod" and data.get("spec", {}).get("serviceAccountName"):
            name = f"{data.get('metadata', {}).get('namespace', 'default')}/{data['spec']['serviceAccountName']}"
            dst = reference(resource, "serviceaccount", name)
            edges.append(relationship(src, dst, "workload_identity", source(snapshot, resource, "spec.serviceAccountName")))
        if resource["type"] == "directory_membership" and "/groups/" in resource["scope"]:
            group_id = resource["scope"].split("/groups/", 1)[1]
            group = reference(resource, "principal", group_id)
            member = reference(resource, "principal", data.get("id", native_id(resource)))
            edges.append(relationship(member, group, "member_of", source(snapshot, resource, "id")))
        if props.get("roleDefinitionId"):
            definition_kind = "directory_role_definition" if resource["type"] == "directory_role_assignment" else "role_definition"
            dst = reference(resource, definition_kind, props["roleDefinitionId"])
            edges.append(relationship(src, dst, "role_definition", source(snapshot, resource, "properties.roleDefinitionId")))
        if resource["type"] in {"role_assignment", "directory_role_assignment"}:
            scope = props.get("scope", props.get("directoryScopeId"))
            if scope:
                dst = reference(resource, "authorization_scope", scope)
                nodes[dst]["evidence"] = {"source": source(snapshot, resource, "properties.scope"),
                    "native_scope": scope, "effective_access": "unknown"}
                edges.append(relationship(src, dst, "declared_scope", source(snapshot, resource, "properties.scope")))
        if resource["provider"] == "gcp":
            for i, binding in enumerate(as_list(data.get("bindings"))):
                if isinstance(binding, dict) and binding.get("role"):
                    dst = reference(resource, "iam_role", binding["role"])
                    edges.append(relationship(src, dst, "role_definition", source(snapshot, resource, f"bindings[{i}].role")))
        role = data.get("roleRef", {})
        if role.get("name"):
            kind = "clusterrole" if role.get("kind") == "ClusterRole" else "role"
            name = f"{data.get('metadata', {}).get('namespace', '_cluster')}/{role['name']}" if kind == "role" else f"_cluster/{role['name']}"
            refscope = resource["scope"]
            if kind == "clusterrole":
                candidates = by_kind_name.get((kind, name), [])
                if len(candidates) == 1:
                    refscope = candidates[0][0]
            dst = reference(resource, kind, name, refscope=refscope)
            edges.append(relationship(src, dst, "role_binding", source(snapshot, resource, "roleRef")))
        for identity, path, fact, kind in principals(resource):
            classification = externality(snapshot, identity, tenant=fact.get("tenantId"))
            everyone = classification in {"public", "everyone_authenticated"}
            dst = reference(resource, "everyone" if everyone else "principal", identity, classification=classification)
            risk_state = "unknown" if classification == "unknown" else "conditional" if classification != "allowlisted" else "observed"
            evidence = {"source": source(snapshot, resource, path), "native_fact": fact,
                "classification": classification, "risk_state": risk_state, "effective_access": "unknown"}
            kind = "trust" if "AssumeRolePolicyDocument" in path else "declared_grant"
            edges.append(relationship(dst, src, kind, evidence))
            observed_bindings.setdefault(dst, []).append({"resource_node": src, "type": kind,
                "source": evidence["source"], "native_fact": fact})
            if classification in {"external", "public", "everyone_authenticated"}:
                card["risk_annotations"].append({"state": "conditional", "type": "external_trust", "classification": classification})
    if deferred:
        linked = {e["source"] for e in edges} | {e["target"] for e in edges}
        for nid, resource in deferred.items():
            if nid in linked:
                _attach_card(snapshot, nodes[nid], resource)
    # Propagate only a conditional review marker along observed attachment /
    # membership facts. This is not transitive permission or chain discovery.
    for nid, facts in observed_bindings.items():
        card = nodes[nid].setdefault("card", {"source_grants": [], "grant_count": 0, "trust": None,
            "usage": {"observations": {}, "window": snapshot.get("metadata", {}).get("usage_window", snapshot.get("metadata", {}).get("activity_window")),
                      "completeness": "unknown", "safe_to_remove": False,
                      "uncertainty": "Principal telemetry is not established by policy or binding evidence"},
            "effective_access": "unknown"})
        card["observed_bindings"] = facts
    declared_high = {nid for nid, current in nodes.items()
                     if any(x.get("type") == "high_risk_grant" and x.get("state") == "conditional"
                            for x in current.get("risk_annotations", []))}
    for edge in edges:
        if edge["type"] not in {"attached_policy", "member_of", "role_definition", "role_binding", "declared_grant"}:
            continue
        target = nodes[edge["target"]]
        if edge["target"] in declared_high:
            nodes[edge["source"]]["risk_annotations"].append({"state": "derived", "type": "high_risk_grant",
                "basis": edge["id"], "effective_access": "unknown"})
            # A reference, not a copy: the grants live once, on source_node's card (grant_count of them;
            # the complete list via the source_node card.detail_ref).
            target_card = target.get("card", {})
            nodes[edge["source"]].setdefault("card", {}).setdefault("referenced_grants", []).append(
                {"source_node": target["id"], "edge_ref": edge["id"],
                 "grant_count": target_card.get("grant_count", len(target_card.get("source_grants", [])))})
    for nid, scopes in principal_scopes.items():
        nodes[nid]["referenced_scopes"] = sorted(scopes)
    return {"nodes": list(nodes.values()), "edges": edges,
            "semantics": "Observed declarations and conditional risk review; no effective-access or exploit-chain claims"}
