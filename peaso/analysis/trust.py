"""Default trust boundary, policy-condition triage and federated-trust review.

The scanned accounts/projects/subscriptions/tenant (and collected AWS
Organizations member accounts) are trusted by default. ``trusted_scope_ids``
and ``trusted_domains`` remain explicit, additive allowlists. Everything else
that can be attributed to a scope is external. Nothing here calls a provider.
"""
from __future__ import annotations

import copy
import re
from fnmatch import fnmatchcase
from urllib.parse import urlsplit

from .common import _CONTEXT, as_list
from .trust_domains import OwnedDomains, normalized as normalized_domains
from peaso.snapshot import FrozenDict, freeze

ACCOUNT = re.compile(r"^[0-9]{12}$")
MICROSOFT_TENANTS = {"f8cdef31-a31e-4b4a-93e4-5f571e91255a", "72f988bf-86f1-41af-91ab-2d7cd011db47"}
# Positive condition keys that bind a public principal to a caller, network or
# organisation. Values must not be bare wildcards and the operator must not be
# a negated or IfExists variant.
RESTRICTIVE_KEYS = {
    "aws:sourcevpc", "aws:sourcevpce", "aws:principalorgid", "aws:principalorgpaths", "aws:sourceaccount",
    "aws:sourcearn", "aws:sourceorgid", "aws:sourceorgpaths", "aws:principalaccount", "aws:principalarn",
    "aws:sourceip", "aws:userid", "aws:sourceowner", "kms:calleraccount", "aws:principalservicename",
    "aws:principalisawsservice", "aws:vpcsourceip", "s3:dataaccesspointaccount", "s3:dataaccesspointarn",
    "aws:resourceorgid", "lambda:sourcefunctionarn", "sns:endpoint"}
SOURCE_KEYS = {"aws:sourceaccount", "aws:sourcearn", "aws:sourceorgid", "aws:sourceorgpaths", "aws:sourceowner"}
POSITIVE = re.compile(r"^(forallvalues:|foranyvalue:)?(stringequals|stringequalsignorecase|stringlike|arnequals|arnlike|ipaddress|bool)$")
# Resource policies only reachable from inside a VPC: a public principal is a
# review item (default endpoint policies are Allow * * *), not internet exposure.
NETWORK_BOUND_TYPES = {"vpc_endpoint", "efs_file_system", "efs_access_point"}


def _aws_network_bound_policy(resource):
    """Generic policy rows retain their EC2 endpoint kind in ResourceArn."""
    if resource.get("type") in NETWORK_BOUND_TYPES:
        return True
    if resource.get("type") != "aws_resource_policy":
        return False
    arn = resource.get("data", {}).get("ResourceArn")
    return isinstance(arn, str) and re.match(r"^arn:[^:]+:ec2:[^:]+:[0-9]{12}:vpc-endpoint(?:-service)?/[^/]+$", arn) is not None
MULTI_TENANT_ISSUERS = ("token.actions.githubusercontent.com", "gitlab.com", "app.terraform.io", "api.bitbucket.org",
                        "oidc.circleci.com", "accounts.google.com", "cognito-identity.amazonaws.com", "vstoken.dev.azure.com",
                        "token.buildkite.com", "agent.buildkite.com", "oidc.codefresh.io")


def _cache(snapshot, key, compute):
    context = _CONTEXT.get()
    if context is None or context["snapshot"] is not snapshot:
        return compute()
    cache = context["derivations"]
    if ("snapshot", key) not in cache:
        cache[("snapshot", key)] = compute()
    return cache[("snapshot", key)]


def _items(snapshot, kind):
    for collection in snapshot.get("collections", []):
        if collection.get("type") == kind and collection.get("status") in ("collected", "partial"):
            yield from (item for item in collection.get("items", []) if isinstance(item, dict))


def explicit_allowlist(snapshot):
    allowed = snapshot.get("metadata", {}).get("trusted_scope_ids", [])
    if isinstance(allowed, dict):
        allowed = allowed.get(snapshot["provider"], [])
    return {str(x) for x in allowed} if isinstance(allowed, list) else set()


def trusted_scopes(snapshot):
    """Return {"ids": set, "domains": set, "sources": {id: reason}} for the default boundary."""
    return _cache(snapshot, "trusted_scopes", lambda: _trusted_scopes(snapshot))


def _trusted_scopes(snapshot):
    provider, metadata = snapshot["provider"], snapshot.get("metadata", {})
    sources = {}

    def add(value, reason):
        if isinstance(value, (str, int)) and str(value):
            sources.setdefault(str(value), reason)
    for value in explicit_allowlist(snapshot):
        add(value, "trusted_scope_ids")
    if provider == "aws":
        for scope in snapshot.get("scopes", []):
            head = scope.split("/", 1)[0]
            if ACCOUNT.match(head):
                add(head, "scanned_scope")
        for identity in as_list(metadata.get("caller_identities")):
            if isinstance(identity, dict):
                add(identity.get("Account"), "caller_identity")
        for key in ("account_id", "account_ids"):
            for value in as_list(metadata.get(key)):
                add(value, "metadata." + key)
        for item in _items(snapshot, "aws_account"):
            add(item.get("Account"), "aws_account")
        for item in _items(snapshot, "organization_account"):
            add(item.get("Id"), "organization_account")
    elif provider == "gcp":
        for scope in snapshot.get("scopes", []):
            if scope.startswith("projects/"):
                add(scope.split("/", 2)[1], "scanned_scope")
            elif "/" not in scope:
                add(scope, "scanned_scope")
        for item in _items(snapshot, "project"):
            for key in ("projectId", "projectNumber"):
                add(item.get(key), "project")
            name = item.get("name")
            if isinstance(name, str) and name.startswith("projects/"):
                add(name.split("/", 2)[1], "project")
        # Collected organizations are part of the scanned trust boundary
        # (e.g. principalSet://agents.global.org-ID.system.id.goog identities).
        for item in _items(snapshot, "organization"):
            name = item.get("name")
            if isinstance(name, str) and re.fullmatch(r"organizations/[0-9]+", name):
                add(name.split("/", 1)[1], "organization")
    elif provider == "azure":
        for key in ("tenant_id", "tenant_ids"):
            for value in as_list(metadata.get(key)):
                add(value, "metadata." + key)
        for item in _items(snapshot, "tenant"):
            add(item.get("tenantId", item.get("id")), "tenant")
        for item in _items(snapshot, "subscription"):
            add(item.get("subscriptionId"), "subscription")
            add(item.get("tenantId"), "subscription.tenantId")
        for scope in snapshot.get("scopes", []):
            match = re.search(r"subscriptions?[:/]([0-9a-fA-F-]{36})", scope)
            if match:
                add(match.group(1), "scanned_scope")
    domains = set(str(x) for x in as_list(metadata.get("trusted_domains")) if isinstance(x, str))
    if provider == "gcp":
        for item in _items(snapshot, "organization"):
            name = item.get("displayName")
            if isinstance(name, str) and "." in name:
                domains.add(name)
    context = _CONTEXT.get()
    if provider in ("gcp", "k8s") and context is not None and context["snapshot"] is snapshot:
        domains = OwnedDomains(domains)
    return {"ids": set(sources), "domains": domains, "sources": sources}


def provider_service(provider, text):
    if provider == "aws":
        return text.endswith(".amazonaws.com") or text.startswith("arn:aws:iam::cloudfront:") or text in {"www.amazon.com", "graph.facebook.com", "accounts.google.com"}
    if provider == "gcp":
        # Google-managed service agents (service-PROJECT@gcp-sa-*.iam..., *@cloudservices..., *@cloudbuild...).
        from .common import gcp_member
        value = gcp_member(text)[1]
        domain = value.rsplit("@", 1)[-1].lower() if "@" in value else ""
        return domain.startswith("gcp-sa-") or (domain.endswith(".gserviceaccount.com") and not domain.endswith(
            (".iam.gserviceaccount.com", "developer.gserviceaccount.com", "appspot.gserviceaccount.com")))
    return False


def _gcp_group_membership(snapshot, email):
    """Classify an owned group from its observed Cloud Identity membership graph."""
    def index():
        groups = {}
        members = {}
        statuses = {}
        for collection in snapshot.get("collections", []):
            if collection.get("type") == "group_membership":
                statuses[collection.get("scope")] = collection.get("status")
        for collection in snapshot.get("collections", []):
            if collection.get("type") != "group" or collection.get("status") not in ("collected", "partial"):
                continue
            for row in collection.get("items", []):
                if not isinstance(row, dict):
                    continue
                key = row.get("groupKey")
                if isinstance(key, dict) and isinstance(key.get("id"), str):
                    groups.setdefault(key["id"].lower(), []).append((row, collection.get("scope")))
        for row in _items(snapshot, "group_membership"):
            if isinstance(row.get("group"), str):
                members.setdefault(row["group"], []).append(row)
        return groups, members, statuses
    groups, members, statuses = _cache(snapshot, "gcp_group_membership_index", index)
    matches = groups.get(email.lower(), [])
    if len(matches) != 1:
        return "unknown", None
    group, scope = matches[0]
    group_name = group.get("name")
    external = []
    unresolved = False
    for row in members.get(group_name, []):
        keys = as_list(row.get("preferredMemberKey"))
        if not keys or (row.get("membershipCoverage") or {}).get("completeTransitiveClosure") is not True:
            unresolved = True
        for key in keys:
            if not isinstance(key, dict) or key.get("namespace") or not isinstance(key.get("id"), str):
                unresolved = True
                continue
            member = key["id"]
            if "@" in member:
                from .common import externality
                classification = externality(snapshot, "serviceAccount:" + member)
                if classification == "external":
                    external.append(member)
                elif classification == "unknown":
                    unresolved = True
            else:
                unresolved = True
    evidence = {"group": group_name, "external_members": sorted(set(external)),
                "transitive_memberships_status": ((group.get("_coverage") or {}).get("transitiveMemberships") or {}).get("status")}
    if external:
        return "external", evidence
    complete = (not unresolved and evidence["transitive_memberships_status"] == "collected" and
                statuses.get(scope) in ("collected", "empty"))
    return ("allowlisted" if complete else "unknown"), evidence


def classify(snapshot, principal, scope=None):
    """public, everyone_authenticated, allowlisted, external, provider_service, or unknown."""
    text = str(principal)
    if text in {"*", "allUsers", "allAuthenticatedUsers", "system:anonymous", "system:unauthenticated"}:
        return "public"
    if text == "system:authenticated":
        return "everyone_authenticated"
    provider = snapshot["provider"]
    if provider_service(provider, text):
        return "provider_service"
    if provider == "k8s":
        return _k8s_subject(snapshot, text)
    trusted = trusted_scopes(snapshot)
    if scope is not None:
        if str(scope) in trusted["ids"]:
            return "allowlisted"
        if provider == "azure" and str(scope).lower() in MICROSOFT_TENANTS:
            return "provider_service"
        return "external" if trusted["ids"] else "unknown"
    if provider == "gcp" and trusted["domains"]:
        from .common import gcp_member
        kind, value = gcp_member(text)
        domains = normalized_domains(trusted["domains"])
        # domain:X grants every identity of a Google Workspace/Cloud Identity domain.
        if kind == "domain" and value:
            return "allowlisted" if value.lower() in domains else "external"
        if kind == "group" and "@" in value:
            if value.rsplit("@", 1)[1].lower() not in domains:
                return "external"
            return _gcp_group_membership(snapshot, value)[0]
        if "@" in value and not value.endswith(".gserviceaccount.com"):
            return "allowlisted" if value.split("@", 1)[1] in domains else "external"
    if provider == "azure":
        foreign = azure_foreign_objects(snapshot).get(text.lower())
        if foreign:
            return foreign
    return "unknown"


K8S_MANAGED_USERS = frozenset(("cluster-autoscaler",))  # GKE control-plane autoscaler identity


def _k8s_subject(snapshot, text):
    """RBAC subjects are cluster-relative. ServiceAccounts (and the all-ServiceAccounts group) live
    inside the scanned cluster; reserved system:/eks: names and control-plane users are
    authenticated by the provider's control plane. Escalation through them is the privesc
    engine's concern, not cross-boundary exposure. Other users and groups come from an external
    IdP: an e-mail is attributable when trusted_scope_ids declares domains, otherwise unknown."""
    from peaso.privesc.effective_permissions.k8s import CONTROL_PLANE_USERS
    if text.startswith("system:serviceaccount:") or text == "system:serviceaccounts":
        return "allowlisted"
    if text.startswith(("system:", "eks:")) or text in CONTROL_PLANE_USERS or text in K8S_MANAGED_USERS:
        return "provider_service"
    domains = normalized_domains(trusted_scopes(snapshot)["domains"])
    if domains and "@" in text:
        return "allowlisted" if text.rsplit("@", 1)[1].lower() in domains else "external"
    return "unknown"


# Rules of the upstream default discovery roles (system:discovery, system:public-info-viewer,
# system:basic-user) that every conformant cluster binds to system:authenticated and/or
# system:unauthenticated: API discovery, health/version and self-review only, no object data.
# https://kubernetes.io/docs/reference/access-authn-authz/rbac/#discovery-roles
SELF_INFO_URLS = frozenset(("/api", "/api/*", "/apis", "/apis/*", "/healthz", "/livez", "/openapi", "/openapi/*",
                            "/readyz", "/version", "/version/"))
SELF_REVIEW_RESOURCES = {"authorization.k8s.io": frozenset(("selfsubjectaccessreviews", "selfsubjectrulesreviews")),
                         "authentication.k8s.io": frozenset(("selfsubjectreviews",))}


def _self_info_rule(rule):
    if not isinstance(rule, dict) or rule.get("resourceNames"):
        return False
    urls, verbs = rule.get("nonResourceURLs") or [], set(rule.get("verbs") or [])
    if urls:
        return not rule.get("resources") and set(urls) <= SELF_INFO_URLS and verbs <= {"get"} and bool(verbs)
    groups, resources = rule.get("apiGroups") or [], set(rule.get("resources") or [])
    return (bool(groups) and bool(resources) and bool(verbs) and verbs <= {"create"}
            and all(resources <= SELF_REVIEW_RESOURCES.get(group, frozenset()) for group in groups))


def _k8s_self_info_roles(snapshot):
    return _cache(snapshot, "k8s_self_info_roles", lambda: frozenset(
        str(item.get("metadata", {}).get("name")) for item in _items(snapshot, "clusterrole")
        if isinstance(item.get("metadata"), dict) and not item.get("aggregationRule")
        and isinstance(item.get("rules"), list) and item["rules"] and all(_self_info_rule(r) for r in item["rules"])))


def _k8s_self_info_binding(snapshot, resource):
    """A binding whose collected ClusterRole only grants discovery/health/self-review: public by design."""
    ref = resource.get("data", {}).get("roleRef") if resource.get("type") in ("clusterrolebinding", "rolebinding") else None
    return isinstance(ref, dict) and ref.get("kind") == "ClusterRole" and str(ref.get("name")) in _k8s_self_info_roles(snapshot)


def azure_foreign_objects(snapshot):
    return _cache(snapshot, "azure_foreign", lambda: _azure_foreign(snapshot))


def _azure_foreign(snapshot):
    if snapshot["provider"] != "azure":
        return {}
    trusted = trusted_scopes(snapshot)["ids"]
    output = {}
    for item in _items(snapshot, "directory_service_principal"):
        owner = str(item.get("appOwnerOrganizationId") or "")
        if owner and trusted and owner not in trusted:
            output[str(item.get("id", "")).lower()] = "provider_service" if owner.lower() in MICROSOFT_TENANTS else "external"
    for item in _items(snapshot, "directory_user"):
        if item.get("userType") == "Guest":
            output[str(item.get("id", "")).lower()] = "external"
    # Objects enumerated from the scanned tenant's own directory are inside the
    # boundary: member users, groups, and service principals whose owning app
    # tenant is trusted. Foreign/guest attributions above take precedence.
    home = [item for kind in ("directory_user", "directory_group") for item in _items(snapshot, kind)
            if kind == "directory_group" or item.get("userType") != "Guest"]
    home += [item for item in _items(snapshot, "directory_service_principal")
             if trusted and str(item.get("appOwnerOrganizationId") or "") in trusted]
    for item in home:
        output.setdefault(str(item.get("id", "")).lower(), "allowlisted")
    output.pop("", None)
    return output


DIRECTORY_PRINCIPAL_KINDS = ("directory_user", "directory_group", "directory_service_principal")


def unknown_principal_context(snapshot, identity):
    """Why a principal stayed unattributed, and which collector facts would resolve it."""
    if snapshot["provider"] != "azure":
        return "principal_scope_unattributed", ["trusted_scope_ids metadata or an attributable principal scope"]
    statuses = {kind: "not_collected" for kind in DIRECTORY_PRINCIPAL_KINDS}
    for collection in snapshot.get("collections", []):
        if collection.get("type") in statuses:
            statuses[collection["type"]] = collection.get("status", "unknown")
    missing = [kind for kind, status in statuses.items() if status not in ("collected", "empty")]
    if missing:
        return "directory_not_collected", [f"{kind} ({statuses[kind]})" for kind in missing]
    if not trusted_scopes(snapshot)["ids"]:
        return "tenant_boundary_unknown", ["tenant or subscription.tenantId (trusted tenant boundary)"]
    return "principal_not_in_directory", ["Graph directoryObjects/" + str(identity) + " (deleted, orphaned or cross-tenant object)"]


def _conditions(condition):
    """Yield (operator, key, values) for a native IAM condition block."""
    if not isinstance(condition, dict):
        return
    for operator, pairs in condition.items():
        if not isinstance(pairs, dict):
            continue
        for key, values in pairs.items():
            yield str(operator), str(key), [str(v) for v in as_list(values)]


def restrictive_conditions(condition):
    """Condition keys that genuinely restrict a public principal (positive, non-wildcard)."""
    output = []
    for operator, key, values in _conditions(condition):
        op, lowered = operator.lower(), key.lower()
        if lowered not in RESTRICTIVE_KEYS or "ifexists" in op or not POSITIVE.match(op):
            continue
        if not values or any(v in ("*", "0.0.0.0/0", "::/0") for v in values):
            continue
        if lowered == "aws:principalisawsservice" and values != ["true"]:
            continue
        if op.endswith("bool") and lowered != "aws:principalisawsservice":
            continue
        output.append({"operator": operator, "key": key, "values": values})
    return output


def source_scoped(condition):
    return any(c["key"].lower() in SOURCE_KEYS for c in restrictive_conditions(condition))


def has_external_id(condition):
    return any(key.lower() == "sts:externalid" and values for _, key, values in _conditions(condition))


def principal_verdict(snapshot, entry, statement, path):
    """Decide FAIL / MANUAL / UNKNOWN / None for one declared principal entry."""
    classification, kind = entry["classification"], entry.get("principal_kind")
    condition = statement.get("Condition", statement.get("condition")) if isinstance(statement, dict) else None
    gcp_unconditional = (condition is None or isinstance(condition, dict)
                         and isinstance(condition.get("expression"), str)
                         and condition["expression"].strip() == "true")
    if classification == "public":
        if snapshot["provider"] == "gcp" and not gcp_unconditional:
            return "MANUAL", "public_conditional"
        if snapshot["provider"] == "k8s" and condition is not None:
            return "MANUAL", "public_conditional"
        restrictive = restrictive_conditions(condition) if snapshot["provider"] == "aws" else []
        entry["restrictive_conditions"] = restrictive
        return ("MANUAL", "public_conditional") if restrictive else ("FAIL", "public")
    if classification == "external":
        entry["external_id_condition"] = has_external_id(condition)
        if snapshot["provider"] == "gcp" and not gcp_unconditional:
            return "MANUAL", "external_conditional"
        if kind in ("VaultAccessPolicy", "GroupMember") and isinstance(statement, dict) and statement.get("keyVaultAccessPolicy") and statement.get("applicationId"):
            return "MANUAL", "application_and_principal_required"
        if snapshot["provider"] == "azure" and condition:
            return "MANUAL", "external_conditional"
        return "FAIL", "external"
    if classification == "everyone_authenticated":
        return "MANUAL", "everyone_authenticated"
    if classification == "service_unscoped":
        return "MANUAL", "service_without_source_condition"
    if classification == "unknown":
        return "UNKNOWN", "unattributed"
    return None, classification


def principal_exposure(snapshot, resource, declared):
    """Turn principal declarations into one finding verdict for analysis.principal_exposure.

    ``declared`` yields (identity, path, statement, kind, scope_hint).
    """
    from .common import source
    if snapshot["provider"] == "k8s" and _k8s_self_info_binding(snapshot, resource):
        return None
    entries = []
    for identity, path, fact, kind, tenant in declared:
        if kind == "Service":
            if snapshot["provider"] != "aws" or "AssumeRolePolicyDocument" in path or source_scoped(fact.get("Condition")):
                continue
            classification = "service_unscoped"
        else:
            from .common import externality
            classification = externality(snapshot, identity, tenant=tenant)
            if kind == "acl_group_domain" and classification == "allowlisted":
                # An owned email domain does not prove membership of a
                # particular group whose address was intentionally hashed.
                classification = "unknown"
        if classification in ("allowlisted", "provider_service"):
            continue
        entry = {"principal": identity, "classification": classification,
                 "source": source(snapshot, resource, path), "native_grant": fact,
                 "condition": fact.get("Condition", fact.get("condition")), "principal_kind": kind}
        if snapshot["provider"] == "gcp" and str(identity).startswith("group:"):
            _, group_evidence = _gcp_group_membership(snapshot, str(identity)[len("group:"):])
            if group_evidence is not None:
                entry["group_membership"] = group_evidence
        verdict, reason = principal_verdict(snapshot, entry, fact, path)
        if (snapshot["provider"] == "gcp" and resource.get("type") == "bigquery_dataset"
                and path.startswith("access[") and fact.get("role") not in ("READER", "WRITER", "OWNER")):
            verdict, reason = "UNKNOWN", "unrecognized_dataset_acl_role"
        if verdict == "FAIL" and reason == "public" and _aws_network_bound_policy(resource):
            verdict, reason = "MANUAL", "public_network_bound"
        if verdict is None:
            continue
        entry["verdict"], entry["reason"] = verdict, reason
        if classification == "external":
            from .common import principal_scope
            entry["external_scope_id"] = tenant or principal_scope(snapshot["provider"], identity)
        if verdict == "UNKNOWN":
            if reason == "unrecognized_dataset_acl_role":
                entry["unknown_reason"] = reason
                entry["facts_needed"] = ["valid BigQuery dataset access role from datasets.get"]
            else:
                entry["unknown_reason"], entry["facts_needed"] = unknown_principal_context(snapshot, identity)
            if kind == "acl_group_domain":
                entry["unknown_reason"] = "redacted_group_membership_unavailable"
                entry["facts_needed"] = ["exact group identity and transitive membership outside ACL domain projection"]
        entries.append(entry)
    if not entries:
        return None
    statuses = {e["verdict"] for e in entries}
    status = "FAIL" if "FAIL" in statuses else "MANUAL" if "MANUAL" in statuses else "UNKNOWN"
    fails = [e for e in entries if e["verdict"] == "FAIL"]
    if status == "FAIL":
        severity = "high" if any(e["reason"] == "public" or not e.get("external_id_condition") for e in fails) else "medium"
    elif status == "MANUAL":
        severity = "low" if all(e["reason"] == "service_without_source_condition" for e in entries) else "medium"
    else:
        severity = "info"
    # Every finding retains the complete boundary. Share one immutable projection
    # per evaluation rather than sorting and copying all scopes for every grant.
    trusted_sources = _cache(snapshot, "trusted_scope_evidence",
                            lambda: freeze(dict(sorted(trusted_scopes(snapshot)["sources"].items()))))
    evidence = {"principals": entries, "risk_state": "observed" if status == "FAIL" else "conditional" if status == "MANUAL" else "unknown",
        "effective_access": "unknown", "trusted_scope_ids": snapshot.get("metadata", {}).get("trusted_scope_ids", []),
        "default_trusted_scopes": trusted_sources,
        "external_scope_ids": sorted({str(e["external_scope_id"]) for e in entries if e.get("external_scope_id")}),
        "public_unconditional": any(e["reason"] == "public" for e in entries),
        "uncertainty": "Deny statements, SCP/RCP guardrails, Block Public Access and session policies can still narrow declared access."}
    if status == "UNKNOWN":
        unknown = [e for e in entries if e["verdict"] == "UNKNOWN"]
        evidence["reason"] = unknown[0]["unknown_reason"] if len({e["unknown_reason"] for e in unknown}) == 1 else "mixed"
        evidence["facts_needed"] = list(dict.fromkeys(fact for e in unknown for fact in e["facts_needed"]))
    return status, severity, evidence


# ---------------------------------------------------------------- federation

def _issuer(federated):
    text = str(federated)
    return text.split("oidc-provider/", 1)[1] if "oidc-provider/" in text else text


def _wildcard_subject(issuer, value):
    if value.strip() in ("*", "?*", "*:*"):
        return True
    if "*" not in value and "?" not in value:
        return False
    prefix = re.split(r"[*?]", value, maxsplit=1)[0]
    if issuer.startswith("token.actions.githubusercontent.com"):
        # repo:OWNER/REPO:...; any wildcard inside OWNER admits other organisations.
        match = re.match(r"^(repo|repository_owner|repository_owner_id):([^/:]*)", value)
        return not match or "*" in match.group(2) or "?" in match.group(2) or len(prefix) <= len(match.group(1)) + 1
    # Generic: a wildcard right after the first claim tag (``project_path:*``)
    # or an empty literal prefix leaves the tenant unconstrained.
    return ":" not in prefix or prefix.endswith(":") and prefix.count(":") == 1


def _aws_identity_provider_inventory(snapshot, kind):
    """Index cached IAM provider lists once for all role trust statements."""
    def build():
        inventory = {}
        for row in snapshot.get("collections", []):
            if row.get("type") != kind:
                continue
            account = str(row.get("scope", "")).split("/", 1)[0]
            entry = inventory.setdefault(account, {"states": [], "providers": {}})
            entry["states"].append(row.get("status"))
            for item in row.get("items", []):
                if isinstance(item, dict) and isinstance(item.get("Arn"), str):
                    entry["providers"][item["Arn"]] = item
        return inventory

    return _cache(snapshot, "aws_" + kind + "_inventory", build)


def _aws_identity_provider_state(snapshot, provider, kind, suffix):
    """Return (exists, item): False only after complete account-scoped LIST."""
    match = re.fullmatch(r"arn:[^:]+:iam::([0-9]{12}):" + suffix + r"/.+", str(provider))
    if not match:
        return None, None
    inventory = _aws_identity_provider_inventory(snapshot, kind)
    account = inventory.get(match.group(1))
    if account is None:
        return None, None
    item = account["providers"].get(provider)
    if item is not None:
        return True, item
    return (False, None) if all(state in ("collected", "empty") for state in account["states"]) else (None, None)


def _aws_saml_provider_state(snapshot, provider):
    return _aws_identity_provider_state(snapshot, provider, "iam_saml_provider", "saml-provider")[0]


def _federated_deny_may_apply(statement, provider, action):
    if not isinstance(statement, dict) or statement.get("Effect") != "Deny":
        return False
    if "Action" in statement and "NotAction" in statement:
        action_matches = True
    elif "NotAction" in statement:
        excluded = as_list(statement.get("NotAction"))
        action_matches = not excluded or any(not isinstance(value, str) for value in excluded) or not any(
            fnmatchcase(action, value.lower()) for value in excluded if isinstance(value, str))
    else:
        actions = as_list(statement.get("Action"))
        action_matches = not actions or any(not isinstance(value, str) for value in actions) or any(
            fnmatchcase(action, value.lower()) for value in actions if isinstance(value, str))
    if not action_matches:
        return False
    if "NotPrincipal" in statement:
        return True
    principal = statement.get("Principal")
    if principal == "*":
        return True
    if isinstance(principal, dict):
        if "Federated" in principal:
            federated = as_list(principal["Federated"])
            return not federated or any(not isinstance(value, str) for value in federated) or provider in federated or "*" in federated
        return not any(key in principal for key in ("AWS", "Service"))
    return True


def aws_federated_trust(snapshot, resource):
    """Return (status, severity, evidence) for AWS OIDC/SAML trust, or None."""
    document = resource["data"].get("AssumeRolePolicyDocument")
    if isinstance(document, str):
        from .iam import assume_role_document, document as parse
        document = assume_role_document(resource) if type(resource['data']) is FrozenDict and type(document) is str else parse(document)
    if not isinstance(document, dict):
        return None
    reviews = []
    statements = as_list(document.get("Statement"))
    for index, statement in enumerate(statements):
        if not isinstance(statement, dict) or statement.get("Effect") != "Allow":
            continue
        principal = statement.get("Principal")
        federated = as_list(principal.get("Federated")) if isinstance(principal, dict) else []
        if "NotAction" in statement and "Action" not in statement:
            excluded = as_list(statement.get("NotAction"))
            if not excluded or any(not isinstance(action, str) or not action for action in excluded):
                continue
            actions = [action.lower() for action in excluded]
            web_action = not any(fnmatchcase("sts:assumerolewithwebidentity", action) for action in actions)
            saml_action = not any(fnmatchcase("sts:assumerolewithsaml", action) for action in actions)
        elif "NotAction" in statement:
            continue  # Action and NotAction together are invalid IAM syntax.
        else:
            actions = [str(a).lower() for a in as_list(statement.get("Action"))]
            web_action = any(fnmatchcase("sts:assumerolewithwebidentity", action) for action in actions)
            saml_action = any(fnmatchcase("sts:assumerolewithsaml", action) for action in actions)
        if not federated or not (web_action or saml_action):
            continue
        conditions = list(_conditions(statement.get("Condition")))
        for provider in federated:
            issuer = _issuer(provider)
            saml = "saml-provider/" in str(provider).lower()
            if saml and not saml_action:
                continue
            if not saml and not web_action:
                continue
            prefix = issuer.lower()
            def claim(name, prefix=prefix):
                return [(op, values) for op, key, values in conditions if key.lower() == f"{prefix}:{name}"
                        and "ifexists" not in op.lower() and POSITIVE.match(op.lower())]
            problems = []
            if saml:
                provider_state = _aws_saml_provider_state(snapshot, provider)
                if provider_state is False:
                    reviews.append({"statement": f"AssumeRolePolicyDocument.Statement[{index}]", "federated_principal": provider,
                                    "issuer": issuer, "multi_tenant_issuer": False,
                                    "conditions": copy.deepcopy(statement.get("Condition")),
                                    "problems": [{"code": "saml_provider_absent", "severity": "low",
                                                  "message": "A complete IAM provider inventory does not contain this SAML provider"}]})
                    continue
                if provider_state is None:
                    reviews.append({"statement": f"AssumeRolePolicyDocument.Statement[{index}]", "federated_principal": provider,
                                    "issuer": issuer, "multi_tenant_issuer": False,
                                    "conditions": copy.deepcopy(statement.get("Condition")),
                                    "problems": [{"code": "saml_provider_unknown", "severity": "review",
                                                  "message": "IAM SAML provider inventory is missing or incomplete"}]})
                    continue
                audience = [(op, values) for op, key, values in conditions if key.lower() == "saml:aud"
                            and "ifexists" not in op.lower() and POSITIVE.match(op.lower())
                            and values and all(value and not any(c in value for c in "*?${}") for value in values)]
                if not audience:
                    problems.append({"code": "saml_no_aud", "severity": "low",
                                     "message": "SAML recipient is not positively pinned in the role trust"})
                identity_claims = [(op, key, values) for op, key, values in conditions
                                   if key.lower().startswith("saml:") and key.lower() not in
                                   {"saml:aud", "saml:iss", "saml:doc", "saml:namequalifier"}
                                   and "ifexists" not in op.lower() and POSITIVE.match(op.lower())
                                   and values and all(value and value not in ("*", "?*") for value in values)]
                if not identity_claims and not any(not key.lower().startswith("saml:") for _, key, _ in conditions):
                    problems.append({"code": "saml_issuer_wide", "message":
                                     "No caller-identity condition limits which SAML provider identities may assume the role"})
                else:
                    problems.append({"code": "saml_claim_scope", "severity": "review",
                                     "message": "SAML claim conditions are declared; IdP assertion ownership and membership are not enumerable from IAM"})
            elif ":oidc-provider/" in str(provider):
                provider_state, provider_item = _aws_identity_provider_state(
                    snapshot, provider, "iam_oidc_provider", "oidc-provider")
                if provider_state is not True:
                    reviews.append({"statement": f"AssumeRolePolicyDocument.Statement[{index}]", "federated_principal": provider,
                                    "issuer": issuer, "multi_tenant_issuer": prefix.startswith(MULTI_TENANT_ISSUERS),
                                    "conditions": copy.deepcopy(statement.get("Condition")),
                                    "problems": [{"code": "oidc_provider_absent" if provider_state is False else "oidc_provider_unknown",
                                                  "severity": "low" if provider_state is False else "review",
                                                  "message": "IAM OIDC provider is absent from a complete inventory" if provider_state is False
                                                             else "IAM OIDC provider inventory is missing or incomplete"}]})
                    continue
                detail = provider_item.get("Provider")
                client_ids = detail.get("ClientIDList") if isinstance(detail, dict) else None
                url = detail.get("Url") if isinstance(detail, dict) else None
                if (isinstance(detail, dict) and detail.get("collection_status") == "collected"
                        and url == issuer and isinstance(client_ids, list) and client_ids
                        and all(isinstance(value, str) and value for value in client_ids)):
                    disjoint = any(op.lower() == "stringequals" and key.lower() == f"{prefix}:aud"
                                   and values and not (set(values) & set(client_ids))
                                   for op, key, values in conditions)
                    if disjoint:
                        reviews.append({"statement": f"AssumeRolePolicyDocument.Statement[{index}]", "federated_principal": provider,
                                        "issuer": issuer, "multi_tenant_issuer": prefix.startswith(MULTI_TENANT_ISSUERS),
                                        "conditions": copy.deepcopy(statement.get("Condition")),
                                        "provider_client_ids": copy.deepcopy(client_ids),
                                        "problems": [{"code": "oidc_audience_disjoint", "severity": "low",
                                                      "message": "The exact trust audience has no match in the provider's registered client IDs"}]})
                        continue
                else:
                    problems.append({"code": "oidc_provider_detail_unknown", "severity": "review",
                                     "message": "OIDC provider URL or registered client IDs are not completely collected"})
                subjects = claim("sub")
                if not subjects:
                    problems.append({"code": "no_sub_condition", "message": "No positive sub condition: every identity of this issuer can assume the role"
                                     + (" (issuer is multi-tenant)" if prefix.startswith(MULTI_TENANT_ISSUERS) else " (issuer-wide)")})
                else:
                    wild = [v for op, values in subjects for v in values if "like" in op.lower() and _wildcard_subject(prefix, v)]
                    if wild:
                        problems.append({"code": "wildcard_sub", "message": "Subject wildcard does not pin the tenant/owner", "values": wild})
                if prefix.startswith("token.actions") and not claim("aud"):
                    problems.append({"code": "no_aud_condition", "message": "No aud condition; GitHub tokens for other audiences are accepted", "severity": "low"})
            elif prefix == "cognito-identity.amazonaws.com":
                if not claim("aud"):
                    problems.append({"code": "cognito_no_aud", "message": "Any Cognito identity pool in any account can assume the role"})
                amr = [v for _, values in claim("amr") for v in values]
                if any("unauthenticated" in v for v in amr):
                    # Guest access to a pinned identity pool is a design choice: review the role's permissions.
                    problems.append({"code": "cognito_unauthenticated", "message": "Unauthenticated (guest) Cognito identities can assume the role",
                                     **({} if not claim("aud") else {"severity": "review"})})
            else:
                subjects = claim("sub")
                if (not subjects and re.fullmatch(r"cognito-idp\.[a-z0-9-]+\.amazonaws\.com(?:\.cn)?/[A-Za-z0-9_-]+", prefix)
                        and any(values and all(isinstance(v, str) and v and not any(c in v for c in "*?${}") for v in values)
                                for op, values in claim("aud") if op.lower() == "stringequals")):
                    problems.append({"code": "cognito_user_pool_audience_scope", "severity": "review",
                                     "message": "The user-pool audience is pinned; validate intended users and supported claim enforcement before assessing role assumption."})
                elif not subjects:
                    problems.append({"code": "no_sub_condition", "message": "No positive sub condition: every identity of this issuer can assume the role"
                                     + (" (issuer is multi-tenant)" if prefix.startswith(MULTI_TENANT_ISSUERS) else " (issuer-wide)")})
                else:
                    wild = [v for op, values in subjects for v in values if "like" in op.lower() and _wildcard_subject(prefix, v)]
                    if wild:
                        problems.append({"code": "wildcard_sub", "message": "Subject wildcard does not pin the tenant/owner", "values": wild})
                if prefix.startswith(MULTI_TENANT_ISSUERS) and not claim("aud") and prefix.startswith("token.actions"):
                    problems.append({"code": "no_aud_condition", "message": "No aud condition; GitHub tokens for other audiences are accepted", "severity": "low"})
            reviews.append({"statement": f"AssumeRolePolicyDocument.Statement[{index}]", "federated_principal": provider, "issuer": issuer,
                            "multi_tenant_issuer": prefix.startswith(MULTI_TENANT_ISSUERS),
                            "conditions": copy.deepcopy(statement.get("Condition")), "problems": problems})
    if not reviews:
        return None
    for review_item in reviews:
        if any(problem.get("code") in {"saml_provider_absent", "oidc_provider_absent", "oidc_audience_disjoint"}
               for problem in review_item["problems"]):
            continue  # The matching provider or audience cannot satisfy the Allow.
        provider = review_item["federated_principal"]
        action = "sts:assumerolewithsaml" if "saml-provider/" in str(provider).lower() else "sts:assumerolewithwebidentity"
        if any(_federated_deny_may_apply(statement, provider, action) for statement in statements):
            review_item["deny_uncertain"] = True
            review_item["problems"].append({"code": "federated_explicit_deny", "severity": "review",
                                            "message": "A role trust Deny may apply to this federation action and provider"})
    serious = [p for r in reviews if not r.get("deny_uncertain") for p in r["problems"]
               if p.get("severity") not in ("low", "review")]
    review = [p for r in reviews for p in r["problems"] if p.get("severity") == "review"]
    status = "FAIL" if serious else "MANUAL" if review else "PASS"
    multi = any(r["multi_tenant_issuer"] and not r.get("deny_uncertain") and
                any(p.get("severity") not in ("low", "review") for p in r["problems"]) for r in reviews)
    severity = "critical" if multi else "high" if serious else "medium" if review else "info"
    return status, severity, {"federated_trusts": reviews, "risk_state": "observed" if serious else "conditional" if review else "reviewed",
        "semantics": "Declared web-identity trust conditions; provider-side claim customisation and session policies are not modelled."}


def gcp_wif_provider(snapshot, resource):
    data = resource["data"]
    if data.get("state") == "DELETED" or data.get("disabled") is True:
        return None
    issuer = str(data.get("oidc", {}).get("issuerUri", "")) if isinstance(data.get("oidc"), dict) else ""
    condition = data.get("attributeCondition")
    def grant_unconditional(binding):
        value = binding["condition"]
        return value is None or (isinstance(value, dict)
                                 and isinstance(value.get("expression"), str)
                                 and value["expression"].strip() == "true")
    host = urlsplit(issuer).hostname or ""
    evidence = {"issuer": issuer or None, "aws_account": data.get("aws", {}).get("accountId") if isinstance(data.get("aws"), dict) else None,
                "provider_type": next((kind for kind in ("oidc", "aws", "saml", "x509") if isinstance(data.get(kind), dict)), None),
                "attribute_condition": condition, "attribute_mapping": copy.deepcopy(data.get("attributeMapping")),
                "actor_providers": copy.deepcopy(data.get("actorProviders"))}
    name = data.get("name")
    pool = name.rsplit("/providers/", 1)[0] if isinstance(name, str) and "/providers/" in name else None
    bindings = []
    direct_bindings = []
    unresolved_service_account_bindings = []
    if pool:
        individual = f"principal://iam.googleapis.com/{pool}/subject/"
        principal_set = f"principalSet://iam.googleapis.com/{pool}/"
        pool_wide = f"principalSet://iam.googleapis.com/{pool}/*"
        def pool_member(member):
            if not isinstance(member, str):
                return False
            if member == pool_wide:
                return True
            if member.startswith(individual):
                return bool(member[len(individual):])
            if not member.startswith(principal_set):
                return False
            selector = member[len(principal_set):]
            if selector.startswith("group/"):
                return bool(selector[len("group/"):])
            if selector.startswith("attribute."):
                attribute, separator, value = selector.partition("/")
                return bool(separator and value and len(attribute) > len("attribute."))
            return False
        def matching(policy, target, output):
            if not isinstance(policy, dict) or policy.get("collection_status", "collected") != "collected":
                return
            for binding in as_list(policy.get("bindings")):
                if not isinstance(binding, dict) or not isinstance(binding.get("role"), str) or not binding["role"]:
                    continue
                members = [member for member in as_list(binding.get("members")) if pool_member(member)]
                if members:
                    output.append({"resource": target, "role": binding.get("role"), "members": members,
                                   "pool_wide": pool_wide in members,
                                   "condition": copy.deepcopy(binding.get("condition"))})
        credential_permissions = {"iam.serviceAccounts.getAccessToken", "iam.serviceAccounts.getOpenIdToken",
                                  "iam.serviceAccounts.signBlob", "iam.serviceAccounts.signJwt",
                                  "iam.serviceAccountKeys.create"}
        known_service_account_roles = {
            "roles/iam.workloadIdentityUser": {"iam.serviceAccounts.getAccessToken", "iam.serviceAccounts.getOpenIdToken"},
            "roles/iam.serviceAccountTokenCreator": credential_permissions - {"iam.serviceAccountKeys.create"},
            "roles/iam.serviceAccountOpenIdTokenCreator": {"iam.serviceAccounts.getOpenIdToken"},
            "roles/iam.serviceAccountKeyAdmin": {"iam.serviceAccountKeys.create"},
            "roles/iam.serviceAccountUser": {"iam.serviceAccounts.actAs"},
        }
        role_rows = {}
        for role_row in _items(snapshot, "iam_role"):
            role_rows.setdefault(role_row.get("name"), []).append(role_row)
        for account in _items(snapshot, "service_account"):
            found = []
            matching(account.get("iamPolicy"), account.get("name") or account.get("email"), found)
            for binding in found:
                role = binding["role"]
                matches = role_rows.get(role, [])
                resolved = matches[0].get("includedPermissions") if len(matches) == 1 else None
                permissions = (set(resolved) if isinstance(resolved, list) and all(
                    isinstance(permission, str) for permission in resolved) else known_service_account_roles.get(role))
                if permissions and permissions & credential_permissions:
                    bindings.append({**binding, "service_account": binding["resource"],
                                     "credential_permissions": sorted(permissions & credential_permissions)})
                else:
                    unresolved_service_account_bindings.append({**binding, "service_account": binding["resource"],
                        "reason": "actAs requires a deployment path" if permissions and "iam.serviceAccounts.actAs" in permissions
                                  else "service-account role permissions unresolved" if permissions is None
                                  else "role does not grant credential creation"})
        for collection in snapshot.get("collections", []):
            if collection.get("status") not in ("collected", "partial") or collection.get("type") == "service_account":
                continue
            for item in collection.get("items", []):
                if not isinstance(item, dict):
                    continue
                policy = item.get("iamPolicy", item.get("policy", item if collection.get("type") == "iam_policy" else None))
                matching(policy, item.get("name") or item.get("id"), direct_bindings)
                inherited_coverage = ((item.get("_coverage") or {}).get("_inherited_iam_policies")
                                      if isinstance(item.get("_coverage"), dict) else None)
                project_scope = collection.get("scope")
                project_alias = project_scope.removeprefix("projects/") if isinstance(project_scope, str) else ""
                project_identity = project_alias and project_alias in {
                    str(item.get("projectId")), str(item.get("projectNumber")),
                    str(item.get("name", "")).removeprefix("projects/")}
                if (collection.get("type") == "project" and project_identity
                        and isinstance(inherited_coverage, dict) and inherited_coverage.get("status") == "collected"
                        and isinstance(item.get("_inherited_iam_policies"), list)):
                    for inherited in item["_inherited_iam_policies"]:
                        if not isinstance(inherited, dict):
                            continue
                        ancestor = inherited.get("ancestor")
                        if (not isinstance(ancestor, str) or not re.fullmatch(r"(?:folders|organizations)/[0-9]+", ancestor)
                                or inherited.get("name") != ancestor):
                            continue
                        found = []
                        matching(inherited, project_scope, found)
                        direct_bindings.extend({**binding, "inherited_from": ancestor} for binding in found)
    evidence["service_account_bindings"] = bindings
    evidence["unresolved_service_account_bindings"] = unresolved_service_account_bindings
    evidence["direct_resource_bindings"] = direct_bindings
    grants = bindings + direct_bindings
    pools = [item for collection in snapshot.get("collections", [])
             if collection.get("type") == "workload_identity_pool" and collection.get("status") == "collected"
             for item in collection.get("items", [])
             if isinstance(item, dict) and item.get("name") == pool]
    if len(pools) == 1:
        evidence["pool_state"] = pools[0].get("state")
        evidence["pool_disabled"] = pools[0].get("disabled")
        if pools[0].get("state") == "DELETED" or pools[0].get("disabled") is True:
            return "PASS", "info", {**evidence, "semantics": "A disabled or deleted pool blocks both token exchange and existing token access at snapshot time."}
    if data.get("state") == "DELETED" or data.get("disabled") is True:
        return "MANUAL", "medium", {**evidence, "problem": "Provider is disabled or deleted, but previously issued tokens can retain resource access until expiry."}
    if data.get("state") != "ACTIVE":
        return "MANUAL", "medium", {**evidence, "problem": "Provider ACTIVE state was not verified; existing issued tokens cannot be inferred."}
    if len(pools) != 1 or pools[0].get("state") != "ACTIVE":
        return "MANUAL", "medium", {**evidence, "problem": "Exact active workload identity pool was not verified in a complete inventory."}
    if condition is not None and condition != "" and (not isinstance(condition, str) or condition.strip() != "true"):
        return "MANUAL", "medium", {
            **evidence, "semantics": "Provider attribute condition needs CEL evaluation with a concrete token; uncollected resource grants may exist."}
    aws_account = evidence["aws_account"]
    if isinstance(aws_account, str) and re.fullmatch(r"[0-9]{12}", aws_account):
        allowlisted = explicit_allowlist(snapshot) if snapshot.get("provider") == "gcp" else set()
        mapping = data.get("attributeMapping")
        aws_name = r"[A-Za-z0-9+=,.@_-]+"
        def non_role_caller_arn(value):
            return any(re.fullmatch(pattern, value) for pattern in (
                rf"arn:aws:iam::{aws_account}:root",
                rf"arn:aws:iam::{aws_account}:user/(?:{aws_name}/)*{aws_name}",
                rf"arn:aws:sts::{aws_account}:federated-user/{aws_name}",
            ))
        def aws_selector_reachable(member):
            if member == pool_wide:
                return True
            if not isinstance(member, str):
                return False
            if (member == f"{principal_set}attribute.account/{aws_account}"
                    and isinstance(mapping, dict)
                    and mapping.get("attribute.account") == "assertion.account"
                    and isinstance(mapping.get("google.subject"), str)):
                return True
            if not mapping and member.startswith(f"{principal_set}attribute.aws_role/"):
                role = member[len(f"{principal_set}attribute.aws_role/"):]
                # The default mapping strips assumed-role sessions and preserves other caller ARNs.
                return non_role_caller_arn(role) or bool(re.fullmatch(
                    rf"arn:aws:sts::{aws_account}:assumed-role/{aws_name}", role))
            if (isinstance(mapping, dict) and mapping.get("attribute.aws_role") == "assertion.arn"
                    and isinstance(mapping.get("google.subject"), str)
                    and member.startswith(f"{principal_set}attribute.aws_role/")):
                role = member[len(f"{principal_set}attribute.aws_role/"):]
                return non_role_caller_arn(role) or bool(re.fullmatch(
                    rf"arn:aws:sts::{aws_account}:assumed-role/{aws_name}/{aws_name}", role))
            if (isinstance(mapping, dict)
                    and mapping.get("google.subject") == "assertion.arn"
                    and mapping.get("attribute.aws_role") == "assertion.arn.extract('assumed-role/{role_name}/')"
                    and member.startswith(f"{principal_set}attribute.aws_role/")):
                role = member[len(f"{principal_set}attribute.aws_role/"):]
                return bool(re.fullmatch(r"[A-Za-z0-9+=,.@_-]+", role))
            if (member.startswith(individual) and
                    (not mapping or isinstance(mapping, dict) and mapping.get("google.subject") == "assertion.arn")):
                subject = member[len(individual):]
                return non_role_caller_arn(subject) or bool(re.fullmatch(
                    rf"arn:aws:sts::{aws_account}:assumed-role/{aws_name}/{aws_name}", subject))
            return False
        reachable_grants = [binding for binding in grants if grant_unconditional(binding)
                            and any(aws_selector_reachable(member) for member in binding["members"])]
        evidence["aws_reachable_grants"] = reachable_grants
        if aws_account not in allowlisted and reachable_grants:
            return "FAIL", "critical", {**evidence, "problem": "External AWS account can exchange tokens for an unconditional IAM grant to this pool"}
        return "MANUAL", "medium", {**evidence, "problem": "AWS provider account and scoped or uncollected IAM grants require claim-mapping review"}
    # These issuer paths identify one CI organization or Bitbucket workspace.
    # A host-only issuer can still mint tokens across organizations.
    issuer_path = urlsplit(issuer).path or ""
    org_uuid = r"[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}"
    org_scoped_issuer = ((host == "oidc.circleci.com" and
                          re.fullmatch(rf"/org/{org_uuid}/?", issuer_path) is not None)
                         or (host == "vstoken.dev.azure.com" and
                             re.fullmatch(rf"/{org_uuid}/?", issuer_path) is not None)
                         or (host == "api.bitbucket.org" and
                             re.fullmatch(r"/2\.0/workspaces/[A-Za-z0-9_-]+/pipelines-config/identity/oidc/?",
                                          issuer_path) is not None))
    if host in MULTI_TENANT_ISSUERS and not org_scoped_issuer:
        mapping = data.get("attributeMapping")
        subject_mapping = mapping.get("google.subject") if isinstance(mapping, dict) else None
        if not isinstance(subject_mapping, str) or subject_mapping.strip() != "assertion.sub":
            return "MANUAL", "medium", {**evidence, "problem": "Multi-tenant OIDC subject mapping is absent or needs CEL reachability review"}
        if any(binding["pool_wide"] and grant_unconditional(binding) for binding in grants):
            return "FAIL", "critical", {**evidence, "problem": "Unrestricted multi-tenant issuer has an unconditional pool-wide IAM grant"}
        return "MANUAL", "medium", {**evidence, "problem": "Unrestricted multi-tenant issuer; effective access through conditional or uncollected grants is unresolved"}
    if workforce and any(binding["pool_wide"] and binding["condition"] is None for binding in grants):
        return "MANUAL", "medium", {**evidence, "problem": "External workforce identities have an unconditional pool-wide IAM grant; IdP membership and effective access require review"}
    return "MANUAL", "medium", {**evidence, "problem": "No attributeCondition; every identity of the issuer can exchange tokens"}


def _gcp_federated_direct_bindings(snapshot, pool):
    """Find collected resource IAM bindings for this exact federation pool."""
    if not isinstance(pool, str) or not pool:
        return []
    return _cache(snapshot, ("gcp_federated_direct_bindings", pool),
                  lambda: _scan_gcp_federated_direct_bindings(snapshot, pool))


def _gcp_federated_service_account_bindings(snapshot, pool):
    if not isinstance(pool, str) or not pool:
        return []
    prefixes = (f"principal://iam.googleapis.com/{pool}/", f"principalSet://iam.googleapis.com/{pool}/")
    found = []
    for account in _items(snapshot, "service_account"):
        policy = account.get("iamPolicy")
        if not isinstance(policy, dict) or policy.get("collection_status", "collected") != "collected":
            continue
        for binding in as_list(policy.get("bindings")):
            if not isinstance(binding, dict) or binding.get("role") not in (
                    "roles/iam.workloadIdentityUser", "roles/iam.serviceAccountTokenCreator"):
                continue
            members = [member for member in as_list(binding.get("members"))
                       if isinstance(member, str) and member.startswith(prefixes)]
            if members:
                found.append({"service_account": account.get("name") or account.get("email"),
                              "role": binding["role"], "members": members,
                              "condition": copy.deepcopy(binding.get("condition")),
                              "source_requests": (account.get("_provenance") or {}).get("source_requests", [])})
    return found


def _gcp_federation_pool_disabled(snapshot, pool, kind):
    return any(item.get("name") == pool and
               (item.get("disabled") is True or item.get("state") == "DELETED")
               for item in _items(snapshot, kind))


def _scan_gcp_federated_direct_bindings(snapshot, pool):
    prefixes = (f"principal://iam.googleapis.com/{pool}/", f"principalSet://iam.googleapis.com/{pool}/")
    found = []
    for collection in snapshot.get("collections", []):
        if collection.get("status") not in ("collected", "partial") or collection.get("type") == "service_account":
            continue
        for item in collection.get("items", []):
            if not isinstance(item, dict):
                continue
            policy = item if collection.get("type") == "iam_policy" else item.get("iamPolicy")
            if not isinstance(policy, dict) or policy.get("collection_status", "collected") != "collected":
                continue
            resource_name = item.get("name") or item.get("resource") or item.get("_resource_id") or collection.get("scope")
            for binding in as_list(policy.get("bindings")):
                if not isinstance(binding, dict) or not isinstance(binding.get("role"), str):
                    continue
                for member in as_list(binding.get("members")):
                    if isinstance(member, str) and member.startswith(prefixes):
                        found.append({"resource": resource_name, "resource_type": collection.get("type"),
                                      "role": binding["role"], "member": member,
                                      "condition": copy.deepcopy(binding.get("condition")),
                                      "source_requests": (item.get("_provenance") or {}).get(
                                          "source_requests", collection.get("source_requests", []))})
    return found


def gcp_workforce_provider(snapshot, resource):
    """Keep workforce federation as a bounded configured-trust UNKNOWN."""
    data = resource["data"]
    if data.get("state") == "DELETED" or data.get("disabled") is True:
        return None
    name = data.get("name")
    pool = name.rsplit("/providers/", 1)[0] if isinstance(name, str) and "/providers/" in name else None
    if _gcp_federation_pool_disabled(snapshot, pool, "workforce_pool"):
        return None
    direct = _gcp_federated_direct_bindings(snapshot, pool)
    impersonation = _gcp_federated_service_account_bindings(snapshot, pool)
    provider_type = next((kind for kind in ("oidc", "saml") if isinstance(data.get(kind), dict)), "unrecorded")
    condition = data.get("attributeCondition")
    binding = direct[0] if direct else None
    account_binding = impersonation[0] if impersonation else None
    observed = "\n".join((
        f"The workforce identity provider {name or 'unrecorded'} has type {provider_type}, disabled false and attributeCondition {condition or 'unset'}.",
        f"Its pool has {len(direct)} collected direct-resource and {len(impersonation)} service-account bindings" +
        (f", including {binding['role']} on {binding['resource']}" if binding else
         f", including {account_binding['role']} on {account_binding['service_account']}" if account_binding else "") + ".",
        ("An external workforce identity may use that binding if its token, mapping and any conditions match."
         if binding or account_binding else "Other uncollected or inherited policies may still bind identities from this pool."),
        "That could let an outside user reach people-facing services or stored data if other access controls allow it."))
    return "UNKNOWN", "medium" if direct or impersonation else "info", {
        "observed": observed, "provider_type": provider_type, "attribute_condition": condition,
        "attribute_mapping": copy.deepcopy(data.get("attributeMapping")), "direct_access_bindings": direct,
        "service_account_bindings": impersonation,
        "semantics": "Configured workforce federation only; token claims, CEL, effective IAM and resource responses are unresolved."}


def azure_federated_credential(snapshot, resource):
    props = resource["data"].get("properties", resource["data"])
    issuer, subject = str(props.get("issuer", "")), str(props.get("subject", "") or "")
    expression = props.get("claimsMatchingExpression")
    evidence = {"issuer": issuer, "subject": subject or None, "audiences": copy.deepcopy(props.get("audiences")),
                "claims_matching_expression": copy.deepcopy(expression)}
    if resource["type"] == "managed_identity_federated_credential":
        parsed = urlsplit(issuer)
        value = expression.get("value") if isinstance(expression, dict) else None
        audiences = props.get("audiences")
        if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
                or parsed.fragment or not isinstance(audiences, (list, tuple)) or not audiences
                or not all(isinstance(audience, str) and audience for audience in audiences)
                or not subject and not isinstance(value, str)):
            return "UNKNOWN", "info", {**evidence, "reason": "federated issuer, audience or subject is incomplete"}
        owned_aks = {str(((item.get("properties") or {}).get("oidcIssuerProfile") or {}).get("issuerURL") or "")
                     for item in _items(snapshot, "aks_cluster")}
        if issuer in owned_aks:
            if isinstance(value, str) and ("*" in value or "?" in value):
                return "UNKNOWN", "medium", {**evidence, "reason": "owned AKS issuer has a flexible subject expression"}
            return "PASS", "info", {**evidence, "issuer_ownership": "collected_aks_cluster"}
        if parsed.hostname == "aks.azure.com" or parsed.hostname.endswith((".aks.azure.com", "-aks.azure.com")):
            aks_states = [row.get("status") for row in snapshot.get("collections", []) if row.get("type") == "aks_cluster"]
            if not aks_states or any(state not in ("collected", "empty") for state in aks_states):
                return "UNKNOWN", "info", {**evidence, "reason": "AKS issuer ownership inventory incomplete"}
        return "FAIL", "high", {**evidence, "external_issuer_trust": True,
                                   "reason": "issuer can exchange matching workload tokens for this managed identity"}
    host = re.sub(r"^https?://", "", issuer).lower()
    if expression is not None:
        if (subject or not isinstance(expression, dict) or type(expression.get("languageVersion")) is not int
                or expression["languageVersion"] != 1
                or not isinstance(expression.get("value"), str)):
            return "UNKNOWN", "info", {**evidence, "reason": "invalid flexible credential shape"}
        clauses = {}
        for clause in expression["value"].split(" and "):
            parsed = re.fullmatch(r"claims\['([A-Za-z_][A-Za-z0-9_]*)'\] (eq|matches) '([^']*)'", clause)
            if not parsed or parsed[1] in clauses:
                return "UNKNOWN", "info", {**evidence, "reason": "unsupported flexible credential expression"}
            clauses[parsed[1]] = {"operator": parsed[2], "value": parsed[3]}
        sub = clauses.get("sub")
        if not sub:
            return "UNKNOWN", "info", {**evidence, "reason": "flexible credential has no subject selector"}
        if host == "token.actions.githubusercontent.com":
            bound = any(clauses.get(key, {}).get("operator") == "eq"
                        and re.fullmatch(r"[0-9]+", clauses[key]["value"])
                        for key in ("repository_id", "repository_owner_id") if key in clauses)
            if not bound:
                return "UNKNOWN", "info", {**evidence, "reason": "GitHub immutable repository selector is unavailable"}
        elif host == "gitlab.com" or host.startswith("gitlab."):
            project = clauses.get("project_id", {})
            if project.get("operator") != "eq" or not re.fullmatch(r"[0-9]+", project.get("value", "")):
                return "UNKNOWN", "info", {**evidence, "reason": "GitLab immutable project selector is unavailable"}
        elif host in ("app.terraform.io", "app.eu.terraform.io"):
            if sub["operator"] == "matches" and _wildcard_subject(host, sub["value"]):
                return "FAIL", "critical", {**evidence, "reason": "Terraform subject selector admits arbitrary workloads"}
        else:
            return "UNKNOWN", "info", {**evidence, "reason": "flexible credential issuer syntax is unsupported"}
        return "MANUAL", "medium", {**evidence, "reason": "flexible credential is bounded by observed claims; external issuer ownership is unverified",
                                    "claim_selectors": clauses}
    if not subject:
        return "UNKNOWN", "info", {**evidence, "reason": "subject not collected"}
    audiences = props.get("audiences")
    if (not issuer.startswith("https://") or not host or not isinstance(audiences, list)
            or len(audiences) != 1 or not isinstance(audiences[0], str) or not audiences[0]):
        return "UNKNOWN", "info", {**evidence, "reason": "exact credential issuer or audience is incomplete"}
    return "MANUAL", "medium", {**evidence, "reason": "exact subject is pinned; external issuer ownership is unverified"}
