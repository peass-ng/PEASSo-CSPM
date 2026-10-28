"""Default trust boundary, policy-condition triage and federated-trust review.

The scanned accounts/projects/subscriptions/tenant (and collected AWS
Organizations member accounts) are trusted by default. ``trusted_scope_ids``
and ``trusted_domains`` remain explicit, additive allowlists. Everything else
that can be attributed to a scope is external. Nothing here calls a provider.
"""
from __future__ import annotations

import copy
import re

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
                        "token.buildkite.com", "oidc.codefresh.io")


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
    if classification == "public":
        if snapshot["provider"] in {"gcp", "k8s"} and condition:
            return "MANUAL", "public_conditional"
        restrictive = restrictive_conditions(condition) if snapshot["provider"] == "aws" else []
        entry["restrictive_conditions"] = restrictive
        return ("MANUAL", "public_conditional") if restrictive else ("FAIL", "public")
    if classification == "external":
        entry["external_id_condition"] = has_external_id(condition)
        if kind in ("VaultAccessPolicy", "GroupMember") and isinstance(statement, dict) and statement.get("keyVaultAccessPolicy") and statement.get("applicationId"):
            return "MANUAL", "application_and_principal_required"
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
        if classification in ("allowlisted", "provider_service"):
            continue
        entry = {"principal": identity, "classification": classification,
                 "source": source(snapshot, resource, path), "native_grant": fact,
                 "condition": fact.get("Condition", fact.get("condition")), "principal_kind": kind}
        verdict, reason = principal_verdict(snapshot, entry, fact, path)
        if verdict == "FAIL" and reason == "public" and _aws_network_bound_policy(resource):
            verdict, reason = "MANUAL", "public_network_bound"
        if verdict is None:
            continue
        entry["verdict"], entry["reason"] = verdict, reason
        if classification == "external":
            from .common import principal_scope
            entry["external_scope_id"] = tenant or principal_scope(snapshot["provider"], identity)
        if verdict == "UNKNOWN":
            entry["unknown_reason"], entry["facts_needed"] = unknown_principal_context(snapshot, identity)
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


def aws_federated_trust(snapshot, resource):
    """Return (status, severity, evidence) for AWS web-identity trust, or None."""
    document = resource["data"].get("AssumeRolePolicyDocument")
    if isinstance(document, str):
        from .iam import assume_role_document, document as parse
        document = assume_role_document(resource) if type(resource['data']) is FrozenDict and type(document) is str else parse(document)
    if not isinstance(document, dict):
        return None
    reviews = []
    for index, statement in enumerate(as_list(document.get("Statement"))):
        if not isinstance(statement, dict) or statement.get("Effect") != "Allow":
            continue
        principal = statement.get("Principal")
        federated = as_list(principal.get("Federated")) if isinstance(principal, dict) else []
        actions = [str(a).lower() for a in as_list(statement.get("Action"))]
        if not federated or not any(a in ("sts:assumerolewithwebidentity", "sts:*", "*") for a in actions):
            continue
        conditions = list(_conditions(statement.get("Condition")))
        for provider in federated:
            issuer = _issuer(provider)
            if "saml-provider/" in str(provider):
                continue
            prefix = issuer.lower()
            def claim(name, prefix=prefix):
                return [(op, values) for op, key, values in conditions if key.lower() == f"{prefix}:{name}"
                        and "ifexists" not in op.lower() and POSITIVE.match(op.lower())]
            problems = []
            if prefix == "cognito-identity.amazonaws.com":
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
    serious = [p for r in reviews for p in r["problems"] if p.get("severity") not in ("low", "review")]
    review = [p for r in reviews for p in r["problems"] if p.get("severity") == "review"]
    status = "FAIL" if serious else "MANUAL" if review else "PASS"
    multi = any(r["multi_tenant_issuer"] and any(p.get("severity") not in ("low", "review") for p in r["problems"]) for r in reviews)
    severity = "critical" if multi else "high" if serious else "medium" if review else "info"
    return status, severity, {"federated_trusts": reviews, "risk_state": "observed" if serious else "conditional" if review else "reviewed",
        "semantics": "Declared web-identity trust conditions; provider-side claim customisation and session policies are not modelled."}


def gcp_wif_provider(snapshot, resource):
    data = resource["data"]
    if data.get("state") == "DELETED" or data.get("disabled") is True:
        return None
    issuer = str(data.get("oidc", {}).get("issuerUri", "")) if isinstance(data.get("oidc"), dict) else ""
    condition = data.get("attributeCondition")
    host = re.sub(r"^https?://", "", issuer).lower()
    evidence = {"issuer": issuer or None, "aws_account": data.get("aws", {}).get("accountId") if isinstance(data.get("aws"), dict) else None,
                "attribute_condition": condition, "attribute_mapping": copy.deepcopy(data.get("attributeMapping"))}
    name = data.get("name")
    pool = name.rsplit("/providers/", 1)[0] if isinstance(name, str) and "/providers/" in name else None
    bindings = []
    if pool:
        prefixes = (f"principal://iam.googleapis.com/{pool}/", f"principalSet://iam.googleapis.com/{pool}/")
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
                    bindings.append({"service_account": account.get("name") or account.get("email"),
                                     "role": binding["role"], "members": members,
                                     "condition": copy.deepcopy(binding.get("condition"))})
    evidence["service_account_bindings"] = bindings
    if condition:
        return ("MANUAL" if bindings else "PASS"), ("medium" if bindings else "info"), {
            **evidence, "semantics": "Provider attribute condition and any service-account binding conditions need CEL evaluation."}
    if host.startswith(MULTI_TENANT_ISSUERS):
        if any(not binding["condition"] for binding in bindings):
            return "FAIL", "critical", {**evidence, "problem": "Unrestricted multi-tenant issuer has a declared service-account impersonation binding"}
        return "MANUAL", "medium", {**evidence, "problem": "Unrestricted multi-tenant issuer; effective access through conditional or uncollected grants is unresolved"}
    return "MANUAL", "medium", {**evidence, "problem": "No attributeCondition; every identity of the issuer can exchange tokens"}


def azure_federated_credential(snapshot, resource):
    props = resource["data"].get("properties", resource["data"])
    issuer, subject = str(props.get("issuer", "")), str(props.get("subject", "") or "")
    expression = props.get("claimsMatchingExpression")
    evidence = {"issuer": issuer, "subject": subject or None, "audiences": copy.deepcopy(props.get("audiences")),
                "claims_matching_expression": copy.deepcopy(expression)}
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
    return "PASS", "info", evidence
