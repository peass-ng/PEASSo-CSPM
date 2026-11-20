"""Principal-centric, evidence-bound suggestions for reducing standing access.

Provider recommendations and explicit tracked-action observations support review.
Declared broad grants without usage evidence remain review candidates.
"""
from __future__ import annotations

from collections.abc import Mapping

def _text(value):
    return value.strip() if isinstance(value, str) else ""


def _resource(row):
    return row.get("data", {}) if isinstance(row.get("data"), Mapping) else {}


def project(provider, resources, snapshot=None):
    resources = list(resources)
    principals = {}
    coverage = {"source": "collected provider evidence", "limitations": []}

    def add(principal, scope, suggestion, label=None):
        principal = _text(principal)
        if not principal:
            return
        card = principals.setdefault(principal, {"id": principal, "principal": principal, "label": _text(label) or principal,
            "scopes": [], "provider": provider, "suggestions": []})
        if _text(label) and card["label"] == principal:
            card["label"] = _text(label)
        if scope not in card["scopes"]:
            card["scopes"].append(scope)
        suggestion = {**suggestion, "scope": scope}
        if suggestion not in card["suggestions"]:
            card["suggestions"].append(suggestion)

    if provider == "aws":
        coverage["limitations"].append("Access Analyzer recommendations require active unused-access findings. Temporary analyzers may still be completing initial analysis when scanned. Dated IAM reports can flag tracked actions with no observed attempt for removal review.")
        analyzers = 0
        for row in resources:
            if row.get("type") != "access_analyzer":
                continue
            data = _resource(row)
            if data.get("type") not in {"ACCOUNT_UNUSED_ACCESS", "ORGANIZATION_UNUSED_ACCESS"} or data.get("status") != "ACTIVE":
                continue
            analyzers += 1
            for finding in data.get("Findings") or []:
                if not isinstance(finding, Mapping) or finding.get("status") != "ACTIVE" or finding.get("findingType") != "UnusedPermission":
                    continue
                principal = _text(finding.get("resource"))
                observation = ((data.get("configuration") or {}).get("unusedAccess") or {}).get("unusedAccessAge")
                window = {"usage_window_days": observation} if type(observation) is int and observation > 0 else {}
                details = finding.get("UnusedPermissionDetails") or {}
                if not isinstance(details, Mapping) or details.get("collection_status") not in {"collected", "empty", "partial"}:
                    continue
                for detail in details.get("items") or []:
                    unused = detail.get("unusedPermissionDetails") if isinstance(detail, Mapping) else None
                    if not isinstance(unused, Mapping):
                        continue
                    namespace = _text(unused.get("serviceNamespace"))
                    for action in unused.get("actions") or []:
                        if not isinstance(action, Mapping) or not _text(action.get("action")):
                            continue
                        name = _text(action["action"])
                        permission = name if ":" in name else f"{namespace}:{name}" if namespace else name
                        add(principal, row.get("scope", ""), {"kind": "permission", "value": permission,
                            "source": "AWS IAM Access Analyzer unused access", "evidence_id": finding.get("id"),
                            "last_accessed": action.get("lastAccessed"), "confidence": "provider_recommendation",
                            "details_complete": details.get("collection_status") in {"collected", "empty"}, **window})
                    if not unused.get("actions") and namespace:
                        add(principal, row.get("scope", ""), {"kind": "service", "value": namespace,
                            "source": "AWS IAM Access Analyzer unused access", "evidence_id": finding.get("id"),
                            "last_accessed": unused.get("lastAccessed"), "confidence": "provider_recommendation",
                            "details_complete": details.get("collection_status") in {"collected", "empty"}, **window})
        coverage["unused_access_analyzers"] = analyzers
    elif provider == "gcp":
        coverage["limitations"].append("IAM Recommender proposes role removal or replacement; individual permissions are shown only when the provider supplies them. Review conditions and business need before applying.")
        for row in resources:
            if row.get("type") != "recommendation":
                continue
            data = _resource(row)
            if (data.get("stateInfo") or {}).get("state") != "ACTIVE":
                continue
            overview = (data.get("content") or {}).get("overview") or {}
            principal = _text(overview.get("member"))
            removed = _text(overview.get("removedRole"))
            operations = [operation for group in (data.get("content") or {}).get("operationGroups") or []
                if isinstance(group, Mapping) for operation in group.get("operations") or []
                if isinstance(operation, Mapping)]
            if not principal or not removed:
                removals = [operation for operation in operations if operation.get("action") == "remove"]
                for operation in removals:
                    filters = operation.get("pathFilters") or {}
                    member = _text(filters.get("/iamPolicy/bindings/*/members/*"))
                    role = _text(filters.get("/iamPolicy/bindings/*/role"))
                    if member and role:
                        principal, removed = member, role
                        break
            if not principal or not removed:
                continue
            replacement = [value for value in overview.get("addedRoles") or [] if _text(value)]
            if not replacement:
                replacement = sorted({_text((operation.get("pathFilters") or {}).get("/iamPolicy/bindings/*/role"))
                    for operation in operations if operation.get("action") == "add"} - {""})
            add(principal, row.get("scope", ""), {"kind": "role", "value": removed,
                "replacement": replacement, "source": "Google Cloud IAM Recommender",
                "evidence_id": data.get("name"), "last_refreshed": data.get("lastRefreshTime"),
                "confidence": "provider_recommendation"})
    elif provider == "azure":
        coverage["limitations"].append("Azure Activity Log does not prove that each granted action was unused, and data-plane operations can be absent. Broad assignments are review candidates, not removal recommendations.")
        definitions = {}
        labels = {}
        for row in resources:
            if row.get("type") == "role_definition":
                data = _resource(row)
                name = _text(data.get("name"))
                if name:
                    definitions[name.rsplit("/", 1)[-1].lower()] = data
            elif row.get("type") in {"directory_user", "directory_group", "directory_service_principal"}:
                data = _resource(row)
                principal_id = _text(data.get("id"))
                if principal_id:
                    labels[principal_id.casefold()] = (_text(data.get("userPrincipalName")) or
                        _text(data.get("mail")) or _text(data.get("displayName")))
        for row in resources:
            if row.get("type") != "role_assignment":
                continue
            props = _resource(row).get("properties") or {}
            principal = _text(props.get("principalId"))
            role_id = _text(props.get("roleDefinitionId"))
            definition = definitions.get(role_id.rsplit("/", 1)[-1].lower()) or {}
            role = (definition.get("properties") or {}).get("roleName") or role_id
            permissions = (definition.get("properties") or {}).get("permissions") or []
            broad = any(isinstance(p, Mapping) and any("*" in str(a) for a in list(p.get("actions") or []) + list(p.get("dataActions") or [])) for p in permissions)
            if principal and role_id and broad:
                add(principal, _text(props.get("scope")) or row.get("scope", ""), {"kind": "role_review",
                    "value": role, "source": "Azure RBAC role assignment", "evidence_id": _resource(row).get("id"),
                    "confidence": "declared_grant_only"}, labels.get(principal.casefold()))
    else:
        coverage["limitations"].append("No provider-backed unused-permission signal is available for this connector.")
    from peaso.principal_exposure import project as exposure_project, canonical, LIMITATIONS, RANK
    if snapshot is None:
        # Historical artifacts have no trust metadata. Preserve that uncertainty.
        collections = [{"type": row["type"], "scope": row.get("scope", ""), "status": "partial", "items": [row.get("data", {})]}
                       for row in resources]
        snapshot = {"provider": provider, "scopes": sorted({r.get("scope", "") for r in resources}),
                    "metadata": {}, "collections": collections}
    normalized = [{**row, "provider": provider, "id": row.get("id", str(i)), "scope": row.get("scope", ""), "data": _resource(row)} for i, row in enumerate(resources)]
    exposure_cards = exposure_project(snapshot, normalized)
    from peaso.least_privilege_permissions import include_resolved_principals
    exposure_cards = include_resolved_principals(provider, normalized, exposure_cards)
    for exposure_key, details in exposure_cards.items():
        if not details["exposures"] and not details["grant_reviews"]:
            continue
        principal = details["principal"]
        card_key = exposure_key
        card = principals.setdefault(card_key, {"id": card_key, "principal": principal, "label": details["label"],
            "scopes": list(details["scopes"]), "provider": provider, "suggestions": []})
        card["scopes"] = sorted(set(card["scopes"]) | set(details["scopes"]))
        for grant in details["grant_reviews"]:
            suggestion = {"kind": "role_review", "value": "high-impact declared access", "scope": grant["scope"],
                          "source": "Collected principal grant", "evidence_id": grant["resource_id"], "confidence": "declared_grant_only"}
            if suggestion not in card["suggestions"]:
                card["suggestions"].append(suggestion)
    for card in principals.values():
        details = exposure_cards.get(card["id"] if provider == "k8s" else canonical(provider, card["principal"]), {})
        card.update(exposures=details.get("exposures", []), severity=details.get("severity", "info"),
                    base_severity=details.get("base_severity", "info"))
    coverage["limitations"].extend(LIMITATIONS)
    output = sorted(principals.values(), key=lambda x: (RANK.get(x["severity"], 4), x["label"].casefold(), x["principal"].casefold()))
    for card in output:
        card["scopes"].sort()
        card["suggestions"].sort(key=lambda x: (x["kind"], x["value"]))
        card["recommendation_count"] = sum(s["confidence"] == "provider_recommendation" for s in card["suggestions"])
    projection = {"items": output, "total": len(output), "coverage": coverage}
    if provider == 'aws':
        from peaso.least_privilege_permissions import with_aws_tracked_reviews
        projection = with_aws_tracked_reviews(projection, normalized, snapshot.get('created_at'))
    return projection
