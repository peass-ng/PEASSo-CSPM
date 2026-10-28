"""Credential-free Sentinel automation playbook routing inventory."""
from __future__ import annotations

import re

from .azure_sentinel_metadata_native import ARM, VERSION, _WORKSPACE

KIND = "sentinel_automation_rule"
_CHILD = re.compile(r"/providers/Microsoft\.SecurityInsights/automationRules/[^/?#%\s]+$", re.I)
_PLAYBOOK = re.compile(r"^/subscriptions/[0-9a-f-]{36}/resourceGroups/[^/?#%\s]+/providers/Microsoft\.Logic/workflows/[^/?#%\s]+$", re.I)
_GUID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", re.I)


def _project(raw, workspace):
    if not isinstance(raw, dict):
        raise ValueError("malformed Sentinel automation rule")
    rid = raw.get("id")
    prefix = workspace + "/providers/Microsoft.SecurityInsights/automationRules/"
    if not isinstance(rid, str) or not _CHILD.search(rid) or not rid.casefold().startswith(prefix.casefold()):
        raise ValueError("foreign Sentinel automation rule")
    props = raw.get("properties")
    if not isinstance(props, dict) or not isinstance(props.get("triggeringLogic"), dict) or not isinstance(props.get("actions"), list):
        raise ValueError("Sentinel automation fields missing")
    logic = props["triggeringLogic"]
    if type(logic.get("isEnabled")) is not bool:
        raise ValueError("Sentinel automation enabled state missing")
    expiration = logic.get("expirationTimeUtc")
    if expiration is not None and not isinstance(expiration, str):
        raise ValueError("Sentinel automation expiration malformed")
    playbooks = []
    unknown = False
    for action in props["actions"]:
        if not isinstance(action, dict) or not isinstance(action.get("actionType"), str):
            raise ValueError("Sentinel automation action malformed")
        if action["actionType"] != "RunPlaybook":
            unknown |= action["actionType"] not in ("ModifyProperties", "AddIncidentTask")
            continue
        config = action.get("actionConfiguration")
        if not isinstance(config, dict):
            raise ValueError("Sentinel playbook action malformed")
        target = config.get("logicAppResourceId")
        tenant = config.get("tenantId")
        if not isinstance(target, str) or not _PLAYBOOK.fullmatch(target):
            raise ValueError("Sentinel playbook target malformed")
        if tenant is not None and (not isinstance(tenant, str) or not _GUID.fullmatch(tenant)):
            raise ValueError("Sentinel playbook tenant malformed")
        playbooks.append({"resource_id": target, "tenant_id": tenant.lower() if tenant else None})
    return {"id": rid, "workspace_id": workspace, "enabled": logic["isEnabled"],
            "expiration_time_utc": expiration, "playbooks": playbooks,
            "unknown_action": unknown}


def collect(reader, request, wanted):
    if KIND not in wanted:
        return
    sentinel = [row for row in reader.collections if row["type"] == "sentinel_workspace"]
    parents = sentinel if sentinel else [row for row in reader.collections if row["type"] == "log_analytics_workspace"]
    jobs = []
    for parent in parents:
        if parent["status"] not in ("collected", "empty"):
            reader.collections.append({"type": KIND, "scope": parent["scope"],
                                       "service": "Microsoft.SecurityInsights", "status": parent["status"],
                                       "items": [], "error": {"code": "workspace_inventory_incomplete"}})
            continue
        for item in parent["items"]:
            workspace = item.get("id")
            if not isinstance(workspace, str) or not _WORKSPACE.fullmatch(workspace):
                reader.collections.append({"type": KIND, "scope": parent["scope"],
                                           "service": "Microsoft.SecurityInsights", "status": "not_collected",
                                           "items": [], "error": {"code": "workspace_identity_unresolved"}})
                continue
            endpoint = ARM + workspace + "/providers/Microsoft.SecurityInsights/automationRules?api-version=" + VERSION

            def rules(endpoint=endpoint, workspace=workspace, onboarded=bool(sentinel)):
                if not onboarded:
                    onboarding = ARM + workspace + "/providers/Microsoft.SecurityInsights/onboardingStates?api-version=" + VERSION
                    seen_onboarding = False
                    for page in reader.pages(request, onboarding):
                        seen_onboarding |= any(str(row.get("name", "")).casefold() == "default" for row in page)
                    if not seen_onboarding:
                        yield []
                        return
                seen = set()
                for page in reader.pages(request, endpoint):
                    output = [_project(raw, workspace) for raw in page]
                    for row in output:
                        if row["id"].casefold() in seen:
                            raise ValueError("duplicate Sentinel automation rule")
                        seen.add(row["id"].casefold())
                    yield output

            jobs.append((KIND, workspace, "Microsoft.SecurityInsights", rules))
        if not parent["items"]:
            reader.collections.append({"type": KIND, "scope": parent["scope"],
                                       "service": "Microsoft.SecurityInsights", "status": "empty",
                                       "items": [], "parent_inventory": parent["type"]})
    reader.run(jobs)
