"""Read-only Defender for Cloud automation destinations without credentials."""

import re


KIND = "defender_automation"
VERSION = "2023-12-01-preview"
TARGET_FIELDS = {"EventHub": "eventHubResourceId", "LogicApp": "logicAppResourceId",
                 "Workspace": "workspaceResourceId"}


def project(row, subscription):
    rid = row.get("id") if isinstance(row, dict) else None
    props = row.get("properties") if isinstance(row, dict) else None
    pattern = re.escape(subscription.rstrip("/")) + r"/resourceGroups/[^/?#%\s]+/providers/Microsoft\.Security/automations/[^/?#%\s]+"
    if (not isinstance(rid, str) or re.fullmatch(pattern, rid, re.I) is None
            or str(row.get("type", "")).casefold() != "microsoft.security/automations"
            or not isinstance(props, dict)):
        raise ValueError("foreign or malformed Defender automation")
    actions = props.get("actions")
    if not isinstance(actions, list):
        raise ValueError("Defender automation actions unavailable")
    safe_actions = []
    for action in actions:
        kind = action.get("actionType") if isinstance(action, dict) else None
        if kind not in TARGET_FIELDS:
            raise ValueError("Defender automation action type unresolved")
        target = action.get(TARGET_FIELDS[kind])
        if (not isinstance(target, str) or re.fullmatch(
                r"/subscriptions/[^/?#%\s]+/resourceGroups/[^/?#%\s]+/providers/[^/?#%\s]+/.+",
                target, re.I) is None or any(char in target for char in "?#%")):
            raise ValueError("Defender automation target resource ID malformed")
        safe_actions.append({"actionType": kind, "resourceId": target})
    sources = props.get("sources")
    if sources is not None and not isinstance(sources, list):
        raise ValueError("Defender automation sources malformed")
    safe_sources = []
    for source in sources or []:
        if not isinstance(source, dict):
            raise ValueError("Defender automation source malformed")
        safe_sources.append({"eventSource": source.get("eventSource")})
    return {"id": rid, "name": row.get("name"), "type": row["type"],
            "properties": {"isEnabled": props.get("isEnabled"), "actions": safe_actions,
                           "sources": safe_sources},
            "_provenance": {"source_operation": "Automations_List", "api_version": VERSION,
                            "read_only": True, "selected_scope": subscription}}


def collect(reader, request, subscriptions, wanted):
    if KIND not in wanted:
        return
    jobs = []
    for subscription in subscriptions:
        url = ("https://management.azure.com" + subscription.rstrip("/")
               + "/providers/Microsoft.Security/automations?api-version=" + VERSION)

        def pages(subscription=subscription, url=url):
            seen = set()
            for page in reader.pages(request, url):
                projected = [project(row, subscription) for row in page]
                for row in projected:
                    if row["id"].casefold() in seen:
                        raise ValueError("duplicate Defender automation")
                    seen.add(row["id"].casefold())
                yield projected

        jobs.append((KIND, subscription, "Microsoft.Security", pages))
    reader.run(jobs)
