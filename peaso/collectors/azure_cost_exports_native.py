"""Credential-free Cost Management export destination collection."""

import re


VERSION = "2025-03-01"
ARM = "https://management.azure.com"
KIND = "cost_export"


def project(row, scope):
    rid = row.get("id") if isinstance(row, dict) else None
    props = row.get("properties") if isinstance(row, dict) else None
    if (not isinstance(rid, str) or re.fullmatch(
            re.escape(scope.rstrip("/") + "/providers/Microsoft.CostManagement/exports/")
            + r"[^/?#%\\\s]+", rid, re.I) is None
            or str(row.get("type", "")).casefold() != "microsoft.costmanagement/exports"
            or not isinstance(props, dict)):
        raise ValueError("foreign or malformed Cost Management export")
    delivery = props.get("deliveryInfo")
    dest = delivery.get("destination") if isinstance(delivery, dict) else None
    if not isinstance(dest, dict):
        raise ValueError("Cost Management export destination missing")
    safe_destination = {key: dest[key] for key in ("resourceId", "storageAccount", "container", "type")
                        if isinstance(dest.get(key), str)}
    schedule = props.get("schedule")
    definition = props.get("definition")
    return {"id": rid, "name": row.get("name"), "type": row["type"],
            "properties": {"deliveryInfo": {"destination": safe_destination},
                           "schedule": {"status": schedule.get("status")} if isinstance(schedule, dict) else None,
                           "definition": {"type": definition.get("type")} if isinstance(definition, dict) else None,
                           "provisioningState": props.get("provisioningState")},
            "_provenance": {"source_operation": "Exports_List", "api_version": VERSION,
                            "read_only": True, "selected_scope": scope}}


def collect(reader, request, selected_subscriptions, wanted):
    if KIND not in wanted:
        return
    scopes = list(selected_subscriptions)
    scopes.extend(item["id"] for collection in reader.collections
                  if collection["type"] in ("resource_group", "management_group")
                  for item in collection["items"] if isinstance(item.get("id"), str))
    scopes = list({scope.casefold(): scope for scope in scopes}.values())
    jobs = []
    for scope in scopes:
        url = ARM + scope.rstrip("/") + "/providers/Microsoft.CostManagement/exports?api-version=" + VERSION

        def pages(scope=scope, url=url):
            seen = set()
            for page in reader.pages(request, url):
                projected = [project(row, scope) for row in page]
                for row in projected:
                    if row["id"].casefold() in seen:
                        raise ValueError("duplicate Cost Management export")
                    seen.add(row["id"].casefold())
                yield projected

        jobs.append((KIND, scope, "Microsoft.CostManagement", pages))
    reader.run(jobs)
