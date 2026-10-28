"""Read-only, secret-free Managed Application definition inventory."""

import re
from urllib.parse import urlsplit


KIND = "managed_application_definition"
VERSION = "2019-07-01"


def project(row, group):
    rid = row.get("id") if isinstance(row, dict) else None
    props = row.get("properties") if isinstance(row, dict) else None
    prefix = group.rstrip("/") + "/providers/Microsoft.Solutions/applicationDefinitions/"
    if (not isinstance(rid, str) or re.fullmatch(re.escape(prefix) + r"[^/?#%\\\s]+", rid, re.I) is None
            or str(row.get("type", "")).casefold() != "microsoft.solutions/applicationdefinitions"
            or not isinstance(props, dict)):
        raise ValueError("foreign or malformed managed application definition")
    policy = props.get("notificationPolicy")
    endpoints = policy.get("notificationEndpoints") if isinstance(policy, dict) else None
    if endpoints is not None and not isinstance(endpoints, list):
        raise ValueError("managed application notification endpoints malformed")
    hosts = []
    for endpoint in endpoints or []:
        uri = endpoint.get("uri") if isinstance(endpoint, dict) else None
        parsed = urlsplit(uri) if isinstance(uri, str) else None
        if (parsed is None or parsed.scheme != "https" or not parsed.hostname
                or not re.fullmatch(r"[a-zA-Z0-9.-]+", parsed.hostname)):
            raise ValueError("managed application notification endpoint malformed")
        hosts.append(parsed.hostname.casefold())
    grants = props.get("authorizations")
    if grants is not None and (not isinstance(grants, list) or any(
            not isinstance(grant, dict) or not isinstance(grant.get("principalId"), str)
            or not isinstance(grant.get("roleDefinitionId"), str) for grant in grants)):
        raise ValueError("managed application definition authorizations malformed")
    management = props.get("managementPolicy")
    safe = {"isEnabled": props.get("isEnabled"),
            "managementMode": management.get("mode") if isinstance(management, dict) else None,
            "notificationHosts": hosts,
            "authorizations": [{"principalId": grant["principalId"],
                                "roleDefinitionId": grant["roleDefinitionId"]} for grant in grants or []]}
    return {"id": rid, "name": row.get("name"), "type": row["type"], "properties": safe,
            "_provenance": {"source_operation": "ApplicationDefinitions_ListByResourceGroup",
                            "api_version": VERSION, "read_only": True, "selected_scope": group}}


def collect(reader, request, wanted):
    if KIND not in wanted:
        return
    groups = {item["id"].casefold(): item["id"] for collection in reader.collections
              if collection["type"] == "resource_group" for item in collection["items"]
              if isinstance(item.get("id"), str)}
    jobs = []
    for group in groups.values():
        url = ("https://management.azure.com" + group.rstrip("/")
               + "/providers/Microsoft.Solutions/applicationDefinitions?api-version=" + VERSION)

        def pages(group=group, url=url):
            seen = set()
            for page in reader.pages(request, url):
                projected = [project(row, group) for row in page]
                for row in projected:
                    if row["id"].casefold() in seen:
                        raise ValueError("duplicate managed application definition")
                    seen.add(row["id"].casefold())
                yield projected

        jobs.append((KIND, group, "Microsoft.Solutions", pages))
    reader.run(jobs)
