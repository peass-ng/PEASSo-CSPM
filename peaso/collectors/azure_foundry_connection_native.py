"""Credential-free Foundry project connection destinations."""
from __future__ import annotations

import re
from urllib.parse import quote, urlsplit

from .azure_foundry_agent_native import AUDIENCE, _PROJECT


KIND = "foundry_connection"
_ARM = re.compile(r"/subscriptions/[^/?#\s]+/resourceGroups/[^/?#\s]+/providers/[^/?#\s]+/[^/?#\s]+", re.I)


def _destination(target):
    if not isinstance(target, str):
        return None, None
    if _ARM.fullmatch(target):
        return None, target
    try:
        parsed = urlsplit(target)
        host = parsed.hostname if parsed.scheme == "https" and not parsed.username and not parsed.password and parsed.port in (None, 443) else None
    except ValueError:
        host = None
    if isinstance(host, str) and re.fullmatch(r"[a-z0-9.-]{1,253}", host.lower()):
        return host.lower(), None
    return None, None


def collect(reader, request, transport, wanted):
    if KIND not in wanted:
        return
    jobs = []
    for parent in [c for c in reader.collections if c["type"] == "foundry_project"]:
        if parent["status"] == "empty":
            reader.collections.append({"type": KIND, "scope": parent["scope"], "service": "Microsoft Foundry",
                                       "status": "empty", "items": [], "parent_inventory": "foundry_project"})
            continue
        if parent["status"] != "collected":
            reader.collections.append({"type": KIND, "scope": parent["scope"], "service": "Microsoft Foundry",
                                       "status": "not_collected", "items": [],
                                       "error": {"code": "project_inventory_unavailable"}})
            continue
        for project in parent["items"]:
            project_id, name, account_id = project.get("id"), project.get("name"), project.get("parent_id")
            account_name = account_id.rsplit("/", 1)[-1] if isinstance(account_id, str) else None
            host = (account_name + ".services.ai.azure.com").lower() if account_name else None
            if (not isinstance(project_id, str) or not isinstance(name, str) or not _PROJECT.fullmatch(name)
                    or not isinstance(host, str) or not re.fullmatch(r"[a-z0-9-]{2,64}\.services\.ai\.azure\.com", host)):
                reader.collections.append({"type": KIND, "scope": project_id or parent["scope"],
                                           "service": "Microsoft Foundry", "status": "not_collected", "items": [],
                                           "error": {"code": "project_endpoint_unavailable"}})
                continue
            transport.foundry_hosts.add(host)
            url = "https://" + host + "/api/projects/" + quote(name, safe="") + "/connections?api-version=v1"

            def pages(url=url, project_id=project_id):
                seen = set()
                for page in reader.pages(request, url, audience=AUDIENCE):
                    safe = []
                    for raw in page:
                        cid = raw.get("id") if isinstance(raw, dict) else None
                        if not isinstance(cid, str) or not cid or cid in seen:
                            raise ValueError("malformed or duplicate Foundry connection identity")
                        seen.add(cid)
                        target_host, target_resource_id = _destination(raw.get("target"))
                        creds = raw.get("credentials")
                        safe.append({"id": project_id + "/connections/" + quote(cid, safe=""), "parent_id": project_id,
                                     "name": raw.get("name"), "connection_type": raw.get("type"),
                                     "target_host": target_host, "target_resource_id": target_resource_id,
                                     "credential_type": creds.get("type") if isinstance(creds, dict) else None,
                                     "_provenance": {"source_operation": "Connections_List", "api_version": "v1",
                                                     "read_only": True, "representation": "metadata"}})
                    yield safe

            jobs.append((KIND, project_id, "Microsoft Foundry", pages))
    reader.run(jobs)
