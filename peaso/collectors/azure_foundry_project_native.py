"""Read-only Foundry project inventory from selected Cognitive Services accounts."""
from __future__ import annotations

import re
from urllib.parse import urlsplit


KIND = "foundry_project"
VERSION = "2025-06-01"
_ACCOUNT = re.compile(r"/subscriptions/[^/?#%\\\s]+/resourceGroups/[^/?#%\\\s]+/providers/Microsoft\.CognitiveServices/accounts/[^/?#%\\\s]+", re.I)
_PROJECT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{1,63}")


def _host(raw):
    try:
        parsed = urlsplit(raw) if isinstance(raw, str) else None
        host = parsed.hostname if parsed and parsed.scheme == "https" and not parsed.username and not parsed.password and parsed.port in (None, 443) else None
    except ValueError:
        host = None
    return host.lower() if isinstance(host, str) and re.fullmatch(r"[a-z0-9.-]{1,253}", host.lower()) else None


def collect(reader, request, wanted, arm):
    if KIND not in wanted:
        return
    jobs = []
    for parent in [c for c in reader.collections if c["type"] == "cognitive_account"]:
        if parent["status"] not in ("collected", "partial", "empty"):
            reader.collections.append({"type": KIND, "scope": parent["scope"],
                                       "service": "Microsoft.CognitiveServices", "status": "not_collected",
                                       "items": [], "error": {"code": "parent_account_unavailable"}})
            continue
        found = False
        for account in parent["items"]:
            if str(account.get("kind", "")).casefold() != "aiservices":
                continue
            found = True
            rid = account.get("id")
            if not isinstance(rid, str) or not _ACCOUNT.fullmatch(rid):
                reader.collections.append({"type": KIND, "scope": rid or parent["scope"],
                                           "service": "Microsoft.CognitiveServices", "status": "not_collected",
                                           "items": [], "error": {"code": "account_identity_unresolved"}})
                continue
            url = arm + rid + "/projects?api-version=" + VERSION

            def pages(url=url, rid=rid):
                seen = set()
                for page in reader.pages(request, url):
                    safe = []
                    for raw in page:
                        pid = raw.get("id") if isinstance(raw, dict) else None
                        name = raw.get("name") if isinstance(raw, dict) else None
                        if (not isinstance(pid, str) or not isinstance(name, str)
                                or not _PROJECT.fullmatch(name)
                                or pid.casefold() != (rid + "/projects/" + name).casefold()
                                or str(raw.get("type", "")).casefold() != "microsoft.cognitiveservices/accounts/projects"
                                or pid.casefold() in seen):
                            raise ValueError("malformed or duplicate Foundry project identity")
                        seen.add(pid.casefold())
                        props = raw.get("properties")
                        if not isinstance(props, dict):
                            raise ValueError("Foundry project properties unavailable")
                        endpoint_map = props.get("endpoints")
                        hosts = []
                        if isinstance(endpoint_map, dict):
                            hosts = sorted({host for value in endpoint_map.values()
                                            if (host := _host(value)) is not None})
                        safe.append({"id": pid, "name": name, "type": raw["type"], "parent_id": rid,
                                     "properties": {"provisioningState": props.get("provisioningState"),
                                                    "endpointHosts": hosts},
                                     "_provenance": {"source_operation": "Projects_List", "api_version": VERSION,
                                                     "read_only": True, "representation": "metadata"}})
                    yield safe

            jobs.append((KIND, rid, "Microsoft.CognitiveServices", pages))
        if parent["status"] == "partial":
            reader.collections.append({"type": KIND, "scope": parent["scope"],
                                       "service": "Microsoft.CognitiveServices", "status": "partial",
                                       "items": [], "error": {"code": "parent_account_partial"}})
        elif not found and parent["status"] in ("collected", "empty"):
            reader.collections.append({"type": KIND, "scope": parent["scope"],
                                       "service": "Microsoft.CognitiveServices", "status": "empty",
                                       "items": [], "parent_inventory": "cognitive_account"})
    reader.run(jobs)
