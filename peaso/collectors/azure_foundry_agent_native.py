"""Credential-free Foundry agent endpoint configuration from selected projects."""
from __future__ import annotations

import re
from urllib.parse import parse_qsl, quote, urlsplit


KIND = "foundry_agent"
AUDIENCE = "https://ai.azure.com"
_NAME = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?")
_PROJECT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{1,63}")


def allowed_route(url, hosts):
    parsed = urlsplit(url)
    try:
        pairs = parse_qsl(parsed.query, strict_parsing=True)
    except ValueError:
        return False
    query = dict(pairs)
    if (parsed.scheme != "https" or parsed.netloc.lower() not in hosts or parsed.port not in (None, 443)
            or parsed.username or parsed.password or parsed.fragment or len(query) != len(pairs)
            or query.get("api-version") != "v1"):
        return False
    segments = parsed.path.split("/")
    if len(segments) not in (5, 6) or segments[:3] != ["", "api", "projects"]:
        return False
    if not _PROJECT.fullmatch(segments[3]):
        return False
    if segments[4] == "connections" and len(segments) == 5:
        return True  # Exact read-only LIST path; server-controlled nextLink may add pagination keys.
    if segments[4] != "agents" or set(query) - {"api-version", "limit", "after"}:
        return False
    if len(segments) == 5:
        return query.get("limit") == "100" and ("after" not in query or bool(query["after"]))
    return _NAME.fullmatch(segments[5]) is not None and set(query) == {"api-version"}


def _config(raw, name, project_id, host):
    endpoint = raw.get("agent_endpoint") if isinstance(raw, dict) else None
    schemes = endpoint.get("authorization_schemes") if isinstance(endpoint, dict) else None
    protocols = endpoint.get("protocol_configuration") if isinstance(endpoint, dict) else None
    if not isinstance(schemes, list) or not isinstance(protocols, dict):
        raise ValueError("Foundry agent endpoint authorization unavailable")
    safe_schemes = []
    for scheme in schemes:
        if not isinstance(scheme, dict) or not isinstance(scheme.get("type"), str):
            raise ValueError("malformed Foundry agent authorization scheme")
        rules = scheme.get("token_validation_rules")
        safe_schemes.append({"type": scheme["type"],
                             "allowed_tenants": rules.get("allowed_tenants") if isinstance(rules, dict) else None,
                             "allowed_clients": rules.get("allowed_clients") if isinstance(rules, dict) else None})
    activity = protocols.get("activity")
    return {"id": project_id + "/agents/" + name, "name": name, "parent_id": project_id,
            "endpoint_host": host, "status": raw.get("status"),
            "protocols": sorted(protocols),
            "m365_public": activity.get("enable_m365_public_endpoint") if isinstance(activity, dict) else None,
            "authorization_schemes": safe_schemes,
            "_provenance": {"source_operation": "Agents_List+Get", "api_version": "v1",
                            "read_only": True, "representation": "metadata"}}


def collect(reader, request, transport, wanted):
    if KIND not in wanted:
        return
    jobs = []
    for parent in [c for c in reader.collections if c["type"] == "foundry_project"]:
        if parent["status"] not in ("collected", "empty"):
            reader.collections.append({"type": KIND, "scope": parent["scope"], "service": "Microsoft Foundry",
                                       "status": "not_collected", "items": [],
                                       "error": {"code": "project_inventory_unavailable"}})
            continue
        if parent["status"] == "empty":
            reader.collections.append({"type": KIND, "scope": parent["scope"], "service": "Microsoft Foundry",
                                       "status": "empty", "items": [], "parent_inventory": "foundry_project"})
            continue
        for project in parent["items"]:
            project_id = project.get("id")
            account_id = project.get("parent_id")
            name = project.get("name")
            account_name = account_id.rsplit("/", 1)[-1] if isinstance(account_id, str) else None
            host = (account_name + ".services.ai.azure.com").lower() if isinstance(account_name, str) else None
            hosts = project.get("properties", {}).get("endpointHosts")
            if (not isinstance(project_id, str) or not isinstance(name, str) or not _PROJECT.fullmatch(name)
                    or not isinstance(host, str) or not re.fullmatch(r"[a-z0-9-]{2,64}\.services\.ai\.azure\.com", host)
                    or not isinstance(hosts, list)):
                reader.collections.append({"type": KIND, "scope": project_id or parent["scope"],
                                           "service": "Microsoft Foundry", "status": "not_collected",
                                           "items": [], "error": {"code": "project_endpoint_unavailable"}})
                continue
            if hasattr(transport, "foundry_hosts"):
                transport.foundry_hosts.add(host)
            base = "https://" + host + "/api/projects/" + quote(name, safe="") + "/agents"

            def pages(base=base, project_id=project_id, host=host):
                seen = set()
                after = None
                count = 0
                while reader.budget.max_pages is None or count < reader.budget.max_pages:
                    url = base + "?api-version=v1&limit=100" + ("&after=" + quote(after, safe="") if after else "")
                    response = reader.call(request, url, audience=AUDIENCE)
                    count += 1
                    rows = response.get("data") if isinstance(response, dict) else None
                    more = response.get("has_more") if isinstance(response, dict) else None
                    if not isinstance(rows, list) or type(more) is not bool:
                        raise ValueError("malformed Foundry agents list")
                    output = []
                    for raw in rows:
                        name = raw.get("name") if isinstance(raw, dict) else None
                        if not isinstance(name, str) or not _NAME.fullmatch(name) or name in seen:
                            raise ValueError("malformed or duplicate Foundry agent identity")
                        seen.add(name)
                        detail = reader.call(request, base + "/" + quote(name, safe="") + "?api-version=v1", audience=AUDIENCE)
                        if not isinstance(detail, dict) or detail.get("name") != name:
                            raise ValueError("Foundry agent GET identity differs from LIST")
                        output.append(_config(detail, name, project_id, host))
                    yield output
                    if not more:
                        return
                    if not rows:
                        raise ValueError("truncated Foundry agents list")
                    cursor = rows[-1].get("id")
                    if not isinstance(cursor, str) or not cursor or cursor == after:
                        raise ValueError("malformed Foundry agent cursor")
                    after = cursor
                raise ValueError("Foundry agent page limit")

            jobs.append((KIND, project_id, "Microsoft Foundry", pages))
    reader.run(jobs)
