"""Credential-free New Relic monitor and observed telemetry inventory."""
from __future__ import annotations

import re
import hashlib
from urllib.parse import parse_qsl, urlsplit


MONITOR = "newrelic_monitor"
RESOURCE = "newrelic_monitored_resource"
TYPES = (MONITOR, RESOURCE)
VERSION = "2026-06-01"
_MONITOR_ID = re.compile(r"(/subscriptions/[^/?#%\\\s]+/resourceGroups/[^/?#%\\\s]+/providers/NewRelic\.Observability/monitors/[^/?#%\\\s]+)", re.I)


def monitored_route(url, body, arm):
    """Accept only the vendor's documented, bodyless metadata-query POST."""
    parsed = urlsplit(url)
    try:
        pairs = parse_qsl(parsed.query, strict_parsing=True)
    except ValueError:
        return False
    query = dict(pairs)
    return (arm == "https://management.azure.com" and parsed.scheme == "https"
            and parsed.netloc == "management.azure.com" and not parsed.fragment
            and not parsed.username and not parsed.password and parsed.port in (None, 443)
            and _MONITOR_ID.fullmatch(parsed.path.removesuffix("/monitoredResources")) is not None
            and parsed.path.endswith("/monitoredResources") and query.get("api-version") == VERSION
            and len(query) == len(pairs) and set(query) <= {"api-version", "$skipToken", "$skiptoken", "skipToken"}
            and body == {})


def _monitor(raw, scope):
    rid = raw.get("id") if isinstance(raw, dict) else None
    props = raw.get("properties") if isinstance(raw, dict) else None
    if (not isinstance(rid, str) or not _MONITOR_ID.fullmatch(rid)
            or not rid.casefold().startswith(scope.casefold() + "/")
            or str(raw.get("type", "")).casefold() != "newrelic.observability/monitors"
            or not isinstance(props, dict)):
        raise ValueError("malformed New Relic monitor identity")
    account = props.get("newRelicAccountProperties")
    info = account.get("accountInfo") if isinstance(account, dict) else None
    org = account.get("organizationInfo") if isinstance(account, dict) else None
    return {"id": rid, "name": raw.get("name"), "type": raw["type"],
            "properties": {"provisioningState": props.get("provisioningState"),
                           "monitoringStatus": props.get("monitoringStatus"),
                           "marketplaceSubscriptionStatus": props.get("marketplaceSubscriptionStatus"),
                           "accountId": info.get("accountId") if isinstance(info, dict) else None,
                           "organizationId": org.get("organizationId") if isinstance(org, dict) else None},
            "_provenance": {"source_operation": "Monitors_ListBySubscription", "api_version": VERSION,
                            "read_only": True, "representation": "metadata"}}


def collect(reader, request, scopes, wanted, arm):
    if MONITOR not in wanted and RESOURCE not in wanted:
        return
    jobs = []
    for scope in scopes:
        url = arm + scope + "/providers/NewRelic.Observability/monitors?api-version=" + VERSION

        def pages(url=url, scope=scope):
            seen = set()
            for page in reader.pages(request, url):
                safe = []
                for raw in page:
                    item = _monitor(raw, scope)
                    rid = item["id"].casefold()
                    if rid in seen:
                        raise ValueError("duplicate New Relic monitor identity")
                    seen.add(rid)
                    safe.append(item)
                yield safe

        jobs.append((MONITOR, scope, "NewRelic.Observability", pages))
    reader.run(jobs)
    if RESOURCE not in wanted:
        return
    jobs = []
    for parent in [c for c in reader.collections if c["type"] == MONITOR]:
        if parent["status"] not in ("collected", "empty"):
            reader.collections.append({"type": RESOURCE, "scope": parent["scope"], "service": "NewRelic.Observability",
                                       "status": "not_collected", "items": [],
                                       "error": {"code": "monitor_inventory_unavailable"}})
            continue
        if parent["status"] == "empty":
            reader.collections.append({"type": RESOURCE, "scope": parent["scope"], "service": "NewRelic.Observability",
                                       "status": "empty", "items": [], "parent_inventory": MONITOR})
            continue
        for monitor in parent["items"]:
            mid = monitor["id"]
            props = monitor["properties"]
            if props.get("monitoringStatus") == "Disabled":
                reader.collections.append({"type": RESOURCE, "scope": mid, "service": "NewRelic.Observability",
                                           "status": "empty", "items": [], "parent_inventory": MONITOR})
                continue
            url = arm + mid + "/monitoredResources?api-version=" + VERSION

            def monitored(url=url, mid=mid):
                seen, seen_urls, count = set(), set(), 0
                origin_path = urlsplit(url).path
                while reader.budget.max_pages is None or count < reader.budget.max_pages:
                    if url in seen_urls:
                        raise ValueError("duplicate New Relic continuation")
                    seen_urls.add(url)
                    response = reader.call(request, url, body={})
                    count += 1
                    rows = response.get("value") if isinstance(response, dict) else None
                    if not isinstance(rows, list):
                        raise ValueError("malformed New Relic monitored resource page")
                    safe = []
                    for raw in rows:
                        rid = raw.get("id") if isinstance(raw, dict) else None
                        if not isinstance(rid, str) or not rid.startswith("/subscriptions/") or rid.casefold() in seen:
                            raise ValueError("malformed or duplicate New Relic monitored resource")
                        seen.add(rid.casefold())
                        digest = hashlib.sha256(rid.casefold().encode()).hexdigest()[:24]
                        safe.append({"id": mid + "/monitoredResources/" + digest,
                                     "monitor_id": mid, "resource_id": rid,
                                     "sendingLogs": raw.get("sendingLogs"),
                                     "sendingMetrics": raw.get("sendingMetrics"),
                                     "_provenance": {"source_operation": "Monitors_ListMonitoredResources",
                                                     "api_version": VERSION, "read_only": True,
                                                     "representation": "metadata"}})
                    yield safe
                    nxt = response.get("nextLink")
                    if not nxt:
                        return
                    if (not isinstance(nxt, str) or not monitored_route(nxt, {}, arm)
                            or urlsplit(nxt).path != origin_path or nxt in seen_urls):
                        raise ValueError("untrusted New Relic continuation")
                    url = nxt
                raise ValueError("New Relic monitored resource page limit")

            jobs.append((RESOURCE, mid, "NewRelic.Observability", monitored))
    reader.run(jobs)
