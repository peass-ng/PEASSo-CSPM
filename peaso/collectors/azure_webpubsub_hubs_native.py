"""Credential-free Web PubSub hub sharing metadata, excluding handler URL secrets."""
from __future__ import annotations

import re
from urllib.parse import urlsplit


ARM = "https://management.azure.com"
VERSION = "2024-03-01"
KIND = "web_pubsub"


def _target(template):
    if not isinstance(template, str):
        raise ValueError("Web PubSub handler URL missing")
    parsed = urlsplit(template)
    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError as exc:
        raise ValueError("Web PubSub handler URL port malformed") from exc
    if (parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username or parsed.password
            or not 1 <= port <= 65535 or "{" in parsed.hostname or "}" in parsed.hostname):
        raise ValueError("Web PubSub handler URL malformed")
    return {"host": parsed.hostname.lower(), "port": port, "scheme": parsed.scheme}


def _hubs(reader, request, rid):
    seen, result = set(), []
    for page in reader.pages(request, ARM + rid + "/hubs?api-version=" + VERSION):
        for row in page:
            hid = row.get("id") if isinstance(row, dict) else None
            props = row.get("properties") if isinstance(row, dict) else None
            if (not isinstance(hid, str) or re.fullmatch(re.escape(rid) + r"/hubs/[^/?#%\\\s]+", hid, re.I) is None
                    or str(row.get("type", "")).casefold() != "microsoft.signalrservice/webpubsub/hubs"
                    or hid.casefold() in seen or not isinstance(props, dict)):
                raise ValueError("malformed Web PubSub hub")
            seen.add(hid.casefold())
            policy = props.get("anonymousConnectPolicy", "deny")
            if not isinstance(policy, str) or policy.casefold() not in ("allow", "deny"):
                raise ValueError("malformed Web PubSub anonymous policy")
            handlers = props.get("eventHandlers", [])
            listeners = props.get("eventListeners", [])
            if not isinstance(handlers, list) or not isinstance(listeners, list):
                raise ValueError("malformed Web PubSub event configuration")
            safe_handlers = []
            for handler in handlers:
                if not isinstance(handler, dict):
                    raise ValueError("malformed Web PubSub event handler")
                target = _target(handler.get("urlTemplate"))
                trigger = bool(handler.get("systemEvents") or handler.get("userEventPattern") or
                               (handler.get("groupPresenceEvents") or {}).get("eventNames"))
                safe_handlers.append({**target, "hasEventFilter": trigger})
            safe_listeners = []
            for listener in listeners:
                endpoint = listener.get("endpoint") if isinstance(listener, dict) else None
                if not isinstance(endpoint, dict) or endpoint.get("type") != "EventHub":
                    raise ValueError("unsupported Web PubSub event listener")
                host = endpoint.get("fullyQualifiedNamespace")
                name = endpoint.get("eventHubName")
                if (not isinstance(host, str) or not re.fullmatch(r"[a-zA-Z0-9.-]+", host)
                        or not isinstance(name, str) or not name):
                    raise ValueError("malformed Web PubSub Event Hub target")
                safe_listeners.append({"host": host.lower(), "eventHubName": name})
            storage = (props.get("chat") or {}).get("persistentStorage") if isinstance(props.get("chat"), dict) else None
            storage_id = storage.get("id") if isinstance(storage, dict) else None
            if storage_id is not None and (not isinstance(storage_id, str) or not storage_id.startswith("/subscriptions/")):
                raise ValueError("malformed Web PubSub persistent storage ID")
            result.append({"id": hid, "name": row.get("name"), "anonymousConnectPolicy": policy.casefold(),
                           "eventHandlers": safe_handlers, "eventListeners": safe_listeners,
                           "persistentStorageId": storage_id})
    return result


def _links(reader, request, rid):
    seen, result = set(), []
    for page in reader.pages(request, ARM + rid + "/sharedPrivateLinkResources?api-version=" + VERSION):
        for row in page:
            link_id = row.get("id") if isinstance(row, dict) else None
            props = row.get("properties") if isinstance(row, dict) else None
            if (not isinstance(link_id, str) or re.fullmatch(re.escape(rid) + r"/sharedPrivateLinkResources/[^/?#%\\\s]+", link_id, re.I) is None
                    or str(row.get("type", "")).casefold() != "microsoft.signalrservice/webpubsub/sharedprivatelinkresources"
                    or link_id.casefold() in seen or not isinstance(props, dict)):
                raise ValueError("malformed Web PubSub shared private link")
            seen.add(link_id.casefold())
            target = props.get("privateLinkResourceId")
            if not isinstance(target, str) or not target.startswith("/subscriptions/"):
                raise ValueError("malformed Web PubSub shared private target")
            result.append({"id": link_id, "targetId": target, "status": props.get("status"),
                           "provisioningState": props.get("provisioningState")})
    return result


def collect(reader, request, scopes, wanted):
    if KIND not in wanted:
        return
    for collection in reader.collections:
        if collection.get("type") != KIND or collection.get("status") not in ("collected", "partial"):
            continue
        for row in collection["items"]:
            rid = row.get("id")
            if not isinstance(rid, str) or not rid.casefold().startswith(collection["scope"].casefold() + "/"):
                continue
            for field, fetch in (("hubExposure", _hubs), ("sharedPrivateLinkExposure", _links)):
                try:
                    row[field] = fetch(reader, request, rid)
                    row.setdefault("_coverage", {})[field] = {"status": "collected"}
                except Exception as exc:
                    row.pop(field, None)
                    row.setdefault("_coverage", {})[field] = {
                        "status": "unknown", "error": {"code": str(getattr(exc, "code", "read_failed"))}}
