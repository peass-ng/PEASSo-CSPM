"""Credential-free Graph authentication extension and listener inventory."""

import re
from urllib.parse import urlsplit


GRAPH = "https://graph.microsoft.com"
GUID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", re.I)
EXTENSION = "external_id_auth_extension"
LISTENER = "external_id_auth_listener"
KINDS = frozenset((EXTENSION, LISTENER))
PATHS = {EXTENSION: "identity/customAuthenticationExtensions",
         LISTENER: "identity/authenticationEventListeners"}


def _guid(value):
    if not isinstance(value, str) or GUID.fullmatch(value) is None:
        raise ValueError("malformed external identity Graph identifier")
    return value


def project(kind, row):
    if not isinstance(row, dict) or kind not in KINDS:
        raise ValueError("malformed external identity Graph resource")
    rid = _guid(row.get("id"))
    event_type = row.get("@odata.type")
    if not isinstance(event_type, str) or not event_type.startswith("#microsoft.graph."):
        raise ValueError("external identity Graph resource subtype unavailable")
    if kind == EXTENSION:
        endpoint = row.get("endpointConfiguration")
        url = endpoint.get("targetUrl") if isinstance(endpoint, dict) else None
        parsed = urlsplit(url) if isinstance(url, str) else None
        host = parsed.hostname if parsed and parsed.scheme == "https" else None
        if not host or re.fullmatch(r"[a-zA-Z0-9.-]+", host) is None:
            raise ValueError("custom authentication endpoint unavailable")
        safe = {"endpointHost": host.casefold(), "extensionType": event_type.removeprefix("#microsoft.graph.")}
    else:
        handler = row.get("handler")
        extension = handler.get("customExtension") if isinstance(handler, dict) else None
        extension_id = extension.get("id") if isinstance(extension, dict) else None
        if extension_id is not None:
            _guid(extension_id)
        conditions = row.get("conditions")
        applications = conditions.get("applications") if isinstance(conditions, dict) else None
        includes = applications.get("includeApplications") if isinstance(applications, dict) else None
        if includes is not None and not isinstance(includes, list):
            raise ValueError("authentication listener applications malformed")
        app_ids = [_guid(app.get("appId") if isinstance(app, dict) else None) for app in includes or []]
        safe = {"extensionId": extension_id, "listenerType": event_type.removeprefix("#microsoft.graph."),
                "appIds": app_ids}
    return {"id": rid, **safe,
            "_provenance": {"source_operation": "Graph_" + PATHS[kind], "read_only": True,
                            "representation": "metadata"}}


def collect(reader, request, wanted, transport):
    if not KINDS.intersection(wanted):
        return
    tenant = getattr(transport, "tenant", None) or "selected"
    scope = "/tenants/" + tenant
    jobs = []
    for kind in sorted(KINDS.intersection(wanted)):
        url = GRAPH + "/v1.0/" + PATHS[kind]

        def pages(kind=kind, url=url):
            seen = set()
            for page in reader.pages(request, url, audience=GRAPH, next_key="@odata.nextLink"):
                projected = [project(kind, row) for row in page]
                for row in projected:
                    if row["id"].casefold() in seen:
                        raise ValueError("duplicate external identity Graph resource")
                    seen.add(row["id"].casefold())
                yield projected

        jobs.append((kind, scope, "Microsoft.Graph", pages))
    reader.run(jobs)
