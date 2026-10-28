"""Read current Container App identity settings and running revision counts."""

from __future__ import annotations

import re


KIND = "container_app_runtime"
VERSION = "2025-07-01"
ARM = "https://management.azure.com"
APP = re.compile(
    r"/subscriptions/[^/?#%\\\s]+/resourcegroups/[^/?#%\\\s]+/providers/"
    r"microsoft\.app/containerapps/[^/?#%\\\s]+", re.I)


def _app_id(value, scope):
    if (not isinstance(value, str) or not APP.fullmatch(value)
            or not value.casefold().startswith(scope.casefold() + "/")
            or any(part in (".", "..") for part in value.split("/"))):
        raise ValueError("foreign or malformed Container App ID")
    return value


def _project(app, revisions, app_id):
    if (not isinstance(app, dict) or str(app.get("id", "")).casefold() != app_id.casefold()
            or str(app.get("type", "")).casefold() != "microsoft.app/containerapps"
            or not isinstance(app.get("properties"), dict)
            or not isinstance(app.get("identity"), dict)):
        raise ValueError("Container App GET did not establish its identity")
    identity = app["identity"]
    assigned = identity.get("userAssignedIdentities") or {}
    if not isinstance(assigned, dict):
        raise ValueError("Container App identities malformed")
    projected_identity = {
        "type": identity.get("type"), "principalId": identity.get("principalId"),
        "userAssignedIdentities": {
            key: {"principalId": value.get("principalId")}
            for key, value in assigned.items() if isinstance(key, str) and isinstance(value, dict)
        },
    }
    if len(projected_identity["userAssignedIdentities"]) != len(assigned):
        raise ValueError("Container App identities malformed")
    props = app["properties"]
    configuration = props.get("configuration") or {}
    if not isinstance(configuration, dict):
        raise ValueError("Container App configuration malformed")
    settings = configuration.get("identitySettings")
    if settings is not None and (not isinstance(settings, list) or any(
            not isinstance(setting, dict) or not isinstance(setting.get("identity"), str)
            or setting.get("lifecycle") is not None and not isinstance(setting["lifecycle"], str)
            for setting in settings)):
        raise ValueError("Container App identity settings malformed")
    safe_settings = [{"identity": setting["identity"], "lifecycle": setting.get("lifecycle")}
                     for setting in settings] if settings is not None else None
    projected_revisions = []
    seen = set()
    for revision in revisions:
        rid = revision.get("id") if isinstance(revision, dict) else None
        if (not isinstance(rid, str)
                or not re.fullmatch(re.escape(app_id) + r"/revisions/[^/?#%\\\s]+", rid, re.I)
                or rid.casefold() in seen or not isinstance(revision.get("properties"), dict)):
            raise ValueError("foreign or malformed Container App revision")
        seen.add(rid.casefold())
        rev_props = revision["properties"]
        projected_revisions.append({"id": rid, "properties": {
            key: rev_props[key] for key in ("active", "provisioningState", "runningState", "replicas",
                                           "healthState", "trafficWeight", "fqdn")
            if key in rev_props}})
    return {
        "id": app_id, "type": "Microsoft.App/containerApps", "identity": projected_identity,
        "properties": {
            "provisioningState": props.get("provisioningState"),
            "runningStatus": props.get("runningStatus"),
            "configuration": {"identitySettings": safe_settings},
        },
        "revisions": projected_revisions,
        "_provenance": {"method": "GET+LIST", "api_version": VERSION, "read_only": True},
    }


def collect(reader, request, scopes, wanted):
    if KIND not in wanted:
        return
    jobs = []
    for scope in scopes:
        def fetch(scope=scope):
            selected = []
            seen = set()
            url = ARM + scope + "/providers/Microsoft.App/containerApps?api-version=" + VERSION
            for page in reader.pages(request, url):
                for row in page:
                    app_id = _app_id(row.get("id") if isinstance(row, dict) else None, scope)
                    if str(row.get("type", "")).casefold() != "microsoft.app/containerapps":
                        raise ValueError("foreign Container App type")
                    if app_id.casefold() in seen:
                        raise ValueError("duplicate Container App")
                    seen.add(app_id.casefold())
                    selected.append(app_id)
            for app_id in selected:
                app = reader.call(request, ARM + app_id + "?api-version=" + VERSION)
                revisions = []
                for page in reader.pages(request, ARM + app_id + "/revisions?api-version=" + VERSION):
                    revisions.extend(page)
                yield [_project(app, revisions, app_id)]
        jobs.append((KIND, scope, "Microsoft.App", fetch))
    reader.run(jobs)
