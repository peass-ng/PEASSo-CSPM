"""Read IAP web IAM policies for inventoried protected web resources."""

import re
from urllib.parse import urlsplit

from .gcp import ReadError


def collection_pages(collector, scope):
    project = collector.collections.get(("project", scope))
    if not project or project["coverage_status"] not in ("collected", "empty") or len(project["items"]) != 1:
        raise ReadError("unavailable", "iap_project_identity_unavailable")
    data = project["items"][0]
    number = str(data.get("projectNumber") or "")
    if not number.isdecimal():
        match = re.fullmatch(r"projects/([0-9]+)", str(data.get("name") or ""))
        number = match[1] if match else ""
    if not number:
        raise ReadError("unavailable", "iap_project_number_unavailable")
    root = f"projects/{number}/iap_web"
    targets = {root: {"name": root, "target_kind": "web_root"}}

    def add(path, kind, source_name, *, enabled):
        targets.setdefault(path, {"name": path, "target_kind": kind,
                                  "source_name": source_name, "iap_enabled": enabled})

    def rows(kind):
        collection = collector.collections.get((kind, scope))
        return collection["items"] if collection and collection["coverage_status"] in ("collected", "empty") else []

    for backend in rows("backend_service"):
        if (backend.get("iap") or {}).get("enabled") is not True:
            continue
        link = backend.get("selfLink")
        match = re.fullmatch(r"/compute/v1/projects/([^/]+)/(global|regions/([a-z0-9-]+))/backendServices/([A-Za-z0-9_-]+)",
                             urlsplit(link).path) if isinstance(link, str) else None
        if not match or match[1] not in {scope.removeprefix("projects/"), number}:
            raise ReadError("malformed", "iap_backend_identity")
        parent = root + "/compute" + ("-" + match[3] if match[3] else "")
        add(parent, "backend_group", link, enabled=True)
        add(parent + "/services/" + match[4], "backend_service", link, enabled=True)

    for rule in rows("forwarding_rule"):
        target = rule.get("target")
        if not isinstance(target, str) or not re.search(r"/target(?:Http|Https)Proxies/", target):
            continue
        link = rule.get("selfLink")
        match = re.fullmatch(r"/compute/v1/projects/([^/]+)/(global|regions/([a-z0-9-]+))/forwardingRules/([A-Za-z0-9_-]+)",
                             urlsplit(link).path) if isinstance(link, str) else None
        if not match or match[1] not in {scope.removeprefix("projects/"), number}:
            raise ReadError("malformed", "iap_forwarding_rule_identity")
        parent = root + "/forwarding_rule" + ("-" + match[3] if match[3] else "")
        add(parent, "forwarding_group", link, enabled=None)
        add(parent + "/services/" + match[4], "forwarding_rule", link, enabled=None)

    for kind in ("cloudrun_service", "cloudrun_instance"):
        for service in rows(kind):
            if service.get("iapEnabled") is not True:
                continue
            name = service.get("name")
            match = re.fullmatch(r"projects/([^/]+)/locations/([a-z0-9-]+)/services/([A-Za-z0-9_-]+)", name) if isinstance(name, str) else None
            if not match or match[1] not in {scope.removeprefix("projects/"), number}:
                raise ReadError("malformed", "iap_cloud_run_identity")
            parent = root + "/cloud_run-" + match[2]
            add(parent, "cloud_run_region", name, enabled=True)
            add(parent + "/services/" + match[3], "cloud_run_service", name, enabled=True)

    apps = [app for app in rows("app_engine_application") if (app.get("iap") or {}).get("enabled") is True]
    for app in apps:
        app_id = app.get("id")
        if not isinstance(app_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", app_id):
            raise ReadError("malformed", "iap_app_engine_identity")
        parent = root + "/appengine-" + app_id
        add(parent, "app_engine_app", app.get("name"), enabled=True)
        for service in rows("app_engine_service"):
            name = service.get("name")
            match = re.fullmatch(r"apps/" + re.escape(app_id) + r"/services/([A-Za-z0-9_-]+)", name) if isinstance(name, str) else None
            if match:
                add(parent + "/services/" + match[1], "app_engine_service", name, enabled=True)
        for version in rows("app_engine_version"):
            name = version.get("name")
            match = re.fullmatch(r"apps/" + re.escape(app_id) + r"/services/([A-Za-z0-9_-]+)/versions/([A-Za-z0-9_-]+)", name) if isinstance(name, str) else None
            if match:
                add(parent + "/services/" + match[1], "app_engine_service", name.rsplit("/versions/", 1)[0], enabled=True)
                add(parent + "/services/" + match[1] + "/versions/" + match[2],
                    "app_engine_version", name, enabled=True)

    targets[root]["iap_enabled"] = any(row.get("iap_enabled") is True for row in targets.values())
    project_settings = f"projects/{number}"
    targets[project_settings] = {"name": project_settings, "target_kind": "project_settings",
                                 "iap_enabled": targets[root]["iap_enabled"]}
    for name in sorted(targets, key=lambda value: (value.count("/"), value)):
        row = targets[name]
        if name != project_settings:
            row = collector.hydrate(row, "iamPolicy",
                                    "https://iap.googleapis.com/v1/" + name + ":getIamPolicy",
                                    scope, method="POST", body={"options": {"requestedPolicyVersion": 3}})
        row = collector.hydrate(row, "iapSettings",
                                "https://iap.googleapis.com/v1/" + name + ":iapSettings", scope)
        settings = row.get("iapSettings")
        if isinstance(settings, dict) and settings.get("collection_status") in (None, "collected"):
            access = settings.get("accessSettings")
            access = access if isinstance(access, dict) else {}
            gcip = access.get("gcipSettings")
            workforce = access.get("workforceIdentitySettings")
            cors = access.get("corsSettings")
            row["iapSettings"] = {
                "identitySources": [source for source in access.get("identitySources", [])
                                    if isinstance(source, str)] if isinstance(access.get("identitySources"), list) else [],
                "gcipConfigured": (isinstance(gcip, dict) and
                                   bool(gcip.get("tenantIds") or gcip.get("loginPageUri"))),
                "workforceConfigured": isinstance(workforce, dict) and bool(workforce),
                "allowHttpOptions": isinstance(cors, dict) and cors.get("allowHttpOptions") is True,
            }
        refs = [ref for detail in row.get("_coverage", {}).values() if isinstance(detail, dict)
                for ref in detail.get("source_requests", [])]
        yield [row], refs[0] if refs else "local:iap_web_policy_read_failed"
