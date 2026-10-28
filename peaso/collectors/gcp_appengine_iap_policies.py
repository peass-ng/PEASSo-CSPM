"""Read App Engine IAP web policies at project, app, service and version scopes."""

import re

from .gcp import ReadError
from .gcp_compliance_wave import complete_parent


_SEGMENT = re.compile(r"[A-Za-z0-9._-]+")


def collection_pages(collector, scope):
    if not scope.startswith("projects/"):
        return
    project_label = scope.removeprefix("projects/")
    project_rows = complete_parent(collector, "project", scope)
    application = complete_parent(collector, "app_engine_application", scope)
    for parent in (project_rows, application):
        for receipt in parent.get("source_requests", []):
            yield [], receipt
    if application["coverage_status"] == "empty":
        return
    services = complete_parent(collector, "app_engine_service", scope)
    versions = complete_parent(collector, "app_engine_version", scope)
    for parent in (services, versions):
        for receipt in parent.get("source_requests", []):
            yield [], receipt
    projects = [row for row in project_rows["items"] if isinstance(row, dict)]
    if len(projects) != 1:
        raise ReadError("malformed", "appengine_iap_project_identity_ambiguous")
    project = projects[0]
    name = project.get("name")
    project_id = project.get("projectId")
    if (not isinstance(name, str) or not re.fullmatch(r"projects/[0-9]+", name)
            or not isinstance(project_id, str) or not _SEGMENT.fullmatch(project_id)
            or project_label not in (project_id, name.removeprefix("projects/"))):
        raise ReadError("malformed", "appengine_iap_project_identity_unbound")
    if len(application["items"]) != 1 or application["items"][0].get("name") != f"apps/{project_id}":
        raise ReadError("malformed", "appengine_iap_application_identity_unbound")
    root = f"projects/{name.removeprefix('projects/')}/iap_web"
    app = root + f"/appengine-{project_id}"
    targets = [(root, "project", None, None), (app, "application", None, None)]
    for service in services["items"]:
        service_name = service.get("name") if isinstance(service, dict) else None
        if (not isinstance(service_name, str) or not service_name.startswith(f"apps/{project_id}/services/")
                or not _SEGMENT.fullmatch(service_name.rsplit("/", 1)[-1])):
            raise ReadError("malformed", "appengine_iap_service_identity_unbound")
        targets.append((app + "/services/" + service_name.rsplit("/", 1)[-1],
                        "service", service_name, None))
    known_services = {row[2] for row in targets if row[1] == "service"}
    for version in versions["items"]:
        version_name = version.get("name") if isinstance(version, dict) else None
        service_name = version.get("serviceName") if isinstance(version, dict) else None
        if (not isinstance(version_name, str) or not isinstance(service_name, str)
                or service_name not in known_services or not version_name.startswith(service_name + "/versions/")
                or not _SEGMENT.fullmatch(version_name.rsplit("/", 1)[-1])):
            raise ReadError("malformed", "appengine_iap_version_identity_unbound")
        targets.append((app + "/services/" + service_name.rsplit("/", 1)[-1]
                        + "/versions/" + version_name.rsplit("/", 1)[-1],
                        "version", service_name, version_name))
    for target, level, service_name, version_name in targets:
        url = f"https://iap.googleapis.com/v1/{target}:getIamPolicy"
        row = collector.hydrate({"name": target, "level": level, "application": f"apps/{project_id}",
                                 **({"service": service_name} if service_name else {}),
                                 **({"version": version_name} if version_name else {})},
                                "iamPolicy", url, scope, method="POST",
                                body={"options": {"requestedPolicyVersion": 3}})
        receipts = row.get("_coverage", {}).get("iamPolicy", {}).get("source_requests", [])
        yield [row], receipts[0] if receipts else "local:appengine_iap_policy_read_failed"
