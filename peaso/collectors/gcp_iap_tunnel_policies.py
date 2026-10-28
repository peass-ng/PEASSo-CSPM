"""Read IAP TCP tunnel policies for exact inventoried Compute instances."""

import re

from .gcp import ReadError


def collection_pages(collector, scope):
    inventory = collector.collections.get(("instance", scope))
    vm_incomplete = not inventory or inventory["coverage_status"] not in ("collected", "empty")
    instances = {}
    zones = set()
    for vm in (inventory["items"] if not vm_incomplete else []):
        link = vm.get("selfLink")
        match = re.fullmatch(
            rf"https://(?:www|compute)\.googleapis\.com/compute/v1/{re.escape(scope)}"
            r"/zones/([a-z][a-z0-9-]*[0-9]-[a-z])/instances/([A-Za-z0-9_-]+)",
            link) if isinstance(link, str) else None
        if not match or vm.get("name") != match.group(2):
            raise ReadError("malformed", "iap_instance_identity_unbound")
        zone, name = match.groups()
        resource = f"{scope}/iap_tunnel/zones/{zone}/instances/{name}"
        if resource in instances:
            raise ReadError("malformed", "duplicate_iap_instance_identity")
        instances[resource] = vm
        zones.add(zone)
    root = scope + "/iap_tunnel"
    project_collection = collector.collections.get(("project", scope))
    aliases = {scope.removeprefix("projects/")}
    if project_collection and project_collection["coverage_status"] == "collected":
        aliases.update(str(item.get("projectNumber")) for item in project_collection["items"]
                       if item.get("projectNumber"))
    resources = [root, *(f"{root}/zones/{zone}" for zone in sorted(zones)), *sorted(instances)]
    for resource in resources:
        url = "https://iap.googleapis.com/v1/" + resource + ":getIamPolicy"
        row = collector.hydrate({"name": resource}, "iamPolicy", url, scope,
                                method="POST", body={"options": {"requestedPolicyVersion": 3}})
        refs = row.get("_coverage", {}).get("iamPolicy", {}).get("source_requests", [])
        yield [row], refs[0] if refs else "local:iap_policy_read_failed"
    seen_locations = set()
    for groups, request_id in collector.pages(
            "https://iap.googleapis.com/v1/" + root + "/locations/-/destGroups",
            scope, key="tunnelDestGroups"):
        yield [], request_id
        locations = set()
        for group in groups:
            name = group.get("name")
            match = re.fullmatch(r"projects/([^/]+)/iap_tunnel/locations/[a-z0-9-]+/destGroups/[a-z-]+",
                                 name) if isinstance(name, str) else None
            if not match or match[1] not in aliases:
                raise ReadError("malformed", "iap_destination_group_identity")
            locations.add(name.rsplit("/destGroups/", 1)[0])
        for location in sorted(locations - seen_locations):
            seen_locations.add(location)
            row = collector.hydrate({"name": location}, "iamPolicy",
                                    "https://iap.googleapis.com/v1/" + location + ":getIamPolicy",
                                    scope, method="POST", body={"options": {"requestedPolicyVersion": 3}})
            refs = row.get("_coverage", {}).get("iamPolicy", {}).get("source_requests", [])
            yield [row], refs[0] if refs else "local:iap_policy_read_failed"
        for group in groups:
            name = group["name"]
            row = collector.hydrate({"name": name, "cidrs": group.get("cidrs", []),
                                     "fqdns": group.get("fqdns", []),
                                     "_coverage": {"destinationGroup": {"status": "collected",
                                                                         "source_requests": [request_id]}}}, "iamPolicy",
                                    "https://iap.googleapis.com/v1/" + name + ":getIamPolicy",
                                    scope, method="POST", body={"options": {"requestedPolicyVersion": 3}})
            refs = row.get("_coverage", {}).get("iamPolicy", {}).get("source_requests", [])
            yield [row], refs[0] if refs else request_id
    if vm_incomplete:
        raise ReadError("unavailable", "instance_inventory_incomplete")
