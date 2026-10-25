"""Read-only Cloud Workstations inventory for exact config and workstation joins."""

import re

from .gcp import ReadError
from .gcp_fanout import fanout_pages


KINDS = ("workstations_cluster", "workstations_config", "workstations_workstation")


def scope_jobs(collector, scope):
    if not scope.startswith("projects/") or not collector.needed.intersection(KINDS):
        return []

    def fetch(kind):
        root = f"https://workstations.googleapis.com/v1/{scope}"

        def complete(data):
            if data.get("unreachable"):
                raise ReadError("unavailable", "workstations_unreachable_resources")

        def checked(items, prefix, child):
            for item in items:
                name = item.get("name") if isinstance(item, dict) else None
                if (not isinstance(name, str) or not name.startswith(prefix + "/" + child + "/") or
                        not re.fullmatch(r"[^/]+", name.rsplit("/", 1)[-1])):
                    raise ReadError("malformed", "workstations_resource_identity_missing")
            return items

        for locations, request_id in collector.pages(root + "/locations", scope, key="locations",
                                                      response_validator=complete):
            yield [], request_id

            def location_pages(location):
                name = location.get("name") if isinstance(location, dict) else None
                if not isinstance(name, str) or not name.startswith(scope + "/locations/"):
                    raise ReadError("malformed", "workstations_location_identity_missing")
                for clusters, cluster_request in collector.pages(
                        f"https://workstations.googleapis.com/v1/{name}/workstationClusters", scope,
                        key="workstationClusters", response_validator=complete):
                    clusters = checked(clusters, name, "workstationClusters")
                    yield (clusters if kind == "workstations_cluster" else []), cluster_request
                    if kind == "workstations_cluster":
                        continue
                    for cluster in clusters:
                        for configs, config_request in collector.pages(
                                f"https://workstations.googleapis.com/v1/{cluster['name']}/workstationConfigs",
                                scope, key="workstationConfigs", response_validator=complete):
                            configs = checked(configs, cluster["name"], "workstationConfigs")
                            if kind == "workstations_config":
                                configs = collector.parallel(lambda item: collector.hydrate(
                                    item, "iamPolicy",
                                    f"https://workstations.googleapis.com/v1/{item['name']}:getIamPolicy",
                                    scope), configs)
                            yield (configs if kind == "workstations_config" else []), config_request
                            if kind == "workstations_config":
                                continue
                            for config in configs:
                                for workstations, workstation_request in collector.pages(
                                        f"https://workstations.googleapis.com/v1/{config['name']}/workstations",
                                        scope, key="workstations", response_validator=complete):
                                    workstations = checked(workstations, config["name"], "workstations")
                                    yield collector.parallel(lambda item: collector.hydrate(
                                        item, "iamPolicy",
                                        f"https://workstations.googleapis.com/v1/{item['name']}:getIamPolicy",
                                        scope), workstations), workstation_request

            yield from fanout_pages(collector, locations, location_pages)

    return [(kind, scope, "workstations", lambda kind=kind: fetch(kind))
            for kind in KINDS if kind in collector.needed]
