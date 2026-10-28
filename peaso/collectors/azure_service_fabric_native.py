"""Safe Service Fabric cluster endpoint inventory."""
from __future__ import annotations

import re
from urllib.parse import urlsplit


CLASSIC = "service_fabric_cluster"
MANAGED = "service_fabric_managed_cluster"
KINDS = {CLASSIC: ("clusters", "2018-02-01"), MANAGED: ("managedClusters", "2026-02-01")}


def _management_endpoint(value):
    try:
        parsed = urlsplit(value) if isinstance(value, str) else None
        host = parsed.hostname if parsed and parsed.scheme in ("http", "https") and not parsed.username and not parsed.password else None
        port = parsed.port or (443 if parsed.scheme == "https" else 80) if parsed else None
    except ValueError:
        return None, None
    if isinstance(host, str) and re.fullmatch(r"[a-z0-9.-]{1,253}", host.lower()) and type(port) is int and 1 <= port <= 65535:
        return host.lower(), port
    return None, None


def collect(reader, request, scopes, wanted, arm):
    jobs = []
    for kind, (resource_type, version) in KINDS.items():
        if kind not in wanted:
            continue
        for scope in scopes:
            url = arm + scope + "/providers/Microsoft.ServiceFabric/" + resource_type + "?api-version=" + version

            def pages(url=url, kind=kind, scope=scope, resource_type=resource_type, version=version):
                seen = set()
                for page in reader.pages(request, url):
                    safe = []
                    for raw in page:
                        rid = raw.get("id") if isinstance(raw, dict) else None
                        props = raw.get("properties") if isinstance(raw, dict) else None
                        pattern = (re.escape(scope) + r"/resourceGroups/[^/?#%\\\s]+/providers/Microsoft\.ServiceFabric/"
                                   + resource_type + r"/[^/?#%\\\s]+")
                        if (not isinstance(rid, str) or not re.fullmatch(pattern, rid, re.I)
                                or str(raw.get("type", "")).casefold() != ("Microsoft.ServiceFabric/" + resource_type).casefold()
                                or not isinstance(props, dict) or rid.casefold() in seen):
                            raise ValueError("malformed or duplicate Service Fabric cluster identity")
                        seen.add(rid.casefold())
                        fields = {"provisioningState": props.get("provisioningState"),
                                  "clusterState": props.get("clusterState")}
                        if kind == CLASSIC:
                            fields["managementHost"], fields["managementPort"] = _management_endpoint(props.get("managementEndpoint"))
                            nodes = props.get("nodeTypes")
                            fields["nodePorts"] = [
                                {"client": node.get("clientConnectionEndpointPort"),
                                 "http": node.get("httpGatewayEndpointPort")}
                                for node in nodes if isinstance(node, dict)] if isinstance(nodes, list) else None
                        else:
                            for name in ("fqdn", "ipv4Address", "ipv6Address", "clientConnectionPort",
                                         "httpGatewayConnectionPort", "httpGatewayTokenAuthConnectionPort"):
                                fields[name] = props.get(name)
                        safe.append({"id": rid, "name": raw.get("name"), "type": raw["type"],
                                     "properties": fields,
                                     "_provenance": {"source_operation": "Clusters_ListBySubscription",
                                                     "api_version": version, "read_only": True,
                                                     "representation": "metadata"}})
                    yield safe

            jobs.append((kind, scope, "Microsoft.ServiceFabric", pages))
    reader.run(jobs)
