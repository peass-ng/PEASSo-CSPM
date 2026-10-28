"""Read-only Azure partner network exposure metadata."""
from __future__ import annotations

import re


ORACLE = "oracle_cloud_vm_cluster"
PALO = "palo_alto_firewall"
KINDS = (ORACLE, PALO)
SPECS = {
    ORACLE: ("Oracle.Database", "cloudVmClusters", "2024-06-01"),
    PALO: ("PaloAltoNetworks.Cloudngfw", "firewalls", "2026-06-01"),
}


def _safe(raw, scope, kind):
    provider, leaf, version = SPECS[kind]
    rid = raw.get("id") if isinstance(raw, dict) else None
    props = raw.get("properties") if isinstance(raw, dict) else None
    pattern = (re.escape(scope) + r"/(?:resourceGroups/[^/?#%\\\s]+/)?providers/"
               + re.escape(provider) + "/" + leaf + r"/[^/?#%\\\s]+")
    if (not isinstance(rid, str) or re.fullmatch(pattern, rid, re.I) is None
            or not isinstance(props, dict)):
        raise ValueError("malformed partner network resource")
    if kind == ORACLE:
        fields = {"provisioningState": props.get("provisioningState"),
                  "lifecycleState": props.get("lifecycleState"),
                  "nsgCidrs": props.get("nsgCidrs"),
                  "scanListenerPortTcp": props.get("scanListenerPortTcp"),
                  "scanListenerPortTcpSsl": props.get("scanListenerPortTcpSsl"),
                  "vnetId": props.get("vnetId"), "subnetId": props.get("subnetId")}
    else:
        network = props.get("networkProfile")
        network = network if isinstance(network, dict) else {}
        ips = network.get("publicIps")
        fields = {"provisioningState": props.get("provisioningState"),
                  "networkProfile": {"networkType": network.get("networkType"),
                                     "publicIps": [{"address": ip.get("address"),
                                                    "resourceId": ip.get("resourceId")}
                                                   for ip in ips if isinstance(ip, dict)]
                                                  if isinstance(ips, list) else None}}
    return {"id": rid, "properties": fields,
            "_provenance": {"source_operation": "ListBySubscription", "api_version": version,
                            "read_only": True, "representation": "network_metadata"}}


def collect(reader, request, scopes, wanted, arm):
    jobs = []
    for kind in KINDS:
        if kind not in wanted:
            continue
        provider, leaf, version = SPECS[kind]
        for scope in scopes:
            url = arm + scope + "/providers/" + provider + "/" + leaf + "?api-version=" + version

            def pages(url=url, scope=scope, kind=kind):
                seen = set()
                for page in reader.pages(request, url):
                    safe = []
                    for raw in page:
                        item = _safe(raw, scope, kind)
                        key = item["id"].casefold()
                        if key in seen:
                            raise ValueError("duplicate partner network resource")
                        seen.add(key)
                        safe.append(item)
                    yield safe

            jobs.append((kind, scope, provider, pages))
    reader.run(jobs)
