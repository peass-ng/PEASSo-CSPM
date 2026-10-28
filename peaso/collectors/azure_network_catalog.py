"""ARM network services and parent-scoped transit/DNS endpoint lists."""
import json
from pathlib import Path

PRIVATE_SERVICES = json.loads(Path(__file__).with_name('azure_network_private_services.json').read_text())
ENDPOINTS = {
    "traffic_manager_profile": ("Microsoft.Network/trafficManagerProfiles", "2022-04-01"),
    "monitor_private_link_scope": ("Microsoft.Insights/privateLinkScopes", "2021-09-01"),
    "monitor_data_collection_endpoint": ("Microsoft.Insights/dataCollectionEndpoints", "2022-06-01"),
    "container_app": ("Microsoft.App/containerApps", "2024-03-01"),
    "container_app_environment": ("Microsoft.App/managedEnvironments", "2024-03-01"),
    "container_app_job": ("Microsoft.App/jobs", "2024-03-01"),
    "redis_enterprise_cluster": ("Microsoft.Cache/redisEnterprise", "2025-07-01"),
    "local_network_gateway": ("Microsoft.Network/localNetworkGateways", "2023-09-01"),
    "network_connection": ("Microsoft.Network/connections", "2023-09-01"),
    "expressroute_circuit": ("Microsoft.Network/expressRouteCircuits", "2023-09-01"),
    "virtual_wan": ("Microsoft.Network/virtualWans", "2023-09-01"),
    "virtual_hub": ("Microsoft.Network/virtualHubs", "2023-09-01"),
    "hub_vpn_gateway": ("Microsoft.Network/vpnGateways", "2023-09-01"),
    "hub_expressroute_gateway": ("Microsoft.Network/expressRouteGateways", "2023-09-01"),
    "vpn_site": ("Microsoft.Network/vpnSites", "2023-09-01"),
    "dns_resolver": ("Microsoft.Network/dnsResolvers", "2022-07-01"),
    "dns_forwarding_ruleset": ("Microsoft.Network/dnsForwardingRulesets", "2022-07-01"),
}
ENDPOINTS.update({kind: (row['resource_type'], row['api_version']) for kind, row in PRIVATE_SERVICES.items()})
CHILDREN = {
    'redis_enterprise_database': ('redis_enterprise_cluster', 'databases', '2025-07-01'),
    'hub_bgp_connection': ('virtual_hub', 'bgpConnections', '2023-09-01'),
    'hub_route_table': ('virtual_hub', 'hubRouteTables', '2023-09-01'),
    'hub_route_map': ('virtual_hub', 'routeMaps', '2025-09-01'),
    'synapse_managed_private_endpoint': ('synapse_workspace', 'managedPrivateEndpoints', '2020-12-01'),
    'load_test_network_test': ('load_test_resource', 'tests', '2022-11-01'),
    'hub_vpn_connection': ('hub_vpn_gateway', 'vpnConnections', '2023-09-01'),
    'hub_vpn_link_connection': ('hub_vpn_connection', 'vpnLinkConnections', '2023-09-01'),
    'hub_expressroute_connection': ('hub_expressroute_gateway', 'expressRouteConnections', '2023-09-01'),
    'cassandra_data_center': ('cassandra_cluster', 'dataCenters', '2026-03-15'),
    'grafana_managed_private_endpoint': ('managed_grafana', 'managedPrivateEndpoints', '2025-08-01'),
    'elastic_san_volume_group': ('elastic_san', 'volumeGroups', '2025-09-01'),
    "monitor_scoped_resource": ("monitor_private_link_scope", "scopedResources", "2021-09-01"),
    "datafactory_managed_vnet": ("data_factory", "managedVirtualNetworks", "2018-06-01"),
    "datafactory_managed_private_endpoint": ("datafactory_managed_vnet", "managedPrivateEndpoints", "2018-06-01"),
    "registry_agent_pool": ("container_registry", "agentPools", "2023-07-01"),
    "hub_vnet_connection": ("virtual_hub", "hubVirtualNetworkConnections", "2023-09-01"),
    "dns_inbound_endpoint": ("dns_resolver", "inboundEndpoints", "2022-07-01"),
    "dns_outbound_endpoint": ("dns_resolver", "outboundEndpoints", "2022-07-01"),
    "dns_forwarding_rule": ("dns_forwarding_ruleset", "forwardingRules", "2022-07-01"),
    "dns_forwarding_vnet_link": ("dns_forwarding_ruleset", "virtualNetworkLinks", "2022-07-01"),
    "private_dns_record_set": ("private_dns_zone", "ALL", "2018-09-01"),
}
PRIVATE_CHILDREN = json.loads(Path(__file__).with_name('azure_network_private_children.json').read_text())
CHILDREN.update({kind: (row['parent'], row['segment'], row['api_version']) for kind, row in PRIVATE_CHILDREN.items()})


def required_parents(wanted):
    roots, pending, seen = set(), list(wanted), set()
    while pending:
        kind = pending.pop()
        if kind in seen or kind not in CHILDREN:
            continue
        seen.add(kind)
        parent = CHILDREN[kind][0]
        if parent in CHILDREN:
            pending.append(parent)
        else:
            roots.add(parent)
    return roots


def collect_children(reader, request, scopes, wanted):
    pending = set(wanted) & CHILDREN.keys()
    while True:
        expanded = pending | {CHILDREN[kind][0] for kind in pending if CHILDREN[kind][0] in CHILDREN}
        if expanded == pending:
            break
        pending = expanded
    while pending:
        ready = {kind for kind in pending if CHILDREN[kind][0] not in pending}
        if not ready:
            raise ValueError("cyclic network child inventory")
        _collect_phase(reader, request, scopes, ready)
        pending -= ready


def _collect_phase(reader, request, scopes, kinds):
    import re
    from .azure import ARM, AzureReadError
    jobs = []
    for kind in sorted(kinds):
        parent_kind, segment, version = CHILDREN[kind]
        for scope in scopes:
            sources = [c for c in reader.collections if c["type"] == parent_kind and c["scope"].casefold() == scope.casefold()]
            def fetch(sources=sources, scope=scope, parent_kind=parent_kind, segment=segment, version=version):
                if not sources or any(c["status"] not in {"collected", "empty"} for c in sources):
                    raise AzureReadError("network_parent_inventory_incomplete")
                any_page = False
                for collection in sources:
                    for parent in collection["items"]:
                        rid = parent.get("id")
                        if not isinstance(rid, str) or not rid.casefold().startswith(scope.casefold() + "/"):
                            raise ValueError("network parent outside subscription")
                        if parent_kind in {'synapse_workspace', 'load_test_resource'}:
                            from .azure_network_data import child_pages
                            for page in child_pages(reader, request, parent, parent_kind):
                                any_page = True
                                yield page
                            continue
                        prefix = rid + "/" + segment + "/"
                        for page in reader.pages(request, ARM + rid + "/" + segment + "?api-version=" + version):
                            def valid_child(row):
                                identity = row.get("id")
                                if not isinstance(identity, str):
                                    return False
                                if segment == "ALL":
                                    return bool(re.fullmatch(re.escape(rid) + r"/(?:A|AAAA|CNAME|MX|PTR|SOA|SRV|TXT)/[^/]+", identity, re.I))
                                return identity.casefold().startswith(prefix.casefold())
                            if any(not valid_child(row) for row in page):
                                raise ValueError("network child outside parent")
                            any_page = True
                            yield page
                if not any_page:
                    yield []
            from .azure import ENDPOINTS as root_endpoints
            root_kind = parent_kind
            while root_kind in CHILDREN:
                root_kind = CHILDREN[root_kind][0]
            service = root_endpoints[root_kind][0].split('/')[0]
            jobs.append((kind, scope, service, fetch))
    reader.run(jobs)

