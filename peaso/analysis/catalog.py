"""Collection planning and check metadata, initialized on explicit request.

Provider support and native metadata lookups keep their original validation.
Offline projections can import their algorithms without constructing catalogs.
"""
from .common import frameworks_for
from .internet_exposure import EXPOSURE_TYPES
from .reachability import REACHABILITY_TYPES

REQUIRED_TYPES = {
    "aws": {"least_privilege": ["iam_user", "iam_group", "iam_role", "iam_policy", "access_analyzer"],
            "exposure": ["iam_role", "bucket", "security_group"],
            "network": ["vpc", "subnet", "network_interface", "instance", "security_group", "route_table", "network_acl",
                        "internet_gateway", "nat_gateway", "vpc_endpoint", "vpc_endpoint_service", "ec2_instance_connect_endpoint",
                        "ec2_client_vpn_endpoint", "vpc_peering", "transit_gateway", "transit_gateway_attachment",
                        "transit_gateway_route_table", "vpn_connection", "vpn_gateway", "network_firewall",
                        "network_firewall_policy", "network_firewall_rule_group",
                        "elastic_ip", "ec2_eip", "load_balancer", "classic_load_balancer", "target_group", "rds_instance", "rds_cluster",
                        "lambda_function", "eks_cluster"]},
    "gcp": {"least_privilege": ["iam_policy", "service_account", "iam_role", "recommendation", "insight"],
            "exposure": ["iam_policy", "bucket", "firewall"],
            "network": ["network", "subnetwork", "instance", "firewall", "firewall_policy", "route", "router",
                        "vpn_gateway", "vpn_tunnel", "forwarding_rule", "backend_service", "backend_bucket",
                        "url_map", "health_check", "address", "target_proxy", "instance_group",
                        "shared_vpc", "gke_cluster"]},
    "azure": {"least_privilege": ["role_assignment", "role_definition", "directory_user", "directory_group", "directory_service_principal"],
              "exposure": ["role_assignment", "storage_account", "nsg"],
              "network": ["vnet", "subnet", "vnet_peering", "nsg", "nic", "vm", "public_ip", "route_table",
                          "load_balancer", "application_gateway", "private_endpoint", "virtual_network_gateway",
                          "firewall_policy", "pod", "service"]},
    "k8s": {"least_privilege": ["role", "clusterrole", "rolebinding", "clusterrolebinding", "serviceaccount"],
            "exposure": ["rolebinding", "clusterrolebinding", "service", "networkpolicy"],
            "network": ["namespace", "pod", "service", "networkpolicy", "ingress", "node",
                        "endpointslice", "network_interface"]},
}
for _requirements in REQUIRED_TYPES.values():
    _requirements["iam_graph"] = list(_requirements["least_privilege"])
for _provider, _types in REACHABILITY_TYPES.items():
    REQUIRED_TYPES[_provider]["network"] = sorted(set(REQUIRED_TYPES[_provider]["network"]) | _types)
from .network_services import SERVICE_TYPES
from .network_catalog import CONTROL_TYPES
for _provider, _types in SERVICE_TYPES.items():
    REQUIRED_TYPES[_provider]["network"] = sorted(set(REQUIRED_TYPES[_provider]["network"]) | _types)
for _provider, _types in CONTROL_TYPES.items():
    REQUIRED_TYPES[_provider]["network"] = sorted(set(REQUIRED_TYPES[_provider]["network"]) | _types)
# Internet-to-asset exposure and federated-trust review (peaso.analysis.internet_exposure / trust).
for _provider, _types in EXPOSURE_TYPES.items():
    REQUIRED_TYPES[_provider]["exposure"] = sorted(set(REQUIRED_TYPES[_provider]["exposure"]) | set(_types))
REQUIRED_TYPES["azure"]["exposure"] = sorted(set(REQUIRED_TYPES["azure"]["exposure"]) | {"container_app_runtime"})
# Inventories read by the catalog-driven privilege-escalation evaluator (peaso.privesc).
# These lists are a floor: privesc_required_types() adds every type the privesc models read (parsed from
# peaso/privesc/effective_permissions/<provider>.py), so the collection plan follows the evaluator.
REQUIRED_TYPES["aws"]["privesc"] = ["iam_user", "iam_group", "iam_role", "iam_policy", "scp_policy", "rcp_policy", "lambda_function", "instance",
                                    "glue_job", "redshift_cluster", "ssm_managed_instance", "ecs_cluster", "ecs_task_definition"]
REQUIRED_TYPES["gcp"]["privesc"] = ["organization", "folder", "project", "iam_policy", "iam_role", "service_account", "iam_deny_policy", "instance"]
REQUIRED_TYPES["azure"]["privesc"] = ["tenant", "management_group", "subscription", "resource_group", "role_assignment", "role_definition", "deny_assignment",
                                      "directory_user", "directory_group", "directory_service_principal", "directory_application", "directory_membership",
                                      "directory_role_assignment", "directory_role_definition", "resource_graph",
                                      "vm", "app_service", "aks_cluster", "storage_account", "vault", "sql_server"]
REQUIRED_TYPES["k8s"]["privesc"] = ["role", "clusterrole", "rolebinding", "clusterrolebinding", "serviceaccount", "namespace", "pod", "node"]


from peaso.principal_exposure_requirements import REQUIRED_TYPES as _PRINCIPAL_EXPOSURE_TYPES
for _provider, _types in _PRINCIPAL_EXPOSURE_TYPES.items():
    # Filter names against provider support when constructing the collection plan.
    from peaso.collectors import supported_types as _supported_types
    for _category in ("least_privilege", "privesc", "exposure"):
        REQUIRED_TYPES[_provider][_category] = sorted(set(REQUIRED_TYPES[_provider][_category]) | (_types & set(_supported_types(_provider))))

ANALYSIS_CHECKS = [
    {"id": "analysis.principal_exposure", "category": "exposure", "title": "Review public or external principal declarations", "severity": "high"},
    {"id": "analysis.coverage", "category": "least_privilege", "title": "Analysis inventory context incomplete", "severity": "info"},
    {"id": "analysis.internet_exposure", "category": "exposure", "title": "Asset reachable from the internet", "severity": "high"},
    {"id": "analysis.exposed_container_cves", "category": "exposure", "title": "Internet-facing container runs an image with known vulnerabilities", "severity": "medium"},
    {"id": "analysis.exposed_privileged_workload", "category": "exposure", "title": "Public workload uses a privileged identity", "severity": "high"},
    {"id": "analysis.federated_trust", "category": "exposure", "title": "Federated (OIDC) trust is not pinned to a subject", "severity": "high"},
]
from .finding_clarity import HOW as _CLARITY_HOW, ACTION as _CLARITY_ACTION
for _check in ANALYSIS_CHECKS:
    from peaso.finding_types import type_for as _finding_type_for
    _check["finding_type"] = _finding_type_for(_check["id"])
    _check.update({"provider": "all", "type": "projection", "frameworks": frameworks_for(_check["id"]),
        "mapping": {"hacktricks": "Defensive identity and network review"} if frameworks_for(_check["id"]) else {},
        "remediation": _CLARITY_ACTION.get(_check["id"], "Review the recorded access declaration before changing it.")})
    if _check["id"] in _CLARITY_HOW:
        _check["description"] = _CLARITY_HOW[_check["id"]]
