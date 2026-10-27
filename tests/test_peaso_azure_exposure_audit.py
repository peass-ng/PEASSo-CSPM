"""Native Azure exposure additions use only collected configuration."""

import pytest

from peaso.analysis.internet_exposure import _nsg_allowed, assess
from peaso.snapshot import make_snapshot, resources

SCOPE = "/subscriptions/test"


def decision(kind, properties):
    item = {"id": f"{SCOPE}/resourceGroups/rg/providers/test/{kind}/asset", "properties": properties}
    snapshot = make_snapshot("azure", [SCOPE], [{"type": kind, "scope": SCOPE, "service": "test",
        "status": "collected", "items": [item]}])
    before = repr(snapshot)
    rows = assess(snapshot, resources(snapshot))
    assert repr(snapshot) == before and len(rows) == 1
    return rows[0]


def test_container_instance_public_ports_and_private_group():
    exposed = decision("container_group", {"ipAddress": {"type": "Public", "ip": "8.8.8.8",
        "ports": [{"protocol": "TCP", "port": 8080}]}})
    assert exposed.verdict() == "FAIL" and exposed.addresses == ["8.8.8.8"]
    assert exposed.ports == {"tcp": ((8080, 8080),)}
    assert decision("container_group", {"ipAddress": {"type": "Public"}}).verdict() == "UNKNOWN"


def test_app_service_unset_public_access_with_private_endpoint_is_uncertain():
    site_id = f"{SCOPE}/resourceGroups/rg/providers/Microsoft.Web/sites/app"
    snap = make_snapshot("azure", [SCOPE], [
        {"type": "app_service", "scope": SCOPE, "service": "web", "status": "collected", "items": [
            {"id": site_id, "properties": {"defaultHostName": "app.azurewebsites.net",
             "privateEndpointConnections": [{"id": "endpoint"}]}}]},
        {"type": "app_service_config", "scope": SCOPE, "service": "web", "status": "collected", "items": [
            {"id": site_id + "/config/web", "parent_id": site_id,
             "properties": {"ipSecurityRestrictions": [], "ipSecurityRestrictionsDefaultAction": "Allow"}}]}])
    row = next(a for a in assess(snap, resources(snap)) if a.resource["type"] == "app_service")
    assert row.verdict() == "UNKNOWN"


def test_app_service_specific_public_source_and_priority_shadowing():
    site_id = f"{SCOPE}/resourceGroups/rg/providers/Microsoft.Web/sites/app"

    def site_decision(rules):
        snap = make_snapshot("azure", [SCOPE], [
            {"type": "app_service", "scope": SCOPE, "service": "web", "status": "collected", "items": [
                {"id": site_id, "properties": {"defaultHostName": "app.azurewebsites.net",
                 "publicNetworkAccess": "Enabled"}}]},
            {"type": "app_service_config", "scope": SCOPE, "service": "web", "status": "collected", "items": [
                {"id": site_id + "/config/web", "parent_id": site_id,
                 "properties": {"ipSecurityRestrictions": rules, "ipSecurityRestrictionsDefaultAction": "Deny"}}]}])
        return next(a for a in assess(snap, resources(snap)) if a.resource["type"] == "app_service")

    allow = {"name": "public-ip", "ipAddress": "8.8.8.8/32", "action": "Allow", "priority": 200}
    deny = {"name": "deny-public-ip", "ipAddress": "8.8.8.8/32", "action": "Deny", "priority": 100}
    first = site_decision([allow])
    assert first.verdict() == "FAIL", first.path
    assert site_decision([deny, allow]).verdict() == "PASS"
    assert site_decision([{**deny, "ipAddress": "10.0.0.0/8"}, allow]).verdict() == "FAIL"


def test_anonymous_blob_requires_container_and_account_gates():
    account_id = f"{SCOPE}/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/a"
    container = {"id": account_id + "/blobServices/default/containers/public",
        "parent_id": account_id, "properties": {"publicAccess": "Blob"}}

    def assess_container(account_properties):
        snap = make_snapshot("azure", [SCOPE], [
            {"type": "storage_account", "scope": SCOPE, "service": "storage", "status": "collected",
             "items": [{"id": account_id, "properties": account_properties}]},
            {"type": "storage_container", "scope": SCOPE, "service": "storage", "status": "collected",
             "items": [container]}])
        return next(row for row in assess(snap, resources(snap)) if row.resource["type"] == "storage_container")

    open_account = {"allowBlobPublicAccess": True, "publicNetworkAccess": "Enabled",
        "networkAcls": {"defaultAction": "Allow"},
        "primaryEndpoints": {"blob": "https://a.blob.core.windows.net/"}}
    assert assess_container(open_account).verdict() == "FAIL"
    assert assess_container({**open_account, "allowBlobPublicAccess": False}).verdict() == "PASS"
    assert assess_container({**open_account, "networkAcls": {"defaultAction": "Deny"}}).verdict() == "PASS"
    assert assess_container({**open_account, "networkAcls": {}}).verdict() == "UNKNOWN"
    public_rule = {"value": "8.8.8.8/32", "action": "Allow"}
    assert assess_container({**open_account, "networkAcls": {"defaultAction": "Deny",
        "ipRules": [public_rule]}}).verdict() == "FAIL"
    assert assess_container({**open_account, "networkAcls": {"defaultAction": "Deny",
        "ipRules": [{"value": "not-an-ip"}]}}).verdict() == "UNKNOWN"
    assert assess_container({**open_account, "publicNetworkAccess": "SecuredByPerimeter"}).verdict() == "UNKNOWN"
    assert assess_container({**open_account, "publicNetworkAccess": "SecuredByPerimeter",
        "networkAcls": {"defaultAction": "Deny"}}).verdict() == "UNKNOWN"


def test_storage_account_deny_default_retains_public_ip_rule_exposure():
    base = {"publicNetworkAccess": "Enabled", "primaryEndpoints": {"blob": "https://a.blob.core.windows.net/"},
            "supportsHttpsTrafficOnly": True}
    assert decision("storage_account", {**base, "networkAcls": {"defaultAction": "Deny",
        "ipRules": [{"value": "8.8.8.8/32", "action": "Allow"}]}}).verdict() == "FAIL"
    assert decision("storage_account", {**base, "networkAcls": {"defaultAction": "Deny",
        "ipRules": [{"value": "10.0.0.0/8", "action": "Allow"}]}}).verdict() == "PASS"
    assert decision("storage_account", {**base, "networkAcls": {"defaultAction": "Deny",
        "ipRules": [{"value": "invalid"}]}}).verdict() == "UNKNOWN"
    assert decision("storage_account", {**base, "publicNetworkAccess": "SecuredByPerimeter",
        "networkAcls": {"defaultAction": "Allow"}}).verdict() == "UNKNOWN"
    assert decision("storage_account", {**base, "publicNetworkAccess": "SecuredByPerimeter",
        "networkAcls": {"defaultAction": "Deny"}}).verdict() == "UNKNOWN"


def test_sql_firewall_public_ip_range_is_exposure_but_private_range_is_not():
    server_id = f"{SCOPE}/resourceGroups/rg/providers/Microsoft.Sql/servers/sql"

    def sql_decision(start, end):
        snap = make_snapshot("azure", [SCOPE], [
            {"type": "sql_server", "scope": SCOPE, "service": "sql", "status": "collected", "items": [
                {"id": server_id, "properties": {"publicNetworkAccess": "Enabled",
                 "fullyQualifiedDomainName": "sql.database.windows.net"}}]},
            {"type": "sql_firewall_rule", "scope": SCOPE, "service": "sql", "status": "collected", "items": [
                {"id": server_id + "/firewallRules/rule", "name": "rule",
                 "properties": {"startIpAddress": start, "endIpAddress": end}}]}])
        return next(row for row in assess(snap, resources(snap)) if row.resource["type"] == "sql_server")

    assert sql_decision("8.8.8.8", "8.8.8.8").verdict() == "FAIL"
    assert sql_decision("10.0.0.1", "10.0.0.9").verdict() == "PASS"
    azure_services = sql_decision("0.0.0.0", "0.0.0.0")
    assert azure_services.verdict() == "FAIL"
    assert azure_services.path[-1]["open_rules"][0]["source"] == "any Azure tenant"
    assert sql_decision("invalid", "8.8.8.8").verdict() == "UNKNOWN"


def test_nsg_specific_public_source_respects_per_source_priority():
    def rule(name, source, access, priority):
        return {"name": name, "properties": {"priority": priority, "direction": "Inbound",
            "access": access, "protocol": "Tcp", "sourceAddressPrefix": source,
            "destinationAddressPrefix": "*", "destinationPortRange": "22"}}

    nsg = {"data": {"properties": {"securityRules": [
        rule("deny-one", "8.8.8.8/32", "Deny", 100),
        rule("allow-rest", "0.0.0.0/0", "Allow", 200)]}}}
    allowed, _ = _nsg_allowed(nsg)
    assert allowed == {"tcp": ((22, 22),)}
    nsg["data"]["properties"]["securityRules"] = [
        rule("deny-one", "8.8.8.8/32", "Deny", 100),
        rule("allow-one", "8.8.8.8/32", "Allow", 200)]
    assert _nsg_allowed(nsg)[0] == {}
    nsg["data"]["properties"]["securityRules"] = [rule("allow-one", "8.8.8.8/32", "Allow", 200)]
    assert _nsg_allowed(nsg)[0] == {"tcp": ((22, 22),)}


def test_nsg_unresolved_public_source_tag_cannot_prove_closed_path():
    nic_id = f"{SCOPE}/resourceGroups/rg/providers/Microsoft.Network/networkInterfaces/nic"
    subnet_id = f"{SCOPE}/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet/subnets/subnet"
    nsg_id = f"{SCOPE}/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/nsg"
    pip_id = f"{SCOPE}/resourceGroups/rg/providers/Microsoft.Network/publicIPAddresses/pip"
    rule = {"name": "azure-cloud", "properties": {"priority": 100, "direction": "Inbound",
            "access": "Allow", "protocol": "Tcp", "sourceAddressPrefix": "AzureCloud",
            "destinationAddressPrefix": "*", "destinationPortRange": "443"}}
    nsg = {"id": nsg_id, "properties": {"securityRules": [rule]}}
    original = repr(nsg)
    allowed, matched = _nsg_allowed({"data": nsg})
    assert allowed == {} and any(row.get("unresolved_public_source") for row in matched)
    assert repr(nsg) == original
    snap = make_snapshot("azure", [SCOPE], [
        {"type": "public_ip", "scope": SCOPE, "service": "network", "status": "collected",
         "items": [{"id": pip_id, "sku": {"name": "Standard"}, "properties": {"ipAddress": "8.8.8.8"}}]},
        {"type": "nsg", "scope": SCOPE, "service": "network", "status": "collected", "items": [nsg]},
        {"type": "subnet", "scope": SCOPE, "service": "network", "status": "collected",
         "items": [{"id": subnet_id, "properties": {}}]},
        {"type": "nic", "scope": SCOPE, "service": "network", "status": "collected",
         "items": [{"id": nic_id, "properties": {"networkSecurityGroup": {"id": nsg_id},
             "ipConfigurations": [{"name": "primary", "properties": {"subnet": {"id": subnet_id},
                 "publicIPAddress": {"id": pip_id}, "privateIPAddress": "10.0.0.4"}}]}}]}])
    row = next(row for row in assess(snap, resources(snap)) if row.resource["type"] == "nic")
    assert row.verdict() == "UNKNOWN"
    assert any(gap["layer"] == "nsg" and "service tag" in gap["reason"] for gap in row.unresolved)


def test_container_app_requires_public_environment_and_effective_ingress():
    env_id = f"{SCOPE}/resourceGroups/rg/providers/Microsoft.App/managedEnvironments/env"
    app_id = f"{SCOPE}/resourceGroups/rg/providers/Microsoft.App/containerApps/app"

    def app_decision(env_public="Enabled", rules=None, transport="http", extra=None):
        ingress = {"external": True, "transport": transport, "fqdn": "app.example.azurecontainerapps.io",
                   "ipSecurityRestrictions": rules or []}
        if transport == "tcp":
            ingress["exposedPort"] = 8443
        if extra:
            ingress["additionalPortMappings"] = extra
        snap = make_snapshot("azure", [SCOPE], [
            {"type": "container_app_environment", "scope": SCOPE, "service": "app", "status": "collected",
             "items": [{"id": env_id, "properties": {"publicNetworkAccess": env_public,
                         "vnetConfiguration": {"internal": False}}}]},
            {"type": "container_app", "scope": SCOPE, "service": "app", "status": "collected",
             "items": [{"id": app_id, "properties": {"managedEnvironmentId": env_id,
                         "configuration": {"ingress": ingress}, "provisioningState": "Succeeded"}}]}])
        observed_resources = resources(snap)
        rows = assess(snap, observed_resources)
        matches = [row for row in rows if row.resource["type"] == "container_app"]
        assert matches, {"resource_types": [row["type"] for row in observed_resources],
                         "assessment_types": [row.resource["type"] for row in rows],
                         "dispatch_present": "container_app" in assess.__globals__["AZURE_TYPES"]}
        return matches[0]

    assert app_decision().verdict() == "FAIL"
    assert app_decision(env_public="Disabled").verdict() == "PASS"
    assert app_decision(env_public=None).verdict() == "UNKNOWN"
    private_allow = [{"action": "Allow", "ipAddressRange": "10.0.0.0/8"}]
    public_allow = [{"action": "Allow", "ipAddressRange": "8.8.8.8/32"}]
    assert app_decision(rules=private_allow).verdict() == "PASS"
    assert app_decision(rules=public_allow).verdict() == "FAIL"
    tcp = app_decision(transport="tcp", extra=[{"external": True, "exposedPort": 9000}])
    assert tcp.verdict() == "FAIL" and tcp.ports == {"tcp": ((8443, 8443), (9000, 9000))}


def test_firewall_dnat_frontend_is_detected_with_unresolved_backend():
    ip_id = f"{SCOPE}/resourceGroups/rg/providers/Microsoft.Network/publicIPAddresses/fw"
    firewall_id = f"{SCOPE}/resourceGroups/rg/providers/Microsoft.Network/azureFirewalls/fw"

    def firewall_decision(rules, policy=None):
        props = {"ipConfigurations": [{"properties": {"publicIPAddress": {"id": ip_id}}}],
                 "natRuleCollections": [{"name": "nat", "properties": {"action": {"type": "Dnat"},
                                          "rules": rules}}]}
        if policy:
            props["firewallPolicy"] = {"id": policy}
        snap = make_snapshot("azure", [SCOPE], [
            {"type": "public_ip", "scope": SCOPE, "service": "network", "status": "collected",
             "items": [{"id": ip_id, "properties": {"ipAddress": "8.8.8.8"}}]},
            {"type": "azure_firewall", "scope": SCOPE, "service": "network", "status": "collected",
             "items": [{"id": firewall_id, "properties": props}]}])
        return next(row for row in assess(snap, resources(snap)) if row.resource["type"] == "azure_firewall")

    rule = {"name": "web", "sourceAddresses": ["0.0.0.0/0"],
            "destinationAddresses": ["8.8.8.8"], "destinationPorts": ["443"],
            "protocols": ["TCP"], "translatedAddress": "10.0.0.4", "translatedPort": "8443"}
    candidate = firewall_decision([rule])
    assert candidate.verdict() == "UNKNOWN" and candidate.ports == {"tcp": ((443, 443),)}
    assert any(gap["layer"] == "backend" for gap in candidate.unresolved)
    assert firewall_decision([]).verdict() == "PASS"
    assert firewall_decision([], policy="/policy").verdict() == "UNKNOWN"


def test_firewall_policy_dnat_uses_collected_full_group():
    policy_id = f"{SCOPE}/resourceGroups/rg/providers/Microsoft.Network/firewallPolicies/p"
    public_id = f"{SCOPE}/resourceGroups/rg/providers/Microsoft.Network/publicIPAddresses/fw"
    group_id = policy_id + "/ruleCollectionGroups/nat"
    group = {"id": group_id, "_provenance": {"representation": "full",
        "source_operation": "get_rule_collection_group"}, "properties": {"ruleCollections": [
        {"name": "nat", "ruleCollectionType": "FirewallPolicyNatRuleCollection",
         "action": {"type": "DNAT"}, "rules": [{"name": "ssh", "ruleType": "NatRule",
             "sourceAddresses": ["1.1.1.1/32"], "destinationAddresses": ["8.8.8.8"],
             "destinationPorts": ["22"], "ipProtocols": ["TCP"],
             "translatedAddress": "10.0.0.4", "translatedPort": "22"}]}]}}
    snap = make_snapshot("azure", [SCOPE], [
        {"type": "public_ip", "scope": SCOPE, "service": "network", "status": "collected",
         "items": [{"id": public_id, "properties": {"ipAddress": "8.8.8.8"}}]},
        {"type": "firewall_policy", "scope": SCOPE, "service": "network", "status": "collected",
         "items": [{"id": policy_id, "properties": {}, "_coverage": {"ruleCollectionGroups": {"status": "collected"}},
                    "ruleCollectionGroups": [group]}]},
        {"type": "azure_firewall", "scope": SCOPE, "service": "network", "status": "collected",
         "items": [{"id": f"{SCOPE}/resourceGroups/rg/providers/Microsoft.Network/azureFirewalls/fw",
                    "properties": {"firewallPolicy": {"id": policy_id},
                                   "ipConfigurations": [{"properties": {"publicIPAddress": {"id": public_id}}}]}}]}])
    row = next(a for a in assess(snap, resources(snap)) if a.resource["type"] == "azure_firewall")
    assert row.verdict() == "UNKNOWN" and row.ports == {"tcp": ((22, 22),)}
    assert any(gap["layer"] == "backend" for gap in row.unresolved)


def test_frontdoor_edge_listener_uses_effective_routes_and_keeps_backend_uncertain():
    edge_id = f"{SCOPE}/resourceGroups/rg/providers/Microsoft.Cdn/profiles/edge"
    endpoint = {"id": edge_id + "/afdEndpoints/default",
                "properties": {"hostName": "edge.azurefd.net"}}
    route = {"id": endpoint["id"] + "/routes/default", "enabledState": "Enabled",
             "paths": [{"acceptedProtocols": ["Http"], "action": "Redirect"},
                       {"acceptedProtocols": ["Https"], "action": "Forward"}]}

    def edge_decision(routes, status="collected", hostname=True):
        item = {"id": edge_id, "sku": {"name": "Standard_AzureFrontDoor"},
                "properties": {}, "endpoints": [endpoint] if hostname else [],
                "effectiveRoutes": routes, "securityPolicies": [],
                "_coverage": {"effectiveRoutes": {"status": status}}}
        snap = make_snapshot("azure", [SCOPE], [
            {"type": "frontdoor_and_cdn_endpoint", "scope": SCOPE, "service": "cdn",
             "status": "collected", "items": [item]}])
        return next(row for row in assess(snap, resources(snap))
                    if row.resource["type"] == "frontdoor_and_cdn_endpoint")

    candidate = edge_decision([route])
    assert candidate.verdict() == "UNKNOWN" and candidate.ports == {"tcp": ((80, 80), (443, 443))}
    assert candidate.addresses == ["edge.azurefd.net"]
    assert any(gap["layer"] == "backend" for gap in candidate.unresolved)
    assert edge_decision([{**route, "paths": [{"acceptedProtocols": ["Http"], "action": "Redirect"}]}]).verdict() == "FAIL"
    assert edge_decision([{**route, "enabledState": "Disabled"}]).verdict() == "PASS"
    assert edge_decision([route], status="not_collected").verdict() == "UNKNOWN"
    assert edge_decision([route], hostname=False).verdict() == "UNKNOWN"


def test_api_management_public_gateway_and_network_gates():
    base = {"publicNetworkAccess": "Enabled", "virtualNetworkType": "None",
            "disableGateway": False, "gatewayUrl": "https://gateway.azure-api.net"}
    exposed = decision("api_management", base)
    assert exposed.verdict() == "FAIL" and exposed.ports == {"tcp": ((443, 443),)}
    assert exposed.addresses == ["https://gateway.azure-api.net"]
    assert decision("api_management", {**base, "publicNetworkAccess": "Disabled"}).verdict() == "PASS"
    assert decision("api_management", {**base, "virtualNetworkType": "Internal"}).verdict() == "PASS"
    assert decision("api_management", {**base, "disableGateway": True}).verdict() == "PASS"
    assert decision("api_management", {**base, "virtualNetworkType": "External"}).verdict() == "UNKNOWN"
    assert decision("api_management", {**base, "gatewayUrl": None}).verdict() == "UNKNOWN"


def test_redis_public_listeners_preserve_firewall_uncertainty():
    base = {"publicNetworkAccess": "Enabled", "hostName": "cache.redis.cache.windows.net",
            "sslPort": 6380, "enableNonSslPort": False}
    candidate = decision("redis_cache", base)
    assert candidate.verdict() == "UNKNOWN" and candidate.ports == {"tcp": ((6380, 6380),)}
    assert any(gap["layer"] == "firewall" for gap in candidate.unresolved)
    non_tls = decision("redis_cache", {**base, "enableNonSslPort": True, "port": 6379})
    assert non_tls.ports == {"tcp": ((6379, 6380),)}
    assert decision("redis_cache", {**base, "publicNetworkAccess": "Disabled"}).verdict() == "PASS"
    assert decision("redis_cache", {**base, "publicNetworkAccess": None}).verdict() == "UNKNOWN"
    injected = decision("redis_cache", {**base, "subnetId": "/subscriptions/test/subnets/cache"})
    assert any(gap["layer"] == "nsg" for gap in injected.unresolved)

    def with_rules(rules, status="collected"):
        item = {"id": f"{SCOPE}/resourceGroups/rg/providers/Microsoft.Cache/redis/cache",
                "properties": base, "firewallRules": rules,
                "_coverage": {"firewallRules": {"status": status}}}
        snap = make_snapshot("azure", [SCOPE], [
            {"type": "redis_cache", "scope": SCOPE, "service": "cache", "status": "collected",
             "items": [item]}])
        return next(row for row in assess(snap, resources(snap)) if row.resource["type"] == "redis_cache")

    assert with_rules([]).verdict() == "FAIL"
    private = {"properties": {"startIP": "10.0.0.1", "endIP": "10.0.0.10"}}
    public = {"properties": {"startIP": "8.8.8.8", "endIP": "8.8.8.8"}}
    assert with_rules([private]).verdict() == "PASS"
    assert with_rules([private, public]).verdict() == "FAIL"
    assert with_rules([public], status="partial").verdict() == "UNKNOWN"


@pytest.mark.parametrize("kind", ["vault", "managed_hsm", "container_registry", "search_service", "servicebus_namespace"])
def test_managed_endpoint_explicit_network_gate(kind):
    rule = {"vault": "networkAcls", "managed_hsm": "networkAcls", "container_registry": "networkRuleSet",
            "search_service": "networkRuleSet", "servicebus_namespace": "networkRuleSet"}[kind]
    assert decision(kind, {"publicNetworkAccess": "Enabled", "endpoint": "https://public.example.test",
                           rule: {"defaultAction": "Allow"}}).verdict() == "FAIL"
    assert decision(kind, {"publicNetworkAccess": "Enabled", rule: {"defaultAction": "Deny"}}).verdict() == "PASS"
    assert decision(kind, {"publicNetworkAccess": "Enabled", rule: {"defaultAction": "Deny",
                           "ipRules": [{"value": "0.0.0.0/0"}]}}).verdict() == "UNKNOWN"
    assert decision(kind, {"publicNetworkAccess": "Enabled"}).verdict() == "UNKNOWN"
    assert decision(kind, {"publicNetworkAccess": "Disabled", rule: {"defaultAction": "Allow"}}).verdict() == "PASS"
