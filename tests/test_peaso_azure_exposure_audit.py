"""Native Azure exposure additions use only collected configuration."""

import pytest

from peaso.analysis.internet_exposure import _nsg_allowed, _observed, assess
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


@pytest.mark.parametrize("kind", ["disk", "snapshot"])
def test_compute_public_sas_export_policy(kind):
    allowed = decision(kind, {"publicNetworkAccess": "Enabled", "networkAccessPolicy": "AllowAll"})
    assert allowed.verdict() == "FAIL"
    assert allowed.kind == "disk_export" and allowed.ports == {"tcp": ((443, 443),)}
    assert "issued SAS URI" in allowed.notes[0]
    from peaso.analysis.internet_exposure import _observed
    assert _observed(allowed, "FAIL").splitlines()[0].startswith(
        f"The {kind} has networkAccessPolicy AllowAll")
    assert len(_observed(allowed, "FAIL").splitlines()) == 4
    for props in (
        {"publicNetworkAccess": "Enabled", "networkAccessPolicy": "DenyAll"},
        {"publicNetworkAccess": "Enabled", "networkAccessPolicy": "AllowPrivate", "diskAccessId": "private"},
        {"publicNetworkAccess": "Disabled", "networkAccessPolicy": "AllowAll"},
    ):
        assert decision(kind, props).verdict() == "PASS"
    assert decision(kind, {"publicNetworkAccess": "Enabled"}).verdict() == "UNKNOWN"
    assert decision(kind, {"networkAccessPolicy": "AllowAll"}).verdict() == "UNKNOWN"
    assert len(_observed(decision(kind, {"networkAccessPolicy": "DenyAll"}), "PASS").splitlines()) == 3
    assert len(_observed(decision(kind, {"publicNetworkAccess": "Enabled"}), "UNKNOWN").splitlines()) == 3


def test_kusto_public_endpoint_ip_allow_list():
    base = {"publicNetworkAccess": "Enabled", "uri": "https://cluster.region.kusto.windows.net"}
    assert decision("kusto_cluster", {**base, "allowedIpRangeList": []}).verdict() == "FAIL"
    public = decision("kusto_cluster", {**base, "allowedIpRangeList": ["8.8.8.8/32"]})
    assert public.verdict() == "FAIL" and public.addresses == [base["uri"]]
    assert decision("kusto_cluster", {**base, "allowedIpRangeList": ["10.0.0.0/8"]}).verdict() == "PASS"
    assert decision("kusto_cluster", {**base, "allowedIpRangeList": ["PowerBI"]}).verdict() == "UNKNOWN"
    assert decision("kusto_cluster", {**base, "allowedIpRangeList": ["8.8.8.8", "PowerBI"]}).verdict() == "FAIL"
    assert decision("kusto_cluster", {**base, "allowedIpRangeList": ["bad//"]}).verdict() == "UNKNOWN"
    assert decision("kusto_cluster", {**base, "allowedIpRangeList": None}).verdict() == "UNKNOWN"
    assert decision("kusto_cluster", {**base, "publicNetworkAccess": "Disabled"}).verdict() == "PASS"


def test_batch_account_independent_public_endpoint_profiles():
    base = {"publicNetworkAccess": "Enabled", "accountEndpoint": "https://b.region.batch.azure.com",
            "nodeManagementEndpoint": "https://node.region.batch.azure.com"}
    deny = {"defaultAction": "Deny", "ipRules": []}
    assert decision("batch_account", base).verdict() == "FAIL"
    assert decision("batch_account", {**base, "networkProfile": {
        "accountAccess": deny, "nodeManagementAccess": deny}}).verdict() == "PASS"
    mixed = decision("batch_account", {**base, "networkProfile": {
        "accountAccess": deny, "nodeManagementAccess": {"defaultAction": "Deny", "ipRules": [
            {"action": "Allow", "value": "8.8.8.8/32"}]}}})
    assert mixed.verdict() == "FAIL" and mixed.ports == {"tcp": ((443, 443),)}
    assert decision("batch_account", {**base, "networkProfile": {
        "accountAccess": deny, "nodeManagementAccess": {"defaultAction": "Deny", "ipRules": [
            {"action": "Allow", "value": "10.0.0.0/8"}]}}}).verdict() == "PASS"
    assert decision("batch_account", {**base, "networkProfile": {
        "accountAccess": deny, "nodeManagementAccess": {"defaultAction": "Deny", "ipRules": [
            {"action": "Allow", "value": "invalid"}]}}}).verdict() == "UNKNOWN"
    assert decision("batch_account", {**base, "publicNetworkAccess": "SecuredByPerimeter"}).verdict() == "UNKNOWN"
    assert decision("batch_account", {**base, "publicNetworkAccess": "Disabled"}).verdict() == "PASS"


def test_load_balancer_pool_embedded_nic_reference_resolves_backend_path():
    base = f"{SCOPE}/resourceGroups/rg/providers/Microsoft.Network"
    lb_id, pip_id, nic_id = base + "/loadBalancers/lb", base + "/publicIPAddresses/pip", base + "/networkInterfaces/nic"
    front_id, pool_id = lb_id + "/frontendIPConfigurations/front", lb_id + "/backendAddressPools/pool"
    config_id, subnet_id, nsg_id = nic_id + "/ipConfigurations/primary", base + "/virtualNetworks/vnet/subnets/subnet", base + "/networkSecurityGroups/nsg"
    rule = {"name": "http", "properties": {"frontendIPConfiguration": {"id": front_id},
        "backendAddressPool": {"id": pool_id}, "protocol": "Tcp", "frontendPort": 443, "backendPort": 8443}}

    def lb_decision(pool_props, *, probed=False, subnet_nsg=False, nic_present=True,
                    nsg_access="Allow", route_drop=False, probe_present=True,
                    public_address="8.8.8.8"):
        lb_rule = {**rule, "properties": {**rule["properties"],
            **({"probe": {"id": lb_id + "/probes/probe"}} if probed else {})}}
        collections = [
            {"type": "load_balancer", "scope": SCOPE, "service": "network", "status": "collected", "items": [{"id": lb_id,
                "sku": {"name": "Standard"}, "properties": {"frontendIPConfigurations": [{"id": front_id,
                    "properties": {"publicIPAddress": {"id": pip_id}}}], "backendAddressPools": [
                    {"id": pool_id, "properties": pool_props}], "loadBalancingRules": [lb_rule],
                    "probes": [{"id": lb_id + "/probes/probe"}] if probed and probe_present else []}}]},
            {"type": "public_ip", "scope": SCOPE, "service": "network", "status": "collected", "items": [
                {"id": pip_id, "properties": {"ipAddress": public_address}}]},
            {"type": "nic", "scope": SCOPE, "service": "network", "status": "collected", "items": ([{"id": nic_id,
                "properties": {"networkSecurityGroup": {"id": nsg_id}, "ipConfigurations": [{"id": config_id,
                    "properties": {"privateIPAddress": "10.0.0.4", "subnet": {"id": subnet_id}}}]}}]
                if nic_present else [])},
            {"type": "subnet", "scope": SCOPE, "service": "network", "status": "collected", "items": [{"id": subnet_id,
                "properties": {"networkSecurityGroup": {"id": nsg_id}} if subnet_nsg else {}}]},
            {"type": "nsg", "scope": SCOPE, "service": "network", "status": "collected", "items": [{"id": nsg_id,
                "properties": {"securityRules": [{"name": "rule", "properties": {"priority": 100,
                    "direction": "Inbound", "access": nsg_access, "protocol": "Tcp", "sourceAddressPrefix": "*",
                    "destinationAddressPrefix": "*", "destinationPortRange": "8443"}}]}}]},
        ]
        if route_drop:
            collections.append({"type": "effective_route", "scope": SCOPE, "service": "network",
                "status": "collected", "items": [{"id": nic_id + "/effectiveRoutes/default",
                "nic_id": nic_id, "route": {"state": "Active", "source": "User",
                "addressPrefix": ["0.0.0.0/0"], "nextHopType": "None"},
                "_provenance": {"source_operation": "effectiveRouteTable", "read_only": True,
                "nic_id": nic_id}}]})
        snap = make_snapshot("azure", [SCOPE], collections)
        return next(row for row in assess(snap, resources(snap)) if row.resource["type"] == "load_balancer")

    for pool in ({"backendIPConfigurations": [{"id": config_id}]},
                 {"loadBalancerBackendAddresses": [{"properties": {"networkInterfaceIPConfiguration": {"id": config_id}}}]}):
        row = lb_decision(pool)
        assert row.verdict() == "FAIL" and row.ports == {"tcp": ((443, 443),)}
        assert row.addresses == ["8.8.8.8"]
        assert lb_decision(pool, route_drop=True).verdict() == "PASS"
    assert lb_decision({"loadBalancerBackendAddresses": [{"properties": {"ipAddress": "10.0.0.4"}}]}).verdict() == "UNKNOWN"
    down = {"loadBalancerBackendAddresses": [{"properties": {"ipAddress": "10.0.0.4", "adminState": "Down"}}]}
    assert lb_decision(down, probed=True).verdict() == "PASS"
    assert lb_decision(down).verdict() == "UNKNOWN"
    assert lb_decision(down, probed=True, probe_present=False).verdict() == "UNKNOWN"
    mixed = {"loadBalancerBackendAddresses": down["loadBalancerBackendAddresses"] + [
        {"properties": {"ipAddress": "10.0.0.5", "adminState": "Up"}}]}
    assert lb_decision(mixed, probed=True).verdict() == "UNKNOWN"
    raw = {"loadBalancerBackendAddresses": [{"properties": {
        "ipAddress": "10.0.0.4", "subnet": {"id": subnet_id}}}]}
    assert lb_decision(raw, subnet_nsg=True).verdict() == "FAIL"
    assert lb_decision(raw).verdict() == "FAIL"
    assert lb_decision(raw, nsg_access="Deny").verdict() == "PASS"
    assert lb_decision(raw, route_drop=True).verdict() == "PASS"
    assert lb_decision(raw, subnet_nsg=True, nic_present=False).verdict() == "UNKNOWN"
    assert lb_decision({"loadBalancerBackendAddresses": [{"properties": {
        "ipAddress": "10.0.0.4"}}]}).verdict() == "UNKNOWN"
    nonglobal = lb_decision({"backendIPConfigurations": [{"id": config_id}]},
                            public_address="10.0.0.4")
    assert nonglobal.verdict() == "UNKNOWN"
    assert "assigned global public frontend address not collected" in _observed(nonglobal, "UNKNOWN")
    assert lb_decision({"backendIPConfigurations": [{"id": config_id}]},
                       public_address="").verdict() == "UNKNOWN"


def test_application_gateway_public_frontend_requires_observed_address():
    base = f"{SCOPE}/resourceGroups/rg/providers/Microsoft.Network"
    gateway_id = base + "/applicationGateways/gateway"
    subnet_id = base + "/virtualNetworks/vnet/subnets/gateway"

    def check(addresses, listener_fronts=("first",), nsg_rules=None):
        fronts = [{"id": gateway_id + "/frontendIPConfigurations/" + name,
                   "properties": {"publicIPAddress": {"id": base + "/publicIPAddresses/" + name}}}
                  for name in addresses]
        listeners = [{"properties": {"frontendIPConfiguration": {"id": front["id"]},
                      "frontendPort": {"id": gateway_id + "/frontendPorts/https"}}}
                     for front in fronts if front["id"].rsplit("/", 1)[1] in listener_fronts]
        collections = [
            {"type": "application_gateway", "scope": SCOPE, "service": "network", "status": "collected",
             "items": [{"id": gateway_id, "properties": {"frontendIPConfigurations": fronts,
                 "frontendPorts": [{"id": gateway_id + "/frontendPorts/https", "properties": {"port": 443}}],
                 "httpListeners": listeners, "gatewayIPConfigurations": [
                     {"properties": {"subnet": {"id": subnet_id}}}]}}]},
            {"type": "public_ip", "scope": SCOPE, "service": "network", "status": "collected",
             "items": [{"id": base + "/publicIPAddresses/" + name,
                        "properties": {"ipAddress": address}} for name, address in addresses.items() if address is not None]},
            {"type": "subnet", "scope": SCOPE, "service": "network", "status": "collected",
             "items": [{"id": subnet_id, "properties": {"networkSecurityGroup": {"id": base + "/networkSecurityGroups/gateway"}}
                       if nsg_rules is not None else {}}]},
        ]
        if nsg_rules is not None:
            collections.append({"type": "nsg", "scope": SCOPE, "service": "network", "status": "collected",
                "items": [{"id": base + "/networkSecurityGroups/gateway",
                           "properties": {"securityRules": nsg_rules}}]})
        snapshot = make_snapshot("azure", [SCOPE], collections)
        return next(row for row in assess(snapshot, resources(snapshot))
                    if row.resource["type"] == "application_gateway")

    known = check({"first": "8.8.8.8"})
    assert known.verdict() == "FAIL" and known.addresses == ["8.8.8.8"]
    assert "assigned public address 8.8.8.8" in _observed(known, "FAIL")
    unassigned = check({"first": None})
    assert unassigned.verdict() == "UNKNOWN"
    assert "no collected assigned public address" in _observed(unassigned, "UNKNOWN")
    assert check({"first": "10.0.0.4"}).verdict() == "UNKNOWN"
    mixed = check({"first": "8.8.8.8", "second": None}, ("first", "second"))
    assert mixed.verdict() == "FAIL" and mixed.addresses == ["8.8.8.8"]
    assert check({"first": None}, ()).verdict() == "PASS"
    def allow_destination(address):
        return {"name": "allow-specific-frontend", "properties": {"priority": 100,
            "direction": "Inbound", "access": "Allow", "protocol": "Tcp",
            "sourceAddressPrefix": "*", "destinationAddressPrefix": address,
            "destinationPortRange": "443"}}
    assert check({"first": "8.8.8.8"}, nsg_rules=[allow_destination("8.8.8.8/32")]).verdict() == "FAIL"
    assert check({"first": "8.8.8.8"}, nsg_rules=[allow_destination("9.9.9.9/32")]).verdict() == "PASS"
    virtual_destination = allow_destination("VirtualNetwork")
    virtual = check({"first": "8.8.8.8"}, nsg_rules=[virtual_destination])
    assert virtual.verdict() == "UNKNOWN"
    assert any(gap["layer"] == "nsg" for gap in virtual.unresolved)
    assert check({"first": "8.8.8.8"}, nsg_rules=[
        {**virtual_destination, "properties": {**virtual_destination["properties"],
          "destinationAddressPrefixes": ["VirtualNetwork", "8.8.8.8/32"],
          "destinationAddressPrefix": None}}]).verdict() == "FAIL"
    dual = check({"first": "8.8.8.8", "second": "9.9.9.9"}, ("first", "second"),
                 [allow_destination("9.9.9.9/32")])
    assert dual.verdict() == "FAIL" and "assigned public address 9.9.9.9" in _observed(dual, "FAIL")
    mixed_blocked = check({"first": "8.8.8.8", "second": None}, ("first", "second"),
                          [allow_destination("9.9.9.9/32")])
    assert mixed_blocked.verdict() == "UNKNOWN"


def test_load_balancer_public_ip_prefix_frontend_is_outbound_only():
    base = f"{SCOPE}/resourceGroups/rg/providers/Microsoft.Network"
    lb_id = base + "/loadBalancers/lb"
    frontend = lb_id + "/frontendIPConfigurations/outbound"
    prefix = base + "/publicIPPrefixes/prefix"
    snapshot = make_snapshot("azure", [SCOPE], [{"type": "load_balancer", "scope": SCOPE,
        "service": "network", "status": "collected", "items": [{"id": lb_id,
            "sku": {"name": "Standard"}, "properties": {
                "frontendIPConfigurations": [{"id": frontend,
                    "properties": {"publicIPPrefix": {"id": prefix}}}],
                "outboundRules": [{"properties": {"frontendIPConfigurations": [{"id": frontend}]}}]}}]}])
    assert not any(row.resource["type"] == "load_balancer" for row in assess(snapshot, resources(snapshot)))


@pytest.mark.parametrize("kind,field", [
    ("container_registry", "networkRuleSet"), ("cognitive_account", "networkAcls")])
def test_managed_endpoint_parent_public_ip_rules(kind, field):
    base = {"publicNetworkAccess": "Enabled", "endpoint": "https://endpoint.example.com"}
    def verdict(rules):
        return decision(kind, {**base, field: rules}).verdict()
    assert verdict({"defaultAction": "Deny", "ipRules": [{"value": "8.8.8.8/32", "action": "Allow"}]}) == "FAIL"
    assert verdict({"defaultAction": "Deny", "ipRules": [{"value": "10.0.0.0/8", "action": "Allow"}]}) == "PASS"
    assert verdict({"defaultAction": "Deny", "ipRules": [{"value": "invalid", "action": "Allow"}]}) == "UNKNOWN"


def test_search_ip_restrictions_and_app_configuration_public_gate():
    search = {"publicNetworkAccess": "Enabled", "endpoint": "https://s.search.windows.net"}
    assert decision("search_service", {**search, "networkRuleSet": {"ipRules": []}}).verdict() == "FAIL"
    assert decision("search_service", {**search, "networkRuleSet": {"ipRules": [{"value": "8.8.8.8"}]}}).verdict() == "FAIL"
    assert decision("search_service", {**search, "networkRuleSet": {"ipRules": [{"value": "10.0.0.0/8"}]}}).verdict() == "PASS"
    assert decision("search_service", {**search, "networkRuleSet": {"ipRules": [{"value": "invalid"}]}}).verdict() == "UNKNOWN"
    assert decision("app_configuration", {"publicNetworkAccess": "Enabled", "endpoint": "https://c.azconfig.io"}).verdict() == "FAIL"
    assert decision("app_configuration", {"publicNetworkAccess": "Disabled", "endpoint": "https://c.azconfig.io"}).verdict() == "PASS"


@pytest.mark.parametrize("kind", ["servicebus_namespace", "eventhub_namespace"])
def test_broker_namespace_cached_network_rule_child(kind):
    rid = f"{SCOPE}/resourceGroups/rg/providers/test/{kind}/asset"
    def child_decision(ip, status="collected", trusted=False):
        item = {"id": rid, "properties": {}, "_coverage": {"networkRuleSet": {"status": status}}}
        if status == "collected":
            item["networkRuleSet"] = {"id": rid + "/networkRuleSets/default", "properties": {
                "publicNetworkAccess": "Enabled", "defaultAction": "Deny",
                "trustedServiceAccessEnabled": trusted,
                "ipRules": [{"action": "Allow", "ipMask": ip}] if ip else []}}
        snap = make_snapshot("azure", [SCOPE], [{"type": kind, "scope": SCOPE, "service": "test",
            "status": "collected", "items": [item]}])
        return next(row for row in assess(snap, resources(snap)) if row.resource["type"] == kind)
    assert child_decision("8.8.8.8/32").verdict() == "FAIL"
    assert child_decision("10.0.0.0/8").verdict() == "PASS"
    assert child_decision(None, trusted=True).verdict() == "UNKNOWN"
    assert child_decision("invalid").verdict() == "UNKNOWN"
    assert child_decision(None, status="denied").verdict() == "UNKNOWN"


def test_ml_workspace_online_endpoint_and_selected_ip_acl():
    rid = f"{SCOPE}/resourceGroups/rg/providers/Microsoft.MachineLearningServices/workspaces/ml"
    endpoint = {"id": rid + "/onlineEndpoints/score", "properties": {
        "publicNetworkAccess": "Enabled", "scoringUri": "https://score.example.test"}}

    def ml_decision(public="Enabled", acls=None, status="collected", endpoint_public="Enabled"):
        item = {"id": rid, "properties": {"publicNetworkAccess": public},
                "_coverage": {"onlineEndpoints": {"status": status}}}
        if acls is not None:
            item["properties"]["networkAcls"] = acls
        if status == "collected":
            item["onlineEndpoints"] = [{**endpoint, "properties": {**endpoint["properties"],
                "publicNetworkAccess": endpoint_public}}]
        snap = make_snapshot("azure", [SCOPE], [{"type": "ml_workspace", "scope": SCOPE,
            "service": "ml", "status": "collected", "items": [item]}])
        return next(row for row in assess(snap, resources(snap)) if row.resource["type"] == "ml_workspace")

    assert ml_decision(public="Disabled").verdict() == "UNKNOWN"
    assert ml_decision(public="Disabled", endpoint_public="Disabled").verdict() == "PASS"
    unknown = ml_decision()
    assert unknown.verdict() == "UNKNOWN" and "https://score.example.test" in unknown.addresses
    assert any("networkAcls" in gap["reason"] for gap in unknown.unresolved)
    assert ml_decision(acls={"defaultAction": "Allow"}).verdict() == "FAIL"
    assert ml_decision(acls={"defaultAction": "Deny", "ipRules": [
        {"value": "8.8.8.8/32"}]}).verdict() == "FAIL"
    assert ml_decision(acls={"defaultAction": "Deny", "ipRules": [
        {"value": "10.0.0.0/8"}]}).verdict() == "PASS"
    assert ml_decision(acls={"defaultAction": "Allow"}, status="denied").verdict() == "FAIL"


def test_databricks_arm_public_gate_keeps_external_ingress_policy_unknown():
    host = "adb-123.4.azuredatabricks.net"
    disabled = decision("databricks_workspace", {"publicNetworkAccess": "Disabled", "workspaceUrl": host})
    assert disabled.verdict() == "PASS"
    enabled = decision("databricks_workspace", {"publicNetworkAccess": "Enabled", "workspaceUrl": host})
    assert enabled.verdict() == "UNKNOWN" and enabled.addresses == [host]
    assert enabled.ports == {"tcp": ((443, 443),)}
    assert any("IP access lists" in gap["reason"] for gap in enabled.unresolved)
    assert decision("databricks_workspace", {"workspaceUrl": host}).verdict() == "UNKNOWN"


def test_compute_gallery_community_and_direct_sharing_policy():
    community = decision("compute_gallery", {"sharingProfile": {"permissions": "Community"},
        "sharingStatus": {"aggregatedState": "Succeeded"}})
    assert community.verdict() == "FAIL" and community.kind == "gallery_share"
    assert "published image versions" in community.notes[0]
    from peaso.analysis.internet_exposure import _observed
    assert len(_observed(community, "FAIL").splitlines()) == 4
    private = decision("compute_gallery", {"sharingProfile": {"permissions": "Private"}})
    assert private.verdict() == "PASS"
    assert _observed(private, "PASS").splitlines()[0].endswith("permissions Private.")
    assert len(_observed(private, "PASS").splitlines()) == 3
    direct = decision("compute_gallery", {"sharingProfile": {"permissions": "Groups",
        "groups": [{"type": "AADTenants", "ids": ["outside-tenant"]}]}})
    assert direct.verdict() == "UNKNOWN"
    assert len(_observed(direct, "UNKNOWN").splitlines()) == 3
    missing = decision("compute_gallery", {})
    assert missing.verdict() == "UNKNOWN"
    assert _observed(missing, "UNKNOWN").splitlines()[0] == (
        "The gallery has no recorded sharingProfile.permissions value.")


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
                 "properties": {"ipSecurityRestrictions": rules, "ipSecurityRestrictionsDefaultAction": "Deny",
                                "scmIpSecurityRestrictionsUseMain": True}}]}])
        return next(a for a in assess(snap, resources(snap)) if a.resource["type"] == "app_service")

    allow = {"name": "public-ip", "ipAddress": "8.8.8.8/32", "action": "Allow", "priority": 200}
    deny = {"name": "deny-public-ip", "ipAddress": "8.8.8.8/32", "action": "Deny", "priority": 100}
    first = site_decision([allow])
    assert first.verdict() == "FAIL", first.path
    assert site_decision([deny, allow]).verdict() == "PASS"
    assert site_decision([{**deny, "ipAddress": "10.0.0.0/8"}, allow]).verdict() == "FAIL"


def test_app_service_multisource_and_header_filtered_restrictions():
    site_id = f"{SCOPE}/resourceGroups/rg/providers/Microsoft.Web/sites/app"

    def app_decision(rules, default=None):
        config = {"ipSecurityRestrictions": rules, "scmIpSecurityRestrictionsUseMain": True}
        if default is not None:
            config["ipSecurityRestrictionsDefaultAction"] = default
        snap = make_snapshot("azure", [SCOPE], [
            {"type": "app_service", "scope": SCOPE, "service": "web", "status": "collected", "items": [
                {"id": site_id, "properties": {"defaultHostName": "app.azurewebsites.net",
                 "publicNetworkAccess": "Enabled"}}]},
            {"type": "app_service_config", "scope": SCOPE, "service": "web", "status": "collected", "items": [
                {"id": site_id + "/config/web", "parent_id": site_id, "properties": config}]}])
        return next(a for a in assess(snap, resources(snap)) if a.resource["type"] == "app_service")

    allow = {"name": "two-sources", "ipAddress": "10.0.0.0/8, 8.8.8.8/32",
             "action": "Allow", "priority": 200}
    assert app_decision([allow]).verdict() == "FAIL"
    assert app_decision([{**allow, "ipAddress": "10.0.0.0/8, 192.168.0.0/16"}]).verdict() == "PASS"
    deny = {"name": "conditional-deny", "ipAddress": "8.8.8.8/32", "action": "Deny",
            "priority": 100, "headers": {"x-forwarded-host": ["private.example"]}}
    assert app_decision([deny, allow]).verdict() == "FAIL"
    assert app_decision([{**deny, "headers": None}, allow]).verdict() == "PASS"
    assert app_decision([{**allow, "priority": "invalid"}]).verdict() == "UNKNOWN"
    assert app_decision(["malformed"]).verdict() == "UNKNOWN"
    assert app_decision([{"name": "any", "ipAddress": "Any", "action": "Deny"}]).path[-1]["main"]["default_action"] == "Deny"


def test_app_service_scm_public_surface_uses_its_recorded_rules_and_hostname():
    site_id = f"{SCOPE}/resourceGroups/rg/providers/Microsoft.Web/sites/app"
    scm_host = "app.scm.azurewebsites.net"

    def app_decision(config, *, scm_hostname=True, public_access="Enabled"):
        site = {"defaultHostName": "app.azurewebsites.net", "publicNetworkAccess": public_access,
                "enabledHostNames": ["app.azurewebsites.net"] + ([scm_host] if scm_hostname else [])}
        snap = make_snapshot("azure", [SCOPE], [
            {"type": "app_service", "scope": SCOPE, "service": "web", "status": "collected", "items": [
                {"id": site_id, "properties": site}]},
            {"type": "app_service_config", "scope": SCOPE, "service": "web", "status": "collected", "items": [
                {"id": site_id + "/config/web", "parent_id": site_id, "properties": config}]}])
        return next(a for a in assess(snap, resources(snap)) if a.resource["type"] == "app_service")

    main_blocked = {"ipSecurityRestrictions": [], "ipSecurityRestrictionsDefaultAction": "Deny"}
    separate = {**main_blocked, "scmIpSecurityRestrictionsUseMain": False,
                "scmIpSecurityRestrictions": [], "scmIpSecurityRestrictionsDefaultAction": "Allow"}
    open_scm = app_decision(separate)
    assert open_scm.verdict() == "FAIL"
    assert open_scm.addresses == [scm_host]
    assert open_scm.path[-1]["main"]["decision"] == "block"
    assert open_scm.path[-1]["scm"]["decision"] == "allow"
    observed = _observed(open_scm, "FAIL")
    assert "SCM IP rules allow a public source" in observed
    assert "could expose deployment controls or app data" in observed
    assert len(observed.splitlines()) == 3
    assert app_decision({**separate, "scmIpSecurityRestrictionsDefaultAction": "Deny"}).verdict() == "PASS"
    assert app_decision({**separate, "scmIpSecurityRestrictionsUseMain": True}).verdict() == "PASS"
    assert app_decision(main_blocked).verdict() == "UNKNOWN"
    assert app_decision(separate, scm_hostname=False).verdict() == "UNKNOWN"
    assert app_decision({**separate, "scmIpSecurityRestrictionsDefaultAction": "invalid"}).verdict() == "UNKNOWN"
    assert app_decision({**separate, "scmIpSecurityRestrictionsDefaultAction": ""}).verdict() == "UNKNOWN"
    invalid_main = app_decision({**separate, "ipSecurityRestrictionsDefaultAction": ""},
                                scm_hostname=False)
    assert invalid_main.verdict() == "UNKNOWN"
    assert invalid_main.path[-1]["main"]["decision"] == "unknown"
    assert app_decision(separate, public_access="Disabled").verdict() == "PASS"
    assert app_decision({**separate, "ipSecurityRestrictionsDefaultAction": "Allow"}, scm_hostname=False).verdict() == "FAIL"


def test_app_service_main_hostname_uses_recorded_enabled_names():
    site_id = f"{SCOPE}/resourceGroups/rg/providers/Microsoft.Web/sites/app"
    config = {"ipSecurityRestrictions": [], "ipSecurityRestrictionsDefaultAction": "Allow",
              "scmIpSecurityRestrictionsUseMain": False,
              "scmIpSecurityRestrictions": [], "scmIpSecurityRestrictionsDefaultAction": "Deny"}

    def check(hosts, default="app.azurewebsites.net", scm_default="Deny"):
        site = {"publicNetworkAccess": "Enabled", "enabledHostNames": hosts}
        if default is not None:
            site["defaultHostName"] = default
        snap = make_snapshot("azure", [SCOPE], [
            {"type": "app_service", "scope": SCOPE, "service": "web", "status": "collected",
             "items": [{"id": site_id, "properties": site}]},
            {"type": "app_service_config", "scope": SCOPE, "service": "web", "status": "collected",
             "items": [{"id": site_id + "/config/web", "parent_id": site_id,
                        "properties": {**config, "scmIpSecurityRestrictionsDefaultAction": scm_default}}]},
        ])
        return next(row for row in assess(snap, resources(snap)) if row.resource["type"] == "app_service")

    custom = check(["custom.example.com"], default=None)
    assert custom.verdict() == "FAIL" and custom.addresses == ["custom.example.com"]
    assert check(["custom.example.com"]).addresses == ["custom.example.com"]
    missing_main = check(["app.scm.azurewebsites.net"])
    assert missing_main.verdict() == "UNKNOWN" and missing_main.addresses == []
    assert "enabled main hostname" in _observed(missing_main, "UNKNOWN")
    scm = check(["app.scm.azurewebsites.net"], scm_default="Allow")
    assert scm.verdict() == "FAIL" and scm.addresses == ["app.scm.azurewebsites.net"]


def test_app_service_hostname_type_selects_independent_main_and_scm_restrictions():
    site_id = f"{SCOPE}/resourceGroups/rg/providers/Microsoft.Web/sites/app"
    main_host = "main.example.com"
    scm_host = "deployment.example.com"

    def check(host_type, *, main_action="Deny", scm_action="Allow"):
        site = {"publicNetworkAccess": "Enabled", "enabledHostNames": [main_host, scm_host],
                "hostNameSslStates": [{"name": main_host, "hostType": "Standard"},
                                      {"name": scm_host, "hostType": host_type}]}
        config = {"ipSecurityRestrictions": [], "ipSecurityRestrictionsDefaultAction": main_action,
                  "scmIpSecurityRestrictionsUseMain": False, "scmIpSecurityRestrictions": [],
                  "scmIpSecurityRestrictionsDefaultAction": scm_action}
        snap = make_snapshot("azure", [SCOPE], [
            {"type": "app_service", "scope": SCOPE, "service": "web", "status": "collected",
             "items": [{"id": site_id, "properties": site}]},
            {"type": "app_service_config", "scope": SCOPE, "service": "web", "status": "collected",
             "items": [{"id": site_id + "/config/web", "parent_id": site_id, "properties": config}]},
        ])
        return next(row for row in assess(snap, resources(snap)) if row.resource["type"] == "app_service")

    repository = check("Repository")
    assert repository.verdict() == "FAIL"
    assert repository.addresses == [scm_host]
    assert repository.path[-1]["scm_hosts"] == [scm_host]
    assert check("Repository", scm_action="Deny").verdict() == "PASS"
    assert check("unexpected").verdict() == "UNKNOWN"
    assert check("unexpected", main_action="Allow").addresses == [main_host]


def test_app_service_service_tag_and_vnet_rules_preserve_public_source_priority():
    site_id = f"{SCOPE}/resourceGroups/rg/providers/Microsoft.Web/sites/app"
    tag = {"name": "AzureFrontDoor.Backend", "properties": {"addressPrefixes": ["8.8.8.0/24"]}}
    public_tag = {"name": "frontdoor", "ipAddress": "AzureFrontDoor.Backend", "action": "Allow", "priority": 200}
    deny_tag = {**public_tag, "name": "deny-frontdoor", "action": "Deny", "priority": 100}
    subnet_rule = {"name": "subnet", "vnetSubnetResourceId":
                   f"{SCOPE}/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/v/subnets/s",
                   "action": "Allow", "priority": 100}

    def site_decision(rules, *, tags=None, tag_status="collected"):
        snap = make_snapshot("azure", [SCOPE], [
            {"type": "app_service", "scope": SCOPE, "service": "web", "status": "collected",
             "items": [{"id": site_id, "properties": {"publicNetworkAccess": "Enabled",
                 "defaultHostName": "app.azurewebsites.net",
                 "enabledHostNames": ["app.azurewebsites.net", "app.scm.azurewebsites.net"]}}]},
            {"type": "app_service_config", "scope": SCOPE, "service": "web", "status": "collected",
             "items": [{"id": site_id + "/config/web", "parent_id": site_id,
                 "properties": {"ipSecurityRestrictions": rules, "scmIpSecurityRestrictionsUseMain": True}}]},
            {"type": "service_tag", "scope": SCOPE, "service": "network", "status": tag_status,
             "items": tags if tags is not None else [tag]},
        ])
        return next(a for a in assess(snap, resources(snap)) if a.resource["type"] == "app_service")

    assert site_decision([public_tag]).verdict() == "FAIL"
    assert site_decision([deny_tag, public_tag]).verdict() == "PASS"
    assert site_decision([subnet_rule]).verdict() == "PASS"
    assert site_decision([{"name": "any-vnet", "ipAddress": "AnyVnets", "action": "Allow"}]).verdict() == "PASS"
    assert site_decision([public_tag], tag_status="partial").verdict() == "UNKNOWN"
    assert site_decision([public_tag], tags=[{"name": tag["name"],
        "properties": {"addressPrefixes": ["malformed"]}}]).verdict() == "UNKNOWN"


def test_app_service_private_endpoint_default_and_ase_surface_modes():
    site_id = f"{SCOPE}/resourceGroups/rg/providers/Microsoft.Web/sites/app"
    plan_id = f"{SCOPE}/resourceGroups/rg/providers/Microsoft.Web/serverfarms/plan"
    ase_id = f"{SCOPE}/resourceGroups/rg/providers/Microsoft.Web/hostingEnvironments/ase"

    def verdict(mode=None, *, private=False, access="Enabled", include_ase=True):
        site = {"defaultHostName": "app.azurewebsites.net", "enabledHostNames": [
            "app.azurewebsites.net", "app.scm.azurewebsites.net"], "publicNetworkAccess": access,
            "serverFarmId": plan_id}
        if private:
            site["privateEndpointConnections"] = [{"id": site_id + "/privateEndpointConnections/pe"}]
        collections = [
            {"type": "app_service", "scope": SCOPE, "service": "web", "status": "collected",
             "items": [{"id": site_id, "properties": site}]},
            {"type": "app_service_config", "scope": SCOPE, "service": "web", "status": "collected",
             "items": [{"id": site_id + "/config/web", "parent_id": site_id, "properties": {
                 "ipSecurityRestrictions": [], "ipSecurityRestrictionsDefaultAction": "Allow",
                 "scmIpSecurityRestrictionsUseMain": False, "scmIpSecurityRestrictions": [],
                 "scmIpSecurityRestrictionsDefaultAction": "Allow"}}]},
            {"type": "app_service_plan", "scope": SCOPE, "service": "web", "status": "collected",
             "items": [{"id": plan_id, "properties": {"hostingEnvironmentProfile": {"id": ase_id}}}]},
            {"type": "app_service_environment", "scope": SCOPE, "service": "web",
             "status": "collected" if include_ase else "partial", "items": [
                 {"id": ase_id, "properties": {"internalLoadBalancingMode": mode}}] if include_ase else []},
        ]
        snap = make_snapshot("azure", [SCOPE], collections)
        return next(a for a in assess(snap, resources(snap)) if a.resource["type"] == "app_service")

    assert verdict("None").verdict() == "FAIL"
    assert verdict("Web").verdict() == "FAIL"  # SCM remains public.
    assert verdict("Web").addresses == ["app.scm.azurewebsites.net"]
    assert verdict("Publishing").verdict() == "FAIL"  # Main site remains public.
    assert verdict("Publishing").addresses == ["app.azurewebsites.net"]
    assert verdict("Web, Publishing").verdict() == "PASS"
    assert verdict(None).verdict() == "UNKNOWN"
    assert verdict("None", include_ase=False).verdict() == "UNKNOWN"
    assert verdict("None", private=True, access=None).verdict() == "PASS"


def test_app_service_parent_authentication_is_informational_for_public_listener():
    site_id = f"{SCOPE}/resourceGroups/rg/providers/Microsoft.Web/sites/app"
    site = {"id": site_id, "properties": {"defaultHostName": "app.azurewebsites.net",
            "publicNetworkAccess": "Enabled", "enabledHostNames": ["app.azurewebsites.net"]},
            "_coverage": {"authSettingsV2": {"status": "collected"}},
            "authSettingsV2": {"id": site_id + "/config/authsettingsV2", "properties": {
                "platform": {"enabled": True}, "globalValidation": {
                    "requireAuthentication": True, "unauthenticatedClientAction": "Return403", "excludedPaths": []}}}}
    config = {"id": site_id + "/config/web", "parent_id": site_id, "properties": {
        "ipSecurityRestrictions": [], "ipSecurityRestrictionsDefaultAction": "Allow",
        "scmIpSecurityRestrictionsUseMain": False, "scmIpSecurityRestrictions": [],
        "scmIpSecurityRestrictionsDefaultAction": "Deny"}}
    snap = make_snapshot("azure", [SCOPE], [
        {"type": "app_service", "scope": SCOPE, "service": "web", "status": "collected", "items": [site]},
        {"type": "app_service_config", "scope": SCOPE, "service": "web", "status": "collected", "items": [config]}])
    result = next(a for a in assess(snap, resources(snap)) if a.resource["type"] == "app_service")
    assert result.verdict() == "FAIL" and result.authenticated is True
    assert next(step for step in result.path if step["layer"] == "app_authentication")["decision"] == "require"


def test_app_service_stopped_and_disabled_hostname_surfaces():
    site_id = f"{SCOPE}/resourceGroups/rg/providers/Microsoft.Web/sites/app"

    def decision(*, enabled=True, scm_stopped=False, hostnames_disabled=False,
                 scm_default="Allow", include_config=True):
        site = {"id": site_id, "properties": {
            "defaultHostName": "app.azurewebsites.net", "publicNetworkAccess": "Enabled",
            "enabledHostNames": ["app.azurewebsites.net", "app.scm.azurewebsites.net"],
            "enabled": enabled, "scmSiteAlsoStopped": scm_stopped,
            "hostNamesDisabled": hostnames_disabled}}
        collections = [{"type": "app_service", "scope": SCOPE, "service": "web",
                        "status": "collected", "items": [site]}]
        if include_config:
            config = {"id": site_id + "/config/web", "parent_id": site_id, "properties": {
                "ipSecurityRestrictions": [], "ipSecurityRestrictionsDefaultAction": "Allow",
                "scmIpSecurityRestrictionsUseMain": False,
                "scmIpSecurityRestrictions": [],
                "scmIpSecurityRestrictionsDefaultAction": scm_default}}
            collections.append({"type": "app_service_config", "scope": SCOPE, "service": "web",
                                "status": "collected", "items": [config]})
        snap = make_snapshot("azure", [SCOPE], collections)
        return next(a for a in assess(snap, resources(snap)) if a.resource["type"] == "app_service")

    stopped = decision(enabled=False, scm_stopped=True, include_config=False)
    assert stopped.verdict() == "PASS" and stopped.blocked_by == "site_state"
    scm_only = decision(enabled=False)
    assert scm_only.verdict() == "FAIL" and scm_only.addresses == ["app.scm.azurewebsites.net"]
    assert decision(enabled=False, scm_stopped=None).verdict() == "FAIL"  # Documented false default.
    assert decision(enabled=False, scm_stopped="unknown").verdict() == "UNKNOWN"
    hostname_gate = decision(hostnames_disabled=True)
    assert hostname_gate.verdict() == "UNKNOWN" and hostname_gate.addresses == []
    assert decision(hostnames_disabled=True, scm_default="Deny").verdict() == "PASS"


def test_app_service_client_certificate_is_a_request_gate_not_network_block():
    site_id = f"{SCOPE}/resourceGroups/rg/providers/Microsoft.Web/sites/app"

    def cert_decision(*, enabled=True, mode="Required", excluded="", https_only=True,
                      main_default="Allow"):
        site = {"id": site_id, "properties": {
            "defaultHostName": "app.azurewebsites.net", "publicNetworkAccess": "Enabled",
            "enabledHostNames": ["app.azurewebsites.net"], "httpsOnly": https_only,
            "clientCertEnabled": enabled, "clientCertMode": mode,
            "clientCertExclusionPaths": excluded}}
        config = {"id": site_id + "/config/web", "parent_id": site_id, "properties": {
            "ipSecurityRestrictions": [], "ipSecurityRestrictionsDefaultAction": main_default,
            "scmIpSecurityRestrictionsUseMain": False, "scmIpSecurityRestrictions": [],
            "scmIpSecurityRestrictionsDefaultAction": "Deny"}}
        snap = make_snapshot("azure", [SCOPE], [
            {"type": "app_service", "scope": SCOPE, "service": "web", "status": "collected", "items": [site]},
            {"type": "app_service_config", "scope": SCOPE, "service": "web", "status": "collected", "items": [config]}])
        result = next(a for a in assess(snap, resources(snap)) if a.resource["type"] == "app_service")
        step = next((step for step in result.path if step["layer"] == "client_certificate"), None)
        return result, step

    protected, cert = cert_decision()
    assert protected.verdict() == "FAIL" and protected.authenticated is False
    assert cert["decision"] == "certificate_required" and cert["excluded_paths"] == []
    assert "application code" in cert["validation"]
    assert cert_decision(excluded="/public;/health")[1]["decision"] == "partial"
    assert cert_decision(https_only=False)[1]["decision"] == "partial"
    assert cert_decision(mode="Optional")[1]["decision"] == "optional"
    assert cert_decision(enabled=False)[1]["decision"] == "not_required"
    blocked, cert = cert_decision(main_default="Deny")
    assert blocked.verdict() == "PASS" and cert is None


def test_function_http_trigger_auth_levels_are_native_evidence():
    site_id = f"{SCOPE}/resourceGroups/rg/providers/Microsoft.Web/sites/fn"

    def trigger_decision(auth_level="anonymous", *, disabled=False, status="collected", complete=True):
        function = {"id": site_id + "/functions/Ping", "type": "Microsoft.Web/sites/functions",
                    "properties": {"isDisabled": disabled, "triggerConfigComplete": complete,
                                   "httpTriggers": [{"authLevel": auth_level, "methods": ["get"], "route": "ping"}]}}
        site = {"id": site_id, "kind": "functionapp", "properties": {
            "defaultHostName": "fn.azurewebsites.net", "publicNetworkAccess": "Enabled",
            "enabledHostNames": ["fn.azurewebsites.net"]},
            "_coverage": {"functions": {"status": status}}, "functions": [function]}
        config = {"id": site_id + "/config/web", "parent_id": site_id, "properties": {
            "ipSecurityRestrictions": [], "ipSecurityRestrictionsDefaultAction": "Allow",
            "scmIpSecurityRestrictionsUseMain": False, "scmIpSecurityRestrictions": [],
            "scmIpSecurityRestrictionsDefaultAction": "Deny"}}
        snap = make_snapshot("azure", [SCOPE], [
            {"type": "app_service", "scope": SCOPE, "service": "web", "status": "collected", "items": [site]},
            {"type": "app_service_config", "scope": SCOPE, "service": "web", "status": "collected", "items": [config]}])
        result = next(a for a in assess(snap, resources(snap)) if a.resource["type"] == "app_service")
        return result, next(step for step in result.path if step["layer"] == "function_triggers")

    public, trigger = trigger_decision()
    assert public.verdict() == "FAIL" and trigger["decision"] == "anonymous"
    assert trigger["anonymous_functions"] == ["Ping"]
    assert trigger_decision("function")[1]["decision"] == "key_required"
    assert trigger_decision("admin")[1]["decision"] == "key_required"
    assert trigger_decision(disabled=True)[1]["decision"] == "none"
    assert trigger_decision(auth_level=None)[1]["decision"] == "unknown"
    assert trigger_decision(complete=False)[1]["decision"] == "unknown"
    assert trigger_decision(status="partial")[1]["decision"] == "unknown"


def test_app_service_slot_uses_its_own_cached_configuration():
    site_id = f"{SCOPE}/resourceGroups/rg/providers/Microsoft.Web/sites/app"
    slot_id = site_id + "/slots/staging"

    def slot_decision(main_default, status="collected", scm_default="Deny", auth_action="Return401", excluded=None):
        slot = {"id": slot_id, "parent_id": site_id, "properties": {
            "defaultHostName": "app-staging.azurewebsites.net", "publicNetworkAccess": "Enabled",
            "enabledHostNames": ["app-staging.azurewebsites.net", "app-staging.scm.azurewebsites.net"]},
            "_coverage": {"configuration": {"status": status}, "authSettingsV2": {"status": "collected"}}}
        slot["authSettingsV2"] = {"id": slot_id + "/config/authsettingsV2", "properties": {
            "platform": {"enabled": True}, "globalValidation": {"requireAuthentication": True,
            "unauthenticatedClientAction": auth_action, "excludedPaths": [] if excluded is None else excluded}}}
        if status == "collected":
            slot["configuration"] = {"id": slot_id + "/config/web", "properties": {
                "ipSecurityRestrictions": [], "ipSecurityRestrictionsDefaultAction": main_default,
                "scmIpSecurityRestrictionsUseMain": False, "scmIpSecurityRestrictions": [],
                "scmIpSecurityRestrictionsDefaultAction": scm_default}}
        snap = make_snapshot("azure", [SCOPE], [
            {"type": "app_service_slot", "scope": SCOPE, "service": "web", "status": "collected",
             "items": [slot]}])
        return next(a for a in assess(snap, resources(snap)) if a.resource["type"] == "app_service_slot")

    public = slot_decision("Allow")
    assert public.verdict() == "FAIL"
    assert public.authenticated is True
    assert next(step for step in public.path if step["layer"] == "app_authentication")["decision"] == "require"
    assert slot_decision("Deny").verdict() == "PASS"
    assert slot_decision("Deny", scm_default="Allow").verdict() == "FAIL"
    assert slot_decision("Allow", status="partial").verdict() == "UNKNOWN"
    anonymous = slot_decision("Allow", auth_action="AllowAnonymous")
    assert anonymous.verdict() == "FAIL" and anonymous.authenticated is False
    excepted = slot_decision("Allow", excluded=["/public"])
    assert excepted.verdict() == "FAIL" and excepted.authenticated is False
    assert next(step for step in excepted.path if step["layer"] == "app_authentication")["decision"] == "unknown"


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
    omitted_public = {key: value for key, value in open_account.items()
                      if key != "allowBlobPublicAccess"}
    assert assess_container(omitted_public).verdict() == "PASS"
    assert assess_container({**open_account, "allowBlobPublicAccess": None}).verdict() == "PASS"
    assert assess_container({**open_account, "allowBlobPublicAccess": "false"}).verdict() == "UNKNOWN"
    assert assess_container({**open_account, "networkAcls": {"defaultAction": "Deny"}}).verdict() == "PASS"
    assert assess_container({**open_account, "networkAcls": {}}).verdict() == "FAIL"
    public_rule = {"value": "8.8.8.8/32", "action": "Allow"}
    assert assess_container({**open_account, "networkAcls": {"defaultAction": "Deny",
        "ipRules": [public_rule]}}).verdict() == "FAIL"
    assert assess_container({**open_account, "networkAcls": {"defaultAction": "Deny",
        "ipRules": [{"value": "not-an-ip"}]}}).verdict() == "UNKNOWN"
    assert assess_container({**open_account, "publicNetworkAccess": "SecuredByPerimeter"}).verdict() == "UNKNOWN"
    assert assess_container({**open_account, "publicNetworkAccess": "SecuredByPerimeter",
        "networkAcls": {"defaultAction": "Deny"}}).verdict() == "UNKNOWN"


def test_storage_static_website_is_anonymous_with_blob_public_access_disabled():
    account_id = f"{SCOPE}/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/a"
    web_url = "https://a.z5.web.core.windows.net/"

    def decision(*, enabled=True, acl=None, public="Enabled", web=True):
        props = {"publicNetworkAccess": public, "allowBlobPublicAccess": False,
                 "networkAcls": acl if acl is not None else {"defaultAction": "Allow", "bypass": "None"},
                 "primaryEndpoints": {"web": web_url} if web else {}}
        snap = make_snapshot("azure", [SCOPE], [
            {"type": "storage_account", "scope": SCOPE, "service": "storage", "status": "collected",
             "items": [{"id": account_id, "properties": props}]},
            {"type": "storage_service", "scope": account_id + "/blobServices",
             "service": "storage", "status": "collected", "items": [{
                 "id": account_id + "/blobServices/default", "properties": {
                     "staticWebsite": {"enabled": enabled}}}]}])
        return next((row for row in assess(snap, resources(snap))
                     if row.resource["type"] == "storage_account"), None)

    site = decision()
    assert site is not None and site.verdict() == "FAIL" and site.data_exposure
    assert web_url in site.addresses
    assert "serves $web anonymously" in _observed(site, "FAIL")
    assert len(_observed(site, "FAIL").splitlines()) == 3
    assert not decision(enabled=False).data_exposure
    assert not decision(web=False).data_exposure
    ip_acl = {"defaultAction": "Deny", "bypass": "None",
              "ipRules": [{"value": "8.8.8.8/32", "action": "Allow"}]}
    assert decision(acl=ip_acl).data_exposure
    blocked = decision(acl={"defaultAction": "Deny", "bypass": "None"})
    assert blocked.verdict() == "PASS" and not blocked.data_exposure
    assert decision(public="Disabled") is None


def test_storage_account_deny_default_retains_public_ip_rule_exposure():
    base = {"publicNetworkAccess": "Enabled", "primaryEndpoints": {"blob": "https://a.blob.core.windows.net/"},
            "supportsHttpsTrafficOnly": True}
    assert decision("storage_account", {**base, "networkAcls": {"defaultAction": "Deny",
        "ipRules": [{"value": "8.8.8.8/32", "action": "Allow"}]}}).verdict() == "FAIL"
    assert decision("storage_account", {**base, "networkAcls": {"defaultAction": "Deny",
        "bypass": "None", "ipRules": [{"value": "10.0.0.0/8", "action": "Allow"}]}}).verdict() == "PASS"
    assert decision("storage_account", {**base, "networkAcls": {"defaultAction": "Deny",
        "ipRules": [{"value": "invalid"}]}}).verdict() == "UNKNOWN"
    assert decision("storage_account", {**base, "publicNetworkAccess": "SecuredByPerimeter",
        "networkAcls": {"defaultAction": "Allow"}}).verdict() == "UNKNOWN"
    assert decision("storage_account", {**base, "publicNetworkAccess": "SecuredByPerimeter",
        "networkAcls": {"defaultAction": "Deny"}}).verdict() == "UNKNOWN"


def test_storage_effective_perimeter_public_rule_overrides_account_firewall():
    from peaso.collectors import azure
    from peaso.collectors.azure import _child_rows

    account_id = f"{SCOPE}/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/a"
    container_id = account_id + "/blobServices/default/containers/public"
    config_id = account_id + "/networkSecurityPerimeterConfigurations/association"
    config = {"id": config_id,
              "type": "Microsoft.Storage/storageAccounts/networkSecurityPerimeterConfigurations",
              "properties": {"provisioningState": "Succeeded",
                             "resourceAssociation": {"accessMode": "Enforced"},
                             "profile": {"accessRules": [{"name": "internet",
                                 "properties": {"direction": "Inbound", "addressPrefixes": ["8.8.8.0/24"]}}]}}}
    assert _child_rows([config], account_id, "networkSecurityPerimeterConfigurations")[0]["id"] == config_id
    with pytest.raises(ValueError):
        _child_rows([{**config, "id": account_id + "/networkSecurityPerimeterConfigurations/../foreign"}],
                    account_id, "networkSecurityPerimeterConfigurations")
    url = ("https://management.azure.com" + account_id +
           "/networkSecurityPerimeterConfigurations?api-version=2026-04-01")
    calls = []

    def request(current, **kwargs):
        calls.append(current)
        return {"value": [config]}

    skip = tuple(field for field, _, _ in azure.EMBEDDED_LISTS["storage_account"]
                 if field != "networkSecurityPerimeterConfigurations") + ("diagnosticSettings",)
    item = {"id": account_id, "type": "Microsoft.Storage/storageAccounts",
            "properties": {"publicNetworkAccess": "SecuredByPerimeter"}}
    azure._embed(azure._Reader({}), request, [("storage_account", item)], skip=skip)
    assert calls == [url]
    assert item["_coverage"]["networkSecurityPerimeterConfigurations"]["status"] == "collected"
    assert item["networkSecurityPerimeterConfigurations"][0]["id"] == config_id
    calls.clear()
    ordinary = {"id": account_id, "type": "Microsoft.Storage/storageAccounts",
                "properties": {"publicNetworkAccess": "Enabled"}}
    azure._embed(azure._Reader({}), request, [("storage_account", ordinary)], skip=skip)
    assert calls == []

    def check(configuration=config, *, status="collected", acls=None):
        account = {"id": account_id, "properties": {
            "publicNetworkAccess": "SecuredByPerimeter", "allowBlobPublicAccess": True,
            "networkAcls": acls if acls is not None else {"defaultAction": "Deny", "bypass": "None"},
            "primaryEndpoints": {"blob": "https://a.blob.core.windows.net/"}},
            "networkSecurityPerimeterConfigurations": [configuration],
            "_coverage": {"networkSecurityPerimeterConfigurations": {"status": status}}}
        snap = make_snapshot("azure", [SCOPE], [
            {"type": "storage_account", "scope": SCOPE, "service": "storage", "status": "collected",
             "items": [account]},
            {"type": "storage_container", "scope": SCOPE, "service": "storage", "status": "collected",
             "items": [{"id": container_id, "parent_id": account_id,
                        "properties": {"publicAccess": "Blob"}}]},
        ])
        rows = [row for row in assess(snap, resources(snap))
                if row.resource["type"] in ("storage_account", "storage_container")]
        return {row.resource["type"]: row for row in rows}

    opened = check()
    assert opened["storage_account"].verdict() == "FAIL"
    assert opened["storage_container"].verdict() == "FAIL"
    assert opened["storage_container"].data_exposure
    assert opened["storage_account"].path[0]["public_ip_rules"][0]["source"] == "8.8.8.0/24"
    for row in opened.values():
        observed = _observed(row, "FAIL")
        assert "effective Storage perimeter" in observed or "effective perimeter rule" in observed
        assert "8.8.8.0/24" in observed
        assert len(observed.splitlines()) == 3
    private = {**config, "properties": {**config["properties"], "profile": {
        "accessRules": [{"name": "private", "properties": {
            "direction": "Inbound", "addressPrefixes": ["10.0.0.0/8"]}}]}}}
    assert all(row.verdict() == "UNKNOWN" for row in check(private).values())
    ipv6_only = {**config, "properties": {**config["properties"], "profile": {
        "accessRules": [{"name": "ipv6", "properties": {
            "direction": "Inbound", "addressPrefixes": ["2001:4860::/32"]}}]}}}
    assert all(row.verdict() == "UNKNOWN" for row in check(ipv6_only).values())
    assert all(row.verdict() == "UNKNOWN" for row in check(status="partial").values())
    learning = {**config, "properties": {**config["properties"],
        "resourceAssociation": {"accessMode": "Learning"}}}
    assert all(row.verdict() == "FAIL" for row in check(learning).values())
    assert check(learning)["storage_account"].path[0]["access_modes"] == ["Learning"]
    learning_private = {**private, "properties": {**private["properties"],
        "resourceAssociation": {"accessMode": "Learning"}}}
    fallback = check(learning_private, acls={"defaultAction": "Allow"})
    assert all(row.verdict() == "FAIL" for row in fallback.values())
    assert fallback["storage_container"].data_exposure
    assert "account-firewall fallback" in _observed(fallback["storage_container"], "FAIL")
    assert "account-firewall fallback" in _observed(fallback["storage_account"], "FAIL")
    assert all(row.verdict() == "UNKNOWN" for row in check(learning_private).values())
    audit = {**config, "properties": {**config["properties"],
        "resourceAssociation": {"accessMode": "Audit"}}}
    assert all(row.verdict() == "UNKNOWN" for row in check(audit).values())
    subscription_id = "/subscriptions/11111111-2222-3333-4444-555555555555"
    named = {**config, "properties": {**config["properties"], "profile": {
        "accessRules": [{"name": "partner", "properties": {"direction": "Inbound",
            "subscriptions": [{"id": subscription_id}]}}]}}}
    named_rows = check(named)
    assert named_rows["storage_account"].verdict() == "FAIL"
    assert named_rows["storage_account"].authenticated is True
    assert named_rows["storage_account"].path[0]["subscription_rules"][0]["subscription_id"] == subscription_id
    named_observed = _observed(named_rows["storage_account"], "FAIL")
    assert subscription_id in named_observed and "owner was not established" in named_observed
    assert len(named_observed.splitlines()) == 3
    assert named_rows["storage_container"].verdict() == "UNKNOWN"
    assert named_rows["storage_container"].data_exposure is False
    learning_named = {**named, "properties": {**named["properties"],
        "resourceAssociation": {"accessMode": "Learning"}}}
    fallback_named = check(learning_named, acls={"defaultAction": "Allow"})
    assert fallback_named["storage_account"].verdict() == "FAIL"
    assert fallback_named["storage_container"].verdict() == "FAIL"
    assert fallback_named["storage_container"].data_exposure
    malformed_named = {**named, "properties": {**named["properties"], "profile": {
        "accessRules": [{"name": "partner", "properties": {"direction": "Inbound",
            "subscriptions": [{"id": "/subscriptions/not-a-uuid"}]}}]}}}
    assert all(row.verdict() == "UNKNOWN" for row in check(malformed_named).values())


def test_storage_unrecognized_public_gate_stays_unknown_for_account_and_anonymous_blob():
    account_id = f"{SCOPE}/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/a"

    def check(access):
        props = {"allowBlobPublicAccess": True,
                 "networkAcls": {"defaultAction": "Allow"},
                 "primaryEndpoints": {"blob": "https://a.blob.core.windows.net/"}}
        if access is not None:
            props["publicNetworkAccess"] = access
        snap = make_snapshot("azure", [SCOPE], [
            {"type": "storage_account", "scope": SCOPE, "service": "storage", "status": "collected",
             "items": [{"id": account_id, "properties": props}]},
            {"type": "storage_container", "scope": SCOPE, "service": "storage", "status": "collected",
             "items": [{"id": account_id + "/blobServices/default/containers/public",
                 "parent_id": account_id, "properties": {"publicAccess": "Blob"}}]},
        ])
        rows = assess(snap, resources(snap))
        return (next(a for a in rows if a.resource["type"] == "storage_account"),
                next(a for a in rows if a.resource["type"] == "storage_container"))

    assert [a.verdict() for a in check("Unexpected")] == ["UNKNOWN", "UNKNOWN"]
    assert [a.verdict() for a in check(None)] == ["FAIL", "FAIL"]  # Documented public default.


@pytest.mark.parametrize("acls, expected", [
    (None, "FAIL"),
    ({}, "FAIL"),
    ({"defaultAction": "Allow"}, "FAIL"),
    ({"defaultAction": "Invalid"}, "UNKNOWN"),
    ([], "UNKNOWN"),
    ({"defaultAction": "Deny", "bypass": "None"}, "PASS"),
])
def test_storage_default_firewall_action_applies_to_anonymous_container(acls, expected):
    account_id = f"{SCOPE}/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/a"
    props = {"publicNetworkAccess": "Enabled", "allowBlobPublicAccess": True,
             "primaryEndpoints": {"blob": "https://a.blob.core.windows.net/"}}
    if acls is not None:
        props["networkAcls"] = acls
    snap = make_snapshot("azure", [SCOPE], [
        {"type": "storage_account", "scope": SCOPE, "service": "storage", "status": "collected",
         "items": [{"id": account_id, "properties": props}]},
        {"type": "storage_container", "scope": SCOPE, "service": "storage", "status": "collected",
         "items": [{"id": account_id + "/blobServices/default/containers/public",
                    "parent_id": account_id, "properties": {"publicAccess": "Blob"}}]},
    ])
    rows = assess(snap, resources(snap))
    assert {row.resource["type"]: row.verdict() for row in rows} == {
        "storage_account": expected, "storage_container": expected}
    if acls in (None, {}):
        container = next(row for row in rows if row.resource["type"] == "storage_container")
        assert any(step.get("default_action") == "Allow (service default)" for step in container.path)


def test_storage_account_open_network_requires_observed_public_endpoint_url():
    base = {"publicNetworkAccess": "Enabled", "networkAcls": {"defaultAction": "Allow"}}
    missing = decision("storage_account", base)
    assert missing.verdict() == "UNKNOWN"
    assert any(gap["reason"] == "storage public endpoint URL is not collected"
               for gap in missing.unresolved)
    known = decision("storage_account", {**base, "primaryEndpoints": {
        "blob": "https://a.blob.core.windows.net/"}})
    assert known.verdict() == "FAIL" and known.addresses == ["https://a.blob.core.windows.net/"]
    blocked = decision("storage_account", {**base, "networkAcls": {
        "defaultAction": "Deny", "bypass": "None"}})
    assert blocked.verdict() == "PASS"


def test_disabled_storage_public_access_retains_authenticated_exception_uncertainty():
    account_id = f"{SCOPE}/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/a"
    instance = {"resourceId": f"{SCOPE}/resourceGroups/rg/providers/Microsoft.DataFactory/factories/f",
                "tenantId": "tenant-a"}

    def check(acls):
        props = {"publicNetworkAccess": "Disabled", "allowBlobPublicAccess": True,
                 "primaryEndpoints": {"blob": "https://a.blob.core.windows.net/"}}
        if acls is not None:
            props["networkAcls"] = acls
        snap = make_snapshot("azure", [SCOPE], [
            {"type": "storage_account", "scope": SCOPE, "service": "storage", "status": "collected",
             "items": [{"id": account_id, "properties": props}]},
            {"type": "storage_container", "scope": SCOPE, "service": "storage", "status": "collected",
             "items": [{"id": account_id + "/blobServices/default/containers/public",
                        "parent_id": account_id, "properties": {"publicAccess": "Blob"}}]},
        ])
        return assess(snap, resources(snap))

    for acls in ({"bypass": "AzureServices", "resourceAccessRules": []},
                 {"bypass": "None", "resourceAccessRules": [instance]},
                 {"bypass": "Bad"}, None):
        rows = check(acls)
        account = next(row for row in rows if row.resource["type"] == "storage_account")
        anonymous = next(row for row in rows if row.resource["type"] == "storage_container")
        assert account.verdict() == "UNKNOWN" and anonymous.verdict() == "PASS"
        assert len(_observed(account, "UNKNOWN").splitlines()) == 3
        assert "can retain these exceptions" in _observed(account, "UNKNOWN")
    assert [row.resource["type"] for row in check({"bypass": "None", "resourceAccessRules": [],
        "ipRules": [{"value": "8.8.8.8"}], "virtualNetworkRules": [{"id": "ignored"}]})] == [
            "storage_container"]


def test_storage_trusted_service_bypass_is_not_an_anonymous_public_source():
    account_id = f"{SCOPE}/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/a"
    base = {"publicNetworkAccess": "Enabled", "allowBlobPublicAccess": True,
            "primaryEndpoints": {"blob": "https://a.blob.core.windows.net/"}}

    def account_and_container(bypass):
        acls = {"defaultAction": "Deny"}
        if bypass is not None:
            acls["bypass"] = bypass
        account = {"id": account_id, "properties": {**base, "networkAcls": acls}}
        container = {"id": account_id + "/blobServices/default/containers/public",
                     "parent_id": account_id, "properties": {"publicAccess": "Blob"}}
        snapshot = make_snapshot("azure", [SCOPE], [
            {"type": "storage_account", "scope": SCOPE, "service": "storage", "status": "collected",
             "items": [account]},
            {"type": "storage_container", "scope": SCOPE, "service": "storage", "status": "collected",
             "items": [container]}])
        rows = assess(snapshot, resources(snapshot))
        return (next(row for row in rows if row.resource["type"] == "storage_account"),
                next(row for row in rows if row.resource["type"] == "storage_container"))

    account, anonymous = account_and_container("AzureServices, Logging")
    assert account.verdict() == "UNKNOWN" and anonymous.verdict() == "PASS"
    assert "trusted-service bypass AzureServices, Logging" in _observed(account, "UNKNOWN")
    assert any(step["layer"] == "trusted_service_exception" and
               step["decision"] == "authenticated_only" for step in anonymous.path)
    assert account_and_container("None")[0].verdict() == "PASS"
    assert account_and_container(None)[0].verdict() == "UNKNOWN"
    assert account_and_container("unknown-service")[0].verdict() == "UNKNOWN"
    assert account_and_container("unknown-service")[1].verdict() == "UNKNOWN"


def test_storage_recorded_secondary_and_published_routing_endpoints():
    account_id = f"{SCOPE}/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/a"
    primary = "https://a.blob.core.windows.net/"
    secondary = "https://a-secondary.blob.core.windows.net/"
    internet = "https://a-internetrouting.blob.core.windows.net/"
    microsoft = "https://a-microsoftrouting.blob.core.windows.net/"

    def check(*, primary_present=True, internet_published=True):
        props = {"publicNetworkAccess": "Enabled", "allowBlobPublicAccess": True,
            "networkAcls": {"defaultAction": "Allow"}, "statusOfSecondary": "available",
            "routingPreference": {"publishInternetEndpoints": internet_published,
                                  "publishMicrosoftEndpoints": True},
            "primaryEndpoints": {"blob": primary} if primary_present else {},
            "secondaryEndpoints": {"blob": secondary, "internetEndpoints": {"blob": internet},
                                   "microsoftEndpoints": {"blob": microsoft}}}
        snapshot = make_snapshot("azure", [SCOPE], [
            {"type": "storage_account", "scope": SCOPE, "service": "storage", "status": "collected",
             "items": [{"id": account_id, "sku": {"name": "Standard_RAGRS"}, "properties": props}]},
            {"type": "storage_container", "scope": SCOPE, "service": "storage", "status": "collected",
             "items": [{"id": account_id + "/blobServices/default/containers/public",
                        "parent_id": account_id, "properties": {"publicAccess": "Blob"}}]}])
        rows = assess(snapshot, resources(snapshot))
        return (next(row for row in rows if row.resource["type"] == "storage_account"),
                next(row for row in rows if row.resource["type"] == "storage_container"))

    account, anonymous = check()
    assert account.verdict() == "FAIL" and anonymous.verdict() == "FAIL"
    assert set((primary, secondary, internet, microsoft)) <= set(account.addresses)
    assert set((primary, secondary, internet, microsoft)) <= set(anonymous.addresses)
    assert f"read-access secondary blob endpoint {secondary}" in _observed(anonymous, "FAIL")
    assert f"read-access secondary blob endpoint {secondary}" in _observed(account, "FAIL")
    account, anonymous = check(primary_present=False, internet_published=False)
    assert account.verdict() == "FAIL" and anonymous.verdict() == "FAIL"
    assert primary not in account.addresses and internet not in account.addresses
    assert secondary in anonymous.addresses


def test_storage_resource_instance_rule_admits_named_source_to_public_endpoint():
    account_id = f"{SCOPE}/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/a"
    blob_url = "https://a.blob.core.windows.net/"
    rule = {"resourceId": f"{SCOPE}/resourceGroups/rg/providers/Microsoft.DataFactory/factories/f",
            "tenantId": "tenant-a"}
    container = {"id": account_id + "/blobServices/default/containers/public",
                 "parent_id": account_id, "properties": {"publicAccess": "Blob"}}

    def account_and_container(rules, subnet_rules=None, subnet_items=None):
        collections = [
            {"type": "storage_account", "scope": SCOPE, "service": "storage", "status": "collected",
             "items": [{"id": account_id, "location": "westeurope", "properties": {"publicNetworkAccess": "Enabled",
                 "allowBlobPublicAccess": True, "primaryEndpoints": {"blob": blob_url},
                 "networkAcls": {"defaultAction": "Deny", "bypass": "None", "resourceAccessRules": rules,
                                 "virtualNetworkRules": subnet_rules or []}}}]},
            {"type": "storage_container", "scope": SCOPE, "service": "storage", "status": "collected",
             "items": [container]},
        ]
        if subnet_items is not None:
            collections.append({"type": "subnet", "scope": SCOPE, "service": "network",
                                "status": "collected", "items": subnet_items})
        snap = make_snapshot("azure", [SCOPE], collections)
        rows = assess(snap, resources(snap))
        return (next(a for a in rows if a.resource["type"] == "storage_account"),
                next(a for a in rows if a.resource["type"] == "storage_container"))

    account, anonymous = account_and_container([rule])
    assert account.verdict() == "FAIL" and anonymous.verdict() == "PASS"
    assert account.path[0]["resource_instance_rules"] == [{"resource_id": rule["resourceId"],
                                                            "tenant_id": rule["tenantId"]}]
    assert anonymous.path[-2]["resource_instance_rules"] == account.path[0]["resource_instance_rules"]
    assert len(_observed(account, "FAIL").splitlines()) == 3
    assert "requires an appropriate role" in _observed(account, "FAIL")
    assert any(step["layer"] == "resource_instance_exception" and
               step["decision"] == "authenticated_only" for step in anonymous.path)
    assert "does not establish an anonymous read path" in _observed(anonymous, "PASS")
    assert len(_observed(anonymous, "PASS").splitlines()) == 3
    assert account_and_container([])[0].verdict() == "PASS"
    assert account_and_container([])[1].verdict() == "PASS"
    assert account_and_container([{"resourceId": rule["resourceId"]}])[0].verdict() == "UNKNOWN"
    assert account_and_container([{"resourceId": rule["resourceId"]}])[1].verdict() == "UNKNOWN"

    foreign_subnet = "/subscriptions/foreign/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/v/subnets/s"
    account, anonymous = account_and_container([], [{"id": foreign_subnet, "state": "Succeeded"}])
    assert account.verdict() == "UNKNOWN" and anonymous.verdict() == "UNKNOWN"
    mixed_account, mixed_anonymous = account_and_container([rule], [{"id": foreign_subnet,
                                                                      "state": "Succeeded"}])
    assert mixed_account.verdict() == "FAIL" and mixed_anonymous.verdict() == "UNKNOWN"
    local_subnet = f"{SCOPE}/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/v/subnets/s"
    rule_subnet = [{"id": local_subnet, "state": "Succeeded"}]
    active_subnet = [{"id": local_subnet, "properties": {"serviceEndpoints": [
        {"service": "Microsoft.Storage.Global", "provisioningState": "Succeeded"}]}}]
    account, anonymous = account_and_container([], rule_subnet, active_subnet)
    assert account.verdict() == "FAIL" and anonymous.verdict() == "FAIL"
    assert account.path[0]["virtual_network_rules"] == [local_subnet]
    assert "Subnet ownership, data authorization" in _observed(account, "FAIL")
    assert "subnet ownership and successful access" in _observed(anonymous, "FAIL")
    assert "provisioned Storage service endpoint" in _observed(anonymous, "FAIL")
    blocked = account_and_container([], rule_subnet, [{"id": local_subnet,
        "properties": {"serviceEndpoints": []}}])
    assert [row.verdict() for row in blocked] == ["PASS", "PASS"]
    regional = [{"id": local_subnet, "properties": {"serviceEndpoints": [
        {"service": "Microsoft.Storage", "provisioningState": "Succeeded", "locations": ["westeurope"]}]}}]
    assert [row.verdict() for row in account_and_container([], rule_subnet, regional)] == ["FAIL", "FAIL"]
    wrong_region = [{"id": local_subnet, "properties": {"serviceEndpoints": [
        {"service": "Microsoft.Storage", "provisioningState": "Succeeded", "locations": ["eastus"]}]}}]
    assert [row.verdict() for row in account_and_container([], rule_subnet, wrong_region)] == ["UNKNOWN", "UNKNOWN"]
    restricted = [{"id": local_subnet, "properties": {"serviceEndpoints": [
        {"service": "Microsoft.Storage.Global", "provisioningState": "Succeeded"}],
        "serviceEndpointPolicies": [{"id": f"{SCOPE}/resourceGroups/rg/providers/Microsoft.Network/serviceEndpointPolicies/p"}]}}]
    assert [row.verdict() for row in account_and_container([], rule_subnet, restricted)] == ["UNKNOWN", "UNKNOWN"]
    assert account_and_container([], [{"id": foreign_subnet, "state": "Failed"}])[0].verdict() == "UNKNOWN"
    assert account_and_container([], [{"id": foreign_subnet}])[0].verdict() == "UNKNOWN"
    assert account_and_container([], [{"id": "malformed", "state": "Succeeded"}])[1].verdict() == "UNKNOWN"


def test_storage_published_ipv6_endpoint_rules_are_public_sources():
    from peaso.collectors.azure import ENDPOINTS

    assert ENDPOINTS["storage_account"] == ("Microsoft.Storage/storageAccounts", "2026-06-01")
    account_id = f"{SCOPE}/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/a"
    ipv6_url = "https://a-ipv6.blob.core.windows.net/"

    def account_and_container(rule, *, published=True, endpoint=True, ipv6_service="blob"):
        props = {"publicNetworkAccess": "Enabled", "allowBlobPublicAccess": True,
                 "dualStackEndpointPreference": {"publishIpv6Endpoint": published},
                 "networkAcls": {"defaultAction": "Deny", "bypass": "None", "ipv6Rules": [rule]},
                 "primaryEndpoints": {"blob": "https://a.blob.core.windows.net/"}}
        if endpoint:
            props["primaryEndpoints"]["ipv6Endpoints"] = {ipv6_service: ipv6_url}
        snap = make_snapshot("azure", [SCOPE], [
            {"type": "storage_account", "scope": SCOPE, "service": "storage", "status": "collected",
             "items": [{"id": account_id, "properties": props}]},
            {"type": "storage_container", "scope": SCOPE, "service": "storage", "status": "collected",
             "items": [{"id": account_id + "/blobServices/default/containers/public",
                 "parent_id": account_id, "properties": {"publicAccess": "Blob"}}]},
        ])
        rows = assess(snap, resources(snap))
        return (next(a for a in rows if a.resource["type"] == "storage_account"),
                next(a for a in rows if a.resource["type"] == "storage_container"))

    rule = {"value": "2606:4700:4700::1111/128", "action": "Allow"}
    account, anonymous = account_and_container(rule)
    assert account.verdict() == "FAIL" and anonymous.verdict() == "FAIL"
    assert ipv6_url in account.addresses and ipv6_url in anonymous.addresses
    assert "publishes an IPv6 endpoint" in _observed(account, "FAIL")
    assert "publishes an IPv6 blob endpoint" in _observed(anonymous, "FAIL")
    assert account_and_container({"value": "fc00::/7", "action": "Allow"})[0].verdict() == "PASS"
    assert account_and_container(rule, endpoint=False)[0].verdict() == "UNKNOWN"
    assert account_and_container(rule, published=False)[1].verdict() == "UNKNOWN"
    queue_only = account_and_container(rule, ipv6_service="queue")
    assert queue_only[0].verdict() == "FAIL" and queue_only[1].verdict() == "UNKNOWN"
    assert account_and_container({"value": "invalid"})[0].verdict() == "UNKNOWN"


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
    private_only = sql_decision("10.0.0.1", "10.0.0.9")
    assert private_only.verdict() == "UNKNOWN"
    assert any("database-level firewall rules" in gap["reason"] for gap in private_only.unresolved)
    assert len(_observed(private_only, "UNKNOWN").splitlines()) == 3
    azure_services = sql_decision("0.0.0.0", "0.0.0.0")
    assert azure_services.verdict() == "FAIL"
    assert azure_services.path[-1]["open_rules"][0]["source"] == "any Azure tenant"
    assert sql_decision("invalid", "8.8.8.8").verdict() == "UNKNOWN"


def test_sql_missing_public_gate_and_partial_firewall_pages_stay_unknown():
    server_id = f"{SCOPE}/resourceGroups/rg/providers/Microsoft.Sql/servers/sql"

    def decision(public, status, rules):
        snap = make_snapshot("azure", [SCOPE], [
            {"type": "sql_server", "scope": SCOPE, "service": "sql", "status": "collected", "items": [
                {"id": server_id, "properties": {"publicNetworkAccess": public,
                 "fullyQualifiedDomainName": "sql.database.windows.net"}}]},
            {"type": "sql_firewall_rule", "scope": SCOPE, "service": "sql", "status": status, "items": [
                {"id": server_id + "/firewallRules/" + name, "name": name,
                 "properties": {"startIpAddress": start, "endIpAddress": end}}
                for name, start, end in rules]}])
        return next(row for row in assess(snap, resources(snap)) if row.resource["type"] == "sql_server")

    private = [("private", "10.0.0.1", "10.0.0.2")]
    public = [("public", "8.8.8.8", "8.8.8.8")]
    assert decision(None, "collected", public).verdict() == "UNKNOWN"
    assert decision("Enabled", "partial", private).verdict() == "UNKNOWN"
    assert decision("Enabled", "partial", public).verdict() == "FAIL"
    assert decision("Enabled", "collected", private).verdict() == "UNKNOWN"


def test_sql_ipv6_firewall_rules_join_enabled_public_server():
    from peaso.collectors.azure import _sql_projected_child_pages, TYPES

    server_id = f"{SCOPE}/resourceGroups/rg/providers/Microsoft.Sql/servers/sql"
    rule_id = server_id + "/ipv6FirewallRules/allow-public"
    url = "https://management.azure.com" + server_id + "/ipv6FirewallRules?api-version=2025-01-01"
    row = {"id": rule_id, "name": "allow-public", "type": "Microsoft.Sql/servers/ipv6FirewallRules",
           "properties": {"startIPv6Address": "2606:4700:4700::1111",
                          "endIPv6Address": "2606:4700:4700::1111"}}

    class Reader:
        def pages(self, request, requested_url):
            assert requested_url == url
            yield [row]

    assert "sql_ipv6_firewall_rule" in TYPES
    assert list(_sql_projected_child_pages(Reader(), None, url, server_id,
                "sql_ipv6_firewall_rule", "ipv6FirewallRules"))[0][0]["id"] == rule_id
    with pytest.raises(ValueError):
        list(_sql_projected_child_pages(Reader(), None, url.replace("2025-01-01", "2023-08-01"),
             server_id, "sql_ipv6_firewall_rule", "ipv6FirewallRules"))

    def decision(ipv6_gate, ipv6_status="collected", rule=row):
        snap = make_snapshot("azure", [SCOPE], [
            {"type": "sql_server", "scope": SCOPE, "service": "sql", "status": "collected", "items": [
                {"id": server_id, "properties": {"publicNetworkAccess": "Enabled",
                 "isIPv6Enabled": ipv6_gate, "fullyQualifiedDomainName": "sql.database.windows.net"}}]},
            {"type": "sql_firewall_rule", "scope": SCOPE, "service": "sql", "status": "empty", "items": []},
            {"type": "sql_ipv6_firewall_rule", "scope": server_id, "service": "sql",
             "status": ipv6_status, "items": [rule] if rule is not None else []}])
        return next(a for a in assess(snap, resources(snap)) if a.resource["type"] == "sql_server")

    exposed = decision("Enabled")
    assert exposed.verdict() == "FAIL"
    assert exposed.path[-1]["open_rules"][0]["address_family"] == "IPv6"
    assert decision(None).verdict() == "UNKNOWN"
    assert decision("Disabled").verdict() == "UNKNOWN"
    private = {**row, "properties": {"startIPv6Address": "fd00::1", "endIPv6Address": "fd00::2"}}
    assert decision("Enabled", rule=private).verdict() == "UNKNOWN"
    assert decision("Enabled", ipv6_status="partial", rule=None).verdict() == "UNKNOWN"
    malformed = {**row, "properties": {"startIPv6Address": "bad", "endIPv6Address": "::1"}}
    assert decision("Enabled", rule=malformed).verdict() == "UNKNOWN"


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


def test_nic_public_return_route_uses_complete_effective_table():
    nic_id = f"{SCOPE}/resourceGroups/rg/providers/Microsoft.Network/networkInterfaces/nic"
    subnet_id = f"{SCOPE}/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet/subnets/subnet"
    nsg_id = f"{SCOPE}/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/nsg"
    pip_id = f"{SCOPE}/resourceGroups/rg/providers/Microsoft.Network/publicIPAddresses/pip"
    table_id = f"{SCOPE}/resourceGroups/rg/providers/Microsoft.Network/routeTables/rt"

    def verdict(hop=None, *, status="collected", extra=(), udr=None, route_status="collected"):
        collections = [
            {"type": "public_ip", "scope": SCOPE, "service": "network", "status": "collected",
             "items": [{"id": pip_id, "sku": {"name": "Standard"},
                        "properties": {"ipAddress": "52.1.2.3"}}]},
            {"type": "nsg", "scope": SCOPE, "service": "network", "status": "collected",
             "items": [{"id": nsg_id, "properties": {"securityRules": [{"name": "allow-ssh",
                 "properties": {"priority": 100, "direction": "Inbound", "access": "Allow",
                                "protocol": "Tcp", "sourceAddressPrefix": "*",
                                "destinationAddressPrefix": "*", "destinationPortRange": "22"}}]}}]},
            {"type": "subnet", "scope": SCOPE, "service": "network", "status": "collected",
             "items": [{"id": subnet_id, "properties": {
                 "routeTable": {"id": table_id}} if udr is not None else {}}]},
            {"type": "nic", "scope": SCOPE, "service": "network", "status": "collected",
             "items": [{"id": nic_id, "properties": {"networkSecurityGroup": {"id": nsg_id},
                 "ipConfigurations": [{"name": "primary", "properties": {"subnet": {"id": subnet_id},
                     "publicIPAddress": {"id": pip_id}, "privateIPAddress": "10.0.0.4"}}]}}]},
        ]
        if hop is not None:
            routes = [{"state": "Active", "source": "User", "addressPrefix": ["0.0.0.0/0"],
                       "nextHopType": hop},
                      {"state": "Active", "source": "Default", "addressPrefix": ["10.0.0.0/8"],
                       "nextHopType": "VnetLocal"}, *extra]
            items = [{"id": nic_id + f"/effectiveRoutes/{i}", "nic_id": nic_id,
                      "route": route, "_provenance": {"source_operation": "effectiveRouteTable",
                      "read_only": True, "nic_id": nic_id}} for i, route in enumerate(routes)]
            collections.append({"type": "effective_route", "scope": SCOPE, "service": "network",
                                "status": status, "items": items})
        if udr is not None:
            collections.append({"type": "route_table", "scope": SCOPE, "service": "network",
                                "status": route_status, "items": [{"id": table_id, "properties": {
                                    "routes": [{"name": f"route-{i}", "properties": route}
                                               for i, route in enumerate(udr)]}}]})
        snap = make_snapshot("azure", [SCOPE], collections)
        return next(row for row in assess(snap, resources(snap)) if row.resource["type"] == "nic")

    assert verdict().verdict() == "FAIL"  # No route inventory in this snapshot.
    dropped = verdict("None")
    assert dropped.verdict() == "PASS" and dropped.blocked_by == "return_route"
    assert verdict("VirtualAppliance").verdict() == "UNKNOWN"
    assert verdict("None", status="partial").verdict() == "UNKNOWN"
    exception = {"state": "Active", "source": "User", "addressPrefix": ["8.8.8.0/24"],
                 "nextHopType": "Internet"}
    assert verdict("None", extra=(exception,)).verdict() == "UNKNOWN"
    assert verdict(udr=[{"addressPrefix": "0.0.0.0/0", "nextHopType": "VirtualAppliance"}]).verdict() == "UNKNOWN"
    assert verdict(udr=[{"addressPrefix": "0.0.0.0/0", "nextHopType": "None"}]).verdict() == "UNKNOWN"
    assert verdict(udr=[{"addressPrefix": "0.0.0.0/0", "nextHopType": "Internet"}]).verdict() == "FAIL"
    assert verdict(udr=[{"addressPrefix": "8.8.8.0/24", "nextHopType": "None"}]).verdict() == "FAIL"
    assert verdict(udr=[{"addressPrefix": "10.0.0.0/8", "nextHopType": "None"}]).verdict() == "FAIL"
    assert verdict(udr=[], route_status="partial").verdict() == "UNKNOWN"


def test_nic_public_ip_reference_requires_assigned_global_address():
    base = f"{SCOPE}/resourceGroups/rg/providers/Microsoft.Network"
    nic_id, subnet_id = base + "/networkInterfaces/nic", base + "/virtualNetworks/v/subnets/s"

    def check(addresses):
        configs = [{"id": nic_id + "/ipConfigurations/" + name, "name": name,
                    "properties": {"privateIPAddress": "10.0.0." + str(index + 4),
                        "subnet": {"id": subnet_id},
                        "publicIPAddress": {"id": base + "/publicIPAddresses/" + name}}}
                   for index, name in enumerate(addresses)]
        snapshot = make_snapshot("azure", [SCOPE], [
            {"type": "nic", "scope": SCOPE, "service": "network", "status": "collected",
             "items": [{"id": nic_id, "properties": {"ipConfigurations": configs}}]},
            {"type": "public_ip", "scope": SCOPE, "service": "network", "status": "collected",
             "items": [{"id": base + "/publicIPAddresses/" + name, "sku": {"name": "Basic"},
                        "properties": {"ipAddress": address}}
                       for name, address in addresses.items() if address is not None]},
            {"type": "subnet", "scope": SCOPE, "service": "network", "status": "collected",
             "items": [{"id": subnet_id, "properties": {}}]}])
        return next(row for row in assess(snapshot, resources(snapshot))
                    if row.resource["type"] == "nic")

    assert check({"first": "8.8.8.8"}).verdict() == "FAIL"
    missing = check({"first": None})
    assert missing.verdict() == "UNKNOWN" and "is not collected" in _observed(missing, "UNKNOWN")
    unassigned = check({"first": ""})
    assert unassigned.verdict() == "UNKNOWN" and "no assigned global address" in _observed(unassigned, "UNKNOWN")
    assert check({"first": "10.0.0.5"}).verdict() == "UNKNOWN"
    mixed = check({"first": "8.8.8.8", "second": None})
    assert mixed.verdict() == "FAIL" and mixed.addresses == ["8.8.8.8"]


def test_nsg_joins_cached_subscription_service_tag_prefixes():
    nic_id = f"{SCOPE}/resourceGroups/rg/providers/Microsoft.Network/networkInterfaces/nic"
    subnet_id = f"{SCOPE}/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet/subnets/subnet"
    nsg_id = f"{SCOPE}/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/nsg"
    pip_id = f"{SCOPE}/resourceGroups/rg/providers/Microsoft.Network/publicIPAddresses/pip"

    def verdict(prefixes, status="collected", preceding_deny=False):
        rules = [{"name": "tag", "properties": {"priority": 200, "direction": "Inbound",
            "access": "Allow", "protocol": "Tcp", "sourceAddressPrefix": "AzureCloud",
            "destinationAddressPrefix": "*", "destinationPortRange": "443"}}]
        if preceding_deny:
            rules.insert(0, {"name": "unknown-deny", "properties": {"priority": 100,
                "direction": "Inbound", "access": "Deny", "protocol": "Tcp",
                "sourceAddressPrefix": "MissingTag", "destinationAddressPrefix": "*",
                "destinationPortRange": "443"}})
        snap = make_snapshot("azure", [SCOPE], [
            {"type": "service_tag", "scope": SCOPE, "service": "network", "status": status,
             "items": [{"id": SCOPE + "/providers/Microsoft.Network/serviceTags/AzureCloud",
                        "name": "AzureCloud", "properties": {"addressPrefixes": prefixes}}]},
            {"type": "public_ip", "scope": SCOPE, "service": "network", "status": "collected",
             "items": [{"id": pip_id, "sku": {"name": "Standard"},
                        "properties": {"ipAddress": "8.8.8.8"}}]},
            {"type": "nsg", "scope": SCOPE, "service": "network", "status": "collected",
             "items": [{"id": nsg_id, "properties": {"securityRules": rules}}]},
            {"type": "subnet", "scope": SCOPE, "service": "network", "status": "collected",
             "items": [{"id": subnet_id, "properties": {}}]},
            {"type": "nic", "scope": SCOPE, "service": "network", "status": "collected",
             "items": [{"id": nic_id, "properties": {"networkSecurityGroup": {"id": nsg_id},
                 "ipConfigurations": [{"name": "primary", "properties": {"subnet": {"id": subnet_id},
                     "publicIPAddress": {"id": pip_id}, "privateIPAddress": "10.0.0.4"}}]}}]}])
        return next(row for row in assess(snap, resources(snap)) if row.resource["type"] == "nic")

    assert verdict(["20.1.2.0/24"]).verdict() == "FAIL"
    assert verdict(["10.0.0.0/8"]).verdict() == "PASS"
    assert verdict(["20.1.2.0/24"], status="partial").verdict() == "UNKNOWN"
    assert verdict(["invalid"]).verdict() == "UNKNOWN"
    assert verdict(["20.1.2.0/24"], preceding_deny=True).verdict() == "UNKNOWN"


def test_nsg_unresolved_lower_priority_tag_does_not_hide_known_public_allow():
    rules = [
        {"name": "public", "properties": {"priority": 100, "direction": "Inbound",
            "access": "Allow", "protocol": "Tcp", "sourceAddressPrefix": "8.8.8.8/32",
            "destinationAddressPrefix": "*", "destinationPortRange": "443"}},
        {"name": "unknown", "properties": {"priority": 200, "direction": "Inbound",
            "access": "Deny", "protocol": "Tcp", "sourceAddressPrefix": "MissingTag",
            "destinationAddressPrefix": "*", "destinationPortRange": "443"}},
    ]
    allowed, matched = _nsg_allowed({"data": {"properties": {"securityRules": rules}}})
    assert allowed == {"tcp": ((443, 443),)}
    assert not any(row.get("unresolved_public_source") for row in matched)


def test_nsg_internet_destination_tag_does_not_match_private_nic_address():
    rule = {"name": "internet-destination", "properties": {"priority": 100,
        "direction": "Inbound", "access": "Allow", "protocol": "Tcp",
        "sourceAddressPrefix": "Internet", "destinationAddressPrefix": "Internet",
        "destinationPortRange": "443"}}
    nsg = {"data": {"properties": {"securityRules": [rule]}}}
    assert _nsg_allowed(nsg, address="10.0.0.4")[0] == {}
    assert _nsg_allowed(nsg, address="8.8.8.8")[0] == {"tcp": ((443, 443),)}
    rule["properties"]["destinationAddressPrefix"] = "0.0.0.0/0"
    assert _nsg_allowed(nsg, address="10.0.0.4")[0] == {"tcp": ((443, 443),)}


def test_nsg_azure_load_balancer_health_probe_tag_is_not_public_client():
    probe = {"name": "azure-probe", "properties": {"priority": 100,
        "direction": "Inbound", "access": "Allow", "protocol": "Tcp",
        "sourceAddressPrefix": "AzureLoadBalancer", "destinationAddressPrefix": "*",
        "destinationPortRange": "443"}}
    nsg = {"data": {"properties": {"securityRules": [probe]}}}
    allowed, matched = _nsg_allowed(nsg, address="10.0.0.4")
    assert allowed == {} and not any(row.get("unresolved_public_source") for row in matched)
    public = {"name": "public", "properties": {**probe["properties"], "priority": 200,
        "sourceAddressPrefix": "8.8.8.8/32"}}
    allowed, matched = _nsg_allowed({"data": {"properties": {"securityRules": [probe, public]}}},
                                    address="10.0.0.4")
    assert allowed == {"tcp": ((443, 443),)}
    assert any(row.get("rule") == "public" for row in matched)


def test_container_app_requires_public_environment_and_effective_ingress():
    env_id = f"{SCOPE}/resourceGroups/rg/providers/Microsoft.App/managedEnvironments/env"
    app_id = f"{SCOPE}/resourceGroups/rg/providers/Microsoft.App/containerApps/app"

    def app_decision(env_public="Enabled", rules=None, transport="http", extra=None,
                     allow_insecure=None, fqdn="app.example.azurecontainerapps.io", domains=None):
        ingress = {"external": True, "transport": transport, "fqdn": fqdn,
                   "ipSecurityRestrictions": rules if rules is not None else []}
        if domains is not None:
            ingress["customDomains"] = domains
        if allow_insecure is not None:
            ingress["allowInsecure"] = allow_insecure
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

    redirected = app_decision()
    assert redirected.verdict() == "FAIL" and redirected.ports == {"tcp": ((80, 80), (443, 443))}
    assert "Port 80 redirects HTTP to HTTPS" in _observed(redirected, "FAIL")
    insecure = app_decision(allow_insecure=True)
    assert insecure.verdict() == "FAIL" and "permits insecure HTTP" in _observed(insecure, "FAIL")
    assert app_decision(allow_insecure="unknown").verdict() == "UNKNOWN"
    assert app_decision(env_public="Disabled").verdict() == "PASS"
    assert app_decision(env_public=None).verdict() == "UNKNOWN"
    private_allow = [{"action": "Allow", "ipAddressRange": "10.0.0.0/8"}]
    public_allow = [{"action": "Allow", "ipAddressRange": "8.8.8.8/32"}]
    assert app_decision(rules=private_allow).verdict() == "PASS"
    assert app_decision(rules=public_allow).verdict() == "FAIL"
    assert app_decision(rules=private_allow[0]).verdict() == "UNKNOWN"
    assert app_decision(rules="").verdict() == "UNKNOWN"
    custom = app_decision(fqdn=None, domains=[
        {"name": "custom.example.org", "bindingType": "SniEnabled"},
        {"name": "disabled.example.org", "bindingType": "Disabled"}])
    assert custom.verdict() == "FAIL" and custom.addresses == ["custom.example.org"]
    assert app_decision(fqdn=None, domains=[
        {"name": "disabled.example.org", "bindingType": "Disabled"}]).verdict() == "UNKNOWN"
    tcp = app_decision(transport="tcp", extra=[{"external": True, "exposedPort": 9000}])
    assert tcp.verdict() == "FAIL" and tcp.ports == {"tcp": ((8443, 8443), (9000, 9000))}


def test_container_app_recorded_stopped_runtime_blocks_external_ingress():
    app_id = f"{SCOPE}/resourceGroups/rg/providers/Microsoft.App/containerApps/app"
    env_id = f"{SCOPE}/resourceGroups/rg/providers/Microsoft.App/managedEnvironments/env"

    def app_decision(status, *, replicas=0, active=True, proven=True):
        snap = make_snapshot("azure", [SCOPE], [
            {"type": "container_app_environment", "scope": SCOPE, "service": "app", "status": "collected",
             "items": [{"id": env_id, "properties": {"publicNetworkAccess": "Enabled",
                 "vnetConfiguration": {"internal": False}}}]},
            {"type": "container_app", "scope": SCOPE, "service": "app", "status": "collected",
             "items": [{"id": app_id, "properties": {"managedEnvironmentId": env_id,
                 "configuration": {"ingress": {"external": True, "transport": "http",
                     "fqdn": "app.example.azurecontainerapps.io"}}, "provisioningState": "Succeeded"}}]},
            {"type": "container_app_runtime", "scope": SCOPE, "service": "app", "status": "collected",
             "items": [{"id": app_id, "properties": {"runningStatus": status,
                 "provisioningState": "Succeeded"},
                 **({"_provenance": {"method": "GET+LIST", "read_only": True}} if proven else {}),
                 "revisions": [{"id": app_id + "/revisions/current", "properties": {
                     "active": active, "runningState": "Running", "replicas": replicas}}]}]},
        ])
        return next(a for a in assess(snap, resources(snap)) if a.resource["type"] == "container_app")

    stopped = app_decision("Stopped")
    assert stopped.verdict() == "PASS" and stopped.path[0]["running_status"] == "Stopped"
    assert len(_observed(stopped, "PASS").splitlines()) == 3
    assert app_decision("Running", replicas=0).verdict() == "FAIL"  # Scale to zero can resume.
    inactive = app_decision("Running", active=False)
    assert inactive.verdict() == "PASS" and "complete runtime revision list" in _observed(inactive, "PASS")
    assert app_decision("Running", active=False, proven=False).verdict() == "FAIL"
    progressing = app_decision("Progressing")
    assert progressing.verdict() == "UNKNOWN"
    assert "public request path is unresolved" in _observed(progressing, "UNKNOWN")


def test_container_app_active_revision_label_routes_with_zero_app_traffic_weight():
    from peaso.collectors.azure_containerapp_runtime import _project

    app_id = f"{SCOPE}/resourceGroups/rg/providers/Microsoft.App/containerApps/app"
    env_id = f"{SCOPE}/resourceGroups/rg/providers/Microsoft.App/managedEnvironments/env"
    label_fqdn = "app---staging.example.azurecontainerapps.io"
    projected = _project({"id": app_id, "type": "Microsoft.App/containerApps",
                          "identity": {"type": "None"},
                          "properties": {"runningStatus": "Running", "provisioningState": "Succeeded"}},
                         [{"id": app_id + "/revisions/rev1", "properties": {
                             "active": True, "trafficWeight": 0, "healthState": "Healthy",
                             "fqdn": "app--rev1.example.azurecontainerapps.io",
                             "template": {"secrets": ["must-not-copy"]}}},
                          {"id": app_id + "/revisions/old", "properties": {
                             "active": False, "trafficWeight": 0, "fqdn": "old.example.azurecontainerapps.io"}}], app_id)
    assert "must-not-copy" not in repr(projected)
    assert projected["revisions"][0]["properties"]["trafficWeight"] == 0
    snap = make_snapshot("azure", [SCOPE], [
        {"type": "container_app_environment", "scope": SCOPE, "service": "app", "status": "collected",
         "items": [{"id": env_id, "properties": {"publicNetworkAccess": "Enabled",
             "defaultDomain": "example.azurecontainerapps.io",
             "vnetConfiguration": {"internal": False}}}]},
        {"type": "container_app", "scope": SCOPE, "service": "app", "status": "collected",
         "items": [{"id": app_id, "properties": {"managedEnvironmentId": env_id,
             "configuration": {"ingress": {"external": True, "transport": "http",
                 "fqdn": "app.example.azurecontainerapps.io",
                 "traffic": [{"revisionName": "rev1", "weight": 0, "label": "staging"},
                             {"revisionName": "old", "weight": 0, "label": "old"}]}},
             "provisioningState": "Succeeded"}}]},
        {"type": "container_app_runtime", "scope": SCOPE, "service": "app", "status": "collected",
         "items": [projected]},
    ])
    row = next(a for a in assess(snap, resources(snap)) if a.resource["type"] == "container_app")
    assert row.verdict() == "FAIL"
    assert label_fqdn in row.addresses
    assert "app---old.example.azurecontainerapps.io" not in row.addresses
    assert "traffic weight" in _observed(row, "FAIL")
    assert len(_observed(row, "FAIL").splitlines()) == 3


def test_container_app_internal_ingress_can_be_targeted_by_environment_http_route():
    from peaso.collectors.azure import _child_rows

    app_id = f"{SCOPE}/resourceGroups/rg/providers/Microsoft.App/containerApps/app"
    env_id = f"{SCOPE}/resourceGroups/rg/providers/Microsoft.App/managedEnvironments/env"
    fqdn = "edge.example.azurecontainerapps.io"
    route = {"id": env_id + "/httpRouteConfigs/edge",
             "type": "Microsoft.App/managedEnvironments/httpRouteConfigs",
             "properties": {"provisioningState": "Succeeded", "fqdn": fqdn,
                            "rules": [{"targets": [{"containerApp": "app"}]}]}}
    assert _child_rows([route], env_id, "httpRouteConfigs")[0]["id"] == route["id"]
    with pytest.raises(ValueError):
        _child_rows([{**route, "id": env_id + "/httpRouteConfigs/../foreign"}], env_id,
                    "httpRouteConfigs")
    with pytest.raises(ValueError):
        _child_rows([{**route, "properties": {**route["properties"], "fqdn": None}}], env_id,
                    "httpRouteConfigs")

    def decision(routes, status="collected", public="Enabled", app_rules=None, external=False,
                 runtime=None, traffic=None):
        ingress = {"external": external, "transport": "http"}
        if app_rules is not None:
            ingress["ipSecurityRestrictions"] = app_rules
        if traffic is not None:
            ingress["traffic"] = traffic
        collections = [
            {"type": "container_app_environment", "scope": SCOPE, "service": "app", "status": "collected",
             "items": [{"id": env_id, "properties": {"publicNetworkAccess": public,
                 "vnetConfiguration": {"internal": False}},
                 "httpRouteConfigs": routes, "_coverage": {"httpRouteConfigs": {"status": status}}}]},
            {"type": "container_app", "scope": SCOPE, "service": "app", "status": "collected",
             "items": [{"id": app_id, "properties": {"managedEnvironmentId": env_id,
                 "configuration": {"ingress": ingress}, "provisioningState": "Succeeded"}}]},
        ]
        if runtime is not None:
            collections.append({"type": "container_app_runtime", "scope": SCOPE,
                                "service": "app", "status": "collected", "items": [runtime]})
        snap = make_snapshot("azure", [SCOPE], collections)
        return [a for a in assess(snap, resources(snap)) if a.resource["type"] == "container_app"]

    exposed = decision([route])[0]
    assert exposed.verdict() == "FAIL" and fqdn in exposed.addresses
    assert "internal ingress but an environment HTTP route" in _observed(exposed, "FAIL")
    assert len(_observed(exposed, "FAIL").splitlines()) == 3
    custom = {**route, "properties": {**route["properties"], "fqdn": None,
        "customDomains": [{"name": "route.example.com", "bindingType": "SniEnabled",
                           "certificateId": env_id + "/certificates/route"}]}}
    assert _child_rows([custom], env_id, "httpRouteConfigs")[0]["id"] == custom["id"]
    custom_row = decision([custom])[0]
    assert custom_row.verdict() == "FAIL"
    assert custom_row.addresses == ["route.example.com"]
    assert custom_row.ports == {"tcp": ((443, 443),)}
    disabled_custom = {**custom, "properties": {**custom["properties"],
        "customDomains": [{**custom["properties"]["customDomains"][0], "bindingType": "Disabled"}]}}
    assert _child_rows([disabled_custom], env_id, "httpRouteConfigs")[0]["id"] == route["id"]
    disabled_row = decision([disabled_custom])[0]
    assert disabled_row.verdict() == "FAIL"
    assert disabled_row.addresses == ["route.example.com"]
    assert disabled_row.ports == {"tcp": ((80, 80),)}
    auto_custom = {**disabled_custom, "properties": {**disabled_custom["properties"],
        "customDomains": [{**disabled_custom["properties"]["customDomains"][0],
                           "bindingType": "Auto", "certificateId": None}]}}
    assert _child_rows([auto_custom], env_id, "httpRouteConfigs")[0]["id"] == route["id"]
    auto_row = decision([auto_custom])[0]
    assert auto_row.verdict() == "FAIL"
    assert auto_row.addresses == ["route.example.com"]
    assert auto_row.ports == {"tcp": ((80, 80),)}
    assert any(step.get("binding_types") == ["Auto"] for step in auto_row.path)
    unbound = {**custom, "properties": {**custom["properties"],
        "customDomains": [{**custom["properties"]["customDomains"][0], "certificateId": None}]}}
    with pytest.raises(ValueError):
        _child_rows([unbound], env_id, "httpRouteConfigs")
    assert decision([unbound])[0].verdict() == "UNKNOWN"
    both = {**custom, "properties": {**custom["properties"], "fqdn": fqdn}}
    assert set(decision([both])[0].addresses) == {fqdn, "route.example.com"}
    assert decision([route], public="Disabled")[0].verdict() == "PASS"
    assert decision([]) == []
    assert decision([], status="partial")[0].verdict() == "UNKNOWN"
    assert decision([], external=None)[0].verdict() == "UNKNOWN"
    for state in (None, "Updating", "Failed"):
        unresolved_route = {**route, "properties": {**route["properties"],
                            "provisioningState": state}}
        row = decision([unresolved_route])[0]
        assert row.verdict() == "UNKNOWN"
        assert any(gap["layer"] == "inventory" for gap in row.unresolved)
    other = {**route, "properties": {**route["properties"],
                                     "rules": [{"targets": [{"containerApp": "other"}]}]}}
    assert decision([other]) == []
    private_rules = [{"action": "Allow", "ipAddressRange": "10.0.0.0/8"}]
    assert decision([route], app_rules=private_rules)[0].verdict() == "UNKNOWN"
    targeted = {**route, "properties": {**route["properties"], "rules": [{"targets": [
        {"containerApp": "app", "revision": "old"}]}]}}
    runtime = {"id": app_id, "properties": {"runningStatus": "Running",
               "provisioningState": "Succeeded"},
               "revisions": [{"id": app_id + "/revisions/old", "properties": {"active": False}},
                             {"id": app_id + "/revisions/current", "properties": {"active": True}}],
               "_provenance": {"method": "GET+LIST", "read_only": True}}
    assert decision([targeted], runtime=runtime) == []
    unresolved_target = decision([targeted])[0]
    assert unresolved_target.verdict() == "UNKNOWN"
    assert "cannot be resolved to an active revision" in _observed(unresolved_target, "UNKNOWN")
    active_target = {**targeted, "properties": {**targeted["properties"], "rules": [{"targets": [
        {"containerApp": "app", "revision": "current"}]}]}}
    assert decision([active_target], runtime=runtime)[0].verdict() == "FAIL"
    labeled = {**targeted, "properties": {**targeted["properties"], "rules": [{"targets": [
        {"containerApp": "app", "label": "preview"}]}]}}
    assert decision([labeled], runtime=runtime)[0].verdict() == "UNKNOWN"
    assert decision([labeled], runtime=runtime, traffic=[
        {"label": "preview", "revisionName": "old", "weight": 0}]) == []
    assert decision([labeled], runtime=runtime, traffic=[
        {"label": "preview", "revisionName": "current", "weight": 0}])[0].verdict() == "FAIL"
    assert decision([labeled], runtime=runtime, traffic=[
        {"label": "preview", "revisionName": "current", "weight": 0},
        {"label": "preview", "revisionName": "old", "weight": 0}])[0].verdict() == "UNKNOWN"


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
    wildcard = firewall_decision([{**rule, "sourceAddresses": ["*"]}])
    assert wildcard.verdict() == "UNKNOWN" and wildcard.ports == {"tcp": ((443, 443),)}
    assert not any(gap["layer"] == "policy" for gap in wildcard.unresolved)
    assert firewall_decision([{**rule, "sourceAddresses": ["10.0.0.0/8"]}]).verdict() == "PASS"
    assert firewall_decision([]).verdict() == "PASS"
    assert firewall_decision([], policy="/policy").verdict() == "UNKNOWN"


def test_firewall_dnat_unique_translated_vm_powered_off_blocks_current_backend():
    base = f"{SCOPE}/resourceGroups/rg/providers/Microsoft.Network"
    ip_id, nic_id = base + "/publicIPAddresses/fw", base + "/networkInterfaces/backend"
    vm_id = f"{SCOPE}/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/backend"
    firewall_id = base + "/azureFirewalls/fw"
    rule = {"name": "web", "sourceAddresses": ["*"], "destinationAddresses": ["8.8.8.8"],
            "destinationPorts": ["443"], "protocols": ["TCP"],
            "translatedAddress": "10.0.0.4", "translatedPort": "8443"}

    def check(power, *, duplicate=False, second_rule=False):
        rules = [rule]
        if second_rule:
            rules.append({**rule, "name": "other", "destinationPorts": ["8443"],
                          "translatedAddress": "10.0.0.5"})
        nic = {"id": nic_id, "properties": {"virtualMachine": {"id": vm_id},
            "ipConfigurations": [{"properties": {"privateIPAddress": "10.0.0.4"}}]}}
        nics = [nic]
        if duplicate:
            nics.append({"id": base + "/networkInterfaces/duplicate",
                         "properties": {"ipConfigurations": [{"properties": {
                             "privateIPAddress": "10.0.0.4"}}]}})
        snapshot = make_snapshot("azure", [SCOPE], [
            {"type": "public_ip", "scope": SCOPE, "service": "network", "status": "collected",
             "items": [{"id": ip_id, "properties": {"ipAddress": "8.8.8.8"}}]},
            {"type": "azure_firewall", "scope": SCOPE, "service": "network", "status": "collected",
             "items": [{"id": firewall_id, "properties": {"ipConfigurations": [{"properties": {
                 "publicIPAddress": {"id": ip_id}}}], "natRuleCollections": [{"name": "nat",
                 "properties": {"action": {"type": "Dnat"}, "rules": rules}}]}}]},
            {"type": "nic", "scope": SCOPE, "service": "network", "status": "collected", "items": nics},
            {"type": "vm", "scope": SCOPE, "service": "compute", "status": "collected",
             "items": [{"id": vm_id, "properties": {"instanceView": {"statuses": [
                 {"code": "PowerState/" + power}]}}}]}])
        return next(row for row in assess(snapshot, resources(snapshot))
                    if row.resource["type"] == "azure_firewall")

    for power in ("stopped", "deallocated"):
        blocked = check(power)
        assert blocked.verdict() == "UNKNOWN" and blocked.ports == {"tcp": ((443, 443),)}
        assert blocked.path[-1]["stopped_vm_candidates"][0]["power_state"] == "PowerState/" + power
        assert any(gap["layer"] == "backend" for gap in blocked.unresolved)
        assert "effective route to that private address is not observed" in _observed(blocked, "UNKNOWN")
    assert check("running").verdict() == "UNKNOWN"
    assert check("deallocated", duplicate=True).verdict() == "UNKNOWN"
    assert check("deallocated", second_rule=True).verdict() == "UNKNOWN"


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


def test_firewall_policy_parent_dnat_is_not_inherited():
    policy_id = f"{SCOPE}/resourceGroups/rg/providers/Microsoft.Network/firewallPolicies/child"
    parent_id = f"{SCOPE}/resourceGroups/rg/providers/Microsoft.Network/firewallPolicies/parent"
    public_id = f"{SCOPE}/resourceGroups/rg/providers/Microsoft.Network/publicIPAddresses/fw"
    firewall_id = f"{SCOPE}/resourceGroups/rg/providers/Microsoft.Network/azureFirewalls/fw"
    snap = make_snapshot("azure", [SCOPE], [
        {"type": "public_ip", "scope": SCOPE, "service": "network", "status": "collected",
         "items": [{"id": public_id, "properties": {"ipAddress": "8.8.8.8"}}]},
        {"type": "firewall_policy", "scope": SCOPE, "service": "network", "status": "collected",
         "items": [{"id": policy_id, "properties": {"basePolicy": {"id": parent_id}},
                    "_coverage": {"ruleCollectionGroups": {"status": "empty"}},
                    "ruleCollectionGroups": []}]},
        {"type": "azure_firewall", "scope": SCOPE, "service": "network", "status": "collected",
         "items": [{"id": firewall_id, "properties": {"firewallPolicy": {"id": policy_id},
                    "ipConfigurations": [{"properties": {"publicIPAddress": {"id": public_id}}}]}}]},
    ])
    row = next(a for a in assess(snap, resources(snap)) if a.resource["type"] == "azure_firewall")
    assert row.verdict() == "PASS"
    assert row.path[-1]["layer"] == "dnat" and row.path[-1]["decision"] == "block"


def test_firewall_dnat_source_ip_group_membership_uses_recorded_arm_addresses():
    from peaso.collectors.azure import ENDPOINTS

    assert ENDPOINTS["ip_group"] == ("Microsoft.Network/ipGroups", "2025-05-01")
    public_id = f"{SCOPE}/resourceGroups/rg/providers/Microsoft.Network/publicIPAddresses/fw"
    group_id = f"{SCOPE}/resourceGroups/rg/providers/Microsoft.Network/ipGroups/sources"
    firewall_id = f"{SCOPE}/resourceGroups/rg/providers/Microsoft.Network/azureFirewalls/fw"
    rule = {"name": "web", "sourceAddresses": [], "sourceIpGroups": [group_id],
            "destinationAddresses": ["8.8.8.8"], "destinationPorts": ["443"],
            "protocols": ["TCP"], "translatedAddress": "10.0.0.4", "translatedPort": "8443"}

    def decision(group_addresses, *, reference=group_id, state="Succeeded", direct=None):
        current_rule = {**rule, "sourceIpGroups": [reference], "sourceAddresses": direct or []}
        collections = [
            {"type": "public_ip", "scope": SCOPE, "service": "network", "status": "collected",
             "items": [{"id": public_id, "properties": {"ipAddress": "8.8.8.8"}}]},
            {"type": "azure_firewall", "scope": SCOPE, "service": "network", "status": "collected",
             "items": [{"id": firewall_id, "properties": {"ipConfigurations": [
                 {"properties": {"publicIPAddress": {"id": public_id}}}],
                 "natRuleCollections": [{"name": "nat", "properties": {
                     "action": {"type": "Dnat"}, "rules": [current_rule]}}]}}]},
            {"type": "ip_group", "scope": SCOPE, "service": "network", "status": "collected",
             "items": [] if group_addresses is None else [{"id": group_id, "properties": {
                 "ipAddresses": group_addresses, "provisioningState": state}}]},
        ]
        snap = make_snapshot("azure", [SCOPE], collections)
        return next(a for a in assess(snap, resources(snap)) if a.resource["type"] == "azure_firewall")

    public = decision(["10.0.0.0/8", "1.1.1.1/32"])
    assert public.verdict() == "UNKNOWN" and public.ports == {"tcp": ((443, 443),)}
    assert any(gap["layer"] == "backend" for gap in public.unresolved)
    assert decision(["10.0.0.0/8"]).verdict() == "PASS"
    assert decision([]).verdict() == "PASS"
    assert decision(None).verdict() == "UNKNOWN"
    assert decision(["bad//"]).verdict() == "UNKNOWN"
    assert decision(["10.0.0.0/8"], reference="").verdict() == "UNKNOWN"
    assert decision(["1.1.1.1/32"], state="Updating").verdict() == "UNKNOWN"
    assert decision(["10.0.0.0/8"], direct=["1.1.1.1/32"]).ports == {"tcp": ((443, 443),)}


def test_frontdoor_edge_listener_uses_effective_routes_and_keeps_backend_uncertain():
    edge_id = f"{SCOPE}/resourceGroups/rg/providers/Microsoft.Cdn/profiles/edge"
    endpoint = {"id": edge_id + "/afdEndpoints/default",
                "properties": {"hostName": "edge.azurefd.net"}}
    route = {"id": endpoint["id"] + "/routes/default", "enabledState": "Enabled",
             "boundHostNames": ["edge.azurefd.net"],
             "paths": [{"acceptedProtocols": ["Http"], "action": "Redirect"},
                       {"acceptedProtocols": ["Https"], "action": "Forward"}]}

    def edge_decision(routes, status="collected", hostname=True):
        item = {"id": edge_id, "sku": {"name": "Standard_AzureFrontDoor"},
                "properties": {}, "endpoints": [endpoint] if hostname else [],
                "effectiveRoutes": routes, "securityPolicies": [],
                "_coverage": {"effectiveRoutes": {"status": status},
                              "securityPolicies": {"status": "empty"}}}
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
    old_projection = {**route, "boundHostNames": None,
                      "paths": [{"acceptedProtocols": ["Http"], "action": "Redirect"}]}
    assert edge_decision([old_projection]).verdict() == "UNKNOWN"


def test_afd_disabled_endpoint_blocks_enabled_child_route():
    from peaso.collectors.azure_frontdoor_native import _routes

    profile = f"{SCOPE}/resourceGroups/rg/providers/Microsoft.Cdn/profiles/edge"
    endpoint_id = profile + "/afdEndpoints/default"
    group_id = profile + "/originGroups/main"
    route = {"id": endpoint_id + "/routes/all", "type": "Microsoft.Cdn/profiles/afdEndpoints/routes",
             "properties": {"enabledState": "Enabled", "patternsToMatch": ["/*"],
                 "ruleSets": [], "customDomains": [], "linkToDefaultDomain": "Enabled",
                 "originGroup": {"id": group_id}, "supportedProtocols": ["Https"],
                 "forwardingProtocol": "HttpsOnly", "httpsRedirect": "Disabled"}}

    def projected(endpoint_state):
        item = {"id": profile, "sku": {"name": "Standard_AzureFrontDoor"}, "properties": {},
                "endpoints": [{"id": endpoint_id, "properties": {
                    "hostName": "edge.azurefd.net", "enabledState": endpoint_state}},
                    {"id": profile + "/afdEndpoints/unbound", "properties": {
                    "hostName": "unbound.azurefd.net", "enabledState": "Enabled"}}],
                "originGroups": [{"id": group_id}], "domains": [], "securityPolicies": []}
        _routes(item, "afd", [route])
        snap = make_snapshot("azure", [SCOPE], [{"type": "frontdoor_and_cdn_endpoint",
            "scope": SCOPE, "service": "cdn", "status": "collected", "items": [item]}])
        return next(a for a in assess(snap, resources(snap))
                    if a.resource["type"] == "frontdoor_and_cdn_endpoint")

    blocked = projected("Disabled")
    assert blocked.verdict() == "PASS" and blocked.ports == {}
    enabled = projected("Enabled")
    assert enabled.verdict() == "UNKNOWN"  # Origin access still unresolved.
    assert enabled.addresses == ["edge.azurefd.net"]
    assert projected(None).verdict() == "UNKNOWN"


def test_classic_frontdoor_disabled_parent_blocks_enabled_routing_rule():
    from peaso.collectors.azure_frontdoor_native import _routes

    frontdoor = f"{SCOPE}/resourceGroups/rg/providers/Microsoft.Network/frontDoors/edge"
    domain = frontdoor + "/frontendEndpoints/default"
    rule = {"id": frontdoor + "/routingRules/all", "type": "Microsoft.Network/frontDoors/routingRules",
            "properties": {"enabledState": "Enabled", "patternsToMatch": ["/*"],
                "frontendEndpoints": [{"id": domain}], "acceptedProtocols": ["Https"],
                "routeConfiguration": {"@odata.type": "#Microsoft.Azure.FrontDoor.Models.FrontdoorRedirectConfiguration",
                                       "redirectProtocol": "HttpsOnly"}}}

    def projected(parent_state):
        item = {"id": frontdoor, "properties": {"enabledState": parent_state},
                "domains": [{"id": domain, "properties": {"hostName": "edge.azurefd.net"}},
                            {"id": frontdoor + "/frontendEndpoints/unbound",
                             "properties": {"hostName": "unbound.azurefd.net"}}],
                "endpoints": [{"id": domain, "properties": {"hostName": "edge.azurefd.net"}}]}
        _routes(item, "classicFrontDoor", [rule])
        snap = make_snapshot("azure", [SCOPE], [{"type": "frontdoor_and_cdn_endpoint",
            "scope": SCOPE, "service": "cdn", "status": "collected", "items": [item]}])
        return next(a for a in assess(snap, resources(snap))
                    if a.resource["type"] == "frontdoor_and_cdn_endpoint")

    assert projected("Disabled").verdict() == "PASS"
    enabled = projected("Enabled")
    assert enabled.verdict() == "FAIL" and enabled.addresses == ["edge.azurefd.net"]
    assert projected(None).verdict() == "UNKNOWN"


def test_afd_route_hostnames_use_bound_custom_domain_only():
    from peaso.collectors.azure_frontdoor_native import _routes

    profile = f"{SCOPE}/resourceGroups/rg/providers/Microsoft.Cdn/profiles/edge"
    endpoint = profile + "/afdEndpoints/default"
    domain = profile + "/customDomains/bound"
    inactive = profile + "/customDomains/inactive"
    group = profile + "/originGroups/main"
    route = {"id": endpoint + "/routes/redirect", "type": "Microsoft.Cdn/profiles/afdEndpoints/routes",
             "properties": {"enabledState": "Enabled", "patternsToMatch": ["/*"],
                "ruleSets": [], "customDomains": [{"id": domain}, {"id": inactive, "isActive": False}],
                "linkToDefaultDomain": "Disabled", "originGroup": {"id": group},
                "supportedProtocols": ["Http"], "forwardingProtocol": "HttpsOnly",
                "httpsRedirect": "Enabled"}}
    item = {"id": profile, "sku": {"name": "Standard_AzureFrontDoor"}, "properties": {},
            "endpoints": [{"id": endpoint, "properties": {"hostName": "unbound.azurefd.net",
                            "enabledState": "Enabled"}}],
            "domains": [{"id": domain, "properties": {"hostName": "bound.example.org"}},
                        {"id": inactive, "properties": {"hostName": "inactive.example.org"}}],
            "originGroups": [{"id": group}], "securityPolicies": []}
    _routes(item, "afd", [route])
    item["_coverage"]["securityPolicies"] = {"status": "empty"}
    snap = make_snapshot("azure", [SCOPE], [{"type": "frontdoor_and_cdn_endpoint",
        "scope": SCOPE, "service": "cdn", "status": "collected", "items": [item]}])
    result = next(a for a in assess(snap, resources(snap))
                  if a.resource["type"] == "frontdoor_and_cdn_endpoint")
    assert result.verdict() == "FAIL"
    assert result.addresses == ["bound.example.org"]


def test_frontdoor_detection_or_disabled_waf_does_not_block_redirect_listener():
    profile = f"{SCOPE}/resourceGroups/rg/providers/Microsoft.Cdn/profiles/edge"
    waf_id = f"{SCOPE}/resourceGroups/rg/providers/Microsoft.Network/frontDoorWebApplicationFirewallPolicies/waf"
    edge = {"id": profile, "sku": {"name": "Premium_AzureFrontDoor"},
            "properties": {}, "endpoints": [{"id": profile + "/afdEndpoints/default",
                "properties": {"hostName": "edge.azurefd.net"}}],
            "effectiveRoutes": [{"id": profile + "/afdEndpoints/default/routes/redirect",
                "enabledState": "Enabled", "boundHostNames": ["edge.azurefd.net"], "paths": [{"acceptedProtocols": ["Http"],
                    "action": "Redirect"}]}],
            "securityPolicies": [{"id": profile + "/securityPolicies/waf",
                "properties": {"parameters": {"type": "WebApplicationFirewall",
                    "wafPolicy": {"id": waf_id}}}}],
            "_coverage": {"effectiveRoutes": {"status": "collected"},
                          "securityPolicies": {"status": "collected"}}}

    def decision(mode=None, enabled=None, include=True, rule_state=None):
        collections = [{"type": "frontdoor_and_cdn_endpoint", "scope": SCOPE,
                        "service": "cdn", "status": "collected", "items": [edge]}]
        if include:
            waf_props = {"policySettings": {"mode": mode, "enabledState": enabled}}
            if rule_state is not None:
                waf_props["customRules"] = {"rules": [] if rule_state != "custom" else [{"name": "block"}]}
                waf_props["managedRules"] = {"managedRuleSets": [] if rule_state != "managed" else [{"ruleSetType": "DefaultRuleSet"}]}
            collections.append({"type": "frontdoor_waf_policy", "scope": SCOPE,
                                "service": "network", "status": "collected", "items": [
                                    {"id": waf_id, "properties": waf_props}]})
        snap = make_snapshot("azure", [SCOPE], collections)
        return next(a for a in assess(snap, resources(snap))
                    if a.resource["type"] == "frontdoor_and_cdn_endpoint")

    detected = decision(mode="Detection", enabled="Enabled")
    assert detected.verdict() == "FAIL"
    assert "records mode Detection" in _observed(detected, "FAIL")
    assert len(_observed(detected, "FAIL").splitlines()) == 3
    assert decision(mode="Prevention", enabled="Disabled").verdict() == "FAIL"
    assert decision(mode="Prevention", enabled="Enabled").verdict() == "UNKNOWN"
    empty_policy = decision(mode="Prevention", enabled="Enabled", rule_state="empty")
    assert empty_policy.verdict() == "FAIL"
    assert "explicitly empty custom and managed rule lists" in _observed(empty_policy, "FAIL")
    assert decision(mode="Prevention", enabled="Enabled", rule_state="custom").verdict() == "UNKNOWN"
    assert decision(mode="Prevention", enabled="Enabled", rule_state="managed").verdict() == "UNKNOWN"
    assert decision(include=False).verdict() == "UNKNOWN"
    edge["_coverage"]["securityPolicies"] = {"status": "partial"}
    assert decision(mode="Detection", enabled="Enabled").verdict() == "UNKNOWN"
    edge["securityPolicies"] = []
    assert decision(mode="Detection", enabled="Enabled").verdict() == "UNKNOWN"


def test_afd_unrelated_waf_policy_does_not_filter_bound_route():
    profile = f"{SCOPE}/resourceGroups/rg/providers/Microsoft.Cdn/profiles/edge"
    endpoint = profile + "/afdEndpoints/default"
    unrelated = profile + "/customDomains/other"
    waf_id = f"{SCOPE}/resourceGroups/rg/providers/Microsoft.Network/frontDoorWebApplicationFirewallPolicies/waf"

    def decision(bound_ids, associations):
        edge = {"id": profile, "sku": {"name": "Premium_AzureFrontDoor"},
            "endpoints": [{"id": endpoint, "properties": {"hostName": "edge.azurefd.net"}}],
            "effectiveRoutes": [{"id": endpoint + "/routes/redirect", "enabledState": "Enabled",
                "boundHostNames": ["edge.azurefd.net"], "boundDomainIds": bound_ids,
                "paths": [{"acceptedProtocols": ["Http"], "action": "Redirect"}]}],
            "securityPolicies": [{"id": profile + "/securityPolicies/other",
                "properties": {"parameters": {"type": "WebApplicationFirewall",
                    "wafPolicy": {"id": waf_id}, "associations": associations}}}],
            "_coverage": {"effectiveRoutes": {"status": "collected"},
                          "securityPolicies": {"status": "collected"}}}
        snap = make_snapshot("azure", [SCOPE], [{"type": "frontdoor_and_cdn_endpoint",
            "scope": SCOPE, "service": "cdn", "status": "collected", "items": [edge]}])
        return next(a for a in assess(snap, resources(snap))
                    if a.resource["type"] == "frontdoor_and_cdn_endpoint")

    other_association = [{"domains": [{"id": unrelated}], "patternsToMatch": ["/*"]}]
    assert decision([endpoint], other_association).verdict() == "FAIL"
    assert decision(None, other_association).verdict() == "UNKNOWN"
    assert decision([endpoint], [{"domains": [{"id": endpoint}],
                                 "patternsToMatch": ["/*"]}]).verdict() == "UNKNOWN"
    assert decision([endpoint], [{"domains": "malformed"}]).verdict() == "UNKNOWN"


def test_classic_frontdoor_frontend_waf_link_is_joined_to_policy():
    frontdoor = f"{SCOPE}/resourceGroups/rg/providers/Microsoft.Network/frontDoors/edge"
    waf_id = f"{SCOPE}/resourceGroups/rg/providers/Microsoft.Network/frontDoorWebApplicationFirewallPolicies/waf"
    edge = {"id": frontdoor, "properties": {},
            "endpoints": [{"id": frontdoor + "/frontendEndpoints/default",
                "properties": {"hostName": "edge.azurefd.net",
                               "webApplicationFirewallPolicyLink": {"id": waf_id}}}],
            "effectiveRoutes": [{"id": frontdoor + "/routingRules/redirect", "enabledState": "Enabled",
                "boundHostNames": ["edge.azurefd.net"],
                "paths": [{"acceptedProtocols": ["Https"], "action": "Redirect"}]}],
            "_coverage": {"effectiveRoutes": {"status": "collected"}}}

    def decision(mode=None, enabled=None, include=True, rule_state=None):
        collections = [{"type": "frontdoor_and_cdn_endpoint", "scope": SCOPE,
                        "service": "cdn", "status": "collected", "items": [edge]}]
        if include:
            waf_props = {"policySettings": {"mode": mode, "enabledState": enabled}}
            if rule_state is not None:
                waf_props["customRules"] = {"rules": [] if rule_state != "custom" else [{"name": "block"}]}
                waf_props["managedRules"] = {"managedRuleSets": [] if rule_state != "managed" else [{"ruleSetType": "DefaultRuleSet"}]}
            collections.append({"type": "frontdoor_waf_policy", "scope": SCOPE,
                                "service": "network", "status": "collected", "items": [
                                    {"id": waf_id, "properties": waf_props}]})
        snap = make_snapshot("azure", [SCOPE], collections)
        return next(a for a in assess(snap, resources(snap))
                    if a.resource["type"] == "frontdoor_and_cdn_endpoint")

    assert decision(mode="Prevention", enabled="Enabled").verdict() == "UNKNOWN"
    assert decision(include=False).verdict() == "UNKNOWN"
    detected = decision(mode="Detection", enabled="Enabled")
    assert detected.verdict() == "FAIL"
    assert "records mode Detection" in _observed(detected, "FAIL")
    assert decision(mode="Prevention", enabled="Disabled").verdict() == "FAIL"
    assert decision(mode="Prevention", enabled="Enabled", rule_state="empty").verdict() == "FAIL"
    assert decision(mode="Prevention", enabled="Enabled", rule_state="custom").verdict() == "UNKNOWN"


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


def test_api_management_enabled_secondary_gateway_survives_primary_disable():
    base = {"publicNetworkAccess": "Enabled", "virtualNetworkType": "None",
            "disableGateway": True, "gatewayUrl": "https://primary.azure-api.net",
            "additionalLocations": [{"location": "west", "disableGateway": False,
                                     "gatewayRegionalUrl": "https://west.azure-api.net"}]}
    regional = decision("api_management", base)
    assert regional.verdict() == "FAIL" and regional.addresses == ["https://west.azure-api.net"]
    assert regional.ports == {"tcp": ((443, 443),)}
    assert "primary gateway disabled and an enabled regional gateway" in _observed(regional, "FAIL")
    assert decision("api_management", {**base, "additionalLocations": [
        {**base["additionalLocations"][0], "disableGateway": True}]}).verdict() == "PASS"
    assert decision("api_management", {**base, "additionalLocations": [
        {"location": "west", "disableGateway": False}]}).verdict() == "UNKNOWN"
    assert decision("api_management", {**base, "virtualNetworkType": "External"}).verdict() == "UNKNOWN"


def test_api_management_single_external_region_uses_its_own_subnet_nsg():
    base = f"{SCOPE}/resourceGroups/rg/providers/Microsoft.Network"
    subnet_id = base + "/virtualNetworks/v/subnets/regional"
    nsg_id = base + "/networkSecurityGroups/regional"
    region = {"location": "west", "disableGateway": False,
              "gatewayRegionalUrl": "https://west.azure-api.net",
              "virtualNetworkConfiguration": {"subnetResourceId": subnet_id}}
    props = {"publicNetworkAccess": "Enabled", "virtualNetworkType": "External",
             "disableGateway": True, "gatewayUrl": "https://primary.azure-api.net",
             "virtualNetworkConfiguration": {"subnetResourceId": base + "/virtualNetworks/v/subnets/primary"},
             "additionalLocations": [region]}

    def check(access, regions=None, *, collected_subnet=True):
        collections = [{"type": "api_management", "scope": SCOPE, "service": "apim", "status": "collected",
            "items": [{"id": f"{SCOPE}/resourceGroups/rg/providers/Microsoft.ApiManagement/service/apim",
                       "sku": {"name": "Premium"}, "properties": {**props,
                           "additionalLocations": regions if regions is not None else [region]}}]},
            {"type": "nsg", "scope": SCOPE, "service": "network", "status": "collected",
             "items": [{"id": nsg_id, "properties": {"securityRules": [{"name": "regional-https",
                 "properties": {"priority": 100, "direction": "Inbound", "access": access,
                                "protocol": "Tcp", "sourceAddressPrefix": "*",
                                "destinationAddressPrefix": "*", "destinationPortRange": "443"}}]}}]},
            {"type": "subnet", "scope": SCOPE, "service": "network", "status": "collected",
             "items": [{"id": subnet_id, "properties": {"networkSecurityGroup": {"id": nsg_id}}}]
             if collected_subnet else []}]
        snapshot = make_snapshot("azure", [SCOPE], collections)
        return next(row for row in assess(snapshot, resources(snapshot))
                    if row.resource["type"] == "api_management")

    allowed = check("Allow")
    assert allowed.verdict() == "FAIL" and allowed.addresses == [region["gatewayRegionalUrl"]]
    assert check("Deny").verdict() == "PASS"
    assert check("Allow", collected_subnet=False).verdict() == "UNKNOWN"
    assert check("Deny", regions=[region, {**region, "location": "east", "gatewayRegionalUrl":
                 "https://east.azure-api.net"}]).verdict() == "UNKNOWN"


def test_api_management_distinct_external_regions_all_block_public_https():
    base = f"{SCOPE}/resourceGroups/rg/providers/Microsoft.Network"
    service_id = f"{SCOPE}/resourceGroups/rg/providers/Microsoft.ApiManagement/service/apim"
    regions = [{"location": name, "disableGateway": False,
                "gatewayRegionalUrl": f"https://{name}.azure-api.net",
                "virtualNetworkConfiguration": {"subnetResourceId": base +
                    f"/virtualNetworks/{name}/subnets/gateway"}}
               for name in ("west", "east")]

    def check(*, east_subnet=True, west_subnet=True, east_access="Deny",
              east_destination="*", east_route=False):
        subnets = [{"id": region["virtualNetworkConfiguration"]["subnetResourceId"],
                    "properties": {"networkSecurityGroup": {"id": base +
                        f"/networkSecurityGroups/{region['location']}"},
                        **({"routeTable": {"id": base + "/routeTables/east"}}
                           if east_route and region["location"] == "east" else {})}}
                   for region in regions if ((east_subnet or region["location"] != "east") and
                                             (west_subnet or region["location"] != "west"))]
        nsgs = []
        for region in regions:
            name = region["location"]
            nsgs.append({"id": base + f"/networkSecurityGroups/{name}",
                         "properties": {"securityRules": [{"name": "https", "properties": {
                             "priority": 100, "direction": "Inbound",
                             "access": east_access if name == "east" else "Deny",
                             "protocol": "Tcp", "sourceAddressPrefix": "*",
                             "destinationAddressPrefix": east_destination if name == "east" else "*",
                             "destinationPortRange": "443"}}]}})
        snap = make_snapshot("azure", [SCOPE], [
            {"type": "api_management", "scope": SCOPE, "service": "apim", "status": "collected",
             "items": [{"id": service_id, "sku": {"name": "Premium"}, "properties": {
                 "publicNetworkAccess": "Enabled", "virtualNetworkType": "External",
                 "disableGateway": True, "additionalLocations": regions}}]},
            {"type": "subnet", "scope": SCOPE, "service": "network", "status": "collected",
             "items": subnets},
            {"type": "nsg", "scope": SCOPE, "service": "network", "status": "collected",
             "items": nsgs},
        ])
        return next(row for row in assess(snap, resources(snap)) if row.resource["type"] == "api_management")

    blocked = check()
    assert blocked.verdict() == "PASS"
    assert blocked.path[-1]["regional_gateway_urls"] == [
        "https://west.azure-api.net", "https://east.azure-api.net"]
    assert "Each regional gateway's collected External VNet subnet NSG blocks" in _observed(blocked, "PASS")
    assert len(_observed(blocked, "PASS").splitlines()) == 3
    open_region = check(east_access="Allow")
    assert open_region.verdict() == "FAIL"
    assert open_region.path[-1]["regional_gateway_url"] == "https://east.azure-api.net"
    assert open_region.addresses[0] == "https://east.azure-api.net"
    assert "regional gateway at https://east.azure-api.net" in _observed(open_region, "FAIL")
    assert check(west_subnet=False, east_access="Allow").verdict() == "FAIL"
    assert check(east_subnet=False).verdict() == "UNKNOWN"
    assert check(east_access="Allow", east_route=True).verdict() == "UNKNOWN"
    assert check(east_access="Allow", east_destination="10.0.0.4/32").verdict() == "UNKNOWN"


def test_api_management_classic_external_vnet_subnet_nsg():
    subnet_id = f"{SCOPE}/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/v/subnets/apim"
    nsg_id = f"{SCOPE}/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/apim"
    service_id = f"{SCOPE}/resourceGroups/rg/providers/Microsoft.ApiManagement/service/apim"
    props = {"publicNetworkAccess": "Enabled", "virtualNetworkType": "External",
             "disableGateway": False, "gatewayUrl": "https://apim.azure-api.net",
             "virtualNetworkConfiguration": {"subnetResourceId": subnet_id}}

    def assess_gateway(*, nsg=True, rule=None, route_table=False, subnet=True, sku="Developer"):
        subnet_props = {"networkSecurityGroup": {"id": nsg_id}} if nsg else {}
        if route_table:
            subnet_props["routeTable"] = {"id": f"{SCOPE}/resourceGroups/rg/providers/Microsoft.Network/routeTables/forced"}
        collections = [{"type": "api_management", "scope": SCOPE, "service": "apim", "status": "collected",
                        "items": [{"id": service_id, "sku": {"name": sku}, "properties": props}]}]
        if subnet:
            collections.append({"type": "subnet", "scope": SCOPE, "service": "network", "status": "collected",
                                "items": [{"id": subnet_id, "properties": subnet_props}]})
        if nsg:
            collections.append({"type": "nsg", "scope": SCOPE, "service": "network", "status": "collected",
                                "items": [{"id": nsg_id, "properties": {"securityRules": [rule] if rule else []}}]})
        snap = make_snapshot("azure", [SCOPE], collections)
        return next(a for a in assess(snap, resources(snap)) if a.resource["type"] == "api_management")

    allow = {"name": "gateway", "properties": {"priority": 100, "direction": "Inbound",
             "access": "Allow", "protocol": "Tcp", "sourceAddressPrefix": "Internet",
             "destinationAddressPrefix": "VirtualNetwork", "destinationPortRange": "443"}}
    assert assess_gateway(rule=allow).verdict() == "FAIL"
    assert assess_gateway().verdict() == "PASS"
    assert assess_gateway(nsg=False).verdict() == "PASS"
    assert assess_gateway(subnet=False).verdict() == "UNKNOWN"
    assert assess_gateway(rule={**allow, "properties": {**allow["properties"],
           "destinationAddressPrefix": "10.0.0.4/32"}}).verdict() == "UNKNOWN"
    assert assess_gateway(rule=allow, route_table=True).verdict() == "UNKNOWN"
    assert assess_gateway(rule=allow, sku="StandardV2").verdict() == "UNKNOWN"


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


def test_cosmos_ip_allow_rules_and_cross_tenant_azure_marker():
    base = {"publicNetworkAccess": "Enabled", "documentEndpoint": "https://db.documents.azure.com:443/",
            "isVirtualNetworkFilterEnabled": False}
    assert decision("cosmos_account", {**base, "ipRules": []}).verdict() == "FAIL"
    assert decision("cosmos_account", {**base, "ipRules": [
        {"ipAddressOrRange": "8.8.8.8"}]}).verdict() == "FAIL"
    azure = decision("cosmos_account", {**base, "ipRules": [{"ipAddressOrRange": "0.0.0.0"}]})
    assert azure.verdict() == "FAIL" and azure.path[-1]["cross_tenant_azure_services"] is True
    assert decision("cosmos_account", {**base, "ipRules": [{"ipAddressOrRange": "bad"}]}).verdict() == "UNKNOWN"
    assert decision("cosmos_account", {**base, "isVirtualNetworkFilterEnabled": True,
        "ipRules": []}).verdict() == "UNKNOWN"
    assert decision("cosmos_account", {**base, "ipRules": None}).verdict() == "UNKNOWN"


@pytest.mark.parametrize("kind", ["signalr_service", "web_pubsub"])
def test_realtime_service_public_request_and_ip_paths(kind):
    base = {"publicNetworkAccess": "Enabled", "hostName": "service.example.signalr.net",
            "publicPort": 443}
    allowed = {"defaultAction": "Deny", "publicNetwork": {"allow": ["ClientConnection"]},
               "ipRules": []}
    public = decision(kind, {**base, "networkACLs": allowed})
    assert public.verdict() == "FAIL" and public.ports == {"tcp": ((443, 443),)}
    assert public.addresses == [base["hostName"]]
    assert decision(kind, {**base, "publicNetworkAccess": "Disabled",
        "networkACLs": allowed}).verdict() == "PASS"
    assert decision(kind, {**base, "networkACLs": {"defaultAction": "Deny",
        "publicNetwork": {"allow": []}, "ipRules": []}}).verdict() == "PASS"
    assert decision(kind, {**base, "networkACLs": {"defaultAction": "Allow",
        "ipRules": [{"value": "0.0.0.0/0", "action": "Deny"},
                    {"value": "::/0", "action": "Deny"}]}}).verdict() == "PASS"
    assert decision(kind, {**base, "networkACLs": {"defaultAction": "Deny",
        "publicNetwork": {"allow": ["ClientConnection"]},
        "ipRules": [{"value": "bad", "action": "Allow"}]}}).verdict() == "UNKNOWN"
    assert decision(kind, {**base, "networkACLs": allowed, "publicPort": None}).verdict() == "UNKNOWN"


def test_synapse_workspace_public_sql_and_cross_tenant_firewall():
    rid = f"{SCOPE}/resourceGroups/rg/providers/Microsoft.Synapse/workspaces/ws"
    base = {"publicNetworkAccess": "Enabled", "connectivityEndpoints": {
        "sql": "ws.sql.azuresynapse.net", "sqlOnDemand": "ws-ondemand.sql.azuresynapse.net",
        "dev": "ws.dev.azuresynapse.net"}}

    def evaluate(rules, status="collected", props=None):
        snap = make_snapshot("azure", [SCOPE], [{"type": "synapse_workspace", "scope": SCOPE,
            "service": "synapse", "status": "collected", "items": [{"id": rid,
                "properties": props if props is not None else base, "firewallRules": rules,
                "_coverage": {"firewallRules": {"status": status}}}]}])
        return next(row for row in assess(snap, resources(snap)) if row.resource["type"] == "synapse_workspace")

    public = {"name": "public", "properties": {"startIpAddress": "8.8.8.8", "endIpAddress": "8.8.8.8"}}
    azure = {"name": "azure", "properties": {"startIpAddress": "0.0.0.0", "endIpAddress": "0.0.0.0"}}
    row = evaluate([public])
    assert row.verdict() == "FAIL" and row.ports == {"tcp": ((443, 443), (1433, 1433))}
    assert evaluate([azure]).path[-1]["public_rules"][0]["source"] == "any Azure tenant"
    assert evaluate([]).verdict() == "PASS"
    assert evaluate([public], status="partial").verdict() == "UNKNOWN"
    assert evaluate([{"properties": {"startIpAddress": "bad", "endIpAddress": "8.8.8.8"}}]).verdict() == "UNKNOWN"
    assert evaluate([public], props={"publicNetworkAccess": "Disabled"}).verdict() == "PASS"
    assert evaluate([public], props={"publicNetworkAccess": "Enabled"}).verdict() == "UNKNOWN"


@pytest.mark.parametrize("kind,port", [("mysql_flexible_server", 3306), ("postgresql_flexible_server", 5432)])
def test_flexible_database_firewall_public_and_cross_tenant_sources(kind, port):
    rid = f"{SCOPE}/resourceGroups/rg/providers/test/{kind}/db"
    base = {"network": {"publicNetworkAccess": "Enabled"},
            "fullyQualifiedDomainName": "db.database.azure.com"}

    def evaluate(rows, status="collected", properties=None):
        parent = {"id": rid, "properties": properties or base, "firewallRules": rows,
                  "_coverage": {"firewallRules": {"status": status}}}
        snap = make_snapshot("azure", [SCOPE], [{"type": kind, "scope": SCOPE,
            "service": "database", "status": "collected", "items": [parent]}])
        return next(row for row in assess(snap, resources(snap)) if row.resource["type"] == kind)

    public = {"name": "public", "properties": {"startIpAddress": "8.8.8.8", "endIpAddress": "8.8.8.8"}}
    azure = {"name": "azure", "properties": {"startIpAddress": "0.0.0.0", "endIpAddress": "0.0.0.0"}}
    assert evaluate([public]).verdict() == "FAIL"
    candidate = evaluate([azure])
    assert candidate.verdict() == "FAIL" and candidate.ports == {"tcp": ((port, port),)}
    assert candidate.path[-1]["public_rules"][0]["source"] == "any Azure tenant"
    assert evaluate([]).verdict() == "PASS"
    assert evaluate([{"properties": {"startIpAddress": "bad", "endIpAddress": "8.8.8.8"}}]).verdict() == "UNKNOWN"
    assert evaluate([public], status="partial").verdict() == "UNKNOWN"
    assert evaluate([public], properties={"network": {"publicNetworkAccess": "Disabled"}}).verdict() == "PASS"


@pytest.mark.parametrize("kind", ["vault", "managed_hsm", "container_registry", "search_service", "servicebus_namespace"])
def test_managed_endpoint_explicit_network_gate(kind):
    rule = {"vault": "networkAcls", "managed_hsm": "networkAcls", "container_registry": "networkRuleSet",
            "search_service": "networkRuleSet", "servicebus_namespace": "networkRuleSet"}[kind]
    if kind == "servicebus_namespace":
        # Parent properties do not stand in for the separate namespace rule child.
        assert decision(kind, {"publicNetworkAccess": "Enabled", "endpoint": "https://public.example.test",
                               rule: {"defaultAction": "Allow"}}).verdict() == "UNKNOWN"
        assert decision(kind, {"publicNetworkAccess": "Enabled", rule: {"defaultAction": "Deny"}}).verdict() == "UNKNOWN"
        return
    if kind == "search_service":
        # The collected IP list is required to distinguish unrestricted and restricted access.
        assert decision(kind, {"publicNetworkAccess": "Enabled", "endpoint": "https://public.example.test",
                               rule: {"defaultAction": "Allow"}}).verdict() == "UNKNOWN"
        assert decision(kind, {"publicNetworkAccess": "Enabled", "endpoint": "https://public.example.test",
                               rule: {"defaultAction": "Allow", "ipRules": []}}).verdict() == "FAIL"
        assert decision(kind, {"publicNetworkAccess": "Enabled",
                               rule: {"ipRules": [{"value": "10.0.0.0/8"}]}}).verdict() == "PASS"
        return
    assert decision(kind, {"publicNetworkAccess": "Enabled", "endpoint": "https://public.example.test",
                           rule: {"defaultAction": "Allow"}}).verdict() == "FAIL"
    vault_like = kind in ("vault", "managed_hsm")
    assert decision(kind, {"publicNetworkAccess": "Enabled", rule: {"defaultAction": "Deny",
        **({"bypass": "None"} if vault_like else {})}}).verdict() == "PASS"
    assert decision(kind, {"publicNetworkAccess": "Enabled", "endpoint": "https://public.example.test",
        rule: {"defaultAction": "Deny", "ipRules": [{"value": "0.0.0.0/0"}],
               **({"bypass": "None"} if vault_like else {})}}).verdict() == "FAIL"
    if vault_like:
        assert decision(kind, {"publicNetworkAccess": "Enabled",
            rule: {"defaultAction": "Deny"}}).verdict() == "UNKNOWN"
        assert decision(kind, {"publicNetworkAccess": "Disabled",
            rule: {"defaultAction": "Deny", "bypass": "AzureServices"}}).verdict() == "UNKNOWN"
    assert decision(kind, {"publicNetworkAccess": "Enabled"}).verdict() == "UNKNOWN"
    assert decision(kind, {"publicNetworkAccess": "Disabled", rule: {"defaultAction": "Allow",
        **({"bypass": "None"} if vault_like else {})}}).verdict() == "PASS"
