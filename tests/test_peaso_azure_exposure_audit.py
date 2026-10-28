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

    def lb_decision(pool_props):
        snap = make_snapshot("azure", [SCOPE], [
            {"type": "load_balancer", "scope": SCOPE, "service": "network", "status": "collected", "items": [{"id": lb_id,
                "sku": {"name": "Standard"}, "properties": {"frontendIPConfigurations": [{"id": front_id,
                    "properties": {"publicIPAddress": {"id": pip_id}}}], "backendAddressPools": [
                    {"id": pool_id, "properties": pool_props}], "loadBalancingRules": [rule]}}]},
            {"type": "public_ip", "scope": SCOPE, "service": "network", "status": "collected", "items": [
                {"id": pip_id, "properties": {"ipAddress": "8.8.8.8"}}]},
            {"type": "nic", "scope": SCOPE, "service": "network", "status": "collected", "items": [{"id": nic_id,
                "properties": {"networkSecurityGroup": {"id": nsg_id}, "ipConfigurations": [{"id": config_id,
                    "properties": {"privateIPAddress": "10.0.0.4", "subnet": {"id": subnet_id}}}]}}]},
            {"type": "subnet", "scope": SCOPE, "service": "network", "status": "collected", "items": [{"id": subnet_id,
                "properties": {}}]},
            {"type": "nsg", "scope": SCOPE, "service": "network", "status": "collected", "items": [{"id": nsg_id,
                "properties": {"securityRules": [{"name": "allow", "properties": {"priority": 100,
                    "direction": "Inbound", "access": "Allow", "protocol": "Tcp", "sourceAddressPrefix": "*",
                    "destinationAddressPrefix": "*", "destinationPortRange": "8443"}}]}}]},
        ])
        return next(row for row in assess(snap, resources(snap)) if row.resource["type"] == "load_balancer")

    for pool in ({"backendIPConfigurations": [{"id": config_id}]},
                 {"loadBalancerBackendAddresses": [{"properties": {"networkInterfaceIPConfiguration": {"id": config_id}}}]}):
        row = lb_decision(pool)
        assert row.verdict() == "FAIL" and row.ports == {"tcp": ((443, 443),)}
        assert row.addresses == ["8.8.8.8"]
    assert lb_decision({"loadBalancerBackendAddresses": [{"properties": {"ipAddress": "10.0.0.4"}}]}).verdict() == "UNKNOWN"


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
    other_subscription = decision("compute_gallery", {"sharingProfile": {"permissions": "Groups",
        "groups": [{"type": "Subscriptions", "ids": ["test", "outside-subscription"]}]}})
    assert other_subscription.verdict() == "FAIL"
    assert other_subscription.external_ids == ["outside-subscription"]
    assert "published image versions" in other_subscription.notes[0]
    own_subscription = decision("compute_gallery", {"sharingProfile": {"permissions": "Groups",
        "groups": [{"type": "Subscriptions", "ids": ["test"]}]}})
    assert own_subscription.verdict() == "PASS"
    assert decision("compute_gallery", {"sharingProfile": {"permissions": "Groups",
        "groups": [{"type": "Subscriptions", "ids": "outside-subscription"}]}}).verdict() == "UNKNOWN"
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
    assert app_decision(separate, public_access="Disabled").verdict() == "PASS"
    assert app_decision({**separate, "ipSecurityRestrictionsDefaultAction": "Allow"}, scm_hostname=False).verdict() == "FAIL"


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
    hostname_gate = decision(hostnames_disabled=True)
    assert hostname_gate.verdict() == "UNKNOWN" and hostname_gate.addresses == []
    assert decision(hostnames_disabled=True, scm_default="Deny").verdict() == "PASS"


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
    assert decision("Enabled", "collected", private).verdict() == "PASS"


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
    injected = decision("redis_cache", {**base, "subnetId":
        "/subscriptions/test/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet/subnets/cache"})
    assert injected.verdict() == "PASS" and injected.ports == {}
    assert any(step["layer"] == "network" and step["decision"] == "block" for step in injected.path)
    assert decision("redis_cache", {**base, "subnetId": "malformed"}).verdict() == "UNKNOWN"

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
    closed = decision("cosmos_account", {**base, "isVirtualNetworkFilterEnabled": True,
        "ipRules": [], "virtualNetworkRules": [], "networkAclBypass": "None",
        "networkAclBypassResourceIds": []})
    assert closed.verdict() == "PASS" and closed.ports == {}
    assert decision("cosmos_account", {**base, "isVirtualNetworkFilterEnabled": True,
        "ipRules": [], "virtualNetworkRules": [], "networkAclBypass": "AzureServices",
        "networkAclBypassResourceIds": []}).verdict() == "UNKNOWN"
    assert decision("cosmos_account", {**base, "isVirtualNetworkFilterEnabled": True,
        "ipRules": [], "virtualNetworkRules": [{"id": "/subscriptions/other/subnets/s"}],
        "networkAclBypass": "None", "networkAclBypassResourceIds": []}).verdict() == "UNKNOWN"
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
