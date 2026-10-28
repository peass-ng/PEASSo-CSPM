"""Native first-pass exposure for Automation, IoT Hub and SQL Managed Instance."""

from peaso.analysis.internet_exposure import assess
from peaso.snapshot import make_snapshot, resources
from tests.test_peaso_azure_bulk_native import SCOPE, parent


def decision(kind, rid, arm_type, properties, **extra):
    item = parent(rid, arm_type, properties)
    item.update(extra)
    snapshot = make_snapshot("azure", [SCOPE], [{"type": kind, "scope": SCOPE,
        "service": arm_type.split("/")[0], "status": "collected", "items": [item]}],
        created_at="2026-10-28T12:00:00+00:00")
    return next(row for row in assess(snapshot, resources(snapshot)) if row.resource["type"] == kind)


def test_automation_webhook_bearer_listener_without_storing_uri():
    rid = SCOPE + "/resourceGroups/rg/providers/Microsoft.Automation/automationAccounts/account"
    hook = {"id": rid + "/webhooks/start", "name": "start", "properties": {
        "isEnabled": True, "expiryTime": "2027-01-01T00:00:00Z"}}
    def row(webhooks, status="collected"):
        return decision("automation_account", rid, "Microsoft.Automation/automationAccounts", {},
                        webhooks=webhooks, _coverage={"webhooks": {"status": status}})
    active = row([hook])
    assert active.verdict() == "FAIL" and active.authenticated is False
    assert "uri" not in repr(active.path).lower()
    assert row([{**hook, "properties": {**hook["properties"], "isEnabled": False}}]).verdict() == "PASS"
    assert row([{**hook, "properties": {**hook["properties"], "expiryTime": "2025-01-01T00:00:00Z"}}]).verdict() == "PASS"
    assert row([], "denied").verdict() == "UNKNOWN"


def test_iot_hub_public_protocols_and_ip_rules():
    rid = SCOPE + "/resourceGroups/rg/providers/Microsoft.Devices/IotHubs/hub"
    base = {"publicNetworkAccess": "Enabled", "hostName": "hub.azure-devices.net"}
    def row(rules):
        return decision("iot_hub", rid, "Microsoft.Devices/IotHubs", {**base, "networkRuleSets": rules})
    open_hub = row({"defaultAction": "Allow", "ipRules": []})
    assert open_hub.verdict() == "FAIL" and open_hub.ports["tcp"] == ((443, 443), (5671, 5671), (8883, 8883))
    assert row({"defaultAction": "Deny", "ipRules": [{"action": "Allow", "ipMask": "8.8.8.8"}]}).verdict() == "FAIL"
    assert row({"defaultAction": "Deny", "ipRules": [{"action": "Allow", "ipMask": "10.0.0.0/8"}]}).verdict() == "PASS"
    assert decision("iot_hub", rid, "Microsoft.Devices/IotHubs", {**base, "publicNetworkAccess": "Disabled"}).verdict() == "PASS"
    assert decision("iot_hub", rid, "Microsoft.Devices/IotHubs", base).verdict() == "UNKNOWN"


def test_sql_managed_instance_public_endpoint_gate():
    rid = SCOPE + "/resourceGroups/rg/providers/Microsoft.Sql/managedInstances/mi"
    subnet = SCOPE + "/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet/subnets/mi"
    assert decision("mssql_managed_instance", rid, "Microsoft.Sql/managedInstances",
                    {"publicDataEndpointEnabled": False}).verdict() == "PASS"
    assert decision("mssql_managed_instance", rid, "Microsoft.Sql/managedInstances",
                    {"publicDataEndpointEnabled": True, "subnetId": subnet}).verdict() == "UNKNOWN"
    assert decision("mssql_managed_instance", rid, "Microsoft.Sql/managedInstances", {}).verdict() == "UNKNOWN"
    nsg_id = SCOPE + "/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/mi"
    def nsg_decision(access):
        rule = {"name": "public-tds", "properties": {"priority": 100, "direction": "Inbound",
            "access": access, "protocol": "Tcp", "sourceAddressPrefix": "Internet",
            "destinationAddressPrefix": "*", "destinationPortRange": "3342"}}
        collections = [
            {"type": "mssql_managed_instance", "scope": SCOPE, "service": "Microsoft.Sql",
             "status": "collected", "items": [parent(rid, "Microsoft.Sql/managedInstances",
                {"publicDataEndpointEnabled": True, "subnetId": subnet})]},
            {"type": "subnet", "scope": SCOPE, "service": "Microsoft.Network",
             "status": "collected", "items": [parent(subnet, "Microsoft.Network/virtualNetworks/subnets",
                {"networkSecurityGroup": {"id": nsg_id}})]},
            {"type": "nsg", "scope": SCOPE, "service": "Microsoft.Network",
             "status": "collected", "items": [parent(nsg_id, "Microsoft.Network/networkSecurityGroups",
                {"securityRules": [rule]})]},
        ]
        snap = make_snapshot("azure", [SCOPE], collections)
        return next(row for row in assess(snap, resources(snap))
                    if row.resource["type"] == "mssql_managed_instance")
    assert nsg_decision("Allow").verdict() == "FAIL"
    assert nsg_decision("Deny").verdict() == "PASS"
