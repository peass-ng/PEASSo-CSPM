"""Provider-shaped, offline route and platform-metric evidence cases."""
from copy import deepcopy

from peaso.checks import evaluate_check
from peaso.checks import compliance_new_azure_network_monitoring as checks
from peaso.checks.facts import MemoIndex


BASE = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/applicationGateways/gw"
VM = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm"


def child(kind, name, **properties):
    return {"id": BASE + "/" + kind + "/" + name, "properties": properties}


def ref(kind, name):
    return {"id": BASE + "/" + kind + "/" + name}


def gateway(*, target="Https", route="Basic"):
    listener = child("httpListeners", "http", protocol="Http")
    target_listener = child("httpListeners", "secure", protocol=target)
    redirect = child("redirectConfigurations", "redirect", redirectType="Permanent",
                     targetListener=ref("httpListeners", "secure"))
    rule = child("requestRoutingRules", "rule", ruleType=route,
                 httpListener=ref("httpListeners", "http"),
                 redirectConfiguration=ref("redirectConfigurations", "redirect"))
    return {"id": BASE, "properties": {"httpListeners": [listener, target_listener],
            "requestRoutingRules": [rule], "urlPathMaps": [], "redirectConfigurations": [redirect]}}


def index(kind, rows, status="collected"):
    return {"collections": {kind: [{"status": status}]}, kind: [{"data": row} for row in rows]}


def verdict(cid, item, kind, status="collected"):
    return evaluate_check(cid, item, index(kind, [item], status))


def test_basic_gateway_redirect_vs_forwarding_and_unresolved_routes():
    good = gateway()
    status, evidence = verdict(checks.GATEWAY_ID, good, "application_gateway")
    assert status == "PASS" and evidence["assessed_route_count"] == 1
    bad_target = gateway(target="Http")
    assert verdict(checks.GATEWAY_ID, bad_target, "application_gateway")[0] == "FAIL"
    backend = gateway()
    route = backend["properties"]["requestRoutingRules"][0]["properties"]
    del route["redirectConfiguration"]
    route["backendAddressPool"] = ref("backendAddressPools", "pool")
    assert verdict(checks.GATEWAY_ID, backend, "application_gateway")[0] == "FAIL"
    unresolved = gateway()
    unresolved["properties"]["redirectConfigurations"] = []
    assert verdict(checks.GATEWAY_ID, unresolved, "application_gateway")[0] == "UNKNOWN"
    unbound = gateway()
    unbound["properties"]["requestRoutingRules"] = []
    assert verdict(checks.GATEWAY_ID, unbound, "application_gateway")[0] == "UNKNOWN"
    assert verdict(checks.GATEWAY_ID, good, "application_gateway", "denied")[0] == "UNKNOWN"


def test_path_map_default_and_each_path_is_assessed_and_url_schemes_are_exact():
    item = gateway(route="PathBasedRouting")
    rule = item["properties"]["requestRoutingRules"][0]["properties"]
    del rule["redirectConfiguration"]
    rule["urlPathMap"] = ref("urlPathMaps", "map")
    item["properties"]["urlPathMaps"] = [child("urlPathMaps", "map",
        defaultRedirectConfiguration=ref("redirectConfigurations", "redirect"),
        pathRules=[child("urlPathMaps/map/pathRules", "api",
                         redirectConfiguration=ref("redirectConfigurations", "redirect"))])]
    assert verdict(checks.GATEWAY_ID, item, "application_gateway")[0] == "PASS"
    path = item["properties"]["urlPathMaps"][0]["properties"]["pathRules"][0]["properties"]
    del path["redirectConfiguration"]
    path["backendAddressPool"] = ref("backendAddressPools", "pool")
    assert verdict(checks.GATEWAY_ID, item, "application_gateway")[0] == "FAIL"
    path.pop("backendAddressPool")
    assert verdict(checks.GATEWAY_ID, item, "application_gateway")[0] == "UNKNOWN"
    duplicate = deepcopy(item)
    path_rows = duplicate["properties"]["urlPathMaps"][0]["properties"]["pathRules"]
    path_rows[0]["properties"]["redirectConfiguration"] = ref("redirectConfigurations", "redirect")
    path_rows.append(deepcopy(path_rows[0]))
    assert verdict(checks.GATEWAY_ID, duplicate, "application_gateway")[0] == "UNKNOWN"
    item = gateway()
    redirect = item["properties"]["redirectConfigurations"][0]["properties"]
    redirect.pop("targetListener")
    redirect["targetUrl"] = "https://example.org/login"
    assert verdict(checks.GATEWAY_ID, item, "application_gateway")[0] == "PASS"
    redirect["targetUrl"] = "http://example.org/login"
    assert verdict(checks.GATEWAY_ID, item, "application_gateway")[0] == "FAIL"
    redirect["targetUrl"] = "//example.org/login"
    assert verdict(checks.GATEWAY_ID, item, "application_gateway")[0] == "UNKNOWN"


def test_gateway_incomplete_graph_malformed_and_no_http():
    good = gateway()
    for change in (lambda x: x["properties"].pop("redirectConfigurations"),
                   lambda x: x["properties"]["requestRoutingRules"][0]["properties"].update(ruleType="Unknown"),
                   lambda x: x["properties"]["redirectConfigurations"][0]["properties"].update(redirectType="Other"),
                   lambda x: x["properties"]["requestRoutingRules"][0]["properties"].update(
                       httpListener={"id": "/subscriptions/other/gw/httpListeners/http"})):
        item = deepcopy(good)
        change(item)
        assert verdict(checks.GATEWAY_ID, item, "application_gateway")[0] == "UNKNOWN"
    no_http = gateway()
    no_http["properties"]["httpListeners"][0]["properties"]["protocol"] = "Https"
    assert verdict(checks.GATEWAY_ID, no_http, "application_gateway")[0] == "NOT_APPLICABLE"
    many = gateway()
    template = many["properties"]["requestRoutingRules"][0]
    many["properties"]["requestRoutingRules"] = [
        {**deepcopy(template), "id": ref("requestRoutingRules", str(n))["id"]} for n in range(1200)]
    assert verdict(checks.GATEWAY_ID, many, "application_gateway")[1]["assessed_route_count"] == 1200


def vm(*, metrics=None, workspace=True, coverage="collected"):
    properties = {"metrics": [{"category": "AllMetrics", "enabled": True}] if metrics is None else metrics}
    if workspace:
        properties["workspaceId"] = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/logs"
    return {"id": VM, "_coverage": {"diagnosticSettings": {"status": coverage}},
            "diagnosticSettings": [{"id": VM + "/providers/Microsoft.Insights/diagnosticSettings/platform",
                                    "parent_id": VM, "properties": properties}]}


def test_vm_platform_metric_export_and_incomplete_settings():
    good = vm()
    status, evidence = verdict(checks.VM_ID, good, "vm")
    assert status == "PASS" and "guest" in evidence["semantics"].lower()
    assert verdict(checks.VM_ID, vm(metrics=[{"category": "AllMetrics", "enabled": False}]), "vm")[0] == "FAIL"
    assert verdict(checks.VM_ID, vm(metrics=[]), "vm")[0] == "FAIL"
    assert verdict(checks.VM_ID, vm(metrics=[{"category": "Percentage CPU", "enabled": True}]), "vm")[0] == "UNKNOWN"
    assert verdict(checks.VM_ID, {**good, "diagnosticSettings": []}, "vm")[0] == "FAIL"
    assert verdict(checks.VM_ID, vm(workspace=False), "vm")[0] == "UNKNOWN"
    assert verdict(checks.VM_ID, vm(coverage="denied"), "vm")[0] == "UNKNOWN"
    assert verdict(checks.VM_ID, vm(), "vm", "partial")[0] == "UNKNOWN"
    missing = deepcopy(good)
    del missing["_coverage"]
    assert verdict(checks.VM_ID, missing, "vm")[0] == "UNKNOWN"
    foreign = vm()
    foreign["diagnosticSettings"][0]["parent_id"] = "/subscriptions/other/vm"
    assert verdict(checks.VM_ID, foreign, "vm")[0] == "UNKNOWN"
    wrong_setting_id = vm()
    wrong_setting_id["diagnosticSettings"][0]["id"] = VM + "/providers/Microsoft.Insights/diagnosticSettings/"
    assert verdict(checks.VM_ID, wrong_setting_id, "vm")[0] == "UNKNOWN"
    malformed = vm()
    malformed["diagnosticSettings"][0]["properties"]["workspaceId"] = "/subscriptions/"
    assert verdict(checks.VM_ID, malformed, "vm")[0] == "UNKNOWN"
    wrong_type = vm()
    wrong_type["diagnosticSettings"][0]["properties"]["workspaceId"] = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/store"
    assert verdict(checks.VM_ID, wrong_type, "vm")[0] == "UNKNOWN"
    cross_subscription = vm()
    cross_subscription["diagnosticSettings"][0]["properties"]["workspaceId"] = "/subscriptions/other/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/logs"
    assert verdict(checks.VM_ID, cross_subscription, "vm")[0] == "PASS"
    eventhub = vm(workspace=False)
    eventhub["diagnosticSettings"][0]["properties"]["eventHubAuthorizationRuleId"] = "/subscriptions/other/resourceGroups/rg/providers/Microsoft.EventHub/namespaces/bus/authorizationRules/export"
    assert verdict(checks.VM_ID, eventhub, "vm")[0] == "PASS"
    partner = vm(workspace=False)
    partner["diagnosticSettings"][0]["properties"]["marketplacePartnerId"] = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Datadog/monitors/partner"
    assert verdict(checks.VM_ID, partner, "vm")[0] == "UNKNOWN"


def test_inventory_validation_is_memoized_for_many_scoped_resources(monkeypatch):
    actual = checks.complete_items
    calls = []

    def counting(index_value, kind):
        calls.append(kind)
        return actual(index_value, kind)

    monkeypatch.setattr(checks, "complete_items", counting)
    rows = [vm() for _ in range(350)]
    scoped = MemoIndex(index("vm", rows))
    for row in rows:
        assert evaluate_check(checks.VM_ID, row, scoped)[0] == "PASS"
    assert calls == ["vm"]
    calls.clear()
    gateways = [gateway() for _ in range(250)]
    scoped = MemoIndex(index("application_gateway", gateways))
    for row in gateways:
        assert evaluate_check(checks.GATEWAY_ID, row, scoped)[0] == "PASS"
    assert calls == ["application_gateway"]
