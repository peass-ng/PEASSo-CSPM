"""Native empty-inventory applicability for the two Defender controls."""
import pytest

from peaso.checks import CHECKS
from peaso.checks.claude_azure_common import scope_index
from peaso.checks.azure_defender_applicability_description_overlay import description
from peaso.engine import evaluate_snapshot, plan_collection
from peaso.snapshot import seal

SCOPE = {"scope": "/subscriptions/s"}
POLICY = "azure.claude.defender_default_initiative_no_disabled_effects"
IOT = "azure.claude.defender_iot_security_solution_enabled"
REGISTRY = {check.id: check for check in CHECKS}


def evaluate(check_id, inventories):
    return REGISTRY[check_id].evaluate(SCOPE, scope_index(inventories))[0]


def test_no_effective_builtin_assignment_is_inapplicable():
    assert evaluate(POLICY, {"policy_assignment": []}) == "NOT_APPLICABLE"
    assert evaluate(POLICY, {"policy_assignment": [{
        "id": "/subscriptions/s/resourceGroups/r/providers/Microsoft.Authorization/policyAssignments/SecurityCenterBuiltIn",
        "name": "SecurityCenterBuiltIn", "properties": {"scope": "/subscriptions/s/resourceGroups/r",
        "parameters": {"effect": {"value": "Disabled"}}}}]}) == "NOT_APPLICABLE"


@pytest.mark.parametrize(("name", "id_name"), [
    ("securitycenterbuiltin", "securitycenterbuiltin"),
    ("SeCuRiTyCeNtErBuIlTiN", "securitycenterbuiltin"),
    ("securitycenterbuiltin", "SecurityCenterBuiltIn"),
])
def test_native_engine_case_insensitive_builtin_name_still_fails(name, id_name):
    scope = "/subscriptions/11111111-1111-1111-1111-111111111111"
    row = {"id": scope + "/providers/Microsoft.Authorization/policyAssignments/" + id_name,
           "name": name, "properties": {"scope": scope,
           "parameters": {"effect": {"value": "Disabled"}}}}
    snapshot = seal({"schema_version": "1.0", "provider": "azure", "scopes": [scope],
                     "created_at": "2026-10-18T00:00:00+00:00", "metadata": {}, "collections": [
                         {"type": "policy_assignment", "scope": scope, "status": "collected",
                          "service": "Microsoft.Authorization", "items": [row]}]})
    findings = evaluate_snapshot(snapshot, checks=[POLICY], categories=[], include_not_applicable=True)["findings"]
    assert [(finding["check_id"], finding["status"]) for finding in findings] == [(POLICY, "FAIL")]


def test_case_variant_duplicate_assignment_is_unknown():
    scope = "/subscriptions/11111111-1111-1111-1111-111111111111"
    def row(name):
        return {"id": scope + "/providers/Microsoft.Authorization/policyAssignments/" + name,
                "name": name, "properties": {"scope": scope,
                "parameters": {"effect": {"value": "Disabled"}}}}
    assert evaluate(POLICY, {"policy_assignment": [row("SecurityCenterBuiltIn"),
                                                    row("securitycenterbuiltin")]}) == "UNKNOWN"


@pytest.mark.parametrize("status", ["denied", "unknown", "truncated"])
def test_incomplete_policy_inventory_cannot_claim_absence(status):
    index = scope_index({"policy_assignment": []})
    index["collections"]["policy_assignment"][0]["status"] = status
    assert REGISTRY[POLICY].evaluate(SCOPE, index)[0] == "UNKNOWN"


def test_iot_empty_requires_both_native_inventories():
    assert evaluate(IOT, {"iot_security_solution": [], "iot_hub": []}) == "NOT_APPLICABLE"
    index = scope_index({"iot_security_solution": [], "iot_hub": [{"id": "hub"}]})
    status, evidence = REGISTRY[IOT].evaluate(SCOPE, index)
    assert status == "UNKNOWN"
    assert evidence["iot_hub_ids"] == ["hub"]
    assert "cross-subscription" in evidence["missing_native_evidence"]
    for missing in ("iot_hub", "iot_security_solution"):
        inventories = {"iot_security_solution": [], "iot_hub": []}
        del inventories[missing]
        assert evaluate(IOT, inventories) == "UNKNOWN"
    index = scope_index({"iot_security_solution": [], "iot_hub": []})
    index["collections"]["iot_hub"][0]["status"] = "denied"
    assert REGISTRY[IOT].evaluate(SCOPE, index)[0] == "UNKNOWN"


def test_disabled_solution_still_fails_even_when_hub_inventory_unavailable():
    index = scope_index({"iot_security_solution": [{"properties": {"status": "Disabled"}}]})
    assert REGISTRY[IOT].evaluate(SCOPE, index)[0] == "FAIL"
    assert REGISTRY[IOT].allow_incomplete_failure
    assert evaluate(IOT, {"iot_security_solution": [{"properties": {"status": "Enabled"}}], "iot_hub": []}) == "PASS"
    assert evaluate(IOT, {"iot_security_solution": [{"properties": {"status": "Bad"}}], "iot_hub": []}) == "UNKNOWN"


def test_filtered_plan_collects_iot_hubs():
    request = {"connector": {"provider": "azure", "scopes": ["/subscriptions/s"],
                             "auth": {"method": "az-cli"}}, "checks": [IOT], "categories": []}
    assert {"iot_hub", "iot_security_solution"} <= set(plan_collection(request))


@pytest.mark.parametrize("solution_status,hub_status,expected", [
    ("Disabled", "denied", "FAIL"),
    ("Enabled", "denied", "DENIED"),
    ("Enabled", "empty", "PASS"),
])
def test_engine_preserves_observed_failure_without_positive_shortcut(solution_status, hub_status, expected):
    scope = "/subscriptions/11111111-1111-1111-1111-111111111111"
    snapshot = seal({"schema_version": "1.0", "provider": "azure", "scopes": [scope],
                     "created_at": "2026-10-18T00:00:00+00:00", "metadata": {}, "collections": [
                         {"type": "iot_security_solution", "scope": scope, "status": "collected",
                          "service": "Microsoft.Security", "items": [{"id": scope + "/resourceGroups/r/providers/Microsoft.Security/iotSecuritySolutions/i",
                                                                    "properties": {"status": solution_status}}]},
                         {"type": "iot_hub", "scope": scope, "status": hub_status,
                          "service": "Microsoft.Devices", "items": []}]})
    findings = evaluate_snapshot(snapshot, checks=[IOT], categories=[], include_not_applicable=True)["findings"]
    assert [(row["check_id"], row["status"]) for row in findings] == [(IOT, expected)]


def test_hash_bound_current_descriptions_leave_historical_rows_intact():
    for check_id in (POLICY, IOT):
        with pytest.raises(ValueError, match="original description changed"):
            description(check_id, {"description": "tampered historical source"})
