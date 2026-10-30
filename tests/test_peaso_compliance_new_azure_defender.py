"""Defender extension facts differ from pricing tier and scanner operation health."""
from copy import deepcopy

import pytest

from peaso.checks import evaluate_check
from peaso.checks import compliance_new_azure_defender as new
from peaso.checks import CHECKS, evaluate_check


def _item(tier="Standard", extensions=None, *, scope="/subscriptions/sub", name="VirtualMachines"):
    if extensions is None:
        extensions = [{"name": "AgentlessVmScanning", "isEnabled": "True"}]
    return {"id": scope + "/providers/Microsoft.Security/pricings/" + name,
            "name": name, "properties": {"pricingTier": tier, "extensions": extensions}}


def _index(rows, status="collected"):
    return {"collections": {"security_pricing": [{"scope": "/subscriptions/sub", "status": status}]},
            "security_pricing": [{"data": row} for row in rows]}


def _verdict(rows, *, scope="/subscriptions/sub", status="collected"):
    return evaluate_check(new.ID, {"scope": scope}, _index(rows, status))


def test_signed_id_scope_and_existing_tier_check_not_equivalent():
    assert _verdict([_item()])[0] == "PASS"
    assert _verdict([_item(extensions=[{"name": "AgentlessVmScanning", "isEnabled": "False"}])])[0] == "FAIL"
    assert _verdict([_item("Free", extensions=[])])[0] == "FAIL"
    assert _verdict([_item()], scope="/tenants/t")[0] == "NOT_APPLICABLE"


def test_true_flag_with_failed_or_pending_operation_is_configuration_only():
    for code in ("Failed", "InProgress"):
        extension = {"name": "AgentlessVmScanning", "isEnabled": "True", "operationStatus": {"code": code}}
        state, evidence = _verdict([_item(extensions=[extension])])
        assert state == "PASS"
        assert evidence["operation_code"] == code
        assert "actual scans" in evidence["semantics"]
        assert "unproved" in evidence["semantics"]


def test_absent_extension_vs_missing_unreadable_extension_fact():
    assert _verdict([_item(extensions=[])])[0] == "FAIL"
    missing = _item()
    del missing["properties"]["extensions"]
    assert _verdict([missing])[0] == "UNKNOWN"
    missing["properties"]["_coverage"] = {"extensions": {"status": "denied"}}
    assert _verdict([missing])[0] == "UNKNOWN"
    assert _verdict([_item(extensions=[])], status="denied")[0] == "UNKNOWN"
    assert _verdict([], status="empty")[0] == "UNKNOWN"


@pytest.mark.parametrize("extension", [
    {"name": "AgentlessVmScanning", "isEnabled": True},
    {"name": "AgentlessVmScanning", "isEnabled": "unknown"},
    {"name": "AgentlessVmScanning"},
    {"name": "AgentlessVmScanning", "isEnabled": "True", "operationStatus": "Failed"},
])
def test_malformed_or_unrecognized_extension_is_unknown(extension):
    assert _verdict([_item(extensions=[extension])])[0] == "UNKNOWN"


def test_ambiguous_duplicate_or_foreign_pricing_never_passes():
    row = _item()
    assert _verdict([row, deepcopy(row)])[0] == "UNKNOWN"
    duplicate_extension = deepcopy(row)
    duplicate_extension["properties"]["extensions"].append(deepcopy(duplicate_extension["properties"]["extensions"][0]))
    assert _verdict([duplicate_extension])[0] == "UNKNOWN"
    assert _verdict([_item(scope="/subscriptions/other")])[0] == "UNKNOWN"
    assert _verdict([_item(scope="/subscriptions/other"), row])[0] == "PASS"
    assert _verdict([_item(name="SqlServers")])[0] == "UNKNOWN"
    nested = deepcopy(row)
    nested["id"] += "/child"
    assert _verdict([nested])[0] == "UNKNOWN"


def test_explicit_free_plan_fails_even_when_extension_projection_missing():
    free = _item(tier="Free")
    del free["properties"]["extensions"]
    state, evidence = _verdict([free])
    assert state == "FAIL"
    assert evidence["pricing_tier"] == "Free"


def test_missing_pricing_or_scope_is_unknown():
    assert evaluate_check(new.ID, {"scope": "/subscriptions/sub"}, {})[0] == "UNKNOWN"
    assert evaluate_check(new.ID, {"scope": None}, {})[0] == "UNKNOWN"
    assert _verdict([_item(tier="Future")])[0] == "UNKNOWN"
