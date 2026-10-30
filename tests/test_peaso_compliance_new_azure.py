"""Adversarial native-snapshot semantics for the implemented signed Azure rows."""
import copy

import pytest

from peaso.checks import evaluate_check
from peaso.checks import compliance_new_azure as new


@pytest.mark.parametrize("check_id", new.IDS)
def test_declared_pass_fail_and_missing(check_id):
    cases = new.CASES[check_id]
    assert evaluate_check(check_id, cases["pass"], {})[0] == "PASS"
    assert evaluate_check(check_id, cases["fail"], {})[0] == "FAIL"
    assert evaluate_check(check_id, cases["missing"], {})[0] == "UNKNOWN"


def test_postgresql_unknown_enum_and_denied_field():
    cid = "azure.cis.public_network_access_should_postgresql_servers"
    assert evaluate_check(cid, {"properties": {"network": {"publicNetworkAccess": "Pending"}}}, {})[0] == "UNKNOWN"
    denied = {"properties": {"network": {"_coverage": {"publicNetworkAccess": {"status": "denied"}}}}}
    assert evaluate_check(cid, denied, {})[0] == "UNKNOWN"


def test_signed_high_severity_and_mysql_public_network_declaration():
    cid = "azure.cis.public_network_access_should_mysql_servers"
    assert evaluate_check(cid, new.CASES[cid]["pass"], {})[0] == "PASS"
    assert evaluate_check(cid, new.CASES[cid]["fail"], {})[0] == "FAIL"
    assert evaluate_check(cid, {"properties": {"network": {"publicNetworkAccess": "Pending"}}}, {})[0] == "UNKNOWN"
    assert evaluate_check(cid, {"properties": {"network": {"_coverage": {"publicNetworkAccess": {"status": "denied"}}}}}, {})[0] == "UNKNOWN"


def test_postgresql_log_duration_requires_complete_unique_parameter():
    cid = "azure.gap.postgres_db_server_log_duration_on"
    assert evaluate_check(cid, new.CASES[cid]["pass"], {})[0] == "PASS"
    assert evaluate_check(cid, new.CASES[cid]["fail"], {})[0] == "FAIL"
    assert evaluate_check(cid, {"configurations": []}, {})[0] == "UNKNOWN"
    assert evaluate_check(cid, {"configurations": [{"name": "log_duration", "properties": {"value": "on"}}, {"name": "log_duration", "properties": {"value": "off"}}]}, {})[0] == "UNKNOWN"
    assert evaluate_check(cid, {"_coverage": {"configurations": {"status": "denied"}}, "configurations": []}, {})[0] == "UNKNOWN"
    assert evaluate_check(cid, {"configurations": [{"name": "log_duration", "properties": {"value": "maybe"}}]}, {})[0] == "UNKNOWN"


def test_search_cmk_requires_enforcement_and_compliance():
    cid = "azure_search_service_3_5_1_19_a3c75c0"
    good = new.CASES[cid]["pass"]
    disabled = copy.deepcopy(good)
    disabled["properties"]["encryptionWithCmk"]["enforcement"] = "Disabled"
    assert evaluate_check(cid, disabled, {})[0] == "FAIL"
    missing = copy.deepcopy(good)
    del missing["properties"]["encryptionWithCmk"]["encryptionComplianceStatus"]
    assert evaluate_check(cid, missing, {})[0] == "UNKNOWN"
    unknown = copy.deepcopy(good)
    unknown["properties"]["encryptionWithCmk"]["enforcement"] = "FutureMode"
    assert evaluate_check(cid, unknown, {})[0] == "UNKNOWN"


def test_vm_identity_system_or_valid_user_reference():
    cid = "azure_vm_app_function_identity_is_configured_bdb10d4"
    arm_id = "/subscriptions/00000000-1111-2222-3333-444444444444/resourceGroups/rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/app"
    assert evaluate_check(cid, {"identity": {"type": "UserAssigned", "userAssignedIdentities": {arm_id: None}}}, {})[0] == "PASS"
    assert evaluate_check(cid, {"identity": {"type": "SystemAssigned, UserAssigned", "userAssignedIdentities": {arm_id: None}}}, {})[0] == "PASS"
    assert evaluate_check(cid, {"identity": {"type": "SystemAssigned, UserAssigned", "principalId": "p", "userAssignedIdentities": {"wrong": {}}}}, {})[0] == "PASS"
    assert evaluate_check(cid, {"identity": {"type": "UserAssigned", "userAssignedIdentities": {"wrong": {}}}}, {})[0] == "UNKNOWN"
    assert evaluate_check(cid, {"identity": {"type": "SystemAssigned"}}, {})[0] == "UNKNOWN"
    assert evaluate_check(cid, {"identity": {"type": "None"}}, {})[0] == "FAIL"
    assert evaluate_check(cid, {"properties": {}}, {})[0] == "UNKNOWN"


def test_nsg_nic_or_subnet_association_requires_typed_arm_reference():
    cid = "azure_pci_1_2_8_39"
    cases = new.CASES[cid]
    assert evaluate_check(cid, cases["pass"], {})[0] == "PASS"
    assert evaluate_check(cid, cases["fail"], {})[0] == "FAIL"
    subnet = {"properties": {"subnets": [{"id": "/subscriptions/00000000-1111-2222-3333-444444444444/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet1/subnets/app"}], "networkInterfaces": []}}
    assert evaluate_check(cid, subnet, {})[0] == "PASS"
    malformed = {"properties": {"subnets": [{"id": "not-an-arm-id"}], "networkInterfaces": []}}
    assert evaluate_check(cid, malformed, {})[0] == "UNKNOWN"
    incomplete = {"properties": {"subnets": []}}
    assert evaluate_check(cid, incomplete, {})[0] == "UNKNOWN"


def test_mysql_cmk_missing_or_invalid_key_and_identity():
    cid = "azure.cis.mysql_flexible_cmk"
    good = new.CASES[cid]["pass"]
    assert evaluate_check(cid, good, {})[0] == "PASS"
    assert evaluate_check(cid, new.CASES[cid]["fail"], {})[0] == "FAIL"
    without_identity = copy.deepcopy(good)
    without_identity["properties"]["dataEncryption"]["primaryUserAssignedIdentityId"] = ""
    assert evaluate_check(cid, without_identity, {})[0] == "FAIL"
    incomplete = copy.deepcopy(good)
    del incomplete["properties"]["dataEncryption"]["primaryKeyURI"]
    assert evaluate_check(cid, incomplete, {})[0] == "UNKNOWN"
    malformed = copy.deepcopy(good)
    malformed["properties"]["dataEncryption"]["primaryKeyURI"] = "http://example.org/key"
    assert evaluate_check(cid, malformed, {})[0] == "UNKNOWN"
