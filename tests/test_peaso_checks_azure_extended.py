"""Behavior and applicability evidence for the reviewed Azure extension."""
import copy

import pytest

from peaso.checks import CHECKS, azure_extended
from peaso.checks.fixtures import CASES
from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot

REGISTRY = {check.id: check for check in CHECKS}
EXTENDED = [REGISTRY[cid] for cid in azure_extended.CHECK_IDS]


def test_extension_has_at_least_twenty_distinct_pure_checks():
    assert len(EXTENDED) >= 20
    assert len(set(azure_extended.CHECK_IDS)) == len(EXTENDED)
    assert all(check.provider == "azure" for check in EXTENDED)


@pytest.mark.parametrize("check", EXTENDED, ids=lambda check: check.id)
def test_every_extended_check_pass_fail_missing_malformed_denied_and_purity(check):
    cases = CASES[check.id]
    for label, status in (("pass", "PASS"), ("fail", "FAIL")):
        native = copy.deepcopy(cases[label])
        original = copy.deepcopy(native)
        index = {"unrelated": ["unchanged"]}
        assert check.evaluate(native, index)[0] == status
        assert native == original
        assert index == {"unrelated": ["unchanged"]}
    for native in ({}, None, [], "not an object", {"collection_status": "denied"}):
        assert check.evaluate(native, {})[0] == "UNKNOWN"


@pytest.mark.parametrize("check", EXTENDED, ids=lambda check: check.id)
@pytest.mark.parametrize("collection_status,expected", [("denied", "DENIED"), ("unknown", "UNKNOWN"), ("malformed", "UNKNOWN"), ("empty", "EMPTY"), ("partial", "UNKNOWN")])
def test_engine_preserves_unavailable_inventory_status(check, collection_status, expected):
    snapshot = make_snapshot("azure", ["/subscriptions/test"], [{"type": check.kind, "scope": "/subscriptions/test", "service": "Azure", "status": collection_status, "items": []}])
    report = evaluate_snapshot(snapshot, checks=[check.id])
    assert {finding["status"] for finding in report["findings"]} == {expected}
    assert "PASS" not in report["stats"]["by_status"]


@pytest.mark.parametrize("days,expected", [(0, "PASS"), (89, "FAIL"), (90, "PASS"), (-1, "UNKNOWN"), (True, "UNKNOWN"), ("90", "UNKNOWN")])
def test_sql_audit_unlimited_retention_is_not_zero_day_retention(days, expected):
    assert REGISTRY["azure.sql.audit_retention"].evaluate({"properties": {"retentionDays": days}}, {})[0] == expected


def test_trusted_launch_secure_boot_and_tpm_are_both_required():
    check = REGISTRY["azure.vm.trusted_launch"]
    for boot, tpm, expected in ((True, True, "PASS"), (True, False, "FAIL"), (False, True, "FAIL"), (False, False, "FAIL")):
        item = {"properties": {"securityProfile": {"securityType": "TrustedLaunch", "uefiSettings": {"secureBootEnabled": boot, "vTpmEnabled": tpm}}}}
        assert check.evaluate(item, {})[0] == expected
    assert check.evaluate({"properties": {"securityProfile": {"securityType": "TrustedLaunch"}}}, {})[0] == "UNKNOWN"
    assert check.evaluate({"properties": {"securityProfile": {"securityType": "FuturePlatform"}}}, {})[0] == "UNKNOWN"


def test_linux_ssh_does_not_claim_guest_configuration_and_windows_is_inapplicable():
    check = REGISTRY["azure.vm.linux_ssh_keys"]
    windows = {"properties": {"storageProfile": {"osDisk": {"osType": "Windows"}}}}
    assert check.evaluate(windows, {})[0] == "NOT_APPLICABLE"
    result = check.evaluate(CASES[check.id]["pass"], {})
    assert "guest sshd runtime is not verified" in result[1]["semantics"]


def test_ephemeral_os_disk_is_inapplicable_and_missing_managed_disk_fact_unknown():
    check = REGISTRY["azure.vm.managed_disks"]
    ephemeral = {"properties": {"storageProfile": {"osDisk": {"diffDiskSettings": {"option": "Local"}}}}}
    assert check.evaluate(ephemeral, {})[0] == "NOT_APPLICABLE"
    missing = {"properties": {"storageProfile": {"osDisk": {}, "dataDisks": []}}}
    assert check.evaluate(missing, {})[0] == "UNKNOWN"


@pytest.mark.parametrize("kind", ["fileServices", "queueServices", "tableServices"])
def test_blob_lifecycle_rules_do_not_apply_to_other_storage_services(kind):
    for cid in ("azure.storage.blob_versioning", "azure.storage.blob_soft_delete_retention", "azure.storage.container_soft_delete"):
        assert REGISTRY[cid].evaluate({"type": "Microsoft.Storage/storageAccounts/" + kind}, {})[0] == "NOT_APPLICABLE"


def test_blob_retention_boundaries_and_denied_details():
    check = REGISTRY["azure.storage.blob_soft_delete_retention"]
    for days, expected in ((6, "FAIL"), (7, "PASS"), (365, "PASS"), (366, "FAIL"), (True, "UNKNOWN")):
        item = {"type": "Microsoft.Storage/storageAccounts/blobServices", "properties": {"deleteRetentionPolicy": {"enabled": True, "days": days}}}
        assert check.evaluate(item, {})[0] == expected
    denied = {"type": "Microsoft.Storage/storageAccounts/blobServices", "properties": {"deleteRetentionPolicy": {"collection_status": "denied", "enabled": True, "days": 90}}}
    assert check.evaluate(denied, {})[0] == "UNKNOWN"


def test_optional_client_certificates_cannot_pass_required_client_auth():
    check = REGISTRY["azure.app.client_certificates"]
    for mode, expected in (("Required", "PASS"), ("Optional", "FAIL"), ("OptionalInteractiveUser", "FAIL"), ("unknown", "UNKNOWN")):
        assert check.evaluate({"properties": {"clientCertEnabled": True, "clientCertMode": mode}}, {})[0] == expected


def test_tls_future_enum_is_unknown_and_scm_is_independent():
    assert REGISTRY["azure.app.minimum_tls"].evaluate({"properties": {"minTlsVersion": "1.4"}}, {})[0] == "UNKNOWN"
    data = {"properties": {"minTlsVersion": "1.3", "scmMinTlsVersion": "1.0"}}
    assert REGISTRY["azure.app.minimum_tls"].evaluate(data, {})[0] == "PASS"
    assert REGISTRY["azure.app.scm_minimum_tls"].evaluate(data, {})[0] == "FAIL"


def test_secret_expiration_metadata_is_not_rotation_or_value_access():
    check = REGISTRY["azure.vault.secret_expiration"]
    assert check.evaluate({"properties": {"attributes": {"enabled": False}}}, {})[0] == "NOT_APPLICABLE"
    assert check.evaluate({"properties": {"attributes": {"enabled": True}}}, {})[0] == "UNKNOWN"
    assert check.evaluate({"properties": {"attributes": {"enabled": True, "exp": True}}}, {})[0] == "UNKNOWN"
    evidence = check.evaluate(CASES[check.id]["pass"], {})[1]
    assert "value and rotation history were not read" in evidence["semantics"]


def test_sql_master_tde_is_inapplicable_and_alert_arrays_are_strict():
    assert REGISTRY["azure.sql.tde_enabled"].evaluate({"parent_id": "/sql/databases/master"}, {})[0] == "NOT_APPLICABLE"
    alerts = REGISTRY["azure.sql.threat_alerts_all"]
    assert alerts.evaluate({"properties": {"disabledAlerts": []}}, {})[0] == "PASS"
    assert alerts.evaluate({"properties": {"disabledAlerts": [123]}}, {})[0] == "UNKNOWN"


def test_defender_tier_does_not_claim_sensor_or_asset_coverage():
    check = REGISTRY["azure.defender.standard_tier"]
    assert "asset coverage" in check.evaluate(CASES[check.id]["pass"], {})[1]["semantics"]
    assert check.evaluate({"name": "UnknownNewPlan", "properties": {"pricingTier": "Standard"}}, {})[0] == "NOT_APPLICABLE"
