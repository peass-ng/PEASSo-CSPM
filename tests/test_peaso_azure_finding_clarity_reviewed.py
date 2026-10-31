"""Actual evaluator outcomes and evidence contracts for reviewed Azure guidance."""
from copy import deepcopy
import json
from pathlib import Path

import pytest


from peaso.checks import CHECKS, resolve_check_id

# The reviewed rows are a frozen record.  #104 (fe6f7901) later retired this
# overlapping reviewed id into its surviving native, which has its own row.
RETIRED_REVIEWED = {'azure.claude.aks_authorized_ip_ranges': 'azure.aks.api_server_restricted'}
from peaso.checks import azure_finding_clarity_reviewed
from peaso.checks.azure_finding_clarity_reviewed import ROWS, description, remediation
from tests.overlay_originals import captured_originals
from peaso.checks.azure_native_review_copy_20261020 import reviewed_fields
from tests.azure_native_successor_inputs_20261020 import current_cases
from peaso.checks import CHECK_ALIASES, CHECKS, resolve_check_id



@pytest.fixture(scope="module")
def source_rows():
    return captured_originals(azure_finding_clarity_reviewed)


@pytest.mark.parametrize("check_id", sorted(ROWS))
def test_description_preserves_actual_evaluation_contract(check_id, source_rows):
    original = source_rows[0][check_id]
    before = deepcopy(original)
    actual = description(check_id, original)
    assert original == before
    fields = reviewed_fields(check_id, 'description', ROWS[check_id]['description_fields'])
    assert actual["description"] == fields["description"]
    assert len(actual["description"].split()) <= 40
    changed = set(fields)
    corrected_contracts = {
        "azure.claude.iam_custom_role_administers_locks",
        "azure.claude.storage_key_expiration_policy_max_90",
        "azure.claude.network_watcher_flow_logs_retention_90",
        "azure.claude.sql_database_long_term_retention",
        "azure.port.keyvault_key_automatic_rotation_enabled",
        "azure.claude2.vnet_flow_logs_to_log_analytics",
        "azure.claude2.nsg_flow_logs_to_log_analytics",
        "azure.claude.storage_access_keys_rotated_90",
        "azure.claude2.nsg_flow_log_configured",
        "azure.claude.vm_windows_secure_boot",
        "azure.claude.managed_hsm_audit_logging",
        "azure.claude.recovery_vault_backup_retention_30_days",
        "azure.claude.aks_authorized_ip_ranges",
        "azure.claude2.app_gateway_min_tls_12",
        "azure.claude2.app_gateway_waf_enabled",
        "azure.claude.sql_database_va_findings_resolved",
    }
    if check_id == 'azure.claude.iam_custom_role_administers_locks':
        assert changed == {'description', 'pass_when', 'fail_when'}
        assert all(actual[k] == v for k, v in fields.items())
    if check_id not in corrected_contracts:
        assert changed == {"description"}
    else:
        assert changed <= {"description", "evaluated", "pass_when", "fail_when", "not_applicable_when"}
    assert {k: v for k, v in actual.items() if k not in changed} == {
        k: v for k, v in original.items() if k not in changed}


@pytest.mark.parametrize("check_id", sorted(ROWS))
def test_remediation_preserves_references_commands_and_bindings(check_id, source_rows):
    original = source_rows[1][check_id]
    before = deepcopy(original)
    actual = remediation(check_id, original)
    assert original == before
    assert 1 <= len(actual["steps"]) <= 2
    assert len(actual["caveats"]) == 1
    assert len(actual["summary"].split()) <= 40
    changed = {"summary", "steps", "caveats"}
    if check_id == 'azure.claude.synapse_workspace_vulnerability_assessment':
        # Correct the unrelated historical diagnostic-settings link explicitly.
        assert actual['references'] == reviewed_fields(check_id, 'remediation', ROWS[check_id]['remediation_fields'])['references']
        changed.add('references')
    if ROWS[check_id].get("new_text_only_template"):
        assert actual["review_status"] == "approved"
        assert actual["cli"] == []
        assert "iac" not in actual
        assert set(actual) == {"review_status", "summary", "steps", "cli", "caveats", "references"}
        assert actual["references"] and all(row["url"].startswith("https://learn.microsoft.com/") for row in actual["references"])
    else:
        assert {k: v for k, v in actual.items() if k not in changed} == {
            k: v for k, v in original.items() if k not in changed}


def test_unowned_check_is_preserved_without_sharing_mutable_state():
    original = {"description": "Keep this exact text.", "evaluated": ["specific.field"]}
    actual = description("unowned.check", original)
    assert actual == original
    actual["evaluated"].append("different")
    assert original["evaluated"] == ["specific.field"]
    assert description("unowned.check", None) is None


def test_private_endpoint_existence_does_not_claim_approval(source_rows):
    cid = "azure.claude.storage_private_endpoint_present"

    from peaso.checks.claude_azure_common import approved_private_link_case
    item = approved_private_link_case()
    item["properties"]["privateEndpointConnections"][0]["properties"]["privateLinkServiceConnectionState"]["status"] = "Pending"
    assert next(c for c in CHECKS if c.id == cid).evaluate(item, {})[0] == "PASS"


def _current_route_cases(check_id, cases):
    """Add only the SQL authentication-mode child read by the current route.

    66b47ab6 reads azureADOnlyAuthentications/Default instead of the flag on
    the administrator row. The sealed native capture predates that route, so
    the child is supplied exactly as tests/azure_current_native_route_successor
    _20261027.py serves it: from the captured administrator flag, which the
    current collector no longer projects on the administrator row.
    """
    if check_id != "azure.htbp.sql.entra_only_authentication":
        return cases
    for branch in ("pass", "fail"):
        item = cases.get(branch)
        if not isinstance(item, dict) or "azureADOnlyAuthentications" in item:
            continue
        admin, = item["serverAdministrators"]
        flag = admin["properties"].pop("azureADOnlyAuthentication")
        assert type(flag) is bool and flag is (branch == "pass")
        item["azureADOnlyAuthentications"] = [{
            "id": item["id"] + "/azureADOnlyAuthentications/Default", "name": "Default",
            "type": "Microsoft.Sql/servers/azureADOnlyAuthentications", "parent_id": item["id"],
            "properties": {"azureADOnlyAuthentication": flag}}]
        item["_coverage"]["azureADOnlyAuthentications"] = {"status": "collected"}
    return cases


@pytest.mark.parametrize("check_id", sorted(ROWS))
def test_reviewed_copy_matches_real_positive_negative_and_missing_facts(check_id):
    from peaso.checks.fixtures import CASES
    if check_id in RETIRED_REVIEWED:
        # The retired id runs as its survivor, whose own row covers its branches.
        assert resolve_check_id(check_id) == RETIRED_REVIEWED[check_id] in ROWS
        assert check_id not in CASES
        return
    check = next(c for c in CHECKS if c.id == check_id)
    cases = _current_route_cases(check_id, current_cases(check_id, CASES.get(check_id) or json.loads((Path(__file__).parent / "fixtures/azure_core6.json").read_text())[check_id]))
    for state in ("pass", "fail", "unknown", "not_applicable"):
        if state not in cases:
            continue
        assert check.evaluate(deepcopy(cases[state]), deepcopy(cases.get(state + "_index", cases.get("index", {}))))[0] == state.upper()
    assert check.evaluate({}, {})[0] == "UNKNOWN"


def test_new_text_templates_discard_pending_commands_iac_and_unreviewed_metadata(source_rows):
    selected = [cid for cid, row in ROWS.items() if row.get("new_text_only_template")]
    assert selected
    for cid in selected:
        before = source_rows[1][cid]
        result = remediation(cid, before)
        assert result["cli"] == []
        assert "iac" not in result
        assert result["review_status"] == "approved"


@pytest.mark.parametrize("slug", ["logic_app_workflow_diagnostic_logging", "nsg_diagnostic_logging"])
@pytest.mark.parametrize("case, enabled", [("pass", True), ("fail", False)])
def test_diagnostic_observation_records_the_actual_boolean(slug, case, enabled):
    from peaso.checks.fixtures import CASES
    cid = "azure.claude." + slug
    check = next(c for c in CHECKS if c.id == cid)
    facts = deepcopy(CASES[cid][case])
    before = deepcopy(facts)
    status, evidence = check.evaluate(facts, {})
    assert status == case.upper()
    assert evidence == {"diagnostic_logging_enabled": enabled}
    assert facts == before

@pytest.mark.parametrize("case, enabled", [("pass", True), ("fail", False)])
def test_managed_instance_assessment_records_the_observed_scan_flag(case, enabled):
    from peaso.checks.fixtures import CASES
    cid = "azure.claude.mssql_managed_instance_vulnerability_assessment"
    check = next(c for c in CHECKS if c.id == cid)
    status, evidence = check.evaluate(deepcopy(CASES[cid][case]), {})
    assert status == case.upper()
    assert evidence["recurring_scans_enabled"] is enabled


def test_container_key_summary_uses_decisive_declaration_flag_without_inventing_key_validity():
    check = next(c for c in CHECKS if c.id == "azure.claude.container_group_cmk")
    status, evidence = check.evaluate({"properties": {"encryptionProperties": {"vaultBaseUrl": False, "keyName": "present"}}}, {})
    assert status == "FAIL" and evidence["customer_key_configured"] is False
    status, evidence = check.evaluate({"properties": {"encryptionProperties": {"vaultBaseUrl": "https://vault.example", "keyName": "present"}}}, {})
    assert status == "PASS" and evidence["customer_key_configured"] is True


def test_databricks_evidence_distinguishes_key_properties_from_a_verified_key_uri():
    check = next(c for c in CHECKS if c.id == "azure.claude.databricks_managed_disk_cmk")
    item = {"properties": {"encryption": {"entities": {"managedDisk": {"keyVaultProperties": {"other_metadata": "value"}}}}}}
    status, evidence = check.evaluate(item, {})
    assert status == "PASS"  # The source criterion is the nonempty object, not URI validity.
    assert evidence["key_properties_present"] is True
    assert evidence["key_vault_uri"] is None


def test_vm_nic_allow_rule_retains_its_actual_protocol_for_priority_decisions():
    from peaso.checks.fixtures import CASES
    cid = "azure.claude.vm_nic_nsg_internet_tcp_ingress"
    case = CASES[cid]
    check = next(c for c in CHECKS if c.id == cid)
    status, evidence = check.evaluate(deepcopy(case["fail"]), deepcopy(case["fail_index"]))
    assert status == "FAIL"
    assert evidence["internet_allow_rules"][0]["protocol"] == "tcp"

@pytest.mark.parametrize('cid,key',[('azure.storage.blob_versioning','versioning_enabled'),('azure.storage.container_soft_delete','container_soft_delete_enabled')])
@pytest.mark.parametrize('state,expected',[('pass',True),('fail',False)])
def test_blob_evidence_reports_the_decisive_read_only_configuration(cid,key,state,expected):
    from peaso.checks.fixtures import CASES
    c=next(c for c in CHECKS if c.id==cid)
    item=deepcopy(CASES[cid][state]);before=deepcopy(item)
    status,evidence=c.evaluate(item,{})
    assert status==state.upper()
    assert evidence[key] is expected
    assert item==before
