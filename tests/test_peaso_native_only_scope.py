"""Automatic product admission excludes external contracts without changing evidence."""
import copy
import pytest
from peaso import engine
from peaso.checks import CHECKS
from peaso.checks.native_only import exclusions
from peaso.snapshot import make_snapshot
from peaso.server import catalog_view
from tests import archived_check_contract


BEDROCK = "aws_bedrock_automated_reasoning_policy_attached"


def test_bedrock_signed_contract_is_archived_out_of_native_only_admission():
    entry = exclusions()[BEDROCK]
    assert "complete_in_scope_bedrock_application_inventory" in entry["mandatory_external_fields"]
    assert "application_to_guardrail_version_bindings" in entry["mandatory_external_fields"]
    assert "approved_active_policy_semantics" in entry["mandatory_external_fields"]
    assert BEDROCK in {check.id for check in CHECKS}
    assert BEDROCK not in {check.id for check in engine._registry()}
    assert BEDROCK not in {row["id"] for row in engine.get_catalog()["checks"]}
    _, selected = engine._selection("aws", None, None, None)
    assert BEDROCK not in {check.id for check in selected}
    request = {"connector": {"provider": "aws"}, "checks": [BEDROCK]}
    with pytest.raises(ValueError, match="external policy or manual evidence"):
        engine.plan_collection(request)
    assert "bedrock_automated_reasoning_policy" in archived_check_contract.plan_collection(request)


@pytest.mark.parametrize("check_id", sorted(exclusions()))
def test_external_contract_cannot_be_selected_for_collection_or_evaluation(check_id):
    check = next(check for check in CHECKS if check.id == check_id)
    snapshot = make_snapshot(check.provider, ["fixture"], [])
    with pytest.raises(ValueError, match="external policy or manual evidence"):
        engine.evaluate_snapshot(snapshot, checks=[check_id])
    with pytest.raises(ValueError, match="external policy or manual evidence"):
        engine.plan_collection({"connector": {"provider": check.provider}, "checks": [check_id]})


def test_all_public_selectors_and_framework_counts_use_active_scope():
    excluded = set(exclusions())
    assert excluded and excluded <= {check.id for check in CHECKS}
    full = engine.get_catalog()
    catalog_view.summary.cache_clear()
    catalog_view.frameworks_view.cache_clear()
    summary = catalog_view.summary()
    active = {check.id for check in engine._registry()}
    assert active.isdisjoint(excluded)
    assert not excluded.intersection(check["id"] for check in full["checks"])
    assert not excluded.intersection(check["id"] for check in summary["checks"])
    assert full["manual_requirements"] == []
    assert full["upstream_coverage"]["native_checks"] == len(active)
    for row in full["framework_versions"]:
        assert not excluded.intersection(row["native_check_ids"])
        assert row["supported_native_checks"] == len(row["native_check_ids"])
    for provider in ("aws", "gcp", "azure", "k8s"):
        _, default = engine._selection(provider, None, None, None)
        _, framework = engine._selection(provider, None, None, ["HackTricks Cloud Best Practices"])
        assert not excluded.intersection(c.id for c in default + framework)


@pytest.mark.parametrize("provider,check,kind", [
    ("aws", "aws.ec2.imdsv2", "instance"),
    ("gcp", "gcp.storage.uniform_access", "bucket"),
    ("azure", "azure.storage.https_only", "storage_account"),
    ("k8s", "k8s.pod.no_privileged_containers", "pod"),
])
@pytest.mark.parametrize("state,expected", [("denied", "DENIED"), ("not_collected", "UNKNOWN")])
def test_native_read_gaps_are_not_excluded_or_reported_as_pass(provider, check, kind, state, expected):
    assert check not in exclusions()
    snapshot = make_snapshot(provider, ["fixture"], [{"type": kind, "scope": "fixture", "status": state, "items": []}])
    original = copy.deepcopy(snapshot)
    report = engine.evaluate_snapshot(snapshot, checks=[check], categories=["hardening"])
    assert snapshot == original
    assert report["findings"][0]["status"] == expected
    assert not report["stats"]["coverage_complete"]


def test_host_file_attestations_are_not_automatic_inventories():
    full = engine.get_catalog()
    assert "file_metadata" not in full["inventories"]["k8s"]
    assert "file_metadata" not in engine.plan_collection({"connector": {"provider": "k8s"}})
    with pytest.raises(ValueError, match="inventories must be supported"):
        engine.plan_collection({"connector": {"provider": "k8s", "options": {"inventories": ["file_metadata"]}}})


REVIEWED_AWS_UNKNOWN_EXTERNAL = {
    "aws.claude_a.organizations.no_untrusted_delegated_administrators": "organizations_trusted_delegated_administrators",
    "aws_cloudtrail_administration_command": "approved_remote_administration_principals",
    "aws_cloudtrail_event_triggered_execution": "approved_event_automation_principals",
    "aws_cloudtrail_permission_group_discovery": "approved_iam_inventory_principals",
}


def test_remaining_aws_unknown_customer_contracts_are_not_auto_admitted():
    entries = exclusions()
    catalog_ids = {row["id"] for row in engine.get_catalog()["checks"]}
    _, default = engine._selection("aws", None, None, None)
    default_ids = {check.id for check in default}
    historical_ids = {check.id for check in CHECKS}
    for check_id, field in REVIEWED_AWS_UNKNOWN_EXTERNAL.items():
        assert field in entries[check_id]["mandatory_external_fields"]
        assert check_id in historical_ids
        assert check_id not in catalog_ids
        assert check_id not in default_ids
        with pytest.raises(ValueError, match="external policy or manual evidence"):
            engine.plan_collection({"connector": {"provider": "aws"}, "checks": [check_id]})


def test_organization_delegate_grant_and_fixed_native_thresholds_remain_admitted():
    native_ids = {
        "aws_cis_organizations_policy_management_delegated",
        "aws.gap.iam.root_not_used_90_days",
    }
    assert native_ids.isdisjoint(exclusions())
    assert native_ids <= {check.id for check in CHECKS}
    assert native_ids <= {row["id"] for row in engine.get_catalog()["checks"]}
    _, default = engine._selection("aws", None, None, None)
    assert native_ids <= {check.id for check in default}
    for check_id in native_ids:
        assert engine.plan_collection({"connector": {"provider": "aws"}, "checks": [check_id]})


def test_owner_scoped_gcp_deployment_projection_is_not_automatic_inventory():
    from peaso.checks.native_only import automated_inventory_types
    assert 'deployed_image' not in automated_inventory_types('gcp',['bucket','deployed_image'])
    plan=engine.plan_collection({'connector':{'provider':'gcp','options':{'collect_all':True}}})
    assert 'deployed_image' not in plan
    with pytest.raises(ValueError,match='inventories must be supported'):
        engine.plan_collection({'connector':{'provider':'gcp','options':{'inventories':['deployed_image']}}})
    assert 'deployed_image' not in engine.get_catalog()['inventories']['gcp']


def test_unsupported_listener_contract_is_separate_from_customer_inputs():
    from peaso.checks.native_only import exclusions, scope
    ident = 'aws_nist_ec2_instance_not_publicly_accessible'
    row = exclusions()[ident]
    assert row['disposition'] == 'unsupported_exact_contract'
    assert row['mandatory_external_fields'] == []
    unsupported = {cid for cid, item in exclusions().items()
                   if item.get('disposition') == 'unsupported_exact_contract'}
    historical = {ident, 'aws_cis_lightsail_ssm_patch_compliance', 'gcp_logging_detect_t1110'}
    assert historical <= unsupported
    # Exact native-source reviews archive impossible or unobservable legacy
    # contracts; they are distinct from customer policy or attestation inputs.
    assert unsupported == historical | {
        'azure.claude.iam_root_custom_role_no_wildcard',
        'azure.claude.managed_hsm_audit_logging',
        'azure.gap.automation_account_encrypted_with_cmk',
        'azure.gap.monitor_log_cluster_encrypted_with_cmk',
        'azure.gap.stream_analytics_job_encrypted_with_cmk',
        'azure.other.access_analysis_coverage',
        'azure_aks_cluster_10_2_1_1_17_885658f',
        'azure_api_management_10_3_1_3_8a50dc0',
        'azure_devops_project_1_2_8_6_fb0e5a8',
        'azure_pci_10_2_1_1_16',
        'gcp_certificate_renewal_30_days',
        'gcp_certificate_rotation_180_days',
        'gcp_certificate_rotation_90_days',
        'gcp_lb_server_header_rewrite',
    }
    grouped = {cid for cid, entry in exclusions().items() if entry.get('disposition') in
               {'unsupported_exact_contract', 'retired_native_service', 'superseded_native_criterion'}}
    assert scope()['excluded_unsupported_controls'] == len(grouped)
    for cid in unsupported:
        assert exclusions()[cid]['mandatory_external_fields'] == []
        assert cid not in {check.id for check in engine._registry()}
    lightsail = exclusions()['aws_cis_lightsail_ssm_patch_compliance']
    assert lightsail['mandatory_external_fields'] == []
    assert 'aws_cis_lightsail_ssm_patch_compliance' not in {check.id for check in engine._registry()}
    assert ident not in {check.id for check in engine._registry()}
    assert row['native_alternative'] in {check.id for check in engine._registry()}
    assert len(row['native_alternatives']) == 5
