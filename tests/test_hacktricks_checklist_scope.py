"""Checklist selection follows reviewed hardening scope, not source/service names."""
import pytest

from peaso.analysis import ANALYSIS_CHECKS
from peaso.checks import CHECKS, HACKTRICKS
from peaso.checks.catalog import framework_display_names, requirement_tags_for
from peaso.checks.hacktricks_scope import includes, validate_review


@pytest.mark.parametrize("cid", [
    "aws.ebs.encryption", "aws.a.cloudtrail.bucket_mfa_delete",
    "aws.a.cloudtrail.joined_bucket_declared_public_grants",
    "aws.claude_a.iam.custom_policy_no_cloudtrail_star",
    "aws.c2b.autoscaling.lc_imdsv2_required", "aws.a.guardduty.region_enabled",
    "aws.cloudtrail.log_validation", "aws.a.cloudwatch.finite_retention_365",
    "aws_backup_recent_restore_test", "aws.cb.redshift.encrypted_and_logging",
    "gcp.gap.firewall_tcp_ingress_iap_health_check_sources_only",
    "gcp_workbench_root_disabled", "azure_c5_ops_30_01ac",
    "k8s.ports.deployment.cpu_limit", "k8s.ports.namespace.namespace_resource_quota_memory_limit",
    "k8s.cis.the_kube_proxy_metrics_service_is_bound_to_localhost",
    "aws.claude_a.iam.group_not_empty", "aws.ecr.immutable_tags",
    "azure.other.storage_geo", "azure.other.storage_lifecycle",
    "aws.c2b.classic_elb.has_registered_instances", "azure.claude.vmss_not_empty",
    "aws_guardduty_trusted_administrator", "aws_g6_api_stage_effective_waf_acl",
])
def test_hardening_and_owner_approved_groups_keep_tag(cid):
    check = next(c for c in CHECKS if c.id == cid)
    assert includes(cid) and HACKTRICKS in check.frameworks and HACKTRICKS in check.mapping


@pytest.mark.parametrize("cid", [
    "aws.a.accessanalyzer.region_active", "aws.a.accessanalyzer.region_present",
    "aws.gap.accessanalyzer.no_active_findings", "aws.a.cloudwatch.alarm_actions_enabled",
    "aws.a.cloudtrail.bucket_access_logging", "aws.cb.transfer.connector_logging_role",
    "aws.gap.cloudwatch.metric_alarm.cmk_disable_or_scheduled_deletion",
    "aws.claude_a.guardduty.finding_archived", "aws.cb.inspector2.coverage_recently_scanned",
    "aws.b.classic_elb.multiple_az", "aws.nist.sc_5_2_coverage",
    "aws.claude_a.organizations.tag_policy_attached", "aws.pci.lambda.expected_configuration",
    "aws.ecr.lifecycle_policy", "gcp_pci_iam_policy_9a8ce875703d",
    "azure.other.ml_download_audit", "azure.port.defender_notify_owner_contact",
    "k8s.ports.deployment.cpu_request", "k8s.ports.deployment.liveness_probe",
    "k8s.namespace.quota_requests_memory", "aws.b.rds.cluster_event_categories",
    "azure.claude.aks_max_pods_at_least_50", "azure.other.azure_activity_anomaly",
])
def test_observability_status_operations_and_metadata_lose_only_this_tag(cid):
    check = next(c for c in CHECKS if c.id == cid)
    assert not includes(cid) and HACKTRICKS not in check.frameworks and HACKTRICKS not in check.mapping
    display = framework_display_names()
    assert set(check.frameworks) == {display[t["framework_id"]] for t in requirement_tags_for(cid)}


def test_entire_registry_is_reviewed_and_new_checks_are_not_implicitly_tagged():
    validate_review([c.id for c in CHECKS] + [c["id"] for c in ANALYSIS_CHECKS])
    assert not includes("aws.new.unreviewed_security_check")
    with pytest.raises(ValueError, match="missing=.*aws.new"):
        validate_review([c.id for c in CHECKS] + [c["id"] for c in ANALYSIS_CHECKS] + ["aws.new.unreviewed_security_check"])


def test_runtime_checklist_selection_excludes_unrelated_checks():
    from peaso.engine import _selection
    _, selected = _selection("aws", None, None, [HACKTRICKS])
    ids = {c.id for c in selected}
    assert "aws.a.cloudwatch.alarm_actions_enabled" not in ids
    assert "aws.a.accessanalyzer.region_present" not in ids
    assert "aws.ebs.encryption" in ids
    assert all(includes(cid) for cid in ids)
    _, explicit = _selection("aws", None, ["aws.a.cloudwatch.alarm_actions_enabled"], None)
    assert [c.id for c in explicit] == ["aws.a.cloudwatch.alarm_actions_enabled"]


def test_inventory_analysis_is_untagged_in_catalog_findings_and_selection():
    from peaso.analysis.common import finding
    from peaso.engine import _analysis_selection
    row = next(c for c in ANALYSIS_CHECKS if c["id"] == "analysis.coverage")
    assert row["frameworks"] == [] and row["mapping"] == {}
    resource = {"provider": "aws", "scope": "test", "type": "iam_user", "native_id": "user"}
    assert finding({}, resource, "least_privilege", "analysis.coverage", "Missing inventory", "info", {})["frameworks"] == []
    assert "analysis.coverage" not in {c["id"] for c in _analysis_selection("aws", ["least_privilege"], None, [HACKTRICKS])}


