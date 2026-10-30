"""Retired overlapping native ids stay resolvable as aliases of their surviving native."""
import pytest

from peaso.checks import CHECKS, alias_check, evaluate_check, register
from peaso.engine import _selection, diff_reports
from peaso.snapshot import digest

EXPECTED = {"gcp.compute.os_login": "gcp.ports.compute_oslogin_metadata_precedence",
            "gcp.sql.require_tls": "gcp.ports.sql_instance_require_ssl_enabled",
            "aws.a.cloudwatch.cross_account_role_absent": "aws.claude2_a.cloudwatch.cross_account_sharing_role_absent",
            "aws.c2b.ecs.service_no_public_ip": "aws.c2b.ecs.awsvpc_service_no_public_ip",
            "aws.c2b.elasticache.cluster_public_subnet": "aws.c2b.elasticache.cluster_public_subnet_prowler",
            "aws.b.redshift.no_public_endpoint": "aws.cb.redshift.not_publicly_accessible",
            "aws.a.s3.bucket_account_public_blocks": "aws.s3.public_access_block",
            "azure.claude.aks_authorized_ip_ranges": "azure.aks.api_server_restricted",
            "aws.cb.sns.policy_prohibit_public_access_perimeter": "aws.cb.sns.policy_no_unrestricted_wildcard",
            "aws_g6_redshift_automatic_version_upgrade": "aws.cb.redshift.allow_version_upgrade",
            "aws.pci.cloudtrail.authentication_events": "aws.gap.cloudtrail.region_logging_management_events",
            "aws_fedramp_rds_cluster_members_enhanced_monitoring": "aws.nist.rds_cluster_member_enhanced_monitoring"}
IDS = {c.id for c in CHECKS}


def test_alias_and_register_reject_collisions():
    with pytest.raises(ValueError):
        alias_check("gcp.compute.os_login", "gcp.ports.compute_oslogin_metadata_precedence")
    with pytest.raises(ValueError):
        alias_check(next(iter(IDS)), "gcp.ports.sql_instance_require_ssl_enabled")
    with pytest.raises(ValueError):
        register("gcp.sql.require_tls", "gcp", "hardening", "sql_instance", "t", "low", "CM-6", "r")(lambda item, index: None)


def test_evaluate_check_resolves_alias():
    item = {"settings": {"ipConfiguration": {"sslMode": "ALLOW_UNENCRYPTED_AND_ENCRYPTED"}}}
    assert evaluate_check("gcp.sql.require_tls", item, {})[0] == evaluate_check("gcp.ports.sql_instance_require_ssl_enabled", item, {})[0] == "FAIL"
    for public, expected in ((False, "PASS"), (True, "FAIL")):
        cluster = {"ClusterIdentifier": "rs1", "PubliclyAccessible": public}
        assert evaluate_check("aws.b.redshift.no_public_endpoint", cluster, {})[0] == \
            evaluate_check("aws.cb.redshift.not_publicly_accessible", cluster, {})[0] == expected
    old_aks = "azure.claude.aks_authorized_ip_ranges"
    new_aks = "azure.aks.api_server_restricted"
    for item, expected in (({"properties": {"apiServerAccessProfile": {"enablePrivateCluster": True}}}, "PASS"),
                           ({"properties": {}}, "UNKNOWN")):
        assert evaluate_check(old_aks, item, {})[0] == evaluate_check(new_aks, item, {})[0] == expected


def test_selection_accepts_retired_ids_and_emits_one_check():
    _, selected = _selection("gcp", None, ["gcp.compute.os_login", "gcp.ports.compute_oslogin_metadata_precedence"], None)
    assert [c.id for c in selected] == ["gcp.ports.compute_oslogin_metadata_precedence"]
    _, selected = _selection("aws", None, ["aws.c2b.ecs.service_no_public_ip",
        "aws.c2b.ecs.awsvpc_service_no_public_ip"], None)
    assert [c.id for c in selected] == ["aws.c2b.ecs.awsvpc_service_no_public_ip"]
    _, selected = _selection("aws", None, ["aws.b.redshift.no_public_endpoint",
        "aws.cb.redshift.not_publicly_accessible"], None)
    assert [c.id for c in selected] == ["aws.cb.redshift.not_publicly_accessible"]
    _, selected = _selection("aws", None, ["aws.a.s3.bucket_account_public_blocks",
        "aws.s3.public_access_block"], None)
    assert [c.id for c in selected] == ["aws.s3.public_access_block"]
    _, selected = _selection("azure", None, ["azure.claude.aks_authorized_ip_ranges",
        "azure.aks.api_server_restricted"], None)
    assert [c.id for c in selected] == ["azure.aks.api_server_restricted"]
    _, selected = _selection("aws", None, ["aws.cb.sns.policy_prohibit_public_access_perimeter",
        "aws.cb.sns.policy_no_unrestricted_wildcard"], None)
    assert [c.id for c in selected] == ["aws.cb.sns.policy_no_unrestricted_wildcard"]


def _finding(cid, status="FAIL", rid="projects/p/instances/i"):
    return {"id": digest(["gcp", "projects/p", rid, cid]), "check_id": cid, "provider": "gcp", "scope": "projects/p",
            "resource_id": rid, "status": status, "evidence": {}, "frameworks": []}


def _report(findings):
    return {"provider": "gcp", "scopes": ["projects/p"], "findings": findings}


def test_diff_of_stored_scan_with_retired_ids_has_no_spurious_removals():
    survivor = "gcp.ports.compute_oslogin_metadata_precedence"
    old = _report([_finding("gcp.compute.os_login"), _finding(survivor)])
    new = _report([_finding(survivor)])
    assert diff_reports(old, new)["stats"] == {"added": 0, "removed": 0, "changed": 0}
    only_retired = _report([_finding("gcp.compute.os_login")])
    assert diff_reports(only_retired, new)["stats"] == {"added": 0, "removed": 0, "changed": 0}
    fixed = _report([_finding(survivor, status="PASS")])
    assert diff_reports(only_retired, fixed)["stats"] == {"added": 0, "removed": 0, "changed": 1}


def test_api_selector_index_accepts_retired_ids():
    from peaso.server.validation import _selector_index
    gcp_aliases = {key for key in EXPECTED if key.startswith("gcp.")}
    manual_alias = "aws.a.cloudwatch.cross_account_role_absent"
    aws_aliases = {key for key in EXPECTED if (key.startswith("aws_") or key.startswith("aws.")) and key != manual_alias}
    assert gcp_aliases <= _selector_index("gcp")[1]
    assert aws_aliases <= _selector_index("aws")[1]
    assert manual_alias not in _selector_index("aws")[1]
    assert not gcp_aliases & _selector_index("aws")[1]
    assert not aws_aliases & _selector_index("gcp")[1]
