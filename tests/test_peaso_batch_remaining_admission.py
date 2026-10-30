"""Single-batch native admission: signed IDs, tags, fixtures and behavior."""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path

import pytest

from peaso.checks import CHECKS, resolve_check_id
from peaso.checks.fixtures import CASES
from scripts.peaso_compliance_compile import reviewed_equivalent_proposal
from scripts.peaso_compliance_merge_new import signed_proposals
from peaso.checks import CHECKS, HACKTRICKS, resolve_check_id
from scripts.peaso_compliance_compile import reviewed_equivalent_proposal, spec_digest





ROOT = Path(__file__).resolve().parents[1]
LEDGER = ROOT / "docs/compliance-ledgers"
POST_DFAF_IDS = set(json.loads((ROOT / "tests/fixtures/post_dfaf_integration/contract.json").read_text()))
NEXT20_IDS = {"aws_backup_plan_rule_required_frequency", "aws_cis_elbv2_only_tls_listeners"}
SUCCESSOR_IDS = {"azure_api_management_appinsights_ensure_is_configured_42aac6a",
                 "gcp_logging_detect_t1136", "gcp_logging_detect_t1546"}
NEXT_GROUP_IDS = {
    "azure.cis.defender_external_attack_surface_monitoring_easm",
    "azure_directory_user_keyvault_rbac_secret_expiration_set_e2e0e28",
    "azure.other.entra_app_secret_age_90", "aws.pci.secretsmanager.kms_encryption_any",
    "aws.nist.rds_cluster_member_enhanced_monitoring",
    "azure.gap.monitor_log_profile_retention_365_days",
    "azure.cis.app_service_entra_registration_enabled",
    "aws_ecs_task_definition_credential_environment_names",
}
MODULES = {"peaso.checks.batch_remaining_aws", "peaso.checks.batch_remaining_azure",
           "peaso.checks.batch_remaining_gcp", "peaso.checks.batch_remaining_k8s",
           "peaso.checks.batch_remaining_azure_vm_storage"}
EXPECTED_COUNT = 181
ONE_SIDED_FAIL = {"gcp.apikeys.active_service_restrictions"}
ONE_SIDED_PASS = {"gcp.logging.access_transparency_entries"}
# These retained local-only fixtures predate native joins. They must remain
# UNKNOWN; current positive/negative native-envelope paths are tested in the
# provider identity, final-services and Azure effective-NSG suites.
INCOMPLETE_NATIVE_CASES = {
    "gcp_pci_backend_service_2ce96d36d0bf": "URL map backend references unavailable",
    "gcp_cloud_armor_waf_enabled": "full native Cloud Armor rule inventory unavailable",
    "gcp_pci_url_map_9ed56c323a05": "Compute reference outside selected project/resource scope",
    "gcp_kms_key_destroy_alert": "Metric or alert filter association needs semantic review",
    "gcp_gke_small_cluster_auto_upgrade": "native short GKE cluster name unavailable",
    "azure.gap.compute_vm_remote_access_restricted_all_ports": "NSG rules unresolved or path has no NSG",
}
HISTORICAL_NATIVE_UNKNOWN = {cid: {"pass", "fail"} for cid in INCOMPLETE_NATIVE_CASES}
HISTORICAL_NATIVE_UNKNOWN["gcp_logging_enumeration_alert"] = {"pass"}
REDSHIFT_PROPOSAL = "aws_g6_redshift_automatic_version_upgrade"
REDSHIFT_SURVIVOR = "aws.cb.redshift.allow_version_upgrade"
REDSHIFT_CONTROL = ("aws-compliance.benchmark.nist_csf_v2",
                    "aws-compliance.control.redshift_cluster_automatic_upgrade_major_versions_enabled")
CLOUDTRAIL_PROPOSAL = "aws.pci.cloudtrail.authentication_events"
CLOUDTRAIL_SURVIVOR = "aws.gap.cloudtrail.region_logging_management_events"
CLOUDTRAIL_CONTROL_KEYS = {
    ("pci_3.2.1_aws", "10.2.5"), ("pci_3.2.1_aws", "10.2.5.a"),
    ("fedramp_low_revision_4_aws", "au-2"),
    ("fedramp_moderate_revision_4_aws", "au-2-a-d"),
    ("nist_800_53_revision_4_aws", "au_2"),
    ("nist_800_53_revision_5_aws", "au_12_a"),
    ("nist_800_53_revision_5_aws", "au_12_c"),
}


def _batch():
    return {check.id: check for check in CHECKS if check.evaluate.__module__ in MODULES}


def _native_cases(path, check_id):
    """Retained synthetic transport captures from the native producer tests."""
    rows = json.loads((ROOT / path).read_text())["cases"]
    selected = [row for row in rows if row["check_id"] == check_id]
    cases = {row["id"].split(":", 1)[1]: row for row in selected}
    assert len(cases) == len(selected)
    assert all(row["source_bound_receipt"]["synthetic_transport"] is True for row in selected)
    return cases


def test_all_real_batch_cases_have_truthful_verdicts_and_no_mutation():
    checks = _batch()

    for cid, check in checks.items():
        cases = CASES[cid]
        present = {name for name in ("pass", "fail") if name in cases}
        expected = ({"fail"} if cid in ONE_SIDED_FAIL else
                    {"pass"} if cid in ONE_SIDED_PASS else {"pass", "fail"})
        assert present == expected, cid
        for name, verdict in (("pass", "PASS"), ("fail", "FAIL"), ("unknown", "UNKNOWN"),
                              ("missing", "UNKNOWN"), ("malformed", "UNKNOWN")):
            if name not in cases:
                assert name in ("pass", "fail") and name not in expected
                continue
            original = cases[name]
            index = cases.get(name + "_index", cases.get("index", {}))
            before_data, before_index = deepcopy(original), deepcopy(index)
            if cid == "gcp_pci_bucket_157fb0c69361" and name == "pass":
                # The old local-only sample lacks the now-required native hierarchy.
                verdict = "UNKNOWN"
            if name in HISTORICAL_NATIVE_UNKNOWN.get(cid, ()):
                # Old local samples lack native relations or coverage. Verify
                # their precise UNKNOWN reason and current producer cases below.
                verdict = "UNKNOWN"
            if cid in {"gcp.identity.non_service_account_mfa", "gcp.identity.super_admin_recovery_group"} and name in {"pass", "fail"}:
                # Old Directory samples predate the independently verified
                # project/customer binding. They cannot now prove either verdict.
                verdict = "UNKNOWN"
            actual, evidence = check.evaluate(original, index)
            if cid in INCOMPLETE_NATIVE_CASES and name in HISTORICAL_NATIVE_UNKNOWN[cid]:
                assert evidence["reason"] == INCOMPLETE_NATIVE_CASES[cid]
            if cid == "gcp_logging_enumeration_alert" and name == "pass":
                assert evidence["reason"] == "missing fact: metricDescriptor"
            assert actual == verdict, (cid, name)
            assert original == before_data and index == before_index, cid
        denied = {"collection_status": "denied"}
        assert check.evaluate(denied, deepcopy(cases.get("index", {})))[0] == "UNKNOWN", cid


def test_current_native_captures_prove_historical_unknowns():
    checks = _batch()
    final_services = "tests/fixtures/gcp-final-services-native-successor-20261020.json"
    azure_verdicts = {"pass_native_declared_configuration": "PASS",
                      "fail_native_declared_configuration": "FAIL",
                      "unknown_child_denied": "UNKNOWN",
                      "unknown_native_default_service_tags": "UNKNOWN"}
    for cid in HISTORICAL_NATIVE_UNKNOWN:
        if cid == "azure.gap.compute_vm_remote_access_restricted_all_ports":
            native = json.loads((ROOT / "tests/fixtures/azure_storage_native_fixes_20261020.json").read_text())["cases"][cid]
            assert set(native) == set(azure_verdicts)
            for scenario, row in native.items():
                assert row["native_calls"] and row["source"].startswith("Actual AzureTransport JSON bytes")
                assert row["status"] == azure_verdicts[scenario]
                item, index = deepcopy(row["item"]), deepcopy(row["index"])
                before_item, before_index = deepcopy(item), deepcopy(index)
                assert checks[cid].evaluate(item, index)[0] == azure_verdicts[scenario], (cid, scenario)
                assert item == before_item and index == before_index
            continue
        path = ("tests/fixtures/gcp-alert-native-successor-20261020.json"
                if cid == "gcp_kms_key_destroy_alert" else final_services)
        native = _native_cases(path, cid)
        verdicts = ({"complete": "PASS", "absent": "FAIL", "denied": "UNKNOWN"}
                    if cid == "gcp_kms_key_destroy_alert" else
                    {"good": "PASS", "bad": "FAIL", "denied_field": "UNKNOWN"})
        assert set(native) == set(verdicts)
        for scenario, row in native.items():
            assert row["expected_status"] == verdicts[scenario]
            item, index = deepcopy(row["item"]), deepcopy(row["index"])
            before_item, before_index = deepcopy(item), deepcopy(index)
            assert checks[cid].evaluate(item, index)[0] == verdicts[scenario], (cid, scenario)
            assert item == before_item and index == before_index


def test_bucket_public_read_pass_requires_complete_inherited_evidence(monkeypatch):
    from tests.test_peaso_gcp_storage_acl_native import API, SCOPE
    from peaso.collectors import collect_live, gcp
    from tests.archived_check_contract import evaluate_snapshot, plan_collection
    cid = "gcp_pci_bucket_157fb0c69361"
    check = _batch()[cid]
    assert check.evaluate(deepcopy(CASES[cid]["pass"]), deepcopy(CASES[cid]["pass_index"]))[0] == "UNKNOWN"
    monkeypatch.setattr(gcp, "Credentials", lambda *a, **kw: None)
    connector = {"provider": "gcp", "scopes": [SCOPE], "options": {
        "resource_iam": False, "metrics_scopes": False, "include_inherited": True}}
    for mode, expected in (("complete", "PASS"), ("ancestor_public", "FAIL")):
        monkeypatch.setattr(gcp, "Transport", lambda *a, _mode=mode, **kw: API(_mode))
        snapshot = collect_live(connector, plan_collection({"connector": connector, "checks": [cid]}))
        findings = evaluate_snapshot(snapshot, checks=[cid], include_not_applicable=True)["findings"]
        assert [row["status"] for row in findings if row["check_id"] == cid] == [expected]
    native = _native_cases("tests/fixtures/gcp-native-review-behavior.json", cid)
    assert set(native) == {"complete", "ancestor_public", "acl_public_read", "denied_ancestry"}
    for scenario, verdict in (("complete", "PASS"), ("ancestor_public", "FAIL"),
                              ("acl_public_read", "FAIL"), ("denied_ancestry", "UNKNOWN")):
        row = native[scenario]
        receipt = row["source_bound_receipt"]
        assert receipt["collector"] == "peaso.collectors.gcp.GCPCollector.collect"
        assert receipt["read_only"] is True and receipt["requests"]
        assert row["expected_status"] == verdict
        item, index = deepcopy(row["item"]), deepcopy(row["index"])
        before_item, before_index = deepcopy(item), deepcopy(index)
        assert check.evaluate(item, index)[0] == verdict, (cid, scenario)
        assert item == before_item and index == before_index


def test_redshift_alias_equivalence_and_exact_compiler_refusal():
    _, signed = signed_proposals(LEDGER)
    spec = signed[REDSHIFT_PROPOSAL]
    native = {REDSHIFT_SURVIVOR: next(row for row in
              json.loads((ROOT / "peaso/rulepacks/native_catalog.json").read_text())["checks"]
              if row["id"] == REDSHIFT_SURVIVOR)}
    assert reviewed_equivalent_proposal(spec, *REDSHIFT_CONTROL, native) == REDSHIFT_SURVIVOR
    for value in (True, False, None):
        item = {"ClusterIdentifier": "rs1"}
        if value is not None:
            item["AllowVersionUpgrade"] = value
        from peaso.checks import evaluate_check
        expected = "UNKNOWN" if value is None else "PASS" if value else "FAIL"
        assert evaluate_check(REDSHIFT_PROPOSAL, item, {})[0] == expected
        assert evaluate_check(REDSHIFT_SURVIVOR, item, {})[0] == expected
    altered = dict(spec, predicate=spec["predicate"] + " changed")
    with pytest.raises(ValueError, match="duplicate proposal changed"):
        reviewed_equivalent_proposal(altered, *REDSHIFT_CONTROL, native)
    with pytest.raises(ValueError, match="duplicate proposal changed"):
        reviewed_equivalent_proposal(spec, "wrong.framework", REDSHIFT_CONTROL[1], native)
    with pytest.raises(ValueError, match="duplicate proposal changed"):
        reviewed_equivalent_proposal(spec, REDSHIFT_CONTROL[0], "wrong.requirement", native)
    with pytest.raises(ValueError, match="duplicate proposal changed"):
        reviewed_equivalent_proposal(spec, *REDSHIFT_CONTROL, {})
    with pytest.raises(ValueError, match="duplicate proposal changed"):
        reviewed_equivalent_proposal(spec, *REDSHIFT_CONTROL,
                                     {REDSHIFT_SURVIVOR: dict(native[REDSHIFT_SURVIVOR], type="s3_bucket")})


def test_redshift_alias_cli_selection_emits_one_canonical_finding(tmp_path):
    from peaso import cli
    from peaso.snapshot import make_snapshot
    scope = "111111111111/us-east-1"
    snapshot = make_snapshot("aws", [scope], [{"type": "redshift_cluster", "scope": scope,
        "service": "redshift", "status": "collected",
        "items": [{"ClusterIdentifier": "rs1", "AllowVersionUpgrade": False}]}])
    source = tmp_path / "snapshot.json"
    report = tmp_path / "report.json"
    source.write_text(json.dumps(snapshot))
    assert cli.main(["evaluate", str(source), "--categories", "hardening",
                     "--checks", REDSHIFT_PROPOSAL, REDSHIFT_SURVIVOR, "-o", str(report)]) == 0
    findings = json.loads(report.read_text())["findings"]
    selected = [row for row in findings if row["check_id"] == REDSHIFT_SURVIVOR]
    assert len(selected) == 1 and selected[0]["status"] == "FAIL"


def test_exact_cloudtrail_signed_alias_has_seven_links_and_no_duplicate_native():
    assert CLOUDTRAIL_PROPOSAL not in {check.id for check in CHECKS}
    assert resolve_check_id(CLOUDTRAIL_PROPOSAL) == CLOUDTRAIL_SURVIVOR
    _, signed = signed_proposals(LEDGER)
    spec = signed[CLOUDTRAIL_PROPOSAL]

    native = {CLOUDTRAIL_SURVIVOR: next(row for row in
              json.loads((ROOT / "peaso/rulepacks/native_catalog.json").read_text())["checks"]
              if row["id"] == CLOUDTRAIL_SURVIVOR)}
    assert (native[CLOUDTRAIL_SURVIVOR]["type"], native[CLOUDTRAIL_SURVIVOR]["target"]) == (
        "cloudtrail", "scope")
    for key in CLOUDTRAIL_CONTROL_KEYS:
        assert reviewed_equivalent_proposal(spec, *key, native) == CLOUDTRAIL_SURVIVOR
    with pytest.raises(ValueError, match="CloudTrail duplicate proposal changed"):
        reviewed_equivalent_proposal(dict(spec, predicate=spec["predicate"] + " changed"),
                                     *next(iter(CLOUDTRAIL_CONTROL_KEYS)), native)
    with pytest.raises(ValueError, match="CloudTrail duplicate proposal changed"):
        reviewed_equivalent_proposal(spec, "wrong.framework", "wrong.requirement", native)
    with pytest.raises(ValueError, match="CloudTrail duplicate proposal changed"):
        reviewed_equivalent_proposal(spec, *next(iter(CLOUDTRAIL_CONTROL_KEYS)),
                                     {CLOUDTRAIL_SURVIVOR: dict(native[CLOUDTRAIL_SURVIVOR], type="cloudtrail_trail")})



def test_cloudtrail_alias_regional_scope_and_missing_fact_truth_table():
    from peaso.checks import aws_gap_core, evaluate_check

    passing = deepcopy(aws_gap_core.TRAIL)
    cases = [
        ("home", aws_gap_core.idx(cloudtrail=[dict(passing, IsMultiRegionTrail=False)]), "PASS"),
        ("multiregion", aws_gap_core.idx(cloudtrail=[passing]), "PASS"),
        ("foreign_home", aws_gap_core.idx(cloudtrail=[dict(passing, IsMultiRegionTrail=False,
                                                          HomeRegion="eu-west-1")]), "FAIL"),
        ("read_only", aws_gap_core.idx(cloudtrail=[aws_gap_core.w(passing,
            EventSelectors__EventSelectors=[{"ReadWriteType": "ReadOnly", "IncludeManagementEvents": True}])]), "FAIL"),
        ("data_only", aws_gap_core.idx(cloudtrail=[aws_gap_core.w(passing,
            EventSelectors=aws_gap_core.ADV_DATA_NAMED)]), "FAIL"),
        ("not_logging", aws_gap_core.idx(cloudtrail=[aws_gap_core.w(passing,
            Status__IsLogging=False)]), "FAIL"),
        ("denied", aws_gap_core.idx(cloudtrail=None), "UNKNOWN"),
        ("missing_status", aws_gap_core.idx(cloudtrail=[aws_gap_core.w(passing,
            Status={"collection_status": "denied"})]), "UNKNOWN"),
        ("missing_selectors", aws_gap_core.idx(cloudtrail=[aws_gap_core.w(passing,
            EventSelectors={"collection_status": "denied"})]), "UNKNOWN"),
    ]
    partial = aws_gap_core.idx(cloudtrail=[passing])
    partial["collections"]["cloudtrail"][0]["status"] = "partial"
    cases.append(("partial", partial, "UNKNOWN"))
    for label, index, expected in cases:
        before = deepcopy(index)
        assert evaluate_check(CLOUDTRAIL_PROPOSAL, {}, index)[0] == expected, label
        assert evaluate_check(CLOUDTRAIL_SURVIVOR, {}, index)[0] == expected, label
        assert index == before, label


def test_cloudtrail_alias_cli_selection_emits_one_canonical_finding(tmp_path):
    from peaso import cli
    from peaso.checks import aws_gap_core
    from peaso.snapshot import make_snapshot

    scope = "123456789012/us-east-1"
    trail = aws_gap_core.w(aws_gap_core.TRAIL, Status__IsLogging=False)
    snapshot = make_snapshot("aws", [scope], [{"type": "cloudtrail", "scope": scope,
        "service": "cloudtrail", "status": "collected", "items": [trail]}])
    source = tmp_path / "snapshot.json"
    report = tmp_path / "report.json"
    source.write_text(json.dumps(snapshot))
    assert cli.main(["evaluate", str(source), "--categories", "hardening",
                     "--checks", CLOUDTRAIL_PROPOSAL, CLOUDTRAIL_SURVIVOR,
                     "-o", str(report)]) == 0
    findings = json.loads(report.read_text())["findings"]
    selected = [row for row in findings if row["check_id"] == CLOUDTRAIL_SURVIVOR]
    assert len(selected) == 1 and selected[0]["status"] == "FAIL"


def test_four_k8s_scope_checks_use_collected_kinds_but_require_external_policy():
    from peaso.engine import _selection
    from peaso.collectors import supported_types
    from peaso.checks.native_only import exclusions

    expected = {
        "k8s_cluster_version_at_least_oldest_supported": ("api_discovery", {"api_discovery"}, "cluster"),
        "k8s_cluster_version_supported": ("api_discovery", {"api_discovery"}, "cluster"),
        "k8s_privileged_utility_access": ("role", {"role", "clusterrole", "rolebinding", "clusterrolebinding", "pod"}, "cluster"),
        "k8s_persistentvolume_persistentvolumeclaims_pvc_permissions_do_not_allow_00af04b0":
            ("role", {"role", "clusterrole", "rolebinding", "clusterrolebinding", "namespace"}, "role,clusterrole"),
    }
    _, signed = signed_proposals(LEDGER)
    collected = set(supported_types("k8s"))
    by_id = {check.id: check for check in CHECKS}
    for cid, (kind, dependencies, source_kind) in expected.items():
        check = by_id[cid]
        assert check.kind == kind and set(check.dependencies) == dependencies and check.target == "scope"
        assert kind in collected and dependencies <= collected
        assert signed[cid]["resource_kind"] == source_kind
        assert cid in exclusions()
        with pytest.raises(ValueError, match="requires external policy or manual evidence"):
            _selection("k8s", None, [cid], None)


def test_exact_ecr_private_policy_fixture_semantics_and_no_mutation():
    cid = "aws_g6_ecr_public_repositories_absent"
    check = _batch()[cid]
    cases = CASES[cid]
    for name, verdict in (("pass", "PASS"), ("fail", "FAIL"),
                          ("unknown", "UNKNOWN"), ("missing", "UNKNOWN"),
                          ("malformed", "UNKNOWN")):
        item = deepcopy(cases[name])
        index = deepcopy(cases.get(name + "_index", cases["index"]))
        before = deepcopy((item, index))
        assert check.evaluate(item, index)[0] == verdict, name
        assert (item, index) == before, name

    def with_policy(item, policy):
        item = deepcopy(item)
        index = deepcopy(cases["pass_index"])
        item["Policy"] = policy
        index["collections"]["ecr_repository"][0]["items"] = [deepcopy(item)]
        index["ecr_repository"][0]["data"] = deepcopy(item)
        return check.evaluate(item, index)[0]

    wildcard = deepcopy(cases["fail"]["Policy"])
    wildcard["policyText"]["Statement"][0]["Effect"] = "Deny"
    assert with_policy(cases["fail"], wildcard) == "PASS"
    scoped = deepcopy(cases["fail"]["Policy"])
    scoped["policyText"]["Statement"][0]["Principal"]["AWS"] = "arn:aws:iam::111111111111:root"
    assert with_policy(cases["fail"], scoped) == "PASS"
    assert with_policy(cases["pass"], {"collection_status": "empty"}) == "UNKNOWN"
    assert with_policy(cases["pass"], {"collection_status": "denied"}) == "UNKNOWN"
    assert with_policy(cases["pass"], {"collection_status": "partial"}) == "UNKNOWN"
    assert with_policy(cases["pass"], {}) == "UNKNOWN"

    foreign = deepcopy(cases["pass"])
    foreign["repositoryArn"] = "arn:aws:ecr-public::111111111111:repository/private-one"
    index = deepcopy(cases["pass_index"])
    index["collections"]["ecr_repository"][0]["items"] = [deepcopy(foreign)]
    index["ecr_repository"][0]["data"] = deepcopy(foreign)
    assert check.evaluate(foreign, index)[0] == "UNKNOWN"




def test_exact_scoped_iam_corrected_fixture_semantics_and_no_mutation():
    from peaso.checks import aws_pci_iam_scoped_source_correction as correction
    cid = correction.CHECK_ID
    cases = CASES[cid]
    check = _batch()[cid]
    for name, verdict in (("pass", "PASS"), ("fail", "FAIL"),
                          ("unknown", "UNKNOWN"), ("missing", "UNKNOWN"),
                          ("malformed", "UNKNOWN")):
        item = deepcopy(cases[name])
        index = deepcopy(cases.get(name + "_index", cases["index"]))
        before = deepcopy((item, index))
        assert check.evaluate(item, index)[0] == verdict, name
        assert (item, index) == before, name
