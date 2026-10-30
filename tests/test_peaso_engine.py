"""Cross-provider shared-engine boundaries; provider-specific predicates live in check tests."""
import copy
import json
import subprocess
import sys
from pathlib import Path
import pytest
from peaso.snapshot import make_snapshot, resources, validate
from peaso.engine import evaluate_snapshot, collect_snapshot, run_scan, diff_reports, get_catalog
from peaso.reports import render_markdown
from peaso.demo import demo_snapshot
from peaso.engine import hydrate_frameworks


@pytest.mark.parametrize("provider,check,kind,item,expected", [
    ("aws", "aws.ec2.imdsv2", "instance", {"InstanceId": "i-1", "MetadataOptions": {"HttpTokens": "required", "HttpEndpoint": "enabled"}}, "PASS"),
    ("aws", "aws.ec2.imdsv2", "instance", {"InstanceId": "i-1", "MetadataOptions": {"HttpTokens": "optional", "HttpEndpoint": "enabled"}}, "FAIL"),
    ("gcp", "gcp.storage.uniform_access", "bucket", {"name": "b", "iamConfiguration": {"uniformBucketLevelAccess": {"enabled": True}}}, "PASS"),
    ("gcp", "gcp.storage.uniform_access", "bucket", {"name": "b", "iamConfiguration": {"uniformBucketLevelAccess": {"enabled": False}}}, "FAIL"),
    ("azure", "azure.storage.https_only", "storage_account", {"id": "a", "properties": {"supportsHttpsTrafficOnly": True}}, "PASS"),
    ("azure", "azure.storage.https_only", "storage_account", {"id": "a", "properties": {"supportsHttpsTrafficOnly": False}}, "FAIL"),
    ("k8s", "k8s.pod.no_privileged_containers", "pod", {"metadata": {"name": "p"}, "spec": {"containers": [{"name": "c", "securityContext": {"privileged": False}}]}}, "PASS"),
    ("k8s", "k8s.pod.no_privileged_containers", "pod", {"metadata": {"name": "p"}, "spec": {"containers": [{"name": "c", "securityContext": {"privileged": True}}]}}, "FAIL"),
])
def test_native_crossprovider_facts(provider, check, kind, item, expected):
    snapshot = make_snapshot(provider, ["scope"], [{"type": kind, "scope": "scope", "status": "collected", "items": [item]}])
    original = copy.deepcopy(snapshot)
    report = evaluate_snapshot(snapshot, categories=["hardening"], checks=[check])
    assert snapshot == original
    assert report["findings"][0]["status"] == expected
    assert "HackTricks Cloud Best Practices" in hydrate_frameworks(report)["findings"][0]["frameworks"]
    assert report["findings"][0]["resource_id"] == report["resources"][0]["id"]


@pytest.mark.parametrize("provider,check,kind", [("aws", "aws.ec2.imdsv2", "instance"), ("gcp", "gcp.storage.uniform_access", "bucket"), ("azure", "azure.storage.https_only", "storage_account"), ("k8s", "k8s.pod.no_privileged_containers", "pod")])
@pytest.mark.parametrize("status,expected", [("denied", "DENIED"), ("unknown", "UNKNOWN"), ("malformed", "UNKNOWN"), ("timeout", "UNKNOWN"), ("not_collected", "UNKNOWN"), ("empty", "EMPTY")])
def test_denied_unknown_empty_are_not_security_passes(provider, check, kind, status, expected):
    snapshot = make_snapshot(provider, ["scope"], [{"type": kind, "scope": "scope", "status": status, "items": []}])
    report = evaluate_snapshot(snapshot, categories=["hardening"], checks=[check])
    assert report["findings"][0]["status"] == expected
    if status != "empty":
        assert not report["stats"]["coverage_complete"]


@pytest.mark.parametrize("provider,check,kind", [("aws", "aws.ec2.imdsv2", "instance"), ("gcp", "gcp.storage.uniform_access", "bucket"), ("azure", "azure.storage.https_only", "storage_account"), ("k8s", "k8s.pod.no_privileged_containers", "pod")])
def test_missing_malformed_facts_are_unknown(provider, check, kind):
    for item in ({}, {"MetadataOptions": [], "iamConfiguration": [], "properties": [], "spec": []}):
        snapshot = make_snapshot(provider, ["scope"], [{"type": kind, "scope": "scope", "status": "collected", "items": [item]}])
        report = evaluate_snapshot(snapshot, categories=["hardening"], checks=[check])
        assert report["findings"][0]["status"] == "UNKNOWN"
        assert not report["stats"]["coverage_complete"]
    report = evaluate_snapshot(make_snapshot(provider, ["scope"], []), categories=["hardening"], checks=[check])
    assert report["coverage"][0]["status"] == "unknown"


def test_partial_keeps_facts_and_explicit_inventory_unknown():
    snapshot = make_snapshot("aws", ["scope"], [{"type": "instance", "scope": "scope", "status": "partial", "items": [{"InstanceId": "i", "MetadataOptions": {"HttpTokens": "required", "HttpEndpoint": "enabled"}}], "error": {"code": "page_limit"}}])
    report = evaluate_snapshot(snapshot, categories=["hardening"], checks=["aws.ec2.imdsv2"])
    assert {f["status"] for f in report["findings"]} == {"PASS", "UNKNOWN"}
    assert not report["stats"]["coverage_complete"]


def test_native_child_identifiers_and_cross_scope_collisions():
    snapshot = make_snapshot("aws", ["111/us-east-1", "222/us-east-1"], [{"type": "subnet", "scope": scope, "status": "collected", "items": [{"VpcId": "vpc-shared", "SubnetId": "subnet-a"}, {"VpcId": "vpc-shared", "SubnetId": "subnet-b"}]} for scope in ("111/us-east-1", "222/us-east-1")])
    inventory = resources(snapshot)
    assert len(inventory) == len({r["id"] for r in inventory}) == 4
    assert {r["native_id"] for r in inventory} == {"subnet-a", "subnet-b"}


def test_content_addressed_snapshot_rejects_tampering_and_returns_copies():
    snapshot = demo_snapshot("aws")
    sealed = validate(snapshot)
    sealed["metadata"]["tampered"] = True
    with pytest.raises(ValueError, match="digest mismatch"):
        validate(sealed)
    assert "tampered" not in snapshot["metadata"]
    snapshot["collections"].append(copy.deepcopy(snapshot["collections"][0]))
    snapshot.pop("snapshot_id")
    with pytest.raises(ValueError, match="duplicate collection"):
        validate(snapshot)


def test_selection_errors_and_framework_aliases():
    snapshot = demo_snapshot("aws")
    report = evaluate_snapshot(snapshot, categories=["hardening"], checks=["aws.ec2.imdsv2"], frameworks=["hacktricks"])
    assert report["stats"]["check_count"] == 1
    for kwargs in ({"categories": ["bogus"]}, {"checks": ["gcp.storage.uniform_access"]}, {"frameworks": ["bogus"]}):
        with pytest.raises(ValueError):
            evaluate_snapshot(snapshot, **kwargs)


def test_offline_scan_and_markdown_preserve_all_evidence():
    request = {"connector": {"provider": "aws", "options": {"demo": True}}, "categories": ["hardening"], "checks": ["aws.ec2.imdsv2"], "embed_snapshot": True}
    report = run_scan(request)
    assert report["snapshot"]["snapshot_id"] == report["snapshot_id"]
    markdown = render_markdown(report)
    assert "IMDSv2" in markdown and report["findings"][0]["resource_id"] in markdown
    assert "demo_permission_denied" in markdown
    assert report["resources"][0]["native_id"] in markdown
    assert collect_snapshot({"provider": "aws", "options": {"snapshot": report["snapshot"]}}) == report["snapshot"]


def test_markdown_handles_embedded_fences_and_table_markup():
    report = {"provider": "aws", "scopes": ["<script>|bad"], "stats": {}, "findings": [], "resources": [{"id": "id", "type": "x", "scope": "s", "data": {"value": "```\n# forged"}}], "coverage": []}
    markdown = render_markdown(report)
    assert "&lt;script&gt;\\|bad" in markdown
    assert "````json" in markdown


def test_diff_changes_evidence_and_ignores_collection_timestamp():
    snapshot = demo_snapshot("aws")
    before = evaluate_snapshot(snapshot, categories=["hardening"], checks=["aws.ec2.imdsv2"])
    after_snapshot = copy.deepcopy(snapshot)
    after_snapshot.pop("snapshot_id")
    after_snapshot["created_at"] = "2026-10-11T00:00:00+00:00"
    after = evaluate_snapshot(after_snapshot, categories=["hardening"], checks=["aws.ec2.imdsv2"])
    assert diff_reports(before, after)["stats"] == {"added": 0, "removed": 0, "changed": 0}
    instance = next(c for c in after_snapshot["collections"] if c["type"] == "instance")
    instance["items"][0]["MetadataOptions"]["HttpTokens"] = "optional"
    after = evaluate_snapshot(after_snapshot, categories=["hardening"], checks=["aws.ec2.imdsv2"])
    assert diff_reports(before, after)["changed"][0]["after"]["status"] == "FAIL"




def test_catalog_checks_have_reviewed_hacktricks_membership_and_provider():
    catalog = get_catalog()
    assert len(catalog["checks"]) >= 29
    for check in catalog["checks"]:
        from peaso.checks.hacktricks_scope import includes
        assert ("HackTricks Cloud Best Practices" in check["frameworks"]) == includes(check["id"])
        assert check["provider"] in catalog["providers"] + ["all"]


def test_selection_planner_limits_to_applicable_inventory():
    from peaso.engine import plan_collection
    request = {"connector": {"provider": "aws"}, "categories": ["hardening"], "checks": ["aws.ec2.imdsv2"]}
    assert plan_collection(request) == ["instance"]
    request["connector"]["options"] = {"inventories": ["bucket"]}
    assert plan_collection(request) == ["bucket"]
    with pytest.raises(ValueError):
        plan_collection({"connector": {"provider": "aws", "options": {"inventories": ["bogus"]}}})


def test_api_empty_selections_are_default_all():
    report = evaluate_snapshot(demo_snapshot("aws"), categories=[], checks=[], frameworks=[])
    assert report["findings"] and report["stats"]["check_count"] > 1
    assert report["graphs"]["network"]["nodes"]
    assert any(f["check_id"].startswith("analysis.") for f in report["findings"])


def test_analysis_ids_and_graph_links_survive_new_snapshot_timestamp():
    before_snapshot = demo_snapshot("aws")
    after_snapshot = copy.deepcopy(before_snapshot)
    after_snapshot.pop("snapshot_id")
    after_snapshot["created_at"] = "2026-10-11T00:00:00+00:00"
    before, after = [evaluate_snapshot(s) for s in (before_snapshot, after_snapshot)]
    assert {f["id"] for f in before["findings"]} == {f["id"] for f in after["findings"]}
    assert diff_reports(before, after)["stats"] == {"added": 0, "removed": 0, "changed": 0}
    resource_ids = {r["id"] for r in before["resources"]}
    for graph in before["graphs"].values():
        nodes = {n["id"] for n in graph["nodes"]}
        assert all(e["source"] in nodes and e["target"] in nodes for e in graph["edges"])
        assert all(n["resource_id"] in resource_ids for n in graph["nodes"] if n.get("resource_id") and n.get("evidence", {}).get("inventory_status") != "reference_only")


def test_explicit_inventory_override_missing_prerequisites_remains_unknown(monkeypatch):
    import peaso.collectors.aws
    from peaso.engine import plan_collection
    seen = []
    def collect(connector, requirements=None):
        seen.append(requirements)
        return make_snapshot("aws", ["scope"], [{"type": "bucket", "scope": "scope", "status": "empty", "items": []}])
    monkeypatch.setattr(peaso.collectors.aws, "collect", collect)
    request = {"connector": {"provider": "aws", "scopes": ["scope"], "options": {"inventories": ["bucket"]}}, "categories": ["hardening"], "checks": ["aws.ec2.imdsv2"], "embed_snapshot": True}
    report = run_scan(request)
    assert seen == [["bucket"]]
    assert report["findings"][0]["status"] == "UNKNOWN"
    assert not report["stats"]["coverage_complete"]
    assert report["snapshot"]["metadata"]["collection_plan"]["mode"] == "explicit_inventories"
    for bad in ("bucket", ["bogus"]):
        with pytest.raises(ValueError):
            plan_collection({"connector": {"provider": "aws", "options": {"inventories": bad}}})
    with pytest.raises(ValueError):
        plan_collection({"connector": {"provider": "aws", "options": {"collect_all": "yes"}}})


@pytest.mark.parametrize("provider,kind,item", [("aws", "bucket", {"Name": "shared"}), ("gcp", "bucket", {"name": "shared"}), ("azure", "storage_account", {"name": "shared"}), ("k8s", "pod", {"metadata": {"name": "shared", "namespace": "same"}})])
def test_native_same_name_cannot_alias_across_provider_scopes(provider, kind, item):
    snapshot = make_snapshot(provider, ["one", "two"], [{"type": kind, "scope": scope, "status": "collected", "items": [item]} for scope in ("one", "two")])
    inventory = resources(snapshot)
    assert len({r["id"] for r in inventory}) == 2
    assert len({r["native_id"] for r in inventory}) == 1


def test_offline_permission_classifier_never_downloads_missing_or_corrupt_rules(monkeypatch, tmp_path):
    from scripts import cloud_permission_risks as classifier
    monkeypatch.setattr(classifier, "_download_risk_rules", lambda provider: pytest.fail("offline classifier downloaded rules"))
    path = tmp_path / "aws.yaml"
    monkeypatch.setattr(classifier, "_bundled_rules_path", lambda provider: path)
    with pytest.raises(OSError):
        classifier.classify_permission("aws", "iam:PutRolePolicy", offline=True)
    for invalid in ("{}", "not: [valid", "version: 1\nprovider: gcp\n"):
        path.write_text(invalid)
        with pytest.raises(ValueError):
            classifier.classify_permission("aws", "iam:PutRolePolicy", offline=True)


def test_offline_permission_classifier_uses_the_same_audited_classification():
    from scripts.cloud_permission_risks import classify_permission
    for provider, permission in [("aws", "iam:PutRolePolicy"), ("gcp", "iam.serviceAccountKeys.create"), ("azure", "Microsoft.Authorization/roleAssignments/write")]:
        assert classify_permission(provider, permission, offline=True) == classify_permission(provider, permission) == "critical"


def test_exact_framework_version_filters_registered_checks_and_exposes_pending():
    catalog = get_catalog()
    implemented = next(row for row in catalog["framework_versions"] if row["provider"] == "aws" and row["native_check_ids"])
    report = evaluate_snapshot(demo_snapshot("aws"), frameworks=[implemented["id"]])
    assert report["findings"]
    assert {f["check_id"] for f in report["findings"] if f["status"] != "MANUAL"}.issubset(set(implemented["native_check_ids"]))
    assert report["framework_versions"][0]["id"] == implemented["id"]
    assert any(c["level"] == "framework" for c in report["coverage"])
    # Incremental ports can give every checklist at least one native predicate
    # while hundreds of its source references remain unimplemented.
    pending = next((row for row in catalog["framework_versions"] if row["provider"] == "aws" and row["pending_source_checks"]), None)
    if pending is None:
        assert not any(row["pending_source_checks"] for row in catalog["framework_versions"] if row["provider"] in ("aws", "gcp", "azure", "k8s"))
        pending = implemented
    report = evaluate_snapshot(demo_snapshot("aws"), frameworks=[pending["id"]])
    manual_ids = {m["id"] for m in report["manual_requirements"] if any(e.get("framework_id") == pending["id"] for e in m["frameworks"])}
    assert {f["check_id"] for f in report["findings"] if f["status"] != "MANUAL"}.issubset(set(pending["native_check_ids"]))
    assert {f["check_id"] for f in report["findings"] if f["status"] == "MANUAL"}.issubset(manual_ids)
    if pending is not implemented:
        assert not report["stats"]["coverage_complete"]
        assert any(c["level"] == "framework" and c["status"] in ("unknown", "partial") and c["pending_source_checks"] for c in report["coverage"])
    foreign = next(row for row in catalog["framework_versions"] if row["provider"] == "gcp")
    with pytest.raises(ValueError, match="framework"):
        evaluate_snapshot(demo_snapshot("aws"), frameworks=[foreign["id"]])
