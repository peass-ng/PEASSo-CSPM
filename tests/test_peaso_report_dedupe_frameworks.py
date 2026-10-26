"""Report data regressions: cross-region duplicates, canonical framework labels, CIS version
consistency, populated framework_versions, the light catalog endpoint and the bulk-stream plan."""
import json

import pytest
from fastapi.testclient import TestClient

from peaso.checks import CHECKS, HACKTRICKS, Check
from peaso.demo import demo_snapshot
from peaso.engine import (CHECK_META_ENCODING, CHECK_META_FIELDS, compact_report, encode_check_meta, evaluate_snapshot,
                          expand_report, factor_check_meta, factor_frameworks,
                          finding_frameworks, hydrate_finding, hydrate_frameworks)
from peaso.snapshot import make_snapshot

ACCOUNT = "111111111111"
REGIONS = ["eu-west-1", "us-east-1", "us-west-2"]
SCOPES = [f"{ACCOUNT}/{region}" for region in REGIONS]
TRAIL_ARN = f"arn:aws:cloudtrail:eu-west-1:{ACCOUNT}:trail/org"
CIS6 = "cis_6.0_aws"
CIS6_NAME = "CIS Amazon Web Services Foundations Benchmark v6.0.0"


def _validation(item, index):
    return ("PASS" if item.get("LogFileValidationEnabled") else "FAIL"), {"validation": item.get("LogFileValidationEnabled")}


def _registry_scan(item, index):
    return ("PASS" if item.get("ScanType") == "ENHANCED" else "FAIL"), {"scan_type": item.get("ScanType")}


TRAIL = Check("aws.test.trail_validation", "aws", "hardening", "cloudtrail", "Trail validation", "medium", "AU-9", "Enable validation", _validation)
REGISTRY = Check("aws.test.registry_scan", "aws", "hardening", "ecr_registry_scanning_configuration", "Registry scanning", "low", "RA-5", "Enable scanning", _registry_scan)
LAMBDA = Check("aws.test.lambda_url", "aws", "hardening", "lambda_function", "Function URL auth", "high", "AC-3", "Require auth", _validation)


def _snapshot(trail_validation=(True, True, True)):
    collections = []
    for scope, valid in zip(SCOPES, trail_validation):
        region = scope.split("/")[1]
        # A multi-region trail is listed by every region (shadow copies) under its home-region ARN.
        collections.append({"type": "cloudtrail", "scope": scope, "service": "cloudtrail", "status": "collected", "account_id": ACCOUNT, "global": False,
                            "items": [{"id": TRAIL_ARN, "TrailARN": TRAIL_ARN, "Name": "org", "HomeRegion": "eu-west-1", "IsMultiRegionTrail": True, "Region": region, "LogFileValidationEnabled": valid}]})
        # A per-region setting whose native id (the account id) repeats in every region.
        collections.append({"type": "ecr_registry_scanning_configuration", "scope": scope, "service": "ecr", "status": "collected",
                            "items": [{"_resource_id": ACCOUNT, "ScanType": "ENHANCED" if region == "us-east-1" else "BASIC"}]})
        collections.append({"type": "lambda_function", "scope": scope, "service": "lambda", "status": "empty", "items": []})
    return make_snapshot("aws", SCOPES, collections, created_at="2026-01-01T00:00:00+00:00")


@pytest.fixture
def registry(monkeypatch):
    monkeypatch.setattr("peaso.engine._registry", lambda: [TRAIL, REGISTRY, LAMBDA])


def _rows(report, check_id):
    return [f for f in report["findings"] if f["check_id"] == check_id]


def test_multi_region_trail_is_one_finding_in_its_home_region(registry):
    report = evaluate_snapshot(_snapshot(), categories=["hardening"], checks=[TRAIL.id])
    rows = _rows(report, TRAIL.id)
    assert len(rows) == 1
    assert rows[0]["scope"] == f"{ACCOUNT}/eu-west-1" and rows[0]["native_resource_id"] == TRAIL_ARN
    assert rows[0]["evidence"]["observed_in_scopes"] == SCOPES
    pairs = [(f["check_id"], f.get("native_resource_id") or f["resource_id"]) for f in report["findings"]]
    assert len(pairs) == len(set(pairs))
    # Coverage remains per scope: every region was evaluated.
    assert sorted(c["scope"] for c in report["coverage"] if c.get("check_id") == TRAIL.id) == SCOPES


def test_same_arn_with_regionally_different_results_is_not_merged(registry):
    report = evaluate_snapshot(_snapshot(trail_validation=(True, False, True)), categories=["hardening"], checks=[TRAIL.id])
    rows = _rows(report, TRAIL.id)
    assert sorted(f["status"] for f in rows) == ["FAIL", "PASS", "PASS"]
    assert all("observed_in_scopes" not in f["evidence"] for f in rows)


def test_per_region_setting_without_arn_stays_per_region(registry):
    report = evaluate_snapshot(_snapshot(), categories=["hardening"], checks=[REGISTRY.id])
    rows = _rows(report, REGISTRY.id)
    assert sorted(f["scope"] for f in rows) == SCOPES
    assert {f["scope"]: f["status"] for f in rows}[f"{ACCOUNT}/us-east-1"] == "PASS"


def test_empty_inventory_rows_aggregate_per_provider_and_check(registry):
    report = evaluate_snapshot(_snapshot(), categories=["hardening"], checks=[LAMBDA.id])
    rows = _rows(report, LAMBDA.id)
    assert len(rows) == 1
    assert rows[0]["resource_id"] == "inventory:lambda_function" and rows[0]["status"] == "EMPTY"
    assert rows[0]["scope"] == ACCOUNT
    assert rows[0]["evidence"]["scopes"] == SCOPES and rows[0]["evidence"]["scope_count"] == 3
    assert report["stats"]["by_status"] == {"EMPTY": 1}
    # The finding_aggregates (collapsed) view keeps every scope and the same status count.
    collapsed = evaluate_snapshot(_snapshot(), categories=["hardening"], checks=[LAMBDA.id], include_not_applicable=False)
    assert not _rows(collapsed, LAMBDA.id)
    (aggregate,) = [row for row in collapsed["finding_aggregates"] if row["check_id"] == LAMBDA.id]
    assert aggregate["count"] == 1 and sorted(aggregate["scopes"]) == SCOPES
    assert collapsed["stats"]["by_status"] == report["stats"]["by_status"]


def test_deduplicated_findings_survive_schema_round_trip(registry):
    snapshot = _snapshot()
    report = evaluate_snapshot(snapshot, categories=["hardening"])
    assert report["schema_version"] == "1.1"
    expanded = expand_report(report, snapshot)
    assert expanded["findings"] == hydrate_frameworks(report)["findings"]
    assert all("frameworks" in f for f in expanded["findings"]) and "check_frameworks" not in expanded
    compacted = compact_report(expanded)
    assert compacted["findings"] == report["findings"] and compacted["check_frameworks"] == report["check_frameworks"]


def test_global_iam_inventory_is_not_a_per_region_analysis_gap():
    from peaso.analysis import REQUIRED_TYPES
    collections = [{"type": kind, "scope": SCOPES[0], "service": "iam", "status": "empty", "items": [], "global": True, "account_id": ACCOUNT}
                   for kind in REQUIRED_TYPES["aws"]["least_privilege"]]
    snapshot = make_snapshot("aws", SCOPES, collections, created_at="2026-01-01T00:00:00+00:00")
    report = evaluate_snapshot(snapshot, categories=["least_privilege"])
    assert not [f for f in report["findings"] if f["check_id"] == "analysis.coverage" and f["resource_id"] == "inventory"]
    missing = make_snapshot("aws", SCOPES, [], created_at="2026-01-01T00:00:00+00:00")
    gaps = [f for f in evaluate_snapshot(missing, categories=["least_privilege"])["findings"] if f["check_id"] == "analysis.coverage"]
    assert sorted(f["scope"] for f in gaps) == SCOPES


def test_framework_labels_use_one_canonical_name_per_version():
    from peaso.checks.catalog import framework_display_names, framework_ids_for
    display = framework_display_names()
    canonical = set(display.values()) | {HACKTRICKS}
    report = hydrate_frameworks(evaluate_snapshot(demo_snapshot("aws")))
    labels = {label for f in report["findings"] for label in f["frameworks"]}
    assert labels <= canonical
    assert "AWS-Foundational-Security-Best-Practices" not in labels and "CIS" not in labels
    for check in CHECKS[:400]:
        assert set(check.frameworks) <= canonical
        assert {display[fid] for fid in framework_ids_for(check.id)} <= set(check.frameworks)
    # Family slugs, display names and ids remain valid filters.
    by_slug = hydrate_frameworks(evaluate_snapshot(demo_snapshot("aws"), frameworks=["AWS-Foundational-Security-Best-Practices"]))
    by_name = evaluate_snapshot(demo_snapshot("aws"), frameworks=["AWS Foundational Security Best Practices"])
    assert by_slug["findings"] and {f["id"] for f in by_slug["findings"]} == {f["id"] for f in by_name["findings"]}
    assert all("AWS Foundational Security Best Practices" in f["frameworks"] for f in by_slug["findings"] if f["status"] != "MANUAL")
    assert evaluate_snapshot(demo_snapshot("aws"), frameworks=["nist_800_53"])["findings"]


def test_version_filter_findings_all_carry_the_version_label():
    report = hydrate_frameworks(evaluate_snapshot(demo_snapshot("aws"), frameworks=[CIS6]))
    assert report["findings"]
    assert all(CIS6_NAME in f["frameworks"] for f in report["findings"])
    assert [row["id"] for row in report["framework_versions"]] == [CIS6]


def test_unfiltered_report_populates_framework_versions():
    report = hydrate_frameworks(evaluate_snapshot(demo_snapshot("aws"), include_not_applicable=False))
    ids = {row["id"] for row in report["framework_versions"]}
    assert CIS6 in ids and all(row["provider"] in ("aws", "all") for row in report["framework_versions"])
    labels = {label for f in report["findings"] for label in f["frameworks"]}
    names = {row["name"] for row in report["framework_versions"]}
    assert labels - {HACKTRICKS} <= names
    assert not any(c["level"] == "framework" for c in report["coverage"])


def _client(tmp_path):
    from peaso.server import create_app
    from peaso.server.config import Settings
    token = "catalog-fixture-token-0123456789abcdef"
    settings = Settings(state_dir=tmp_path / "state", identity_dir=tmp_path / "identity", local_token=token)
    client = TestClient(create_app(settings), base_url="http://127.0.0.1:8000")
    return client, token


def test_light_frameworks_endpoint_and_catalog_etag(tmp_path, monkeypatch):
    import peaso.engine as engine
    client, token = _client(tmp_path)
    with client:
        assert client.get("/api/catalog/frameworks").status_code == 401
        client.headers["Authorization"] = "Bearer " + token
        def forbidden():
            pytest.fail("light endpoint must not build the full catalog")
        monkeypatch.setattr(engine, "get_catalog", forbidden)
        light = client.get("/api/catalog/frameworks")
        assert light.status_code == 200 and light.json()["view"] == "frameworks"
        body = light.json()
        assert len(light.content) < 512 * 1024
        assert body["framework_versions"] and all("native_check_ids" not in row for row in body["framework_versions"])
        assert any(row["id"] == CIS6 and row["name"] == CIS6_NAME and row["supported_native_checks"] for row in body["framework_versions"])
        assert any(row["name"] == CIS6_NAME and CIS6 in row["framework_ids"] for row in body["frameworks"])
        etag = light.headers["etag"]
        assert "no-cache" in light.headers["cache-control"] and "no-store" not in light.headers["cache-control"]
        assert client.get("/api/catalog/frameworks", headers={"If-None-Match": etag}).status_code == 304
        monkeypatch.undo()
        full = client.get("/api/catalog")
        assert full.status_code == 200 and full.headers["etag"] and "private" in full.headers["cache-control"]
        cached = client.get("/api/catalog", headers={"If-None-Match": full.headers["etag"]})
        assert cached.status_code == 304 and not cached.content
        # Other API responses stay uncacheable.
        assert client.get("/api/me").headers["cache-control"] == "no-store"


def test_server_version_and_family_filters_return_labelled_findings(tmp_path):
    from peaso.server import create_app
    from peaso.server.config import Settings
    from peaso.storage import SQLiteStore, FileArtifacts
    from tests.test_peaso_api_large import Identities, completed_job
    settings = Settings(state_dir=tmp_path / "state", identity_dir=tmp_path / "identity", local_token="filter-test-token-0123456789")
    store, artifacts = SQLiteStore(settings.state_dir), FileArtifacts(settings.state_dir / "artifacts")
    report = evaluate_snapshot(demo_snapshot("aws"), include_not_applicable=False)
    ident, _ = completed_job(store, artifacts, report)
    with TestClient(create_app(settings, store=store, artifacts=artifacts, authenticator=Identities()), base_url="http://127.0.0.1") as client:
        version = client.get(f"/api/scans/{ident}/findings?framework={CIS6}&limit=500").json()
        assert version["total"] and all(CIS6_NAME in item["frameworks"] for item in version["items"])
        assert version["total"] == sum(CIS6_NAME in finding_frameworks(f, report["check_frameworks"]) for f in report["findings"])
        by_label = client.get(f"/api/scans/{ident}/findings", params={"framework": CIS6_NAME, "limit": 500}).json()
        assert by_label["total"] == version["total"]
        family = client.get(f"/api/scans/{ident}/findings?framework=CIS&limit=500").json()
        assert family["total"] >= version["total"]
        assert "CIS" not in version["facets"]["frameworks"]


def test_validate_selectors_accepts_aliases_without_building_full_catalog(monkeypatch):
    import peaso.engine as engine
    from fastapi import HTTPException
    from peaso.server.validation import validate_selectors
    monkeypatch.setattr(engine, "get_catalog", lambda: pytest.fail("selector validation built the full catalog"))
    validate_selectors({"frameworks": [CIS6, CIS6_NAME, "CIS", "nist", "AWS-Foundational-Security-Best-Practices"], "checks": ["aws.ec2.imdsv2"]}, "aws")
    with pytest.raises(HTTPException):
        validate_selectors({"frameworks": ["no-such-framework"]}, "aws")


def test_default_plan_skips_bulk_streams_but_keeps_every_dependency():
    from peaso.analysis import REQUIRED_TYPES
    from peaso.collectors import supported_types
    from peaso.engine import BULK_STREAM_TYPES, plan_collection
    assert {"activity_log", "directory_audit"} <= BULK_STREAM_TYPES["azure"] and "activity" in BULK_STREAM_TYPES["gcp"]
    for provider in ("aws", "azure", "gcp", "k8s"):
        from peaso.checks.native_only import automated_inventory_types
        available = set(automated_inventory_types(provider, supported_types(provider)))
        plan = set(plan_collection({"connector": {"provider": provider}}))
        assert not plan & BULK_STREAM_TYPES[provider]
        dependencies = {kind for check in CHECKS if check.provider == provider for kind in check.dependencies}
        dependencies |= {kind for kinds in REQUIRED_TYPES.get(provider, {}).values() for kind in kinds}
        # Audit predicates remain UNKNOWN until the caller explicitly requests
        # their event streams; registering them does not widen default collection.
        assert (dependencies & available) - BULK_STREAM_TYPES[provider] <= plan
        # AWS-owned managed-policy library collection remains explicit opt-in.
        assert plan == available - BULK_STREAM_TYPES[provider] - ({"iam_managed_policy"} if provider == "aws" else set())
    explicit = plan_collection({"connector": {"provider": "azure", "options": {"inventories": ["activity_log", "directory_audit"]}}})
    assert explicit == ["activity_log", "directory_audit"]
    assert "activity_log" in plan_collection({"connector": {"provider": "azure", "options": {"collect_all": True}}})


@pytest.mark.parametrize("provider", ["aws", "azure", "gcp", "k8s"])
def test_default_and_privesc_plans_cover_every_privesc_required_type(provider):
    from peaso.analysis import REQUIRED_TYPES, privesc_required_types
    from peaso.analysis.privesc_requirements import privesc_collection_types
    from peaso.collectors import supported_types
    from peaso.engine import BULK_STREAM_TYPES, plan_collection
    from peaso.checks.native_only import automated_inventory_types
    available = set(automated_inventory_types(provider, supported_types(provider)))
    required = set(privesc_required_types(provider))
    # The privesc model's own reads are part of the requirement, not only the hand-written floor.
    assert set(REQUIRED_TYPES[provider]["privesc"]) <= required
    assert privesc_collection_types(provider) & available <= required
    assert required & available
    default_plan = set(plan_collection({"connector": {"provider": provider}}))
    privesc_plan = set(plan_collection({"connector": {"provider": provider}, "categories": ["privesc"]}))
    assert required & available <= default_plan
    assert required & available <= privesc_plan
    assert not privesc_plan & BULK_STREAM_TYPES[provider]


def test_aws_privesc_requirements_include_workload_and_guardrail_inventories():
    from peaso.analysis import privesc_required_types
    required = set(privesc_required_types("aws"))
    assert {"ssm_managed_instance", "ecs_cluster", "ecs_task_definition", "rcp_policy", "scp_policy"} <= required
    # Read through WORKLOAD_HOSTS.items() loops in the AWS model, not the hand-written floor.
    assert {"codebuild_project", "rds_instance"} <= required


def test_privesc_requirement_scanner_follows_loops_tables_and_declarations():
    from peaso.analysis.privesc_requirements import scan_source
    source = '''
REQUIRED_COLLECTIONS = ("declared_type",)
HOSTS = {"table_key": "host_kind"}
FACTS = {"fact": "fact_type"}
def load(snap):
    for scope, item in items(snap, "direct_type"):
        pass
    for kind in ("loop_a", "loop_b"):
        inventory_status(snap, kind)
    for kind, host in (("pair_type", "x"), *HOSTS.items()):
        items(snap, kind)
    for fact, collection in FACTS.items():
        inventory_status(snap, collection)
    chosen = {"a": "mapped_type"}["a"]
    collections(snap, chosen)
    self.require_collections(("req_a", "req_b"), {})
'''
    found = scan_source(source)
    assert {"declared_type", "direct_type", "loop_a", "loop_b", "pair_type", "table_key", "fact_type", "mapped_type", "req_a", "req_b"} <= found
    assert "host_kind" not in found and "x" not in found


def _home_only(item, index):
    if item.get("Region") != item.get("HomeRegion"):
        return "NOT_APPLICABLE", {"reason": "shadow copy"}
    return ("PASS" if item.get("LogFileValidationEnabled") else "FAIL"), {"validation": item.get("LogFileValidationEnabled")}


HOME_ONLY = Check("aws.test.trail_home_only", "aws", "hardening", "cloudtrail", "Home trail", "medium", "AU-9", "Enable", _home_only)


def test_home_region_result_absorbs_not_applicable_shadow_copies(monkeypatch):
    monkeypatch.setattr("peaso.engine._registry", lambda: [HOME_ONLY])
    report = evaluate_snapshot(_snapshot(trail_validation=(False, True, True)), categories=["hardening"])
    rows = _rows(report, HOME_ONLY.id)
    assert [(f["scope"], f["status"]) for f in rows] == [(f"{ACCOUNT}/eu-west-1", "FAIL")]
    assert rows[0]["evidence"]["observed_in_scopes"] == SCOPES


def test_not_collected_inventory_rows_merge_but_distinct_statuses_do_not(registry):
    missing = make_snapshot("aws", SCOPES, [], created_at="2026-01-01T00:00:00+00:00")
    report = evaluate_snapshot(missing, categories=["hardening"], checks=[LAMBDA.id])
    (row,) = _rows(report, LAMBDA.id)
    assert row["status"] == "UNKNOWN" and row["scope"] == ACCOUNT and row["evidence"]["scopes"] == SCOPES
    assert row["evidence"]["collection_status"] == "not_collected"
    assert sorted(c["scope"] for c in report["coverage"] if c.get("check_id") == LAMBDA.id) == SCOPES
    mixed = make_snapshot("aws", SCOPES, [
        {"type": "lambda_function", "scope": SCOPES[0], "service": "lambda", "status": "denied", "items": [], "error": {"code": "AccessDenied"}},
        {"type": "lambda_function", "scope": SCOPES[1], "service": "lambda", "status": "empty", "items": []},
        {"type": "lambda_function", "scope": SCOPES[2], "service": "lambda", "status": "empty", "items": []}], created_at="2026-01-01T00:00:00+00:00")
    rows = sorted(_rows(evaluate_snapshot(mixed, categories=["hardening"], checks=[LAMBDA.id]), LAMBDA.id), key=lambda f: f["status"])
    assert [(f["status"], f["scope"]) for f in rows] == [("DENIED", SCOPES[0]), ("EMPTY", ACCOUNT)]
    assert rows[1]["evidence"]["scopes"] == SCOPES[1:]


def test_labels_are_stored_once_per_check_and_round_trip_losslessly():
    snapshot = demo_snapshot("aws")
    report = evaluate_snapshot(snapshot, include_not_applicable=False)
    assert report["check_frameworks"]
    assert {f["check_id"] for f in report["findings"]} <= set(report["check_frameworks"])
    hydrated = hydrate_frameworks(report)
    from peaso.checks.hacktricks_scope import includes
    assert all(isinstance(f["frameworks"], list) and (HACKTRICKS in f["frameworks"]) == includes(f["check_id"]) for f in hydrated["findings"])
    # compact(expand(r)) == r, and hydrate does not modify its input.
    assert compact_report(expand_report(report, snapshot)) == report
    assert not any("frameworks" in f for f in report["findings"])
    assert len(json.dumps(report["findings"])) < len(json.dumps(hydrated["findings"]))


def test_findings_with_non_default_labels_keep_an_explicit_list():
    findings = [{"check_id": "c", "frameworks": ["A", "B"]}, {"check_id": "c", "frameworks": ["A", "B"]},
                {"check_id": "c", "frameworks": ["A"]}, {"check_id": "d", "frameworks": []}]
    labels = factor_frameworks(findings)
    assert labels == {"c": ["A", "B"], "d": []}
    assert findings == [{"check_id": "c"}, {"check_id": "c"}, {"check_id": "c", "frameworks": ["A"]}, {"check_id": "d"}]
    assert [finding_frameworks(f, labels) for f in findings] == [["A", "B"], ["A", "B"], ["A"], []]
    # Older reports without check_frameworks are served as they are.
    legacy = {"findings": [{"check_id": "c", "frameworks": ["A"]}]}
    assert hydrate_frameworks(legacy) is legacy


def test_api_hydrates_labels_and_filters_through_check_frameworks(tmp_path):
    from peaso.server import create_app
    from peaso.server.config import Settings
    from peaso.storage import SQLiteStore, FileArtifacts
    from tests.test_peaso_api_large import Identities, completed_job
    settings = Settings(state_dir=tmp_path / "state", identity_dir=tmp_path / "identity", local_token="filter-test-token-0123456789")
    store, artifacts = SQLiteStore(settings.state_dir), FileArtifacts(settings.state_dir / "artifacts")
    report = evaluate_snapshot(demo_snapshot("aws"), include_not_applicable=False)
    # One finding with its own (non-default) labels, e.g. a manual requirement.
    override = next(f for f in report["findings"] if f["check_id"] != report["findings"][0]["check_id"])
    override["frameworks"] = [HACKTRICKS, "Only This Finding"]
    ident, bundle = completed_job(store, artifacts, report)
    # Stored chunks and the index carry labels only where a finding overrides its check.
    assert bundle["check_frameworks"] == report["check_frameworks"] and "check_frameworks" not in bundle["summary"]
    for chunk in bundle["finding_chunks"]:
        for reference in (chunk["reference"], chunk["index_reference"]):
            assert [f["id"] for f in artifacts.get("alice", reference)["items"] if "frameworks" in f] in ([], [override["id"]])
    with TestClient(create_app(settings, store=store, artifacts=artifacts, authenticator=Identities()), base_url="http://127.0.0.1") as client:
        page = client.get(f"/api/scans/{ident}/findings?limit=500").json()
        assert page["total"] == len(report["findings"])
        assert all(item["frameworks"] == finding_frameworks(f, report["check_frameworks"])
                   for item in page["items"] for f in report["findings"] if f["id"] == item["id"])
        assert "Only This Finding" in page["facets"]["frameworks"] and CIS6_NAME in page["facets"]["frameworks"]
        only = client.get(f"/api/scans/{ident}/findings", params={"framework": "Only This Finding"}).json()
        assert [item["id"] for item in only["items"]] == [override["id"]]
        cis = client.get(f"/api/scans/{ident}/findings?framework={CIS6}&limit=500").json()
        assert cis["total"] == sum(CIS6_NAME in finding_frameworks(f, report["check_frameworks"]) for f in report["findings"])
        assert override["id"] not in {item["id"] for item in cis["items"]}
        assert all(CIS6_NAME in item["frameworks"] for item in cis["items"])
        detail = client.get(f"/api/scans/{ident}/findings/{report['findings'][0]['id']}").json()
        assert detail["frameworks"] == report["check_frameworks"][report["findings"][0]["check_id"]]
        summary = client.get(f"/api/scans/{ident}/summary")
        assert "check_frameworks" not in summary.json()
        # The polled summary keeps framework version metadata but not catalog-sized ID lists.
        assert report["framework_versions"] and any(row.get("native_check_ids") for row in report["framework_versions"])
        assert [row["id"] for row in summary.json()["framework_versions"]] == [row["id"] for row in report["framework_versions"]]
        assert all("native_check_ids" not in row for row in summary.json()["framework_versions"])
        assert len(summary.content) < 100_000


def test_per_check_fields_keep_only_overrides_and_hydrate_losslessly():
    findings = [{"check_id": "c", "title": "T", "severity": "high", "category": "hardening", "service": "s3", "remediation": "R"},
                {"check_id": "c", "title": "T", "severity": "low", "category": "hardening", "service": "s3", "remediation": "R"},
                {"check_id": "c", "title": "T", "severity": "high", "category": "hardening", "service": "s3", "remediation": "R"},
                # "remediation" is missing on one finding of d, so it is not factored (hydration never adds a field).
                {"check_id": "d", "title": "D", "severity": {"score": 3}, "remediation": "X"}, {"check_id": "d", "title": "D", "severity": "info"}]
    original = json.loads(json.dumps(findings))
    meta = factor_check_meta(findings)
    assert meta == {"c": {"title": "T", "severity": "high", "category": "hardening", "service": "s3", "remediation": "R"},
                    "d": {"title": "D", "severity": "info"}}
    assert findings == [{"check_id": "c"}, {"check_id": "c", "severity": "low"}, {"check_id": "c"},
                        {"check_id": "d", "severity": {"score": 3}, "remediation": "X"}, {"check_id": "d"}]
    assert [hydrate_finding(f, None, meta) for f in findings] == original
    # The legacy (pre-check_meta) report is served unchanged.
    legacy = {"findings": original}
    assert hydrate_frameworks(legacy) is legacy


def test_check_meta_round_trips_through_expand_compact_and_diff():
    from peaso.engine import diff_reports
    from peaso.reports import render_markdown
    snapshot = demo_snapshot("aws")
    native_before = json.dumps(snapshot, sort_keys=True)
    report = evaluate_snapshot(snapshot, include_not_applicable=False)
    assert json.dumps(snapshot, sort_keys=True) == native_before
    assert report["check_meta_encoding"] == CHECK_META_ENCODING
    assert report["check_meta"] and {f["check_id"] for f in report["findings"]} <= set(report["check_meta"])
    hydrated = hydrate_frameworks(report)
    assert "check_meta" not in hydrated and "check_meta" not in expand_report(report, snapshot)
    assert all(all(field in f for field in ("title", "severity", "category", "service", "remediation")) for f in hydrated["findings"])
    # Factoring the hydrated findings again gives back the stored report exactly.
    assert compact_report(expand_report(report, snapshot)) == report
    refactored = [dict(f) for f in hydrated["findings"]]
    factor_frameworks(refactored)
    assert encode_check_meta(factor_check_meta(refactored), report["remediation_templates"]) == report["check_meta"]
    assert refactored == report["findings"]
    # Severity breakdown and per-finding fields are the same as before factoring.
    assert report["stats"]["by_severity"] == dict(__import__("collections").Counter(f["severity"] for f in hydrated["findings"] if f["status"] == "FAIL"))
    assert diff_reports(report, hydrated)["stats"] == {"added": 0, "removed": 0, "changed": 0}
    markdown = render_markdown(report)
    first = hydrated["findings"][0]
    assert f"### {first['status']}: {first['title']}" in markdown and "- Severity: " + first["severity"] in markdown
    assert len(json.dumps(report["findings"])) < len(json.dumps(hydrated["findings"]))


def test_archived_check_meta_encoding_preserves_legacy_absence_and_explicit_overrides():
    legacy = {"check_meta": {"c": {"description": "Archived condition"}},
              "remediation_templates": {"c": {"summary": "Archived action"}},
              "findings": [{"check_id": "c"}]}
    old = hydrate_frameworks(legacy)["findings"][0]
    assert old["description"] == "Archived condition"
    assert "rationale" not in old and "remediation" not in old
    encoded = dict(legacy, check_meta_encoding=dict(CHECK_META_ENCODING),
                   check_meta={"c": {"description": "Archived condition", "_derived": "rm"}},
                   findings=[{"check_id": "c"}, {"check_id": "c", "remediation": "Resource-specific action"}])
    first, second = hydrate_frameworks(encoded)["findings"]
    assert first["rationale"] == "Archived condition" and first["remediation"] == "Archived action"
    assert second["rationale"] == "Archived condition" and second["remediation"] == "Resource-specific action"
    assert "_derived" not in first and "_derived" not in second
    distinct = dict(encoded, check_meta={"c": {"description": "Archived condition", "rationale": "Distinct risk",
                                               "remediation": "Distinct reviewed action"}})
    value = hydrate_frameworks(distinct)["findings"][0]
    assert value["rationale"] == "Distinct risk" and value["remediation"] == "Distinct reviewed action"
    assert encoded["findings"][0] == {"check_id": "c"}, "hydration must not mutate stored findings"


def test_api_hydrates_per_check_fields_for_filters_facets_summary_and_detail(tmp_path):
    from collections import Counter
    from peaso.server import create_app
    from peaso.server.config import Settings
    from peaso.storage import SQLiteStore, FileArtifacts
    from tests.test_peaso_api_large import Identities, completed_job
    settings = Settings(state_dir=tmp_path / "state", identity_dir=tmp_path / "identity", local_token="meta-test-token-0123456789")
    store, artifacts = SQLiteStore(settings.state_dir), FileArtifacts(settings.state_dir / "artifacts")
    report = evaluate_snapshot(demo_snapshot("aws"), include_not_applicable=False)
    from peaso.remediation import template
    override = next(f for f in report['findings'] if template(f['check_id'],'aws') is not None)
    override["severity"] = "critical" if report["check_meta"][override["check_id"]]["severity"] != "critical" else "info"
    full = {f["id"]: f for f in hydrate_frameworks(report)["findings"]}
    ident, bundle = completed_job(store, artifacts, report)
    assert bundle["check_meta"] == report["check_meta"] and "check_meta" not in bundle["summary"]
    assert bundle["summary"]["stats"]["by_category"] == dict(Counter(f["category"] for f in full.values()))
    stored = [f for chunk in bundle["finding_chunks"] for f in artifacts.get("alice", chunk["index_reference"])["items"]]
    assert {f["id"] for f in stored if "severity" in f} == {override["id"]} and not any("title" in f for f in stored)
    with TestClient(create_app(settings, store=store, artifacts=artifacts, authenticator=Identities()), base_url="http://127.0.0.1") as client:
        page = client.get(f"/api/scans/{ident}/findings?limit=500").json()
        assert page["total"] == len(full)
        for item in page["items"]:
            assert {field: item.get(field) for field in CHECK_META_FIELDS} == {field: full[item["id"]].get(field) for field in CHECK_META_FIELDS}
        assert page["facets"]["services"] == sorted({f["service"] for f in full.values()})
        for severity in {f["severity"] for f in full.values()}:
            rows = client.get(f"/api/scans/{ident}/findings", params={"severity": severity, "limit": 500}).json()
            assert rows["total"] == sum(f["severity"] == severity for f in full.values())
        rows = client.get(f"/api/scans/{ident}/findings", params={"categories": "hardening", "limit": 500}).json()
        assert rows["total"] == sum(f["category"] == "hardening" for f in full.values())
        title = full[report["findings"][1]["id"]]["title"]
        assert client.get(f"/api/scans/{ident}/findings", params={"search": title, "limit": 500}).json()["total"] >= 1
        detail = client.get(f"/api/scans/{ident}/findings/{override['id']}").json()
        assert detail["guidance_refresh"] == {"version":"archived-finding-presentation-v1", "status":"current_text", "basis":"matching_archived_criteria", "allow_summary":True}
        assert detail["evidence_summary_format"] == "natural-language-v2"
        assert {k: v for k, v in detail.items() if k not in {"runtime", "remediation_details", "guidance_refresh", "evidence_summary", "evidence_summary_format"}} == full[override["id"]]
        assert isinstance(detail.get("evidence_summary"), str) and detail["evidence_summary"]
        from peaso.remediation import template
        expected = bundle["remediation_templates"][override["check_id"]]
        assert template(override["check_id"], override["provider"])["review_status"] == "approved"
        assert detail["remediation_details"]["summary"] == expected["summary"]
        assert detail["remediation_details"]["steps"] == expected["steps"]
        assert detail["remediation_details"]["references"] == expected["references"]
        assert "check_meta" not in client.get(f"/api/scans/{ident}/summary").json()
        client.headers["Authorization"] = "Bearer bob"
        assert client.get(f"/api/scans/{ident}/findings/{override['id']}").status_code == 404
