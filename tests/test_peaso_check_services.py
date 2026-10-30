"""Every registered check has a stable, reviewed service for service grouping."""
import pytest

from peaso.checks import CHECKS
from peaso.check_services import (ANALYSIS_KIND_SERVICES, _manifest,
                                  canonical_observed_service, finding_service,
                                  service_for, service_for_check)
from peaso.engine import _finding
from peaso.finding_groups import group_findings
from peaso.snapshot import resources


def test_every_registered_check_has_a_non_generic_service():
    manifest = _manifest()
    # Every registered target must have a reviewed label. The manifest also
    # retains dependency-only inventories and archived target labels.
    assert {(check.provider, check.kind) for check in CHECKS} <= {
        (provider, kind) for provider, kinds in manifest.items() for kind in kinds
    }
    for check in CHECKS:
        service = service_for_check(check.id, check.provider, check.kind)
        assert service and service not in {"azure", "aws", "gcp"}


def test_new_gcp_content_and_literal_kinds_group_with_their_source_service():
    # Source review: gcp.py dependent_jobs and the bounded content readers
    # name the product that supplied each observation. Composer DAG content
    # belongs to the Composer finding even when fetched from its GCS bucket.
    expected = {
        "app_engine_version_secret": "appengine", "appengine_deployment_source": "appengine",
        "artifact_image": "artifactregistry", "artifact_selected_file": "artifactregistry",
        "batch_job": "batch", "cloudbuild_artifact_source": "cloudbuild",
        "cloudbuild_build": "cloudbuild", "cloudbuild_log_source": "cloudbuild",
        "clouddeploy_release_source": "clouddeploy", "composer_dag_source": "composer",
        "dataflow_job": "dataflow", "dataform_selected_file": "dataform",
        "dataproc_job": "dataproc", "function_source_archive": "cloudfunctions",
        "gcs_selected_archive": "storage", "gcs_selected_object": "storage",
        "gke_workload_literal": "container", "log_secret_sample": "logging.googleapis.com",
        "source_repository_file": "sourcerepo", "workflow_source": "workflows",
    }
    assert len(expected) == 20
    for kind, service in expected.items():
        assert _manifest()["gcp"][kind] == service
        assert service_for("gcp", kind) == service


def test_manifest_covers_collector_services_and_all_kubernetes_kinds():
    from peaso.collectors.aws import SPECS
    from peaso.collectors.azure import ENDPOINTS, AUTHORIZATION, DIRECTORY, DIRECTORY_SINGLETONS
    from peaso.collectors.gcp import GCPCollector, SUPPORTED_TYPES
    from peaso.collectors.k8s import TYPES

    kinds = {(check.provider, check.kind) for check in CHECKS}
    assert all(service_for("k8s", kind) == "kubernetes" for kind in TYPES if ("k8s", kind) in kinds)
    aws_aliases = {"elbv2": "elasticloadbalancing", "elb": "elasticloadbalancing",
                   "apigatewayv2": "apigateway", "s3control": "s3", "wafv2": "waf",
                   "waf-regional": "waf", "redshift-serverless": "redshift", "bedrock-agent": "bedrock"}
    # These selected content kinds can read across account services;
    # SPECS names only the discovery fallback for each kind.
    account_content = {"configuration_selected_content",
                       "workload_referenced_source_content",
                       "build_deployment_referenced_source_content"}
    for kind, (service, *_) in SPECS.items():
        if ("aws", kind) in kinds:
            expected = "account" if kind in account_content else aws_aliases.get(service, service)
            assert service_for("aws", kind) == expected
    azure_sources = {**{kind: spec[0].split("/")[0] for kind, spec in ENDPOINTS.items()},
                     **{kind: "Microsoft.Authorization" for kind in AUTHORIZATION},
                     **{kind: "Microsoft.Graph" for kind in DIRECTORY},
                     **{kind: "Microsoft.Graph" for kind in DIRECTORY_SINGLETONS}}
    for kind, service in azure_sources.items():
        if ("azure", kind) in kinds:
            assert service_for("azure", kind) == service
    gcp_aliases = {"iam/cloudasset": "iam"}
    for scope in ("projects/a", "organizations/123", "folders/123"):
        collector = GCPCollector({"scopes": [scope], "auth": {}}, requirements=list(SUPPORTED_TYPES), transport=object())
        try:
            for kind, _, service, _ in collector.scope_jobs(scope):
                if ("gcp", kind) in kinds:
                    assert service_for("gcp", kind) == gcp_aliases.get(service, service)
        finally:
            collector.hydration_pool.shutdown(wait=False)


def test_resource_scope_and_archived_findings_use_check_service():
    checks = {check.id: check for check in CHECKS}
    bucket_check = next(check for check in CHECKS if check.provider == "aws" and check.kind == "bucket")
    storage_check = next(check for check in CHECKS if check.provider == "azure" and check.kind == "storage_container")
    for check, observed, expected in ((bucket_check, "bucket", "s3"),
                                      (storage_check, "azure", "Microsoft.Storage")):
        finding = _finding(check, check.provider, "scope", "inventory:" + check.kind,
                           observed, "EMPTY", {})
        assert finding["service"] == expected
        archived = dict(finding, service=observed)
        assert finding_service(archived) == expected
        assert group_findings([archived])[0]["service"] == expected
    scope_check = checks["azure.gap.monitor_log_profile_enabled_for_all_categories"]
    assert _finding(scope_check, "azure", "scope", "scope:scope", "subscription", "FAIL", {})["service"] == "Microsoft.Insights"
    assert service_for_check("aws.a.iam.password_policy_lowercase", "aws", "aws_account") == "iam"
    assert service_for_check("gcp.claude.logging.project_sink_all_entries", "gcp", "project") == "logging"
    assert service_for_check("gcp.htbp.orgpolicy.domain_restricted_sharing", "gcp", "project") == "orgpolicy"
    assert service_for_check("gcp.claude.project.no_api_keys", "gcp", "project") == "apikeys"


def test_collected_azure_child_is_labeled_from_its_target_kind():
    rows = resources({"provider": "azure", "collections": [{"type": "storage_container", "scope": "/subscriptions/sub1",
                      "service": "azure", "items": [{"id": "/subscriptions/sub1/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/a/blobServices/default/containers/c"}]}]})
    assert len(rows) == 1
    assert rows[0]["service"] == "Microsoft.Storage"
    assert service_for("k8s", "cluster") == "kubernetes"


def test_legacy_analysis_service_labels_follow_the_registered_resource_kinds():
    from peaso.analysis import REQUIRED_TYPES
    for provider, kinds in _manifest().items():
        for kind, expected in kinds.items():
            assert canonical_observed_service(provider, kind) == expected
        analysis_kinds = set(REQUIRED_TYPES[provider]["exposure"]) | set(REQUIRED_TYPES[provider]["network"])
        missing = analysis_kinds - set(kinds)
        if provider == "k8s":
            assert all(canonical_observed_service(provider, kind) == "kubernetes" for kind in missing)
        else:
            assert missing <= set(ANALYSIS_KIND_SERVICES[provider])
    for observed in ("s3_account_public_access_block", "bucket", "s3control", "s3_access_point"):
        assert finding_service({"provider": "aws", "check_id": "analysis.internet_exposure",
                                "service": observed}) == "s3"
    assert canonical_observed_service("aws", "lambda_function") == "lambda"
    assert canonical_observed_service("aws", "target_group") == "elasticloadbalancing"
    assert canonical_observed_service("gcp", "firewall_policy") == "compute"
    assert canonical_observed_service("azure", "vnet_peering") == "Microsoft.Network"
    assert canonical_observed_service("aws", "unknown_future_service") == "unknown_future_service"


@pytest.mark.parametrize("chunked", [False, True], ids=["inline", "chunked"])
def test_archived_report_service_filter_and_facet_use_corrected_service(tmp_path, chunked):
    from fastapi.testclient import TestClient
    from peaso.server import create_app
    from peaso.server.config import Settings
    from peaso.storage import SQLiteStore, FileArtifacts
    from peaso.storage.reports import publish_report
    from tests.test_peaso_api import TestIdentities

    store, artifacts = SQLiteStore(tmp_path / "state"), FileArtifacts(tmp_path / "artifacts")
    connector = store.add_connector("alice", {"provider": "aws", "name": "fixture"}, "encrypted")
    job = store.enqueue("alice", {"connector_id": connector["id"]})
    check = next(check for check in CHECKS if check.provider == "aws" and check.kind == "bucket")
    archived = _finding(check, "aws", "123456789012/global", "asset:bucket", "bucket", "FAIL", {})
    archived["category"] = "hardening"
    exposure = [dict(archived, id=f"exposure-{index}", category="exposure",
                     check_id="analysis.internet_exposure", service=service,
                     resource_id=f"asset:{index}", title=f"Exposure {index}")
                for index, service in enumerate(("s3_account_public_access_block", "s3control", "lambda_function"))]
    report = {"schema_version": "1.0", "snapshot_id": "fixture", "provider": "aws",
              "scopes": ["123456789012/global"], "created_at": "2026-10-19T00:00:00Z",
              "findings": [archived, *exposure], "coverage": [], "resources": [], "graphs": {},
              "stats": {"finding_count": 4, "by_status": {"FAIL": 4}, "by_severity": {"high": 4}}}
    reference = (publish_report(artifacts, "alice", job["id"], report) if chunked
                 else artifacts.put("alice", job["id"], "report", report))
    with store.transaction() as db:
        db.execute("UPDATE jobs SET status='completed',report=? WHERE id=?", (reference, job["id"]))
    app = create_app(Settings(state_dir=tmp_path / "settings", identity_dir=tmp_path / "identity"),
                     store=store, artifacts=artifacts, authenticator=TestIdentities())
    with TestClient(app, base_url="http://127.0.0.1:8000", headers={"Authorization": "Bearer alice"}) as client:
        selected = client.get(f"/api/scans/{job['id']}/findings", params={"service": "s3", "aggregation": "check"})
        assert selected.status_code == 200
        assert selected.json()["total"] == 3
        assert {item["service"] for item in selected.json()["items"]} == {"s3"}
        assert "s3" in selected.json()["facets"]["services"]
        all_exposure = client.get(f"/api/scans/{job['id']}/findings",
                                  params={"categories": "exposure", "aggregation": "check"}).json()
        assert [(group["service"], group["count"]) for group in all_exposure["service_groups"]] == [
            ("lambda", 1), ("s3", 2)]
