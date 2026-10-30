"""Isolated contract tests for the five signed sw55 GCP checks."""
from __future__ import annotations

from copy import deepcopy

import pytest

from peaso.checks import CHECKS, evaluate_check
from peaso.checks import compliance_new_sw55 as sw55


@pytest.fixture(scope="module", autouse=True)
def remove_draft_registry_after_module():
    yield
    CHECKS[:] = [check for check in CHECKS if check.id not in sw55.SPECS]


def snapshot(scope, kind, row, *, policy=None, extra=None):
    collections = {}
    def add(resource_kind, values, status="collected"):
        collections[resource_kind] = [{"type": resource_kind, "scope": scope,
            "status": status if values else "empty", "items": values}]
    add(kind, [row])
    for resource_kind, values in (extra or {}).items():
        add(resource_kind, values)
    index = {"context": {"provider": "gcp", "scope": scope,
        "metadata": {"sw55_policy": {"scope": scope, "status": "collected", **(policy or {})}}},
        "collections": collections}
    for resource_kind, envelopes in collections.items():
        index[resource_kind] = [{"type": resource_kind, "scope": scope, "data": value}
            for value in envelopes[0]["items"]]
    return index


def run(check_id, row, index):
    return evaluate_check(check_id, row, index)[0]


def variants_unknown(check_id, row, index, dependent):
    partial = deepcopy(index)
    partial["collections"][dependent][0]["status"] = "partial"
    assert run(check_id, row, partial) == "UNKNOWN"
    missing = deepcopy(index)
    del missing["collections"][dependent]
    assert run(check_id, row, missing) == "UNKNOWN"
    foreign = deepcopy(index)
    foreign[dependent][0]["scope"] = "projects/foreign" if index["context"]["scope"] != "projects/foreign" else "projects/other"
    assert run(check_id, row, foreign) == "UNKNOWN"


def test_table_classification_pass_fail_unknown():
    key = "my-project.dataset.table"
    row = {"tableReference": {"projectId": "my-project", "datasetId": "dataset", "tableId": "table"},
        "_provenance": {"schema_full": True}, "schema": {"fields": [
            {"name": "customer", "fields": [{"name": "email", "policyTags": {"names": ["tags/pii"]}}]}]}}
    policy = {"required_classification": {key: {"customer.email": ["tags/pii"]}}}
    index = snapshot("projects/my-project", "bigquery_table", row, policy=policy)
    assert run("gcp.bigquery.table_classification_tags", row, index) == "PASS"
    bad = deepcopy(row)
    bad["schema"]["fields"][0]["fields"][0]["policyTags"]["names"] = []
    assert run("gcp.bigquery.table_classification_tags", bad, snapshot("projects/my-project", "bigquery_table", bad, policy=policy)) == "FAIL"
    assert run("gcp.bigquery.table_classification_tags", row, snapshot("projects/my-project", "bigquery_table", row)) == "UNKNOWN"
    unlisted = snapshot("projects/my-project", "bigquery_table", row, policy={"required_classification": {"my-project.other.table": {"x": ["tags/pii"]}}})
    assert run("gcp.bigquery.table_classification_tags", row, unlisted) == "UNKNOWN"
    malformed = deepcopy(row)
    malformed["schema"]["fields"] = "bad"
    assert run("gcp.bigquery.table_classification_tags", malformed, snapshot("projects/my-project", "bigquery_table", malformed, policy=policy)) == "UNKNOWN"
    variants_unknown("gcp.bigquery.table_classification_tags", row, index, "bigquery_table")


def test_folder_environment_pass_fail_unknown_not_applicable():
    scope = "organizations/123"
    folders = [
        {"name": "folders/10", "displayName": "prod", "parent": scope},
        {"name": "folders/11", "displayName": "restricted", "parent": "folders/10"}]
    project = {"name": "projects/sample", "parent": "folders/11"}
    policy = {"environment_labels": ["prod"], "sensitivity_labels": ["restricted"]}
    index = snapshot(scope, "folder", folders[0], policy=policy, extra={"project": [project]})
    index["collections"]["folder"][0]["items"] = folders
    index["folder"] = [{"type": "folder", "scope": scope, "data": f} for f in folders]
    check = "gcp.resourcemanager.folder_environment_structure"
    assert run(check, folders[0], index) == "PASS"
    failed = deepcopy(index)
    failed["project"][0]["data"]["parent"] = "folders/10"
    failed["collections"]["project"][0]["items"][0]["parent"] = "folders/10"
    assert run(check, folders[0], failed) == "FAIL"
    empty = deepcopy(index)
    empty["project"] = []
    empty["collections"]["project"][0].update(status="empty", items=[])
    assert run(check, folders[0], empty) == "NOT_APPLICABLE"
    broken = deepcopy(index)
    broken["folder"][1]["data"]["parent"] = "folders/999"
    broken["collections"]["folder"][0]["items"][1]["parent"] = "folders/999"
    assert run(check, folders[0], broken) == "UNKNOWN"
    no_labels = deepcopy(index)
    del no_labels["context"]["metadata"]["sw55_policy"]["sensitivity_labels"]
    assert run(check, folders[0], no_labels) == "UNKNOWN"
    variants_unknown(check, folders[0], index, "project")


def test_vpc_perimeter_pass_fail_unknown():
    scope = "projects/sample"
    row = {"name": "accessPolicies/10/servicePerimeters/p", "_representation": "full",
        "status": {"resources": ["projects/123"], "restrictedServices": ["bigquery.googleapis.com"]}}
    service = {"name": scope + "/services/bigquery.googleapis.com", "state": "ENABLED"}
    policy = {"project_id": "sample", "project_number": "123", "protected_project_numbers": ["123"],
        "supported_services": ["bigquery.googleapis.com"]}
    check = "gcp.network.vpc_service_controls_supported_services"
    index = snapshot(scope, "service_perimeter", row, policy=policy, extra={"service_usage": [service]})
    assert run(check, row, index) == "PASS"
    bad = deepcopy(row)
    bad["status"]["restrictedServices"] = []
    assert run(check, bad, snapshot(scope, "service_perimeter", bad, policy=policy, extra={"service_usage": [service]})) == "FAIL"
    no_project = deepcopy(row)
    no_project["status"]["resources"] = []
    assert run(check, no_project, snapshot(scope, "service_perimeter", no_project, policy=policy, extra={"service_usage": [service]})) == "FAIL"
    malformed = deepcopy(row)
    malformed["status"]["resources"] = "projects/123"
    assert run(check, malformed, snapshot(scope, "service_perimeter", malformed, policy=policy, extra={"service_usage": [service]})) == "UNKNOWN"
    variants_unknown(check, row, index, "service_usage")


def test_access_approval_pass_fail_unknown_not_applicable():
    scope = "projects/sample"
    row = {"name": scope + "/accessApprovalSettings"}
    event = {"name": "events/1", "timestamp": "2026-10-12T12:00:00Z", "serviceName": "bigquery.googleapis.com",
        "resourceName": "projects/sample", "principal": "google-support@example.com", "provider_access": True}
    approval = {"name": "projects/sample/approvalRequests/1", "requestedResourceName": "//bigquery.googleapis.com/projects/sample", "requestTime": "2026-10-12T10:00:00Z",
        "requestedExpiration": "2026-10-12T14:00:00Z", "approve": {"decisionTime": "2026-10-12T11:00:00Z"}}
    policy = {"consent_scopes": [{"serviceName": event["serviceName"], "resourceName": event["resourceName"]}],
        "log_coverage": {"status": "collected", "start": "2026-10-12T00:00:00Z", "end": "2026-10-13T00:00:00Z"}}
    check = "gcp_c5_access_approval"
    index = snapshot(scope, "access_approval_settings", row, policy=policy,
        extra={"access_approval_request": [approval], "provider_access_event": [event]})
    assert run(check, row, index) == "PASS"
    assert run(check, row, snapshot(scope, "access_approval_settings", row, policy=policy,
        extra={"access_approval_request": [], "provider_access_event": [event]})) == "FAIL"
    assert run(check, row, snapshot(scope, "access_approval_settings", row, policy=policy,
        extra={"access_approval_request": [], "provider_access_event": []})) == "NOT_APPLICABLE"
    unknown_policy = deepcopy(index)
    unknown_policy["context"]["metadata"]["sw55_policy"]["log_coverage"]["status"] = "partial"
    assert run(check, row, unknown_policy) == "UNKNOWN"
    malformed_event = deepcopy(event)
    malformed_event["timestamp"] = "no-time"
    assert run(check, row, snapshot(scope, "access_approval_settings", row, policy=policy,
        extra={"access_approval_request": [approval], "provider_access_event": [malformed_event]})) == "UNKNOWN"
    variants_unknown(check, row, index, "access_approval_request")


def test_scc_routes_pass_fail_unknown_not_applicable():
    scope = "organizations/123"
    row = {"name": scope}
    finding = {"name": scope + "/sources/1/findings/1", "state": "ACTIVE", "severity": "HIGH",
        "createTime": "2026-10-12T10:00:00Z"}
    config = {"name": scope + "/notificationConfigs/oncall",
        "filter": 'state = "ACTIVE" AND severity = "HIGH"',
        "pubsubTopic": "projects/alerts/topics/oncall"}
    policy = {"approved_on_call_topics": [config["pubsubTopic"]]}
    check = "gcp_logging_scc_findings_alert"
    index = snapshot(scope, "organization", row, policy=policy,
        extra={"scc_finding": [finding], "scc_notification_config": [config]})
    assert run(check, row, index) == "PASS"
    wrong = deepcopy(config)
    wrong["filter"] = 'severity = "CRITICAL"'
    assert run(check, row, snapshot(scope, "organization", row, policy=policy,
        extra={"scc_finding": [finding], "scc_notification_config": [wrong]})) == "FAIL"
    inactive = deepcopy(finding)
    inactive["state"] = "INACTIVE"
    assert run(check, row, snapshot(scope, "organization", row, policy=policy,
        extra={"scc_finding": [inactive], "scc_notification_config": [config]})) == "NOT_APPLICABLE"
    arbitrary = deepcopy(config)
    arbitrary["filter"] = 'category = "MALWARE"'
    assert run(check, row, snapshot(scope, "organization", row, policy=policy,
        extra={"scc_finding": [finding], "scc_notification_config": [arbitrary]})) == "UNKNOWN"
    malformed = deepcopy(finding)
    malformed["severity"] = 3
    assert run(check, row, snapshot(scope, "organization", row, policy=policy,
        extra={"scc_finding": [malformed], "scc_notification_config": [config]})) == "UNKNOWN"
    variants_unknown(check, row, index, "scc_finding")
