"""Signed App Engine version count semantics through the production snapshot engine."""
from __future__ import annotations

from peaso.checks import evaluate_check
from peaso.checks import compliance_new_gcp_appengine  # noqa: F401
from peaso.checks.facts import MemoIndex
from tests.archived_check_contract import evaluate_snapshot
from peaso.snapshot import make_snapshot
from peaso.checks import CHECKS, evaluate_check


CHECK_ID = "gcp.appengine.service_version_count"
SERVICE = "apps/p-one/services/default"
MASK = "versions(id,name,servingStatus,env,handlers(securityLevel)),nextPageToken"


def _snapshot(statuses=("SERVING", "STOPPED"), *, installed_max=2, serving_max=1,
              service_status="collected", version_status="collected", field_mask=MASK,
              project_scopes=("projects/p-one",), include_maxima=True, version_rows=None,
              service_rows=None):
    versions = [{"id": f"v{number}", "name": f"{SERVICE}/versions/v{number}",
                 "serviceName": SERVICE, "_field_mask": field_mask,
                 **({"servingStatus": state} if state is not None else {})}
                for number, state in enumerate(statuses, 1)]
    versions = versions if version_rows is None else version_rows
    if version_status in {"empty", "denied", "unknown", "malformed", "timeout", "not_collected"}:
        versions = []
    policy = {"status": "collected", "project_scopes": list(project_scopes)}
    if include_maxima:
        policy.update(appengine_max_installed_versions=installed_max,
                      appengine_max_serving_versions=serving_max)
    return make_snapshot("gcp", ["projects/p-one"], [
        {"type": "app_engine_service", "scope": "projects/p-one", "service": "appengine",
         "status": service_status, "items": [{"id": "default", "name": SERVICE,
             "_field_mask": "services(id,name),nextPageToken"}] if service_rows is None else service_rows},
        {"type": "app_engine_version", "scope": "projects/p-one", "service": "appengine",
         "status": version_status, "items": versions},
    ], metadata={"appengine_version_policy": policy}, created_at="2026-10-12T00:00:00+00:00")


def _statuses(snapshot):
    report = evaluate_snapshot(snapshot, categories=["hardening"], checks=[CHECK_ID])
    findings = [finding for finding in report["findings"] if finding["check_id"] == CHECK_ID]
    assert findings
    return [finding["status"] for finding in findings]


def _outcome(snapshot):
    statuses = _statuses(snapshot)
    assert len(statuses) == 1
    return statuses[0]


def test_complete_counts_pass_fail_and_documented_omission_default():
    assert _outcome(_snapshot()) == "PASS"
    assert _outcome(_snapshot(installed_max=1)) == "FAIL"
    assert _outcome(_snapshot(serving_max=0)) == "FAIL"
    assert _outcome(_snapshot((None,), installed_max=1, serving_max=0)) == "FAIL"
    assert _outcome(_snapshot((), installed_max=0, serving_max=0)) == "PASS"


def test_missing_owner_policy_partial_inventory_and_projection_are_unknown():
    assert _outcome(_snapshot(include_maxima=False)) == "UNKNOWN"
    assert _outcome(_snapshot(project_scopes=("projects/other",))) == "UNKNOWN"
    assert set(_statuses(_snapshot(service_status="partial"))) == {"UNKNOWN"}
    assert set(_statuses(_snapshot(version_status="denied"))) == {"UNKNOWN"}
    assert _outcome(_snapshot(field_mask="versions(id,name),nextPageToken")) == "UNKNOWN"
    assert _outcome(_snapshot(("SERVING_STATUS_UNSPECIFIED",))) == "UNKNOWN"


def test_duplicate_foreign_and_detached_version_sources_are_unknown():
    base = {"id": "v1", "name": SERVICE + "/versions/v1", "serviceName": SERVICE,
            "_field_mask": MASK, "servingStatus": "SERVING"}
    assert _outcome(_snapshot(version_rows=[{**base, "_resource_id": "one"},
                                           {**base, "_resource_id": "two"}])) == "UNKNOWN"
    assert _outcome(_snapshot(version_rows=[{**base, "serviceName": "apps/other/services/default"}])) == "UNKNOWN"
    assert _outcome(_snapshot(version_rows=[{**base, "serviceName": "apps/p-one/services/detached",
                                                    "name": "apps/p-one/services/detached/versions/v1"}])) == "UNKNOWN"
    assert _outcome(_snapshot(service_rows=[{"id": "default", "name": "apps/other/services/default",
                                                 "_field_mask": "services(id,name),nextPageToken"}])) == "UNKNOWN"


def test_many_services_build_counts_once_per_immutable_scope_index(monkeypatch):
    services, versions = [], []
    for number in range(80):
        name = f"apps/p-one/services/s{number}"
        services.append({"id": f"s{number}", "name": name,
                         "_field_mask": "services(id,name),nextPageToken"})
        versions.append({"id": "v1", "name": name + "/versions/v1", "serviceName": name,
                         "_field_mask": MASK, "servingStatus": "SERVING"})
    index = MemoIndex({"context": {"scope": "projects/p-one", "metadata": {
        "appengine_version_policy": {"status": "collected", "project_scopes": ["projects/p-one"],
            "appengine_max_installed_versions": 1, "appengine_max_serving_versions": 1}}},
        "collections": {kind: [{"status": "collected"}] for kind in ("app_engine_service", "app_engine_version")},
        "app_engine_service": [{"data": row} for row in services],
        "app_engine_version": [{"data": row} for row in versions]})
    original = compliance_new_gcp_appengine.complete_items
    calls = []
    def tracked(index, kind):
        calls.append(kind)
        return original(index, kind)
    monkeypatch.setattr(compliance_new_gcp_appengine, "complete_items", tracked)
    assert all(evaluate_check(CHECK_ID, service, index)[0] == "PASS" for service in services)
    assert calls == ["app_engine_service", "app_engine_version"]
