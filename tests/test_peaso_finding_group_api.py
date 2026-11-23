"""Live and archived report shapes group before pagination, with member-level filters."""
from copy import deepcopy
import json

import pytest
from fastapi.testclient import TestClient

from peaso.server import create_app
from peaso.server.config import Settings
from peaso.storage import SQLiteStore, FileArtifacts
from peaso.storage.reports import publish_report
from peaso.finding_groups import group_id
from tests.test_peaso_api import TestIdentities


def fixture_report():
    rows = []
    for number in range(125):
        region = ("us-east-1", "eu-north-1")[number % 2]
        rows.append(dict(id=f"member-{number:04d}", provider="aws", category="hardening", check_id="fixture.retention",
            finding_type="logging",
            title="Log retention", service="logs", severity="medium", status="FAIL" if number < 120 else "PASS", scope="123456789012/" + region,
            region=region, resource_id=f"stable-{number}", native_resource_id=f"arn:aws:logs:{region}:123456789012:log-group:log-{number}", resource_name=f"log-{number}",
            frameworks=["Reviewed"], evidence={"retention_days": 7 if number < 120 else 365},
            evidence_summary=f"log-{number} retains logs for {7 if number < 120 else 365} days.", remediation="Set retention to 365 days."))
    rows.append(dict(rows[0], id="guard-1", finding_type="threat_detection", check_id="fixture.guardduty", title="GuardDuty", service="guardduty", resource_id="scope:123456789012/us-east-1"))
    return dict(schema_version="1.0", snapshot_id="fixture", provider="aws", scopes=["123456789012/us-east-1", "123456789012/eu-north-1"], created_at="2026-10-19T00:00:00Z",
        findings=rows, coverage=[], resources=[], graphs={}, stats={"finding_count": 126, "by_status": {"FAIL": 121, "PASS": 5}, "by_severity": {"medium": 121}})


@pytest.fixture(params=[False, True], ids=["inline-old-report", "chunked-bundle"])
def live(request, tmp_path):
    store, artifacts = SQLiteStore(tmp_path / "state"), FileArtifacts(tmp_path / "artifacts")
    connector = store.add_connector("alice", {"provider": "aws", "name": "fixture"}, "encrypted")
    job = store.enqueue("alice", {"connector_id": connector["id"]})
    report = fixture_report()
    reference = publish_report(artifacts, "alice", job["id"], report) if request.param else artifacts.put("alice", job["id"], "report", report)
    with store.transaction() as db:
        db.execute("UPDATE jobs SET status='completed',report=? WHERE id=?", (reference, job["id"]))
    app = create_app(Settings(state_dir=tmp_path / "settings", identity_dir=tmp_path / "identity"), store=store, artifacts=artifacts, authenticator=TestIdentities())
    with TestClient(app, base_url="http://127.0.0.1:8000", headers={"Authorization": "Bearer alice"}) as client:
        yield client, job["id"], report


def test_one_card_per_check_before_pagination_and_legacy_observations_are_retained(live):
    client, scan, report = live
    path = f"/api/scans/{scan}/findings"
    response = client.get(path, params={"aggregation": "check", "limit": 1})
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["total"] == 2 and len(data["items"]) == 1 and data["next_offset"] == 1
    second = client.get(path, params={"aggregation": "check", "limit": 1, "offset": 1}).json()
    assert second["total"] == 2 and second["next_offset"] is None
    assert data["items"][0]["check_id"] != second["items"][0]["check_id"]
    assert client.get(path).json()["total"] == 126


def test_service_groups_cover_all_filtered_check_cards_before_pagination(live):
    client, scan, _ = live
    path = f"/api/scans/{scan}/findings"
    first = client.get(path, params={"aggregation": "check", "group_by": "service", "limit": 1}).json()
    assert first["total"] == 2 and len(first["items"]) == 1
    assert first["service_groups"] == [
        {"service": "guardduty", "count": 1, "status_counts": {"FAIL": 1}},
        {"service": "logs", "count": 1, "status_counts": {"FAIL": 1}},
    ]
    selected = client.get(path, params={"aggregation": "check", "group_by": "service", "service": "logs", "limit": 1}).json()
    assert selected["service_groups"] == [{"service": "logs", "count": 1, "status_counts": {"FAIL": 1}}]
    passed = client.get(path, params={"aggregation": "check", "group_by": "service", "status": "PASS", "limit": 1}).json()
    assert passed["service_groups"] == [{"service": "logs", "count": 1, "status_counts": {"PASS": 1}}]


def test_type_groups_count_all_checks_before_paging_and_filter_member_evidence(live):
    client, scan, _ = live
    path = f"/api/scans/{scan}/findings"
    response = client.get(path, params={"aggregation": "check", "group_by": "finding_type", "limit": 1})
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["total"] == 2 and len(data["items"]) == 1
    assert data["type_groups"] == [
        {"finding_type": "logging", "label": "Logging", "count": 1, "status_counts": {"FAIL": 1}},
        {"finding_type": "threat_detection", "label": "Threat detection", "count": 1, "status_counts": {"FAIL": 1}},
    ]
    filtered = client.get(path, params={"aggregation": "check", "group_by": "finding_type", "finding_type": "logging", "status": "PASS"}).json()
    assert filtered["total"] == 1 and filtered["items"][0]["finding_type"] == "logging"
    assert filtered["items"][0]["member_filters"] == {"status": "PASS", "finding_type": "logging"}
    item = filtered["items"][0]
    members = client.get(f"/api/scans/{scan}/finding-groups/{item['id']}", params=item["member_filters"]).json()
    assert members["members_total"] == 5
    assert all(member["status"] == "PASS" for member in members["members"])


def test_raw_type_filter_and_unknown_archived_ids(live):
    client, scan, _ = live
    path = f"/api/scans/{scan}/findings"
    assert client.get(path, params={"finding_type": "logging"}).json()["total"] == 125
    assert client.get(path, params={"finding_type": "unknown"}).json()["total"] == 0


def test_status_filter_counts_cover_all_grouped_checks_and_survive_selection(live):
    client, scan, _ = live
    path = f"/api/scans/{scan}/findings"
    first = client.get(path, params={"aggregation": "check", "categories": "hardening", "limit": 1}).json()
    assert first["total"] == 2 and first["status_filter_total"] == 2
    assert first["status_filter_counts"] == {"FAIL": 2, "PASS": 1, "UNKNOWN,MANUAL": 0,
                                             "DENIED": 0, "NOT_APPLICABLE,EMPTY": 0}
    passed = client.get(path, params={"aggregation": "check", "categories": "hardening", "status": "PASS", "limit": 1}).json()
    assert passed["total"] == 1 and passed["status_filter_total"] == 2
    assert passed["status_filter_counts"] == first["status_filter_counts"]
    logs = client.get(path, params={"aggregation": "check", "service": "logs", "status": "PASS"}).json()
    assert logs["status_filter_total"] == 1
    assert logs["status_filter_counts"]["FAIL"] == logs["status_filter_counts"]["PASS"] == 1
    raw = client.get(path, params={"aggregation": "none", "limit": 1}).json()
    assert raw["status_filter_total"] == 126
    assert raw["status_filter_counts"]["FAIL"] == 121
    assert raw["status_filter_counts"]["PASS"] == 5


@pytest.mark.parametrize("chunked", [False, True], ids=["inline-old-report", "chunked-bundle"])
def test_internet_exposure_assets_do_not_become_one_mislabeled_service_card(tmp_path, chunked):
    store, artifacts = SQLiteStore(tmp_path / "state"), FileArtifacts(tmp_path / "artifacts")
    connector = store.add_connector("alice", {"provider": "aws", "name": "fixture"}, "encrypted")
    job = store.enqueue("alice", {"connector_id": connector["id"]})
    report = fixture_report()
    base = report["findings"][0]
    report["findings"] = []
    for number, service, title, kind in [
        (1, "apigateway", "Internet access to an API endpoint", "api"),
        (2, "s3", "Public stored-data access", "data_share"),
        (3, "lambda", "Internet access to a Lambda URL", "function_url"),
    ]:
        item = deepcopy(base)
        item.update(id=f"exposure-{number}", category="exposure", check_id="analysis.internet_exposure",
                    service=service, title=title, resource_id=f"asset-{number}", native_resource_id=f"asset-{number}",
                    evidence={"exposure_kind": kind}, evidence_summary=f"{service} observation")
        report["findings"].append(item)
    report["stats"] = {"finding_count": 3, "by_status": {"FAIL": 3}}
    reference = publish_report(artifacts, "alice", job["id"], report) if chunked else artifacts.put("alice", job["id"], "report", report)
    with store.transaction() as db:
        db.execute("UPDATE jobs SET status='completed',report=? WHERE id=?", (reference, job["id"]))
    app = create_app(Settings(state_dir=tmp_path / "settings", identity_dir=tmp_path / "identity"), store=store,
                     artifacts=artifacts, authenticator=TestIdentities())
    with TestClient(app, base_url="http://127.0.0.1:8000", headers={"Authorization": "Bearer alice"}) as client:
        path = f"/api/scans/{job['id']}/findings"
        data = client.get(path, params={"aggregation": "check", "categories": "exposure", "limit": 1}).json()
        assert data["total"] == data["status_filter_total"] == 3
        assert data["status_filter_counts"]["FAIL"] == 3
        assert [(group["service"], group["count"]) for group in data["service_groups"]] == [
            ("apigateway", 1), ("lambda", 1), ("s3", 1)]
        selected = client.get(path, params={"aggregation": "check", "service": "s3"}).json()
        assert selected["total"] == 1
        assert selected["items"][0]["title"] == "Public stored-data access"
        assert selected["items"][0]["service"] == "s3"
        assert not selected["items"][0].get("grouped")
        assert client.get(f"/api/scans/{job['id']}/finding-groups/{group_id('aws', 'analysis.internet_exposure')}").status_code == 404
        assert client.get(f"/api/scans/{job['id']}/summary?aggregation=check").json()["finding_count"] == 3



@pytest.mark.parametrize("chunked", [False, True], ids=["inline-old-report", "chunked-bundle"])
def test_exposed_container_findings_are_grouped_by_service_with_all_assets(tmp_path, chunked):
    store, artifacts = SQLiteStore(tmp_path / "state"), FileArtifacts(tmp_path / "artifacts")
    connector = store.add_connector("alice", {"provider": "aws", "name": "fixture"}, "encrypted")
    job = store.enqueue("alice", {"connector_id": connector["id"]})
    report = fixture_report()
    check = "analysis.exposed_container_cves"
    report["findings"] = [
        dict(report["findings"][0], id=f"{service}-{number}", check_id=check, category="exposure",
             service=service, resource_id=f"{service}-{number}", native_resource_id=f"{service}-{number}",
             resource_name=f"{service}-{number}", evidence={"container": f"{service}-container-{number}"})
        for service in ("ec2", "ecs", "lambda") for number in (1, 2)
    ]
    report["stats"] = {"finding_count": 6, "by_status": {"FAIL": 6}}
    reference = publish_report(artifacts, "alice", job["id"], report) if chunked else artifacts.put("alice", job["id"], "report", report)
    with store.transaction() as db:
        db.execute("UPDATE jobs SET status='completed',report=? WHERE id=?", (reference, job["id"]))
    app = create_app(Settings(state_dir=tmp_path / "settings", identity_dir=tmp_path / "identity"),
                     store=store, artifacts=artifacts, authenticator=TestIdentities())
    with TestClient(app, base_url="http://127.0.0.1", headers={"Authorization": "Bearer alice"}) as client:
        base = f"/api/scans/{job['id']}"
        query = {"aggregation": "check", "categories": "exposure", "status": "FAIL"}
        result = client.get(base + "/findings", params=query)
        assert result.status_code == 200, result.text
        data = result.json()
        assert data["total"] == data["status_filter_counts"]["FAIL"] == data["status_filter_total"] == 3
        assert [(entry["service"], entry["count"]) for entry in data["service_groups"]] == [
            ("ec2", 1), ("ecs", 1), ("lambda", 1)]
        assert len({item["id"] for item in data["items"]}) == 3
        for card in data["items"]:
            service = card["service"]
            assert card["title"].endswith(f"({service})")
            assert card["affected_asset_count"] == 2
            assert "2 affected assets" in card["evidence_summary"]
            path = base + "/finding-groups/" + card["id"]
            detail = client.get(path, params={"search": card["title"]})
            assert detail.status_code == 200, detail.text
            group = detail.json()
            assert group["title"] == card["title"]
            assert {member["native_resource_id"] for member in group["members"]} == {f"{service}-1", f"{service}-2"}
            for member in group["members"]:
                observation = client.get("/api" + member["detail_path"]).json()
                assert observation["evidence"]["container"].startswith(f"{service}-container-")
        assert client.get(base + "/findings", params={**query, "aggregation": "none"}).json()["total"] == 6
        summary = client.get(base + "/summary", params={"aggregation": "check"}).json()
        assert summary["stats"]["failed_by_category"]["exposure"] == 3


def test_member_pages_retain_exact_evidence_status_native_asset_and_location(live):
    client, scan, _ = live
    base = f"/api/scans/{scan}/finding-groups/" + group_id("aws", "fixture.retention")
    seen = []
    for offset, expected in [(0, 50), (50, 50), (100, 25)]:
        response = client.get(base, params={"members_offset": offset})
        assert response.status_code == 200, response.text
        group = response.json()
        assert group["status_counts"] == {"FAIL": 120, "PASS": 5}
        assert group["affected_regions"] == ["eu-north-1", "us-east-1"]
        assert group["members_total"] == 125 and len(group["members"]) == expected
        seen += group["members"]
    assert len({member["id"] for member in seen}) == 125
    for member in seen:
        number = int(member["id"].rsplit("-", 1)[-1])
        assert member["asset"] == f"log-{number}"
        assert member["evidence_summary"] == f"log-{number} retains logs for {7 if number < 120 else 365} days."
        original = client.get("/api" + member["detail_path"])
        assert original.status_code == 200
        assert original.json()["evidence"]["retention_days"] == (7 if number < 120 else 365)


def test_filter_members_before_grouping_and_keep_filters_on_the_group(live):
    client, scan, _ = live
    data = client.get(f"/api/scans/{scan}/findings", params={"aggregation": "check", "status": "PASS"}).json()
    assert data["total"] == 1 and data["items"][0]["status"] == "PASS"
    assert data["items"][0]["member_filters"] == {"status": "PASS"}
    item = data["items"][0]
    group = client.get(f"/api/scans/{scan}/finding-groups/{item['id']}", params=item["member_filters"]).json()
    assert group["members_total"] == 5 and all(member["status"] == "PASS" for member in group["members"])
    data = client.get(f"/api/scans/{scan}/findings", params={"aggregation": "check", "search": "log-119"}).json()
    assert data["total"] == 1 and data["items"][0]["member_count"] == 1


def test_grouped_summary_counts_checks_without_changing_coverage(live):
    client, scan, _ = live
    original = client.get(f"/api/scans/{scan}/summary").json()
    grouped = client.get(f"/api/scans/{scan}/summary?aggregation=check").json()
    assert original["finding_count"] == 126
    assert grouped["finding_count"] == grouped["stats"]["finding_count"] == 2
    assert grouped["stats"]["observation_count"] == 126
    assert grouped["stats"]["by_status"] == {"FAIL": 2}
    assert grouped["stats"]["by_category"] == {"hardening": 2}
    assert grouped["coverage_count"] == original["coverage_count"]


def test_group_ownership_bounds_and_unknown_ids(live):
    client, scan, _ = live
    path = f"/api/scans/{scan}/finding-groups/" + group_id("aws", "fixture.retention")
    assert client.get(path, params={"members_limit": 101}).status_code == 422
    assert client.get(path, params={"members_offset": -1}).status_code == 422
    assert client.get(path + "invalid").status_code == 404
    client.headers["Authorization"] = "Bearer bob"
    assert client.get(path).status_code == 404
    assert client.get(f"/api/scans/{scan}/findings?aggregation=check").status_code == 404


def test_grouped_downloads_include_all_assets_for_old_and_new_reports(live):
    client, scan, report = live
    response = client.get(f"/api/scans/{scan}/report?aggregation=check")
    assert response.status_code == 200, response.text
    value = response.json()
    assert value["finding_grouping"] == "check-v1" and len(value["findings"]) == 2
    assert sum(len(group["observations"]) for group in value["findings"]) == len(report["findings"])
    markdown = client.get(f"/api/scans/{scan}/report?format=markdown&aggregation=check")
    assert markdown.status_code == 200
    assert markdown.text.count("### FAIL:") == 2
    assert "log-124" in markdown.text and "log-0" in markdown.text


def test_large_local_grouped_download_streams_exact_owned_artifact(live, monkeypatch):
    from peaso.server import app as application
    client, scan, original = live
    artifacts, store = client.app.state.artifacts, client.app.state.store
    report = deepcopy(original)
    for row in report['findings']:
        row['evidence']['recorded_configuration'] = 'synthetic configuration ' * 200
    reference = artifacts.put('alice', scan, 'report', report)
    with store.transaction() as db:
        db.execute('UPDATE jobs SET report=? WHERE id=?', (reference, scan))
    streamed = []
    response_type = application.FileResponse

    def file_response(path, **kwargs):
        streamed.append(path)
        return response_type(path, **kwargs)

    monkeypatch.setattr(application, 'FileResponse', file_response)
    path = f'/api/scans/{scan}/report?aggregation=check'
    response = client.get(path)
    assert response.status_code == 200
    assert len(streamed) == 1 and response.json() == json.loads(streamed[0].read_text())
    assert response.headers['cache-control'] == 'no-store'
    assert sum(len(group['observations']) for group in response.json()['findings']) == len(original['findings'])
    client.headers['Authorization'] = 'Bearer bob'
    assert client.get(path, headers={'Range': 'bytes=0-15'}).status_code == 404


def test_summary_failed_category_count_excludes_passed_controls(live):
    client, scan, report = live
    changed = deepcopy(report)
    changed['findings'].append(dict(changed['findings'][-1], id='passed-control', check_id='fixture.passing', status='PASS'))
    artifacts, store = client.app.state.artifacts, client.app.state.store
    reference = artifacts.put('alice', scan, 'report', changed)
    with store.transaction() as db:
        db.execute("UPDATE jobs SET report=? WHERE id=?", (reference, scan))
    summary = client.get(f'/api/scans/{scan}/summary?aggregation=check').json()
    assert summary['stats']['by_category'] == {'hardening': 3}
    assert summary['stats']['failed_by_category'] == {'hardening': 2}
