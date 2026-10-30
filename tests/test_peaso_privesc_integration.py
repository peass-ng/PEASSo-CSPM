"""Engine, report, CLI and API integration of the read-only privesc evaluator (peaso.privesc)."""
import json

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from peaso.auth import Identity
from peaso.cli import main
from peaso.engine import diff_reports, evaluate_snapshot, get_catalog, plan_collection
from peaso.reports import render_markdown
from peaso.server import create_app
from peaso.server.config import Settings
from peaso.snapshot import make_snapshot
from peaso.storage.reports import privesc_projection
from peaso.worker import Worker
from peaso.engine import hydrate_frameworks

ACCOUNT = "111111111111"
SCOPE = f"{ACCOUNT}/us-east-1"
ALICE = f"arn:aws:iam::{ACCOUNT}:user/alice"
ADMIN_ROLE = f"arn:aws:iam::{ACCOUNT}:role/ec2-admin"
INSTANCE = f"arn:aws:ec2:us-east-1:{ACCOUNT}:instance/i-0123456789abcdef0"
IMAGE = "arn:aws:ec2:us-east-1::image/ami-0123456789abcdef0"
SUBNET = f"arn:aws:ec2:us-east-1:{ACCOUNT}:subnet/subnet-0123456789abcdef0"
GROUP = f"arn:aws:ec2:us-east-1:{ACCOUNT}:security-group/sg-0123456789abcdef0"
INTERFACE = f"arn:aws:ec2:us-east-1:{ACCOUNT}:network-interface/eni-0123456789abcdef0"
PROFILE = f"arn:aws:iam::{ACCOUNT}:instance-profile/ec2-admin"


def policy(*statements):
    return {"Version": "2012-10-17", "Statement": list(statements)}


def privesc_snapshot():
    alice = {"UserName": "alice", "Arn": ALICE, "GroupList": [], "AttachedManagedPolicies": [],
             "UserPolicyList": [{"PolicyName": "alice-inline", "PolicyDocument": policy(
                 {"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"},
                 {"Effect": "Allow", "Action": "ec2:RunInstances", "Resource": "*"})}]}
    role = {"RoleName": "ec2-admin", "Arn": ADMIN_ROLE, "RoleId": "AROAEC2ADMIN123456789", "Path": "/", "RolePolicyList": [],
            "AssumeRolePolicyDocument": policy({"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}),
            "AttachedManagedPolicies": [{"PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess", "PolicyName": "AdministratorAccess"}],
            "InstanceProfileList": [{"Arn": PROFILE}]}
    launch = {"TechniqueId": "aws-ec2-passrole-runinstances", "SourceArn": ALICE,
              "TargetKind": "aws_role", "TargetId": ADMIN_ROLE, "Status": "verified",
              "VerifiedPreconditions": True, "InstanceArn": INSTANCE, "ImageArn": IMAGE,
              "SubnetArn": SUBNET, "SecurityGroupArn": GROUP, "NetworkInterfaceArn": INTERFACE,
              "InstanceProfileArn": PROFILE, "TargetRoleId": role["RoleId"],
              "InstanceRoleId": role["RoleId"], "RunInstancesSucceeded": True,
              "InstanceLaunchedSucceeded": True, "InstanceProfileApplied": True,
              "UserDataControlledBySource": True, "UserDataExecuted": True,
              "UserDataUsedRoleCredentials": True, "RoleAction": "s3:PutObject",
              "RoleActionResource": "arn:aws:s3:::instance-output/result",
              "RoleActionSucceeded": True, "EffectUsefulToSource": True,
              "RunInstancesAuthorizationResourcesComplete": True,
              "RunInstancesAuthorizationResources": [INSTANCE, IMAGE, SUBNET, GROUP, INTERFACE],
              "TagsRequested": False, "EvidenceRef": "reviewed-runinstances-integration",
              "EvidenceObservedAt": "2026-01-01T00:00:00Z",
              "EvidenceExpiresAt": "2026-01-01T00:05:00Z"}
    collections = [{"type": kind, "scope": SCOPE, "service": kind, "status": status, "items": items} for kind, status, items in (
        ("iam_user", "collected", [alice]), ("iam_role", "collected", [role]), ("iam_group", "empty", []),
        ("iam_policy", "empty", []), ("scp_policy", "empty", []),
        ("aws_privesc_challenge_evidence", "collected", [launch]))]
    return make_snapshot("aws", [SCOPE], collections, created_at="2026-01-01T00:00:00+00:00")


@pytest.fixture(scope="module")
def report():
    return hydrate_frameworks(evaluate_snapshot(privesc_snapshot(), categories=["privesc"]))


def test_engine_produces_privesc_findings_graph_coverage_and_stats(report):
    privesc = [f for f in report["findings"] if f["category"] == "privesc"]
    assert privesc and len(privesc) == report["stats"]["finding_count"]
    assert any(f["check_id"] == "aws-ec2-passrole-runinstances" for f in privesc)
    assert any(f["check_id"] == "admin-equivalent" and f["status"] == "FAIL" for f in privesc)
    assert {f["status"] for f in privesc} <= {"FAIL", "MANUAL", "UNKNOWN"}
    graph = report["graphs"]["privesc"]
    assert graph["nodes"] and graph["edges"] and report["graphs"]["network"] == {"nodes": [], "edges": []}
    assert any("aws-ec2-passrole-runinstances" in e["techniques"] for e in graph["edges"])
    assert any(c["level"] == "privesc" for c in report["coverage"]) or report["stats"]["privesc"]["catalog_errors"] == 0
    summary = next(c for c in report["coverage"] if c["level"] == "check" and c["check_id"] == "privesc")
    assert summary["by_status"].get("FAIL")
    stats = report["stats"]["privesc"]
    assert stats["nodes"] == len(graph["nodes"]) and stats["edges"] == len(graph["edges"])
    assert "timing_seconds" not in stats  # wall-clock timings are out of band (deterministic report)
    assert report["stats"]["categories"] == ["privesc"] and report["stats"]["check_count"] == 1


def test_report_is_json_valid_deterministic_and_diffable(report):
    encoded = json.dumps(report, allow_nan=False)
    assert json.loads(encoded) == report
    again = evaluate_snapshot(privesc_snapshot(), categories=["privesc"])
    assert hydrate_frameworks(again) == report  # the fixture is the hydrated view
    diff = diff_reports(report, again)
    assert diff["stats"] == {"added": 0, "removed": 0, "changed": 0}
    # Principal resource ids never collide with inventory resource ids.
    inventory_ids = {r["id"] for r in report["resources"]}
    assert not inventory_ids & {f["resource_id"] for f in report["findings"]}


def test_timings_and_run_scan_out_of_band():
    timings = {}
    evaluate_snapshot(privesc_snapshot(), categories=["privesc"], timings=timings)
    assert timings["privesc"]["engine_seconds"] >= 0


def test_analyze_exception_becomes_coverage_not_a_crashed_scan(monkeypatch):
    from peaso import privesc

    def broken(*args, **kwargs):
        raise RuntimeError("boom")
    monkeypatch.setattr(privesc, "analyze", broken)
    value = evaluate_snapshot(privesc_snapshot(), categories=["privesc", "least_privilege"])
    entry = next(c for c in value["coverage"] if c.get("check_id") == "privesc")
    assert entry["status"] == "unknown" and entry["error_kind"] == "RuntimeError"
    assert value["stats"]["privesc"] == {"error": "RuntimeError"}
    assert value["graphs"]["privesc"] == {"nodes": [], "edges": []}
    assert any(f["category"] == "least_privilege" for f in hydrate_frameworks(value)["findings"])
    assert "Evaluation failed" in render_markdown(value)


def test_selection_and_collection_plan():
    plan = plan_collection({"connector": {"provider": "aws"}, "categories": ["privesc"]})
    assert {"iam_user", "iam_group", "iam_role", "iam_policy", "scp_policy", "lambda_function", "instance"} <= set(plan)
    gcp = plan_collection({"connector": {"provider": "gcp"}, "categories": ["privesc"]})
    assert {"project", "folder", "iam_policy", "iam_role", "service_account", "iam_deny_policy", "instance"} <= set(gcp)
    k8s = plan_collection({"connector": {"provider": "k8s"}, "categories": ["privesc"]})
    assert {"role", "clusterrole", "rolebinding", "clusterrolebinding", "serviceaccount", "namespace", "pod", "node"} <= set(k8s)
    assert "iam_user" not in plan_collection({"connector": {"provider": "aws"}, "categories": ["hardening"], "checks": ["aws.ec2.imdsv2"]})
    one = evaluate_snapshot(privesc_snapshot(), categories=["privesc"], checks=["aws-ec2-passrole-runinstances"])
    assert {f["check_id"] for f in one["findings"]} <= {"aws-ec2-passrole-runinstances", "admin-equivalent"}
    nist_only = evaluate_snapshot(privesc_snapshot(), categories=["privesc"], frameworks=["nist_800_53"])
    assert not [f for f in nist_only["findings"] if f["category"] == "privesc"]
    assert "privesc" in get_catalog()["categories"]
    with pytest.raises(ValueError):
        evaluate_snapshot(privesc_snapshot(), categories=["privesc"], checks=["not-a-technique"])


def test_markdown_privesc_section(report):
    text = render_markdown(report)
    section = text[text.index("## Privilege Escalation"):text.index("## Findings")]
    for heading in ("### Principals reaching admin-equivalent", "### Top escalation paths", "### Techniques with broad reach", "### Unknowns and coverage gaps"):
        assert heading in section
    assert "alice" in section and "aws-ec2-passrole-runinstances" in section
    assert "AdministratorAccess" in section  # evidence for the admin-equivalent hop
    assert "Mitigation:" in section


def test_privesc_projection_truncates_whole_edges_and_keeps_aggregates(report):
    graph = report["graphs"]["privesc"]
    assert privesc_projection(graph, 500) is graph
    small = privesc_projection(graph, 2)
    assert small["truncated"] and len(small["nodes"]) <= 2
    ids = {n["id"] for n in small["nodes"]}
    assert all(e["source"] in ids and e["target"] in ids for e in small["edges"])




# ---------------------------------------------------------------------------- API
class Identities:
    def authenticate(self, authorization):
        users = {"Bearer alice": Identity("alice"), "Bearer bob": Identity("bob")}
        if authorization not in users:
            raise HTTPException(401, "Invalid authentication")
        return users[authorization]

    def is_paid(self, tenant):
        return False


@pytest.fixture
def api(tmp_path):
    settings = Settings(state_dir=tmp_path / "state", identity_dir=tmp_path / "identity", local_token="local-test-token-0123456789abcdef")
    with TestClient(create_app(settings, authenticator=Identities()), base_url="http://127.0.0.1:8000") as client:
        client.headers["Authorization"] = "Bearer alice"
        connector = client.post("/api/connectors", json={"name": "privesc", "provider": "aws", "auth": {}, "scopes": [SCOPE],
                                                         "options": {"snapshot": privesc_snapshot()}})
        assert connector.status_code == 201, connector.text
        job = client.post("/api/scans", json={"ai_enabled": False, "connector_id": connector.json()["id"], "categories": ["privesc"]})
        assert job.status_code == 201, job.text
        assert Worker("collector", settings).run_once() and Worker("analyzer", settings).run_once()
        assert client.get(f"/api/scans/{job.json()['id']}").json()["status"] == "completed"
        yield client, job.json()["id"]


def test_api_privesc_graph_and_queries(api):
    client, ident = api
    graph = client.get(f"/api/scans/{ident}/graphs/privesc")
    assert graph.status_code == 200 and graph.json()["edges"]
    assert any(n["kind"] == "entity" for n in graph.json()["nodes"])
    projected = client.get(f"/api/scans/{ident}/graphs/privesc?max_nodes=2").json()
    assert projected["truncated"] and len(projected["nodes"]) <= 2
    admins = client.get(f"/api/scans/{ident}/privesc/admins").json()
    assert {row["principal"] for row in admins["items"]} >= {ALICE, ADMIN_ROLE} and admins["total"] == len(admins["items"])
    paths = client.get(f"/api/scans/{ident}/privesc/paths", params={"from": ALICE, "max_depth": 6}).json()
    assert paths["items"] and paths["items"][0]["length"] == 2
    assert client.get(f"/api/scans/{ident}/privesc/paths", params={"source": ALICE, "to": ADMIN_ROLE}).json()["items"][0]["target"] == ADMIN_ROLE
    assert client.get(f"/api/scans/{ident}/privesc/paths").status_code == 422
    assert client.get(f"/api/scans/{ident}/privesc/paths", params={"from": ALICE, "max_depth": 99}).status_code == 422
    assert client.get(f"/api/scans/{ident}/privesc/paths", params={"from": "arn:aws:iam::1:user/nobody"}).status_code == 404
    broad = client.get(f"/api/scans/{ident}/privesc/broad", params={"min_targets": 1}).json()
    assert any(row["principal"] == ALICE for row in broad["items"])
    card = client.get(f"/api/scans/{ident}/privesc/principals/{ALICE}")
    assert card.status_code == 200, card.text
    card = card.json()
    assert "aws-ec2-passrole-runinstances" in card["techniques"] and card["findings"]
    assert all(f["resource_id"] == ALICE and f["category"] == "privesc" for f in card["findings"])
    assert client.get(f"/api/scans/{ident}/privesc/principals/arn:aws:iam::1:user/nobody").status_code == 404
    findings = client.get(f"/api/scans/{ident}/findings", params={"categories": "privesc"}).json()
    assert findings["total"] and all(f["category"] == "privesc" for f in findings["items"])
    markdown = client.get(f"/api/scans/{ident}/report?format=markdown")
    assert "## Privilege Escalation" in markdown.text


def test_api_privesc_tenant_isolation_and_auth(api):
    client, ident = api
    paths = [f"scans/{ident}/graphs/privesc", f"scans/{ident}/privesc/admins", f"scans/{ident}/privesc/paths?from={ALICE}",
             f"scans/{ident}/privesc/broad", f"scans/{ident}/privesc/principals/{ALICE}"]
    client.headers["Authorization"] = "Bearer bob"
    for path in paths:
        response = client.get("/api/" + path)
        assert response.status_code == 404, (path, response.text)
        assert "alice" not in response.text
    client.headers["Authorization"] = "Bearer mallory"
    for path in paths:
        assert client.get("/api/" + path).status_code == 401


def test_api_privesc_hosted_presigned_graph_and_server_side_queries(tmp_path):
    """Hosted (S3-style) artifacts: the graph is a signed download, queries read the artifact server side."""
    from peaso.storage import FileArtifacts, SQLiteStore

    class SignedArtifacts(FileArtifacts):
        def presign(self, tenant, reference, filename=None):
            from peaso.storage.artifacts import check_reference
            check_reference(tenant, reference)
            return "https://signed.invalid/" + reference

    settings = Settings(state_dir=tmp_path / "state", identity_dir=tmp_path / "identity", local_token="local-test-token-0123456789abcdef")
    store, artifacts = SQLiteStore(settings.state_dir), SignedArtifacts(settings.state_dir / "artifacts")
    with TestClient(create_app(settings, store=store, authenticator=Identities(), artifacts=artifacts), base_url="http://127.0.0.1:8000") as client:
        client.headers["Authorization"] = "Bearer alice"
        connector = client.post("/api/connectors", json={"name": "privesc", "provider": "aws", "auth": {}, "scopes": [SCOPE],
                                                         "options": {"snapshot": privesc_snapshot()}}).json()
        ident = client.post("/api/scans", json={"ai_enabled": False, "connector_id": connector["id"], "categories": ["privesc"]}).json()["id"]
        assert Worker("collector", settings).run_once() and Worker("analyzer", settings).run_once()
        signed = client.get(f"/api/scans/{ident}/graphs/privesc").json()
        assert signed["download_url"].startswith("https://signed.invalid/") and "graph-privesc" in signed["download_url"]
        assert "graph-privesc" in client.get(f"/api/scans/{ident}/graphs/privesc?max_nodes=500").json()["download_url"]
        assert client.get(f"/api/scans/{ident}/graphs/privesc?max_nodes=7").status_code == 422
        assert any(row["principal"] == ALICE for row in client.get(f"/api/scans/{ident}/privesc/admins").json()["items"])
        client.headers["Authorization"] = "Bearer bob"
        assert client.get(f"/api/scans/{ident}/graphs/privesc").status_code == 404
        assert client.get(f"/api/scans/{ident}/privesc/admins").status_code == 404


def test_api_finding_detail_accepts_ids_with_slashes_without_shadowing(api):
    from urllib.parse import quote
    client, ident = api
    finding_id = f"privesc:aws-ec2-passrole-runinstances:{ALICE}"
    assert "/" in finding_id
    raw = client.get(f"/api/scans/{ident}/findings/{finding_id}")
    assert raw.status_code == 200, raw.text
    assert raw.json()["id"] == finding_id
    assert "ec2_runinstances_exact_instance_role_effect" in raw.json()["evidence"]["conditions"]
    encoded = client.get(f"/api/scans/{ident}/findings/{quote(finding_id, safe='')}")
    assert encoded.status_code == 200 and encoded.json()["id"] == finding_id
    assert client.get(f"/api/scans/{ident}/findings/{finding_id}/extra").status_code == 404
    assert client.get(f"/api/scans/{ident}/findings/privesc:none:arn:aws:iam::1:user/x").status_code == 404
    # Sibling and list routes are not shadowed by the path converter.
    assert client.get(f"/api/scans/{ident}/findings").json()["total"]
    assert client.get(f"/api/scans/{ident}/summary").status_code == 200
    assert client.get(f"/api/scans/{ident}/coverage").status_code == 200
    client.headers["Authorization"] = "Bearer bob"
    assert client.get(f"/api/scans/{ident}/findings/{finding_id}").status_code == 404


def test_api_principal_card_edges_carry_catalog_technique_details(api):
    client, ident = api
    card = client.get(f"/api/scans/{ident}/privesc/principals/{ALICE}").json()
    edge = next(e for e in card["outgoing"] if "aws-ec2-passrole-runinstances" in e["techniques"])
    detail = next(d for d in edge["technique_details"] if d["id"] == "aws-ec2-passrole-runinstances")
    assert detail["summary"] and detail["mitigation"] and detail["source"].startswith("src/pentesting-cloud/")
    assert detail["required_permissions"]["all_of"] == []
    assert "conditions" in detail and detail["edge_confidence"] == edge["confidence"]
    assert detail["evidence"] == edge["evidence_refs"]
    assert "ec2_runinstances_exact_instance_role_effect" in detail["evaluated_conditions"]
    assert card["technique_details"]["aws-ec2-passrole-runinstances"]["title"]

    role = client.get(f"/api/scans/{ident}/privesc/principals/{ADMIN_ROLE}").json()
    admin_edge = next(e for e in role["outgoing"] if "admin-equivalent" in e["techniques"])
    # Already-admin is a synthetic assessment label, not an escalation entry
    # in the strict catalog, so the bound report cannot give it a technique.
    admin_detail = admin_edge["technique_details"][0]
    assert admin_detail["id"] == "admin-equivalent"
    assert admin_detail["unknown"] is True
    assert admin_detail["catalog_lookup_status"] == "exact_strict_privesc"
    assert admin_detail["edge_confidence"] == admin_edge["confidence"]
    assert admin_detail["evidence"] == admin_edge["evidence_refs"]
    permission = admin_detail["granting_permissions"][0]
    assert permission["permission"] == "*"
    assert permission["grant"]["statement_document"] == {"Effect": "Allow", "Action": ["*"], "Resource": ["*"]}
