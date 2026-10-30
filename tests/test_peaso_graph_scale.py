"""Report schema 1.1 (native data by reference), projection dimensions, hierarchy paging and the bounded
graph endpoints (expand, network page, privesc subgraph, aggregate members, native resource detail)."""
import json

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from peaso.analysis import build_graphs, expand_projected_node, page_graph, project_graph
from peaso.auth import Identity
from peaso.cli import main
from peaso.engine import REPORT_SCHEMA_VERSION, compact_report, evaluate_snapshot, expand_report
from peaso.server import create_app
from peaso.server.config import Settings
from peaso.snapshot import FrozenDict, make_snapshot, resources
from peaso.worker import Worker

ACCOUNT = "111111111111"
SCOPE = f"{ACCOUNT}/us-east-1"
ADMIN_ROLE = f"arn:aws:iam::{ACCOUNT}:role/ec2-admin"


def policy(*statements):
    return {"Version": "2012-10-17", "Statement": list(statements)}


def scale_snapshot(users=240, vpcs=4, subnets_per_vpc=6, instances_per_subnet=5):
    people = []
    for i in range(users):
        path = "/eng/" if i % 2 else "/ops/"
        statements = [{"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"},
                      {"Effect": "Allow", "Action": "ec2:RunInstances", "Resource": "*"}] if i % 3 == 0 else \
                     [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]
        if i % 40 == 0:
            statements = [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
        people.append({"UserName": f"user-{i:04d}", "Arn": f"arn:aws:iam::{ACCOUNT}:user{path}user-{i:04d}", "Path": path,
                       "GroupList": [], "AttachedManagedPolicies": [],
                       "UserPolicyList": [{"PolicyName": f"inline-{i}", "PolicyDocument": policy(*statements)}]})
    role = {"RoleName": "ec2-admin", "Arn": ADMIN_ROLE, "Path": "/", "RolePolicyList": [],
            "AssumeRolePolicyDocument": policy({"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}),
            "AttachedManagedPolicies": [{"PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess", "PolicyName": "AdministratorAccess"}],
            "InstanceProfileList": [{"Arn": f"arn:aws:iam::{ACCOUNT}:instance-profile/ec2-admin"}]}
    vpc_items = [{"VpcId": f"vpc-{v}", "CidrBlock": f"10.{v}.0.0/16", "OwnerId": ACCOUNT} for v in range(vpcs)]
    subnet_items, instance_items = [], []
    for v in range(vpcs):
        for s in range(subnets_per_vpc):
            subnet = f"subnet-{v}-{s}"
            subnet_items.append({"SubnetId": subnet, "VpcId": f"vpc-{v}", "CidrBlock": f"10.{v}.{s}.0/24"})
            for k in range(instances_per_subnet):
                instance_items.append({"InstanceId": f"i-{v}-{s}-{k}", "SubnetId": subnet, "VpcId": f"vpc-{v}",
                                       "PrivateIpAddress": f"10.{v}.{s}.{k + 10}", "SecurityGroups": [{"GroupId": f"sg-{v}"}]})
    sg_items = [{"GroupId": f"sg-{v}", "VpcId": f"vpc-{v}", "IpPermissions": [], "IpPermissionsEgress": []} for v in range(vpcs)]
    facts = (("iam_user", people), ("iam_role", [role]), ("iam_group", []), ("iam_policy", []), ("scp_policy", []),
             ("vpc", vpc_items), ("subnet", subnet_items), ("instance", instance_items), ("security_group", sg_items))
    collections = [{"type": kind, "scope": SCOPE, "service": kind, "status": "collected" if items else "empty", "items": items} for kind, items in facts]
    return make_snapshot("aws", [SCOPE], collections, created_at="2026-01-01T00:00:00+00:00")


@pytest.fixture(scope="module")
def snap():
    return scale_snapshot()


@pytest.fixture(scope="module")
def report(snap):
    return evaluate_snapshot(snap, categories=["iam_graph", "network", "privesc", "least_privilege"])


# ------------------------------------------------------------------ report schema 1.1
def test_report_references_native_data_instead_of_copying_it(snap, report):
    assert report["schema_version"] == REPORT_SCHEMA_VERSION == "1.1"
    assert report["resources"] and all("data" not in r for r in report["resources"])
    assert report["native_data"]["mode"] == "snapshot_reference" and report["native_data"]["snapshot_id"] == snap["snapshot_id"]
    ids = {r["id"] for r in report["resources"]}
    nodes = [n for g in ("iam", "network") for n in report["graphs"][g]["nodes"]]
    assert all("native_resource" not in n["evidence"] for n in nodes)
    refs = [n["evidence"]["native_resource_ref"] for n in nodes if "native_resource_ref" in n["evidence"]]
    assert refs and set(refs) <= ids
    documents = [n for n in report["graphs"]["iam"]["nodes"] if n["type"] == "policy_document"]
    assert documents and all("native_document" not in n["evidence"] and n["evidence"]["native_document_ref"] for n in documents)
    # Schema 1.0 carried the native items twice more (resources[].data and node evidence); 1.1 carries neither.
    items = sum(len(json.dumps(item)) for c in snap["collections"] for item in c["items"])
    assert len(json.dumps(expand_report(report, snap))) - len(json.dumps(report)) >= 2 * items * 0.9


def test_expand_and_compact_are_inverse_and_share_native_objects(snap, report):
    expanded = expand_report(report, snap)
    assert expanded["schema_version"] == "1.0" and "native_data" not in expanded
    assert all("data" in r for r in expanded["resources"])
    native = {r["id"]: r["data"] for r in resources(snap)}
    assert all(r["data"] == native[r["id"]] for r in expanded["resources"])
    node = next(n for n in expanded["graphs"]["iam"]["nodes"] if "native_resource" in n["evidence"])
    assert isinstance(node["evidence"]["native_resource"], FrozenDict)  # shared, read-only, not a copy
    documents = [n for n in expanded["graphs"]["iam"]["nodes"] if n["type"] == "policy_document"]
    assert documents and all(isinstance(n["evidence"]["native_document"], dict) and "Statement" in n["evidence"]["native_document"] for n in documents)
    assert report["schema_version"] == "1.1" and all("data" not in r for r in report["resources"])  # input untouched
    assert json.loads(json.dumps(compact_report(json.loads(json.dumps(expanded))))) == json.loads(json.dumps(report))
    assert expand_report(expanded) is expanded
    with pytest.raises(ValueError):
        expand_report(report)  # no snapshot available
    with pytest.raises(ValueError):
        expand_report(report, dict(snap, snapshot_id="sha256:other"))


def test_cli_json_is_compact_by_default_and_embeds_native_on_request(tmp_path, snap, capsys):
    path = tmp_path / "snap.json"
    path.write_text(json.dumps(snap))
    assert main(["evaluate", str(path), "--categories", "iam_graph"]) == 0
    compact = json.loads(capsys.readouterr().out)
    assert compact["schema_version"] == "1.1" and all("data" not in r for r in compact["resources"])
    assert main(["evaluate", str(path), "--categories", "iam_graph", "--embed-native"]) == 0
    embedded = json.loads(capsys.readouterr().out)
    assert embedded["schema_version"] == "1.0" and all("data" in r for r in embedded["resources"])
    assert main(["evaluate", str(path), "--categories", "iam_graph", "--format", "markdown"]) == 0
    assert '"UserName": "user-0000"' in capsys.readouterr().out


# ------------------------------------------------------------------ projection
def test_projection_uses_budget_with_risk_and_facet_dimensions(snap, report):
    graph = report["graphs"]["iam"]
    projected = project_graph(graph, 60)
    assert len(projected["nodes"]) <= 60 and projected["projection"]["collapsed"]
    assert sum(n["underlying_count"] for n in projected["nodes"]) == len(graph["nodes"])
    users = [n for n in projected["nodes"] if n["type"] == "iam_user"]
    assert len(users) > 4  # not one bucket per type
    prefixes = {n.get("group_dimensions", {}).get("facets", {}).get("path_prefix") or n.get("facets", {}).get("path_prefix") for n in users}
    assert {"/eng/", "/ops/"} <= prefixes
    tiers = {n.get("group_dimensions", {}).get("risk_tier") for n in users if n.get("aggregate")}
    assert len(tiers) >= 2 or projected["projection"]["promoted_individual_nodes"]


def test_expand_projected_node_returns_members_with_boundary_stubs(report):
    graph = report["graphs"]["iam"]
    projected = project_graph(graph, 30)
    aggregate = max((n for n in projected["nodes"] if n.get("aggregate")), key=lambda n: n["underlying_count"])
    view = expand_projected_node(graph, aggregate["id"], projected=projected)
    members = {n["id"] for n in view["nodes"] if not n.get("stub")}
    assert view["member_count"] == aggregate["underlying_count"]
    assert sum(n["underlying_count"] for n in view["nodes"] if not n.get("stub")) == aggregate["underlying_count"]
    stubs = {n["id"] for n in view["nodes"] if n.get("stub")}
    assert all(e["source"] in members | stubs and e["target"] in members | stubs for e in view["edges"])
    with pytest.raises(KeyError):
        expand_projected_node(graph, "missing", projected=projected)


def test_network_paging_follows_hierarchy_and_keeps_cross_page_edges(report):
    graph = report["graphs"]["network"]
    first = page_graph(graph, 0, page_size=20)
    assert first["page_count"] > 1 and first["total_nodes"] == len(graph["nodes"])
    seen, crossing = set(), 0
    for number in range(first["page_count"]):
        current = page_graph(graph, number, page_size=20)
        real = [n for n in current["nodes"] if not n.get("stub")]
        assert len(real) <= 20 or len(real) == 1
        seen.update(n["id"] for n in real)
        ids = {n["id"] for n in current["nodes"]}
        assert all(e["source"] in ids and e["target"] in ids for e in current["edges"])
        crossing += current["cross_page_edges"]
        for node in real:  # a subnet that fits a page lands with its instances
            if node["type"] == "subnet":
                kids = [n["id"] for n in graph["nodes"] if n.get("parent_id") == node["id"]]
                assert set(kids) <= {n["id"] for n in real}
    assert seen == {n["id"] for n in graph["nodes"]}
    assert crossing  # edges across pages are kept (with stubs), never dropped
    with pytest.raises(ValueError):
        page_graph(graph, first["page_count"], page_size=20)


# ------------------------------------------------------------------ API
class Identities:
    def authenticate(self, authorization):
        users = {"Bearer alice": Identity("alice"), "Bearer bob": Identity("bob")}
        if authorization not in users:
            raise HTTPException(401, "Invalid authentication")
        return users[authorization]

    def is_paid(self, tenant):
        return False


@pytest.fixture(scope="module")
def api(tmp_path_factory, snap):
    tmp_path = tmp_path_factory.mktemp("graph-api")
    settings = Settings(state_dir=tmp_path / "state", identity_dir=tmp_path / "identity", local_token="local-test-token-0123456789abcdef")
    with TestClient(create_app(settings, authenticator=Identities()), base_url="http://127.0.0.1:8000") as client:
        client.headers["Authorization"] = "Bearer alice"
        connector = client.post("/api/connectors", json={"name": "scale", "provider": "aws", "auth": {}, "scopes": [SCOPE], "options": {"snapshot": snap}})
        assert connector.status_code == 201, connector.text
        job = client.post("/api/scans", json={"ai_enabled": False, "connector_id": connector.json()["id"], "categories": ["iam_graph", "network", "privesc"]})
        assert job.status_code == 201, job.text
        assert Worker("collector", settings).run_once() and Worker("analyzer", settings).run_once()
        assert client.get(f"/api/scans/{job.json()['id']}").json()["status"] == "completed"
        yield client, job.json()["id"]


def test_api_graph_expand_and_network_page(api):
    client, ident = api
    projected = client.get(f"/api/scans/{ident}/graphs/iam?max_nodes=500").json()
    full = client.get(f"/api/scans/{ident}/graphs/iam").json()
    assert all("native_resource" not in n["evidence"] for n in full["nodes"])
    first = projected["nodes"][0]["id"]
    expanded = client.get(f"/api/scans/{ident}/graphs/iam/expand", params={"node": first})
    assert expanded.status_code == 200, expanded.text
    assert expanded.json()["expanded"] == first
    assert client.get(f"/api/scans/{ident}/graphs/iam/expand", params={"node": "missing"}).status_code == 404
    assert client.get(f"/api/scans/{ident}/graphs/privesc/expand", params={"node": first}).status_code == 422
    page = client.get(f"/api/scans/{ident}/graphs/network/page", params={"page": 0, "page_size": 40}).json()
    assert page["page_count"] >= 1 and page["nodes"] and "pages" in page
    assert client.get(f"/api/scans/{ident}/graphs/network/page", params={"page": 999}).status_code == 404


def test_api_privesc_subgraph_overview_focus_and_members(api):
    client, ident = api
    overview = client.get(f"/api/scans/{ident}/graphs/privesc/subgraph", params={"top": 5, "max_nodes": 40}).json()
    assert overview["mode"] == "overview" and 0 < len(overview["seeds"]) <= 5 and len(overview["nodes"]) <= 40
    ids = {n["id"] for n in overview["nodes"]}
    assert all(e["source"] in ids and e["target"] in ids for e in overview["edges"])
    focus = overview["seeds"][0]["principal"]
    around = client.get(f"/api/scans/{ident}/graphs/privesc/subgraph",
                        params={"focus": focus, "depth": 1, "direction": "out", "max_nodes": 20, "max_edges": 50, "member_cap": 3}).json()
    assert around["mode"] == "neighbourhood" and around["focus"] == focus and around["nodes"][0]["id"] == focus
    assert len(around["nodes"]) <= 20 and len(around["edges"]) <= 50
    assert all(len(n.get("members") or []) <= 3 for n in around["nodes"])
    assert all(around["distances"][n["id"]] <= 1 for n in around["nodes"])
    assert client.get(f"/api/scans/{ident}/graphs/privesc/subgraph", params={"focus": "arn:aws:iam::1:user/nobody"}).status_code == 404
    assert client.get(f"/api/scans/{ident}/graphs/privesc/subgraph", params={"depth": 99}).status_code == 422
    graph = client.get(f"/api/scans/{ident}/graphs/privesc").json()
    aggregate = next((n for n in graph["nodes"] if n.get("kind") == "aggregate"), None)
    if aggregate is not None:
        members = client.get(f"/api/scans/{ident}/graphs/privesc/aggregates/{aggregate['id']}/members", params={"limit": 2}).json()
        assert members["total"] == len(aggregate.get("members") or []) and len(members["items"]) <= 2
    assert client.get(f"/api/scans/{ident}/graphs/privesc/aggregates/missing/members").status_code == 404


def test_api_native_resource_detail_and_tenant_isolation(api, snap):
    client, ident = api
    report = client.get(f"/api/scans/{ident}/report").json()
    assert report["schema_version"] == "1.1" and all("data" not in r for r in report["resources"])
    target = next(r for r in report["resources"] if r["type"] == "iam_user")
    detail = client.get(f"/api/scans/{ident}/resources/{target['id']}")
    assert detail.status_code == 200, detail.text
    assert detail.json()["data"]["UserName"].startswith("user-")
    assert client.get(f"/api/scans/{ident}/resources/sha256:missing").status_code == 404
    markdown = client.get(f"/api/scans/{ident}/report?format=markdown").text
    assert '"UserName": "user-0000"' in markdown  # Markdown keeps native facts inline
    for path in (f"resources/{target['id']}", "graphs/privesc/subgraph", "graphs/network/page", f"graphs/iam/expand?node=x"):
        assert client.get(f"/api/scans/{ident}/{path}", headers={"Authorization": "Bearer bob"}).status_code == 404


def test_not_applicable_and_empty_rows_aggregate_per_check_unless_requested(tmp_path):
    from collections import Counter
    from peaso.engine import collect_snapshot, evaluate_snapshot, run_scan, scan
    from peaso.reports import render_markdown
    snapshot = collect_snapshot({"provider": "azure", "options": {"demo": True}})
    full = evaluate_snapshot(snapshot, include_not_applicable=True)
    compact = evaluate_snapshot(snapshot, include_not_applicable=False)
    aggregated = Counter(f["status"] for f in full["findings"] if f["status"] in ("NOT_APPLICABLE", "EMPTY"))
    assert aggregated["EMPTY"] and aggregated["NOT_APPLICABLE"]
    assert "finding_aggregates" not in full
    assert not any(f["status"] in ("NOT_APPLICABLE", "EMPTY") for f in compact["findings"])
    assert len(compact["findings"]) == len(full["findings"]) - sum(aggregated.values())
    rows = compact["finding_aggregates"]
    assert sum(r["count"] for r in rows) == sum(aggregated.values()) == compact["stats"]["aggregated_finding_count"]
    per_check = Counter((f["check_id"], f["status"]) for f in full["findings"] if f["status"] in ("NOT_APPLICABLE", "EMPTY"))
    assert {(r["check_id"], r["status"]): r["count"] for r in rows} == dict(per_check)
    assert all(sum(r["scopes"].values()) == r["count"] and 0 < len(r["sample_resource_ids"]) <= 5 for r in rows)
    assert compact["stats"]["by_status"] == full["stats"]["by_status"]
    assert compact["stats"]["finding_count"] == len(compact["findings"])
    assert "Aggregated not-applicable and empty results" in render_markdown(compact)

    request = {"connector": {"provider": "azure", "options": {"demo": True}}}
    report = run_scan(dict(request))
    assert "snapshot" not in report and "finding_aggregates" in report
    assert all("data" not in r for r in report["resources"])
    report, snap = scan(dict(request, include_not_applicable=True))
    assert "finding_aggregates" not in report and snap["snapshot_id"] == report["snapshot_id"]
    assert run_scan(dict(request, embed_snapshot=True))["snapshot"]["snapshot_id"] == report["snapshot_id"]




def _azure_role_definitions(count):
    from peaso.engine import collect_snapshot
    demo = collect_snapshot({"provider": "azure", "options": {"demo": True}})
    collections = []
    for col in demo["collections"]:
        col = json.loads(json.dumps(col))
        if col["type"] == "role_definition":
            base = col["items"][0]
            for i in range(count):
                extra = json.loads(json.dumps(base))
                extra["id"] = f"/subscriptions/demo-subscription/providers/Microsoft.Authorization/roleDefinitions/unused-{i:04d}"
                extra["name"] = f"unused-{i:04d}"
                extra.setdefault("properties", {})["roleName"] = f"Unused role {i:04d}"
                col["items"].append(extra)
        collections.append(col)
    return make_snapshot("azure", demo["scopes"], collections)


def test_unassigned_role_definitions_fold_into_stored_aggregates_with_member_paging(tmp_path):
    snapshot = _azure_role_definitions(30)
    full = evaluate_snapshot(snapshot, categories=["iam_graph"], include_not_applicable=True)
    compact = evaluate_snapshot(snapshot, categories=["iam_graph"], include_not_applicable=False)
    full_defs = [n for n in full["graphs"]["iam"]["nodes"] if n["type"] == "role_definition"]
    assert len(full_defs) == 31
    graph = compact["graphs"]["iam"]
    aggregates = [n for n in graph["nodes"] if n.get("collapsed") == "unreferenced_definitions"]
    assert len(aggregates) == 1 and aggregates[0]["underlying_count"] == 30 and aggregates[0]["aggregate"]
    linked = {e["source"] for e in graph["edges"]} | {e["target"] for e in graph["edges"]}
    kept_defs = [n for n in graph["nodes"] if n["type"] == "role_definition" and not n.get("aggregate")]
    assert len(kept_defs) == 1 and kept_defs[0]["id"] in linked  # the assigned definition stays individual
    assert graph["collapsed_unreferenced"]["node_count"] == 30
    assert len(graph["nodes"]) == len(full["graphs"]["iam"]["nodes"]) - 29 and graph["edges"] == full["graphs"]["iam"]["edges"]
    members = aggregates[0]["members"]
    assert {m["node_id"] for m in members} == {n["id"] for n in full_defs} - {kept_defs[0]["id"]}
    assert all(m["resource_ref"] in {r["id"] for r in compact["resources"]} for m in members)
    assert len(json.dumps(graph)) < len(json.dumps(full["graphs"]["iam"]))
    folded = {m["node_id"] for m in members}
    assert {n["id"]: n for n in graph["nodes"] if not n.get("collapsed")} == {n["id"]: n for n in full["graphs"]["iam"]["nodes"] if n["id"] not in folded}
    projected = project_graph(dict(graph, nodes=graph["nodes"] * 1), 2)
    node = next(n for n in projected["nodes"] if n["id"] == aggregates[0]["id"])
    assert node["aggregate"] and node["underlying_count"] == 30 and node["members_total"] == 30 and len(node["members"]) == 20

    settings = Settings(state_dir=tmp_path / "state", identity_dir=tmp_path / "identity", local_token="local-test-token-0123456789abcdef")
    with TestClient(create_app(settings, authenticator=Identities()), base_url="http://127.0.0.1:8000") as client:
        client.headers["Authorization"] = "Bearer alice"
        connector = client.post("/api/connectors", json={"name": "agg", "provider": "azure", "auth": {}, "scopes": snapshot["scopes"],
                                                         "options": {"snapshot": snapshot}})
        assert connector.status_code == 201, connector.text
        job = client.post("/api/scans", json={"ai_enabled": False, "connector_id": connector.json()["id"], "categories": ["iam_graph"]})
        assert job.status_code == 201, job.text
        assert Worker("collector", settings).run_once() and Worker("analyzer", settings).run_once()
        ident = job.json()["id"]
        stored = client.get(f"/api/scans/{ident}/graphs/iam").json()
        aggregate = next(n for n in stored["nodes"] if n.get("collapsed"))
        page = client.get(f"/api/scans/{ident}/graphs/iam/aggregates/{aggregate['id']}/members", params={"offset": 25, "limit": 10}).json()
        assert page["total"] == 30 and len(page["items"]) == 5 and not page["has_more"]
        detail = client.get(f"/api/scans/{ident}/resources/{page['items'][0]['resource_ref']}")
        assert detail.status_code == 200 and detail.json()["type"] == "role_definition"
        assert client.get(f"/api/scans/{ident}/graphs/iam/aggregates/missing/members").status_code == 404
