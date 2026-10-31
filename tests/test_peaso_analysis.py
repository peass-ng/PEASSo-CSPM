import copy
import json

import pytest
import yaml

from peaso.analysis import analyze, analyze_findings, build_graphs, filter_graph, project_graph
from peaso.analysis.iam import grants
from peaso.analysis.network import public_rules
from peaso.snapshot import make_snapshot, resources
from scripts.peaso_validate_risk_catalog import DEFAULT, validate_bundled_provenance, validate_catalog


def snapshot(provider, facts, *, metadata=None, scopes=None):
    scopes = scopes or ["scope-a"]
    collections = [{"type": kind, "scope": scope, "service": kind,
                    "status": "collected" if items else "empty", "items": items}
                   for (kind, scope), items in facts.items()]
    return make_snapshot(provider, scopes, collections, metadata=metadata,
                         created_at="2026-01-01T00:00:00+00:00")


def test_aws_grants_usage_restrictions_and_immutable_source():
    policy = {"Arn": "arn:aws:iam::111111111111:policy/review", "PermissionsBoundary": {"Arn": "boundary"},
        "Usage": {"activity_count": 0, "window": {"start": "2025-12-01", "end": "2026-01-01"}, "completeness": "partial"},
        "PolicyDocument": {"Statement": [
            {"Effect": "Allow", "Action": "*", "Resource": "*", "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}}},
            {"Effect": "Deny", "Action": "*", "Resource": "*"}]}}
    snap = snapshot("aws", {("iam_policy", "scope-a"): [policy]})
    before = copy.deepcopy(snap)
    result = analyze(snap)
    assert snap == before
    review = next(f for f in result["findings"] if f["check_id"] == "analysis.grant_review")
    assert review["status"] == "MANUAL"
    assert review["evidence"]["effective_access"] == "unknown"
    assert review["evidence"]["restrictions"]["PermissionsBoundary"] == {"Arn": "boundary"}
    assert review["evidence"]["usage"]["completeness"] == "partial"
    assert review["evidence"]["usage"]["safe_to_remove"] is False
    card = next(n["card"] for n in result["graphs"]["iam"]["nodes"] if n["type"] == "iam_policy")
    assert len(card["source_grants"]) == 2
    assert card["source_grants"][1]["allowed_declaration"] is False
    assert review["frameworks"] == ["HackTricks Cloud Best Practices"]
    assert review["resource_id"] == result["resources"][0]["id"]


@pytest.mark.parametrize("allowlist,classification", [([], "unknown"), (["111111111111"], "external"), (["222222222222"], "allowlisted")])
def test_explicit_account_allowlist(allowlist, classification):
    snap = snapshot("aws", {("iam_role", "scope-a"): [{"RoleName": "review", "AssumeRolePolicyDocument": {
        "Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::222222222222:root"},
                       "Condition": {"StringEquals": {"sts:ExternalId": "owner-reviewed"}}}]}}]},
        metadata={"trusted_scope_ids": allowlist})
    graph = analyze(snap)["graphs"]["iam"]
    edge = next(e for e in graph["edges"] if e["type"] == "trust")
    assert edge["evidence"]["classification"] == classification
    assert edge["evidence"]["native_fact"]["Condition"]
    assert edge["evidence"]["effective_access"] == "unknown"


def test_aws_membership_attachment_and_derived_review():
    snap = snapshot("aws", {
        ("iam_policy", "scope-a"): [{"Arn": "arn:aws:iam::111111111111:policy/full", "PolicyDocument": {"Statement": [{"Effect": "Allow", "Action": "*"}]}}],
        ("iam_group", "scope-a"): [{"GroupName": "ops", "AttachedManagedPolicies": [{"PolicyArn": "arn:aws:iam::111111111111:policy/full"}]}],
        ("iam_user", "scope-a"): [{"UserName": "alice", "GroupList": ["ops"]}]})
    graph = build_graphs(snap, resources(snap))["iam"]
    assert {e["type"] for e in graph["edges"]} >= {"member_of", "attached_policy"}
    group = next(n for n in graph["nodes"] if n["type"] == "iam_group")
    assert any(a["state"] == "derived" and a["effective_access"] == "unknown" for a in group["risk_annotations"])
    filtered = filter_graph(graph, risk="high_risk_grant")
    assert group["id"] in filtered["query"]["matched_node_ids"]


def test_gcp_conditions_everyone_and_custom_role():
    snap = snapshot("gcp", {("iam_policy", "projects/a"): [{"name": "projects/a", "bindings": [
        {"role": "roles/editor", "members": ["allAuthenticatedUsers"], "condition": {"expression": "request.time < timestamp('2026-01-01T00:00:00Z')"}}]}],
        ("iam_role", "projects/a"): [{"name": "projects/a/roles/review", "includedPermissions": ["storage.buckets.get"]}]}, scopes=["projects/a"])
    result = analyze(snap)
    edge = next(e for e in result["graphs"]["iam"]["edges"] if e["type"] == "declared_grant")
    assert edge["evidence"]["native_fact"]["condition"]
    assert any(n["type"] == "everyone" for n in result["graphs"]["iam"]["nodes"])
    everyone = next(n for n in result["graphs"]["iam"]["nodes"] if n["type"] == "everyone")
    assert everyone["card"]["observed_bindings"][0]["native_fact"]["condition"]
    assert everyone["card"]["usage"]["completeness"] == "unknown"
    assert any(n["type"] == "iam_role" for n in result["graphs"]["iam"]["nodes"])
    assert all(f["status"] in {"MANUAL", "UNKNOWN"} for f in result["findings"])


def test_azure_notactions_dataactions_and_unknown_tenant():
    snap = snapshot("azure", {("role_definition", "scope-a"): [{"id": "definition", "properties": {"permissions": [
        {"actions": ["*"], "notActions": ["Microsoft.Authorization/*"], "dataActions": ["*"], "notDataActions": ["sensitive/read"]}]}}],
        ("role_assignment", "scope-a"): [{"id": "assignment", "properties": {"principalId": "objectid", "roleDefinitionId": "definition", "condition": "owner-context"}}]},
        metadata={"trusted_scope_ids": ["tenant-a"]})
    result = analyze(snap)
    review = next(f for f in result["findings"] if f["check_id"] == "analysis.grant_review")
    assert review["evidence"]["grants"][0]["native_grant"]["notActions"]
    external = next(f for f in result["findings"] if f["check_id"] == "analysis.principal_exposure")
    assert external["status"] == "UNKNOWN"
    assert external["evidence"]["principals"][0]["classification"] == "unknown"
    assert any(e["type"] == "role_definition" for e in result["graphs"]["iam"]["edges"])


def test_k8s_rbac_subject_role_and_resource_name_constraints():
    snap = snapshot("k8s", {("role", "ns-a"): [{"metadata": {"name": "review", "namespace": "ns-a"},
        "rules": [{"apiGroups": [""], "resources": ["secrets"], "verbs": ["get"], "resourceNames": ["approved"]}]}],
        ("rolebinding", "ns-a"): [{"metadata": {"name": "binding", "namespace": "ns-a"},
            "roleRef": {"name": "review", "kind": "Role"}, "subjects": [{"kind": "Group", "name": "system:authenticated"}]}]}, scopes=["ns-a"])
    result = analyze(snap)
    graph = result["graphs"]["iam"]
    assert len([n for n in graph["nodes"] if n["type"] == "role"]) == 1
    assert any(n["type"] == "everyone" for n in graph["nodes"])
    review = next(f for f in result["findings"] if f["check_id"] == "analysis.grant_review")
    assert review["evidence"]["grants"][0]["native_grant"]["resourceNames"] == ["approved"]


@pytest.mark.parametrize("provider,kind,data,expected", [
    ("aws", "security_group", {"IpPermissions": [{"IpProtocol": "-1", "Ipv6Ranges": [{"CidrIpv6": "::/0"}]}]}, True),
    ("gcp", "firewall", {"allowed": [{"IPProtocol": "tcp"}], "sourceRanges": ["0.0.0.0/0"], "disabled": True}, False),
    ("gcp", "firewall", {"allowed": [{"IPProtocol": "tcp"}], "direction": "EGRESS", "sourceRanges": ["0.0.0.0/0"]}, False),
    ("gcp", "firewall", {"allowed": [{"IPProtocol": "tcp"}], "sourceTags": ["internal"]}, False),
    ("azure", "nsg", {"properties": {"securityRules": [{"properties": {"sourceAddressPrefix": "Internet", "direction": "Inbound", "access": "Deny"}}]}}, False),
    ("azure", "nsg", {"properties": {"securityRules": [{"properties": {"sourceAddressPrefix": "Internet", "direction": "Inbound", "access": "Allow", "priority": 200}}]}}, True),
    ("k8s", "networkpolicy", {"spec": {"podSelector": {}, "ingress": []}}, False),
    ("k8s", "networkpolicy", {"spec": {"podSelector": {}, "ingress": [{}]}}, True),
    ("k8s", "networkpolicy", {"spec": {"ingress": [{"from": [{"ipBlock": {"cidr": "0.0.0.0/0", "except": ["10.0.0.0/8"]}}]}]}}, True),
])
def test_native_public_rule_semantics(provider, kind, data, expected):
    snap = snapshot(provider, {(kind, "scope-a"): [data]})
    candidates = list(public_rules(resources(snap)[0]))
    assert bool(candidates) is expected
    reviews = [f for f in analyze_findings(snap) if f["check_id"] == "analysis.network_review"]
    assert bool(reviews) is expected
    if expected:
        assert reviews[0]["evidence"]["reachability"] == "unknown"


def test_gcp_global_shared_vpc_and_overlapping_scope_ids():
    link = "https://www.googleapis.com/compute/v1/projects/host/global/networks/shared"
    snap = snapshot("gcp", {
        ("network", "projects/host"): [{"name": "shared", "selfLink": link}],
        ("network", "projects/service"): [{"name": "shared", "selfLink": link.replace("host", "service")}],
        ("subnetwork", "projects/service"): [{"name": "same-cidr", "network": link, "ipCidrRange": "10.0.0.0/24"}]}, scopes=["projects/host", "projects/service"])
    graph = build_graphs(snap, resources(snap))["network"]
    networks = [n for n in graph["nodes"] if n["type"] == "network"]
    assert len(networks) == 2
    assert len({n["id"] for n in networks}) == 2
    host = next(n for n in networks if n["scope"] == "projects/host")
    assert any(e["target"] == host["id"] for e in graph["edges"])


def test_k8s_namespace_containment_and_selector_is_not_subnet():
    snap = snapshot("k8s", {("namespace", "*"): [{"metadata": {"name": "team"}}],
        ("pod", "*"): [{"metadata": {"name": "web", "namespace": "team"}, "spec": {"serviceAccountName": "web"}}],
        ("service", "*"): [{"metadata": {"name": "web", "namespace": "team"}, "spec": {"selector": {"app": "web"}}}]}, scopes=["*"])
    graph = build_graphs(snap, resources(snap))["network"]
    assert not any(n["type"] == "subnet" for n in graph["nodes"])
    assert any(e["type"] == "contained_in_namespace" for e in graph["edges"])
    assert any(e["type"] == "declared_selector" for e in graph["edges"])
    assert all(e["layer"] == "structural" for e in graph["edges"])


def test_large_group_projection_counts_and_evidence_refs():
    snap = snapshot("aws", {("iam_group", "scope-a"): [{"GroupName": "large"}],
        ("iam_user", "scope-a"): [{"UserName": f"u{i}", "GroupList": ["large"]} for i in range(1500)]})
    graph = build_graphs(snap, resources(snap), max_nodes=50)["iam"]
    assert graph["projection"]["node_count"] == 1501
    # The budget is used: 1,500 flat principals split into contiguous label ranges, not one bucket per type.
    assert 2 < len(graph["nodes"]) <= 50
    assert sum(n["underlying_count"] for n in graph["nodes"]) == 1501
    assert sorted(ref for n in graph["nodes"] for ref in n["node_refs"]) == sorted(n["id"] for n in build_graphs(snap, resources(snap), max_nodes=None)["iam"]["nodes"])
    ranges = [n for n in graph["nodes"] if n.get("label_range")]
    assert ranges and all(n["type"] == "iam_user" and n["aggregate"] for n in ranges)
    assert sum(e["underlying_count"] for e in graph["edges"]) == 1500
    assert sum(len(e["edge_refs"]) for e in graph["edges"]) == 1500
    assert any(e["evidence"]["sampled_evidence"] for e in graph["edges"])


def test_denied_and_missing_inventory_never_clean():
    snap = make_snapshot("aws", ["scope-a"], [{"type": "iam_policy", "scope": "scope-a", "service": "iam", "status": "denied", "items": []}])
    review = next(f for f in analyze_findings(snap) if f["check_id"] == "analysis.coverage")
    assert review["status"] == "DENIED"
    assert {g["status"] for g in review["evidence"]["gaps"]} == {"denied", "not_collected"}


@pytest.mark.parametrize("provider", ["aws", "gcp", "azure", "k8s"])
def test_engine_real_snapshot_contract_and_offline_demo(provider, monkeypatch):
    from peaso.demo import demo_snapshot
    from peaso.engine import evaluate_snapshot
    # Evaluation is permitted no provider calls, even when criticality is reused.
    import requests
    monkeypatch.setattr(requests, "get", lambda *a, **k: pytest.fail("network call during analysis"))
    snap = demo_snapshot(provider)
    result = evaluate_snapshot(snap)
    assert result["snapshot_id"] == snap["snapshot_id"]
    assert result["graphs"]["iam"]["nodes"]
    assert result["graphs"]["network"]["nodes"]
    if provider == "k8s":
        # The demo cluster only binds an in-cluster ServiceAccount to a read-only Role: no exposure or broad grant.
        assert not any(f["check_id"] == "analysis.principal_exposure" for f in result["findings"])
    else:
        assert any(f["check_id"].startswith("analysis.") for f in result["findings"])
    assert all(f["resource_id"] in {r["id"] for r in result["resources"]} or f["resource_id"] == "inventory" for f in result["findings"] if f["check_id"].startswith("analysis."))


def test_finding_id_stable_across_snapshot_times():
    snap = snapshot("aws", {("iam_policy", "scope-a"): [{"Arn": "review", "PolicyDocument": {"Statement": [{"Effect": "Allow", "Action": "*"}]}}]})
    later = copy.deepcopy(snap)
    later.pop("snapshot_id")
    later["created_at"] = "2026-02-01T00:00:00+00:00"
    first = next(f for f in analyze(snap)["findings"] if f["check_id"] == "analysis.grant_review")
    second = next(f for f in analyze(later)["findings"] if f["check_id"] == "analysis.grant_review")
    assert first["id"] == second["id"]
    assert first["evidence"]["source"]["snapshot_id"] != second["evidence"]["source"]["snapshot_id"]


def test_catalog_schema_source_and_license_disclosure():
    catalog = yaml.safe_load(DEFAULT.read_text())
    assert validate_catalog(catalog) == []
    assert validate_bundled_provenance(catalog) == []
    assert {r["coverage"] for r in catalog["reviews"]} == {"manual-review"}
    assert catalog["sources"][0]["license_status"] == "unverified"
    bad = copy.deepcopy(catalog)
    bad["reviews"][0]["exact_targets"] = ["forbidden extra field"]
    assert any("extra" in e for e in validate_catalog(bad))
    bad = copy.deepcopy(catalog)
    bad["sources"][0]["revision"] = "main"
    assert any("revision" in e for e in validate_catalog(bad))
    bad = copy.deepcopy(catalog)
    bad["sources"][0]["imported_text"] = True
    assert any("copied" in e for e in validate_catalog(bad))


def test_bad_query_and_projection_limits():
    with pytest.raises(ValueError):
        project_graph({"nodes": [], "edges": []}, 0)
    with pytest.raises(ValueError):
        filter_graph({"nodes": [], "edges": []}, risk="proven_chain")


def test_malformed_native_permissions_are_unknown_without_report_failure():
    snap = snapshot("gcp", {("iam_role", "scope-a"): [{"name": "bad", "includedPermissions": [None]}],
        ("network", "scope-a"): [{"name": "valid"}]})
    result = analyze(snap)
    assert any(f["status"] == "UNKNOWN" and f["evidence"].get("reason") == "malformed_native_fact" for f in result["findings"])
    assert result["graphs"]["iam"]["status"] == "partial"
    assert result["graphs"]["network"]["nodes"]


def test_projected_network_preserves_three_vpc_roots_and_containment():
    snap = snapshot("aws", {("vpc", "scope-a"): [{"VpcId": f"vpc-{i}"} for i in range(3)],
        ("subnet", "scope-a"): [{"SubnetId": f"subnet-{i}", "VpcId": f"vpc-{i % 3}", "CidrBlock": "10.0.0.0/24"} for i in range(60)]})
    graph = build_graphs(snap, resources(snap), max_nodes=15)["network"]
    roots = [n for n in graph["nodes"] if n["type"] == "vpc"]
    assert len(roots) == 3
    assert len({n["id"] for n in roots}) == 3
    assert {n["label"] for n in roots} == {"vpc-0", "vpc-1", "vpc-2"}
    root_ids = {n["id"] for n in roots}
    descendants = [n for n in graph["nodes"] if n["type"] == "subnet"]
    assert len(descendants) == 3
    assert all(n["parent_id"] in root_ids and n["underlying_count"] == 20 for n in descendants)


def test_k8s_identical_role_names_across_namespaces_and_cluster_binding():
    snap = snapshot("k8s", {("role", "*"): [
        {"metadata": {"name": "reader", "namespace": "a"}, "rules": []},
        {"metadata": {"name": "reader", "namespace": "b"}, "rules": []}],
        ("clusterrole", "*"): [{"metadata": {"name": "reader"}, "rules": []}],
        ("rolebinding", "*"): [
        {"metadata": {"name": "reader", "namespace": "b"}, "roleRef": {"name": "reader", "kind": "Role"}},
        {"metadata": {"name": "cluster-reader", "namespace": "b"}, "roleRef": {"name": "reader", "kind": "ClusterRole"}}]}, scopes=["*"])
    graph = build_graphs(snap, resources(snap))["iam"]
    assert len([n for n in graph["nodes"] if n["type"] == "role"]) == 2
    assert len([n for n in graph["nodes"] if n["type"] == "clusterrole"]) == 1
    edges = [e for e in graph["edges"] if e["type"] == "role_binding"]
    assert len(edges) == 2
    actual = {n["id"] for n in graph["nodes"] if n["type"] in {"role", "clusterrole"} and "card" in n}
    assert all(e["target"] in actual for e in edges)


def test_gcp_embedded_interfaces_have_native_evidence_and_host_network_parent():
    link = "https://www.googleapis.com/compute/v1/projects/host/global/networks/shared"
    snap = snapshot("gcp", {("network", "projects/host"): [{"name": "shared", "selfLink": link}],
        ("instance", "projects/service"): [{"name": "vm", "networkInterfaces": [{"name": "nic0", "network": link}]}]},
        scopes=["projects/host", "projects/service"])
    graph = build_graphs(snap, resources(snap))["network"]
    interface = next(n for n in graph["nodes"] if n["type"] == "network_interface")
    host = next(n for n in graph["nodes"] if n["type"] == "network")
    assert interface["parent_id"] == host["id"]
    assert interface["evidence"]["native_resource"]["network"] == link
    assert any(e["type"] == "attached_interface" and e["target"] == interface["id"] for e in graph["edges"])


@pytest.mark.parametrize("kind,wrapper", [
    ("bucket", {"Policy": {"Policy": {"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::review/*"}]}}}),
    ("ecr_repository", {"Policy": {"policyText": {"Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::222222222222:root"}, "Action": "ecr:DescribeImages"}]}}}),
    ("sqs_queue", {"Attributes": {"Policy": json.dumps({"Statement": [{"Effect": "Allow", "Principal": "*"}]})}}),
])
def test_native_wrapped_resource_policy_principals_have_attribution(kind, wrapper):
    snap = snapshot("aws", {(kind, "scope-a"): [{"Arn": f"arn:aws:test::111111111111:{kind}/review", **wrapper}]},
        metadata={"trusted_scope_ids": ["111111111111"]})
    result = analyze(snap)
    review = next(f for f in result["findings"] if f["check_id"] == "analysis.principal_exposure")
    assert review["evidence"]["principals"][0]["classification"] in {"public", "external"}
    assert review["evidence"]["principals"][0]["source"]["path"].endswith(".Principal")
    assert any(e["type"] == "declared_grant" for e in result["graphs"]["iam"]["edges"])


def test_scan_context_reuses_derivations_and_isolates_other_snapshots(monkeypatch):
    from peaso.analysis import analysis_context
    from peaso.analysis import iam
    snap = snapshot("aws", {("iam_policy", "scope-a"): [{"Arn": "review", "PolicyDocument": {"Statement": [{"Effect": "Allow", "Action": "*"}]}}]})
    inventory = resources(snap)
    calls = []
    original = iam._grants
    def counted(resource):
        calls.append(resource["id"])
        return original(resource)
    monkeypatch.setattr(iam, "_grants", counted)
    with analysis_context(snap):
        analyze_findings(snap, inventory)
        build_graphs(snap, inventory)
    assert len(calls) == 1
    changed = snapshot("aws", {("iam_policy", "scope-a"): [{"Arn": "review", "PolicyDocument": {"Statement": [{"Effect": "Deny", "Action": "*"}]}}]})
    assert not any(f["check_id"] == "analysis.grant_review" for f in analyze_findings(changed))
    assert len(calls) == 2


def test_unrecognized_permission_criticality_is_unknown_not_low():
    from peaso.analysis.iam import permission_severity
    assert permission_severity("aws", "unknownvendor:UnmappedOpaqueOperation") is None
    snap = snapshot("aws", {("iam_policy", "scope-a"): [{"Arn": "review", "PolicyDocument": {"Statement": [{"Effect": "Allow", "Action": "unknownvendor:UnmappedOpaqueOperation"}]}}]})
    result = analyze(snap)
    unknown = next(f for f in result["findings"] if f["evidence"].get("reason") == "permission_criticality_unknown")
    assert unknown["status"] == "UNKNOWN"
    assert unknown["severity"] == "info"
    card = next(n["card"] for n in result["graphs"]["iam"]["nodes"] if n["type"] == "iam_policy")
    assert card["source_grants"][0]["criticality_state"] == "unknown"


def test_hosted_catalog_excludes_wholly_manual_analysis_but_keeps_archived_reviews():
    from peaso import engine
    from peaso.analysis import MANUAL_ONLY_ANALYSIS_CHECK_IDS
    snap = snapshot("aws", {("iam_policy", "scope-a"): [{
        "Arn": "arn:aws:iam::123456789012:policy/review",
        "PolicyDocument": {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]},
    }]})
    assert any(f["check_id"] == "analysis.grant_review" for f in analyze_findings(snap))
    assert not MANUAL_ONLY_ANALYSIS_CHECK_IDS.intersection(f["check_id"] for f in analyze_findings(snap, include_manual_only=False))
    assert not MANUAL_ONLY_ANALYSIS_CHECK_IDS.intersection(c["id"] for c in engine.get_catalog()["checks"])
    for check_id in MANUAL_ONLY_ANALYSIS_CHECK_IDS:
        with pytest.raises(ValueError, match="unknown check ID"):
            engine.plan_collection({"connector": {"provider": "aws"}, "checks": [check_id]})


@pytest.mark.parametrize("condition,expected", [(None, "FAIL"), ({"StringEquals": {"aws:SourceVpce": "vpce-fixture"}}, "MANUAL")])
def test_hosted_analysis_retains_conditional_checks(condition, expected):
    from peaso import engine
    statement = {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::fixture/*"}
    if condition:
        statement["Condition"] = condition
    snap = snapshot("aws", {("bucket", "scope-a"): [{"Name": "fixture", "Policy": {
        "collection_status": "collected", "Policy": {"Statement": [statement]}}}]})
    report = engine.evaluate_snapshot(snap, checks=["analysis.principal_exposure"])
    finding = next(f for f in report["findings"] if f["check_id"] == "analysis.principal_exposure")
    assert finding["status"] == expected


def test_azure_tenant_and_child_scope_inventories_cover_each_subscription():
    from peaso.analysis import REQUIRED_TYPES
    sub, tenant = "/subscriptions/00000000-0000-0000-0000-000000000001", "/tenants/00000000-0000-0000-0000-000000000002"
    site = sub + "/resourceGroups/rg/providers/Microsoft.Web/sites/app"
    collections = []
    for kind in REQUIRED_TYPES["azure"]["least_privilege"]:
        where = tenant if kind.startswith("directory_") or kind == "tenant" else site if kind == "app_service_config" else sub
        collections.append({"type": kind, "scope": where, "service": kind, "status": "empty", "items": []})
    snap = make_snapshot("azure", [sub], collections, created_at="2026-01-01T00:00:00+00:00")
    assert not [f for f in analyze_findings(snap) if f["check_id"] == "analysis.coverage" and f["evidence"].get("gaps")]
    collections[0] = dict(collections[0], status="denied")
    gaps = [f for f in analyze_findings(make_snapshot("azure", [sub], collections, created_at="2026-01-01T00:00:00+00:00"))
            if f["check_id"] == "analysis.coverage" and f["evidence"].get("gaps")]
    assert gaps and gaps[0]["evidence"]["gaps"] == [{"type": collections[0]["type"], "status": "denied"}]
