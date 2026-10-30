"""Regression tests for the privesc audit fixes (historical gap review) and the K8s live-QA findings:

* IAM Condition evaluation (proven -> edge kept, excluded -> edge dropped, undecidable -> conditional/MANUAL);
* machine-checked `preconditions` (missing facts -> unresolved/UNKNOWN, never FAIL);
* service-linked roles are not sources; admins are short-circuited; management-to-member needs another account;
* K8s: namespaced TokenRequest grants, EKS/OpenShift preconditions, legacy token Secrets, phantom ServiceAccounts,
  per-technique group labels;
* scale benchmarks (10x always runs; 100x needs PEASO_PRIVESC_BENCH=1).
"""
from __future__ import annotations

import importlib.util
import os
import resource
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from peaso import privesc
from peaso.privesc.versioned_catalog import _verified_prior
from peaso.privesc.effective_permissions import ANY, AllTargets, Node
from peaso.privesc.effective_permissions import aws_conditions as C
from peaso.privesc.effective_permissions.aws import AwsModel
from peaso.privesc.effective_permissions.k8s import K8sModel

FIXTURES = Path(__file__).parent / "fixtures" / "privesc"
ACCOUNT, OTHER = "111111111111", "222222222222"
REGION = "us-east-1"


# --------------------------------------------------------------------------- helpers
def snapshot(provider, collections):
    cols = [{"type": t, "scope": scope, "service": t, "status": status, "items": items, "error": None}
            for t, scope, items, status in collections]
    return {"schema_version": 1, "provider": provider, "scopes": sorted({c["scope"] for c in cols}),
            "collections": cols, "metadata": {}}


def real(snap, *ids, **kw):
    """Analyze with the shipped catalog restricted to the given technique ids."""
    entries = [e for e in privesc.catalog()["entries"] if e["id"] in ids]
    assert {e["id"] for e in entries} == set(ids)
    return privesc.analyze(snap, entries=entries, **kw)


def archived_real(snap, technique_id, **kw):
    """Exercise a historical rule without admitting it to the active catalog."""
    assert technique_id not in {e["id"] for e in privesc.catalog()["entries"]}
    prior, _ = _verified_prior()
    return privesc.analyze(snap, entries=[prior[technique_id]], **kw)


def reached(result, source, technique=None):
    nodes = {n["id"]: n for n in result["graph"]["nodes"]}
    out = {}
    for edge in result["graph"]["edges"]:
        if edge["source"] != source or (technique and technique not in edge["techniques"]):
            continue
        node = nodes.get(edge["target"], {})
        for member in (node.get("members") if node.get("kind") == "aggregate" else [edge["target"]]) or []:
            if member != source:  # a full-scope group lists every candidate; the source is not its own target
                out[member] = edge["confidence"]
    return out


def statuses(result, technique):
    return sorted(f["status"] for f in result["findings"] if f["check_id"] == technique)


def policy(*statements):
    return {"Version": "2012-10-17", "Statement": list(statements)}


def user(name, *statements, account=ACCOUNT, tags=None):
    return {"UserName": name, "Arn": f"arn:aws:iam::{account}:user/{name}", "Path": "/", "GroupList": [],
            "UserPolicyList": [{"PolicyName": "p", "PolicyDocument": policy(*statements)}] if statements else [],
            "AttachedManagedPolicies": [], "Tags": tags or []}


def role(name, service="ec2.amazonaws.com", *statements, account=ACCOUNT, path="/", profile=True):
    arn_path = path if path != "/" else "/"
    return {"RoleName": name, "Arn": f"arn:aws:iam::{account}:role{arn_path}{name}", "Path": path,
            "AssumeRolePolicyDocument": policy({"Effect": "Allow", "Principal": {"Service": service}, "Action": "sts:AssumeRole"}),
            "RolePolicyList": [{"PolicyName": "p", "PolicyDocument": policy(*statements)}] if statements else [],
            "AttachedManagedPolicies": [],
            "InstanceProfileList": [{"Arn": f"arn:aws:iam::{account}:instance-profile/{name}"}] if profile else []}


def aws(users=(), roles=(), extra=()):
    scope = f"{ACCOUNT}/{REGION}"
    return snapshot("aws", [("iam_user", scope, list(users), "collected"), ("iam_role", scope, list(roles), "collected"),
                            ("iam_group", scope, [], "empty"), ("iam_policy", scope, [], "empty"),
                            ("scp_policy", scope, [], "empty"), *extra])


PASS_RUN = [{"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"},
            {"Effect": "Allow", "Action": "ec2:RunInstances", "Resource": "*"}]
ALICE = f"arn:aws:iam::{ACCOUNT}:user/alice"
EC2_ROLE = f"arn:aws:iam::{ACCOUNT}:role/ec2-role"


# ------------------------------------------------------------------ IAM conditions
def _ctx(action="iam:passrole", passed_to=("ec2.amazonaws.com",), tags=None, resource=None, resource_tags=None, org=None):
    principal = Node(ALICE, "aws_user", "aws", ACCOUNT, "alice", attrs={"tags": tags} if tags is not None else {})
    return C.Context(principal=principal, action=action, resource=resource, passed_to=passed_to,
                     resource_tags=resource_tags, org_id=org)


@pytest.mark.parametrize("condition,ctx,effect,expected", [
    ({"StringEquals": {"iam:PassedToService": "ec2.amazonaws.com"}}, _ctx(), "allow", True),
    ({"StringEquals": {"iam:PassedToService": "lambda.amazonaws.com"}}, _ctx(), "allow", False),
    ({"StringEquals": {"iam:PassedToService": "lambda.amazonaws.com"}},
     _ctx(passed_to=("ec2.amazonaws.com", "lambda.amazonaws.com")), "allow", True),
    ({"ArnLike": {"iam:AssociatedResourceArn": "arn:aws:lambda:*:*:function:*"}}, _ctx(), "allow", False),
    ({"ArnLike": {"iam:AssociatedResourceArn": "arn:aws:ec2:*:*:instance/*"}}, _ctx(), "allow", None),
    ({"StringEquals": {"aws:PrincipalTag/team": "a"}}, _ctx(tags={"team": "a"}), "allow", True),
    ({"StringEquals": {"aws:PrincipalTag/team": "b"}}, _ctx(tags={"team": "a"}), "allow", False),
    ({"StringEquals": {"aws:PrincipalTag/team": "a"}}, _ctx(), "allow", None),            # principal tags unknown
    ({"StringEquals": {"aws:ResourceTag/env": "prod"}}, _ctx(resource_tags={"env": "prod"}), "allow", True),
    ({"StringEquals": {"aws:ResourceTag/env": "prod"}}, _ctx(resource_tags={"env": "dev"}), "allow", False),
    ({"StringEquals": {"aws:ResourceTag/env": "prod"}}, _ctx(), "allow", None),
    ({"ArnLike": {"aws:SourceArn": "arn:aws:*"}}, _ctx(), "allow", False),                 # absent on a direct call
    ({"StringNotEquals": {"aws:SourceAccount": ACCOUNT}}, _ctx(), "deny", True),           # negated + absent -> applies
    ({"StringEqualsIfExists": {"aws:SourceAccount": OTHER}}, _ctx(), "allow", True),
    ({"StringEquals": {"aws:RequestedRegion": "eu-west-1"}}, _ctx(), "allow", False),      # IAM is global: us-east-1
    ({"StringEquals": {"aws:RequestedRegion": "eu-west-1"}}, _ctx(action="ec2:runinstances"), "allow", None),
    ({"Null": {"aws:RequestTag/owner": "false"}}, _ctx(), "allow", True),                  # requester adds the tag
    ({"Null": {"aws:RequestTag/owner": "false"}}, _ctx(), "deny", False),                  # ... or omits it
    ({"NumericLessThan": {"aws:MultiFactorAuthAge": "3600"}}, _ctx(), "allow", None),
    ({"StringEquals": {"aws:PrincipalOrgID": "o-abc"}}, _ctx(), "allow", None),
    ({"StringEquals": {"aws:PrincipalOrgID": "o-abc"}}, _ctx(org="o-abc"), "allow", True),
])
def test_condition_three_valued(condition, ctx, effect, expected):
    verdict, reasons = C.evaluate(condition, ctx, effect)
    assert verdict is expected
    if verdict is None:
        assert reasons


def test_condition_policy_variable_substitution():
    ctx = _ctx(action="iam:createaccesskey")
    assert C.substitute("arn:aws:iam::*:user/${aws:username}", ctx) == "arn:aws:iam::*:user/alice"
    assert C.substitute("arn:aws:iam::*:user/${aws:PrincipalTag/x}", ctx) is None


def test_condition_excluding_technique_drops_edge_and_missing_launch_stays_unknown():
    excluded = {"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*",
                "Condition": {"StringEquals": {"iam:PassedToService": "lambda.amazonaws.com"}}}
    result = real(aws([user("alice", excluded, PASS_RUN[1])], [role("ec2-role")]), "aws-ec2-passrole-runinstances")
    assert reached(result, ALICE) == {}
    mfa = {"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*", "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}}}
    result = real(aws([user("alice", mfa, PASS_RUN[1])], [role("ec2-role")]),
                  "aws-ec2-passrole-runinstances", include_unknown=True)
    assert reached(result, ALICE) == {}
    assert statuses(result, "aws-ec2-passrole-runinstances") == ["UNKNOWN"]
    assert any("ec2_runinstances_role_execution_evidence_missing_or_conflicting" in row.get("reason", "")
               for row in result["coverage"])


def test_proven_passrole_condition_still_needs_ec2_launch_witness():
    ok = {"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*",
          "Condition": {"StringEquals": {"iam:PassedToService": "ec2.amazonaws.com"}}}
    result = real(aws([user("alice", ok, PASS_RUN[1])], [role("ec2-role")]),
                  "aws-ec2-passrole-runinstances", include_unknown=True)
    assert reached(result, ALICE) == {}
    assert statuses(result, "aws-ec2-passrole-runinstances") == ["UNKNOWN"]


# -------------------------------------------------------------------- preconditions
SEND = [{"Effect": "Allow", "Action": "ssm:SendCommand", "Resource": "*"}]


def _instances(state="running", ping="Online", ssm=True):
    scope = f"{ACCOUNT}/{REGION}"
    out = [("instance", scope, [{"InstanceId": "i-1", "State": {"Name": state},
                                 "IamInstanceProfile": {"Arn": f"arn:aws:iam::{ACCOUNT}:instance-profile/ec2-role"}}], "collected")]
    if ssm:
        out.append(("ssm_managed_instance", scope, [{"InstanceId": "i-1", "PingStatus": ping}], "collected"))
    return out


def test_precondition_ssm_running_managed_instance_reaches_role():
    result = real(aws([user("alice", *SEND)], [role("ec2-role")], _instances()), "aws-ssm-sendcommand")
    assert EC2_ROLE in reached(result, ALICE)


@pytest.mark.parametrize("extra", [_instances(state="stopped"), _instances(ping="ConnectionLost")])
def test_precondition_excluding_facts_drop_the_edge(extra):
    result = real(aws([user("alice", *SEND)], [role("ec2-role")], extra), "aws-ssm-sendcommand")
    assert reached(result, ALICE) == {}
    assert statuses(result, "aws-ssm-sendcommand") == []


@pytest.mark.parametrize("extra", [[], _instances(ssm=False)])
def test_precondition_missing_facts_are_unknown_not_fail(extra):
    result = real(aws([user("alice", *SEND)], [role("ec2-role")], extra), "aws-ssm-sendcommand", include_unknown=True)
    assert statuses(result, "aws-ssm-sendcommand") == ["UNKNOWN"]
    unresolved = [n for n in result["graph"]["nodes"] if n.get("unresolved")]
    assert unresolved and all(n["members"] == [] for n in unresolved)


def test_precondition_target_in_other_account():
    snap = aws([user("alice")], [role("here"), role("there", account=OTHER)])
    model = AwsModel(snap)
    candidates = {n.id: n for n in model.targets("aws_role")}
    got = model.precondition("target_in_other_account", candidates, model.principals[ALICE])
    assert set(got) == {f"arn:aws:iam::{OTHER}:role/there"}


def test_schema_rejects_unknown_precondition():
    from peaso.privesc.schema import validate_entry
    entry = next(e for e in privesc.catalog()["entries"] if e["id"] == "aws-ssm-sendcommand")
    entry = {k: v for k, v in entry.items() if not k.startswith("_")}
    assert not any("precondition" in e for e in validate_entry(entry)[0])
    errors = validate_entry({**entry, "preconditions": ["no_such_fact"]})[0]
    assert any("no_such_fact" in e for e in errors)
    errors = validate_entry({**entry, "preconditions": ["k8s_openshift_cluster"]})[0]    # wrong provider
    assert any("k8s_openshift_cluster" in e for e in errors)


# ------------------------------------------------------- SLR sources and admin skip
def test_service_linked_role_is_not_a_source():
    slr = role("AWSServiceRoleForX", "x.amazonaws.com", *PASS_RUN, path="/aws-service-role/x.amazonaws.com/", profile=False)
    result = real(aws([], [slr, role("ec2-role")]), "aws-ec2-passrole-runinstances")
    assert result["graph"]["edges"] == []
    assert result["stats"]["skipped_service_managed_sources"] >= 1


def test_admin_source_is_short_circuited():
    admin = user("root-ish", {"Effect": "Allow", "Action": "*", "Resource": "*"})
    result = real(aws([admin], [role("ec2-role")]), "aws-ec2-passrole-runinstances")
    sid = f"arn:aws:iam::{ACCOUNT}:user/root-ish"
    assert reached(result, sid, "aws-ec2-passrole-runinstances") == {}
    assert result["stats"]["skipped_admin_source_evaluations"] >= 1
    assert [f["status"] for f in result["findings"] if f["check_id"] == "admin-equivalent"] == ["FAIL"]
    full = real(aws([admin], [role("ec2-role")]), "aws-ec2-passrole-runinstances", include_admin_sources=True)
    assert reached(full, sid, "aws-ec2-passrole-runinstances") == {}


def test_memoized_sources_match_individual_evaluation():
    users = [user(f"u{i}", *PASS_RUN) for i in range(5)]
    snap = aws(users, [role(f"ec2-role{i}") for i in range(4)])
    memo = real(snap, "aws-ec2-passrole-runinstances")
    original = AwsModel.source_memo_key
    AwsModel.source_memo_key = lambda self, source: None
    try:
        plain = real(snap, "aws-ec2-passrole-runinstances")
    finally:
        AwsModel.source_memo_key = original
    key = lambda r: sorted((e["source"], e["target"], e["confidence"]) for e in r["graph"]["edges"])
    assert key(memo) == key(plain)
    for u in users:
        assert reached(memo, u["Arn"]) == {}


# ----------------------------------------------------------------------- Kubernetes
def kobj(kind, name, ns=None, **body):
    meta = {"name": name, **({"namespace": ns} if ns else {})}
    meta.update(body.pop("meta", {}))
    return {"kind": kind, "metadata": meta, "provenance": {"cluster_id": "c1"}, **body}


def k8s(roles=(), bindings=(), provider_id="kind://docker/c1/n1", groups=("apps", "rbac.authorization.k8s.io"),
        secrets=None, configmaps=(), sas=None):
    sas = sas if sas is not None else [kobj("ServiceAccount", n, "a") for n in ("default", "builder", "ca")]
    cols = [("role", "*", [r for r in roles if r["kind"] == "Role"], "collected"),
            ("clusterrole", "*", [r for r in roles if r["kind"] == "ClusterRole"], "collected"),
            ("rolebinding", "*", [b for b in bindings if b["kind"] == "RoleBinding"], "collected"),
            ("clusterrolebinding", "*", [b for b in bindings if b["kind"] == "ClusterRoleBinding"], "collected"),
            ("serviceaccount", "*", sas, "collected"),
            ("namespace", "*", [kobj("Namespace", n) for n in ("a", "default", "kube-system")], "collected"),
            ("pod", "*", [], "empty"),
            ("node", "*", [kobj("Node", "n1", spec={"providerID": provider_id})], "collected"),
            ("api_discovery", "*", [{"groups": [{"name": g} for g in groups], "provenance": {"cluster_id": "c1"}}], "collected"),
            ("configmap_metadata", "*", list(configmaps), "collected")]
    if secrets is not None:
        cols.append(("secret_metadata", "*", secrets, "collected"))
    return snapshot("k8s", cols)


def grant(name, ns, rules, subject):
    kind = "Role" if ns else "ClusterRole"
    return (kobj(kind, name, ns, rules=rules),
            kobj("RoleBinding" if ns else "ClusterRoleBinding", name + "-b", ns, roleRef={"kind": kind, "name": name},
                 subjects=[subject]))


def test_k8s_namespaced_role_grants_token_request():
    r, b = grant("tok", "a", [{"apiGroups": [""], "resources": ["serviceaccounts/token"], "verbs": ["create"]}],
                 {"kind": "ServiceAccount", "name": "default", "namespace": "a"})
    result = real(k8s([r], [b]), "k8s-rbac-serviceaccounts-token-create")
    assert set(reached(result, "k8s:c1:sa:a:default")) == {"k8s:c1:sa:a:builder", "k8s:c1:sa:a:ca"}


def test_k8s_namespace_bind_path_requires_exact_cluster_admin_role():
    technique = "k8s-rbac-bind-rolebinding-namespace"
    source = "k8s:c1:sa:a:default"
    for role_name, expected in (("view", set()),
                                ("cluster-admin", {"k8s:c1:sa:a:builder", "k8s:c1:sa:a:ca"})):
        role, binding = grant("binder", None, [
            {"apiGroups": ["rbac.authorization.k8s.io"], "resources": ["clusterroles"],
             "verbs": ["bind"], "resourceNames": [role_name]},
            {"apiGroups": ["rbac.authorization.k8s.io"], "resources": ["rolebindings"],
             "verbs": ["create"]},
        ], {"kind": "ServiceAccount", "name": "default", "namespace": "a"})
        cluster_admin = kobj("ClusterRole", "cluster-admin", rules=[
            {"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}])
        result = real(k8s([role, cluster_admin], [binding]), technique)
        assert set(reached(result, source, technique)) == expected


OPENSHIFT_IDS = ("k8s-openshift-privileged-default-projects", "k8s-openshift-scc-via-namespace-sa")


def _cm_writer():
    return grant("cm", "kube-system", [{"apiGroups": [""], "resources": ["configmaps"], "verbs": ["update", "patch", "create"]}],
                 {"kind": "User", "name": "dev"})


def test_k8s_openshift_techniques_need_openshift_api():
    r, b = grant("pods", "default", [{"apiGroups": [""], "resources": ["pods"], "verbs": ["create"]}],
                 {"kind": "User", "name": "dev"})
    plain = real(k8s([r], [b]), *OPENSHIFT_IDS)
    assert [f for f in plain["findings"] if f["check_id"] in OPENSHIFT_IDS] == []
    assert not any("openshift" in str(c.get("reason")) for c in plain["coverage"])
    ocp = real(k8s([r], [b], groups=("apps", "security.openshift.io")), *OPENSHIFT_IDS)
    assert statuses(ocp, "k8s-openshift-privileged-default-projects") == ["MANUAL"]
    collected = k8s([r], [b], groups=("apps", "security.openshift.io"))
    collected["collections"].extend(snapshot("k8s", [
        ("admission_policy", "*", [], "empty"),
        ("admission_configuration", "*", [], "empty"),
    ])["collections"])
    next(c for c in collected["collections"] if c["type"] == "node")["items"][0]["status"] = {
        "conditions": [{"type": "Ready", "status": "True"}]}
    assert statuses(real(collected, "k8s-openshift-privileged-default-projects"),
                    "k8s-openshift-privileged-default-projects") == ["FAIL"]
    no_discovery = k8s([r], [b])
    no_discovery["collections"] = [c for c in no_discovery["collections"] if c["type"] != "api_discovery"]
    assert statuses(real(no_discovery, "k8s-openshift-privileged-default-projects", include_unknown=True),
                    "k8s-openshift-privileged-default-projects") == ["UNKNOWN"]


def _secret(name, sa, kind="kubernetes.io/service-account-token"):
    return {"metadata": {"name": name, "namespace": "a", "annotations": {"kubernetes.io/service-account.name": sa}},
            "type": kind, "provenance": {"cluster_id": "c1"}}


def test_k8s_legacy_token_metadata_alone_does_not_prove_usable_credentials():
    r, b = grant("read", "a", [{"apiGroups": [""], "resources": ["secrets"], "verbs": ["list"]}], {"kind": "User", "name": "dev"})
    tid = "k8s-rbac-secrets-read-legacy-sa-token"
    result = real(k8s([r], [b], secrets=[_secret("ca-token", "ca"), _secret("x", "builder", "Opaque")]), tid)
    assert reached(result, "k8s:c1:user:dev", tid) == {}
    unknown = real(k8s([r], [b]), tid)                                              # secret metadata not collected
    assert reached(unknown, "k8s:c1:user:dev", tid) == {}


def test_k8s_phantom_service_account_only_for_dangling_and_impersonation():
    r, b = grant("pods", "a", [{"apiGroups": [""], "resources": ["pods"], "verbs": ["create"]},
                               {"apiGroups": [""], "resources": ["serviceaccounts"], "verbs": ["impersonate", "create"]}],
                 {"kind": "User", "name": "dev"})
    secret_reader = kobj("Role", "secret-reader", "a", rules=[
        {"apiGroups": [""], "resources": ["secrets"], "verbs": ["get"]}])
    ghost = kobj("RoleBinding", "ghost-b", "a", roleRef={"kind": "Role", "name": "secret-reader"},
                 subjects=[{"kind": "ServiceAccount", "name": "ghost", "namespace": "a"}])
    result = real(k8s([r, secret_reader], [b, ghost]), "k8s-workloads-pods-create", "k8s-rbac-impersonate-serviceaccounts",
                  "k8s-rbac-dangling-serviceaccount-reference")
    phantom = "k8s:c1:sa:a:ghost"
    assert phantom not in reached(result, "k8s:c1:user:dev", "k8s-workloads-pods-create")
    assert phantom in reached(result, "k8s:c1:user:dev", "k8s-rbac-impersonate-serviceaccounts")
    assert set(reached(result, "k8s:c1:user:dev", "k8s-rbac-dangling-serviceaccount-reference")) == {phantom}


def _sa_node_readers(names=("builder", "ca")):
    """Bind builder and ca to a cluster-scoped read that a namespaced grant cannot hold.
    Impersonating a ServiceAccount is an escalation only when that account adds a right."""
    role = kobj("ClusterRole", "node-reader", rules=[{"apiGroups": [""], "resources": ["nodes"], "verbs": ["get"]}])
    binding = kobj("ClusterRoleBinding", "node-reader-b", roleRef={"kind": "ClusterRole", "name": "node-reader"},
                   subjects=[{"kind": "ServiceAccount", "name": n, "namespace": "a"} for n in names])
    return role, binding


def test_k8s_group_labels_are_per_technique_and_namespace():
    r, b = grant("ns-admin", "a", [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}], {"kind": "User", "name": "dev"})
    # Every ServiceAccount in the namespace adds a right, so each technique reaches the whole group.
    reader, reader_binding = _sa_node_readers(("default", "builder", "ca"))
    tids = ("k8s-workloads-pods-create", "k8s-rbac-serviceaccounts-token-create", "k8s-rbac-impersonate-serviceaccounts")
    result = real(k8s([r, reader], [b, reader_binding]), *tids)
    nodes = {n["id"]: n for n in result["graph"]["nodes"]}
    labels = {}
    for edge in result["graph"]["edges"]:
        target = nodes[edge["target"]]
        if target.get("kind") == "aggregate":
            for technique in edge["techniques"]:
                labels[technique] = target["label"]
    assert set(labels) == set(tids)
    assert len(set(labels.values())) == len(tids)                       # no label borrowed from another technique
    assert all(label.endswith("c1/a") for label in labels.values())     # the namespace is rendered


def test_k8s_qa_admin_set_and_no_cloud_flavour_fails():
    """Shape of the kind live-QA cluster: only real cluster-admins are admin-equivalent."""
    admin = kobj("ClusterRole", "cluster-admin", rules=[{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}])
    crb = kobj("ClusterRoleBinding", "admins", roleRef={"kind": "ClusterRole", "name": "cluster-admin"},
               subjects=[{"kind": "Group", "name": "system:masters"}, {"kind": "ServiceAccount", "name": "ca", "namespace": "a"}])
    r, b = _cm_writer()
    result = privesc.analyze(k8s([admin, r], [crb, b]))
    admins = {e["source"] for e in result["graph"]["edges"] if "admin-equivalent" in e["techniques"]}
    assert admins == {"k8s:c1:sa:a:ca"}  # system:masters is control-plane managed: an admin target, never a source
    flavoured = [f for f in result["findings"] if f["status"] == "FAIL" and (".eks" in f["check_id"] or "openshift" in f["check_id"]
                                                                              or f["check_id"].startswith("k8s-cloud-eks"))]
    assert flavoured == []


# ------------------------------------------------------------------------ benchmarks
def _synthetic():
    spec = importlib.util.spec_from_file_location("synthetic_aws", FIXTURES / "synthetic_aws.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _bench(scale):
    synthetic = _synthetic()
    snap = synthetic.snapshot(scale)
    privesc.catalog()
    before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    started = time.perf_counter()
    result = privesc.analyze(snap)
    elapsed = time.perf_counter() - started
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    unit = 1 if os.uname().sysname == "Darwin" else 1024      # ru_maxrss: bytes on macOS, KiB on Linux
    grown_mb = (peak - before) * unit / 2 ** 20
    print(f"\nprivesc synthetic {scale}x: {synthetic.principals(snap)} principals, {elapsed:.2f}s, "
          f"+{grown_mb:.0f} MB peak RSS, {result['stats']['edges']} edges, stats={result['stats']['timing_seconds']}")
    return synthetic.principals(snap), elapsed, grown_mb, result


def test_passrole_request_context_bulk_matches_each_role_across_accounts():
    model = AwsModel(_synthetic().snapshot(1))
    roles = model.targets("aws_role")
    model.current_cset = SimpleNamespace(id="all_roles", kind="aws_role",
                                         members={role.id: role for role in roles})
    model.current_entry = {}
    model.current_selector = {}
    req = {"action": "iam:PassRole", "request_context": {"iam:PassedToService": "ec2.amazonaws.com"}}

    def signature(grant):
        return None if grant is None else (grant.confidence, grant.refs, grant.conditions, grant.permission_refs)

    for username in ("user3-0", "user5-0"):
        source = model.principals[f"arn:aws:iam::{ACCOUNT}:user/{username}"]
        bulk = model.check_targets(source, req, "{target.arn}", model.current_cset.members.values())
        for role in roles:
            bulk_grant = bulk.grant if isinstance(bulk, AllTargets) else bulk.get(role.id)
            individual_grant = model.check_targets(source, req, "{target.arn}", [role]).get(role.id)
            assert signature(bulk_grant) == signature(individual_grant), (username, role.id)


def test_bench_privesc_10x_aws():
    principals, elapsed, grown_mb, result = _bench(10)
    assert principals >= 3130
    assert result["stats"]["memoized_source_evaluations"] > 0
    assert elapsed < 20
    assert grown_mb < 1024


@pytest.mark.skipif(os.environ.get("PEASO_PRIVESC_BENCH") != "1", reason="set PEASO_PRIVESC_BENCH=1 for the 100x benchmark")
def test_bench_privesc_100x_aws():
    principals, elapsed, grown_mb, _ = _bench(100)
    assert principals >= 31300
    assert elapsed < 300


# ------------------------------------------- shared placeholders (real GCP scan: 415k unknown edges)
def _gcp_projects(n_projects, users, extra_bindings=None):
    cols = []
    for i in range(n_projects):
        scope = f"projects/p{i}"
        bindings = [{"role": "roles/viewer", "members": [f"user:{u}@x.com" for u in users]}] + list((extra_bindings or {}).get(i, []))
        cols += [("project", scope, [{"projectId": f"p{i}", "name": f"projects/{100 + i}", "_ancestry": []}], "collected"),
                 ("iam_policy", scope, [{"name": scope, "bindings": bindings}], "collected"),
                 ("iam_role", scope, [], "empty"),
                 ("service_account", scope, [], "empty"),
                 ("iam_deny_policy", scope, [], "empty")]
    return snapshot("gcp", cols)


def test_uncollected_facts_give_one_holder_group_edge_not_sources_x_scopes():
    tid = "gcp-pam-entitlement-request-grant"   # PAM entitlements are never collected
    users = [f"u{i}" for i in range(6)]
    result = archived_real(_gcp_projects(4, users), tid, include_unknown=True)
    edges = [e for e in result["graph"]["edges"] if tid in e["techniques"]]
    assert len(edges) == 1
    nodes = {n["id"]: n for n in result["graph"]["nodes"]}
    source, target = nodes[edges[0]["source"]], nodes[edges[0]["target"]]
    assert source["type"] == "principal_group" and source["members"] == sorted(f"user:{u}@x.com" for u in users)
    assert target["unresolved"] and target["members"] == [] and target["scopes"] == [f"projects/p{i}" for i in range(4)]
    assert target["facts_needed"]
    findings = [f for f in result["findings"] if f["check_id"] == tid]
    assert [f["status"] for f in findings] == ["UNKNOWN"]


def test_shared_placeholders_skip_scopes_the_holder_administers():
    tid = "gcp-pam-entitlement-request-grant"
    result = archived_real(_gcp_projects(2, ["u0", "u1"], {0: [{"role": "roles/owner", "members": ["user:boss@x.com"]}]}), tid, include_unknown=True)
    nodes = {n["id"]: n for n in result["graph"]["nodes"]}
    by_source = {}
    for e in result["graph"]["edges"]:
        if tid in e["techniques"]:
            members = nodes[e["source"]].get("members") or [e["source"]]
            target = nodes[e["target"]]
            for m in members:
                by_source.setdefault(m, set()).update(target.get("scopes") or [target["scope"]])
    assert by_source["user:u0@x.com"] == {"projects/p0", "projects/p1"}
    assert "projects/p0" not in by_source.get("user:boss@x.com", set())     # already owner of p0


def test_gcp_service_account_inventory_gaps_only_in_projects():
    from peaso.privesc.effective_permissions.gcp import GcpModel
    snap = _gcp_projects(1, ["u0"])
    snap["collections"].append({"type": "service_account", "scope": "organizations/1", "service": "iam", "status": "denied",
                                "items": [], "error": None})
    snap["collections"].append({"type": "service_account", "scope": "projects/p9", "service": "iam", "status": "denied",
                                "items": [], "error": None})
    assert set(GcpModel(snap).unknown_target_scopes("gcp_service_account")) == {"projects/p9"}


# ----------------------------------------------------------------------------- GCP IAM Conditions (CEL)

from peaso.privesc.effective_permissions import gcp_conditions as cel  # noqa: E402
from peaso.privesc.effective_permissions.gcp import GcpModel  # noqa: E402

_SA = "projects/p0/serviceAccounts/{}@p0.iam.gserviceaccount.com"
_TOKEN_TID = "gcp-iam-serviceaccounts-getaccesstoken"


def _gcp_conditional(expression, title="c"):
    binding = {"role": "projects/p0/roles/tc", "members": ["user:u@x.com"],
               "condition": {"title": title, "expression": expression}}
    sas = [{"email": f"{n}@p0.iam.gserviceaccount.com", "projectId": "p0", "uniqueId": str(i)} for i, n in enumerate("ab")]
    return snapshot("gcp", [
        ("project", "projects/p0", [{"projectId": "p0", "name": "projects/100", "_ancestry": []}], "collected"),
        ("iam_policy", "projects/p0", [{"name": "projects/p0", "bindings": [binding]}], "collected"),
        ("iam_role", "projects/p0", [{"name": "projects/p0/roles/tc", "includedPermissions": ["iam.serviceAccounts.getAccessToken"]}], "collected"),
        ("service_account", "projects/p0", sas, "collected"),
        ("iam_deny_policy", "projects/p0", [], "empty")])


@pytest.mark.parametrize("expression,resource,expected", [
    ('resource.name.endsWith("a@p0.iam.gserviceaccount.com")', _SA.format("a"), False),
    ('resource.name.endsWith("a@p0.iam.gserviceaccount.com")', _SA.format("b"), False),
    ('resource.name == "projects/p0"', "projects/p0", False),
    ('resource.name == "projects/100"', "projects/p0", False),         # the model passes the number as an alias
    ('resource.name.startsWith("projects/p9/")', _SA.format("a"), False),
    ('resource.type == "iam.googleapis.com/ServiceAccount"', _SA.format("a"), False),
    ('resource.type != "iam.googleapis.com/ServiceAccount"', _SA.format("a"), False),
    ('resource.service == "iam.googleapis.com"', _SA.format("a"), False),
    ('resource.type == "storage.googleapis.com/Bucket" || resource.service == "iam.googleapis.com"', _SA.format("a"), False),
    ('resource.type == "storage.googleapis.com/Bucket"', "projects/_/buckets/b", True),
    ('resource.service == "storage.googleapis.com"', "projects/_/buckets/b", True),
    ('request.time < timestamp("2001-01-01T00:00:00Z")', _SA.format("a"), False),
    ('request.time < timestamp("2999-01-01T00:00:00Z")', _SA.format("a"), True),
    ('resource.matchTag("123/env", "prod")', _SA.format("a"), None),
    ('request.time.getHours("UTC") > 8', _SA.format("a"), None),
    ('resource.name.startsWith("projects/p0/serviceAccounts/a")', _SA.format("a"), False),
    ('resource.name.startsWith("x") &&', _SA.format("a"), None),       # unsupported syntax
    ('!(resource.type == "iam.googleapis.com/ServiceAccount") || resource.matchTag("k", "v")', "projects/p0", True),
])
def test_cel_three_valued(expression, resource, expected):
    assert cel.evaluate(expression, cel.resource_context(resource)) is expected


def test_cel_condition_on_resource_name_restricts_targets():
    result = real(_gcp_conditional('resource.name.endsWith("a@p0.iam.gserviceaccount.com")'), _TOKEN_TID)
    got = reached(result, "user:u@x.com", _TOKEN_TID)
    # IAM Conditions do not expose resource.name for service accounts, even when the
    # policy lookup has their resource path. Neither target can satisfy this condition.
    assert got == {}


def test_cel_decided_true_condition_is_derived():
    result = real(_gcp_conditional('request.time < timestamp("2999-01-01T00:00:00Z")'), _TOKEN_TID)
    got = reached(result, "user:u@x.com", _TOKEN_TID)
    assert got == {f"serviceAccount:{n}@p0.iam.gserviceaccount.com": "derived" for n in "ab"}


def test_cel_resource_type_mismatch_grants_nothing():
    result = real(_gcp_conditional('resource.type == "storage.googleapis.com/Bucket"'), _TOKEN_TID)
    assert reached(result, "user:u@x.com", _TOKEN_TID) == {}


def test_cel_expired_binding_is_inactive_future_expiry_is_derived():
    past = _gcp_conditional('request.time < timestamp("2001-01-01T00:00:00Z")')
    model = GcpModel(past)
    assert model.inactive_bindings == 1
    assert reached(real(past, _TOKEN_TID), "user:u@x.com", _TOKEN_TID) == {}
    future = real(_gcp_conditional('request.time < timestamp("2999-01-01T00:00:00Z")'), _TOKEN_TID)
    assert set(reached(future, "user:u@x.com", _TOKEN_TID).values()) == {"derived"}


def test_cel_undecidable_condition_is_conditional_with_expression():
    expression = 'resource.matchTag("123/env", "prod")'
    snap = _gcp_conditional(expression)
    got = reached(real(snap, _TOKEN_TID), "user:u@x.com", _TOKEN_TID)
    assert set(got) == {f"serviceAccount:{n}@p0.iam.gserviceaccount.com" for n in "ab"}
    assert set(got.values()) == {"conditional"}
    model = GcpModel(snap)
    user_node = model.principals["user:u@x.com"]
    grant = model.check(user_node, {"permission": "iam.serviceAccounts.getAccessToken"}, _SA.format("a"))
    assert grant.confidence == "conditional" and "binding_condition" in grant.conditions
    assert any(ref.get("expression") == expression for ref in grant.refs)


def test_cel_unconditional_binding_still_wins_over_false_condition():
    snap = _gcp_conditional('resource.type == "storage.googleapis.com/Bucket"')
    policy_item = snap["collections"][1]["items"][0]
    policy_item["bindings"].append({"role": "projects/p0/roles/tc", "members": ["user:u@x.com"]})
    got = reached(real(snap, _TOKEN_TID), "user:u@x.com", _TOKEN_TID)
    assert set(got.values()) == {"derived"} and len(got) == 2


# ----------------------------------------------------------------------------- Azure ABAC + PIM

from peaso.privesc.effective_permissions.azure import AzureModel, _abac_restricts  # noqa: E402

_AZ_SUB = "/subscriptions/00000000-0000-0000-0000-00000000aaaa"
_AZ_ROLE = "11111111-1111-1111-1111-111111111111"
_RA_WRITE = "Microsoft.Authorization/roleAssignments/write"
_DELEGATION = ("((!(ActionMatches{'Microsoft.Authorization/roleAssignments/write'})) OR "
               "(@Request[Microsoft.Authorization/roleAssignments:RoleDefinitionId] ForAnyOfAnyValues:GuidEquals "
               "{ba92f5b4-2d11-453d-a403-e96b0029c9fe}))")
_BLOB = ("((!(ActionMatches{'Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read'} AND "
         "NOT SubOperationMatches{'Blob.List'})) OR (@Resource[Microsoft.Storage/storageAccounts/blobServices/"
         "containers:name] StringEquals 'logs'))")


def _azure(condition=None, eligibility=(), instances=None, actions=(_RA_WRITE, "Microsoft.Compute/virtualMachines/write")):
    role_def = {"id": f"{_AZ_SUB}/providers/Microsoft.Authorization/roleDefinitions/{_AZ_ROLE}",
                "properties": {"roleName": "custom", "type": "CustomRole", "assignableScopes": [_AZ_SUB],
                               "permissions": [{"actions": list(actions)}]}}
    props = {"principalId": "u-alice", "principalType": "User", "scope": _AZ_SUB,
             "roleDefinitionId": f"/providers/Microsoft.Authorization/roleDefinitions/{_AZ_ROLE}"}
    if condition:
        props.update(condition=condition, conditionVersion="2.0")
    cols = [("subscription", _AZ_SUB, [{"id": _AZ_SUB, "subscriptionId": _AZ_SUB.rsplit("/", 1)[-1]}], "collected"),
            ("role_definition", _AZ_SUB, [role_def], "collected"),
            ("role_assignment", _AZ_SUB, [{"id": f"{_AZ_SUB}/providers/Microsoft.Authorization/roleAssignments/1",
                                           "properties": props}], "collected"),
            ("deny_assignment", _AZ_SUB, [], "empty"),
            ("directory_user", "/tenants/t", [{"id": "u-alice", "userPrincipalName": "alice@t.com", "accountEnabled": True,
                                               "userType": "Member"}], "collected"),
            ("directory_role_eligibility_schedule", "/tenants/t", list(eligibility), "collected" if eligibility else "empty")]
    if instances is not None:
        cols.append(("directory_role_eligibility_instance", "/tenants/t", instances, "collected" if instances else "empty"))
    snap = snapshot("azure", cols)
    snap["metadata"] = {"tenant_id": "t"}
    return AzureModel(snap)


def _az_check(model, action):
    return model.check(model.principals["u-alice"], {"action": action}, _AZ_SUB.lower())


@pytest.mark.parametrize("condition,action,restricted", [
    (_DELEGATION, _RA_WRITE, True),                                        # delegation condition: assignable roles limited
    (_DELEGATION, "Microsoft.Compute/virtualMachines/write", False),       # other actions pass the condition
    (_BLOB, "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read", True),
    (_BLOB, _RA_WRITE, False),
    (_DELEGATION + " AND " + _BLOB, _RA_WRITE, True),
    ("@Resource[x] StringEquals 'y'", _RA_WRITE, True),                    # non-standard form: undecidable
    ("((!(ActionMatches{'Microsoft.Storage/*'})) || (@Resource[x] StringEquals 'y'))", "microsoft.storage/a/b", True),
])
def test_azure_abac_condition_scope(condition, action, restricted):
    assert _abac_restricts(condition, action.lower()) is restricted


def test_azure_abac_condition_conditional_only_for_named_actions():
    model = _azure(_DELEGATION)
    grant = _az_check(model, _RA_WRITE)
    assert grant.confidence == "conditional" and "role_assignment_condition" in grant.conditions
    assert grant.refs[0]["condition"] == _DELEGATION                       # expression attached
    assert _az_check(model, "Microsoft.Compute/virtualMachines/write").confidence == "derived"
    assert _az_check(_azure(), _RA_WRITE).confidence == "derived"          # no condition: derived


def _eligible(status="Provisioned", scope="/"):
    return {"id": "e1", "principalId": "u-alice", "roleDefinitionId": GA_ROLE, "directoryScopeId": scope, "status": status}


GA_ROLE = "62e90394-69f5-4237-9190-012177145e10"
_PIM_REQ = {"entra_pim_eligible_role": GA_ROLE}


def test_azure_pim_eligible_is_conditional_never_active():
    model = _azure(eligibility=[_eligible()])
    grant = model.check(model.principals["u-alice"], _PIM_REQ, "dir:" + GA_ROLE)
    assert grant.confidence == "unknown" and "pim_eligibility_instance_not_collected" in grant.conditions
    live = {"principalId": "u-alice", "roleDefinitionId": GA_ROLE, "directoryScopeId": "/",
            "endDateTime": "2999-01-01T00:00:00Z"}
    model = _azure(eligibility=[_eligible()], instances=[live])
    grant = model.check(model.principals["u-alice"], _PIM_REQ, "dir:" + GA_ROLE)
    assert grant.confidence == "conditional" and list(grant.conditions) == ["pim_activation_required"]
    # Eligibility never counts as an active directory role assignment.
    assert model.check(model.principals["u-alice"], {"entra_role": GA_ROLE}, ANY) is None


@pytest.mark.parametrize("status,instances,expected", [
    ("Revoked", None, None),
    ("Canceled", None, None),
    ("Provisioned", [{"principalId": "u-alice", "roleDefinitionId": GA_ROLE, "directoryScopeId": "/",
                      "endDateTime": "2001-01-01T00:00:00Z"}], None),                      # expired instance
    ("Provisioned", [{"principalId": "u-alice", "roleDefinitionId": GA_ROLE, "directoryScopeId": "/",
                      "endDateTime": "2999-01-01T00:00:00Z"}], "conditional"),
    ("Provisioned", [], None),                                                             # instances collected: none live
])
def test_azure_pim_eligibility_status_and_expiry(status, instances, expected):
    model = _azure(eligibility=[_eligible(status)], instances=instances)
    grant = model.check(model.principals["u-alice"], _PIM_REQ, "dir:" + GA_ROLE)
    assert (grant.confidence if grant else None) == expected


def test_azure_pim_eligibility_scoped_to_au_is_flagged():
    model = _azure(eligibility=[_eligible(scope="/administrativeUnits/au1")])
    grant = model.check(model.principals["u-alice"], _PIM_REQ, "dir:" + GA_ROLE)
    assert "pim_eligibility_scope_restricted" in grant.conditions


# ----------------------------------------------------------------------------- K8s resourceNames

@pytest.mark.parametrize("tid,rule", [
    ("k8s-rbac-impersonate-serviceaccounts", {"apiGroups": [""], "resources": ["serviceaccounts"], "verbs": ["impersonate"]}),
    ("k8s-rbac-serviceaccounts-token-create", {"apiGroups": [""], "resources": ["serviceaccounts/token"], "verbs": ["create"]}),
])
def test_k8s_resource_names_restrict_targets_to_named_objects(tid, rule):
    def snap(r):
        role_obj, binding = grant("r", "a", [r], {"kind": "User", "name": "dev"})
        reader, reader_binding = _sa_node_readers()
        return k8s([role_obj, reader], [binding, reader_binding])

    everyone = real(snap(rule), tid)
    assert set(reached(everyone, "k8s:c1:user:dev", tid)) >= {"k8s:c1:sa:a:builder", "k8s:c1:sa:a:ca"}
    named = real(snap(dict(rule, resourceNames=["ca"])), tid)
    assert reached(named, "k8s:c1:user:dev", tid) == {"k8s:c1:sa:a:ca": "derived"}       # TP: only the named SA
    ghost = real(snap(dict(rule, resourceNames=["nope"])), tid)
    assert reached(ghost, "k8s:c1:user:dev", tid) == {}                                  # FP guard: name matches nothing


def test_k8s_resource_names_never_satisfy_list_or_create():
    tid = "k8s-rbac-secrets-read-legacy-sa-token"
    r, b = grant("read", "a", [{"apiGroups": [""], "resources": ["secrets"], "verbs": ["list"], "resourceNames": ["ca-token"]}],
                 {"kind": "User", "name": "dev"})
    result = real(k8s([r], [b], secrets=[_secret("ca-token", "ca")]), tid)
    assert reached(result, "k8s:c1:user:dev", tid) == {}                                 # list ignores resourceNames grants


# ----------------------------------------------------------------------------- AWS policy-language coverage

from peaso.privesc.effective_permissions.aws import AwsModel  # noqa: E402

OTHER_ROLE = f"arn:aws:iam::{ACCOUNT}:role/other"
BOUNDARY = f"arn:aws:iam::{ACCOUNT}:policy/boundary"


def _aws_model(*statements, extra=(), boundary=None, roles=None):
    alice = user("alice", *statements)
    if boundary:
        alice["PermissionsBoundary"] = {"PermissionsBoundaryArn": boundary}
    return AwsModel(aws([alice], roles if roles is not None else [role("ec2-role"), role("other")], extra))


def _aws_check(model, action, ref=None):
    grant = model.check(model.principals[ALICE], {"action": action}, ref if ref is not None else EC2_ROLE)
    return grant.confidence if grant else None


def _managed(arn, *statements):
    return {"Arn": arn, "PolicyName": arn.rsplit("/", 1)[-1],
            "PolicyVersionList": [{"IsDefaultVersion": True, "Document": policy(*statements)}]}


def test_aws_notaction_and_notresource():
    model = _aws_model({"Effect": "Allow", "NotAction": ["iam:*"], "Resource": "*"})
    assert _aws_check(model, "iam:PassRole") is None and _aws_check(model, "ec2:RunInstances", "*") == "derived"
    model = _aws_model({"Effect": "Allow", "Action": "iam:PassRole", "NotResource": EC2_ROLE})
    assert _aws_check(model, "iam:PassRole") is None and _aws_check(model, "iam:PassRole", OTHER_ROLE) == "derived"
    model = _aws_model({"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"},
                       {"Effect": "Deny", "Action": "iam:PassRole", "NotResource": OTHER_ROLE})
    assert _aws_check(model, "iam:PassRole") is None and _aws_check(model, "iam:PassRole", OTHER_ROLE) == "derived"
    model = _aws_model({"Effect": "Allow", "Action": "*", "Resource": "*"}, {"Effect": "Deny", "NotAction": "ec2:*", "Resource": "*"})
    assert _aws_check(model, "iam:PassRole") is None and _aws_check(model, "ec2:RunInstances", "*") == "derived"


def test_aws_permissions_boundary_intersection():
    admin = {"Effect": "Allow", "Action": "*", "Resource": "*"}
    only_ec2 = ("iam_policy", f"{ACCOUNT}/{REGION}", [_managed(BOUNDARY, {"Effect": "Allow", "Action": "ec2:*", "Resource": "*"})],
                "collected")
    model = _aws_model(admin, boundary=BOUNDARY, extra=[only_ec2])
    assert _aws_check(model, "iam:PassRole") is None                                  # FP guard: boundary cuts it
    assert _aws_check(model, "ec2:RunInstances", "*") == "derived"                    # TP: inside the boundary
    missing = _aws_model(admin, boundary=BOUNDARY)                                     # boundary document not collected
    assert _aws_check(missing, "iam:PassRole") == "conditional"


def _org_policy(kind, pid, *statements, target=ACCOUNT):
    return {"Id": pid, "Name": pid, "TargetId": target, "Type": kind,
            "Detail": {"Policy": {"Content": policy(*statements)}}}


def test_aws_scp_deny_and_allow_list():
    scope = f"{ACCOUNT}/{REGION}"
    full = {"Effect": "Allow", "Action": "*", "Resource": "*"}
    deny = _org_policy("SERVICE_CONTROL_POLICY", "p-deny", full, {"Effect": "Deny", "Action": "iam:PassRole", "Resource": "*"})
    snap = aws([user("alice", {"Effect": "Allow", "Action": "*", "Resource": "*"})], [role("ec2-role")])
    snap["collections"] = [c for c in snap["collections"] if c["type"] != "scp_policy"] + [
        {"type": "scp_policy", "scope": scope, "service": "scp_policy", "status": "collected", "items": [deny], "error": None}]
    model = AwsModel(snap)
    assert _aws_check(model, "iam:PassRole") is None
    # Allow-list SCP without ec2: everything else is implicitly denied by the SCP.
    allow_iam = _org_policy("SERVICE_CONTROL_POLICY", "p-iam", {"Effect": "Allow", "Action": "iam:*", "Resource": "*"})
    snap["collections"][-1]["items"] = [allow_iam]
    model = AwsModel(snap)
    assert _aws_check(model, "ec2:RunInstances", "*") is None
    assert _aws_check(model, "iam:PassRole") == "conditional"                         # OU path unknown: conditional


@pytest.mark.parametrize("statement,expected", [
    ({"Effect": "Deny", "Action": "sts:AssumeRole", "Resource": "*"}, None),           # unconditional RCP deny
    ({"Effect": "Deny", "Action": "sts:AssumeRole", "Resource": "*",
      "Condition": {"StringNotEqualsIfExists": {"aws:SourceIp": "10.0.0.0/8"}}}, "conditional"),
    ({"Effect": "Deny", "Action": "sts:AssumeRole", "Resource": "*",
      "Condition": {"Bool": {"aws:PrincipalIsAWSService": "true"}}}, "derived"),       # never true for IAM principals
    ({"Effect": "Deny", "Action": "s3:*", "Resource": "*"}, "derived"),                # other service: no effect
])
def test_aws_resource_control_policies(statement, expected):
    rcp = _org_policy("RESOURCE_CONTROL_POLICY", "p-rcp", {"Effect": "Allow", "Action": "*", "Resource": "*"}, statement)
    model = _aws_model({"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": "*"},
                       extra=[("rcp_policy", f"{ACCOUNT}/{REGION}", [rcp], "collected")])
    assert _aws_check(model, "sts:AssumeRole") == expected
    # RCPs never touch non-RCP services
    assert _aws_check(_aws_model({"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"},
                                 extra=[("rcp_policy", f"{ACCOUNT}/{REGION}", [rcp], "collected")]), "iam:PassRole") == "derived"


@pytest.mark.parametrize("condition,effect,expected", [
    ({"IpAddress": {"aws:SourceIp": "203.0.113.0/24"}}, "Allow", "conditional"),          # attacker's IP is unknown
    ({"NotIpAddress": {"aws:SourceIp": "203.0.113.0/24"}}, "Deny", "conditional"),
    ({"Bool": {"aws:MultiFactorAuthPresent": "true"}}, "Allow", "conditional"),           # session property
    ({"BoolIfExists": {"aws:MultiFactorAuthPresent": "false"}}, "Deny", "conditional"),
    ({"StringEquals": {"aws:PrincipalOrgID": "o-abc123"}}, "Allow", "derived"),           # org known: decided
    ({"StringEquals": {"aws:PrincipalOrgID": "o-other1"}}, "Allow", None),
    ({"StringNotEquals": {"aws:PrincipalOrgID": "o-abc123"}}, "Deny", "derived"),         # deny never applies in org
])
def test_aws_condition_keys(condition, effect, expected):
    org = ("organization_account", f"{ACCOUNT}/{REGION}",
           [{"Id": ACCOUNT, "Arn": f"arn:aws:organizations::{ACCOUNT}:account/o-abc123/{ACCOUNT}", "State": "ACTIVE"}], "collected")
    statements = [{"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"}] if effect == "Deny" else []
    statements.append({"Effect": effect, "Action": "iam:PassRole", "Resource": "*", "Condition": condition})
    assert _aws_check(_aws_model(*statements, extra=[org]), "iam:PassRole") == expected


# ---------------------------------------------- attached_to_service: an authoritatively empty inventory is no edge
# A typed collection collected with no items (status "empty", or "collected" with 0 items) proves there is no attached
# workload: the selector emits no edge. Only a denied / missing / partial collection yields unknown.
_AZ_SUB2 = "/subscriptions/00000000-0000-0000-0000-00000000bbbb"
_VM = "microsoft.compute/virtualmachines"


def _az_attached(collections, value, scope=None, subs=(_AZ_SUB,)):
    cols = [("subscription", "/tenants/t", [{"id": s, "subscriptionId": s.rsplit("/", 1)[-1]} for s in subs], "collected"),
            *collections]
    snap = snapshot("azure", cols)
    snap["metadata"] = {"tenant_id": "t"}
    model = AzureModel(snap)
    mi = Node("mi-1", "azure_managed_identity", "azure", scope or _AZ_SUB.lower(), "mi", attrs={"mi_type": "user_assigned", "hosts": []})
    return model.selector("attached_to_service", value, {"mi-1": mi}, None)


@pytest.mark.parametrize("collections,value,expected", [
    ([("vm", _AZ_SUB, [], "empty")], _VM, {}),
    ([("vm", _AZ_SUB, [], "collected")], _VM, {}),                       # collected with 0 items
    ([("vm", _AZ_SUB, [], "denied")], _VM, "unknown"),
    ([("vm", _AZ_SUB, [], "partial")], _VM, "unknown"),
    ([], _VM, "unknown"),                                                # never collected
    ([("resource_graph", _AZ_SUB, [], "empty")], _VM, {}),               # complete Resource Graph inventory
    ([("resource_graph", _AZ_SUB, [], "denied")], _VM, "unknown"),
    # Child type: Resource Graph does not track it, but no parent resource exists so no child can exist.
    ([("resource_graph", _AZ_SUB, [], "empty")], "microsoft.automation/automationaccounts/runbooks", {}),
    ([("resource_graph", _AZ_SUB, [{"id": f"{_AZ_SUB}/resourceGroups/rg/providers/Microsoft.Automation/automationAccounts/a",
                                     "type": "Microsoft.Automation/automationAccounts"}], "collected")],
     "microsoft.automation/automationaccounts/runbooks", "unknown"),
    ([("resource_graph", _AZ_SUB, [], "empty")], "microsoft.web/sites/slots", {}),  # tracked child
])
def test_azure_attached_to_service_empty_inventory_is_no_edge(collections, value, expected):
    out = _az_attached(collections, value)
    assert (out == {}) if expected == {} else out["mi-1"][0] == expected


def test_azure_attached_to_service_tenant_scoped_identity_needs_every_subscription():
    both = [("vm", _AZ_SUB, [], "empty"), ("vm", _AZ_SUB2, [], "empty")]
    assert _az_attached(both, _VM, scope="/tenants/t", subs=(_AZ_SUB, _AZ_SUB2)) == {}
    one = [("vm", _AZ_SUB, [], "empty"), ("vm", _AZ_SUB2, [], "denied")]
    assert _az_attached(one, _VM, scope="/tenants/t", subs=(_AZ_SUB, _AZ_SUB2))["mi-1"][0] == "unknown"


from peaso.privesc.effective_permissions.gcp import GcpModel  # noqa: E402

_GSA = "app@p1.iam.gserviceaccount.com"
_GDEF = "123-compute@developer.gserviceaccount.com"


def _gcp_attached(extra, email=_GSA):
    sas = [{"email": e, "projectId": "p1", "name": f"projects/p1/serviceAccounts/{e}"} for e in (_GSA, _GDEF)]
    snap = snapshot("gcp", [("project", "projects/p1", [{"projectId": "p1", "name": "projects/123", "_ancestry": []}], "collected"),
                            ("iam_policy", "projects/p1", [{"name": "projects/p1", "bindings": []}], "collected"),
                            ("service_account", "projects/p1", sas, "collected"), *extra])
    model = GcpModel(snap)
    node = model.principals[f"serviceAccount:{email}"]
    return model, node


@pytest.mark.parametrize("kind,service,item", [
    ("cloudrun_service", "run_service", {"name": "projects/p1/locations/us/services/s", "template": {"serviceAccount": _GSA}}),
    ("function", "cloudfunctions_function", {"name": "projects/p1/locations/us/functions/f", "serviceConfig": {"serviceAccountEmail": _GSA}}),
    ("dataproc_cluster", "dataproc_cluster", {"clusterName": "c", "_region": "us-central1", "config": {"gceClusterConfig": {"serviceAccount": _GSA}}}),
    ("gke_cluster", "gke_nodepool", {"name": "k", "location": "us", "nodePools": [{"config": {"serviceAccount": _GSA}}]}),
    ("instance", "compute_instance", {"name": "vm", "zone": "zones/us-a", "serviceAccounts": [{"email": _GSA}]}),
])
def test_gcp_attached_to_service_inventories(kind, service, item):
    for status, expected in (("empty", {}), ("denied", "unknown")):
        model, node = _gcp_attached([(kind, "projects/p1", [], status)])
        out = model.selector("attached_to_service", service, {node.id: node}, None)
        assert (out == {}) if expected == {} else out[node.id][0] == expected
    model, node = _gcp_attached([(kind, "projects/p1", [item], "collected")])
    assert model.selector("attached_to_service", service, {node.id: node}, None) == {node.id: None}
    model.current_selector = {"attached_to_service": service}
    assert model.placeholder_values("target.host_resource", None, node)          # the host resource is a target ref
    other, node = _gcp_attached([(kind, "projects/p1", [item], "collected")], email=_GDEF)
    assert other.selector("attached_to_service", service, {node.id: node}, None) == {}  # collected: other SA has none


@pytest.mark.parametrize("kind,service,item", [
    ("cloudrun_service", "run_service", {"name": "projects/p1/locations/us/services/s", "template": {}}),
    ("gke_cluster", "gke_nodepool", {"name": "k", "location": "us", "nodePools": [{"config": {"serviceAccount": "default"}}]}),
    ("dataproc_cluster", "dataproc_cluster", {"clusterName": "c", "_region": "us-central1", "config": {}}),
])
def test_gcp_workloads_without_service_account_run_as_the_default_compute_sa(kind, service, item):
    model, node = _gcp_attached([(kind, "projects/p1", [item], "collected")], email=_GDEF)
    assert model.selector("attached_to_service", service, {node.id: node}, None) == {node.id: None}


def test_gcp_workload_with_unresolved_identity_keeps_inventory_partial():
    model, node = _gcp_attached([("gke_cluster", "projects/p1", [{"name": "k", "location": "us"}], "collected")])  # Autopilot
    assert model.selector("attached_to_service", "gke_nodepool", {node.id: node}, None)[node.id][0] == "unknown"


def _aws_attached(extra, name="build-role", service="codebuild.amazonaws.com"):
    model = AwsModel(aws([], [role(name, service, profile=False)], extra))
    return model, model.principals[f"arn:aws:iam::{ACCOUNT}:role/{name}"]


@pytest.mark.parametrize("kind,service,trust,item", [
    ("codebuild_project", "codebuild", "codebuild.amazonaws.com",
     {"Configuration": {"collection_status": "collected", "projects": [
         {"arn": f"arn:aws:codebuild:{REGION}:{ACCOUNT}:project/p", "serviceRole": f"arn:aws:iam::{ACCOUNT}:role/build-role"}]}}),
    ("glue_job", "glue", "glue.amazonaws.com", {"Name": "job", "Role": "build-role"}),  # Glue may name the role
    ("redshift_cluster", "redshift_cluster", "redshift.amazonaws.com",
     {"ClusterIdentifier": "c", "IamRoles": [{"IamRoleArn": f"arn:aws:iam::{ACCOUNT}:role/build-role"}]}),
    ("rds_instance", "rds_db_instance", "rds.amazonaws.com",
     {"DBInstanceArn": f"arn:aws:rds:{REGION}:{ACCOUNT}:db:d", "AssociatedRoles": [{"RoleArn": f"arn:aws:iam::{ACCOUNT}:role/build-role"}]}),
])
def test_aws_attached_to_service_inventories(kind, service, trust, item):
    scope = f"{ACCOUNT}/{REGION}"
    model, node = _aws_attached([(kind, scope, [], "empty")], service=trust)
    assert model._attached(node, service) is False                          # authoritative empty: no edge
    model, node = _aws_attached([(kind, scope, [], "denied")], service=trust)
    assert model._attached(node, service)[0] == "unknown"
    model, node = _aws_attached([(kind, scope, [item], "collected")], service=trust)
    assert model._attached(node, service) is None
    assert model.placeholder_values("target.attached_resource_arn", None, node, {"attached_to_service": service})


# ------------------------------------------------- K8s managed control-plane subjects (live GKE QA, item 1)
def _managed_cluster():
    admin = kobj("ClusterRole", "cluster-admin", rules=[{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}])
    boot = {"labels": {"kubernetes.io/bootstrapping": "rbac-defaults"}}
    reconcile = {"labels": {"addonmanager.kubernetes.io/mode": "Reconcile"}}
    bindings = [
        kobj("ClusterRoleBinding", "cluster-admin", roleRef={"kind": "ClusterRole", "name": "cluster-admin"}, meta=boot,
             subjects=[{"kind": "Group", "name": "system:masters"}]),
        kobj("ClusterRoleBinding", "system:controller:deployment-controller", meta=boot,
             roleRef={"kind": "ClusterRole", "name": "cluster-admin"},
             subjects=[{"kind": "ServiceAccount", "name": "deployment-controller", "namespace": "kube-system"}]),
        kobj("ClusterRoleBinding", "gmp", meta=reconcile, roleRef={"kind": "ClusterRole", "name": "cluster-admin"},
             subjects=[{"kind": "ServiceAccount", "name": "operator", "namespace": "gmp-system"}]),
        kobj("ClusterRoleBinding", "apiserver", meta=reconcile, roleRef={"kind": "ClusterRole", "name": "cluster-admin"},
             subjects=[{"kind": "User", "name": "kube-apiserver"}, {"kind": "User", "name": "system:gke-common-webhooks"}]),
        # User-created binding naming a kube-system SA and a binding to a managed role for an ordinary user.
        kobj("ClusterRoleBinding", "my-ci", roleRef={"kind": "ClusterRole", "name": "cluster-admin"},
             subjects=[{"kind": "ServiceAccount", "name": "ci", "namespace": "kube-system"}]),
        kobj("ClusterRoleBinding", "dev-to-managed", roleRef={"kind": "ClusterRole", "name": "system:controller:x"},
             subjects=[{"kind": "User", "name": "dev"}]),
        kobj("ClusterRoleBinding", "anon", roleRef={"kind": "ClusterRole", "name": "cluster-admin"},
             subjects=[{"kind": "Group", "name": "system:unauthenticated"}]),
    ]
    managed_role = kobj("ClusterRole", "system:controller:x", meta=boot,
                        rules=[{"apiGroups": [""], "resources": ["serviceaccounts"], "verbs": ["impersonate"]}])
    sas = [kobj("ServiceAccount", n, ns) for ns, n in (("a", "default"), ("kube-system", "deployment-controller"),
                                                       ("kube-system", "ci"), ("gmp-system", "operator"))]
    sas.append(kobj("ServiceAccount", "agent", "a", meta={"annotations": {"components.gke.io/component-name": "x"}}))
    return K8sModel(k8s([admin, managed_role], bindings, sas=sas))


@pytest.mark.parametrize("pid,managed", [
    ("k8s:c1:group:system:masters", True),
    ("k8s:c1:sa:kube-system:deployment-controller", True),    # bootstrapping binding
    ("k8s:c1:sa:gmp-system:operator", True),                  # provider-managed namespace
    ("k8s:c1:sa:a:agent", True),                              # components.gke.io annotation
    ("k8s:c1:user:kube-apiserver", True),                     # known control-plane user
    ("k8s:c1:user:system:gke-common-webhooks", True),         # reserved system: prefix
    ("k8s:c1:sa:kube-system:ci", False),                      # user-created binding keeps it a source
    ("k8s:c1:user:dev", False),                               # user bound to a managed role: still a source
    ("k8s:c1:group:system:unauthenticated", False),           # anonymous access is attacker reachable
    ("k8s:c1:sa:a:default", False),
])
def test_k8s_managed_control_plane_subjects(pid, managed):
    model = _managed_cluster()
    assert model.managed_source(model.principals[pid]) is managed
    assert model.service_managed(model.principals[pid]) is False  # managed subjects stay targets


def test_k8s_managed_subjects_are_not_sources_but_stay_targets():
    model = _managed_cluster()
    admins = {p.id for p in model.sources() if model.admin_targets(p)}
    assert admins == {"k8s:c1:sa:kube-system:ci", "k8s:c1:group:system:unauthenticated"}
    # dev is bound (user-created binding) to the managed role system:controller:x (impersonate serviceaccounts):
    # the path is kept, and managed ServiceAccounts remain targets.
    result = real(model.snapshot, "k8s-rbac-impersonate-serviceaccounts")
    assert "k8s:c1:sa:kube-system:deployment-controller" in reached(result, "k8s:c1:user:dev")
    assert not any(e["source"] in ("k8s:c1:group:system:masters", "k8s:c1:sa:kube-system:deployment-controller",
                                   "k8s:c1:user:kube-apiserver") for e in result["graph"]["edges"])
    assert result["stats"]["skipped_service_managed_sources"] > 0


# ------------------------------------------------------ node cloud identities (live GKE QA, item 2)
_NODE_IDS = ("k8s-cloud-node-cloud-identity", "k8s-cloud-pod-imds-node-identity", "k8s-cloud-hostnetwork-pod-node-identity")
_PODS = grant("pods", "a", [{"apiGroups": [""], "resources": ["pods"], "verbs": ["create"]}],
              {"kind": "ServiceAccount", "name": "builder", "namespace": "a"})


def _k8s_nodes(provider_id, labels=None):
    snap = k8s([_PODS[0]], [_PODS[1]], provider_id=provider_id)
    for col in snap["collections"]:
        if col["type"] == "node":
            col["items"][0]["metadata"]["labels"] = labels or {}
    return snap


def _gke(mode, sa="default"):
    pool = {"name": "pool-a", "config": {"serviceAccount": sa, "workloadMetadataConfig": {"mode": mode}}}
    sas = [{"email": e, "projectId": "p1", "name": f"projects/p1/serviceAccounts/{e}"}
           for e in ("123-compute@developer.gserviceaccount.com", "nodes@p1.iam.gserviceaccount.com")]
    return snapshot("gcp", [
        ("project", "projects/p1", [{"projectId": "p1", "name": "projects/123", "_ancestry": []}], "collected"),
        ("iam_policy", "projects/p1", [{"name": "projects/p1", "bindings": [
            {"role": "roles/editor", "members": ["serviceAccount:123-compute@developer.gserviceaccount.com"]}]}], "collected"),
        ("service_account", "projects/p1", sas, "collected"),
        ("gke_cluster", "projects/p1", [{"name": "c1", "location": "us-a", "nodePools": [pool]}], "collected")])


def _node_reach(result):
    return {tid: (conf, src) for src in ("k8s:c1:node:n1", "k8s:c1:sa:a:builder") for tid, conf in reached(result, src).items()}


@pytest.mark.parametrize("mode,pod_imds", [("GCE_METADATA", True), ("GKE_METADATA", False)])
def test_gke_node_pool_service_account_is_the_node_identity(mode, pod_imds):
    k = _k8s_nodes("gce://p1/us-a/n1", {"cloud.google.com/gke-nodepool": "pool-a"})
    ident = "cloud:gke_node:123-compute@developer.gserviceaccount.com"   # unset / "default" = default compute SA
    result = real(k, *_NODE_IDS, related_snapshots=[_gke(mode)])
    assert reached(result, "k8s:c1:node:n1")[ident] == "conditional"
    edges = [e for e in result["graph"]["edges"] if e["source"] == "k8s:c1:sa:a:builder" and e["target"] == ident]
    details = {d["id"]: d["confidence"] for d in edges[0]["technique_details"]}
    assert details["k8s-cloud-hostnetwork-pod-node-identity"] == "conditional"
    assert ("k8s-cloud-pod-imds-node-identity" in details) is pod_imds
    if pod_imds:
        assert details["k8s-cloud-pod-imds-node-identity"] == "conditional"
    join = [e for e in result["graph"]["edges"] if e["source"] == ident]
    assert join and join[0]["target"] == "serviceAccount:123-compute@developer.gserviceaccount.com"
    assert result["stats"]["cross_snapshot_edges"] == 1


def test_node_identity_without_related_snapshot_stays_unresolved():
    k = _k8s_nodes("gce://p1/us-a/n1", {"cloud.google.com/gke-nodepool": "pool-a"})
    result = real(k, *_NODE_IDS)
    targets = set(reached(result, "k8s:c1:node:n1")) | {e["target"] for e in result["graph"]["edges"]}
    assert all(t.startswith("unresolved:") for t in targets if "cloud" in t or "unresolved" in t)
    assert not any(t.startswith("cloud:gke_node:") for t in targets)


def _aws_node(options):
    inst = {"InstanceId": "i-1", "AccountId": ACCOUNT, "Region": REGION, "State": {"Name": "running"},
            "IamInstanceProfile": {"Arn": f"arn:aws:iam::{ACCOUNT}:instance-profile/ec2-role"}, "MetadataOptions": options}
    return aws([], [role("ec2-role")], [("instance", f"{ACCOUNT}/{REGION}", [inst], "collected")])


@pytest.mark.parametrize("options,pod_imds_route", [
    ({"HttpTokens": "required", "HttpPutResponseHopLimit": 2}, True),
    ({"HttpTokens": "optional", "HttpPutResponseHopLimit": 1}, True),
    ({"HttpTokens": "required", "HttpPutResponseHopLimit": 1}, False),
])
def test_eks_node_instance_role_is_the_node_identity(options, pod_imds_route):
    k = _k8s_nodes("aws:///us-east-1a/i-1")
    result = real(k, *_NODE_IDS, related_snapshots=[_aws_node(options)])
    ident = f"cloud:eks_node:{EC2_ROLE}"
    # The node identity is known, but API access to the node does not prove host control.
    assert reached(result, "k8s:c1:node:n1")[ident] == "conditional"
    edge = next(e for e in result["graph"]["edges"] if e["source"] == "k8s:c1:sa:a:builder" and e["target"] == ident)
    details = {d["id"]: d["confidence"] for d in edge["technique_details"]}
    assert details.get("k8s-cloud-pod-imds-node-identity") == ("conditional" if pod_imds_route else None)
    assert details["k8s-cloud-hostnetwork-pod-node-identity"] == "conditional"


def test_aks_kubelet_identity_is_the_node_identity():
    sub = _AZ_SUB
    mi = {"id": f"{sub}/resourceGroups/mc_rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/agentpool",
          "type": "Microsoft.ManagedIdentity/userAssignedIdentities", "name": "agentpool",
          "properties": {"principalId": "obj-kubelet", "clientId": "client-kubelet"}}
    aks = {"id": f"{sub}/resourceGroups/rg/providers/Microsoft.ContainerService/managedClusters/c1",
           "type": "Microsoft.ContainerService/managedClusters", "name": "c1",
           "properties": {"nodeResourceGroup": "MC_rg", "identityProfile": {"kubeletidentity": {"clientId": "client-kubelet",
                                                                                                "objectId": "obj-kubelet"}}}}
    az = snapshot("azure", [("subscription", sub, [{"id": sub, "subscriptionId": sub.rsplit("/", 1)[-1]}], "collected"),
                            ("resource_graph", sub, [mi], "collected"), ("aks_cluster", sub, [aks], "collected")])
    az["metadata"] = {"tenant_id": "t"}
    k = _k8s_nodes(f"azure://{sub}/resourceGroups/mc_rg/providers/Microsoft.Compute/virtualMachineScaleSets/vmss/virtualMachines/0")
    result = real(k, *_NODE_IDS, related_snapshots=[az])
    # The AKS identity is linked to this node, but an API view of the node
    # does not establish control of its host or access to its credential.
    assert reached(result, "k8s:c1:node:n1")["cloud:aks_kubelet:client-kubelet"] == "conditional"
    assert any(e["source"] == "cloud:aks_kubelet:client-kubelet" and e["target"] == "obj-kubelet" for e in result["graph"]["edges"])


# --------------------------------------------- cross-snapshot counter / provider labels (live GKE QA, item 3)
def test_gcp_with_joined_k8s_counts_cross_snapshot_edges_and_labels_groups_k8s():
    actor = {"name": "projects/p1/roles/secrets", "includedPermissions": ["container.clusters.get", "container.secrets.get", "container.secrets.list"]}
    gcp = _gke("GCE_METADATA")
    for col in gcp["collections"]:
        if col["type"] == "iam_policy":
            col["items"][0]["bindings"].append({"role": "projects/p1/roles/secrets", "members": ["user:alice@x.com"]})
        if col["type"] == "gke_cluster":
            col["items"][0].update({"status": "RUNNING", "endpoint": "203.0.113.10"})
    gcp["collections"].append({"type": "iam_role", "scope": "projects/p1", "service": "iam_role", "status": "collected",
                               "items": [actor], "error": None})
    gcp["collections"].append({"type": "iam_deny_policy", "scope": "projects/p1", "service": "iam", "status": "empty",
                               "items": [], "error": None})
    secret = kobj("Secret", "tok", "a", type="kubernetes.io/service-account-token",
                  meta={"annotations": {"kubernetes.io/service-account.name": "builder",
                                        "kubernetes.io/service-account.uid": "builder-uid"}})
    k = k8s(secrets=[secret], sas=[kobj("ServiceAccount", "builder", "a", meta={"uid": "builder-uid"})])
    k["metadata"] = {"cluster_id": "c1"}
    result = real(gcp, "gcp-container-secrets-read-ksa-token-secret", related_snapshots=[k])
    nodes = {n["id"]: n for n in result["graph"]["nodes"]}
    edges = [e for e in result["graph"]["edges"] if e["source"] == "user:alice@x.com"]
    assert edges and all(nodes[e["target"]]["provider"] == "k8s" for e in edges)   # KSAs of the joined cluster
    cross = [e for e in result["graph"]["edges"] if nodes[e["target"]]["provider"] == "k8s"]
    assert result["stats"]["cross_snapshot_edges"] == len(cross) >= 1
    alone = real(gcp, "gcp-container-secrets-read-ksa-token-secret")
    assert alone["stats"]["cross_snapshot_edges"] == 0


_CROSS_PROJECT_SERVICES = {
    "run": ("run.services.create",),
    "run_job": ("run.jobs.create", "run.jobs.run"),
    "cloudbuild": ("cloudbuild.builds.create",),
    "workflows": ("workflows.workflows.create", "workflows.executions.create"),
}
_CROSS_PROJECT_AGENTS = {
    "run": "serverless-robot-prod.iam.gserviceaccount.com",
    "run_job": "serverless-robot-prod.iam.gserviceaccount.com",
    "cloudbuild": "gcp-sa-cloudbuild.iam.gserviceaccount.com",
    "workflows": "gcp-sa-workflows.iam.gserviceaccount.com",
}
_CROSS_PROJECT_IDS = {
    "run": "gcp-run-services-create-cross-project-actas",
    "run_job": "gcp-run-jobs-create-run-cross-project-actas",
    "cloudbuild": "gcp-cloudbuild-builds-create-cross-project-actas",
    "workflows": "gcp-workflows-create-cross-project-actas",
}


def _cross_project_run_snapshot(policy=False, agent_grant=True, host_access=True, disabled=False, mechanism="run"):
    host, target = "projects/host", "projects/target"
    sa = "a@target.iam.gserviceaccount.com"
    agent = "service-100@" + _CROSS_PROJECT_AGENTS[mechanism]
    sa_bindings = [{"role": "roles/iam.serviceAccountUser", "members": ["user:u@x.com"]}]
    if agent_grant:
        sa_bindings.append({"role": "roles/iam.serviceAccountTokenCreator", "members": ["serviceAccount:" + agent]})
    rows = [] if policy is None else [{"constraint": "iam.disableCrossProjectServiceAccountUsage",
                                      "spec": {"rules": [{"enforce": policy}]}}]
    return snapshot("gcp", [
        ("project", host, [{"projectId": "host", "name": "projects/100"}], "collected"),
        ("project", target, [{"projectId": "target", "name": "projects/200"}], "collected"),
        ("iam_role", host, [{"name": host + "/roles/creator", "includedPermissions":
                              list(_CROSS_PROJECT_SERVICES[mechanism]) if host_access else []}], "collected"),
        ("iam_policy", host, [{"name": host, "bindings": [
            {"role": host + "/roles/creator", "members": ["user:u@x.com"]}]}], "collected"),
        ("service_account", target, [{"email": sa, "projectId": "target", "disabled": disabled,
                                      "iamPolicy": {"bindings": sa_bindings}}], "collected"),
        ("service_usage", host, ([{"name": host + "/services/cloudbuild.googleapis.com", "state": "ENABLED"}]
                                 if mechanism == "cloudbuild" else
                                 [{"name": host + "/services/run.googleapis.com", "state": "ENABLED"}]
                                 if mechanism in ("run", "run_job") else []), "collected"),
        ("org_policy_effective", target, rows, "collected"),
        ("iam_deny_policy", host, [], "empty"),
        ("iam_deny_policy", target, [], "empty"),
        ("service_perimeter", host, [], "empty"),
        ("service_perimeter", target, [], "empty")])
