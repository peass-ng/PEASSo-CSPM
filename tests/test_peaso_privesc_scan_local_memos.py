"""Scan-local memos and indexes of the privesc / IAM stage equal the plain computations they replace.

Each memo is checked against the uncached code path (or a reference scan) on the same model, so the
optimizations keep paths, findings and evidence identical for the same input.
"""
import json
from types import SimpleNamespace

import pytest

from peaso import privesc
from peaso.privesc import grant_evidence
from peaso.privesc.effective_permissions import ANY, glob_match, items
from peaso.privesc.effective_permissions import gcp_osconfig_index
from peaso.privesc.effective_permissions.k8s import K8sModel


# --------------------------------------------------------------------------- Kubernetes RBAC gains

def _obj(kind, name, ns=None, cluster="c1", **body):
    meta = {"name": name}
    if ns:
        meta["namespace"] = ns
    return {"kind": kind, "metadata": meta, "provenance": {"cluster_id": cluster}, **body}


def _rule(verbs, resources, groups=("",), names=None):
    rule = {"verbs": list(verbs), "apiGroups": list(groups), "resources": list(resources)}
    if names:
        rule["resourceNames"] = list(names)
    return rule


def _binding(kind, name, role_kind, role, subjects, ns=None, cluster="c1"):
    return _obj(kind, name, ns, cluster, roleRef={"apiGroup": "rbac.authorization.k8s.io", "kind": role_kind, "name": role},
                subjects=subjects)


def _sa(ns, name):
    return {"kind": "ServiceAccount", "name": name, "namespace": ns}


def _user(name):
    return {"kind": "User", "apiGroup": "rbac.authorization.k8s.io", "name": name}


def k8s_snapshot():
    rbac = "rbac.authorization.k8s.io"
    clusterroles = []
    roles = []
    rolebindings = []
    clusterrolebindings = []
    for cluster in ("c1", "c2"):
        clusterroles += [
            _obj("ClusterRole", "binder", None, cluster, rules=[
                _rule(["bind", "escalate"], ["roles", "clusterroles"], [rbac]),
                _rule(["create", "patch", "update"], ["rolebindings", "clusterrolebindings"], [rbac])]),
            _obj("ClusterRole", "secrets-admin", None, cluster, rules=[
                _rule(["get", "list"], ["secrets"]), _rule(["create"], ["pods", "pods/exec"]),
                _rule(["get"], ["nodes"])]),
            _obj("ClusterRole", "wild", None, cluster, rules=[_rule(["*"], ["*"], ["*"])]),
            _obj("ClusterRole", "named-only", None, cluster, rules=[
                _rule(["get", "update"], ["configmaps"], names=["cfg"])]),
        ]
        for ns in ("a", "b"):
            roles += [_obj("Role", "pod-runner", ns, cluster, rules=[
                          _rule(["create", "get"], ["pods", "pods/log"]), _rule(["get"], ["secrets"], names=["tok"])]),
                      _obj("Role", "binder-ns", ns, cluster, rules=[
                          _rule(["bind"], ["roles", "clusterroles"], [rbac]),
                          _rule(["create", "patch"], ["rolebindings"], [rbac])])]
            rolebindings += [
                _binding("RoleBinding", "run", "Role", "pod-runner", [_sa(ns, "builder")], ns, cluster),
                _binding("RoleBinding", "bind", "Role", "binder-ns", [_sa(ns, "builder"), _user("bob")], ns, cluster),
                _binding("RoleBinding", "sec", "ClusterRole", "secrets-admin", [_sa(ns, "app")], ns, cluster),
                _binding("RoleBinding", "cfg", "ClusterRole", "named-only", [_user("carol")], ns, cluster),
            ]
        clusterrolebindings += [
            _binding("ClusterRoleBinding", "alice-binder", "ClusterRole", "binder", [_user("alice")], cluster=cluster),
            _binding("ClusterRoleBinding", "ops-wild", "ClusterRole", "wild", [_sa("kube-system", "ops")], cluster=cluster),
            _binding("ClusterRoleBinding", "app-secrets", "ClusterRole", "secrets-admin", [_sa("b", "app")], cluster=cluster),
        ]
    sas = [_obj("ServiceAccount", n, ns, c) for c in ("c1", "c2") for ns, n in
           (("a", "builder"), ("a", "app"), ("b", "builder"), ("b", "app"), ("kube-system", "ops"))]
    pods = [_obj("Pod", f"p{i}", ns, c, spec={"serviceAccountName": sa, "nodeName": "n1",
                                               "containers": [{"name": "c", "image": "i"}]},
                 status={"phase": "Running"})
            for i, (c, ns, sa) in enumerate((("c1", "a", "builder"), ("c1", "b", "app"), ("c2", "a", "app")))]
    nodes = [_obj("Node", "n1", None, c) for c in ("c1", "c2")]
    namespaces = [_obj("Namespace", ns, None, c) for c in ("c1", "c2") for ns in ("a", "b", "kube-system")]
    cols = [("pod", pods), ("serviceaccount", sas), ("node", nodes), ("namespace", namespaces), ("role", roles),
            ("rolebinding", rolebindings), ("clusterrole", clusterroles), ("clusterrolebinding", clusterrolebindings)]
    return {"schema_version": "1.0", "provider": "k8s", "scopes": ["c1"], "metadata": {},
            "collections": [{"type": t, "scope": "c1", "service": t, "status": "collected", "items": i, "error": None}
                            for t, i in cols]}


def _canonical(result):
    def strip(value):
        if isinstance(value, dict):
            return {k: strip(v) for k, v in value.items() if k != "timing_seconds"}
        if isinstance(value, list):
            return [strip(v) for v in value]
        return value
    return json.dumps(strip(result), sort_keys=True, default=str)


def test_k8s_role_gain_memos_match_uncached_analysis(monkeypatch):
    memoized = privesc.analyze(k8s_snapshot(), include_unknown=True)
    assert memoized["graph"]["edges"], "fixture must reach RBAC gain techniques"
    with monkeypatch.context() as patch:
        # Reference: every lookup recomputed from scratch, as before the memos.
        patch.setattr(K8sModel, "_role_gain_memo",
                      lambda self: {"plans": {}, "gain": {}, "bindings": None})
        patch.setattr(K8sModel, "_role_binding_names",
                      lambda self, memo, kind, cluster, binding_ns, role:
                      self._role_binding_names_scan(kind, cluster, binding_ns, role))
        patch.setattr(K8sModel, "_one_ns_verdict", K8sModel._one_ns_verdict_uncached)
        plain = privesc.analyze(k8s_snapshot(), include_unknown=True)
    assert _canonical(memoized) == _canonical(plain)


def test_k8s_role_binding_index_matches_scan_in_order():
    model = K8sModel(k8s_snapshot())
    memo = model._role_gain_memo()
    checked = 0
    for role in model.roles.values():
        for cluster in ("c1", "c2", "missing"):
            for kind, binding_ns in (("rolebinding", "a"), ("rolebinding", "b"), ("rolebinding", "zz"),
                                     ("clusterrolebinding", None)):
                got = list(model._role_binding_names(memo, kind, cluster, binding_ns, role))
                assert got == model._role_binding_names_scan(kind, cluster, binding_ns, role)
                checked += bool(got)
    assert checked >= 6


def test_k8s_bound_role_gain_memo_matches_uncached_per_pair():
    model = K8sModel(k8s_snapshot())
    sources = list(model.principals.values())
    targets = list(model._bound_role_gain_targets().values())
    assert len(targets) > 10
    memo = model._role_gain_memo()
    gains = 0
    for source in sources:
        for target in targets:
            cached = model._bound_role_gain(source, target, memo)
            fresh = model._bound_role_gain(source, target, {"plans": {}, "gain": {}, "bindings": None})
            assert cached == fresh
            assert model._bound_role_gain(source, target, memo) == cached
            gains += cached is not False
    assert gains


# --------------------------------------------------------------------------- evaluator blockers

def test_apply_blockers_per_target_downgrade_keeps_input_and_order():
    from peaso.privesc.effective_permissions import Grant
    from peaso.privesc.evaluator import Evaluator

    original = {"t1": Grant("derived", [{"r": 1}], []), "t2": Grant("derived", [{"r": 2}], []),
                "t3": Grant("derived", [{"r": 3}], [])}
    snapshot_of_input = dict(original)
    verdicts = iter([{"t1": ("possibly_blocked", "pss"), "t3": ("possibly_blocked", "pss")},
                     {"t3": None, "missing": ("possibly_blocked", "x")}])
    model = SimpleNamespace(provider="k8s",
                            blocker_verdict=lambda *a, **k: next(verdicts))
    fake = SimpleNamespace(model=model, note=lambda *a, **k: None)
    out = Evaluator._apply_blockers(fake, {"model_blockers": ["b1", "b2"]}, SimpleNamespace(scope="c1", id="s"),
                                    original)
    assert original == snapshot_of_input  # the caller's reach is never modified
    assert list(out) == ["t1", "t2", "t3"]
    assert out["t2"] is original["t2"]
    assert out["t1"].confidence == "conditional" and any("blocker_b1_possibly_enforced" in c for c in out["t1"].conditions)
    assert any("blocker_b2_not_evaluated" in c for c in out["t3"].conditions)
    assert any("blocker_b1_possibly_enforced" in c for c in out["t3"].conditions)


# --------------------------------------------------------------------------- GCP explanations and OS Config

def test_matched_role_permissions_equals_glob_scan():
    role = SimpleNamespace(native_permissions=(
        "compute.instances.get", "Compute.Instances.GET", "compute.instances.*", "compute.*", "*",
        "storage.objects.get", "compute.instances.get", "compute.instances.s?tMetadata", "iam.[x].get"))
    model = SimpleNamespace()
    for permission in ("compute.instances.get", "COMPUTE.INSTANCES.GET", "compute.instances.setMetadata",
                       "storage.objects.get", "iam.[x].get", "unrelated.thing", ""):
        expected = sorted(p for p in role.native_permissions if glob_match(p, permission))
        assert grant_evidence._matched_role_permissions(model, role, permission) == expected
    other = SimpleNamespace(native_permissions=("storage.objects.get",))
    assert grant_evidence._matched_role_permissions(model, other, "compute.instances.get") == []


class _Slotted:
    __slots__ = ("snapshot",)

    def __init__(self, snapshot):
        self.snapshot = snapshot

    def _norm_scope(self, name):
        return str(name or "").replace("projects/123", "projects/p1")


def test_osconfig_rows_in_matches_scan_and_memo_falls_back():
    snapshot = {"collections": [
        {"type": "instance", "scope": "projects/p1", "items": [{"name": "a"}, {"name": "b"}]},
        {"type": "instance", "scope": "projects/123", "items": [{"name": "c"}, "not-a-row"]},
        {"type": "instance", "scope": "projects/p2", "items": [{"name": "d"}]},
        {"type": "project", "scope": "projects/p1", "items": [{"projectId": "p1"}]}]}

    class Model(_Slotted):
        __slots__ = ("__dict__",)

    for model in (Model(snapshot), _Slotted(snapshot)):
        for scope in ("projects/p1", "projects/p2", "projects/none"):
            expected = [(raw, row) for raw, row in items(snapshot, "instance") if model._norm_scope(raw) == scope]
            assert list(gcp_osconfig_index.rows_in(model, "instance", scope)) == expected
        calls = []
        compute = lambda: calls.append(1) or ["x"]
        assert gcp_osconfig_index.memo(model, "kind", "key", compute) == ["x"]
        assert gcp_osconfig_index.memo(model, "kind", "key", compute) == ["x"]
        assert len(calls) == (1 if hasattr(model, "__dict__") else 2)
        assert gcp_osconfig_index.memo(model, "kind", ["unhashable"], compute) == ["x"]


def test_osconfig_name_lists_are_private_copies():
    from peaso.privesc.effective_permissions import gcp_osconfig_guest_policy as guest

    project = "projects/p1"
    snapshot = {"collections": [{"type": "osconfig_guest_policy", "scope": project, "status": "collected",
                                 "items": [{"name": project + "/guestPolicies/two"},
                                           {"name": project + "/guestPolicies/one"}]}]}
    model = SimpleNamespace(snapshot=snapshot, _norm_scope=lambda name: str(name or ""))
    first = guest.policy_resources(model, project)
    assert first == [project + "/guestPolicies/one", project + "/guestPolicies/two"]
    first.append("caller-mutation")
    assert guest.policy_resources(model, project) == [project + "/guestPolicies/one", project + "/guestPolicies/two"]


# --------------------------------------------------------------------------- AWS trust

def _aws_trust_snapshot():
    from tests.test_peaso_perf_benchmark import ACCOUNT, synthetic_snapshot

    snap = synthetic_snapshot(vpcs=1, subnets=1, groups_count=1, instances=1, principals=12, iam_groups=2)
    roles = next(c for c in snap["collections"] if c["type"] == "iam_role")["items"]
    user_arn = next(c for c in snap["collections"] if c["type"] == "iam_user")["items"][0]["Arn"]
    extra = [
        # names one exact user: that user is evaluated on its own, everyone else shares the account verdict
        {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Principal": {"AWS": [f"arn:aws:iam::{ACCOUNT}:root", user_arn]}, "Action": "sts:AssumeRole"}]},
        # conditional trust: never shared
        {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT}:root"}, "Action": "sts:AssumeRole",
             "Condition": {"StringEquals": {"aws:PrincipalTag/team": "blue"}}}]},
        # explicit deny of one exact user
        {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Principal": {"AWS": ACCOUNT}, "Action": "sts:AssumeRole"},
            {"Effect": "Deny", "Principal": {"AWS": user_arn}, "Action": "sts:AssumeRole"}]},
    ]
    for i, trust in enumerate(extra):
        if i < len(roles):
            roles[i]["AssumeRolePolicyDocument"] = trust
    return snap


def test_aws_trusting_shares_only_source_independent_verdicts():
    from peaso.privesc.effective_permissions.aws import AwsModel, _norm_arn

    model = AwsModel(_aws_trust_snapshot())
    sources = list(model.principals.values())
    assert sources
    shared_any = False
    for source in sources:
        expected = {}
        for table in (model.trust_by_arn.get(_norm_arn(source.id), {}), model.trust_by_account.get(source.scope, {}),
                      model.trust_public):
            for rid, value in table.items():
                if rid == source.id or rid in expected:
                    continue
                verdict = model._trust_verdict(source, rid, value)
                if verdict is not None:
                    expected[rid] = verdict
        got = model._trusting(source)
        assert list(got) == list(expected)
        assert got == expected
        shared_any |= bool(model.__dict__.get("_plain_trust_verdicts"))
    assert shared_any
    plain = model.__dict__["_plain_trust_principal_cache"]
    assert None in plain.values()  # the conditional trust policy is never shared


# --------------------------------------------------------------------------- offline risk rules

def test_bundled_rules_path_stays_patchable(monkeypatch, tmp_path):
    from scripts import cloud_permission_risks as risks

    real = risks._bundled_rules_path("aws")
    assert real == risks._install_root() / "risk_rules" / "aws.yaml"
    assert risks._install_root() is risks._install_root()
    replacement = tmp_path / "aws.yaml"
    replacement.write_text(real.read_text(encoding="utf-8"), encoding="utf-8")
    monkeypatch.setattr(risks, "_bundled_rules_path", lambda provider: replacement)
    with risks.offline_rules():
        assert risks._load_yaml("aws").get("provider") == "aws"
    replacement.unlink()
    with risks.offline_rules():
        with pytest.raises(OSError):
            risks._load_yaml("aws")


def test_verified_catalog_reuses_the_process_catalog_only_for_identical_bytes(tmp_path, monkeypatch):
    import shutil
    from peaso import privesc
    from peaso.privesc import schema, versioned_catalog

    root = tmp_path / "catalog"
    shutil.copytree(schema.CATALOG_DIR, root)
    loaded = privesc.catalog(root)
    actual = {str(path.relative_to(root)): versioned_catalog._sha(path) for path in root.rglob("*.y*ml")}
    assert privesc.loaded_catalog_for(str(root), actual) is loaded
    assert loaded["entries"] == schema.load_catalog(root, strict=True)["entries"]

    changed = dict(actual)
    changed[next(iter(changed))] = "0" * 64
    assert privesc.loaded_catalog_for(str(root), changed) is None
    assert privesc.loaded_catalog_for(str(tmp_path / "other"), actual) is None

    # The strict verifier raises exactly what a strict load of the same bytes raises.
    monkeypatch.setitem(privesc._CATALOG_FINGERPRINTS, str(root),
                        (actual, {**loaded, "errors": ["aws/x.yaml: broken"]}))
    calls = []
    monkeypatch.setattr(versioned_catalog, "load_catalog", lambda *a, **k: calls.append(a) or loaded)
    with pytest.raises(schema.CatalogError, match="aws/x.yaml: broken"):
        versioned_catalog._current_entries.__wrapped__(str(root))
    assert calls == []


def _azure_snapshot(owners=True):
    import random
    rnd = random.Random(7)
    tenant = "/tenants/t"
    subs = [f"/subscriptions/00000000-0000-0000-0000-{i:012d}" for i in range(2)]
    users = [f"u-{i:03d}" for i in range(30)]
    sps = [f"sp-{i:03d}" for i in range(12)]
    groups = [f"g-{i:02d}" for i in range(4)]
    pool = ["Microsoft.Authorization/roleAssignments/write", "Microsoft.Compute/virtualMachines/runCommand/action",
            "Microsoft.Compute/virtualMachines/extensions/write",
            "Microsoft.ManagedIdentity/userAssignedIdentities/*/assign/action", "Microsoft.Automation/automationAccounts/*",
            "*/read", "Microsoft.Web/sites/write"]
    roles = [f"{i:08d}-1111-1111-1111-111111111111" for i in range(8)]
    defs = [{"id": f"{subs[0]}/providers/Microsoft.Authorization/roleDefinitions/{rid}",
             "properties": {"roleName": f"role-{i}", "type": "CustomRole", "assignableScopes": ["/"],
                            "permissions": [{"actions": sorted(rnd.sample(pool, rnd.randint(1, 3))), "dataActions": []}]}}
            for i, rid in enumerate(roles)]

    def col(kind, scope, rows, status=None):
        return {"type": kind, "scope": scope, "service": "synthetic", "status": status or ("collected" if rows else "empty"),
                "items": rows}

    collections, rgs, vms, ras = [], [], [], []
    for index, sub in enumerate(subs):
        groups_here = [f"{sub}/resourceGroups/rg{j}" for j in range(2)]
        rgs += groups_here
        collections += [col("resource_group", sub, [{"id": r, "name": r.rsplit("/", 1)[-1]} for r in groups_here]),
                        col("role_definition", sub, defs if index == 0 else [])]
        for rg in groups_here:
            vms.append({"id": f"{rg}/providers/Microsoft.Compute/virtualMachines/vm", "name": "vm",
                        "type": "Microsoft.Compute/virtualMachines", "identity": {"principalId": rnd.choice(sps)}})
            vms.append({"id": f"{rg}/providers/Microsoft.Automation/automationAccounts/aa", "name": "aa",
                        "type": "Microsoft.Automation/automationAccounts"})
            vms.append({"id": f"{rg}/providers/Microsoft.Automation/automationAccounts/aa/runbooks/rb", "name": "rb",
                        "type": "Microsoft.Automation/automationAccounts/runbooks"})
    for i in range(160):
        principal, kind = rnd.choice([(rnd.choice(users), "User"), (rnd.choice(sps), "ServicePrincipal"),
                                      (rnd.choice(groups), "Group")])
        scope = rnd.choice(rgs + subs)
        ras.append({"id": f"{scope}/providers/Microsoft.Authorization/roleAssignments/{i}",
                    "properties": {"principalId": principal, "principalType": kind, "scope": scope,
                                   "roleDefinitionId": f"/providers/Microsoft.Authorization/roleDefinitions/{rnd.choice(roles)}"}})
    for sub in subs:
        collections += [col("role_assignment", sub, [r for r in ras if r["properties"]["scope"].startswith(sub)]),
                        col("deny_assignment", sub, [], "empty"),
                        col("vm", sub, [v for v in vms if v["id"].startswith(sub) and "virtualMachines" in v["id"]]),
                        col("resource_graph", sub, [v for v in vms if v["id"].startswith(sub)])]
    collections += [
        col("directory_user", tenant, [{"id": u, "userPrincipalName": f"{u}@t.com", "userType": "Member",
                                        "accountEnabled": True} for u in users]),
        col("directory_service_principal", tenant, [{"id": s, "displayName": s, "servicePrincipalType": "Application",
                                                     "accountEnabled": True} for s in sps]),
        col("directory_group", tenant, [{"id": g, "displayName": g, "securityEnabled": True} for g in groups]),
        col("directory_role_assignment", tenant, [], "empty"), col("directory_role_definition", tenant, [], "empty")]
    for group in groups:
        collections.append(col("directory_membership", f"{tenant}/groups/{group}", [{"id": m} for m in rnd.sample(users, 5)]))
    if owners:
        for sp in sps[:8]:
            collections.append(col("directory_owner", f"{tenant}/servicePrincipals/{sp}", [
                {"objectId": sp, "objectType": "servicePrincipal", "ownerIds": rnd.sample(users, 2)}]))
    return {"schema_version": "1.0", "provider": "azure", "scopes": [tenant] + subs, "created_at": "2026-10-10T00:00:00+00:00",
            "collections": collections, "metadata": {"tenant_id": "t"}}


@pytest.mark.parametrize("owners", [True, False])
def test_azure_scan_local_indexes_match_the_original_scans(monkeypatch, owners):
    from peaso import privesc
    from peaso.privesc import evaluator
    from peaso.privesc.effective_permissions import Grant, downgrade, items
    from peaso.privesc.effective_permissions import azure, azure_automation_assign as automation
    from peaso.snapshot import validate

    snapshot = validate(_azure_snapshot(owners), read_only=True)
    fast = privesc.analyze(snapshot)

    def candidates(self, principal, action, data):
        return [(pid, a, self.roles[a["role"]]) for pid in [principal.id, *principal.attrs.get("groups", [])]
                for a in self.assignments.get(pid, [])
                if self.roles.get(a["role"]) is not None and self.roles[a["role"]].allows(action, data)]

    def runbooks(model):
        single, nested = {}, []
        for rid, resource in model.resources.items():
            if resource.get("type") == automation.RUNBOOK_TYPE:
                if rid.count("/runbooks/") == 1:
                    single.setdefault(rid.partition("/runbooks/")[0], []).append(rid)
                else:
                    nested.append(rid)
        return single, nested

    monkeypatch.setattr(azure.AzureModel, "_rbac_candidates", candidates)
    monkeypatch.setattr(azure.AzureModel, "_owned_rows", lambda self, pid: items(self.snapshot, "directory_owner"))
    monkeypatch.setattr(azure.AzureModel, "_shared_unknown", lambda self, reason: Grant("unknown", [], [reason]))
    monkeypatch.setattr(automation, "_runbook_index", runbooks)
    monkeypatch.setattr(evaluator, "_downgrade_each", lambda current, verdict: {
        tid: (downgrade(g, *verdict[tid]) if verdict[tid] else g) for tid, g in current.items() if tid in verdict})
    slow = privesc.analyze(snapshot)
    assert _canonical(fast) == _canonical(slow)
    assert fast["graph"]["edges"]


def test_azure_rbac_candidates_follow_group_changes_and_owner_index_keeps_order():
    from peaso.privesc.effective_permissions import azure, items
    from peaso.snapshot import validate

    model = azure.AzureModel(validate(_azure_snapshot(), read_only=True))
    principal = next(p for p in model.principals.values() if p.attrs.get("groups"))
    action = "microsoft.automation/automationaccounts/runbooks/write"
    first = model._rbac_candidates(principal, action, False)
    assert model._rbac_candidates(principal, action, False) is first
    groups = principal.attrs["groups"]
    principal.attrs["groups"] = []
    try:
        direct = model._rbac_candidates(principal, action, False)
        assert all(pid == principal.id for pid, _, _ in direct)
    finally:
        principal.attrs["groups"] = groups
    owner = "u-000"
    expected = [(scope, row) for scope, row in items(model.snapshot, "directory_owner")
                if owner in (row.get("ownerIds") or [])]
    assert [pair for pair in model._owned_rows(owner) if owner in pair[1]["ownerIds"]] == expected
    assert model._shared_unknown("x") is model._shared_unknown("x")


def test_downgrade_each_shares_one_result_per_grant_and_verdict():
    from peaso.privesc.effective_permissions import Grant
    from peaso.privesc.evaluator import _downgrade_each

    shared, other = Grant("derived", [{"a": 1}]), Grant("conditional", [{"b": 2}])
    current = {"t1": shared, "t2": shared, "t3": other, "t4": shared}
    verdict = {"t1": ("conditional", "x"), "t2": ("conditional", "x"), "t3": None, "t4": ["unknown", "y"]}
    out = _downgrade_each(current, verdict)
    assert list(out) == ["t1", "t2", "t3", "t4"]
    assert out["t1"] is out["t2"] and out["t1"].conditions == ("x",) and out["t1"].confidence == "conditional"
    assert out["t3"] is other
    assert out["t4"].confidence == "unknown" and out["t4"].conditions == ("y",)


def _modify_target_scan(model, principal, verb, resource, namespace, name, rule):
    from peaso.privesc.effective_permissions import as_list, inventory_status, unavailable
    from peaso.privesc.effective_permissions.k8s import MODIFIABLE_OBJECTS, _cluster
    if verb not in ("patch", "update") or resource not in MODIFIABLE_OBJECTS:
        return True
    kind = MODIFIABLE_OBJECTS[resource]
    names = set(str(v) for v in as_list(rule.get("resourceNames")))
    for _, item in items(model.snapshot, kind):
        meta = item.get("metadata") or {}
        if resource == "mutatingwebhookconfigurations" and item.get("kind") != "MutatingWebhookConfiguration":
            continue
        if _cluster(item) != principal.attrs.get("cluster") or (
                namespace not in (ANY, "*") and meta.get("namespace") != namespace):
            continue
        object_name = str(meta.get("name") or "")
        if object_name and (name in (None, ANY) or object_name == name) and (not names or object_name in names):
            return True
    states = inventory_status(model.snapshot, kind)
    return False if states and not unavailable(states) else None


def test_k8s_modify_target_index_matches_the_inventory_scan():
    from peaso.privesc.effective_permissions.k8s import MODIFIABLE_OBJECTS
    snapshot = k8s_snapshot()
    snapshot["collections"].append({"type": "admission_configuration", "scope": "c1", "service": "x",
                                    "status": "collected", "error": None, "items": [
                                        _obj("MutatingWebhookConfiguration", "hook"), _obj("Other", "not-a-hook")]})
    model = K8sModel(snapshot)
    principals = [p for p in model.principals.values() if p.attrs.get("cluster")]
    rules = [{}, {"resourceNames": ["p0"]}, {"resourceNames": ["missing"]}, {"resourceNames": ["hook", "not-a-hook"]}]
    checked = 0
    for principal in principals[:6]:
        for resource in sorted(MODIFIABLE_OBJECTS) + ["secrets"]:
            for verb in ("patch", "update", "get"):
                for namespace in (ANY, "*", "a", "b", "zz"):
                    for name in (None, ANY, "p0", "p1", "hook", "not-a-hook", "nope"):
                        for rule in rules:
                            expected = _modify_target_scan(model, principal, verb, resource, namespace, name, rule)
                            assert model._modify_target_exists(principal, verb, resource, namespace, name,
                                                               rule) == expected, (resource, namespace, name, rule)
                            checked += 1
    assert checked


def test_k8s_rbac_only_confidence_matches_check_for_every_principal():
    model = K8sModel(k8s_snapshot())
    probes = [("get", "", "secrets", "", "a", None), ("get", "", "secrets", "", "a", "tok"),
              ("create", "", "pods", "exec", "b", None), ("bind", "rbac.authorization.k8s.io", "roles", "", "a", None),
              ("update", "", "configmaps", "", "b", "cfg"), ("get", "", "nodes", "", "*", None)]
    for principal in list(model.principals.values()):
        for verb, group, base, sub, ns, name in probes:
            req = {"verb": verb, "api_group": group, "resource": base, "_rbac_only": True,
                   **({"subresource": sub} if sub else {})}
            ref = (ns, name, None)
            grant = model.check(principal, req, ref)
            expected = None if grant is None else grant.confidence
            probe = (verb, group, base, sub, ns, name)
            assert model._rbac_only_confidence(principal, req, ref, probe) == expected
            assert model._rbac_only_confidence(principal, req, ref, probe) == expected


def _reference_index(self):
    model = self.model
    self.by_key, self.universal = {}, set()
    for node in model.sources():
        keys, universal = model.possible(node)
        if universal:
            self.universal.add(node.id)
        for key in keys:
            self.by_key.setdefault(key, set()).add(node.id)
    self.all_sources = {n.id: n for n in model.sources()}
    self.service_managed_sources = {sid for sid, n in self.all_sources.items() if model.managed_source(n)}


def _gcp_shared_roles_snapshot():
    from tests.test_peaso_privesc_schema_ext import snapshot

    scope = "projects/p1"
    writer = {"name": "projects/p1/roles/writer", "includedPermissions": [
        "iam.serviceAccounts.actAs", "iam.serviceAccountKeys.create", "compute.instances.create",
        "resourcemanager.projects.setIamPolicy", "storage.objects.get"]}
    reader = {"name": "projects/p1/roles/reader", "includedPermissions": ["storage.objects.get"]}
    return snapshot("gcp", [
        ("project", scope, [{"projectId": "p1", "name": "projects/123", "_ancestry": []}]),
        ("iam_policy", scope, [{"name": scope, "bindings": [
            {"role": writer["name"], "members": ["user:a@corp.com", "user:b@corp.com",
                                                 "serviceAccount:w@p1.iam.gserviceaccount.com"]},
            {"role": reader["name"], "members": ["user:c@corp.com", "user:d@corp.com"]},
            {"role": "roles/owner", "members": ["user:o@corp.com"]}]}]),
        ("iam_role", scope, [writer, reader]),
        ("service_account", scope, [{"email": "w@p1.iam.gserviceaccount.com",
                                     "name": "projects/p1/serviceAccounts/w@p1.iam.gserviceaccount.com"},
                                    {"email": "t@p1.iam.gserviceaccount.com",
                                     "name": "projects/p1/serviceAccounts/t@p1.iam.gserviceaccount.com"}]),
        ("iam_deny_policy", scope, [], "empty"),
    ])


@pytest.mark.parametrize("provider", ["k8s", "aws", "azure", "gcp"])
def test_grouped_source_index_matches_per_source_index(monkeypatch, provider):
    from tests.test_peaso_perf_benchmark import synthetic_snapshot
    from peaso.privesc.evaluator import Evaluator
    from peaso.snapshot import validate

    build = {"k8s": k8s_snapshot, "aws": lambda: synthetic_snapshot(
        vpcs=1, subnets=1, groups_count=1, instances=1, principals=12, iam_groups=2), "azure": _azure_snapshot,
             "gcp": _gcp_shared_roles_snapshot}[provider]
    load = build if provider in ("k8s", "gcp") else (lambda: validate(build(), read_only=True))
    fast = privesc.analyze(load(), include_unknown=True)
    seen = []
    original = Evaluator._index

    def checked(self):
        original(self)
        grouped = (self.by_key, self.universal, self.all_sources, self.service_managed_sources)
        _reference_index(self)
        wanted = {r.key for c in self.compiled for alt in c["alternatives"] for r in alt}
        # Every looked-up key maps to the same sources; keys no requirement names are not indexed.
        assert {k: v for k, v in self.by_key.items() if k in wanted} == grouped[0]
        assert (self.universal, self.all_sources.keys(), self.service_managed_sources) == (
            grouped[1], grouped[2].keys(), grouped[3])
        seen.append(len(grouped[0]))

    with monkeypatch.context() as patch:
        patch.setattr(Evaluator, "_index", checked)
        privesc.analyze(load(), include_unknown=True)
    with monkeypatch.context() as patch:
        patch.setattr(Evaluator, "_index", _reference_index)
        slow = privesc.analyze(load(), include_unknown=True)
    assert seen and max(seen) > 0
    assert _canonical(fast) == _canonical(slow)


def _reference_rules(model, principal):
    for ns, role_key, evidence in principal.attrs.get("bound", ()):
        role = model.roles.get(role_key)
        if role is None:
            yield ns, None, dict(evidence)
            continue
        for rule in role["rules"]:
            yield ns, rule, {**dict(evidence), "namespace": ns, "rule": rule}


def test_k8s_rule_rows_and_lazy_evidence_match_the_eager_rules():
    from peaso.snapshot import freeze

    snap = k8s_snapshot()
    model = K8sModel(snap)
    model.roles[("c1", None, "missing-role")] = None  # a binding to an absent role stays visible as rule None
    for principal in model.principals.values():
        expected = list(_reference_rules(model, principal))
        assert list(model._rules(principal)) == expected
        assert [(ns, rule) for ns, rule, _ in model._rule_rows(principal)] == [(ns, rule) for ns, rule, _ in expected]
    plain = privesc.analyze(snap, include_unknown=True)
    sealed = privesc.analyze(freeze(snap), include_unknown=True)
    assert plain["graph"]["edges"] and _canonical(plain) == _canonical(sealed)


def test_k8s_sealed_rule_verbs_are_cached_by_identity_and_bounded(monkeypatch):
    from peaso.privesc.effective_permissions import k8s
    from peaso.snapshot import freeze

    monkeypatch.setattr(k8s, "_SEALED_RULE_VERBS", {})
    monkeypatch.setattr(k8s, "_SEALED_RULE_VERBS_LIMIT", 2)
    plain = {"verbs": ["GET", "Patch"], "apiGroups": [""], "resources": ["pods", "pods/exec"], "resourceNames": ["a"]}
    sealed = freeze(plain)
    for verb, sub, name in [("get", "", "a"), ("patch", "", None), ("create", "exec", "a"), ("list", "", "a"),
                            ("prefix:pa", "", "b")]:
        verb = k8s.PREFIX + verb[len("prefix:"):] if verb.startswith("prefix:") else verb
        for partial in (False, True):
            assert k8s._rule_matches(sealed, verb, "", "pods", sub, name, partial) == \
                k8s._rule_matches(plain, verb, "", "pods", sub, name, partial)
    assert list(k8s._SEALED_RULE_VERBS.values()) == [(sealed, ["get", "patch"])]
    k8s._rule_matches(plain, "get", "", "pods", "", "a")
    assert len(k8s._SEALED_RULE_VERBS) == 1  # mutable rules are never cached
    others = [freeze({"verbs": [v], "apiGroups": [""], "resources": ["pods"]}) for v in ("LIST", "WATCH")]
    for rule in others:
        assert k8s._rule_matches(rule, rule["verbs"][0].lower(), "", "pods", "", None) is True
    assert len(k8s._SEALED_RULE_VERBS) <= 2


def _grant_view(grant):
    return None if grant is None else (grant.confidence, grant.conditions, grant.refs, grant.permission_refs)


def test_k8s_name_shared_check_matches_check_for_named_and_plain_principals():
    from peaso.privesc.effective_permissions.k8s import MODIFIABLE_OBJECTS
    model = K8sModel(k8s_snapshot())
    principals = [p for p in model.principals.values() if p.attrs.get("cluster")]
    reqs = [{"verb": "get", "resource": "secrets"}, {"verb": "create", "resource": "pods", "subresource": "exec"},
            {"verb": "update", "resource": "configmaps"}, {"verb": "patch", "resource": "pods"},
            {"verb": "update", "resource": "pods"}, {"verb": "create", "resource": "pods"},
            {"verb": "patch", "resource": "pods", "subresource": "status"},
            {"verb": "update", "resource": "pods", "_rbac_only": True},
            {"verb": "patch", "api_group": "rbac.authorization.k8s.io", "resource": "rolebindings"},
            {"verb": "get", "resource_match": "any", "api_group": ""}]
    assert "pods" in MODIFIABLE_OBJECTS
    refs = [(ns, name, res) for ns in ("a", "b", "*", ANY) for name in (None, ANY, "p0", "p1", "tok", "cfg", "nope")
            for res in (None, "pods")]
    named = shared = 0
    for principal in principals:
        plain = not any(rule is not None and rule.get("resourceNames") for _, rule, _ in model._rule_rows(principal))
        named += not plain
        for req in reqs:
            seen = {}
            for ref in refs:
                got = model._name_shared_check(principal, req, ref)
                assert _grant_view(got) == _grant_view(model.check(principal, req, ref)), (principal.id, req, ref)
                if got is not None and plain:
                    first = seen.setdefault((ref[0], ref[2]), (ref[1], got))
                    shared += first[0] != ref[1] and first[1] is got
    assert named, "fixture must hold principals whose rules list resourceNames"
    assert shared, "plain principals must share one result across object names"


def test_k8s_compact_check_cache_and_shared_rule_grants_match_the_plain_path(monkeypatch):
    from peaso.privesc.effective_permissions import Grant, Model
    from peaso.privesc.effective_permissions.k8s import _rule_evidence
    model = K8sModel(k8s_snapshot())
    principal = next(p for p in model.principals.values() if p.attrs.get("bound"))
    req = {"verb": "get", "resource": "secrets"}
    first = model.cached_check(principal, req, ("a", None, None))
    assert model.cached_check(principal, req, tuple(["a", None, None])) is first
    assert len(model._interned_refs) == 1
    shared = privesc.analyze(k8s_snapshot(), include_unknown=True)
    with monkeypatch.context() as patch:
        patch.setattr(K8sModel, "cached_check", Model.cached_check)
        patch.setattr(K8sModel, "_name_shared_check", K8sModel.check)
        patch.setattr(K8sModel, "_rule_grant", lambda self, bind_ns, rule, evidence, conf, conditions: Grant(
            conf, [{**_rule_evidence(bind_ns, rule, evidence), "namespace": bind_ns or "*"}], conditions))
        plain = privesc.analyze(k8s_snapshot(), include_unknown=True)
    assert shared["graph"]["edges"]
    assert _canonical(shared) == _canonical(plain)


def test_k8s_requirement_key_memo_matches_and_skips_non_text(monkeypatch):
    from peaso.privesc.effective_permissions import k8s
    model = K8sModel(k8s_snapshot())
    reqs = [{"verb": "get", "resource": "secrets"}, {"verb": "GET", "resource": "secrets"},
            {"verb_prefix": "impersonate-on:", "resource": "x"}, {"verb": "get", "resource_match": "any"},
            {"verb": "get", "resource_match": "any", "api_group": ""}, {"verb": "get", "api_group": "apps",
                                                                        "resource": "deployments", "subresource": "scale"},
            {"verb": 1, "resource": "secrets"}, {"verb": True, "resource": "secrets"}, {"verb": 1.0, "resource": "secrets"},
            {"verb": "get", "resource": ["unhashable"]}, {}]
    monkeypatch.setattr(k8s, "_REQUIREMENT_KEYS", {})
    monkeypatch.setattr(k8s, "_REQUIREMENT_KEYS_LIMIT", 3)
    for _ in range(2):
        for req in reqs:
            assert model.requirement_key(req) == model._requirement_key(req), req
            assert len(k8s._REQUIREMENT_KEYS) <= 3
    assert all(type(v) is str or v is None or v is k8s._MISSING for shape in k8s._REQUIREMENT_KEYS for v in shape)


@pytest.mark.parametrize("owners", [True, False])
def test_azure_owner_sharing_and_scope_memos_match_the_per_pair_path(monkeypatch, owners):
    from peaso.privesc.effective_permissions import azure, items
    from peaso.snapshot import validate

    snapshot = validate(_azure_snapshot(owners), read_only=True)
    fast = privesc.analyze(snapshot, include_unknown=True)
    model = azure.AzureModel(snapshot)
    principal = next(p for p in model.principals.values() if p.kind == "azure_user" and not model._owned_rows(p.id))
    req = {"entra_owner_of": "{target.id}", "object_type": "servicePrincipal"}
    targets = [p for p in model.principals.values() if p.kind == "azure_service_principal"]
    assert model._ownerless_shared(principal, req, "{target.id}")
    assert not model._ownerless_shared(principal, {**req, "action": "x"}, "{target.id}")
    assert not model._ownerless_shared(principal, req, "{source.id}")
    with monkeypatch.context() as patch:
        patch.setattr(azure.AzureModel, "_ownerless_shared", lambda self, principal, req, template: False)
        per_pair = {t: _grant_view(g) for t, g in model.check_targets(principal, req, "{target.id}", targets).items()}
    assert {t: _grant_view(g) for t, g in model.check_targets(principal, req, "{target.id}", targets).items()} == per_pair
    with monkeypatch.context() as patch:
        patch.setattr(azure.AzureModel, "_ownerless_shared", lambda self, principal, req, template: False)
        patch.setattr(azure.AzureModel, "_owner_absent", azure.AzureModel._owner_absent_uncached)
        patch.setattr(azure.AzureModel, "covers", azure.AzureModel._covers)
        patch.setattr(azure.AzureModel, "_graph_principal_listed", lambda self: any(
            azure._low(row.get("appId")) == "00000003-0000-0000-c000-000000000000"
            for _, row in items(self.snapshot, "directory_service_principal")))
        slow = privesc.analyze(snapshot, include_unknown=True)
    assert _canonical(fast) == _canonical(slow)
    assert fast["graph"]["edges"]


def test_azure_covers_memo_is_bounded_and_matches(monkeypatch):
    from peaso.privesc.effective_permissions import azure
    from peaso.snapshot import validate

    model = azure.AzureModel(validate(_azure_snapshot(), read_only=True))
    monkeypatch.setattr(azure, "_COVERS_MEMO_LIMIT", 4)
    scopes = ["/", "/subscriptions/00000000-0000-0000-0000-000000000000",
              "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg0",
              "/providers/Microsoft.Management/managementGroups/mg", "/subscriptions/x/"]
    for outer in scopes:
        for ref in scopes + ["/subscriptions/00000000-0000-0000-0000-000000000000/resourcegroups/rg1/providers/a/b/c"]:
            assert model.covers(outer, ref) == model._covers(outer, ref)
            assert len(model._covers_memo) <= 4
