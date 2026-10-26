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
    monkeypatch.setattr(versioned_catalog, "_sha", lambda path: versioned_catalog.CURRENT_MANIFEST
                        if path.name.endswith(".json") else actual.get(str(path.relative_to(root))))
    import json as _json
    manifest = tmp_path / "manifest.json"
    manifest.write_text(_json.dumps({"sha256": actual}))
    monkeypatch.setattr(versioned_catalog, "CURRENT_TREE", __import__("hashlib").sha256(
        "".join(f"{name} {actual[name]}\n" for name in sorted(actual)).encode()).hexdigest())
    with pytest.raises(schema.CatalogError, match="aws/x.yaml: broken"):
        versioned_catalog._verified_current.__wrapped__(str(root), str(manifest))
    assert calls == []
