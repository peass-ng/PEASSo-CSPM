"""Focused public fixtures for three signed Kubernetes declaration checks."""
from datetime import datetime, timezone

import pytest

from peaso.checks.facts import MemoIndex
from peaso.collectors import k8s
from peaso.engine import _index
from peaso.snapshot import resources

from peaso.checks import evaluate_check
from peaso.checks import compliance_next_k8s as candidate

CLUSTER = "cluster-fixture"
STAMP = "2026-10-13T20:00:00Z"


def row(kind, name, *, namespace="apps", **facts):
    scope_name = namespace if kind in {"pod", "service", "ingress", "networkpolicy", "rolebinding"} else "_cluster"
    return {"id": f"k8s://{CLUSTER}/{kind}/{scope_name}/{name}",
            "metadata": {"name": name, **({"namespace": namespace} if scope_name != "_cluster" else {})},
            "provenance": {"cluster_id": CLUSTER, "evidence": "read-only list"}, **facts}


def snapshot(kinds, policy=None, status=None):
    policy = policy or {}
    context = {"provider": "k8s", "scope": "*", "created_at": STAMP,
               "metadata": {"cluster_id": CLUSTER, "compliance_policy": {
                   "status": "collected", "cluster_id": CLUSTER, "observed_at": STAMP,
                   "max_age_seconds": 300, **policy}}}
    index = MemoIndex(context=context, collections={})
    for kind, rows in kinds.items():
        state = (status or {}).get(kind, "collected" if rows else "empty")
        index["collections"][kind] = [{"type": kind, "scope": "*", "status": state, "items": rows}]
        index[kind] = [{"type": kind, "scope": "*", "provider": "k8s", "data": r} for r in rows]
    return index


def verdict(cid, index, kind=None):
    item = index["context"] if cid in candidate.IDS[:2] else index[kind or candidate.KINDS[cid]][0]["data"]
    return evaluate_check(cid, item, index)[0]


@pytest.mark.parametrize("cid,kind,good,bad,policy", [
    (candidate.IDS[2], "pod", {"metadata": {"name": "target", "namespace": "apps"}},
     {"metadata": {"name": "target", "namespace": "other"}}, {"approved_namespaces": ["apps"]}),
])
def test_per_resource_pass_fail_partial_missing(cid, kind, good, bad, policy):
    def make(facts):
        base = row(kind, "target", namespace=facts.get("metadata", {}).get("namespace", "apps"))
        base.update(facts)
        return base
    good_index = snapshot({kind: [make(good)]}, policy)
    bad_index = snapshot({kind: [make(bad)]}, policy)
    assert verdict(cid, good_index) == "PASS"
    assert verdict(cid, bad_index) == "FAIL"
    missing = snapshot({}, policy)
    assert evaluate_check(cid, good_index[kind][0]["data"], missing)[0] == "UNKNOWN"
    partial = snapshot({kind: [make(good)]}, policy, {kind: "partial"})
    assert verdict(cid, partial) == "UNKNOWN"


def test_required_response_binding_pass_fail_and_denied():
    cid = candidate.IDS[1]
    policy = {"allowed_namespaces": ["apps"], "required_subject_kind": "Group",
              "required_subject_name": "responders", "required_role_kind": "ClusterRole",
              "required_role_name": "incident-reader"}
    matching = row("rolebinding", "response", roleRef={"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "incident-reader"},
                   subjects=[{"kind": "Group", "name": "responders"}])
    good = snapshot({"rolebinding": [matching], "clusterrolebinding": []}, policy)
    assert verdict(cid, good) == "PASS"
    absent = snapshot({"rolebinding": [], "clusterrolebinding": []}, policy)
    assert verdict(cid, absent) == "FAIL"
    denied = snapshot({"rolebinding": [], "clusterrolebinding": []}, policy, {"rolebinding": "denied"})
    assert verdict(cid, denied) == "UNKNOWN"
    no_policy = snapshot({"rolebinding": [matching], "clusterrolebinding": []})
    assert verdict(cid, no_policy) == "UNKNOWN"


@pytest.mark.parametrize("subject_kind,subject", [
    ("User", {"kind": "User", "name": "responder", "apiGroup": "rbac.authorization.k8s.io"}),
    ("Group", {"kind": "Group", "name": "responder"}),  # Native apiGroup default.
])
def test_response_binding_valid_user_and_group(subject_kind, subject):
    policy = {"allowed_namespaces": ["apps"], "required_subject_kind": subject_kind,
              "required_subject_name": "responder", "required_role_kind": "ClusterRole",
              "required_role_name": "incident-reader"}
    binding = row("rolebinding", "response", roleRef={"apiGroup": "rbac.authorization.k8s.io",
                                                       "kind": "ClusterRole", "name": "incident-reader"},
                  subjects=[subject])
    assert verdict(candidate.IDS[1], snapshot({"rolebinding": [binding], "clusterrolebinding": []}, policy)) == "PASS"


@pytest.mark.parametrize("namespace", ["apps", "other"])
def test_response_binding_service_account_policy_lacks_namespace(namespace):
    policy = {"allowed_namespaces": ["apps"], "required_subject_kind": "ServiceAccount",
              "required_subject_name": "responder", "required_role_kind": "ClusterRole",
              "required_role_name": "incident-reader"}
    binding = row("rolebinding", "response", roleRef={"apiGroup": "rbac.authorization.k8s.io",
                                                       "kind": "ClusterRole", "name": "incident-reader"},
                  subjects=[{"kind": "ServiceAccount", "name": "responder", "namespace": namespace}])
    index = snapshot({"rolebinding": [binding], "clusterrolebinding": []}, policy)
    status, evidence = evaluate_check(candidate.IDS[1], index["context"], index)
    assert status == "UNKNOWN"
    assert "namespace absent" in evidence["reason"]


@pytest.mark.parametrize("role_ref,subject", [
    ({"kind": "ClusterRole", "name": "incident-reader"}, {"kind": "Group", "name": "responder"}),
    ({"apiGroup": "wrong", "kind": "ClusterRole", "name": "incident-reader"}, {"kind": "Group", "name": "responder"}),
    ({"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "incident-reader"},
     {"kind": "Group", "name": "responder", "apiGroup": "wrong"}),
    ({"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "incident-reader"},
     {"kind": "Group", "name": "responder", "namespace": "apps"}),
])
def test_response_binding_malformed_identity_unknown(role_ref, subject):
    policy = {"allowed_namespaces": ["apps"], "required_subject_kind": "Group",
              "required_subject_name": "responder", "required_role_kind": "ClusterRole",
              "required_role_name": "incident-reader"}
    binding = row("rolebinding", "response", roleRef=role_ref, subjects=[subject])
    assert verdict(candidate.IDS[1], snapshot({"rolebinding": [binding], "clusterrolebinding": []}, policy)) == "UNKNOWN"


def test_response_binding_matching_binding_cannot_hide_malformed_peer():
    policy = {"allowed_namespaces": ["apps"], "required_subject_kind": "User",
              "required_subject_name": "responder", "required_role_kind": "ClusterRole",
              "required_role_name": "incident-reader"}
    valid = row("rolebinding", "valid", roleRef={"apiGroup": "rbac.authorization.k8s.io",
                                                   "kind": "ClusterRole", "name": "incident-reader"},
                subjects=[{"kind": "User", "name": "responder"}])
    malformed = row("rolebinding", "malformed", roleRef={"apiGroup": "other", "kind": "ClusterRole",
                                                           "name": "view"}, subjects=[])
    assert verdict(candidate.IDS[1], snapshot({"rolebinding": [valid, malformed], "clusterrolebinding": []}, policy)) == "UNKNOWN"


def test_system_masters_observed_fail_or_unobserved_unknown():
    cid = candidate.IDS[0]
    cluster = row("clusterrolebinding", "base", roleRef={"kind": "ClusterRole", "name": "view"}, subjects=[])
    binding = row("rolebinding", "bad", roleRef={"kind": "ClusterRole", "name": "view"},
                  subjects=[{"kind": "Group", "name": "system:masters"}])
    observed = snapshot({"clusterrolebinding": [cluster], "rolebinding": [binding]})
    assert verdict(cid, observed) == "FAIL"
    assert evaluate_check(cid, observed["context"], observed)[1]["affected_bindings"] == [
        {"kind": "rolebinding", "binding_id": binding["id"]}]
    safe = snapshot({"clusterrolebinding": [cluster], "rolebinding": []})
    assert verdict(cid, safe) == "UNKNOWN"
    user_name_only = row("rolebinding", "user", subjects=[{"kind": "User", "name": "system:masters"}])
    negative = snapshot({"clusterrolebinding": [cluster], "rolebinding": [user_name_only]})
    assert verdict(cid, negative) == "UNKNOWN"
    partial = snapshot({"clusterrolebinding": [cluster], "rolebinding": []}, status={"rolebinding": "partial"})
    assert verdict(cid, partial) == "UNKNOWN"


def test_system_masters_many_clean_one_bad_and_all_partials():
    clean = [row("clusterrolebinding", f"clean-{i}", subjects=[]) for i in range(25)]
    bad = row("rolebinding", "bad", subjects=[{"kind": "Group", "name": "system:masters"}])
    index = snapshot({"clusterrolebinding": clean, "rolebinding": [bad]})
    status, evidence = evaluate_check(candidate.IDS[0], index["context"], index)
    assert status == "FAIL"
    assert evidence["affected_bindings"] == [{"kind": "rolebinding", "binding_id": bad["id"]}]
    assert len([key for key in index.memo if key[0] == "native_next_inventory"]) == 2
    for kind in ("clusterrolebinding", "rolebinding"):
        partial = snapshot({"clusterrolebinding": clean, "rolebinding": [bad]}, status={kind: "partial"})
        assert verdict(candidate.IDS[0], partial) == "UNKNOWN"


def test_service_account_subject_native_namespace_default():
    local = row("rolebinding", "local-sa", subjects=[{"kind": "ServiceAccount", "name": "responder"}])
    index = snapshot({"rolebinding": [local], "clusterrolebinding": []})
    status, evidence = evaluate_check(candidate.IDS[0], index["context"], index)
    assert status == "UNKNOWN"
    assert "no system:masters subject" in evidence["reason"]
    unqualified = row("clusterrolebinding", "unqualified-sa",
                      subjects=[{"kind": "ServiceAccount", "name": "responder"}])
    index = snapshot({"rolebinding": [], "clusterrolebinding": [unqualified]})
    status, evidence = evaluate_check(candidate.IDS[0], index["context"], index)
    assert status == "UNKNOWN"
    assert "no system:masters subject" in evidence["reason"]
    assert "memberships unobserved" in evidence["reason"]


def test_real_collector_policy_writer_to_memoindex_to_evaluate():
    """Use the actual collector policy projection and paged resource normalization."""
    captured = datetime.now(timezone.utc).isoformat()
    policy = {"cluster_id": CLUSTER, "max_policy_items": 20,
              "observed_at": captured, "max_age_seconds": 600,
              "allowed_namespaces": ["apps"], "required_subject_kind": "Group",
              "required_subject_name": "responders", "required_role_kind": "ClusterRole",
              "required_role_name": "incident-reader", "in_scope_service_names": ["lb"],
              "required_external_traffic_policy": "Local", "approved_namespaces": ["apps"]}
    objects = {
        "rolebindings": [{"metadata": {"name": "response", "namespace": "apps", "uid": "rb-1"},
                          "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "incident-reader"},
                          "subjects": [{"kind": "Group", "name": "responders"}]}],
        "clusterrolebindings": [],
        "services": [{"metadata": {"name": "lb", "namespace": "apps", "uid": "svc-1"},
                      "spec": {"type": "LoadBalancer", "externalTrafficPolicy": "Local"}}],
        "pods": [{"metadata": {"name": "app", "namespace": "apps", "uid": "pod-1"},
                  "spec": {"containers": [{"name": "app", "image": "registry.k8s.io/pause:3.5"}]}}],
    }
    class FakeAPI:
        server = "https://fixture.invalid"
        def get_json(self, path, params=None):
            return {"metadata": {"resourceVersion": "7"}, "items": objects[path.rsplit("/", 1)[-1]]}
    native = k8s.collect({"provider": "k8s", "auth": {"cluster_id": CLUSTER}, "scopes": ["*"],
                          "options": {"inventories": ["rolebinding", "clusterrolebinding", "service", "pod"],
                                      "compliance_policy": policy}}, api=FakeAPI())
    assert native["metadata"]["compliance_policy"]["status"] == "collected"
    index = MemoIndex(_index(native, resources(native)))
    index["context"] = {"provider": "k8s", "scope": "*", "created_at": native["created_at"],
                        "metadata": native["metadata"]}
    assert verdict(candidate.IDS[0], index) == "UNKNOWN"
    assert verdict(candidate.IDS[1], index) == "PASS", evaluate_check(candidate.IDS[1], index["context"], index)
    assert verdict(candidate.IDS[2], index) == "PASS"
    assert len([key for key in index.memo if key[0] == "native_next_inventory"]) == 3

    missing = dict(policy)
    del missing["approved_namespaces"]
    missing_native = k8s.collect({"provider": "k8s", "auth": {"cluster_id": CLUSTER}, "scopes": ["*"],
                                  "options": {"inventories": ["pod"], "compliance_policy": missing}}, api=FakeAPI())
    missing_index = MemoIndex(_index(missing_native, resources(missing_native)))
    missing_index["context"] = {"provider": "k8s", "scope": "*", "created_at": missing_native["created_at"],
                                "metadata": missing_native["metadata"]}
    assert verdict(candidate.IDS[2], missing_index) == "UNKNOWN"


def test_memoized_inventory_across_shared_pod_predicates():
    pod = row("pod", "target", spec={"containers": [{"name": "app", "image": "registry.k8s.io/pause:3.5"}]})
    index = snapshot({"pod": [pod]}, {"approved_namespaces": ["apps"]})
    assert verdict(candidate.IDS[2], index) == "PASS"
    assert verdict(candidate.IDS[2], index) == "PASS"
    assert len([key for key in index.memo if key[0] == "native_next_inventory"]) == 1
