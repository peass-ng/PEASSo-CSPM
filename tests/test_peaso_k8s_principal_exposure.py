"""analysis.principal_exposure on Kubernetes RBAC subjects: only cross-boundary or public subjects."""
from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot

SCOPE = "k8s-cluster:test"
PUBLIC_INFO = [{"nonResourceURLs": ["/healthz", "/livez", "/readyz", "/version", "/version/"], "verbs": ["get"]}]
SELF_REVIEW = [{"apiGroups": ["authorization.k8s.io"], "resources": ["selfsubjectaccessreviews", "selfsubjectrulesreviews"], "verbs": ["create"]}]


def role(name, rules):
    return {"metadata": {"name": name, "uid": "r-" + name}, "rules": rules}


def binding(name, role_name, subjects):
    return {"metadata": {"name": name, "uid": "b-" + name}, "roleRef": {"kind": "ClusterRole", "name": role_name, "apiGroup": "rbac.authorization.k8s.io"},
            "subjects": subjects}


def exposure(roles, bindings, metadata=None):
    snap = make_snapshot("k8s", [SCOPE], [
        {"type": "clusterrole", "scope": SCOPE, "service": "rbac", "status": "collected", "items": roles},
        {"type": "clusterrolebinding", "scope": SCOPE, "service": "rbac", "status": "collected", "items": bindings}], metadata=metadata)
    return {f["evidence"]["principals"][0]["principal"]: f["status"]
            for f in evaluate_snapshot(snap)["findings"] if f["check_id"] == "analysis.principal_exposure"}


def group(name):
    return {"kind": "Group", "name": name, "apiGroup": "rbac.authorization.k8s.io"}


def test_in_cluster_and_control_plane_subjects_are_not_exposure():
    subjects = [{"kind": "ServiceAccount", "name": "ctrl", "namespace": "kube-system"}, {"kind": "User", "name": "system:kube-scheduler"},
                {"kind": "User", "name": "kubelet-bootstrap"}, {"kind": "User", "name": "cluster-autoscaler"}, group("system:nodes"),
                group("system:serviceaccounts")]
    assert exposure([role("edit-all", [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}])],
                    [binding("b" + str(i), "edit-all", [s]) for i, s in enumerate(subjects)]) == {}


def test_default_discovery_roles_bound_to_everyone_are_not_exposure():
    assert exposure([role("system:public-info-viewer", PUBLIC_INFO), role("system:basic-user", SELF_REVIEW)],
                    [binding("system:public-info-viewer", "system:public-info-viewer", [group("system:authenticated"), group("system:unauthenticated")]),
                     binding("system:basic-user", "system:basic-user", [group("system:authenticated")])]) == {}


def test_public_binding_to_a_widened_discovery_role_fails():
    widened = PUBLIC_INFO + [{"apiGroups": [""], "resources": ["secrets"], "verbs": ["get"]}]
    assert exposure([role("system:public-info-viewer", widened)],
                    [binding("system:public-info-viewer", "system:public-info-viewer", [group("system:unauthenticated")])]) == {"system:unauthenticated": "FAIL"}


def test_public_binding_to_uncollected_role_still_fails():
    assert exposure([], [binding("anon", "system:discovery", [group("system:unauthenticated")])]) == {"system:unauthenticated": "FAIL"}


def test_idp_users_are_unknown_until_domains_are_trusted():
    bindings = [binding("alice", "view", [{"kind": "User", "name": "alice@corp.example"}]),
                binding("mallory", "view", [{"kind": "User", "name": "mallory@evil.example"}])]
    assert exposure([], bindings) == {"alice@corp.example": "UNKNOWN", "mallory@evil.example": "UNKNOWN"}
    assert exposure([], bindings, metadata={"trusted_domains": ["corp.example"]}) == {"mallory@evil.example": "FAIL"}


def test_kcc_iam_policies_and_openshift_scc_public_subjects():
    snap = make_snapshot("k8s", [SCOPE], [
        {"type": "kcc_iampolicy", "scope": SCOPE, "status": "collected", "items": [{
            "metadata": {"name": "public", "generation": 1},
            "spec": {"resourceRef": {"kind": "StorageBucket", "name": "b"},
                     "bindings": [{"role": "roles/storage.objectViewer", "members": ["allUsers"]}]}}]},
        {"type": "kcc_iampartialpolicy", "scope": SCOPE, "status": "collected", "items": [{
            "metadata": {"name": "conditional", "generation": 2},
            "spec": {"resourceRef": {"kind": "Project", "name": "p"}, "bindings": [{
                "role": "roles/viewer", "members": [{"member": "allAuthenticatedUsers"}],
                "condition": {"expression": "request.time < timestamp('2030-01-01T00:00:00Z')"}}]}}]},
        {"type": "securitycontextconstraint", "scope": SCOPE, "status": "collected", "items": [{
            "metadata": {"name": "privileged"}, "users": ["system:anonymous"], "groups": ["system:authenticated"]}]},
    ])
    report = evaluate_snapshot(snap)
    findings = [f for f in report["findings"] if f["check_id"] == "analysis.principal_exposure"]
    by_type = {next(r["type"] for r in report["resources"] if r["id"] == f["resource_id"]): f for f in findings}
    assert by_type["kcc_iampolicy"]["status"] == "FAIL"
    assert by_type["kcc_iampartialpolicy"]["status"] == "MANUAL"
    assert by_type["securitycontextconstraint"]["status"] == "FAIL"


def test_kcc_current_observed_bindings_override_stale_public_spec():
    policy = {"metadata": {"name": "private", "generation": 3},
              "spec": {"bindings": [{"role": "roles/viewer", "members": ["allUsers"]}]},
              "status": {"observedGeneration": 3, "allBindings": [{"role": "roles/viewer", "members": ["user:owner@example.com"]}]}}
    snap = make_snapshot("k8s", [SCOPE], [{"type": "kcc_iampartialpolicy", "scope": SCOPE,
                                           "status": "collected", "items": [policy]}],
                         metadata={"trusted_domains": ["example.com"]})
    assert not [f for f in evaluate_snapshot(snap)["findings"] if f["check_id"] == "analysis.principal_exposure"]


def test_k8s_exposure_collection_plan_includes_new_principal_sources():
    from peaso.analysis.catalog import REQUIRED_TYPES
    assert {"kcc_iampolicy", "kcc_iampartialpolicy", "securitycontextconstraint", "component_configuration"} <= set(
        REQUIRED_TYPES["k8s"]["exposure"])
