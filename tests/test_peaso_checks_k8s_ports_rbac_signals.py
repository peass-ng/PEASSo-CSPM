"""Complete declared binding proof, scope constraints and system exemptions."""
import copy
import pytest
from peaso.checks import CHECKS, k8s_ports_rbac_signals as ports
from peaso.checks.fixtures import CASES

REGISTRY = {check.id: check for check in CHECKS if check.id in ports.IDS}


@pytest.mark.parametrize("cid", ports.IDS)
@pytest.mark.parametrize("case,wanted", [("pass", "PASS"), ("fail", "FAIL"), ("missing", "UNKNOWN"), ("malformed", "UNKNOWN"), ("denied", "UNKNOWN")])
def test_bound_signal_truths(cid, case, wanted):
    fixture = CASES[cid]
    item = {"collection_status": "denied"} if case == "denied" else copy.deepcopy(fixture[case])
    index = copy.deepcopy(fixture["pass_index"] if case == "pass" else fixture["fail_index"])
    before = copy.deepcopy((item, index))
    status, evidence = REGISTRY[cid].evaluate(item, index)
    assert status == wanted, evidence
    assert (item, index) == before


def scenario(mode="secret_read", kind="rolebinding"):
    cid = f"k8s.ports.{kind}.bound_{mode}_review"
    fixture = CASES[cid]
    return REGISTRY[cid], copy.deepcopy(fixture["fail"]), copy.deepcopy(fixture["fail_index"])


def test_named_secret_grant_is_preserved_and_top_level_create_cannot_use_resource_names():
    check, binding, index = scenario()
    index["role"][0]["data"]["rules"][0]["resourceNames"] = ["specific-secret"]
    status, evidence = check.evaluate(binding, index)
    assert status == "FAIL"
    assert evidence["declared_rules_needing_review"][0]["resource_names"] == ["specific-secret"]
    check, binding, index = scenario("pod_create")
    index["role"][0]["data"]["rules"][0]["resourceNames"] = ["specific-pod"]
    assert check.evaluate(binding, index)[0] == "PASS"


@pytest.mark.parametrize("group", ["system:authenticated", "system:unauthenticated", "system:serviceaccounts", "system:serviceaccounts:apps"])
def test_universal_and_application_serviceaccount_groups_are_never_system_exempt(group):
    check, binding, index = scenario()
    binding["subjects"] = [{"kind": "Group", "name": group}]
    assert check.evaluate(binding, index)[0] == "FAIL"


def test_system_user_exemption_and_application_sa_username_are_distinct():
    check, binding, index = scenario()
    binding["subjects"] = [{"kind": "User", "name": "system:kube-controller-manager"}]
    assert check.evaluate(binding, index)[0] == "NOT_APPLICABLE"
    binding["subjects"] = [{"kind": "User", "name": "system:serviceaccount:apps:app"}]
    assert check.evaluate(binding, index)[0] == "FAIL"


def test_kube_system_addon_exemption_requires_matching_collected_identity_metadata():
    check, binding, index = scenario()
    binding["subjects"] = [{"kind": "ServiceAccount", "name": "coredns", "namespace": "kube-system"}]
    assert check.evaluate(binding, index)[0] == "UNKNOWN"
    account = {"metadata": {"name": "coredns", "namespace": "kube-system", "labels": {"k8s-app": "coredns"}}, "provenance": {"cluster_id": "c"}}
    index["collections"]["serviceaccount"] = [{"scope": "*", "status": "collected"}]
    index["serviceaccount"] = [{"data": account}]
    assert check.evaluate(binding, index)[0] == "NOT_APPLICABLE"
    account["metadata"]["labels"] = {}
    assert check.evaluate(binding, index)[0] == "FAIL"
    account["provenance"]["cluster_id"] = "other"
    assert check.evaluate(binding, index)[0] == "UNKNOWN"


def test_same_named_role_in_other_namespace_or_cluster_is_not_binding_proof():
    check, binding, index = scenario()
    index["role"][0]["data"]["metadata"]["namespace"] = "other"
    assert check.evaluate(binding, index)[0] == "UNKNOWN"
    index["role"][0]["data"]["metadata"]["namespace"] = "apps"
    index["role"][0]["data"]["provenance"]["cluster_id"] = "other"
    assert check.evaluate(binding, index)[0] == "UNKNOWN"
    index["collections"]["role"][0]["status"] = "denied"
    assert check.evaluate(binding, index)[0] == "UNKNOWN"


def test_wildcards_and_exact_subresources_match_without_executing_any_action():
    check, binding, index = scenario("pod_exec")
    rule = index["role"][0]["data"]["rules"][0]
    rule.update(apiGroups=["*"], resources=["*/exec"], verbs=["*"])
    assert check.evaluate(binding, index)[0] == "FAIL"
    rule["resources"] = ["pods"]
    assert check.evaluate(binding, index)[0] == "PASS"


def test_namespaced_binding_cannot_grant_cluster_user_impersonation_and_userextras_are_covered():
    check, binding, index = scenario("impersonation")
    rule = index["role"][0]["data"]["rules"][0]
    rule["resources"] = ["users"]
    assert check.evaluate(binding, index)[0] == "PASS"
    check, binding, index = scenario("impersonation", "clusterrolebinding")
    index["clusterrole"][0]["data"]["rules"][0] = {"apiGroups": ["authentication.k8s.io"], "resources": ["userextras/scopes"], "verbs": ["impersonate"]}
    assert check.evaluate(binding, index)[0] == "FAIL"


def test_aggregation_selector_closure_is_complete_and_input_only():
    check, binding, index = scenario(kind="clusterrolebinding")
    aggregate = index["clusterrole"][0]["data"]
    aggregate["rules"] = []
    aggregate["aggregationRule"] = {"clusterRoleSelectors": [{"matchLabels": {"security-review": "include"}}]}
    child = {"metadata": {"name": "child", "labels": {"security-review": "include"}}, "provenance": {"cluster_id": "c"},
        "rules": [{"apiGroups": [""], "resources": ["secrets"], "verbs": ["list"]}]}
    index["clusterrole"].append({"data": child})
    status, evidence = check.evaluate(binding, index)
    assert status == "FAIL" and evidence["declared_rules_needing_review"][0]["declaring_role"] == "child"
    index["collections"]["clusterrole"][0]["status"] = "partial"
    assert check.evaluate(binding, index)[0] == "UNKNOWN"


def test_empty_subjects_and_malformed_role_group_are_explicit():
    check, binding, index = scenario()
    binding["subjects"] = []
    assert check.evaluate(binding, index)[0] == "NOT_APPLICABLE"
    binding["roleRef"]["apiGroup"] = "unknown.example"
    assert check.evaluate(binding, index)[0] == "UNKNOWN"
