"""Semantic regressions for native workload templates and namespace quota evidence."""
from peaso.checks.hacktricks_scope import includes
import copy
import pytest
from peaso.checks import CHECKS, HACKTRICKS
from peaso.checks.k8s_extended import EXTENDED_IDS, CONTROLLERS, GOOD
from peaso.checks.fixtures import CASES, nest
from peaso.engine import evaluate_snapshot, plan_collection
from peaso.snapshot import make_snapshot


def registry():
    return {c.id: c for c in CHECKS}


@pytest.mark.parametrize("cid", EXTENDED_IDS)
def test_extended_semantic_matrix(cid):
    check = registry()[cid]
    cases = CASES[cid]
    index = cases.get("index", {})
    for name, expected in (("pass", "PASS"), ("fail", "FAIL")):
        item = copy.deepcopy(cases[name])
        original = copy.deepcopy(item)
        assert check.evaluate(item, copy.deepcopy(index))[0] == expected
        assert item == original
    assert check.evaluate({}, index)[0] == "UNKNOWN"
    assert check.evaluate(None, index)[0] == "UNKNOWN"
    assert check.evaluate({"collection_status": "denied"}, index)[0] == "UNKNOWN"
    assert (HACKTRICKS in check.frameworks) == includes(check.id)


@pytest.mark.parametrize("kind", CONTROLLERS)
def test_controller_nonroot_inheritance_overrides_init_ephemeral_and_windows(kind):
    check = registry()[f"k8s.{kind}.non_root"]
    path = "spec.jobTemplate.spec.template.spec" if kind == "cronjob" else "spec.template.spec"
    spec = {"securityContext": {"runAsNonRoot": True}, "containers": [{"name": "app"}], "initContainers": [{"name": "init"}]}
    assert check.evaluate(nest(path, spec), {})[0] == "PASS"
    spec["ephemeralContainers"] = [{"name": "debug", "securityContext": {"runAsUser": 0}}]
    assert check.evaluate(nest(path, spec), {})[0] == "FAIL"
    spec["ephemeralContainers"][0]["securityContext"] = {"runAsNonRoot": False}
    assert check.evaluate(nest(path, spec), {})[0] == "FAIL"
    spec["ephemeralContainers"][0]["securityContext"] = {"runAsUser": "1000"}
    assert check.evaluate(nest(path, spec), {})[0] == "UNKNOWN"
    spec["os"] = {"name": "windows"}
    assert check.evaluate(nest(path, spec), {})[0] == "NOT_APPLICABLE"


@pytest.mark.parametrize("kind", CONTROLLERS)
def test_controller_defaults_are_documented_configuration_not_missing_templates(kind):
    path = "spec.jobTemplate.spec.template.spec" if kind == "cronjob" else "spec.template.spec"
    spec = {"containers": [{"name": "app"}]}
    assert registry()[f"k8s.{kind}.no_privileged"].evaluate(nest(path, spec), {})[0] == "PASS"
    assert registry()[f"k8s.{kind}.no_host_network"].evaluate(nest(path, spec), {})[0] == "PASS"
    assert registry()[f"k8s.{kind}.no_host_ports"].evaluate(nest(path, spec), {})[0] == "PASS"
    assert registry()[f"k8s.{kind}.non_root"].evaluate(nest(path, spec), {})[0] == "FAIL"
    for predicate in GOOD:
        assert registry()[f"k8s.{kind}.{predicate}"].evaluate(nest(path, {"containers": []}), {})[0] == "UNKNOWN"
        assert registry()[f"k8s.{kind}.{predicate}"].evaluate(nest(path, {"containers": [{"name": "app", "securityContext": []}]}), {})[0] == "UNKNOWN"


def test_hostport_zero_vs_nonzero_range_and_init_containers():
    check = registry()["k8s.pod.no_host_ports"]
    spec = {"containers": [{"name": "app", "ports": [{"containerPort": 443, "hostPort": 0}]}]}
    assert check.evaluate({"spec": spec}, {})[0] == "PASS"
    spec["initContainers"] = [{"name": "init", "ports": [{"hostPort": 443}]}]
    assert check.evaluate({"spec": spec}, {})[0] == "FAIL"
    for invalid in (-1, 65536, "443", True):
        spec["initContainers"][0]["ports"][0]["hostPort"] = invalid
        assert check.evaluate({"spec": spec}, {})[0] == "UNKNOWN"


def test_proc_and_selinux_do_not_claim_runtime_enforcement():
    check = registry()["k8s.pod.default_proc_mount"]
    spec = {"containers": [{"name": "app", "securityContext": {"procMount": "invented"}}]}
    assert check.evaluate({"spec": spec}, {})[0] == "UNKNOWN"
    spec["os"] = {"name": "windows"}
    assert check.evaluate({"spec": spec}, {})[0] == "NOT_APPLICABLE"
    check = registry()["k8s.pod.restrict_selinux_identity"]
    item = {"spec": {"containers": [{"name": "app", "securityContext": {"seLinuxOptions": {"type": "container_t"}}}]}}
    status, evidence = check.evaluate(item, {})
    assert status == "PASS" and "availability" in evidence["semantics"]
    item["spec"]["initContainers"] = [{"name": "init", "securityContext": {"seLinuxOptions": {"role": "custom_r"}}}]
    assert check.evaluate(item, {})[0] == "FAIL"
    item["spec"]["initContainers"][0]["securityContext"]["seLinuxOptions"] = []
    assert check.evaluate(item, {})[0] == "UNKNOWN"


def test_serviceaccount_default_and_pod_override_are_distinct():
    check = registry()["k8s.serviceaccount.disable_automount"]
    status, evidence = check.evaluate({"metadata": {"name": "app"}}, {})
    assert status == "FAIL" and evidence["automount_service_account_token"] is True
    assert "Pod may override" in evidence["semantics"]
    assert check.evaluate({"metadata": {"name": "app"}, "automountServiceAccountToken": "false"}, {})[0] == "UNKNOWN"


@pytest.mark.parametrize("field", ["limits_cpu", "requests_cpu", "limits_memory", "requests_memory"])
def test_quota_incomplete_scoped_invalid_and_other_namespace(field):
    cid = "k8s.namespace.quota_" + field
    check = registry()[cid]
    item = {"metadata": {"name": "apps"}}
    index = copy.deepcopy(CASES[cid]["index"])
    assert check.evaluate(item, {})[0] == "UNKNOWN"
    index["collections"]["resourcequota"][0]["status"] = "denied"
    assert check.evaluate(item, index)[0] == "UNKNOWN"
    index["collections"]["resourcequota"][0]["status"] = "partial"
    assert check.evaluate(item, index)[0] == "UNKNOWN"
    index["collections"]["resourcequota"][0]["status"] = "collected"
    index["resourcequota"][0]["data"]["spec"]["scopes"] = ["NotBestEffort"]
    assert check.evaluate(item, index)[0] == "MANUAL"
    index["resourcequota"][0]["data"]["spec"].pop("scopes")
    key = field.replace("_", ".")
    index["resourcequota"][0]["data"]["spec"]["hard"][key] = "invalid"
    assert check.evaluate(item, index)[0] == "UNKNOWN"
    index["resourcequota"][0]["data"]["metadata"]["namespace"] = "other"
    assert check.evaluate(item, index)[0] == "FAIL"


def test_quota_engine_scoping_and_missing_inventory():
    cid = "k8s.namespace.quota_limits_cpu"
    collections = [
        {"type": "namespace", "scope": scope, "status": "collected", "items": [{"metadata": {"name": "apps"}}]}
        for scope in ("cluster-one/*", "cluster-two/*")]
    collections += [
        {"type": "resourcequota", "scope": "cluster-one/*", "status": "collected", "items": [{"metadata": {"name": "quota", "namespace": "apps"}, "spec": {"hard": {"limits.cpu": "2"}}}]},
        {"type": "resourcequota", "scope": "cluster-two/*", "status": "empty", "items": []}]
    snapshot = make_snapshot("k8s", ["cluster-one/*", "cluster-two/*"], collections)
    report = evaluate_snapshot(snapshot, categories=["hardening"], checks=[cid])
    assert {(f["scope"], f["status"]) for f in report["findings"]} == {("cluster-one/*", "PASS"), ("cluster-two/*", "FAIL")}
    request = {"connector": {"provider": "k8s"}, "categories": ["hardening"], "checks": [cid]}
    assert plan_collection(request) == ["namespace", "resourcequota"]


def test_unrelated_namespace_inventory_cannot_establish_quota_absence():
    cid = "k8s.namespace.quota_limits_cpu"
    index = {"collections": {"resourcequota": [{"scope": "cluster/other", "status": "empty"}]}, "resourcequota": []}
    assert registry()[cid].evaluate({"metadata": {"name": "apps"}}, index)[0] == "UNKNOWN"
