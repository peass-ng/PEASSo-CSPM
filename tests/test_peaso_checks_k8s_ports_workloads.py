"""Differential truth fixtures for reviewed workload expression families."""
import copy

import pytest

from peaso.checks import CHECKS
from peaso.checks import k8s_ports_workloads as ports
from peaso.checks.fixtures import nest
from peaso.checks.fixtures import CASES, nest

REGISTRY = {check.id: check for check in CHECKS if check.id in ports.IDS}


@pytest.mark.parametrize("cid", ports.IDS)
@pytest.mark.parametrize("case,wanted", [("pass", "PASS"), ("fail", "FAIL"), ("missing", "UNKNOWN"), ("malformed", "UNKNOWN"), ("denied", "UNKNOWN")])
def test_each_predicate_truth_coverage_and_immutability(cid, case, wanted):
    item = {"collection_status": "denied"} if case == "denied" else copy.deepcopy(ports.PORT_CASES[cid][case])
    original = copy.deepcopy(item)
    status, evidence = REGISTRY[cid].evaluate(item, {})
    assert status == wanted, evidence
    assert item == original


@pytest.mark.parametrize("kind,path", ports.KIND_PATHS.items())
def test_actual_template_paths_cover_init_and_ephemeral_containers(kind, path):
    item = nest(path, {"containers": [{"name": "app", "securityContext": {"privileged": False}}],
        "initContainers": [{"name": "init", "securityContext": {"privileged": True}}],
        "ephemeralContainers": [{"name": "debug", "securityContext": {"privileged": True}}]})
    original = copy.deepcopy(item)
    status, evidence = REGISTRY[ports.native_id(kind, "privileged")].evaluate(item, {})
    assert status == "FAIL"
    assert evidence.get("containers_needing_review", evidence.get("privileged_containers")) == ["init", "debug"]
    assert item == original


def reference_regular_container_status(suffix, container):
    """Independent CASE truth projections read from the pinned query bodies."""
    context = container.get("securityContext", {})
    if suffix == "privileged":
        return "FAIL" if context.get("privileged") is True else "PASS"
    if suffix == "privilege_escalation":
        return "PASS" if context.get("allowPrivilegeEscalation") is False else "FAIL"
    if suffix == "readonly_root":
        return "PASS" if context.get("readOnlyRootFilesystem") is True else "FAIL"
    if suffix == "declared_nonroot":
        return "PASS" if context.get("runAsNonRoot") is True else "FAIL"
    if suffix == "drop_all":
        return "PASS" if set(context.get("capabilities", {}).get("drop", [])) & {"all", "ALL"} else "FAIL"
    if suffix == "context_present":
        return "PASS" if "securityContext" in container else "FAIL"
    raise AssertionError("unmodeled reference expression")


@pytest.mark.parametrize("predicate", ["privileged", "privilege_escalation", "readonly_root", "declared_nonroot", "drop_all", "context_present"])
@pytest.mark.parametrize("context", [{}, {"privileged": True}, {"privileged": False}, {"allowPrivilegeEscalation": False},
    {"readOnlyRootFilesystem": True}, {"runAsNonRoot": True}, {"capabilities": {"drop": ["ALL"]}}])
def test_native_result_matches_pinned_reference_truth(predicate, context):
    container = {"name": "app", "securityContext": copy.deepcopy(context)}
    actual = REGISTRY[ports.native_id("pod", predicate)].evaluate({"spec": {"containers": [container]}}, {})[0]
    assert actual == reference_regular_container_status(predicate, container)


def test_seccomp_scope_is_not_collapsed_between_pod_and_controller_sources():
    pod = {"spec": {"containers": [{"name": "app", "securityContext": {"seccompProfile": {"type": "RuntimeDefault"}}}]}}
    assert REGISTRY["k8s.ports.pod.pod_runtime_default_seccomp"].evaluate(pod, {})[0] == "FAIL"
    deployment = {"spec": {"template": copy.deepcopy(pod)}}
    assert REGISTRY["k8s.ports.deployment.container_runtime_default_seccomp"].evaluate(deployment, {})[0] == "PASS"


def test_digest_pin_satisfies_immutable_intent_but_preserves_literal_source_alternative():
    item = {"spec": {"containers": [{"name": "app", "image": "repo/app@sha256:" + "a" * 64, "imagePullPolicy": "IfNotPresent"}]}}
    assert REGISTRY[ports.native_id("pod", "content_digest_or_always_pull")].evaluate(item, {})[0] == "PASS"
    # Source-bound successor: literal Always is distinct from immutable-image intent.
    # The explicit digest exception belongs only to content_digest_or_always_pull.
    assert REGISTRY[ports.native_id("pod", "always_pull")].evaluate(item, {})[0] == "FAIL"
    assert item["spec"]["containers"][0]["imagePullPolicy"] != "Always"
    item["spec"]["containers"][0]["imagePullPolicy"] = "Never"
    assert REGISTRY[ports.native_id("pod", "always_pull")].evaluate(item, {})[0] == "FAIL"
    item["spec"]["containers"][0]["imagePullPolicy"] = "IfNotPresent"
    item["spec"]["containers"][0]["image"] = "repo/app@sha256:invalid"
    assert REGISTRY[ports.native_id("pod", "content_digest_or_always_pull")].evaluate(item, {})[0] == "UNKNOWN"
    assert REGISTRY[ports.native_id("pod", "always_pull")].evaluate(item, {})[0] == "UNKNOWN"


def test_known_denied_property_does_not_use_optional_boolean_default():
    item = {"spec": {"containers": [{"name": "app", "securityContext": {"_coverage": {"privileged": {"status": "denied"}}}}]}}
    assert REGISTRY[ports.native_id("pod", "privileged")].evaluate(item, {})[0] == "UNKNOWN"


def test_capability_source_defects_have_counterexample_fixtures():
    item = {"spec": {"containers": [{"name": "app", "securityContext": {"capabilities": {"add": ["SYS_ADMIN"]}}}]}}
    assert REGISTRY["k8s.ports.pod.no_sys_admin"].evaluate(item, {})[0] == "FAIL"
    assert reference_regular_container_status("privileged", {"securityContext": {}}) == "PASS"
    # Actual source CAP_SYS_ADMIN membership misses this valid symbolic name.
    assert "CAP_SYS_ADMIN" not in item["spec"]["containers"][0]["securityContext"]["capabilities"]["add"]
    item["spec"]["containers"][0]["securityContext"]["capabilities"]["add"] = []
    assert REGISTRY["k8s.ports.pod.no_added_capabilities"].evaluate(item, {})[0] == "PASS"


def test_image_registry_port_and_optional_default_pull_policy():
    check = REGISTRY["k8s.ports.pod.pinned_image"]
    assert check.evaluate({"spec": {"containers": [{"name": "a", "image": "registry.example:5000/app:v2"}]}}, {})[0] == "PASS"
    pull = REGISTRY["k8s.ports.pod.always_pull"]
    assert pull.evaluate({"spec": {"containers": [{"name": "a", "image": "app:latest"}]}}, {})[0] == "FAIL"
    assert pull.evaluate({"spec": {"containers": [{"name": "a", "image": "app:v2"}]}}, {})[0] == "FAIL"
    assert pull.evaluate({"spec": {"containers": [{"name": "a", "image": "app:v2", "imagePullPolicy": "Always"}]}}, {})[0] == "PASS"
