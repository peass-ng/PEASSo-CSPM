"""Isolated signed sw56 Kubernetes draft checks."""
from __future__ import annotations

import copy

import pytest

from peaso.checks import CHECKS, evaluate_check
from peaso.checks import compliance_new_sw56 as sw

CLUSTER = "k8s-cluster:test"
SCOPE = "*"


def native(kind, name, **extra):
    return {"kind": kind, "metadata": {"name": name, "uid": name + "-uid"},
            "provenance": {"cluster_id": CLUSTER, "evidence": "read-only list"}, **extra}


def namespace(name="default", labels=None):
    row = native("Namespace", name)
    row["metadata"]["labels"] = {} if labels is None else labels
    return row


def pod(name="demo", image=None, **spec):
    row = native("Pod", name, spec={"containers": [{"name": "app", "image": image or IMAGE}], **spec})
    row["metadata"]["namespace"] = "default"
    return row


IMAGE = "registry.example/team/app@sha256:" + "a" * 64
OTHER = "registry.example/team/other@sha256:" + "b" * 64


@pytest.fixture(scope="module", autouse=True)
def clean_draft_registration():
    yield
    CHECKS[:] = [entry for entry in CHECKS if entry.id not in sw.IDS]


def index(**inventories):
    context = {"provider": "k8s", "scope": SCOPE, "metadata": {"cluster_id": CLUSTER}}
    result = {"context": context, "collections": {}}
    for kind, rows in inventories.items():
        result["collections"][kind] = [{"type": kind, "scope": SCOPE,
                                         "status": "collected", "items": rows}]
        result[kind] = [{"type": kind, "scope": SCOPE, "data": row} for row in rows]
    return result


def rule(operations=None):
    return {"apiGroups": [""], "apiVersions": ["v1"], "resources": ["pods"],
            "operations": operations or ["CREATE", "UPDATE"], "scope": "Namespaced"}


def policy(expression):
    return native("ValidatingAdmissionPolicy", "safe-pods", spec={
        "failurePolicy": "Fail", "matchConstraints": {"resourceRules": [rule()]},
        "validations": [{"expression": expression}]})


def binding(**match):
    return native("ValidatingAdmissionPolicyBinding", "safe-pods-binding", spec={
        "policyName": "safe-pods", "validationActions": ["Deny"],
        "matchResources": match})


def admission(expression=None, *, policies=True, bindings=True, namespaces=None):
    return index(namespace=[namespace()] if namespaces is None else namespaces,
                 admission_policy=([policy(expression)] if policies else []) +
                    ([binding()] if bindings else []))


def approved(index_):
    index_["context"]["metadata"]["compliance_policy"] = {
        "status": "collected", "cluster_id": CLUSTER, "approved_images": [IMAGE]}
    return index_


def check(check_id, row, facts):
    return evaluate_check(check_id, row, facts)[0]


@pytest.mark.parametrize("check_id", sw.ADMISSION_IDS)
def test_admission_pass_fail_unknown_and_empty_namespace(check_id):
    target = {"scope": SCOPE}
    good = admission(sw._required_cel(check_id.removeprefix("k8s.cis.admission_")))
    assert check(check_id, target, good) == "PASS"
    absent = admission(policies=False, bindings=False)
    assert check(check_id, target, absent) == "FAIL"
    assert check(check_id, target, admission("true")) == "UNKNOWN"
    assert check(check_id, target, admission(namespaces=[])) == "NOT_APPLICABLE"
    partial = copy.deepcopy(good)
    partial["collections"]["admission_policy"][0]["status"] = "partial"
    assert check(check_id, target, partial) == "UNKNOWN"
    malformed = copy.deepcopy(good)
    malformed["admission_policy"][0]["data"]["spec"]["matchConstraints"]["resourceRules"] = "pods"
    assert check(check_id, target, malformed) == "UNKNOWN"
    missing = copy.deepcopy(good)
    missing.pop("admission_policy")
    missing["collections"].pop("admission_policy")
    assert check(check_id, target, missing) == "UNKNOWN"
    foreign = copy.deepcopy(good)
    foreign["collections"]["namespace"][0]["scope"] = "elsewhere"
    assert check(check_id, target, foreign) == "UNKNOWN"


def test_admission_selectors_and_operations_cannot_overclaim():
    target = {"scope": SCOPE}
    check_id = "k8s.cis.admission_hostpid"
    good = admission("!has(object.spec.hostPID) || object.spec.hostPID == false")
    good["admission_policy"][1]["data"]["spec"]["matchResources"] = {
        "namespaceSelector": {"matchLabels": {"team": "allowed"}}}
    assert check(check_id, target, good) == "FAIL"
    good["namespace"][0]["data"]["metadata"]["labels"] = {"team": "allowed"}
    assert check(check_id, target, good) == "PASS"
    good["admission_policy"][1]["data"]["spec"]["matchResources"]["objectSelector"] = {
        "matchLabels": {"app": "trusted"}}
    assert check(check_id, target, good) == "UNKNOWN"
    good["admission_policy"][1]["data"]["spec"]["matchResources"] = {}
    good["admission_policy"][0]["data"]["spec"]["matchConstraints"]["resourceRules"] = [rule(["CREATE"])]
    assert check(check_id, target, good) == "FAIL"


def test_admission_unknown_for_conditions_fail_open_and_changed_literal():
    check_id = "k8s.cis.admission_capabilities_add_net_raw"
    target = {"scope": SCOPE}
    expression = sw._required_cel("capabilities_add_net_raw")
    facts = admission(expression.replace("NET_RAW", "NET _RAW"))
    assert check(check_id, target, facts) == "UNKNOWN"
    facts = admission(expression)
    facts["admission_policy"][0]["data"]["spec"]["failurePolicy"] = "Ignore"
    assert check(check_id, target, facts) == "UNKNOWN"
    facts["admission_policy"][0]["data"]["spec"]["failurePolicy"] = "Fail"
    facts["admission_policy"][0]["data"]["spec"]["matchConditions"] = [
        {"expression": "object.metadata.name != 'excluded'"}]
    assert check(check_id, target, facts) == "UNKNOWN"


def test_secret_reference_pass_fail_unknown():
    row = pod(imagePullSecrets=[{"name": "registry-auth"}])
    assert check(sw.SECRET_ID, row, index(pod=[row])) == "PASS"
    empty = pod()
    assert check(sw.SECRET_ID, empty, index(pod=[empty])) == "FAIL"
    missing = copy.deepcopy(empty)
    missing["provenance"]["evidence"] = "projection"
    assert check(sw.SECRET_ID, missing, index(pod=[missing])) == "UNKNOWN"
    malformed = pod(imagePullSecrets=[{"name": 4}])
    assert check(sw.SECRET_ID, malformed, index(pod=[malformed])) == "UNKNOWN"
    partial = index(pod=[row])
    partial["collections"]["pod"][0]["status"] = "partial"
    assert check(sw.SECRET_ID, row, partial) == "UNKNOWN"
    assert check(sw.SECRET_ID, row, index()) == "UNKNOWN"
    foreign = copy.deepcopy(row)
    foreign["provenance"]["cluster_id"] = "other"
    assert check(sw.SECRET_ID, foreign, index(pod=[foreign])) == "UNKNOWN"


def test_approved_images_require_allowlist_and_deny_binding():
    row = pod()
    facts = approved(index(pod=[row], namespace=[namespace()],
                           admission_policy=[policy(sw._image_cel([IMAGE])), binding()]))
    assert check(sw.APPROVED_ID, row, facts) == "PASS"
    bad = pod(image=OTHER)
    bad_facts = copy.deepcopy(facts)
    bad_facts["pod"][0]["data"] = bad
    assert check(sw.APPROVED_ID, bad, bad_facts) == "FAIL"
    no_binding = approved(index(pod=[row], namespace=[namespace()], admission_policy=[]))
    assert check(sw.APPROVED_ID, row, no_binding) == "FAIL"
    uncertain = approved(index(pod=[row], namespace=[namespace()],
                               admission_policy=[policy("true"), binding()]))
    assert check(sw.APPROVED_ID, row, uncertain) == "UNKNOWN"
    missing_policy = copy.deepcopy(facts)
    missing_policy["context"]["metadata"].pop("compliance_policy")
    assert check(sw.APPROVED_ID, row, missing_policy) == "UNKNOWN"
    malformed = copy.deepcopy(facts)
    malformed["context"]["metadata"]["compliance_policy"]["approved_images"] = ["not-pinned"]
    assert check(sw.APPROVED_ID, row, malformed) == "UNKNOWN"
    partial = copy.deepcopy(facts)
    partial["collections"]["admission_policy"][0]["status"] = "partial"
    assert check(sw.APPROVED_ID, row, partial) == "UNKNOWN"
    foreign = copy.deepcopy(facts)
    foreign["context"]["metadata"]["compliance_policy"]["cluster_id"] = "foreign"
    assert check(sw.APPROVED_ID, row, foreign) == "UNKNOWN"


def apiserver_pod(*, enabled=True, path=True):
    row = pod()
    flags = {"enable-admission-plugins": "ImagePolicyWebhook" if enabled else "NamespaceLifecycle",
             "disable-admission-plugins": "NamespaceLifecycle"}
    if path:
        flags["admission-control-config-file"] = "/etc/kubernetes/admission.yaml"
    row["spec"]["containers"][0]["_component_config"] = {
        "component": "kube-apiserver", "flags_complete": True, "flags": flags}
    return row


def file_for(row, *, plugins=None):
    return {"pod_uid": row["metadata"]["uid"], "path": "/etc/kubernetes/admission.yaml",
            "verification_status": "verified", "plugins": plugins if plugins is not None else [
                {"name": "ImagePolicyWebhook", "configuration": {
                    "kubeConfigFile": "/etc/kubernetes/image-policy.kubeconfig"}}],
            "provenance": {"cluster_id": CLUSTER, "evidence": "read-only list"}}


def test_image_provenance_flags_and_verified_file():
    row = apiserver_pod()
    facts = index(pod=[row], admission_configuration_file=[file_for(row)])
    assert check(sw.PROVENANCE_ID, row, facts) == "PASS"
    no_plugin = apiserver_pod(enabled=False)
    assert check(sw.PROVENANCE_ID, no_plugin, index(pod=[no_plugin])) == "FAIL"
    no_path = apiserver_pod(path=False)
    assert check(sw.PROVENANCE_ID, no_path, index(pod=[no_path])) == "UNKNOWN"
    assert check(sw.PROVENANCE_ID, row, index(pod=[row])) == "UNKNOWN"
    broken = index(pod=[row], admission_configuration_file=[file_for(row, plugins=[])])
    assert check(sw.PROVENANCE_ID, row, broken) == "FAIL"
    ordinary = pod()
    ordinary["spec"]["containers"][0]["_component_config"] = {
        "component": None, "component_identification": "ordinary_command", "flags_complete": True}
    assert check(sw.PROVENANCE_ID, ordinary, index(pod=[ordinary])) == "NOT_APPLICABLE"
    partial = copy.deepcopy(facts)
    partial["collections"]["pod"][0]["status"] = "partial"
    assert check(sw.PROVENANCE_ID, row, partial) == "UNKNOWN"
    malformed = copy.deepcopy(facts)
    malformed["admission_configuration_file"][0]["data"]["plugins"] = "bad"
    assert check(sw.PROVENANCE_ID, row, malformed) == "UNKNOWN"
    foreign = copy.deepcopy(facts)
    foreign["admission_configuration_file"][0]["data"]["provenance"]["cluster_id"] = "other"
    assert check(sw.PROVENANCE_ID, row, foreign) == "UNKNOWN"


