"""Kubernetes component declaration checks evaluate real flag inputs correctly."""
from copy import deepcopy

import pytest

from peaso.checks import CHECKS
from peaso.checks.k8s_finding_clarity_reviewed import ROWS


@pytest.mark.parametrize("check_id", sorted(ROWS))
def test_exact_kind_component_comparison_and_declaration_scope(check_id):
    from peaso.checks.fixtures import CASES
    from peaso.checks.facts import get
    check = next(check for check in CHECKS if check.id == check_id)
    binding = ROWS[check_id]["reviewed_binding"]
    component, fields, operation = binding["component"], binding["fields"], binding["operation"]
    def current_input(branch):
        item = deepcopy(CASES[check_id][branch])
        if branch == "pass" and check_id.endswith(".container_argument_kubelet_authorization_mode_no_always_allow"):
            pod = get(item, binding["pod_spec_path"], dict)
            flags = pod["containers"][0]["_component_config"]["flags"]
            assert flags["authorization-mode"] == "Webhook"
        return item
    for branch, expected_status in [("pass", "PASS"), ("fail", "FAIL")]:
        item = current_input(branch)
        assert check.evaluate(item, {})[0] == expected_status
    item = current_input("pass")
    pod = get(item, binding["pod_spec_path"], dict)
    flags = pod["containers"][0]["_component_config"]["flags"]
    for field in fields:
        flags.pop(field, None)
    assert check.evaluate(item, {})[0] == ("PASS" if operation == "absent" else "UNKNOWN")
    item = current_input("pass")
    pod = get(item, binding["pod_spec_path"], dict)
    pod["containers"][0]["_component_config"]["component"] = "etcd" if "kube-scheduler" in ((component,) if isinstance(component, str) else component) else "kube-scheduler"
    assert check.evaluate(item, {})[0] == "NOT_APPLICABLE"


@pytest.mark.parametrize("operation,fields,expected,flags,wanted", [
    ("gt", ["secure-port"], 0, {"secure-port": "0"}, False),
    ("gt", ["secure-port"], 0, {"secure-port": "1"}, True),
    ("gt", ["secure-port"], 0, {"secure-port": "-1"}, None),
    ("gt", ["secure-port"], 0, {"secure-port": "65536"}, True),
    ("nonzero_duration", ["streaming-connection-idle-timeout"], None,
     {"streaming-connection-idle-timeout": "0s"}, False),
    ("nonzero_duration", ["streaming-connection-idle-timeout"], None,
     {"streaming-connection-idle-timeout": "-1s"}, None),
    ("nonzero_duration", ["streaming-connection-idle-timeout"], None,
     {"streaming-connection-idle-timeout": "1m"}, True),
    ("nonzero_duration", ["streaming-connection-idle-timeout"], None,
     {"streaming-connection-idle-timeout": "unavailable"}, None),
    ("contains", ["authorization-mode"], "RBAC", {"authorization-mode": "Node,RBAC"}, True),
    ("contains", ["authorization-mode"], "RBAC", {"authorization-mode": "Node, RBAC"}, False),
    ("contains", ["authorization-mode"], "Node", {"authorization-mode": "NodeRestriction"}, False),
    ("present", ["cert-file", "key-file"], None, {"cert-file": "/cert", "key-file": ""}, False),
    ("equal", ["client-cert-auth"], "true", {"client-cert-auth": True}, None),
])
def test_family_comparison_boundaries_are_not_runtime_inferences(operation, fields, expected, flags, wanted):
    from peaso.checks.facts import Unavailable
    from peaso.checks.k8s_ports_components import compare
    if wanted is None:
        with pytest.raises(Unavailable):
            compare(flags, fields, operation, expected)
    else:
        assert compare(flags, fields, operation, expected) is wanted


@pytest.mark.parametrize("check_id", [cid for cid in sorted(ROWS) if
    "pod_security_policy_enabled" in cid or "security_context_deny_enabled" in cid])
def test_legacy_admission_version_boundaries_never_enable_removed_plugins(check_id):
    from peaso.checks.fixtures import CASES
    from peaso.checks.facts import get
    check = next(check for check in CHECKS if check.id == check_id)
    item = deepcopy(CASES[check_id]["fail"])
    config = get(item, ROWS[check_id]["reviewed_binding"]["pod_spec_path"], dict)["containers"][0]["_component_config"]
    config["version"] = "v1.24.9"
    assert check.evaluate(item, {})[0] == "FAIL"
    config.pop("version")
    assert check.evaluate(item, {})[0] == "UNKNOWN"
    config["version"] = "v1.30.0"
    assert check.evaluate(item, {})[0] == "NOT_APPLICABLE"
    if "pod_security_policy_enabled" in check_id:
        config["version"] = "v1.25.0"
        assert check.evaluate(item, {})[0] == "NOT_APPLICABLE"
    else:
        config["version"] = "v1.25.0"
        config["flags"]["enable-admission-plugins"] = "PodSecurityPolicy"
        assert check.evaluate(item, {})[0] == "FAIL"
        config["flags"]["enable-admission-plugins"] = "SecurityContextDeny"
        assert check.evaluate(item, {})[0] == "PASS"
