"""Component flag truth fixtures and safe metadata projection acceptance."""
import copy
import json
import pytest
from peaso.checks import CHECKS
from peaso.checks import k8s_ports_components as ports
from peaso.checks.fixtures import CASES


@pytest.mark.parametrize("value", ["0", "0s", "0.0s", "+0s", "-0s", "0h0m0s", "0ms", "0.000us"])
def test_zero_duration_spellings_cannot_pass_numeric_timeout_policy(value):
    assert not ports.compare({"streaming-connection-idle-timeout": value}, ["streaming-connection-idle-timeout"], "nonzero_duration", None)
    if value != "0":
        assert "--streaming-connection-idle-timeout=" + value != "--streaming-connection-idle-timeout=0"  # Pinned SQL misses it.


def test_nonzero_subsecond_and_compound_durations_are_real_declarations():
    for value in ("1ms", "0.5s", "0h0m1s", "4h0m0s"):
        assert ports.compare({"streaming-connection-idle-timeout": value}, ["streaming-connection-idle-timeout"], "nonzero_duration", None)


def test_ordinary_workload_is_not_component_configuration_and_ambiguous_component_unknown():
    spec = ports.SPECS["container_argument_api_server_anonymous_auth_disabled"]
    ordinary = {"metadata": {"namespace": "apps", "labels": {"app": "api"}}, "spec": {"containers": [{"name": "app", "image": "nginx:1.27"}]}}
    assert ports.evaluate_component(ordinary, "pod", spec)[0] == "NOT_APPLICABLE"
    ordinary["metadata"] = {"namespace": "kube-system", "labels": {"component": "kube-apiserver"}}
    assert ports.evaluate_component(ordinary, "pod", spec)[0] == "UNKNOWN"
    ordinary["metadata"]["labels"]["component"] = "kube-scheduler"
    assert ports.evaluate_component(ordinary, "pod", spec)[0] == "NOT_APPLICABLE"
from peaso.collectors.k8s import _sanitize

REGISTRY = {check.id: check for check in CHECKS if check.id in ports.IDS}


@pytest.mark.parametrize("cid", ports.IDS)
@pytest.mark.parametrize("case,wanted", [("pass", "PASS"), ("fail", "FAIL"), ("missing", "UNKNOWN"), ("malformed", "UNKNOWN"), ("denied", "UNKNOWN")])
def test_modeled_available_settings_and_actual_gaps_are_distinct(cid, case, wanted):
    item = {"collection_status": "denied"} if case == "denied" else copy.deepcopy(CASES[cid][case])
    if case == "pass" and cid.endswith(".container_argument_kubelet_authorization_mode_no_always_allow"):
        _, rows = ports.pod_spec(item, REGISTRY[cid].kind)
        assert rows[0]["_component_config"]["flags"]["authorization-mode"] == "Webhook"
    original = copy.deepcopy(item)
    actual, evidence = REGISTRY[cid].evaluate(item, {})
    assert actual == wanted, evidence
    assert item == original


@pytest.mark.parametrize("cid", [cid for cid in ports.IDS if cid.endswith(".container_argument_kubelet_authorization_mode_no_always_allow")])
def test_kubelet_rbac_is_invalid_and_cannot_pass(cid):
    item = copy.deepcopy(CASES[cid]["pass"])
    _, rows = ports.pod_spec(item, REGISTRY[cid].kind)
    assert rows[0]["_component_config"]["flags"]["authorization-mode"] == "Webhook"
    rows[0]["_component_config"]["flags"]["authorization-mode"] = "RBAC"
    assert REGISTRY[cid].evaluate(item, {})[0] == "UNKNOWN"


def sample_config(component="kube-apiserver", flags=None, **extra):
    return {"spec": {"containers": [{"name": "component", "_component_config": {
        "component": component, "flags_complete": True, "flags": flags or {}, **extra}}]}}


def source_case_config(check, flags, version="v1.24.0"):
    item = copy.deepcopy(CASES[check.id]["pass"])
    _, containers = ports.pod_spec(item, check.kind)
    assert len(containers) == 1
    containers[0]["_component_config"]["flags"] = flags
    containers[0]["_component_config"]["version"] = version
    return item


def test_only_approved_configuration_fields_survive_projection():
    value = {"command": ["kube-apiserver", "--authorization-mode=Node,RBAC", "--private-token=INERT_PRIVATE_MARKER"],
             "args": ["--profiling=false", "--tls-private-key-file=/etc/tls/private.key"]}
    scrubbed = _sanitize(value)
    assert "INERT_PRIVATE_MARKER" not in json.dumps(scrubbed)
    assert scrubbed["command_redacted"] and scrubbed["args_redacted"]
    assert scrubbed["_component_config"]["flags"] == {"authorization-mode": "Node,RBAC", "profiling": "false",
                                                   "tls-private-key-file": "/etc/tls/private.key"}


def test_projection_rejects_shell_text_uri_credentials_and_duplicate_flags():
    for command in [["kube-apiserver", "--audit-log-path=secret with spaces"],
                    ["kube-apiserver", "--audit-log-path=https://user:password@example.org"],
                    ["kube-apiserver", "--profiling=false", "--profiling=true"]]:
        assert _sanitize({"command": command})["_component_config"]["collection_status"] == "malformed"


def test_known_component_absence_is_not_a_safe_default():
    check = REGISTRY["k8s.ports.pod.container_argument_authorization_mode_rbac"]
    assert check.evaluate(sample_config(flags={}), {})[0] == "UNKNOWN"
    assert check.evaluate(sample_config(component="etcd", flags={"client-cert-auth": "true"}), {})[0] == "NOT_APPLICABLE"
    assert check.evaluate({"spec": {"containers": [{"name": "app"}]}}, {})[0] == "UNKNOWN"


def test_component_property_denial_and_incomplete_projection_remain_unknown():
    check = REGISTRY["k8s.ports.pod.container_argument_authorization_mode_rbac"]
    item = sample_config(flags={"authorization-mode": "RBAC"}, flags_complete=False)
    assert check.evaluate(item, {})[0] == "UNKNOWN"
    item = sample_config(flags={"authorization-mode": "RBAC", "_coverage": {"authorization-mode": {"status": "denied"}}})
    assert check.evaluate(item, {})[0] == "UNKNOWN"


def test_legacy_psp_is_version_bounded_and_not_admission_enforcement_proof():
    check = REGISTRY["k8s.ports.pod.container_argument_pod_security_policy_enabled"]
    assert check.evaluate(sample_config(flags={"enable-admission-plugins": "PodSecurityPolicy"}, version="v1.24.0"), {})[0] == "PASS"
    assert check.evaluate(sample_config(flags={"enable-admission-plugins": "PodSecurityPolicy"}, version="v1.25.0"), {})[0] == "NOT_APPLICABLE"
    assert check.evaluate(sample_config(flags={"enable-admission-plugins": "PodSecurityPolicy"}), {})[0] == "UNKNOWN"


def test_multi_plugin_declaration_has_true_membership_not_singleton_argv_match():
    check = REGISTRY["k8s.ports.pod.container_argument_node_restriction_enabled"]
    assert check.evaluate(sample_config(flags={"enable-admission-plugins": "NamespaceLifecycle,NodeRestriction,ServiceAccount"}), {})[0] == "PASS"
    # Pinned query literal singleton element is absent in this valid argv.
    assert "--enable-admission-plugins=NodeRestriction" not in ["--enable-admission-plugins=NamespaceLifecycle,NodeRestriction,ServiceAccount"]


def test_audit_path_and_pem_extension_rejection_counterexamples():
    check = REGISTRY["k8s.ports.pod.container_argument_audit_log_path_configured"]
    assert check.evaluate(sample_config(flags={"audit-log-path": "/var/log/audit.log"}), {})[0] == "PASS"
    # Source Pod CASE has ELSE alarm even when its missing-path condition is false.
    reference_has_path = "--audit-log-path=/var/log/audit.log"
    assert "--audit-log-path=" in reference_has_path
    ca = REGISTRY["k8s.ports.pod.container_argument_kube_controller_manager_root_ca_file_configured"]
    assert ca.evaluate(sample_config(component="kube-controller-manager", flags={"root-ca-file": "/etc/pki/root-ca.crt"}), {})[0] == "PASS"
    assert "pem" not in "/etc/pki/root-ca.crt"


def test_numeric_threshold_boundaries_match_reviewed_case_conditions():
    check = REGISTRY["k8s.ports.pod.container_argument_audit_log_maxage_greater_than_30"]
    for value, expected in [("29", "FAIL"), ("30", "PASS"), ("31", "PASS"), ("thirty", "UNKNOWN")]:
        assert check.evaluate(sample_config(flags={"audit-log-maxage": value}), {})[0] == expected


@pytest.mark.parametrize("suffix,flag,boundary,below,above,title", [
    ("container_argument_audit_log_maxage_greater_than_30", "audit-log-maxage", 30, 29, 31, "at least 30 days"),
    ("container_argument_audit_log_maxbackup_greater_than_10", "audit-log-maxbackup", 10, 9, 11, "at least 10 files"),
    ("container_argument_audit_log_maxsize_greater_than_100", "audit-log-maxsize", 100, 99, 101, "at least 100 MB"),
    ("container_argument_event_qps_less_than_5", "event-qps", 5, 4, 6, "at most 5"),
])
def test_pinned_inclusive_boundaries_and_titles_for_all_nine_variants(suffix, flag, boundary, below, above, title):
    checks = [check for cid, check in REGISTRY.items() if cid.endswith("." + suffix)]
    assert len(checks) == 9
    for check in checks:
        assert title in check.title
        assert check.evaluate(source_case_config(check, {flag: str(boundary)}), {})[0] == "PASS"
        assert check.evaluate(source_case_config(check, {flag: str(below)}), {})[0] == ("PASS" if flag == "event-qps" else "FAIL")
        assert check.evaluate(source_case_config(check, {flag: str(above)}), {})[0] == ("FAIL" if flag == "event-qps" else "PASS")


def test_security_context_deny_legacy_version_bands_for_all_nine_variants():
    suffix = "container_argument_security_context_deny_enabled"
    checks = [check for cid, check in REGISTRY.items() if cid.endswith("." + suffix)]
    assert len(checks) == 9
    for check in checks:
        assert "legacy PSP or SecurityContextDeny" in check.title
        for version, plugins, expected in (
            ("v1.24.0", "PodSecurityPolicy", "PASS"),
            ("v1.24.0", "SecurityContextDeny", "PASS"),
            ("v1.24.0", "NamespaceLifecycle", "FAIL"),
            ("v1.25.0", "SecurityContextDeny", "PASS"),
            ("v1.25.0", "PodSecurityPolicy", "FAIL"),
            ("v1.29.1+k3s1", "SecurityContextDeny", "PASS"),
            ("v1.29.1", "PodSecurityPolicy", "FAIL"),
            ("v1.30.0", "SecurityContextDeny", "NOT_APPLICABLE"),
            ("v1.37.0", "PodSecurityPolicy", "NOT_APPLICABLE"),
            ("v1.25.0-alpha.1", "SecurityContextDeny", "UNKNOWN"),
            ("garbled", "SecurityContextDeny", "UNKNOWN"),
        ):
            assert check.evaluate(source_case_config(check, {"enable-admission-plugins": plugins}, version), {})[0] == expected
        item = source_case_config(check, {"enable-admission-plugins": "SecurityContextDeny"})
        _, containers = ports.pod_spec(item, check.kind)
        containers[0]["_component_config"].pop("version")
        assert check.evaluate(item, {})[0] == "UNKNOWN"


def test_security_context_deny_each_container_keeps_its_own_version_band():
    check = REGISTRY["k8s.ports.pod.container_argument_security_context_deny_enabled"]
    item = sample_config(flags={"enable-admission-plugins": "SecurityContextDeny"}, version="v1.25.0")
    item["spec"]["containers"].append({"name": "older", "_component_config": {
        "component": "kube-apiserver", "flags_complete": True,
        "flags": {"enable-admission-plugins": "PodSecurityPolicy"}, "version": "v1.24.0"}})
    status, evidence = check.evaluate(item, {})
    assert status == "PASS"
    assert {row["observed_version"] for row in evidence["observations"]} == {"v1.24.0", "v1.25.0"}
