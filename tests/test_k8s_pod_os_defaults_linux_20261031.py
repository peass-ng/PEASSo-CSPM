"""A Pod without spec.os is a Linux Pod, which is the Kubernetes default."""
from peaso.checks import compliance_new_k8s, compliance_new_k8s_workload_ingress  # noqa: F401
from peaso.checks import evaluate_check

BASE = {"id": "pod-1", "kind": "pod", "metadata": {"name": "web", "namespace": "apps"}}


def run(check, spec):
    return evaluate_check(check, {**BASE, "spec": spec})


def status(out):
    return out[0] if isinstance(out, tuple) else out["status"] if isinstance(out, dict) else out


def test_seccomp_without_spec_os_is_judged_as_linux():
    check = "k8s.cis.pod_effective_runtime_default_seccomp"
    good = {"securityContext": {"seccompProfile": {"type": "RuntimeDefault"}}, "containers": [{"name": "c"}]}
    bad = {"containers": [{"name": "c", "securityContext": {"seccompProfile": {"type": "Unconfined"}}}]}
    assert status(run(check, good)) == "PASS"
    assert status(run(check, bad)) == "FAIL"
    assert status(run(check, {**good, "os": {"name": "windows"}})) == "NOT_APPLICABLE"


def test_run_as_user_without_spec_os_is_judged_as_linux():
    check = "k8s_pod_effective_run_as_user_nonzero"
    assert status(run(check, {"securityContext": {"runAsUser": 1000}, "containers": [{"name": "c"}]})) == "PASS"
    assert status(run(check, {"containers": [{"name": "c", "securityContext": {"runAsUser": 0}}]})) == "FAIL"
