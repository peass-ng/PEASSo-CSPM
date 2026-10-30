"""Source-bound Kubernetes batch fixtures captured from prior family tests."""
import json
from pathlib import Path

import pytest

from peaso.checks import CHECKS, evaluate_check
from peaso.checks.facts import MemoIndex
from peaso.checks import batch_remaining_k8s  # noqa: F401  (registration side effect)


ROOT = Path(__file__).resolve().parents[1]
DISPOSITION = json.loads((ROOT / "tests/fixtures/batch_remaining_gcp_k8s/full-id-disposition.json").read_text())
CENTRAL = json.loads((ROOT / "tests/fixtures/batch_remaining_gcp_k8s/central-fixture-fragment.json").read_text())
FIXTURES = {check_id: {label: {"item": case[label], "index": case.get(label + "_index", case["index"])}
                       for label in ("pass", "fail", "unknown") if label in case}
            for check_id, case in CENTRAL.items()}
IDS = [row["id"] for row in DISPOSITION["ids"] if row["provider"] == "k8s" and row["disposition"] == "implemented"]


@pytest.mark.parametrize("check_id", IDS)
def test_k8s_native_identity_and_snapshot_outcomes(check_id):
    checks = [check for check in CHECKS if check.id == check_id]
    assert len(checks) == 1
    assert checks[0].provider == "k8s"
    scenarios = FIXTURES[check_id]
    assert {"pass", "fail", "unknown"} <= set(scenarios)
    for expected in ("pass", "fail", "unknown"):
        fixture = scenarios[expected]
        assert evaluate_check(check_id, fixture["item"], fixture["index"])[0] == expected.upper(), (check_id, expected)


@pytest.mark.parametrize("check_id", IDS)
def test_k8s_central_case_fragment(check_id):
    case = CENTRAL[check_id]
    for label, expected in (("pass", "PASS"), ("fail", "FAIL"), ("unknown", "UNKNOWN"),
                            ("missing", "UNKNOWN"), ("malformed", "UNKNOWN")):
        if label in case:
            index = case.get(label + "_index", case["index"])
            assert evaluate_check(check_id, case[label], index)[0] == expected, (check_id, label)
    assert evaluate_check(check_id, {"collection_status": "denied"}, case["index"])[0] == "UNKNOWN"


def test_k8s_admission_inventory_validation_is_once_per_memo_index():
    class Counted(list):
        iterations = 0

        def __iter__(self):
            self.iterations += 1
            return super().__iter__()

    check_id = "k8s.cis.admission_hostpid"
    case = FIXTURES[check_id]["pass"]
    index = MemoIndex(case["index"])
    index["admission_policy"] = Counted(index["admission_policy"])
    assert evaluate_check(check_id, case["item"], index)[0] == "PASS"
    first = index["admission_policy"].iterations
    assert first > 0
    assert evaluate_check(check_id, case["item"], index)[0] == "PASS"
    assert index["admission_policy"].iterations == first


@pytest.mark.parametrize("timeout,expected", [("30s", "PASS"), ("90s", "FAIL")])
def test_collector_projected_apiserver_timeout_reaches_native_verdict(timeout, expected):
    from datetime import datetime, timezone
    from types import SimpleNamespace
    from peaso.collectors import k8s

    class API:
        server = "https://fixture.invalid"
        api_client = SimpleNamespace(configuration=SimpleNamespace(host=server))

        def get_json(self, path, params=None):
            assert path == "/api/v1/pods"
            return {"metadata": {"resourceVersion": "1", "continue": ""}, "items": [{
                "metadata": {"namespace": "kube-system", "name": "apiserver", "uid": "pod-1"},
                "spec": {"containers": [{"name": "api", "command": ["kube-apiserver"],
                                         "args": ["--request-timeout=" + timeout]}]}}]}

    now = datetime.now(timezone.utc).isoformat()
    policy = {"cluster_id": "fixture", "observed_at": now, "max_age_seconds": 600,
              "max_policy_items": 20, "approved_max_request_timeout": 60}
    collected = k8s.collect({"provider": "k8s", "auth": {"cluster_id": "fixture"},
                             "scopes": ["*"], "options": {"inventories": ["pod"], "retries": 0,
                                                            "compliance_policy": policy}}, api=API())
    envelope = next(row for row in collected["collections"] if row["type"] == "pod")
    item = envelope["items"][0]
    index = {"context": {"provider": "k8s", "scope": "*", "metadata": collected["metadata"],
                         "created_at": collected["created_at"]},
             "collections": {"pod": [envelope]}, "pod": [{"type": "pod", "scope": "*", "data": item}]}
    assert evaluate_check("k8s.cis.the_request_timeout_argument_is_set_as_appropriate", item, index)[0] == expected


@pytest.mark.parametrize("declared,expected", [
    ("RotateKubeletServerCertificate=true", "PASS"),
    ("RotateKubeletServerCertificate=false", "FAIL"),
    ("Other=true", "UNKNOWN"),
    ("RotateKubeletServerCertificate=true,RotateKubeletServerCertificate=false", "UNKNOWN"),
])
def test_controller_rotation_only_grades_explicit_unique_flag(declared, expected):
    import copy

    check_id = "k8s.cis.controller_manager_rotate_kubelet_server_certificate_true"
    case = CENTRAL[check_id]
    item = copy.deepcopy(case["pass"])
    item["spec"]["containers"][0]["_component_config"]["flags"]["feature-gates"] = declared
    index = copy.deepcopy(case["pass_index"])
    index["collections"]["pod"][0]["items"][0] = item
    index["pod"][0]["data"] = item
    assert evaluate_check(check_id, item, index)[0] == expected


def test_controller_rotation_foreign_component_is_not_applicable():
    import copy

    check_id = "k8s.cis.controller_manager_rotate_kubelet_server_certificate_true"
    case = CENTRAL[check_id]
    item = copy.deepcopy(case["pass"])
    item["spec"]["containers"][0]["_component_config"]["component"] = "kube-scheduler"
    index = copy.deepcopy(case["pass_index"])
    index["collections"]["pod"][0]["items"][0] = item
    index["pod"][0]["data"] = item
    assert evaluate_check(check_id, item, index)[0] == "NOT_APPLICABLE"


@pytest.mark.parametrize("version,expected", [
    ("v1.6.0", "NOT_APPLICABLE"),
    ("v1.30.4", "PASS"),
    ("v1.38.0", "UNKNOWN"),
])
def test_kubelet_rotation_is_one_observed_declaration_with_version_gate(version, expected):
    import copy

    check_id = "k8s.cis.kubelet_rotate_kubelet_server_certificate_true"
    case = CENTRAL[check_id]
    item = copy.deepcopy(case["pass"])
    item["kubeletVersion"] = version
    assert evaluate_check(check_id, item, case["pass_index"])[0] == expected


def test_kubelet_rotation_foreign_component_and_node_identity():
    import copy

    check_id = "k8s.cis.kubelet_rotate_kubelet_server_certificate_true"
    case = CENTRAL[check_id]
    foreign = copy.deepcopy(case["pass"])
    foreign["component"] = "etcd"
    assert evaluate_check(check_id, foreign, case["pass_index"])[0] == "NOT_APPLICABLE"
    missing_node = copy.deepcopy(case["pass"])
    missing_node["node_uid"] = "other"
    assert evaluate_check(check_id, missing_node, case["pass_index"])[0] == "UNKNOWN"
