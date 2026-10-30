"""CIS Kubernetes 1.2.3/1.2.9 admission-plugin natives and k8s framework re-adjudications."""
import json
from pathlib import Path

import pytest

from peaso.checks import CHECKS, evaluate_check
from peaso.checks.fixtures import CASES
from tests.compliance_source_conservation import assert_source_frameworks_conserved

ROOT = Path(__file__).resolve().parent.parent
PACK = ROOT / "peaso" / "rulepacks"
IDS = ("k8s.gap.apiserver.deny_service_external_ips", "k8s.gap.apiserver.event_rate_limit")
PLUGIN = {IDS[0]: "DenyServiceExternalIPs", IDS[1]: "EventRateLimit"}


def apiserver(flags, complete=True, component="kube-apiserver", name="kube-apiserver"):
    return {"metadata": {"name": "kube-apiserver-cp", "namespace": "kube-system", "labels": {"component": "kube-apiserver"}},
            "spec": {"containers": [{"name": name, "_component_config": {"component": component,
                     "flags_complete": complete, "flags": flags, "version": "v1.31.0"}}]}}


@pytest.mark.parametrize("cid", IDS)
def test_registered_with_fixture_cases(cid):
    check = next(c for c in CHECKS if c.id == cid)
    assert check.provider == "k8s" and check.kind == "pod" and check.public()["dependencies"] == ["pod"]
    assert evaluate_check(cid, CASES[cid]["pass"], {})[0] == "PASS"
    assert evaluate_check(cid, CASES[cid]["fail"], {})[0] == "FAIL"


@pytest.mark.parametrize("cid", IDS)
def test_enabled_plugin_passes_and_absence_fails(cid):
    plugin = PLUGIN[cid]
    assert evaluate_check(cid, apiserver({"enable-admission-plugins": "NodeRestriction," + plugin}), {})[0] == "PASS"
    assert evaluate_check(cid, apiserver({"enable-admission-plugins": "NodeRestriction"}), {})[0] == "FAIL"
    # Prowler's inverted evaluator passed when the plugin was only in --disable-admission-plugins.
    status, _ = evaluate_check(cid, apiserver({"enable-admission-plugins": "NodeRestriction", "disable-admission-plugins": plugin}), {})
    assert status == "FAIL"
    # Substring matches are not membership (e.g. a hypothetical plugin name prefix).
    assert evaluate_check(cid, apiserver({"enable-admission-plugins": plugin + "X"}), {})[0] == "FAIL"


@pytest.mark.parametrize("cid", IDS)
def test_missing_or_incomplete_facts_are_unknown_not_pass(cid):
    assert evaluate_check(cid, apiserver({}), {})[0] == "UNKNOWN"
    assert evaluate_check(cid, apiserver({"enable-admission-plugins": PLUGIN[cid]}, complete=False), {})[0] == "UNKNOWN"
    assert evaluate_check(cid, {}, {})[0] == "UNKNOWN"


@pytest.mark.parametrize("cid", IDS)
def test_other_components_are_not_applicable(cid):
    pod = apiserver({"rotate-certificates": "true"}, component="kubelet", name="kubelet")
    pod["metadata"]["labels"] = {}
    pod["metadata"]["namespace"] = "default"
    assert evaluate_check(cid, pod, {})[0] == "NOT_APPLICABLE"


def manifest_rows():
    return {r["check_id"]: r for r in json.loads((PACK / "upstream_manifest.json").read_text())["checks"]}


def test_every_k8s_corrected_merge_preserves_defect_and_links_frameworks():
    rows = [r for r in manifest_rows().values() if r["provider"] == "k8s" and r.get("review_classification") == "corrected_native_merge"]
    assert len(rows) == 114
    registry = {c.id for c in CHECKS}
    for row in rows:
        assert row["disposition"] == "merged" and row["native_checks"], row["check_id"]
        assert set(row["native_checks"]) <= registry, row["check_id"]
        assert row["upstream_defect"]["classification"] == "invalid_predicate" and row["upstream_defect"]["reason"]
        for native in row["native_checks"]:
            assert_source_frameworks_conserved(row, native)
