"""Fail-closed K8s native-final admission and exact row selection."""
import json

from peaso.ai import k8s_native_final


def test_disabled_and_pending_manifest_guard(tmp_path, monkeypatch):
    body = k8s_native_final.MANIFEST.read_bytes()
    monkeypatch.delenv("PEASO_K8S_HARDENING_NATIVE_FINAL_ENABLED", raising=False)
    assert not k8s_native_final.admitted_check_ids()
    monkeypatch.setenv("PEASO_K8S_HARDENING_NATIVE_FINAL_ENABLED", "1")
    assert len(k8s_native_final.ELIGIBLE) == 43
    assert not k8s_native_final.admitted_check_ids()  # hosted gate remains pending
    for mutation in (
        lambda row: row["checks"][0].update(disagreements=1),
        lambda row: row["checks"][0].update(check_id="k8s.job.non_root"),
        lambda row: row["qualification"].update(status="pending"),
    ):
        manifest = json.loads(body)
        manifest["qualification"] = {"status": "hosted_qualified", "hosted_cost_gate": "passed"}
        mutation(manifest)
        path = tmp_path / "manifest.json"
        path.write_text(json.dumps(manifest, sort_keys=True) + "\n")
        assert not k8s_native_final.admitted_check_ids(path)


def test_exact_k8s_hardening_failure_selection():
    base = {"provider": "k8s", "category": "hardening",
            "check_id": "k8s.deployment.non_root", "status": "FAIL", "scope": "*"}
    coverage = [{"level": "check", "check_id": base["check_id"],
                 "scope": "*", "status": "evaluated"},
                {"level": "collection", "type": "deployment",
                 "scope": "*", "status": "collected"}]
    rows = [dict(base, id="admit"),
            dict(base, id="other", check_id="k8s.job.non_root"),
            dict(base, id="pass", status="PASS"),
            dict(base, id="scanner_unknown", scanner_status="UNKNOWN"),
            dict(base, id="partial", evidence={"incomplete_dependencies": []}),
            dict(base, id="other_provider", provider="aws"),
            dict(base, id="other_category", category="exposure")]
    native, ai = k8s_native_final.partition(rows, k8s_native_final.ELIGIBLE, coverage)
    assert [row["id"] for row in native] == ["admit"]
    assert [row["id"] for row in ai] == [
        "other", "pass", "scanner_unknown", "partial", "other_provider", "other_category"]


def test_partial_serviceaccount_default_never_becomes_native_final():
    from peaso.checks.k8s_extended import serviceaccount_automount

    status, evidence = serviceaccount_automount({'metadata': {'name': 'sa'}}, {})
    assert status == 'FAIL'  # Missing flag defaults to true on a full object.
    check_id = 'k8s.serviceaccount.disable_automount'
    row = {'id': 'sa', 'provider': 'k8s', 'category': 'hardening',
           'check_id': check_id, 'status': status, 'scope': '*', 'evidence': evidence}
    coverage = [{'level': 'check', 'check_id': check_id,
                 'scope': '*', 'status': 'evaluated'},
                {'level': 'collection', 'type': 'serviceaccount',
                 'scope': '*', 'status': 'partial'}]
    assert k8s_native_final.partition([row], k8s_native_final.ELIGIBLE, coverage)[0] == []
    coverage[1]['status'] = 'collected'
    assert k8s_native_final.partition([row], k8s_native_final.ELIGIBLE, coverage)[0] == [row]
    coverage[0]['status'] = 'partial'
    assert k8s_native_final.partition([row], k8s_native_final.ELIGIBLE, coverage)[0] == []
    assert k8s_native_final.partition([row], k8s_native_final.ELIGIBLE)[0] == []


def test_hosted_qualification_required_for_activation(tmp_path, monkeypatch):
    value = json.loads(k8s_native_final.MANIFEST.read_text())
    value["qualification"] = {"status": "hosted_qualified", "hosted_cost_gate": "passed"}
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(value, sort_keys=True) + "\n")
    monkeypatch.setenv("PEASO_K8S_HARDENING_NATIVE_FINAL_ENABLED", "1")
    assert k8s_native_final.admitted_check_ids(path) == k8s_native_final.ELIGIBLE
    value["qualification"]["hosted_cost_gate"] = "failed"
    path.write_text(json.dumps(value, sort_keys=True) + "\n")
    assert not k8s_native_final.admitted_check_ids(path)
