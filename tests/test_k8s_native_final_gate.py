"""Fail-closed K8s native-final admission and exact row selection."""
import hashlib
import json

from peaso.ai import k8s_native_final


def test_disabled_pin_and_source_guard(tmp_path, monkeypatch):
    body = k8s_native_final.MANIFEST.read_bytes()
    digest = hashlib.sha256(body).hexdigest()
    monkeypatch.delenv("PEASO_K8S_HARDENING_NATIVE_FINAL_ENABLED", raising=False)
    monkeypatch.setenv("PEASO_K8S_HARDENING_NATIVE_FINAL_SHA256", digest)
    assert not k8s_native_final.admitted_check_ids()
    monkeypatch.setenv("PEASO_K8S_HARDENING_NATIVE_FINAL_ENABLED", "1")
    assert len(k8s_native_final.ELIGIBLE) == 43
    assert not k8s_native_final.admitted_check_ids()  # hosted gate remains pending
    monkeypatch.setenv("PEASO_K8S_HARDENING_NATIVE_FINAL_SHA256", "0" * 64)
    assert not k8s_native_final.admitted_check_ids()
    monkeypatch.setenv("PEASO_K8S_HARDENING_NATIVE_FINAL_SHA256", digest)
    for mutation in (
        lambda row: row["checks"][0].update(disagreements=1),
        lambda row: row["checks"][0].update(check_id="k8s.job.non_root"),
        lambda row: row["qualification"].update(status="pending"),
        lambda row: row["checks"][0]["source"].update(sha256="0" * 64),
    ):
        manifest = json.loads(body)
        mutation(manifest)
        path = tmp_path / "manifest.json"
        altered = (json.dumps(manifest, sort_keys=True) + "\n").encode()
        path.write_bytes(altered)
        monkeypatch.setenv("PEASO_K8S_HARDENING_NATIVE_FINAL_SHA256",
                           hashlib.sha256(altered).hexdigest())
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


def test_hosted_receipt_required_for_activation(tmp_path, monkeypatch):
    receipt = tmp_path / "hosted.json"
    receipt.write_text(json.dumps({"version": 2, "status": "qualified",
        "paired_run_count": 2, "admitted_check_ids": 43,
        "audit_receipt_sha256": k8s_native_final.AUDIT_SHA}) + "\n")
    monkeypatch.setattr(k8s_native_final, "HOSTED", receipt)
    value = json.loads(k8s_native_final.MANIFEST.read_text())
    value["qualification"] = {
        "status": "hosted_qualified", "hosted_cost_gate": "passed",
        "hosted_receipt_sha256": hashlib.sha256(receipt.read_bytes()).hexdigest()}
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(value, sort_keys=True) + "\n")
    monkeypatch.setenv("PEASO_K8S_HARDENING_NATIVE_FINAL_ENABLED", "1")
    monkeypatch.setenv("PEASO_K8S_HARDENING_NATIVE_FINAL_SHA256",
                       hashlib.sha256(path.read_bytes()).hexdigest())
    assert k8s_native_final.admitted_check_ids(path) == k8s_native_final.ELIGIBLE
    receipt.write_text('{"status":"failed"}\n')
    assert not k8s_native_final.admitted_check_ids(path)
