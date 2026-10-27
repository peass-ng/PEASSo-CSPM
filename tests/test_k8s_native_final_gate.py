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
    assert k8s_native_final.admitted_check_ids() == k8s_native_final.ELIGIBLE
    monkeypatch.setenv("PEASO_K8S_HARDENING_NATIVE_FINAL_SHA256", "0" * 64)
    assert not k8s_native_final.admitted_check_ids()
    monkeypatch.setenv("PEASO_K8S_HARDENING_NATIVE_FINAL_SHA256", digest)
    for mutation in (
        lambda row: row["checks"][0].update(disagreements=1),
        lambda row: row["checks"][0].update(check_id="k8s.job.non_root"),
        lambda row: row["qualification"].update(status="pending"),
        lambda row: row.update(source_sha256="0" * 64),
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
            "check_id": "k8s.deployment.non_root", "status": "FAIL"}
    rows = [dict(base, id="admit"),
            dict(base, id="other", check_id="k8s.job.non_root"),
            dict(base, id="pass", status="PASS"),
            dict(base, id="scanner_unknown", scanner_status="UNKNOWN"),
            dict(base, id="partial", evidence={"incomplete_dependencies": []}),
            dict(base, id="other_provider", provider="aws"),
            dict(base, id="other_category", category="exposure")]
    native, ai = k8s_native_final.partition(rows, k8s_native_final.ELIGIBLE)
    assert [row["id"] for row in native] == ["admit"]
    assert [row["id"] for row in ai] == [
        "other", "pass", "scanner_unknown", "partial", "other_provider", "other_category"]
