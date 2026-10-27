"""A scan that could read nothing (every collection denied) must not exit 0 with an empty report."""
import json
import pytest

from peaso.snapshot import make_snapshot


def _write(tmp_path, collections):
    path = tmp_path / "snap.json"
    path.write_text(json.dumps(make_snapshot("gcp", ["*"], collections)))
    return path


def test_scan_with_all_collections_denied_exits_nonzero(tmp_path, capsys):
    from peaso.cli import main
    denied = [{"type": t, "scope": "*", "service": "workspace", "status": "denied", "items": [],
               "error": {"code": "credential_refresh_failed", "kind": "denied"}} for t in ("workspace_role", "workspace_user")]
    out = tmp_path / "report.json"
    assert main(["scan", "--snapshot", str(_write(tmp_path, denied)), "-o", str(out), "--quiet"]) == 3
    assert "credential_refresh_failed" in capsys.readouterr().err
    assert json.loads(out.read_text())["findings"] is not None  # the report is still written for inspection


def test_scan_with_readable_empty_scope_exits_zero(tmp_path):
    from peaso.cli import main
    empty = [{"type": "project", "scope": "projects/p", "service": "resourcemanager", "status": "empty", "items": []},
             {"type": "workspace_user", "scope": "*", "service": "workspace", "status": "denied", "items": [],
              "error": {"code": "permission_denied", "kind": "denied"}}]
    assert main(["scan", "--snapshot", str(_write(tmp_path, empty)), "-o", str(tmp_path / "r.json"), "--quiet"]) == 0


def test_hosted_collector_fails_scan_when_nothing_was_readable(tmp_path, monkeypatch):
    import peaso.engine
    from peaso import worker

    class Pipe:
        sent = None

        def send(self, value):
            Pipe.sent = value

        def close(self):
            pass
    denied = make_snapshot("gcp", ["*"], [{"type": "workspace_user", "scope": "*", "service": "workspace", "status": "denied",
                                           "items": [], "error": {"code": "credential_refresh_failed", "kind": "denied"}}])
    monkeypatch.setattr(peaso.engine, "collect_snapshot", lambda request: denied)
    monkeypatch.setattr(worker.os, "dup2", lambda *a: None)
    request = {"artifact_config": {"mode": "file", "root": str(tmp_path)}, "tenant_id": "t", "scan_id": "0" * 32,
               "connector": {"provider": "gcp", "auth": {}}}
    worker._process("collector", request, Pipe())
    # credential_refresh_failed names a rejected credential, not missing permissions.
    assert Pipe.sent[:2] == (False, "credentials_invalid")


@pytest.mark.parametrize("failure, expected", [
    (PermissionError(13, "private local artifact", "/private/fixture-secret.json"), "dependency_unavailable"),
    (PermissionError("provider authorization failed with sensitive detail"), "credential_access_denied"),
])
def test_hosted_collector_distinguishes_file_permission_from_provider_denial(
    tmp_path, monkeypatch, failure, expected
):
    import peaso.engine
    from peaso import worker

    class Pipe:
        sent = None

        def send(self, value):
            self.sent = value

        def close(self):
            pass

    def fail_collection(_request):
        raise failure

    monkeypatch.setattr(peaso.engine, "collect_snapshot", fail_collection)
    monkeypatch.setattr(worker.os, "dup2", lambda *_args: None)
    request = {"artifact_config": {"mode": "file", "root": str(tmp_path)}, "tenant_id": "t", "scan_id": "0" * 32,
               "connector": {"provider": "gcp", "auth": {}}}
    pipe = Pipe()
    worker._process("collector", request, pipe)
    assert pipe.sent[:2] == (False, expected)
    assert pipe.sent[2]["exception_type"] == "PermissionError"
    assert "/private/fixture-secret.json" not in repr(pipe.sent)
    assert "private local artifact" not in repr(pipe.sent)
    assert "sensitive detail" not in repr(pipe.sent)
