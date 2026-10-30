"""Offline receipts for the isolated Compose acceptance runner."""
import json
import subprocess

import pytest

from scripts.peaso_test_resources.compose_api_acceptance import Acceptance, COPY_INPUTS, CONTEXT_FILES, source_manifest




def test_failed_scan_summary_redacts_provider_error_before_persisting(tmp_path):
    run = Acceptance(tmp_path, "unused-offline-profile", "eu-west-1")
    run.secret_values.append("private-provider-key")
    run.request = lambda *_args, **_kwargs: {
        "status": "failed", "error": {"detail": "private-provider-key"},
        "error_code": "analysis_failed", "error_stage": "analyzer",
        "timeline": [{"status": "queued", "at": "2026-10-12T10:00:00Z", "secret": "private-provider-key"}],
    }
    try:
        with pytest.raises(RuntimeError, match="scan ended failed"):
            run.wait_scan("offline-scan")
        saved = (tmp_path / "summary.json").read_text()
        assert "private-provider-key" not in saved
        assert "[REDACTED]" in saved
        error = json.loads(saved)["scan_error"]
        assert error["id"] == "offline-scan"
        assert error["error_code"] == "analysis_failed" and error["error_stage"] == "analyzer"
        assert error["timeline"] == [{"status": "queued", "at": "2026-10-12T10:00:00Z"}]
    finally:
        run.client.close()


def test_explicit_playwright_binary_is_validated_and_fingerprinted_before_docker(tmp_path):
    run = Acceptance(tmp_path / "evidence", "unused-offline-profile", "eu-west-1")
    package = tmp_path / "node_modules" / "@playwright" / "test"
    package.mkdir(parents=True)
    binary = package / "cli.js"
    binary.write_text("#!/usr/bin/env node\n")
    binary.chmod(0o755)
    (package / "package.json").write_text('{"name":"@playwright/test","version":"1.55.1"}')
    run.env["PEASO_PLAYWRIGHT_BIN"] = str(binary)
    try:
        assert run.playwright_command() == [str(binary)]
        receipt = json.loads((tmp_path / "evidence" / "summary.json").read_text())["playwright_binary"]
        assert receipt["mode"] == "explicit local binary"
        assert receipt["package_name"] == "@playwright/test"
        assert receipt["binary_sha256"] and receipt["metadata_sha256"]
        run.env["PEASO_PLAYWRIGHT_BIN"] = "relative/playwright"
        with pytest.raises(RuntimeError, match="existing executable absolute file"):
            run.playwright_command()
    finally:
        run.client.close()


def test_failure_diagnostics_capture_only_owned_bounded_logs_and_state(tmp_path, monkeypatch):
    run = Acceptance(tmp_path, "unused-offline-profile", "eu-west-1")
    run.secret_values.append("private-provider-key")
    run.summary["scan_error"] = {"id": "offline-scan", "status": "failed"}
    run.summary["images"] = {service: {"container_id": service + "-owned-id"}
                             for service in ("api", "collector", "analyzer")}
    calls = []

    def fake_run(argv, **_kwargs):
        calls.append(argv)
        if "logs" in argv:
            return subprocess.CompletedProcess(argv, 0,
                "Scan worker failed: code=analysis_failed type=ValueError source=evaluator private-provider-key\n", "")
        assert argv[:3] == ["docker", "inspect", "--format"]
        return subprocess.CompletedProcess(argv, 0, "1 false\n", "")

    monkeypatch.setattr(subprocess, "run", fake_run)
    try:
        run.capture_failure_diagnostics()
        receipt = json.loads((tmp_path / "summary.json").read_text())["failure_diagnostics"]
        assert receipt["owned_logs"] and not receipt["errors"]
        assert receipt["container_state"] == {service: {"exit_code": 1, "oom_killed": False}
                                               for service in ("api", "collector", "analyzer")}
        assert calls[0] == run.compose + ["logs", "--no-color", "--tail", "80", "api", "collector", "analyzer"]
        assert len(calls) == 4 and all(".State.ExitCode" in argv[3] for argv in calls[1:])
        log = (tmp_path / "failure-owned-project-logs.log").read_text()
        assert "private-provider-key" not in log and "[REDACTED]" in log
    finally:
        run.client.close()
