"""Real CLI process stdout framing with progress enabled and explicit native categories."""
import json
import subprocess
import sys

import pytest


@pytest.mark.parametrize("format", ["json", "markdown"])
@pytest.mark.parametrize("quiet", [False, True])
def test_scan_stdout_contains_only_report(format, quiet):
    command = [sys.executable, "-m", "peaso.cli", "scan", "--provider", "gcp", "--demo",
               "--categories", "hardening", "--checks", "gcp.storage.uniform_access", "--format", format]
    if quiet:
        command.append("--quiet")
    result = subprocess.run(command, capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr
    assert "peaso progress:" not in result.stdout
    if format == "json":
        assert json.loads(result.stdout)["provider"] == "gcp"
    else:
        assert result.stdout.startswith("# ")
        assert "Resource inventory" in result.stdout
    if quiet:
        assert result.stderr == ""
    else:
        assert "peaso progress: starting" in result.stderr
        assert "peaso progress: completed" in result.stderr
