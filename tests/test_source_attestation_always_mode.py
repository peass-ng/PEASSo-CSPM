"""The suite runs in the shipped "once" mode; this file exercises "always"."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]

_PROBE = r"""
import peaso.source_attestation_mode as mode
calls = []
def verifier(tag):
    calls.append(tag)
for _ in range(3):
    mode.prove_once(verifier, "x")
failing = []
def broken():
    failing.append(1)
    raise RuntimeError("tampered")
for _ in range(2):
    try:
        mode.prove_once(broken)
    except RuntimeError:
        pass
print(mode.MODE, len(calls), len(failing))
"""


def _run(value: str | None, code: str = _PROBE) -> str:
    env = {k: v for k, v in os.environ.items() if k != "PEASO_SOURCE_ATTESTATION"}
    if value is not None:
        env["PEASO_SOURCE_ATTESTATION"] = value
    env["PYTHONPATH"] = str(ROOT)
    out = subprocess.run([sys.executable, "-c", code], cwd=ROOT, env=env,
                         capture_output=True, text=True, timeout=600)
    assert out.returncode == 0, out.stderr[-4000:]
    return out.stdout.strip().splitlines()[-1]


def test_always_mode_reproves_every_call_and_failures_are_never_cached():
    assert _run("always") == "always 3 2"


def test_once_mode_reuses_a_success_but_never_a_failure():
    assert _run("once") == "once 1 2"
    assert _run(None) == "once 1 2"


def test_unknown_mode_fails_closed_to_always():
    assert _run("sometimes") == "always 3 2"

