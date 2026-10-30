"""Run each unpublished check family without changing the parent registry."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from types import SimpleNamespace

import pytest

from tests.compliance_draft_isolation import CHILD_FILE_ENV, DRAFT_TEST_MODULES, unpublished_check_imports
from tests import compliance_draft_isolation as boundary, conftest as draft_hook


ROOT = Path(__file__).resolve().parents[1]
TESTS = Path(__file__).resolve().parent




def test_full_suite_hook_ignores_only_reviewed_draft_imports(monkeypatch):
    monkeypatch.delenv(CHILD_FILE_ENV, raising=False)
    full = SimpleNamespace(args=[str(TESTS)])
    draft = TESTS / "test_peaso_compliance_new_gcp_gke.py"
    new_aws = TESTS / "test_peaso_compliance_new_aws_inspector_ec2.py"
    new_gcp = TESTS / "test_peaso_compliance_new_gcp_api_keys.py"
    inactive_port = TESTS / "test_peaso_checks_azure_ports_sql.py"
    published = TESTS / "test_peaso_compliance_new_gcp.py"
    admitted_api = TESTS / "test_peaso_compliance_new_aws_apigateway.py"
    admitted_collector = TESTS / "test_peaso_collectors_aws_apigateway_stage_ids.py"
    pack = TESTS / "test_peaso_compliance_requirements.py"
    proxy = TESTS / "test_peaso_compliance_draft_isolation.py"
    staged = TESTS / "test_peaso_compliance_new_sw01.py"
    assert draft_hook.pytest_ignore_collect(draft, full) is True
    assert draft_hook.pytest_ignore_collect(inactive_port, full) is True
    assert draft_hook.pytest_ignore_collect(staged, full) is True
    assert all(draft_hook.pytest_ignore_collect(path, full) is None for path in
               (published, admitted_api, admitted_collector, new_aws, new_gcp, pack, proxy))
    assert draft_hook.pytest_ignore_collect(draft, SimpleNamespace(args=[str(draft)])) is None
    assert draft_hook.pytest_ignore_collect(inactive_port, SimpleNamespace(args=[str(inactive_port)])) is None
    assert draft_hook.pytest_ignore_collect(staged, SimpleNamespace(args=[str(staged)])) is None


def test_staged_import_drift_and_mixed_selection_fail_closed(monkeypatch):
    staged = TESTS / "test_peaso_compliance_new_sw01.py"
    pack = TESTS / "test_peaso_compliance_requirements.py"
    with pytest.raises(pytest.UsageError, match="sole pytest selection"):
        draft_hook.pytest_configure(SimpleNamespace(args=[str(staged), str(pack)]))
    original = draft_hook.unpublished_check_imports
    monkeypatch.setattr(draft_hook, "unpublished_check_imports",
                        lambda path: original(path) | {"compliance_new_sw02"} if path == staged else original(path))
    with pytest.raises(pytest.UsageError, match="Staged-unselected registrar boundary drift"):
        draft_hook.pytest_ignore_collect(staged, SimpleNamespace(args=[str(TESTS)]))


def test_inactive_non_compliance_registrar_is_detected_with_transitive_modules(monkeypatch):
    monkeypatch.delenv(CHILD_FILE_ENV, raising=False)
    tail = TESTS / "test_peaso_checks_azure_ports_tail_context.py"
    assert unpublished_check_imports(tail) == {"azure_ports_tail_context"}
    assert draft_hook.pytest_ignore_collect(tail, SimpleNamespace(args=[str(TESTS)])) is True
    assert draft_hook.pytest_ignore_collect(tail, SimpleNamespace(args=[str(tail)])) is None
    assert draft_hook.pytest_configure(SimpleNamespace(args=[str(tail)])) is None


def test_new_unlisted_native_registrar_import_fails_closed(tmp_path, monkeypatch):
    module = "unlisted_native_registrar_fixture"
    (tmp_path / (module + ".py")).write_text("@register('fixture.id')\ndef check(item, index):\n    pass\n")
    test = tmp_path / "test_unlisted_native_registrar.py"
    test.write_text(f"from peaso.checks import {module}\n")
    monkeypatch.setattr(boundary, "CHECKS_DIR", tmp_path)
    monkeypatch.setattr(draft_hook, "TESTS_DIR", tmp_path)
    boundary._unpublished_module.cache_clear()
    assert unpublished_check_imports(test) == {module}
    with pytest.raises(pytest.UsageError, match="Unreviewed unpublished-check import"):
        draft_hook.pytest_ignore_collect(test, SimpleNamespace(args=[str(tmp_path)]))
    boundary._unpublished_module.cache_clear()


def test_mixed_or_mismatched_child_selection_fails_loudly(monkeypatch):
    draft = str(TESTS / "test_peaso_compliance_new_gcp_gke.py")
    pack = str(TESTS / "test_peaso_compliance_requirements.py")
    monkeypatch.delenv(CHILD_FILE_ENV, raising=False)
    with pytest.raises(pytest.UsageError, match="mixed with other selections"):
        draft_hook.pytest_configure(SimpleNamespace(args=[draft, pack]))
    monkeypatch.setenv(CHILD_FILE_ENV, "test_peaso_compliance_new_gcp_gke.py")
    with pytest.raises(pytest.UsageError, match="exactly its named draft"):
        draft_hook.pytest_configure(SimpleNamespace(args=[pack]))
    assert draft_hook.pytest_configure(SimpleNamespace(args=[draft])) is None
    monkeypatch.delenv(CHILD_FILE_ENV, raising=False)
    inactive_port = str(TESTS / "test_peaso_checks_azure_ports_sql.py")
    with pytest.raises(pytest.UsageError, match="mixed with other selections"):
        draft_hook.pytest_configure(SimpleNamespace(args=[inactive_port, pack]))
    monkeypatch.setenv(CHILD_FILE_ENV, "test_peaso_checks_azure_ports_sql.py")
    assert draft_hook.pytest_configure(SimpleNamespace(args=[inactive_port])) is None


def test_unrelated_sibling_is_not_rejected_but_selected_unknown_import_is(monkeypatch):
    monkeypatch.delenv(CHILD_FILE_ENV, raising=False)
    unknown = TESTS / "test_peaso_compliance_new_unreviewed_fixture.py"
    reviewed = TESTS / "test_peaso_compliance_new_gcp_gke.py"
    selected = SimpleNamespace(args=[str(TESTS / "test_peaso_collectors_aws_lambda_role_usage.py")])
    full = SimpleNamespace(args=[str(TESTS)])
    direct = SimpleNamespace(args=[str(unknown)])
    original = draft_hook.unpublished_check_imports
    monkeypatch.setattr(draft_hook, "unpublished_check_imports",
                        lambda path: {"compliance_new_unreviewed_fixture"} if path in (unknown, reviewed) else original(path))
    assert draft_hook.pytest_ignore_collect(unknown, selected) is None
    assert draft_hook.pytest_ignore_collect(reviewed, selected) is None
    with pytest.raises(pytest.UsageError, match="Unreviewed unpublished-check import"):
        draft_hook.pytest_ignore_collect(unknown, full)
    with pytest.raises(pytest.UsageError, match="Unreviewed unpublished-check import"):
        draft_hook.pytest_ignore_collect(unknown, direct)


@pytest.mark.parametrize("name", sorted(DRAFT_TEST_MODULES))
def test_unpublished_checks_in_isolated_child(name, record_property):
    env = os.environ.copy()
    assert CHILD_FILE_ENV not in env, "the proxy must run in the ordinary parent process"
    env[CHILD_FILE_ENV] = name
    # The suite-wide PEASO_SOURCE_ATTESTATION=always re-proves every pinned source on
    # each nested call (minutes of CPU for a cold peaso.checks import). This child
    # does not test attestation, so it runs the shipped mode, which still proves
    # every pinned source once on first use.
    env["PEASO_SOURCE_ATTESTATION"] = "once"
    with tempfile.TemporaryDirectory(prefix="peaso-compliance-draft-") as temp:
        junit = Path(temp) / "child.xml"
        command = [sys.executable, "-m", "pytest", "-q", "-ra", "-p", "no:cacheprovider",
                   f"--junitxml={junit}", str(TESTS / name)]
        try:
            completed = subprocess.run(command, cwd=ROOT, env=env, text=True,
                                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                       timeout=120, check=False)
        except subprocess.TimeoutExpired as exc:
            pytest.fail(f"Isolated draft test {name} timed out after 120 seconds: {exc.stdout}", pytrace=False)
        if not junit.exists():
            pytest.fail(f"Isolated draft test {name} produced no JUnit evidence; exit={completed.returncode}\n"
                        f"{completed.stdout}", pytrace=False)
        suites = list(ET.parse(junit).getroot().iter("testsuite"))
        counts = {key: sum(int(suite.get(key, "0")) for suite in suites)
                  for key in ("tests", "failures", "errors", "skipped")}
        executed = counts["tests"] - counts["skipped"]
        record_property("isolated_draft_file", name)
        record_property("isolated_child_cases", counts["tests"])
        record_property("isolated_child_executed", executed)
        record_property("isolated_child_skipped", counts["skipped"])
        if completed.returncode or counts["tests"] <= 0 or counts["failures"] or counts["errors"] or counts["skipped"]:
            pytest.fail(f"Isolated draft test {name} failed: exit={completed.returncode}, "
                        f"JUnit={counts}\n{completed.stdout}", pytrace=False)
        print(f"isolated draft {name}: {executed} executed, 0 skipped")
