"""Keep unpublished check registrations out of the full-suite registry."""

from __future__ import annotations

import os
import json
from pathlib import Path

import pytest

# Synthetic deployment identities for isolated tests; production has no defaults.
for _name, _value in {
    "PEASO_AWS_COLLECTOR_ROLE_ARN": "arn:aws:iam::111122223333:role/HackTricks-CSPM",
    "PEASO_PLATFORM_ACCOUNT_IDS": "111122223333,444455556666",
    "PEASO_GCP_PLATFORM_PROJECT": "example-platform-project",
    "PEASO_GCP_PLATFORM_EMAIL": "cspm@example-platform-project.iam.gserviceaccount.com",
    "PEASO_DEPLOY_ACCOUNT_ID": "111122223333",
    "PEASO_DEPLOY_COGNITO_POOL_ID": "us-east-1_example",
    "PEASO_DEPLOY_COGNITO_CLIENT_ID": "example-client",
    "PEASO_DEPLOY_BACKEND": json.dumps({"bucket": "example-deployment-state", "key": "cspm/terraform.tfstate", "region": "us-east-1", "encrypt": True, "use_lockfile": True}),
}.items():
    os.environ.setdefault(_name, _value)

# Production proves each pinned source once per process; tests re-prove on
# every nested call so live rebinding after import is still detected.
os.environ.setdefault("PEASO_SOURCE_ATTESTATION", "always")

from tests.compliance_draft_isolation import (CHILD_FILE_ENV, DRAFT_TEST_MODULES,
    STAGED_UNSELECTED_TEST_MODULES, staged_modules_unregistered, staged_registry, unpublished_check_imports)


TESTS_DIR = Path(__file__).resolve().parent


def _requested_draft_files(config) -> list[str]:
    requested = []
    for arg in config.args:
        path = Path(str(arg).split("::", 1)[0]).resolve()
        if path.parent == TESTS_DIR and path.name in DRAFT_TEST_MODULES:
            requested.append(path.name)
    return requested


def _requested_staged_files(config) -> list[str]:
    return [path.name for arg in config.args
            if (path := Path(str(arg).split("::", 1)[0]).resolve()).parent == TESTS_DIR
            and path.name in STAGED_UNSELECTED_TEST_MODULES]


def _selected_path(path: Path, config) -> bool:
    """Pytest may ask about siblings outside an explicitly requested file."""
    if not config.args:
        return True
    arguments = tuple(str(arg).split("::", 1)[0] for arg in config.args)
    cached = getattr(config, "_peaso_collection_roots", None)
    if cached is None or cached[0] != arguments:
        roots = tuple(Path(arg).resolve() for arg in arguments)
        cached = (arguments, tuple((root, root.is_dir()) for root in roots))
        config._peaso_collection_roots = cached
    parents = path.parents
    return any(path == selected or (directory and selected in parents)
               for selected, directory in cached[1])


def pytest_configure(config):
    requested = _requested_draft_files(config)
    staged = _requested_staged_files(config)
    child_file = os.environ.get(CHILD_FILE_ENV)
    if child_file is not None:
        if child_file not in DRAFT_TEST_MODULES or len(config.args) != 1 or requested != [child_file]:
            raise pytest.UsageError(
                f"{CHILD_FILE_ENV} requires exactly its named draft test file as the sole pytest selection"
            )
    elif requested and (len(config.args) != 1 or len(requested) != 1):
        raise pytest.UsageError(
            "An explicit draft test mixed with other selections would contaminate the runtime registry; "
            "run each draft file alone or run the full suite through test_peaso_compliance_draft_isolation.py"
        )
    elif staged and (len(config.args) != 1 or len(staged) != 1):
        raise pytest.UsageError("An explicitly selected staged registrar test must be the sole pytest selection")


def pytest_ignore_collect(collection_path: Path, config):
    path = Path(collection_path).resolve()
    if path.suffix != ".py" or not path.name.startswith("test_") or TESTS_DIR not in path.parents:
        return None
    if not _selected_path(path, config):
        return None
    if path.parent == TESTS_DIR and path.name in STAGED_UNSELECTED_TEST_MODULES:
        expected = set(STAGED_UNSELECTED_TEST_MODULES[path.name])
        if unpublished_check_imports(path) != expected or not staged_modules_unregistered(expected):
            raise pytest.UsageError(f"Staged-unselected registrar boundary drift in {path.name}")
        return None if _requested_staged_files(config) == [path.name] else True
    if path.parent != TESTS_DIR or path.name not in DRAFT_TEST_MODULES:
        if unpublished_check_imports(path):
            raise pytest.UsageError(
                f"Unreviewed unpublished-check import in {path}; add the exact file/module to the "
                "reviewed draft-isolation allowlist before collecting it"
            )
        return None
    imported = unpublished_check_imports(path)
    if imported != {DRAFT_TEST_MODULES[path.name]}:
        raise pytest.UsageError(f"Draft-isolation allowlist drift in {path.name}: {sorted(imported)}")
    child_file = os.environ.get(CHILD_FILE_ENV)
    if child_file == path.name or (child_file is None and _requested_draft_files(config) == [path.name]):
        return None
    return True


def pytest_sessionstart(session):
    from tests.release_test_inputs import restore_missing_inputs

    # These are ignored, immutable synthetic fixtures. Keep the cache so one
    # pytest/xdist session cannot delete inputs another session still needs.
    restore_missing_inputs(TESTS_DIR.parent)
    selected = _requested_staged_files(session.config)
    drafts = _requested_draft_files(session.config)
    modules = STAGED_UNSELECTED_TEST_MODULES[selected[0]] if selected else [DRAFT_TEST_MODULES[drafts[0]]] if drafts else []
    if modules:
        sandbox = staged_registry(modules)
        sandbox.__enter__()
        session.config.add_cleanup(lambda: sandbox.__exit__(None, None, None))
