"""Exact native reference parity for the API-only presentation successor."""
import ast
from copy import deepcopy
from pathlib import Path
import os
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]

# These children only need the native reference values, not source attestation. The shipped
# default proves every pinned source once per process; conftest's repeat-every-proof mode
# re-proves on each nested call during the cold peaso.checks import (minutes of CPU).
NATIVE_ENV = {key: value for key, value in os.environ.items() if key != 'PEASO_SOURCE_ATTESTATION'}
NATIVE_ENV['PEASO_SOURCE_ATTESTATION'] = 'once'


def test_identity_command_and_exposure_functions_preserve_native_asts():
    source = ast.parse((ROOT / 'peaso/remediation.py').read_text())
    copied = ast.parse((ROOT / 'peaso/server/remediation_presentation_static_20261020.py').read_text())
    names = ('_bounded', 'identity_bindings', 'bind_command', 'exposure_action', 'exposure_details')
    for name in names:
        left = next(n for n in source.body if isinstance(n, ast.FunctionDef) and n.name == name)
        right = next(n for n in copied.body if isinstance(n, ast.FunctionDef) and n.name == name)
        assert ast.dump(left, include_attributes=False) == ast.dump(right, include_attributes=False)
    def assignments(tree):
        return {target.id: ast.dump(node, include_attributes=False)
                for node in tree.body if isinstance(node, ast.Assign)
                for target in node.targets if isinstance(target, ast.Name)}
    left, right = assignments(source), assignments(copied)
    for name in left:
        if name.startswith('_SAFE') or name in ('MAX_IDENTITY_LENGTH', '_AWS_NAMED_KINDS', '_PLACEHOLDER'):
            assert left[name] == right[name], name


def test_all_registered_and_analysis_templates_preserve_presentation_inputs():
    from peaso.checks import CHECKS, CHECK_ALIASES
    from peaso.analysis import ANALYSIS_CHECKS
    from peaso.remediation import template
    from peaso.finding_presentation import _approved_text
    from peaso.server.materialized_catalog import template_for
    for check in CHECKS:
        expected, actual = template(check.id, check.provider), template_for(check.id, check.provider)
        assert _approved_text(actual) == _approved_text(expected), check.id
        if actual is not None:
            original = deepcopy(actual)
            actual['summary'] = 'caller mutation'
            assert template_for(check.id, check.provider) == original
    for cid in [*(row['id'] for row in ANALYSIS_CHECKS), *CHECK_ALIASES,
                'gcp_cloudsql_failed_attempts_lockout', 'azure_vm_8_2_1_1_712e1ad', 'unknown', 'analysis.unknown']:
        for provider in (None, 'aws', 'gcp', 'azure', 'k8s', 'other'):
            assert _approved_text(template_for(cid, provider)) == _approved_text(template(cid, provider)), (cid, provider)


def test_native_free_lookup_then_real_native_import_in_same_process():
    script = r'''
import importlib.abc, sys
class Guard(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname in ('peaso.checks','peaso.engine','peaso.analysis') or fullname.startswith(('peaso.checks.','peaso.analysis.')):
            raise AssertionError(fullname)
guard = Guard(); sys.meta_path.insert(0, guard)
from peaso.server.materialized_catalog import template_for
from peaso.server.remediation_presentation_static_20261020 import bind_command
assert template_for('aws.iam.root_mfa', 'aws')
bind_command('inspect <ACCOUNT_ID>', {'provider':'aws','scope':'123456789012','check_id':'aws.iam.root_mfa'})
assert not any(name in ('peaso.checks','peaso.engine','peaso.analysis') for name in sys.modules)
sys.meta_path.remove(guard)
from peaso.checks import CHECKS
assert len(CHECKS) > 4000
'''
    result = subprocess.run([sys.executable, '-c', script], cwd=ROOT, capture_output=True, text=True, timeout=90, env=NATIVE_ENV)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize('missing', [False, True])
def test_changed_or_missing_remediation_source_fails_closed(tmp_path, monkeypatch, missing):
    from fastapi import HTTPException
    from peaso.server import materialized_catalog as catalog
    # Only the first verified source is needed: it must reject before loading
    # any catalog or trusting presentation metadata.
    first = next(iter(catalog._REMEDIATION_PRESENTATION_SOURCES))
    path = tmp_path / first
    path.parent.mkdir(parents=True)
    if not missing:
        path.write_bytes((ROOT / first).read_bytes() + b'\n# changed\n')
    catalog._presentation_sources_valid.cache_clear()
    monkeypatch.setattr(catalog, 'ROOT', tmp_path / 'peaso')
    try:
        with pytest.raises(HTTPException) as raised:
            catalog.template_for('aws.iam.root_mfa', 'aws')
        assert raised.value.status_code == 503
    finally:
        catalog._presentation_sources_valid.cache_clear()

