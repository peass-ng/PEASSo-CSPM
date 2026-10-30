"""Current guard baseline, exact tamper rejection and independent package replay."""
from copy import deepcopy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

from peaso import engine
from peaso.collectors import aws
from peaso.server import validation
from peaso.checks import aws_codebuild_buildspec_shared_successor_20261020 as shared
from peaso.checks import aws_codebuild_buildspec_s3_successor_20261020 as s3
from peaso.checks import aws_codebuild_buildspec_runtime_admission_20261020 as codebuild
from peaso.checks import gcp_dataflow_batch_source_runtime_admission_20261020 as dataflow

ROOT = Path(__file__).resolve().parents[1]


def baseline():
    shared.reviewed_inputs()
    s3.reviewed_inputs()
    dataflow.reviewed_inputs()
    codebuild.reviewed_inputs()


@pytest.mark.parametrize('owner,name', [(engine, '_request'), (engine, 'collect_snapshot'),
    (validation, 'validate_connector'), (aws, 'collect')])
def test_current_guard_executing_code_tamper_rejects_then_restored_passes(monkeypatch, owner, name):
    baseline()
    with monkeypatch.context() as patch:
        patch.setattr(owner, name, lambda *args, **kwargs: None)
        with pytest.raises((RuntimeError, KeyError, TypeError)):
            shared.reviewed_inputs() if owner is not aws else s3.reviewed_inputs()
    baseline()


def test_bundle_registration_failure_restores_aliases_cases_and_registry(monkeypatch):
    import peaso.checks as checks
    from peaso.checks import CHECKS
    from peaso.checks.fixtures import CASES
    baseline()
    before = tuple(CHECKS)
    stored = {k: deepcopy(v) for k, v in CASES.items() if k in {shared.original.CHECK, codebuild.runtime.CHECK, *dataflow.runtime.CHECKS}}
    aliases = (shared.original.reviewed_inputs, shared.original._INSTALLED, dataflow.shared)
    original = next(c for c in CHECKS if c.id == codebuild.runtime.CHECK)
    CHECKS.remove(original); CASES.pop(codebuild.runtime.CHECK)
    original_register = checks.register
    def broken_register(ident, *args, **kwargs):
        if ident == codebuild.runtime.CHECK:
            def broken(function):
                CHECKS.append(original)
                raise RuntimeError('final registration failed')
            return broken
        return original_register(ident, *args, **kwargs)
    try:
        with monkeypatch.context() as patch:
            patch.setattr(checks, 'register', broken_register)
            with pytest.raises(RuntimeError, match='final registration failed'):
                shared.install_bundle()
        assert not any(c.id == codebuild.runtime.CHECK for c in CHECKS)
        assert (shared.original.reviewed_inputs, shared.original._INSTALLED, dataflow.shared) == aliases
        assert all(CASES[k] == v for k, v in stored.items() if k != codebuild.runtime.CHECK)
    finally:
        CHECKS[:] = before
        CASES[codebuild.runtime.CHECK] = stored[codebuild.runtime.CHECK]
    baseline()


def test_independent_package_data_normal_import_and_cross_process_json_replay(tmp_path):
    """Copy installable package bytes, not a wheel build or a source-read mock."""
    installed = tmp_path / 'installed'
    shutil.copytree(ROOT / 'peaso', installed / 'peaso', ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
    # Existing Azure package data uses this deliberately packaged namespace.
    fixture_names = ('azure_nsp_query_cmk_metadata_proposal_20261020.json.gz',
        'azure_nsp_query_cmk_runtime_native_20261020.json.gz',
        'azure_nsp_query_cmk_production_native_20261020.json.gz',
        'azure_sql_tde_parent_identity_predecessor_20261020.json.gz')
    namespace = installed / 'tests/fixtures'
    namespace.mkdir(parents=True)
    (installed / 'tests/__init__.py').write_text('')
    (namespace / '__init__.py').write_text('')
    for name in fixture_names:
        shutil.copyfile(ROOT / 'tests/fixtures' / name, namespace / name)
    script = '''
import json
from pathlib import Path
import peaso
from peaso.checks import aws_codebuild_buildspec_runtime_admission_20261020 as admission
from peaso.checks import aws_codebuild_buildspec_runtime_consumer_20261020 as consumer
from peaso.checks import aws_codebuild_buildspec_shared_successor_20261020 as shared
assert Path(peaso.__file__).resolve().is_relative_to(Path.cwd())
receipt,cases=admission.reviewed_inputs()
assert receipt['native_cases_required'] is True
shared.reviewed_inputs()
case=cases[consumer.runtime.CHECK]
statuses={name:consumer.evaluate(json.loads(json.dumps(case[name])),json.loads(json.dumps(case[name+'_index'])))[0] for name in ('pass','fail','unknown','malformed','partial')}
assert statuses=={'pass':'PASS','fail':'FAIL','unknown':'UNKNOWN','malformed':'UNKNOWN','partial':'FAIL'}
print(json.dumps(statuses,sort_keys=True))
'''
    environment = dict(os.environ, PYTHONPATH=str(installed), AWS_EC2_METADATA_DISABLED='true',
        AWS_CONFIG_FILE='/nonexistent/package-proof', AWS_SHARED_CREDENTIALS_FILE='/nonexistent/package-proof')
    process = subprocess.run([sys.executable, '-c', script], cwd=installed, env=environment,
        capture_output=True, text=True, timeout=90)
    assert process.returncode == 0, process.stderr[-6000:]
    assert json.loads(process.stdout)['partial'] == 'FAIL'
