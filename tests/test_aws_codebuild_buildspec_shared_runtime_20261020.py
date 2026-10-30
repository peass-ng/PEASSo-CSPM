"""Independent package replay of the CodeBuild buildspec runtime check."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]


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
