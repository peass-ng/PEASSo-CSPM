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
    script = '''
import json
from pathlib import Path
import peaso
from peaso.checks import aws_codebuild_buildspec_runtime_admission_20261020 as admission
from peaso.checks import aws_codebuild_buildspec_runtime_consumer_20261020 as consumer
from peaso.checks import selected_admission
assert Path(peaso.__file__).resolve().is_relative_to(Path.cwd())
cases=selected_admission.load_cases(admission.CASES)
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
