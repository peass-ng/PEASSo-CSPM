"""The wheel retains the exact immutable NSP/TDE admission input closure."""
import json
import subprocess
import sys

from tests.test_peaso_installed_wheel import installed_wheel  # noqa: F401  (pytest fixture)


RECEIPTS = (
    'azure_nsp_query_cmk_metadata_admission_20261020.json',
    'azure_nsp_query_cmk_runtime_admission_20261020.json',
    'azure_nsp_query_cmk_production_tde_successor_20261020.json',
)


def input_closure(root):
    paths = set()
    for name in RECEIPTS:
        relative = 'peaso/checks/' + name
        receipt = json.loads((root / relative).read_bytes())
        paths.update((relative, receipt['helper_path']))
        paths.update(receipt.get('sources', {}))
        paths.update(row['path'] for row in receipt['functions'].values())
        paths.update(row['path'] for row in receipt['fixtures'])
        paths.update(receipt.get('predecessor_files', {}))
        if 'predecessor_pack' in receipt:
            paths.add(receipt['predecessor_pack']['path'])
    return paths


def test_installed_current_admission_accepts_intact_wheel(installed_wheel):
    target, environment = installed_wheel
    code = '''
import sys
sys.path.insert(0, sys.argv[1])
from peaso.checks import azure_metadata_only_tde_admission_successor_20261020 as admission
import pytest
from tests.test_peaso_installed_wheel import ADMISSION_RUNTIME_DATA, installed_wheel
import json,pathlib,subprocess,sys
assert admission.reviewed_inputs()[2]
'''
    result = subprocess.run([sys.executable, '-I', '-c', code, str(target)],
                            cwd=target, env=environment, capture_output=True, text=True, timeout=180)
    assert result.returncode == 0, result.stderr[-4000:]


