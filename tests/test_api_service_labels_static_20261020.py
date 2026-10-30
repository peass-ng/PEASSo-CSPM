"""Exact service presentation parity without importing provider evaluators."""
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]


def test_cold_service_projection_never_imports_native_or_analysis():
    program = r'''
import importlib.abc,sys
class BlockNative(importlib.abc.MetaPathFinder):
 def find_spec(self,fullname,path=None,target=None):
  if fullname in ('peaso.checks','peaso.analysis') or fullname.startswith(('peaso.checks.','peaso.analysis.')):
   raise AssertionError('Native or analysis package reached by service presentation')
sys.meta_path.insert(0,BlockNative())
from peaso.server import service_labels_static_20261020 as static
assert static.finding_service({'check_id':'aws.iam.root_mfa','provider':'aws','service':'legacy'})=='iam'
assert static.finding_service({'check_id':'unknown','provider':'k8s','service':'anything'})=='kubernetes'
assert static.finding_service({'check_id':'unknown','provider':'azure','service':'vnet'})=='Microsoft.Network'
assert not any(name in ('peaso.checks','peaso.analysis') or name.startswith(('peaso.checks.','peaso.analysis.')) for name in sys.modules)
print('passed')
'''
    result = subprocess.run([sys.executable, '-B', '-c', program], cwd=ROOT,
                            capture_output=True, text=True, check=True, timeout=90)
    assert result.stdout.strip() == 'passed'
