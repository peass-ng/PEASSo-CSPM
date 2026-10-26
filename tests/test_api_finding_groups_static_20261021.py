"""API grouping preserves native display semantics without native API imports."""
import ast
import hashlib
from pathlib import Path
import subprocess
import sys

from peaso.server import finding_groups_static_20261021 as static

ROOT = Path(__file__).resolve().parents[1]


def test_grouping_source_and_projection_asts_match_native():
    source = (ROOT / 'peaso/finding_groups.py').read_bytes()
    assert hashlib.sha256(source).hexdigest() == static.SOURCE_SHA256
    original = ast.parse(source)
    copied = ast.parse(Path(static.__file__).read_bytes())
    native_defs = {n.name: n for n in original.body if isinstance(n, ast.FunctionDef)}
    static_defs = {n.name: n for n in copied.body if isinstance(n, ast.FunctionDef)}
    assert native_defs.keys() == static_defs.keys()
    # Only display-provider imports differ. The grouping algorithm, membership,
    # verdict ordering and all archived evidence transformations remain exact.
    for name, node in native_defs.items():
        if name == 'regionless_checks':
            continue
        for descendant in ast.walk(node):
            if isinstance(descendant, ast.ImportFrom):
                if descendant.module == 'peaso.check_services':
                    descendant.module, descendant.level = 'service_labels_static_20261020', 1
                elif descendant.module == 'peaso.engine':
                    descendant.module, descendant.level = 'report_projection_static_20261020', 1
        assert ast.dump(node, include_attributes=False) == ast.dump(static_defs[name], include_attributes=False), name


def test_complete_regionless_roster_and_grouping_match_normal_native_registry():
    program = r'''
import copy
from peaso import checks
from peaso import finding_groups as native
from peaso.server import finding_groups_static_20261021 as static
assert static.regionless_checks() == native.regionless_checks()
assert len(static.regionless_checks()) == 253
rows=[]
for number,check in enumerate(checks.CHECKS):
 for offset,status in enumerate(('PASS','FAIL','UNKNOWN')):
  scopes={'aws':'123456789012/'+('eu-west-1' if offset else 'us-east-1'),
          'gcp':'projects/fixture','azure':'/subscriptions/fixture','k8s':'cluster/namespace'}
  rows.append(dict(id=str(number*3+offset),check_id=check.id,provider=check.provider,
   category=check.category,service=check.kind,severity='high',status=status,
   scope=scopes[check.provider],resource_id='resource-'+str(offset),
   evidence={'observed':status},frameworks=[]))
original=copy.deepcopy(rows)
assert static.group_findings(rows,observations=True) == native.group_findings(rows,observations=True)
report=dict(provider='aws',findings=rows,stats={})
assert static.group_report(report) == native.group_report(report)
assert rows == original
print('complete native grouping parity:',len(checks.CHECKS),'checks; regionless roster:',len(static.regionless_checks()))
'''
    result = subprocess.run([sys.executable, '-B', '-c', program], cwd=ROOT,
                            capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, result.stdout + result.stderr
