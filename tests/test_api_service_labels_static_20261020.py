"""Exact service presentation parity without importing provider evaluators."""
import ast
import hashlib
import json
from pathlib import Path
import os
import subprocess
import sys

from peaso.server import service_labels_static_20261020 as static

ROOT = Path(__file__).resolve().parents[1]
# The native reference child needs only native label values, not source attestation. The shipped
# default proves every pinned source once per process; conftest's repeat-every-proof mode
# re-proves on each nested call during the cold peaso.checks import (minutes of CPU).
NATIVE_ENV = {key: value for key, value in os.environ.items() if key != 'PEASO_SOURCE_ATTESTATION'}
NATIVE_ENV['PEASO_SOURCE_ATTESTATION'] = 'once'
FUNCTIONS = ('service_for', 'canonical_observed_service', 'service_for_check', 'finding_service')
CONSTANTS = ('CHECK_SERVICE_OVERRIDES', 'CHECK_SERVICE_PREFIXES', 'SERVICE_ALIASES', 'ANALYSIS_KIND_SERVICES', 'NETWORK_SERVICE_LABELS')


def test_original_service_sources_and_all_projection_asts_are_exact():
    paths = {'peaso/check_services.py': static.SOURCE_SHA256,
             'peaso/analysis/network_catalog.py': static.NETWORK_SOURCE_SHA256,
             'peaso/check_services.json': static.MANIFEST_SHA256}
    for name, expected in paths.items():
        assert len(expected) == 64
        assert hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == expected
    original = ast.parse((ROOT / 'peaso/check_services.py').read_text())
    current = ast.parse(Path(static.__file__).read_text())
    for name in FUNCTIONS:
        before = next(node for node in original.body if isinstance(node, ast.FunctionDef) and node.name == name)
        after = next(node for node in current.body if isinstance(node, ast.FunctionDef) and node.name == name)
        assert ast.dump(before, include_attributes=False) == ast.dump(after, include_attributes=False)


def test_every_registered_service_and_observed_label_matches_native_reference():
    program = r'''
import json
from peaso import checks
from peaso import check_services as native
pairs = native._check_kinds()
cases=[]
for cid, (provider, kind) in sorted(pairs.items()):
 for observed in (None, '', kind, 'azure', 'legacy-unknown-service'):
  finding={'check_id':cid,'provider':provider,'service':observed}
  cases.append([finding,native.finding_service(finding)])
for provider in ('aws','gcp','azure','k8s','unknown',None):
 for cid in ('unknown-check','analysis.internet_exposure',None):
  for observed in (None,'','azure','virtual_network','security_group','Microsoft.Network','compute',17,[],{}):
   finding={'check_id':cid,'provider':provider,'service':observed}
   cases.append([finding,native.finding_service(finding)])
print(json.dumps({'cases':cases,'constants':{name:getattr(native,name)for name in ('CHECK_SERVICE_OVERRIDES','CHECK_SERVICE_PREFIXES','SERVICE_ALIASES','ANALYSIS_KIND_SERVICES','NETWORK_SERVICE_LABELS')}}))
'''
    result = subprocess.run([sys.executable, '-B', '-c', program], cwd=ROOT,
                            capture_output=True, text=True, check=True, timeout=180, env=NATIVE_ENV)
    reference = json.loads(result.stdout)
    assert len(reference['cases']) > 17000
    for name in CONSTANTS:
        assert json.loads(json.dumps(getattr(static, name))) == reference['constants'][name]
    for finding, expected in reference['cases']:
        assert static.finding_service(finding) == expected, finding


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
