"""Packaging-safe, fresh-process parity for the frozen evidence presentation."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
RUNTIME_ROOT = ROOT/'peaso/server'
NATIVE_ROOT = (ROOT/'peaso/checks').resolve().parents[1]
ARCHIVE = ROOT/'tests/fixtures/evidence_static_parity_all_20261020.jsonl.gz'
ARCHIVE_SHA256 = '87196e7873b320bdc8109b8c685977baa4c5ce5fc8e848e0b98ec1f33c14b24c'
SKIPPED = ROOT/'tests/fixtures/evidence_static_skipped_20261020.json'
SKIPPED_SHA256 = '73162790353f206ca8b2e8e8fd5bc3d505d04960bb7736a448c17fef4146357f'
RUNTIME = ('evidence_static.py', 'evidence_static_source_manifest.json',
           'evidence_static_data_manifest.json', 'evidence_static_field_specs.json',
           'evidence_static_privesc_entries.json')
REVIEWED_SUCCESSORS = {
    5155: {
        'check_id': 'aws.claude_a.accessanalyzer.active_without_findings',
        'old': 'No findings were found in the collected evidence. Analyzer findings identify access relationships needing review; finding count does not prove an exploitable path.',
        'current': 'The active regional IAM Access Analyzers returned no active findings after complete collection.',
    },
    10040: {
        'check_id': 'azure.review.machine_learning.selected_command_job_secret_indicators',
        'old': 'Both offline detectors found no supported secret in selected Machine Learning Command-job literals. Only returned Command-job literals are covered. ',
        'current': 'The selected Command-job literals could not be fully inspected; no clean result is established. Only returned Command-job literals are covered. ',
    },
    10041: {
        'check_id': 'azure.review.machine_learning.selected_command_job_secret_indicators',
        'old': 'A likely secret was detected in selected Machine Learning Command-job literals. Its value is hidden and was not validated. Only returned Command-job literals are covered. ',
        'current': 'The selected Command-job literals could not be fully inspected; no clean result is established. Only returned Command-job literals are covered. ',
    },
    10043: {
        'check_id': 'azure.review.databricks.selected_notebook_source_secret_indicators',
        'old': 'Both offline detectors found no supported secret in the selected Databricks notebook source. Only the selected point-in-time notebook export is covered. ',
        'current': 'The selected notebook source could not be fully inspected; no clean result is established. Only the selected point-in-time notebook export is covered. ',
    },
    10044: {
        'check_id': 'azure.review.databricks.selected_notebook_source_secret_indicators',
        'old': 'A likely secret was detected in the selected Databricks notebook source. Its value is hidden and was not validated. Only the selected point-in-time notebook export is covered. ',
        'current': 'The selected notebook source could not be fully inspected; no clean result is established. Only the selected point-in-time notebook export is covered. ',
    },
}


# Preserve the original 12,145 rendered witnesses. This exact successor records
# reviewed privilege evidence wording, catalog retirements, and historical
# source anchors; the native formatter must reproduce every successor below.
PRIVESC_SUCCESSOR_RAW = (ROOT/'tests/fixtures/evidence_static_privesc_successor_20261022.json.gz').read_bytes()
assert hashlib.sha256(PRIVESC_SUCCESSOR_RAW).hexdigest() == 'aa73fc86a3a7294f0b4a5edbc249799f4bc6050150a8954ffe1828a3e5359b71'
import gzip
PRIVESC_SUCCESSOR = json.loads(gzip.decompress(PRIVESC_SUCCESSOR_RAW))
assert PRIVESC_SUCCESSOR['original_archive_sha256'] == ARCHIVE_SHA256
assert len(PRIVESC_SUCCESSOR['rows']) == 1899
for relative, digest in PRIVESC_SUCCESSOR['sources'].items():
    assert hashlib.sha256((ROOT/relative).read_bytes()).hexdigest() == digest, relative
assert not set(map(int, PRIVESC_SUCCESSOR['rows'])) & set(REVIEWED_SUCCESSORS)
REVIEWED_SUCCESSORS.update({int(index): row for index, row in PRIVESC_SUCCESSOR['rows'].items()})

AZURE_SUCCESSOR_RAW = (ROOT/'tests/fixtures/evidence_static_azure_successor_20261023.json.gz').read_bytes()
assert hashlib.sha256(AZURE_SUCCESSOR_RAW).hexdigest() == 'df98471857455bbeb698ada3fb129608b35a458d3a833cf3e6474645af3a013e'
AZURE_SUCCESSOR = json.loads(gzip.decompress(AZURE_SUCCESSOR_RAW))
assert AZURE_SUCCESSOR['original_archive_sha256'] == ARCHIVE_SHA256
assert len(AZURE_SUCCESSOR['rows']) == 1578
for relative, digest in AZURE_SUCCESSOR['sources'].items():
    assert hashlib.sha256((ROOT/relative).read_bytes()).hexdigest() == digest, relative
for index, row in AZURE_SUCCESSOR['rows'].items():
    previous = REVIEWED_SUCCESSORS.get(int(index))
    if previous is not None:
        assert previous['check_id'] == row['check_id']
        assert previous['old'] == row['old']
REVIEWED_SUCCESSORS.update({int(index): row for index, row in AZURE_SUCCESSOR['rows'].items()})


def _stage(tmp_path):
    """Build a package overlay without writing to the source checkout."""
    (tmp_path/'risk_rules').symlink_to(ROOT/'risk_rules', target_is_directory=True)
    peaso = tmp_path/'peaso'
    peaso.mkdir()
    for child in (ROOT/'peaso').iterdir():
        if child.name != 'server':
            (peaso/child.name).symlink_to(child, target_is_directory=child.is_dir())
    server=peaso/'server'
    server.mkdir()
    for child in RUNTIME_ROOT.iterdir():
        if child.name not in RUNTIME:
            (server/child.name).symlink_to(child, target_is_directory=child.is_dir())
    for name in RUNTIME:
        (server/name).write_bytes((RUNTIME_ROOT/name).read_bytes())
    return tmp_path


def _run(stage, script):
    # The copied helper reads the package overlay; normal Python imports use
    # the actual source package, as they do after installation.
    assert hashlib.sha256(ARCHIVE.read_bytes()).hexdigest() == ARCHIVE_SHA256
    # Run the shipped attestation mode: each fresh process still proves every pinned
    # source on first use, so the manifest and catalog tamper cases stay covered.
    # PEASO_SOURCE_ATTESTATION=always re-proves on every nested call and makes the
    # cold peaso.checks import cost ~143 CPU s instead of ~11, which is unrelated to formatting.
    env={key: value for key, value in os.environ.items() if key != 'PEASO_SOURCE_ATTESTATION'}
    env.update(PYTHONPATH=str(NATIVE_ROOT)+os.pathsep+str(ROOT)+os.pathsep+str(stage))
    successors_path = stage/'reviewed-successors.json'
    successors_path.write_text(json.dumps(REVIEWED_SUCCESSORS), encoding='utf-8')
    result=subprocess.run([sys.executable,'-c',script,str(ARCHIVE),str(stage),
                           str(successors_path)],
                          cwd=NATIVE_ROOT,env=env,text=True,capture_output=True,timeout=180)
    assert result.returncode == 0, result.stdout+'\n'+result.stderr
    return result.stdout


COLD = r'''
import copy,gzip,importlib.util,json,sys
from pathlib import Path
path=Path(sys.argv[2])/'peaso/server/evidence_static.py'
spec=importlib.util.spec_from_file_location('evidence_static_cold',path)
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
assert not any(name=='peaso.checks' or name.startswith('peaso.checks.') or name=='peaso.analysis' or name.startswith('peaso.analysis.') or name=='peaso.engine' for name in sys.modules)
reviewed=json.loads(Path(sys.argv[3]).read_text());count=0;changed=set()
with gzip.open(sys.argv[1],'rt',encoding='utf-8') as file:
 for line in file:
  row=json.loads(line);finding=copy.deepcopy(row['finding']);before=copy.deepcopy(finding)
  try: actual={'value':module.evidence_summary(finding)}
  except Exception as error: actual={'error':type(error).__name__,'message':str(error)}
  successor=reviewed.get(str(count))
  if successor:
   assert row['finding']['check_id']==successor['check_id'],count
   assert row['expected']=={'value':successor['old']},count
   assert actual=={'value':successor['current']},(count,actual)
   changed.add(count)
  else:
   assert actual==row['expected'],(count,row['finding']['check_id'],actual,row['expected'])
  assert finding==row['after'],count
  count+=1
  assert not any(name=='peaso.checks' or name.startswith('peaso.checks.') or name=='peaso.analysis' or name.startswith('peaso.analysis.') or name=='peaso.engine' for name in sys.modules),count
assert count==12145,count
assert changed=={int(index) for index in reviewed},changed
print('cold parity',count)
'''


def test_all_fixtures_exact_cold_parity(tmp_path):
    assert 'cold parity 12145' in _run(_stage(tmp_path),COLD)


def test_skipped_fixture_accounting():
    assert hashlib.sha256(SKIPPED.read_bytes()).hexdigest() == SKIPPED_SHA256
    rows=json.loads(SKIPPED.read_text())
    assert len(rows)==1081
    assert sum(row['reason']=='no CASES entry' for row in rows)==581
    assert sum(row['reason']=='fixture variant absent' for row in rows)==500
    assert all(row['stage']=='selection' for row in rows)


def test_pinned_manifest_rejects_tamper(tmp_path):
    stage=_stage(tmp_path)
    for name in ('evidence_static_source_manifest.json','evidence_static_data_manifest.json'):
        path=stage/'peaso/server'/name
        original=path.read_bytes()
        path.write_bytes(original+b' ')
        script=r'''
import importlib.util,sys
from pathlib import Path
path=Path(sys.argv[2])/'peaso/server/evidence_static.py'
spec=importlib.util.spec_from_file_location('evidence_static_tamper',path)
module=importlib.util.module_from_spec(spec)
try:spec.loader.exec_module(module)
except ImportError as error:
 assert 'manifest changed' in str(error),str(error)
else:raise AssertionError('tampered manifest accepted')
'''
        _run(stage,script)
        path.write_bytes(original)


def test_native_registry_imports_after_cold_formatting(tmp_path):
    script=r'''
import gzip,importlib.util,json,sys
from pathlib import Path
path=Path(sys.argv[2])/'peaso/server/evidence_static.py'
spec=importlib.util.spec_from_file_location('evidence_static_then_native',path)
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
rows=[];reviewed=json.loads(Path(sys.argv[3]).read_text());changed=[]
with gzip.open(sys.argv[1],'rt',encoding='utf-8') as file:
 for index,line in enumerate(file):
  row=json.loads(line)
  if row['kind']=='native-pass' and row['finding']['provider'] not in {x['finding']['provider'] for x in rows}:
   row['_archive_index']=index
   rows.append(row)
  if str(index) in reviewed:changed.append((index,row))
for row in rows:
 actual=module.evidence_summary(row['finding'])
 successor=reviewed.get(str(row['_archive_index']))
 if successor:
  assert successor['old']==row['expected']['value']
  assert actual==successor['current'],(row['finding']['check_id'],actual,successor['current'])
 else:
  assert actual==row['expected']['value'],(row['finding']['check_id'],actual,row['expected']['value'])
assert 'peaso.checks' not in sys.modules and 'peaso.analysis' not in sys.modules
from peaso.checks import CHECKS
from peaso.finding_observation import evidence_summary as original
assert len(CHECKS)>=4000,len(CHECKS)
for row in rows:assert original(row['finding'])==module.evidence_summary(row['finding'])
assert len(changed)==len(reviewed)
for index,row in changed:
 successor=reviewed[str(index)]
 assert row['finding']['check_id']==successor['check_id']
 assert row['expected']=={'value':successor['old']}
 cold=module.evidence_summary(row['finding'])
 assert cold==successor['current']
 native=original(row['finding'])
 if row['finding']['check_id'] in {'aws-cloudcontrol-passrole-createresource',
                                  'aws-organizations-createaccount-principalorgid-trust',
                                  'aws-bedrock-agentcore-createcodeinterpreter-passrole',
                                  'aws-bedrock-agentcore-updateagentruntime-passrole',
                                  'aws-emr-getclustersessioncredentials-runtime-role',
                                  'aws-finspace-passrole-createkxcluster'}:
  assert native is None,(index,native)
 else:
  assert native==cold,(index,native,cold)
print('native later',len(CHECKS))
'''
    assert 'native later' in _run(_stage(tmp_path),script)


def test_concurrent_first_import_never_exposes_partial_formatter(monkeypatch):
    import builtins
    from concurrent.futures import ThreadPoolExecutor
    import importlib.util
    from threading import Event
    from peaso.server import evidence_static
    spec = importlib.util.spec_from_file_location('isolated_evidence_thread_test', evidence_static.__file__)
    loader = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loader)
    entered, release, second_started, second_finished = (Event() for _ in range(4))
    def delayed_exec(code, namespace):
        entered.set()
        assert release.wait(10)
        return builtins.exec(code, namespace)
    monkeypatch.setattr(loader, 'exec', delayed_exec, raising=False)
    name = 'checks.aws_ai_recheck_evidence_20261020'
    def concurrent_reader():
        second_started.set()
        try:
            return loader._load_source(name).evidence_summary({})
        finally:
            second_finished.set()
    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(loader._load_source, name)
        try:
            assert entered.wait(5)
            second = pool.submit(concurrent_reader)
            assert second_started.wait(5)
            assert not second_finished.wait(0.2)
        finally:
            release.set()
        assert second.result(timeout=5) is None
        assert loader._load_source(name) is first.result(timeout=5)


def test_presentation_runs_when_engine_catalogs_are_absent(tmp_path):
    stage = _stage(tmp_path)
    privesc = stage/'peaso/privesc'
    privesc.unlink()
    privesc.mkdir()
    for child in (ROOT/'peaso/privesc').iterdir():
        if child.name not in {'catalog', 'catalog_versions', '__pycache__'}:
            (privesc/child.name).symlink_to(child, target_is_directory=child.is_dir())
    script = r'''
import importlib.util,json,sys
from pathlib import Path
path=Path(sys.argv[2])/'peaso/server/evidence_static.py'
spec=importlib.util.spec_from_file_location('presentation_without_engine_catalog',path)
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
assert not (module.SOURCE_ROOT/'peaso/privesc/catalog').exists()
assert not any(name.startswith('peaso/privesc/catalog/') for name in module.MANIFEST)
module.verify_closure()
entries=module._catalog()['entries']
assert entries and all('id' in row for row in entries)
finding={'check_id':'aws.a.iam.root_summary_mfa','provider':'aws','status':'FAIL','evidence':{'AccountMFAEnabled':0}}
assert module.evidence_summary(finding)
# The substituted materialized catalog remains mandatory and hash-verified.
path=Path(sys.argv[2])/'peaso/server/evidence_static_privesc_entries.json'
path.write_bytes(path.read_bytes()+b' ')
module.verify_closure.cache_clear()
try:module.verify_closure()
except ImportError as error:assert 'materialized presentation input changed' in str(error)
else:raise AssertionError('tampered materialized catalog accepted')
print('catalog-free presentation and materialized tamper rejection passed')
'''
    assert 'catalog-free presentation' in _run(stage, script)
