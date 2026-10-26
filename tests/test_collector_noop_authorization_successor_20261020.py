"""Exact source epochs and fail-closed current authorization owner proofs."""
from copy import deepcopy
import hashlib
import importlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import os
import types
import pytest
from peaso import checks
canonical_noop = importlib.import_module('peaso.checks.collector_noop_authorization_shared_successor_20261020')
from tests.shared_admission_epoch_compatibility_20261020 import active_shared
bridge = active_shared()
ROOT = Path(__file__).resolve().parents[1]
sha = lambda raw: hashlib.sha256(raw).hexdigest()
PRODUCERS = (
    'peaso.collectors.aws_workload_command_runtime_20261020',
    'peaso.collectors.aws_codebuild_buildspec_runtime_20261020',
    'peaso.collectors.azure_function_package_integration_20261020',
)
OWNERS = (bridge._COMMAND_SUCCESSOR, bridge._CODEBUILD_SUCCESSOR, bridge._PACKAGE_SUCCESSOR)


def test_all137_native_epoch_callable_proof_rows_and_original_objects_preserved():
    prior = json.loads((ROOT / 'peaso/checks' / bridge.accepted_native.RECEIPT).read_bytes())
    current = bridge.reviewed_delta(ROOT)
    noop_raw = (ROOT / 'peaso/checks' / canonical_noop.RECEIPT).read_bytes()
    assert sha(noop_raw) == canonical_noop.RECEIPT_SHA256 == '5709994cbe4aa84b8546c21807952dd8873bbca0c6bd354b99459090dccc7be1'
    noop_receipt = json.loads(noop_raw)
    assert len(noop_receipt['functions']) == 168
    assert bridge.accepted_noop is canonical_noop
    assert bridge._NOOP_FUNCTIONS == canonical_noop._FUNCTIONS
    assert all(current['functions'][name] == row for name, row in noop_receipt['functions'].items())
    assert len(prior['functions']) == 137
    assert all(current['functions'][name] == value for name, value in prior['functions'].items())
    assert all(current[key] == prior[key] for key in ('shared_functions', 'integration_functions', 'azure_collect'))
    for qualified, function in bridge._NATIVE_FUNCTIONS.items():
        assert getattr(bridge.accepted_native, qualified.split(':')[1]) is function
    for qualified, function in bridge._NATIVE_PACKAGE_FUNCTIONS.items():
        assert getattr(bridge._NATIVE_PACKAGE, qualified.split(':')[1]) is function
    assert checks.aws_workload_command_shared_successor_20261020 is bridge
    assert bridge.accepted_native._COMPILED_TRANSACTION.get() is None


def test_only3_exact_whole_file_and_callable_deltas_are_admitted():
    receipt = bridge.reviewed_delta(ROOT)
    expected = {name.replace('.', '/') + '.py' for name in PRODUCERS}
    assert set(receipt['producer_file_deltas']) == expected
    assert len(receipt['producer_functions']) == 3
    for relative, row in receipt['producer_file_deltas'].items():
        raw = (ROOT / relative).read_bytes()
        projected = bridge._private_before(relative, raw, ROOT)
        assert sha(projected) == row['current_sha256']
        old = bridge.predecessor_producer_bytes(relative, raw, ROOT)
        assert sha(old) == row['predecessor_sha256']
        assert row['exact_additions'] == [] and len(row['exact_replacements']) == 1
    for qualified, row in receipt['producer_functions'].items():
        module, name = qualified.split(':')
        function = getattr(importlib.import_module(module), name)
        import inspect
        current = inspect.getsource(function)
        transition = bridge._private_receipt()['provider_group_callables'].get(module.replace('.', '/') + '.py:' + name)
        if transition is not None:
            current = bridge._reverse(current, transition)
        restored = bridge._reverse(current, row)
        assert sha(restored.encode()) == row['predecessor']['sha256']
        assert row['predecessor_sha256'] == row['predecessor']['sha256']
        assert bridge.current_producer_row(function, row['predecessor'], ROOT) == dict(row['predecessor'], sha256=row['current_sha256'])
    relative = 'peaso/checks/__init__.py'
    # Retain the original no-op→CPU row. Reverse only the signed current
    # metadata-only initializer alias before applying that unchanged row.
    from tests.gcp_positive_conservation_epoch_20261020 import metadata_initializer_bytes
    metadata_text = metadata_initializer_bytes((ROOT / relative).read_bytes()).decode()
    noop_text = bridge._reverse(metadata_text, receipt['metadata_only_epoch_file_deltas'][relative])
    restored = bridge._reverse(noop_text, receipt['native_epoch_file_deltas'][relative])
    assert sha(restored.encode()) == receipt['native_epoch_file_deltas'][relative]['predecessor_sha256']


@pytest.mark.parametrize('owner', OWNERS, ids=lambda module: module.__name__.split('.')[-1])
def test_canonical_current_owner_alias_and_idempotent_registration(owner):
    before = tuple(checks.CHECKS)
    assert owner.original.reviewed_inputs is owner.reviewed_inputs
    owner.reviewed_inputs()
    owner.install()
    assert tuple(checks.CHECKS) == before
    assert owner.original.reviewed_inputs is owner.reviewed_inputs


@pytest.mark.parametrize('qualified', sorted(bridge._PRODUCER_FUNCTIONS))
@pytest.mark.parametrize('mutation', ['identity', 'code', 'defaults', 'kwdefaults'])
def test_authorizer_live_callable_tamper_rejected(qualified, mutation, monkeypatch):
    module_name, name = qualified.split(':')
    module = importlib.import_module(module_name)
    function = getattr(module, name)
    bridge.verify_authorization_successors(ROOT)
    if mutation == 'identity':
        replacement = types.FunctionType(function.__code__, function.__globals__, function.__name__, function.__defaults__)
        monkeypatch.setattr(module, name, replacement)
    elif mutation == 'code':
        monkeypatch.setattr(function, '__code__', function.__code__.replace(co_consts=function.__code__.co_consts + ('unreviewed',)))
    elif mutation == 'defaults': monkeypatch.setattr(function, '__defaults__', ('unreviewed',))
    else: monkeypatch.setattr(function, '__kwdefaults__', {'unreviewed': True})
    with pytest.raises(RuntimeError): bridge.verify_authorization_successors(ROOT)


@pytest.mark.parametrize('owner', OWNERS, ids=lambda module: module.__name__.split('.')[-1])
@pytest.mark.parametrize('mutation', ['canonical_alias', 'helper_identity', 'helper_code', 'helper_set', 'grant_class', 'grant_token'])
def test_current_owner_and_typed_grant_proof_tamper_rejected(owner, mutation, monkeypatch):
    bridge.verify_authorization_successors(ROOT)
    if mutation == 'canonical_alias': monkeypatch.setattr(owner.original, 'reviewed_inputs', lambda *a, **k: None)
    elif mutation == 'helper_identity': monkeypatch.setattr(owner, 'reviewed_inputs', lambda *a, **k: None)
    elif mutation == 'helper_code':
        function = owner.reviewed_inputs
        monkeypatch.setattr(function, '__code__', function.__code__.replace(co_consts=function.__code__.co_consts + ('unreviewed',)))
    elif mutation == 'helper_set': monkeypatch.setattr(owner, '_FUNCTIONS', {})
    elif mutation == 'grant_class': monkeypatch.setattr(owner.runtime, '_Grant', type('UnreviewedGrant', (), {}))
    else: monkeypatch.setattr(owner.runtime, '_TOKEN', object())
    with pytest.raises(RuntimeError):
        if mutation in ('grant_class', 'grant_token'): owner.reviewed_inputs()
        else: bridge.verify_authorization_successors(ROOT)


@pytest.mark.parametrize('mutation', ['missing', 'identity'])
def test_producer_snapshot_carrier_cannot_be_poisoned(mutation, monkeypatch):
    copied = dict(bridge._PRODUCER_FUNCTIONS)
    name = next(iter(copied))
    if mutation == 'missing': copied.pop(name)
    else: copied[name] = lambda *a: None
    monkeypatch.setattr(bridge, '_PRODUCER_FUNCTIONS', copied)
    with pytest.raises(RuntimeError): bridge.verify_authorization_successors(ROOT)


def test_historical_catalog_has_all3496_controls_with_exact_non_source_metadata():
    from tests.shared_admission_epoch_compatibility_20261020 import historical_metadata_catalog
    value = historical_metadata_catalog()
    assert len(value['checks']) == 3496
    for row in value['checks']: row.pop('clarity_evaluation_contract', None)
    assert sha(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()) == '55e4ef383df3d4408654b95b46789264d024bb8eb4197ca926f37b7eb0d7a718'


@pytest.fixture(scope='module')
def copied_package(tmp_path_factory):
    target = tmp_path_factory.mktemp('noop-source-copies').resolve()
    for directory in ('peaso', 'bluepeass', 'risk_rules', 'tests', 'docs', 'scripts'):
        shutil.copytree(ROOT / directory, target / directory, ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
    for name in ('aws_permissions_cat.yaml', 'azure_permissions_cat.yaml', 'gcp_permissions_cat.yaml'):
        shutil.copy2(ROOT / name, target / name)
    return target


@pytest.mark.parametrize('relative', [name.replace('.', '/') + '.py' for name in PRODUCERS] + [
    'peaso/checks/collector_noop_command_admission_successor_20261020.py',
    'peaso/checks/collector_noop_codebuild_admission_successor_20261020.py',
    'peaso/checks/collector_noop_package_admission_successor_20261020.py',
    'peaso/checks/native_admission_cpu_shared_successor_20261020.py',
    'peaso/checks/native_admission_cpu_shared_successor_20261020.json',
])
def test_actual_warm_disk_tamper_is_rejected_without_source_reader_redirection(copied_package, relative):
    code = r'''
import pathlib,socket,sys

def blocked(*args,**kwargs):raise AssertionError('No network in source tamper proof')
for owner,names in ((socket,('create_connection','getaddrinfo')),(socket.socket,('connect','connect_ex','sendto'))):
 for name in names:setattr(owner,name,blocked)
from peaso.checks import collector_noop_authorization_shared_successor_20261020 as canonical_noop
from tests.shared_admission_epoch_compatibility_20261020 import active_shared
from peaso.private_secret_source_epoch_20261021 import AdmissionError
bridge = active_shared()
root=pathlib.Path.cwd();path=root/sys.argv[1];raw=path.read_bytes()
try:
 bridge.reviewed_delta(root);bridge.verify_authorization_successors(root)
 path.write_bytes(raw+b'\n# deliberate unreviewed source mutation\n')
 try:bridge.reviewed_delta(root);bridge.verify_authorization_successors(root)
 except (RuntimeError, AdmissionError):print('rejected')
 else:raise AssertionError('Source mutation admitted')
finally:path.write_bytes(raw)
'''
    env = dict(os.environ, PYTHONPATH=str(copied_package), PYTHONDONTWRITEBYTECODE='1', AWS_EC2_METADATA_DISABLED='true', AWS_CONFIG_FILE='/nonexistent/offline', AWS_SHARED_CREDENTIALS_FILE='/nonexistent/offline')
    result = subprocess.run([sys.executable, '-B', '-c', code, relative], cwd=copied_package, env=env, capture_output=True, text=True, timeout=90)
    assert result.returncode == 0, result.stderr[-9000:]
    assert result.stdout.strip() == 'rejected'
