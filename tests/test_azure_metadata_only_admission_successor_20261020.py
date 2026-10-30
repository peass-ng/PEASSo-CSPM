"""Normal native admission, original metadata contract and fail-closed epoch proofs."""
import copy
import hashlib
import importlib
import inspect
import json
import linecache
import os
from pathlib import Path
import shutil
import subprocess
import sys
import types
import pytest
from peaso.collectors import azure
from tests.shared_admission_epoch_compatibility_20261020 import active_shared
bridge = active_shared()
from tests.test_peaso_azure_tls_owner_policy import options, owner, SCOPE, FOREIGN

ROOT = Path(__file__).resolve().parents[1]
sha = lambda raw: hashlib.sha256(raw).hexdigest()
TENANT = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'


class Inert:
    tenant = verified_tenant = TENANT
    def request(self, *a, **k): raise AssertionError('No native IO allowed')


@pytest.mark.parametrize('case', ['tls', 'namespaces', 'scope', 'invalid_scope', 'window', 'package', 'wildcard', 'hosted'])
def test_supplied8_metadata_only_cases_through_normal_admitted_collect(case, monkeypatch):
    constructions = []
    def forbidden(*a, **k): constructions.append((a, k)); raise AssertionError('Transport construction forbidden')
    monkeypatch.setattr(azure, 'AzureTransportExposure', forbidden)
    supplied = options() if case in ('tls', 'namespaces', 'scope') else {'activity_days': 0} if case == 'window' else {'hosted': True} if case == 'hosted' else {}
    raw_policy = {'sw03': {'status': 'collected', 'scope': SCOPE, 'legacyAgentBaseline': {'required': False}}, 'sw33': {'status': 'collected', 'scope': SCOPE, 'databricksAccount': {'accountId': TENANT}}}
    if case == 'namespaces': supplied['compliance_policy'] = copy.deepcopy(raw_policy)
    before = copy.deepcopy(supplied)
    scopes = [FOREIGN] if case == 'scope' else ['sub/../../other'] if case == 'invalid_scope' else ['*'] if case == 'wildcard' else [SCOPE]
    requirements = [azure.package_source.KIND] if case == 'package' else []
    if case in ('scope', 'invalid_scope', 'window'):
        with pytest.raises(ValueError): azure.collect({'auth': {}, 'scopes': scopes, 'options': supplied}, requirements=requirements)
    else:
        kw = {} if case == 'hosted' else {'transport': Inert()}
        value = azure.collect({'auth': {}, 'scopes': scopes, 'options': supplied}, requirements=requirements, **kw)
        assert value['metadata']['calls'] == 0 and value['collections'] == []
        assert value['metadata']['omitted_inventories']
        if case == 'tls': assert value['metadata']['compliance_policy'] == owner()
        if case == 'namespaces': assert value['metadata']['compliance_policy'] == {**raw_policy, **owner()}
        if case == 'hosted': assert value['metadata']['tenant_verified'] is False
    assert not constructions and supplied == before


@pytest.mark.parametrize('requirements', [[], [azure.package_source.KIND]])
def test_empty_ungranted_selection_cannot_expand_into_dependency_reads(requirements, monkeypatch):
    from peaso.collectors import azure_disclosure_native
    monkeypatch.setattr(azure_disclosure_native, 'required_types', lambda options: {'subscription', 'app_service'})
    def forbidden(*a, **k): raise AssertionError('No dependency or credential IO')
    monkeypatch.setattr(azure, 'AzureTransportExposure', forbidden)
    supplied = {}
    value = azure.collect({'auth': {}, 'scopes': [SCOPE], 'options': supplied}, requirements=requirements)
    assert value['metadata']['calls'] == 0 and value['collections'] == [] and supplied == {}


@pytest.mark.parametrize('denied', [False, True])
def test_active_selection_retains_one_read_and_exact_owner_authority(denied):
    class Transport:
        tenant = verified_tenant = TENANT
        def __init__(self): self.calls = []
        def request(self, url, **kwargs):
            self.calls.append((url, kwargs))
            assert url == azure.ARM + SCOPE + '?api-version=2022-12-01'
            if denied: raise ValueError('deliberate denial')
            return {'id': SCOPE, 'subscriptionId': SCOPE.rsplit('/', 1)[-1], 'tenantId': TENANT}
    transport = Transport(); supplied = options(); before = copy.deepcopy(supplied)
    value = azure.collect({'auth': {}, 'scopes': [SCOPE], 'options': supplied}, requirements=['subscription'], transport=transport)
    assert len(transport.calls) == value['metadata']['calls'] == 1
    assert value['metadata']['compliance_policy'] == owner() and supplied == before
    rows = [row for row in value['collections'] if row['type'] == 'subscription']
    assert len(rows) == 1 and rows[0]['status'] == ('malformed' if denied else 'collected')


def test_all168_prior_callable_rows_receipts_and_exact_source_epochs_preserved():
    receipt = bridge.reviewed_delta(ROOT)
    prior = json.loads((ROOT / 'peaso/checks' / bridge.accepted_noop.RECEIPT).read_bytes())
    assert sha((ROOT / 'peaso/checks' / bridge.accepted_noop.RECEIPT).read_bytes()) == '5709994cbe4aa84b8546c21807952dd8873bbca0c6bd354b99459090dccc7be1'
    assert len(prior['functions']) == 168 and len(receipt['functions']) == 201
    assert all(receipt['functions'][name] == row for name, row in prior['functions'].items())
    for key in ('shared_functions', 'integration_functions', 'azure_collect', 'file_deltas', 'parent_file_deltas', 'integration_file_deltas', 'prior_epoch_file_deltas', 'native_epoch_file_deltas', 'producer_file_deltas', 'producer_functions'):
        assert receipt[key] == prior[key]
    assert set(receipt['metadata_only_epoch_file_deltas']) == {'peaso/checks/__init__.py', 'peaso/collectors/azure.py'}
    raw = (ROOT / 'peaso/collectors/azure.py').read_bytes()
    if hasattr(bridge, '_private_before'):
        raw = bridge._private_before('peaso/collectors/azure.py', raw, ROOT)
    assert sha(raw) == 'd27a5f2b861fef622c20bff80bf5e8f559d7f5d70604606643eb9267254101e5'
    assert sha(bridge.predecessor_epoch_bytes('peaso/collectors/azure.py', (ROOT / 'peaso/collectors/azure.py').read_bytes(), ROOT)) == 'b69db967e65722174e847116620b63c7de4f0da835e3edde1a882456dc37afea'
    assert bridge.predecessor_epoch_bytes('unlisted/path.py', b'unmodified', ROOT) == b'unmodified'
    assert bridge._COMPILED_TRANSACTION.get() is None


def test_historical_catalog_metadata_stays_exact_and_new_tde_lineage_admitted():
    from tests.shared_admission_epoch_compatibility_20261020 import historical_metadata_catalog
    value = historical_metadata_catalog()
    assert len(value['checks']) == 3496
    for row in value['checks']: row.pop('clarity_evaluation_contract', None)
    assert sha(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()) == '55e4ef383df3d4408654b95b46789264d024bb8eb4197ca926f37b7eb0d7a718'
    bridge._METADATA_TDE.reviewed_inputs(ROOT)


@pytest.mark.parametrize('mutation', ['identity', 'code', 'defaults', 'kwdefaults', 'globals', 'snapshot'])
def test_collect_code_defaults_global_and_identity_tamper_rejected(mutation, monkeypatch):
    bridge.verify_metadata_only(ROOT)
    function = azure.collect
    if mutation in ('identity', 'globals'):
        namespace = dict(vars(azure)) if mutation == 'globals' else vars(azure)
        replacement = types.FunctionType(function.__code__, namespace, function.__name__, function.__defaults__)
        replacement.__kwdefaults__ = function.__kwdefaults__
        monkeypatch.setattr(azure, 'collect', replacement)
        if mutation == 'globals': monkeypatch.setattr(bridge, '_METADATA_COLLECT', replacement)
    elif mutation == 'snapshot': monkeypatch.setattr(bridge, '_METADATA_COLLECT', lambda *a: None)
    elif mutation == 'code': monkeypatch.setattr(function, '__code__', function.__code__.replace(co_consts=function.__code__.co_consts + ('changed',)))
    elif mutation == 'defaults': monkeypatch.setattr(function, '__defaults__', ('changed',))
    else: monkeypatch.setattr(function, '__kwdefaults__', {'transport': 'changed'})
    with pytest.raises(RuntimeError): bridge.verify_metadata_only(ROOT)


@pytest.mark.parametrize('mutation', ['identity', 'bases', 'doc', 'init', 'module', 'qualname', 'extra', 'snapshot', 'weakref_snapshot'])
def test_sentinel_class_behavior_and_identity_tamper_rejected(mutation, monkeypatch):
    bridge.verify_metadata_only(ROOT)
    cls = azure._MetadataOnlyCollection
    if mutation == 'module':
        before = cls.__module__
        first = vars(cls).get('__firstlineno__')
        try:
            cls.__module__ = 'changed'
            with pytest.raises(RuntimeError): bridge.verify_metadata_only(ROOT)
        finally:
            cls.__module__ = before
            if first is not None: cls.__firstlineno__ = first
        bridge.verify_metadata_only(ROOT)
        return
    if mutation in ('bases', 'qualname'):
        attribute = '__bases__' if mutation == 'bases' else '__qualname__'
        before = getattr(cls, attribute)
        try:
            setattr(cls, attribute, (RuntimeError,) if mutation == 'bases' else 'Changed')
            with pytest.raises(RuntimeError): bridge.verify_metadata_only(ROOT)
        finally:
            setattr(cls, attribute, before)
        bridge.verify_metadata_only(ROOT)
        return
    if mutation == 'identity': monkeypatch.setattr(azure, '_MetadataOnlyCollection', type(cls.__name__, (Exception,), {'__module__': cls.__module__, '__doc__': cls.__doc__}))
    elif mutation == 'doc': monkeypatch.setattr(cls, '__doc__', 'changed')
    elif mutation == 'init': monkeypatch.setattr(cls, '__init__', lambda self: None)
    elif mutation == 'extra': monkeypatch.setattr(cls, 'injected', True, raising=False)
    elif mutation == 'snapshot': monkeypatch.setattr(bridge, '_METADATA_CLASS', Exception)
    else: monkeypatch.setattr(bridge, '_METADATA_WEAKREF', object())
    with pytest.raises(RuntimeError): bridge.verify_metadata_only(ROOT)


@pytest.mark.parametrize('mutation', ['helper_identity', 'helper_code', 'helper_set', 'helper_binding', 'noop_set', 'self_set'])
def test_new_helper_and_original_function_carriers_tamper_rejected(mutation, monkeypatch):
    bridge.verify_metadata_only(ROOT)
    helper = bridge._METADATA_TDE
    if mutation == 'helper_identity': monkeypatch.setattr(helper, '_lineage', lambda *a: None)
    elif mutation == 'helper_code': monkeypatch.setattr(helper._lineage, '__code__', helper._lineage.__code__.replace(co_consts=helper._lineage.__code__.co_consts + ('changed',)))
    elif mutation == 'helper_set': monkeypatch.setattr(helper, '_FUNCTIONS', {})
    elif mutation == 'helper_binding': monkeypatch.setattr(helper, 'azure', object())
    elif mutation == 'noop_set': monkeypatch.setattr(bridge, '_NOOP_FUNCTIONS', {})
    else: monkeypatch.setattr(bridge, '_FUNCTIONS', {})
    with pytest.raises(RuntimeError): bridge.verify_metadata_only(ROOT)


@pytest.fixture(scope='module')
def copied_package(tmp_path_factory):
    target = tmp_path_factory.mktemp('metadata-only-copied-source').resolve()
    for directory in ('peaso', 'bluepeass', 'risk_rules', 'tests', 'docs', 'scripts'):
        shutil.copytree(ROOT / directory, target / directory, ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
    for name in ('aws_permissions_cat.yaml', 'azure_permissions_cat.yaml', 'gcp_permissions_cat.yaml'): shutil.copy2(ROOT / name, target / name)
    return target


@pytest.mark.parametrize('relative', ['peaso/collectors/azure.py', 'peaso/checks/__init__.py', 'peaso/checks/azure_metadata_only_shared_successor_20261020.py', 'peaso/checks/azure_metadata_only_shared_successor_20261020.json', 'peaso/checks/azure_metadata_only_tde_admission_successor_20261020.py', 'peaso/checks/collector_noop_authorization_shared_successor_20261020.py', 'peaso/checks/collector_noop_authorization_shared_successor_20261020.json'])
def test_actual_warm_disk_tamper_rejected_with_no_reader_redirection(copied_package, relative):
    code = r'''
import pathlib,socket,sys
def blocked(*a,**k):raise AssertionError('No network in disk tamper proof')
for owner,names in ((socket,('create_connection','getaddrinfo')),(socket.socket,('connect','connect_ex','sendto'))):
 for name in names:setattr(owner,name,blocked)
from tests.shared_admission_epoch_compatibility_20261020 import active_shared
from peaso.private_secret_source_epoch_20261021 import AdmissionError
bridge = active_shared()
from peaso import source_attestation_mode
source_attestation_mode.ALWAYS=True  # warm calls below must re-prove, as in tests and the image build
root=pathlib.Path.cwd();path=root/sys.argv[1];raw=path.read_bytes()
try:
 bridge.reviewed_delta(root);bridge.verify_metadata_only(root)
 path.write_bytes(raw+b'\n# unreviewed source mutation\n')
 try:bridge.reviewed_delta(root);bridge.verify_metadata_only(root)
 except (RuntimeError, AdmissionError):print('rejected')
 else:raise AssertionError('Unreviewed disk mutation admitted')
finally:path.write_bytes(raw)
'''
    # The cold import runs the shipped first-use proofs ("once"); the warm calls above re-prove
    # every time. Inheriting conftest's repeat-every-proof mode for the import costs minutes.
    env = {key: value for key, value in os.environ.items() if key != 'PEASO_SOURCE_ATTESTATION'}
    env.update(PEASO_SOURCE_ATTESTATION='once', PYTHONPATH=str(copied_package), PYTHONDONTWRITEBYTECODE='1', AWS_EC2_METADATA_DISABLED='true', AWS_CONFIG_FILE='/nonexistent', AWS_SHARED_CREDENTIALS_FILE='/nonexistent')
    result = subprocess.run([sys.executable, '-B', '-c', code, relative], cwd=copied_package, env=env, text=True, capture_output=True, timeout=90)
    assert result.returncode == 0, result.stderr[-9000:]
    assert result.stdout.strip() == 'rejected'


def test_interpreter_supplied_class_attributes_are_exact_and_current():
    receipt = bridge.reviewed_delta(ROOT)
    cls = azure._MetadataOnlyCollection
    expected = {'__module__', '__doc__', '__weakref__'}
    if sys.version_info >= (3, 13):
        expected |= {'__firstlineno__', '__static_attributes__'}
        assert type(cls.__firstlineno__) is int
        assert cls.__firstlineno__ == receipt['portable_class_source']['firstlineno'] == 1820
        assert type(cls.__static_attributes__) is tuple and cls.__static_attributes__ == ()
    assert set(vars(cls)) == expected
    assert bridge.class_source_digest(cls, ROOT, receipt) == receipt['metadata_only_class']['source_sha256']


@pytest.mark.parametrize('mutation', ['first_wrong', 'first_bool', 'first_missing', 'static_nonempty', 'static_list', 'static_missing', 'extra'])
def test_interpreter_attributes_never_exempt_extra_or_wrong_values(mutation):
    bridge.verify_metadata_only(ROOT)
    cls = azure._MetadataOnlyCollection
    name = '__firstlineno__' if mutation.startswith('first') else '__static_attributes__' if mutation.startswith('static') else 'unreviewed'
    exists = name in vars(cls); old = vars(cls).get(name)
    try:
        if mutation.endswith('missing') and exists: delattr(cls, name)
        else: setattr(cls, name, False if mutation == 'first_bool' else 0 if mutation.startswith('first') else [] if mutation == 'static_list' else ('changed',) if mutation.startswith('static') else True)
        with pytest.raises(RuntimeError): bridge.verify_metadata_only(ROOT)
    finally:
        if exists: setattr(cls, name, old)
        elif name in vars(cls): delattr(cls, name)
    bridge.verify_metadata_only(ROOT)


SAMPLE = 'def selected(value=1, *, flag=True):\n    return value if flag else 0\n'
@pytest.fixture
def signed_source_artifacts(tmp_path, monkeypatch):
    path = tmp_path.resolve() / 'sample.py'; path.write_text(SAMPLE)
    module = types.ModuleType('portable_metadata_signed_sample'); module.__file__ = str(path)
    monkeypatch.setitem(sys.modules, module.__name__, module)
    exec(compile(SAMPLE, str(path), 'exec'), vars(module))
    fn = module.selected
    row = dict(path='sample.py', qualname='selected', sha256=sha(SAMPLE.encode()), defaults=[1], kwdefaults={'flag': True})
    compiler = bridge._transaction_compiler(); token = bridge._COMPILED_TRANSACTION.set(compiler)
    try:
        bridge._check_function(fn, row, path.parent, {})
        assert bridge.native_artifacts(fn, path)[2] == SAMPLE
        yield fn, row, path, compiler
    finally:
        bridge._COMPILED_TRANSACTION.reset(token); linecache.cache.pop(str(path), None)


@pytest.mark.parametrize('mutation', ['fragment', 'digest', 'code', 'signature'])
def test_signed_compiled_source_fragment_poisoning_is_rejected(signed_source_artifacts, mutation):
    fn, row, path, compiler = signed_source_artifacts
    cache = inspect.getclosurevars(compiler).nonlocals['cache']
    key = next(iter(cache)); rows = list(cache[key]); record, signature = rows[0]; record = list(record)
    if mutation == 'fragment': record[3] = SAMPLE.replace('else 0', 'else 999')
    elif mutation == 'digest': record[1] = '0' * 64
    elif mutation == 'code': record[2] = record[2].replace(co_consts=(None, 999))
    else: signature = b'changed'
    rows[0] = (tuple(record), signature); cache[key] = tuple(rows)
    with pytest.raises(RuntimeError, match='compiled cache artifact changed'): bridge.native_artifacts(fn, path)


@pytest.mark.parametrize('mutation', ['source', 'linecache', 'code', 'defaults', 'kwdefaults', 'globals', 'location'])
def test_warm_signed_artifacts_recheck_every_live_input(signed_source_artifacts, mutation):
    fn, row, path, compiler = signed_source_artifacts
    if mutation == 'source': path.write_text(SAMPLE.replace('else 0', 'else 8'))
    elif mutation == 'linecache': linecache.cache[str(path)][2][-1] = '    return value if flag else 8\n'
    elif mutation == 'code': fn.__code__ = fn.__code__.replace(co_consts=(None, 8))
    elif mutation == 'defaults': fn.__defaults__ = (2,)
    elif mutation == 'kwdefaults': fn.__kwdefaults__ = {'flag': False}
    elif mutation == 'globals':
        fn = types.FunctionType(fn.__code__, dict(fn.__globals__), fn.__name__, fn.__defaults__); fn.__kwdefaults__ = {'flag': True}
    else: fn.__code__ = fn.__code__.replace(co_filename=str(path.parent / 'foreign.py'))
    with pytest.raises((RuntimeError, OSError, IndexError)): bridge._check_function(fn, row, path.parent, {})


def test_source_text_reuse_still_rejects_later_default_changes(signed_source_artifacts, monkeypatch):
    fn, row, path, compiler = signed_source_artifacts
    before = inspect.getclosurevars(compiler).nonlocals['source_cache'].copy()
    original = inspect.getsource
    def forbidden(value):
        if value is fn: raise AssertionError('Repeated source inspection escaped signed artifact reuse')
        return original(value)
    monkeypatch.setattr(inspect, 'getsource', forbidden)
    assert bridge.native_artifacts(fn, path)[2] == SAMPLE
    bridge._check_function(fn, row, path.parent, {})
    assert inspect.getclosurevars(compiler).nonlocals['source_cache'] == before
    fn.__defaults__ = (99,)
    with pytest.raises(RuntimeError): bridge._check_function(fn, row, path.parent, {})


@pytest.mark.parametrize('mutation', ['identity', 'code', 'defaults', 'kwdefaults'])
def test_current_tde_still_rejects_live_selected_callable_changes(mutation, monkeypatch):
    bridge._METADATA_TDE.reviewed_inputs(ROOT)
    fn = azure._selected
    if mutation == 'identity': monkeypatch.setattr(azure, '_selected', types.FunctionType(fn.__code__, vars(azure), fn.__name__, fn.__defaults__))
    elif mutation == 'code': monkeypatch.setattr(fn, '__code__', fn.__code__.replace(co_consts=fn.__code__.co_consts + ('changed',)))
    elif mutation == 'defaults': monkeypatch.setattr(fn, '__defaults__', ('changed',))
    else: monkeypatch.setattr(fn, '__kwdefaults__', {'changed': True})
    with pytest.raises(RuntimeError): bridge._METADATA_TDE.reviewed_inputs(ROOT)
