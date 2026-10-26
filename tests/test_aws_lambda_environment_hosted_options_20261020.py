"""Explicit function environments never expand account, Region or version scope."""
from types import SimpleNamespace
import pytest
from fastapi import HTTPException
from peaso.server.validation import OPTIONS,validate_connector
SCOPE='123456789012/us-east-1'
ARN='arn:aws:lambda:us-east-1:123456789012:function:review'
def validate(targets,scopes=None,provider='aws'):
    validate_connector(provider,{}, {'selected_aws_lambda_functions':targets,'content_secret_scans':True},
                       SimpleNamespace(auth_mode='local'),scopes=[SCOPE]if scopes is None else scopes)
def test_exact_unqualified_scope_target_needs_no_credential_read():
    assert 'selected_aws_lambda_functions'in OPTIONS
    validate([ARN])
@pytest.mark.parametrize('fault',['empty','none','string','duplicate','foreign_account','foreign_region','version','alias','wildcard','url','many','missing_scopes','account_only','wrong_provider'])
def test_invalid_optional_environment_selection_fails_before_authentication(fault):
    targets,scopes,provider=[ARN],[SCOPE],'aws'
    if fault=='empty':targets=[]
    elif fault=='none':targets=None
    elif fault=='string':targets=ARN
    elif fault=='duplicate':targets*=2
    elif fault=='foreign_account':targets=[ARN.replace('123456789012','210987654321')]
    elif fault=='foreign_region':targets=[ARN.replace('us-east-1','eu-west-1')]
    elif fault in ('version','alias'):targets=[ARN+(':'+('1'if fault=='version'else'live'))]
    elif fault=='wildcard':targets=[ARN+'*']
    elif fault=='url':targets=['https://lambda.amazonaws.com/'+ARN]
    elif fault=='many':targets=[ARN+str(i)for i in range(9)]
    elif fault=='missing_scopes':scopes=[]
    elif fault=='account_only':scopes=['123456789012']
    elif fault=='wrong_provider':provider='gcp'
    with pytest.raises(HTTPException)as error:validate(targets,scopes,provider)
    assert error.value.status_code==422


def test_cold_hosted_lambda_preflight_never_imports_collectors():
    """The worker's 30s lease must not be spent loading the native catalog."""
    import os
    from pathlib import Path
    import subprocess
    import sys
    program = '''
import importlib.abc, sys
from types import SimpleNamespace
class NoNativeImports(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == 'peaso.collectors' or fullname.startswith('peaso.collectors.') or fullname == 'peaso.checks':
            raise AssertionError('Native import during pure hosted preflight: ' + fullname)
sys.meta_path.insert(0, NoNativeImports())
from peaso.server.validation import validate_connector
validate_connector('aws', {'method': 'access_keys', 'aws_access_key_id': 'testing',
    'aws_secret_access_key': 'testing'}, {'content_secret_scans': True,
    'selected_aws_lambda_functions': ['arn:aws:lambda:us-east-1:123456789012:function:review']},
    SimpleNamespace(auth_mode='cognito'), scopes=['123456789012/us-east-1'])
assert 'peaso.collectors' not in sys.modules and 'peaso.checks' not in sys.modules
print('pure hosted preflight passed')
'''
    root = Path(__file__).resolve().parents[1]
    result = subprocess.run([sys.executable, '-c', program], cwd=root,
                            env={**os.environ, 'PYTHONPATH': str(root)},
                            capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == 'pure hosted preflight passed'


def test_pure_lambda_selector_retains_exact_native_grammar():
    import ast
    from pathlib import Path
    root = Path(__file__).resolve().parents[1]
    native = ast.parse((root / 'peaso/collectors/aws_lambda_environment_secret_indicators.py').read_text())
    pure = ast.parse((root / 'peaso/server/content_selection_preflight_20261021.py').read_text())
    closure = next(n for n in pure.body if isinstance(n, ast.FunctionDef) and n.name == '_make_lambda_environment')
    names = {'Incomplete', 'enabled', 'parse', 'selected_targets'}
    defs = lambda nodes: {n.name: ast.dump(n, include_attributes=False) for n in nodes
                          if isinstance(n, (ast.FunctionDef, ast.ClassDef)) and n.name in names}
    assert defs(native.body) == defs(closure.body)
    constants = {'KIND', 'OPTION', 'MAX_TARGETS', 'MAX_SELECTED_SCOPES', 'ARN', 'SCOPE'}
    values = lambda nodes: {n.targets[0].id: ast.dump(n.value, include_attributes=False) for n in nodes
                            if isinstance(n, ast.Assign) and isinstance(n.targets[0], ast.Name)
                            and n.targets[0].id in constants}
    assert values(native.body) == values(closure.body)


# Automatic content selections are resolved only after native inventory.
import pytest
from peaso.collectors import aws
from peaso.collectors import aws_lambda_environment_secret_indicators as env
from peaso.collectors import aws_selected_configuration_secret_indicators as config

class ReachedDiscovery(Exception):
    pass

@pytest.fixture
def no_cloud(monkeypatch):
    def reached(connector):
        raise ReachedDiscovery
    monkeypatch.setattr(aws, '_selection', reached)
    def forbidden(*args, **kwargs):
        pytest.fail('Preflight must not contact AWS')
    monkeypatch.setattr(aws, '_session', forbidden)

@pytest.mark.parametrize('scopes', [[], ['123456789012'], ['us-east-2'], ['123456789012/us-east-2']])
@pytest.mark.parametrize('kinds', [[env.KIND], [config.KIND], [env.KIND, config.KIND]])
def test_automatic_content_reaches_inventory_planning(no_cloud, scopes, kinds):
    with pytest.raises(ReachedDiscovery):
        aws.collect({'auth': {}, 'scopes': scopes, 'options': {
            'content_secret_scans': True, '_content_secret_scan_kinds': kinds}})

@pytest.mark.parametrize('module', [env, config])
@pytest.mark.parametrize('targets', [None, [], 'not-a-list', ['invalid-target']])
def test_invalid_explicit_selection_fails_before_discovery(no_cloud, module, targets):
    with pytest.raises(ValueError):
        aws.collect({'auth': {}, 'scopes': ['123456789012/us-east-2'], 'options': {
            'content_secret_scans': True, '_content_secret_scan_kinds': [module.KIND],
            module.OPTION: targets}})

@pytest.mark.parametrize('flag', [1, 'true', None, []])
def test_invalid_flag_is_rejected_before_discovery(no_cloud, flag):
    with pytest.raises(ValueError):
        aws.collect({'auth': {}, 'scopes': ['123456789012'], 'options': {
            'content_secret_scans': flag, '_content_secret_scan_kinds': [env.KIND]}})
