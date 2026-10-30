"""Server-only ACR request validation and runtime selector parity."""
from copy import deepcopy
from pathlib import Path
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
PYTHON = sys.executable
SCOPE = '/subscriptions/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
TARGET = {'registry_id': SCOPE+'/resourceGroups/rg/providers/Microsoft.ContainerRegistry/registries/registry1',
          'repository': 'team/repo', 'digest': 'sha256:'+'a'*64}


@pytest.fixture
def static():
    from peaso.server import acr_image_selection_static_20261021 as module
    return module


@pytest.mark.parametrize('mutation', [
    lambda o,s: None,
    lambda o,s: o.update(image_vulnerability_scans=False),
    lambda o,s: o.update(content_secret_scans='irrelevant'),
    lambda o,s: o.update(selected_azure_acr_image_vulnerabilities=[]),
    lambda o,s: o.update(selected_azure_acr_image_vulnerabilities=[{**TARGET,'tag':'latest'}]),
    lambda o,s: o.update(selected_azure_acr_image_vulnerabilities=[{**TARGET,'digest':'sha256:'+'A'*64}]),
    lambda o,s: o.update(selected_azure_acr_image_vulnerabilities=[{**TARGET,'repository':'Team/repo'}]),
    lambda o,s: o.update(selected_azure_acr_image_vulnerabilities=[{**TARGET,'repository':'team//repo'}]),
    lambda o,s: o.update(selected_azure_acr_image_vulnerabilities=[{**TARGET,'registry_id':TARGET['registry_id'].replace('/resourceGroups/','/resourcegroups/')}]),
    lambda o,s: o.update(selected_azure_acr_image_vulnerabilities=[{'registryId':TARGET['registry_id'],'repository':'team/repo','digest':TARGET['digest']}]),
    lambda o,s: o.update(selected_azure_acr_image_vulnerabilities=[TARGET,TARGET]),
    lambda o,s: o.update(selected_azure_acr_image_vulnerabilities=[{**TARGET,'registry_id':TARGET['registry_id']+'/' }]),
    lambda o,s: o.update(image_vulnerability_scans=1),
    lambda o,s: s.clear(),
    lambda o,s: s.append(s[0].upper()),
    lambda o,s: s.__setitem__(0,'/subscriptions/bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'),
    lambda o,s: o.pop('selected_azure_acr_image_vulnerabilities'),
    lambda o,s: o.update(image_vulnerability_scans=False,selected_azure_acr_image_vulnerabilities=[TARGET]),
])
def test_static_runtime_exact_parity(static,proposal,mutation):
    runtime=proposal[2]
    options={runtime.ENABLE:True,runtime.OPTION:[deepcopy(TARGET)]}
    scopes=[SCOPE]
    mutation(options,scopes)
    outcomes=[]
    for validator in (static.selected_targets,runtime.selected_targets):
        try:outcomes.append(('ok',validator(options,scopes)))
        except ValueError:outcomes.append(('error',None))
    assert outcomes[0]==outcomes[1]


def test_disabled_and_no_selection_zero_runtime_requirement(static,proposal):
    runtime=proposal[2]
    for value in ({},{'image_vulnerability_scans':False},
                  {'content_secret_scans':True},{'content_secret_scans':'ignored'}):
        assert static.selected_targets(value,[])==runtime.selected_targets(value,[])==[]
    with pytest.raises(ValueError):static.selected_targets({'image_vulnerability_scans':True},[SCOPE])


def test_fresh_process_actual_hosted_validation_never_imports_runtime():
    code=r'''
import importlib.abc,sys
from types import SimpleNamespace
from fastapi import HTTPException
sys.path.insert(0,sys.argv[1])
import peaso
blocked=('peaso.collectors','peaso.checks','peaso.engine','peaso.analysis')
class Block(importlib.abc.MetaPathFinder):
    def find_spec(self,fullname,path=None,target=None):
        if any(fullname==name or fullname.startswith(name+'.') for name in blocked):
            raise AssertionError('runtime import at API validation: '+fullname)
sys.meta_path.insert(0,Block())
import peaso.server
sys.modules.pop('peaso.server.validation',None)
from peaso.server.image_selection_options_20261021 import validate_image_options
from peaso.server.validation import validate_connector
import peaso.server.app as app
app.validate_connector=validate_connector
scope='/subscriptions/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
target={'registry_id':scope+'/resourceGroups/rg/providers/Microsoft.ContainerRegistry/registries/registry1',
        'repository':'team/repo','digest':'sha256:'+'a'*64}
selected={'image_vulnerability_scans':True,'selected_azure_acr_image_vulnerabilities':[target]}
auths=[{'method':'token','token':'x'}, {'method':'auto','arm_token':'x'},
       {'method':'client-secret','tenant_id':'t','client_id':'c','client_secret':'s'},
       {'method':'client-cert','tenant_id':'t','client_id':'c','certificate_data':'-----BEGIN CERTIFICATE-----'},
       {'method':'workload-identity','tenant_id':'t','client_id':'c','federated_token':'f'}]
for auth in auths:
    validate_image_options('azure',selected,[scope])
    validate_connector('azure',auth,selected,SimpleNamespace(auth_mode='cognito'),scopes=[scope])
    validate_connector('azure',auth,{'image_vulnerability_scans':False},SimpleNamespace(auth_mode='cognito'),scopes=[])
for options in ({'image_vulnerability_scans':True},
                {'image_vulnerability_scans':1,'selected_azure_acr_image_vulnerabilities':[target]},
                {'selected_azure_acr_image_vulnerabilities':[dict(target,tag='latest')]},
                {'image_vulnerability_scans':True,'selected_azure_acr_image_vulnerabilities':[dict(target,digest='sha256:'+'A'*64)]}):
    try:validate_connector('azure',auths[0],options,SimpleNamespace(auth_mode='cognito'),scopes=[scope])
    except HTTPException as exc:assert exc.status_code==422
    else:raise AssertionError('invalid selection accepted')
try:validate_connector('gcp',{'method':'token','token':'x'},
    {'selected_azure_acr_image_vulnerabilities':[target]},SimpleNamespace(auth_mode='cognito'),scopes=[scope])
except HTTPException as exc:assert exc.status_code==422
else:raise AssertionError('cross-provider selector accepted')
assert not any(any(name==prefix or name.startswith(prefix+'.') for prefix in blocked) for name in sys.modules)
print('5 Azure auth modes, negative selectors, disabled case: no runtime import')
'''
    result=subprocess.run([PYTHON,'-I','-c',code,str(ROOT)],capture_output=True,text=True,timeout=30)
    assert result.returncode==0,result.stdout+result.stderr
    assert 'no runtime import' in result.stdout
