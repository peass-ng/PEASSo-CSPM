"""Exact atomic two-control admission and actual Azure ML asset production hooks."""
from copy import deepcopy
from tests.case_state_contract_20261020 import case_copy, case_state
import json
import socket
from types import SimpleNamespace
import pytest
from fastapi import HTTPException
from peaso import checks,engine,secret_scanning as scanning
from peaso import rawv2_private_source_successor_20261021 as current_admission
from peaso.checks.fixtures import CASES
from peaso.checks import azure_ml_selected_asset_secret_review_20261020 as consumer
from peaso.collectors import azure,azure_ml_selected_asset_secret_indicators as source
from peaso.server.validation import OPTIONS,validate_connector
from peaso.snapshot import make_snapshot
from tests import test_azure_ml_selected_asset_secret_review_20261020 as native
from peaso.checks import azure_ml_asset_secrets_admission_20261020 as admission

IDS=tuple(p['check']for p in source.PROFILES.values())


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def blocked(*a,**kw):pytest.fail('Live auth/socket/DNS or generic cached content request forbidden')
    for n in('connect','connect_ex','sendto'):monkeypatch.setattr(socket.socket,n,blocked)
    for n in('getaddrinfo','gethostbyname','gethostbyname_ex','create_connection'):monkeypatch.setattr(socket,n,blocked)
    monkeypatch.setattr(azure,'credential_for',blocked);monkeypatch.setattr(azure.AzureTransport,'request',blocked)
    scanning._RESULTS.clear();yield;scanning._RESULTS.clear()


@pytest.mark.parametrize('profile',source.PROFILES)
@pytest.mark.parametrize('branch',['pass','fail','unknown'])
def test_actual_production_three_branches_and_current_registry_consumer(monkeypatch,profile,branch):
    def fault(op,r,t):return native.Response({'error':native.TOKEN},403)if branch=='unknown'and op=='asset_before'else r
    snapshot,rows,trace=native.collect(monkeypatch,profile,native.TOKEN if branch=='fail'else'mode=ready',real=True,fault=fault)
    assert {r['status']for r in rows}=={branch.upper()}
    assert len(trace.calls)==(3 if branch=='unknown'else len(source.operations(profile)))
    assert native.TOKEN not in json.dumps([snapshot,rows])and native.AUTH not in json.dumps(snapshot)
    native.capture(branch,profile,snapshot,rows,trace)


@pytest.mark.parametrize('profile',source.PROFILES)
@pytest.mark.parametrize('auth_mode',['local','cognito'])
def test_hosted_two_exact_selector_options_provider_binding_and_defaults(profile,auth_mode):
    p=source.PROFILES[profile];options={'content_secret_scans':True,p['option']:[native.target(profile)]}
    auth={'method':'token','tenant_id':native.TENANT,'arm_token':'offline-validator'}
    validate_connector('azure',auth,options,SimpleNamespace(auth_mode=auth_mode),scopes=[native.SCOPE])
    with pytest.raises(HTTPException)as error:validate_connector('aws',{},options,SimpleNamespace(auth_mode=auth_mode),scopes=[native.SCOPE])
    assert error.value.status_code==422
    assert p['option']in OPTIONS and p['kind']in engine.BULK_STREAM_TYPES['azure']and p['kind']not in azure._selected({},None)


@pytest.mark.parametrize('profile',source.PROFILES)
@pytest.mark.parametrize('failure',['empty','duplicate','foreign','extra','count','malformed','scope'])
def test_hosted_invalid_selection_nonsensitive_422(profile,failure):
    p=source.PROFILES[profile];t=native.target(profile);options={p['option']:[t]};scopes=[native.SCOPE]
    if failure=='empty':options[p['option']]=[]
    if failure=='duplicate':options[p['option']].append(deepcopy(t))
    if failure=='foreign':t['resource_id']=t['resource_id'].replace(native.SCOPE,native.FOREIGN)
    if failure=='extra':t['endpoint']=native.TOKEN
    if failure=='count':options[p['option']]=[{**t,'resource_id':t['resource_id']+str(i)}for i in range(5)]
    if failure=='malformed':t['resource_id']=native.TOKEN
    if failure=='scope':scopes=[]
    with pytest.raises(HTTPException)as error:validate_connector('azure',{},options,SimpleNamespace(auth_mode='local'),scopes=scopes)
    assert error.value.status_code==422 and native.TOKEN not in str(error.value.detail)


@pytest.mark.parametrize('failure',['combined_limit','one_named_missing','nonbool_flag'])
def test_two_profile_request_validation_before_credentials(failure):
    options={'content_secret_scans':True};ids=list(IDS)
    for name,p in source.PROFILES.items():options[p['option']]=[native.target(name)]
    if failure=='combined_limit':
        t=native.target('code');options[source.PROFILES['code']['option']]=[{**deepcopy(t),'resource_id':t['resource_id']+str(i)}for i in range(4)]
    if failure=='one_named_missing':options.pop(source.PROFILES['code']['option'])
    if failure=='nonbool_flag':options['content_secret_scans']='true'
    with pytest.raises(ValueError):engine.collect_snapshot({'connector':{'provider':'azure','scopes':[native.SCOPE],'auth':{},'options':options},'checks':ids})




def test_second_registration_failure_rolls_back_both_controls_and_new_cases(monkeypatch):
    original=list(checks.CHECKS);saved=case_copy(CASES);saved_state=case_state(CASES)
    checks.CHECKS[:]=[c for c in checks.CHECKS if c.id not in IDS]
    for ident in IDS:CASES.pop(ident,None)
    before=tuple(checks.CHECKS);cases=case_copy(CASES);cases_state=case_state(CASES);register=checks.register;calls=[]
    def inject(*a,**kw):
        decorator=register(*a,**kw)
        def changed(function):
            decorator(function);calls.append(a[0])
            if len(calls)==2:raise RuntimeError('injected second-control failure')
        return changed
    monkeypatch.setattr(checks,'register',inject)
    try:
        with pytest.raises(RuntimeError,match='second-control'):
            current_admission.install_admission('azure_ml_asset_secrets_admission_20261020')
        assert calls==list(IDS)and tuple(checks.CHECKS)==before and case_state(CASES)==cases_state
    finally:checks.CHECKS[:]=original;CASES.clear();CASES.update(saved)


def test_second_fixture_collision_is_checked_before_any_mutation():
    original=list(checks.CHECKS);saved=case_copy(CASES);saved_state=case_state(CASES)
    checks.CHECKS[:]=[c for c in checks.CHECKS if c.id not in IDS];CASES.pop(IDS[0],None);CASES[IDS[1]]={'collision':True}
    before=tuple(checks.CHECKS);cases=case_copy(CASES);cases_state=case_state(CASES)
    try:
        with pytest.raises(RuntimeError,match='collision'):
            current_admission.install_admission('azure_ml_asset_secrets_admission_20261020')
        assert tuple(checks.CHECKS)==before and case_state(CASES)==cases_state
    finally:checks.CHECKS[:]=original;CASES.clear();CASES.update(saved)


@pytest.mark.parametrize('profile',source.PROFILES)
@pytest.mark.parametrize('mode',['default','category','framework','spoof','inventories'])
def test_default_bulk_category_framework_and_private_kind_spoof_never_authorize_content(monkeypatch,profile,mode):
    import peaso.collectors as collectors
    p=source.PROFILES[profile];options={'content_secret_scans':True,p['option']:[native.target(profile)]}
    if mode in('spoof','inventories'):options['_content_secret_scan_kinds']=list(source.KINDS)
    if mode=='inventories':options['inventories']=[p['kind']]
    request={'connector':{'provider':'azure','scopes':[native.SCOPE],'auth':{},'options':options}}
    if mode=='category':request['categories']=['exposure']
    if mode=='framework':request['frameworks']=[checks.HACKTRICKS]
    def inspect_plan(connector,requirements=None):
        if mode in('default','spoof'):assert not(set(source.KINDS)&set(requirements))
        assert not(set(source.KINDS)&set(connector['options']['_content_secret_scan_kinds']))
        return make_snapshot('azure',[native.SCOPE],[],metadata={})
    monkeypatch.setattr(collectors,'collect_live',inspect_plan)
    assert engine.collect_snapshot(request)['collections']==[]


@pytest.mark.parametrize('profile',source.PROFILES)
def test_actual_explicit_inventory_with_forged_private_kind_has_no_token_or_content(monkeypatch,profile):
    p=source.PROFILES[profile]
    class Credential:
        def get_token(self,*a,**kw):pytest.fail('Unnamed selected content requested token')
        def close(self):pass
    monkeypatch.setattr(azure,'credential_for',lambda auth:Credential())
    options={'content_secret_scans':True,p['option']:[native.target(profile)],'inventories':[p['kind']],'_content_secret_scan_kinds':list(source.KINDS),'retries':0}
    snapshot=engine.collect_snapshot({'connector':{'provider':'azure','scopes':[native.SCOPE],
        'auth':{'method':'client-secret','tenant_id':native.TENANT,'client_id':native.TENANT,'client_secret':'offline'},'options':options}})
    assert snapshot['collections']==[]and snapshot['metadata'][p['kind']+'_authorized']is False
    assert {r['status']for r in engine.evaluate_snapshot(snapshot,checks=[p['check']])['findings']}=={'UNKNOWN'}


