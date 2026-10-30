"""Exact atomic declaration admission and actual production public-engine hooks."""
from copy import deepcopy
from tests.case_state_contract_20261020 import case_copy, case_state
import json
from pathlib import Path
import socket
from types import SimpleNamespace
import pytest
from fastapi import HTTPException
from peaso import checks,engine,secret_scanning as scanning
from peaso.checks.fixtures import CASES
from peaso import rawv2_private_source_successor_20261021 as current_admission
from peaso.checks import azure_selected_declaration_secret_review_20261020 as consumer
from peaso.collectors import azure
from peaso.collectors import azure_selected_declaration_secret_indicators as source
from peaso.server.validation import OPTIONS,validate_connector
from peaso.snapshot import make_snapshot
from tests import test_azure_selected_declaration_secret_review_20261020 as native
from peaso.checks import azure_declaration_secrets_admission_20261020 as admission


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def blocked(*args,**kwargs):pytest.fail('Live IO/authentication forbidden')
    for name in ('connect','connect_ex','sendto'):monkeypatch.setattr(socket.socket,name,blocked)
    for name in ('getaddrinfo','gethostbyname','gethostbyname_ex','create_connection'):monkeypatch.setattr(socket,name,blocked)
    monkeypatch.setattr(azure,'credential_for',blocked);scanning._RESULTS.clear()
    yield
    scanning._RESULTS.clear()


@pytest.mark.parametrize('surface',['app_configuration','adf_pipeline','synapse'])
@pytest.mark.parametrize('branch',['pass','fail','unknown'])
def test_actual_production_native_three_branches_with_real_pinned_engines(monkeypatch,surface,branch):
    final='key_bound'if surface=='app_configuration'else'pipeline'if surface=='synapse'else'declaration'
    def fault(s,op,response):return native.Response({'error':native.TOKEN},403)if branch=='unknown'and op==final else response
    snapshot,rows,trace=native.collect(monkeypatch,surface,native.TOKEN if branch=='fail'else'mode=ready',real=True,fault=fault)
    assert {r['status']for r in rows}=={branch.upper()}
    assert native.TOKEN not in json.dumps([snapshot,rows])and native.AUTH not in json.dumps(snapshot)
    assert all(r.closed for r in trace.responses)


@pytest.mark.parametrize('profile',source.PROFILES)
@pytest.mark.parametrize('auth_mode',['local','cognito'])
def test_public_hosted_validation_and_help_exact_native_profiles(profile,auth_mode):
    surface='adf_pipeline'if profile=='data_factory'else profile
    option=source.PROFILES[profile]['option'];options={'content_secret_scans':True,option:[native.target(surface)]}
    auth={'method':'token','tenant_id':native.TENANT,'arm_token':'offline-validator-token'}
    validate_connector('azure',auth,options,SimpleNamespace(auth_mode=auth_mode),scopes=[native.SCOPE])
    with pytest.raises(HTTPException)as error:validate_connector('aws',{},options,SimpleNamespace(auth_mode=auth_mode),scopes=[native.SCOPE])
    assert error.value.status_code==422
    help=Path('frontend/src/ConnectorFieldHelp.tsx').read_text()
    assert option in OPTIONS and option+':'in help
    assert source.PROFILES[profile]['kind']in engine.BULK_STREAM_TYPES['azure']
    assert source.PROFILES[profile]['kind']not in azure._selected({},None)


def test_atomic_mid_install_failure_rolls_back_all_three(monkeypatch):
    ids={p['check']for p in source.PROFILES.values()};original_checks=list(checks.CHECKS);original_cases=case_copy(CASES);cases_state=case_state(CASES)
    checks.CHECKS[:]=[c for c in checks.CHECKS if c.id not in ids]
    for ident in ids:CASES.pop(ident,None)
    before=tuple(checks.CHECKS);cases=case_copy(CASES);cases_state=case_state(CASES);register=checks.register;count=0
    def fail_second(*args,**kwargs):
        nonlocal count
        count+=1
        if count==2:raise RuntimeError('injected transaction failure')
        return register(*args,**kwargs)
    monkeypatch.setattr(checks,'register',fail_second)
    try:
        with pytest.raises(RuntimeError,match='transaction'):current_admission.install_admission('azure_declaration_secrets_admission_20261020')
        assert tuple(checks.CHECKS)==before and case_state(CASES)==cases_state
    finally:
        checks.CHECKS[:]=original_checks;CASES.clear();CASES.update(original_cases)


@pytest.mark.parametrize('profile',source.PROFILES)
@pytest.mark.parametrize('failure',['missing','foreign','extra','wrong_provider'])
def test_public_selector_rejected_before_authentication(monkeypatch,profile,failure):
    surface='adf_pipeline'if profile=='data_factory'else profile;p=source.PROFILES[profile];target=native.target(surface)
    options={'content_secret_scans':True,p['option']:[target]}
    if failure=='missing':options.pop(p['option'])
    if failure=='foreign':target['resource_id']=target['resource_id'].replace(native.SCOPE,native.FOREIGN)
    if failure=='extra':target['endpoint']='https://evil.invalid/'+native.TOKEN
    req={'connector':{'provider':'aws'if failure=='wrong_provider'else'azure','scopes':[native.SCOPE],'auth':{},'options':options},'checks':[]if failure=='wrong_provider'else[p['check']]}
    with pytest.raises(ValueError):engine.collect_snapshot(req)


@pytest.mark.parametrize('mode',['default','category','spoof','inventories'])
def test_unnamed_bulk_and_internal_kind_spoof_cannot_authorize_content(monkeypatch,mode):
    import peaso.collectors as collectors
    p=source.PROFILES['app_configuration'];options={'content_secret_scans':True,p['option']:[native.target('app_configuration')]}
    if mode in('spoof','inventories'):options['_content_secret_scan_kinds']=list(source.KINDS)
    if mode=='inventories':options['inventories']=list(source.KINDS)
    request={'connector':{'provider':'azure','scopes':[native.SCOPE],'auth':{},'options':options}}
    if mode=='category':request['categories']=['hardening']
    def observe(connector,requirements=None):
        if mode in ('default','spoof'):assert not(set(source.KINDS)&set(requirements))
        assert not(set(source.KINDS)&set(connector['options']['_content_secret_scan_kinds']))
        return make_snapshot('azure',[native.SCOPE],[],metadata={})
    monkeypatch.setattr(collectors,'collect_live',observe)
    snapshot=engine.collect_snapshot(request)
    assert snapshot['collections']==[]


def test_combined_selector_limit_enforced_by_public_and_hosted_validation():
    options={'content_secret_scans':True}
    for profile,p in source.PROFILES.items():
        surface='adf_pipeline'if profile=='data_factory'else profile;targets=[]
        for i in range(3):
            t=native.target(surface)
            if profile=='app_configuration':t['key']=str(i)
            else:t['resource_id']+=str(i)
            targets.append(t)
        options[p['option']]=targets
    with pytest.raises(ValueError):engine.collect_snapshot({'connector':{'provider':'azure','scopes':[native.SCOPE],'auth':{},'options':options},'checks':[p['check']for p in source.PROFILES.values()]})
    with pytest.raises(HTTPException)as error:validate_connector('azure',{},options,SimpleNamespace(auth_mode='local'),scopes=[native.SCOPE])
    assert error.value.status_code==422


@pytest.mark.parametrize('target',['function','helper'])
def test_typed_function_and_reachable_helper_tampering_rejected(monkeypatch,target):
    before=tuple(checks.CHECKS);cases=case_copy(CASES);cases_state=case_state(CASES)
    def changed(item,index):return 'PASS',{}
    if target=='function':monkeypatch.setitem(consumer.EVALUATORS,'app_configuration',changed)
    else:monkeypatch.setattr(consumer,'_evaluate',lambda profile,item,index:('PASS',{}))
    with pytest.raises(RuntimeError):current_admission.install_admission('azure_declaration_secrets_admission_20261020')
    assert tuple(checks.CHECKS)==before and case_state(CASES)==cases_state


def test_existing_fixture_collision_cannot_partially_readmit():
    ident=source.PROFILES['synapse']['check'];saved=deepcopy(CASES[ident]);before=tuple(checks.CHECKS)
    CASES[ident]={'unexpected':'collision'}
    try:
        with pytest.raises(RuntimeError,match='collision'):current_admission.install_admission('azure_declaration_secrets_admission_20261020')
        assert tuple(checks.CHECKS)==before and CASES[ident]=={'unexpected':'collision'}
    finally:CASES[ident]=saved


def test_explicit_inventories_and_spoofed_kinds_do_not_read_without_named_check(monkeypatch):
    class Credential:
        def get_token(self,*args,**kwargs):pytest.fail('unnamed content cannot acquire a token')
        def close(self):pass
    monkeypatch.setattr(azure,'credential_for',lambda auth:Credential())
    options={'content_secret_scans':True,'inventories':list(source.KINDS),'_content_secret_scan_kinds':list(source.KINDS),
        source.PROFILES['app_configuration']['option']:[native.target('app_configuration')],'retries':0}
    snapshot=engine.collect_snapshot({'connector':{'provider':'azure','scopes':[native.SCOPE],
        'auth':{'method':'client-secret','tenant_id':native.TENANT,'client_id':native.TENANT,'client_secret':'offline'},'options':options}})
    assert snapshot['collections']==[]
    assert all(snapshot['metadata'][p['kind']+'_authorized']is False for p in source.PROFILES.values())
    result=engine.evaluate_snapshot(snapshot,checks=[p['check']for p in source.PROFILES.values()])
    assert {r['status']for r in result['findings']}=={'UNKNOWN'}
