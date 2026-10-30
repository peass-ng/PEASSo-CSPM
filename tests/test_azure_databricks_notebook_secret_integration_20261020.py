"""Exact single-control atomic admission and real public Databricks production hooks."""
from copy import deepcopy
import json
from pathlib import Path
import socket
from types import SimpleNamespace
import pytest
from fastapi import HTTPException
from peaso import checks,engine,secret_scanning as scanning
from peaso.checks.fixtures import CASES
from peaso import rawv2_private_source_successor_20261021 as current_admission
from peaso.checks import azure_databricks_notebook_secret_review_20261020 as consumer
from peaso.collectors import azure
from peaso.collectors import azure_databricks_notebook_secret_indicators as source
from peaso.server.validation import OPTIONS,validate_connector
from peaso.snapshot import make_snapshot
from tests import test_azure_databricks_notebook_secret_review_20261020 as native


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def blocked(*a,**kw):pytest.fail('Live network/auth or generic cached content request forbidden')
    for n in('connect','connect_ex','sendto'):monkeypatch.setattr(socket.socket,n,blocked)
    for n in('getaddrinfo','gethostbyname','gethostbyname_ex','create_connection'):monkeypatch.setattr(socket,n,blocked)
    monkeypatch.setattr(azure,'credential_for',blocked);monkeypatch.setattr(azure.AzureTransport,'request',blocked)
    scanning._RESULTS.clear();yield;scanning._RESULTS.clear()


@pytest.mark.parametrize('branch',['pass','fail','unknown'])
def test_native_public_production_three_branches_both_real_pinned_engines(monkeypatch,branch):
    def fault(op,response,rid):return native.Response({'error':native.TOKEN},403)if branch=='unknown'and op=='export'else response
    snapshot,rows,trace=native.collect(monkeypatch,native.TOKEN if branch=='fail'else'mode=ready',real=True,fault=fault)
    assert {r['status']for r in rows}=={branch.upper()}
    assert len(trace.calls)==(4 if branch=='unknown'else 5) and all(r.closed for r in trace.responses)
    assert native.TOKEN not in json.dumps([snapshot,rows])and native.AUTH not in json.dumps(snapshot)
    native.capture(branch,snapshot,rows,trace,real=branch!='unknown')


@pytest.mark.parametrize('auth_mode',['local','cognito'])
def test_hosted_exact_validator_and_help_default_exclusion(auth_mode):
    options={'content_secret_scans':True,source.OPTION:[native.target()]}
    auth={'method':'token','tenant_id':native.TENANT,'arm_token':'offline-validator'}
    validate_connector('azure',auth,options,SimpleNamespace(auth_mode=auth_mode),scopes=[native.SCOPE])
    with pytest.raises(HTTPException)as error:validate_connector('aws',{},options,SimpleNamespace(auth_mode=auth_mode),scopes=[native.SCOPE])
    assert error.value.status_code==422
    assert source.OPTION in OPTIONS and source.OPTION+':'in Path('frontend/src/ConnectorFieldHelp.tsx').read_text()
    assert source.KIND in engine.BULK_STREAM_TYPES['azure']and source.KIND not in azure._selected({},None)


@pytest.mark.parametrize('failure',['missing','empty','foreign','extra','too_many','scope_missing','malformed','wrong_provider'])
def test_public_invalid_selectors_stop_before_any_credentials(monkeypatch,failure):
    t=native.target();options={'content_secret_scans':True,source.OPTION:[t]};scopes=[native.SCOPE]
    if failure=='missing':options.pop(source.OPTION)
    if failure=='empty':options[source.OPTION]=[]
    if failure=='foreign':t['workspace_resource_id']=native.WORKSPACE.replace(native.SCOPE,native.FOREIGN)
    if failure=='extra':t['codeUri']='https://evil.invalid/'+native.TOKEN
    if failure=='too_many':options[source.OPTION]=[native.target(native.NOTEBOOK+str(i))for i in range(5)]
    if failure=='scope_missing':scopes=[]
    if failure=='malformed':t['workspace_resource_id']=native.TOKEN
    provider='aws'if failure=='wrong_provider'else'azure'
    req={'connector':{'provider':provider,'scopes':scopes,'auth':{},'options':options},'checks':[]if failure=='wrong_provider'else[source.CHECK]}
    with pytest.raises(ValueError):engine.collect_snapshot(req)


@pytest.mark.parametrize('failure',['empty','duplicate','foreign','extra','count','malformed'])
def test_hosted_invalid_selection_has_fixed_nonsensitive_error(failure):
    t=native.target();options={source.OPTION:[t]}
    if failure=='empty':options[source.OPTION]=[]
    if failure=='duplicate':options[source.OPTION].append(deepcopy(t))
    if failure=='foreign':t['workspace_resource_id']=native.WORKSPACE.replace(native.SCOPE,native.FOREIGN)
    if failure=='extra':t['endpoint']=native.TOKEN
    if failure=='count':options[source.OPTION]=[native.target(native.NOTEBOOK+str(i))for i in range(5)]
    if failure=='malformed':t['workspace_resource_id']=native.TOKEN
    with pytest.raises(HTTPException)as error:validate_connector('azure',{},options,SimpleNamespace(auth_mode='local'),scopes=[native.SCOPE])
    assert error.value.status_code==422 and native.TOKEN not in str(error.value.detail)


@pytest.mark.parametrize('target',['function','helper'])
def test_typed_consumer_and_reachable_helper_identity_guard(monkeypatch,target):
    before=tuple(checks.CHECKS);cases=deepcopy(CASES[source.CHECK])
    if target=='function':monkeypatch.setattr(consumer,'evaluate',lambda item,index:('PASS',{}))
    else:monkeypatch.setattr(consumer,'_evaluate',lambda item,index:('PASS',{}))
    with pytest.raises(RuntimeError):current_admission.install_admission('azure_databricks_notebook_secrets_admission_20261020')
    assert tuple(checks.CHECKS)==before and CASES[source.CHECK]==cases


def test_partial_registration_mutation_is_rolled_back_atomically(monkeypatch):
    original=list(checks.CHECKS);saved=deepcopy(CASES)
    checks.CHECKS[:]=[c for c in checks.CHECKS if c.id!=source.CHECK];CASES.pop(source.CHECK,None)
    before=tuple(checks.CHECKS);case_keys=set(CASES);register=checks.register
    def fail_after_install(*a,**kw):
        decorator=register(*a,**kw)
        def changed(function):decorator(function);raise RuntimeError('injected post-registration failure')
        return changed
    monkeypatch.setattr(checks,'register',fail_after_install)
    try:
        with pytest.raises(RuntimeError,match='post-registration'):
            current_admission.install_admission('azure_databricks_notebook_secrets_admission_20261020')
        assert tuple(checks.CHECKS)==before and set(CASES)==case_keys and source.CHECK not in CASES
    finally:checks.CHECKS[:]=original;CASES.clear();CASES.update(saved)


def test_existing_fixture_collision_cannot_be_silently_replaced():
    saved=deepcopy(CASES[source.CHECK]);before=tuple(checks.CHECKS);CASES[source.CHECK]={'collision':True}
    try:
        with pytest.raises(RuntimeError,match='collision'):
            current_admission.install_admission('azure_databricks_notebook_secrets_admission_20261020')
        assert tuple(checks.CHECKS)==before and CASES[source.CHECK]=={'collision':True}
    finally:CASES[source.CHECK]=saved


@pytest.mark.parametrize('mode',['default','category','spoof','inventories'])
def test_bulk_category_and_internal_spoof_do_not_authorize_content(monkeypatch,mode):
    import peaso.collectors as collectors
    options={'content_secret_scans':True,source.OPTION:[native.target()]}
    if mode in('spoof','inventories'):options['_content_secret_scan_kinds']=[source.KIND]
    if mode=='inventories':options['inventories']=[source.KIND]
    request={'connector':{'provider':'azure','scopes':[native.SCOPE],'auth':{},'options':options}}
    if mode=='category':request['categories']=['exposure']
    def observe(connector,requirements=None):
        if mode in('default','spoof'):assert source.KIND not in requirements
        assert source.KIND not in connector['options']['_content_secret_scan_kinds']
        return make_snapshot('azure',[native.SCOPE],[],metadata={})
    monkeypatch.setattr(collectors,'collect_live',observe)
    assert engine.collect_snapshot(request)['collections']==[]


def test_actual_explicit_inventory_with_spoofed_private_kind_never_reads_unnamed_content(monkeypatch):
    class Credential:
        def get_token(self,*a,**kw):pytest.fail('Unnamed content attempted token acquisition')
        def close(self):pass
    monkeypatch.setattr(azure,'credential_for',lambda auth:Credential())
    options={'content_secret_scans':True,source.OPTION:[native.target()],'inventories':[source.KIND],'_content_secret_scan_kinds':[source.KIND],'retries':0}
    snapshot=engine.collect_snapshot({'connector':{'provider':'azure','scopes':[native.SCOPE],
        'auth':{'method':'client-secret','tenant_id':native.TENANT,'client_id':native.TENANT,'client_secret':'offline'},'options':options}})
    assert snapshot['collections']==[]and snapshot['metadata'][source.KIND+'_authorized']is False
    assert {r['status']for r in engine.evaluate_snapshot(snapshot,checks=[source.CHECK])['findings']}=={'UNKNOWN'}


def test_new_hit_scrubs_all_old_ledgers_and_late_metadata_before_cleanup(monkeypatch):
    def late(reader,snapshot):
        snapshot['metadata']['late']=native.TOKEN
        for attr in('ml_command_job_secret_metadata','log_sample_secret_metadata','declaration_secret_metadata','configuration_secret_metadata','storage_source_secret_metadata','devops_selected_metadata','app_setting_secret_metadata','acr_image_secret_metadata'):
            setattr(reader,attr,{attr+'_late':native.TOKEN})
    snapshot,rows,trace=native.collect(monkeypatch,native.TOKEN,late=late,real=True)
    assert {r['status']for r in rows}=={'FAIL'}
    assert native.TOKEN in json.dumps([snapshot,rows])and not trace.readers[0].configuration_secret_redactions


