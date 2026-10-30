"""Actual registered Azure selected-content hooks, admission and hosted contract."""
from copy import deepcopy
import json
from pathlib import Path
import socket
from types import SimpleNamespace
import pytest
from fastapi import HTTPException
from peaso import checks,engine,secret_scanning as scanning
from peaso.collectors import azure
# The 2026-10-20 receipt is historical for today's reviewed selected sources;
# the registered installer is the current RawV2 successor of the same receipt.
from peaso import rawv2_private_source_successor_20261021 as current_admission
from peaso.checks.fixtures import CASES
from peaso.server.validation import validate_connector,OPTIONS
from tests import test_azure_app_settings_secret_review_20261020 as app
from tests import test_azure_selected_configuration_secret_review_20261020 as arm
from tests import test_azure_selected_storage_secret_review_20261020 as storage
from tests import test_azure_devops_selected_content_secret_review_20261020 as devops
from tests.shared_admission_epoch_compatibility_20261020 import snapshot_cases


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def blocked(*a,**kw):pytest.fail('No sockets/DNS/default credentials')
    for n in ('connect','connect_ex','sendto'):monkeypatch.setattr(socket.socket,n,blocked)
    for n in ('create_connection','getaddrinfo','gethostbyname','gethostbyname_ex'):monkeypatch.setattr(socket,n,blocked)
    monkeypatch.setattr(azure,'credential_for',blocked);scanning._RESULTS.clear()
    yield
    scanning._RESULTS.clear()


@pytest.mark.parametrize('profile',['arm','storage','devops'])
@pytest.mark.parametrize('state',['pass','fail','unknown'])
def test_real_registered_public_engine_native_branches(monkeypatch,profile,state):
    if profile=='arm':
        def fault(t,content,response):return arm.Response(b'{}',403) if state=='unknown' else response
        snapshot,rows,_=arm.collect(monkeypatch,literal=arm.TOKEN if state=='fail' else 'mode=ready',real=True,fault=fault)
    elif profile=='storage':
        def fault(t,op,response):return storage.Response(b'error',403) if state=='unknown' and op=='content' else response
        snapshot,rows,_=storage.collect(monkeypatch,raw=('TOKEN='+storage.TOKEN if state=='fail' else 'mode=ready').encode(),real=True,fault=fault)
    else:
        # Convert the reviewed SDK/HTTP driver to the public collect_snapshot
        # boundary while preserving its native transport and current real hooks.
        original=azure.collect
        def public(connector,requirements=None,*,transport=None):
            class NativeTransport:
                def __new__(cls,auth):return transport
            monkeypatch.setattr(azure,'AzureTransport',NativeTransport)
            monkeypatch.setattr(azure,'AzureTransportExposure',NativeTransport)
            monkeypatch.setattr(azure,'collect',original)
            request={'connector':deepcopy(connector),'checks':[devops.source.CHECK]}
            if connector['options'].get('content_secret_scans') is False:request['connector']['options']['content_secret_scans']=False
            return engine.collect_snapshot(request)
        monkeypatch.setattr(azure,'collect',public)
        snapshot,rows,_=devops.collect(monkeypatch,hit=state=='fail',real=True,fault=('item','denied') if state=='unknown' else None)
    assert {r['status']for r in rows}=={state.upper()}


@pytest.mark.parametrize('profile',['arm','storage','devops'])
@pytest.mark.parametrize('auth_mode',['local','cognito'])
def test_hosted_selector_accepts_exact_native_shape_and_rejects_foreign_provider(profile,auth_mode):
    if profile=='arm':request=arm.request([arm.target('aci_literals')])
    elif profile=='storage':request=storage.request([storage.target()])
    else:request={'connector':devops.connector([devops.target()])}
    connector=request['connector'];options=connector['options'];auth=connector['auth']
    # Public hosted input never includes trusted internal gate options.
    options.pop('_content_secret_scan_kinds',None)
    options.pop('retries',None)  # native drivers disable retries; hosted uses its supported default
    validate_connector('azure',auth,options,SimpleNamespace(auth_mode=auth_mode),scopes=connector['scopes'])
    with pytest.raises(HTTPException)as error:validate_connector('aws',{},options,SimpleNamespace(auth_mode=auth_mode),scopes=connector['scopes'])
    assert error.value.status_code==422


def test_three_selector_help_and_default_exclusion_are_explicit():
    help=Path('frontend/src/ConnectorFieldHelp.tsx').read_text()
    for source in (arm.source,storage.source,devops.source):
        assert source.OPTION in OPTIONS and source.OPTION+':' in help
        assert source.KIND in azure.TYPES and source.KIND in engine.BULK_STREAM_TYPES['azure']
        assert source.KIND not in azure._selected({},None)
    assert 'backup semantics' in help and 'definition_revision' in help and 'automation_variable' in help


def test_atomic_rollback_after_second_registration_failure(monkeypatch):
    _,cases,_=current_admission._azure_reviewed_inputs();prior=tuple(checks.CHECKS);saved=snapshot_cases(CASES)
    try:
        checks.CHECKS[:]=[c for c in checks.CHECKS if c.id not in cases]
        for ident in cases:CASES.pop(ident)
        before=tuple(checks.CHECKS);before_cases=snapshot_cases(CASES);original=checks.register;count=0
        def failing(*args,**kwargs):
            nonlocal count
            count+=1
            if count==2:raise RuntimeError('injected registration failure')
            return original(*args,**kwargs)
        monkeypatch.setattr(checks,'register',failing)
        with pytest.raises(RuntimeError,match='injected'):current_admission.install_selected_azure()
        assert tuple(checks.CHECKS)==before and CASES==before_cases
    finally:checks.CHECKS[:]=prior;CASES.clear();CASES.update(saved)


class NativeMetadataPatch:
    """Route an independently selected NSG through the actual native collector."""
    def __init__(self,patch):self.patch=patch
    def setattr(self,obj,name,value,*args,**kwargs):
        if obj is azure and name in ('AzureTransport','AzureTransportExposure'):
            original=value
            class Transport(original):
                def request(self,url,**kw):
                    resource=app.SCOPE+'/resourceGroups/review/providers/Microsoft.Network/networkSecurityGroups/'+app.TOKEN
                    native={'id':resource,'name':app.TOKEN,'type':'Microsoft.Network/networkSecurityGroups','location':'eastus','properties':{'provisioningState':'Succeeded','securityRules':[],'defaultSecurityRules':[]}}
                    if url=='https://management.azure.com'+app.SCOPE+'/providers/Microsoft.Network/networkSecurityGroups?api-version=2023-09-01':return {'value':[native]}
                    if url=='https://management.azure.com'+resource+'?api-version=2023-09-01':return native
                    raise AssertionError('Unexpected native NSG operation')
            value=Transport
        return self.patch.setattr(obj,name,value,*args,**kwargs)


def test_older_appsettings_match_does_not_survive_unrelated_native_nsg_identity(monkeypatch):
    req=app.request([app.SITE]);req['connector']['options']['inventories']=['nsg',app.source.KIND]
    snapshot,trace=app.capture(NativeMetadataPatch(monkeypatch),req=req,real=True,data={app.SITE:app.native(app.SITE,{'TOKEN':app.TOKEN})})
    assert {r['status'] for r in app.findings(snapshot)}=={'FAIL'}
    assert any(c['type']=='nsg' and c['items']for c in snapshot['collections'])
    # Found secrets are shown in clear text in the collected native content.
    assert app.TOKEN in json.dumps(snapshot)


@pytest.mark.parametrize('predecessor',[False,True])
def test_acr_completed_native_hit_and_unrelated_nsg_metadata_successor(monkeypatch,predecessor):
    from tests import test_azure_acr_image_secret_review_20261020 as acr
    if predecessor:
        # Execute only the trusted retained predecessor callback function to
        # reproduce its native counterexample; never scanned source content.
        import ast,gzip
        path=Path('tests/fixtures/azure_acr_image_secret_indicators_pre_union_20261020.py.gz')
        raw=gzip.decompress(path.read_bytes());node=next(n for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef) and n.name=='_scan_bytes')
        namespace=dict(acr.source.__dict__)
        exec(compile(ast.Module(body=[node],type_ignores=[]),str(path),'exec'),namespace)
        monkeypatch.setattr(acr.source,'_scan_bytes',namespace['_scan_bytes'])
    img=acr.image(positive='config');req=acr.request([img.target]);req['connector']['options']['inventories']=['nsg',acr.source.KIND]
    snapshot,trace=acr.capture(NativeMetadataPatch(monkeypatch),img=img,req=req,real=True)
    assert {r['status']for r in acr.findings(snapshot)}=={'FAIL'}
    assert any(c['type']=='nsg' and c['items']for c in snapshot['collections'])
    # Found secrets are shown in clear text for the current and predecessor scan.
    assert acr.TOKEN in json.dumps(snapshot)


def test_union_scrub_includes_later_metadata_reinsertions_and_clears_all_sets():
    from peaso.collectors import azure_selected_secret_integration_20261020 as joined
    from peaso.snapshot import make_snapshot
    secret=app.TOKEN
    reader=SimpleNamespace(collections=[],configuration_secret_redactions={secret},storage_source_secret_redactions=set(),
        devops_selected_redactions=set(),app_setting_secret_redactions=set(),acr_image_secret_redactions=set(),
        configuration_secret_metadata={},storage_source_secret_metadata={},devops_selected_metadata={'late_native_name':secret})
    snapshot=make_snapshot('azure',[app.SCOPE],[],metadata={})
    result=joined.final_snapshot(reader,snapshot)
    assert secret in json.dumps([result,reader.collections])
    assert all(not getattr(reader,n)for n in ('configuration_secret_redactions','storage_source_secret_redactions','devops_selected_redactions','app_setting_secret_redactions','acr_image_secret_redactions'))


def test_old_reader_redaction_budget_overflow_withholds_mixed_projections(monkeypatch):
    from peaso.collectors import azure_selected_secret_integration_20261020 as joined
    from peaso.collectors import azure_selected_storage_secret_indicators as source
    from peaso.snapshot import make_snapshot
    reader=SimpleNamespace(collections=[],app_setting_secret_redactions=set())
    monkeypatch.setattr(joined,'MAX_UNION_VALUES',0)
    joined.remember(reader,'app_setting_secret_redactions',{app.TOKEN})
    assert reader.storage_source_secret_overflow and not reader.app_setting_secret_redactions
    result=joined.final_snapshot(reader,make_snapshot('azure',[app.SCOPE],[],metadata={'native_name':app.TOKEN}))
    assert app.TOKEN not in json.dumps(result) and result['metadata'][source.KIND+'_redaction_complete'] is False


def test_exception_finalizer_clears_transient_union_sets(monkeypatch):
    from peaso.collectors import azure_selected_secret_integration_20261020 as joined
    from peaso.snapshot import make_snapshot
    names=('configuration_secret_redactions','storage_source_secret_redactions','devops_selected_redactions','app_setting_secret_redactions','acr_image_secret_redactions')
    reader=SimpleNamespace(collections=[],**{n:{app.TOKEN}for n in names})
    def unavailable(*args):raise RuntimeError('injected finalizer unavailable')
    monkeypatch.setattr(joined.devops,'final_snapshot',unavailable)
    with pytest.raises(RuntimeError,match='injected finalizer'):joined.final_snapshot(reader,make_snapshot('azure',[app.SCOPE],[],metadata={}))
    assert all(not getattr(reader,n)for n in names)


@pytest.mark.parametrize('profile',['arm','storage','devops'])
@pytest.mark.parametrize('failure',['empty','foreign','extra'])
def test_public_invalid_selection_stops_before_authentication(monkeypatch,profile,failure):
    if profile=='arm':request=arm.request([arm.target('aci_literals')]);source=arm.source
    elif profile=='storage':request=storage.request([storage.target()]);source=storage.source
    else:request={'connector':devops.connector([devops.target()]),'checks':[devops.source.CHECK]};source=devops.source
    targets=request['connector']['options'][source.OPTION]
    if failure=='empty':targets.clear()
    elif failure=='extra':targets[0]['unexpected_url']='https://untrusted.invalid'
    elif profile=='devops':targets[0]['scope']='/subscriptions/'+app.OTHER.rsplit('/',1)[-1]
    else:targets[0]['resource_id']=targets[0]['resource_id'].replace(arm.SCOPE,app.OTHER)
    def no_auth(*args,**kwargs):pytest.fail('Invalid selection reached authentication')
    monkeypatch.setattr(azure,'AzureTransport',no_auth)
    monkeypatch.setattr(azure,'AzureTransportExposure',no_auth)
    with pytest.raises(ValueError):engine.collect_snapshot(request)


@pytest.mark.parametrize('explicit_inventory',[False,True])
def test_bulk_or_unnamed_selection_never_authorizes_content(monkeypatch,explicit_inventory):
    from peaso import collectors
    from peaso.snapshot import make_snapshot
    sources=(arm.source,storage.source,devops.source);observed=[]
    def stop_before_io(connector,requirements):
        assert connector['options']['_content_secret_scan_kinds']==[]
        if not explicit_inventory:assert all(s.KIND not in requirements for s in sources)
        observed.append(True)
        return make_snapshot('azure',[app.SCOPE],[],metadata={})
    monkeypatch.setattr(collectors,'collect_live',stop_before_io)
    connector={'provider':'azure','scopes':[app.SCOPE],'auth':{'method':'token','tenant_id':app.TENANT,'arm_token':'offline'},'options':{'content_secret_scans':True}}
    if explicit_inventory:connector['options']['inventories']=[s.KIND for s in sources]
    engine.collect_snapshot({'connector':connector})
    assert observed
