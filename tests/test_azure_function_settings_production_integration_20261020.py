"""Actual Function declaration production hooks, additive provenance and privacy."""
from copy import deepcopy
from tests.case_state_contract_20261020 import case_copy, case_state
import gzip
import hashlib
import inspect
import io
import json
import logging
from pathlib import Path
import socket
from types import SimpleNamespace
import pytest
from fastapi import HTTPException
from peaso import checks,engine,secret_scanning
from peaso.checks.fixtures import CASES
from peaso.checks import azure_function_settings_runtime_admission_20261020 as admission
from peaso.checks import azure_function_settings_runtime_consumer_20261020 as consumer
from peaso.rawv2_private_source_successor_20261021 import install_admission
from peaso.collectors import azure,azure_function_settings_declarations_20261020 as source
from peaso.collectors import azure_function_settings_runtime_hooks_20261020 as hooks
from peaso.server.validation import OPTIONS,validate_connector
from peaso.snapshot import make_snapshot,seal
from tests import test_azure_function_settings_declarations_20261020 as native


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def blocked(*a,**kw):pytest.fail('No live socket/DNS/auth, generic content cache or detectors')
    for n in('connect','connect_ex','sendto'):monkeypatch.setattr(socket.socket,n,blocked)
    for n in('getaddrinfo','gethostbyname','gethostbyname_ex','create_connection'):monkeypatch.setattr(socket,n,blocked)
    monkeypatch.setattr(azure,'credential_for',blocked);monkeypatch.setattr(azure.AzureTransport,'request',blocked)
    # RawV2 admission re-verifies the live secret_scanning functions and their
    # from-import cohorts on every collect, so detectors are blocked at the
    # process boundary every Kingfisher/TruffleHog run must cross.
    monkeypatch.setattr(secret_scanning.subprocess,'Popen',blocked)


def view(snapshot):
    own,=[c for c in snapshot['collections']if c['type']==source.KIND]
    return own['items'][0],{'context':{'provider':'azure','scope':native.SCOPE,'metadata':snapshot['metadata']},'collections':{source.KIND:[own]}}


def _receipt_cases():
    receipt=json.loads((Path(admission.__file__).parent/admission.RECEIPT).read_text())
    return json.loads(Path(receipt['fixture']['path']).read_text())


def test_actual_registered_successor_identity_cases_and_idempotent_install():
    # The historical installer stays strict on the drifted Function proposal
    # sources; production admits them only through the RawV2 successor.
    with pytest.raises((RuntimeError,ValueError)):admission.reviewed_inputs()
    install_admission('azure_function_settings_runtime_admission_20261020')
    cases=_receipt_cases()
    declarations=[(d,d['evaluate'])for d in consumer.PROPOSALS]
    assert len(declarations)==2
    for d,function in declarations:
        current,=[c for c in checks.CHECKS if c.id==d['id']]
        assert inspect.unwrap(current.evaluate)is function and function.__module__==consumer.__name__
        assert CASES[d['id']]==cases[d['id']]
        assert cases[d['id']]['pass']['_provenance']['credential_context_id']==cases[d['id']]['pass_index']['context']['metadata']['credential_context_id']
    before=tuple(checks.CHECKS);saved=case_copy(CASES);saved_state=case_state(CASES);install_admission('azure_function_settings_runtime_admission_20261020')
    assert tuple(checks.CHECKS)==before and case_state(CASES)==saved_state


@pytest.mark.parametrize('branch',['pass','fail','unknown'])
def test_actual_public_three_native_branches_and_parent_context(monkeypatch,branch):
    values={'APPLICATIONINSIGHTS_CONNECTION_STRING':'declared','FUNCTIONS_EXTENSION_VERSION':'~4'}if branch=='pass'else{}
    def fault(op,data):return native.Response({'error':native.CANARY},403)if branch=='unknown'and op=='settings'else data
    snapshot,found,wire,credential=native.capture(monkeypatch,settings=native.native_settings(values),fault=fault)
    assert {f['status']for f in found.values()}=={branch.upper()}
    item,index=view(snapshot);meta=index['context']['metadata'];own=index['collections'][source.KIND][0]
    assert item['_provenance']['capture']==meta['credential_context_id']==meta[source.KIND+'_capture']
    assert item['_provenance']['customer_context_id']==own['_provenance']['customer_context_id']==meta['customer_context_id']
    assert len(wire.calls)==3 and native.CANARY not in json.dumps([snapshot,found])


@pytest.mark.parametrize('function',[consumer.telemetry,consumer.runtime],ids=['telemetry','runtime'])
@pytest.mark.parametrize('fault',['missing_parent_credential','missing_parent_customer','foreign_parent_credential','foreign_parent_customer','foreign_parent_tenant','missing_parent_tenant','unverified_parent_tenant','wrong_parent_binding','missing_item_credential','missing_item_customer','foreign_item_credential','foreign_item_customer','missing_collection_credential','missing_collection_customer','foreign_collection_credential','foreign_collection_customer','extra_item_provenance','extra_collection_provenance','foreign_item_scope','foreign_item_tenant','foreign_item_capture','foreign_marker_capture','foreign_marker_scope','missing_source_capture','unknown_native_payload','duplicate_item'])
def test_current_native_successor_rejects_missing_foreign_conflicting_and_unknown_context(monkeypatch,function,fault):
    snapshot,_,_,_=native.capture(monkeypatch);item,index=view(snapshot);snapshot=deepcopy(snapshot);item,index=view(snapshot)
    meta=index['context']['metadata'];own=index['collections'][source.KIND][0];p=item['_provenance'];cp=own['_provenance'];marker=item[source.MARKER]
    if fault=='missing_parent_credential':meta.pop('credential_context_id')
    if fault=='missing_parent_customer':meta.pop('customer_context_id')
    if fault=='foreign_parent_credential':meta['credential_context_id']='f'*32
    if fault=='foreign_parent_customer':meta['customer_context_id']='scan-local:foreign'
    if fault=='foreign_parent_tenant':meta['tenant_id']=native.FOREIGN
    if fault=='missing_parent_tenant':meta.pop('tenant_id')
    if fault=='unverified_parent_tenant':meta['tenant_verified']=False
    if fault=='wrong_parent_binding':meta['context_binding']='foreign'
    if fault=='missing_item_credential':p.pop('credential_context_id')
    if fault=='missing_item_customer':p.pop('customer_context_id')
    if fault=='foreign_item_credential':p['credential_context_id']='f'*32
    if fault=='foreign_item_customer':p['customer_context_id']='scan-local:foreign'
    if fault=='missing_collection_credential':cp.pop('credential_context_id')
    if fault=='missing_collection_customer':cp.pop('customer_context_id')
    if fault=='foreign_collection_credential':cp['credential_context_id']='f'*32
    if fault=='foreign_collection_customer':cp['customer_context_id']='scan-local:foreign'
    if fault=='extra_item_provenance':p['synthetic_coverage']=True
    if fault=='extra_collection_provenance':cp['synthetic_coverage']=True
    if fault=='foreign_item_scope':p['scope']='/subscriptions/'+native.FOREIGN
    if fault=='foreign_item_tenant':p['tenant_id']=native.FOREIGN
    if fault=='foreign_item_capture':p['capture']='f'*32
    if fault=='foreign_marker_capture':marker['capture']='f'*32
    if fault=='foreign_marker_scope':marker['scope']='/subscriptions/'+native.FOREIGN
    if fault=='missing_source_capture':meta.pop(source.KIND+'_capture')
    if fault=='unknown_native_payload':item['settings']={'raw':native.CANARY}
    if fault=='duplicate_item':own['items'].append(deepcopy(item))
    before=deepcopy((item,index));assert function(item,index)[0]=='UNKNOWN'
    assert (item,index)==before # Unknown never strips or repairs the supplied data.


@pytest.mark.parametrize('function',[consumer.telemetry,consumer.runtime],ids=['telemetry','runtime'])
def test_validated_additive_projection_never_mutates_inputs(monkeypatch,function):
    snapshot,_,_,_=native.capture(monkeypatch);item,index=view(snapshot);before=deepcopy((item,index))
    assert function(item,index)[0]=='PASS'and(item,index)==before
    projected,context=consumer._bound(item,index)
    assert set(projected['_provenance'])=={'scope','capture','tenant_id','source_requests'}
    assert set(item['_provenance'])==set(projected['_provenance'])|{'credential_context_id','customer_context_id'}
    assert projected[source.MARKER]==item[source.MARKER]


@pytest.mark.parametrize('auth_mode',['local','cognito'])
def test_hosted_selected_scope_shape_and_shared_optional_default(auth_mode):
    options={'content_secret_scans':True,source.OPTION:[native.SITE]};auth={'method':'token','tenant_id':native.TENANT,'arm_token':'offline'}
    validate_connector('azure',auth,options,SimpleNamespace(auth_mode=auth_mode),scopes=[native.SCOPE])
    assert source.OPTION in OPTIONS and source.KIND in engine.BULK_STREAM_TYPES['azure']and source.KIND not in azure._selected({},None)


@pytest.mark.parametrize('fault',['slot','url','foreign','duplicate','too_many','empty','wrong_provider','missing_scope'])
def test_public_and_hosted_invalid_selectors_rejected_before_credentials(fault):
    targets=[native.SITE];scope=[native.SCOPE];provider='azure'
    if fault=='slot':targets=[native.SITE+'/slots/staging']
    if fault=='url':targets=['https://evil.invalid/'+native.CANARY]
    if fault=='foreign':targets=[native.SITE.replace(native.SUB,native.FOREIGN)]
    if fault=='duplicate':targets*=2
    if fault=='too_many':targets=[native.SITE+str(i)for i in range(5)]
    if fault=='empty':targets=[]
    if fault=='wrong_provider':provider='aws'
    if fault=='missing_scope':scope=[]
    options={'content_secret_scans':True,source.OPTION:targets}
    with pytest.raises(ValueError):engine.collect_snapshot({'connector':{'provider':provider,'scopes':scope,'auth':{},'options':options},'checks':[source.RUNTIME]if provider=='azure'else[]})
    with pytest.raises(HTTPException)as e:validate_connector(provider,{},options,SimpleNamespace(auth_mode='local'),scopes=scope)
    assert e.value.status_code==422 and native.CANARY not in str(e.value.detail)


@pytest.mark.parametrize('mode',['default','category','framework','kind_spoof','inventory'])
def test_exact_named_check_only_gate_ignores_bulk_and_private_spoof(monkeypatch,mode):
    import peaso.collectors as collectors
    options={'content_secret_scans':True,source.OPTION:[native.SITE],'_azure_function_settings_checks':list(source.CHECKS),'_content_secret_scan_kinds':[source.KIND]}
    if mode=='inventory':options['inventories']=[source.KIND]
    request={'connector':{'provider':'azure','scopes':[native.SCOPE],'auth':{},'options':options}}
    if mode=='category':request['categories']=['hardening']
    if mode=='framework':request['frameworks']=[checks.HACKTRICKS]
    def planner(connector,requirements=None):
        assert not connector['options']['_azure_function_settings_checks']
        if mode in('default','kind_spoof'):assert source.KIND not in requirements
        return make_snapshot('azure',[native.SCOPE],[],metadata={})
    monkeypatch.setattr(collectors,'collect_live',planner)
    assert engine.collect_snapshot(request)['collections']==[]


def test_actual_inventory_private_check_spoof_never_acquires_tokens(monkeypatch):
    class Credential:
        def get_token(self,*a,**kw):pytest.fail('Unnamed Function setting read')
        def close(self):pass
    monkeypatch.setattr(azure,'credential_for',lambda auth:Credential())
    options={'content_secret_scans':True,source.OPTION:[native.SITE],'inventories':[source.KIND],'_azure_function_settings_checks':list(source.CHECKS),'retries':0}
    snapshot=engine.collect_snapshot({'connector':{'provider':'azure','scopes':[native.SCOPE],'auth':{},'options':options}})
    assert snapshot['collections']==[]
    assert {f['status']for f in engine.evaluate_snapshot(snapshot,checks=list(source.CHECKS))['findings']}=={'UNKNOWN'}


def test_production_read_callable_drift_stops_before_sdk_credentials(monkeypatch):
    monkeypatch.setattr(source,'_read',lambda *a: {'synthetic':True})
    # RawV2 admission now rejects the relocated callable before the proposal's
    # own digest check; either guard stops before any SDK credential is built.
    with pytest.raises((RuntimeError,ValueError),match='Function proposal callable location changed|function_proposal_source_mismatch'):
        engine.collect_snapshot({'connector':{'provider':'azure','scopes':[native.SCOPE],'auth':{},'options':{'content_secret_scans':True,source.OPTION:[native.SITE]}},'checks':list(source.CHECKS)})


def test_parent_owned_credential_rejection_is_private_unresolved_not_empty(monkeypatch,caplog):
    caplog.set_level(logging.DEBUG)
    def reject(auth):logging.getLogger('azure.identity').debug(native.CANARY);raise RuntimeError(native.CANARY)
    monkeypatch.setattr(azure,'credential_for',reject)
    snapshot=engine.collect_snapshot({'connector':{'provider':'azure','scopes':[native.SCOPE],'auth':{},'options':{'content_secret_scans':True,source.OPTION:[native.SITE],'retries':0}},'checks':list(source.CHECKS)})
    findings=engine.evaluate_snapshot(snapshot,checks=list(source.CHECKS))['findings']
    assert {f['status']for f in findings}=={'UNKNOWN'}
    assert native.CANARY not in json.dumps([snapshot,findings])+caplog.text


@pytest.mark.parametrize('budget',['wire','cumulative'])
def test_actual_production_transfer_budgets_do_not_relax_native_source_guards(monkeypatch,budget):
    def fault(op,payload):
        if budget=='wire':return native.Response(payload,headers={'Content-Length':str(source.MAX_WIRE+1)})
        # Adversarial valid-JSON HTTP body sizes test only byte accounting,
        # never positive provider semantics or functional configuration proof.
        return {**payload,'adversarial_wire_padding':'x'*(source.MAX_WIRE-2048)}
    targets=[native.SITE+str(i)for i in range(4)]if budget=='cumulative'else[native.SITE]
    snapshot,found,wire,_=native.capture(monkeypatch,targets=targets,fault=fault)
    assert {f['status']for f in engine.evaluate_snapshot(snapshot,checks=list(source.CHECKS))['findings']}=={'UNKNOWN'}
    assert all(r.closed for r in wire.responses)


def test_functions_metadata_precedes_every_existing_ledger_union_and_cleanup(monkeypatch):
    # A found value queued by readers, distinct from the private settings
    # canary that capture() still requires never to leave native projection.
    FOUND='found-secret-value-visible-to-owner'
    original=azure._Reader.metadata;readers=[]
    def metadata(reader):
        readers.append(reader);reader.configuration_secret_redactions={FOUND}
        for attr in('ml_asset_secret_metadata','databricks_notebook_secret_metadata','ml_command_job_secret_metadata','log_sample_secret_metadata','declaration_secret_metadata','configuration_secret_metadata','storage_source_secret_metadata','devops_selected_metadata','app_setting_secret_metadata','acr_image_secret_metadata','function_declaration_metadata'):
            ledger=getattr(reader,attr,{})
            ledger.update({attr+'_union_alias':FOUND});setattr(reader,attr,ledger)
        return {**original(reader),'late_alias':FOUND}
    monkeypatch.setattr(azure._Reader,'metadata',metadata)
    snapshot,found,_,_=native.capture(monkeypatch)
    assert {f['status']for f in found.values()}=={'PASS'}
    # Found values stay visible to the tenant: the function ledger joins the
    # union before cleanup, and only the ephemeral redaction sets are cleared.
    assert snapshot['metadata']['function_declaration_metadata_union_alias']==FOUND
    assert snapshot['metadata']['configuration_secret_metadata_union_alias']==FOUND
    assert readers and not readers[-1].configuration_secret_redactions
    assert FOUND not in json.dumps(readers[-1].function_declaration_metadata)


def test_predecessor_sources_and_test_rosters_are_byte_preserved():
    archive=Path('docs/check-review/azure-function-settings-pre-integration-20261020.json.gz')
    saved=json.loads(gzip.decompress(archive.read_bytes()))['files']
    prior=json.loads(Path('docs/check-review/azure-function-settings-declarations-native-review-20261020.json').read_text())
    original='tests/test_azure_function_settings_declarations_20261020.py'
    assert original in saved and 'Only a test-local Check overlay'in saved[original]
    receipt=json.loads(Path('peaso/checks/azure_function_settings_runtime_admission_20261020.json').read_text())
    assert receipt['predecessor_runtime']['archive_sha256']==hashlib.sha256(archive.read_bytes()).hexdigest()
    with pytest.raises((RuntimeError,ValueError)):admission.reviewed_inputs()
    install_admission('azure_function_settings_runtime_admission_20261020')
    assert len([c for c in checks.CHECKS if c.id in {d['id']for d in consumer.PROPOSALS}])==2


@pytest.mark.parametrize('denied',[False,True])
def test_real_stdlib_http_framing_debug_privacy_without_auth_or_settings_retention(monkeypatch,denied,capsys,caplog):
    caplog.set_level(logging.DEBUG);monkeypatch.setattr(source.http.client.HTTPConnection,'debuglevel',1)
    def fault(op,payload):return native.Response({'error':native.CANARY},403)if denied and op=='settings'else payload
    wire=native.Wire([native.SITE],fault=fault);https=source.http.client.HTTPSConnection
    class MemorySocket:
        def __init__(self,response):self.stream=io.BytesIO(('HTTP/1.1 '+str(response.status)+' OK\r\n'+''.join(k+': '+v+'\r\n'for k,v in response.headers.items())+'\r\n').encode()+response.raw)
        def sendall(self,data):assert isinstance(data,bytes)
        def makefile(self,mode):assert mode=='rb';return self.stream
        def settimeout(self,n):assert 0<n<=10
        def close(self):pass
    class NativeHTTPS(https):
        def __init__(self,host,timeout):source.http.client.HTTPConnection.__init__(self,host,timeout=timeout)
        def connect(self):self.sock=MemorySocket(self.driver.response)
        def request(self,method,path,body=None,headers=None,**kw):
            self.driver=wire.connection(self.host,self.timeout);self.driver.set_debuglevel(self.debuglevel);self.driver.request(method,path,body,headers)
            return super().request(method,path,body,headers,**kw)
        def close(self):
            if hasattr(self,'driver'):self.driver.response.close();self.driver.close()
            super().close()
    credential=native.Credential();monkeypatch.setattr(azure,'credential_for',lambda auth:credential)
    monkeypatch.setattr(source.http.client,'HTTPSConnection',NativeHTTPS)
    snapshot=engine.collect_snapshot({'connector':{'provider':'azure','scopes':[native.SCOPE],'auth':{'tenant_id':native.TENANT},'options':{'content_secret_scans':True,source.OPTION:[native.SITE],'retries':0}},'checks':list(source.CHECKS)})
    findings=engine.evaluate_snapshot(snapshot,checks=list(source.CHECKS))['findings']
    assert {f['status']for f in findings}=={'UNKNOWN'if denied else'PASS'}
    out=capsys.readouterr();text=json.dumps([snapshot,findings])+out.out+out.err+caplog.text
    assert native.CANARY not in text and 'Bearer ey'not in text and 'InstrumentationKey='not in text
    assert len(wire.calls)==3 and all(r.closed for r in wire.responses)


def test_selected_private_site_name_is_only_an_opaque_location(monkeypatch):
    snapshot,found,wire,_=native.capture(monkeypatch,targets=[native.SITE.rsplit('/',1)[0]+'/'+native.CANARY])
    assert {f['status']for f in found.values()}=={'PASS'}
    assert native.CANARY not in json.dumps([snapshot,found])
