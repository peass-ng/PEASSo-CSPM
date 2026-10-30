"""Optional native Fabric certificate metadata never retrieves a secret value."""
import base64
import copy
from datetime import datetime,timezone
import json
import pytest
from peaso.collectors import azure,azure_disclosure_native as native
from peaso.privesc.effective_permissions.azure_disclosure_effects import CONTRACT
from peaso.snapshot import make_snapshot
from test_peaso_privesc_azure_disclosures_v7 import ENTRIES,case,run

OID='11111111-2222-3333-4444-555555555555'
TENANT='aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
ENTRY=next(e for e in ENTRIES if e['id']==native.TECHNIQUE)
BINDING={'credential_context_id':'scan-credential-opaque','customer_context_id':'scan-customer-opaque'}


def replace(value):
    if isinstance(value,dict):return{k:replace(v)for k,v in value.items()}
    if isinstance(value,list):return[replace(v)for v in value]
    if isinstance(value,str):return OID if value=='u-alice'else TENANT if value=='t'else value.replace('/tenants/t','/tenants/'+TENANT)
    return value


def token(audience,oid=OID,tenant=TENANT,issuer=None):
    payload={'oid':oid,'tid':tenant,'iss':issuer or'https://sts.windows.net/'+tenant+'/', 'aud':audience}
    return 'header.'+base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')+'.provider-validates-this-signature'


class Transport:
    def __init__(self,responses,mode='good'):
        self.responses=responses;self.mode=mode;self.calls=[];self.disclosure_accepted_subjects={};self.verified_tenant=TENANT;self.tenant=TENANT
    def token(self,audience):return token(audience,oid='99999999-2222-3333-4444-555555555555'if self.mode=='vault_identity_mismatch'and audience==native.VAULT else OID)
    def close(self):self.closed=True
    def allow_vault(self,origin):assert origin=='https://test.vault.azure.net'
    def request(self,url,*,body=None,audience=native.ARM,capture_subject=False):
        self.calls.append(url)
        assert '/secrets/'not in url or'/versions?'in url # never Secrets_Get
        if self.mode=='denied':raise azure.AzureReadError('denied',403)
        response=copy.deepcopy(self.responses[url])
        if capture_subject and self.mode!='no_native_acceptance':self.disclosure_accepted_subjects[audience]=native.accepted_subject(self.token(audience),audience)
        return response


def setup(mode='good'):
    snap,fact,metadata=case(ENTRY);snap=replace(snap);fact=replace(fact);metadata=replace(metadata)
    snap['collections']=[c for c in snap['collections']if not c['type'].startswith('azure_disclosure')and c['type']!='azure_privesc_challenge_evidence']
    for c in snap['collections']:
        if c.get('error')is None:c.pop('error',None)
    snap['metadata'].update(BINDING,tenant_verified=True,context_binding='scan_local',tenant_id=TENANT)
    link=metadata['CertificateLink'];cluster=link['ClusterId'];vault=link['VaultId'];certificate=link['CertificateVersionId'];secret=link['SecretVersionId']
    for env in snap['collections']:
        if env['type']=='resource_graph':
            for row in env['items']:
                if row['id']==cluster:row.get('properties',{}).pop('certificate',None)
                if row['id']==vault:row['properties']['enableRbacAuthorization']=mode!='access_policy_vault'
    origin='https://test.vault.azure.net';cid=certificate.rsplit('/',1)[0]
    cert={'id':certificate,'sid':secret,'x5t':base64.urlsafe_b64encode(bytes.fromhex('ab'*20)).decode().rstrip('='),
          'attributes':{'enabled':True},'policy':{'key_props':{'exportable':True}},'cer':'PUBLIC-CERTIFICATE-OMITTED'}
    cluster_response={'id':cluster,'type':'Microsoft.ServiceFabric/clusters','properties':{'certificate':{'thumbprint':'ab'*20}}}
    versions={'value':[{'id':secret,'attributes':{'enabled':True}}]}
    if mode=='thumbprint_mismatch':cluster_response['properties']['certificate']['thumbprint']='cd'*20
    if mode=='non_exportable':cert['policy']['key_props']['exportable']=False
    if mode=='foreign_sid':cert['sid']='https://foreign.vault.azure.net/secrets/client-cert/v1'
    if mode=='secret_disabled':versions['value'][0]['attributes']['enabled']=False
    if mode=='secret_missing':versions['value']=[]
    if mode=='secret_expired':versions['value'][0]['attributes']['exp']=1
    if mode=='certificate_disabled':cert['attributes']['enabled']=False
    responses={native.ARM+cluster+'?api-version=2021-06-01':cluster_response,
      origin+'/certificates?api-version='+native.VERSION:{'value':[{'id':cid}]},
      cid+'?api-version='+native.VERSION:cert,
      certificate+'?api-version='+native.VERSION:cert,
      origin+'/secrets/client-cert/versions?api-version='+native.VERSION:versions}
    if mode=='versions_partial':versions['nextLink']=origin+'/secrets/client-cert/versions?api-version='+native.VERSION+'&page=2'
    transport=Transport(responses,mode);reader=azure._Reader({'concurrency':1,'retries':0,**({'max_pages':1}if mode=='versions_partial'else{})});reader.collections=copy.deepcopy(snap['collections'])
    return snap,reader,transport


def collect(mode='good'):
    snap,reader,transport=setup(mode)
    scopes=snap['scopes'];native.collect(reader,transport,scopes,{'native_disclosure_metadata':True},**BINDING)
    snap['collections']=reader.collections;snap['created_at']=datetime.now(timezone.utc).isoformat()
    accepted=transport.disclosure_accepted_subjects
    if accepted.get(native.ARM)and accepted.get(native.ARM)==accepted.get(native.VAULT):snap['metadata']['native_disclosure_subject']=accepted[native.ARM]
    return make_snapshot('azure',scopes,snap['collections'],metadata=snap['metadata'],created_at=snap['created_at']),transport


def targets(snap):
    result=run(snap,ENTRY)
    return[e for e in result['graph']['edges']if e.get('technique_id')==ENTRY['id']or e.get('technique')==ENTRY['id']]


def test_native_certificate_metadata_reaches_terminal_effect_without_secret_get():
    snap,transport=collect();result=run(snap,ENTRY)
    from test_peaso_privesc_schema_ext import reached
    reached_targets={k:v for k,v in reached(result,OID,ENTRY['id']).items()if v!='unknown'}
    assert len(reached_targets)==1 and set(reached_targets.values())=={'conditional'},result
    assert len(transport.calls)==5
    assert all('/secrets/'not in url or'/versions?'in url for url in transport.calls)
    serialized=json.dumps(snap)
    assert 'PUBLIC-CERTIFICATE-OMITTED'not in serialized and 'provider-validates-this-signature'not in serialized
    assert not any(e['source']in reached_targets for e in result['graph']['edges'])


@pytest.mark.parametrize('mode',['access_policy_vault','thumbprint_mismatch','non_exportable','foreign_sid','secret_disabled','secret_missing','secret_expired','certificate_disabled','versions_partial','vault_identity_mismatch','no_native_acceptance','denied'])
def test_native_missing_facts_never_generate_verified_disclosure(mode):
    snap,_=collect(mode)
    assert not any(c['type']=='azure_privesc_challenge_evidence'for c in snap['collections'])
    from test_peaso_privesc_schema_ext import reached
    assert not {k:v for k,v in reached(run(snap,ENTRY),OID,ENTRY['id']).items()if v!='unknown'}


@pytest.mark.parametrize('mutation',['foreign_source','foreign_scan','missing_context','disabled_secret','missing_cluster','unverified_tenant'])
def test_native_validator_rechecks_subject_scan_and_backing_metadata(mutation):
    snap,_=collect()
    if mutation=='foreign_source':snap['metadata']['native_disclosure_subject']['oid']='foreign'
    if mutation=='foreign_scan':snap['metadata']['credential_context_id']='other'
    if mutation=='missing_context':snap['metadata'].pop('native_disclosure_subject')
    if mutation=='unverified_tenant':snap['metadata']['tenant_verified']=False
    if mutation=='disabled_secret':
        for c in snap['collections']:
            if c['type']=='azure_disclosure_secret_version_metadata':c['items'][0]['attributes']['enabled']=False
    if mutation=='missing_cluster':snap['collections']=[c for c in snap['collections']if c['type']!='azure_disclosure_cluster_metadata']
    from test_peaso_privesc_schema_ext import reached
    assert not {k:v for k,v in reached(run(snap,ENTRY),OID,ENTRY['id']).items()if v!='unknown'}


def test_optional_flag_is_strict_and_off_by_default():
    snap,reader,transport=setup()
    native.collect(reader,transport,snap['scopes'],{},**BINDING)
    assert transport.calls==[]
    with pytest.raises(ValueError):native.required_types({'native_disclosure_metadata':'yes'})


def test_native_subject_receipt_requires_exact_oid_tid_issuer_audience():
    assert native.accepted_subject(token(native.ARM),native.ARM)=={'oid':OID,'tid':TENANT}
    assert native.accepted_subject(token(native.VAULT),native.ARM)is None
    assert native.accepted_subject(token(native.ARM,issuer='https://attacker.invalid'),native.ARM)is None
    assert native.accepted_subject(token(native.ARM,oid='user-declared'),native.ARM)is None


@pytest.mark.parametrize('accepted',[True,False])
def test_transport_subject_receipt_is_recorded_only_after_native_http_success(monkeypatch,accepted):
    import io
    from urllib.error import HTTPError
    from types import SimpleNamespace
    class Response(io.BytesIO):
        status=200
        def __enter__(self):return self
        def __exit__(self,*args):self.close()
    def open_response(request,timeout):
        if not accepted:raise HTTPError(request.full_url,403,'denied',{},None)
        return Response(b'{"id":"accepted-native-resource"}')
    monkeypatch.setattr(azure,'build_opener',lambda *args:SimpleNamespace(open=open_response))
    transport=azure.AzureTransport({'method':'token','arm_token':token(native.ARM),'tenant_id':TENANT})
    if accepted:
        transport.request(native.ARM+'/subscriptions?api-version=2022-12-01',capture_subject=True)
        assert transport.disclosure_accepted_subjects[native.ARM]=={'oid':OID,'tid':TENANT}
        assert 'provider-validates-this-signature'not in json.dumps(transport.disclosure_accepted_subjects)
    else:
        with pytest.raises(HTTPError):transport.request(native.ARM+'/subscriptions?api-version=2022-12-01',capture_subject=True)
        assert not getattr(transport,'disclosure_accepted_subjects',{})


@pytest.mark.parametrize('hosted',[False,True])
def test_real_azure_collect_hook_retains_safe_proofs_and_scan_generated_binding(hosted,tmp_path,monkeypatch):
    from urllib.parse import urlsplit
    snap,_,base=setup();scope=snap['scopes'][0]
    bykind={c['type']:c['items']for c in snap['collections']}
    bykind['subscription'][0]['tenantId']=TENANT
    # Native Authorization List responses include ARM type/name and GUID IDs;
    # retain the offline fixture's same principals, permissions and scopes.
    for row in bykind['role_definition']:
        row.update(type='Microsoft.Authorization/roleDefinitions',name=row['id'].rsplit('/',1)[-1])
    for index,row in enumerate(bykind['role_assignment']):
        name='22222222-3333-4444-5555-'+format(index+1,'012x')
        row.update(id=row['id'].rsplit('/',1)[0]+'/'+name,
                   type='Microsoft.Authorization/roleAssignments',name=name)
    class FullTransport(Transport):
        def request(self,url,*,body=None,audience=native.ARM,capture_subject=False):
            if capture_subject:return super().request(url,body=body,audience=audience,capture_subject=True)
            self.calls.append(url);path=urlsplit(url).path
            if path=='/subscriptions':return {'value':bykind['subscription']}
            if path==scope:return copy.deepcopy(bykind['subscription'][0])
            if path=='/providers/Microsoft.ResourceGraph/resources':return {'data':copy.deepcopy(bykind['resource_graph'])}
            if path.endswith('/roleDefinitions'):return {'value':copy.deepcopy(bykind['role_definition'])if path.startswith(scope)else[]}
            if path.endswith('/roleAssignments'):return {'value':copy.deepcopy(bykind['role_assignment'])if path.startswith(scope)else[]}
            if path.endswith('/denyAssignments'):return {'value':[]}
            if path=='/v1.0/users':return {'value':copy.deepcopy(bykind['directory_user'])}
            return {'value':[]}
    transport=FullTransport(base.responses)
    connector={'name':'Native Fabric metadata','provider':'azure','scopes':[scope],
      'auth':{'method':'token','tenant_id':TENANT,'arm_token':token(native.ARM),'vault_token':token(native.VAULT)},
      'options':{'native_disclosure_metadata':True,'retries':1,'concurrency':1}}
    required=['subscription','resource_graph','role_definition','role_assignment','deny_assignment','directory_user']
    if hosted:
        from fastapi.testclient import TestClient
        from peaso.auth import Identity
        from peaso.server import create_app
        from peaso.server.config import Settings
        from peaso.storage import SQLiteStore,FileArtifacts
        from peaso.collectors import collect_live
        class Owner:
            def authenticate(self,header):return Identity('fixture-customer')
        settings=Settings(state_dir=tmp_path/'state',identity_dir=tmp_path/'identity',auth_mode='cognito')
        store=SQLiteStore(settings.state_dir)
        app=create_app(settings,store=store,artifacts=FileArtifacts(tmp_path/'artifacts'),authenticator=Owner())
        from tests.connector_access_receipts import mock_access_pass
        # Saving requires a passing Check access receipt; the cloud probe is stubbed.
        mock_access_pass(monkeypatch)
        with TestClient(app,base_url='https://cspm.hacktricks.wiki')as client:
            checked=client.post('/api/connectors/check-access',json=connector,headers={'Authorization':'Bearer test-owner'})
            assert checked.status_code==200 and checked.json()['status']=='pass',checked.text
            response=client.post('/api/connectors',json={**connector,'check_token':checked.json()['check_token']},headers={'Authorization':'Bearer test-owner'})
            assert response.status_code==201,response.text
            assert 'provider-validates-this-signature'not in response.text
            row=store.connector('fixture-customer',response.json()['id'])
            private=app.state.cipher.decrypt(row['auth']);stored=json.loads(row['data'])
            assert private['options']['native_disclosure_metadata']is True
            assert 'native_disclosure_subject'not in private['options']
            connector={**stored,'auth':private['auth'],'options':{**private['options'],'hosted':True}}
            monkeypatch.setattr(azure,'AzureTransport',lambda auth:transport);monkeypatch.setattr(azure,'AzureTransportExposure',lambda auth:transport)
            result=collect_live(connector,required)
    else:result=azure.collect(connector,required,transport=transport)
    assert result['metadata']['native_disclosure_subject']=={'oid':OID,'tid':TENANT}
    facts=[r for c in result['collections']if c['type']=='azure_privesc_challenge_evidence'for r in c['items']]
    assert len(facts)==1
    for key in BINDING:assert facts[0]['_provenance'][key]==result['metadata'][key]and result['metadata'][key]!=BINDING[key]
    from test_peaso_privesc_schema_ext import reached
    assert 'conditional'in reached(run(result,ENTRY),OID,ENTRY['id']).values()
    assert 'PUBLIC-CERTIFICATE-OMITTED'not in json.dumps(result)


def test_native_configuration_presence_does_not_replace_secret_read_permission():
    snap,_=collect()
    for c in snap['collections']:
        if c['type']=='role_definition':
            for r in c['items']:
                for permission in r['properties']['permissions']:permission['dataActions']=[]
    from test_peaso_privesc_schema_ext import reached
    assert not {k:v for k,v in reached(run(snap,ENTRY),OID,ENTRY['id']).items()if v!='unknown'}


def test_native_positive_coverage_is_explicitly_partial_and_source_bound():
    snap,_=collect();result=run(snap,ENTRY)
    rows=[r for r in result['coverage']if r['kind']=='adapter'and ENTRY['id']in r['reason']]
    assert len(rows)==1 and rows[0]['status']=='partial'
    assert 'source-bound native metadata witness' in rows[0]['reason']


@pytest.mark.parametrize('provider',['aws','gcp','k8s'])
@pytest.mark.parametrize('selection',[False,True])
def test_hosted_disclosure_selection_is_azure_only_even_when_disabled(provider,selection):
    from types import SimpleNamespace
    from fastapi import HTTPException
    from peaso.server.validation import validate_connector
    with pytest.raises(HTTPException)as error:
        validate_connector(provider,{}, {'native_disclosure_metadata':selection},SimpleNamespace(auth_mode='cognito'))
    assert error.value.status_code==422


@pytest.mark.parametrize('selection',[None,0,1,'true',{},[]])
def test_hosted_disclosure_flag_never_accepts_imported_observation(selection):
    from types import SimpleNamespace
    from fastapi import HTTPException
    from peaso.server.validation import validate_connector
    with pytest.raises(HTTPException)as error:
        validate_connector('azure',{'method':'token','arm_token':'fixture'}, {'native_disclosure_metadata':selection},SimpleNamespace(auth_mode='cognito'))
    assert error.value.status_code==422


@pytest.mark.parametrize('field',['native_disclosure_subject','credential_context_id','customer_context_id'])
def test_hosted_disclosure_cannot_supply_authenticated_subject_or_scan_binding(field):
    from types import SimpleNamespace
    from fastapi import HTTPException
    from peaso.server.validation import validate_connector
    with pytest.raises(HTTPException)as error:
        validate_connector('azure',{'method':'token','arm_token':'fixture'}, {'native_disclosure_metadata':True,field:'caller-controlled'},SimpleNamespace(auth_mode='cognito'))
    assert error.value.status_code==422


@pytest.mark.parametrize('selection',[False,True])
def test_hosted_azure_accepts_exact_boolean_without_mutating_options(selection):
    from types import SimpleNamespace
    from peaso.server.validation import validate_connector
    options={'native_disclosure_metadata':selection};before=copy.deepcopy(options)
    validate_connector('azure',{'method':'token','arm_token':'fixture'},options,SimpleNamespace(auth_mode='cognito'))
    assert options==before

# Real observed ARM/Vault shape: current GET has policy; exact-version GET omits it.
def policy_binding_capture(mode='real_exact_omits_policy'):
    snap,reader,transport=setup()
    transport.responses={key:copy.deepcopy(value)for key,value in transport.responses.items()}
    base=next(key for key in transport.responses if '/certificates/client-cert?'in key)
    exact=next(key for key in transport.responses if '/certificates/client-cert/version1?'in key)
    resolved=transport.responses[base];version=transport.responses[exact]
    if mode!='legacy_exact_policy':version.pop('policy',None)
    if mode=='current_omits_policy':resolved.pop('policy',None);version['policy']={'key_props':{'exportable':True}}
    if mode=='rotation':version['id']=version['id'].replace('/version1','/version2')
    if mode=='sid_mismatch':version['sid']=version['sid'].rsplit('/',1)[0]+'/other-version'
    if mode=='thumb_mismatch':version['x5t']=base64.urlsafe_b64encode(bytes.fromhex('cd'*20)).decode().rstrip('=')
    if mode=='current_unexportable':resolved['policy']['key_props']['exportable']=False
    if mode=='exact_unexportable':version['policy']={'key_props':{'exportable':False}}
    if mode=='exact_null_policy':version['policy']=None
    if mode=='exact_disabled':version['attributes']['enabled']=False
    if mode=='exact_expired':version['attributes']['exp']=1
    if mode=='exact_future':version['attributes']['nbf']=4102444800
    if mode=='exact_float_exp':version['attributes']['exp']=4102444800.0
    if mode=='exact_missing_attrs':version.pop('attributes',None)
    native.collect(reader,transport,snap['scopes'],{'native_disclosure_metadata':True},**BINDING)
    snap['collections']=reader.collections;snap['created_at']=datetime.now(timezone.utc).isoformat()
    subjects=transport.disclosure_accepted_subjects
    if subjects.get(native.ARM)==subjects.get(native.VAULT):snap['metadata']['native_disclosure_subject']=subjects.get(native.ARM)
    return make_snapshot('azure',snap['scopes'],snap['collections'],metadata=snap['metadata'],created_at=snap['created_at']),transport

@pytest.mark.parametrize('mode',['real_exact_omits_policy','legacy_exact_policy','current_omits_policy'])
def test_current_policy_exact_version_binding_reaches_conditional_effect(mode):
    snap,transport=policy_binding_capture(mode)
    facts=[r for c in snap['collections']if c['type']=='azure_privesc_challenge_evidence'for r in c['items']]
    assert len(facts)==1
    certificate=next(r for c in snap['collections']if c['type']=='azure_disclosure_certificate_metadata'for r in c['items'])
    operation='Certificates_GetCurrent'if mode=='real_exact_omits_policy'else'Certificates_Get'
    assert certificate['_provenance']['policy_source_operation']==operation
    assert certificate['_provenance']['policy_version_id']==certificate['id']
    assert certificate['policy_binding']['id']==certificate['id']
    assert certificate['attributes']['enabled']is True
    from test_peaso_privesc_schema_ext import reached
    assert 'conditional'in reached(run(snap,ENTRY),OID,ENTRY['id']).values()
    assert all('/secrets/'not in u or'/versions?'in u for u in transport.calls)

@pytest.mark.parametrize('mode',['rotation','sid_mismatch','thumb_mismatch','current_unexportable','exact_unexportable','exact_null_policy','exact_disabled','exact_expired','exact_future','exact_float_exp','exact_missing_attrs'])
def test_contradictory_or_unusable_exact_version_never_produces_fact(mode):
    snap,_=policy_binding_capture(mode)
    assert not any(c['type']=='azure_privesc_challenge_evidence'for c in snap['collections'])

@pytest.mark.parametrize('field',['id','sid','x5t','policy','source_operation','request_uri','provenance_operation','provenance_uri','provenance_version','exact_enabled','exact_exp'])
def test_validator_independently_rejects_policy_binding_tamper(field):
    snap,_=policy_binding_capture()
    cert=next(r for c in snap['collections']if c['type']=='azure_disclosure_certificate_metadata'for r in c['items'])
    if field=='policy':cert['policy_binding']['policy']={'key_props':{'exportable':False}}
    elif field=='exact_enabled':cert['attributes']['enabled']=False
    elif field=='exact_exp':cert['attributes']['exp']=1
    elif field.startswith('provenance_'):
        key={'provenance_operation':'policy_source_operation','provenance_uri':'policy_request_uri','provenance_version':'policy_version_id'}[field];cert['_provenance'][key]='foreign'
    else:cert['policy_binding'][field]='foreign'
    snap.pop('snapshot_id',None)
    from test_peaso_privesc_schema_ext import reached
    assert not {k:v for k,v in reached(run(snap,ENTRY),OID,ENTRY['id']).items()if v!='unknown'}
