"""Native configuration does not attest the human issuance procedure."""
import json
from datetime import datetime,timezone
from urllib.parse import urlsplit
import pytest
from peaso.collectors import azure,collect_live
from tests.archived_check_contract import evaluate_snapshot, plan_collection
from peaso.snapshot import make_snapshot
SCOPE='/subscriptions/11111111-1111-1111-1111-111111111111';TENANT='22222222-2222-2222-2222-222222222222'
VAULT=SCOPE+'/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/vaultfixture';ORIGIN='https://vaultfixture.vault.azure.net'
CHECK='azure_c5_cry_08_01b';KIND='key_vault_certificate_current';NOW=datetime.now(timezone.utc).isoformat()
def capture(monkeypatch,mode='good',reviewed_process=False):
 class API:
  tenant=verified_tenant=TENANT
  def __init__(self):self.calls=[];self.allowed=[]
  def close(self):pass
  def allow_vault(self,uri):self.allowed.append(uri)
  def request(self,url,*,body=None,audience=azure.ARM):
   self.calls.append((url,audience));path=urlsplit(url).path
   if body is not None:return {'data':[]}
   if path=='/subscriptions' or path==SCOPE:
    row={'id':SCOPE,'tenantId':TENANT,'state':'Enabled','subscriptionId':SCOPE.rsplit('/',1)[1]}
    return {'value':[row]} if path=='/subscriptions' else row
   if path==SCOPE+'/providers/Microsoft.KeyVault/vaults':
    row={'id':VAULT,'type':'Microsoft.KeyVault/vaults','properties':{'vaultUri':ORIGIN,'tenantId':TENANT}}
    if mode=='foreign_vault':row['id']=VAULT.replace(SCOPE,'/subscriptions/foreign')
    if mode=='foreign_origin':row['properties']['vaultUri']='https://different.vault.azure.net'
    return {'value':[row]}
   if path=='/certificates':
    if mode=='denied':raise azure.AzureReadError('denied',403)
    rows=[{'id':ORIGIN+'/certificates/cert'}]
    if mode=='foreign_list':rows[0]['id']='https://foreign.vault.azure.net/certificates/cert'
    if mode=='duplicate':rows*=2
    result={'value':rows}
    if mode=='paging':result['nextLink']=url+'&page=2'
    return result
   if path=='/certificates/cert':
    row={'id':ORIGIN+'/certificates/cert/v1','attributes':{'enabled':True},'policy':{'issuer':{'name':'ContosoCA'},'key_props':{'kty':'RSA','key_size':2048}},'value':'NEVER_RETAIN','sid':'NEVER_RETAIN','tags':{'secret':'NEVER_RETAIN'}}
    if mode=='bad_issuer':row['policy']['issuer']['name']='Self'
    if mode=='weak_rsa':row['policy']['key_props']['key_size']=1024
    if mode=='good_ec':row['policy']['key_props']={'kty':'EC','crv':'P-256'}
    if mode=='bad_curve':row['policy']['key_props']={'kty':'EC','crv':'P-256K'}
    if mode=='fake_curve':row['policy']['key_props']={'kty':'EC','curve':'P-256'}
    if mode=='missing_policy':row.pop('policy')
    if mode=='missing_issuer':row['policy'].pop('issuer')
    if mode=='foreign_current':row['id']=ORIGIN+'/certificates/other/v1'
    if mode=='unversioned_current':row['id']=ORIGIN+'/certificates/cert'
    return row
   return {'value':[]}
 api=API();monkeypatch.setattr(azure,'AzureTransport',lambda auth:api);monkeypatch.setattr(azure,'AzureTransportExposure',lambda auth:api)
 policy={'status':'collected','scope':SCOPE,'certificateIssuance':{'approvedIssuers':['ContosoCA'],'approvedKeyTypes':['RSA','EC'],'approvedEcCurves':['P-256'],'minimumRsaBits':2048,'assessedAt':NOW}}
 connector={'provider':'azure','scopes':[SCOPE],'auth':{'tenant_id':TENANT,'method':'token','arm_token':'fixture','vault_token':'fixture'},'options':{'retries':0,'max_pages':1,'compliance_policy':{'sw33':policy}}}
 snap=collect_live(connector,plan_collection({'connector':connector,'checks':[CHECK]}))
 if reviewed_process:
  record={'id':SCOPE,'periodStart':'2026-01-01T00:00:00Z','periodEnd':'2027-01-01T00:00:00Z','procedureCurrent':True,'identityVerified':True,'secureIssuance':True,'trustedCaVerified':True}
  snap=make_snapshot('azure',[SCOPE],snap['collections']+[{'type':'certificate_issuance_evidence','scope':SCOPE,'status':'collected','items':[record]}],metadata=snap['metadata'],created_at=snap['created_at'])
 findings=evaluate_snapshot(snap,checks=[CHECK])['findings'];assert len(findings)==1,findings
 assert 'NEVER_RETAIN' not in json.dumps(snap)
 assert not any('/secrets/' in url or '/keys/' in url or 'listKeys' in url for url,_ in api.calls)
 return findings[0],snap,api
@pytest.mark.parametrize('mode,expected',[
 ('good','UNKNOWN'),('good_ec','UNKNOWN'),('bad_issuer','FAIL'),('weak_rsa','FAIL'),('bad_curve','FAIL'),
 ('fake_curve','UNKNOWN'),('missing_policy','UNKNOWN'),('missing_issuer','UNKNOWN'),('foreign_current','UNKNOWN'),('unversioned_current','UNKNOWN'),
 ('foreign_vault','UNKNOWN'),('foreign_origin','UNKNOWN'),('foreign_list','UNKNOWN'),('duplicate','UNKNOWN'),('paging','UNKNOWN'),('denied','DENIED')])
def test_metadata_to_engine_preserves_process_requirement(monkeypatch,mode,expected):
 finding,snap,api=capture(monkeypatch,mode);assert finding['status']==expected,finding
 if mode in ('good','good_ec','bad_issuer','weak_rsa','bad_curve'):
  col=next(c for c in snap['collections'] if c['type']==KIND);row=col['items'][0]
  assert col['scope']==SCOPE and row['isCurrentVersion'] is True
  assert row['data_plane_id']==ORIGIN+'/certificates/cert/v1'
  assert row['_provenance']['source_operation']=='certificates_get_current'
  assert api.allowed==[ORIGIN]
  assert 'certificate_issuance_evidence' not in {c['type'] for c in snap['collections']}
@pytest.mark.parametrize('mode,expected',[('good','PASS'),('good_ec','PASS'),('bad_issuer','FAIL'),('weak_rsa','FAIL')])
def test_full_pass_requires_separate_process_attestation(monkeypatch,mode,expected):
 finding,_,_=capture(monkeypatch,mode,reviewed_process=True);assert finding['status']==expected,finding
def test_new_selection_keeps_existing_certificate_reader_available():
 assert {'vault',KIND}<=azure._selected({},[KIND])
 assert {'vault','key_vault_certificate'}<=azure._selected({},['key_vault_certificate'])
