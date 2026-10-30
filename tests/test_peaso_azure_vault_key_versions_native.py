"""Native Key Vault metadata does not prove use, import provenance or TLS issuance."""
import copy
import json
from urllib.parse import urlsplit
import pytest
from peaso.collectors import azure, collect_live
from tests.archived_check_contract import evaluate_snapshot

SUB='/subscriptions/11111111-1111-1111-1111-111111111111'
RID=SUB+'/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/fixturevault'
ORIGIN='https://fixturevault.vault.azure.net'
KID=ORIGIN+'/keys/fixture'
CHECK='azure.other.vault_key_approved_algorithm'
POLICY={'status':'collected','scope':SUB,'approved_key_algorithms':{'industry_standard_confirmed':True,'minimum_rsa_bits':2048,'approved_ec_curves':['P-256']}}
class Denied(Exception):status_code=403


def capture(monkeypatch,mode,*,keys_next='ABSENT',versions_next='ABSENT',**limits):
 attrs={'enabled':mode!='disabled','created':1700000000}
 class Transport:
  tenant=verified_tenant='aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
  def __init__(self):self.calls=[]
  def close(self):pass
  def allow_vault(self,url):assert url==ORIGIN
  def request(self,url,*,body=None,audience=azure.ARM):
   self.calls.append((url,audience));path=urlsplit(url).path
   if audience==azure.VAULT:
    assert body is None and path.startswith('/keys'), 'No secret or certificate private material endpoint'
    if mode=='denied':raise Denied('SENSITIVE_SENTINEL')
    if path=='/keys':
     if 'skiptoken=last' in url:return {'value':[]}
     values=[{'kid':KID,'attributes':attrs,'tags':{'secret':'SENSITIVE_SENTINEL'}}]
     if mode=='duplicate_key':values*=2
     result={'value':values}
     if keys_next!='ABSENT':result['nextLink']=keys_next
     return result
    if path=='/keys/fixture/versions':
     if 'skiptoken=last' in url:return {'value':[]}
     vid=KID+'/v1'
     if mode=='foreign':vid='https://foreign.vault.azure.net/keys/fixture/v1'
     values=[{'kid':vid,'attributes':attrs}]
     if mode=='duplicate':values*=2
     if mode=='empty_versions':values=[]
     result={'value':values}
     if versions_next!='ABSENT':result['nextLink']=versions_next
     if mode in ('partial','two_pages') and 'skiptoken'not in url:
      result['nextLink']=(ORIGIN if mode=='two_pages'else'https://foreign.example')+'/keys/fixture/versions?api-version=2025-07-01&skiptoken=next'
     if mode=='two_pages'and'skiptoken'in url:result={'value':[{'kid':KID+'/v2','attributes':attrs}]}
     return result
    assert path in('/keys/fixture/v1','/keys/fixture/v2')
    if mode=='version_denied':raise Denied('SENSITIVE_SENTINEL')
    key={'kid':ORIGIN+path,'kty':'EC','crv':'P-256','key_ops':['encrypt'],'d':'SENSITIVE_SENTINEL','k':'SENSITIVE_SENTINEL'}
    if mode=='recovery_injection':attrs['recoveryLevel']={'secret':'SENSITIVE_SENTINEL'}
    if mode=='foreign_get':key['kid']=KID+'/foreign'
    if mode=='invalid_type':key['kty']='EC-invented'
    if mode=='bad_enabled':return {'key':key,'attributes':{'enabled':1}}
    return {'key':key,'attributes':copy.deepcopy(attrs),'tags':{'secret':'SENSITIVE_SENTINEL'}}
   if path==SUB+'/providers/Microsoft.KeyVault/vaults':
    uri='https://foreign.vault.azure.net'if mode=='foreign_vault'else ORIGIN
    return {'value':[{'id':RID,'type':'Microsoft.KeyVault/vaults','name':'fixturevault','properties':{'vaultUri':uri}}]}
   if path==RID:return {'id':RID,'type':'Microsoft.KeyVault/vaults','name':'fixturevault','properties':{'vaultUri':ORIGIN}}
   if path.endswith('/resources'):return {'data':[],'resultTruncated':False}
   return {'value':[]}
 transport=Transport();monkeypatch.setattr(azure,'AzureTransport',lambda auth:transport);monkeypatch.setattr(azure,'AzureTransportExposure',lambda auth:transport)
 options={'retries':0,'concurrency':1,**limits}
 if mode!='missing_policy':options['compliance_policy']={'sw32':copy.deepcopy(POLICY)}
 snapshot=collect_live({'provider':'azure','scopes':[SUB],'auth':{'method':'token','arm_token':'fixture','vault_token':'fixture-vault'},'options':options},['vault_key'])
 before=json.dumps(snapshot,sort_keys=True)
 report=evaluate_snapshot(snapshot,checks=[CHECK])
 assert json.dumps(snapshot,sort_keys=True)==before
 assert 'SENSITIVE_SENTINEL'not in before
 findings=[f for f in report['findings']if f['check_id']==CHECK]
 assert len(findings)==1
 return findings[0]['status'],snapshot,transport


@pytest.mark.parametrize('mode,expected', [('enabled','UNKNOWN'),('disabled','PASS'),('missing_policy','UNKNOWN'),('denied','DENIED'),('foreign','UNKNOWN'),('duplicate','UNKNOWN'),('empty_versions','UNKNOWN'),('partial','UNKNOWN'),('foreign_get','UNKNOWN'),('invalid_type','UNKNOWN'),('bad_enabled','UNKNOWN'),('foreign_vault','UNKNOWN'),('two_pages','UNKNOWN'),('recovery_injection','UNKNOWN'),('duplicate_key','UNKNOWN'),('version_denied','DENIED')])
def test_native_public_pipeline(monkeypatch,mode,expected):
 status,snapshot,transport=capture(monkeypatch,mode)
 assert status==expected
 if mode in('enabled','two_pages','disabled'):
  envelope=next(c for c in snapshot['collections']if c['type']=='vault_key')
  assert envelope['status']=='collected'
  versions=envelope['items'][0]['versions']
  assert len(versions)==(2 if mode=='two_pages'else 1)
  assert all('encryption_use'not in v and 'algorithm_policy_approved'not in v and 'import_provenance'not in v for v in versions)
 if mode=='foreign_vault':assert not any(audience==azure.VAULT for _,audience in transport.calls)


def test_page_limit_not_empty_or_compliant(monkeypatch):
 status,snapshot,_=capture(monkeypatch,'two_pages',max_pages=1)
 assert status=='UNKNOWN'
 assert next(c for c in snapshot['collections']if c['type']=='vault_key')['status']not in('collected','empty')


def test_normative_algorithm_is_not_live_tls_or_use_proof(monkeypatch):
 status,snapshot,_=capture(monkeypatch,'enabled')
 assert status=='UNKNOWN'
 ids=['azure.other.certificate_rotation_90_days','azure.other.certificate_rotation_180_days']
 report=evaluate_snapshot(snapshot,checks=ids)
 outcomes={f['check_id']:f['status']for f in report['findings']if f['check_id']in ids}
 assert outcomes==dict.fromkeys(ids,'UNKNOWN')


def test_resource_bound_preserves_uncertainty(monkeypatch):
 status,snapshot,_=capture(monkeypatch,'two_pages',max_resources=2)
 assert status=='UNKNOWN'
 assert next(c for c in snapshot['collections']if c['type']=='vault_key')['status']not in('collected','empty')


@pytest.mark.parametrize('field',['keys_next','versions_next'])
@pytest.mark.parametrize('value',[0,False,[],{},'', ' ', 'https://foreign.vault.azure.net/keys', 'https://fixturevault.vault.azure.net/keys/other', 'https://fixturevault.vault.azure.net/keys#fragment', 'https://user@fixturevault.vault.azure.net/keys'])
def test_falsy_or_foreign_continuation_never_proves_complete(monkeypatch,field,value):
 status,snapshot,transport=capture(monkeypatch,'disabled',**{field:value})
 assert status=='UNKNOWN'
 envelope=next(c for c in snapshot['collections']if c['type']=='vault_key')
 assert envelope['status']not in('collected','empty')
 assert not any('foreign.vault' in url or 'user@' in url for url,_ in transport.calls)


@pytest.mark.parametrize('field,path',[('keys_next','/keys'),('versions_next','/keys/fixture/versions')])
@pytest.mark.parametrize('port',['',':443'])
def test_documented_https_continuation_ports(monkeypatch,field,path,port):
 link='https://fixturevault.vault.azure.net'+port+path+'?api-version=2025-07-01&skiptoken=last'
 status,snapshot,transport=capture(monkeypatch,'disabled',**{field:link})
 assert status=='PASS'
 assert (link,azure.VAULT)in transport.calls


@pytest.mark.parametrize('field',['keys_next','versions_next'])
def test_explicit_null_is_native_terminal(monkeypatch,field):
 assert capture(monkeypatch,'disabled',**{field:None})[0]=='PASS'
