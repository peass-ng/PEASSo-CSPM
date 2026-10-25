"""Real google-auth offline credentials and the native first-metadata HTTP boundary."""
import importlib.util,json,threading,time
from datetime import datetime,timedelta,timezone
from pathlib import Path
from types import SimpleNamespace
import pytest
import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from google.auth import identity_pool
from google.oauth2 import credentials as adc,service_account
from peaso.collectors import gcp_registry_trivy_20261021 as native

P=Path(__file__).parent
from peaso.collectors import gcp as m
TOKEN='synthetic-offline-token-not-authorized'

@pytest.fixture(scope='module')
def key_info():
 key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
 return {'type':'service_account','project_id':'owned-project','private_key_id':'offline-only',
  'private_key':key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()).decode(),
  'client_email':'reader@owned-project.iam.gserviceaccount.com','client_id':'1234567890',
  'token_uri':'https://oauth2.googleapis.com/token'}

def sdk(kind,key_info):
 if kind=='service-account':obj=service_account.Credentials.from_service_account_info(key_info,scopes=m.OAUTH_SCOPES)
 elif kind=='adc':obj=adc.Credentials(token=TOKEN,quota_project_id='owned-quota-project')
 else:obj=identity_pool.Credentials(audience='//iam.googleapis.com/projects/1234567890/locations/global/workloadIdentityPools/owned-pool/providers/owned-provider',subject_token_type='urn:ietf:params:oauth:token-type:jwt',token_url='https://sts.googleapis.com/v1/token',credential_source={'file':'/must-not-be-read'},scopes=m.OAUTH_SCOPES)
 obj.token=TOKEN;obj.expiry=datetime.now(timezone.utc).replace(tzinfo=None)+timedelta(minutes=30)
 # Newer google-auth performs background regional-policy lookups. Seed its
 # ordinary cached policy fixture too, keeping this header test strictly offline.
 if hasattr(obj,'_set_regional_access_boundary'):
  obj._set_regional_access_boundary({'encodedLocations':'0xA30','expiry':datetime.now(timezone.utc).replace(tzinfo=None)+timedelta(hours=6)})
 return obj

def wrapper(credential):
 obj=object.__new__(m.Credentials);obj.lock=threading.Lock();obj.failure=None;obj.direct_token=None;obj.gcloud=None;obj.timeout=5;obj.credential=credential
 def forbidden(*args,**kwargs):raise AssertionError('offline credential unexpectedly requested HTTP')
 obj.request=forbidden
 return obj

@pytest.mark.parametrize('kind',['service-account','adc','federation'])
def test_actual_sdk_before_request_single_canonical_authorization_preserves_non_auth(kind,key_info):
 cred=sdk(kind,key_info);raw={};cred.before_request(lambda *a,**k:pytest.fail('unexpected refresh'),'GET','https://cloudasset.googleapis.com/',raw)
 assert 'authorization' in raw and 'Authorization' not in raw
 headers=wrapper(cred).headers()
 assert headers['Authorization']=='Bearer '+TOKEN
 assert [k for k in headers if k.lower()=='authorization']==['Authorization']
 assert {k:v for k,v in headers.items() if k!='Authorization'}=={k:v for k,v in raw.items() if k.lower()!='authorization'}
 if kind=='adc':assert headers['x-goog-user-project']=='owned-quota-project'

class Emits:
 def __init__(self,headers):self.values=headers;self.calls=0
 def before_request(self,request,method,url,headers):self.calls+=1;headers.update(self.values)

@pytest.mark.parametrize('keys',[['authorization'],['AUTHORIZATION'],['Authorization'],['authorization','AUTHORIZATION','Authorization']])
def test_sdk_header_case_and_same_value_duplicates_collapse(keys):
 cred=Emits({**{k:'Bearer '+TOKEN for k in keys},'x-goog-api-client':'sdk-offline','X-Other':'untouched'})
 assert wrapper(cred).headers()=={'Authorization':'Bearer '+TOKEN,'x-goog-api-client':'sdk-offline','X-Other':'untouched'}

def test_conflicting_case_duplicates_rejected_and_failure_cached_without_values():
 cred=Emits({'authorization':'Bearer PRIVATE_FIRST','Authorization':'Bearer PRIVATE_SECOND'})
 obj=wrapper(cred)
 with pytest.raises(m.ReadError) as first:obj.headers()
 with pytest.raises(m.ReadError) as second:obj.headers()
 assert first.value is second.value and cred.calls==1
 assert first.value.error['code']=='credential_refresh_failed'
 assert 'PRIVATE_' not in str(first.value) and 'PRIVATE_' not in repr(first.value.error)

def test_missing_auth_not_invented_or_other_headers_changed():
 assert wrapper(Emits({'x-goog-api-client':'unchanged'})).headers()=={'x-goog-api-client':'unchanged'}

@pytest.mark.parametrize('kind',['service-account','adc','federation'])
def test_native_metadata_first_http_uses_actual_sdk_canonical_header(kind,key_info):
 calls=[];body=json.dumps({'name':'projects/1234567890','projectId':'owned-project','state':'ACTIVE'}).encode()
 class Response:
  status_code=200;history=[]
  headers={'Content-Encoding':'identity','Content-Length':str(len(body))}
  def __init__(self,url,params):self.url=requests.Request('GET',url,params=params).prepare().url;self.closed=False
  def iter_content(self,chunk_size):yield body
  def close(self):self.closed=True
 class Session:
  def request(self,method,url,**kwargs):
   calls.append((method,url,kwargs));assert kwargs['headers']['Authorization']=='Bearer '+TOKEN
   assert kwargs['allow_redirects'] is False and kwargs['stream'] is True
   return Response(url,kwargs['params'])
 transport=SimpleNamespace(lock=threading.Lock(),calls=0,max_calls=2,credentials=wrapper(sdk(kind,key_info)),timeout=5,evidence=[],check_cancelled=lambda:None)
 reader=native.MetadataReader(transport,Session(),time.monotonic()+10,'projects/owned-project')
 assert reader.get('https://cloudresourcemanager.googleapis.com/v3/projects/owned-project',native.metadata.PROJECT_FIELDS)['state']=='ACTIVE'
 assert len(calls)==1 and transport.calls==1
 assert reader.records[0]['status']=='collected' and reader.records[0]['http_attempts']==1 and reader.records[0]['http_status']==200
 assert TOKEN not in json.dumps(reader.records)

def test_direct_token_branch_unchanged():
 obj=wrapper(None);obj.direct_token=TOKEN
 assert obj.headers()=={'Authorization':'Bearer '+TOKEN}

@pytest.mark.parametrize('kind',['service-account','adc','federation'])
@pytest.mark.parametrize('positive',[False,True])
def test_full_native_registry_binding_actual_sdk_auth_and_scripted_tool_verdict(kind,positive,key_info):
 # Existing synthetic owned OCI bytes + full native metadata/registry receipts.
 # This is an offline runner contract regression, not a real Trivy execution.
 import gcp_job_image_vulnerability_fixture_20261021 as fixture
 selectors,bodies,blobs=fixture.fixtures()
 ref=selectors[0]['immutable_reference'];metadata=fixture.MetadataSession(bodies);images=fixture.ImageSession(blobs)
 credential=sdk(kind,key_info);credential.token='fixture-access-token'
 transport=fixture.transport();transport.credentials=wrapper(credential)
 reached=[]
 def runner(identity,manifest,config,layers,**kwargs):
  assert kwargs['native_verifier']()==identity
  assert layers and all(isinstance(layer,Path) and layer.exists() for layer in layers)
  reached.append(True)
  return {'image':identity,'status':'FAIL' if positive else 'PASS','complete':True,'scan_complete':True,
   'coverage_status':'COMPLETE','database':{'fresh':True},
   'findings':[{'vulnerability_id':'CVE-2026-12345','severity':'HIGH'}] if positive else []}
 result=native.collect_native(transport,scope=fixture.SCOPE,selectors=[ref],enabled=True,
  metadata_session=metadata,image_session=images,runner=runner)
 assert result['status']==('FAIL' if positive else 'PASS') and result['complete'] is True
 assert len(reached)==1 and len(metadata.calls)==6 and len(images.calls)==3 and transport.calls==9
 assert len(result['rows'][0]['scan']['findings'])==(1 if positive else 0)
 assert all(row.get('status')=='collected' and row.get('http_attempts')==1 for row in result['source_requests'])
 assert metadata.closed and images.closed
 assert 'fixture-access-token' not in json.dumps(result)
