"""Native Command job codeId to one selected code-version file, with normal imports."""
import base64
import io
import json
import time
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch

from peaso import secret_scanning
from peaso.collectors import azure_ml_selected_asset_secret_indicators as source
from peaso.collectors import azure_selected_storage_secret_indicators as storage
from peaso.checks import azure_ml_selected_asset_secret_review_20261020 as review
from peaso.server import content_selection_preflight_20261021 as preflight

SUB='/subscriptions/11111111-1111-1111-1111-111111111111'
TENANT='22222222-2222-2222-2222-222222222222'
WS=SUB+'/resourceGroups/review/providers/Microsoft.MachineLearningServices/workspaces/selected'
CODE=WS+'/codes/Source/versions/V1'
JOB=WS+'/jobs/train-1'
ACCOUNT=SUB+'/resourceGroups/review/providers/Microsoft.Storage/storageAccounts/sourceaccount'
TARGET={'resource_id':CODE,'job_resource_id':JOB,'datastore':'source_store','storage':{
    'service':'blob','resource_id':ACCOUNT,'container':'sources','object':'code/main.py','format':'text'}}

def token(aud):
    claims={'aud':aud,'tid':TENANT,'oid':'33333333-3333-3333-3333-333333333333','exp':int(time.time())+3600}
    return 'x.'+base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip('=')+'.x'

class Transport:
    tenant=verified_tenant=TENANT
    def __init__(self):self.calls=[]
    def token(self,aud):self.calls.append(aud);return token(aud)

class Response:
    def __init__(self,body,status=200,headers=None,head=False):
        self.raw=json.dumps(body).encode() if isinstance(body,dict) else body
        self.stream=io.BytesIO(b'' if head else self.raw);self.status=status
        self.headers={'Content-Type':'application/json','Content-Length':str(len(self.raw)),
            'x-ms-request-id':'11111111-1111-4111-8111-111111111111',**(headers or {})}
        self.closed=False
    def getheader(self,name):return self.headers.get(name)
    def read(self,n):return self.stream.read(n)
    def close(self):self.closed=True

class Wire:
    plan=[];seen=[]
    def __init__(self,host,timeout):self.host=host;self.sock=None
    def set_debuglevel(self,n):assert n==0
    def request(self,method,path,body=None,headers=None):
        assert method in ('GET','HEAD') and body is None and 'Authorization' in headers
        assert self.host in ('management.azure.com','sourceaccount.blob.core.windows.net')
        self.seen.append((method,self.host,path,headers))
    def getresponse(self):return self.plan.pop(0)
    def close(self):pass

class Reader:
    def __init__(self):self.collections=[];self.configuration_secret_redactions=set()
    def check_cancelled(self):pass
    def call(self,fn,*args):return fn(*args)
    def run(self,tasks):
        for kind,scope,service,fetch in tasks:
            items=[item for page in fetch() for item in page]
            self.collections.append({'scope':scope,'service':service,'status':'collected' if all(
                item[source.MARKER]['complete'] for item in items) else 'partial','items':items,
                '_provenance':{'credential_context_id':'cred','customer_context_id':'cust'}})

def run_case(*,hit=False,job_after='same',job_before='same',denied=False,enabled=True,capture=False):
    sub={'id':SUB,'subscriptionId':SUB.rsplit('/',1)[1],'tenantId':TENANT,'state':'Enabled'}
    ws={'id':WS,'name':'selected','type':source.SERVICE+'/workspaces','properties':{
        'tenantId':TENANT,'workspaceId':'44444444-4444-4444-4444-444444444444','provisioningState':'Succeeded'}}
    job={'id':JOB,'name':'train-1','type':source.SERVICE+'/workspaces/jobs','properties':{
        'jobType':'Command','codeId':CODE,'command':'python main.py'}}
    code={'id':CODE,'name':'V1','type':source.SERVICE+'/workspaces/codes/versions','properties':{
        'codeUri':'azureml://datastores/source_store/paths/code/'}}
    ds={'id':WS+'/datastores/source_store','name':'source_store','type':source.SERVICE+'/workspaces/datastores','properties':{
        'datastoreType':'AzureBlob','accountName':'sourceaccount','containerName':'sources','endpoint':'core.windows.net',
        'protocol':'https','subscriptionId':SUB.rsplit('/',1)[1],'resourceGroup':'review',
        'credentials':{'credentialsType':'None','secrets':{'secretsType':'None'}}}}
    account={'id':ACCOUNT,'name':'sourceaccount','type':'Microsoft.Storage/storageAccounts','properties':{
        'provisioningState':'Succeeded','primaryEndpoints':{'blob':'https://sourceaccount.blob.core.windows.net/'}}}
    raw=b'TOKEN=private-value\n' if hit else b'mode=ready\n'
    hdr={'Content-Type':'application/octet-stream','ETag':'"0x123ABC"','x-ms-version':storage.DATA_VERSION,'x-ms-blob-type':'BlockBlob'}
    first=deepcopy(job)
    if job_before=='foreign':first['properties']['codeId']=CODE+'/foreign'
    last=deepcopy(job)
    if job_after=='drift':last['properties']['codeId']=CODE+'/foreign'
    responses=[Response(sub),Response(ws),Response(first),Response(code),Response(ds),Response(account),
        Response(raw,headers=hdr,head=True),Response({'error':'denied'},status=403) if denied else Response(raw,headers=hdr),
        Response(raw,headers=hdr,head=True),Response(ds),Response(code),Response(ds),Response(ws),Response(last)]
    Wire.plan=responses[:];Wire.responses=responses;Wire.seen=[];reader=Reader();transport=Transport();profile=source.PROFILES['code']
    options={'content_secret_scans':enabled,'_content_secret_scan_kinds':[profile['kind']] if enabled else [],
        profile['option']:[TARGET]}
    def detector(data,path,timeout):return [('private-value','fixture-rule',1)] if hit else []
    with patch.object(source.http.client,'HTTPSConnection',Wire),patch.object(secret_scanning,'_scan_kingfisher',detector),\
            patch.object(secret_scanning,'_scan_trufflehog',detector):
        source.collect(reader,transport,[SUB],[profile['kind']],options)
    if not enabled:return reader,transport,None,None
    item=reader.collections[0]['items'][0]
    item['_provenance'].update(credential_context_id='cred',customer_context_id='cust')
    meta={**reader.ml_asset_secret_metadata,'context_binding':'scan_local','tenant_verified':True,'tenant_id':TENANT,
        'credential_context_id':'cred','customer_context_id':'cust'}
    index={'context':{'provider':'azure','scope':SUB,'metadata':meta},'collections':{profile['kind']:reader.collections}}
    result=review.code(item,index)
    return (reader,transport,item,result,index) if capture else (reader,transport,item,result)

def test_native_job_code_association_positive_clean():
    for hit,expected in ((False,'PASS'),(True,'FAIL')):
        reader,transport,item,result=run_case(hit=hit)
        assert result[0]==expected
        assert len(Wire.seen)==14 and len(transport.calls)==14
        assert Wire.seen[2][2]==JOB+'?api-version=2024-04-01'
        assert Wire.seen[-1][2]==Wire.seen[2][2]
        assert Wire.seen[7][3]['If-Match']=='"0x123ABC"'
        assert 'private-value' not in json.dumps([item,result])
        if hit:
            assert 'private-value' not in reader.configuration_secret_redactions  # found values are not redacted
            assert {d['engine'] for d in result[1]['secret_leaks'][0]['detectors']}=={'kingfisher','trufflehog'}
        assert all(response.closed for response in Wire.responses) and not Wire.plan

def test_foreign_and_changed_job_do_not_pass():
    assert run_case(hit=False,job_before='foreign')[3][0]=='UNKNOWN'
    assert run_case(hit=False,job_after='drift')[3][0]=='UNKNOWN'
    assert run_case(hit=True,job_after='drift')[3][0]=='FAIL'
    assert run_case(hit=True,denied=True)[3][0]=='UNKNOWN'

def test_default_off_and_scope_preflight():
    reader,transport,_,_=run_case(enabled=False)
    assert Wire.seen==[] and transport.calls==[] and reader.collections==[]
    profile=source.PROFILES['code'];options={'content_secret_scans':True,'_content_secret_scan_kinds':[profile['kind']],profile['option']:[TARGET]}
    assert source.selected_targets(options,[SUB],'code')==[TARGET]
    assert preflight.ml_asset.selected_targets(options,[SUB],'code')==[TARGET]
    bad={**TARGET,'job_resource_id':JOB.replace(SUB,'/subscriptions/66666666-6666-6666-6666-666666666666')}
    try:source.selected_targets({**options,profile['option']:[bad]},[SUB],'code')
    except ValueError:pass
    else:raise AssertionError('foreign job accepted')
    try:preflight.ml_asset.selected_targets({**options,profile['option']:[bad]},[SUB],'code')
    except ValueError:pass
    else:raise AssertionError('foreign job accepted by API preflight')

def test_cross_process_native_case_replay():
    document=json.loads((Path(__file__).resolve().parent/'fixtures/azure_ml_job_code_native_20261021.json').read_text())
    assert document['check_id']==source.PROFILES['code']['check'] and len(document['cases'])==6
    for case in document['cases']:
        assert review.code(case['item'],case['index'])[0]==case['expected']
