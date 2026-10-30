"""Native selected content: normal package imports and bounded fake HTTP."""
import base64
import io
import json
import time
import unittest
import types
from copy import deepcopy
from unittest.mock import patch
from pathlib import Path
import pytest
from peaso import secret_scanning
from peaso import secret_evidence
from peaso.collectors import azure_selected_secret_integration_20261020 as integration
from peaso.collectors import azure_selected_storage_secret_indicators as storage
from peaso.collectors import azure_ml_selected_asset_secret_indicators as source
from peaso.checks import azure_ml_selected_asset_secret_review_20261020 as consumer
scanning=secret_scanning

SUB='/subscriptions/11111111-1111-1111-1111-111111111111';TENANT='22222222-2222-2222-2222-222222222222';OID='33333333-3333-3333-3333-333333333333'
WORKSPACE=SUB+'/resourceGroups/review/providers/Microsoft.MachineLearningServices/workspaces/selected';ASSET=WORKSPACE+'/environments/Build/versions/V1';ACCOUNT=SUB+'/resourceGroups/review/providers/Microsoft.Storage/storageAccounts/sourceaccount'
TARGET={'resource_id':ASSET,'datastore':'source_store','storage':{'service':'blob','resource_id':ACCOUNT,'container':'sources','object':'build/prod/Dockerfile','format':'text'}}
def jwt(aud):
    data={'aud':aud,'tid':TENANT,'oid':OID,'exp':int(time.time())+3600};return 'x.'+base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip('=')+'.x'
class Transport:
    tenant=verified_tenant=TENANT
    def __init__(self):self.aud=[]
    def token(self,aud):self.aud.append(aud);return jwt(aud)
class Response:
    def __init__(self,body,status=200,headers=None,head=False):
        self.raw=json.dumps(body).encode() if isinstance(body,dict) else body;self.stream=io.BytesIO(b''if head else self.raw);self.status=status;self.headers={'Content-Type':'application/json','Content-Length':str(len(self.raw)),'x-ms-request-id':'11111111-1111-4111-8111-111111111111',**(headers or{})};self.closed=False
    def getheader(self,n):return self.headers.get(n)
    def read(self,n):return self.stream.read(n)
    def close(self):self.closed=True
class HTTP:
    seen=[];plan=[];connections=[]
    def __init__(self,host,timeout):self.host=host;self.sock=None;self.closed=False;self.connections.append(self)
    def set_debuglevel(self,n):assert n==0
    def request(self,method,path,body=None,headers=None):
        assert body is None and method in ('GET','HEAD') and not path.startswith('//') and headers['Accept-Encoding']=='identity'
        token=headers['Authorization'][7:];data=json.loads(base64.urlsafe_b64decode(token.split('.')[1]+'='*(-len(token.split('.')[1])%4)))
        assert data['aud']==(storage.ARM if self.host=='management.azure.com' else storage.STORAGE)
        assert self.host in ('management.azure.com','sourceaccount.blob.core.windows.net')
        self.seen.append((method,self.host,path,headers))
    def getresponse(self):
        if not self.plan:raise AssertionError('unexpected HTTP request')
        return self.plan.pop(0)
    def close(self):self.closed=True
class Reader:
    def __init__(self,cancel=False):self.collections=[];self.configuration_secret_redactions=set();self.cancel=cancel
    def check_cancelled(self):
        if self.cancel:raise RuntimeError('cancelled')
    def call(self,fn,*args):return fn(*args)
    def run(self,tasks):
        for kind,scope,service,fetch in tasks:
            items=[item for page in fetch() for item in page]
            self.collections.append({'scope':scope,'service':service,'status':'collected','items':items,'_provenance':{'credential_context_id':'cred','customer_context_id':'cust'}})
class Cases(unittest.TestCase):
    def setUp(self):HTTP.seen=[];HTTP.connections=[];HTTP.plan=[];scanning._RESULTS.clear();self.responses=[]
    def response(self,*args,**kwargs):
        r=Response(*args,**kwargs);self.responses.append(r);return r
    def plan(self,value='RUN echo ready',change=None,denied=False,truncated=False,foreign=False,uri=None,object_id=None,redirect=False):
        HTTP.seen=[];HTTP.connections=[]
        sub={'id':SUB,'subscriptionId':SUB.split('/')[-1],'tenantId':TENANT,'state':'Enabled'}
        ws={'id':WORKSPACE,'name':'selected','type':source.SERVICE+'/workspaces','properties':{'tenantId':TENANT,'workspaceId':'44444444-4444-4444-4444-444444444444','provisioningState':'Succeeded'}}
        build={'contextUri':uri or 'azureml://datastores/source_store/paths/build/','dockerfilePath':'prod/Dockerfile'}
        asset={'id':ASSET,'name':'V1','type':source.SERVICE+'/workspaces/environments/versions','properties':{'build':build,'provisioningState':'Succeeded'}}
        ds={'id':WORKSPACE+'/datastores/source_store','name':'source_store','type':source.SERVICE+'/workspaces/datastores','properties':{'datastoreType':'AzureBlob','accountName':'sourceaccount','containerName':'sources','endpoint':'core.windows.net','protocol':'https','subscriptionId':SUB.split('/')[-1],'resourceGroup':'review','credentials':{'credentialsType':'None','secrets':{'secretsType':'None'}}}}
        account={'id':object_id or ACCOUNT,'name':'sourceaccount','type':'Microsoft.Storage/storageAccounts','properties':{'provisioningState':'Succeeded','primaryEndpoints':{'blob':'https://sourceaccount.blob.core.windows.net/'}}}
        raw=value.encode();hdr={'Content-Type':'application/octet-stream','ETag':'"0x123ABC"','x-ms-version':storage.DATA_VERSION,'x-ms-blob-type':'BlockBlob'}
        after_hdr={**hdr,'ETag':'"0x999"'}if change=='object'else hdr
        after_asset=json.loads(json.dumps(asset));after_ds=json.loads(json.dumps(ds));after_ws=json.loads(json.dumps(ws))
        if change=='asset':after_asset['properties']['build']['dockerfilePath']='other/Dockerfile'
        if change=='datastore':after_ds['properties']['containerName']='elsewhere'
        if change=='workspace':after_ws['properties']['workspaceId']='55555555-5555-5555-5555-555555555555'
        if foreign:asset['id']=asset['id'].replace(SUB,'/subscriptions/66666666-6666-6666-6666-666666666666')
        self.responses=[]
        self.responses.extend([self.response(sub),self.response(ws),self.response(asset),self.response(ds),self.response(account),
            self.response(raw,headers=hdr,head=True),self.response({'error':'denied'},status=403)if denied else self.response(raw,headers={'Content-Type':'application/octet-stream',**hdr},head=False),
            self.response(raw,headers=after_hdr,head=True),self.response(after_ds),self.response(after_asset),self.response(after_ds),self.response(after_ws)])
        if truncated:self.responses[6].headers['Content-Length']=str(len(raw)+1)
        if redirect:self.responses[6].status=302;self.responses[6].headers['Location']='https://evil.invalid/Dockerfile'
        HTTP.plan=self.responses[:]
    def collect(self,secret=None,partial=False,enabled=True,cancel=False,target=TARGET):
        reader=Reader(cancel);transport=Transport();p=source.PROFILES['environment'];opts={'content_secret_scans':enabled,'_content_secret_scan_kinds':[p['kind']]if enabled else[],p['option']:[target]}
        def detector(raw,path,timeout):return [(secret,'rule',1)]if secret else []
        def other(raw,path,timeout):
            if partial:raise RuntimeError('detector unavailable')
            return detector(raw,path,timeout)
        with patch.object(source.http.client,'HTTPSConnection',HTTP),patch.object(scanning,'_scan_kingfisher',detector),patch.object(scanning,'_scan_trufflehog',other):source.collect(reader,transport,[SUB],[p['kind']],opts)
        if not enabled:return reader,transport,None,None
        item=reader.collections[0]['items'][0];item['_provenance'].update(credential_context_id='cred',customer_context_id='cust')
        meta={**reader.ml_asset_secret_metadata,'context_binding':'scan_local','tenant_verified':True,'tenant_id':TENANT,'credential_context_id':'cred','customer_context_id':'cust'}
        index={'context':{'provider':'azure','scope':SUB,'metadata':meta},'collections':{p['kind']:reader.collections}}
        return reader,transport,item,consumer.environment(item,index)
    def test_positive_clean_private_union(self):
        for value,secret,expected in [('RUN echo ready',None,'PASS'),('ENV TOKEN=private-secret','private-secret','FAIL')]:
            with self.subTest(expected=expected):
                self.plan(value);reader,transport,item,(status,result)=self.collect(secret=secret)
                self.assertEqual(status,expected);self.assertTrue(result['complete']);self.assertEqual(len(HTTP.seen),12)
                self.assertEqual([x[1]for x in HTTP.seen],[*['management.azure.com']*5,*['sourceaccount.blob.core.windows.net']*3,*['management.azure.com']*4])
                self.assertEqual([(x[0],x[2])for x in HTTP.seen],[('GET',SUB+'?api-version=2022-12-01'),
                    ('GET',WORKSPACE+'?api-version='+source.WORKSPACE_API),('GET',ASSET+'?api-version='+source.API),
                    ('GET',WORKSPACE+'/datastores/source_store?api-version='+source.API),('GET',ACCOUNT+'?api-version='+storage.ARM_VERSION),
                    ('HEAD','/sources/build/prod/Dockerfile'),('GET','/sources/build/prod/Dockerfile'),('HEAD','/sources/build/prod/Dockerfile'),
                    ('GET',WORKSPACE+'/datastores/source_store?api-version='+source.API),('GET',ASSET+'?api-version='+source.API),
                    ('GET',WORKSPACE+'/datastores/source_store?api-version='+source.API),('GET',WORKSPACE+'?api-version='+source.WORKSPACE_API)])
                self.assertEqual(HTTP.seen[6][3]['If-Match'],'"0x123ABC"')
                self.assertNotIn(value,json.dumps([item,result]));self.assertTrue(all(r.closed for r in self.responses));self.assertTrue(all(c.closed for c in HTTP.connections))
                if secret:
                    self.assertEqual({d['engine']for d in result['secret_leaks'][0]['detectors']},{'kingfisher','trufflehog'})
                    # Found values stay visible to the owner: nothing is queued for redaction.
                    self.assertNotIn(secret,reader.configuration_secret_redactions)
                    safe=source.final_snapshot(reader,{'metadata':{'ordinary_alias':secret},'collections':reader.collections})
                    self.assertIn(secret,json.dumps(safe));self.assertEqual(reader.configuration_secret_redactions,set())
    def test_incomplete_positive_and_clean_unknown(self):
        self.plan('ENV TOKEN=private-secret');_,_,_,(status,result)=self.collect(secret='private-secret',partial=True)
        self.assertEqual(status,'FAIL');self.assertFalse(result['complete'])
        self.plan();_,_,_,(status,_)=self.collect(partial=True);self.assertEqual(status,'UNKNOWN')
    def test_binding_failures(self):
        for kw in ({'foreign':True},{'denied':True},{'truncated':True},{'redirect':True},{'change':'object'},{'change':'asset'},{'change':'datastore'},{'change':'workspace'},
                   {'uri':'https://evil.invalid/sources/build/'},{'uri':'https://sourceaccount.blob.core.windows.net/foreign/build/'},{'uri':'azureml://datastores/source_store/paths/build/../'},
                   {'object_id':ACCOUNT.replace(SUB,'/subscriptions/66666666-6666-6666-6666-666666666666')}):
            with self.subTest(kw=kw):
                self.plan('ENV TOKEN=private-secret',**kw);_,_,item,(status,_)=self.collect(secret='private-secret')
                self.assertEqual(status,'UNKNOWN');self.assertFalse(item[source.MARKER]['complete'])
    def test_cancel_disabled_and_selectors(self):
        self.plan();_,transport,_,_=self.collect(enabled=False);self.assertEqual(HTTP.seen,[]);self.assertEqual(transport.aud,[])
        self.plan();_,transport,_,(status,_)=self.collect(cancel=True);self.assertEqual(status,'UNKNOWN');self.assertEqual(HTTP.seen,[])
        p=source.PROFILES['environment'];opts={'content_secret_scans':True,'_content_secret_scan_kinds':[p['kind']],p['option']:[TARGET]}
        self.assertEqual(source.selected_targets(opts,[SUB],'environment'),[TARGET])
        for bad in ({**TARGET,'storage':{**TARGET['storage'],'object':'build/../prod/Dockerfile'}},
                    {**TARGET,'storage':{**TARGET['storage'],'resource_id':ACCOUNT.replace(SUB,'/subscriptions/66666666-6666-6666-6666-666666666666')}},
                    {**TARGET,'storage':{**TARGET['storage'],'service':'file'}},):
            with self.subTest(bad=bad),self.assertRaises(ValueError):source.selected_targets({**opts,p['option']:[bad]},[SUB],'environment')
        with self.assertRaises(ValueError):source.selected_targets({**opts,p['option']:[TARGET]*5},[SUB],'environment')
if __name__=='__main__':unittest.main(verbosity=2)
