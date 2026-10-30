"""Selected Synapse source through normal runtime modules and bounded fake HTTP."""
import base64, io, json, time, types, unittest
from pathlib import Path
from unittest.mock import patch
from peaso import secret_scanning as scanning
from peaso.collectors import azure_selected_secret_integration_20261020 as integration
from peaso.collectors import azure_synapse_selected_notebook_secret_indicators as source
from peaso.checks import azure_synapse_selected_notebook_secret_review_20261021 as consumer
from peaso.checks import catalog
ROOT=Path(__file__).resolve().parents[1]
CANDIDATE=ROOT
SUB='/subscriptions/11111111-1111-1111-1111-111111111111';TENANT='22222222-2222-2222-2222-222222222222';OID='33333333-3333-3333-3333-333333333333';CLIENT='44444444-4444-4444-4444-444444444444'
RID=SUB+'/resourceGroups/review/providers/Microsoft.Synapse/workspaces/selected';HOST='selected.dev.azuresynapse.net';NAME='NotebookOne';TARGET={'workspace_resource_id':RID,'notebook_name':NAME};SECRET='private-secret-value'
def jwt(aud):
    data={'tid':TENANT,'oid':OID,'appid':CLIENT,'aud':aud,'exp':int(time.time())+3600}
    return 'x.'+base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip('=')+'.x'
class Transport:
    tenant=verified_tenant=TENANT;auth={}
    def __init__(self):self.aud=[]
    def token(self,aud):self.aud.append(aud);return jwt(aud)
class Response:
    def __init__(self,payload,status=200,headers=None):
        self.raw=json.dumps(payload).encode();self.stream=io.BytesIO(self.raw);self.status=status;self.closed=False
        self.headers={'Content-Type':'application/json','Content-Length':str(len(self.raw)),'x-ms-request-id':'11111111-1111-4111-8111-111111111111',**(headers or{})}
    def getheader(self,n):return self.headers.get(n)
    def read(self,n):return self.stream.read(n)
    def close(self):self.closed=True
class HTTP:
    plan=[];seen=[];connections=[]
    def __init__(self,host,timeout):
        assert host in('management.azure.com',HOST);self.host=host;self.sock=None;self.closed=False;self.connections.append(self)
    def set_debuglevel(self,n):assert n==0
    def request(self,method,path,body=None,headers=None):
        assert method=='GET'and body is None and headers['Accept-Encoding']=='identity'and not path.startswith('//')
        token=headers['Authorization'][7:];encoded=token.split('.')[1];claims=json.loads(base64.urlsafe_b64decode(encoded+'='*(-len(encoded)%4)))
        assert claims['aud']==(source.ARM if self.host=='management.azure.com'else source.SYNAPSE)
        self.seen.append((self.host,path))
    def getresponse(self):
        if not self.plan:raise AssertionError('unexpected request')
        return self.plan.pop(0)
    def close(self):self.closed=True
class Reader:
    def __init__(self,cancel=False):self.collections=[];self.configuration_secret_redactions=set();self.cancel=cancel
    def check_cancelled(self):
        if self.cancel:raise RuntimeError('cancelled')
    def call(self,fn,*args):return fn(*args)
    def run(self,tasks):
        for kind,scope,service,fetch in tasks:
            items=[item for page in fetch()for item in page]
            self.collections.append({'scope':scope,'service':service,'status':'collected','items':items,'_provenance':{'credential_context_id':'cred','customer_context_id':'cust'}})
class Cases(unittest.TestCase):
    def setUp(self):HTTP.plan=[];HTTP.seen=[];HTTP.connections=[];scanning._RESULTS.clear();self.responses=[]
    def plan(self,value='print("hello")',*,denied=False,truncated=False,redirect=False,foreign=False,change=None,etag_header=False,nested_partial=False):
        HTTP.seen=[];HTTP.connections=[]
        sub={'id':SUB,'subscriptionId':SUB.split('/')[-1],'tenantId':TENANT,'state':'Enabled'}
        ws={'id':RID,'name':'selected','type':'Microsoft.Synapse/workspaces','identity':{'tenantId':TENANT},
            'properties':{'provisioningState':'Succeeded','connectivityEndpoints':{'dev':'https://evil.invalid'if foreign else'https://'+HOST}}}
        nb={'id':RID+'/notebooks/'+NAME,'name':NAME,'type':'Microsoft.Synapse/workspaces/Notebooks','etag':'1500504f-0000-0200-0000-5cbe090f0000',
            'properties':{'nbformat':4,'cells':[{'cell_type':'code','source':['x = "'+value+'"'],'outputs':[{'text':SECRET}]}]}}
        after_nb=json.loads(json.dumps(nb));after_ws=json.loads(json.dumps(ws))
        if change=='etag':after_nb['etag']='1500504f-0000-0200-0000-5cbe090f0001'
        if change=='notebook':after_nb['properties']['cells'][0]['source']=['different source']
        if change=='owner':after_nb['id']=RID+'/notebooks/Other'
        if change=='workspace':after_ws['identity']['tenantId']='55555555-5555-5555-5555-555555555555'
        if nested_partial:nb['properties']['partial']=True
        self.responses=[Response(sub),Response(ws),Response(nb),Response(after_nb),Response(after_ws)]
        if denied:self.responses[2]=Response({'error':'denied'},status=403)
        if truncated:self.responses[2].headers['Content-Length']=str(len(self.responses[2].raw)+1)
        if redirect:self.responses[2].headers['Location']='https://evil.invalid/notebook'
        if etag_header:self.responses[2].headers['ETag']='"wrong"'
        HTTP.plan=self.responses[:]
    def collect(self,secret=None,partial=False,enabled=True,cancel=False,target=TARGET):
        reader=Reader(cancel);transport=Transport();opts={'content_secret_scans':enabled,'_content_secret_scan_kinds':[source.KIND]if enabled else[],source.OPTION:[target]}
        def hit(raw,path,timeout):return[(secret,'rule',1)]if secret else[]
        def other(raw,path,timeout):
            if partial:raise RuntimeError('unavailable')
            return hit(raw,path,timeout)
        with patch.object(source.http.client,'HTTPSConnection',HTTP),patch.object(scanning,'_scan_kingfisher',hit),patch.object(scanning,'_scan_trufflehog',other):source.collect(reader,transport,[SUB],[source.KIND],opts)
        if not enabled:return reader,transport,None,None,None
        item=reader.collections[0]['items'][0];item['_provenance'].update(credential_context_id='cred',customer_context_id='cust')
        meta={**reader.synapse_notebook_secret_metadata,'context_binding':'scan_local','tenant_verified':True,'tenant_id':TENANT,'credential_context_id':'cred','customer_context_id':'cust'}
        index={'context':{'provider':'azure','scope':SUB,'metadata':meta},'collections':{source.KIND:reader.collections}}
        return reader,transport,item,index,consumer.evaluate(item,index)
    def test_positive_clean_private_and_exact_sequence(self):
        for value,secret,status in [('ordinary cell',None,'PASS'),(SECRET,SECRET,'FAIL')]:
            with self.subTest(status=status):
                self.plan(value);reader,transport,item,index,result=self.collect(secret=secret)
                self.assertEqual(result[0],status);self.assertTrue(result[1]['complete'])
                self.assertEqual(HTTP.seen,[('management.azure.com',SUB+'?api-version=2022-12-01'),('management.azure.com',RID+'?api-version='+source.ARM_API),
                    (HOST,'/notebooks/'+NAME+'?api-version='+source.DATA_API),(HOST,'/notebooks/'+NAME+'?api-version='+source.DATA_API),
                    ('management.azure.com',RID+'?api-version='+source.ARM_API)])
                self.assertEqual(transport.aud,[source.ARM,source.ARM,source.SYNAPSE,source.SYNAPSE,source.ARM])
                self.assertNotIn(value,json.dumps([item,index,result]));self.assertTrue(all(r.closed for r in self.responses));self.assertTrue(all(c.closed for c in HTTP.connections))
                if secret:
                    self.assertEqual({d['engine']for d in result[1]['secret_leaks'][0]['detectors']},{'kingfisher','trufflehog'})
                    self.assertNotIn(secret,json.dumps(item))
    def test_partial_positive_clean_unknown(self):
        self.plan(SECRET);_,_,_,_,result=self.collect(secret=SECRET,partial=True);self.assertEqual(result[0],'FAIL');self.assertFalse(result[1]['complete'])
        self.plan();_,_,_,_,result=self.collect(partial=True);self.assertEqual(result[0],'UNKNOWN')
    def test_unbound_denied_truncated_changed(self):
        for kw in ({'denied':True},{'truncated':True},{'redirect':True},{'foreign':True},{'etag_header':True},{'nested_partial':True},{'change':'etag'},{'change':'notebook'},{'change':'owner'},{'change':'workspace'}):
            with self.subTest(kw=kw):
                self.plan(SECRET,**kw);_,_,item,_,result=self.collect(secret=SECRET)
                self.assertEqual(result[0],'UNKNOWN');self.assertFalse(item[source.MARKER]['complete'])
                if kw.get('foreign'):self.assertEqual(len(HTTP.seen),2)
    def test_disabled_cancel_and_selection(self):
        self.plan();_,transport,_,_,_=self.collect(enabled=False);self.assertEqual(HTTP.seen,[]);self.assertEqual(transport.aud,[])
        self.plan();reader=Reader();transport=Transport()
        source.collect(reader,transport,[SUB],[source.KIND],{'content_secret_scans':True,'_content_secret_scan_kinds':[],source.OPTION:[TARGET]})
        self.assertEqual(HTTP.seen,[]);self.assertEqual(transport.aud,[])
        self.plan();_,_,_,_,result=self.collect(cancel=True);self.assertEqual(result[0],'UNKNOWN');self.assertEqual(HTTP.seen,[])
        opts={'content_secret_scans':True,'_content_secret_scan_kinds':[source.KIND],source.OPTION:[TARGET]}
        self.assertEqual(source.selected_targets(opts,[SUB]),[TARGET])
        for bad in ({**TARGET,'workspace_resource_id':RID.replace(SUB,'/subscriptions/55555555-5555-5555-5555-555555555555')},
                    {**TARGET,'notebook_name':'../Other'},{**TARGET,'notebook_name':'https://evil.invalid/Other'}):
            with self.subTest(bad=bad),self.assertRaises(ValueError):source.selected_targets({**opts,source.OPTION:[bad]},[SUB])
        with self.assertRaises(ValueError):source.selected_targets({**opts,source.OPTION:[TARGET]*5},[SUB])
    def test_capture_portable_cases(self):
        cases=[]
        for label,kw,secret in [('pass',{},None),('fail',{},SECRET),('unknown',{'denied':True},None)]:
            self.plan(SECRET if secret else'ordinary',**kw);_,_,item,index,result=self.collect(secret=secret)
            cases.append({'label':label,'expected':result[0],'item':item,'index':index})
        cases.append({'label':'missing_item','expected':'UNKNOWN','item':{},'index':cases[0]['index']})
        replay=json.loads(json.dumps(cases))
        for row in replay:
            self.assertEqual(consumer.evaluate(row['item'],row['index'])[0],row['expected'])
        self.assertNotIn(SECRET,json.dumps(replay))
    def test_public_description_has_exact_references(self):
        row=catalog._base_description_for(source.CHECK)
        self.assertEqual(row['ui_group'],'Secrets')
        self.assertEqual(row['requirements'],[])
        self.assertTrue(all(x.startswith('https://learn.microsoft.com/')for x in row['references']))
if __name__=='__main__':unittest.main(verbosity=2)
