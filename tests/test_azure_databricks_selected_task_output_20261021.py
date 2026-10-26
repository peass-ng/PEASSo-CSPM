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
from peaso.collectors import azure_databricks_notebook_secret_indicators as source
from peaso.checks import azure_databricks_notebook_secret_review_20261020 as check
captured_union=[]
@pytest.fixture(autouse=True)
def observe_transient_union(monkeypatch):
    captured_union.clear()
    original=integration.storage.final_snapshot
    def observe(reader,snapshot):
        captured_union.append(set(getattr(reader,'storage_source_secret_redactions',())))
        return original(reader,snapshot)
    monkeypatch.setattr(integration.storage,'final_snapshot',observe)

TENANT='11111111-1111-1111-1111-111111111111'
SUB='/subscriptions/'+TENANT
RID=SUB+'/resourceGroups/review/providers/Microsoft.Databricks/workspaces/selected'
HOST='adb-12345.12.azuredatabricks.net'
TARGET={'workspace_resource_id':RID,'job_id':66,'parent_run_id':77,'task_run_id':88,'task_key':'selected_task','content':'notebook_result'}

def jwt(audience):
    claims={'tid':TENANT,'oid':'22222222-2222-2222-2222-222222222222','appid':'33333333-3333-3333-3333-333333333333','aud':audience,'exp':int(time.time())+3600}
    return 'x.'+base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip('=')+'.x'
class Transport:
    tenant=verified_tenant=TENANT;auth={}
    def __init__(self):self.audiences=[]
    def token(self,audience):self.audiences.append(audience);return jwt(audience)
class Response:
    def __init__(self,status,body,headers=None):
        self.status=status;self.body=json.dumps(body).encode();self.offset=0
        self.headers={'Content-Type':'application/json','Content-Length':str(len(self.body)),**(headers or {})}
    def getheader(self,name):return self.headers.get(name)
    def read(self,n):part=self.body[self.offset:self.offset+n];self.offset+=len(part);return part
    def close(self):pass
class HTTP:
    plan=[];seen=[]
    def __init__(self,host,timeout):self.host=host;self.sock=None
    def set_debuglevel(self,n):assert n==0
    def request(self,method,path,body,headers):
        assert method=='GET' and body is None and headers['Authorization'].startswith('Bearer ')
        assert not path.startswith('//')
        token=headers['Authorization'][7:]
        encoded=token.split('.')[1]
        claims=json.loads(base64.urlsafe_b64decode(encoded+'='*(-len(encoded)%4)))
        assert claims['aud']==(source.ARM if self.host=='management.azure.com' else source.DATABRICKS)
        self.seen.append((self.host,path))
    def getresponse(self):
        if not self.plan:raise AssertionError('unexpected_request')
        return self.plan.pop(0)
    def close(self):pass
class Reader:
    def __init__(self,cancel_at=None):self.collections=[];self.cancel_at=cancel_at;self.cancellations=0
    def check_cancelled(self):
        self.cancellations+=1
        if self.cancel_at and self.cancellations>=self.cancel_at:raise RuntimeError('cancelled')
    def call(self,fn,*args):return fn(*args)
    def run(self,tasks):
        for kind,scope,service,fetch in tasks:
            items=[item for page in fetch() for item in page]
            self.collections.append({'kind':kind,'scope':scope,'service':service,'status':'collected','items':items,
                '_provenance':{'credential_context_id':'cred','customer_context_id':'cust'}})
class Cases(unittest.TestCase):
    def setUp(self):HTTP.plan=[];HTTP.seen=[];secret_scanning._RESULTS.clear()
    def plan(self,value='ordinary output',*,content='notebook_result',truncated=False,denied=False,foreign=False,change=None,partial_wire=False):
        workspace={'id':RID,'name':'selected','type':'Microsoft.Databricks/workspaces',
            'properties':{'workspaceId':'12345','workspaceUrl':'other.example.com' if foreign else HOST,'provisioningState':'Succeeded'}}
        task={'run_id':88,'job_id':66,'task_key':'selected_task','start_time':100,'end_time':200,
            'state':{'life_cycle_state':'TERMINATED','result_state':'SUCCESS'},
            ('notebook_task' if content=='notebook_result' else 'spark_python_task'):{} }
        parent={'run_id':77,'job_id':66,'start_time':90,'end_time':210,
            'state':{'life_cycle_state':'TERMINATED','result_state':'SUCCESS'},'tasks':[task]}
        output={'metadata':task,**({'notebook_output':{'result':value,'truncated':truncated}}
            if content=='notebook_result' else {'logs':value,'logs_truncated':truncated})}
        parent_after=json.loads(json.dumps(parent));task_after=json.loads(json.dumps(task));workspace_after=json.loads(json.dumps(workspace))
        if change=='parent':parent_after['end_time']=211
        if change=='task':task_after['end_time']=201
        if change=='workspace':workspace_after['properties']['workspaceId']='12346'
        if change=='owner':parent_after['tasks'][0]['run_id']=89
        HTTP.plan=[Response(200,{'id':SUB,'subscriptionId':TENANT,'tenantId':TENANT,'state':'Enabled'}),
            Response(200,workspace),Response(200,parent),Response(200,task),
            Response(403,{'error_code':'DENIED'}) if denied else Response(200,output,{'Content-Length':'9999999'} if partial_wire else None),
            Response(200,task_after),Response(200,parent_after),Response(200,workspace_after)]
    def collect(self,*,secret=None,other_unavailable=False,selected=True,cancel_at=None,target=TARGET):
        reader=Reader(cancel_at);transport=Transport()
        opts={'content_secret_scans':selected,'_content_secret_scan_kinds':[source.KIND] if selected else [],source.RUN_OPTION:[target]}
        def detector(payload,path,timeout):return [(secret,'Rule',1)] if secret else []
        def other(payload,path,timeout):
            if other_unavailable:raise RuntimeError('engine unavailable')
            return detector(payload,path,timeout)
        with patch.object(source.http.client,'HTTPSConnection',HTTP),patch.object(secret_scanning,'_scan_kingfisher',detector),patch.object(secret_scanning,'_scan_trufflehog',other):
            source.collect(reader,transport,[SUB],[source.KIND],opts)
        if not selected:return reader,transport,None,None
        item=reader.collections[0]['items'][0]
        meta={**reader.databricks_notebook_secret_metadata,'context_binding':'scan_local','tenant_verified':True,'tenant_id':TENANT,
            'credential_context_id':'cred','customer_context_id':'cust'}
        item['_provenance'].update(credential_context_id='cred',customer_context_id='cust')
        index={'context':{'provider':'azure','scope':SUB,'metadata':meta},'collections':{source.KIND:reader.collections}}
        return reader,transport,item,check.evaluate(item,index)
    def test_clean_result_exact_native_sequence(self):
        self.plan();reader,transport,item,(status,result)=self.collect()
        self.assertEqual(status,'PASS');self.assertTrue(result['complete'])
        self.assertEqual(transport.audiences,[source.ARM]*2+[source.DATABRICKS]*5+[source.ARM])
        self.assertEqual(HTTP.seen,[('management.azure.com',SUB+'?api-version=2022-12-01'),
            ('management.azure.com',RID+'?api-version='+source.API),
            (HOST,'/api/2.2/jobs/runs/get?run_id=77'),(HOST,'/api/2.2/jobs/runs/get?run_id=88'),
            (HOST,'/api/2.2/jobs/runs/get-output?run_id=88'),(HOST,'/api/2.2/jobs/runs/get?run_id=88'),
            (HOST,'/api/2.2/jobs/runs/get?run_id=77'),('management.azure.com',RID+'?api-version='+source.API)])
        self.assertNotIn('ordinary output',json.dumps(item)+json.dumps(result))
    def test_truncated_positive_and_clean_unknown(self):
        self.plan('token=example-secret',truncated=True);reader,_,item,(status,result)=self.collect(secret='example-secret')
        self.assertEqual(status,'FAIL');self.assertFalse(result['complete']);self.assertEqual(len(result['secret_leaks']),1)
        self.assertEqual({d['engine'] for d in result['secret_leaks'][0]['detectors']},{'kingfisher','trufflehog'})
        self.assertNotIn('example-secret',json.dumps(item)+json.dumps(result))
        # Found values stay visible: nothing is queued for redaction.
        self.assertNotIn('example-secret',reader.configuration_secret_redactions)
        snapshot=source.final_snapshot(reader,{'metadata':{},'collections':reader.collections})
        self.assertNotIn('example-secret',captured_union[-1])
        self.assertEqual(reader.configuration_secret_redactions,set())
        self.assertNotIn('example-secret',json.dumps(snapshot))
        self.plan(truncated=True);_,_,_,(status,result)=self.collect();self.assertEqual(status,'UNKNOWN')
    def test_log_sample_and_partial_engine(self):
        self.plan('token=log-secret',content='task_logs');_,_,_,(status,result)=self.collect(secret='log-secret',other_unavailable=True,target={**TARGET,'content':'task_logs'})
        self.assertEqual(status,'FAIL');self.assertFalse(result['complete'])
        self.assertEqual([d['engine'] for d in result['secret_leaks'][0]['detectors']],['kingfisher'])
        self.plan('ordinary log',content='task_logs');_,_,_,(status,result)=self.collect(target={**TARGET,'content':'task_logs'})
        self.assertEqual(status,'PASS');self.assertTrue(result['complete'])
    def test_denied_wire_change_foreign_and_cancellation(self):
        for kwargs in ({'denied':True},{'partial_wire':True},{'change':'task'},{'change':'parent'},
                       {'change':'workspace'},{'change':'owner'},{'foreign':True}):
            with self.subTest(kwargs=kwargs):
                self.plan(**kwargs);HTTP.seen=[];_,_,item,(status,_)=self.collect()
                self.assertEqual(status,'UNKNOWN');self.assertFalse(item[source.MARKER]['complete'])
                if kwargs.get('foreign'):self.assertEqual(len(HTTP.seen),2)
        self.plan();HTTP.seen=[];_,_,item,(status,_)=self.collect(cancel_at=1)
        self.assertEqual(status,'UNKNOWN');self.assertEqual(HTTP.seen,[])
    def test_disabled_and_selector_rejections(self):
        self.plan();reader,transport,_,_=self.collect(selected=False)
        self.assertEqual(HTTP.seen,[]);self.assertEqual(transport.audiences,[])
        self.plan();reader=Reader();transport=Transport()
        source.collect(reader,transport,[SUB],[source.KIND],{'content_secret_scans':True,'_content_secret_scan_kinds':[],source.RUN_OPTION:[TARGET]})
        self.assertEqual(HTTP.seen,[]);self.assertEqual(transport.audiences,[])
        opts={source.RUN_OPTION:[TARGET],'content_secret_scans':True,'_content_secret_scan_kinds':[source.KIND]}
        self.assertEqual(source.selected_targets(opts,[SUB]),[TARGET])
        for replacement in ({'task_run_id':77},{'parent_run_id':88},{'task_run_id':'88'},
                            {'task_key':'../bad'},{'content':'all_logs'},
                            {'workspace_resource_id':RID.replace('/subscriptions/'+TENANT,'/subscriptions/00000000-0000-0000-0000-000000000000')}):
            with self.subTest(replacement=replacement),self.assertRaises(ValueError):
                source.selected_targets({**opts,source.RUN_OPTION:[{**TARGET,**replacement}]},[SUB])
if __name__=='__main__':unittest.main(verbosity=2)
