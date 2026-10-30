"""Read-only native Workbench response -> registered predicate contracts."""
from copy import deepcopy
import pytest
from peaso.checks import CHECKS
from peaso.collectors.gcp import GCPCollector, ReadError
from peaso.engine import evaluate_snapshot

SCOPE='projects/review'
NAME=SCOPE+'/locations/us-central1-a/instances/notebook'
PREFIX='gcp.review.workbench.'
LIST_URL='https://notebooks.googleapis.com/v2/'+SCOPE+'/locations/-/instances'
IAM_URL='https://notebooks.googleapis.com/v2/'+NAME+':getIamPolicy'

class Transport:
    def __init__(self, row, denied=False):
        self.row=row;self.denied=denied;self.calls=[]
    def request(self,method,url,**kwargs):
        self.calls.append((method,url))
        if url==IAM_URL:
            # 75087001 hydrates each listed instance's IAM policy once.
            assert method=='GET' and kwargs.get('params')=={'options.requestedPolicyVersion':3}
            return {'version':3,'bindings':[]},'iam-1'
        assert method=='GET' and url==LIST_URL
        if self.denied:
            error=ReadError('denied','api_error',http_status=403);error.request_id='read-1';raise error
        return {'instances':[deepcopy(self.row)]},'read-1'

def run(row, suffix, denied=False):
    transport=Transport(row,denied)
    connector={'provider':'gcp','scopes':[SCOPE],'options':{'inventories':['workbench_instance'],'include_inherited':False,'concurrency':1,'metrics_scopes':False}}
    snapshot=GCPCollector(connector,requirements=['workbench_instance'],transport=transport).collect()
    findings=evaluate_snapshot(snapshot,checks=[PREFIX+suffix])['findings']
    # One list read, plus one IAM read per listed instance in this project.
    iam=[('GET',IAM_URL)] if not denied and row.get('name')==NAME else []
    assert transport.calls==[('GET',LIST_URL)]+iam
    assert findings
    return findings,snapshot

@pytest.mark.parametrize('suffix,field,good,bad',[
    ('public_ip_disabled','disablePublicIp',True,False),
    ('root_access_disabled','metadata',{'notebook-disable-root':'true'},{'notebook-disable-root':'false'})])
@pytest.mark.parametrize('case,expected',[('good','PASS'),('bad','FAIL'),('omitted','FAIL'),('deleted','NOT_APPLICABLE'),('denied','DENIED'),('foreign','UNKNOWN'),('malformed','UNKNOWN')])
def test_public_native_response_consumed(suffix,field,good,bad,case,expected):
    row={'name':NAME,'state':'ACTIVE','gceSetup':{field:good}}
    if case=='bad':row['gceSetup'][field]=bad
    elif case=='omitted':row['gceSetup']={}
    elif case=='deleted':row['state']='DELETED'
    elif case=='foreign':row['name']=NAME.replace('/review/','/other/')
    elif case=='malformed':row['gceSetup'][field]=17
    findings,snapshot=run(row,suffix,case=='denied')
    assert {f['status'] for f in findings}=={expected},findings
    if case!='denied':
        native=next(e for e in snapshot['collections'] if e['type']=='workbench_instance')['items'][0]
        assert native['_provenance']['representation']=='full'

@pytest.mark.parametrize('suffix',['public_ip_disabled','root_access_disabled'])
def test_unproven_omission_cannot_be_defaulted(suffix):
    check=next(c for c in CHECKS if c.id==PREFIX+suffix)
    assert check.evaluate({'name':NAME,'state':'ACTIVE','gceSetup':{}},{'context':{'provider':'gcp','scope':SCOPE}})[0]=='UNKNOWN'

@pytest.mark.parametrize('suffix',['public_ip_disabled','root_access_disabled'])
def test_unrecognized_state_and_unreadable_setting(suffix):
    check=next(c for c in CHECKS if c.id==PREFIX+suffix)
    row={'name':NAME,'state':'NEW_UNKNOWN_STATE','gceSetup':{'disablePublicIp':True,'metadata':{'notebook-disable-root':'true'}}}
    index={'context':{'provider':'gcp','scope':SCOPE}}
    assert check.evaluate(row,index)[0]=='UNKNOWN'
    row['state']='ACTIVE';row['_coverage']={'gceSetup':{'status':'denied'}}
    assert check.evaluate(row,index)[0]=='UNKNOWN'
