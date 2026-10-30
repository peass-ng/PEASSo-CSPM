"""Native Docker assessment metadata reads: exact IDs, no verdict fabrication."""
from copy import deepcopy
from urllib.parse import urlsplit,parse_qs
import json
import pytest
from peaso.collectors import azure,azure_docker_assessment_native as n
SCOPE='/subscriptions/11111111-1111-1111-1111-111111111111'
VM=SCOPE+'/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm'
RID=VM+'/providers/Microsoft.Security/assessments/'+n.KEY

def row():
    return {'id':RID,'name':n.KEY,'type':'Microsoft.Security/assessments','properties':{
        'resourceDetails':{'source':'Azure','id':VM},'status':{'code':'Unhealthy'},
        'metadata':{'assessmentType':'BuiltIn','policyDefinitionId':n.POLICY}}}

def reader():
    r=azure._Reader({'retries':0,'concurrency':1})
    r.collections=[{'type':'vm','scope':SCOPE,'status':'collected','items':[{'id':VM}]},
                   {'type':'security_assessment','scope':SCOPE,'status':'collected','items':[row()]}]
    return r

def run(r,response,wanted=None):
    calls=[]
    def request(url):
        calls.append(url)
        if isinstance(response,Exception):raise response
        return deepcopy(response)
    n.collect(r,request,[SCOPE],{'vm','security_assessment'} if wanted is None else wanted,'capture','customer')
    return r.collections[1]['items'][0],calls

def test_metadata_get_is_exact_read_and_projection_has_actual_capture_without_secret_or_guest_claim():
    r=reader();original=deepcopy(r.collections);response=row()
    response['properties']['metadata']['partnerData']={'secret':'never-retain'}
    response['properties']['ignoredSecret']='never-retain'
    actual,calls=run(r,response)
    assert len(calls)==1 and urlsplit(calls[0]).path==RID
    assert parse_qs(urlsplit(calls[0]).query)=={'api-version':[n.VERSION],'$expand':['metadata']}
    assert actual['properties']['metadata']==original[1]['items'][0]['properties']['metadata']
    proof=actual['_provenance'];assert proof['source_operation']=='Assessments_Get' and proof['read_only'] is True
    assert proof['credential_context_id']=='capture' and proof['customer_context_id']=='customer'
    assert proof['metadata_expanded'] is True and proof['scope']==SCOPE
    assert 'observed_at' in proof and 'never-retain' not in json.dumps(r.collections)
    assert not {'applicable','complete','healthy','allRulesScanned'}&proof.keys()
    assert original[1]['items'][0].get('_provenance') is None

def test_unrequested_metadata_or_unrecognized_assessment_makes_no_requests():
    for wanted in [set(),{'vm'},{'security_assessment'}]:
        _,calls=run(reader(),row(),wanted);assert calls==[]
    r=reader();r.collections[1]['items'][0]['name']='another-key'
    _,calls=run(r,row());assert calls==[]

@pytest.mark.parametrize('failure',['denied','missing_metadata','foreign_id','foreign_vm','foreign_name','unknown_status'])
def test_unavailable_or_mismatched_get_cannot_reuse_old_metadata_or_claim_get_success(failure):
    response=row()
    if failure=='denied':response=azure.AzureReadError('denied',403)
    elif failure=='missing_metadata':response['properties'].pop('metadata')
    elif failure=='foreign_id':response['id']=RID.replace('/vm/','/another/')
    elif failure=='foreign_vm':response['properties']['resourceDetails']['id']=VM+'other'
    elif failure=='foreign_name':response['name']='another-key'
    elif failure=='unknown_status':response['properties']['status']['code']='Unknown'
    actual,calls=run(reader(),response)
    assert len(calls)==1
    assert actual['properties']['_coverage']['metadata']['status']=='not_collected'
    assert 'metadata' not in actual['properties'] and '_provenance' not in actual
    assert actual['properties']['status']['code']=='Unhealthy'

def test_partial_or_foreign_roster_and_shared_call_limit_do_not_make_metadata_claims():
    r=reader();r.collections[0]['status']='partial';_,calls=run(r,row());assert calls==[]
    r=reader();r.collections[1]['scope']='/subscriptions/other';_,calls=run(r,row());assert calls==[]
    r=reader();r.budget.max_calls=0;actual,calls=run(r,row());assert calls==[]
    assert actual['properties']['_coverage']['metadata']['status']=='not_collected'
    assert actual['properties']['_coverage']['metadata']['error']=={'code':'call_limit'}

def test_normal_collect_live_uses_same_native_get_and_scope_capture_without_secret_reads(monkeypatch):
    from peaso.collectors import collect_live
    class Transport:
        tenant=verified_tenant='22222222-2222-2222-2222-222222222222'
        def __init__(self):self.calls=[]
        def close(self):pass
        def request(self,url,*,body=None,audience=azure.ARM):
            assert body is None
            self.calls.append(url);path=urlsplit(url).path
            if path==SCOPE+'/providers/Microsoft.Compute/virtualMachines':
                return {'value':[{'id':VM,'name':'vm','type':'Microsoft.Compute/virtualMachines','properties':{}}]}
            if path==VM:return {'id':VM,'name':'vm','type':'Microsoft.Compute/virtualMachines','properties':{},'instanceView':{}}
            if path==SCOPE+'/providers/Microsoft.Security/assessments':
                value=row();value['properties'].pop('metadata');return {'value':[value]}
            if path==RID:return row()
            return {'value':[]}
    t=Transport();monkeypatch.setattr(azure,'AzureTransport',lambda auth:t);monkeypatch.setattr(azure,'AzureTransportExposure',lambda auth:t)
    snapshot=collect_live({'provider':'azure','scopes':[SCOPE],'options':{'retries':0}},['vm','security_assessment'])
    rows=[e for e in snapshot['collections'] if e['type']=='security_assessment'];assert len(rows)==1
    value=rows[0]['items'][0];assert value['properties']['metadata']['assessmentType']=='BuiltIn'
    assert value['_provenance']['credential_context_id']==snapshot['metadata']['credential_context_id']
    assert value['_provenance']['customer_context_id']==snapshot['metadata']['customer_context_id']
    assert any(urlsplit(url).path==RID and '$expand=metadata' in url for url in t.calls)
    assert not any('/listkeys' in url.lower() or '/appsettings' in url.lower() for url in t.calls)


def test_native_detail_reads_share_bounded_parallelism_and_preserve_source_order():
    import threading
    r=reader();r.workers=2
    vm2=VM+'2';second=row();second['id']=vm2+'/providers/Microsoft.Security/assessments/'+n.KEY
    second['properties']['resourceDetails']['id']=vm2
    r.collections[0]['items'].append({'id':vm2});r.collections[1]['items'].append(second)
    barrier=threading.Barrier(2);seen=[];lock=threading.Lock()
    def request(url):
        with lock:seen.append(url)
        barrier.wait(timeout=2)
        return deepcopy(second if urlsplit(url).path==second['id'] else row())
    n.collect(r,request,[SCOPE],{'vm','security_assessment'},'capture','customer')
    assert len(seen)==2 and r.budget.calls==2
    values=r.collections[1]['items'];assert [v['id'] for v in values]==[RID,second['id']]
    assert all(v['_provenance']['metadata_expanded'] is True for v in values)


@pytest.mark.parametrize('bad_vm',[VM.replace('/rg/','/../'),VM.replace('/vm','/%2e%2e'),VM.replace('/rg/','/rg%2f..%2f../')])
def test_encoded_or_navigating_vm_reference_never_becomes_a_request(bad_vm):
    r=reader();r.collections[0]['items']=[{'id':bad_vm}]
    value=r.collections[1]['items'][0];value['id']=bad_vm+'/providers/Microsoft.Security/assessments/'+n.KEY
    value['properties']['resourceDetails']['id']=bad_vm
    _,calls=run(r,row());assert calls==[]
