"""Both Defender controls preserve complete native policy-assignment inventory."""
from urllib.parse import urlsplit, parse_qs
import pytest
from peaso.collectors import azure
from peaso.engine import plan_collection, collect_snapshot, evaluate_snapshot

SUB='11111111-1111-1111-1111-111111111111'
TENANT='22222222-2222-2222-2222-222222222222'
SCOPE='/subscriptions/'+SUB
EFFECT='azure.claude.defender_default_initiative_no_disabled_effects'
ENFORCE='azure.claude.defender_default_policy_enforced'
CHECKS=[EFFECT,ENFORCE]


def row(effect='AuditIfNotExists', mode='Default', scope=SCOPE):
    return {'id':scope+'/providers/Microsoft.Authorization/policyAssignments/SecurityCenterBuiltIn',
        'name':'SecurityCenterBuiltIn','properties':{'scope':scope,'enforcementMode':mode,
        'parameters':{'systemUpdatesMonitoringEffect':{'value':effect}}}}


def scan(monkeypatch, rows=(), fault=None):
    calls=[]
    class Transport:
        def __init__(self, auth): self.tenant=TENANT; self.verified_tenant=TENANT
        def request(self,url,*,body=None,audience=azure.ARM,capture_subject=False):
            assert audience==azure.ARM
            parsed=urlsplit(url); path=parsed.path; query=parse_qs(parsed.query)
            calls.append(('POST_READ' if body is not None else 'GET',path,query))
            if path=='/providers/Microsoft.ResourceGraph/resources' and body is not None:
                return {'data':[],'totalRecords':0,'count':0}
            if path==SCOPE:
                return {'id':SCOPE,'subscriptionId':SUB,'tenantId':TENANT,'state':'Enabled'}
            if path==SCOPE+'/providers/Microsoft.Authorization/policyAssignments':
                assert '$filter' not in query
                if fault=='denied': raise azure.AzureReadError('denied',403)
                values=list(rows)
                if fault=='foreign':
                    values=[{**values[0],'id':values[0]['id'].replace(SUB,'33333333-3333-3333-3333-333333333333')}]
                if fault=='partial':return {'value':values,'nextLink':url+'&skiptoken=unread'}
                return {'value':values}
            raise AssertionError('unexpected request '+path)
        def close(self):pass
    monkeypatch.setattr(azure,'AzureTransport',Transport)
    monkeypatch.setattr(azure,'AzureTransportExposure',Transport)
    req={'connector':{'provider':'azure','scopes':[SCOPE],
        'auth':{'method':'az-cli','tenant_id':TENANT},
        'options':{'max_calls':10,'max_resources':100,'retries':0,'concurrency':1}},
        'checks':CHECKS,'categories':[]}
    assert 'policy_assignment' in plan_collection(req)
    snapshot=collect_snapshot(req)
    report=evaluate_snapshot(snapshot,checks=CHECKS,categories=[],include_not_applicable=True)
    found={r['check_id']:r['status'] for r in report['findings'] if r['check_id'] in CHECKS}
    assert set(found)==set(CHECKS)
    assert all(method in ('GET','POST_READ') for method,_,_ in calls)
    return found,snapshot,calls


@pytest.mark.parametrize('assignment,effect,enforce',[
    (row(),'PASS','PASS'),(row('Disabled','DoNotEnforce'),'FAIL','FAIL'),
    (row('Disabled','Default'),'FAIL','PASS'),
    (row('AuditIfNotExists','DoNotEnforce'),'PASS','FAIL')])
def test_direct_assignment_independent_criteria(monkeypatch,assignment,effect,enforce):
    found,_,_=scan(monkeypatch,[assignment])
    assert found=={EFFECT:effect,ENFORCE:enforce}


@pytest.mark.parametrize('effect,mode',[('AuditIfNotExists','Default'),('Disabled','DoNotEnforce')])
def test_child_only_retained_but_cannot_decide_subscription(monkeypatch,effect,mode):
    child=row(effect,mode,SCOPE+'/resourceGroups/child')
    found,snapshot,calls=scan(monkeypatch,[child])
    assert found=={EFFECT:'NOT_APPLICABLE',ENFORCE:'NOT_APPLICABLE'}
    inventory=[c for c in snapshot['collections'] if c['type']=='policy_assignment']
    assert len(inventory)==1 and inventory[0]['status']=='collected'
    assert [r['id'] for r in inventory[0]['items']]==[child['id']]
    assert all('$filter' not in query for _,path,query in calls if path.endswith('/policyAssignments'))


@pytest.mark.parametrize('direct,child,expected',[
    (row(),row('Disabled','DoNotEnforce',SCOPE+'/resourceGroups/child'),'PASS'),
    (row('Disabled','DoNotEnforce'),row(scope=SCOPE+'/resourceGroups/child'),'FAIL')])
def test_mixed_direct_child_uses_direct_and_keeps_both(monkeypatch,direct,child,expected):
    found,snapshot,_=scan(monkeypatch,[direct,child])
    assert found=={EFFECT:expected,ENFORCE:expected}
    assert len([c for c in snapshot['collections'] if c['type']=='policy_assignment'][0]['items'])==2


@pytest.mark.parametrize('fault',['denied','partial','foreign'])
def test_incomplete_or_foreign_collection_never_certifies(monkeypatch,fault):
    found,_,_=scan(monkeypatch,[row()],fault)
    assert all(status in ('UNKNOWN','DENIED') for status in found.values())


@pytest.mark.parametrize('case',['missing_scope','scope_conflict','id_name_conflict',
                                 'malformed_child','child_scope_conflict','inherited_list_proven'])
def test_assignment_scope_binding_for_both(monkeypatch,case):
    assignment=row();rows=[assignment]
    if case=='missing_scope':del assignment['properties']['scope']
    elif case=='scope_conflict':assignment['properties']['scope']=SCOPE+'/resourceGroups/child'
    elif case=='id_name_conflict':assignment['id']=assignment['id'].replace('SecurityCenterBuiltIn','other')
    elif case=='malformed_child':rows.append(row(scope=SCOPE+'/notAnArmChild/x'))
    elif case=='child_scope_conflict':
        child=row(scope=SCOPE+'/resourceGroups/child');child['properties']['scope']=SCOPE;rows.append(child)
    else:rows=[row(scope='/providers/Microsoft.Management/managementGroups/unproved')]
    found,_,_=scan(monkeypatch,rows)
    expected={EFFECT:'PASS',ENFORCE:'PASS'} if case=='inherited_list_proven' else {EFFECT:'UNKNOWN',ENFORCE:'UNKNOWN'}
    assert found==expected


def test_signed_absence_branches_preserved(monkeypatch):
    found,_,_=scan(monkeypatch,[])
    assert found=={EFFECT:'NOT_APPLICABLE',ENFORCE:'NOT_APPLICABLE'}
