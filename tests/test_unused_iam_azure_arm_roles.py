from copy import deepcopy
from types import SimpleNamespace
import pytest
from peaso import unused_iam_azure_arm_roles as subject
from peaso import azure_unused_arm_role_contract as contract

TENANT='11111111-1111-4111-8111-111111111111'
SUB='/subscriptions/22222222-2222-4222-8222-222222222222'
OTHER='/subscriptions/33333333-3333-4333-8333-333333333333'
ROLE='44444444-4444-4444-8444-444444444444'
PRINCIPAL='55555555-5555-4555-8555-555555555555'
ASSIGNMENT='66666666-6666-4666-8666-666666666666'
MG=contract.MG+'synthetic-parent'
CHILD=contract.MG+'synthetic-child'
NOW='2026-10-21T12:00:00Z'


def proof(tenant=False):
    data={'credential_context_id':'capture-one','customer_context_id':'customer-one'}
    if tenant:data.update(tenant_id=TENANT,tenant_verified=True,read_only=True,schema=contract.SCHEMA,
        endpoint='native-unused-arm-role-projection',observed_at=NOW)
    return data


def binding(sc):
    return {'scope':sc,'path':sc,'api_version':'2020-05-01' if sc.startswith(contract.MG) else '2022-12-01',
        'method':'GET','body':None,'audience':contract.ARM,'status':'collected','tenant_id':TENANT}


def grant(sc=SUB,name='assignments',role=None):
    endpoint,_=contract.REPORTS[name]
    row={'id':sc+'/providers/Microsoft.Authorization/'+endpoint+'/'+ASSIGNMENT,'name':ASSIGNMENT,
        'type':'Microsoft.Authorization/'+endpoint,'properties':{'scope':sc,'roleDefinitionId':role or SUB+'/providers/Microsoft.Authorization/roleDefinitions/'+ROLE,
            'principalId':PRINCIPAL,'principalType':'ServicePrincipal','condition':None}}
    if name!='assignments':row['properties'].update(status='Provisioned',startDateTime='2025-01-01T00:00:00Z',endDateTime='2027-01-01T00:00:00Z')
    return row


def source(sc,name,rows=None):
    p,v=contract.path(sc,name)
    return {'scope':sc,'name':name,'path':p,'api_version':v,'audience':contract.ARM,'method':'GET','body':None,'filter':None,
        'status':'collected' if rows else 'empty','items':rows or [],'integrity_error':False}


def tree(sc=MG,rows=None):
    return {'scope':sc,'path':sc+'/descendants','api_version':'2020-05-01','audience':contract.ARM,'method':'GET','body':None,'filter':None,
        'status':'collected' if rows else 'empty','items':rows or [],'integrity_error':False}


def fixture(bound=None,sc=SUB,assignable=None):
    item={'id':SUB+'/providers/Microsoft.Authorization/roleDefinitions/'+ROLE,'name':ROLE,'type':'Microsoft.Authorization/roleDefinitions',
        'properties':{'type':'CustomRole','roleName':'Synthetic storage role','assignableScopes':assignable or [SUB],
            'permissions':[{'actions':['Microsoft.Storage/storageAccounts/read'],'notActions':[],'dataActions':[],'notDataActions':[]}]},
        '_provenance':proof(),'_authorization_native_list':{'source_operation':'roleDefinitions_ListForScope','read_only':True,'api_version':'2022-04-01',
            'requested_scope':sc,'request_path':sc.rstrip('/')+'/providers/Microsoft.Authorization/roleDefinitions','filter':None}}
    frame={'schema':contract.SCHEMA,'selected_subscriptions':[SUB],'bindings':{SUB:binding(SUB)},'hierarchies':{},
        'sources':[source(SUB,name,[grant(name=name)] if name==bound else []) for name in contract.REPORTS],
        'unresolved_assignable_scopes':[],'_provenance':proof(True)}
    ref={'id':sc.rstrip('/')+'/unusedArmRoleEvidence','schema':contract.SCHEMA,'metadata_key':contract.META,'_provenance':proof(True)}
    index={'context':{'provider':'azure','scope':sc,'created_at':NOW,'metadata':{**proof(True),contract.META:frame}},'collections':{}}
    for kind,rows in [('role_definition',[item]),(contract.KIND,[ref])]:
        index[kind]=[{'type':kind,'scope':sc,'data':r} for r in rows]
        index['collections'][kind]=[{'type':kind,'scope':sc,'service':'Microsoft.Authorization','status':'collected','items':rows,'_provenance':proof()}]
    return item,index


def frame(index):return index['context']['metadata'][contract.META]


def test_complete_subscription_role_without_consumers_fails_with_exact_exclusions():
    item,index=fixture();before=deepcopy(index)
    status,evidence=subject.evaluate(item,index)
    assert status=='FAIL',evidence
    assert evidence['permissions']==item['properties']['permissions']
    assert index==before


@pytest.mark.parametrize('name',list(contract.REPORTS))
def test_current_and_future_assignment_or_pim_consumers_pass(name):
    item,index=fixture(name)
    if name!='assignments':frame(index)['sources'][list(contract.REPORTS).index(name)]['items'][0]['properties'].update(startDateTime='2027-01-01T00:00:00Z',endDateTime='2028-01-01T00:00:00Z')
    assert subject.evaluate(item,index)[0]=='PASS'


@pytest.mark.parametrize('sc',[SUB+'/resourceGroups/storage',SUB+'/resourceGroups/storage/providers/Microsoft.Storage/storageAccounts/synthetic'])
def test_every_declared_resource_or_group_scope_must_be_read(sc):
    item,index=fixture(assignable=[sc])
    assert subject.evaluate(item,index)[0]=='UNKNOWN'
    frame(index)['sources'].extend(source(sc,n) for n in contract.REPORTS)
    assert subject.evaluate(item,index)[0]=='FAIL'


def test_other_assignable_subscription_is_not_silently_treated_as_empty():
    item,index=fixture(assignable=[SUB,OTHER])
    assert subject.evaluate(item,index)[0]=='UNKNOWN'
    frame(index)['selected_subscriptions'].append(OTHER);frame(index)['bindings'][OTHER]=binding(OTHER)
    frame(index)['sources'].extend(source(OTHER,n) for n in contract.REPORTS)
    assert subject.evaluate(item,index)[0]=='FAIL'
    row=grant(OTHER);frame(index)['sources'][-3].update(status='collected',items=[row])
    assert subject.evaluate(item,index)[0]=='PASS'


def management_fixture(data_actions=False):
    item,index=fixture(sc=MG,assignable=[MG]);data=frame(index)
    data['bindings'][MG]=binding(MG)
    data['hierarchies'][MG]=tree(rows=[{'id':CHILD,'parent':MG},{'id':SUB,'parent':CHILD}])
    for sc in (MG,CHILD):data['sources'].extend(source(sc,n) for n in contract.REPORTS)
    if data_actions:item['properties']['permissions'][0]['dataActions']=['Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read']
    return item,index


def test_management_group_requires_complete_descendants_and_their_native_reads():
    item,index=management_fixture()
    assert subject.evaluate(item,index)[0]=='FAIL'
    frame(index)['sources']=[s for s in frame(index)['sources'] if s['scope']!=CHILD]
    assert subject.evaluate(item,index)[0]=='UNKNOWN'


def test_management_group_with_unselected_subscription_is_unknown_but_bound_positive_survives():
    item,index=management_fixture()
    frame(index)['hierarchies'][MG]['items'].append({'id':OTHER,'parent':MG})
    assert subject.evaluate(item,index)[0]=='UNKNOWN'
    frame(index)['sources'][0].update(status='collected',items=[grant()])
    assert subject.evaluate(item,index)[0]=='PASS'


def test_management_group_data_action_role_uses_descendant_subscriptions_not_impossible_group_grants():
    item,index=management_fixture(True)
    for source in frame(index)['sources']:
        if source['scope'].startswith(contract.MG):source.update(status='denied')
    assert subject.evaluate(item,index)[0]=='FAIL'
    frame(index)['sources'][2]['status']='denied'
    assert subject.evaluate(item,index)[0]=='DENIED'


@pytest.mark.parametrize('mutation',['tenant','capture','row_source','projection','definition_filter','missing_frame','frame_pointer','future_capture','foreign_binding',
    'binding_denied','source_denied','partial_denied','source_filter','source_endpoint','integrity','missing_scope','root_assignable','duplicate_scope','bad_permissions',
    'duplicate_role','malformed_scope_row','foreign_subscription_row','duplicate_consumer','pim_lifetime','pim_state','missing_end'])
def test_absence_requires_bound_current_complete_native_sources(mutation):
    item,index=fixture();data=frame(index);expected='UNKNOWN'
    if mutation=='tenant':index['context']['metadata']['tenant_id']='77777777-7777-4777-8777-777777777777'
    elif mutation=='capture':item['_provenance']['credential_context_id']='other'
    elif mutation=='row_source':item['_authorization_native_list']['read_only']=False
    elif mutation=='projection':index['role_definition']=[]
    elif mutation=='definition_filter':item['_authorization_native_list']['filter']="roleName eq 'other'"
    elif mutation=='missing_frame':index['context']['metadata'].pop(contract.META)
    elif mutation=='frame_pointer':index[contract.KIND][0]['data']['metadata_key']='other'
    elif mutation=='future_capture':data['_provenance']['observed_at']='2027-01-01T00:00:00Z'
    elif mutation=='foreign_binding':data['bindings'][SUB]['tenant_id']='77777777-7777-4777-8777-777777777777'
    elif mutation=='binding_denied':data['bindings'][SUB]['status']='denied';expected='DENIED'
    elif mutation=='source_denied':data['sources'][2]['status']='denied';expected='DENIED'
    elif mutation=='partial_denied':data['sources'][2].update(status='partial',error={'cause_status':'denied'});expected='DENIED'
    elif mutation=='source_filter':data['sources'][1]['filter']='atScope()'
    elif mutation=='source_endpoint':data['sources'][0]['path']='/other'
    elif mutation=='integrity':data['sources'][0]['integrity_error']=True
    elif mutation=='missing_scope':item['properties'].pop('assignableScopes')
    elif mutation=='root_assignable':item['properties']['assignableScopes']=['/']
    elif mutation=='duplicate_scope':item['properties']['assignableScopes']=[SUB,SUB.upper()]
    elif mutation=='bad_permissions':item['properties']['permissions']=[{}]
    elif mutation=='duplicate_role':index['role_definition'].append(deepcopy(index['role_definition'][0]));index['collections']['role_definition'][0]['items'].append(deepcopy(item))
    else:
        name='assignment_schedules' if mutation in ('pim_lifetime','pim_state','missing_end') else 'assignments'
        r=grant(name=name);source=data['sources'][list(contract.REPORTS).index(name)];source.update(status='collected',items=[r])
        if mutation=='malformed_scope_row':r['properties']['scope']=OTHER
        elif mutation=='foreign_subscription_row':source['items']=[grant(OTHER)]
        elif mutation=='duplicate_consumer':source['items'].append(deepcopy(r))
        elif mutation=='pim_lifetime':r['properties']['endDateTime']='2024-01-01T00:00:00Z'
        elif mutation=='pim_state':r['properties']['status']='unknown'
        elif mutation=='missing_end':r['properties'].pop('endDateTime')
    assert subject.evaluate(item,index)[0]==expected


@pytest.mark.parametrize('status',sorted(subject.INACTIVE))
def test_revoked_or_expired_pim_does_not_hide_unassigned_role(status):
    item,index=fixture('eligibility_schedules');row=frame(index)['sources'][2]['items'][0]['properties']
    row['status']=status
    assert subject.evaluate(item,index)[0]=='FAIL'
    row.update(status='Provisioned',endDateTime=NOW)
    assert subject.evaluate(item,index)[0]=='FAIL'


def test_known_consumer_survives_denied_other_assignable_scope():
    item,index=fixture('assignments',assignable=[SUB,OTHER])
    assert subject.evaluate(item,index)[0]=='PASS'


def test_builtin_is_not_applicable_and_shared_native_memo_joins_once(monkeypatch):
    from peaso.checks.facts import MemoIndex
    item,index=fixture();item['properties']['type']='BuiltInRole'
    assert subject.evaluate(item,index)[0]=='NOT_APPLICABLE'
    item,index=fixture('assignments');calls=[];original=subject.project
    def tracked(*args):calls.append(True);return original(*args)
    monkeypatch.setattr(subject,'project',tracked);index=MemoIndex(index)
    assert subject.evaluate(item,index)[0]=='PASS' and subject.evaluate(item,index)[0]=='PASS'
    assert len(calls)==1


@pytest.mark.parametrize('mode',['empty','bound','eligibility','binding_denied','partial_positive','filter_injection','resource_limit','foreign_binding'])
def test_real_shared_reader_collects_only_authorized_native_gets_and_preserves_failure(mode,monkeypatch):
    from urllib.parse import urlsplit
    from peaso.collectors.azure import _Reader
    from peaso.collectors import azure_unused_arm_roles_20261021 as producer
    from datetime import datetime
    # Bind this native collection to the fixed snapshot clock. Letting wall
    # time advance made valid captures fail the unchanged one-day freshness guard.
    monkeypatch.setattr(producer,'datetime',SimpleNamespace(
        now=lambda tz:datetime.fromisoformat(NOW.replace('Z','+00:00')).astimezone(tz)))
    reader=_Reader({'retries':0,'concurrency':1,**({'max_resources':1} if mode=='resource_limit' else {})})
    item,index=fixture()
    reader.collections=[deepcopy(index['collections']['role_definition'][0])]
    calls=[]
    class Denied(Exception):status_code=403
    def request(url,*,audience=contract.ARM,body=None):
        assert audience==contract.ARM and body is None;calls.append(url);p=urlsplit(url).path.casefold()
        if p==SUB:
            if mode=='binding_denied':raise Denied('PRIVATE_ERROR_DO_NOT_RETAIN')
            return {'id':SUB,'subscriptionId':SUB.rsplit('/',1)[-1],'tenantId':TENANT if mode!='foreign_binding' else '77777777-7777-4777-8777-777777777777'}
        name=next((n for n,(endpoint,_) in contract.REPORTS.items() if p.endswith('/'+endpoint.casefold())),None)
        assert name is not None
        if name=='assignments':
            if '$skiptoken=' in url:raise Denied('PRIVATE_ERROR_DO_NOT_RETAIN')
            if mode in ('partial_positive','filter_injection'):return {'value':[grant()], 'nextLink':url+('&$filter=atScope()' if mode=='filter_injection' else '&$skiptoken=next')}
            if mode=='resource_limit':
                second=grant();second['id']=second['id'].replace(ASSIGNMENT,'88888888-8888-4888-8888-888888888888');second['name']='88888888-8888-4888-8888-888888888888'
                return {'value':[grant(),second]}
            if mode=='bound':return {'value':[dict(grant(),expandedProperties={'principal':{'displayName':'PRIVATE_NAME_DO_NOT_RETAIN'}})]}
        if name=='eligibility_schedules' and mode=='eligibility':return {'value':[grant(name=name)]}
        return {'value':[]}
    producer.collect(reader,request,[SUB],{contract.KIND},SimpleNamespace(tenant=TENANT,verified_tenant=TENANT),'capture-one','customer-one')
    index['context']['metadata'].update(reader.unused_arm_role_metadata)
    refs=[c for c in reader.collections if c['type']==contract.KIND]
    index['collections'][contract.KIND]=refs
    index[contract.KIND]=[{'type':contract.KIND,'scope':c['scope'],'data':r} for c in refs for r in c['items']]
    expected={'empty':'FAIL','bound':'PASS','eligibility':'PASS','binding_denied':'DENIED','partial_positive':'PASS','filter_injection':'UNKNOWN','resource_limit':'PASS','foreign_binding':'UNKNOWN'}[mode]
    status,evidence=subject.evaluate(item,index)
    assert status==expected,evidence
    assert not any('$filter' in c for c in calls)
    assert all('PRIVATE_' not in str(s) for s in reader.unused_arm_role_metadata.values())
    assert len(calls)==(1 if mode in ('binding_denied','foreign_binding') else 5 if mode=='partial_positive' else 4)


@pytest.mark.parametrize('outside',[False,True])
def test_real_management_hierarchy_collects_descendant_scopes_only_when_all_subscriptions_are_selected(outside,monkeypatch):
    from urllib.parse import urlsplit
    from peaso.collectors.azure import _Reader
    from peaso.collectors import azure_unused_arm_roles_20261021 as producer
    from datetime import datetime
    monkeypatch.setattr(producer,'datetime',SimpleNamespace(
        now=lambda tz:datetime.fromisoformat(NOW.replace('Z','+00:00')).astimezone(tz)))
    reader=_Reader({'retries':0,'concurrency':1});item,index=fixture(sc=MG,assignable=[MG])
    reader.collections=[deepcopy(index['collections']['role_definition'][0])];calls=[]
    def request(url,*,audience=contract.ARM,body=None):
        assert body is None and audience==contract.ARM;calls.append(url);p=urlsplit(url).path.casefold()
        if p==SUB:return {'id':SUB,'subscriptionId':SUB.rsplit('/',1)[-1],'tenantId':TENANT}
        if p==MG:return {'id':MG,'properties':{'tenantId':TENANT}}
        if p==MG+'/descendants':
            rows=[{'id':CHILD,'type':'Microsoft.Management/managementGroups','properties':{'parent':{'id':MG}}},
                  {'id':SUB,'type':'Microsoft.Management/managementGroups/subscriptions','properties':{'parent':{'id':CHILD}}}]
            if outside:rows.append({'id':OTHER,'type':'Microsoft.Management/managementGroups/subscriptions','properties':{'parent':{'id':MG}}})
            return {'value':rows}
        assert any(p.endswith('/'+endpoint.casefold()) for endpoint,_ in contract.REPORTS.values())
        return {'value':[]}
    producer.collect(reader,request,[SUB],{contract.KIND},SimpleNamespace(tenant=TENANT,verified_tenant=TENANT),'capture-one','customer-one')
    index['context']['metadata'].update(reader.unused_arm_role_metadata)
    refs=[c for c in reader.collections if c['type']==contract.KIND];index['collections'][contract.KIND]=refs
    index[contract.KIND]=[{'type':contract.KIND,'scope':c['scope'],'data':r} for c in refs for r in c['items']]
    assert subject.evaluate(item,index)[0]==('UNKNOWN' if outside else 'FAIL')
    assert not any(urlsplit(u).path.casefold().startswith(OTHER) for u in calls)
    assert (any(CHILD+'/providers/' in u for u in calls)) is not outside


@pytest.mark.parametrize('source,expected',[(None,'FAIL'),('assignments','PASS'),('eligibility_schedules','PASS')])
def test_native_hardening_json_has_exact_permissions_and_hacktricks_membership(source,expected):
    from peaso.checks import CHECKS
    from peaso.checks.fixtures import CASES
    from peaso.engine import evaluate_snapshot,hydrate_frameworks
    from peaso.snapshot import make_snapshot
    check=next(c for c in CHECKS if c.id==subject.CHECK);case=CASES[subject.CHECK]
    for verdict in ('PASS','FAIL'):
        key=verdict.lower();assert check.evaluate(case[key],case[key+'_index'])[0]==verdict
    item,index=fixture(source)
    snap=make_snapshot('azure',[SUB],[c for cs in index['collections'].values() for c in cs],created_at=NOW,metadata=index['context']['metadata'])
    finding=hydrate_frameworks(evaluate_snapshot(snap,categories=['hardening'],checks=[subject.CHECK]))['findings'][0]
    assert finding['status']==expected,finding['evidence']
    assert finding['evidence']['permissions']==item['properties']['permissions']
    assert finding['service']=='Microsoft.Authorization'
    assert 'HackTricks Cloud Best Practices' in finding['frameworks']


def test_normal_azure_connector_requests_arm_consumer_evidence_and_engine_uses_the_shared_frame():
    from urllib.parse import urlsplit
    from peaso.collectors import azure
    from peaso.engine import evaluate_snapshot,hydrate_frameworks
    item,_=fixture();raw={k:deepcopy(v) for k,v in item.items() if not k.startswith('_')}
    class Transport:
        tenant=TENANT
        verified_tenant=TENANT
        def __init__(self):self.calls=[]
        def request(self,url,*,audience=contract.ARM,body=None):
            assert audience==contract.ARM and body is None;self.calls.append(url);p=urlsplit(url).path.casefold()
            if p==SUB:return {'id':SUB,'subscriptionId':SUB.rsplit('/',1)[-1],'tenantId':TENANT}
            if p=='/providers/microsoft.management/managementgroups':return {'value':[]}
            if p.endswith('/roledefinitions'):return {'value':[deepcopy(raw)]}
            if any(p.endswith('/'+endpoint.casefold()) for endpoint,_ in contract.REPORTS.values()):return {'value':[]}
            raise AssertionError('Unexpected native read '+p)
    transport=Transport()
    snap=azure.collect({'provider':'azure','scopes':[SUB],'auth':{'tenant_id':TENANT},'options':{'inventories':[contract.KIND],'concurrency':1,'retries':0}},transport=transport)
    assert contract.META in snap['metadata']
    findings=hydrate_frameworks(evaluate_snapshot(snap,categories=['hardening'],checks=[subject.CHECK]))['findings']
    assert findings and all(f['status']=='FAIL' for f in findings),findings
    assert all(f['evidence']['permissions']==raw['properties']['permissions'] for f in findings)
    assert sum(urlsplit(c).path.casefold().endswith('/roleassignments') for c in transport.calls)==1
    assert len([c for c in snap['collections'] if c['type']==contract.KIND])==2


def test_native_engine_reuses_shared_arm_source_join_across_scope_indexes(monkeypatch):
    from peaso.engine import evaluate_snapshot
    from peaso.snapshot import make_snapshot
    item,index=fixture('assignments');collections=[deepcopy(c) for cs in index['collections'].values() for c in cs]
    for original in list(collections):
        clone=deepcopy(original);clone['scope']='/'
        if clone['type']=='role_definition':
            clone['items'][0]['_authorization_native_list'].update(requested_scope='/',request_path='/providers/Microsoft.Authorization/roleDefinitions')
        else:clone['items'][0]['id']='/unusedArmRoleEvidence'
        collections.append(clone)
    calls=[];project=subject.project
    def counted(*args):calls.append(True);return project(*args)
    monkeypatch.setattr(subject,'project',counted)
    report=evaluate_snapshot(make_snapshot('azure',[SUB,'/'],collections,created_at=NOW,metadata=index['context']['metadata']),categories=['hardening'],checks=[subject.CHECK])
    assert len(report['findings'])==2 and all(f['status']=='PASS' for f in report['findings']),report['findings']
    assert len(calls)==1


def test_management_group_cannot_accept_a_consumer_from_an_unselected_subscription():
    item,index=management_fixture();src=next(s for s in frame(index)['sources'] if s['scope']==MG and s['name']=='assignments')
    src.update(status='collected',items=[grant(OTHER)])
    assert subject.evaluate(item,index)[0]=='UNKNOWN'
