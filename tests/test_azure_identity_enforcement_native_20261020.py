"""Independent native HTTP -> AzureTransport -> collector -> public engine.

No CASES, caller effective flags, owner approval, credentials or cloud network.
"""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import io
import json
import socket
from urllib.parse import parse_qs, urlsplit

import pytest
from peaso import engine
from peaso.collectors import azure
from peaso.collectors import azure_identity_enforcement_review_20261020 as native

TENANT='22222222-2222-2222-2222-222222222222'
SUB='11111111-1111-1111-1111-111111111111'
USER='33333333-3333-3333-3333-333333333333'
OTHER='99999999-9999-9999-9999-999999999999'
GROUP='44444444-4444-4444-4444-444444444444'
POLICY='77777777-7777-7777-7777-777777777777'
ASSIGN='88888888-8888-8888-8888-888888888888'
ROLE=native.GLOBAL_ADMIN
SCOPE='/subscriptions/'+SUB
TSCOPE='/tenants/'+TENANT
REAL_TRANSPORT=azure.AzureTransport
IDS=sorted(native.IDS)

@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def blocked(*args,**kwargs):pytest.fail('socket/DNS/credential discovery forbidden')
    for key in ('connect','connect_ex'):monkeypatch.setattr(socket.socket,key,blocked)
    for key in ('getaddrinfo','gethostbyname','gethostbyname_ex','create_connection'):monkeypatch.setattr(socket,key,blocked)
    monkeypatch.setattr(azure,'credential_for',blocked)
    monkeypatch.setattr(azure,'urlopen',blocked)
    monkeypatch.setattr(azure.time,'sleep',lambda seconds:None)


def policy():
    return {'id':POLICY,'displayName':'Independent native universal policy','state':'enabled',
        'conditions':{'users':{'includeUsers':['All'],'excludeUsers':[],'includeGroups':[],'excludeGroups':[],
                              'includeRoles':[],'excludeRoles':[]},
            'applications':{'includeApplications':['All'],'excludeApplications':[],'includeUserActions':[],'applicationFilter':None},
            'clientAppTypes':['all'],'locations':None,'platforms':None,'devices':None,'signInRiskLevels':[],
            'userRiskLevels':[],'authenticationFlows':None},
        'grantControls':{'operator':'AND','builtInControls':['mfa'],'customAuthenticationFactors':[],
                         'termsOfUse':[],'authenticationStrength':None}}


def baseline(cid):
    role={'id':ROLE,'displayName':'Global Administrator','templateId':ROLE,'isBuiltIn':True,
          'rolePermissions':[{'allowedResourceActions':['*']}], 'isEnabled':True}
    directory={'id':ASSIGN,'principalId':USER,'roleDefinitionId':ROLE,'directoryScopeId':'/','appScopeId':None}
    return {
        ('arm','/tenants'):{'value':[{'id':TSCOPE,'tenantId':TENANT,'tenantCategory':'Home'}]},
        ('arm',SCOPE):{'id':SCOPE,'subscriptionId':SUB,'tenantId':TENANT,'state':'Enabled'},
        ('arm','/providers/Microsoft.Management/managementGroups'):{'value':[]},
        ('graph','/v1.0/users'):{'value':[{'id':USER,'displayName':'Native user','userPrincipalName':'reader@example.test',
             'userType':'Member','accountEnabled':True}]},
        ('graph','/v1.0/groups'):{'value':[]},
        ('graph','/v1.0/users/'+USER+'/transitiveMemberOf'):{'value':[]},
        ('graph','/v1.0/identity/conditionalAccess/policies'):{'value':[policy()]},
        ('graph','/v1.0/policies/identitySecurityDefaultsEnforcementPolicy'):{'id':'00000000-0000-0000-0000-000000000005','isEnabled':False},
        ('graph','/v1.0/reports/authenticationMethods/userRegistrationDetails'):{'value':[{'id':USER,'isMfaCapable':True,'isMfaRegistered':True}]},
        ('graph','/v1.0/policies/authenticationStrengthPolicies'):{'value':[]},
        ('graph','/v1.0/roleManagement/directory/roleAssignments'):{'value':[directory] if cid in (native.ADMIN,native.CIS) else []},
        ('graph','/v1.0/roleManagement/directory/roleDefinitions'):{'value':[role]},
        ('graph','/beta/roleManagement/directory/roleDefinitions'):{'value':[{'id':ROLE,'isPrivileged':True}]},
        ('graph','/v1.0/roleManagement/directory/roleAssignmentScheduleInstances'):{'value':[]},
        ('graph','/v1.0/roleManagement/directory/roleEligibilityScheduleInstances'):{'value':[]},
        ('graph','/beta/users/'+USER+'/authentication/requirements'):{'perUserMfaState':'disabled' if cid==native.ALL else 'enforced'},
        ('graph','/v1.0/identityGovernance/privilegedAccess/group/assignmentScheduleInstances'):{'value':[]},
        ('graph','/v1.0/identityGovernance/privilegedAccess/group/eligibilityScheduleInstances'):{'value':[]},
        ('arm','/providers/Microsoft.Authorization/roleAssignments'):{'value':[]},
        ('arm','/providers/Microsoft.Authorization/roleAssignmentScheduleInstances'):{'value':[]},
        ('arm','/providers/Microsoft.Authorization/roleEligibilityScheduleInstances'):{'value':[]},
    }


class Wire:
    def __init__(self,data):self.data=data;self.calls=[]
    def open(self,request,timeout):
        parts=urlsplit(request.full_url);q=parse_qs(parts.query)
        assert request.get_method()=='GET' and request.data is None and timeout==20
        assert parts.scheme=='https' and parts.netloc in ('graph.microsoft.com','management.azure.com')
        assert request.get_header('Authorization')=='Bearer offline-native-fixture'
        service='graph' if parts.netloc=='graph.microsoft.com' else 'arm'
        key=(service,parts.path)
        self.calls.append({'method':'GET','host':parts.netloc,'path':parts.path,'query':q,'body':None})
        if service=='arm':assert 'api-version' in q
        if key not in self.data:pytest.fail('Unexpected native route '+str(key))
        row=self.data[key]
        if callable(row):row=row(q)
        if isinstance(row,BaseException):raise row
        row=deepcopy(row)
        if service=='graph' and '$select' in q and isinstance(row.get('value'),list):
            fields=set(q['$select'][0].split(','));row['value']=[{k:v for k,v in x.items() if k in fields or k.startswith('@odata.')} for x in row['value']]
        response=io.BytesIO(json.dumps(row).encode())
        response.status=200
        return response


def capture(monkeypatch,cid,data=None,*,verified_tenant=TENANT,concurrency=1):
    wire=Wire(data if data is not None else baseline(cid))
    monkeypatch.setattr(azure,'build_opener',lambda *args:wire)
    transport=object.__new__(REAL_TRANSPORT)
    transport.tenant=TENANT;transport.verified_tenant=verified_tenant;transport.owned=False;transport.credential=None
    transport.token=lambda audience:'offline-native-fixture' if audience in (azure.ARM,azure.GRAPH) else pytest.fail('wrong native audience')
    monkeypatch.setattr(azure,'AzureTransport',lambda auth:transport)
    monkeypatch.setattr(azure,'AzureTransportExposure',lambda auth:transport)
    snapshot=engine.collect_snapshot({'connector':{'provider':'azure','scopes':[SUB],'auth':{'tenant_id':TENANT},
                    'options':{'retries':0,'concurrency':concurrency}},'checks':[cid]})
    findings=engine.evaluate_snapshot(snapshot,checks=[cid])['findings']
    assert wire.calls
    return snapshot,findings,wire


def states(findings):return {f['status'] for f in findings}

def direct_assignment(*,scope=SCOPE,pid=USER):
    return {'id':scope+'/providers/Microsoft.Authorization/roleAssignments/'+ASSIGN,'name':ASSIGN,
        'type':'Microsoft.Authorization/roleAssignments','properties':{'principalId':pid,'principalType':'User',
        'roleDefinitionId':scope+'/providers/Microsoft.Authorization/roleDefinitions/'+ROLE,'scope':scope,
        'condition':None,'conditionVersion':None}}


@pytest.mark.parametrize('cid',IDS)
def test_native_positive_and_opposite(monkeypatch,cid):
    _,f,_=capture(monkeypatch,cid);assert states(f)=={'PASS'},f
    data=baseline(cid)
    if cid==native.DIRECT:data[('arm','/providers/Microsoft.Authorization/roleAssignments')]['value']=[direct_assignment()]
    else:data[('graph','/v1.0/identity/conditionalAccess/policies')]['value'][0]['grantControls'].update(operator='OR',builtInControls=['mfa','compliantDevice'])
    if cid==native.CIS:data[('graph','/beta/users/'+USER+'/authentication/requirements')]['perUserMfaState']='disabled'
    _,f,_=capture(monkeypatch,cid,data);assert states(f)==({'UNKNOWN'} if cid==native.ADMIN else {'FAIL'}),f


@pytest.mark.parametrize('cid',IDS)
@pytest.mark.parametrize('mode',['denied','malformed','partial','foreign'])
def test_native_unavailable_scope_and_identity(monkeypatch,cid,mode):
    data=baseline(cid);key=('graph','/v1.0/users')
    if mode=='denied':data[key]=azure.AzureReadError('forbidden',403)
    if mode=='malformed':
        if cid==native.DIRECT:data[('arm','/providers/Microsoft.Authorization/roleAssignments')]['value']=[direct_assignment()|{'properties':{}}]
        else:data[key]['value'][0]['accountEnabled']='true'
    if mode=='partial':
        initial=deepcopy(data[key])
        data[key]=lambda q: azure.AzureReadError('forbidden',403) if '$skiptoken' in q else {**initial,'@odata.nextLink':azure.GRAPH+'/v1.0/users?$skiptoken=next'}
    _,f,_=capture(monkeypatch,cid,data,verified_tenant=OTHER if mode=='foreign' else TENANT)
    assert f and states(f)<={'UNKNOWN','DENIED'},f


@pytest.mark.parametrize('cid',[native.ALL,native.ADMIN,native.CIS])
@pytest.mark.parametrize('mode,expected',[
    ('or_device','FAIL'),('mfa_and_device','PASS'),('only_mfa_or','PASS'),('no_enabled','FAIL'),
    ('report_only','FAIL'),('target_exclusion','UNKNOWN'),('excluded_user','FAIL'),
    ('location','UNKNOWN'),('device_filter','UNKNOWN'),('risk','UNKNOWN'),('unknown_control','UNKNOWN'),
    ('invalid_operator','UNKNOWN'),('custom_factor','UNKNOWN'),('blocked','UNKNOWN'),
    ('defaults_enabled','UNKNOWN'),('defaults_missing','UNKNOWN'),('missing_grant','UNKNOWN'),
    ('denied_policy','UNKNOWN'),('partial_policy','UNKNOWN')])
def test_native_universal_mfa_applicability(monkeypatch,cid,mode,expected):
    data=baseline(cid);key=('graph','/v1.0/identity/conditionalAccess/policies');p=data[key]['value'][0]
    if mode=='or_device':p['grantControls'].update(operator='OR',builtInControls=['mfa','compliantDevice'])
    if mode=='mfa_and_device':p['grantControls']['builtInControls']=['mfa','compliantDevice']
    if mode=='only_mfa_or':p['grantControls']['operator']='OR'
    if mode=='no_enabled':data[key]['value']=[]
    if mode=='report_only':p['state']='enabledForReportingButNotEnforced'
    if mode=='target_exclusion':p['conditions']['applications']['excludeApplications']=[OTHER]
    if mode=='excluded_user':p['conditions']['users']['excludeUsers']=[USER]
    if mode=='location':p['conditions']['locations']={'includeLocations':['All'],'excludeLocations':['AllTrusted']}
    if mode=='device_filter':p['conditions']['devices']={'deviceFilter':{'mode':'include','rule':'device.isCompliant -eq true'}}
    if mode=='risk':p['conditions']['signInRiskLevels']=['high']
    if mode=='unknown_control':p['grantControls']['builtInControls']=['futureGrant']
    if mode=='invalid_operator':p['grantControls']['operator']='NOT'
    if mode=='custom_factor':p['grantControls']['customAuthenticationFactors']=[OTHER]
    if mode=='blocked':p['grantControls']['builtInControls']=['block']
    if mode=='defaults_enabled':data[('graph','/v1.0/policies/identitySecurityDefaultsEnforcementPolicy')]['isEnabled']=True
    if mode=='defaults_missing':data[('graph','/v1.0/policies/identitySecurityDefaultsEnforcementPolicy')].pop('isEnabled')
    if mode=='missing_grant':p.pop('grantControls')
    if mode=='denied_policy':data[key]=azure.AzureReadError('forbidden',403)
    if mode=='partial_policy':
        initial=deepcopy(data[key]);data[key]=lambda q: azure.AzureReadError('forbidden',403) if '$skiptoken' in q else {**initial,'@odata.nextLink':azure.GRAPH+key[1]+'?$skiptoken=next'}
    if cid in (native.ADMIN,native.CIS) and expected=='FAIL':expected='UNKNOWN'
    _,f,_=capture(monkeypatch,cid,data);assert states(f)=={expected},f


def graph_pim(offset_start=-1,offset_end=1):
    now=datetime.now(timezone.utc)
    return {'id':'opaque-native-PIM-instance','principalId':USER,'roleDefinitionId':ROLE,'directoryScopeId':'/','appScopeId':None,
        'memberType':'Direct','startDateTime':(now+timedelta(days=offset_start)).isoformat(),
        'endDateTime':(now+timedelta(days=offset_end)).isoformat()}


@pytest.mark.parametrize('cid',IDS)
@pytest.mark.parametrize('mode',['active','expired','future','invalid','eligible','null_start'])
def test_native_directory_pim_temporal(monkeypatch,cid,mode):
    data=baseline(cid);data[('graph','/v1.0/roleManagement/directory/roleAssignments')]['value']=[]
    row=graph_pim();path='/v1.0/roleManagement/directory/roleAssignmentScheduleInstances'
    if mode=='expired':row=graph_pim(-3,-1)
    if mode=='future':row=graph_pim(1,3)
    if mode=='invalid':row['startDateTime']='not-a-time'
    if mode=='eligible':path='/v1.0/roleManagement/directory/roleEligibilityScheduleInstances'
    if mode=='null_start':row['startDateTime']=None
    data[('graph',path)]['value']=[row]
    _,f,_=capture(monkeypatch,cid,data)
    expected=('UNKNOWN' if mode in ('invalid','null_start') else 'FAIL' if mode in ('active','eligible') else 'PASS') if cid==native.DIRECT else (
        'PASS' if cid==native.ALL else 'UNKNOWN' if mode in ('invalid','null_start') or cid==native.ADMIN and mode=='eligible' else
        'NOT_APPLICABLE' if cid==native.ADMIN and mode in ('expired','future') else 'PASS')
    assert states(f)=={expected},f


@pytest.mark.parametrize('mode,expected',[('disabled','FAIL'),('enabled','PASS'),('enforced','PASS'),('missing','UNKNOWN'),('denied','UNKNOWN'),('foreign','UNKNOWN')])
def test_native_cis_legacy_status_is_independent_of_ca(monkeypatch,mode,expected):
    data=baseline(native.CIS);key=('graph','/beta/users/'+USER+'/authentication/requirements')
    data[key]={'perUserMfaState':mode}
    if mode=='missing':data[key]={}
    if mode=='denied':data[key]=azure.AzureReadError('forbidden',403)
    if mode=='foreign':data[key]={'id':OTHER,'perUserMfaState':'enforced'}
    _,f,_=capture(monkeypatch,native.CIS,data);assert states(f)=={expected},f


@pytest.mark.parametrize('cid',IDS)
def test_native_duplicate_roles_and_partial_pim(monkeypatch,cid):
    data=baseline(cid);key=('graph','/v1.0/roleManagement/directory/roleAssignments')
    role={'id':ASSIGN,'principalId':USER,'roleDefinitionId':ROLE,'directoryScopeId':'/','appScopeId':None}
    data[key]={'value':[role,deepcopy(role)]}
    _,f,_=capture(monkeypatch,cid,data)
    assert states(f)==({'PASS'} if cid==native.ALL else {'UNKNOWN'}),f

@pytest.mark.parametrize('operation',['assigned','active','eligible'])
@pytest.mark.parametrize('mode,expected',[('present','FAIL'),('expired','PASS'),('future','PASS'),('inverted','UNKNOWN'),
    ('denied','UNKNOWN'),('partial','UNKNOWN'),('foreign_principal','UNKNOWN'),('foreign_parent','UNKNOWN'),
    ('duplicate','UNKNOWN'),('bad_type','UNKNOWN')])
def test_native_arm_direct_assignment_scope_and_timing(monkeypatch,operation,mode,expected):
    cid=native.DIRECT;data=baseline(cid);api=native.ARM_READS[operation][0]
    key=('arm','/providers/Microsoft.Authorization/'+api)
    row=direct_assignment()
    if operation!='assigned':
        row['id']=SCOPE+'/providers/Microsoft.Authorization/'+api+'/'+ASSIGN;row['type']='Microsoft.Authorization/'+api
        now=datetime.now(timezone.utc)
        row['properties'].update(memberType='Direct',status='Provisioned',startDateTime=(now-timedelta(days=1)).isoformat(),endDateTime=(now+timedelta(days=1)).isoformat())
        if mode=='expired':row['properties']['endDateTime']=(now-timedelta(hours=1)).isoformat()
        if mode=='future':row['properties'].update(startDateTime=(now+timedelta(days=1)).isoformat(),endDateTime=(now+timedelta(days=2)).isoformat())
        if mode=='inverted':row['properties'].update(startDateTime=(now+timedelta(days=2)).isoformat(),endDateTime=(now-timedelta(days=2)).isoformat())
    elif mode in ('expired','future','inverted'):
        # Standing roleAssignments have no schedule times; these extra fields
        # cannot turn a declared standing direct grant into an expiring grant.
        row['properties'].update(startDateTime='not-a-native-standing-field',endDateTime='not-a-native-standing-field');expected='FAIL'
    data[key]={'value':[row]}
    if mode=='denied':data[key]=azure.AzureReadError('forbidden',403)
    if mode=='partial':
        initial=deepcopy(data[key]);data[key]=lambda q: azure.AzureReadError('forbidden',403) if '$skiptoken' in q else {**initial,'nextLink':azure.ARM+key[1]+'?api-version='+native.ARM_READS[operation][1]+'&$skiptoken=next'}
    if mode=='foreign_principal':row['properties']['principalId']=OTHER
    if mode=='foreign_parent':data[('arm',SCOPE)]['tenantId']=OTHER
    if mode=='duplicate':data[key]['value'].append(deepcopy(row))
    if mode=='bad_type':row['type']='Microsoft.Authorization/denyAssignments'
    _,f,wire=capture(monkeypatch,cid,data);assert states(f)=={expected},f
    queries=[c for c in wire.calls if c['path']==key[1]]
    assert queries and queries[0]['query']['$filter']==["principalId eq '"+USER+"'"]


@pytest.mark.parametrize('cid',IDS)
@pytest.mark.parametrize('source',['users','registration','pim'])
def test_native_source_duplicates_and_denials(monkeypatch,cid,source):
    data=baseline(cid)
    if source=='users':
        key=('graph','/v1.0/users');data[key]['value'].append(deepcopy(data[key]['value'][0]))
    elif source=='registration':
        key=('graph','/v1.0/reports/authenticationMethods/userRegistrationDetails');data[key]['value'].append(deepcopy(data[key]['value'][0]))
    else:data[('graph','/v1.0/roleManagement/directory/roleEligibilityScheduleInstances')]=azure.AzureReadError('forbidden',403)
    _,f,_=capture(monkeypatch,cid,data)
    expected='PASS' if source=='registration' and cid==native.DIRECT or source=='pim' and cid==native.ALL else 'UNKNOWN'
    # A proven current direct directory grant stays decisive despite unrelated
    # unavailable PIM; this baseline has no such grant for the direct criterion.
    assert states(f)=={expected},f


def add_group(data,*,role=False):
    data[('graph','/v1.0/groups')]={'value':[{'id':GROUP,'displayName':'Native group','securityEnabled':True,
        'groupTypes':[],'isAssignableToRole':role,'visibility':None,'membershipRule':None,'membershipRuleProcessingState':None}]}
    data[('graph','/v1.0/users/'+USER+'/transitiveMemberOf')]={'value':[{'id':GROUP,'@odata.type':'#microsoft.graph.group'}]}
    data[('graph','/v1.0/groups/'+GROUP)]={'id':GROUP,'visibility':None,'groupTypes':[],'membershipRuleProcessingState':None}
    data[('graph','/v1.0/groups/'+GROUP+'/transitiveMembers')]={'value':[{'id':USER,'@odata.type':'#microsoft.graph.user'}]}
    data[('graph','/v1.0/groups/'+GROUP+'/owners')]={'value':[]}


@pytest.mark.parametrize('cid',[native.ALL,native.ADMIN,native.CIS])
@pytest.mark.parametrize('mode,expected',[('included','PASS'),('excluded','FAIL'),('denied','UNKNOWN'),('dynamic','UNKNOWN')])
def test_native_ca_group_include_minus_exclude(monkeypatch,cid,mode,expected):
    data=baseline(cid);add_group(data)
    users=data[('graph','/v1.0/identity/conditionalAccess/policies')]['value'][0]['conditions']['users']
    users.update(includeUsers=[],includeGroups=[GROUP])
    if mode=='excluded':users['excludeGroups']=[GROUP]
    if mode=='denied':data[('graph','/v1.0/groups/'+GROUP+'/transitiveMembers')]=azure.AzureReadError('forbidden',403)
    if mode=='dynamic':data[('graph','/v1.0/groups/'+GROUP)]['groupTypes']=['DynamicMembership']
    if cid in (native.ADMIN,native.CIS) and expected=='FAIL':expected='UNKNOWN'
    _,f,_=capture(monkeypatch,cid,data);assert states(f)=={expected},f


@pytest.mark.parametrize('cid',[native.ADMIN,native.CIS])
@pytest.mark.parametrize('mode,expected',[('group_role','PASS'),('owner','UNKNOWN'),('eligible_group','UNKNOWN'),('expired_group','PASS')])
def test_native_directory_role_group_and_pim_limits(monkeypatch,cid,mode,expected):
    data=baseline(cid);add_group(data,role=True)
    data[('graph','/v1.0/roleManagement/directory/roleAssignments')]['value'][0]['principalId']=GROUP
    if mode=='owner':data[('graph','/v1.0/groups/'+GROUP+'/owners')]['value']=[{'id':USER}]
    if mode in ('eligible_group','expired_group'):
        now=datetime.now(timezone.utc)
        row={'id':'opaque-group-eligibility','principalId':USER,'groupId':GROUP,'accessId':'member',
            'startDateTime':(now-timedelta(days=2)).isoformat(),'endDateTime':(now+timedelta(days=1) if mode=='eligible_group' else now-timedelta(days=1)).isoformat()}
        data[('graph','/v1.0/identityGovernance/privilegedAccess/group/eligibilityScheduleInstances')]=lambda q: {'value':[row] if q.get('$filter')==["principalId eq '"+USER+"'"] else []}
    _,f,_=capture(monkeypatch,cid,data);assert states(f)=={expected},f


@pytest.mark.parametrize('cid',IDS)
@pytest.mark.parametrize('field',['customer_context_id','credential_context_id','tenant_id','endpoint'])
def test_post_native_capture_inconsistency_never_falls_back(monkeypatch,cid,field):
    # An explicit corruption test after real native capture; never positive
    # provider proof and never caller-created effective/coverage flags.
    snapshot,_,_=capture(monkeypatch,cid)
    env=next(c for c in snapshot['collections'] if c['type']==native.KIND)
    if field=='endpoint':env['items'][0]['sources'][0]['endpoint']='/v1.0/foreign'
    else:env['items'][0]['_provenance'][field]='foreign-capture'
    snapshot.pop('snapshot_id',None)
    f=engine.evaluate_snapshot(snapshot,checks=[cid])['findings']
    assert states(f)=={'UNKNOWN'},f

@pytest.mark.parametrize('cid',[native.ALL,native.ADMIN,native.CIS])
@pytest.mark.parametrize('mode,expected',[('mfa_strength','PASS'),('single_factor','FAIL'),('unreadable','UNKNOWN'),('foreign_reference','UNKNOWN')])
def test_native_authentication_strength_reference(monkeypatch,cid,mode,expected):
    data=baseline(cid);g=data[('graph','/v1.0/identity/conditionalAccess/policies')]['value'][0]['grantControls']
    g.update(builtInControls=[],authenticationStrength={'id':ASSIGN})
    definition={'id':ASSIGN,'displayName':'Native method policy','policyType':'custom',
        'requirementsSatisfied':'mfa','allowedCombinations':['password,sms']}
    if mode=='single_factor':definition.update(requirementsSatisfied='none',allowedCombinations=['password'])
    if mode=='unreadable':data[('graph','/v1.0/policies/authenticationStrengthPolicies')]=azure.AzureReadError('forbidden',403)
    else:data[('graph','/v1.0/policies/authenticationStrengthPolicies')]={'value':[definition]}
    if mode=='foreign_reference':g['authenticationStrength']['id']=OTHER
    if cid in (native.ADMIN,native.CIS) and expected=='FAIL':expected='UNKNOWN'
    _,f,_=capture(monkeypatch,cid,data);assert states(f)=={expected},f


@pytest.mark.parametrize('cid',[native.ALL,native.ADMIN,native.CIS])
def test_native_independent_universal_rule_is_sufficient(monkeypatch,cid):
    data=baseline(cid);p=deepcopy(policy());p['id']=OTHER
    p['conditions']['devices']={'deviceFilter':{'mode':'exclude','rule':'device.extensionAttribute1 -eq "unmodeled"'}}
    data[('graph','/v1.0/identity/conditionalAccess/policies')]['value'].insert(0,p)
    _,f,_=capture(monkeypatch,cid,data);assert states(f)=={'PASS'},f


@pytest.mark.parametrize('mode,expected',[('nonprivileged_empty_arm','PASS'),('ambiguous_writer','UNKNOWN')])
def test_native_cis_disabled_legacy_scope_is_not_generalized(monkeypatch,mode,expected):
    data=baseline(native.CIS)
    data[('graph','/v1.0/roleManagement/directory/roleAssignments')]['value']=[]
    data[('graph','/beta/users/'+USER+'/authentication/requirements')]['perUserMfaState']='disabled'
    if mode=='ambiguous_writer':data[('arm','/providers/Microsoft.Authorization/roleAssignments')]['value']=[direct_assignment()]
    _,f,_=capture(monkeypatch,native.CIS,data);assert states(f)=={expected},f


@pytest.mark.parametrize('cid',IDS)
@pytest.mark.parametrize('field',['users','policies'])
def test_native_complete_pagination_and_empty_inventory(monkeypatch,cid,field):
    data=baseline(cid);key=('graph','/v1.0/users' if field=='users' else '/v1.0/identity/conditionalAccess/policies')
    final=deepcopy(data[key])
    # First page is empty but has a continuation: it is not a complete empty
    # inventory. Only the final successful page supplies actual resources.
    data[key]=lambda q: final if '$skiptoken' in q else {'value':[],'@odata.nextLink':azure.GRAPH+key[1]+'?$skiptoken=final'}
    _,f,wire=capture(monkeypatch,cid,data);assert states(f)=={'PASS'},f
    assert any('$skiptoken' in c['query'] for c in wire.calls if c['path']==key[1])


@pytest.mark.parametrize('cid',IDS)
def test_native_empty_users_are_empty_not_compliance(monkeypatch,cid):
    data=baseline(cid);data[('graph','/v1.0/users')]={'value':[]}
    _,f,_=capture(monkeypatch,cid,data);assert states(f)=={'EMPTY'},f


def role_definition(actions):
    return {'id':SCOPE+'/providers/Microsoft.Authorization/roleDefinitions/'+ASSIGN,'name':ASSIGN,
        'type':'Microsoft.Authorization/roleDefinitions','properties':{'type':'CustomRole','roleName':'Supported scope role',
        'assignableScopes':[SCOPE],'permissions':[{'actions':actions,'notActions':[],'dataActions':[],'notDataActions':[]}]}}



@pytest.mark.parametrize('cid',[native.ADMIN,native.ALL])
def test_missing_ca_does_not_prove_bypass_of_other_native_mfa_mechanisms(monkeypatch,cid):
    data=baseline(cid)
    data[('graph','/v1.0/identity/conditionalAccess/policies')]={'value':[]}
    # ADMIN: platform mandatory portal MFA is independent of tenant CA.
    # ALL: enforced per-user MFA cannot be silently treated as disabled.
    data[('graph','/beta/users/'+USER+'/authentication/requirements')]['perUserMfaState']='enforced'
    _,f,_=capture(monkeypatch,cid,data);assert states(f)=={'UNKNOWN'},f

@pytest.mark.parametrize('state,expected',[('disabled','FAIL'),('enabled','UNKNOWN'),('enforced','UNKNOWN'),
    ('missing','UNKNOWN'),('denied','UNKNOWN'),('foreign','UNKNOWN')])
def test_native_all_users_negative_requires_resolved_disabled_legacy(monkeypatch,state,expected):
    data=baseline(native.ALL);data[('graph','/v1.0/identity/conditionalAccess/policies')]={'value':[]}
    key=('graph','/beta/users/'+USER+'/authentication/requirements')
    data[key]={'perUserMfaState':state}
    if state=='missing':data[key]={}
    if state=='denied':data[key]=azure.AzureReadError('forbidden',403)
    if state=='foreign':data[key]={'id':OTHER,'perUserMfaState':'disabled'}
    _,f,_=capture(monkeypatch,native.ALL,data);assert states(f)=={expected},f

@pytest.mark.parametrize('cid',[native.ALL,native.ADMIN,native.CIS])
def test_native_unconditional_block_does_not_become_mfa_pass(monkeypatch,cid):
    data=baseline(cid);block=deepcopy(policy());block['id']=OTHER
    block['grantControls']['builtInControls']=['block']
    data[('graph','/v1.0/identity/conditionalAccess/policies')]['value'].append(block)
    _,f,_=capture(monkeypatch,cid,data);assert states(f)=={'UNKNOWN'},f


@pytest.mark.parametrize('cid', IDS)
def test_native_bounded_lookahead_preserves_engine_verdict_and_source_reads(monkeypatch, cid):
    serial, serial_findings, serial_wire = capture(monkeypatch, cid)
    parallel, parallel_findings, parallel_wire = capture(monkeypatch, cid, concurrency=4)
    assert states(parallel_findings) == states(serial_findings) == {'PASS'}
    a = next(c for c in serial['collections'] if c['type'] == native.KIND)['items'][0]
    b = next(c for c in parallel['collections'] if c['type'] == native.KIND)['items'][0]
    assert a['sources'] == b['sources']
    from collections import Counter
    key = lambda row: json.dumps(row, sort_keys=True)
    assert Counter(map(key, serial_wire.calls)) == Counter(map(key, parallel_wire.calls))
