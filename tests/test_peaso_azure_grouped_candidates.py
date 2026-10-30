"""Private grouped Graph and ARM producer-to-engine fixtures; zero network."""
import copy
import importlib.util
from pathlib import Path

import pytest
from peaso.engine import evaluate_snapshot

HERE=Path(__file__).resolve().parent
TENANT='11111111-1111-1111-1111-111111111111'
SCOPE='/subscriptions/22222222-2222-2222-2222-222222222222'
APP='33333333-3333-3333-3333-333333333333'
SP='44444444-4444-4444-4444-444444444444'
KEY='55555555-5555-5555-5555-555555555555'
PROFILE=SCOPE+'/providers/Microsoft.Insights/logProfiles/default'
APP_URL='https://graph.microsoft.com/v1.0/applications?$select=id,appId,displayName,requiredResourceAccess,signInAudience,passwordCredentials,keyCredentials,servicePrincipalLockConfiguration&$top=999'
SP_URL='https://graph.microsoft.com/v1.0/servicePrincipals?$select=id,appId,appOwnerOrganizationId,displayName,servicePrincipalType,alternativeNames,accountEnabled,appRoles,passwordCredentials,keyCredentials,preferredSingleSignOnMode,createdDateTime'
PROFILE_URL='https://management.azure.com'+SCOPE+'/providers/Microsoft.Insights/logProfiles?api-version=2016-03-01'
ARG_URL='https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=2022-10-01'
DIAG_URL='https://management.azure.com'+PROFILE+'/providers/Microsoft.Insights/diagnosticSettings?api-version=2021-05-01-preview'
CREATED='2026-10-14T06:00:00+00:00'
SUB_URL='https://management.azure.com/subscriptions?api-version=2022-12-01'


from peaso.collectors import azure as COLLECT
from peaso.checks import azure_graph_credential_age as GRAPH
from peaso.checks import azure_log_profile_retention as PROFILE_CHECK
from peaso.checks import azure_easm_native as EASM
from peaso.checks import next_group_azure_fixtures as FIXTURES


class Transport:
    tenant=TENANT
    verified_tenant=True
    def __init__(self,answers):self.answers=answers;self.calls=[]
    def request(self,url,*,body=None,audience=None):
        self.calls.append(url)
        if url==ARG_URL:return {'data':[]}
        if url==DIAG_URL:return {'value':[]}
        response=self.answers[url]
        if isinstance(response,Exception):raise response
        return copy.deepcopy(response)


def credential(start='2026-10-01T00:00:00Z',end='2027-10-01T00:00:00Z',secret=False):
    row={'keyId':KEY,'startDateTime':start,'endDateTime':end}
    if secret:row['secretText']='MUST-NOT-SURVIVE'
    return row


def collect_graph(kind,items,*,next_page=None,denied=False,options=None):
    url=APP_URL if kind=='application_scope' else SP_URL
    responses={url:PermissionError('denied') if denied else {'value':items}}
    if next_page is not None:
        continuation=url+'&$skiptoken=2'
        responses[url]={'value':items,'@odata.nextLink':continuation}
        responses[continuation]={'value':next_page}
    t=Transport(responses)
    connector={'scopes':[],'auth':{'tenant_id':TENANT},'options':{'concurrency':1,'retries':0,**(options or {})}}
    snapshot=COLLECT.collect(connector,requirements=[kind if kind=='application_scope' else 'service_principal_scope'],transport=t)
    check_id=GRAPH.APPLICATION if kind=='application_scope' else GRAPH.PRINCIPAL
    result=evaluate_snapshot(snapshot,checks=[check_id])
    return [r for r in result['findings'] if r['check_id']==check_id],t.calls,snapshot


def test_application_zero_active_complete_and_aged():
    rows=[{'id':APP,'passwordCredentials':[credential()],'keyCredentials':[]}]
    findings,calls,snapshot=collect_graph('application_scope',rows)
    assert [f['status'] for f in findings]==['PASS']
    assert calls==[SUB_URL,APP_URL] and 'MUST-NOT-SURVIVE' not in str(snapshot)
    rows[0]['passwordCredentials']=[credential('2025-01-01T00:00:00Z',secret=True)]
    findings,_,snapshot=collect_graph('application_scope',rows)
    assert findings[0]['status']=='FAIL' and 'MUST-NOT-SURVIVE' not in str(snapshot)
    findings,_,_=collect_graph('application_scope',[])
    assert findings[0]['status']=='PASS'


def test_application_unknown_denied_partial_and_malformed():
    base={'id':APP,'passwordCredentials':[credential(start=None)],'keyCredentials':[]}
    assert collect_graph('application_scope',[base])[0][0]['status']=='UNKNOWN'
    assert collect_graph('application_scope',[],denied=True)[0][0]['status'] in ('DENIED','UNKNOWN')
    assert collect_graph('application_scope',[{'id':'-'*36,'passwordCredentials':[],'keyCredentials':[]}])[0][0]['status']=='UNKNOWN'
    rows=[{'id':APP,'passwordCredentials':[],'keyCredentials':[]}]
    findings,_,_=collect_graph('application_scope',rows,options={'max_pages':1})
    assert findings[0]['status']=='PASS'  # no next page; explicit limit is not truncation
    url=APP_URL; next_url=url+'&$skiptoken=2'
    transport=Transport({url:{'value':rows,'@odata.nextLink':next_url},next_url:{'value':[]}})
    snap=COLLECT.collect({'scopes':[],'auth':{'tenant_id':TENANT},'options':{'concurrency':1,'retries':0,'max_pages':1}},requirements=['application_scope'],transport=transport)
    report=evaluate_snapshot(snap,checks=[GRAPH.APPLICATION])
    assert [r['status'] for r in report['findings'] if r['check_id']==GRAPH.APPLICATION][0]=='UNKNOWN'



def test_graph_duplicate_page_is_unknown():
    duplicate={'id':APP,'passwordCredentials':[],'keyCredentials':[]}
    findings,_,_=collect_graph('application_scope',[duplicate],next_page=[duplicate])
    assert findings[0]['status']=='UNKNOWN'

def test_service_principal_shared_metadata_and_age_parameter():
    row={'id':SP,'passwordCredentials':[credential()],'keyCredentials':[]}
    findings,calls,snapshot=collect_graph('directory_service_principal',[row])
    assert [f['status'] for f in findings]==['PASS'] and calls==[SUB_URL,SP_URL], findings
    row['passwordCredentials']=[credential('2025-01-01T00:00:00Z',secret=True)]
    findings,_,snapshot=collect_graph('directory_service_principal',[row])
    assert findings[0]['status']=='FAIL' and 'MUST-NOT-SURVIVE' not in str(snapshot)
    findings,_,_=collect_graph('directory_service_principal',[row],options={'maxCredentialAgeDays':1000})
    assert findings[0]['status']=='PASS'
    row['passwordCredentials']=[credential(end=None)]
    assert collect_graph('directory_service_principal',[row])[0][0]['status']=='UNKNOWN'
    assert collect_graph('directory_service_principal',[])[0][0]['status']=='PASS'
    unknown={'id':SP,'passwordCredentials':[credential(end=None)],'keyCredentials':[]}
    old={'id':APP,'passwordCredentials':[credential('2025-01-01T00:00:00Z')],'keyCredentials':[]}
    assert collect_graph('directory_service_principal',[unknown,old])[0][0]['status']=='FAIL'


def profile(days,enabled=True,rid=PROFILE):
    return {'id':rid,'type':'Microsoft.Insights/logProfiles','properties':{'retentionPolicy':{'days':days,'enabled':enabled}}}


def collect_profile(rows,*,denied=False,next_page=None,options=None):
    answers={PROFILE_URL:PermissionError('denied') if denied else {'value':rows}}
    if next_page is not None:
        next_url=PROFILE_URL+'&$skiptoken=2'
        answers[PROFILE_URL]={'value':rows,'nextLink':next_url}
        answers[next_url]={'value':next_page}
    t=Transport(answers)
    snap=COLLECT.collect({'scopes':[SCOPE],'auth':{},'options':{'concurrency':1,'retries':0,**(options or {})}},requirements=['monitor_log_profile'],transport=t)
    report=evaluate_snapshot(snap,checks=[PROFILE_CHECK.CHECK_ID])
    return [r for r in report['findings'] if r['check_id']==PROFILE_CHECK.CHECK_ID],t.calls,snap


@pytest.mark.parametrize('rows,expected',[
    ([profile(365)],'PASS'),([{**profile(365),'type':''}],'PASS'),([profile(364)],'FAIL'),([profile(0)],'UNKNOWN'),
    ([profile(365,False)],'UNKNOWN'),([profile(None)],'UNKNOWN'),([], 'NOT_APPLICABLE'),
    ([profile(365,True,SCOPE.replace('222222222222','999999999999')+PROFILE[len(SCOPE):])],'UNKNOWN'),
    ([profile(365),profile(365)],'UNKNOWN'),
])
def test_log_profile_main_planner(rows,expected):
    findings,calls,_=collect_profile(rows)
    assert findings[0]['status']==expected
    assert calls.count(PROFILE_URL)==1 and calls.count(ARG_URL)==1
    assert set(calls)<={ARG_URL,PROFILE_URL,DIAG_URL}


def test_log_profile_pagination_denial_and_limit():
    findings,calls,_=collect_profile([],next_page=[profile(365)])
    assert findings[0]['status']=='PASS' and calls.count(PROFILE_URL)==1
    findings,_,_=collect_profile([],denied=True)
    assert findings[0]['status'] in ('DENIED','UNKNOWN')
    findings,_,_=collect_profile([],next_page=[profile(365)],options={'max_pages':1})
    assert findings[0]['status']=='UNKNOWN'


def test_private_central_fixture_contracts():
    from peaso.checks import CHECKS
    fragment=FIXTURES
    mapping={check.id:check for check in CHECKS}
    for check_id,cases in fragment.CASES_FRAGMENT.items():
        check=mapping[check_id]
        for label,expected in [('pass','PASS'),('fail','FAIL'),('unknown','UNKNOWN')]:
            actual=check.evaluate(copy.deepcopy(cases[label]),copy.deepcopy(cases[label+'_index']))[0]
            assert actual==expected,(check_id,label,actual)
        assert check.evaluate({}, {})[0]=='UNKNOWN'
        assert check.evaluate(None,{})[0]=='UNKNOWN'
        assert check.evaluate({'collection_status':'denied'}, {})[0]=='UNKNOWN'


def test_malformed_singleton_envelopes_are_unknown():
    fragment=FIXTURES
    from peaso.checks import CHECKS
    registered={c.id:c for c in CHECKS}
    for check,item,index,kind in ((registered[GRAPH.APPLICATION],fragment.APP_PASS,fragment.APP_PASS_INDEX,'directory_application'),
                                   (registered[GRAPH.PRINCIPAL],fragment.SP_PASS,fragment.SP_PASS_INDEX,'directory_service_principal'),
                                   (registered[PROFILE_CHECK.CHECK_ID],fragment.LOG_PASS,fragment.LOG_PASS_INDEX,'monitor_log_profile')):
        malformed=copy.deepcopy(index)
        malformed['collections'][kind]=['malformed-envelope']
        assert check.evaluate(item,malformed)[0]=='UNKNOWN'


def test_grouped_collector_still_produces_easm_finding():
    rid=SCOPE+'/resourceGroups/rg/providers/Microsoft.Easm/workspaces/example'
    url='https://management.azure.com'+SCOPE+'/providers/Microsoft.Easm/workspaces?api-version=2023-04-01-preview'
    t=Transport({url:{'value':[{'id':rid,'type':'Microsoft.Easm/workspaces','properties':{'provisioningState':'Succeeded'}}]}})
    snap=COLLECT.collect({'scopes':[SCOPE],'auth':{},'options':{'concurrency':1,'retries':0}},
                         requirements=['easm_workspace'],transport=t)
    report=evaluate_snapshot(snap,checks=[EASM.EASM])
    findings=[r for r in report['findings'] if r['check_id']==EASM.EASM]
    assert [r['status'] for r in findings]==['PASS']
    assert t.calls.count(url)==t.calls.count(ARG_URL)==1


@pytest.mark.parametrize("value,expected", [(90, "PASS"), (1000, "PASS"), (999999999, "PASS"), (10**12, "UNKNOWN"), (0, "UNKNOWN"), (-1, "UNKNOWN"), (True, "UNKNOWN"), (90.0, "UNKNOWN"), ("90", "UNKNOWN")])
def test_service_principal_age_parameter_representability(value, expected):
    from peaso.checks import evaluate_check
    item = copy.deepcopy(FIXTURES.SP_PASS)
    index = copy.deepcopy(FIXTURES.SP_PASS_INDEX)
    index["context"]["metadata"]["parameters"] = {"maxCredentialAgeDays": value}
    assert evaluate_check(GRAPH.PRINCIPAL, item, index)[0] == expected


def test_credential_age_boundary_remains_exact_and_inclusive_only_for_application():
    row = {"id": FIXTURES.SP, "passwordCredentials": [FIXTURES.credential(90)], "keyCredentials": []}
    assert GRAPH._credential_outcome(row, FIXTURES.NOW, 90, True)[0]
    assert not GRAPH._credential_outcome(row, FIXTURES.NOW, 90, False)[0]


def test_graph_credential_capture_context_and_tenant_isolation():
    from peaso.checks import evaluate_check
    for field in ["tenant_id", "credential_context_id", "customer_context_id"]:
        index = copy.deepcopy(FIXTURES.SP_PASS_INDEX)
        index["context"]["metadata"][field] = "99999999-9999-9999-9999-999999999999" if field == "tenant_id" else "another-context"
        assert evaluate_check(GRAPH.PRINCIPAL, copy.deepcopy(FIXTURES.SP_PASS), index)[0] == "UNKNOWN"
