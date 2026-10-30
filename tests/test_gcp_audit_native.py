"""Fake transport, sealed snapshot and real engine path; no cloud calls."""
import json
from pathlib import Path
from types import SimpleNamespace
import pytest
from fastapi import HTTPException

HERE=Path(__file__).parent
from peaso.collectors.gcp_audit_native import AuditGCPCollector, URL
def candidate_gcp_collect(connector, requirements, *, transport):
    return AuditGCPCollector(connector, requirements, transport=transport).collect()
from peaso.checks.gcp_audit_native import ELIGIBLE
from peaso.collectors.gcp import ReadError
from peaso.collectors.gcp import GCPCollector
from peaso.checks import CHECKS
from tests.archived_check_contract import evaluate_snapshot
from peaso.snapshot import make_snapshot
from peaso.checks.gcp_audit_native import ELIGIBLE, SPEC_SHA256

SCOPE='projects/audit-fixture'
START='2026-10-13T00:00:00Z'; END='2026-10-13T01:00:00Z'
SPECS={row['id']:row for row in json.loads(Path('docs/compliance-ledgers/new-checks-gcp.json').read_text()) if row['id'].startswith('gcp_logging_detect_t')}

def intake_module(monkeypatch):
    from peaso.server import validation
    return validation

@pytest.fixture(autouse=True)
def registry():
    assert all(any(check.id == cid for check in CHECKS) for cid in ELIGIBLE)
    yield

class Transport:
    def __init__(self,pages): self.pages=list(pages); self.calls=[]; self.evidence=[]
    def request(self,method,url,*,params=None,body=None,scope=None,operation=None):
        assert (method,url,scope)==('POST',URL,SCOPE)
        assert body['resourceNames']==[SCOPE] and 'timestamp >=' in body['filter'] and 'log_id(' in body['filter']
        assert 'protoPayload.methodName="google.iam.admin.v1.CreateServiceAccount"' in body['filter']
        self.calls.append((method,url,body.copy()))
        if not self.pages: raise AssertionError('unplanned page')
        response=self.pages.pop(0)
        if isinstance(response,Exception): raise response
        return response,'fake-request-'+str(len(self.calls))

def event(method='google.iam.admin.v1.CreateServiceAccount',principal='unapproved@example.com',code=0, identity='evt-1',ts='2026-10-13T00:01:00Z', project='audit-fixture',logclass='activity',service=None,resource_type=None):
    from peaso.checks.gcp_audit_native import SERVICES
    service=service if service is not None else SERVICES.get(method,'unrelated.googleapis.com')
    resource_type=resource_type or ('service_account' if method=='google.iam.admin.v1.CreateServiceAccount' else 'audited_resource')
    return {'insertId':identity,'timestamp':ts,'logName':f'projects/{project}/logs/cloudaudit.googleapis.com%2F{logclass}',
      'resource':{'type':resource_type,'labels':{'project_id':project}},
      'protoPayload':{'@type':'type.googleapis.com/google.cloud.audit.AuditLog','serviceName':service,
        'methodName':method,'authenticationInfo':{'principalEmail':principal},'status':{'code':code},
        'requestMetadata':{'callerIp':'192.0.2.3'},'request':{'secret':'do-not-retain'}}}

def collect(pages,*,classes=['activity'],policy=None,max_pages=3):
    transport=Transport(pages)
    connector={'scopes':[SCOPE],'auth':{},'options':{'inventories':['audit_log'],
        'audit_window':{'start':START,'end':END,'classes':classes},'audit_detection_policy':policy or {},
        'max_pages':max_pages,'max_calls':10,'max_resources':100,'concurrency':1}}
    snapshot=candidate_gcp_collect(connector,['audit_log'],transport=transport)
    return snapshot,transport

def status(snapshot,cid):
    report=evaluate_snapshot(snapshot,checks=[cid])
    entries=[row for row in report['findings'] if row['check_id']==cid]
    assert len(entries)<=1
    return entries[0]['status'] if entries else 'NO_FINDING'

def test_selector_and_pagination_and_redaction():
    snap,t=collect([{'entries':[event()],'nextPageToken':'second'}, {'entries':[]}],policy={'approved_identity_admins':[]})
    assert len(t.calls)==2 and t.calls[1][2]['pageToken']=='second'
    assert status(snap,'gcp_logging_detect_t1136')=='FAIL'
    row=snap['collections'][0]['items'][0]
    assert 'request' not in row['protoPayload'] and 'do-not-retain' not in json.dumps(snap)
    assert snap['collections'][0]['audit_coverage']['absence_proves_no_event'] is False

def test_real_generic_dispatcher_reaches_private_gcp_collect_hook(monkeypatch):
    import peaso.collectors as generic
    import peaso.collectors.gcp as public_gcp
    t=Transport([{'entries':[event()]}])
    class FakeAuditCollector(AuditGCPCollector):
        def __init__(self, connector, requirements=None):
            super().__init__(connector, requirements, transport=t)
    monkeypatch.setattr(__import__('peaso.collectors.gcp_audit_native', fromlist=['AuditGCPCollector']), 'AuditGCPCollector', FakeAuditCollector)
    snap=generic.collect_live({'provider':'gcp','scopes':[SCOPE],'auth':{},'options':{
      'inventories':['audit_log'],'audit_window':{'start':START,'end':END,'classes':['activity']},
      'audit_detection_policy':{'approved_identity_admins':[]},'max_pages':3,'max_calls':10,'max_resources':100}},
      ['audit_log'])
    assert len(t.calls)==1 and status(snap,'gcp_logging_detect_t1136')=='FAIL'

def test_iam_resource_without_project_label_uses_scoped_log_name():
    row=event(); row['resource']['labels']={}
    snap,_=collect([{'entries':[row]}],policy={'approved_identity_admins':[]})
    assert status(snap,'gcp_logging_detect_t1136')=='FAIL'

def test_empty_inventory_is_empty_and_authorized_observed_event_passes():
    snap,_=collect([{'entries':[]}],policy={'approved_identity_admins':[]})
    assert status(snap,'gcp_logging_detect_t1136')=='EMPTY'
    snap,_=collect([{'entries':[event(principal='approved@example.com')]}],policy={'approved_identity_admins':['approved@example.com']})
    assert status(snap,'gcp_logging_detect_t1136')=='PASS'

def test_arbitrary_coverage_claim_cannot_prove_pass():
    snap,_=collect([{'entries':[]}],policy={'approved_identity_admins':[]})
    env=snap['collections'][0]
    env['audit_coverage']['verified_coverage']={'scope':SCOPE,'classes':['activity'],
        'routing':True,'retention':True,'read_access':True,'production':True,'ingestion':True}
    snap=make_snapshot('gcp',snap['scopes'],snap['collections'],created_at=snap['created_at'],metadata=snap['metadata'])
    assert status(snap,'gcp_logging_detect_t1136')=='EMPTY'

@pytest.mark.parametrize('cid,method,policy',[
 ('gcp_logging_detect_t1546','google.cloud.scheduler.v1.CloudScheduler.CreateJob',{'approved_automation_admins':[]}),
 ('gcp_logging_detect_t1546','google.devtools.cloudbuild.v1.CloudBuild.CreateBuildTrigger',{'approved_automation_admins':[]}),
])
def test_exact_positive(cid,method,policy):
    snap,_=collect([{'entries':[event(method=method)]}],policy=policy)
    assert status(snap,cid)=='FAIL'

def test_authorized_observed_trigger_passes_only_that_event():
    method='google.cloud.scheduler.v1.CloudScheduler.CreateJob'
    snap,_=collect([{'entries':[event(method=method,principal='approved@example.com')]}],
      policy={'approved_automation_admins':['approved@example.com']})
    assert status(snap,'gcp_logging_detect_t1546')=='PASS'

@pytest.mark.parametrize('bad',[
 ReadError('denied','permission_denied'),
 ReadError('unavailable','rate_exhausted'),
 {'entries':[{'malformed':True}]},
 {'entries':[event(project='other')]},
 {'entries':[event(ts='2026-10-14T00:01:00Z')]},
])
def test_denied_malformed_foreign_out_of_window_never_pass(bad):
    snap,_=collect([bad],policy={'approved_identity_admins':[]})
    assert status(snap,'gcp_logging_detect_t1136') in ('UNKNOWN','DENIED','NO_FINDING')

def test_page_limit_and_empty_page_token():
    snap,t=collect([{'entries':[],'nextPageToken':'next'}, {'entries':[event()],'nextPageToken':'third'}],
      policy={'approved_identity_admins':[]},max_pages=2)
    assert len(t.calls)==2
    report=evaluate_snapshot(snap,checks=['gcp_logging_detect_t1136'])
    statuses=[row['status'] for row in report['findings'] if row['check_id']=='gcp_logging_detect_t1136']
    assert statuses and set(statuses)<= {'UNKNOWN','DENIED'}

def test_default_planner_has_no_audit_request():
    transport=Transport([])
    connector={'scopes':[SCOPE],'auth':{},'options':{'inventories':[]}}
    collector=AuditGCPCollector(connector,[],transport=transport)
    assert collector.audit_selected is False and collector.needed==set() and transport.calls==[]

@pytest.mark.parametrize('options,requirements',[
    ({},None),
    ({'inventories':['bucket']},None),
    ({'inventories':['bucket']},['bucket']),
])
def test_ordinary_planner_preserved_bit_for_bit(options,requirements):
    connector={'scopes':[SCOPE],'auth':{},'options':options}
    original=GCPCollector(connector,requirements,transport=Transport([]))
    candidate=AuditGCPCollector(connector,requirements,transport=Transport([]))
    try:
        assert candidate.options==original.options
        assert candidate.wanted==original.wanted and candidate.needed==original.needed
        old_jobs=[job[:3] for job in original.scope_jobs(SCOPE)]
        new_jobs=[job[:3] for job in candidate.scope_jobs(SCOPE)]
        assert old_jobs==new_jobs and all(job[0]!='audit_log' for job in new_jobs)
        assert candidate.transport.calls==[]
    finally:
        original.hydration_pool.shutdown(wait=True)
        candidate.hydration_pool.shutdown(wait=True)

def test_exact_method_and_status_do_not_trigger_on_other_events():
    snap,_=collect([{'entries':[event(method='google.iam.admin.v1.DeleteServiceAccount')]}],
      policy={'approved_identity_admins':[]})
    assert status(snap,'gcp_logging_detect_t1136')=='UNKNOWN'
    snap,_=collect([{'entries':[event(code=7)]}],policy={'approved_identity_admins':[]})
    assert status(snap,'gcp_logging_detect_t1136')=='UNKNOWN'
    snap,_=collect([{'entries':[event(service='unrelated.googleapis.com')]}],policy={'approved_identity_admins':[]})
    assert status(snap,'gcp_logging_detect_t1136')=='UNKNOWN'
    snap,_=collect([{'entries':[event(resource_type='unrelated')]}],policy={'approved_identity_admins':[]})
    assert status(snap,'gcp_logging_detect_t1136')=='UNKNOWN'
    omitted=event(); omitted['protoPayload'].pop('status')
    snap,_=collect([{'entries':[omitted]}],policy={'approved_identity_admins':[]})
    assert status(snap,'gcp_logging_detect_t1136')=='UNKNOWN'

@pytest.mark.parametrize('incomplete', ['status', 'principal'])
def test_incomplete_event_does_not_suppress_independent_unauthorized_event(incomplete):
    valid=event(identity='valid')
    uncertain=event(identity='uncertain')
    if incomplete=='status': uncertain['protoPayload'].pop('status')
    else: uncertain['protoPayload']['authenticationInfo'].pop('principalEmail')
    snap,_=collect([{'entries':[valid,uncertain]}],policy={'approved_identity_admins':[]})
    report=evaluate_snapshot(snap,checks=['gcp_logging_detect_t1136'])
    findings=[row for row in report['findings'] if row['check_id']=='gcp_logging_detect_t1136']
    assert sorted(row['status'] for row in findings)==['FAIL','UNKNOWN']
    assert next(row for row in findings if row['status']=='FAIL')['evidence']['event_id']=='valid'

def test_unhashable_allowlist_rejected_at_collector_and_unknown_at_evaluator():
    options={'inventories':['audit_log'],'audit_window':{'start':START,'end':END,'classes':['activity']},
        'audit_detection_policy':{'approved_identity_admins':[{'unexpected':'object'}]},
        'max_pages':3,'max_calls':10,'max_resources':100}
    with pytest.raises(ValueError,match='invalid audit allowlist'):
        AuditGCPCollector({'scopes':[SCOPE],'auth':{},'options':options},['audit_log'],transport=Transport([]))
    snap,_=collect([{'entries':[event()]}],policy={'approved_identity_admins':[]})
    metadata={**snap['metadata'],'audit_detection_policy':{'approved_identity_admins':[{'unexpected':'object'}]}}
    malformed=make_snapshot('gcp',snap['scopes'],snap['collections'],created_at=snap['created_at'],metadata=metadata)
    assert status(malformed,'gcp_logging_detect_t1136')=='UNKNOWN'

def test_hosted_intake_accepts_bounded_gcp_audit_and_reaches_engine(monkeypatch):
    api=intake_module(monkeypatch)
    options={'inventories':['audit_log'],'audit_window':{'start':START,'end':END,'classes':['activity']},
        'audit_detection_policy':{'approved_identity_admins':[]},
        'max_pages':3,'max_calls':10,'max_resources':100}
    api.validate_connector('gcp',{'method':'token','token':'fixture-only'},options,
        SimpleNamespace(auth_mode='cognito'))
    transport=Transport([{'entries':[event()]}])
    snap=candidate_gcp_collect({'scopes':[SCOPE],'auth':{},'options':options},
        ['audit_log'],transport=transport)
    assert len(transport.calls)==1
    assert status(snap,'gcp_logging_detect_t1136')=='FAIL'

@pytest.mark.parametrize('mutation,provider,mode',[
    ({'audit_window':{'start':START,'end':END,'classes':['activity','extra']}},'gcp','cognito'),
    ({'audit_window':{'start':START,'end':END,'classes':[{}]}},'gcp','local'),
    ({'audit_detection_policy':{'approved_identity_admins':[{}]}},'gcp','local'),
    ({'audit_detection_policy':{'unknown_policy':[]}},'gcp','cognito'),
    ({'max_pages':101},'gcp','cognito'),
    ({'inventories':[]},'gcp','local'),
    ({},'aws','local'),
    ({'unexpected_outer_option':True},'gcp','cognito'),
])
def test_audit_intake_rejects_invalid_selection_before_scan(monkeypatch,mutation,provider,mode):
    api=intake_module(monkeypatch)
    options={'inventories':['audit_log'],'audit_window':{'start':START,'end':END,'classes':['activity']},
        'audit_detection_policy':{'approved_identity_admins':[]},
        'max_pages':3,'max_calls':10,'max_resources':100}
    options.update(mutation)
    auth={'method':'token','token':'fixture-only'} if provider=='gcp' else {}
    with pytest.raises(HTTPException) as exc:
        api.validate_connector(provider,auth,options,SimpleNamespace(auth_mode=mode))
    assert exc.value.status_code==422

def test_two_checks_share_one_scoped_event_parse(monkeypatch):
    import peaso.checks.gcp_audit_native as candidate
    original=candidate.read_scope; calls=[]
    def counted(index):
        calls.append(1)
        return original(index)
    monkeypatch.setattr(candidate,'read_scope',counted)
    snap,_=collect([{'entries':[event()]}],policy={
      'approved_identity_admins':[],'approved_automation_admins':[]})
    report=evaluate_snapshot(snap,checks=['gcp_logging_detect_t1136','gcp_logging_detect_t1546'])
    assert len(calls)==1 and len([x for x in report['findings'] if x['check_id'] in ELIGIBLE])==2

def test_no_explicit_selection_or_bounds_rejects_audit_job():
    options={'inventories':['audit_log'],'audit_window':{'start':START,'end':END,'classes':['activity']}}
    with pytest.raises(ValueError,match='max_pages'):
        AuditGCPCollector({'scopes':[SCOPE],'options':options},['audit_log'],transport=Transport([]))

@pytest.mark.parametrize('cid',sorted(ELIGIBLE))
def test_no_policy_is_unknown(cid):
    method=next(iter(__import__('peaso.checks.gcp_audit_native', fromlist=['METHODS']).METHODS.get(cid,{'x.List'})))
    snap,_=collect([{'entries':[event(method=method)]}])
    assert status(snap,cid)=='UNKNOWN'
