"""A tenant risk decision with zero real policy resources; no fake cloud object."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from urllib.parse import urlsplit

import pytest
from peaso.collectors import azure, collect_live, azure_geo_consideration_native as native
from tests.archived_check_contract import archived_registry
from tests.archived_check_contract import evaluate_snapshot, plan_collection
from peaso.snapshot import make_snapshot, resources
from peaso.server.validation import validate_connector
from tests.test_peaso_azure_geo_consideration_native import case, SCOPE, TENANT
from tests.test_peaso_collectors_azurek8s import FakeAzure

DEVICE = 'azure.cis.exclusionary_device_code_flow_policy_considered'


def capture(monkeypatch, decision='noBlockRequired', approval=True, nonempty=False):
    policy, location, config, context = case(decision)
    policy.pop('_provenance'); location.pop('_provenance')
    def response(url, body, audience):
        assert body is None and audience == azure.GRAPH
        path = urlsplit(url).path
        if path == native.POLICIES: return {'value':[deepcopy(policy)] if nonempty else []}
        if path == native.LOCATIONS: return {'value':[deepcopy(location)]}
        if path == '/v1.0/users': return {'value':[]}
        if path == '/v1.0/policies/identitySecurityDefaultsEnforcementPolicy': return {'id':'defaults','isEnabled':False}
        assert path == '/v1.0/policies/authenticationStrengthPolicies'
        return {'value':[]}
    transport = FakeAzure(response); transport.tenant=transport.verified_tenant=TENANT
    monkeypatch.setattr(azure,'AzureTransport',lambda auth:transport)
    monkeypatch.setattr(azure,'AzureTransportExposure',lambda auth:transport)
    options={'retries':1,'concurrency':1}
    if approval: options['compliance_policy']=deepcopy(context['metadata']['compliance_policy'])
    auth={'method':'token','arm_token':'inert','graph_token':'inert'}
    validate_connector('azure',auth,options,SimpleNamespace(auth_mode='cognito'))
    connector={'provider':'azure','scopes':['/subscriptions/11111111-1111-1111-1111-111111111111'],'auth':auth,'options':options}
    snapshot=collect_live(connector,plan_collection({'connector':connector,'checks':[native.CID,DEVICE]}))
    assert transport.closed
    return snapshot


def changed(snapshot, mutate):
    value=deepcopy(snapshot); mutate(value)
    return make_snapshot(value['provider'],value['scopes'],value['collections'],created_at=value['created_at'],metadata=value['metadata'])


def collection(snapshot):
    return next(c for c in snapshot['collections'] if c['type']=='conditional_access_policy')


def findings(snapshot, selected=None, include=True):
    report=evaluate_snapshot(snapshot,checks=selected or [native.CID],include_not_applicable=include)
    return report, [f for f in report['findings'] if f['check_id']==native.CID]


def test_normal_hosted_empty_policies_are_still_a_scoped_reviewed_decision(monkeypatch):
    snapshot=capture(monkeypatch)
    before=deepcopy(snapshot)
    report, rows=findings(snapshot,include=False)
    assert collection(snapshot)['status']=='empty' and collection(snapshot)['items']==[]
    assert not [r for r in resources(snapshot) if r['type']=='conditional_access_policy']
    assert len(rows)==1 and rows[0]['status']=='PASS' and rows[0]['resource_id']=='scope:'+SCOPE
    assert rows[0]['evidence']['decision']=='noBlockRequired'
    assert 'no enforced block' in rows[0]['evidence']['semantics']
    assert snapshot==before
    check=next(c for c in report['coverage'] if c.get('check_id')==native.CID)
    inventory=next(c for c in report['coverage'] if c['level']=='collection' and c['type']=='conditional_access_policy')
    assert check['target']=='scope' and check['status']=='evaluated' and check['by_status']=={'PASS':1}
    assert inventory['status']=='empty' and inventory['resource_count']==0


@pytest.mark.parametrize('mode', ['unverified_metadata','foreign_metadata_tenant','unverified_collection',
    'foreign_collection_tenant','foreign_collection_scope','wrong_service','credential_mismatch','customer_mismatch',
    'missing_binding','missing_scope_binding','read_write_proof','malformed_readonly','wrong_endpoint',
    'stale_review','future_review','foreign_review','missing_owner','missing_rationale','wrong_user_scope',
    'wrong_context_binding','empty_error','continuation'])
def test_explicit_but_unproved_empty_decisions_never_pass(monkeypatch,mode):
    snapshot=capture(monkeypatch)
    def mutate(value):
        meta=value['metadata']; env=collection(value); proof=env['_provenance']; review=meta['compliance_policy']['sw13']
        now=datetime.fromisoformat(value['created_at'])
        if mode=='unverified_metadata': meta['tenant_verified']=False
        if mode=='foreign_metadata_tenant': meta['tenant_id']='33333333-3333-3333-3333-333333333333'
        if mode=='unverified_collection': proof['tenant_verified']=False
        if mode=='foreign_collection_tenant': proof['tenant_id']='33333333-3333-3333-3333-333333333333'
        if mode=='foreign_collection_scope': env['scope']='/tenants/33333333-3333-3333-3333-333333333333'
        if mode=='wrong_service': env['service']='UnverifiedSource'
        if mode=='credential_mismatch': proof['credential_context_id']='foreign'
        if mode=='customer_mismatch': proof['customer_context_id']='foreign'
        if mode=='missing_binding': proof.pop('credential_context_id')
        if mode=='missing_scope_binding': meta.pop('customer_context_id')
        if mode=='read_write_proof': proof['read_only']=False
        if mode=='malformed_readonly': proof['read_only']='false'
        if mode=='wrong_endpoint': proof['endpoint']='/v1.0/users'
        if mode=='stale_review': review['expires_at']=(now-timedelta(minutes=1)).isoformat()
        if mode=='future_review': review['observed_at']=(now+timedelta(minutes=1)).isoformat()
        if mode=='foreign_review': review['scope']='/tenants/33333333-3333-3333-3333-333333333333'
        if mode=='missing_owner': review['authorized_by']=''
        if mode=='missing_rationale': review['checks'][native.KEY]['consideration']['rationale']=''
        if mode=='wrong_user_scope': review['checks'][native.KEY]['userScope']='designated'
        if mode=='wrong_context_binding': meta['context_binding']='imported_unverified'
        if mode=='empty_error': env['error']={'code':'incomplete'}
        if mode=='continuation': env['nextLink']='https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies?next=1'
    report,rows=findings(changed(snapshot,mutate))
    assert rows and {f['status'] for f in rows}=={'UNKNOWN'},rows
    assert all(f['resource_id'].startswith('scope:') for f in rows)
    assert all(c['status']=='unknown' for c in report['coverage'] if c.get('check_id')==native.CID)


def test_empty_block_decision_cannot_invent_a_policy_gap_or_success(monkeypatch):
    _,rows=findings(capture(monkeypatch,decision='block'))
    assert rows and {f['status'] for f in rows}=={'UNKNOWN'}


def test_no_declared_review_and_other_check_keep_default_empty(monkeypatch):
    snapshot=capture(monkeypatch,approval=False)
    report,rows=findings(snapshot,[native.CID,DEVICE])
    assert rows and {f['status'] for f in report['findings']}=={'EMPTY'}
    assert all(c['status']=='empty' for c in report['coverage'] if c.get('level')=='check')
    assert all('target' not in c for c in report['coverage'] if c.get('level')=='check')


@pytest.mark.parametrize('status,expected', [('partial','UNKNOWN'),('denied','DENIED'),('unknown','UNKNOWN'),
    ('timeout','UNKNOWN'),('not_collected','UNKNOWN'),('malformed','UNKNOWN'),('collected','UNKNOWN')])
def test_callback_is_never_invoked_for_nonempty_statuses(monkeypatch,status,expected):
    snapshot=capture(monkeypatch); called=[]
    callback=next(c.evaluate for c in archived_registry([native.CID]) if c.id==native.CID)
    monkeypatch.setattr(callback,'evaluate_empty_inventory',lambda *args: called.append(args) or ('PASS',{}), raising=False)
    updated=changed(snapshot,lambda value: collection(value).update(status=status))
    _,rows=findings(updated)
    assert not called and {f['status'] for f in rows}=={expected}


@pytest.mark.parametrize('mode',['exception','invalid_status','invalid_evidence','invalid_arity','mutation','envelope_mutation'])
def test_callback_errors_are_scoped_unknown_and_do_not_leak(monkeypatch,mode):
    snapshot=capture(monkeypatch); before=deepcopy(snapshot)
    def callback(context,env):
        if mode=='exception': raise RuntimeError('NEVER_RETAIN_CALLBACK_SECRET')
        if mode=='invalid_status': return 'BROKEN',{}
        if mode=='invalid_evidence': return 'PASS',[]
        if mode=='invalid_arity': return 'PASS',{},'extra'
        if mode=='envelope_mutation':
            env['_provenance']['tenant_verified']=False
        env['items'].append({'id':'fake'})
        return 'PASS',{}
    evaluate=next(c.evaluate for c in archived_registry([native.CID]) if c.id==native.CID)
    monkeypatch.setattr(evaluate,'evaluate_empty_inventory',callback, raising=False)
    report,rows=findings(snapshot)
    assert rows and {f['status'] for f in rows}=={'UNKNOWN'}
    assert snapshot==before and rows[0]['resource_id']=='scope:'+SCOPE
    import json
    assert 'NEVER_RETAIN_CALLBACK_SECRET' not in json.dumps(report)


def test_empty_callback_is_not_called_for_actual_policy_resources(monkeypatch):
    snapshot=capture(monkeypatch,nonempty=True); called=[]
    evaluate=next(c.evaluate for c in archived_registry([native.CID]) if c.id==native.CID)
    monkeypatch.setattr(evaluate,'evaluate_empty_inventory',lambda *args: called.append(args) or ('UNKNOWN',{}), raising=False)
    report,rows=findings(snapshot)
    assert not called and rows and {f['status'] for f in rows}=={'PASS'}
    assert all(not f['resource_id'].startswith('scope:') for f in rows)


def test_duplicate_empty_envelopes_are_rejected_before_any_decision(monkeypatch):
    snapshot=capture(monkeypatch)
    with pytest.raises(ValueError,match='duplicate collection'):
        changed(snapshot,lambda value: value['collections'].append(deepcopy(collection(value))))
