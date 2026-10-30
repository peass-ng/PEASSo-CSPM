from tests.observed_evidence_successors import assert_original_evidence_preserved
"""Hash-bound guidance and independent native/signed-fixture callback replay."""
from copy import deepcopy
import gzip
import hashlib
import inspect
import json
from pathlib import Path
import pytest
from peaso.checks import CHECKS
from peaso.checks.catalog import _base_description_for
from peaso.checks.aws_bulk_clarity_reviewed import ROWS,_digest,description,remediation,severity_review
from peaso.checks.aws_bulk_finding_summary import evidence_summary
ROOT=Path(__file__).resolve().parents[1]
CHECK_BY_ID={c.id:c for c in CHECKS}
CASES=json.loads(gzip.decompress((ROOT/'tests/fixtures/aws_bulk_clarity_reviewed.json.gz').read_bytes()))

@pytest.mark.parametrize('cid',sorted(ROWS))
def test_concise_how_preserves_actual_source_contracts_and_provenance(cid):
    original=_base_description_for(cid);before=deepcopy(original);actual=description(cid,original)
    assert original==before
    assert len(actual['description'].split())<=40
    assert {k:v for k,v in actual.items() if k!='description'}=={k:v for k,v in original.items() if k!='description'}

@pytest.mark.parametrize('cid',sorted(ROWS))
def test_new_guidance_is_brief_text_only_with_explicit_binding_and_references(cid):
    assert ROWS[cid]['remediation_base_sha256']==_digest(None)
    actual=remediation(cid,None)
    assert actual['review_status']=='approved'
    assert len(actual['steps'])==1 and len(actual['steps'][0].split())<=40
    assert len(actual['caveats'])==1
    assert actual['cli']==[] and not actual.get('iac')
    assert actual['field_binding']['kind']==CHECK_BY_ID[cid].kind
    assert actual['field_binding']['fields']
    assert all(x['url'].startswith('https://docs.aws.amazon.com/') for x in actual['references'])

@pytest.mark.parametrize('cid',sorted(ROWS))
@pytest.mark.parametrize('kind,apply',[('description',description),('remediation',remediation)])
def test_unreviewed_description_or_template_sources_fail_closed(cid,kind,apply):
    original=deepcopy(_base_description_for(cid)) if kind=='description' else {}
    original['unreviewed']='drift'
    with pytest.raises(ValueError,match='Reviewed AWS bulk clarity base changed'):apply(cid,original)


def _stable(v):
    if inspect.isfunction(v):return {'callable':v.__module__+'.'+v.__qualname__}
    if isinstance(v,dict):return {str(k):_stable(x) for k,x in sorted(v.items())}
    if isinstance(v,(list,tuple)):return [_stable(x) for x in v]
    if isinstance(v,(set,frozenset)):return sorted(_stable(x) for x in v)
    if isinstance(v,(str,int,float,bool)) or v is None:return v
    if hasattr(v,'isoformat') and v.__class__.__module__=='datetime':return {'datetime':v.isoformat()}
    if hasattr(v,'pattern') and hasattr(v,'flags'):return {'regex':v.pattern,'flags':v.flags}
    return {'type':type(v).__name__}

def _closure_digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()

# 334b8376 memoized the sw46 inventory joins (_items now delegates to
# _validated_items, _resource reuses a per-index lookup) and shifted later
# callback line numbers; every other callback body hash is unchanged.
BINDING_SUCCESSORS={
    'aws_nist_sns_topic_notification_delivery_status_enabled':{
        'historical_predicate_sources':'e866c03c80996d786c81166599bd2a92379806454521350113cd082067d9e479',
        'historical_constants':'3732e2e665c4ae7db552be8e89506c8cfe3878a198f9a98643c0d7e3a1c168ce',
        'current_predicate_sources':'56409bd070a0947e61480248239601f858334c003959ebe62a86b4ae9ad08da2',
        'current_constants':'48017d284b97d753604309aabbe565e5ed0b058a45262f9415787c5b827aa5d2'},
    'aws_shield_ddos_detected_alarm':{
        'historical_predicate_sources':'abf717caa44284910561687ec81385050cde56c09e37645f59bb7f24fce98f93',
        'historical_constants':'bfa1d75e683bd2e2df425c4e661adea290a4385a0a8ec5c6d1c8a4f46f14a096',
        'current_predicate_sources':'bdf9b152e76b59c2d91251f6e040342d506998691e58e82d7faf14788a9d683a',
        'current_constants':'a4e12c6f9c4ba504acf5263344752abb3695f11e514e3d27f8248faec1a56b2c'},
}

@pytest.mark.parametrize('cid',sorted(ROWS))
def test_real_default_callbacks_dispatch_closures_constants_and_severities_are_pinned(cid):
    c=CHECK_BY_ID[cid];binding=ROWS[cid]['reviewed_binding'];f=inspect.unwrap(c.evaluate)
    assert binding['kind']==c.kind
    assert binding['module']==f.__module__ and binding['source_qualname']==f.__qualname__
    assert binding['closure']==_stable(inspect.getclosurevars(f).nonlocals)
    assert binding['defaults']==_stable(f.__defaults__)
    funcs={};pending=[f];g=f.__globals__
    for key in ['_EVALUATORS','EVALUATORS']:
        if isinstance(g.get(key),dict) and inspect.isfunction(g[key].get(cid)):pending.append(g[key][cid])
    while pending:
        fn=pending.pop();key=fn.__module__+'.'+fn.__qualname__+':'+str(fn.__code__.co_firstlineno)
        if key in funcs:continue
        funcs[key]=fn
        values=list(inspect.getclosurevars(fn).nonlocals.values())+list(fn.__defaults__ or ())
        values.extend(fn.__globals__.get(k) for k in fn.__code__.co_names)
        for value in values:
            if inspect.isfunction(value) and ('_bulk_pending_' in value.__module__ or (cid=='aws_cis_aws_resource_policy_unrestricted_principal' and value.__module__==f.__module__)):pending.append(value)
    sources={k:hashlib.sha256(inspect.getsource(v).encode()).hexdigest() for k,v in sorted(funcs.items())}
    constants={}
    for key,fn in funcs.items():
        for name in fn.__code__.co_names:
            value=fn.__globals__.get(name)
            if name.isupper() and value is not None and not inspect.ismodule(value) and not inspect.isclass(value) and not inspect.isfunction(value):constants[key+'::'+name]=_stable(value)
    successor=BINDING_SUCCESSORS.get(cid)
    if successor is None:
        assert binding['predicate_sources']==sources
        assert binding['constants']==constants
    else:
        # The reviewed binding stays historical; only this exact current
        # callback closure and constant set is admitted after the edit.
        assert _closure_digest(binding['predicate_sources'])==successor['historical_predicate_sources']
        assert _closure_digest(binding['constants'])==successor['historical_constants']
        assert _closure_digest(sources)==successor['current_predicate_sources']
        assert _closure_digest(constants)==successor['current_constants']
    assert severity_review(cid,c.severity)==ROWS[cid]['reviewed_severity']
    with pytest.raises(ValueError):severity_review(cid,'changed')

@pytest.mark.parametrize('cid',sorted(ROWS))
def test_independent_native_and_signed_wave_fixture_replay(cid):
    # Native API-stub tests and original signed-wave test constructors supplied
    # these item/index facts. They are local fixtures, not cloud acceptance.
    assert 'PASS' in CASES[cid] and 'FAIL' in CASES[cid]
    for expected,case in CASES[cid].items():
        item,index=deepcopy((case['item'],case['index']))
        status,evidence=CHECK_BY_ID[cid].evaluate(item,index)
        assert status==expected,(cid,expected,status,evidence)
        assert_original_evidence_preserved(cid, json.loads(json.dumps(evidence)), case['evidence'])
        finding={'provider':'aws','status':status,'check_id':cid,'evidence':evidence};before=deepcopy(finding)
        summary=evidence_summary(finding)
        if status != 'FAIL':assert summary is None
        if summary:assert len(summary)<260
        assert finding==before


def test_nonfailure_unknown_or_unowned_findings_do_not_become_confirmed_observations():
    cid=next(iter(ROWS))
    for status in ['PASS','UNKNOWN','MANUAL','DENIED','NOT_APPLICABLE']:
        assert evidence_summary({'provider':'aws','status':status,'check_id':cid,'evidence':{}}) is None
    assert evidence_summary({'provider':'gcp','status':'FAIL','check_id':cid,'evidence':{}}) is None
    assert evidence_summary({'provider':'aws','status':'FAIL','check_id':'unowned','evidence':{}}) is None
    assert evidence_summary({'provider':'aws','status':'FAIL','check_id':cid,'evidence':None}) is None
    original={'nested':[]};result=description('unowned',original);result['nested'].append(1)
    assert original['nested']==[]


def test_known_stale_how_claims_are_replaced_by_actual_predicates():
    assert 'global Classic, regional Classic and WAFv2' in ROWS['aws_nist_waf_web_acl_logging_enabled']['description_fields']['description']
    assert 'missing or zero windows fail' in ROWS['aws_nist_rds_db_cluster_aurora_backtracking_enabled']['description_fields']['description']
    for cid in ['aws.pci.sns.delivery_status_logging','aws_nist_sns_topic_notification_delivery_status_enabled']:
        assert 'success/failure' in ROWS[cid]['description_fields']['description']
        assert 'sampling' in ROWS[cid]['description_fields']['description']
    assert 'HTTP APIs have no execution-logging applicability' in ROWS['aws_nist_apigateway_stage_logging_enabled']['description_fields']['description']


def test_zero_backtrack_window_is_disabled_not_configuration_presence():
    cid='aws_nist_rds_db_cluster_aurora_backtracking_enabled'
    item,index=deepcopy((CASES[cid]['FAIL']['item'],CASES[cid]['FAIL']['index']))
    item['BacktrackWindow']=0
    # The real captured complete inventory holds the same subject value.
    assert CHECK_BY_ID[cid].evaluate(item,index)[0]=='FAIL'
    assert evidence_summary({'provider':'aws','status':'FAIL','check_id':cid,'evidence':{'backtrack_window':0}})=='Aurora BacktrackWindow is zero, so backtracking is disabled.'


def test_user_data_summary_never_exposes_credential_material():
    finding={'provider':'aws','status':'FAIL','check_id':'aws_autoscaling_userdata_plaintext_aws_key','evidence':{'secret_access_key':'DO-NOT-PRINT','UserData':'DO-NOT-PRINT'}}
    assert evidence_summary(finding) is None

@pytest.mark.parametrize('protocol,port',[('tcp',443),(6,22),('udp',53)])
def test_native_public_path_summary_names_configured_port_without_claiming_listener(protocol,port):
    evidence={'configured_path_witness':{'model':'aws-public-config-witness-v1','public_address':'8.8.8.8','protocol':protocol,'destination_port':port,'application_listening':'unknown'}}
    summary=evidence_summary({'provider':'aws','status':'FAIL','check_id':'aws.nist.ec2_instance_effective_public_reachability','evidence':evidence})
    assert f'/{port} ingress' in summary and 'a listening service is unverified' in summary


@pytest.mark.parametrize('cid',sorted(ROWS))
@pytest.mark.parametrize('evidence',[{}, {'unrelated':True}, {'configured_path_witness':{'protocol':'tcp','destination_port':22}}, {'healthy_target_zones':[None]}, {'missing_feedback_protocols':[{}]}, {'rules_without_alarm':[None]}])
def test_missing_and_wrong_shape_witnesses_do_not_get_static_observations(cid,evidence):
    assert evidence_summary({'provider':'aws','status':'FAIL','check_id':cid,'evidence':evidence}) is None

@pytest.mark.parametrize('cid',sorted(ROWS))
def test_native_positive_evidence_relabelled_fail_does_not_invent_weakness(cid):
    evidence=CASES[cid]['PASS']['evidence']
    assert evidence_summary({'provider':'aws','status':'FAIL','check_id':cid,'evidence':evidence}) is None


def test_resource_policy_scope_successor_preserves_historical_review_and_structured_witness():
    cid='aws_cis_aws_resource_policy_unrestricted_principal'
    archived=json.loads((ROOT/'tests/fixtures/aws_resource_policy_pre_scope_review.json').read_text())
    assert archived['check_id']==cid and len(archived['source_sha256'])==64
    assert archived['cases']['FAIL']['evidence']['unrestricted_statements']==['one']
    case=CASES[cid]['FAIL'];status,evidence=CHECK_BY_ID[cid].evaluate(deepcopy(case['item']),deepcopy(case['index']))
    assert status=='FAIL'
    assert evidence['unrestricted_statements']==[{'statement_index':0,'sid':'one'}]
    assert 'declaration review' in evidence['semantics']
    summary=evidence_summary({'provider':'aws','status':status,'check_id':cid,'evidence':evidence})
    assert summary=='1 resource-policy statements grant wildcard principals access without a recognized caller or network boundary.'
    for index in [-1, True, '0', None]:
        invalid=deepcopy(evidence);invalid['unrestricted_statements'][0]['statement_index']=index
        assert evidence_summary({'provider':'aws','status':status,'check_id':cid,'evidence':invalid}) is None
