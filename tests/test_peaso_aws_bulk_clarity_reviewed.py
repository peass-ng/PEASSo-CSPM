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
from peaso.checks.aws_bulk_clarity_reviewed import ROWS, description
from peaso.checks.aws_bulk_finding_summary import evidence_summary
ROOT=Path(__file__).resolve().parents[1]
CHECK_BY_ID={c.id:c for c in CHECKS}
CASES=json.loads(gzip.decompress((ROOT/'tests/fixtures/aws_bulk_clarity_reviewed.json.gz').read_bytes()))


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


