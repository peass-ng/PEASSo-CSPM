"""Replay real native facts and prove source guards for specific reviewed compute/storage controls."""
from copy import deepcopy
import hashlib
import inspect
import json
import os
from pathlib import Path
import pytest
from peaso.checks import CHECK_ALIASES,CHECKS
from peaso.checks.catalog import _base_description_for
from peaso.checks.fixtures import CASES
from peaso.checks.aws_compute_storage_clarity_reviewed import ROWS,_digest,description,remediation
from peaso.checks.aws_compute_storage_finding_summary import evidence_summary

CHECK_BY_ID={c.id:c for c in CHECKS}
SELECTED=sorted(cid for cid,row in ROWS.items() if not os.getenv('PEASS_REVIEW_BATCH') or row['batch']==os.getenv('PEASS_REVIEW_BATCH'))
PACK=Path(__file__).resolve().parents[1]/'peaso/rulepacks'
# fe6f7901 (#104) retired overlapping ids as aliases of surviving natives;
# their reviewed copy rows stay as history but no longer own a predicate.
RETIRED=sorted(cid for cid in SELECTED if cid in CHECK_ALIASES)
ACTIVE=[cid for cid in SELECTED if cid not in CHECK_ALIASES]

@pytest.mark.parametrize('cid',RETIRED)
def test_retired_reviewed_rows_resolve_to_registered_survivor(cid):
    assert cid not in CHECK_BY_ID and CHECK_ALIASES[cid] in CHECK_BY_ID

@pytest.fixture(scope='module')
def originals():
    out={cid:None for cid in SELECTED if ROWS[cid]['remediation_base_sha256']==_digest(None)}
    for path in PACK.glob('remediation*.json'):
        value=json.loads(path.read_text())
        if not isinstance(value,dict):continue
        for cid in SELECTED:
            if cid in value and _digest(value[cid])==ROWS[cid]['remediation_base_sha256']:out[cid]=value[cid]
    assert set(out)==set(SELECTED)
    return out

@pytest.mark.parametrize('cid',SELECTED)
def test_guarded_copy_preserves_source_contract_and_approved_instructions(cid,originals):
    original=_base_description_for(cid);saved=deepcopy(original);actual=description(cid,original)
    assert original==saved
    assert 5<=len(actual['description'].split())<=45
    changed=set(ROWS[cid]['description_fields'])
    assert changed <= ({'description','pass_when','fail_when'} if cid.startswith('aws.cb.lightsail.') else {'description'})
    assert {k:v for k,v in actual.items() if k not in changed}=={k:v for k,v in original.items() if k not in changed}
    original=originals[cid];saved=deepcopy(original);actual=remediation(cid,original)
    assert original==saved
    assert actual['steps']==[actual['summary']]
    assert len(actual['summary'].split())<=40
    assert len(actual['caveats'])==1
    if ROWS[cid]['new_text_only_template']:
        assert actual['review_status']=='approved' and actual['cli']==[] and 'iac' not in actual
        assert set(actual)=={'summary','steps','caveats','references','cli','review_status'}
    else:
        changed=ROWS[cid]['remediation_fields']
        assert {k:v for k,v in actual.items() if k not in changed}=={k:v for k,v in original.items() if k not in changed}
        assert actual.get('references')==original.get('references')
        assert actual.get('cli')==original.get('cli')
        assert actual.get('iac')==original.get('iac')

@pytest.mark.parametrize('cid',ACTIVE)
def test_review_binds_actual_predicate_and_source_severity(cid):
    row=ROWS[cid];check=CHECK_BY_ID[cid];fn=inspect.unwrap(check.evaluate)
    assert row['reviewed_binding']['kind']==check.kind
    assert row['reviewed_binding']['predicate_qualname']==fn.__qualname__
    assert row['reviewed_binding']['predicate_source_sha256']==hashlib.sha256(inspect.getsource(fn).encode()).hexdigest()
    cv=inspect.getclosurevars(fn)
    for name,expected in row['reviewed_binding'].get('closure',{}).items():
        value=cv.nonlocals[name]
        if isinstance(value,set):value=sorted(value)
        elif isinstance(value,tuple):value=list(value)
        assert value==expected
    delegates=[]
    for value in list(cv.nonlocals.values())+list(fn.__defaults__ or ()):
        if inspect.isfunction(value):delegates.append(value)
    for name in ('EVALUATORS','_EVALUATORS'):
        if cid in cv.globals.get(name,{}):delegates.append(cv.globals[name][cid])
    actual_delegates=[{'qualname':d.__qualname__,'sha256':hashlib.sha256(inspect.getsource(d).encode()).hexdigest()} for d in delegates]
    if 'delegates' in row['reviewed_binding']:assert row['reviewed_binding']['delegates']==actual_delegates
    if 'helper_contract' in row['reviewed_binding']:
        from peaso.checks.claude_aws_b_compute import _open_ports
        assert row['reviewed_binding']['helper_contract']['source_sha256']==hashlib.sha256(inspect.getsource(_open_ports).encode()).hexdigest()
    assert row['reviewed_source_severity']==check.severity
    assert row['reviewed_severity'] in {'critical','high','medium','low','info'}

@pytest.mark.parametrize('cid',ACTIVE)
def test_actual_native_outcomes_and_concise_observations_do_not_mutate_evidence(cid):
    cases=CASES.get(cid) or json.loads((Path(__file__).parent/'fixtures/aws_compute_storage_signed_cases.json').read_text()).get(cid)
    if cid=='aws_g6_ecs_fargate_storage_encryption':
        # Legacy tests replace this global CASES entry with intentionally
        # incomplete examples. Replay the reviewed immutable authority fixture.
        cases=json.loads((Path(__file__).parent/'fixtures/aws_compute_storage_signed_cases.json').read_text())[cid]
    if cid=='aws.ec2.imdsv2':
        cases={'pass':{'MetadataOptions':{'HttpEndpoint':'enabled','HttpTokens':'required'}},'fail':{'MetadataOptions':{'HttpEndpoint':'enabled','HttpTokens':'optional'}},'unknown':{'MetadataOptions':{'HttpEndpoint':'broken'}}}
    assert cases is not None
    check=CHECK_BY_ID[cid];outcomes=set()
    for state in ('pass','fail','missing','malformed','unknown','manual','not_applicable','na'):
        if state not in cases:continue
        status,evidence=check.evaluate(deepcopy(cases[state]),deepcopy(cases.get(state+'_index',cases.get('index',{}))))
        value={'provider':'aws','check_id':cid,'status':status,'evidence':evidence};before=deepcopy(value)
        summary=evidence_summary(value)
        assert value==before
        if status=='FAIL':
            assert summary==ROWS[cid]['observed_fail']
            assert len(summary.split())<=40
            assert len(summary)<300
        else:assert summary is None
        outcomes.add(status)
    if ROWS[cid].get('no_fail_outcome'):
        assert 'FAIL' not in outcomes and 'PASS' in outcomes
    else:
        assert {'PASS','FAIL'}<=outcomes

@pytest.mark.parametrize('cid',SELECTED)
def test_guard_rejects_changed_source_text_or_template(cid,originals):
    for original,apply in [(_base_description_for(cid),description),(originals[cid],remediation)]:
        altered=deepcopy(original) if isinstance(original,dict) else {}
        altered['unexpected_drift']=True
        with pytest.raises(ValueError,match='Reviewed compute/storage clarity base changed'):apply(cid,altered)


def test_uncertain_foreign_and_unowned_rows_keep_their_existing_observations():
    cid=next(iter(ROWS))
    for value in [None,{}, {'provider':'gcp','status':'FAIL','check_id':cid,'evidence':{}},{'provider':'aws','status':'UNKNOWN','check_id':cid,'evidence':{}},{'provider':'aws','status':'FAIL','check_id':'unowned','evidence':{}}]:
        assert evidence_summary(value) is None
