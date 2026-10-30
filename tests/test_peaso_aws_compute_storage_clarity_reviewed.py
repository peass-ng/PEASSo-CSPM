"""Replay real native facts and prove source guards for specific reviewed compute/storage controls."""
from copy import deepcopy
import json
import os
from pathlib import Path
import pytest
from peaso.checks import CHECKS
from peaso.checks.fixtures import CASES
from peaso.checks.aws_compute_storage_clarity_reviewed import ROWS, _digest
from peaso.checks.aws_compute_storage_finding_summary import evidence_summary

CHECK_BY_ID={c.id:c for c in CHECKS}
SELECTED=sorted(cid for cid,row in ROWS.items() if not os.getenv('PEASS_REVIEW_BATCH') or row['batch']==os.getenv('PEASS_REVIEW_BATCH'))
PACK=Path(__file__).resolve().parents[1]/'peaso/rulepacks'

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


def test_uncertain_foreign_and_unowned_rows_keep_their_existing_observations():
    cid=next(iter(ROWS))
    for value in [None,{}, {'provider':'gcp','status':'FAIL','check_id':cid,'evidence':{}},{'provider':'aws','status':'UNKNOWN','check_id':cid,'evidence':{}},{'provider':'aws','status':'FAIL','check_id':'unowned','evidence':{}}]:
        assert evidence_summary(value) is None
