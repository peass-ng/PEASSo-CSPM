"""Selected-content copy uses complete detector facts, never status/text alone."""
from copy import deepcopy
import pytest
from peaso.checks.fixtures import CASES
from peaso.checks.selected_content_observed import observation
from peaso.checks import evaluate_check
from tests.azure_native_successor_inputs_20261020 import current_cases

CASES_BY_PROVIDER=[('azure','azure.review.app_service.selected_app_settings_secret_indicators'),
                   ('k8s','k8s.review.selected_literals.secret_indicators'),
                   ('azure','azure.review.acr.selected_image_secret_indicators'),
                   ('aws','aws.review.lambda.selected_environment_secret_indicators')]
def finding(provider,cid,branch):
    # Historical Azure CASES predate current native captures (for example ACR
    # per-file name/chunk parts); use the reviewed current successor inputs.
    case=current_cases(cid,CASES[cid])if provider=='azure'else CASES[cid];status,evidence=evaluate_check(cid,deepcopy(case[branch]),deepcopy(case.get(branch+'_index',case.get('index',{}))))
    return {'provider':provider,'check_id':cid,'status':status,'evidence':evidence}
@pytest.mark.parametrize('provider,cid',CASES_BY_PROVIDER)
@pytest.mark.parametrize('branch',['pass','fail'])
def test_native_fixture_observation_is_brief_and_honest(provider,cid,branch):
    value=finding(provider,cid,branch);assert value['status']==branch.upper()
    text=observation(value)
    assert text and len(text.split())<25
    assert ('likely secret was detected'in text)==(branch=='fail')
    from peaso.checks.azure_evidence_explanations import evidence_summary as azure
    from peaso.checks.k8s_evidence_explanations import evidence_summary as k8s
    from peaso.checks.aws_evidence_explanations import evidence_summary as aws
    result={'azure':azure,'k8s':k8s,'aws':aws}[provider](value)
    if provider=='azure':
        # Azure summaries now use reviewed plain-language lines (AGENTS.md):
        # 3-5 sentences that keep the same detected/not-detected outcome.
        lines=result.split('\n')
        assert 3<=len(lines)<=5 and all(line.endswith('.') for line in lines)
        assert ('likely secret' in lines[0])==(branch=='fail')
        assert ('no supported secret' in lines[0])==(branch=='pass')
    else:
        assert result.startswith(text)
    assert result.count('.')<=3
    assert observation({**value,'status':'FAIL'if branch=='pass'else'PASS'})is None
@pytest.mark.parametrize('provider,cid',CASES_BY_PROVIDER)
@pytest.mark.parametrize('fault',['status_only','raw_text','incomplete','engine_missing','wrong_version','unverified','invalid_leak','empty_literals','malformed_parts'])
def test_unproven_or_contradictory_copy_is_not_invented(provider,cid,fault):
    value=finding(provider,cid,'fail');e=value['evidence']
    if fault=='status_only':value['evidence']={}
    elif fault=='raw_text':value['evidence']={'observed':'ATTACKER CONTROLLED CLAIM'}
    elif fault=='incomplete':e['complete']=False
    elif fault=='engine_missing':(e['engines']if provider=='aws'else e['parts'][0]['engines']).pop()
    elif fault=='wrong_version':(e['engines']if provider=='aws'else e['parts'][0]['engines'])[0]['version']='unknown'
    elif fault=='unverified':e['credential_validation']='attempted'
    elif fault=='invalid_leak':e['secret_leaks']=[{'value':'raw-secret'}]
    elif fault=='empty_literals':
        if '.acr.' in cid:e['parts']=[]
        elif provider=='aws':e['variable_count']=0
        else:e['literal_count']=0
    elif fault=='malformed_parts':e['engines'if provider=='aws'else'parts']=['not-a-part']
    assert observation(value)is None
