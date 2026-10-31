from copy import deepcopy
import pytest
from peaso.checks import k8s_kubelet_configmap_review_20261020 as native
from peaso.checks.fixtures import CASES
from peaso.checks.k8s_kubelet_declaration_observed_20261020 import observation
from peaso.checks.k8s_evidence_explanations import evidence_summary


@pytest.mark.parametrize('cid',native.IDS)
@pytest.mark.parametrize('branch',['pass','fail'])
def test_exact_native_declaration_brief(cid,branch):
    cases=CASES[cid]
    status,evidence=native.evaluate(cid,cases[branch],cases[branch+'_index'])
    finding={'provider':'k8s','check_id':cid,'status':status,'evidence':evidence}
    assert observation(finding)==evidence['observed']
    assert evidence_summary(finding)==evidence['observed']
    assert len(evidence['observed'].split())<50
    for key,value in [('scope','node_runtime'),('field','other'),('raw_content_retained',True),('observed','Nodes are secure.')]:
        bad=deepcopy(finding);bad['evidence'][key]=value
        assert observation(bad) is None
    bad=deepcopy(finding);bad['status']='FAIL' if status=='PASS' else 'PASS'
    assert observation(bad) is None


@pytest.mark.parametrize('cid',native.IDS)
@pytest.mark.parametrize('branch',['unknown','empty'])
def test_exact_native_unknown_declaration_stays_uncertain_and_brief(cid,branch):
    cases=CASES[cid]
    status,evidence=(native.evaluate_empty({}, {}) if branch=='empty' else
                     native.evaluate(cid,cases['unknown'],cases['unknown_index']))
    assert status=='UNKNOWN'
    finding={'provider':'k8s','check_id':cid,'status':status,'evidence':evidence}
    before=deepcopy(finding)
    summary=observation(finding)
    assert summary and len(summary.split())<40 and 'Node configuration was not assessed.' in summary
    assert evidence_summary(finding)==summary and finding==before
    for key,value in [('observed','Nodes are secure.'),('scope','node_runtime'),('raw_content_retained',True),('field','invented')]:
        bad=deepcopy(finding);bad['evidence'][key]=value
        assert observation(bad) is None
    for status in ('PASS','FAIL','DENIED'):
        bad=deepcopy(finding);bad['status']=status
        assert observation(bad) is None
