"""Nine exact historical IDs now bind the GC flag to its real component."""
from copy import deepcopy
import pytest
from peaso.checks import CHECKS
from peaso.checks.fixtures import CASES, nest
from peaso.checks.facts import get
from peaso.checks.k8s_ports_workloads import KIND_PATHS
from peaso.checks.k8s_gc_threshold_source_correction import ROWS



@pytest.mark.parametrize('cid', sorted(ROWS))
def test_manager_threshold_values_and_kubelet_exclusion(cid):
    check = next(c for c in CHECKS if c.id == cid)
    for value, expected in [('1','PASS'),('12500','PASS'),('0','FAIL'),('-1','UNKNOWN'),('bad','UNKNOWN')]:
        item = deepcopy(CASES[cid]['pass'])
        config = get(item, KIND_PATHS[check.kind], dict)['containers'][0]['_component_config']
        config['flags']['terminated-pod-gc-threshold'] = value
        assert check.evaluate(item,{})[0] == expected
    config['component'] = 'kubelet'
    assert check.evaluate(item,{})[0] == 'NOT_APPLICABLE'
    config['component'] = 'kube-controller-manager'
    config['flags'].clear()
    assert check.evaluate(item,{})[0] == 'UNKNOWN'


@pytest.mark.parametrize('cid', sorted(ROWS))
def test_raw_read_only_projection_identifies_manager(cid):
    from peaso.collectors.k8s import _native
    check = next(c for c in CHECKS if c.id == cid)
    raw = nest(KIND_PATHS[check.kind], {'containers':[{'name':'manager','command':['kube-controller-manager','--terminated-pod-gc-threshold=0']}]})
    raw['metadata']={'name':'manager','namespace':'apps'}
    projected = _native(raw, check.kind, 'fixture', '*', True)
    assert check.evaluate(projected,{})[0] == 'FAIL'


@pytest.mark.parametrize('cid', sorted(ROWS))
def test_corrected_observed_evidence_and_guarded_risk(cid):
    from peaso.checks.k8s_gc_threshold_source_correction import evidence_summary
    check=next(c for c in CHECKS if c.id==cid)
    status,evidence=check.evaluate(deepcopy(CASES[cid]['fail']),{})
    finding={'provider':'k8s','check_id':cid,'status':status,'evidence':evidence}
    assert 'threshold 0' in evidence_summary(finding)
    finding['status']='UNKNOWN'
    assert evidence_summary(finding) is None
