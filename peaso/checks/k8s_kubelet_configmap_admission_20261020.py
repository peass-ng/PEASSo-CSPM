"""Register the eight kubelet ConfigMap declaration checks and their native cases."""
from copy import deepcopy
import json
from pathlib import Path

from . import k8s_kubelet_configmap_review_20261020 as candidate
from peaso.collectors import k8s_kubelet_configmap_indicators_20261020 as producer

CASES_FILE = 'k8s_kubelet_configmap_admitted_cases_20261020.json'
MARK = '_kubelet_configmap_admission_20261020'
IDS = candidate.IDS


def install():
    from . import CHECKS, register
    from .fixtures import CASES
    from peaso.collectors import k8s
    if k8s.TYPES.count(producer.KIND) != 1 or producer.KIND in k8s.ENDPOINTS:
        raise RuntimeError('Kubelet declaration dedicated producer kind unavailable')
    cases = json.loads(Path(__file__).with_name(CASES_FILE).read_text())
    for spec in candidate.DECLARATIONS:
        cid = spec['id']
        if not any(check.id == cid for check in CHECKS):
            register(cid, 'k8s', 'hardening', producer.KIND, spec['title'], spec['severity'], spec['control'],
                     spec['remediation'], dependencies=[producer.KIND])(candidate.evaluate_for(cid))
            setattr(CHECKS[-1].evaluate, MARK, cid)
        CASES[cid] = deepcopy(cases[cid])
