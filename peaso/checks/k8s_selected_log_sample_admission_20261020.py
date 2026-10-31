"""Register the optional bounded K8s container-log secret check and its native cases."""
from copy import deepcopy
import json
from pathlib import Path

from . import k8s_selected_log_sample_secret_review_20261020 as candidate
from peaso.collectors import k8s_selected_log_sample_secret_indicators as producer

CASES_FILE = 'k8s_selected_log_sample_admitted_cases_20261020.json'
MARK = '_k8s_selected_log_sample_admission_20261020'
CHECK = producer.CHECK


def install():
    from . import CHECKS, register
    from .fixtures import CASES
    from peaso.collectors import k8s
    if k8s.TYPES.count(producer.KIND) != 1 or producer.KIND in k8s.ENDPOINTS:
        raise RuntimeError('K8s log dedicated kind changed')
    cases = json.loads(Path(__file__).with_name(CASES_FILE).read_text())
    if not any(check.id == CHECK for check in CHECKS):
        spec = candidate.DECLARATIONS[0]
        register(CHECK, 'k8s', spec['category'], producer.KIND, spec['title'], spec['severity'], spec['control'],
            spec['remediation'], dependencies=[producer.KIND], allow_incomplete_failure=True)(candidate.evaluate)
        setattr(CHECKS[-1].evaluate, MARK, CHECK)
    CASES[CHECK] = deepcopy(cases[CHECK])
