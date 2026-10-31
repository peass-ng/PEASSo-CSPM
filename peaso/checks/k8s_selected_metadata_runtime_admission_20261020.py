"""Register the selected K8s metadata secret check and its native cases."""
from copy import deepcopy
import json
from pathlib import Path

from . import k8s_selected_metadata_secret_review_20261020 as candidate
from peaso.collectors import k8s_selected_metadata_runtime_20261020 as runtime

CASES = 'k8s_selected_metadata_runtime_cases_20261020.json'
CHECK = runtime.CHECK
MARK = '_k8s_selected_metadata_runtime_admission_20261020'


def install():
    from . import CHECKS, register
    from .fixtures import CASES as store
    declaration = candidate.DECLARATION
    if not any(check.id == CHECK for check in CHECKS):
        register(CHECK, 'k8s', declaration['category'], runtime.KIND, declaration['title'], declaration['severity'],
                 'security_configuration', declaration['remediation'], dependencies=[runtime.KIND],
                 allow_incomplete_failure=True)(candidate.evaluate)
        setattr(CHECKS[-1].evaluate, MARK, CHECK)
    store[CHECK] = deepcopy(json.loads(Path(__file__).with_name(CASES).read_text())[CHECK])
