"""Register the NSP association and Log Analytics query-storage CMK checks."""
from copy import deepcopy
import json
from pathlib import Path

from . import azure_nsp_query_cmk_runtime_review_20261020 as candidate

CASES_FILE = 'azure_nsp_query_cmk_production_cases_20261020.json'
IDS = candidate.IDS
MARK = '_azure_nsp_query_cmk_production_tde_successor_20261020'


def install():
    from . import CHECKS, register
    from .fixtures import CASES
    cases = json.loads(Path(__file__).with_name(CASES_FILE).read_text())
    for spec, function in zip(candidate.DECLARATIONS, (candidate.nsp, candidate.query)):
        if not any(check.id == spec['id'] for check in CHECKS):
            register(spec['id'], 'azure', spec['category'], spec['kind'], spec['title'], spec['severity'],
                     'security_configuration', spec['remediation'], dependencies=spec['dependencies'])(function)
            setattr(CHECKS[-1].evaluate, MARK, spec['id'])
        CASES[spec['id']] = deepcopy(cases[spec['id']])
