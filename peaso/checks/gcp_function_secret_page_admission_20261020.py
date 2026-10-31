"""Replace the existing Functions literal-secret check with its partial-page successor."""
from copy import deepcopy
import inspect
import json
from pathlib import Path

from . import gcp_function_secret_partial_page_20261020 as consumer
from . import gcp_function_secret_review_20261019 as original

CASES_FILE = 'gcp_function_secret_partial_page_cases_20261020.json'


def install():
    from . import CHECKS, register
    from .fixtures import CASES
    ident = original.CHECK_ID
    found = [check for check in CHECKS if check.id == ident]
    if len(found) != 1:
        raise RuntimeError('Functions partial-page registration collision')
    check = found[0]
    if inspect.unwrap(check.evaluate) is consumer.evaluate:
        return
    cases = json.loads(Path(__file__).with_name(CASES_FILE).read_text())
    position = CHECKS.index(check)
    declaration = consumer.DECLARATION
    CHECKS.remove(check)
    register(ident, 'gcp', declaration['category'], declaration['kind'], declaration['title'],
        declaration['severity'], check.control, declaration['remediation'],
        dependencies=check.dependencies, allow_incomplete_failure=check.allow_incomplete_failure)(consumer.evaluate)
    CHECKS.insert(position, CHECKS.pop())
    CASES[ident] = deepcopy(cases[ident])
