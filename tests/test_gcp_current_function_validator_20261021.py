"""The registered Functions secret check evaluates its native cases correctly."""
from copy import deepcopy
import inspect

from peaso.checks import CHECKS
from peaso.checks import gcp_function_secret_partial_page_20261020 as consumer
from peaso.checks.fixtures import CASES

CHECK_ID = 'gcp.review.function.literal_environment_secret_indicators'


def test_registered_runtime_evaluates_native_cases():
    check, = [c for c in CHECKS if c.id == CHECK_ID]
    assert inspect.unwrap(check.evaluate) is consumer.evaluate
    for branch, expected in [('pass', 'PASS'), ('fail', 'FAIL'), ('unknown', 'UNKNOWN')]:
        case = CASES[CHECK_ID]
        status, _ = check.evaluate(deepcopy(case[branch]),
            deepcopy(case.get(branch + '_index', case['index'])))
        assert status == expected
