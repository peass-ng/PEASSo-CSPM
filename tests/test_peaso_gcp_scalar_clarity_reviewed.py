import pytest

from peaso.checks import CHECKS
from peaso.checks.fixtures import CASES
from peaso.checks.gcp_scalar_clarity_reviewed import ROWS
from peaso.checks.gcp_scalar_clarity_reviewed import ROWS, description, remediation


@pytest.mark.parametrize("cid", ROWS)
def test_scalar_setting_verdicts_for_pass_fail_missing_and_malformed(cid):
    check = next(c for c in CHECKS if c.id == cid)
    for case, status in (("pass", "PASS"), ("fail", "FAIL"),
                         ("missing", "UNKNOWN"), ("malformed", "UNKNOWN")):
        assert check.evaluate(CASES[cid][case], {})[0] == status
