"""Preserve exact upstream identities while admitting only narrower native claims."""
import inspect
import pytest
from peaso.checks import CHECKS
from peaso.checks.fixtures import CASES


@pytest.mark.parametrize('cid',[
    'azure.review.function.application_insights_setting_declared',
    'azure.review.function.runtime_major4_update_channel_declared'])
@pytest.mark.parametrize('branch',['pass','fail','unknown'])
def test_association_points_to_actual_decisive_native_consumer(cid,branch):
    from copy import deepcopy
    check=next(c for c in CHECKS if c.id==cid);case=CASES[cid]
    status,evidence=inspect.unwrap(check.evaluate)(deepcopy(case[branch]),deepcopy(case[branch+'_index']))
    assert status==branch.upper() and isinstance(evidence,dict)
