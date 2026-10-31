"""A Lambda function with no environment values has nothing to leak, so it PASSes instead of staying UNKNOWN."""
import pytest

from peaso.checks.automatic_workload_batch import _automatic_issue


def _case(code):
    item = {'id': 'fn-1', 'marker': {'identity': 'fn-1', 'scope': '111111111111/us-east-1', 'complete': False, 'capture': 'cap',
            'request': {'operation': 'lambda:GetFunctionConfiguration', 'status': 'unavailable'}}}
    index = {'context': {'scope': '111111111111/us-east-1', 'provider': 'aws', 'metadata': {}}}
    batch = {'issues': {'fn-1': {'status': 'unknown', 'code': code, 'operation': 'lambda:GetFunctionConfiguration'}},
             'metadata': {'lambda_selected_environment_capture': 'cap',
                          'lambda_selected_environment_selection': {'111111111111/us-east-1': ['fn-1']}}}
    return _automatic_issue(item, index, 'lambda_selected_environment', batch, 'marker')


@pytest.mark.parametrize('code', ['environment_no_literals', 'environment_empty'])
def test_function_without_environment_values_passes(code):
    status, detail = _case(code)
    assert status == 'PASS' and detail['complete'] is True


@pytest.mark.parametrize('code', ['environment_error', 'environment_unavailable'])
def test_unreadable_environment_stays_unknown(code):
    assert _case(code)[0] == 'UNKNOWN'
