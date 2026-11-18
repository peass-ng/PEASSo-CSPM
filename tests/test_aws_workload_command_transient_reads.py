"""Actual loopback TLS/SDK command reads recover within the original budgets."""
from test_aws_workload_command_wire import aws_stub, target, task_definition, collect
from peaso.checks import aws_workload_command_source_20261020 as consumer
from peaso.collectors import aws_workload_command_source_20261020 as source
from peaso.secret_scanning import KINGFISHER_VERSION, TRUFFLEHOG_VERSION
import pytest


@pytest.fixture(autouse=True)
def zero_literal_detectors(monkeypatch):
    # These cases exercise SDK transport retries, not detector installation.
    # Every successful definition omits its command arrays (zero literals).
    def scanned(callback, payload, path, **kwargs):
        assert payload == b''
        return {'leaks': [], 'complete': True, 'engines': [
            {'engine': 'kingfisher', 'version': KINGFISHER_VERSION, 'status': 'complete'},
            {'engine': 'trufflehog', 'version': TRUFFLEHOG_VERSION, 'status': 'complete'}]}
    monkeypatch.setattr(source, 'scan_with_source', scanned)


def test_two_transient_definition_errors_do_not_leave_all_eight_unassessed(aws_stub):
    targets = [target('svc-' + str(i)) for i in range(8)]
    for t in targets:
        aws_stub['definitions'][t['definition_arn']] = task_definition(t)
    aws_stub['failures'][targets[3]['definition_arn']] = [(400, 'ThrottlingException')]
    aws_stub['failures'][targets[6]['definition_arn']] = [(503, 'ServiceUnavailableException')]
    result = collect(targets)
    assert result['complete'] and result['calls'] == 11
    assert all(row['native_bound'] and row['complete'] for row in result['items'])
    assert consumer.evaluate_collection(result)[0] == 'PASS'


def test_real_permission_denial_is_not_retried_and_counts_only_unread_definition(aws_stub):
    targets = [target('assessed'), target('denied')]
    for t in targets:
        aws_stub['definitions'][t['definition_arn']] = task_definition(t)
    aws_stub['failures'][targets[1]['definition_arn']] = [(403, 'AccessDeniedException')]
    result = collect(targets)
    assert result['calls'] == 3 and len(aws_stub['hosts']) == 3
    assert result['items'][1]['read_error'] == 'access_denied'
    status, evidence = consumer.evaluate_collection(result)
    assert status == 'UNKNOWN'
    assert evidence['reason'] == '1 of 2 selected definitions unassessed: definition_read_failed: access_denied'
    assert 'ghp_' not in str(result)


def test_repeated_throttling_exhausts_original_shared_call_budget_without_a_clean_verdict(aws_stub):
    targets = [target('limited-' + str(i)) for i in range(8)]
    for t in targets:
        aws_stub['definitions'][t['definition_arn']] = task_definition(t)
        aws_stub['failures'][t['definition_arn']] = [(400, 'ThrottlingException')] * 3
    result = collect(targets)
    assert result['calls'] == 12 and len(aws_stub['hosts']) == 12
    assert not result['complete'] and not any(row['native_bound'] for row in result['items'])
    status, evidence = consumer.evaluate_collection(result)
    assert status == 'UNKNOWN' and 'budget_exhausted' in evidence['reason']


def test_diagnostics_cannot_forge_completion_or_reflect_arbitrary_provider_text(aws_stub):
    selected = target('one-definition')
    aws_stub['definitions'][selected['definition_arn']] = task_definition(selected)
    result = collect([selected])
    assert consumer.evaluate_collection(result)[0] == 'PASS'
    result['items'][0]['read_error'] = 'access_denied'
    assert consumer.evaluate_collection(result)[0] == 'UNKNOWN'
    result['items'][0].update(native_bound=False, native_complete=False, complete=False,
                              scans=[], leaks=[], read_error='provider-secret-message')
    result['complete'] = False
    status, evidence = consumer.evaluate_collection(result)
    assert status == 'UNKNOWN' and 'provider-secret-message' not in str(evidence)
    del result['items'][0]['read_error']
    assert consumer.evaluate_collection(result)[0] == 'UNKNOWN'  # Saved legacy captures remain readable.
