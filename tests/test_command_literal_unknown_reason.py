"""UNKNOWN command-literal results must say what kept them unassessed."""
from peaso.checks import aws_workload_command_source_20261020 as check


def test_summary_names_unassessed_definitions_and_cause():
    rows = [{'id': 'x', 'native_bound': False}, {'id': 'y', 'native_bound': True, 'native_complete': True,
             'scans': [{'engines': [{'engine': 'trufflehog', 'status': 'unavailable'}]}]}]
    status, evidence = check.evaluate_collection({'items': rows})
    assert status == 'UNKNOWN'
    assert evidence['reason'] == '2 of 2 selected definitions unassessed: definition_not_read, secret_engine_unavailable: trufflehog'


def test_unreadable_collection_still_reports_a_reason():
    status, evidence = check.evaluate({'id': 'x'}, None)
    assert status == 'UNKNOWN' and evidence['reason'] == 'definition_not_read'
