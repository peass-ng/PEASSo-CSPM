"""Accept exact reviewed helpers and concise native successor observations."""
from pathlib import Path

import pytest

from peaso.checks.gcp_remaining_finding_summary import evidence_summary

ROOT = Path(__file__).resolve().parents[1]
REVIEW = ROOT / 'docs/gcp-review/recheck-20261020'


@pytest.mark.parametrize('seconds,period,expected', [
    ('8640000.000000001', '8640000.000000001s', True),
    ('8640000.999999999', '8640000.999999999s', True),
    ('8640000', '8640000s', False),
    ('8639999.999999999', '8639999.999999999s', False),
    ('8640000.000000001', '8640000s', False),
    ('8640000.000000001', None, False),
    ('NaN', 'NaNs', False),
    ('8640000.0000000010', '8640000.000000001s', False),
])
def test_fractional_rotation_copy_preserves_exact_boundary(seconds, period, expected):
    finding = {'provider': 'gcp', 'check_id': 'gcp.claude.kms_key.rotation_100_days', 'status': 'FAIL',
               'evidence': {'rotation_seconds': seconds, 'rotation_period': period}}
    text = evidence_summary(finding)
    assert bool(text) == expected
    if expected:
        assert seconds in text and '100 days' in text
    finding['status'] = 'PASS'
    assert evidence_summary(finding) is None


@pytest.mark.parametrize('cid', ['gcp.ports.function_logging_mutation_declarations',
                                'gcp.ports.function_legacy_deployment_role_declarations'])
@pytest.mark.parametrize('records,expected', [
    ([{'role': 'projects/native-project/roles/selected', 'policy': 'projects/native-project', 'condition': None}], True),
    ([], False), ([{}], False), ([{'role': '', 'policy': 'projects/native-project'}], False),
    ([{'role': 'roles/editor', 'policy': None}], False),
])
def test_filtered_function_role_declarations_need_named_role_and_policy(cid, records, expected):
    finding = {'provider': 'gcp', 'check_id': cid, 'status': 'FAIL',
               'evidence': {'role_assignment_declarations': records}}
    assert bool(evidence_summary(finding)) == expected
