from copy import deepcopy
from datetime import timedelta
import pytest
from peaso import unused_iam_aws_activity as subject
from peaso.iam_usage_evidence import instant

NOW = '2026-10-21T12:00:00Z'
ACCOUNT = '123456789012'


def role(created='2024-01-01T00:00:00Z', last='2026-01-01T00:00:00Z'):
    return {'RoleName': 'synthetic', 'RoleId': 'AROASYNTHETIC', 'Arn': f'arn:aws:iam::{ACCOUNT}:role/synthetic',
            'CreateDate': created, 'RoleLastUsed': {'LastUsedDate': last} if last else {},
            '_provenance': {'collected_at': NOW, 'scope': ACCOUNT+'/global'}}


def capture():
    return {'context': {'provider': 'aws', 'scope': ACCOUNT+'/global', 'created_at': NOW}}


def test_new_role_without_recorded_use_does_not_fail():
    item = role(created='2026-10-20T12:00:00Z', last=None)
    status, evidence = subject.evaluate(item, capture())
    assert status == 'PASS' and evidence['object_age_days'] == 1 and evidence['last_used'] is None


def test_old_role_with_no_usage_is_not_automatically_60_days_unused():
    assert subject.evaluate(role(last=None), capture())[0] == 'UNKNOWN'


def test_old_recorded_use_fails_with_actual_date_and_recent_use_passes():
    for last, expected in [('2026-01-01T00:00:00Z', 'FAIL'), ('2026-10-20T00:00:00Z', 'PASS')]:
        item = role(last=last);before = deepcopy(item)
        status, evidence = subject.evaluate(item, capture())
        assert status == expected
        assert evidence['last_used'] and evidence['days_since_recorded_use'] >= 1
        assert item == before


@pytest.mark.parametrize('mutation', ['future_creation', 'future_use', 'pre_creation_use', 'missing_creation', 'denied', 'wrong_account', 'wrong_arn', 'missing_id', 'naive', 'wrong_provider', 'foreign_proof', 'foreign_proof_account', 'future_capture', 'empty_date'])
def test_role_inactivity_requires_consistent_current_metadata(mutation):
    item, index = role(), capture();expected = 'UNKNOWN'
    if mutation == 'future_creation': item['CreateDate'] = '2027-01-01T00:00:00Z'
    elif mutation == 'future_use': item['RoleLastUsed']['LastUsedDate'] = '2027-01-01T00:00:00Z'
    elif mutation == 'pre_creation_use': item['RoleLastUsed']['LastUsedDate'] = '2023-01-01T00:00:00Z'
    elif mutation == 'missing_creation': item.pop('CreateDate')
    elif mutation == 'denied': item['_coverage'] = {'RoleLastUsed': {'status': 'denied'}};expected = 'DENIED'
    elif mutation == 'wrong_account': index['context']['scope'] = '999999999999/global'
    elif mutation == 'wrong_arn': item['Arn'] += '-other'
    elif mutation == 'missing_id': item.pop('RoleId')
    elif mutation == 'naive': item['CreateDate'] = '2024-01-01T00:00:00'
    elif mutation == 'wrong_provider': index['context']['provider'] = 'azure'
    elif mutation == 'foreign_proof': item['_provenance']['scope'] = '999999999999/global'
    elif mutation == 'foreign_proof_account': item['_provenance']['account_id'] = '999999999999'
    elif mutation == 'future_capture': item['_provenance']['collected_at'] = '2027-01-01T00:00:00Z'
    elif mutation == 'empty_date': item['RoleLastUsed']['LastUsedDate'] = ''
    assert subject.evaluate(item, index)[0] == expected


def test_exact_threshold_is_not_older_than_the_review_window():
    cutoff = (instant(NOW)-timedelta(days=60)).isoformat()
    assert subject.evaluate(role(last=cutoff), capture())[0] == 'PASS'
    assert subject.evaluate(role(created=cutoff, last=None), capture())[0] == 'PASS'




def test_flattened_native_last_use_coverage_cannot_be_bypassed():
    item = role()
    item['_coverage'] = {'RoleLastUsed.LastUsedDate': {'status': 'denied'}}
    assert subject.evaluate(item, capture())[0] == 'DENIED'
