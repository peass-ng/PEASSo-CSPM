"""Exact native key ages get brief copy without rounded boundary claims."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone

import pytest

from peaso.checks.azure_review_observed_20261020 import observation
from tests.test_azure_storage_native_review_20261020 import capture, offline

CID = 'azure.claude.storage_access_keys_rotated_90'


def finding(age):
    now = datetime(2026, 10, 20, tzinfo=timezone.utc)
    values = {'key1': age, 'key2': 86400}
    return {'provider': 'azure', 'check_id': CID, 'status': 'FAIL' if age > 7776000 else 'PASS',
            'evidence': {'key_age_seconds': values, 'threshold_seconds': 7776000,
                         'captured_at': now.isoformat(), 'time_source': 'scan_capture',
                         'key_creation_time': {k: (now - timedelta(seconds=v)).isoformat() for k, v in values.items()}}}


@pytest.mark.parametrize('age', [7776000, 7776000.000001, 7775999.999999])
def test_microsecond_boundary_survives_brief_observation(age):
    row = finding(age)
    before = deepcopy(row)
    assert bool(observation(row))
    assert ('older than' in observation(row)) == (age > 7776000)
    assert row == before
    row['status'] = 'PASS' if row['status'] == 'FAIL' else 'FAIL'
    assert observation(row) is None


@pytest.mark.parametrize('fault', ['one-key', 'contradictory-age', 'future-time', 'wrong-threshold',
                                 'no-capture', 'invalid-time', 'boolean-age', 'unknown-time-source'])
def test_missing_or_contradictory_deciding_facts_do_not_supply_copy(fault):
    row = finding(7776000.000001)
    e = row['evidence']
    if fault == 'one-key': e['key_age_seconds'].pop('key2')
    elif fault == 'contradictory-age': e['key_age_seconds']['key1'] = 1
    elif fault == 'future-time': e['key_creation_time']['key2'] = '2027-01-01T00:00:00Z'
    elif fault == 'wrong-threshold': e['threshold_seconds'] = 1
    elif fault == 'no-capture': e.pop('captured_at')
    elif fault == 'invalid-time': e['key_creation_time']['key2'] = 'not-a-date'
    elif fault == 'boolean-age': e['key_age_seconds']['key2'] = True
    else: e['time_source'] = 'untrusted'
    assert observation(row) is None
