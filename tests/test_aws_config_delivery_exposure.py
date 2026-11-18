"""Declared Config delivery ownership through the public analysis path."""
import pytest
from peaso.analysis import analyze
from peaso.snapshot import make_snapshot

ACCOUNT = '123456789012'
SCOPE = ACCOUNT + '/us-east-1'


@pytest.mark.parametrize('owned,topic,expected', [
    (True, None, 'PASS'),
    (True, 'arn:aws:sns:us-east-1:123456789012:config', 'PASS'),
    (True, 'arn:aws:sns:us-east-1:999999999999:config', 'FAIL'),
    (True, 'malformed', 'UNKNOWN'),
    (False, None, 'UNKNOWN'),
])
def test_complete_local_delivery_and_unresolved_or_foreign_destinations(owned, topic, expected):
    data = {'name': 'default', 's3BucketName': 'fixture-config'}
    if topic is not None:
        data['snsTopicARN'] = topic
    collections = [
        {'type': 'config_delivery_channel', 'scope': SCOPE, 'service': 'config',
         'status': 'collected', 'items': [data]},
        {'type': 'bucket', 'scope': ACCOUNT + '/global', 'service': 's3',
         'status': 'collected' if owned else 'empty',
         'items': [{'Name': 'fixture-config'}] if owned else []},
    ]
    snap = make_snapshot('aws', [SCOPE, ACCOUNT + '/global'], collections,
                         metadata={'trusted_scope_ids': [ACCOUNT]})
    rows = [f for f in analyze(snap)['findings']
            if f['check_id'] == 'analysis.internet_exposure'
            and f['evidence'].get('exposure_kind') == 'external_configuration_delivery']
    assert len(rows) == 1
    assert rows[0]['status'] == expected
    if expected == 'PASS':
        assert rows[0]['evidence']['unresolved'] == []
        assert rows[0]['evidence']['path'][0]['decision'] == 'local'
