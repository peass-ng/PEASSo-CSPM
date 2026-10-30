"""Whole-page preparation preserves every admitted event and private source."""
import json
from collections import OrderedDict

import pytest
from peaso import secret_evidence as evidence
from peaso import secret_scanning as scanning, secret_scanning_batch as batch
from peaso import secret_scan_clean
from peaso.collectors import aws_code_log_content_indicators as logs


PRIMARY = 'synthetic-primary'
FULL = PRIMARY + ':' + 'A' * 40


@pytest.mark.parametrize('preparation_fails', [False, True])
def test_full_page_preserves_public_and_private_per_event_sources(monkeypatch, preparation_fails):
    events = [dict(timestamp=100+i, eventId=f'event-{i}', logStreamName='owned-stream',
                   message=f'event={i} value={FULL}' if i % 2 else f'clean event {i}')
              for i in range(100)]
    groups, serial = [], []

    def output(payload):
        return (json.dumps(dict(Raw=PRIMARY, RawV2=FULL, Verified=False,
                                DetectorName='AWS')).encode() if FULL.encode() in payload else b'')

    def prepare(items, timeout):
        assert timeout == 60
        groups.append(items)
        if preparation_fails:
            raise RuntimeError('synthetic preparation failure')
        return {item: output(item[0]) for item in items}

    def run(argv, payload, timeout):
        serial.append(payload)
        return output(payload)

    # Each case starts cold: the per-process clean-byte memo would otherwise
    # skip the clean events an earlier case already scanned.
    monkeypatch.setattr(secret_scan_clean, '_CLEAN', OrderedDict())
    monkeypatch.setattr(batch, '_prepare_trufflehog_batch', prepare)
    monkeypatch.setattr(scanning, '_trufflehog', lambda: '/synthetic-trufflehog')
    monkeypatch.setattr(scanning, '_run', run)
    monkeypatch.setattr(scanning, '_scan_kingfisher', lambda payload, *a:
                        [(PRIMARY, 'synthetic', 1)] if FULL.encode() in payload else [])
    scanning._RESULTS.clear()
    cipher = evidence.EphemeralCipher()
    with evidence.capture(cipher, tenant='offline', scan_id='a' * 32) as sink:
        with evidence.source_context(resource_id='owned-log', scope='us-east-1'):
            result = logs.project_response({'events': events}, 'logs', 'filter_log_events',
                dict(logGroupName='owned-group', startTime=100, endTime=200, limit=100),
                region='us-east-1', request_context={'remaining_bytes': logs.MAX_BYTES})['value']
        for token in (PRIMARY, FULL):
            record = cipher.decrypt(sink.records[scanning._fingerprint(token)])
            assert {json.loads(loc['source'])['eventId'] for loc in record['locations']} == {
                f'event-{i}' for i in range(100) if i % 2}
            assert all(loc['resource_id'] == 'owned-log' and loc['path'] == 'owned-group'
                       and loc['scope'] == 'us-east-1' for loc in record['locations'])
        assert not sink.incomplete
    assert [len(group) for group in groups] == [100]
    assert all(path == 'log-message' for group in groups for _, path in group)
    assert len(serial) == (100 if preparation_fails else 0)
    assert [row['timestamp'] for row in result['events']] == list(range(100, 200))
    assert all(row['scanner_complete'] and row['readable'] for row in result['events'])
    assert [i for i, row in enumerate(result['events']) if row['leaks']] == list(range(1, 100, 2))
    assert PRIMARY not in json.dumps(result) and FULL not in json.dumps(result)
    assert batch._PREPARED_BATCH.get() is None
    scanning._RESULTS.clear()


def test_unreadable_middle_event_preserves_byte_budget_and_order(monkeypatch):
    scanned = []

    def scan(payload, path):
        scanned.append(payload)
        return dict(leaks=[], complete=True)

    monkeypatch.setattr(scanning, 'scan_content', scan)
    result = logs.project_response({'events': [dict(timestamp=100+i, message=message)
        for i, message in enumerate(['first-12byte', 'x' * 40, 'last-12bytes'])]},
        'logs', 'filter_log_events',
        dict(logGroupName='owned-group', startTime=100, endTime=200, limit=100),
        region='us-east-1', request_context={'remaining_bytes': 24})['value']
    assert scanned == [b'first-12byte', b'last-12bytes']
    assert [row['timestamp'] for row in result['events']] == [100, 101, 102]
    assert [row['readable'] for row in result['events']] == [True, False, True]
    assert [row['scanner_complete'] for row in result['events']] == [True, False, True]
