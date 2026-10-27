"""Bounded log content fanout keeps the serial evidence contract."""
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timezone

from peaso import secret_evidence, secret_scanning
from peaso.collectors import aws_code_log_content_indicators as content


REGION = 'us-east-1'
GROUPS = [
    {'logGroupName': f'group-{index}',
     'arn': f'arn:aws:logs:{REGION}:123456789012:log-group:group-{index}:*'}
    for index in range(5)
]


class Requests:
    content_secret_scans = True
    max_calls = max_items = deadline = None
    workers = 4
    max_pages = 10
    observed_at = datetime(2026, 10, 27, tzinfo=timezone.utc)
    progress_callback = None

    def __init__(self):
        self.lock = threading.Lock()
        self.active = self.peak = 0
        self.calls = []

    def call(self, session, service, region, operation, **kwargs):
        name = kwargs['logGroupName']
        with self.lock:
            self.active += 1
            self.peak = max(self.peak, self.active)
            self.calls.append((name, kwargs.get('nextToken')))
        try:
            time.sleep(0.015)
            if name == 'group-1':
                from peaso.collectors.aws import ReadFailure
                raise ReadFailure('access_denied', 'AccessDeniedException')
            event = {'timestamp': kwargs['startTime'] + 1, 'eventId': name,
                     'logStreamName': 'stream', 'message': 'synthetic-token'}
            response = {'events': [event]}
            if name == 'group-0' and 'nextToken' not in kwargs:
                response['nextToken'] = 'page-2'
            return content.project_response(response, service, operation,
                {k: v for k, v in kwargs.items() if not k.startswith('_')},
                request_context=kwargs['_projection_context'], region=region)
        finally:
            with self.lock:
                self.active -= 1


def test_log_groups_match_serial_status_order_and_private_source(monkeypatch):
    # Use the real source_context boundary; the fake detector returns its
    # thread-local source identity as a stand-in for encrypted evidence.
    monkeypatch.setattr(secret_evidence, 'enabled', lambda: True)
    def scanner(payload, path):
        source = secret_evidence._source.fields
        return {'leaks': [{'source': source['source'], 'path': source['path']}],
                'complete': True}
    monkeypatch.setattr(secret_scanning, 'scan_content', scanner)
    serial = content._enricher(content.scan_logs)(Requests(), None, REGION, GROUPS)
    requests = Requests()
    parallel = content.ENRICHERS['log_group'](requests, None, REGION, GROUPS)
    assert parallel == serial
    assert [row['ContentSecretIndicators']['collection_status'] for row in parallel] == [
        'collected', 'access_denied', 'collected', 'collected', 'collected']
    assert requests.peak == 2
    assert all('ContentSecretIndicators' not in row for row in GROUPS)
    assert not hasattr(secret_evidence._source, 'fields') or not secret_evidence._source.fields


def test_global_caps_and_deadline_keep_serial_admission(monkeypatch):
    monkeypatch.setattr(secret_scanning, 'scan_content',
                        lambda payload, path: {'leaks': [], 'complete': True})
    requests = Requests()
    requests.max_calls = 10
    result = content.ENRICHERS['log_group'](requests, None, REGION, GROUPS)
    assert len(result) == len(GROUPS) and requests.peak == 1
    requests = Requests()
    requests.max_items = 10
    content.ENRICHERS['log_group'](requests, None, REGION, GROUPS)
    assert requests.peak == 1
    requests = Requests()
    requests.deadline = time.monotonic() + 60
    content.ENRICHERS['log_group'](requests, None, REGION, GROUPS)
    assert requests.peak == 1


def test_detector_batch_memory_is_one_group_at_a_time(monkeypatch):
    active = peak = 0
    lock = threading.Lock()
    @contextmanager
    def prepared(items, *, timeout):
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
        try:
            time.sleep(0.01)
            yield
        finally:
            with lock:
                active -= 1
    monkeypatch.setattr(secret_scanning, 'scan_content',
                        lambda payload, path: {'leaks': [], 'complete': True})
    monkeypatch.setattr(secret_scanning, 'prepared_content_batch', prepared)
    requests = Requests()
    content.ENRICHERS['log_group'](requests, None, REGION, GROUPS)
    assert requests.peak == 2 and peak == 1


def test_disabled_and_repository_enrichment_do_not_spawn(monkeypatch):
    class Disabled(Requests):
        content_secret_scans = False
        def call(self, *args, **kwargs):
            raise AssertionError('content API called')
    requests = Disabled()
    rows = content.ENRICHERS['log_group'](requests, None, REGION, GROUPS)
    assert all(row['ContentSecretIndicators']['collection_status'] == 'not_collected' for row in rows)
    assert requests.peak == 0
