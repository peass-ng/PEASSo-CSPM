"""Bounded early IAM usage jobs overlap independent AWS collection safely."""
import copy
from concurrent.futures import ThreadPoolExecutor
from contextvars import ContextVar, copy_context
from datetime import datetime, timezone
from pathlib import Path
from threading import Event, RLock, current_thread
from types import SimpleNamespace
import pytest
import peaso.checks
from peaso.collectors import aws
from peaso.collectors import aws_iam_usage_extension as current_usage
from peaso.snapshot import make_snapshot, validate

ACCOUNT = "123456789012"
REGION = "us-east-1"
ARN = f"arn:aws:iam::{ACCOUNT}:group/operators"

@pytest.fixture
def candidate():
    return current_usage


def requests(**extra):
    return SimpleNamespace(_lock=RLock(), observed_at=datetime(2026, 10, 24, tzinfo=timezone.utc),
        service_last_accessed_wait=120, service_last_accessed_workers=4,
        calls=10, cache_hits=2, evidence_generations=1, service_last_accessed_generations=0,
        iam_report_generation_requested=True, iam_service_access_reports_requested=True,
        iam_credential_report_generation_requested=True, max_calls=None, max_pages=None,
        max_items=None, **extra)


def seed(arn=ARN):
    return {'iam_group': aws.ReadResult([{'Arn': arn, 'GroupName': 'operators'}])}


def collections(arn=ARN):
    return [{'type': 'iam_group', 'scope': ACCOUNT + '/global', 'status': 'collected',
        'items': [{'Arn': arn, 'GroupName': 'operators'}]}]


def report(rows):
    return {arn: ([{'ServiceNamespace': 'iam', 'TrackedActionsUnobserved': ['DeleteRole']}],
        {'collection_status': 'collected', 'granularity': 'ACTION_LEVEL', 'principal_arn': arn})
        for arn in rows}


def test_started_while_independent_work_blocked_and_joins_exact_fields(candidate, monkeypatch):
    started, finish = Event(), Event()
    req, session = requests(), object()
    original = collections()
    before = copy.deepcopy(original)
    marker = ContextVar('candidate_test_context')
    token = marker.set('bound')
    calls = []
    def reports(actual, actual_session, region, arns, *, granularity):
        assert marker.get() == 'bound'
        assert actual is req and actual_session is session and region == REGION
        assert granularity == 'ACTION_LEVEL'
        calls.append(tuple(arns)); started.set(); assert finish.wait(3)
        actual.calls += 3; actual.service_last_accessed_generations += 1
        return report(arns)
    monkeypatch.setattr('peaso.collectors.aws_iam_report_native.service_reports', reports)
    try:
        with candidate.capture_contexts() as contexts:
            candidate.register_context(req, session, {'Account': ACCOUNT}, [REGION])
            assert req.iam_usage_scan is True
            assert candidate.start_account_usage(req, session, {'Account': ACCOUNT}, REGION, seed())
            assert started.wait(3)
            assert original == before
            assert not candidate.start_account_usage(req, session, {'Account': ACCOUNT}, REGION, seed())
            finish.set(); candidate.join_account_usage(original)
            assert original[0]['items'][0]['GroupName'] == 'operators'
            assert original[0]['items'][0]['ServicesLastAccessedStatus']['collection_status'] == 'collected'
            assert len(calls) == 1
            candidate.join_account_usage(original)
            assert len(calls) == 1
        assert contexts.closed and contexts.pool is None and not contexts.futures
    finally:
        marker.reset(token)


@pytest.mark.parametrize('limit', ['max_calls', 'max_pages', 'max_items'])
def test_explicit_budget_retains_late_serial_path(candidate, limit):
    req, session = requests(), object()
    setattr(req, limit, 1)
    with candidate.capture_contexts() as contexts:
        candidate.register_context(req, session, {'Account': ACCOUNT}, [REGION])
        assert not candidate.start_account_usage(req, session, {'Account': ACCOUNT}, REGION, seed())
        assert contexts.pool is None


def test_shared_session_and_foreign_context_cannot_start(candidate):
    req, session = requests(), object()
    with candidate.capture_contexts():
        candidate.register_context(req, session, {'Account': ACCOUNT}, [REGION])
        assert not candidate.start_account_usage(req, object(), {'Account': ACCOUNT}, REGION, seed())
        candidate.register_context(req, session, {'Account': '234567890123'}, [REGION])
        assert not candidate.start_account_usage(req, session, {'Account': ACCOUNT}, REGION, seed())


def test_denied_and_missing_report_remain_denied(candidate, monkeypatch):
    req, session = requests(), object()
    def reports(*args, **kwargs):
        return {ARN: (None, {'collection_status': 'denied', 'granularity': 'ACTION_LEVEL',
            'error': {'code': 'AccessDenied'}})}
    monkeypatch.setattr('peaso.collectors.aws_iam_report_native.service_reports', reports)
    rows = collections()
    with candidate.capture_contexts():
        candidate.register_context(req, session, {'Account': ACCOUNT}, [REGION])
        candidate.start_account_usage(req, session, {'Account': ACCOUNT}, REGION, seed())
        candidate.join_account_usage(rows)
    item = rows[0]['items'][0]
    assert 'ServicesLastAccessed' not in item
    assert item['ServicesLastAccessedStatus']['collection_status'] == 'denied'


def test_finalizer_preserves_unrelated_input_and_updates_actual_counters(candidate, monkeypatch):
    req, session = requests(), object()
    native = make_snapshot('aws', [ACCOUNT + '/global'], collections() + [
        {'type': 'cloudwatch_metric', 'scope': ACCOUNT + '/' + REGION, 'status': 'collected',
         'items': [{'id': 'fixture', 'nested': {'values': [1]}}]}],
        created_at=req.observed_at.isoformat(), metadata={'calls': 10, 'cache_hits': 2,
        'authorized_evidence_generation': {'generation_requests': 1,
        'service_last_accessed_generation_requests': 0}})
    before = copy.deepcopy(native)
    def reports(*args, **kwargs):
        req.calls += 3; req.cache_hits += 1; req.service_last_accessed_generations += 1
        return report(args[3])
    monkeypatch.setattr('peaso.collectors.aws_iam_report_native.service_reports', reports)
    result = candidate.enrich_snapshot(native, {ACCOUNT: (req, session, REGION)})
    assert native == before
    assert result['metadata']['calls'] == 13 and result['metadata']['cache_hits'] == 3
    assert result['metadata']['authorized_evidence_generation']['service_last_accessed_generation_requests'] == 1
    assert validate(result) == result
    result['collections'][1]['items'][0]['nested']['values'].append(2)
    assert native == before


def test_callback_registration_precedes_native_iam_and_report_overlaps_collection(candidate, monkeypatch):
    namespace = dict(aws.__dict__)
    namespace['copy_context'] = copy_context
    entered, release, report_started, report_done = Event(), Event(), Event(), Event()
    reqs = []
    class Requests(aws.Requests):
        def __init__(self, options):
            super().__init__(options); reqs.append(self)
        def pages(self, *args, **kwargs):
            return aws.ReadResult([], 'empty')
    session = SimpleNamespace(region_name=REGION, get_partition_for_region=lambda _: 'aws')
    namespace['Requests'] = Requests
    namespace['_session'] = lambda *args: (session, 'offline-fixture')
    namespace['_identity'] = lambda *args: {'Account': ACCOUNT,
        'Arn': f'arn:aws:iam::{ACCOUNT}:role/reviewer', 'UserId': 'fixture'}
    def native_iam(req, session, region, wanted):
        assert req.iam_usage_scan is True
        result = seed()
        result['iam_role'] = aws.ReadResult([], 'empty')
        return {kind: result[kind] for kind in wanted}
    namespace['_iam'] = native_iam
    def enrich(req, session, region, kind, items, **kwargs):
        if kind == 'instance':
            entered.set(); assert release.wait(5)
        return items
    namespace['_enrich'] = enrich
    class Lifecycle:
        def __init__(self, *args, **kwargs): pass
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def prepare(self, *args): pass
        def collect(self, *args): return aws.ReadResult([], 'empty')
    monkeypatch.setattr('peaso.collectors.aws_access_analyzer_lifecycle.AnalyzerLifecycle', Lifecycle)
    def reports(req, actual_session, region, arns, *, granularity):
        assert actual_session is session and granularity == 'ACTION_LEVEL'
        report_started.set(); assert entered.wait(3)
        req.calls += 2; req.service_last_accessed_generations += 1
        report_done.set(); return report(arns)
    monkeypatch.setattr('peaso.collectors.aws_iam_report_native.service_reports', reports)
    for name in ('Requests', '_session', '_identity', '_iam', '_enrich'):
        monkeypatch.setattr(aws, name, namespace[name])
    connector = {'provider': 'aws', 'scopes': [ACCOUNT + '/' + REGION], 'auth': {},
        'options': {'regions': [REGION], 'service_concurrency': 4,
                    '_iam_report_generation_requested': True, '_iam_service_access_reports_requested': True}}
    with candidate.capture_contexts(), ThreadPoolExecutor(1) as pool:
        pending = pool.submit(copy_context().run, aws.collect, connector,
            ['iam_role', 'iam_group', 'access_analyzer', 'instance'])
        try:
            if not entered.wait(3) and pending.done():
                pending.result()
            assert entered.is_set() and report_started.wait(3) and report_done.wait(3)
            assert not pending.done()
        finally:
            release.set()
        result = pending.result(timeout=5)
    group = next(c for c in result['collections'] if c['type'] == 'iam_group')['items'][0]
    assert group['ServicesLastAccessedStatus']['collection_status'] == 'collected'
    assert result['metadata']['authorized_evidence_generation']['service_last_accessed_generation_requests'] == 1
    assert result['metadata']['calls'] == 2
    assert validate(result) == result


def test_two_accounts_keep_exact_report_provenance(candidate, monkeypatch):
    from threading import Barrier
    accounts = (ACCOUNT, '234567890123')
    barrier = Barrier(2)
    req = requests()
    sessions = {account: object() for account in accounts}
    rows = []
    def reports(observed, session, region, arns, *, granularity):
        account = next(account for account in accounts if sessions[account] is session)
        assert all(arn.split(':')[4] == account for arn in arns)
        barrier.wait(timeout=3)
        return {arn: ([{'ServiceNamespace': 'iam', 'LastAuthenticatedRegion': account}],
            {'collection_status': 'collected', 'granularity': granularity, 'principal_arn': arn}) for arn in arns}
    monkeypatch.setattr('peaso.collectors.aws_iam_report_native.service_reports', reports)
    with candidate.capture_contexts():
        for account in accounts:
            candidate.register_context(req, sessions[account], {'Account': account}, [REGION])
        for account in accounts:
            arn = f'arn:aws:iam::{account}:group/operators'
            rows.append({'type': 'iam_group', 'scope': account + '/global', 'status': 'collected',
                'items': [{'Arn': arn}]})
            assert candidate.start_account_usage(req, sessions[account], {'Account': account}, REGION, seed(arn))
        # A spliced scope must not receive a report for another scope's ARN.
        rows.append({'type': 'iam_group', 'scope': 'foreign/global', 'status': 'collected',
            'items': [{'Arn': ARN}]})
        candidate.join_account_usage(rows)
    for row, account in zip(rows, accounts):
        item = row['items'][0]
        assert item['ServicesLastAccessed'][0]['LastAuthenticatedRegion'] == account
        assert item['ServicesLastAccessedStatus']['principal_arn'].split(':')[4] == account
    assert 'ServicesLastAccessed' not in rows[-1]['items'][0]


def test_join_observes_every_started_job_before_error(candidate, monkeypatch):
    accounts = (ACCOUNT, '234567890123')
    req = requests()
    sessions = {account: object() for account in accounts}
    done = Event()
    def reports(observed, session, region, arns, *, granularity):
        if session is sessions[ACCOUNT]:
            raise RuntimeError('synthetic report failure')
        done.set()
        return report(arns)
    monkeypatch.setattr('peaso.collectors.aws_iam_report_native.service_reports', reports)
    with candidate.capture_contexts() as contexts:
        for account in accounts:
            candidate.register_context(req, sessions[account], {'Account': account}, [REGION])
        for account in accounts:
            candidate.start_account_usage(req, sessions[account], {'Account': account}, REGION,
                seed(f'arn:aws:iam::{account}:group/operators'))
        with pytest.raises(RuntimeError, match='synthetic report failure'):
            candidate.join_account_usage([])
        assert done.is_set()
    assert contexts.pool is None and not contexts.futures


def test_completed_early_reports_are_not_requested_again(candidate, monkeypatch):
    req, session = requests(), object()
    calls = []
    def reports(*args, **kwargs):
        calls.append(tuple(args[3])); return report(args[3])
    monkeypatch.setattr('peaso.collectors.aws_iam_report_native.service_reports', reports)
    rows = collections()
    with candidate.capture_contexts() as contexts:
        candidate.register_context(req, session, {'Account': ACCOUNT}, [REGION])
        candidate.start_account_usage(req, session, {'Account': ACCOUNT}, REGION, seed())
        candidate.join_account_usage(rows)
        current = make_snapshot('aws', [ACCOUNT+'/global'], rows)
        final = candidate.enrich_snapshot(current, contexts)
        assert final['collections'] == current['collections']
    assert calls == [(ARN,)]


def test_disabled_capture_cannot_generate_reports(candidate):
    req = requests()
    with candidate.capture_contexts(False) as contexts:
        assert contexts is None
        assert candidate.register_context(req, object(), {'Account': ACCOUNT}, [REGION]) is False
        assert candidate.start_account_usage(req, object(), {'Account': ACCOUNT}, REGION, seed()) is False
        assert not hasattr(req, 'iam_usage_scan')


def test_finalizer_collects_new_iam_rows_without_repeating_early_reports(candidate, monkeypatch):
    req, session = requests(), object()
    calls = []
    def reports(*args, **kwargs):
        calls.append(tuple(args[3])); return report(args[3])
    monkeypatch.setattr('peaso.collectors.aws_iam_report_native.service_reports', reports)
    rows = collections()
    second = f'arn:aws:iam::{ACCOUNT}:group/later'
    with candidate.capture_contexts() as contexts:
        candidate.register_context(req, session, {'Account': ACCOUNT}, [REGION])
        candidate.start_account_usage(req, session, {'Account': ACCOUNT}, REGION, seed())
        candidate.join_account_usage(rows)
        rows[0]['items'].append({'Arn': second, 'GroupName': 'later'})
        final = candidate.enrich_snapshot(make_snapshot('aws', [ACCOUNT + '/global'], rows), contexts)
    assert calls == [(ARN,), (second,)]
    assert all(item['ServicesLastAccessedStatus']['collection_status'] == 'collected'
               for item in final['collections'][0]['items'])


def test_cancelled_native_report_is_not_clean_or_completed(candidate):
    req = requests()
    calls = []
    def cancelled():
        raise aws.ReadFailure('not_collected', 'collection_cancelled')
    def call(session, service, region, operation, **kwargs):
        calls.append(operation)
        assert operation == 'get_caller_identity'
        return {'Account': ACCOUNT, 'Arn': f'arn:aws:iam::{ACCOUNT}:role/reviewer'}
    req.check_deadline, req.call = cancelled, call
    session = SimpleNamespace(get_partition_for_region=lambda region: 'aws')
    rows = collections()
    with candidate.capture_contexts():
        candidate.register_context(req, session, {'Account': ACCOUNT}, [REGION])
        assert candidate.start_account_usage(req, session, {'Account': ACCOUNT}, REGION, seed())
        candidate.join_account_usage(rows)
    item = rows[0]['items'][0]
    assert 'ServicesLastAccessed' not in item
    assert item['ServicesLastAccessedStatus']['collection_status'] == 'not_collected'
    assert item['ServicesLastAccessedStatus']['error']['code'] == 'collection_cancelled'
    assert calls == ['get_caller_identity']


def native_requests_and_session(mode):
    """Exercise real Requests cache/pacing and native report parser, without AWS."""
    from peaso.collectors import aws_iam_report_native as native
    phase = {'mode': mode}
    calls = []
    job = '11111111-1111-1111-1111-111111111111'
    created = datetime(2026, 10, 24, tzinfo=timezone.utc)
    class Client:
        def get_caller_identity(self):
            calls.append(('identity', {}))
            return {'Account': ACCOUNT, 'Arn': f'arn:aws:iam::{ACCOUNT}:role/reviewer'}
        def generate_service_last_accessed_details(self, **arguments):
            calls.append(('generate', arguments))
            return {'JobId': job}
        def get_service_last_accessed_details(self, **arguments):
            calls.append(('read', arguments))
            if phase['mode'] == 'pending':
                return {'JobStatus': 'IN_PROGRESS'}
            if phase['mode'] == 'transient':
                raise RuntimeError('synthetic unavailable response')
            if phase['mode'] == 'failed':
                return {'JobStatus': 'FAILED'}
            return {'JobStatus': 'COMPLETED', 'JobType': 'ACTION_LEVEL',
                'JobCreationDate': created, 'JobCompletionDate': created,
                'IsTruncated': False, 'ServicesLastAccessed': [{'ServiceNamespace': 'iam',
                    'ServiceName': 'Identity and Access Management',
                    'TrackedActionsLastAccessed': [{'ActionName': 'DeleteRole'}]}]}
    client = Client()
    session = SimpleNamespace(client=lambda *args, **kwargs: client,
        get_partition_for_region=lambda region: 'aws')
    req = aws.Requests({'_iam_report_generation_requested': True,
        '_iam_service_access_reports_requested': True}, sleep=lambda seconds: None)
    req.iam_usage_scan = True
    return native, req, session, phase, calls, job


@pytest.mark.parametrize('initial_mode', ['pending', 'transient'])
def test_early_pending_native_job_can_complete_late_without_regeneration(candidate, initial_mode):
    native, req, session, phase, calls, job = native_requests_and_session(initial_mode)
    role = f'arn:aws:iam::{ACCOUNT}:role/operators'
    # Initial native ACTION_LEVEL job can time out before ordinary inventory ends.
    unused, initial_state = native.service_reports(req, session, REGION, [role])[role]
    assert unused is None
    assert initial_state['collection_status'] in {'timeout', 'unknown'}
    seed_read = {'iam_role': aws.ReadResult([{'Arn': role, 'RoleName': 'operators',
        'ServicesLastAccessedStatus': initial_state}])}
    rows = [{'type': 'iam_role', 'scope': ACCOUNT + '/global', 'status': 'collected',
        'items': copy.deepcopy(seed_read['iam_role'].items)}]
    with candidate.capture_contexts() as contexts:
        candidate.register_context(req, session, {'Account': ACCOUNT}, [REGION])
        assert candidate.start_account_usage(req, session, {'Account': ACCOUNT}, REGION, seed_read)
        candidate.join_account_usage(rows)
        assert rows[0]['items'][0]['ServicesLastAccessedStatus']['collection_status'] in {'timeout', 'unknown'}
        # Independent image/network work continues; the original AWS job finishes.
        phase['mode'] = 'complete'
        snapshot = make_snapshot('aws', [ACCOUNT + '/global'], rows, metadata={'calls': 0,
            'authorized_evidence_generation': {'service_last_accessed_generation_requests': 0}})
        result = candidate.enrich_snapshot(snapshot, contexts)
        item = result['collections'][0]['items'][0]
        assert item['ServicesLastAccessedStatus']['collection_status'] == 'collected'
        assert item['ServicesLastAccessedStatus']['job_id'] == job
        assert item['ServicesLastAccessed'][0]['TrackedActionsUnobserved'] == ['DeleteRole']
        assert result['metadata']['calls'] == req.calls
        assert result['metadata']['authorized_evidence_generation']['service_last_accessed_generation_requests'] == 1
        before = len(calls)
        assert candidate.enrich_snapshot(result, contexts) == result
        assert len(calls) == before
    assert len([row for row in calls if row[0] == 'generate']) == 1
    # A late-only successful request produces the same complete native evidence.
    _, late_req, late_session, late_phase, late_calls, _ = native_requests_and_session('complete')
    late = native.service_reports(late_req, late_session, REGION, [role])[role]
    assert (item['ServicesLastAccessed'], item['ServicesLastAccessedStatus']) == late
    assert len([row for row in late_calls if row[0] == 'generate']) == 1


def test_late_native_pending_retry_is_bounded_to_once(candidate):
    native, req, session, phase, calls, job = native_requests_and_session('pending')
    unused, state = native.service_reports(req, session, REGION, [ARN])[ARN]
    rows = collections()
    rows[0]['items'][0]['ServicesLastAccessedStatus'] = state
    with candidate.capture_contexts() as contexts:
        candidate.register_context(req, session, {'Account': ACCOUNT}, [REGION])
        result = candidate.enrich_snapshot(make_snapshot('aws', [ACCOUNT + '/global'], rows), contexts)
        assert result['collections'][0]['items'][0]['ServicesLastAccessedStatus']['collection_status'] == 'timeout'
        before = len(calls)
        again = candidate.enrich_snapshot(result, contexts)
        assert again == result and len(calls) == before
    assert len([row for row in calls if row[0] == 'generate']) == 1


def test_native_failed_job_is_not_retried_or_reported_clean(candidate):
    native, req, session, phase, calls, job = native_requests_and_session('failed')
    unused, state = native.service_reports(req, session, REGION, [ARN])[ARN]
    assert state['collection_status'] == 'unknown' and state['error']['code'] == 'service_report_job_failed'
    rows = collections(); rows[0]['items'][0]['ServicesLastAccessedStatus'] = state
    with candidate.capture_contexts() as contexts:
        candidate.register_context(req, session, {'Account': ACCOUNT}, [REGION])
        before = len(calls)
        phase['mode'] = 'complete'
        result = candidate.enrich_snapshot(make_snapshot('aws', [ACCOUNT + '/global'], rows), contexts)
        assert len(calls) == before
    assert result['collections'][0]['items'][0]['ServicesLastAccessedStatus'] == state
    assert 'ServicesLastAccessed' not in result['collections'][0]['items'][0]


def test_native_resume_requires_same_caller_principal_and_granularity_binding(candidate):
    native, req, session, phase, calls, job = native_requests_and_session('pending')
    native.service_reports(req, session, REGION, [ARN])
    req._sla_job_bindings[(id(session), REGION, job)] = f'arn:aws:iam::{ACCOUNT}:group/another'
    phase['mode'] = 'complete'
    before = len(calls)
    unused, state = native.service_reports(req, session, REGION, [ARN])[ARN]
    assert unused is None and state['collection_status'] == 'malformed'
    assert state['error']['code'] == 'service_report_resume_binding_invalid'
    assert len(calls) == before
