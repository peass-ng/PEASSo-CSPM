from copy import deepcopy
import json
from pathlib import Path

from peaso.collectors import azure_unused_iam_user_completion as producer
from peaso import unused_iam_azure_user_completion as subject


CASES = json.loads((Path(__file__).parents[1] / 'peaso/checks/unused_iam_azure_user_completion_cases.json').read_text())[subject.CHECK]


def case(name='fail'):
    return deepcopy(CASES[name]), deepcopy(CASES[name + '_index'])


def _aligned(item, index, **changes):
    row = index['collections'][producer.KIND][0]['items'][0]['source']['items'][0]
    row.update(changes)
    if 'signInActivity' in changes:
        item['signInActivity'] = deepcopy(changes['signInActivity'])
        index['collections']['directory_user'][0]['items'][0]['signInActivity'] = deepcopy(changes['signInActivity'])
        index['directory_user'][0]['data']['signInActivity'] = deepcopy(changes['signInActivity'])
    report = index['collections'][producer.KIND][0]['items'][0]['source']
    report['items_sha256'] = producer.digest(report['items'])
    index[producer.KIND][0]['data'] = deepcopy(index['collections'][producer.KIND][0]['items'][0])
    return item, index


def test_native_pass_fail_unknown_cases():
    for name, expected in [('pass', 'PASS'), ('fail', 'FAIL'), ('unknown', 'UNKNOWN')]:
        item, index = case(name)
        status, details = subject.evaluate(item, index)
        assert status == expected, details
        assert 1 <= len(details['summary'].splitlines()) <= 3


def test_failed_attempt_does_not_replace_old_success():
    item, index = case('fail')
    activity = {'lastSuccessfulSignInDateTime': '2026-01-01T00:00:00Z',
                'lastSignInDateTime': '2026-10-20T00:00:00Z'}
    item, index = _aligned(item, index, signInActivity=activity)
    assert subject.evaluate(item, index)[0] == 'FAIL'


def test_missing_success_creation_conflict_and_future_are_unknown():
    item, index = case('fail')
    item, index = _aligned(item, index, signInActivity={'lastSignInDateTime': '2026-10-20T00:00:00Z'})
    assert subject.evaluate(item, index)[0] == 'UNKNOWN'
    item, index = case('fail')
    item, index = _aligned(item, index, createdDateTime='2026-02-01T00:00:00Z')
    assert subject.evaluate(item, index)[0] == 'UNKNOWN'
    item, index = case('fail')
    item, index = _aligned(item, index, signInActivity={'lastSuccessfulSignInDateTime': '2026-10-22T00:00:00Z'})
    assert subject.evaluate(item, index)[0] == 'UNKNOWN'


def test_nullable_historical_creation_does_not_hide_recorded_old_success():
    item, index = case('fail')
    item, index = _aligned(item, index, createdDateTime=None)
    status, details = subject.evaluate(item, index)
    assert status == 'FAIL' and details['created_at'] is None


def test_foreign_capture_and_modified_projection_are_unknown():
    item, index = case('fail')
    index['context']['metadata']['customer_context_id'] = 'another-customer'
    assert subject.evaluate(item, index)[0] == 'UNKNOWN'
    item, index = case('fail')
    index['collections'][producer.KIND][0]['items'][0]['source']['items'][0]['displayName'] = 'changed'
    assert subject.evaluate(item, index)[0] == 'UNKNOWN'
    item, index = case('fail')
    index['collections']['directory_user'][0]['items'][0]['accountEnabled'] = False
    assert subject.evaluate(item, index)[0] == 'UNKNOWN'


def test_denied_and_partial_activity_cannot_fail():
    for status, expected in [('denied', 'DENIED'), ('partial', 'UNKNOWN')]:
        item, index = case('fail')
        index['collections'][producer.KIND][0]['items'][0]['source']['status'] = status
        index[producer.KIND][0]['data']['source']['status'] = status
        assert subject.evaluate(item, index)[0] == expected


def test_mismatched_current_identity_and_missing_projection_are_unknown():
    item, index = case('fail')
    item['id'] = '33333333-3333-4333-8333-333333333333'
    assert subject.evaluate(item, index)[0] == 'UNKNOWN'
    item, index = case('fail')
    item.pop('signInActivity')
    index['collections']['directory_user'][0]['items'][0].pop('signInActivity')
    index['directory_user'][0]['data'].pop('signInActivity')
    assert subject.evaluate(item, index)[0] == 'UNKNOWN'


def test_continuation_rejects_foreign_host_and_changed_projection():
    base = producer.GRAPH + producer.ENDPOINT
    producer.validate_read(base + '&$skiptoken=opaque', audience=producer.GRAPH, body=None)
    for url in (base.replace('graph.microsoft.com', 'other.example'),
                base.replace('signInActivity', 'createdDateTime'),
                base + '&$filter=accountEnabled%20eq%20true',
                base + '&$select=id'):
        try:
            producer.validate_read(url, audience=producer.GRAPH, body=None)
        except ValueError:
            pass
        else:
            raise AssertionError('unsafe continuation accepted: ' + url)


def test_adapter_paginates_and_records_denial_without_inactivity():
    class Reader:
        def __init__(self, fail=False):
            self.collections = []
            self.fail = fail
        def pages(self, request, url, *, audience, next_key):
            if self.fail:
                error = RuntimeError('forbidden')
                error.status_code = 403
                raise error
            request(url, audience=audience, body=None)
            yield [{'id': CASES['fail']['id'], 'displayName': 'Synthetic user',
                    'accountEnabled': True, 'createdDateTime': '2025-01-01T00:00:00Z',
                    'signInActivity': {'lastSuccessfulSignInDateTime': '2026-01-01T00:00:00Z'}}]
    class Transport:
        tenant = CASES['fail_index']['context']['metadata']['tenant_id']
        verified_tenant = tenant
    sent = []
    reader = Reader()
    producer.collect(reader, lambda url, **kwargs: sent.append(url) or {}, [], {producer.KIND},
                     Transport(), 'capture-one', 'customer-one')
    assert sent == [producer.GRAPH + producer.ENDPOINT]
    assert reader.collections[0]['items'][0]['source']['status'] == 'collected'
    reader = Reader(fail=True)
    producer.collect(reader, lambda url, **kwargs: {}, [], {producer.KIND},
                     Transport(), 'capture-one', 'customer-one')
    assert reader.collections[0]['items'][0]['source']['status'] == 'denied'


def test_collector_receipt_evaluates_current_directory_user(monkeypatch):
    item, index = case('fail')
    from datetime import datetime
    from types import SimpleNamespace
    # This fixture intentionally uses a fixed snapshot. Keep native proof
    # capture at that instant rather than bypassing its freshness requirement.
    captured=datetime.fromisoformat(index['context']['created_at'].replace('Z','+00:00'))
    monkeypatch.setattr(producer,'datetime',SimpleNamespace(now=lambda tz:captured.astimezone(tz)))
    class Reader:
        collections = []
        def pages(self, request, url, *, audience, next_key):
            request(url, audience=audience, body=None)
            yield [{'id': item['id'], 'displayName': item['displayName'],
                    'accountEnabled': True, 'createdDateTime': '2025-01-01T00:00:00Z',
                    'signInActivity': item['signInActivity']}]
    class Transport:
        tenant = index['context']['metadata']['tenant_id']
        verified_tenant = tenant
    reader = Reader()
    producer.collect(reader, lambda url, **kwargs: {}, [], {producer.KIND},
                     Transport(), 'capture-one', 'customer-one')
    record = reader.collections[0]['items'][0]
    index['collections'][producer.KIND] = reader.collections
    index[producer.KIND] = [{'type': producer.KIND, 'scope': index['context']['scope'], 'data': record}]
    assert subject.evaluate(item, index)[0] == 'FAIL'


def test_existing_control_id_and_native_registration_shape():
    from peaso.checks import CHECKS
    from types import SimpleNamespace
    before = next(check for check in CHECKS if check.id == subject.CHECK)
    registry = SimpleNamespace(CHECKS=[before])
    subject.install(registry)
    after, = registry.CHECKS
    assert after.id == 'azure.claude.entra_user_recent_sign_in'
    assert after.evaluate is subject.evaluate
    assert after.frameworks == before.frameworks
    assert after.category == before.category == 'hardening'
    assert tuple(after.dependencies) == ('directory_user', producer.KIND)
