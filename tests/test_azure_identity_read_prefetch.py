"""Late identity projection consumes bounded lookahead without losing native reads."""
import collections
from copy import deepcopy
import threading
from types import SimpleNamespace

import pytest

from peaso.collectors import azure
from peaso.collectors import azure_identity_enforcement_review_20261020 as native

TENANT = '22222222-2222-2222-2222-222222222222'
SCOPE = '/tenants/' + TENANT
USER = '33333333-3333-3333-3333-333333333333'
TRANSPORT = SimpleNamespace(tenant=TENANT, verified_tenant=TENANT)


def reader(options=None, count=1):
    result = azure._Reader({'concurrency': 4, 'retries': 0, **(options or {})})
    users = [{'id': USER}] if count == 1 else [{'id': f'{i:08x}-3333-3333-3333-333333333333'} for i in range(1, count + 1)]
    result.collections.append({'type': 'directory_user', 'scope': SCOPE, 'service': 'Microsoft.Graph',
                               'status': 'collected', 'items': users})
    return result


def project(prefetched, *, failure=False, count=1):
    r = reader(count=count); calls = collections.Counter(); lock = threading.Lock()
    entered = threading.Event(); release = threading.Event()
    def request(url, **kwargs):
        with lock:
            calls[url] += 1
        if url.startswith(azure.ARM):
            entered.set()
            if prefetched:
                assert release.wait(3), 'independent inventory did not release native read'
            if failure:
                if '&next=2' in url:
                    raise azure.AzureReadError('forbidden', 403)
                return {'value': [{'id': USER}], 'nextLink': url + '&next=2'}
        if '/authentication/requirements' in url:
            return {'perUserMfaState': 'enforced'}
        return {'value': []}
    managers = native.prefetch(r, request, {native.KIND}, TRANSPORT) if prefetched else ()
    try:
        if prefetched:
            assert entered.wait(3), 'ARM identity read waited for late projection'
            release.set()
        windows = [(len(m.streams), m.lookahead) for m in managers]
        native.collect(r, request, [], {native.KIND}, TRANSPORT, 'credential', 'customer')
        row = deepcopy(r.collections[-1])
        for proof in (row.get('_provenance', {}), row['items'][0]['_provenance']):
            proof.pop('observed_at', None)
        return row, calls, r.budget.calls, windows
    finally:
        release.set()
        for manager in managers:
            manager.close()
        assert not hasattr(r, 'identity_arm_prefetch')
        assert not hasattr(r, 'identity_graph_prefetch')
        assert all(m.request is None for m in managers)


@pytest.mark.parametrize('failure', [False, True])
def test_native_projection_requests_budgets_and_errors_match_serial(failure):
    serial = project(False, failure=failure)
    prefetched = project(True, failure=failure)
    assert prefetched[:3] == serial[:3]
    assert max(prefetched[1].values()) == 1
    assert all(m[1] == 1 for m in prefetched[3])


def test_bounded_window_preserves_later_principals_and_singletons():
    serial = project(False, count=70)
    prefetched = project(True, count=70)
    assert prefetched[:3] == serial[:3]
    assert prefetched[3] == [(64, 1), (64, 1)]
    assert len(prefetched[0]['items'][0]['sources']) == 427
    assert max(prefetched[1].values()) == 1


@pytest.mark.parametrize('options', [{'concurrency': 1}, {'max_pages': 1}, {'max_calls': 100},
    {'max_resources': 10}, {'max_scopes': 1}])
def test_explicit_limits_preserve_late_scheduling(options):
    def forbidden(*args, **kwargs):
        pytest.fail('capped lookahead made a request')
    assert native.prefetch(reader(options), forbidden, {native.KIND}, TRANSPORT) == ()


@pytest.mark.parametrize('wanted,transport', [(set(), TRANSPORT),
    ({native.KIND}, SimpleNamespace(tenant=TENANT, verified_tenant=None)),
    ({native.KIND}, SimpleNamespace(tenant=USER, verified_tenant=TENANT))])
def test_unselected_or_unverified_native_source_keeps_late_authority(wanted, transport):
    def forbidden(*args, **kwargs):
        pytest.fail('unselected/unverified native lookahead made a request')
    assert native.prefetch(reader(), forbidden, wanted, transport) == ()
