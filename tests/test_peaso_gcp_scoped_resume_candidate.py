"""Exact scoped resume path without cloud calls or source-guard substitutes."""
from concurrent.futures import ThreadPoolExecutor
from threading import Lock

import pytest

from peaso.collectors.gcp import GCPCollector
from peaso.collectors.resume import scoped_gcp_lookup
from peaso.snapshot import make_snapshot


def prior_snapshot():
    rows = [
        {'type': 'project', 'scope': 'projects/a', 'service': 'cloudresourcemanager',
         'status': 'collected', 'coverage_status': 'collected', 'items': [{
             'name': 'projects/a', '_resource_id': 'projects/a', 'native_id': 'projects/a',
             '_provenance': {'scope': 'projects/a', 'source_requests': ['req-saved-a'], 'collected_at': 'saved-time'}}],
         'source_requests': ['req-saved-a']},
        {'type': 'project', 'scope': 'projects/b', 'service': 'cloudresourcemanager',
         'status': 'denied', 'coverage_status': 'denied', 'items': [],
         'error': {'kind': 'denied', 'code': 'PERMISSION_DENIED'}, 'source_requests': ['req-old-b']},
        {'type': 'project', 'scope': 'projects/d', 'service': 'cloudresourcemanager',
         'status': 'empty', 'coverage_status': 'empty', 'items': [], 'source_requests': ['req-saved-d']},
    ]
    return make_snapshot('gcp', ['projects/a', 'projects/b', 'projects/d'], rows,
                         metadata={'requested_scopes': [], 'resolved_scopes': ['projects/a', 'projects/b', 'projects/d'],
                                   'collection_mode': 'full'})


def collector(lookup):
    instance = GCPCollector.__new__(GCPCollector)
    instance.resume_collection_lookup = lookup
    instance._resumed_collection_keys = set()
    instance.collections = {}
    instance.lock = Lock()
    instance.workers = 4
    emitted, progress, sdk_calls = [], [], []
    instance.collection_callback = lambda row: emitted.append((row['type'], row['scope'], row['service'], row['status']))
    instance.progress = lambda **kwargs: progress.append(kwargs)
    def envelope(kind, scope, service, fetch):
        sdk_calls.append((kind, scope, service))
        return {'type': kind, 'scope': scope, 'service': service, 'status': 'collected',
                'coverage_status': 'collected', 'items': [fetch()], 'source_requests': ['req-fresh-' + scope]}
    instance.envelope = envelope
    return instance, emitted, progress, sdk_calls


def request(scope):
    return {'name': scope, '_resource_id': scope, 'native_id': scope,
            '_provenance': {'scope': scope, 'source_requests': ['req-fresh-' + scope], 'collected_at': 'fresh-time'}}


def test_exact_saved_success_and_empty_skip_sdk_while_denied_and_new_fetch():
    prior = prior_snapshot()
    callback = scoped_gcp_lookup({'provider': 'gcp', 'scopes': [], 'options': {}}, ['project'], prior)
    instance, emitted, progress, calls = collector(callback)
    rows = [instance.add('project', scope, 'cloudresourcemanager', lambda scope=scope: request(scope))
            for scope in ('projects/a', 'projects/b', 'projects/c', 'projects/d')]
    assert sorted(calls) == [('project', 'projects/b', 'cloudresourcemanager'),
                             ('project', 'projects/c', 'cloudresourcemanager')]
    assert [row['status'] for row in rows] == ['collected', 'collected', 'collected', 'empty']
    assert rows[0]['source_requests'] == ['req-saved-a']
    assert rows[0]['items'][0]['_provenance']['source_requests'] == ['req-saved-a']
    assert rows[3]['source_requests'] == ['req-saved-d']
    assert len(emitted) == len(progress) == 4
    assert instance.add('project', 'projects/a', 'cloudresourcemanager', lambda: request('duplicate')) is rows[0]
    assert len(emitted) == len(progress) == 4 and len(calls) == 2
    rows[0]['items'][0]['name'] = 'changed-after-reuse'
    assert prior['collections'][0]['items'][0]['name'] == 'projects/a'


def test_exact_service_scope_and_stale_plan_never_reuse():
    prior = prior_snapshot()
    callback = scoped_gcp_lookup({'provider': 'gcp', 'scopes': [], 'options': {}}, ['project'], prior)
    instance, emitted, progress, calls = collector(callback)
    instance.add('project', 'projects/a', 'cloudasset', lambda: request('projects/a'))
    instance.add('project', 'projects/c', 'cloudresourcemanager', lambda: request('projects/c'))
    assert calls == [('project', 'projects/a', 'cloudasset'), ('project', 'projects/c', 'cloudresourcemanager')]
    assert len(emitted) == len(progress) == 2
    assert scoped_gcp_lookup({'provider': 'gcp', 'scopes': ['projects/a'], 'options': {}}, ['project'], prior) is None
    assert scoped_gcp_lookup({'provider': 'gcp', 'scopes': [], 'options': {'max_calls': 10}}, ['project'], prior) is None
    assert callback('project', 'projects/b', 'cloudresourcemanager') is None
    assert callback('bucket', 'projects/a', 'cloudresourcemanager') is None
    stale = make_snapshot('gcp', prior['scopes'], prior['collections'],
                          metadata={'requested_scopes': [], 'resolved_scopes': ['projects/a'],
                                    'collection_mode': 'full'})
    assert scoped_gcp_lookup({'provider': 'gcp', 'scopes': [], 'options': {}}, ['project'], stale) is None
    checkpoint_only = make_snapshot('gcp', prior['scopes'], prior['collections'],
                                    metadata={'requested_scopes': [], 'resolved_scopes': prior['scopes'],
                                              'collection_mode': 'checkpoint'})
    assert scoped_gcp_lookup({'provider': 'gcp', 'scopes': [], 'options': {}}, ['project'], checkpoint_only) is None
    discovery, emitted, progress, calls = collector(lambda *_: prior['collections'][0])
    discovery.add('project', 'discovery', 'cloudresourcemanager', lambda: request('discovery'))
    assert calls == [('project', 'discovery', 'cloudresourcemanager')]
    assert len(emitted) == len(progress) == 1


def test_parallel_saved_add_settles_once_and_malformed_callback_fails_closed():
    prior = prior_snapshot()
    callback = scoped_gcp_lookup({'provider': 'gcp', 'scopes': [], 'options': {}}, ['project'], prior)
    instance, emitted, progress, calls = collector(callback)
    with ThreadPoolExecutor(max_workers=4) as pool:
        rows = list(pool.map(lambda _: instance.add('project', 'projects/a', 'cloudresourcemanager',
                                                    lambda: request('unexpected')), range(8)))
    assert all(row is rows[0] for row in rows)
    assert calls == [] and len(emitted) == len(progress) == 1
    for invalid in ({'type': 'project', 'scope': 'projects/other', 'service': 'cloudresourcemanager',
                     'status': 'collected', 'items': [], 'source_requests': []},
                    {'type': 'project', 'scope': 'projects/a', 'service': 'cloudresourcemanager',
                     'status': 'denied', 'items': [], 'source_requests': []},
                    {'type': 'project', 'scope': 'projects/a', 'service': 'cloudresourcemanager',
                     'status': 'collected', 'items': [], 'error': {'code': 'stale'}, 'source_requests': []}):
        rejected, emitted, progress, calls = collector(lambda *_: invalid)
        with pytest.raises(ValueError, match='Invalid resumed native collection'):
            rejected.add('project', 'projects/a', 'cloudresourcemanager', lambda: request('unexpected'))
        assert emitted == progress == calls == []


def test_parallel_scheduler_saved_kind_scope_owns_both_native_views_once():
    prior = prior_snapshot()
    callback = scoped_gcp_lookup({'provider': 'gcp', 'scopes': [], 'options': {}}, ['project'], prior)
    instance, emitted, progress, calls = collector(callback)
    instance.run_jobs([
        ('project', 'projects/a', 'cloudasset', lambda: request('unexpected-cloudasset-view')),
        ('project', 'projects/a', 'cloudresourcemanager', lambda: request('unexpected-saved-view')),
        ('project', 'projects/b', 'cloudresourcemanager', lambda: request('projects/b')),
        ('project', 'projects/c', 'cloudresourcemanager', lambda: request('projects/c')),
    ])
    assert sorted(calls) == [('project', 'projects/b', 'cloudresourcemanager'),
                             ('project', 'projects/c', 'cloudresourcemanager')]
    assert emitted.count(('project', 'projects/a', 'cloudresourcemanager', 'collected')) == 1
    assert len(emitted) == len(progress) == 3
    assert instance.collections[('project', 'projects/a')]['source_requests'] == ['req-saved-a']


