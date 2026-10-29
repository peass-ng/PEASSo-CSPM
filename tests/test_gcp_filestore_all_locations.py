"""Filestore's native wildcard includes all zones/regions without discovery."""
import pytest

from peaso.collectors import gcp
from tests.test_peaso_collectors_gcp import FixtureTransport, connector, collection


def snapshot(kinds, resolve, **options):
    # Exercise the real list factory and envelope, independently of additional
    # supporting inventories selected by full-provider requirements expansion.
    transport = FixtureTransport(resolve)
    collector = gcp.GCPCollector(connector(kinds, **options), transport=transport)
    rows = [collector.envelope(*job) for job in collector.scope_jobs('projects/p-one')
            if job[0] in kinds]
    return {'collections': rows}, transport


@pytest.mark.parametrize('kind,key,locations', [
    ('filestore_instance', 'instances', ['us-central1-a', 'europe-west1-b']),
    ('filestore_backup', 'backups', ['us-central1', 'europe-west1']),
])
def test_all_locations_paginate_and_keep_full_native_items(kind, key, locations):
    def resolve(request):
        assert request['method'] == 'GET'
        assert request['url'] == f'https://file.googleapis.com/v1/projects/p-one/locations/-/{key}'
        second = bool(request.get('params', {}).get('pageToken'))
        item = {'name': f'projects/p-one/locations/{locations[int(second)]}/{key}/item',
                'network': 'native-network', 'labels': {'keep': 'exact'}}
        return {key: [item], **({} if second else {'nextPageToken': 'next'})}
    result, transport = snapshot([kind], resolve)
    row = collection(result, kind)
    assert row['status'] == 'collected'
    assert len(transport.requests) == 2
    assert len(row['source_requests']) == 2
    assert [item['name'].split('/')[3] for item in row['items']] == locations
    assert all(item['labels'] == {'keep': 'exact'} and
               item['_provenance']['representation'] == 'full' for item in row['items'])


@pytest.mark.parametrize('kind,key', [('filestore_instance', 'instances'),
                                     ('filestore_backup', 'backups')])
def test_unreachable_location_keeps_positive_items_and_incomplete_status(kind, key):
    item = {'name': f'projects/p-one/locations/us-central1-a/{key}/visible'}
    result, transport = snapshot([kind], lambda request: {
        key: [item], 'unreachable': ['europe-west1']})
    row = collection(result, kind)
    assert len(transport.requests) == 1
    assert row['status'] == 'partial'
    assert row['error']['code'] == 'unreachable_locations'
    assert len(row['items']) == 1 and row['items'][0]['name'] == item['name']
    assert row['items'][0]['_provenance']['representation'] == 'full'


@pytest.mark.parametrize('options', [{'filestore_locations': ['us-central1-a']},
                                    {'regions': ['us-central1-a']},
                                    {'filestore_locations': [], 'regions': ['us-central1-a']}])
def test_explicit_locations_keep_their_original_scope(options):
    def resolve(request):
        assert '/locations/us-central1-a/instances' in request['url']
        return {'instances': []}
    result, transport = snapshot(['filestore_instance'], resolve, **options)
    assert len(transport.requests) == (0 if options.get('filestore_locations') == [] else 1)
    assert collection(result, 'filestore_instance')['status'] == 'empty'


@pytest.mark.parametrize('error', [gcp.ReadError('denied', 'permission_denied'),
                                  gcp.ReadError('unavailable', 'quota_exhausted'),
                                  gcp.ReadError('denied', 'policy_denied',
                                                reason='LOCATION_POLICY_VIOLATED')])
def test_wildcard_errors_are_not_converted_to_empty_or_retried_per_region(error):
    def resolve(request):
        assert '/locations/-/instances' in request['url']
        raise error
    result, transport = snapshot(['filestore_instance'], resolve)
    row = collection(result, 'filestore_instance')
    assert len(transport.requests) == 1
    assert row['status'] != 'empty'
    assert row['error']['code'] == error.error['code']


@pytest.mark.parametrize('failure', ['page_limit', 'permission_denied'])
def test_incomplete_pagination_keeps_the_successful_prefix(failure):
    def resolve(request):
        if request.get('params', {}).get('pageToken'):
            raise gcp.ReadError('denied', 'permission_denied')
        return {'backups': [{'name': 'projects/p-one/locations/us-central1/backups/visible'}],
                'nextPageToken': 'next'}
    options = {'max_pages': 1} if failure == 'page_limit' else {}
    result, transport = snapshot(['filestore_backup'], resolve, **options)
    row = collection(result, 'filestore_backup')
    assert row['status'] == 'partial' and row['error']['code'] == failure
    assert len(row['items']) == 1
    assert len(transport.requests) == (1 if failure == 'page_limit' else 2)
