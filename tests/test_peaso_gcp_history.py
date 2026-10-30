"""Native API shapes, pagination, denied children and privacy boundaries."""
import pytest

from peaso.collectors import gcp
from tests.test_peaso_collectors_gcp import snapshot, collection

NETWORK = 'https://www.googleapis.com/compute/v1/projects/p-one/global/networks/private'


def record_reads(transport):
    return [r for r in transport.requests if '/rrsets' in r['url']]


def zone(name='private', **extra):
    return {'name': name, 'visibility': 'private',
            'privateVisibilityConfig': {'networks': [{'networkUrl': NETWORK}]}, **extra}


def test_dns_records_preserve_same_hostname_across_zones_and_vpcs():
    second = NETWORK + '-two'
    def resolve(request):
        if request['url'].endswith('/managedZones'):
            return {'managedZones': [zone('one'), zone('two', privateVisibilityConfig={
                'networks': [{'networkUrl': NETWORK}, {'networkUrl': second}]})]}
        if request['url'].endswith(':getIamPolicy'):
            return {'bindings': []}
        assert request['method'] == 'GET' and request['params']['maxResults'] == 100
        return {'rrsets': [{'name': 'private.googleapis.com.', 'type': 'A', 'ttl': 300, 'rrdatas': ['10.0.0.1']}]}
    result, transport = snapshot(['dns_record'], resolve)
    rows = collection(result, 'dns_record')['items']
    assert len(rows) == len({r['native_id'] for r in rows}) == 3
    assert {r['network'] for r in rows} == {NETWORK, second}
    assert {r['name'] for r in rows} == {'private.googleapis.com.'}
    assert len(record_reads(transport)) == 2
    assert all(r['_provenance']['representation'] == 'full' for r in rows)


def test_dns_denied_zone_retains_collected_records_as_partial():
    def resolve(request):
        if request['url'].endswith('/managedZones'):
            return {'managedZones': [zone('one'), zone('two')]}
        if '/two/' in request['url']:
            raise gcp.ReadError('denied', 'fixture_denied')
        return {'rrsets': [{'name': 'private.googleapis.com.', 'type': 'A', 'rrdatas': ['10.0.0.1']}]}
    result, _ = snapshot(['dns_record'], resolve)
    env = collection(result, 'dns_record')
    assert env['status'] == 'partial' and len(env['items']) == 1
    assert env['error']['code'] == 'fixture_denied'


def test_dns_incomplete_parent_does_not_read_child():
    result, transport = snapshot(['dns_record'], lambda request: {'managedZones': [zone()], 'nextPageToken': 'more'}, max_pages=1)
    assert record_reads(transport) == []
    assert collection(result, 'dns_record')['status'] == 'unknown'


@pytest.mark.parametrize('network', ['http://www.googleapis.com/compute/v1/projects/p-one/global/networks/n',
                                   NETWORK + '?access_token=private', 'https://evil.invalid/network'])
def test_dns_does_not_accept_unverified_network_identity(network):
    result, transport = snapshot(['dns_record'], lambda request: {'managedZones': [zone(privateVisibilityConfig={
        'networks': [{'networkUrl': network}]})]})
    assert record_reads(transport) == []
    assert collection(result, 'dns_record')['status'] == 'malformed'


def test_public_dns_zone_is_not_claimed_as_private_visibility():
    result, transport = snapshot(['dns_record'], lambda request: {'managedZones': [zone(visibility='public')]})
    assert record_reads(transport) == [] and collection(result, 'dns_record')['status'] == 'empty'


def test_cloud_builds_pagination_regions_identity_and_secret_projection():
    def resolve(request):
        location = request['url'].split('/locations/')[1].split('/')[0]
        assert request['params']['projectId'] == 'p-one'
        ident = 'second' if request['params'].get('pageToken') else 'first'
        row = {'id': ident, 'name': f'projects/p-one/locations/{location}/builds/{ident}', 'status': 'SUCCESS',
               'buildTriggerId': 'trigger', 'createTime': '2026-10-14T00:00:00Z',
               'sourceProvenance': {'resolvedRepoSource': {'commitSha': 'a' * 40}, 'fileHashes': {'secret-path': 'private'}},
               'substitutions': {'COMMIT_SHA': 'b' * 40, '_PASSWORD': 'private'},
               'steps': [{'args': ['private'], 'secretEnv': ['PASSWORD']}], 'secrets': ['private']}
        return {'builds': [row], **({'nextPageToken': 'next'} if ident == 'first' else {})}
    result, transport = snapshot(['cloudbuild_build'], resolve, cloudbuild_locations=['us-central1'])
    rows = collection(result, 'cloudbuild_build')['items']
    assert len(rows) == 4 and len(transport.requests) == 4
    assert len({r['native_id'] for r in rows}) == 4
    for row in rows:
        assert row['buildTriggerId'] == 'trigger' and 'triggerId' not in row
        assert row['substitutions'] == {'COMMIT_SHA': 'b' * 40}
        assert row['sourceProvenance'] == {'resolvedRepoSource': {'commitSha': 'a' * 40}}
        assert 'steps' not in row and 'secrets' not in row and 'productionDeployment' not in row
        assert row['_provenance']['representation'] == 'partial'


def test_cloud_build_foreign_location_or_project_is_malformed():
    result, _ = snapshot(['cloudbuild_build'], lambda request: {'builds': [{'id': 'one',
        'name': 'projects/foreign/locations/global/builds/one'}]}, cloudbuild_locations=[])
    assert collection(result, 'cloudbuild_build')['status'] == 'malformed'


@pytest.mark.parametrize('kind,segment,key', [('cloudbuild_build', 'builds', 'builds'),
                                            ('cloudbuild_trigger', 'triggers', 'triggers')])
def test_cloud_build_default_discovers_and_reads_all_regions(kind, segment, key):
    def resolve(request):
        if request['url'].endswith('/locations'):
            assert request['url'] == 'https://cloudbuild.googleapis.com/v2/projects/p-one/locations'
            return {'locations': [{'locationId': 'us-central1'}, {'locationId': 'europe-west1'}]}
        location = request['url'].split('/locations/')[1].split('/')[0]
        assert request['url'].endswith('/' + segment)
        return {key: [{'id': 'one', 'name': f'projects/p-one/locations/{location}/{segment}/one'}]}
    result, transport = snapshot([kind], resolve)
    assert collection(result, kind)['status'] == 'collected'
    assert len(collection(result, kind)['items']) == 3 and len(transport.requests) == 4


def test_cloud_build_location_discovery_failure_never_claims_empty_inventory():
    def resolve(request):
        raise gcp.ReadError('denied', 'fixture_denied')
    result, _ = snapshot(['cloudbuild_build'], resolve)
    assert collection(result, 'cloudbuild_build')['status'] == 'denied'


@pytest.mark.parametrize('kind,key', [('cloudbuild_build', 'builds'), ('cloudbuild_trigger', 'triggers')])
def test_global_region_denial_does_not_hide_readable_regional_history(kind, key):
    def resolve(request):
        if '/locations/global/' in request['url']:
            raise gcp.ReadError('denied', 'fixture_denied')
        return {key: [{'id': 'one', 'name': f'projects/p-one/locations/us-central1/{key}/one'}]}
    result, _ = snapshot([kind], resolve, cloudbuild_locations=['us-central1'])
    env = collection(result, kind)
    assert env['status'] == 'partial' and len(env['items']) == 1
    assert result['metadata']['cloudbuild_location_mode'] == 'selected'
    assert result['metadata']['cloudbuild_location_selection'] == ['us-central1']


@pytest.mark.parametrize('selection', [None, 'us-central1', ['../secret'], ['us-central1', 'us-central1'], list(range(101))])
def test_hosted_cloud_build_location_selection_rejects_invalid_input(selection):
    from types import SimpleNamespace
    from fastapi import HTTPException
    from peaso.server.validation import validate_connector
    with pytest.raises(HTTPException) as exc:
        validate_connector('gcp', {'method': 'token', 'token': 'fixture'},
                           {'cloudbuild_locations': selection}, SimpleNamespace(auth_mode='cognito'))
    assert exc.value.status_code == 422


def test_hosted_cloud_build_location_selection_accepts_explicit_regions():
    from types import SimpleNamespace
    from peaso.server.validation import validate_connector
    options = {'cloudbuild_locations': ['us-central1']}
    validate_connector('gcp', {'method': 'token', 'token': 'fixture'}, options, SimpleNamespace(auth_mode='cognito'))
    assert options == {'cloudbuild_locations': ['us-central1']}


def test_cloud_build_project_number_alias_requires_native_project_id():
    def resolve(request):
        return {'builds': [{'id': 'one', 'projectId': 'p-one',
                           'name': 'projects/123456789/locations/global/builds/one'}]}
    result, _ = snapshot(['cloudbuild_build'], resolve, cloudbuild_locations=[])
    assert collection(result, 'cloudbuild_build')['items'][0]['name'] == 'projects/123456789/locations/global/builds/one'
    result, _ = snapshot(['cloudbuild_build'], lambda request: {'builds': [{'id': 'one',
        'name': 'projects/123456789/locations/global/builds/one'}]}, cloudbuild_locations=[])
    assert collection(result, 'cloudbuild_build')['status'] == 'malformed'


def test_sql_operation_projects_native_fields_without_validation_inference():
    def resolve(request):
        if request['url'].endswith('/instances'):
            return {'items': [{'name': 'restored-db'}]}
        if request['url'].endswith('/users'):
            return {'items': []}
        assert request['url'] == 'https://sqladmin.googleapis.com/sql/v1beta4/projects/p-one/operations'
        assert request['params']['instance'] == 'restored-db'
        assert request['method'] == 'GET'
        return {'items': [{'name': 'op-one', 'targetProject': 'p-one', 'targetId': 'restored-db',
            'operationType': 'RESTORE_VOLUME', 'status': 'DONE', 'endTime': '2026-10-14T00:00:00Z',
            'error': {'errors': [{'code': 'FAILED', 'message': 'private-cause'}]}, 'user': 'private-user'}]}
    result, _ = snapshot(['sql_operation'], resolve)
    row = collection(result, 'sql_operation')['items'][0]
    assert row['name'] == 'projects/p-one/operations/op-one'
    assert row['error'] == {'errors': [{'code': 'FAILED'}]}
    assert 'validated' not in row and 'sourceInstance' not in row and 'user' not in row
    assert row['_provenance']['representation'] == 'partial'


def test_sql_operation_foreign_project_is_malformed():
    def resolve(request):
        if request['url'].endswith('/instances'):
            return {'items': [{'name': 'db'}]}
        if request['url'].endswith('/users'):
            return {'items': []}
        return {'items': [{'name': 'op', 'targetProject': 'foreign'}]}
    result, _ = snapshot(['sql_operation'], resolve)
    assert collection(result, 'sql_operation')['status'] == 'malformed'
