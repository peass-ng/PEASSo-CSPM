"""BackupDR wildcard discovery keeps multi-regions and proves each native owner."""
import pytest

from peaso.collectors import gcp
from peaso.collectors import gcp_network_catalog as catalog
from tests.test_peaso_collectors_gcp import NativeDataFixtureTransport, connector

KINDS = tuple(sorted(catalog.BACKUPDR_ALL_LOCATIONS))
SCOPE = 'projects/p-one'


def collect(kind, resolve, **options):
    transport = NativeDataFixtureTransport(resolve)
    reader = gcp.GCPCollector(connector([kind], **options), transport=transport)
    # The independent CRM alias proof itself is tested by the project-binding
    # suite; here test that this list uses that proof and rejects other owners.
    reader._data_project_binding = lambda scope, **kw: {
        'project_id': 'p-one', 'project_number': '123', 'source_requests': ['crm-proof']}
    jobs = [job for job in reader.scope_jobs(SCOPE) if job[0] == kind]
    assert len(jobs) == 1
    return reader.envelope(*jobs[0]), transport


@pytest.mark.parametrize('kind', KINDS)
def test_native_wildcard_keeps_all_pages_multi_regions_and_concrete_iam_routes(kind):
    plan = catalog.PRIVATE_SERVICES[kind]
    def resolve(request):
        assert request['method'] == 'GET'
        if ':getIamPolicy' in request['url']:
            assert '/locations/-/' not in request['url']
            location = request['url'].split('/locations/')[1].split('/')[0]
            assert request['url'].startswith(catalog.api_root('backupdr', 'v1', location) + '/')
            return {'version': 3, 'bindings': []}
        assert request['url'] == f'https://backupdr.googleapis.com/v1/{SCOPE}/locations/-/{plan["segment"]}'
        index = int(request.get('params', {}).get('pageToken', '0'))
        location = ['eu', 'us', 'us-central1'][index]
        return {plan['key']: [{'name': f'{SCOPE}/locations/{location}/{plan["segment"]}/item',
                              'state': 'ACTIVE', 'nativeField': {'keep': location}}],
                **({'nextPageToken': str(index + 1)} if index < 2 else {})}
    row, transport = collect(kind, resolve)
    assert row['status'] == 'collected'
    assert [item['nativeField']['keep'] for item in row['items']] == ['eu', 'us', 'us-central1']
    expected = 6 if plan.get('iam_policy') else 3
    assert len(transport.requests) == expected
    if plan.get('iam_policy'):
        assert all(item['iamPolicy']['bindings'] == [] for item in row['items'])


@pytest.mark.parametrize('kind', KINDS)
@pytest.mark.parametrize('option', ['regions', 'backupdr_network_locations'])
def test_explicit_location_selection_retains_the_exact_request(kind, option):
    plan = catalog.PRIVATE_SERVICES[kind]
    def resolve(request):
        assert request['url'] == catalog.api_root('backupdr', 'v1', 'eu') + f'/{SCOPE}/locations/eu/{plan["segment"]}'
        return {plan['key']: []}
    row, transport = collect(kind, resolve, **{option: ['eu']})
    assert row['status'] == 'empty' and len(transport.requests) == 1


@pytest.mark.parametrize('kind', KINDS)
def test_unreachable_keeps_successful_items_and_partial_status(kind):
    plan = catalog.PRIVATE_SERVICES[kind]
    def resolve(request):
        if ':getIamPolicy' in request['url']:
            return {'version': 3, 'bindings': []}
        return {plan['key']: [{'name': f'{SCOPE}/locations/eu/{plan["segment"]}/visible'}],
                'unreachable': ['us-central1']}
    row, _ = collect(kind, resolve)
    assert len(row['items']) == 1
    assert row['status'] == 'partial' and row['error']['code'] == 'unreachable_locations'


@pytest.mark.parametrize('name', [
    'projects/foreign/locations/eu/backupPlans/item',
    'projects/p-one/locations/-/backupPlans/item',
    'projects/p-one/locations/eu?redirect/backupPlans/item',
    'projects/p-one/locations/eu/backupVaults/item',
    'projects/p-one/locations/eu/backupPlans/..',
    'projects/p-one/locations/eu/backupPlans/item/extra',
])
def test_malformed_or_foreign_row_never_hydrates_or_erases_valid_prefix(name):
    def resolve(request):
        assert ':getIamPolicy' not in request['url']
        return {'backupPlans': [{'name': f'{SCOPE}/locations/eu/backupPlans/visible'}, {'name': name}]}
    row, transport = collect('backupdr_backup_plan', resolve)
    assert len(transport.requests) == 1
    assert row['status'] == 'partial'
    assert [item['name'] for item in row['items']] == [f'{SCOPE}/locations/eu/backupPlans/visible']


@pytest.mark.parametrize('project,accepted', [('123', True), ('999', False)])
def test_numeric_project_alias_requires_independent_selected_project_binding(project, accepted):
    row, _ = collect('backupdr_backup_plan', lambda request: {
        'backupPlans': [{'name': f'projects/{project}/locations/us/backupPlans/item'}]})
    assert bool(row['items']) is accepted
    if accepted:
        assert row['status'] == 'collected' and 'crm-proof' in row['source_requests']
    else:
        assert row['status'] not in {'collected', 'empty'}


@pytest.mark.parametrize('kind', ['knowledge_catalog_lake', 'bigquery_private_connection'])
def test_other_inventory_location_discovery_is_unchanged(kind):
    from types import SimpleNamespace
    reader = SimpleNamespace(options={}, pages=lambda *a, **kw: iter([
        ([{'locationId': location} for location in ['eu', 'us', 'global', 'asia', 'future-region']], 'locations-proof')]))
    result = list(catalog.locations(reader, SCOPE, kind))
    assert result == [([], 'locations-proof'),
                      (['eu', 'us', 'global', 'asia', 'future-region'], None)]


def test_explicit_empty_selection_does_not_become_a_full_scan():
    row, transport = collect('backupdr_backup_plan', lambda request: pytest.fail('unexpected read'), regions=[])
    assert transport.requests == []
    assert row['error']['code'] == 'network_service_locations_unavailable'
