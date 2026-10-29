"""Lake-only region selection preserves catalog multi-regions and failures."""
from types import SimpleNamespace
from urllib.parse import urlsplit

import pytest

from peaso.collectors.gcp import GCPCollector, ReadError
from peaso.collectors import gcp_dataplex_privesc as privesc
from peaso.collectors import gcp_network_catalog as catalog

SCOPE = 'projects/p1'
NON_REGIONS = ['global', 'us', 'eu', 'asia', 'nam5', 'nam7', 'eur3']
REGIONS = ['us-central1', 'europe-west1', 'new-private-region9']
LAKE_KINDS = ['dataplex_network_task', 'knowledge_catalog_lake',
              'knowledge_catalog_zone', 'knowledge_catalog_asset']


class Collector:
    page_size = 100
    max_pages = None
    needed = {'dataplex_privesc_lake'}
    location_pool = None
    pages = GCPCollector.pages

    def __init__(self, *, options=None, failure=None, locations=None):
        self.options = options or {}
        self.calls = []
        self.failure = failure
        self.location_names = locations if locations is not None else NON_REGIONS + REGIONS

    def read(self, url, scope, **kwargs):
        assert scope == SCOPE
        self.calls.append((url, kwargs.get('params')))
        path = urlsplit(url).path
        if path.endswith('/locations'):
            # Exercise real token pagination of the native service-wide list.
            names = self.location_names[:3] if not kwargs['params'].get('pageToken') else self.location_names[3:]
            result = {'locations': [{'name': SCOPE + '/locations/' + name,
                                     'locationId': name} for name in names]}
            if not kwargs['params'].get('pageToken'):
                result['nextPageToken'] = 'locations-next'
        elif path.endswith('/lakes'):
            region = path.split('/locations/')[1].split('/')[0]
            if self.failure and region == 'europe-west1':
                raise self.failure
            name = SCOPE + '/locations/' + region + '/lakes/main'
            result = {'lakes': [{'name': name, 'state': 'ACTIVE'}]}
            if self.failure and region == 'us-central1':
                result['nextPageToken'] = 'lake-next'
                if kwargs['params'].get('pageToken'):
                    raise self.failure
        else:
            segment = path.rsplit('/', 1)[-1]
            result = {segment: []}
        return result, 'request-' + str(len(self.calls))

    def hydrate(self, item, field, url, scope, **kwargs):
        self.calls.append((url, kwargs.get('params')))
        return {**item, field: {'bindings': []}}


def discovered(collector, kind):
    pages = list(catalog.locations(collector, SCOPE, kind))
    return [name for names, _ in pages for name in names], [ref for _, ref in pages if ref]


@pytest.mark.parametrize('kind', LAKE_KINDS)
def test_only_automatic_lake_routes_exclude_non_regions(kind):
    collector = Collector()
    names, refs = discovered(collector, kind)
    assert names == REGIONS
    assert len(refs) == 2
    assert collector.calls[1][1]['pageToken'] == 'locations-next'
    # All four actual factory paths remain present and issue concrete lake reads.
    pages = list(catalog.regional_pages(collector, SCOPE, kind))
    lakes = [url for url, _ in collector.calls if url.endswith('/lakes')]
    assert len(lakes) == len(REGIONS)
    assert all('/locations/' + region + '/lakes' in lakes[i] for i, region in enumerate(REGIONS))
    assert any(ref for _, ref in pages)


@pytest.mark.parametrize('kind', ['knowledge_catalog_aspect_type',
                                'knowledge_catalog_entry_group', 'knowledge_catalog_entry_type',
                                'backupdr_backup_plan', 'backupdr_backup_plan_association',
                                'backupdr_management_server', 'backupdr_backup_vault'])
def test_other_inventory_location_routes_are_unchanged(kind):
    assert discovered(Collector(), kind)[0] == NON_REGIONS + REGIONS


@pytest.mark.parametrize('option', ['regions', 'dataplex_network_locations'])
@pytest.mark.parametrize('selected', [[], ['eu', 'us', 'global', 'nam7', 'us-central1']])
def test_explicit_location_selection_is_preserved(option, selected):
    collector = Collector(options={option: selected})
    assert discovered(collector, 'knowledge_catalog_lake') == (selected, [])
    assert not collector.calls


def test_privesc_lakes_keep_concrete_identity_policy_and_discovery_receipts():
    collector = Collector()
    pages = list(privesc.scope_jobs(collector, SCOPE)[0][3]())
    items = [row for page, _ in pages for row in page]
    assert {row['name'] for row in items} == {
        SCOPE + '/locations/' + region + '/lakes/main' for region in REGIONS}
    assert all(row['iamPolicy'] == {'bindings': []} for row in items)
    assert len([url for url, _ in collector.calls if url.endswith(':getIamPolicy')]) == 3
    assert pages[0][1] == 'request-1' and pages[1][1] == 'request-2'
    assert not any('/locations/' + loc + '/lakes' in url
                   for url, _ in collector.calls for loc in NON_REGIONS)


@pytest.mark.parametrize('mode', ['network', 'privesc'])
@pytest.mark.parametrize('failure', [ReadError('denied', 'permission_denied', http_status=403),
                                    ReadError('unavailable', 'api_error', http_status=400),
                                    ReadError('unavailable', 'unreachable_locations')])
def test_valid_prefix_and_later_error_are_retained(mode, failure):
    collector = Collector(failure=failure, locations=['us-central1'])
    factory = (catalog.regional_pages(collector, SCOPE, 'knowledge_catalog_lake')
               if mode == 'network' else privesc.scope_jobs(collector, SCOPE)[0][3]())
    seen = []
    with pytest.raises(ReadError) as raised:
        for page, ref in factory:
            seen.extend(page)
    assert raised.value is failure
    assert [row['name'] for row in seen] == [SCOPE + '/locations/us-central1/lakes/main']
    assert any(params.get('pageToken') == 'lake-next' for _, params in collector.calls)


def test_unrecognized_location_is_not_silently_dropped():
    assert discovered(Collector(locations=['future-location']), 'knowledge_catalog_lake')[0] == ['future-location']
