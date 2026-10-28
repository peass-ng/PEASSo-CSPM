"""Dataplex native masks retain the API's actual incomplete-location field."""
import json
from types import SimpleNamespace

import pytest

from peaso.collectors import gcp
from peaso.collectors.gcp_network_catalog import PRIVATE_SERVICES


@pytest.mark.parametrize('kind,key,coverage', [
    ('knowledge_catalog_aspect_type', 'aspectTypes', ',unreachableLocations'),
    ('knowledge_catalog_entry_type', 'entryTypes', ',unreachableLocations'),
    ('knowledge_catalog_entry_group', 'entryGroups', ',unreachableLocations'),
    ('knowledge_catalog_lake', 'lakes', ',unreachableLocations'),
    ('knowledge_catalog_asset', 'assets', ''),
    ('knowledge_catalog_zone', 'zones', ''),
])
def test_field_masks_match_native_list_response(kind, key, coverage):
    # Dataplex v1 discovery: ListAspectTypes/EntryTypes/EntryGroups/Lakes have
    # unreachableLocations. ListAssets/ListZones have no location failure field.
    assert PRIVATE_SERVICES[kind]['fields'] == f'{key}(name),nextPageToken{coverage}'


@pytest.mark.parametrize('items', [[], [{'name': 'observed'}]])
def test_unreachable_locations_preserve_items_then_fail_completeness(items, monkeypatch):
    payload = {'entryTypes': items, 'unreachableLocations': ['us-central1']}
    response = SimpleNamespace(status_code=200, headers={}, content=json.dumps(payload).encode(), json=lambda: payload)
    session = SimpleNamespace(request=lambda *a, **kw: response, close=lambda: None)
    transport = gcp.Transport(SimpleNamespace(headers=lambda: {}, close=lambda: None), {'retries': 0})
    monkeypatch.setattr(transport, '_session', lambda: session)
    value = SimpleNamespace(page_size=100, max_pages=None,
        read=lambda url, scope, **kw: transport.request('GET', url, scope=scope, params=kw['params']))
    pages = gcp.GCPCollector.pages(value, 'https://dataplex.googleapis.com/v1/projects/p/locations/us/entryTypes',
                                    'projects/p', key='entryTypes')
    assert next(pages) == (items, transport.evidence[0]['id'])
    with pytest.raises(gcp.ReadError, match='unreachable_locations'):
        next(pages)
    assert transport.evidence[0]['http_attempts'] == 1


def test_complete_paginated_list_keeps_every_page():
    responses = iter([({'entryTypes': [{'name': 'one'}], 'nextPageToken': 'next'}, 'native-1'),
                      ({'entryTypes': [{'name': 'two'}], 'unreachableLocations': []}, 'native-2')])
    calls = []
    def read(*a, **kwargs):
        calls.append(dict(kwargs['params']))
        return next(responses)
    value = SimpleNamespace(page_size=100, max_pages=None, read=read)
    assert list(gcp.GCPCollector.pages(value, 'https://dataplex.googleapis.com/v1/projects/p/locations/us/entryTypes',
                                       'projects/p', key='entryTypes')) == [([{'name': 'one'}], 'native-1'), ([{'name': 'two'}], 'native-2')]
    assert calls == [{'pageSize': 100}, {'pageSize': 100, 'pageToken': 'next'}]
