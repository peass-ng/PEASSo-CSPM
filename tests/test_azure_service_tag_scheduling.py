"""Independent service-tag reads share the native batch without extra requests."""
import pytest

from peaso.collectors import azure
from tests.test_peaso_collectors_azurek8s import FakeAzure, collection


@pytest.mark.parametrize('options,overlap', [
    ({'concurrency': 2}, True),
    ({'concurrency': 1}, False),
    ({'max_pages': 1}, False),
    ({'max_resources': 10}, False),
    ({'max_calls': 100}, False),
    ({'max_scopes': 1}, False),
])
def test_service_tags_join_independent_inventory_batch_only_without_caps(monkeypatch, options, overlap):
    batches = []
    original = azure._Reader.run
    def run(reader, jobs):
        jobs = list(jobs)
        batches.append([job[0] for job in jobs])
        return original(reader, jobs)
    monkeypatch.setattr(azure._Reader, 'run', run)
    def resolve(url, body, audience):
        assert body is None
        return {'values': []} if '/serviceTags?' in url else {'value': []}
    transport = FakeAzure(resolve)
    result = azure.collect({'scopes': ['sub-a'], 'options': options},
                           ['service_tag', 'vm'], transport=transport)
    assert any('service_tag' in batch and 'vm' in batch for batch in batches) is overlap
    assert sum('/serviceTags?' in url for url, _, _ in transport.calls) == 1
    assert sum(row['type'] == 'service_tag' for row in result['collections']) == 1
    assert collection(result, 'service_tag')['status'] == 'empty'


def test_service_tag_later_page_error_keeps_prefix_and_does_not_refetch():
    first = 'https://management.azure.com/subscriptions/sub-a/providers/Microsoft.Network/locations/westcentralus/serviceTags?api-version=2025-09-01'
    def resolve(url, body, audience):
        if url == first:
            return {'values': [{'name': 'Storage.Test',
                                'properties': {'addressPrefixes': ['10.0.0.0/8']}}],
                    'nextLink': first + '&next=2'}
        if '/serviceTags?' in url:
            raise azure.AzureReadError('continuation_denied', 403)
        return {'value': []}
    transport = FakeAzure(resolve)
    result = azure.collect({'scopes': ['sub-a']}, ['service_tag', 'vm'], transport=transport)
    row = collection(result, 'service_tag')
    assert row['status'] == 'partial'
    assert len(row['items']) == 1
    assert row['items'][0]['properties']['addressPrefixes'] == ['10.0.0.0/8']
    assert sum('/serviceTags?' in url for url, _, _ in transport.calls) == 2
