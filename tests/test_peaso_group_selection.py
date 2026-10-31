"""Grouped API views preserve complete responses while dropping unused cards."""
import importlib
from unittest.mock import patch

from tests.synthetic.benchmark_peaso_finding_pages import api_fixture
from tests.synthetic.benchmark_peaso_group_selection import reference_client


def test_grouped_list_summary_and_members_match_eager_selection():
    with api_fixture(6000) as (client, ident), reference_client(client) as baseline:
        path = f'/api/scans/{ident}/findings'
        queries = [{}, {'sort_by': 'title'}, {'sort_by': 'severity', 'sort_order': 'desc'},
            {'sort_by': 'resource_id'}, {'group_by': 'finding_type'}, {'status': 'FAIL'},
            {'status': 'UNKNOWN,MANUAL'}, {'service': 'service-1'}, {'search': 'configuration'},
            {'framework': 'Synthetic framework'}, {'finding_type': 'configuration'},
            {'categories': 'hardening', 'offset': 10}]
        for query in queries:
            params = dict(aggregation='check', limit=20, **query)
            actual, expected = client.get(path, params=params), baseline.get(path, params=params)
            assert actual.status_code == expected.status_code == 200, (actual.text, expected.text)
            assert actual.content == expected.content, query
        first = client.get(path, params={'aggregation': 'check'}).json()['items'][0]
        group_path = f"/api/scans/{ident}/finding-groups/{first['id']}"
        for query in ({}, {'members_offset': 7, 'members_limit': 10}, {'status': 'PASS'},
                      {'search': 'configuration'}, {'members_offset': 10000}):
            actual, expected = client.get(group_path, params=query), baseline.get(group_path, params=query)
            assert actual.content == expected.content, query
        summary = f'/api/scans/{ident}/summary'
        assert client.get(summary, params={'aggregation': 'check'}).content == baseline.get(summary, params={'aggregation': 'check'}).content
        module = importlib.import_module('peaso.server.app')
        with patch.object(module, 'finding_summary', wraps=module.finding_summary) as summary_card:
            assert client.get(path, params={'aggregation': 'check'}).status_code == 200
            assert client.get(group_path).status_code == 200
            assert client.get(summary, params={'aggregation': 'check'}).status_code == 200
            assert summary_card.call_count == 0
            assert client.get(path, params={'limit': 20}).status_code == 200
            assert summary_card.call_count >= 6000
        client.headers['Authorization'] = 'Bearer bob'
        assert client.get(path, params={'aggregation': 'check'}).status_code == 404
        assert client.get(group_path).status_code == 404
