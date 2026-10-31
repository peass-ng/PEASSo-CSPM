"""Full owned API responses retain paging, facets, counts and isolation."""
from tests.synthetic.benchmark_peaso_finding_pages import api_fixture, implementation


def test_complete_large_api_pages_match_original_algorithms():
    queries = [{}, {'sort_by': 'title'}, {'sort_by': 'title', 'sort_order': 'desc', 'offset': 27},
        {'sort_by': 'severity', 'sort_order': 'desc'}, {'sort_by': 'resource_id', 'offset': 111},
        {'sort_by': 'account'}, {'sort_by': 'status'}, {'sort_by': 'service'},
        {'sort_by': 'title', 'status': 'FAIL,PASS'}, {'sort_by': 'title', 'search': 'configuration'},
        {'sort_by': 'title', 'aggregation': 'check'}, {'sort_by': 'title', 'offset': 5990},
        {'sort_by': 'title', 'offset': 9999}, {'group_by': 'check_id'}, {'group_by': 'finding_type'}]
    with api_fixture(6000) as (client, ident):
        path = f'/api/scans/{ident}/findings'
        for query in queries:
            params = dict(limit=20, **query)
            actual = client.get(path, params=params)
            assert actual.status_code == 200, actual.text
            with implementation(True):
                expected = client.get(path, params=params)
            assert expected.status_code == 200, expected.text
            assert actual.content == expected.content, params
        response = client.get(path, params={'limit': 20}).json()
        assert response['total'] == response['status_filter_total'] == 6000
        assert len(response['facets']['services']) == 12
        assert response['status_filter_counts'] == {'FAIL': 1500, 'PASS': 1500,
            'UNKNOWN,MANUAL': 3000, 'DENIED': 0, 'NOT_APPLICABLE,EMPTY': 0}
        client.headers['Authorization'] = 'Bearer bob'
        assert client.get(path, params={'limit': 20}).status_code == 404
