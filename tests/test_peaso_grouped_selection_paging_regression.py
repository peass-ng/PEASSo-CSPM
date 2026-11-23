"""Grouped pages preserve ordering from archived fields and mixed observations."""
import pytest
from tests.test_peaso_report_api_paging_perf import api, route


@pytest.mark.parametrize('group_by',['service','check_id','resource_id','finding_type'])
def test_grouped_page_sorts_and_status_facets_survive_member_selection(api,group_by):
    client, _, _, _ = api
    headers={'Authorization':'Bearer alice'}
    params={'aggregation':'check','group_by':group_by,'limit':100}
    full=client.get(route('findings'),params=params,headers=headers)
    assert full.status_code==200,full.text
    full=full.json()
    expected_total = 3 if group_by == 'finding_type' else 2
    assert full['total'] == expected_total
    if group_by == 'finding_type':
        assert {item['title'] for item in full['items']} == {
            'Archived alpha', 'Archived beta', 'Explicit title'}
    for sort_by in ('title','severity','service','account','status','resource_id'):
        for order in ('asc','desc'):
            sorted_params=dict(params,sort_by=sort_by,sort_order=order)
            all_rows=client.get(route('findings'),params=sorted_params,headers=headers).json()
            pages = [client.get(route('findings'), params=dict(sorted_params, limit=1, offset=offset),
                                headers=headers).json() for offset in range(expected_total)]
            assert [item for page in pages for item in page['items']] == all_rows['items']
            for page in pages:
                assert page['facets'] == full['facets']
                assert page['status_filter_counts'] == full['status_filter_counts']
                assert page['total'] == expected_total
    passed=client.get(route('findings'),params=dict(params,status='PASS'),headers=headers).json()
    assert passed['status_filter_counts']==full['status_filter_counts']
    assert all(item['status']=='PASS'for item in passed['items'])
    assert client.get(route('findings'),params=params,headers={'Authorization':'Bearer bob'}).status_code==404
