"""Ordered graph queries keep complete totals with bounded result selection."""
import copy
import pytest
from tests.synthetic.benchmark_peaso_privesc_pages import fixture, reference
from peaso.privesc import queries


@pytest.mark.parametrize('query', ['reach_admin', 'broad_reach'])
@pytest.mark.parametrize('offset,limit', [(0, 1), (0, 100), (23, 50), (2047, 10), (2300, 100), (9000, 20)])
@pytest.mark.parametrize('include_unknown', [False, True])
def test_page_matches_full_order_and_counts(query, offset, limit, include_unknown):
    graph = fixture(6000)
    # Cycle and aggregate membership exercise zero-hop and confidence paths.
    graph['nodes'].append({'id': 'aggregate', 'kind': 'aggregate', 'type': 'principal_group',
        'members': [graph['nodes'][0]['id']], 'confidence': 'unknown', 'underlying_count': 1})
    graph['edges'].extend([
        {'id': 'aggregate-edge', 'source': 'aggregate', 'target': 'admin', 'confidence': 'unknown'},
        {'id': 'cycle', 'source': graph['nodes'][1]['id'], 'target': graph['nodes'][0]['id'], 'confidence': 'conditional'}])
    before = copy.deepcopy(graph)
    index = queries.GraphIndex(graph)
    kwargs = {'include_unknown': include_unknown}
    assert getattr(queries, query + '_page')(index, offset=offset, limit=limit, **kwargs) == reference(index, query, offset, limit, **kwargs)
    assert graph == before


def test_empty_graph_and_fresh_rows():
    for query in ['reach_admin', 'broad_reach']:
        method = getattr(queries, query + '_page')
        assert method({'nodes': [], 'edges': []})['total'] == 0
        index = queries.GraphIndex(fixture(20))
        first = method(index)
        first['items'][0]['principal'] = 'changed'
        assert method(index)['items'][0]['principal'] != 'changed'
