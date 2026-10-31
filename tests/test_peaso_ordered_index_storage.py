"""Dense posting storage retains row identity, source order and error behavior."""
import gc
import random
import tracemalloc

import pytest

from tests.synthetic.reference_peaso_ordered_matches import OriginalOrderedMatchIndex
from peaso.analysis.resource_index import OrderedMatchIndex


def outcome(function):
    try:
        return 'value',function()
    except (TypeError,KeyError,AttributeError) as error:
        return 'error',type(error)


@pytest.mark.parametrize('strict',[False,True])
def test_randomized_nomination_and_smallest_runs_match_original(strict):
    randomizer=random.Random(8842)
    values=['a','b','c',None,False,0,3,('tuple','key'),[],['a'],{'a':1}]
    rows=[{'position':i,'keys':[randomizer.choice(values) for _ in range(randomizer.randrange(1,5))]}
        for i in range(100)]
    rows += [rows[0],rows[17]]
    old=OriginalOrderedMatchIndex(rows,lambda row:row['keys'],strict=strict)
    new=OrderedMatchIndex(rows,lambda row:row['keys'],strict=strict)
    for _ in range(100):
        keys=[randomizer.choice(values) for _ in range(randomizer.randrange(5))]
        expected=outcome(lambda:old.matching(keys))
        actual=outcome(lambda:new.matching(keys))
        assert actual==expected
        if actual[0]=='value':
            assert all(left is right for left,right in zip(actual[1],expected[1]))
        assert outcome(lambda:new.smallest_matching(keys,always=['a']))==outcome(lambda:old.smallest_matching(keys,always=['a']))


@pytest.mark.parametrize('iterator',[False,True])
def test_rows_are_read_once_and_source_mutation_keeps_the_indexed_records(iterator):
    rows=[{'name':'first','keys':['shared','one']},{'name':'second','keys':['shared','two']}]
    source=iter(rows) if iterator else rows
    calls=[]
    def keys(row):
        calls.append(row)
        return row['keys']
    owner=OrderedMatchIndex(source,keys)
    first=owner.matching(['shared','one'])
    assert first==rows and len(calls)==2
    rows.reverse()
    rows.append({'name':'new','keys':['shared']})
    assert owner.matching(['shared'])==first
    assert len(calls)==2
    first.clear()
    assert [row['name'] for row in owner.matching(['shared'])]==['first','second']


def test_rows_added_while_keys_are_read_keep_original_iterator_order():
    def run(factory):
        rows=[{'name':'first','keys':['shared']}]
        def keys(row):
            if len(rows)==1:
                rows.append({'name':'second','keys':['shared']})
            return row['keys']
        owner=factory(rows,keys)
        return owner.matching(['shared']),owner.matching(['shared'])
    assert run(OrderedMatchIndex)==run(OriginalOrderedMatchIndex)


@pytest.mark.parametrize('shared',[False,True])
def test_index_uses_less_peak_allocation_for_large_unique_and_shared_relations(shared):
    rows=[{'position':i,'key':'shared' if shared else str(i)} for i in range(20000)]
    requested=['shared'] if shared else [str(i) for i in range(20000)]
    peaks=[]
    for factory in (OriginalOrderedMatchIndex,OrderedMatchIndex):
        gc.collect()
        tracemalloc.start()
        owner=factory(rows,lambda row:[row['key']])
        result=owner.matching(requested)
        peak=tracemalloc.get_traced_memory()[1]
        tracemalloc.stop()
        assert result==rows
        peaks.append(peak)
        del owner,result
    assert peaks[1]<peaks[0]*0.75
