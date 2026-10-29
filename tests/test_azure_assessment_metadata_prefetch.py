"""ARM definition lookahead preserves the native late comparison and budgets."""
import threading

import pytest

from peaso.collectors import azure
from peaso.collectors.azure_page_prefetch import PagePrefetch
from tests.test_peaso_collectors_azurek8s import FakeAzure, collection

SCOPE='/subscriptions/sub-a'
DEFINITION={'id':SCOPE+'/providers/Microsoft.Security/assessmentMetadata/check-a',
            'name':'check-a','properties':{'severity':'High'}}


def test_definition_read_overlaps_earlier_resource_read_and_is_not_fetched_twice():
    definition_started=threading.Event();resource_started=threading.Event()
    def resolve(url,body,audience):
        if '/assessmentMetadata?' in url:
            definition_started.set()
            assert resource_started.wait(3), 'definition read did not overlap earlier inventory'
            return {'value':[DEFINITION]}
        if '/resources?' in url:
            assert definition_started.wait(3), 'definition lookahead did not start'
            resource_started.set()
        return {'value':[]}
    transport=FakeAzure(resolve)
    snapshot=azure.collect({'scopes':['sub-a'],'options':{'concurrency':4}},
                           ['assessment_metadata','azure_resource'],transport=transport)
    assert definition_started.is_set() and resource_started.is_set()
    assert sum('/assessmentMetadata?' in url for url,_,_ in transport.calls)==1
    row=collection(snapshot,'assessment_metadata')
    assert row['status']=='collected' and row['items'][0]['properties']=={'severity':'High'}


@pytest.mark.parametrize('options',[{'concurrency':1},{'max_pages':1},
    {'max_resources':10},{'max_calls':100},{'max_scopes':1}])
def test_capped_or_single_worker_collection_keeps_ordinary_late_reads(monkeypatch,options):
    original=PagePrefetch.start;assessment_prefetch=[]
    def start(manager):
        if manager.audience==azure.ARM:assessment_prefetch.append(manager)
        return original(manager)
    monkeypatch.setattr(PagePrefetch,'start',start)
    def resolve(url,body,audience):return {'value':[DEFINITION]} if '/assessmentMetadata?' in url else {'value':[]}
    transport=FakeAzure(resolve)
    result=azure.collect({'scopes':['sub-a'],'options':options},['assessment_metadata','vm'],transport=transport)
    assert assessment_prefetch==[]
    assert sum('/assessmentMetadata?' in url for url,_,_ in transport.calls)==1
    assert collection(result,'assessment_metadata')['status']=='collected'


def test_arm_continuation_failure_preserves_positive_prefix_without_refetch():
    def resolve(url,body,audience):
        if '/assessmentMetadata?' in url:
            if '&next=2' in url:raise azure.AzureReadError('denied',403)
            return {'value':[DEFINITION],'nextLink':url+'&next=2'}
        return {'value':[]}
    transport=FakeAzure(resolve)
    result=azure.collect({'scopes':['sub-a']},['assessment_metadata','vm'],transport=transport)
    row=collection(result,'assessment_metadata')
    assert row['status']=='partial' and len(row['items'])==1
    assert sum('/assessmentMetadata?' in url for url,_,_ in transport.calls)==2


def test_arm_manager_requires_matching_audience_and_continuation_shape():
    reader=azure._Reader({'concurrency':2,'retries':0})
    url=azure.ARM+SCOPE+'/providers/Microsoft.Security/assessmentMetadata?api-version=2020-01-01'
    calls=[]
    def request(target,**kwargs):
        calls.append(target)
        return {'value':[DEFINITION]}
    manager=reader.assessment_metadata_prefetch=PagePrefetch(reader,request,[url],azure.ARM,
                                                            next_key='nextLink',lookahead=1)
    try:
        manager.start()
        assert manager.take(request,url,azure.GRAPH,'value','nextLink',None) is None
        assert manager.take(request,url,azure.ARM,'value','@odata.nextLink',None) is None
        assert list(reader.pages(request,url))==[[DEFINITION]]
        assert calls==[url]
    finally:manager.close()
    assert not hasattr(reader,'assessment_metadata_prefetch')
    assert manager.request is None and manager.on_page is None


def test_prefetch_window_does_not_limit_later_subscription_coverage(monkeypatch):
    windows=[];original=PagePrefetch.start
    def start(manager):
        if manager.audience==azure.ARM:windows.append((len(manager.streams),manager.lookahead))
        return original(manager)
    monkeypatch.setattr(PagePrefetch,'start',start)
    definition={**DEFINITION,'id':'/providers/Microsoft.Security/assessmentMetadata/check-a'}
    def resolve(url,body,audience):
        return {'value':[definition]} if '/assessmentMetadata?' in url else {'value':[]}
    transport=FakeAzure(resolve)
    result=azure.collect({'scopes':['sub-'+str(i) for i in range(5)],'options':{'concurrency':4}},
                         ['assessment_metadata'],transport=transport)
    rows=[row for row in result['collections'] if row['type']=='assessment_metadata']
    assert windows==[(4,1)]
    assert len(rows)==5 and all(row['status']=='collected' and len(row['items'])==1 for row in rows)
    assert sum('/assessmentMetadata?' in url for url,_,_ in transport.calls)==5
