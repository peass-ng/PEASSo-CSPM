"""Offline canonical BigQuery location query, pagination and native error regression."""
from types import MethodType, SimpleNamespace
import pytest
from peaso.collectors import gcp_network_catalog as catalog
from peaso.collectors.gcp import GCPCollector, ReadError

SCOPE='projects/owned-test'
BASE='https://bigqueryconnection.googleapis.com/v1/'+SCOPE
KIND='bigquery_private_connection'

def collector(resolver,**options):
    value=SimpleNamespace(options=options,page_size=100,max_pages=None,calls=[])
    def read(url,scope,**kwargs):
        assert scope==SCOPE
        value.calls.append((url,dict(kwargs['params'])))
        return resolver(url,kwargs['params']), 'request-'+str(len(value.calls))
    value.read=read
    value.pages=MethodType(GCPCollector.pages,value)
    return value


def test_default_pages_reproduces_rejected_query_for_comparison():
    def resolver(url,params):
        assert url==BASE+'/locations' and params=={'pageSize':100}
        raise ReadError('unavailable','HTTP400')
    c=collector(resolver)
    with pytest.raises(ReadError):list(c.pages(BASE+'/locations',SCOPE,key='locations'))


def test_location_tokens_and_connection_page_size_survive():
    native=SCOPE+'/locations/us-central1/connections/native'
    def resolver(url,params):
        if url==BASE+'/locations':
            assert params==({} if len(c.calls)==1 else {'pageToken':'next-location'})
            return {'locations':[{'locationId':'us-central1'}], 'nextPageToken':'next-location'} if not params else {'locations':[]}
        if url==BASE+'/locations/us-central1/connections':
            assert params['pageSize']==100 and params['fields']==catalog.PRIVATE_SERVICES[KIND]['fields']
            return {'connections':[{'name':native}], 'nextPageToken':'next-connection'} if 'pageToken' not in params else {'connections':[]}
        assert url.endswith('/connections/native') and 'pageSize' not in params
        return {'name':native,'configuration':{'network':{'privateServiceConnect':{'networkAttachment':'synthetic-owned-attachment'}}}}
    c=collector(resolver)
    pages=list(catalog.regional_pages(c,SCOPE,KIND))
    rows=[r for page,_ in pages for r in page]
    assert len(rows)==1 and rows[0]['name']==native
    assert len(c.calls)==5
    assert c.calls[-1][1]['pageToken']=='next-connection'
    assert {receipt for _,receipt in pages}=={'request-'+str(i) for i in range(1,6)}


def test_denied_location_discovery_preserves_exact_native_error():
    error=ReadError('denied','IAM_PERMISSION_DENIED')
    def resolver(url,params):
        assert url==BASE+'/locations' and params=={}
        raise error
    c=collector(resolver)
    with pytest.raises(ReadError) as caught:list(catalog.regional_pages(c,SCOPE,KIND))
    assert caught.value is error and len(c.calls)==1


def test_partial_location_results_are_yielded_before_native_failure():
    error=ReadError('denied','IAM_PERMISSION_DENIED')
    native=SCOPE+'/locations/us-central1/connections/native'
    def resolver(url,params):
        if url==BASE+'/locations':return {'locations':[{'locationId':'us-central1'},{'locationId':'us-east1'}]}
        if '/us-east1/' in url:raise error
        if url.endswith('/connections'):return {'connections':[{'name':native}]}
        return {'name':native}
    c=collector(resolver)
    pages=[]
    with pytest.raises(ReadError) as caught:
        for page in catalog.regional_pages(c,SCOPE,KIND):pages.append(page)
    assert caught.value is error
    assert [r['name'] for page,_ in pages for r in page]==[native]


def test_empty_location_list_stays_unavailable():
    c=collector(lambda url,params:{'locations':[]})
    with pytest.raises(ReadError) as caught:list(catalog.regional_pages(c,SCOPE,KIND))
    assert caught.value.error['code']=='network_service_locations_unavailable'
    assert len(c.calls)==1


@pytest.mark.parametrize('options',[{'regions':['us-central1']},{'bigqueryconnection_network_locations':['us-central1']}])
def test_explicit_locations_keep_connection_list_page_size(options):
    c=collector(lambda url,params:{'connections':[]},**options)
    list(catalog.regional_pages(c,SCOPE,KIND))
    assert len(c.calls)==1 and c.calls[0][0]==BASE+'/locations/us-central1/connections'
    assert c.calls[0][1]['pageSize']==100


def test_unrelated_location_discovery_keeps_its_native_page_size():
    c=collector(lambda url,params:{'locations':[]})
    list(catalog.locations(c,SCOPE,'datastream_private_connection'))
    assert c.calls==[('https://datastream.googleapis.com/v1/'+SCOPE+'/locations',{'pageSize':100})]
