"""Storage precise reuse/differential categories, scope eligibility and full identity joins."""
import copy

import pytest

from peaso.checks import CHECKS, azure_ports_storage_extra as ports
from peaso.checks.fixtures import CASES

REGISTRY={c.id:c for c in CHECKS}


@pytest.mark.parametrize('query', ports.SOURCE_QUERIES)
def test_storage_exact_new_and_reused_pass_fail_unknown_denied_partial_and_purity(query):
    cid=ports.SOURCE_QUERIES[query];fixture=CASES[cid]
    for label,expected in (('pass','PASS'),('fail','FAIL')):
        item,index=copy.deepcopy(fixture[label]),copy.deepcopy(fixture.get(label+'_index',{}));before=copy.deepcopy((item,index))
        assert REGISTRY[cid].evaluate(item,index)[0]==expected
        assert (item,index)==before
    for item in ({},None,[],{'collection_status':'denied'},{'collection_status':'partial'}):
        assert REGISTRY[cid].evaluate(item,{})[0]=='UNKNOWN'


@pytest.mark.parametrize('service,query', [('blob','storage_account_blob_service_logging_enabled'),('table','storage_account_table_service_logging_enabled'),('queue','storage_account_queue_services_logging_enabled')])
def test_literal_source_category_union_premium_scope_and_alllogs_distinction(service,query):
    duckdb=pytest.importorskip('duckdb');check=REGISTRY[ports.SOURCE_QUERIES[query]]
    item=copy.deepcopy(CASES[check.id]['pass'])
    logs=item['serviceDiagnosticSettings'][service][0]['properties']['logs']
    with duckdb.connect(':memory:') as db:
        db.execute('CREATE TABLE logs(category VARCHAR,enabled BOOLEAN)')
        db.executemany('INSERT INTO logs VALUES (?,?)',[(x['category'],x['enabled']) for x in logs])
        flags=db.execute("SELECT max(CASE WHEN category='StorageRead' THEN enabled::INTEGER ELSE 0 END)=1,max(CASE WHEN category='StorageWrite' THEN enabled::INTEGER ELSE 0 END)=1,max(CASE WHEN category='StorageDelete' THEN enabled::INTEGER ELSE 0 END)=1 FROM logs").fetchone()
    assert all(flags)
    item['serviceDiagnosticSettings'][service]=[{'properties':{'logs':[{'categoryGroup':'allLogs','enabled':True}]}}]
    assert check.evaluate(item,{})[0]=='FAIL'
    item['sku']['tier']='Premium'
    assert check.evaluate(item,{})[0]=='NOT_APPLICABLE'
    if service=='blob':
        item['kind']='BlockBlobStorage'
        assert check.evaluate(item,{})[0]=='FAIL'
    item=copy.deepcopy(CASES[check.id]['pass']);item['serviceDiagnosticSettings']['_coverage']={service:{'status':'denied'}}
    assert check.evaluate(item,{})[0]=='UNKNOWN'


def test_all_connections_approved_is_not_atleast_one_approved():
    check=REGISTRY[ports.SOURCE_QUERIES['storage_account_uses_private_link']]
    item=copy.deepcopy(CASES[check.id]['pass'])
    item['properties']['privateEndpointConnections'].append({'properties':{'privateLinkServiceConnectionState':{'status':'Pending'}}})
    assert check.evaluate(item,{})[0]=='FAIL'


def test_file_share_scope_and_one_to365_day_boundaries_require_readable_share_list():
    check=REGISTRY[ports.SOURCE_QUERIES['storage_account_file_share_soft_delete_enabled']]
    item,index=copy.deepcopy(CASES[check.id]['pass']),copy.deepcopy(CASES[check.id]['pass_index'])
    service=index['storage_service'][0]['data']
    for days,expected in ((0,'FAIL'),(1,'PASS'),(365,'PASS'),(366,'FAIL'),(True,'UNKNOWN')):
        service['properties']['shareDeleteRetentionPolicy']['days']=days
        assert check.evaluate(item,index)[0]==expected
    service['shares']=[]
    assert check.evaluate(item,index)[0]=='NOT_APPLICABLE'
    service['_coverage']={'shares':{'status':'denied'}}
    assert check.evaluate(item,index)[0]=='UNKNOWN'
    index['collections']['storage_service'][0]['status']='partial'
    assert check.evaluate(item,index)[0]=='UNKNOWN'


def test_container_parent_conjunction_scope_join_duplicate_and_denial():
    check=REGISTRY[ports.SOURCE_QUERIES['storage_account_blob_containers_public_access_disabled']]
    item,index=copy.deepcopy(CASES[check.id]['pass']),copy.deepcopy(CASES[check.id]['pass_index'])
    account=index['storage_account'][0]['data']
    for allow,level,expected in ((False,'None','PASS'),(True,'None','FAIL'),(False,'Blob','FAIL'),(False,'Container','FAIL')):
        account['properties']['allowBlobPublicAccess']=allow;item['properties']['publicAccess']=level
        assert check.evaluate(item,index)[0]==expected
    account['id']=account['id'].replace('/group/','/other/')
    assert check.evaluate(item,index)[0]=='UNKNOWN'
    account['id']=account['id'].replace('/other/','/group/')
    index['storage_account'].append(copy.deepcopy(index['storage_account'][0]))
    assert check.evaluate(item,index)[0]=='UNKNOWN'
    index['collections']['storage_account'][0]['status']='denied'
    assert check.evaluate(item,index)[0]=='UNKNOWN'
