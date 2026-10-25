"""Cross-resource empty-inventory evidence must survive AI input preparation."""
from copy import deepcopy
import pytest
from peaso.ai import collection_coverage as coverage
from peaso.ai import pipeline


def fixture():
    finding={'id':'quota-failure','check_id':'k8s.namespace.quota_limits_cpu',
             'provider':'k8s','scope':'apps','resource_id':'namespace-id',
             'category':'hardening','status':'FAIL','evidence':{'broad_quotas':[]}}
    report={'provider':'k8s','snapshot_id':'captured','created_at':'now','coverage':[
        {'level':'collection','type':'resourcequota','scope':'apps','status':'empty','resource_count':0},
        {'level':'collection','type':'resourcequota','scope':'other','status':'collected','resource_count':1,'data':'must-not-share'},
        {'level':'check','type':'namespace','scope':'apps','status':'evaluated','reason':'not-a-receipt'}]}
    return report,finding


def test_empty_inventory_reaches_actual_document_without_foreign_scope():
    report,finding=fixture();before=deepcopy(report)
    context=pipeline.review_context(report,{},[finding])
    document=pipeline.findings_document(context['scan'],[finding],context['resources'])
    assert document['scan']['collection_coverage']=={'entries':[
        {'scope':'apps','type':'resourcequota','status':'empty','resource_count':0}], 'truncated':False}
    assert document['items'][0]['evidence']=={'broad_quotas':[]}
    assert document['items'][0]['supporting_resources']==[]
    assert report==before and 'other' not in str(document)


@pytest.mark.parametrize('status',['partial','denied','unknown','malformed','timeout','not_collected'])
def test_unavailable_inventory_stays_unavailable(status):
    report,finding=fixture();report['coverage'][0]['status']=status
    context=pipeline.review_context(report,{},[finding])
    assert context['scan']['collection_coverage']['entries'][0]['status']==status


def test_changed_collection_receipt_invalidates_review_reuse():
    report,finding=fixture()
    def fingerprint():return pipeline.review_fingerprints(report,{},[finding],identity={},entries=[])
    original=fingerprint();report['coverage'][0]['status']='denied'
    assert fingerprint()!=original
    report['coverage'][0]['status']='empty';report['coverage'][0]['resource_count']=2
    assert fingerprint()!=original


def test_bounded_metadata_never_includes_errors_or_native_values():
    row={'level':'collection','scope':'apps','type':'resourcequota','status':'denied',
         'resource_count':False,'error':'secret provider output','data':{'private':'value'}}
    assert coverage.for_findings(coverage.index([row]),[{'scope':'apps'}])=={
        'entries':[{'scope':'apps','type':'resourcequota','status':'denied'}],'truncated':False}


def test_large_inventory_is_explicitly_truncated():
    rows=[{'level':'collection','scope':'apps','type':str(n),'status':'empty','resource_count':0}
          for n in range(coverage.MAX_ENTRIES+1)]
    value=coverage.for_findings(coverage.index(rows),[{'scope':'apps'}])
    assert len(value['entries'])==coverage.MAX_ENTRIES and value['truncated'] is True
    doc=pipeline.findings_document({'collection_coverage':value},[{'scope':'apps'}])
    assert doc['scan']['collection_coverage']['truncated'] is True


@pytest.mark.parametrize('row',[None,{}, {'level':'collection','scope':'apps','type':'quota','status':{}},
    {'level':'collection','scope':'apps\nsecret','type':'quota','status':'empty'}])
def test_malformed_receipts_do_not_become_empty(row):
    assert coverage.index([row])=={}


def test_explicit_global_receipt_and_per_finding_scope_filter():
    rows=[{'level':'collection','scope':s,'type':'quota','status':'empty','resource_count':0}
          for s in ('*','apps','foreign')]
    scan={'collection_coverage':{'entries':[{k:v for k,v in r.items() if k!='level'} for r in rows],
                                 'truncated':False}}
    doc=pipeline.findings_document(scan,[{'scope':'apps'}])
    assert {r['scope'] for r in doc['scan']['collection_coverage']['entries']}=={'*','apps'}
