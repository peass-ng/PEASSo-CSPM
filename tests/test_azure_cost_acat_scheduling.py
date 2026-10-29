"""Independent inventories overlap without weakening continuation or parent rules."""
import threading
import pytest
from peaso.collectors import azure
from tests.test_peaso_collectors_azurek8s import FakeAzure, collection


@pytest.mark.parametrize('options,overlap', [
    ({'concurrency': 2}, True), ({'concurrency': 1}, False),
    ({'max_pages': 1}, False), ({'max_resources': 10}, False),
    ({'max_calls': 100}, False), ({'max_scopes': 1}, False),
])
def test_cost_and_report_lists_share_batch_only_without_caps(monkeypatch, options, overlap):
    batches=[]
    original=azure._Reader.run
    def run(reader,jobs):
        jobs=list(jobs);batches.append([job[0] for job in jobs]);return original(reader,jobs)
    monkeypatch.setattr(azure._Reader,'run',run)
    transport=FakeAzure(lambda url,body,audience:{'value':[]})
    result=azure.collect({'scopes':['sub-a'],'options':options},['cost_export','acat_report'],transport=transport)
    assert any('cost_export' in b and 'acat_report' in b for b in batches) is overlap
    assert collection(result,'cost_export')['status']=='empty'
    assert collection(result,'acat_report')['status']=='empty'
    assert sum('/Microsoft.CostManagement/exports?' in u for u,_,_ in transport.calls)==1
    assert sum('/Microsoft.AppComplianceAutomation/reports?' in u for u,_,_ in transport.calls)==1


def test_independent_calls_really_overlap_and_webhooks_wait_for_report():
    barrier=threading.Barrier(2,timeout=3)
    report_finished=threading.Event()
    def resolve(url,body,audience):
        if '/Microsoft.CostManagement/exports?' in url:
            barrier.wait();return {'value':[]}
        if '/Microsoft.AppComplianceAutomation/reports?' in url:
            barrier.wait();report_finished.set()
            return {'value':[{'name':'test','properties':{'subscriptions':[]}}]}
        if '/reports/test/webhooks?' in url:
            assert report_finished.is_set();return {'value':[]}
        return {'value':[]}
    result=azure.collect({'scopes':['sub-a'],'options':{'concurrency':2}},['cost_export','acat_report','acat_webhook'],transport=FakeAzure(resolve))
    assert collection(result,'cost_export')['status']=='empty'
    assert collection(result,'acat_report')['status']=='collected'
    assert collection(result,'acat_webhook')['status']=='empty'


@pytest.mark.parametrize('failed_kind',['cost_export','acat_report'])
def test_late_page_denial_keeps_prefix_and_other_inventory(failed_kind):
    def resolve(url,body,audience):
        kind='cost_export' if '/Microsoft.CostManagement/exports?' in url else 'acat_report' if '/Microsoft.AppComplianceAutomation/reports?' in url else None
        if kind:
            if '&page=2' in url:raise azure.AzureReadError('continuation_denied',403)
            row=({'id':'/subscriptions/sub-a/providers/Microsoft.CostManagement/exports/test','properties':{}} if kind=='cost_export' else {'name':'test','properties':{'subscriptions':[]}})
            return {'value':[row],**({'nextLink':url+'&page=2'} if kind==failed_kind else {})}
        return {'value':[]}
    transport=FakeAzure(resolve)
    result=azure.collect({'scopes':['sub-a'],'options':{'concurrency':2}},['cost_export','acat_report'],transport=transport)
    for kind in ['cost_export','acat_report']:
        row=collection(result,kind)
        assert row['status']==('partial' if kind==failed_kind else 'collected')
        assert len(row['items'])==1
    assert sum('&page=2' in u for u,_,_ in transport.calls)==1


@pytest.mark.parametrize('wanted',[['cost_export'],['acat_report']])
def test_single_inventory_selection_still_runs(wanted):
    transport=FakeAzure(lambda url,body,audience:{'value':[]})
    result=azure.collect({'scopes':['sub-a'],'options':{'concurrency':2}},wanted,transport=transport)
    assert collection(result,wanted[0])['status']=='empty'
