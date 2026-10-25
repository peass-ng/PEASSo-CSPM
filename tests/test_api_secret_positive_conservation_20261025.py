"""Published secret cards, counts and details share validated detector proof."""
import copy
import importlib.util
import json
import gc
import weakref
from collections import Counter
from pathlib import Path
import pytest
from fastapi.testclient import TestClient
from peaso.server.config import Settings
from peaso.storage import SQLiteStore, FileArtifacts
from peaso.storage.reports import publish_report
from tests.test_peaso_api import TestIdentities
from tests.test_peaso_finding_group_api import fixture_report

root=Path(__import__('peaso').__file__).parent.parent
candidate=Path(__file__).parents[1]/'peaso/server/app.py'
spec=importlib.util.spec_from_file_location('peaso.server._secret_card_candidate',candidate)
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)

@pytest.mark.parametrize('detached',[False,True],ids=['chunk-proof','separate-detail-proof'])
@pytest.mark.parametrize('provider',['aws','gcp','azure','k8s'])
def test_published_positive_filters_counts_cards_details_and_chunk_cache(tmp_path,monkeypatch,detached,provider):
    cases=json.loads((root/'tests/fixtures/ai-secret-positive-redacted.json').read_text())['cases']
    scope={'aws':'123456789012/us-east-1','gcp':'projects/qa-owned','azure':'/subscriptions/00000000-0000-0000-0000-000000000001','k8s':'qa-owned'}[provider]
    findings=[];reviews=[]
    for case in cases:
        finding=copy.deepcopy(case['finding']);finding.update(provider=provider,scope=scope,status='FAIL');finding.pop('scanner_status',None)
        for leak in finding['evidence']['secret_leaks']:
            for loc in leak['locations']:loc['scope']=scope
        finding['evidence']['public_padding']='x' * 1_100_000
        findings.append(finding);reviews.append(case['review'])
    ordinary=copy.deepcopy(findings[0]);ordinary.update(id='ordinary',check_id='fixture.ordinary',resource_id='ordinary',evidence={'setting':False});ordinary.pop('secret_fingerprint');findings.append(ordinary)
    reviews.append({'finding_id':'ordinary','verdict':'PASS','reason':'A recorded effective setting corrects the original failure.'})
    data=fixture_report();data.update(provider=provider,findings=findings,graphs={},resources=[],ai={'status':'completed','reviews':{'hardening':reviews,'exposure':[]}})
    store,artifacts=SQLiteStore(tmp_path/'state'),FileArtifacts(tmp_path/'artifacts')
    connector=store.add_connector('alice',{'provider':provider},'encrypted');job=store.enqueue('alice',{'connector_id':connector['id']})
    if detached:monkeypatch.setattr('peaso.storage.reports.CHUNK_BYTES',600)
    ref=publish_report(artifacts,'alice',job['id'],data);bundle=artifacts.get('alice',ref)
    with store.transaction() as db:db.execute("UPDATE jobs SET status='completed',report=? WHERE id=?",(ref,job['id']))
    public_rows=[item for chunk in bundle['finding_chunks'] for item in artifacts.get('alice',chunk['reference'])['items']]
    assert all(bool(row.get('_detail_reference')) == detached for row in public_rows if row['id'] != 'ordinary')
    original_reviews=copy.deepcopy(artifacts.get('alice',bundle['ai_review']))
    source_details={r['reference'] for r in bundle['finding_chunks']};calls=[];get=artifacts.get
    assert len(source_details)>=2, 'Exercise more than one actual public chunk'
    payload_refs=[];listing=[True]
    class TrackedPayload(dict):
        pass
    def counted(tenant,reference):
        calls.append(reference)
        body=get(tenant,reference)
        if listing[0] and (reference in source_details or '/detail-' in reference):
            # Before a new native payload loads, every prior large payload must
            # have been released. Weak references cannot keep the data alive.
            assert not any(probe() is not None for probe in payload_refs), 'Listing retained a previous large detector payload'
            if '/detail-' in reference:
                body=TrackedPayload(body);payload_refs.append(weakref.ref(body))
            else:
                for i,item in enumerate(body['items']):
                    if isinstance(item.get('evidence'),dict) and item['evidence'].get('secret_leaks'):
                        body['items'][i]=TrackedPayload(item);payload_refs.append(weakref.ref(body['items'][i]))
        return body
    monkeypatch.setattr(artifacts,'get',counted)
    app=module.create_app(Settings(state_dir=tmp_path/'settings',identity_dir=tmp_path/'identity'),store=store,artifacts=artifacts,authenticator=TestIdentities())
    with TestClient(app,base_url='http://127.0.0.1:8000',headers={'Authorization':'Bearer alice'}) as client:
        url=f"/api/scans/{job['id']}";response=client.get(url+'/findings',params={'status':'FAIL','finding_type':'detected_leaks'})
        assert response.status_code==200,response.text
        listing[0]=False;gc.collect();assert not any(probe() is not None for probe in payload_refs), 'Selected cards retained full detector payloads'
        failed=response.json();assert failed['total']==2 and {r['id'] for r in failed['items']}=={r['id'] for r in findings[:2]}
        assert all(r['status']=='FAIL' and r['scanner_status']=='FAIL' and 'evidence' not in r for r in failed['items'])
        assert failed['status_filter_counts']['FAIL']==2 and 'FAIL' in failed['facets']['statuses']
        assert all(n==1 for ref,n in Counter(calls).items() if ref in source_details), 'One read per needed public chunk per request'
        assert not any('/secret-evidence-' in ref for ref in calls), 'Listing must never read or decrypt private values'
        for item in failed['items']:
            detail=client.get(url+'/findings/'+item['id']);assert detail.status_code==200,detail.text
            assert detail.json()['status']=='FAIL' and detail.json()['evidence']['secret_leaks']
        summary=client.get(url+'/summary',params={'aggregation':'check'});assert summary.status_code==200,summary.text
        assert summary.json()['stats']['by_status']['FAIL']==2
        passed=client.get(url+'/findings',params={'status':'PASS'}).json();assert [r['id'] for r in passed['items']]==['ordinary']
        assert client.get(url+'/findings',params={'status':'UNKNOWN','finding_type':'detected_leaks'}).json()['total']==0
        assert artifacts.get('alice',bundle['ai_review'])==original_reviews
        client.headers['Authorization']='Bearer bob';assert client.get(url+'/findings').status_code==404
