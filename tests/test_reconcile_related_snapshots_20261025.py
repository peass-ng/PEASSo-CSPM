"""The real operator reconciler requires the exact original joined native sources."""
import importlib.util
import json
from copy import deepcopy
from pathlib import Path
import pytest
from peaso.snapshot import make_snapshot
from tests.test_peaso_ai_reconcile import setup_scan

CANDIDATE = Path(__file__).parents[1] / 'peaso/ai/reconcile.py'
spec = importlib.util.spec_from_file_location('peaso.ai._related_reconcile_candidate', CANDIDATE)
module = importlib.util.module_from_spec(spec);spec.loader.exec_module(module)


def prepared(tmp_path, monkeypatch):
    store, art, ident, old, snap, decision = setup_scan(tmp_path, monkeypatch)
    related = [make_snapshot('k8s', ['cluster-' + str(i)], [], created_at='2026-10-25T00:00:00Z') for i in range(2)]
    prior = art.get('alice', old)
    prior['related_snapshots'] = [dict((k, row[k]) for k in ('snapshot_id', 'provider', 'scopes', 'created_at')) | {'scan_id':str(i)*32,'connector_id':'fixture-'+str(i)} for i,row in enumerate(related)]
    old = art.put('alice', ident, 'report', prior)
    with store.transaction() as db:db.execute('UPDATE jobs SET report=? WHERE id=?', (old,ident))
    calls = []
    def evaluate(snapshot, **kw):
        calls.append(kw)
        result = deepcopy(prior);result.pop('ai')
        result['related_snapshots'] = [{k: row[k] for k in ('snapshot_id', 'provider', 'scopes', 'created_at')} for row in kw['related_snapshots']]
        result['graphs'] = {'privesc':{'nodes':[{'id':r['snapshot_id']} for r in kw['related_snapshots']], 'edges':[]}}
        return result
    monkeypatch.setattr('peaso.engine.evaluate_snapshot', evaluate)
    return store,art,ident,old,snap,decision,related,prior,calls


def test_exact_two_joined_sources_retained_and_original_history_preserved(tmp_path, monkeypatch):
    s,a,ident,old,snap,decision,related,prior,calls = prepared(tmp_path,monkeypatch)
    result = module.reconcile_scan(s,a,'alice',ident,old,source_version='test',related_snapshots=related,adjudications=[decision],dry_run=False)
    assert result['report_replaced'] and len(calls)==1
    new = a.get('alice',s.job('alice',ident)['report'])
    report = a.get('alice',new['report_json'])
    assert report['related_snapshots']==prior['related_snapshots']
    assert {r['id'] for r in report['graphs']['privesc']['nodes']}=={r['snapshot_id'] for r in related}
    assert a.get('alice',old)==prior and s.job('alice',ident)['snapshot']==snap
    assert a.get('alice',new['ai_review'])['adjudications'][0]['original_review']['verdict']=='PASS'


@pytest.mark.parametrize('variant',['missing','one_missing','duplicate','foreign','unsealed','tampered','provider_mismatch','scope_mismatch','time_mismatch','extra'])
def test_source_mismatch_rejected_before_evaluation_or_publication(tmp_path,monkeypatch,variant):
    s,a,ident,old,snap,decision,related,prior,calls = prepared(tmp_path,monkeypatch)
    supplied=deepcopy(related)
    if variant=='missing':supplied=None
    elif variant=='one_missing':supplied=supplied[:1]
    elif variant=='duplicate':supplied=[supplied[0],supplied[0]]
    elif variant=='foreign':supplied[0]=make_snapshot('k8s',['foreign'],[],created_at='2026-10-25T00:00:00Z')
    elif variant=='unsealed':supplied[0].pop('snapshot_id')
    elif variant=='tampered':supplied[0]['scopes']=['tampered']
    elif variant=='extra':supplied.append(make_snapshot('azure',['/subscriptions/foreign'],[],created_at='2026-10-25T00:00:00Z'))
    else:
        field={'provider_mismatch':'provider','scope_mismatch':'scopes','time_mismatch':'created_at'}[variant]
        prior['related_snapshots'][0][field]={'provider':'gcp','scopes':['not-the-original'],'created_at':'2020-01-01T00:00:00Z'}[field]
        old=a.put('alice',ident,'report',prior)
        with s.transaction() as db:db.execute('UPDATE jobs SET report=? WHERE id=?',(old,ident))
    files=sorted(a.root.rglob('*.json'))
    with pytest.raises(ValueError):module.reconcile_scan(s,a,'alice',ident,old,source_version='test',related_snapshots=supplied,dry_run=False)
    assert calls==[] and sorted(a.root.rglob('*.json'))==files and s.job('alice',ident)['report']==old
