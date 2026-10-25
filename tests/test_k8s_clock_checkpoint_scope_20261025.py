"""Actual checkpoint builder + native privacy boundary retain global clock evidence."""
import ast,copy
from pathlib import Path
from types import SimpleNamespace
import pytest
from peaso.snapshot import make_snapshot
from peaso.snapshot_public_identity import public_snapshot_adapter

def method():
 candidate=Path(__file__).parent/'sources/peaso/incremental.py'
 if not candidate.exists():
  import peaso.incremental as module
  candidate=Path(module.__file__)
 tree=ast.parse(candidate.read_text());klass=next(n for n in tree.body if isinstance(n,ast.ClassDef) and n.name=='CheckpointSession');node=next(n for n in klass.body if isinstance(n,ast.FunctionDef) and n.name=='_snapshot');env={'copy':copy,'make_snapshot':make_snapshot};exec(compile(ast.Module(body=[node],type_ignores=[]),str(candidate),'exec'),env);return env['_snapshot']

def session(provider='k8s'):
 return SimpleNamespace(provider=provider,requested_scopes=['qa-owned','kube-system'],collection_finished=False,final_metadata=None,sequence=2,scope_plan=None,image_targets=[])
def row(kind='node_clock',scope='*',status='not_collected'):
 return {'type':kind,'scope':scope,'status':status,'items':[]}

@pytest.mark.parametrize('clock_status',['not_collected','empty','collected','partial'])
def test_real_checkpoint_builder_keeps_global_clock_without_wildcard_target(clock_status):
 rows=[row('pod','qa-owned','empty'),row(status=clock_status)];before=copy.deepcopy(rows);snapshot=method()(session(),rows);public=public_snapshot_adapter(copy.deepcopy,provider='k8s',trusted_scopes=['qa-owned','kube-system'])(snapshot)
 assert snapshot['scopes']==['qa-owned'] and public['collections']==before and rows==before
 assert next(r for r in public['collections'] if r['type']=='node_clock')['scope']=='*'

def test_clock_only_batch_uses_exact_requested_boundary_and_retains_clock():
 snapshot=method()(session(),[row()]);public=public_snapshot_adapter(copy.deepcopy,provider='k8s',trusted_scopes=['qa-owned','kube-system'])(snapshot)
 assert public['scopes']==['qa-owned','kube-system'] and public['collections']==[row()]

@pytest.mark.parametrize('foreign',[row('pod','*','empty'),row('pod','foreign','empty'),row('node_clock','foreign','empty')])
def test_foreign_or_nonclock_wildcard_still_rejected(foreign):
 snapshot=method()(session(),[row(),foreign])
 with pytest.raises(ValueError):public_snapshot_adapter(copy.deepcopy,provider='k8s',trusted_scopes=['qa-owned','kube-system'])(snapshot)

def test_non_kubernetes_global_scope_derivation_unchanged():
 assert method()(session('aws'),[row()])['scopes']==['*']


def test_real_session_settlement_batch_and_cumulative_publication(monkeypatch,tmp_path):
 """Real scheduler/publisher with a small evaluator stub; no check verdict claim."""
 import sys,types
 from peaso import engine
 from peaso.incremental import CheckpointSession
 from peaso.storage.artifacts import FileArtifacts
 fake=SimpleNamespace(id='synthetic.scope-boundary',category='hardening',kind='pod',dependencies=('pod',))
 monkeypatch.setattr(engine,'_selection',lambda *args,**kwargs:(['hardening'],[fake]))
 monkeypatch.setattr(engine,'_analysis_selection',lambda *args:[])
 monkeypatch.setattr(engine,'_privesc_selected',lambda *args:None)
 monkeypatch.setattr(engine,'_selected_graph_categories',lambda *args:[])
 monkeypatch.setattr(engine,'plan_collection',lambda *args:['pod','node_clock'])
 monkeypatch.setattr(engine,'evaluate_snapshot',lambda *args,**kwargs:{'findings':[],'coverage':[],'stats':{'finding_count':0}})
 analysis=types.ModuleType('peaso.analysis');analysis.REQUIRED_TYPES={};analysis.privesc_required_types=lambda p:[];monkeypatch.setitem(sys.modules,'peaso.analysis',analysis)
 monkeypatch.setattr(CheckpointSession,'_snapshot',method())
 artifacts=FileArtifacts(tmp_path/'artifacts');published=[]
 def commit(snapshot,report,sequence):
  reference=artifacts.put('local','a'*32,'snapshot',snapshot);published.append((reference,report is not None))
 public=public_snapshot_adapter(copy.deepcopy,provider='k8s',trusted_scopes=['qa-owned'])
 request={'connector':{'provider':'k8s','scopes':['qa-owned'],'options':{}},'categories':['hardening'],'checks':['synthetic.scope-boundary']}
 session=CheckpointSession(request,commit,public,interval=999999,min_report_interval=999999)
 try:
  session.stop=True;session.wake.set();session.thread.join(timeout=2)
  session.on_collection(row());session.on_collection(row('pod','qa-owned','empty'));session.publish()
  assert published and published[-1][1]
  saved=artifacts.get('local',published[-1][0]);assert saved['scopes']==['qa-owned'] and len(saved['collections'])==2
  assert next(r for r in saved['collections'] if r['type']=='node_clock')==row()
 finally:session.close()
