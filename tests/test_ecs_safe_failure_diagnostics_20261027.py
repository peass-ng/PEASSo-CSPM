"""Canonical finite diagnostics; portable two-phase fixtures use admitted source."""
import ast,copy,importlib.util,json,sys,threading,time
from pathlib import Path
import pytest
P=Path(__file__).parent
from tests.test_ecs_two_phase_20261027 import Reader,target,native_fakes,A,R,S,CALLER
from peaso.collectors.aws import ReadFailure
from peaso.collectors import aws_selected_configuration_secret_indicators as m,workload_environment_discovery as fold

@pytest.mark.parametrize('code,category',[
 ('ExpiredToken','credential_expiry'),('ExpiredTokenException','credential_expiry'),('RequestExpired','credential_expiry'),
 ('AccessDenied','access_denied'),('selected_configuration_call_bound','call_bound'),('call_limit','call_bound'),
 ('intentional_scan_deadline','local_deadline'),('retry_wait_exceeds_deadline','local_deadline'),
 ('private-value-should-never-appear','unknown_read_failure')])
def test_fixed_failure_taxonomy_never_copies_messages_or_arbitrary_codes(code,category):
 r=Reader(m,[target(0)],workers=1)
 m._record_read_failure(r,ReadFailure('denied',code))
 metadata=r.configuration_content_metadata
 assert metadata[m.KIND+'_read_failures']=={category+':ReadFailure':1}
 assert 'private-value' not in json.dumps(metadata)
 assert (metadata.get(m.KIND+'_credential_expiry_codes',[])==[code])==(category=='credential_expiry')

@pytest.mark.parametrize('boundary',['local_deadline','call_bound'])
def test_state_proven_limits_distinguished_without_exception_text(boundary):
 r=Reader(m,[target(0)],workers=1)
 if boundary=='local_deadline':r.configuration_content_state['deadline']=time.monotonic()-1
 else:r.configuration_content_state['attempts']=m.MAX_CALLS
 m._record_read_failure(r,ValueError('DO NOT LOG THIS'))
 assert r.configuration_content_metadata[m.KIND+'_read_failures']=={boundary+':ValueError':1}

@pytest.mark.parametrize('code',['ExpiredToken','ExpiredTokenException','RequestExpired','AccessDenied','arbitrary-private-code'])
def test_one_failed_source_names_its_own_gap_without_demoting_the_others(native_fakes,code):
 class FailingReader(Reader):
  def call(self,session,service,region,operation,**kwargs):
   if getattr(self,'fail',True)and 'fixture-1:'in kwargs.get('taskDefinition',''):
    self.module.before_request(self)
    raise ReadFailure('denied',code)
   return super().call(session,service,region,operation,**kwargs)
 r=FailingReader(m,[target(0),target(1)],workers=1)
 out=m.collect_selected(r,object(),R,CALLER,r.options,[S])
 expired=code.startswith(('Expired','RequestExpired'))
 assert len(out.items)==2 and out.items[0][m.MARKER]['leaks']
 failed=out.items[1][m.MARKER]
 assert failed['complete']is False and failed['status']=='unavailable'
 assert failed['operation']=='ecs:DescribeTaskDefinition'
 assert failed['reason']==('credential_expired' if expired else 'access_denied' if code=='AccessDenied'
                           else 'selected_configuration_read_unavailable')
 assert failed.get('provider_code')==(code if expired or code=='AccessDenied' else None)
 # Only credential expiry ends the whole capture; any other gap stays on its own source.
 assert out.status==('partial' if expired else 'collected')
 if expired:assert out.error=={'code':'selected_configuration_read_incomplete','additional_errors':[{'code':code}]}
 else:assert out.error is None
 assert 'arbitrary-private-code'not in json.dumps([out.error,out.items])
 r.fail=False
 recovered=m.collect_selected(r,object(),R,CALLER,r.options,[S])
 assert recovered.status=='collected'and recovered.error is None  # no cross-invocation failure promotion


def test_fold_preserves_only_finite_expiry_for_worker_status():
 rows=[{'type':m.KIND,'scope':S,'items':[{'id':'one'}],'status':'collected','automatic_batch':'a'},
       {'type':m.KIND,'scope':S,'items':[{'id':'two'}],'status':'partial','automatic_batch':'b',
        'error':{'code':'selected_configuration_read_incomplete','additional_errors':[{'code':'ExpiredToken'},{'code':'private-value','message':'private-value'}]}}]
 batches=[{'id':'a','scope':S},{'id':'b','scope':S}]
 fold.fold_collections(rows,m.KIND,batches)
 assert len(rows)==1 and len(rows[0]['items'])==2 and rows[0]['status']=='partial'
 assert rows[0]['error']=={'code':'automatic_content_incomplete','additional_errors':[{'code':'ExpiredToken'}]}
 # Exact worker predicate only, no registry/callable stubbing or guard changes.
 import peaso
 worker=Path(peaso.__file__).parent/'worker.py';tree=ast.parse(worker.read_text());node=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='_expired_snapshot')
 scope={'_EXPIRED_CODES':frozenset({'ExpiredToken','ExpiredTokenException','RequestExpired'})}
 exec(compile(ast.Module(body=[node],type_ignores=[]),str(worker),'exec'),scope)
 assert scope['_expired_snapshot']({'provider':'aws','collections':rows})is True

def test_region_without_selected_sources_is_empty_not_an_inventory_gap(native_fakes):
 r=Reader(m,[target(0)],workers=1)
 west=A+'/us-west-2'
 out=m.collect_selected(r,object(),'us-west-2',CALLER,r.options,[S,west])
 assert out.items==[] and out.status=='empty'
 assert out.error=={'code':'selected_configuration_none_in_scope'}

@pytest.mark.parametrize('workers,count',[(1,1),(8,3)])
def test_spent_read_budget_does_not_starve_detection_of_already_read_sources(native_fakes,monkeypatch,workers,count):
 # Detectors queue behind other content scans; that wait comes out of the
 # scan lease, not the native-read budget the reads already used up.
 from peaso import secret_scanning as scanner
 from tests.test_ecs_two_phase_20261027 import TOKEN
 def slow_kingfisher(payload,path,timeout):
  if timeout<.5:raise TimeoutError('scanner deadline')
  time.sleep(.3)
  return [(TOKEN,'synthetic',1)]if TOKEN.encode()in payload else[]
 monkeypatch.setattr(scanner,'_scan_kingfisher',slow_kingfisher)
 if workers==1:  # no prepared batch: the subprocess engine also sees the detector timeout
  monkeypatch.setattr(scanner,'_scan_trufflehog',lambda payload,path,timeout:slow_kingfisher(b'',path,timeout))
 r=Reader(m,[target(i)for i in range(count)],workers=workers)
 r.configuration_content_state['deadline']=time.monotonic()+.4
 out=m.collect_selected(r,object(),R,CALLER,r.options,[S])
 assert len(out.items)==count
 for item in out.items:
  marker=item[m.MARKER]
  assert marker['complete']is True,json.dumps(marker)
  assert {e['status']for e in marker['engines']}=={'complete'}
 assert out.items[0][m.MARKER]['leaks']
