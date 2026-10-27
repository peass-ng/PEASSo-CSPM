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
def test_actual_reader_keeps_marker_shape_but_exports_failure_envelope(native_fakes,code):
 class FailingReader(Reader):
  def call(self,session,service,region,operation,**kwargs):
   if getattr(self,'fail',True)and 'fixture-1:'in kwargs.get('taskDefinition',''):
    self.module.before_request(self)
    raise ReadFailure('denied',code)
   return super().call(session,service,region,operation,**kwargs)
 r=FailingReader(m,[target(0),target(1)],workers=1)
 out=m.collect_selected(r,object(),R,CALLER,r.options,[S])
 assert len(out.items)==2 and out.status=='partial'
 assert out.items[0][m.MARKER]['leaks'] and out.items[1][m.MARKER]['complete']is False
 assert set(out.items[0][m.MARKER])==set(out.items[1][m.MARKER])
 assert out.error['code']=='selected_configuration_read_incomplete'
 assert ('additional_errors'in out.error)==code.startswith(('Expired','RequestExpired'))
 assert 'arbitrary-private-code'not in json.dumps(out.error)
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

@pytest.mark.parametrize('profile',['aws-selected-configuration-content-v1','aws-lambda-environment-content-v1'])
@pytest.mark.parametrize('code',['ExpiredToken','RequestExpired','call_limit','unknown-private-code'])
def test_exact_requests_catch_retains_only_allowed_configuration_codes(profile,code):
 tree=ast.parse((P.parent/'peaso/collectors/aws.py').read_text())
 assign=next(n for n in ast.walk(tree)if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='safe_configuration_code'for t in n.targets))
 condition=next(n for n in ast.walk(tree)if isinstance(n,ast.If)and isinstance(n.test,ast.BoolOp)and any(isinstance(x,ast.UnaryOp)and isinstance(x.operand,ast.Name)and x.operand.id=='safe_configuration_code'for x in n.test.values))
 from types import SimpleNamespace
 scope={'_metadata_profile':profile,'failure':ReadFailure('denied',code),'self':SimpleNamespace(automatic_workload_environment_active=False)}
 exec(compile(ast.Module(body=[assign],type_ignores=[]),'<exact safe classification>','exec'),scope)
 redacts=eval(compile(ast.Expression(condition.test),'<exact catch condition>','eval'),scope)
 assert (not redacts)==(profile=='aws-selected-configuration-content-v1'and code!='unknown-private-code')
