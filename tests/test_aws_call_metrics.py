"""Actual SDK clients/events with offline HTTP responses, no AWS calls."""
from copy import deepcopy
from concurrent.futures import ThreadPoolExecutor
import importlib.util
import json
import logging
from pathlib import Path
from types import SimpleNamespace
import threading
import time

import boto3
import botocore.session
from botocore.awsrequest import AWSResponse
from botocore.config import Config
from botocore.exceptions import ClientError, EndpointConnectionError
import pytest
from peaso import aws_call_metrics as metrics

SUCCESS=b'<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><GetCallerIdentityResult><Arn>arn:aws:iam::123456789012:user/private</Arn><UserId>PRIVATE-ACTOR</UserId><Account>123456789012</Account></GetCallerIdentityResult></GetCallerIdentityResponse>'
ERROR=b'<ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><Error><Type>Sender</Type><Code>Throttling</Code><Message>PRIVATE-RESPONSE-MESSAGE</Message></Error></ErrorResponse>'

class Raw:
 def __init__(self,body):self.body=body
 def stream(self,amt=None,decode_content=False):yield self.body

def response(status,body):return AWSResponse('https://sts.amazonaws.com/',status,{'content-length':str(len(body))},Raw(body))
def client(session=None):
 session=session or boto3.Session(aws_access_key_id='PRIVATEACCESS',aws_secret_access_key='PRIVATESECRET',aws_session_token='PRIVATETOKEN')
 return session.client('sts',region_name='us-east-1',config=Config(retries={'max_attempts':0},connect_timeout=1,read_timeout=1))

@pytest.fixture
def installed():
 events=[];handle=metrics.install(events.append)
 assert handle is not None
 yield handle,events
 handle.close()


def rows(events):return [row for kind,event in events for row in event['rows']]


def test_real_sdk_success_across_independent_and_preexisting_sessions(monkeypatch):
 old_session=boto3.Session(aws_access_key_id='PRIVATEACCESS',aws_secret_access_key='PRIVATESECRET')
 events=[];original=botocore.session.Session.create_client
 handle=metrics.install(events.append)
 try:
  assert metrics.install(lambda _:pytest.fail('second sink used')) is handle
  for session in (old_session,boto3.Session(aws_access_key_id='PRIVATEACCESS',aws_secret_access_key='PRIVATESECRET')):
   actual=client(session);handle.attach(actual) # Explicit duplicate registration is harmless.
   monkeypatch.setattr(actual._endpoint.http_session,'send',lambda request:response(200,SUCCESS))
   output=actual.get_caller_identity()
   assert output['Account']=='123456789012'
  handle.flush()
  assert len(rows(events))==1
  row=rows(events)[0]
  assert row['service']=='sts' and row['operation']=='GetCallerIdentity'
  assert row['calls']==row['completed']==2 and row['errors']==row['sdk_retries']==0
  assert row['response_declared_bytes']==2*len(SUCCESS)
  assert row['responses_with_length']==2 and row['inflight']==0
  serialized=json.dumps(events)
  for private in ('PRIVATE','123456789012','https://','arn:aws:'):
   assert private not in serialized
 finally:handle.close()
 assert botocore.session.Session.create_client is original
 assert events[-1][1]['reason']=='final'


def test_real_sdk_throttle_then_retry_success_and_final_error(installed,monkeypatch):
 handle,events=installed;actual=client();attempts=[]
 def send(_):
  attempts.append(True);return response(429,ERROR) if len(attempts)==1 else response(200,SUCCESS)
 monkeypatch.setattr(actual._endpoint.http_session,'send',send)
 # This test-only retry choice keeps the actual SDK endpoint loop but removes sleep.
 actual.meta.events.register_first('needs-retry.sts.GetCallerIdentity',lambda attempts,**kw:0 if attempts==1 else None,unique_id='test-retry-once')
 actual.get_caller_identity();handle.flush()
 row=rows(events)[-1]
 assert row['calls']==row['completed']==1
 assert row['sdk_retries']==row['throttle_attempts']==row['attempt_errors']==1 and row['errors']==0
 assert row['responses_with_length']==2 and row['response_declared_bytes']==len(ERROR)+len(SUCCESS)
 actual.meta.events.unregister('needs-retry.sts.GetCallerIdentity',unique_id='test-retry-once')
 monkeypatch.setattr(actual._endpoint.http_session,'send',lambda _:response(429,ERROR))
 with pytest.raises(ClientError):actual.get_caller_identity()
 handle.flush();row=rows(events)[-1]
 assert row['calls']==row['completed']==2 and row['errors']==1
 assert row['throttle_attempts']==row['attempt_errors']==2 and row['sdk_retries']==1
 assert 'PRIVATE' not in json.dumps(events)


def test_real_sdk_transport_exception_is_counted_without_message(installed,monkeypatch):
 handle,events=installed;actual=client()
 def fail(_):raise EndpointConnectionError(endpoint_url='https://PRIVATE-CREDENTIAL.example')
 monkeypatch.setattr(actual._endpoint.http_session,'send',fail)
 with pytest.raises(EndpointConnectionError):actual.get_caller_identity()
 handle.flush();row=rows(events)[0]
 assert row['calls']==row['completed']==row['errors']==row['attempt_errors']==1,row
 assert row['inflight']==row['sdk_retries']==row['throttle_attempts']==0
 assert 'PRIVATE' not in json.dumps(events)


def test_thread_safe_aggregation_and_bounded_memory():
 events=[];handle=metrics.Metrics(events.append);model=SimpleNamespace(name='ListThings',service_model=SimpleNamespace(service_name='ec2'))
 def call(_):
  context={};assert handle._before(model=model,context=context) is None
  assert handle._after(context=context,http_response=SimpleNamespace(status_code=200,headers={}),parsed={}) is None
 with ThreadPoolExecutor(max_workers=8) as pool:list(pool.map(call,range(2000)))
 handle.flush();row=rows(events)[0]
 assert row['calls']==row['completed']==2000 and row['inflight']==0
 for n in range(metrics.MAX_KEYS+20):
  context={};handle._before(model=SimpleNamespace(name='Operation'+str(n),service_model=SimpleNamespace(service_name='ec2')),context=context);handle._after(context=context)
 assert len(handle.rows)==metrics.MAX_KEYS
 assert ('other','Other') in handle.rows
 events.clear();handle.flush('final')
 assert len(events)<=metrics.MAX_KEYS//metrics.MAX_ROWS+1
 assert all(len(frame[1]['rows'])<=metrics.MAX_ROWS for frame in events)
 assert sum(row['calls'] for row in rows(events))==2000+metrics.MAX_KEYS+20


def test_periodic_sender_and_final_flush_use_real_background_loop(monkeypatch):
 events=[];handle=metrics.Metrics(events.append)
 class Stop:
  count=0
  def wait(self,interval):
   assert interval>=30;self.count+=1;return self.count>1
 handle.stop=Stop();context={};handle._before(model=SimpleNamespace(name='ListThings',service_model=SimpleNamespace(service_name='s3')),context=context)
 handle._periodic()
 assert events[0][0]=='__aws_metrics__' and events[0][1]['reason']=='periodic'
 assert rows(events)[0]['inflight']==1
 handle._after(context=context)
 handle.flush('final')
 assert events[-1][1]['reason']=='final' and rows(events)[-1]['completed']==1


def sample():
 row={'service':'sts','operation':'GetCallerIdentity',**dict.fromkeys(metrics._NUMBERS,0)}
 return dict(schema=1,sequence=1,reason='manual',uptime_ms=0,rows=[row])

@pytest.mark.parametrize('mutation',[
 lambda e:e.update(parameters='PRIVATE'),
 lambda e:e['rows'][0].update(url='https://PRIVATE'),
 lambda e:e['rows'][0].update(service='arn:aws:PRIVATE'),
 lambda e:e['rows'][0].update(operation='Get PRIVATE'),
 lambda e:e['rows'][0].update(calls=True),
 lambda e:e['rows'][0].update(errors=1),
 lambda e:e['rows'][0].update(wall_ms=-1),
 lambda e:e.update(rows=[e['rows'][0]]*(metrics.MAX_ROWS+1)),
])
def test_supervisor_rejects_injected_or_unbounded_frames(mutation):
 event=sample();mutation(event)
 class Poison:
  def info(self,*a):raise AssertionError('invalid event logged')
 assert metrics.safe_metrics(event) is None
 assert metrics.record_metrics(event,Poison()) is False


def test_logger_or_sender_failures_do_not_change_calls(installed,monkeypatch):
 handle,_=installed;actual=client()
 def fail(_):raise RuntimeError('PRIVATE-LOGGER-FAILURE')
 handle.sink=fail
 monkeypatch.setattr(actual._endpoint.http_session,'send',lambda _:response(200,SUCCESS))
 assert actual.get_caller_identity()['Account']=='123456789012'
 assert handle.flush() is False
 class Logger:
  def info(self,*a):raise RuntimeError('PRIVATE-LOGGER-FAILURE')
 assert metrics.record_metrics(sample(),Logger()) is False


def test_event_handlers_never_choose_retries_and_preserve_call_context():
 handle=metrics.Metrics(lambda _:None);context={'existing':'value'};model=SimpleNamespace(name='ListThings',service_model=SimpleNamespace(service_name='s3'))
 assert handle._before(model=model,context=context,params={'PRIVATE':'PRIVATE'}) is None
 assert handle._retry(request_dict={'context':context,'PRIVATE':'PRIVATE'},attempts=1,response=(SimpleNamespace(status_code=200,headers={}),{'PRIVATE':'PRIVATE'})) is None
 assert handle._after(context=context,parsed={'PRIVATE':'PRIVATE'}) is None
 assert context=={'existing':'value'}


def test_failed_background_start_restores_factory_and_does_not_raise(monkeypatch):
 original=botocore.session.Session.create_client
 def fail(_):raise RuntimeError('thread unavailable')
 monkeypatch.setattr(threading.Thread,'start',fail)
 assert metrics.install(lambda _:None) is None
 assert botocore.session.Session.create_client is original
 assert metrics._ACTIVE is None


def test_closing_twice_is_harmless(installed):
 handle,events=installed
 handle.close();count=len(events);handle.close()
 assert len(events)==count


def _spawn_sdk_metrics(connection):
 handle=metrics.install(connection.send)
 try:
  actual=client();actual._endpoint.http_session.send=lambda _:response(200,SUCCESS)
  assert actual.get_caller_identity()['Account']=='123456789012'
  handle.flush('periodic')
 finally:
  handle.close()
 connection.send(('result',True));connection.close()


def test_spawned_collector_to_supervisor_logs_only_valid_aggregates(caplog):
 import multiprocessing
 context=multiprocessing.get_context('spawn');parent,child=context.Pipe(duplex=False)
 process=context.Process(target=_spawn_sdk_metrics,args=(child,));process.start();child.close()
 received=[]
 with caplog.at_level(logging.INFO,logger='owned-sdk-test'):
  while True:
   assert parent.poll(10),'child did not publish metrics/result'
   frame=parent.recv()
   if frame[0]=='result':assert frame==('result',True);break
   assert frame[0]=='__aws_metrics__' and metrics.record_metrics(frame[1],logging.getLogger('owned-sdk-test'))
   received.append(frame)
 process.join(timeout=10);assert process.exitcode==0
 assert [event['reason'] for _,event in received]==['periodic','final']
 assert 'service=sts operation=GetCallerIdentity calls=1 completed=1' in caplog.text
 for private in ('PRIVATE','123456789012','https://','arn:aws:'):assert private not in caplog.text



def test_background_join_failure_cannot_replace_success_or_leave_factory_installed(monkeypatch):
 original=botocore.session.Session.create_client
 handle=metrics.install(lambda _:None)
 assert handle is not None
 def fail(*a,**kw):raise RuntimeError('PRIVATE-CLEANUP-FAILURE')
 monkeypatch.setattr(handle.thread,'join',fail)
 handle.close()
 assert handle.closed and metrics._ACTIVE is None
 assert botocore.session.Session.create_client is original
