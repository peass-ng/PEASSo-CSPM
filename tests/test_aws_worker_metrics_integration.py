"""Actual worker/supervisor telemetry contract; SDK HTTP is offline scripted."""
import io
import json
import logging
import multiprocessing
import time
from unittest.mock import patch
import pytest


def _collector_sdk_child(role,request,connection):
    # Replace only the external inventory producer/HTTP boundary. The actual
    # integrated worker, IPC parser, stage/checkpoint storage and metrics run.
    import peaso.checks
    from peaso import engine,aws_call_metrics
    from peaso.snapshot import make_snapshot
    from peaso.worker import _process
    import boto3
    from botocore.awsrequest import AWSResponse
    from botocore.config import Config
    def collect(request):
        assert aws_call_metrics._ACTIVE is not None
        actual=boto3.Session(aws_access_key_id='PRIVATEACCESS',aws_secret_access_key='PRIVATESECRET',aws_session_token='PRIVATETOKEN').client('sts',region_name='us-east-1',config=Config(retries={'max_attempts':0}))
        body=b'<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><GetCallerIdentityResult><Arn>arn:aws:iam::123456789012:user/private</Arn><UserId>PRIVATE-ACTOR</UserId><Account>123456789012</Account></GetCallerIdentityResult></GetCallerIdentityResponse>'
        class Raw:
            def stream(self,amt=None,decode_content=False):yield body
        actual._endpoint.http_session.send=lambda _:AWSResponse('https://sts.amazonaws.com/',200,{'content-length':str(len(body))},Raw())
        assert actual.get_caller_identity()['Account']=='123456789012'
        # A diagnostic delivery failure must not replace a successful scan.
        handle=aws_call_metrics._ACTIVE;original=handle.sink
        def broken(_):raise RuntimeError('PRIVATE-SENDER-ERROR')
        handle.sink=broken
        assert handle.flush() is False
        handle.sink=original
        assert actual.get_caller_identity()['Account']=='123456789012'
        # Malformed diagnostic input is consumed, never logged or treated as
        # a checkpoint/terminal result and never acknowledged.
        connection.send(('__aws_metrics__',{'private':'PRIVATE-INJECTED'}))
        assert handle.flush('manual')
        return make_snapshot('aws',['222222222222'],[dict(type='vpc',scope='222222222222/us-east-1',service='ec2',status='empty',items=[])])
    engine.collect_snapshot=collect
    request['connector']['input_mode']='offline_snapshot'
    _process(role,request,connection)


def test_real_worker_supervisor_keeps_metrics_nonterminal_nonfatal_and_private(tmp_path):
    from peaso.auth import CredentialCipher
    from peaso.server.config import Settings
    from peaso.storage import SQLiteStore,FileArtifacts
    import peaso.worker as worker
    settings=Settings(state_dir=tmp_path/'state',identity_dir=tmp_path/'identity')
    store=SQLiteStore(settings.state_dir)
    connector=store.add_connector('alice',{'provider':'aws'},CredentialCipher(settings.identity_dir).encrypt({'auth':{},'options':{}}))
    job=store.enqueue('alice',{'connector_id':connector['id'],'ai_enabled':False})
    assert store.admit('alice',job['id'])
    context=multiprocessing.get_context('spawn')
    class Context:
        Pipe=staticmethod(context.Pipe)
        @staticmethod
        def Process(*,target,args,daemon):
            assert target is worker._process
            return context.Process(target=_collector_sdk_child,args=args,daemon=daemon)
    output=io.StringIO();order=[]
    class Handler(logging.StreamHandler):
        failed=False
        def emit(self,record):
            if str(record.msg).startswith('aws_sdk_metrics'):
                if not self.failed:
                    self.failed=True;order.append('logger-failed')
                    raise RuntimeError('PRIVATE-LOGGER-ERROR')
                if 'reason=final' in record.getMessage():order.append('final-metrics')
            super().emit(record)
    handler=Handler(output);original_logger=(worker.LOGGER.level,worker.LOGGER.propagate)
    worker.LOGGER.setLevel(logging.INFO);worker.LOGGER.propagate=False;worker.LOGGER.addHandler(handler)
    finish=store.finish
    def finished(*a,**kw):order.append('terminal-store-finish');return finish(*a,**kw)
    try:
        with patch.object(worker.multiprocessing,'get_context',return_value=Context()),patch.object(store,'finish',side_effect=finished):
            assert worker.Worker('collector',settings,store=store,artifacts=FileArtifacts(tmp_path/'artifacts')).run_once('alice',job['id'])
    finally:
        worker.LOGGER.removeHandler(handler);worker.LOGGER.setLevel(original_logger[0]);worker.LOGGER.propagate=original_logger[1]
    saved=store.job('alice',job['id'])
    assert saved['status']=='collected',saved
    assert saved['snapshot']
    assert handler.failed and 'logger-failed' in order
    assert 'final-metrics' in order
    assert order.index('final-metrics')<order.index('terminal-store-finish')
    text=output.getvalue()
    assert 'service=sts operation=GetCallerIdentity calls=2 completed=2' in text
    for private in ('PRIVATE','123456789012','arn:aws:','https://sts'):assert private not in text


@pytest.mark.parametrize('role,provider,expected',[('collector','aws',True),('collector','gcp',False),('analyzer','aws',False)])
def test_actual_process_installs_only_aws_collector_before_artifacts_and_flushes_before_error(role,provider,expected,tmp_path,monkeypatch):
    import peaso.worker as worker
    from peaso import aws_call_metrics
    order=[];frames=[]
    class Handle:
        closed=False
        def close(self):
            if not self.closed:order.append('final-metrics');self.closed=True
    def install(sink):
        assert callable(sink);order.append('install');return Handle()
    def artifact(_):order.append('artifact');raise ValueError('PRIVATE-ARTIFACT-ERROR')
    class Connection:
        def send(self,value):frames.append(value);order.append('terminal' if value[0] is False else 'frame')
        def close(self):order.append('closed')
        def recv(self):raise AssertionError('unexpected metric acknowledgement')
    monkeypatch.setattr(aws_call_metrics,'install',install)
    monkeypatch.setattr(worker,'FileArtifacts',artifact)
    monkeypatch.setattr(worker.os,'dup2',lambda *a:None)
    monkeypatch.setattr(worker.signal,'signal',lambda *a:None)
    worker._process(role,{'connector':{'provider':provider},'artifact_config':{'mode':'file','root':str(tmp_path)}},Connection())
    assert ('install' in order) is expected
    terminal=[frame for frame in frames if type(frame[0]) is bool]
    assert len(terminal)==1 and terminal[0][0] is False and terminal[0][1]=='invalid_input'
    from peaso import runtime_metrics
    assert all(frame[0]=='__runtime_metrics__' and runtime_metrics.validate(frame[1]) for frame in frames if type(frame[0]) is not bool)
    assert 'PRIVATE' not in json.dumps(frames)
    if expected:assert order.index('install')<order.index('artifact')<order.index('final-metrics')<order.index('terminal')
    else:assert 'final-metrics' not in order
    assert order[-1]=='closed'
