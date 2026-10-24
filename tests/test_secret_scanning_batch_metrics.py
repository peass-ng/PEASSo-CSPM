"""Bounded diagnostics use the real spawned worker pipe, never child stdout."""
import io
import json
import logging
import multiprocessing
import time
from unittest.mock import patch

import pytest
from peaso import secret_scanning_batch as batch


def _collector_child(role, request, connection):
    # This isolated native producer replaces network collection, not the worker.
    import peaso.checks
    import peaso.engine
    from peaso.snapshot import make_snapshot
    from peaso.worker import _process
    def collect(request):
        items = [(b'PRIVATE_VALUE_SENTINEL', '/PRIVATE_PATH_SENTINEL')]
        with batch.prepared_content_batch(items):
            assert batch.prepared_output(*items[0]) is None
            time.sleep(.01)
        connection.send(('__content_metrics__', {'private': 'PRIVATE_VALUE_SENTINEL'}))
        return make_snapshot('aws', ['222222222222'], [dict(type='vpc',
            scope='222222222222/us-east-1', service='ec2', status='empty', items=[])])
    peaso.engine.collect_snapshot = collect
    request["connector"]["input_mode"] = "offline_snapshot"
    _process(role, request, connection)


def test_real_spawned_worker_supervisor_logs_only_valid_metrics(tmp_path):
    from peaso.auth import CredentialCipher
    from peaso.server.config import Settings
    from peaso.storage import SQLiteStore, FileArtifacts
    import peaso.worker as worker
    settings = Settings(state_dir=tmp_path/'state', identity_dir=tmp_path/'identity')
    store=SQLiteStore(settings.state_dir)
    connector=store.add_connector('alice', {'provider':'aws'},
        CredentialCipher(settings.identity_dir).encrypt({'auth':{},'options':{},'input_mode':'offline_snapshot'}))
    job=store.enqueue('alice', {'connector_id':connector['id'], 'ai_enabled':False})
    assert store.admit('alice',job['id'])
    ctx=multiprocessing.get_context('spawn')
    class Context:
        Pipe=staticmethod(ctx.Pipe)
        @staticmethod
        def Process(*,target,args,daemon):
            assert target is worker._process
            return ctx.Process(target=_collector_child,args=args,daemon=daemon)
    output=io.StringIO();handler=logging.StreamHandler(output)
    original=(worker.LOGGER.level,worker.LOGGER.propagate)
    worker.LOGGER.setLevel(logging.INFO);worker.LOGGER.propagate=False
    worker.LOGGER.addHandler(handler)
    try:
        with patch.object(worker.multiprocessing,'get_context',return_value=Context()):
            assert worker.Worker('collector',settings,store=store,artifacts=FileArtifacts(tmp_path/'artifacts')).run_once('alice',job['id'])
    finally:
        worker.LOGGER.removeHandler(handler);worker.LOGGER.setLevel(original[0]);worker.LOGGER.propagate=original[1]
    text=output.getvalue()
    assert 'Content scanner batch metrics:' in text
    event=json.loads(next(line.split(': ',1)[1] for line in text.splitlines() if line.startswith('Content scanner batch metrics:')))
    assert event['items']==1 and event['reason']=='single_source'
    assert event['lookups']==1 and event['serial_lookups']==1
    assert event['consumer_ms']>=5
    assert 'PRIVATE' not in text
    assert store.job('alice',job['id'])['status']=='collected'


def test_timeout_fallback_preserves_exact_sources_and_cleans_context(monkeypatch):
    events=[];items=[(b'FIRST_PRIVATE','/first'),(b'SECOND_PRIVATE','/second')]
    def timeout(*_):raise TimeoutError('PRIVATE exception')
    monkeypatch.setattr(batch,'_prepare_trufflehog_batch',timeout)
    batch.configure_metrics(events.append)
    try:
        with batch.prepared_content_batch(items):
            assert [batch.prepared_output(*item) for item in items]==[None,None]
        assert batch._BATCH_METRICS.get() is None
    finally:batch.configure_metrics(None)
    assert len(events)==1 and events[0][0]=='__content_metrics__'
    event=events[0][1]
    assert event['reason']=='preparation_timeout' and event['serial_lookups']==2
    assert event['unique_bytes']==len(b'FIRST_PRIVATESECOND_PRIVATE')
    assert 'PRIVATE' not in json.dumps(event)


def test_prepared_reads_and_consumer_exception_preserve_cleanup(monkeypatch):
    events=[];items=[(b'A','/a'),(b'A','/b')];prepared=dict.fromkeys(items,b'')
    monkeypatch.setattr(batch,'_prepare_trufflehog_batch',lambda *_:prepared)
    batch.configure_metrics(events.append)
    try:
        with pytest.raises(RuntimeError,match='consumer'):
            with batch.prepared_content_batch(items):
                assert [batch.prepared_output(*item) for item in items]==[b'',b'']
                raise RuntimeError('consumer')
    finally:batch.configure_metrics(None)
    event=events[0][1]
    assert event['prepared_reads']==2 and event['consumer_failed']==1
    assert event['unique_payloads']==1 and event['unique_bytes']==1 and event['input_bytes']==2
    assert prepared=={} and batch._PREPARED_BATCH.get() is None


@pytest.mark.parametrize('change',[{'path':'PRIVATE'}, {'reason':'PRIVATE'}, {'input_bytes':'PRIVATE'},
    {'consumer_ms':True}, {'items':129}, {'lookups':2**64}, {'reason':[]}, {'schema':True}])
def test_supervisor_rejects_unknown_or_unbounded_payload(change):
    event=dict(schema=1,batch=1,items=1,input_bytes=1,unique_payloads=1,unique_bytes=1,
        prepared=0,reason='single_source',preparation_ms=0,consumer_ms=0,lookups=0,
        prepared_reads=0,serial_lookups=0,consumer_failed=0)
    event.update(change)
    class Logger:
        def info(self,*_):raise AssertionError('invalid payload reached logger')
    assert batch.record_metrics(event,Logger()) is False


def test_broken_diagnostic_pipe_does_not_change_result():
    def broken(_):raise OSError('PRIVATE')
    batch.configure_metrics(broken)
    try:
        with batch.prepared_content_batch([(b'A','/a')]):
            assert batch.prepared_output(b'A','/a') is None
    finally:batch.configure_metrics(None)


def test_valid_metrics_handler_failure_does_not_escape():
    events=[]
    batch.configure_metrics(events.append)
    try:
        with batch.prepared_content_batch([(b'A', '/a')]):
            pass
    finally:
        batch.configure_metrics(None)
    class BrokenLogger:
        def info(self,*_):
            raise RuntimeError('PRIVATE handler failure')
    assert batch.safe_metrics(events[0][1]) is not None
    assert batch.record_metrics(events[0][1], BrokenLogger()) is False


def test_metrics_handler_control_flow_is_not_swallowed():
    events=[]
    batch.configure_metrics(events.append)
    try:
        with batch.prepared_content_batch([(b'A', '/a')]):
            pass
    finally:
        batch.configure_metrics(None)
    class InterruptedLogger:
        def info(self,*_):
            raise KeyboardInterrupt
    with pytest.raises(KeyboardInterrupt):
        batch.record_metrics(events[0][1], InterruptedLogger())
