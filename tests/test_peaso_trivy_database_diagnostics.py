"""Real DB lifecycle boundaries; diagnostics cannot alter admission or leak data."""
from contextlib import contextmanager, ExitStack
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import pytest

ROOT=Path(__file__).resolve().parents[1]

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,ROOT/path)
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

@pytest.fixture
def db():return load('diagnostic_db','peaso/trivy_database_20261021.py')

@pytest.mark.parametrize('message,reason',[
 ('DB schema is not version 2','schema_unsupported'),
 ('DB is older than 24 hours or future dated','database_stale_or_future'),
 ('DB NextUpdate has passed','database_expired'),
 ('DB bbolt meta page is invalid','database_header_invalid'),
 ('insufficient free disk for bounded DB refresh','refresh_disk_headroom'),
 ('DB cache is busy','lease_busy'),
 ('https://private.invalid/?token=SECRET','database_unavailable'),
])
def test_fixed_classifications_no_raw_values(db,message,reason):
    data={}
    with pytest.raises(db.DatabaseUnavailable):
        with db.diagnostic_phase('database_validation',data):
            raise db.DatabaseUnavailable(message)
    row=data['phases']['database_validation']
    assert row==dict(calls=1,wall_ms=row['wall_ms'],status='unavailable',reason=reason)
    assert 'SECRET' not in json.dumps(data) and 'https://' not in json.dumps(data)

@pytest.mark.parametrize('error,reason,code',[
 (subprocess.CalledProcessError(23,['SECRET'],stderr=b'SECRET'),'download_process_failed',23),
 (subprocess.CalledProcessError(999999,['SECRET']),'download_process_failed',None),
 (subprocess.TimeoutExpired(['SECRET'],660,stderr=b'SECRET'),'download_timeout',None),
 (PermissionError('SECRET'),'filesystem_permission_denied',None),
 (RuntimeError('SECRET'),'validation_failed',None),
 (ValueError('fresh_offline_database_required'),'offline_database_not_fresh',None),
])
def test_process_failure_privacy_and_bounded_exit(db,error,reason,code):
    data={}
    with pytest.raises(type(error)):
        with db.diagnostic_phase('download',data):raise error
    row=data['phases']['download']
    assert row['reason']==reason and row.get('exit_code')==code
    assert 'SECRET' not in json.dumps(data)


def test_refresh_disk_failure_records_real_phase_and_never_downloads(db,tmp_path,monkeypatch):
    class Usage:free=0
    monkeypatch.setattr(db.shutil,'disk_usage',lambda _:Usage())
    monkeypatch.setattr(db.subprocess,'Popen',lambda *a,**kw:pytest.fail('no headroom'))
    data={}
    with pytest.raises(db.DatabaseUnavailable):
        with db.database_lease(enabled=True,cache_root=tmp_path/'cache',diagnostics=data):
            pytest.fail('unavailable DB accepted')
    assert data['phases']['cache_validation']['reason']=='cache_pointer_missing'
    assert data['phases']['refresh']['reason']=='refresh_disk_headroom'
    assert data['phases']['lease_acquisition']['reason']=='refresh_disk_headroom'


def test_actual_failed_child_duration_exit_and_cleanup(db,tmp_path,monkeypatch):
    class Usage:free=db.FREE_RESERVE_BYTES+1
    monkeypatch.setattr(db.shutil,'disk_usage',lambda _:Usage())
    data={}
    token=db._DIAGNOSTICS.set(data)
    try:
        with pytest.raises(subprocess.CalledProcessError):
            db._download([sys.executable,'-c','import time; time.sleep(.025); raise SystemExit(7)'],tmp_path,{})
    finally:db._DIAGNOSTICS.reset(token)
    row=data['phases']['download']
    assert row['exit_code']==7 and row['wall_ms']>=25
    assert row['calls']==1 # real decorated subprocess, including wait and reap


def test_lease_duration_excludes_consumers_and_context_restored(db,tmp_path,monkeypatch):
    generation=tmp_path/'generation';generation.mkdir()
    monkeypatch.setattr(db,'current_cache',lambda _:generation)
    data={}
    with db.database_lease(enabled=True,cache_root=tmp_path/'cache',diagnostics=data):
        original=dict(data['phases']['lease_acquisition'])
        db.time.sleep(.025)
        assert data['phases']['lease_acquisition']==original
    assert db._DIAGNOSTICS.get() is None
    # Historical callers do not need a diagnostics argument.
    with db.database_lease(enabled=True,cache_root=tmp_path/'cache') as cache:
        assert cache==generation


def test_disabled_no_io(db,tmp_path,monkeypatch):
    monkeypatch.setattr(db.os,'open',lambda *a,**kw:pytest.fail('disabled I/O'))
    with db.database_lease(enabled=False,cache_root=tmp_path/'absent',diagnostics={}) as cache:
        assert cache is None
    assert not (tmp_path/'absent').exists()


def test_malformed_diagnostic_state_does_not_change_error(db):
    data={'phases':{'download':{'calls':'malformed'}}}
    with pytest.raises(PermissionError,match='original'):
        with db.diagnostic_phase('download',data):raise PermissionError('original')


def test_control_flow_not_swallowed(db):
    with pytest.raises(KeyboardInterrupt):
        with db.diagnostic_phase('download',{}):raise KeyboardInterrupt()


def test_real_runtime_transport_has_only_fixed_rows_and_counts(db,monkeypatch):
    metrics=load('diagnostic_runtime','peaso/runtime_metrics.py')
    monkeypatch.setitem(sys.modules,'peaso.runtime_metrics',metrics)
    frames=[]
    metrics.configure(frames.append,role='collector',interval_seconds=60)
    try:
        data={}
        with db.diagnostic_phase('download',data):pass
        with db.diagnostic_phase('lease_acquisition',data):pass
        metrics.flush()
    finally:metrics.close()
    assert frames and all(frame[0]=='__runtime_metrics__' for frame in frames)
    assert all(metrics.validate(frame[1]) for frame in frames)
    rows=frames[-1][1]['rows']
    assert {row['stage'] for row in rows}=={'image.database.acquire','image.database.download'}
    assert all(row['count']==1 for row in rows)
    assert 'paths' not in json.dumps(frames)


def test_runtime_handler_failure_nonfatal(db,monkeypatch):
    metrics=load('failed_diagnostic_runtime','peaso/runtime_metrics.py')
    @contextmanager
    def fail(stage):raise RuntimeError('SECRET');yield
    monkeypatch.setattr(metrics,'span',fail)
    monkeypatch.setitem(sys.modules,'peaso.runtime_metrics',metrics)
    with db.diagnostic_phase('download',{}) as ignored:pass
    with pytest.raises(ValueError,match='original'):
        with db.diagnostic_phase('download',{}):raise ValueError('original')


def test_acquire_optional_diagnostics_and_legacy_call_compatibility(db,monkeypatch):
    monkeypatch.setitem(sys.modules,'peaso.trivy_database_20261021',db)
    acquire=load('diagnostic_acquire','peaso/collectors/selected_image_trivy_database_20261021.py')
    seen=[]
    @contextmanager
    def lease(**kwargs):seen.append(kwargs);yield Path('/safe')
    monkeypatch.setattr(acquire,'database_lease',lease)
    with ExitStack() as stack:
        assert acquire.acquire(stack,enabled=True,cancel=lambda:None)==Path('/safe')
    assert seen[-1]=={'enabled':True}
    diagnostics={}
    with ExitStack() as stack:
        assert acquire.acquire(stack,enabled=True,cancel=lambda:None,diagnostics=diagnostics)==Path('/safe')
    assert seen[-1]=={'enabled':True,'diagnostics':diagnostics}

@pytest.mark.parametrize('change,reason',[
 ({'Version':3},'schema_unsupported'),
 ({'UpdatedAt':'2026-10-23T00:00:00Z'},'database_stale_or_future'),
 ({'UpdatedAt':'2026-10-26T00:00:00Z'},'database_stale_or_future'),
 ({'NextUpdate':'2026-10-25T00:00:00Z'},'database_expired'),
 ({'UpdatedAt':'invalid'},'timestamp_invalid'),
])
def test_actual_database_validation_preserves_rejections(db,tmp_path,change,reason):
    import datetime as dt
    import struct
    folder=tmp_path/'db';folder.mkdir()
    page=bytearray(8192)
    struct.pack_into('<QHHI',page,0,0,4,0,0)
    struct.pack_into('<IIII',page,16,0xed0cdaed,2,4096,0)
    checksum=14695981039346656037
    for octet in page[16:72]:checksum=((checksum ^ octet)*1099511628211)&((1<<64)-1)
    struct.pack_into('<Q',page,72,checksum)
    (folder/'trivy.db').write_bytes(page)
    metadata={'Version':2,'UpdatedAt':'2026-10-25T00:00:00Z','NextUpdate':'2026-10-26T00:00:00Z'}
    metadata.update(change)
    (folder/'metadata.json').write_text(json.dumps(metadata))
    data={};token=db._DIAGNOSTICS.set(data)
    try:
        with pytest.raises(db.DatabaseUnavailable):
            db.validate_db(tmp_path,dt.datetime(2026,10,25,12,tzinfo=dt.timezone.utc))
    finally:db._DIAGNOSTICS.reset(token)
    assert data['phases']['database_validation']['reason']==reason
    assert data['phases']['database_validation']['status']=='unavailable'


def test_actual_lease_busy_remains_bounded_and_reports_phase(db,tmp_path,monkeypatch):
    tick=iter([0,0,31,32])
    monkeypatch.setattr(db.time,'monotonic',lambda:next(tick))
    def busy(*args):raise BlockingIOError()
    monkeypatch.setattr(db.fcntl,'flock',busy)
    data={}
    with pytest.raises(db.DatabaseUnavailable,match='DB cache is busy'):
        with db.database_lease(enabled=True,cache_root=tmp_path/'cache',diagnostics=data):
            pytest.fail('busy lease acquired')
    assert data['phases']['lease_acquisition']['reason']=='lease_busy'
