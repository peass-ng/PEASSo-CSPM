import importlib.util,os,time
from pathlib import Path
from types import SimpleNamespace
import pytest
import ast,importlib.util,math,os,threading,time
P=Path(__file__).resolve().parents[1]/'peaso/collection_lease.py'
@pytest.fixture
def lease():
    spec=importlib.util.spec_from_file_location('isolated_collection_lease',P)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
@pytest.mark.parametrize('value',[None,True,'600',float('inf'),float('nan')])
def test_unbounded_or_invalid_authority_rejected(lease,value):
    with pytest.raises(ValueError):lease.configure(value)
    assert lease.effective_deadline(SimpleNamespace(deadline=None))is None

def test_same_job_cannot_renew_monotonic_deadline_after_wall_clock_change(lease,monkeypatch):
    clock=[100.,1000.]
    monkeypatch.setattr(lease.time,'monotonic',lambda:clock[0]);monkeypatch.setattr(lease.time,'time',lambda:clock[1])
    assert lease.configure(1600)==700
    clock[:]=[200.,0.]
    assert lease.configure(1600)==700
    with pytest.raises(RuntimeError):lease.configure(1700)
    assert lease.effective_deadline(SimpleNamespace(deadline=None))==700

def test_minimum_with_existing_explicit_native_deadline(lease):
    inherited=lease.configure(time.time()+60)
    assert lease.effective_deadline(SimpleNamespace(deadline=inherited-1))==inherited-1
    assert lease.effective_deadline(SimpleNamespace(deadline=inherited+100))==inherited

def test_expired_job_is_not_given_new_time(lease):
    deadline=lease.configure(time.time()-10)
    assert deadline<time.monotonic()
    with pytest.raises(TimeoutError):lease.check(SimpleNamespace(deadline=None,check_deadline=lambda:None))

def test_no_hook_has_no_lease_and_does_not_weaken_native_check(lease):
    assert lease.effective_deadline(SimpleNamespace(deadline=None))is None
    def native():raise PermissionError('native cancellation')
    with pytest.raises(PermissionError):lease.check(SimpleNamespace(deadline=None,check_deadline=native))

@pytest.mark.skipif(not hasattr(os,'fork'),reason='fork unavailable')
def test_actual_fork_discards_parent_job_authority(lease):
    deadline=lease.configure(time.time()+60);read,write=os.pipe();pid=os.fork()
    if pid==0:
        try:
            os.close(read);empty=lease.effective_deadline(SimpleNamespace(deadline=None))is None
            child=lease.configure(time.time()+10)
            os.write(write,b'OK'if empty and child<deadline else b'FAIL')
        finally:os._exit(0)
    os.close(write)
    try:assert os.read(read,16)==b'OK'
    finally:os.close(read);os.waitpid(pid,0)
    assert lease.effective_deadline(SimpleNamespace(deadline=None))==deadline
