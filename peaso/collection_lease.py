"""Authoritative worker collection lease; no user input or renewable timeout."""
import math
import os
import threading
import time

_lock=threading.Lock()
_epoch=None
_monotonic_deadline=None
_pid=None


def _after_fork():
    global _lock,_epoch,_monotonic_deadline,_pid
    _lock=threading.Lock()
    _epoch=_monotonic_deadline=_pid=None


if hasattr(os,'register_at_fork'):
    os.register_at_fork(after_in_child=_after_fork)


def configure(epoch_deadline):
    """Convert an existing trusted job deadline once; never renew it."""
    global _epoch,_monotonic_deadline,_pid
    if type(epoch_deadline)not in (int,float)or not math.isfinite(epoch_deadline):
        raise ValueError('invalid collection lease')
    with _lock:
        if _epoch is not None:
            if _pid!=os.getpid()or epoch_deadline!=_epoch:
                raise RuntimeError('collection lease already configured')
            return _monotonic_deadline
        _epoch=epoch_deadline
        _monotonic_deadline=time.monotonic()+(epoch_deadline-time.time())
        _pid=os.getpid()
        return _monotonic_deadline


def effective_deadline(requests):
    explicit=getattr(requests,'deadline',None)
    if explicit is not None and(type(explicit)not in (int,float)or not math.isfinite(explicit)):
        raise ValueError('invalid native collection lease')
    with _lock:
        inherited=_monotonic_deadline if _pid==os.getpid()else None
    if explicit is None:return inherited
    if inherited is None:return explicit
    return min(explicit,inherited)


def check(requests):
    requests.check_deadline()
    deadline=effective_deadline(requests)
    if deadline is not None and time.monotonic()>=deadline:
        raise TimeoutError('collection lease expired')
