"""Keyed memo of payload bytes the pinned TruffleHog reported clean.

TruffleHog stdin and staged-file results depend only on the bytes, never on
the source path, so identical clean bytes need not be scanned twice. Only a
per-process HMAC of the bytes is kept: no content, path or value.
"""
import hashlib
import hmac
import os
import secrets
import threading
from collections import OrderedDict

MAX_CLEAN = 16384
_KEY = secrets.token_bytes(32)
_LOCK = threading.Lock()
_CLEAN = OrderedDict()


def _after_fork():
    global _KEY, _LOCK, _CLEAN
    _KEY, _LOCK, _CLEAN = secrets.token_bytes(32), threading.Lock(), OrderedDict()


if hasattr(os, 'register_at_fork'):
    os.register_at_fork(after_in_child=_after_fork)


def _payload_key(payload):
    return hmac.new(_KEY, payload, hashlib.sha256).digest()


def known_clean(payload):
    """True when these exact bytes already produced a clean TruffleHog result."""
    key = _payload_key(payload)
    with _LOCK:
        if key in _CLEAN:
            _CLEAN.move_to_end(key)
            return True
    return False


def remember_clean(payload):
    key = _payload_key(payload)
    with _LOCK:
        _CLEAN[key] = None
        _CLEAN.move_to_end(key)
        while len(_CLEAN) > MAX_CLEAN:
            _CLEAN.popitem(last=False)
