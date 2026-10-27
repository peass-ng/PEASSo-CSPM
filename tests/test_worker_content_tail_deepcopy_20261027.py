"""The worker's internal content callback survives real engine connector copying."""

import copy
import threading

import pytest

from peaso.engine import collect_snapshot
from peaso.snapshot import make_snapshot
from peaso.worker import _checkpoint_content_tail_callback


def test_content_enabled_worker_callback_survives_real_collect_snapshot():
    scope = '123456789012/us-east-1'

    class Checkpoint:
        def __init__(self):
            self.lock = threading.RLock()
            self.transitions = []

        def on_content_tail(self, active):
            self.transitions.append(active)

    checkpoint = Checkpoint()
    callback = _checkpoint_content_tail_callback(checkpoint)
    assert copy.deepcopy(callback) is callback
    snapshot = make_snapshot('aws', [scope], [])
    request = {'connector': {'provider': 'aws', 'scopes': [scope], 'options': {
        'content_secret_scans': True, 'snapshot': snapshot,
        '_content_tail_callback': callback}}, 'categories': ['hardening']}
    bound = copy.copy(request)
    bound['connector'] = copy.copy(request['connector'])
    bound['connector']['options'] = dict(request['connector']['options'],
        _content_tail_callback=checkpoint.on_content_tail)
    with pytest.raises(TypeError):
        collect_snapshot(bound)
    assert collect_snapshot(request) == snapshot
    callback(True)
    callback(False)
    assert checkpoint.transitions == [True, False]
    assert request['connector']['options']['_content_tail_callback'] is callback
