import os

from peaso import worker as worker_module
from peaso.worker import Worker


class _Process:
    def __init__(self, alive=True):
        self.alive = alive
        self.terminated = False
        self.joined = False

    def is_alive(self):
        return self.alive and not self.terminated

    def terminate(self):
        self.terminated = True

    def kill(self):
        self.terminated = True

    def join(self, timeout=None):
        self.joined = True


class _Pipe:
    def __init__(self, messages=()):
        self.sent = []
        self.closed = False
        self.messages = list(messages)

    def send(self, message):
        if self.closed:
            raise OSError("closed")
        self.sent.append(message)

    def recv(self):
        if not self.messages:
            raise EOFError
        return self.messages.pop(0)

    def close(self):
        self.closed = True


def _worker(role="analyzer"):
    worker = Worker.__new__(Worker)
    worker.role = role
    worker._prewarmed = None
    return worker


def test_warm_child_receives_the_exact_job_once():
    worker = _worker()
    process, parent = _Process(), _Pipe()
    worker._prewarmed = (process, parent)
    request = {"scan_id": "s1", "snapshot_ref": "ref"}
    assert worker._take_prewarmed(request) == (process, parent)
    assert parent.sent == [("__job__", "analyzer", request)]
    assert worker._prewarmed is None
    assert worker._take_prewarmed(request) is None


def test_dead_warm_child_is_discarded_for_a_fresh_spawn():
    worker = _worker()
    process, parent = _Process(alive=False), _Pipe()
    worker._prewarmed = (process, parent)
    assert worker._take_prewarmed({"scan_id": "s1"}) is None
    assert parent.sent == [] and parent.closed and process.joined
    assert worker._prewarmed is None


def test_unused_warm_child_is_stopped():
    worker = _worker()
    process, parent = _Process(), _Pipe()
    worker._prewarmed = (process, parent)
    worker.discard_prewarmed()
    assert process.terminated and parent.closed and worker._prewarmed is None
    worker.discard_prewarmed()


def test_only_the_analyzer_prewarms(monkeypatch):
    started = []
    monkeypatch.setattr(worker_module.multiprocessing, "get_context",
                        lambda kind: started.append(kind))
    worker = _worker("collector")
    worker.prewarm()
    assert started == [] and worker._prewarmed is None


def test_prewarmed_child_runs_the_normal_job_path(monkeypatch):
    monkeypatch.setattr(os, "dup2", lambda *args: None)
    seen = []
    monkeypatch.setattr(worker_module, "_process",
                        lambda role, request, connection: seen.append((role, request, connection)))
    request = {"scan_id": "s1"}
    connection = _Pipe([("__job__", "analyzer", request)])
    worker_module._prewarmed_process(connection)
    assert seen == [("analyzer", request, connection)]


def test_prewarmed_child_without_a_job_exits_quietly(monkeypatch):
    monkeypatch.setattr(os, "dup2", lambda *args: None)
    seen = []
    monkeypatch.setattr(worker_module, "_process", lambda *args: seen.append(args))
    worker_module._prewarmed_process(_Pipe())
    worker_module._prewarmed_process(_Pipe([("other", 1)]))
    assert seen == []
