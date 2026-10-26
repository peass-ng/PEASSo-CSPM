"""Natural child exits and cgroup-wide counters are separate internal facts."""
import io
import json
import logging
from pathlib import Path
from types import SimpleNamespace

import pytest

from peaso import worker
from peaso.auth import CredentialCipher
from peaso.server.config import Settings
from peaso.storage import FileArtifacts, SQLiteStore


@pytest.fixture
def memory_files(monkeypatch):
    files = {
        '/proc/self/cgroup': '0::/slice/job\n',
        '/proc/self/mountinfo': '31 20 0:28 /slice /sys/fs/cgroup rw - cgroup2 cgroup rw\n',
        '/sys/fs/cgroup/job/memory.events.local': 'low 0\nhigh 1\nmax 2\noom 3\noom_kill 4\noom_group_kill 0\n',
        '/sys/fs/cgroup/job/memory.current': '100\n',
        '/sys/fs/cgroup/job/memory.peak': '200\n',
        '/sys/fs/cgroup/job/memory.max': '1000\n',
    }
    original = Path.open

    def opened(path, *args, **kwargs):
        name = str(path)
        if name.startswith(('/proc/self/', '/sys/fs/cgroup/')):
            value = files.get(name, FileNotFoundError())
            if isinstance(value, Exception):
                raise value
            return io.StringIO(value)
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, 'open', opened)
    return files


def test_memory_resolution_uses_mount_root_and_only_numeric_allowlisted_fields(memory_files):
    memory_files['/sys/fs/cgroup/job/memory.events.local'] += 'future_counter 999\n'
    result = worker._worker_cgroup_memory()
    assert result['_group'] == '/sys/fs/cgroup/job'
    assert result['events'] == {'low': 0, 'high': 1, 'max': 2, 'oom': 3, 'oom_kill': 4, 'oom_group_kill': 0}
    assert (result['current'], result['peak'], result['max']) == (100, 200, 1000)


def test_namespaced_root_and_hierarchical_fallback_remain_explicit(memory_files):
    memory_files['/proc/self/cgroup'] = '0::/\n'
    memory_files['/proc/self/mountinfo'] = '31 20 0:28 /slice/job /sys/fs/cgroup/job rw - cgroup2 cgroup rw\n'
    memory_files['/sys/fs/cgroup/job/memory.events'] = memory_files.pop('/sys/fs/cgroup/job/memory.events.local')
    memory_files['/sys/fs/cgroup/job/memory.max'] = 'max\n'
    result = worker._worker_cgroup_memory()
    assert result['source'] == 'hierarchical' and result['events']['oom_kill'] == 4
    assert result['max'] is None


@pytest.mark.parametrize('path,value', [
    ('/proc/self/cgroup', 'malformed'),
    ('/proc/self/mountinfo', '31 20 0:28 /slice /sys/fs/cgroup rw - cgroup2\n'),
    ('/sys/fs/cgroup/job/memory.current', '-1'),
    ('/sys/fs/cgroup/job/memory.peak', PermissionError()),
    ('/sys/fs/cgroup/job/memory.max', 'not-a-counter'),
    ('/sys/fs/cgroup/job/memory.events.local', 'oom_kill bad\n'),
    ('/sys/fs/cgroup/job/memory.events.local', 'oom_kill 1\noom_kill 2\n'),
    ('/sys/fs/cgroup/job/memory.events.local', 'x' * 65537),
])
def test_missing_unreadable_or_malformed_memory_is_unavailable(memory_files, path, value):
    memory_files[path] = value
    assert worker._worker_cgroup_memory() is None


def memory(kills, group='/private-cgroup-name'):
    return {'_group': group, 'source': 'local', 'events': {'oom_kill': kills},
            'current': 100, 'peak': 200, 'max': 1000}


@pytest.mark.parametrize('exitcode,alive,before,after,expected_delta', [
    (-9, False, memory(4), memory(4), '0'),
    (-9, False, memory(4), memory(6), '2'),
    (-9, False, None, None, 'None'),
    (-9, False, memory(4), memory(6, '/different-group'), 'None'),
    (None, True, memory(4), None, 'None'),
])
def test_real_worker_eof_records_natural_exit_before_cleanup_without_oom_attribution(
        monkeypatch, tmp_path, caplog, exitcode, alive, before, after, expected_delta):
    settings = Settings(state_dir=tmp_path / 'state', identity_dir=tmp_path / 'identity')
    store = SQLiteStore(settings.state_dir)
    connector = store.add_connector('alice', {'provider': 'aws'}, CredentialCipher(settings.identity_dir).encrypt(
        {'auth': {'token': 'private-fixture-value'}, 'options': {}}))
    job = store.enqueue('alice', {'connector_id': connector['id'], 'ai_enabled': False})
    assert store.admit('alice', job['id'])
    observations = []

    def observed():
        observations.append(True)
        return before if len(observations) == 1 else after

    monkeypatch.setattr(worker, '_worker_cgroup_memory', observed)

    class Process:
        def __init__(self, **kwargs):
            self.exitcode, self.alive = exitcode, alive

        def start(self): pass
        def is_alive(self): return self.alive
        def join(self, timeout): pass
        def terminate(self):
            self.alive, self.exitcode = False, -15
        def kill(self):
            self.alive, self.exitcode = False, -9

    class Pipe:
        def poll(self, timeout): return True
        def recv(self): raise EOFError()
        def close(self): pass

    context = SimpleNamespace(Pipe=lambda **kwargs: (Pipe(), Pipe()), Process=Process)
    monkeypatch.setattr(worker.multiprocessing, 'get_context', lambda mode: context)
    with caplog.at_level(logging.INFO, logger=worker.__name__):
        assert worker.Worker('collector', settings, store=store,
                             artifacts=FileArtifacts(tmp_path / 'artifacts')).run_once('alice', job['id'])
    current = store.job('alice', job['id'])
    assert current['status'] == 'failed' and current['error_code'] == 'worker_interrupted'
    natural = next(record.getMessage() for record in caplog.records if 'Scan worker interrupted:' in record.getMessage())
    assert 'child_exitcode=' + str(exitcode) in natural
    assert 'child_signal=' + ('9' if exitcode == -9 else 'None') in natural
    assert 'cleanup_started=false' in natural and 'group_oom_kill_delta=' + expected_delta in natural
    assert 'child_oom' not in caplog.text and 'private-fixture-value' not in caplog.text
    assert '/private-cgroup-name' not in caplog.text and '/different-group' not in caplog.text
    if alive:
        assert len(observations) == 1
        assert 'natural_exit_observed=False' in natural
        assert 'Scan worker cleanup: terminate_requested=True' in caplog.text
        assert 'exitcode_after_cleanup=-15' in caplog.text
    else:
        assert len(observations) == 2 and 'natural_exit_observed=True' in natural
        assert 'Scan worker cleanup:' not in caplog.text
