import json
import multiprocessing
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

import peaso.source_attestation_mode as attestation_mode
import peaso.worker as worker_module

ROOT = Path(__file__).resolve().parents[1]


class _Worker(worker_module.Worker):
    def __init__(self):
        self.role = "analyzer"
        self._prewarmed = None
        self.warm_children = False


def _record_contexts(monkeypatch):
    seen = []
    real = multiprocessing.get_context

    def get_context(method=None):
        seen.append(method)
        return real(method)

    monkeypatch.setattr(worker_module.multiprocessing, "get_context", get_context)
    return seen


def test_one_shot_tasks_and_always_mode_keep_a_spawned_child(monkeypatch):
    seen = _record_contexts(monkeypatch)
    worker = _Worker()
    assert worker._child_context().get_start_method() == "spawn"
    worker.warm_children = True
    monkeypatch.setattr(attestation_mode, "ALWAYS", True)
    assert worker._child_context().get_start_method() == "spawn"
    assert seen == ["spawn", "spawn"]


@pytest.mark.skipif("forkserver" not in multiprocessing.get_all_start_methods(), reason="no forkserver")
def test_long_lived_worker_children_fork_from_the_preloaded_forkserver(monkeypatch):
    from multiprocessing import forkserver
    previous = list(forkserver._forkserver._preload_modules)
    monkeypatch.setattr(attestation_mode, "ALWAYS", False)
    worker = _Worker()
    worker.warm_children = True
    try:
        context = worker._child_context()
        assert context.get_start_method() == "forkserver"
        assert forkserver._forkserver._preload_modules == ["peaso.worker_preload"]
    finally:
        forkserver.set_forkserver_preload(previous)


def _production_env():
    env = {key: value for key, value in os.environ.items() if key != "PEASO_SOURCE_ATTESTATION"}
    env["PYTHONPATH"] = str(ROOT)
    return env


@pytest.mark.skipif("forkserver" not in multiprocessing.get_all_start_methods(), reason="no forkserver")
def test_forked_children_inherit_the_proven_engine_but_not_each_others_state(tmp_path):
    (tmp_path / "warm_probe.py").write_text(textwrap.dedent("""
        import resource, sys

        def probe(connection, mark):
            ready = 'peaso.checks' in sys.modules
            import peaso.checks
            seen = getattr(peaso.checks, '_warm_probe_mark', None)
            peaso.checks._warm_probe_mark = mark
            usage = resource.getrusage(resource.RUSAGE_SELF)
            connection.send((ready, seen, usage.ru_utime + usage.ru_stime))
            connection.close()
    """))
    script = textwrap.dedent("""
        import json, sys
        sys.path.insert(0, sys.argv[1])
        import warm_probe
        from peaso.worker import _warm_context
        context = _warm_context()
        rows = []
        for mark in ('first', 'second'):
            parent, child = context.Pipe(duplex=False)
            process = context.Process(target=warm_probe.probe, args=(child, mark))
            process.start(); child.close()
            rows.append(parent.recv()); process.join(30)
            assert process.exitcode == 0
        print(json.dumps({'method': context.get_start_method(), 'rows': rows}))
    """)
    result = subprocess.run([sys.executable, "-c", script, str(tmp_path)], cwd=ROOT, env=_production_env(),
                            capture_output=True, text=True, timeout=600)
    assert result.returncode == 0, result.stderr[-2000:]
    out = json.loads(result.stdout.strip().splitlines()[-1])
    assert out["method"] == "forkserver"
    # Both children start with peaso.checks already proven by the forkserver,
    # and neither sees state the other one wrote after its fork.
    assert [row[:2] for row in out["rows"]] == [[True, None], [True, None]]
    assert all(row[2] < 5 for row in out["rows"])


def test_a_failed_preload_leaves_nothing_half_proven_to_inherit():
    script = textwrap.dedent("""
        import builtins, sys
        sys.modules['peaso.checks'] = None  # importing it now raises ImportError
        original = builtins.compile
        import peaso.worker_preload as preload
        assert preload.WARM is False
        assert builtins.compile is original
        left = sorted(name for name in sys.modules if name.startswith('peaso.'))
        assert left == ['peaso.worker_preload'], left
        print('ok')
    """)
    result = subprocess.run([sys.executable, "-c", script], cwd=ROOT, env=_production_env(),
                            capture_output=True, text=True, timeout=300)
    assert result.returncode == 0 and result.stdout.strip() == "ok", result.stderr[-2000:]
