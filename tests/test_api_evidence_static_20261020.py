"""Packaging-safe, fresh-process parity for the frozen evidence presentation."""
import os
from pathlib import Path
import subprocess
import sys
import json
import copy,gzip,importlib.util,json,sys
import gzip,importlib.util,json,sys
import importlib.util,sys
import importlib.util,json,sys

ROOT = Path(__file__).resolve().parents[1]
RUNTIME_ROOT = ROOT/'peaso/server'
NATIVE_ROOT = (ROOT/'peaso/checks').resolve().parents[1]
RUNTIME = ('evidence_static.py', 'evidence_static_source_manifest.json',
           'evidence_static_data_manifest.json', 'evidence_static_field_specs.json',
           'evidence_static_privesc_entries.json')


def _stage(tmp_path):
    """Build a package overlay without writing to the source checkout."""
    (tmp_path/'risk_rules').symlink_to(ROOT/'risk_rules', target_is_directory=True)
    peaso = tmp_path/'peaso'
    peaso.mkdir()
    for child in (ROOT/'peaso').iterdir():
        if child.name != 'server':
            (peaso/child.name).symlink_to(child, target_is_directory=child.is_dir())
    server=peaso/'server'
    server.mkdir()
    for child in RUNTIME_ROOT.iterdir():
        if child.name not in RUNTIME:
            (server/child.name).symlink_to(child, target_is_directory=child.is_dir())
    for name in RUNTIME:
        (server/name).write_bytes((RUNTIME_ROOT/name).read_bytes())
    return tmp_path


def _run(stage, script):
    # Copied runtime files read the package overlay; normal imports use the source package.
    env={key: value for key, value in os.environ.items() if key != 'PEASO_SOURCE_ATTESTATION'}
    env.update(PYTHONPATH=str(NATIVE_ROOT)+os.pathsep+str(ROOT)+os.pathsep+str(stage))
    result=subprocess.run([sys.executable,'-c',script,'',str(stage)],
                          cwd=NATIVE_ROOT,env=env,text=True,capture_output=True,timeout=180)
    assert result.returncode == 0, result.stdout+'\n'+result.stderr
    return result.stdout




def test_concurrent_first_import_never_exposes_partial_formatter(monkeypatch):
    import builtins
    from concurrent.futures import ThreadPoolExecutor
    import importlib.util
    from threading import Event
    from peaso.server import evidence_static
    spec = importlib.util.spec_from_file_location('isolated_evidence_thread_test', evidence_static.__file__)
    loader = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loader)
    entered, release, second_started, second_finished = (Event() for _ in range(4))
    def delayed_exec(code, namespace):
        entered.set()
        assert release.wait(10)
        return builtins.exec(code, namespace)
    monkeypatch.setattr(loader, 'exec', delayed_exec, raising=False)
    name = 'checks.aws_ai_recheck_evidence_20261020'
    def concurrent_reader():
        second_started.set()
        try:
            return loader._load_source(name).evidence_summary({})
        finally:
            second_finished.set()
    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(loader._load_source, name)
        try:
            assert entered.wait(5)
            second = pool.submit(concurrent_reader)
            assert second_started.wait(5)
            assert not second_finished.wait(0.2)
        finally:
            release.set()
        assert second.result(timeout=5) is None
        assert loader._load_source(name) is first.result(timeout=5)


