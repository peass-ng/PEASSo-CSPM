"""Only immutable artifacts are reused; source and active bindings stay live."""
import hashlib
import inspect
import linecache
from pathlib import Path
import sys
import types

import pytest
from peaso import rawv2_public_source_successor_20261021 as rawv2
from peaso import gcp_positive_conservation_source_admission_successor_20261020 as source
from peaso.checks import gcp_positive_conservation_shared_source_successor_20261020 as shared


@pytest.mark.parametrize('failure', [False, True])
def test_installer_scope_releases_on_success_and_baseexception(failure):
    previous = source._MODULE_ARTIFACTS.get()
    class Stop(BaseException): pass
    seen = []
    def invoke():
        compiler = source._MODULE_ARTIFACTS.get()
        assert compiler is not None
        path = Path('/tmp/rawv2-immutable-artifact.py')
        first = source._compiled_module(path, b'value = 1\n')
        assert source._compiled_module(path, b'value = 1\n') is first
        seen.append(compiler)
        if failure: raise Stop()
        return 'ok'
    if failure:
        with pytest.raises(Stop): rawv2._with_artifacts(invoke)
    else:
        assert rawv2._with_artifacts(invoke) == 'ok'
    assert seen and source._MODULE_ARTIFACTS.get() is previous


def test_installer_scope_preserves_outer_transaction():
    outer = source._module_compiler()
    token = source._MODULE_ARTIFACTS.set(outer)
    try:
        assert rawv2._with_artifacts(lambda: source._MODULE_ARTIFACTS.get()) is outer
        assert source._MODULE_ARTIFACTS.get() is outer
    finally:
        source._MODULE_ARTIFACTS.reset(token)


def test_factory_substitution_is_rejected_before_callback(monkeypatch):
    before = source._MODULE_ARTIFACTS.get()
    monkeypatch.setattr(source, '_module_compiler', lambda: None)
    called = []
    with pytest.raises(RuntimeError, match='provider callable changed'):
        rawv2._with_artifacts(lambda: called.append(True))
    assert not called and source._MODULE_ARTIFACTS.get() is before


def test_active_scope_still_rechecks_own_live_defaults(monkeypatch):
    token = source._MODULE_ARTIFACTS.set(source._module_compiler())
    try:
        rawv2._with_artifacts(lambda: None)
        monkeypatch.setattr(rawv2._install_admission, '__defaults__', ('foreign',))
        with pytest.raises(RuntimeError, match='helper callable changed'):
            rawv2._with_artifacts(lambda: None)
    finally:
        source._MODULE_ARTIFACTS.reset(token)


def test_signed_module_artifact_rejects_equal_code_object_substitution(tmp_path):
    compiler = source._module_compiler()
    raw = b'value = 1\n'
    original = compiler(tmp_path / 'sample.py', raw)
    cache = inspect.getclosurevars(compiler).nonlocals['cache']
    key = next(iter(cache)); code, signature = cache[key]
    changed = code.replace()
    assert changed == original and changed is not original
    cache[key] = (changed, signature)
    with pytest.raises(RuntimeError, match='module artifact changed'):
        compiler(tmp_path / 'sample.py', raw)




def test_active_scope_rechecks_provider_before_callback(monkeypatch):
    compiler = source._module_compiler()
    token = source._MODULE_ARTIFACTS.set(compiler)
    original = source._compiled_module
    def substituted(path, raw):
        return original(path, raw)
    called = []
    try:
        monkeypatch.setattr(source, '_compiled_module', substituted)
        with pytest.raises(RuntimeError, match='provider callable changed'):
            rawv2._with_artifacts(lambda: called.append(True))
        assert not called and source._MODULE_ARTIFACTS.get() is compiler
    finally:
        source._MODULE_ARTIFACTS.reset(token)
