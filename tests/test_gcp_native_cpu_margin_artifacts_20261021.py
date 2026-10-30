"""Artifact reuse preserves every current proof and immutable predecessor."""
import hashlib
import inspect
from pathlib import Path
import sys
import types

import pytest
from peaso import gcp_positive_conservation_source_admission_successor_20261020 as source
from peaso.checks import gcp_positive_conservation_shared_source_successor_20261020 as bridge

ROOT = Path(source.__file__).resolve().parents[1]




def test_module_artifact_new_source_is_recompiled(tmp_path):
    compiler = source._module_compiler(); path = tmp_path / 'sample.py'
    first = compiler(path, b'value = 1\n')
    second = compiler(path, b'value = 2\n')
    assert first is not second
    namespace = {}; exec(second, namespace)
    assert namespace['value'] == 2


@pytest.mark.parametrize('mutation', ['callable', 'globals', 'code'])
def test_module_compiler_live_identity_rejected(tmp_path, mutation):
    compiler = source._module_compiler()
    if mutation == 'callable': changed = lambda path, raw: compile(raw, str(path), 'exec')
    elif mutation == 'globals':
        changed = types.FunctionType(compiler.__code__, dict(compiler.__globals__),
                                     compiler.__name__, compiler.__defaults__, compiler.__closure__)
    else:
        changed = types.FunctionType(compiler.__code__.replace(co_consts=compiler.__code__.co_consts + ('unreviewed',)),
                                     compiler.__globals__, compiler.__name__, compiler.__defaults__, compiler.__closure__)
    token = source._MODULE_ARTIFACTS.set(changed)
    try:
        with pytest.raises(RuntimeError, match='compiler callable changed'):
            source._compiled_module(tmp_path / 'sample.py', b'value = 1\n')
    finally:
        source._MODULE_ARTIFACTS.reset(token)


@pytest.mark.parametrize('mutation', ['code', 'json', 'signature'])
def test_normalized_code_cache_poisoning_rejected(mutation):
    compiler = bridge._transaction_compiler()
    normalized = inspect.getclosurevars(compiler).nonlocals['normalized']
    code = compile('answer = 1', '<sample>', 'exec')
    key = ('<sample>', 'digest', sys.flags.optimize)
    expected = normalized(key, code)
    assert normalized(key, code) == expected
    cache = inspect.getclosurevars(normalized).nonlocals['code_cache']
    artifact_key = next(iter(cache)); saved, value, signature = cache[artifact_key]
    if mutation == 'code': saved = compile('answer = 2', '<sample>', 'exec')
    elif mutation == 'json': value = '{}'
    else: signature = b'0' * 32
    cache[artifact_key] = (saved, value, signature)
    with pytest.raises(RuntimeError, match='Normalized code artifact changed'):
        normalized(key, code)


def test_code_serialization_keeps_false_integer_float_distinct():
    compiler = bridge._transaction_compiler()
    normalized = inspect.getclosurevars(compiler).nonlocals['normalized']
    base = compile('answer = 1', '<sample>', 'exec')
    values = [normalized(('<sample>', 'digest', 0), base.replace(co_consts=(v,))) for v in (False, 0, 0.0)]
    assert len(set(values)) == 3


@pytest.mark.parametrize('constant', [type('BytesSubclass', (bytes,), {})(b'x'), type('TupleSubclass', (tuple,), {})((1,))])
def test_mutable_subclass_constants_refused(constant):
    compiler = bridge._transaction_compiler()
    normalized = inspect.getclosurevars(compiler).nonlocals['normalized']
    code = compile('answer = 1', '<sample>', 'exec').replace(co_consts=(constant,))
    with pytest.raises(RuntimeError, match='Mutable native code artifact refused'):
        normalized(('<sample>', 'digest', 0), code)


@pytest.mark.parametrize('installer', ['install_bundle', 'install_s3'])
def test_constructor_or_earlier_live_guard_failure_restores_artifact_context(monkeypatch, installer):
    outer = source._module_compiler()
    token = source._MODULE_ARTIFACTS.set(outer)
    def fail(): raise RuntimeError('injected constructor failure')
    monkeypatch.setattr(bridge, '_transaction_compiler', fail)
    try:
        expected = ('injected constructor failure' if installer == 'install_s3'
                    else 'bridge callable roster changed')
        with pytest.raises(RuntimeError, match=expected):
            getattr(bridge, installer)()
        assert source._MODULE_ARTIFACTS.get() is outer
    finally:
        source._MODULE_ARTIFACTS.reset(token)


def test_real_source_proof_rechecks_live_function_inside_warm_module_context(monkeypatch):
    token = source._MODULE_ARTIFACTS.set(source._module_compiler())
    try:
        source._bridge_source(ROOT)
        source._bridge_source(ROOT)
        fn = source._compiled_module
        monkeypatch.setattr(fn, '__defaults__', ('unreviewed',))
        with pytest.raises(RuntimeError, match='executing callable changed'):
            source._bridge_source(ROOT)
    finally:
        source._MODULE_ARTIFACTS.reset(token)


def test_module_carrier_replacement_rejected(monkeypatch):
    monkeypatch.setattr(source, '_MODULE_ARTIFACTS', object())
    with pytest.raises(RuntimeError, match='artifact context changed'):
        source._bridge_source(ROOT)
