"""Exact compiler parity and live checks after admission-local compiled reuse."""
import hashlib
import inspect
from pathlib import Path
import sys
import types

import pytest
from tests.shared_admission_epoch_compatibility_20261020 import active_shared


ROOT = Path(__file__).resolve().parents[1]
SOURCE = '''\
def decorate(*, flag):
    def wrapper(function):
        return function
    return wrapper

@decorate(flag=True)
def selected(value=1, *, flag=True):
    return value if flag else 0

def outer(value):
    def inner(extra=2):
        return value + extra
    return inner

class Container:
    @staticmethod
    async def pending(value=None):
        return value

def branches(value):
    try:
        if value:
            class Nested:
                @staticmethod
                async def pending(extra=2):
                    return extra
    except Exception:
        def recover():
            return None
    match value:
        case _:
            def fallback():
                return value
'''


@pytest.fixture(scope='module')
def bridge():
    from peaso.checks import native_admission_cpu_shared_successor_20261020
    return native_admission_cpu_shared_successor_20261020


def consumed(rows):
    return [(record['qualname'], record['source_sha256'], code) for record, code in rows]


def test_compiler_preserves_decorated_nested_async_class_and_defaults(bridge):
    raw = SOURCE.encode()
    expected = bridge.original.proof._compiled_source(raw, 'compiler-parity.py', sys.flags.optimize)
    actual = bridge._compiled_source(raw, 'compiler-parity.py', sys.flags.optimize)
    assert consumed(actual) == consumed(expected)
    assert {record['qualname'] for record, _ in actual} == {
        'decorate', 'decorate.<locals>.wrapper', 'selected', 'outer',
        'outer.<locals>.inner', 'Container.pending',
        'branches', 'branches.<locals>.Nested.pending',
        'branches.<locals>.recover', 'branches.<locals>.fallback',
    }


@pytest.mark.parametrize('relative', [
    'peaso/checks/native_admission_cpu_shared_successor_20261020.py',
    'peaso/engine.py', 'peaso/collectors/aws.py',
])
def test_current_real_source_consumed_records_match_historical_compiler(bridge, relative):
    path = ROOT / relative
    raw = path.read_bytes()
    expected = bridge.original.proof._compiled_source(raw, str(path), sys.flags.optimize)
    assert consumed(bridge._compiled_source(raw, str(path), sys.flags.optimize)) == consumed(expected)


@pytest.fixture(params=[False, True], ids=['local', 'transaction'])
def warmed(bridge, tmp_path, monkeypatch, request):
    root = tmp_path.resolve()
    path = root / 'sample.py'
    path.write_text(SOURCE)
    module = types.ModuleType('provider_bridge_compiler_sample')
    module.__file__ = str(path)
    monkeypatch.setitem(sys.modules, module.__name__, module)
    exec(compile(SOURCE, str(path), 'exec'), vars(module))
    function = module.selected
    row = dict(path='sample.py', qualname='selected',
               sha256=hashlib.sha256(inspect.getsource(function).encode()).hexdigest(),
               defaults=[1], kwdefaults={'flag': True})
    compiled = {}
    token = bridge._COMPILED_TRANSACTION.set(bridge._transaction_compiler()) if request.param else None
    try:
        bridge._check_function(function, row, root, compiled)
        bridge._check_function(function, row, root, compiled)
        assert len(compiled) == (0 if request.param else 1)
        yield function, row, root, compiled
    finally:
        if token is not None:
            bridge._COMPILED_TRANSACTION.reset(token)




@pytest.mark.parametrize('name', ['_compiled_source', '_check_function', '_transaction_compiler'])
@pytest.mark.parametrize('mutation', ['identity', 'code'])
def test_bridge_independently_rejects_optimization_helper_tampering(bridge, monkeypatch, name, mutation):
    bridge._verify_bridge(ROOT)
    if mutation == 'identity':
        monkeypatch.setattr(bridge, name, lambda *args, **kwargs: None)
    else:
        monkeypatch.setattr(getattr(bridge, name), '__code__', (lambda *args, **kwargs: None).__code__)
    with pytest.raises(RuntimeError, match='callable'):
        bridge._verify_bridge(ROOT)








def test_bundle_compilation_context_is_released_on_success_and_failure(bridge, monkeypatch):
    # The genuine cold import has already completed a successful install wave.
    current = active_shared()
    assert current._COMPILED_TRANSACTION.get() is None
    commands = current._COMMAND_SUCCESSOR

    def refuse():
        assert current._COMPILED_TRANSACTION.get() is not None
        raise RuntimeError('deliberate preflight refusal')

    monkeypatch.setattr(commands, 'reviewed_inputs', refuse)
    # Either the refusal or the entrypoint identity guard fails the wave.
    with pytest.raises(RuntimeError):
        current.install_bundle()
    assert current._COMPILED_TRANSACTION.get() is None
