"""Real native bridge: signed artifact reuse never reuses a trust verdict."""
import hashlib
import inspect
import linecache
from pathlib import Path
import sys
import types

import pytest
from peaso.checks import gcp_positive_conservation_shared_source_successor_20261020 as bridge
from peaso.checks import private_secret_shared_source_successor_20261021 as live

ROOT = Path(bridge.__file__).resolve().parents[2]
SAMPLE = 'def selected(value=1, *, flag=True):\n    return value if flag else 0\n'

@pytest.fixture
def sample(tmp_path, monkeypatch):
    path = tmp_path.resolve() / 'sample.py'
    path.write_text(SAMPLE)
    module = types.ModuleType('gcp_cpu_cache_sample')
    module.__file__ = str(path)
    monkeypatch.setitem(sys.modules, module.__name__, module)
    exec(compile(SAMPLE, str(path), 'exec'), vars(module))
    row = dict(path='sample.py', qualname='selected', sha256=hashlib.sha256(SAMPLE.encode()).hexdigest(), defaults=[1], kwdefaults={'flag': True})
    compiler = bridge._transaction_compiler()
    token = bridge._COMPILED_TRANSACTION.set(compiler)
    try:
        bridge._check_function(module.selected, row, path.parent, {})
        yield module.selected, row, path, compiler
    finally:
        bridge._COMPILED_TRANSACTION.reset(token)
        linecache.cache.pop(str(path), None)

@pytest.mark.parametrize('mutation', ['code', 'defaults', 'kwdefaults', 'globals', 'row', 'disk', 'linecache', 'location'])
def test_warm_live_inputs_still_rejected(sample, mutation):
    fn, row, path, compiler = sample
    if mutation == 'code': fn.__code__ = fn.__code__.replace(co_consts=(None, 999))
    elif mutation == 'defaults': fn.__defaults__ = (2,)
    elif mutation == 'kwdefaults': fn.__kwdefaults__ = {'flag': False}
    elif mutation == 'globals':
        fn = types.FunctionType(fn.__code__, dict(fn.__globals__), fn.__name__, fn.__defaults__)
        fn.__kwdefaults__ = {'flag': True}
    elif mutation == 'row': row = dict(row, sha256='0' * 64)
    elif mutation == 'disk': path.write_text(SAMPLE.replace('else 0', 'else 8'))
    elif mutation == 'linecache': linecache.cache[str(path)][2][-1] = '    return value if flag else 8\n'
    else: fn.__code__ = fn.__code__.replace(co_filename=str(path.parent / 'foreign.py'))
    with pytest.raises((RuntimeError, OSError, IndexError)):
        bridge._check_function(fn, row, path.parent, {})

@pytest.mark.parametrize('mutation', ['digest', 'code', 'signature'])
def test_signed_source_artifact_corruption_rejected(sample, mutation):
    fn, row, path, compiler = sample
    cache = inspect.getclosurevars(compiler).nonlocals['source_cache']
    key = next(iter(cache)); code, digest, signature = cache[key]
    if mutation == 'digest': digest = '0' * 64
    elif mutation == 'code': code = code.replace(co_consts=(None, 999))
    else: signature = b'0' * 32
    cache[key] = (code, digest, signature)
    with pytest.raises(RuntimeError, match='source cache artifact changed'):
        bridge._check_function(fn, row, path.parent, {})


def test_repeated_historical_proof_reuses_fragments_but_rechecks_live_code(monkeypatch):
    # The private successor proves the live initializer; this bridge is its canonical predecessor.
    counts = {}
    native_getsource = inspect.getsource
    def counted(fn):
        if fn.__module__ == live.historical_bridge.__name__:
            counts[fn.__qualname__] = counts.get(fn.__qualname__, 0) + 1
        return native_getsource(fn)
    monkeypatch.setattr(inspect, 'getsource', counted)
    token = live._COMPILED_TRANSACTION.set(live._transaction_compiler())
    try:
        live._verify_bridge(ROOT)
        first = counts.copy()
        assert len(first) == len(live._FUNCTIONS)
        assert set(first.values()) == {1}
        live._verify_bridge(ROOT)
        assert counts == first
        function = live.historical_bridge.reviewed_delta
        old = function.__defaults__
        try:
            function.__defaults__ = ('unreviewed',)
            with pytest.raises(RuntimeError): live._verify_bridge(ROOT)
        finally:
            function.__defaults__ = old
    finally:
        live._COMPILED_TRANSACTION.reset(token)

@pytest.mark.parametrize('mutation', ['historical_carrier', 'historical_callable', 'current_carrier', 'own_code'])
def test_real_bridge_binding_tampering_rejected(monkeypatch, mutation):
    live._verify_bridge(ROOT)  # untampered live proof succeeds, so each rejection below is the mutation's
    if mutation == 'historical_carrier':
        monkeypatch.setattr(live.historical_bridge, '_COMPILED_TRANSACTION', object())
    elif mutation == 'historical_callable':
        monkeypatch.setattr(live.historical_bridge, 'reviewed_delta', lambda: None)
    elif mutation == 'current_carrier':
        monkeypatch.setattr(live, '_COMPILED_TRANSACTION', object())
    else:
        fn = live._check_function
        monkeypatch.setattr(fn, '__code__', fn.__code__.replace(co_consts=fn.__code__.co_consts + ('unreviewed',)))
    with pytest.raises(RuntimeError): live._verify_bridge(ROOT)


def test_s3_transaction_releases_on_failure_and_restores_outer_context(monkeypatch):
    outer = bridge._transaction_compiler()
    token = bridge._COMPILED_TRANSACTION.set(outer)
    # Force an ordinary registration collision only after the real source proof.
    from peaso.checks.fixtures import CASES
    from peaso.checks import aws_s3_selected_source_secret_review_20261020 as reviewed
    monkeypatch.setitem(CASES, reviewed.CHECK, {})
    try:
        with pytest.raises(RuntimeError): bridge.install_s3()
        assert bridge._COMPILED_TRANSACTION.get() is outer
    finally:
        bridge._COMPILED_TRANSACTION.reset(token)


