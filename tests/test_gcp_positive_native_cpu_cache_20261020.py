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
from peaso import gcp_positive_conservation_source_admission_successor_20261020 as source

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


