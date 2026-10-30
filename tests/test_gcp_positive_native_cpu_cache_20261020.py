"""Real native bridge: signed artifact reuse never reuses a trust verdict."""
import hashlib
import inspect
import linecache
import sys
import types

import pytest
from peaso.checks import gcp_positive_conservation_shared_source_successor_20261020 as bridge
from peaso import gcp_positive_conservation_source_admission_successor_20261020 as source

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


