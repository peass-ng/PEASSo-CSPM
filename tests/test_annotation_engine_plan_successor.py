"""Exact planner successor preserves annotation ancestry and rejects live drift."""
import json,sys,types
from pathlib import Path
import pytest
import peaso.checks
from peaso import engine
from peaso.checks import k8s_annotation_native_source_successor_20261021 as subject


def attestor():
    return sys.modules[subject._PRIVATE_NAME]._trusted_definition


def test_current_planner_maps_to_unchanged_historical_definition():
    row,current,previous=subject._engine_plan_source()
    expected=subject.historical._source_receipt()['compiled_sources']['peaso/engine.py']['functions']['plan_collection']
    path,record=attestor()(engine.plan_collection)
    assert path=='peaso/engine.py'
    assert record['source_sha256']==expected['source_sha256']==row['predecessor_fragment_sha256']
    assert record['ast_sha256']==expected['ast_sha256']
    assert row['current_fragment_sha256']!=row['predecessor_fragment_sha256']
    assert current!=previous


def test_equivalent_unbound_planner_clone_is_rejected():
    fn=engine.plan_collection
    clone=types.FunctionType(fn.__code__,fn.__globals__,fn.__name__,fn.__defaults__,fn.__closure__)
    clone.__qualname__=fn.__qualname__;clone.__kwdefaults__=dict(fn.__kwdefaults__)
    with pytest.raises(RuntimeError,match='live binding changed'):
        attestor()(clone)


def test_live_keyword_default_drift_is_rejected(monkeypatch):
    monkeypatch.setattr(engine.plan_collection,'__kwdefaults__',{'_runtime_connector':True})
    with pytest.raises(RuntimeError,match='live binding changed'):
        attestor()(engine.plan_collection)


@pytest.mark.parametrize('field',['current_fragment_sha256','predecessor_fragment_sha256'])
def test_receipt_transition_hash_drift_is_rejected(monkeypatch,tmp_path,field):
    row=json.loads(subject.RECEIPT.read_text());row['engine_plan_admission'][field]='0'*64
    receipt=tmp_path/'altered.json';receipt.write_text(json.dumps(row));monkeypatch.setattr(subject,'RECEIPT',receipt)
    with pytest.raises(RuntimeError,match='exact transition changed'):
        subject._engine_plan_source()
