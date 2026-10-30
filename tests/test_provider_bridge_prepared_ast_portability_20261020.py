"""Portable AST receipts retain source, runtime identity and rollback guarantees."""
import ast
from copy import deepcopy
from dataclasses import replace
import importlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from tests.shared_admission_epoch_compatibility_20261020 import active_shared
from peaso import checks
from peaso.checks import native_admission_cpu_shared_successor_20261020 as bridge
from peaso.collectors.k8s import K8sReader

ROOT = Path(__file__).resolve().parents[1]
ADMISSION = importlib.import_module('peaso.checks.gcp_dataflow_batch_source_runtime_admission_20261020')


def test_sealed_ast_format_is_independent_of_interpreter_empty_field_defaults():
    assert bridge._prepared_ast(ast.parse('def f(x):\n return x\n')) == (
        "Module(body=[FunctionDef(name='f', args=arguments(args=[arg(arg='x')]), "
        "body=[Return(value=Name(id='x', ctx=Load()))])])")
    assert bridge._prepared_ast(ast.parse('def f(x):\n return x\n')) != bridge._prepared_ast(ast.parse('def f(x):\n return 1\n'))


def test_canonical_runtime_entrypoint_preserves_historical_objects_without_transport():
    current = active_shared()
    assert ADMISSION.reviewed_inputs is current.dataflow_reviewed_inputs
    assert ADMISSION._FUNCTIONS == bridge._DATAFLOW_FUNCTIONS
    assert bridge._DATAFLOW_REVIEWED_INPUTS is ADMISSION._FUNCTIONS[ADMISSION.__name__ + ':reviewed_inputs']
    assert ADMISSION._gcp_delta is bridge._DATAFLOW_FUNCTIONS[ADMISSION.__name__ + ':_gcp_delta']
    ADMISSION.reviewed_inputs()
    current.prepared_inputs(ROOT, {}, {})
    assert list(ADMISSION.runtime.collection_pages(SimpleNamespace(options={}, scopes=[]), 'projects/example', 'dataflow')) == []


@pytest.mark.parametrize('field', ('current_sha256', 'predecessor_ast', 'exact_additions'))
def test_prepared_guard_rejects_each_changed_source_or_ast_contract(field):
    receipt = json.loads((ROOT / 'peaso/checks/gcp_workbench_shared_hook_successor_20261020.json').read_bytes())
    name = 'shared:k8s_reader_call'
    predecessor = receipt['prepared_functions'][name]['predecessor']
    bridge._check_prepared_shared(K8sReader.call, predecessor, name, ROOT, {}, receipt)
    changed = deepcopy(receipt)
    changed['prepared_functions'][name][field] = ['unreviewed'] if field == 'exact_additions' else 'unreviewed'
    with pytest.raises(RuntimeError):
        bridge._check_prepared_shared(K8sReader.call, predecessor, name, ROOT, {}, changed)


@pytest.mark.parametrize('field', ('predecessor_sha256', 'predecessor_ast', 'exact_additions'))
def test_dataflow_guard_rejects_each_changed_source_or_ast_contract(field):
    # The active shared successor carries the reviewed current GCP collector transitions.
    current = active_shared()
    receipt = json.loads((ROOT / 'peaso/checks' / ADMISSION.RECEIPT).read_bytes())
    current._dataflow_gcp_delta(ROOT, receipt)
    changed = deepcopy(receipt)
    changed['gcp_function_deltas']['__init__'][field] = ['unreviewed'] if field == 'exact_additions' else 'unreviewed'
    with pytest.raises(RuntimeError):
        current._dataflow_gcp_delta(ROOT, changed)


@pytest.mark.parametrize('attribute', ('reviewed_inputs', 'shared'))
def test_dataflow_admission_rejects_unreviewed_entrypoint_alias(monkeypatch, attribute):
    current = active_shared()
    monkeypatch.setattr(ADMISSION, attribute, object())
    with pytest.raises(RuntimeError, match='alias|entrypoint'):
        current.dataflow_reviewed_inputs()


def test_late_install_collision_restores_both_canonical_aliases():
    current = active_shared()
    old_shared, old_reviewed = ADMISSION.shared, ADMISSION.reviewed_inputs
    before = tuple(checks.CHECKS)
    try:
        ADMISSION.shared = bridge.predecessor.predecessor.predecessor
        ADMISSION.reviewed_inputs = bridge._DATAFLOW_REVIEWED_INPUTS
        selected = next(i for i, check in enumerate(checks.CHECKS) if check.id in ADMISSION.runtime.CHECKS)
        checks.CHECKS[selected] = replace(checks.CHECKS[selected], title='collision proof')
        with pytest.raises(RuntimeError, match='collision'):
            current.install_dataflow(ADMISSION)
        assert ADMISSION.shared is bridge.predecessor.predecessor.predecessor
        assert ADMISSION.reviewed_inputs is bridge._DATAFLOW_REVIEWED_INPUTS
    finally:
        checks.CHECKS[:] = before
        ADMISSION.shared, ADMISSION.reviewed_inputs = old_shared, old_reviewed
