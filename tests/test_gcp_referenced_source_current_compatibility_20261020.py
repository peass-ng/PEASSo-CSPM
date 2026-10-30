"""Finite regressions for the six exact sealed predecessor/current boundaries.

Ordinary collection loads the plugin before execution, even when the historical
files collect first. Directed runs must include this file or explicitly use -p.
Official mechanism: https://docs.pytest.org/en/stable/how-to/writing_plugins.html
#requiring-loading-plugins-in-a-test-module-or-conftest-file
"""
from dataclasses import replace
import importlib
from pathlib import Path
from types import FunctionType, SimpleNamespace

import pytest

pytest_plugins = ('tests.gcp_referenced_source_historical_compatibility_20261020',)


@pytest.fixture
def bridge():
    # Delay import until pytest has processed pytest_plugins and assertion rewrite.
    return importlib.import_module(pytest_plugins[0])


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    module = importlib.import_module('tests.gcp_referenced_source_independent_review_20261020_test')
    yield from module.offline.__wrapped__(monkeypatch)


def original(bridge, spec, pytestconfig):
    module = importlib.import_module(spec.path.removesuffix('.py').replace('/', '.'))
    return module, bridge.bound_function(module, spec, pytestconfig)


@pytest.mark.parametrize('which', range(6))
def test_exact_original_failure_then_current_on_identical_capture(bridge, which, monkeypatch, pytestconfig):
    """Actual old red remains reproducible; actual successor consumes its locals."""
    bridge.attest_sources()
    spec = tuple(bridge.NODES.values())[which]
    _, function = original(bridge, spec, pytestconfig)
    current = bridge.prepare_current(spec)
    arguments = dict(spec.parameters)
    if 'monkeypatch' in function.__code__.co_varnames[:function.__code__.co_argcount]:
        arguments['monkeypatch'] = monkeypatch
    frame = bridge.historical_frame(function, spec, arguments)
    try:
        assert frame.f_code is function.__code__ and frame.f_lineno in (spec.line, spec.line + 1)
        proof = bridge.current_on_same_capture(spec, frame, current)
        if spec.semantics.endswith('_proposal'):
            assert proof['proposal_registration_delta'] == 0
        else:
            assert proof['complete'] is False
            assert proof['current_status'] == ('FAIL' if dict(spec.parameters).get('hit') else 'UNKNOWN')
    finally:
        del frame


def test_only_six_literal_nodes_can_be_intercepted(bridge, monkeypatch):
    assert len(bridge.NODES) == 6
    def forbidden():
        pytest.fail('Unrelated node reached compatibility attestation')
    monkeypatch.setattr(bridge, 'attest_sources', forbidden)
    for node in ('tests/other_test.py::test_proposal_not_installed',
                 bridge.INDEPENDENT + '::' + bridge._workbench_fn + '[new_case]',
                 bridge.BATCH_REVIEW + '::' + bridge._batch_fn + '[bad_engine_version-trusted_hit]'):
        assert bridge.pytest_pyfunc_call(SimpleNamespace(nodeid=node)) is None


@pytest.mark.parametrize('relative', [
    'tests/gcp_referenced_source_independent_review_20261020_test.py',
    'peaso/checks/gcp_workbench_source_runtime_consumer_20261020.py',
    'peaso/checks/gcp_dataflow_referenced_source_request_binding_20261020.py',
])
def test_source_drift_cannot_be_accepted(bridge, monkeypatch, relative):
    original_read = Path.read_bytes
    path = bridge.ROOT / relative
    monkeypatch.setattr(Path, 'read_bytes', lambda self: b'changed source' if self == path else original_read(self))
    with pytest.raises(AssertionError, match='source changed'):
        bridge.attest_sources()


@pytest.mark.parametrize('tamper', ['path', 'function_code', 'line_spec'])
def test_tampered_live_source_mapping_rejected(bridge, monkeypatch, pytestconfig, tamper):
    spec = tuple(bridge.NODES.values())[1]
    module, function = original(bridge, spec, pytestconfig)
    if tamper == 'path':
        monkeypatch.setattr(module, '__file__', str(bridge.ROOT / bridge.WORKBENCH))
    elif tamper == 'function_code':
        changed = FunctionType(function.__code__.replace(co_filename=str(bridge.ROOT / bridge.WORKBENCH)),
                               function.__globals__, function.__name__)
        monkeypatch.setattr(module, spec.function, changed)
    else:
        spec = replace(spec, line=spec.line - 1)
    with pytest.raises(AssertionError, match='mapping|executing code'):
        bridge.bound_function(module, spec, pytestconfig)


@pytest.mark.parametrize('error_type', [AssertionError, RuntimeError, TypeError])
def test_earlier_assertion_and_unexpected_exceptions_propagate(bridge, monkeypatch, pytestconfig, error_type):
    spec = tuple(bridge.NODES.values())[1]
    module, function = original(bridge, spec, pytestconfig)
    error = error_type('unexpected earlier native-capture failure')
    def broken_capture(*args, **kwargs):
        raise error
    monkeypatch.setattr(module.workbench, 'capture', broken_capture)
    with pytest.raises(error_type) as observed:
        bridge.historical_frame(function, spec, {'monkeypatch': monkeypatch, 'hit': False})
    assert observed.value is error


def test_earlier_assertion_in_original_test_cannot_be_accepted(bridge, monkeypatch, pytestconfig):
    spec = tuple(bridge.NODES.values())[1]
    module, function = original(bridge, spec, pytestconfig)
    capture = module.workbench.capture
    def early_red(*args, **kwargs):
        snapshot, rows, trace = capture(*args, **kwargs)
        return snapshot, [('UNKNOWN', rows[0][1])], trace
    monkeypatch.setattr(module.workbench, 'capture', early_red)
    with pytest.raises(AssertionError):
        bridge.historical_frame(function, spec, {'monkeypatch': monkeypatch, 'hit': False})


def test_unexpected_predecessor_pass_is_rejected_using_actual_capture(bridge, monkeypatch, pytestconfig):
    spec = tuple(bridge.NODES.values())[1]
    module, function = original(bridge, spec, pytestconfig)
    current = importlib.import_module('peaso.checks.gcp_workbench_source_runtime_consumer_20261020')
    # Deliberately change only the harness's consumer reference: original test
    # would now pass on real native data, which this historical bridge must reject.
    monkeypatch.setattr(module.workbench, 'consumer', current)
    with pytest.raises(AssertionError, match='unexpectedly passed'):
        bridge.historical_frame(function, spec, {'monkeypatch': monkeypatch, 'hit': False})


def test_regressed_current_consumer_fails_on_the_same_actual_data(bridge, monkeypatch, pytestconfig):
    spec = tuple(bridge.NODES.values())[3]
    module, function = original(bridge, spec, pytestconfig)
    prepared = bridge.prepare_current(spec)
    frame = bridge.historical_frame(function, spec, {'monkeypatch': monkeypatch})
    try:
        current = importlib.import_module('peaso.checks.gcp_dataflow_referenced_source_request_binding_20261020')
        monkeypatch.setattr(current, 'evaluate', module.dataflow.consumer.evaluate)
        with pytest.raises(AssertionError):
            bridge.current_on_same_capture(spec, frame, prepared)
    finally:
        del frame


