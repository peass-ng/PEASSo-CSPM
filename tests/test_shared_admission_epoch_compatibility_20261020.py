"""Compatibility checks retain exact evidence and reject unrelated drift."""
import ast
from copy import deepcopy
import hashlib
import inspect

import pytest

from tests import shared_admission_epoch_compatibility_20261020 as compatibility
from peaso.private_secret_source_epoch_20261021 import AdmissionError


def test_all_seven_original_test_sources_are_retained_exactly():
    original = compatibility.original_tests()
    assert len(original) == 7
    azure = original['tests/test_azure_function_package_runtime_20261020.py']['text']
    assert 'def test_actual_native_both_scanners_runtime_json' in azure
    assert 'def test_union_bounds_fail_closed' in azure
    assert 'def test_saved_cases_exact_local_source_binding_and_declaration' in azure




def test_finite_historical_ast_format_preserves_tamper_rejection():
    from peaso import engine
    row = compatibility.receipt('gcp_workbench_shared_hook_successor_20261020')['shared_functions']['engine._request']
    source = compatibility.source_at_epoch(engine._request, 'engine._request', row['predecessor']['sha256'])
    tree = ast.parse(source)
    ordinary = ast.dump(tree, include_attributes=False)
    assert ordinary != row['predecessor_ast']  # Exact observed 3.12/3.13 format difference.
    original_dump = ast.dump
    with compatibility.historical_ast_format() as observations:
        assert ast.dump(tree, include_attributes=False) == row['predecessor_ast']
        changed = ast.parse(source + '\nUNREVIEWED = True\n')
        assert ast.dump(changed, include_attributes=False) == original_dump(changed, include_attributes=False)
        assert ast.dump(changed, include_attributes=False) != row['predecessor_ast']
        # Nondefault output options also remain ordinary standard-library output.
        assert ast.dump(tree, include_attributes=True) == original_dump(tree, include_attributes=True)
    assert ast.dump is original_dump
    assert observations and all(item['different_format'] for item in observations)


def test_rollback_snapshot_retains_only_real_opaque_witness_and_copies_mutables():
    from peaso.azure_function_package_index_20261020 import _Admitted
    from peaso.checks import fixtures
    from peaso.collectors.azure_function_package_runtime_20261020 import CHECK
    tokens = []
    def visit(value):
        if type(value) is _Admitted:
            tokens.append(value)
        elif isinstance(value, dict):
            for child in value.values():
                visit(child)
        elif isinstance(value, (list, tuple)):
            for child in value:
                visit(child)
    visit(fixtures.CASES[CHECK])
    assert tokens
    original = {'opaque': tokens[0], 'mutable': {'values': ['before']}}
    retained = compatibility.snapshot_cases(original)
    assert retained == original and retained['opaque'] is original['opaque']
    assert retained['mutable'] is not original['mutable']
    original['mutable']['values'].append('after')
    assert retained != original and retained['mutable']['values'] == ['before']


def test_historical_policy_body_is_preserved_without_shared_tmp_input():
    retained = compatibility.s3_historical_policy_before()
    assert retained['default_policy']['Version'] == '2012-10-17'
    assert retained['scripts.peaso_deploy_customer_policy:build_policy']['sha256'] == 'a7c4734c2a3c6ffdfc3220e96227a2b8f707d6a7e6cacc47339632002a0ca92d'


def test_final_noop_alias_preserves_exact_cpu_and_three_producer_delta_closure():
    import json
    current = compatibility.active_shared()
    assert current.__name__ in {
        'peaso.checks.collector_noop_authorization_shared_successor_20261020',
        'peaso.checks.azure_metadata_only_shared_successor_20261020',
        'peaso.checks.private_secret_shared_source_successor_20261021'}
    proof = json.loads((compatibility.ROOT / 'peaso/checks' / current.RECEIPT).read_bytes())
    compatibility._noop_native_parent(current, proof)
    assert set(proof['native_epoch_file_deltas']) == {'peaso/checks/__init__.py'}
    delta = proof['native_epoch_file_deltas']['peaso/checks/__init__.py']
    assert delta['exact_additions'] == []
    assert delta['exact_replacements'] == [[
        'from . import native_admission_cpu_shared_successor_20261020 as _deployed_ai_shared_source\n',
        'from . import collector_noop_authorization_shared_successor_20261020 as _deployed_ai_shared_source\n']]
    initializer = (compatibility.ROOT / 'peaso/checks/__init__.py').read_text()
    if 'metadata_only_epoch_file_deltas' in proof:
        from tests.gcp_positive_conservation_epoch_20261020 import metadata_initializer_bytes
        initializer = metadata_initializer_bytes(initializer.encode()).decode()
        initializer = compatibility._reverse(initializer, proof['metadata_only_epoch_file_deltas']['peaso/checks/__init__.py'])
    compatibility._reverse(initializer, delta)
    assert set(proof['producer_file_deltas']) == {
        'peaso/collectors/aws_workload_command_runtime_20261020.py',
        'peaso/collectors/aws_codebuild_buildspec_runtime_20261020.py',
        'peaso/collectors/azure_function_package_integration_20261020.py'}
    for relative, row in proof['producer_file_deltas'].items():
        raw = (compatibility.ROOT / relative).read_bytes()
        if hasattr(current, '_private_before'):
            raw = current._private_before(relative, raw, compatibility.ROOT)
        compatibility._reverse(raw.decode(), row)
    assert current.reviewed_inputs()  # Real production source/code/closure guards run.




@pytest.mark.parametrize('field', ['accepted_native_receipt_sha256', 'prior_bridge_receipt_sha256'])
def test_noop_parent_wrong_prior_receipt_rejected(field):
    import json
    current = compatibility.active_shared()
    proof = json.loads((compatibility.ROOT / 'peaso/checks' / current.RECEIPT).read_bytes())
    proof[field] = '0' * 64
    # Exercise relationship validation directly; no disk/source guard is bypassed.
    with pytest.raises(AssertionError, match='receipt ancestry changed'):
        compatibility._noop_native_parent(current, proof)


@pytest.mark.parametrize('target', ['accepted_native', 'prior_bridge', 'native_prior_bridge'])
def test_noop_parent_pointer_substitution_rejected(monkeypatch, target):
    from types import SimpleNamespace
    current = compatibility.active_shared()
    parent = current.accepted_native if target == 'native_prior_bridge' else current
    attr = 'prior_bridge' if target == 'native_prior_bridge' else target
    real = getattr(parent, attr)
    with monkeypatch.context() as patch:
        patch.setattr(parent, attr, SimpleNamespace(__name__=real.__name__))
        with pytest.raises((AssertionError, RuntimeError), match='parent pointer changed|inherited binding changed'):
            compatibility.active_shared()
    assert compatibility.active_shared() is current




def _metadata_epoch():
    current = compatibility.active_shared()
    assert current.__name__ in {'peaso.checks.azure_metadata_only_shared_successor_20261020',
        'peaso.checks.private_secret_shared_source_successor_20261021'}
    import json
    return current, json.loads((compatibility.ROOT / 'peaso/checks' / current.RECEIPT).read_bytes())






@pytest.mark.parametrize('tamper', ['noop_pointer', 'noop_snapshot', 'sentinel_class', 'collect_pointer'])
def test_metadata_only_parent_snapshot_and_class_identity_rejected(monkeypatch, tamper):
    from types import SimpleNamespace
    from peaso.collectors import azure
    current, _ = _metadata_epoch()
    with monkeypatch.context() as patch:
        if tamper == 'noop_pointer':
            patch.setattr(current, 'accepted_noop', SimpleNamespace(__name__=current.accepted_noop.__name__))
        elif tamper == 'noop_snapshot':
            patch.setattr(current, '_NOOP_FUNCTIONS', {})
        elif tamper == 'sentinel_class':
            patch.setattr(azure, '_MetadataOnlyCollection', type('_MetadataOnlyCollection', (Exception,), {}))
        else:
            def replacement(*args, **kwargs):
                return None
            patch.setattr(azure, 'collect', replacement)
        with pytest.raises((AssertionError, RuntimeError, AdmissionError)):
            compatibility.active_shared()
    assert compatibility.active_shared() is current






@pytest.mark.parametrize('name', [
    'azure_jit_parent_type_shared_successor_20261020',
    'native_admission_cpu_shared_successor_20261020',
    'collector_noop_authorization_shared_successor_20261020',
    'azure_metadata_only_shared_successor_20261020'])
def test_all_four_finite_canonical_aliases_remain_recognized(monkeypatch, name):
    import importlib
    import peaso.checks as checks
    canonical = importlib.import_module('peaso.checks.' + name)
    with monkeypatch.context() as patch:
        patch.setattr(checks, 'azure_function_package_shared_successor_20261020', canonical)
        assert compatibility.active_shared() is canonical
