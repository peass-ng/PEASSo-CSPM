"""The CASES snapshot helper keeps opaque witnesses and copies mutable content."""
from tests import shared_admission_epoch_compatibility_20261020 as compatibility


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
