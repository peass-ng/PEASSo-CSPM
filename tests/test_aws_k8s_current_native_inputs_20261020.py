"""Conservation, mutation and exact predecessor proofs for the finite test layer."""
from copy import deepcopy
import hashlib
from pathlib import Path
import pytest
from tests.aws_k8s_current_native_inputs_20261020 import (
    OWNED_TESTS, case_state, exact_test_predecessor)
ROOT = Path(__file__).resolve().parents[1]






@pytest.mark.parametrize('mutation', ['snapshot', 'expected', 'scope', 'identity'])
def test_case_state_checks_all_opaque_owner_fields_and_exact_identity(mutation):
    from peaso import azure_function_package_index_20261020 as owner
    token = owner._Admitted({'collections': []}, {'scope': 'a'}, 'a')
    value = {'pass_index': {owner.INDEX_KEY: token}, 'ordinary': {'values': [1, 2]}}
    before = case_state(value)
    assert case_state(value) == before
    if mutation == 'snapshot': token.snapshot['collections'].append({'unexpected': True})
    elif mutation == 'expected': token.expected['scope'] = 'other'
    elif mutation == 'scope': token.scope = 'other'
    else: value['pass_index'][owner.INDEX_KEY] = owner._Admitted(token.snapshot, token.expected, token.scope)
    assert case_state(value) != before


def test_case_state_does_not_hide_nested_ordinary_fixture_mutation():
    value = {'case': {'item': {'flags': [False, 0, '0']}}}
    before = case_state(value)
    value['case']['item']['flags'][0] = 'false'
    assert before != case_state(value)
