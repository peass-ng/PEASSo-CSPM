"""The parity receipt may discard only generated scan identity/read times."""
import copy
import importlib.util
from pathlib import Path

import pytest

SPEC = importlib.util.spec_from_file_location('multicloud_envelope_compare',
    Path(__file__).resolve().parents[1] / 'docs/multicloud-test/compare_azure_collection_envelopes.py')
comparison = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(comparison)


def fixture():
    return {'collections': [{'type': 'security_admin_rule', 'scope': 'scope',
        'status': 'collected', 'items': [{'properties': {'observed_at': 'native-time'}}],
        '_provenance': {'credential_context_id': 'first'},
        'source_evidence': [{'source_operation': 'listNetworkManagerEffectiveSecurityAdminRules',
            'read_only': True, 'representation': 'full', 'observed_at': 'local-time',
            'response_sha256': 'exact-response-hash'}]}]}


def test_generated_context_and_typed_local_read_times_may_differ():
    before = fixture(); after = copy.deepcopy(before)
    after['collections'][0]['_provenance']['credential_context_id'] = 'second'
    after['collections'][0]['source_evidence'][0]['observed_at'] = 'later-local-time'
    assert comparison.compare(before, after)['complete_collection_envelopes_equal']


@pytest.mark.parametrize('field', ['native_time', 'response_hash', 'status', 'untyped_time'])
def test_native_facts_and_untyped_timestamps_cannot_be_hidden(field):
    before = fixture(); after = copy.deepcopy(before); row = after['collections'][0]
    if field == 'native_time':
        row['items'][0]['properties']['observed_at'] = 'different-native-time'
    elif field == 'response_hash':
        row['source_evidence'][0]['response_sha256'] = 'different-response'
    elif field == 'status':
        row['status'] = 'partial'
    else:
        before['collections'][0]['source_evidence'][0]['source_operation'] = 'unknown-operation'
        row['source_evidence'][0]['source_operation'] = 'unknown-operation'
        row['source_evidence'][0]['observed_at'] = 'different-untyped-time'
    assert not comparison.compare(before, after)['complete_collection_envelopes_equal']
