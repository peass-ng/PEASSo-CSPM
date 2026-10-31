"""A Graph parent inventory the identity may not read leaves dependents unknown, not malformed."""
import pytest

from peaso.collectors import azure, azure_conditional_access_native, azure_sw18_mfa_native
from tests.test_peaso_azure_bulk_native import Transport

SCOPE = '/tenants/' + Transport.tenant


def _denied(kind):
    return {'type': kind, 'scope': SCOPE, 'service': 'Microsoft.Graph', 'status': 'denied',
            'items': [], 'error': {'code': '403', 'kind': 'HTTPError'}}


@pytest.mark.parametrize('kind', ['conditional_access_risk_entitlement', 'conditional_access_group_membership'])
def test_conditional_access_dependents_of_a_denied_policy_read_are_unknown(kind):
    api = Transport({})
    reader = azure._Reader({'retries': 0})
    reader.collections.append(_denied('conditional_access_policy'))
    azure_conditional_access_native.collect(reader, api.request, {kind}, api)
    result = [c for c in reader.collections if c['type'] == kind]
    assert [c['status'] for c in result] == ['unknown']
    assert api.calls == []


def test_mfa_evidence_with_a_denied_user_read_is_unknown():
    api = Transport({})
    reader = azure._Reader({'retries': 0})
    reader.collections.append(_denied('directory_user'))
    azure_sw18_mfa_native.collect(reader, api.request, {'azure_sw18_evidence'}, api, 'ctx', 'customer')
    result = [c for c in reader.collections if c['type'] == 'azure_sw18_evidence']
    assert [c['status'] for c in result] == ['unknown']
