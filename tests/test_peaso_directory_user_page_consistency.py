"""Directory-user fallbacks cannot erase contradictory pagination evidence."""
from urllib.parse import urlsplit, parse_qs
import pytest
from peaso.collectors import azure
from test_peaso_mfa_native_direct_user_partitions import PartitionAPI, collect, row, assert_status, U1, U2


@pytest.mark.parametrize('mode', ['fallback-conflict', 'partial-primary', 'valid-fallback'])
def test_user_fallback_retains_complete_identity_semantics(monkeypatch, mode):
    original = PartitionAPI.request
    def request(self, url, *, body=None, audience=azure.ARM):
        if urlsplit(url).path != '/v1.0/users':
            return original(self, url, body=body, audience=audience)
        self.calls.append((url, audience, body))
        params = parse_qs(urlsplit(url).query)
        enhanced = 'signInActivity' in params.get('$select', [''])[0]
        second = '$skiptoken' in params
        if enhanced:
            if mode != 'partial-primary' or second:
                raise azure.AzureReadError('inert_signin_permission', 403)
            return {'value': [{'id': U1, 'accountEnabled': True}, {'id': U2, 'accountEnabled': False}],
                    '@odata.nextLink': azure.GRAPH + '/v1.0/users?$select=id,accountEnabled,signInActivity&$skiptoken=next'}
        if mode == 'valid-fallback':
            return {'value': [{'id': U1, 'accountEnabled': True}, {'id': U2, 'accountEnabled': True}]}
        if mode == 'partial-primary':
            return {'value': [{'id': U1, 'accountEnabled': True}]}
        if second:
            return {'value': [{'id': U2, 'accountEnabled': True}]}
        return {'value': [{'id': U1, 'accountEnabled': True}, {'id': U2, 'accountEnabled': False}],
                '@odata.nextLink': azure.GRAPH + '/v1.0/users?$skiptoken=next'}
    monkeypatch.setattr(PartitionAPI, 'request', request)
    # collect() constructs AzureTransportExposure; route it to the fixture installed as AzureTransport.
    monkeypatch.setattr(azure, 'AzureTransportExposure', lambda auth: azure.AzureTransport(auth))
    policies = [row('only-a', [U1])]
    if mode == 'valid-fallback':
        policies.append(row('also-b', [U2]))
    assert_status(collect(monkeypatch, policies), 'PASS' if mode == 'valid-fallback' else 'UNKNOWN')
