"""Current shared transport and dedicated adapter reject preserved risk inputs.

Original acceptance assertions/report remain byte-for-byte in the compressed
predecessor fixture; registered SAS impact is tested in the new fix matrix.
"""
import io
import json
import socket
import pytest
from peaso.collectors import azure
from peaso.collectors import azure_nsp_query_cmk_metadata_proposal_20261020 as producer

URL = azure.ARM + '/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/review/providers/Microsoft.Storage/storageAccounts/storageone?api-version=2023-05-01'


@pytest.mark.parametrize('mode', ['http206', 'duplicate_deciding_key'])
def test_current_transport_and_strict_adapter_reject_preserved_risks(monkeypatch, mode):
    def blocked(*a, **kw): raise AssertionError('network/DNS/auth forbidden')
    for owner, names in ((socket, ('create_connection', 'getaddrinfo', 'gethostbyname', 'gethostbyname_ex')),
                         (socket.socket, ('connect', 'connect_ex', 'sendto')), (azure, ('credential_for',))):
        for name in names: monkeypatch.setattr(owner, name, blocked)
    raw = b'{"properties":{"encryption":{"keySource":"Microsoft.Keyvault"}}}'
    if mode == 'duplicate_deciding_key':
        raw = b'{"properties":{"encryption":{"keySource":"Microsoft.Storage","keySource":"Microsoft.Keyvault"}}}'
    calls = []
    class Opener:
        def open(self, request, timeout):
            assert request.full_url == URL and request.get_method() == 'GET' and request.data is None
            assert request.get_header('Authorization') == 'Bearer INERT_RISK_FIXTURE'
            calls.append(request.full_url)
            response = io.BytesIO(raw);response.status = 206 if mode == 'http206' else 200
            return response
    monkeypatch.setattr(azure, 'build_opener', lambda *a: Opener())
    transport = azure.AzureTransport({'method': 'token', 'arm_token': 'INERT_RISK_FIXTURE'})
    with pytest.raises((ValueError, azure.AzureReadError)):
        transport.request(URL, max_response_bytes=producer.MAX_BYTES)
    with pytest.raises(ValueError): producer.metadata_get(transport, URL)
    # A complete 200 body is shared through the per-scan response cache, so the
    # strict adapter re-parses it without a second wire read; partial responses
    # are never cached and are read again.
    assert calls == ([URL, URL] if mode == 'http206' else [URL])
