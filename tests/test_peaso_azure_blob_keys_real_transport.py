"""Public planner through real JSON/XML transports to the native key verdict."""
from copy import deepcopy
import io
import json
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit
import xml.etree.ElementTree as ET

import pytest

from peaso.collectors import azure, collect_live
from peaso.collectors import azure_blob_inventory_xml as xml
from peaso.engine import evaluate_snapshot, plan_collection
from peaso.server.validation import validate_connector
from tests.test_peaso_azure_storage_blob_keys_native import fixture, SCOPE, ACCOUNT, CONTAINER, ES, EP, PRIVATE, native


def _public_capture(monkeypatch, duplicate_kind=None, arm_etags=True):
    account, containers, scopes, _ = fixture('cmk')
    if not arm_etags:  # real ARM GETs of accounts and encryption scopes carry no etag
        account.pop('etag'); [scope.pop('etag') for scope in scopes]
    calls = []
    class Response(io.BytesIO):
        status = 200  # native transport accepts only documented 200 representations
        def __enter__(self): return self
        def __exit__(self, *args): self.close()
    class Opener:
        def open(self, request, timeout):
            parsed = urlsplit(request.full_url)
            path = parsed.path.casefold()
            calls.append((request.get_method(), parsed.netloc, parsed.path))
            assert timeout == 20
            if parsed.netloc == 'account.blob.core.windows.net':
                assert request.get_method() == 'GET' and request.data is None
                if parsed.path == '/':
                    # Existing storage enrichment also reads legacy Analytics
                    # properties. Keep that separate from the new Blob list.
                    assert parse_qs(parsed.query) == {'restype': ['service'], 'comp': ['properties']}
                    return Response(b'<StorageServiceProperties><Logging><Read>true</Read><Write>true</Write><Delete>true</Delete></Logging></StorageServiceProperties>')
                assert parsed.path == '/data'
                assert request.get_header('X-ms-version') == xml.API_VERSION
                assert parse_qs(parsed.query)['include'] == [xml.INCLUDE]
                root = ET.Element('EnumerationResults', ServiceEndpoint=EP, ContainerName='data')
                ET.SubElement(root, 'Marker'); ET.SubElement(root, 'MaxResults').text = '500'
                blob = ET.SubElement(ET.SubElement(root, 'Blobs'), 'Blob')
                ET.SubElement(blob, 'Name').text = PRIVATE
                props = ET.SubElement(blob, 'Properties')
                ET.SubElement(props, 'ServerEncrypted').text = 'true'
                ET.SubElement(props, 'EncryptionScope').text = 'customer'
                ET.SubElement(ET.SubElement(blob, 'Metadata'), 'private').text = PRIVATE
                ET.SubElement(root, 'NextMarker')
                return Response(ET.tostring(root, encoding='utf-8'))
            assert parsed.netloc == 'management.azure.com'
            if request.data is not None:
                assert request.get_method() == 'POST' and path == '/providers/microsoft.resourcegraph/resources'
                value = {'data': [], 'resultTruncated': False}
            else:
                assert request.get_method() == 'GET'
                if path == (SCOPE + '/providers/Microsoft.Storage/storageAccounts').casefold():
                    value = {'value': [deepcopy(account)] * (2 if duplicate_kind == 'account' else 1)}
                elif path == ACCOUNT.casefold(): value = deepcopy(account)
                elif path == (ACCOUNT + '/blobServices/default/containers').casefold(): value = {'value': deepcopy(containers) * (2 if duplicate_kind == 'container' else 1)}
                elif path == (ACCOUNT + '/encryptionScopes').casefold(): value = {'value': deepcopy(scopes) * (2 if duplicate_kind == 'scope' else 1)}
                elif path == CONTAINER.casefold(): value = deepcopy(containers[0])
                elif path == ES.casefold(): value = deepcopy(scopes[0])
                else:
                    assert path.startswith(ACCOUNT.casefold() + '/'), path
                    assert all(word not in path for word in ('listkeys', 'listaccountsas', 'getuserdelegationkey'))
                    value = {'value': []}
            return Response(json.dumps(value).encode())
    def token(self, audience):
        assert audience in (azure.ARM, azure.STORAGE)
        return 'inert-fixture-token'
    monkeypatch.setattr(azure.AzureTransport, 'token', token)
    monkeypatch.setattr(azure, 'build_opener', lambda policy: Opener())
    auth = {'method': 'token', 'arm_token': 'inert', 'storage_token': 'inert'}
    options = {'retries': 1}
    validate_connector('azure', auth, options, SimpleNamespace(auth_mode='cognito'))
    connector = {'provider': 'azure', 'scopes': [SCOPE], 'auth': auth, 'options': options}
    requirements = plan_collection({'connector': connector, 'checks': [native.CID]})
    snapshot = collect_live(connector, requirements)
    results = evaluate_snapshot(snapshot, checks=[native.CID], include_not_applicable=True)['findings']
    assert results and {r['status'] for r in results} == {'UNKNOWN' if duplicate_kind else 'PASS'}, (results,
        [(c['type'], c['status'], c.get('error')) for c in snapshot['collections']], calls)
    assert PRIVATE not in json.dumps(snapshot)
    assert sum(host == 'account.blob.core.windows.net' and path == '/data' for method, host, path in calls) == (0 if duplicate_kind else 1)
    if duplicate_kind:
        source_type = {'account': 'storage_account', 'container': 'storage_container', 'scope': 'storage_encryption_scope'}[duplicate_kind]
        source = next(c for c in snapshot['collections'] if c['type'] == source_type)
        assert source['status'] == 'partial'
    assert sum(host == 'account.blob.core.windows.net' and path == '/' for method, host, path in calls) == 1
    assert all(method == 'GET' or path == '/providers/Microsoft.ResourceGraph/resources' for method, host, path in calls)


def test_real_transport_projects_blob_xml_before_public_evaluation(monkeypatch):
    _public_capture(monkeypatch)


@pytest.mark.parametrize('duplicate_kind', ['account', 'container', 'scope'])
def test_duplicate_native_arm_lists_are_partial_before_key_projection(monkeypatch, duplicate_kind):
    _public_capture(monkeypatch, duplicate_kind)


def test_account_and_scope_without_arm_etag_still_reach_a_verdict(monkeypatch):
    _public_capture(monkeypatch, arm_etags=False)
