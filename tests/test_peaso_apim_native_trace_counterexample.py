"""Native APIM negative configuration evidence; no credentials or network probes."""
from copy import deepcopy
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit
import json
import pytest

from peaso.collectors import azure, collect_live, azure_apim_native, azure_apim_diagnostics_native
from peaso.engine import plan_collection
from peaso.server.validation import validate_connector
from peaso.snapshot import make_snapshot
from peaso.collectors import azure_apim_diagnostic_evidence_native as native
from peaso.collectors.azure_apim_diagnostic_evidence_native import CID, KIND

SCOPE = '/subscriptions/11111111-1111-1111-1111-111111111111'
SERVICE = SCOPE + '/resourceGroups/rg/providers/Microsoft.ApiManagement/service/native'
API = SERVICE + '/apis/orders'
LOGGER = SERVICE + '/loggers/insights'
PRIVATE = 'NEVER_RETAIN_LOGGER_CREDENTIALS_OR_BODY'


@pytest.mark.parametrize('mode,expected', [('no_diag', 'FAIL'), ('deleted_logger', 'FAIL'),
    ('configured', 'UNKNOWN'), ('unrelated_logger', 'FAIL'), ('one_existing', 'UNKNOWN'),
    ('missing_type', 'UNKNOWN'), ('partial_api', 'UNKNOWN'), ('revision_denied', 'UNKNOWN'),
    ('diag_denied', 'UNKNOWN'), ('logger_denied', 'UNKNOWN'), ('foreign_api', 'UNKNOWN'),
    ('duplicate_api', 'UNKNOWN'), ('foreign_diag', 'UNKNOWN'), ('foreign_ref', 'UNKNOWN'),
    ('duplicate_diag', 'UNKNOWN'), ('missing_sampling', 'UNKNOWN'), ('missing_always', 'UNKNOWN'),
    ('boolean_sampling', 'UNKNOWN'), ('no_apis', 'NOT_APPLICABLE'), ('soap_only', 'NOT_APPLICABLE')])
def test_normal_hosted_native_configuration_counterexamples(monkeypatch, mode, expected):
    parent = {'id': SERVICE, 'type': 'Microsoft.ApiManagement/service', 'properties': {}}
    api = {'id': API, 'properties': {'type': 'soap' if mode == 'soap_only' else 'http',
        'protocols': ['https'], 'isCurrent': True, 'apiRevision': '1'}}
    if mode == 'missing_type': api['properties'].pop('type')
    if mode == 'foreign_api': api['id'] = SERVICE + 'foreign/apis/orders'
    logger = {'id': LOGGER, 'properties': {'loggerType': 'applicationInsights',
        'credentials': {'instrumentationKey': PRIVATE, 'connectionString': PRIVATE}}}
    diagnostic = {'id': API + '/diagnostics/applicationinsights', 'properties': {
        'loggerId': LOGGER, 'sampling': {'samplingType': 'fixed', 'percentage': 100}, 'alwaysLog': None,
        'frontend': {'request': {'headers': [PRIVATE], 'body': {'bytes': 0}}}}}
    if mode == 'foreign_diag': diagnostic['id'] = SERVICE + '/apis/other/diagnostics/applicationinsights'
    if mode == 'foreign_ref': diagnostic['properties']['loggerId'] = SERVICE + 'foreign/loggers/insights'
    if mode == 'missing_sampling': diagnostic['properties'].pop('sampling')
    if mode == 'missing_always': diagnostic['properties'].pop('alwaysLog')
    if mode == 'boolean_sampling': diagnostic['properties']['sampling']['percentage'] = True
    diagnostics = [] if mode in ('no_diag', 'unrelated_logger', 'soap_only') else [deepcopy(diagnostic)]
    loggers = [] if mode == 'deleted_logger' else [deepcopy(logger)]
    if mode == 'one_existing':
        diagnostics.append({**deepcopy(diagnostic), 'id': API + '/diagnostics/deleted',
            'properties': {**diagnostic['properties'], 'loggerId': SERVICE + '/loggers/deleted'}})
    if mode == 'duplicate_diag': diagnostics.append(deepcopy(diagnostic))
    api_rows = [] if mode == 'no_apis' else [api]
    if mode == 'duplicate_api': api_rows.append(deepcopy(api))
    calls, closed = [], []
    class Transport:
        tenant = verified_tenant = '22222222-2222-2222-2222-222222222222'
        def close(self): closed.append(True)
        def request(self, url, *, body=None, audience=azure.ARM):
            calls.append((url, deepcopy(body)))
            path = urlsplit(url).path
            assert audience == azure.ARM
            if path == '/providers/Microsoft.ResourceGraph/resources':
                assert isinstance(body, dict)
                return {'data': [], 'resultTruncated': False}
            assert body is None
            if path == '/subscriptions':
                return {'value': [{'id': SCOPE, 'subscriptionId': SCOPE.rsplit('/', 1)[1], 'tenantId': self.tenant, 'state': 'Enabled'}]}
            if path == SCOPE: return {'id': SCOPE, 'subscriptionId': SCOPE.rsplit('/', 1)[1], 'tenantId': self.tenant, 'state': 'Enabled'}
            if path == SCOPE + '/providers/Microsoft.ApiManagement/service': return {'value': [deepcopy(parent)]}
            if path == SERVICE: return deepcopy(parent)
            if path == SERVICE + '/providers/Microsoft.Insights/diagnosticSettings': return {'value': []}
            if path == SERVICE + '/apis':
                if mode == 'partial_api' and 'page' in parse_qs(urlsplit(url).query): raise azure.AzureReadError('fixture_denied', 403)
                return {'value': deepcopy(api_rows), **({'nextLink': azure.ARM + SERVICE + '/apis?api-version=2024-05-01&page=2'} if mode == 'partial_api' else {})}
            if path == SERVICE + '/loggers':
                if mode == 'logger_denied': raise azure.AzureReadError('fixture_denied', 403)
                return {'value': deepcopy(loggers)}
            if path == SERVICE + '/diagnostics': return {'value': []}
            if path == API + '/revisions':
                if mode == 'revision_denied': raise azure.AzureReadError('fixture_denied', 403)
                return {'value': [{'apiId': API, 'isOnline': True, 'isCurrent': True}]}
            if path == API + '/diagnostics':
                if mode == 'diag_denied': raise azure.AzureReadError('fixture_denied', 403)
                return {'value': deepcopy(diagnostics)}
            raise AssertionError('Unexpected endpoint: ' + path)
    monkeypatch.setattr(azure, 'AzureTransportExposure', lambda auth: Transport())
    auth, options = {'method': 'token', 'arm_token': 'inert-fixture'}, {'concurrency': 1, 'retries': 1}
    validate_connector('azure', auth, options, SimpleNamespace(auth_mode='cognito'))
    connector = {'provider': 'azure', 'scopes': [SCOPE], 'auth': auth, 'options': options}
    with pytest.raises(ValueError, match='requires external policy or manual evidence'):
        plan_collection({'connector': connector, 'checks': [CID]})
    required = {'api_management', KIND}
    snapshot = collect_live(connector, required)
    inventories = {kind: {row['id'].casefold(): row for collection in snapshot['collections']
                   if collection['type'] == kind for row in collection['items']}
                   for kind in ('api_management', native.SOURCE, KIND)}
    status, _ = native.assess(SERVICE.casefold(), snapshot, inventories[KIND],
                              inventories[native.SOURCE], inventories['api_management'])
    assert status == expected
    assert PRIVATE not in json.dumps(snapshot) and closed == [True]
    evidence = next(c for c in snapshot['collections'] if c['type'] == KIND)
    for row in evidence['items']:
        assert row['_provenance']['captured_at'] == snapshot['created_at']
        assert row['_coverage']['loggerCredentialUsability']['status'] == 'not_collected'
        assert 'credentials_measured' not in json.dumps(row) and 'policy_approved' not in json.dumps(row)
    paths = [urlsplit(url).path for url, body in calls]
    assert paths.count(SERVICE + '/apis') == (2 if mode == 'partial_api' else 1)
    assert all(paths.count(path) == 1 for path in (SERVICE + '/loggers', SERVICE + '/diagnostics', API + '/revisions', API + '/diagnostics') if path in paths)
    assert all(urlsplit(url).hostname == 'management.azure.com' for url, body in calls)


def test_native_api_type_is_parallel_and_keeps_established_sw24_digest():
    raw = {'id': API, 'properties': {'protocols': ['https'], 'apiRevision': '1', 'isCurrent': True}}
    before = azure_apim_native._api(raw, API)
    raw['properties']['type'] = 'http'
    after = azure_apim_native._api(raw, API)
    assert after['apiType'] == 'http' and after['_provenance']['api_type_source'] == 'properties.type'
    assert before['properties'] == after['properties']
    def configuration(api): return azure_apim_diagnostics_native.configuration({'id': SERVICE, 'apis': [api]})
    assert azure_apim_diagnostics_native.digest(configuration(before)) == azure_apim_diagnostics_native.digest(configuration(after))
