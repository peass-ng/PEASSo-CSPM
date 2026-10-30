"""Normal public path exports current metadata, never fabricated triage history."""
from copy import deepcopy
from datetime import datetime, timezone
import json
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit
import pytest

from peaso.collectors import azure, collect_live
from tests.archived_check_contract import evaluate_snapshot, plan_collection
from peaso.server.validation import validate_connector
from tests.test_peaso_azure_bulk_native import SCOPE, BASE, parent

CHECK = 'azure.other.incident_triage_trace'
WORKSPACE = BASE + 'Microsoft.OperationalInsights/workspaces/security'
ONBOARD = WORKSPACE + '/providers/Microsoft.SecurityInsights/onboardingStates'
INCIDENTS = WORKSPACE + '/providers/Microsoft.SecurityInsights/incidents'
FIRST = INCIDENTS + '/11111111-2222-3333-4444-555555555555'
SECOND = INCIDENTS + '/66666666-7777-8888-9999-000000000000'
WORKSPACES = SCOPE + '/providers/Microsoft.OperationalInsights/workspaces'
GRAPH = '/providers/Microsoft.ResourceGraph/resources'
PRIVATE = 'NEVER_STORE_INCIDENT_BODY_OR_OWNER'


@pytest.mark.parametrize('mode,state,count', [('complete', 'collected', 1), ('type_omitted', 'collected', 1),
    ('pagination', 'collected', 2), ('partial', 'partial', 1), ('duplicate', 'partial', 1),
    ('denied', 'denied', 0), ('foreign_workspace', 'malformed', 0), ('foreign_incident', 'malformed', 0),
    ('wrong_type', 'malformed', 0), ('null_type', 'malformed', 0), ('missing_created', 'malformed', 0),
    ('invalid_severity', 'malformed', 0), ('empty', 'not_collected', 0), ('not_onboarded', 'not_collected', 0),
    ('no_workspace', 'not_collected', 0)])
def test_hosted_native_incidents_reuse_sentinel_traversal(monkeypatch, mode, state, count):
    row = {'id': FIRST, 'type': 'Microsoft.SecurityInsights/incidents', 'properties': {
        'createdTimeUtc': datetime.now(timezone.utc).isoformat(), 'status': 'Closed', 'severity': 'High',
        'title': PRIVATE, 'description': PRIVATE, 'owner': {'email': PRIVATE}, 'comments': [PRIVATE],
        'entities': [PRIVATE], 'triageHistoryComplete': True, 'triageHistory': [{'type': 'triage', 'at': PRIVATE}]}}
    if mode == 'type_omitted': row.pop('type')
    if mode == 'wrong_type': row['type'] = 'Microsoft.Security/incidents'
    if mode == 'null_type': row['type'] = None
    if mode == 'missing_created': row['properties'].pop('createdTimeUtc')
    if mode == 'invalid_severity': row['properties']['severity'] = 'Bogus'
    if mode == 'foreign_incident': row['id'] = FIRST.replace('/workspaces/security/', '/workspaces/foreign/')
    workspace = parent(WORKSPACE, 'Microsoft.OperationalInsights/workspaces', {})
    if mode == 'foreign_workspace': workspace['id'] = WORKSPACE.replace(SCOPE, '/subscriptions/33333333-3333-3333-3333-333333333333')
    calls, closed = [], []
    class Transport:
        tenant = verified_tenant = '22222222-2222-2222-2222-222222222222'
        def close(self): closed.append(True)
        def request(self, url, *, body=None, audience=azure.ARM):
            calls.append((url, deepcopy(body)))
            parsed = urlsplit(url); path, query = parsed.path, parse_qs(parsed.query)
            assert audience == azure.ARM
            if path == GRAPH:
                assert isinstance(body, dict)
                return {'data': [], 'resultTruncated': False}
            assert body is None
            if path == WORKSPACES: return {'value': [] if mode == 'no_workspace' else [deepcopy(workspace)]}
            if path == ONBOARD:
                return {'value': [] if mode == 'not_onboarded' else [{'id': ONBOARD + '/default', 'properties': {}}]}
            if path == INCIDENTS:
                if mode == 'denied' or mode == 'partial' and 'page' in query:
                    raise azure.AzureReadError('fixture_incident_denied', 403)
                assert query.get('api-version') == ['2025-09-01']
                if 'page' in query:
                    other = deepcopy(row); other['id'] = SECOND
                    return {'value': [other]}
                values = [] if mode == 'empty' else [deepcopy(row)]
                if mode == 'duplicate': values.append(deepcopy(row))
                return {'value': values, **({'nextLink': azure.ARM + INCIDENTS + '?api-version=2025-09-01&page=2'}
                    if mode in ('pagination', 'partial') else {})}
            raise AssertionError('Unexpected endpoint: ' + path)
    monkeypatch.setattr(azure, 'AzureTransport', lambda auth: Transport())
    monkeypatch.setattr(azure, 'AzureTransportExposure', lambda auth: Transport())
    auth = {'method': 'token', 'arm_token': 'inert-fixture'}
    options = {'concurrency': 1, 'retries': 1, 'compliance_policy': {'sw27': {
        'status': 'collected', 'scope': SCOPE, 'incidentTriage': {
            'approvedTriageHours': 1, 'observationWindowHours': 24, 'requiredResponseSteps': ['ack']}}}}
    validate_connector('azure', auth, options, SimpleNamespace(auth_mode='cognito'))
    connector = {'provider': 'azure', 'scopes': [SCOPE], 'auth': auth, 'options': options}
    required = plan_collection({'connector': connector, 'checks': [CHECK]})
    assert required == ['defender_incident']
    snapshot = collect_live(connector, required)
    result = next(c for c in snapshot['collections'] if c['type'] == 'defender_incident')
    assert result['status'] == state and len(result['items']) == count
    assert PRIVATE not in json.dumps(snapshot)
    assert closed == [True]
    findings = evaluate_snapshot(snapshot, checks=[CHECK], include_not_applicable=True)['findings']
    assert findings and all(f['status'] == ('DENIED' if state == 'denied' else 'UNKNOWN') for f in findings)
    for incident in result['items']:
        assert incident['type'] == 'Microsoft.SecurityInsights/incidents' and incident['parent_id'] == WORKSPACE
        assert set(incident['properties']) == {'createdTimeUtc', 'status', 'severity'}
        assert incident['_coverage']['triageHistory']['status'] == 'not_collected'
        assert 'triageHistoryComplete' not in incident and 'triageHistory' not in incident
        assert incident['_provenance']['api_version'] == '2025-09-01'
    if state == 'collected': assert 'triageHistory' in json.dumps(findings)
    paths = [urlsplit(url).path for url, body in calls]
    assert set(paths) <= {GRAPH, WORKSPACES, ONBOARD, INCIDENTS}
    assert paths.count(WORKSPACES) == 1
    assert paths.count(INCIDENTS) == (2 if mode in ('pagination', 'partial') else
        0 if mode in ('foreign_workspace', 'not_onboarded', 'no_workspace') else 1)
