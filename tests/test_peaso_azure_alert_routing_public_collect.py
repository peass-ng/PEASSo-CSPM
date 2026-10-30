"""Public hosted input -> native ARM transport fixture -> routing control."""
from copy import deepcopy
from types import SimpleNamespace
from urllib.parse import urlsplit
import pytest

from peaso.collectors import azure, collect_live
from peaso.engine import evaluate_snapshot
from peaso.server.validation import validate_connector
from peaso.checks.compliance_new_sw25_facts import ROUTING_ID
from tests.test_peaso_azure_alert_routing_native import native, CONTRACTS, SCOPE


@pytest.mark.parametrize('kind', CONTRACTS)
@pytest.mark.parametrize('groups,expected', [(True, 'PASS'), (False, 'FAIL'), (None, 'UNKNOWN')])
def test_public_native_collect_routes_without_owner_observations(monkeypatch, kind, groups, expected):
    calls, closed = [], []
    class Transport:
        tenant = verified_tenant = '22222222-2222-2222-2222-222222222222'
        def close(self): closed.append(True)
        def request(self, url, *, body=None, audience=azure.ARM):
            assert audience == azure.ARM
            path = urlsplit(url).path
            calls.append((url, body))
            if path == '/providers/Microsoft.ResourceGraph/resources':
                assert isinstance(body, dict)
                return {'data': [], 'resultTruncated': False}
            assert body is None
            for family, (native_type, _) in CONTRACTS.items():
                if path == SCOPE + '/providers/' + native_type:
                    raw = deepcopy(native(kind, groups is not False))
                    if groups is None:
                        raw['properties']['actions'] = None
                    return {'value': [raw] if family == kind else []}
            if path == native(kind)['id'] + '/providers/Microsoft.Insights/diagnosticSettings':
                return {'value': []}  # Existing shared diagnostic enrichment.
            raise AssertionError('Unexpected endpoint: ' + path)
    monkeypatch.setattr(azure, 'AzureTransportExposure', lambda auth: Transport())
    auth = {'method': 'token', 'arm_token': 'inert-fixture'}
    options = {'concurrency': 1, 'retries': 1}
    validate_connector('azure', auth, options, SimpleNamespace(auth_mode='cognito'))
    snapshot = collect_live({'provider': 'azure', 'scopes': [SCOPE], 'auth': auth, 'options': options}, set(CONTRACTS))
    assert closed == [True]
    rows = next(c['items'] for c in snapshot['collections'] if c['type'] == kind)
    assert len(rows) == 1
    if groups is None:
        assert rows[0]['_routing_provenance']['status'] == 'unavailable'
    else:
        assert rows[0]['_routing_provenance']['read_only'] is True
        assert rows[0]['_routing_provenance']['semantics'] == 'configured_routing_only'
    findings = evaluate_snapshot(snapshot, checks=[ROUTING_ID])['findings']
    assert next(f['status'] for f in findings if f['check_id'] == ROUTING_ID) == expected
    expected_lists = {SCOPE + '/providers/' + contract[0] for contract in CONTRACTS.values()}
    observed_lists = [urlsplit(url).path for url, _ in calls if urlsplit(url).path in expected_lists]
    assert len(observed_lists) == 3 and set(observed_lists) == expected_lists
    assert all(body is None for url, body in calls if urlsplit(url).path != '/providers/Microsoft.ResourceGraph/resources')
