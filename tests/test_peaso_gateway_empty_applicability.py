"""Only a scoped explicitly EMPTY gateway roster bypasses irrelevant evidence."""
from copy import deepcopy
from urllib.parse import urlsplit

import pytest

from peaso.checks import CHECKS
from peaso.collectors import azure, collect_live
from peaso.snapshot import make_snapshot
from tests.test_peaso_gateway_empty_alerts_counterexample import capture, verdict, GATEWAY_ID, SCOPE, NOW


@pytest.mark.parametrize('history', ['missing', 'denied', 'partial'])
def test_explicit_empty_gateway_inventory_needs_no_policy_or_child_evidence(history):
    snapshot = capture(history=history, gateway=False)
    snapshot['metadata'] = {}
    assert verdict(make_snapshot('azure', [SCOPE], snapshot['collections'], metadata={}, created_at=NOW.isoformat())) == 'NOT_APPLICABLE'
    check = next(c for c in CHECKS if c.id == GATEWAY_ID)
    assert check.empty_applicability_dependencies == ('application_gateway',)
    assert check.allow_incomplete_failure is True


@pytest.mark.parametrize('mode', ['populated', 'partial', 'denied', 'collected_empty', 'foreign_scope'])
def test_unproven_empty_gateway_inventory_never_becomes_not_applicable(mode):
    snapshot = capture(history='denied', gateway=mode == 'populated')
    parent = snapshot['collections'][0]
    if mode in ('partial', 'denied'): parent['status'] = mode
    elif mode == 'collected_empty': parent['status'] = 'collected'
    elif mode == 'foreign_scope': parent['scope'] = SCOPE.replace('1111', '2222')
    sealed = make_snapshot('azure', [SCOPE], snapshot['collections'], metadata={}, created_at=NOW.isoformat())
    assert verdict(sealed) != 'NOT_APPLICABLE'


def test_public_empty_gateway_roster_is_not_applicable_despite_denied_alerts_and_no_policy(monkeypatch):
    calls, closed = [], []
    class Transport:
        tenant = verified_tenant = '22222222-2222-2222-2222-222222222222'
        def close(self): closed.append(True)
        def request(self, url, *, body=None, audience=azure.ARM):
            assert audience == azure.ARM
            calls.append((url, deepcopy(body)))
            path = urlsplit(url).path
            assert 'backendhealth' not in path.casefold()
            if '/resourcegraph/' in path.casefold():
                return {'data': [], 'resultTruncated': False}
            assert body is None
            if 'microsoft.insights' in path.casefold(): raise azure.AzureReadError('inert_forbidden', 403)
            return {'value': []}
    monkeypatch.setattr(azure, 'AzureTransport', lambda auth: Transport());monkeypatch.setattr(azure,'AzureTransportExposure',lambda auth: Transport())
    check = next(c for c in CHECKS if c.id == GATEWAY_ID)
    snapshot = collect_live({'provider': 'azure', 'scopes': [SCOPE],
        'auth': {'method': 'token', 'arm_token': 'inert-fixture'}, 'options': {'retries': 0, 'concurrency': 1}}, check.dependencies)
    assert next(c for c in snapshot['collections'] if c['type'] == 'application_gateway')['status'] == 'empty'
    assert any(c['status'] == 'denied' for c in snapshot['collections'])
    assert closed == [True]
    assert verdict(snapshot) == 'NOT_APPLICABLE'
