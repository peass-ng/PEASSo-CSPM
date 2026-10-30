"""Portable native collector-to-engine Azure log-profile scope regressions."""
import copy
from urllib.parse import urlsplit

import pytest

from peaso.collectors import azure
from peaso.engine import collect_snapshot, evaluate_snapshot, plan_collection

SUB = '11111111-1111-1111-1111-111111111111'
TENANT = '22222222-2222-2222-2222-222222222222'
SCOPE = '/subscriptions/' + SUB
CHECK = 'azure.gap.monitor_log_profile_enabled_for_all_categories'
PROFILE = SCOPE + '/providers/Microsoft.Insights/logProfiles/fixture'
SINK = SCOPE + '/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/sink'


def _scan(monkeypatch, *, profiles=None, wrong_subscription=False, denied=False,
          partial=False, response_subscription_id=SUB, response_tenant_id=TENANT,
          auth_tenant=TENANT, verified_tenant=TENANT, discover_all=False,
          max_scopes=None):
    profiles = [] if profiles is None else profiles
    calls = []

    class Transport:
        def __init__(self, auth):
            assert auth.get('tenant_id') == auth_tenant
            self.tenant = auth_tenant or verified_tenant
            self.verified_tenant = verified_tenant

        def request(self, url, *, body=None, audience=azure.ARM, capture_subject=False):
            path = urlsplit(url).path
            calls.append(('POST_READ' if body is not None else 'GET', path))
            assert audience == azure.ARM
            if path == SCOPE and body is None:
                if denied:
                    raise azure.AzureReadError('denied', 403)
                other = SCOPE.replace(SUB, '99999999-9999-9999-9999-999999999999')
                return {'id': other if wrong_subscription else SCOPE,
                        'subscriptionId': response_subscription_id,
                        'tenantId': response_tenant_id, 'state': 'Enabled'}
            if path == '/subscriptions' and body is None:
                other = '99999999-9999-9999-9999-999999999999'
                return {'value': [
                    {'id': SCOPE, 'subscriptionId': SUB, 'tenantId': TENANT,
                     'state': 'Enabled'},
                    {'id': '/subscriptions/' + other, 'subscriptionId': other,
                     'tenantId': TENANT, 'state': 'Enabled'}]}
            if path == '/providers/Microsoft.ResourceGraph/resources' and body is not None:
                assert body['subscriptions'] == [SUB]
                return {'data': [], 'totalRecords': 0, 'count': 0}
            if path == SCOPE + '/providers/Microsoft.Insights/logProfiles' and body is None:
                if partial and 'skiptoken' in url:
                    raise azure.AzureReadError('page_unavailable', 403)
                return {'value': copy.deepcopy(profiles),
                        **({'nextLink': url + '&skiptoken=fixture'} if partial and 'skiptoken' not in url else {})}
            raise AssertionError('unexpected or non-read-only request')

        def close(self):
            pass

    monkeypatch.setattr(azure, 'AzureTransport', Transport);monkeypatch.setattr(azure,'AzureTransportExposure',Transport)
    auth = {'method': 'az-cli'}
    if auth_tenant is not None:
        auth['tenant_id'] = auth_tenant
    options = {'max_calls': 10, 'max_resources': 100, 'retries': 0,
               'concurrency': 1}
    if max_scopes is not None:
        options['max_scopes'] = max_scopes
    request = {'connector': {'provider': 'azure', 'scopes': ['*'] if discover_all else [SCOPE],
        'auth': auth,
        'options': options}, 'checks': [CHECK], 'categories': []}
    assert plan_collection(request) == ['monitor_log_profile', 'subscription']
    snap = collect_snapshot(request)
    report = evaluate_snapshot(snap, checks=[CHECK], categories=[], include_not_applicable=True)
    findings = [row for row in report['findings'] if row.get('check_id') == CHECK]
    return snap, findings, calls


def _profile(categories=('Write', 'Delete', 'Action'), *, resource_id=PROFILE):
    return {'id': resource_id, 'type': 'Microsoft.Insights/logProfiles',
        'name': 'fixture', 'properties': {'categories': list(categories),
        'locations': ['global'], 'storageAccountId': SINK, 'serviceBusRuleId': None,
        'retentionPolicy': {'enabled': False, 'days': 0}}}


@pytest.mark.parametrize('profiles,expected', [
    ([], 'FAIL'),
    ([_profile()], 'PASS'),
    ([_profile(('Write', 'Delete'))], 'FAIL'),
])
def test_selected_subscription_only_and_categories(monkeypatch, profiles, expected):
    snap, findings, calls = _scan(monkeypatch, profiles=profiles)
    subscription = [row for row in snap['collections'] if row['type'] == 'subscription']
    assert len(subscription) == 1
    assert subscription[0]['scope'] == SCOPE
    assert [row['id'] for row in subscription[0]['items']] == [SCOPE]
    assert len(findings) == 1 and findings[0]['status'] == expected
    assert not any(path == '/subscriptions' for _, path in calls)
    assert all(method in ('GET', 'POST_READ') for method, _ in calls)


@pytest.mark.parametrize('case', ['denied', 'foreign_subscription', 'foreign_profile',
                                  'missing_categories', 'partial_page'])
def test_incomplete_or_unbound_evidence_never_passes(monkeypatch, case):
    opts = {}
    if case == 'denied': opts['denied'] = True
    elif case == 'foreign_subscription': opts['wrong_subscription'] = True
    elif case == 'foreign_profile': opts['profiles'] = [_profile(resource_id=PROFILE.replace(SUB, '99999999-9999-9999-9999-999999999999'))]
    elif case == 'missing_categories':
        item = _profile(); del item['properties']['categories']; opts['profiles'] = [item]
    else:
        opts['profiles'] = [_profile()]
        opts['partial'] = True
    _, findings, _ = _scan(monkeypatch, **opts)
    assert findings and all(row['status'] in ('UNKNOWN', 'DENIED') for row in findings)


@pytest.mark.parametrize('overrides', [
    {'response_subscription_id': '99999999-9999-9999-9999-999999999999'},
    {'response_subscription_id': None},
    {'response_tenant_id': None},
    {'response_tenant_id': ''},
    {'response_tenant_id': 'not-a-guid'},
    {'response_tenant_id': '33333333-3333-3333-3333-333333333333'},
    {'verified_tenant': '33333333-3333-3333-3333-333333333333'},
    {'auth_tenant': '33333333-3333-3333-3333-333333333333'},
])
def test_subscription_and_all_expected_tenant_claims_must_agree(monkeypatch, overrides):
    _, findings, _ = _scan(monkeypatch, profiles=[_profile()], **overrides)
    assert findings and all(row['status'] in ('UNKNOWN', 'DENIED') for row in findings)


@pytest.mark.parametrize('verified_tenant', [TENANT, None])
def test_implicit_cli_tenant_can_use_bound_arm_get(monkeypatch, verified_tenant):
    snap, findings, calls = _scan(monkeypatch, profiles=[_profile()],
        auth_tenant=None, verified_tenant=verified_tenant)
    assert [row['scope'] for row in snap['collections'] if row['type'] == 'subscription'] == [SCOPE]
    assert len(findings) == 1 and findings[0]['status'] == 'PASS'
    assert snap['metadata']['tenant_verified'] is (verified_tenant is not None)
    assert ('GET', SCOPE) in calls


def test_discover_all_keeps_tenant_list_and_max_scope_limit(monkeypatch):
    snap, _, calls = _scan(monkeypatch, discover_all=True, max_scopes=1)
    subscription = [row for row in snap['collections'] if row['type'] == 'subscription']
    assert len(subscription) == 1
    assert subscription[0]['scope'] == '/tenants/' + TENANT
    assert subscription[0]['status'] == 'partial'
    assert subscription[0]['error']['code'] == 'scope_limit'
    assert len(subscription[0]['items']) == 2
    assert ('GET', '/subscriptions') in calls
    assert ('GET', SCOPE) not in calls
