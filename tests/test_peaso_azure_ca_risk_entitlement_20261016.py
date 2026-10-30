"""Directed passive Graph entitlement facts for sign-in risk Conditional Access."""
from urllib.parse import urlsplit

import pytest

from peaso.collectors import azure, collect_live
from peaso.collectors import azure_conditional_access_risk_native as risk
from tests.test_peaso_azure_bulk_native import SUB, Transport


TENANT = Transport.tenant
POLICY = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
SKU = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'
USER = 'cccccccc-cccc-cccc-cccc-cccccccccccc'
P1 = '41781fb2-bc02-4b7c-bd55-b576c07bb09d'
P2 = risk.P2_SERVICE_PLAN_ID
POLICIES = '/v1.0/identity/conditionalAccess/policies'
SKUS = '/v1.0/subscribedSkus'
USERS = '/v1.0/users'


def policy(levels=None):
    return {'id': POLICY, 'state': 'enabled', 'conditions': {
        'signInRiskLevels': ['medium', 'high'] if levels is None else levels}}


def sku(*, name='AAD_PREMIUM_P2', plan=P2, state='Enabled', provision='Success'):
    return {'id': SKU + '_tenant', 'skuId': SKU, 'capabilityStatus': state,
            'appliesTo': 'User', 'servicePlans': [{'servicePlanId': plan,
            'servicePlanName': name, 'provisioningStatus': provision}],
            'accountName': 'private-marker'}


def user(*, plan=P2, state='Enabled'):
    return {'id': USER, 'accountEnabled': True, 'assignedPlans': [
        {'servicePlanId': plan, 'capabilityStatus': state}],
        'userPrincipalName': 'private-marker@example.test'}


def routes(*, policies=None, skus=None, users=None):
    return {POLICIES: {'value': [policy()] if policies is None else policies},
            SKUS: {'value': [sku()] if skus is None else skus},
            USERS: {'value': [user()] if users is None else users}}


def collect(api, wanted=None):
    return azure.collect({'scopes': [SUB], 'options': {'retries': 0}},
                         ['conditional_access_policy', risk.KIND] if wanted is None else wanted,
                         transport=api)


def fact(snapshot):
    return next(row for row in snapshot['collections'] if row['type'] == risk.KIND)


def test_normal_collect_live_p2_user_match_and_minimized_row(monkeypatch):
    api = Transport(routes())
    api.close = lambda: None
    monkeypatch.setattr(azure, 'AzureTransport', lambda auth: api);monkeypatch.setattr(azure,'AzureTransportExposure',lambda auth: api)
    snapshot = collect_live({'provider': 'azure', 'scopes': [SUB], 'options': {'retries': 0}},
                            ['conditional_access_policy', risk.KIND])
    got = fact(snapshot)
    assert got['status'] == 'collected' and got['scope'] == '/tenants/' + TENANT
    row = got['items'][0]
    assert row['user_id'] == USER and row['account_enabled'] is True
    assert row['active_service_plan_ids'] == [P2]
    assert row['risk_p2_service_plan_ids'] == [P2]
    assert row['_provenance']['tenant_verified'] is True
    assert row['_provenance']['source_operation'] == 'Graph_UsersAssignedPlans+SubscribedSkus_List'
    assert 'private-marker' not in str(got)
    assert {urlsplit(call).path for call in api.calls} >= {POLICIES, SKUS, USERS}


@pytest.mark.parametrize('sku_row,user_row', [
    (sku(name='AAD_PREMIUM', plan=P1), user(plan=P1)),
    (sku(state='Suspended'), user()),
    (sku(provision='Disabled'), user()),
    (sku(), user(state='Suspended')),
    (sku(), user(plan=P1)),
])
def test_pool_or_unassigned_or_suspended_plan_never_claims_p2(sku_row, user_row):
    got = fact(collect(Transport(routes(skus=[sku_row], users=[user_row]))))
    assert got['status'] == 'collected'
    assert got['items'][0]['risk_p2_service_plan_ids'] == []


def test_no_enabled_risk_policy_emits_empty_relevant_evidence_without_license_reads():
    api = Transport(routes(policies=[policy(levels=[])]))
    got = fact(collect(api))
    assert got['status'] == 'empty' and got['items'] == []
    assert got['metadata']['reason'] == 'no-enabled-signin-risk-policy'
    assert not any(urlsplit(call).path in (SKUS, USERS) for call in api.calls)


@pytest.mark.parametrize('endpoint', [SKUS, USERS])
def test_denied_required_graph_inventory_remains_unavailable(endpoint):
    r = routes()
    r[endpoint] = azure.AzureReadError('forbidden', 403)
    got = fact(collect(Transport(r)))
    assert got['status'] not in ('collected', 'empty')


@pytest.mark.parametrize('endpoint', [SKUS, USERS])
def test_unfinished_pagination_remains_unavailable(endpoint):
    r = routes()
    first = r[endpoint]
    first['@odata.nextLink'] = azure.GRAPH + endpoint + '?page=again'
    def unfinished(query):
        if 'page' in query:
            raise azure.AzureReadError('forbidden', 403)
        return first
    r[endpoint] = unfinished
    got = fact(collect(Transport(r)))
    assert got['status'] not in ('collected', 'empty')


@pytest.mark.parametrize('mutation', ['duplicate_user', 'bad_plan_id', 'unknown_status',
                                      'duplicate_sku', 'bad_p2_mapping'])
def test_ambiguous_or_malformed_native_identity_never_proves_entitlement(mutation):
    r = routes()
    if mutation == 'duplicate_user': r[USERS]['value'] = [user(), user()]
    if mutation == 'bad_plan_id': r[USERS]['value'][0]['assignedPlans'][0]['servicePlanId'] = 'not-a-guid'
    if mutation == 'unknown_status': r[USERS]['value'][0]['assignedPlans'][0]['capabilityStatus'] = 'Future'
    if mutation == 'duplicate_sku': r[SKUS]['value'] = [sku(), sku()]
    if mutation == 'bad_p2_mapping': r[SKUS]['value'][0]['servicePlans'][0]['servicePlanId'] = P1
    assert fact(collect(Transport(r)))['status'] not in ('collected', 'empty')


def test_unverified_tenant_and_caps_are_unavailable_before_complete_rows(monkeypatch):
    api = Transport(routes())
    api.verified_tenant = None
    assert fact(collect(api))['status'] not in ('collected', 'empty')
    assert not any(urlsplit(call).path in (SKUS, USERS) for call in api.calls)
    monkeypatch.setattr(risk, 'MAX_SKUS', 0)
    assert fact(collect(Transport(routes())))['status'] not in ('collected', 'empty')


def test_selected_tenant_mismatch_does_not_read_license_inventory():
    api = Transport(routes())
    api.tenant = 'ffffffff-ffff-ffff-ffff-ffffffffffff'
    got = fact(collect(api))
    assert got['status'] not in ('collected', 'empty')
    assert not any(urlsplit(call).path in (SKUS, USERS) for call in api.calls)


def test_kind_not_requested_makes_no_license_calls():
    api = Transport(routes())
    collect(api, wanted=['conditional_access_policy'])
    assert not any(urlsplit(call).path in (SKUS, USERS) for call in api.calls)
