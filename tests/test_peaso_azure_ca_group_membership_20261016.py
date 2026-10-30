"""Passive Graph Conditional Access group membership producer boundaries."""
from urllib.parse import urlsplit

import pytest

from peaso.collectors import azure, collect_live
from peaso.collectors import azure_conditional_access_native as native
from tests.test_peaso_azure_bulk_native import SUB, Transport


TENANT = Transport.tenant
POLICY = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
G1 = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'
G2 = 'cccccccc-cccc-cccc-cccc-cccccccccccc'
USER = 'dddddddd-dddd-dddd-dddd-dddddddddddd'
DEVICE = 'eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee'
PARENT = '/v1.0/identity/conditionalAccess/policies'
KIND = 'conditional_access_group_membership'


def policy(*, includes=None, excludes=None, state='enabled'):
    return {'id': POLICY, 'state': state, 'conditions': {'users': {
        'includeGroups': [G1] if includes is None else includes,
        'excludeGroups': [G2] if excludes is None else excludes}}}


def routes(*, policies=None, group1=None, group2=None):
    return {
        PARENT: {'value': [policy()] if policies is None else policies},
        '/v1.0/groups/' + G1: {'id': G1, 'visibility': 'Private', 'groupTypes': []},
        '/v1.0/groups/' + G2: {'id': G2, 'visibility': 'Private', 'groupTypes': []},
        '/v1.0/groups/' + G1 + '/transitiveMembers': {'value': [
            {'id': USER, '@odata.type': '#microsoft.graph.user', 'mail': 'private-marker'},
            {'id': DEVICE, '@odata.type': '#microsoft.graph.device'}]} if group1 is None else group1,
        '/v1.0/groups/' + G2 + '/transitiveMembers': {'value': []} if group2 is None else group2,
    }


def collect(api, wanted=None):
    return azure.collect({'scopes': [SUB], 'options': {'retries': 0}},
                         ['conditional_access_policy', KIND] if wanted is None else wanted,
                         transport=api)


def groups(snapshot):
    return [row for row in snapshot['collections'] if row['type'] == KIND]


def test_enabled_include_exclude_dedup_transitive_user_and_empty_200():
    p = policy(includes=[G1, G2], excludes=[G1])
    api = Transport(routes(policies=[p]))
    got = groups(collect(api))
    assert len(got) == 2
    rows = {row['items'][0]['group_id']: row['items'][0] for row in got}
    assert rows[G1]['user_ids'] == [USER]
    assert rows[G2]['user_ids'] == []
    assert rows[G1]['_provenance']['requested_group_id'] == G1
    assert rows[G1]['_provenance']['tenant_id'] == TENANT
    assert rows[G1]['_provenance']['source_operation'] == 'Groups_TransitiveMembers_List'
    assert all(row['status'] == 'collected' for row in got)
    assert sum('/transitiveMembers' in call for call in api.calls) == 2
    assert 'private-marker' not in str(got)


def test_no_requested_inventory_makes_zero_group_calls():
    api = Transport(routes())
    collect(api, wanted=['conditional_access_policy'])
    assert not any('/groups/' in call for call in api.calls)


def test_no_referenced_groups_produces_explicit_empty_tenant_inventory():
    api = Transport(routes(policies=[policy(includes=[], excludes=[])]))
    assert groups(collect(api))[0]['status'] == 'empty'
    assert not any('/groups/' in call for call in api.calls)


@pytest.mark.parametrize('mutate', [
    lambda r: r.update({PARENT: {'value': [policy(), policy()]}}),
    lambda r: r.update({PARENT: {'value': [policy(includes=['not-a-guid'])]}}),
    lambda r: r.update({PARENT: azure.AzureReadError('forbidden', 403)}),
    lambda r: r.update({PARENT: {'value': [policy()], '@odata.nextLink':
        azure.GRAPH + PARENT + '?page=again'}}),
])
def test_invalid_or_incomplete_policy_source_never_calls_membership(mutate):
    r = routes()
    mutate(r)
    api = Transport(r)
    got = groups(collect(api))
    assert len(got) == 1 and got[0]['status'] not in ('collected', 'empty')
    assert not any('/groups/' in call for call in api.calls)


@pytest.mark.parametrize('response', [
    {'value': [{'id': USER, '@odata.type': '#microsoft.graph.futureObject'}]},
    {'value': [{'id': 'not-a-guid', '@odata.type': '#microsoft.graph.user'}]},
    {'value': [{'id': USER, '@odata.type': '#microsoft.graph.user'},
               {'id': USER, '@odata.type': '#microsoft.graph.user'}]},
    azure.AzureReadError('forbidden', 403),
    {'value': [{'id': USER, '@odata.type': '#microsoft.graph.user'}],
     '@odata.nextLink': azure.GRAPH + '/v1.0/groups/' + G1 + '/transitiveMembers?page=again'},
])
def test_unresolved_member_or_page_never_yields_complete_group(response):
    r = routes(policies=[policy(excludes=[])], group1=response)
    if isinstance(response, dict) and '@odata.nextLink' in response:
        def unfinished(query):
            if 'page' in query:
                raise azure.AzureReadError('forbidden', 403)
            return response
        r['/v1.0/groups/' + G1 + '/transitiveMembers'] = unfinished
    got = groups(collect(Transport(r)))
    assert len(got) == 1 and got[0]['status'] not in ('collected', 'empty')
    assert got[0]['items'] == []


@pytest.mark.parametrize('metadata', [
    {'id': G1, 'visibility': 'HiddenMembership', 'groupTypes': ['Unified']},
    {'id': G1, 'visibility': 'Private', 'groupTypes': ['DynamicMembership']},
    {'id': G1, 'groupTypes': []},
    {'id': G2, 'visibility': 'Private', 'groupTypes': []},
])
def test_hidden_dynamic_missing_or_foreign_group_metadata_stays_unavailable(metadata):
    r = routes(policies=[policy(excludes=[])])
    r['/v1.0/groups/' + G1] = metadata
    api = Transport(r)
    got = groups(collect(api))
    assert len(got) == 1 and got[0]['status'] not in ('collected', 'empty')
    assert not any('/transitiveMembers' in call for call in api.calls)


def test_group_cap_and_wrong_tenant_prevent_member_calls():
    ids = [f'{n:08x}-0000-0000-0000-000000000000' for n in range(65)]
    api = Transport(routes(policies=[policy(includes=ids, excludes=[])]))
    assert groups(collect(api))[0]['status'] not in ('collected', 'empty')
    assert not any('/groups/' in call for call in api.calls)
    api = Transport(routes())
    api.verified_tenant = None
    assert groups(collect(api))[0]['status'] not in ('collected', 'empty')
    assert not any('/groups/' in call for call in api.calls)
    api = Transport(routes())
    api.tenant = 'ffffffff-ffff-ffff-ffff-ffffffffffff'
    assert groups(collect(api))[0]['status'] not in ('collected', 'empty')
    assert not any('/groups/' in call for call in api.calls)


def test_collect_live_uses_existing_native_hook(monkeypatch):
    api = Transport(routes(policies=[policy(excludes=[])]))
    api.close = lambda: None
    monkeypatch.setattr(azure, 'AzureTransport', lambda auth: api)
    monkeypatch.setattr(azure, 'AzureTransportExposure', lambda auth: api)
    snapshot = collect_live({'provider': 'azure', 'scopes': [SUB], 'options': {'retries': 0}},
                            ['conditional_access_policy', KIND])
    got = groups(snapshot)
    assert len(got) == 1 and got[0]['status'] == 'collected'
    assert got[0]['items'][0]['user_ids'] == [USER]
    assert any(urlsplit(call).path.endswith('/transitiveMembers') for call in api.calls)
