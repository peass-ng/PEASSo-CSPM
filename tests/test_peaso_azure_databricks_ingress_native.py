"""Bounded account ingress reads joined to an exact Azure Databricks workspace."""
import json

import pytest

from peaso.analysis.internet_exposure import assess
from peaso.collectors import azure_databricks_ingress_native as native
from peaso.snapshot import make_snapshot, resources

SCOPE = '/subscriptions/11111111-1111-1111-1111-111111111111'
ACCOUNT = '33333333-3333-3333-3333-333333333333'
RID = SCOPE + '/resourceGroups/rg/providers/Microsoft.Databricks/workspaces/one'
BINDING = f'/api/2.0/accounts/{ACCOUNT}/workspaces/123/network'
POLICY = f'/api/2.0/accounts/{ACCOUNT}/network-policies/default-policy'
TOKEN = 'explicit-account-oauth'


def approval():
    return {'compliance_policy': {'sw33': {'status': 'collected', 'scope': SCOPE,
            'databricksAccount': {'accountId': ACCOUNT}}}}


@pytest.mark.parametrize('path', [
    '/api/2.0/accounts/' + ACCOUNT + '/network-policies/../secret',
    BINDING + '?x=1', BINDING.replace('/network', '/network/'),
    '/api/2.0/accounts/' + ACCOUNT + '/network-policies/',
    '/api/2.0/accounts/' + ACCOUNT + '/network-policies/..',
    '/api/2.0/accounts/' + ACCOUNT + '/workspaces/0/network',
])
def test_only_fixed_account_get_paths(path):
    with pytest.raises(ValueError):
        native.request_policy(path, {'databricks_account_token': TOKEN})


def test_projection_binds_ids_and_discards_rule_contents():
    assert native.project({'workspace_id': 123, 'network_policy_id': 'default-policy', 'secret': TOKEN}, BINDING) == {
        'workspace_id': 123, 'network_policy_id': 'default-policy'}
    value = {'account_id': ACCOUNT, 'network_policy_id': 'default-policy', 'ingress': {'public_access': {
        'restriction_mode': 'RESTRICTED_ACCESS', 'allow_rules': [{'label': TOKEN}], 'deny_rules': []}}}
    projected = native.project(value, POLICY)
    assert projected == {'account_id': ACCOUNT, 'network_policy_id': 'default-policy',
                         'restriction_mode': 'RESTRICTED_ACCESS', 'allow_rule_count': 1,
                         'deny_rule_count': 0, 'public_ui_rules': [], 'public_ui_denies': []}
    assert TOKEN not in json.dumps(projected)
    assert native.project(projected, POLICY) == projected
    with pytest.raises(ValueError):
        native.project({**value, 'account_id': '44444444-4444-4444-4444-444444444444'}, POLICY)
    with pytest.raises(ValueError):
        native.project({'workspace_id': 456, 'network_policy_id': 'default-policy'}, BINDING)


class Reader:
    def __init__(self):
        self.collections = [
            {'type': 'databricks_workspace', 'scope': SCOPE, 'service': 'ARM', 'status': 'collected',
             'items': [{'id': RID, 'properties': {'workspaceUrl': 'adb-123.4.azuredatabricks.net',
                                                'publicNetworkAccess': 'Enabled'}}]},
            {'type': 'databricks_account_workspace', 'scope': SCOPE, 'service': 'Databricks.Account',
             'status': 'collected', 'items': [{'id': RID, 'accountId': ACCOUNT, 'workspaceId': 123}]},
        ]

    def call(self, operation, *args):
        return operation(*args)

    def run(self, jobs):
        for kind, scope, service, fetch in jobs:
            self.collections.append({'type': kind, 'scope': scope, 'service': service,
                                     'status': 'collected', 'items': next(fetch())})


class Transport:
    def __init__(self, mode):
        self.calls, self.mode = [], mode

    def request_databricks_ingress(self, path):
        native.endpoint(path)
        self.calls.append(path)
        if path == BINDING:
            return {'workspace_id': 123, 'network_policy_id': 'default-policy'}
        assert path == POLICY
        return {'account_id': ACCOUNT, 'network_policy_id': 'default-policy', 'ingress': {'public_access': {
            'restriction_mode': self.mode, 'allow_rules': [] if self.mode == 'RESTRICTED_ACCESS' else []}}}


def test_transport_projection_survives_collector_projection():
    class Projected(Transport):
        def request_databricks_ingress(self, path):
            return native.project(super().request_databricks_ingress(path), path)

    reader, transport = Reader(), Projected('RESTRICTED_ACCESS')
    native.collect(reader, transport, [SCOPE], {'databricks_workspace'}, approval(), {'databricks_account_token': TOKEN})
    assert reader.collections[-1]['items'][0]['policyStatus'] == 'collected'


@pytest.mark.parametrize('mode,verdict', [('RESTRICTED_ACCESS', 'PASS'), ('FULL_ACCESS', 'UNKNOWN')])
def test_account_policy_join_and_exposure(mode, verdict):
    reader, transport = Reader(), Transport(mode)
    native.collect(reader, transport, [SCOPE], {'databricks_workspace'}, approval(), {'databricks_account_token': TOKEN})
    assert transport.calls == [BINDING, POLICY]
    assert TOKEN not in json.dumps(reader.collections)
    snapshot = make_snapshot('azure', [SCOPE], reader.collections)
    row = next(row for row in assess(snapshot, resources(snapshot))
               if row.resource['type'] == 'databricks_workspace')
    assert row.verdict() == verdict


def test_no_approval_no_network_request():
    reader, transport = Reader(), Transport('FULL_ACCESS')
    native.collect(reader, transport, [SCOPE], {'databricks_workspace'}, {}, {})
    assert transport.calls == [] and len(reader.collections) == 2


def test_denied_policy_read_keeps_ingress_unknown():
    from peaso.collectors.azure import AzureReadError

    class Denied(Transport):
        def request_databricks_ingress(self, path):
            if path == POLICY:
                raise AzureReadError('forbidden', 403)
            return super().request_databricks_ingress(path)

    reader, transport = Reader(), Denied('FULL_ACCESS')
    native.collect(reader, transport, [SCOPE], {'databricks_workspace'}, approval(), {'databricks_account_token': TOKEN})
    child = reader.collections[-1]
    assert child['items'][0]['policyStatus'] == 'denied'
    assert 'restriction_mode' not in child['items'][0]
    snapshot = make_snapshot('azure', [SCOPE], reader.collections)
    row = next(row for row in assess(snapshot, resources(snapshot))
               if row.resource['type'] == 'databricks_workspace')
    assert row.verdict() == 'UNKNOWN'


def test_full_ingress_and_disabled_ip_lists_prove_public_listener():
    reader, transport = Reader(), Transport('FULL_ACCESS')
    native.collect(reader, transport, [SCOPE], {'databricks_workspace'}, approval(), {'databricks_account_token': TOKEN})
    reader.collections.append({'type': 'databricks_workspace_ip_policy', 'scope': SCOPE,
        'service': 'Databricks.Workspace', 'status': 'collected', 'items': [{
            'id': RID, 'policyStatus': 'collected', 'ipAccessListsEnabled': False, 'ipAccessLists': []}]})
    snapshot = make_snapshot('azure', [SCOPE], reader.collections)
    row = next(row for row in assess(snapshot, resources(snapshot))
               if row.resource['type'] == 'databricks_workspace')
    assert row.verdict() == 'FAIL' and row.ports == {'tcp': ((443, 443),)}


def test_project_public_ui_allow_without_retaining_label():
    rule = {'origin': {'all_ip_ranges': True}, 'destination': {'workspace_ui': {'all_destinations': True}},
            'label': TOKEN}
    value = {'account_id': ACCOUNT, 'network_policy_id': 'default-policy', 'ingress': {'public_access': {
        'restriction_mode': 'RESTRICTED_ACCESS', 'allow_rules': [rule], 'deny_rules': []}}}
    projected = native.project(value, POLICY)
    assert projected['public_ui_rules'] == [{'origin': 'all', 'ranges': []}]
    assert TOKEN not in json.dumps(projected)
    assert native.project(projected, POLICY) == projected


@pytest.mark.parametrize('source,ip_lists,expected', [
    ({'all_ip_ranges': True}, [], 'FAIL'),
    ({'included_ip_ranges': {'ip_ranges': ['8.8.8.8/32']}}, [], 'FAIL'),
    ({'included_ip_ranges': {'ip_ranges': ['8.8.8.8/32']}},
     [{'list_id': 'a', 'list_type': 'ALLOW', 'enabled': True, 'ip_addresses': ['8.8.8.8/32']}], 'FAIL'),
    ({'included_ip_ranges': {'ip_ranges': ['8.8.8.8/32']}},
     [{'list_id': 'a', 'list_type': 'ALLOW', 'enabled': True, 'ip_addresses': ['8.8.8.8/32']},
      {'list_id': 'b', 'list_type': 'BLOCK', 'enabled': True, 'ip_addresses': ['8.8.8.8/32']}], 'UNKNOWN'),
    ({'included_ip_ranges': {'ip_ranges': ['8.8.8.0/29']}},
     [{'list_id': 'a', 'list_type': 'ALLOW', 'enabled': True, 'ip_addresses': ['8.8.8.0/29']},
      {'list_id': 'b', 'list_type': 'BLOCK', 'enabled': True,
       'ip_addresses': ['8.8.8.0/31', '8.8.8.4/32', '8.8.8.7/32']}], 'FAIL'),
])
def test_restricted_public_ui_rule_with_ip_intersection(source, ip_lists, expected):
    class Rules(Transport):
        def request_databricks_ingress(self, path):
            if path == BINDING:
                return super().request_databricks_ingress(path)
            return {'account_id': ACCOUNT, 'network_policy_id': 'default-policy', 'ingress': {'public_access': {
                'restriction_mode': 'RESTRICTED_ACCESS', 'allow_rules': [{
                    'origin': source, 'destination': {'workspace_ui': {'all_destinations': True}}}],
                'deny_rules': []}}}

    reader, transport = Reader(), Rules('RESTRICTED_ACCESS')
    native.collect(reader, transport, [SCOPE], {'databricks_workspace'}, approval(), {'databricks_account_token': TOKEN})
    reader.collections.append({'type': 'databricks_workspace_ip_policy', 'scope': SCOPE,
        'service': 'Databricks.Workspace', 'status': 'collected', 'items': [{
            'id': RID, 'policyStatus': 'collected', 'ipAccessListsEnabled': bool(ip_lists),
            'ipAccessLists': ip_lists}]})
    snapshot = make_snapshot('azure', [SCOPE], reader.collections)
    row = next(row for row in assess(snapshot, resources(snapshot))
               if row.resource['type'] == 'databricks_workspace')
    assert row.verdict() == expected
    if expected == 'FAIL':
        assert any(step.get('layer') == 'workspace_context_ingress' and step.get('decision') == 'allow'
                   for step in row.path)
        if ip_lists and any(item.get('list_id') == 'b' for item in ip_lists):
            assert any(step.get('public_source_ip') == '8.8.8.2' for step in row.path)


def test_malformed_ip_list_cannot_complete_public_path():
    reader, transport = Reader(), Transport('FULL_ACCESS')
    native.collect(reader, transport, [SCOPE], {'databricks_workspace'}, approval(), {'databricks_account_token': TOKEN})
    reader.collections.append({'type': 'databricks_workspace_ip_policy', 'scope': SCOPE,
        'service': 'Databricks.Workspace', 'status': 'collected', 'items': [{
            'id': RID, 'policyStatus': 'collected', 'ipAccessListsEnabled': True,
            'ipAccessLists': [{'enabled': True, 'list_type': 'UNKNOWN', 'ip_addresses': []}]}]})
    snapshot = make_snapshot('azure', [SCOPE], reader.collections)
    row = next(row for row in assess(snapshot, resources(snapshot))
               if row.resource['type'] == 'databricks_workspace')
    assert row.verdict() == 'UNKNOWN'


@pytest.mark.parametrize('deny,expected,witness', [
    ({'origin': {'all_ip_ranges': True}, 'destination': {'all_destinations': True}}, 'UNKNOWN', None),
    ({'origin': {'included_ip_ranges': {'ip_ranges': ['8.8.8.0/30']}},
      'destination': {'workspace_ui': {'all_destinations': True}}}, 'FAIL', '8.8.8.4'),
    ({'origin': {'excluded_ip_ranges': {'ip_ranges': ['8.8.8.0/30']}},
      'destination': {'workspace_ui': {'all_destinations': True}}}, 'FAIL', '8.8.8.0'),
    ({'origin': {'included_ip_ranges': {'ip_ranges': ['8.8.8.0/30']}},
      'destination': {'workspace_ui': {'all_destinations': True}},
      'authentication': {'identity_type': 'IDENTITY_TYPE_SELECTED_IDENTITIES'}}, 'UNKNOWN', None),
])
def test_nonempty_deny_rules_prevent_unqualified_public_claim(deny, expected, witness):
    class DenyAll(Transport):
        def request_databricks_ingress(self, path):
            if path == BINDING:
                return super().request_databricks_ingress(path)
            broad = {'origin': {'all_ip_ranges': True}, 'destination': {'all_destinations': True}}
            return {'account_id': ACCOUNT, 'network_policy_id': 'default-policy', 'ingress': {'public_access': {
                'restriction_mode': 'RESTRICTED_ACCESS', 'allow_rules': [broad],
                'deny_rules': [{**deny, 'label': TOKEN}]}}}

    reader, transport = Reader(), DenyAll('RESTRICTED_ACCESS')
    native.collect(reader, transport, [SCOPE], {'databricks_workspace'}, approval(), {'databricks_account_token': TOKEN})
    assert TOKEN not in json.dumps(reader.collections)
    reader.collections.append({'type': 'databricks_workspace_ip_policy', 'scope': SCOPE,
        'service': 'Databricks.Workspace', 'status': 'collected', 'items': [{
            'id': RID, 'policyStatus': 'collected', 'ipAccessListsEnabled': True,
            'ipAccessLists': [{'enabled': True, 'list_type': 'ALLOW', 'ip_addresses': ['8.8.8.0/29']}]}]})
    snapshot = make_snapshot('azure', [SCOPE], reader.collections)
    row = next(row for row in assess(snapshot, resources(snapshot))
               if row.resource['type'] == 'databricks_workspace')
    assert row.verdict() == expected
    if witness:
        assert any(step.get('layer') == 'workspace_context_ingress'
                   and step.get('public_source_ip') == witness for step in row.path)


def test_workspace_block_overrides_same_public_allow_under_full_context_access():
    reader, transport = Reader(), Transport('FULL_ACCESS')
    native.collect(reader, transport, [SCOPE], {'databricks_workspace'}, approval(), {'databricks_account_token': TOKEN})
    reader.collections.append({'type': 'databricks_workspace_ip_policy', 'scope': SCOPE,
        'service': 'Databricks.Workspace', 'status': 'collected', 'items': [{
            'id': RID, 'policyStatus': 'collected', 'ipAccessListsEnabled': True,
            'ipAccessLists': [
                {'list_type': 'ALLOW', 'enabled': True, 'ip_addresses': ['8.8.8.8/32']},
                {'list_type': 'BLOCK', 'enabled': True, 'ip_addresses': ['8.8.8.8/32']}]}]})
    snapshot = make_snapshot('azure', [SCOPE], reader.collections)
    row = next(row for row in assess(snapshot, resources(snapshot))
               if row.resource['type'] == 'databricks_workspace')
    assert row.verdict() == 'UNKNOWN'


def test_transport_uses_account_oauth_get(monkeypatch):
    calls = []

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self, size):
            assert size == native.MAX_RESPONSE_BYTES + 1
            return b'{"workspace_id":123,"network_policy_id":"default-policy","private":"discard"}'

    class Opener:
        def open(self, request, timeout):
            calls.append((request, timeout))
            return Response()

    monkeypatch.setattr(native, 'build_opener', lambda *handlers: Opener())
    assert native.request_policy(BINDING, {'databricks_account_token': TOKEN})['workspace_id'] == 123
    request, timeout = calls[0]
    assert request.get_method() == 'GET' and request.full_url == native.HOST + BINDING
    assert request.headers['Authorization'] == 'Bearer ' + TOKEN and timeout == 20


def test_full_account_arm_join_collects_ingress(monkeypatch):
    from tests.test_peaso_azure_databricks_native import API, capture

    def request_ingress(self, path):
        self.calls.append(native.HOST + path)
        if path == BINDING:
            return {'workspace_id': 123, 'network_policy_id': 'default-policy'}
        assert path == POLICY
        return {'account_id': ACCOUNT, 'network_policy_id': 'default-policy', 'ingress': {
            'public_access': {'restriction_mode': 'RESTRICTED_ACCESS', 'allow_rules': []}}}

    monkeypatch.setattr(API, 'request_databricks_ingress', request_ingress, raising=False)
    snapshot, api = capture()
    child = next(c for c in snapshot['collections'] if c['type'] == native.KIND)
    assert child['status'] == 'collected' and child['items'][0]['allow_rule_count'] == 0
    assert native.HOST + BINDING in api.calls and native.HOST + POLICY in api.calls
