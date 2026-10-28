"""Workspace-bound PAT reads and conservative ingress decisions."""
import json

import pytest

from peaso.auth import redact
from peaso.analysis.internet_exposure import assess
from peaso.collectors import azure_databricks_workspace_ip_native as native
from peaso.snapshot import make_snapshot, resources

SCOPE = '/subscriptions/11111111-1111-1111-1111-111111111111'
RID = SCOPE + '/resourceGroups/rg/providers/Microsoft.Databricks/workspaces/one'
HOST = 'adb-123.4.azuredatabricks.net'
PAT = 'dapi' + 'a' * 32
CONF = '/api/2.0/workspace-conf?keys=enableIpAccessLists'
LIST = '/api/2.0/ip-access-lists'


@pytest.mark.parametrize('host', [
    'http://' + HOST, HOST + '.evil', 'https://' + HOST + ':443',
    'https://user@' + HOST, 'https://' + HOST + '/path',
    'https://adb-124.4.azuredatabricks.net',
])
def test_foreign_host_rejected_before_request(host):
    with pytest.raises(ValueError):
        native.request_policy(host, '123', LIST, PAT)


def test_pat_mapping_and_secret_redaction():
    native.validate_auth({native.FIELD: {RID: PAT}})
    assert redact({native.FIELD: {RID: PAT}})[native.FIELD] == '[REDACTED]'
    for bad in ({RID: 'eyJ.bad.jwt'}, {RID + '/other': PAT}, {RID: PAT, RID.upper(): PAT}, {}):
        with pytest.raises(ValueError):
            native.validate_auth({native.FIELD: bad})


def test_project_discards_labels_and_rejects_bad_policy():
    value = {'ip_access_lists': [{'list_id': 'abc', 'list_type': 'ALLOW', 'enabled': True,
              'ip_addresses': ['10.0.0.1/8'], 'address_count': 1, 'label': PAT}]}
    assert native.project(value, LIST) == {'ip_access_lists': [
        {'list_id': 'abc', 'list_type': 'ALLOW', 'enabled': True, 'ip_addresses': ['10.0.0.0/8']}]}
    with pytest.raises(ValueError):
        native.project({'ip_access_lists': [dict(value['ip_access_lists'][0], ip_addresses=['invalid'])]}, LIST)
    with pytest.raises(ValueError):
        native.project({'ip_access_lists': [dict(value['ip_access_lists'][0], address_count=2)]}, LIST)
    with pytest.raises(ValueError):
        native.project({**value, 'next_page_token': 'unread'}, LIST)


class Reader:
    def __init__(self):
        self.collections = [{'type': 'databricks_workspace', 'scope': SCOPE, 'service': 'ARM',
                             'status': 'collected', 'items': [{'id': RID, 'properties': {
                                 'workspaceId': '123', 'workspaceUrl': HOST,
                                 'publicNetworkAccess': 'Enabled'}}]}]

    def call(self, operation, *args):
        return operation(*args)

    def run(self, jobs):
        for kind, scope, service, fetch in jobs:
            self.collections.append({'type': kind, 'scope': scope, 'service': service,
                                     'status': 'collected', 'items': next(fetch())})


class Transport:
    def __init__(self, addresses):
        self.calls = []
        self.addresses = addresses

    def request_databricks_workspace_ip(self, host, wid, path, token):
        assert token == PAT
        native.endpoint(host, wid, path)
        self.calls.append(path)
        if path == CONF:
            return {'enableIpAccessLists': 'true'}
        return {'ip_access_lists': [{'list_id': 'abc', 'list_type': 'ALLOW',
                 'enabled': True, 'ip_addresses': self.addresses,
                 'address_count': len(self.addresses), 'label': PAT}]}


@pytest.mark.parametrize('addresses,verdict', [
    (['10.0.0.0/8'], 'PASS'), (['8.8.8.0/24'], 'UNKNOWN'), (['0.0.0.0/1'], 'UNKNOWN')])
def test_collected_ip_lists_join_workspace(addresses, verdict):
    reader, transport = Reader(), Transport(addresses)
    native.collect(reader, transport, [SCOPE], {'databricks_workspace'}, {native.FIELD: {RID: PAT}})
    assert transport.calls == [CONF, LIST]
    assert PAT not in json.dumps(reader.collections)
    snapshot = make_snapshot('azure', [SCOPE], reader.collections)
    row = next(row for row in assess(snapshot, resources(snapshot))
               if row.resource['type'] == 'databricks_workspace')
    assert row.verdict() == verdict


def test_missing_pat_never_calls_workspace():
    reader, transport = Reader(), Transport([])
    native.collect(reader, transport, [SCOPE], {'databricks_workspace'}, {})
    assert transport.calls == []
    assert reader.collections[-1]['items'][0]['policyStatus'] == 'missing_credential'


def test_foreign_arm_host_skips_both_reads():
    reader, transport = Reader(), Transport([])
    reader.collections[0]['items'][0]['properties']['workspaceUrl'] = 'adb-124.4.azuredatabricks.net'
    native.collect(reader, transport, [SCOPE], {'databricks_workspace'}, {native.FIELD: {RID: PAT}})
    assert transport.calls == []
    assert reader.collections[-1]['items'][0]['policyStatus'] != 'collected'


def test_direct_azure_collection_joins_arm_parent():
    from peaso.collectors import azure
    from tests.test_peaso_azure_bulk_native import Transport as ArmTransport, parent

    class API(ArmTransport):
        def request_databricks_workspace_ip(self, host, wid, path, token):
            assert token == PAT and native.endpoint(host, wid, path)
            self.calls.append(path)
            return ({'enableIpAccessLists': 'true'} if path == CONF else
                    {'ip_access_lists': [{'list_id': 'abc', 'list_type': 'BLOCK',
                                          'enabled': True, 'ip_addresses': ['0.0.0.0/0'],
                                          'address_count': 1}]})

    arm = parent(RID, 'Microsoft.Databricks/workspaces',
                 {'workspaceId': '123', 'workspaceUrl': HOST, 'publicNetworkAccess': 'Enabled'})
    api = API({SCOPE + '/providers/Microsoft.Databricks/workspaces': {'value': [arm]}, RID: arm})
    snapshot = azure.collect({'scopes': [SCOPE.rsplit('/', 1)[-1]], 'auth': {native.FIELD: {RID: PAT}},
                              'options': {'retries': 0}}, ['databricks_workspace'], transport=api)
    assert api.calls.count(CONF) == 1 and api.calls.count(LIST) == 1
    assert PAT not in json.dumps(snapshot)
    row = next(row for row in assess(snapshot, resources(snapshot))
               if row.resource['type'] == 'databricks_workspace')
    assert row.verdict() == 'PASS'


def test_real_transport_uses_only_pat_get_and_projects(monkeypatch):
    calls = []

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self, size):
            assert size == native.MAX_RESPONSE_BYTES + 1
            return b'{"enableIpAccessLists":"true","secret":"discard"}'

    class Opener:
        def open(self, request, timeout):
            calls.append((request, timeout))
            return Response()

    monkeypatch.setattr(native, 'build_opener', lambda *handlers: Opener())
    assert native.request_policy(HOST, '123', CONF, PAT) == {'enableIpAccessLists': 'true'}
    request, timeout = calls[0]
    assert request.get_method() == 'GET' and request.full_url == 'https://' + HOST + CONF
    assert request.headers['Authorization'] == 'Bearer ' + PAT and timeout == 20
