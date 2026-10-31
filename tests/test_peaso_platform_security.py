"""Local attack regressions: no cloud requests or credential-helper execution."""
import copy
import socket
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from botocore.exceptions import ClientError

from peaso.collectors import k8s
from peaso.server.config import Settings
from peaso.server.validation import validate_connector
from peaso.storage.dynamodb import DynamoStore, row
from peaso.storage import StoreError


def kubeconfig(user=None):
    return {'apiVersion': 'v1', 'kind': 'Config', 'current-context': 'scan',
            'clusters': [{'name': 'target', 'cluster': {'server': 'https://cluster.example'}}],
            'users': [{'name': 'reader', 'user': user or {'token': 'customer-token'}}],
            'contexts': [{'name': 'scan', 'context': {'cluster': 'target', 'user': 'reader'}}]}


@pytest.fixture
def public_dns(monkeypatch):
    monkeypatch.setattr(socket, 'getaddrinfo', lambda *a, **kw: [
        (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('93.184.216.34', 443))])


@pytest.mark.parametrize('method', ['in_cluster', 'in-cluster', 'kubeconfig', 'context'])
def test_hosted_kubernetes_cannot_select_ambient_credentials(method, public_dns):
    auth = {'method': method, 'server': 'https://cluster.example', 'token': 'customer-token'}
    with pytest.raises(HTTPException) as caught:
        validate_connector('k8s', auth, {}, Settings(auth_mode='cognito'))
    assert caught.value.status_code == 422


def test_hosted_access_probe_uses_dns_pinned_transport(monkeypatch):
    from peaso.server.access_check import check_access
    from peaso.server import k8s_access_transport
    captured = []
    def public_server(server):
        captured.append(server)
        raise ValueError('Stop before I/O')
    # Hosted preflight never loads the generated SDK client; it resolves and
    # pins the public endpoint through the collector's DNS guard.
    monkeypatch.setattr(k8s, '_new_api', lambda auth: pytest.fail('hosted preflight used the SDK loader'))
    monkeypatch.setattr(k8s_access_transport, '_public_server', public_server)
    result = check_access('k8s', {'method': 'token', 'server': 'https://cluster.example', 'token': 'customer-token'},
                          ['default'], {}, Settings(auth_mode='cognito'))
    assert captured == ['https://cluster.example']
    assert result['status'] == 'blocked'


def test_local_kubeconfig_exec_helper_never_reaches_sdk_loader(tmp_path, monkeypatch):
    import json
    from kubernetes import config
    path = tmp_path / 'untrusted-config'
    path.write_text(json.dumps(kubeconfig({'exec': {'command': 'never-execute', 'apiVersion': 'client.authentication.k8s.io/v1'}})))
    invoked = []
    monkeypatch.setattr(config, 'new_client_from_config', lambda **kw: invoked.append(kw))
    with pytest.raises(ValueError, match='exec plugin could not run'):
        k8s._new_api({'method': 'kubeconfig', 'kubeconfig': str(path)})
    assert invoked == []


@pytest.mark.parametrize('accept', [True, False])
def test_reissued_workspace_invite_cannot_be_consumed_using_stale_admin_role(accept):
    old = {'role': 'admin', 'email': 'reader@example.com', 'created': 1.0, 'invited_by': 'owner'}
    current = dict(old, role='read', created=2.0)
    class Client:
        committed = False
        def transact_write_items(self, *, TransactItems):
            deletion = TransactItems[0]['Delete']
            expected = row(deletion.get('ExpressionAttributeValues', {}))
            # Model DynamoDB's snapshot conditions on the invitation currently
            # present, after its owner revoked and reissued the old invitation.
            if expected and any(current[key] != expected[':' + key] for key in ('role', 'email', 'created', 'invited_by')):
                raise ClientError({'Error': {'Code': 'TransactionCanceledException'}}, 'TransactWriteItems')
            self.committed = True
    client = Client()
    store = DynamoStore('fixture', client)
    store._workspace_get = lambda key: copy.deepcopy(old)
    with pytest.raises(StoreError) as caught:
        store.respond_workspace_invitation('ws_fixture', 'reader', accept)
    assert caught.value.status == 409 and not client.committed


@pytest.mark.parametrize('user', [
    {'exec': {'command': '/bin/sh', 'args': ['-c', 'touch /never-run']}},
    {'auth-provider': {'name': 'gcp', 'config': {'cmd-path': '/never-run'}}},
    {'tokenFile': '/private/token'}, {'client-key': '/private/key'},
    {'client-certificate': '/private/cert'}, {'username': 'user', 'password': 'password'},
])
def test_kubeconfigs_reject_every_helper_and_external_credential_source(user):
    with pytest.raises(ValueError, match='helpers|files'):
        k8s.validate_inline_kubeconfig(kubeconfig(user))


def test_unused_kubeconfig_context_cannot_hide_an_exec_helper():
    document = kubeconfig()
    document['users'].append({'name': 'unused', 'user': {'exec': {'command': '/never-run'}}})
    with pytest.raises(ValueError, match='helpers'):
        k8s.validate_inline_kubeconfig(document)


def test_safe_inline_kubeconfig_uses_its_embedded_credentials(monkeypatch):
    from kubernetes import client, config
    configurations = []
    monkeypatch.setattr(config, 'new_client_from_config', lambda **kw: pytest.fail('SDK kubeconfig loaders must never execute'))
    def api(configuration):
        configurations.append(configuration)
        return SimpleNamespace(close=lambda: None)
    monkeypatch.setattr(client, 'ApiClient', api)
    monkeypatch.setattr(k8s, '_wrap_client', lambda obj, *args: obj)
    k8s._new_api({'method': 'inline', 'kubeconfig_data': kubeconfig()})
    assert configurations[0].host == 'https://cluster.example'
    assert configurations[0].api_key['authorization'] == 'customer-token'


def test_ai_cannot_launch_without_deployment_isolation(monkeypatch):
    from peaso.ai import pipeline
    monkeypatch.delenv('PEASO_AI_ISOLATION_LAUNCHER', raising=False)
    monkeypatch.setattr(pipeline.subprocess, 'Popen', lambda *a, **kw: pytest.fail('Unisolated AI must not start'))
    with pytest.raises(RuntimeError, match='ai_isolation_unavailable'):
        pipeline.invoke('hardening', {}, [], 'inert-token', [], [], 1)


def test_ai_isolation_launcher_is_explicit_and_not_group_writable(tmp_path, monkeypatch):
    from peaso.ai import isolation
    path = tmp_path / 'deployment-sandbox'
    path.write_text('#!/bin/sh\nexit 1\n')
    path.chmod(0o700)
    monkeypatch.setenv('PEASO_AI_ISOLATION_LAUNCHER', str(path))
    assert isolation.wrap_command(['python', '-m', 'peaso.ai.runner', 'hardening'], tmp_path) == [
        str(path.resolve()), '--workspace', str(tmp_path), '--', 'python', '-m', 'peaso.ai.runner', 'hardening']
    path.chmod(0o770)
    assert isolation.available() is False
    monkeypatch.setenv('PEASO_AI_ISOLATION_LAUNCHER', 'deployment-sandbox')
    assert isolation.available() is False


def test_ai_status_and_local_launch_explain_missing_isolation(tmp_path, monkeypatch):
    from tests.connector_access_receipts import checked_create, mock_access_pass
    mock_access_pass(monkeypatch)
    from fastapi.testclient import TestClient
    from peaso.server import create_app
    from peaso.ai import auth
    monkeypatch.delenv('PEASO_AI_ISOLATION_LAUNCHER', raising=False)
    monkeypatch.setattr('peaso.ai.providers.resolve_access', lambda *a, **kw: ('inert-model-token', 'platform'))
    settings = Settings(state_dir=tmp_path / 'state', identity_dir=tmp_path / 'identity',
                        auth_mode='local', local_token='security-fixture-token-12345678')
    with TestClient(create_app(settings), base_url='http://127.0.0.1') as client:
        client.headers['Authorization'] = 'Bearer ' + settings.local_token
        status = client.get('/api/ai/codex').json()
        assert status['available'] is False and status['isolation_available'] is False
        assert status['unavailable_reason'] == 'ai_isolation_unavailable'
        connector = client.post('/api/connectors', json=checked_create(client, {'name': 'Fixture', 'provider': 'aws'})).json()['id']
        response = client.post('/api/scans', json={'connector_id': connector, 'ai_enabled': True})
        assert response.status_code == 409 and 'isolation launcher' in response.json()['detail']


def test_ai_worker_guard_preserves_deterministic_scan_without_starting_agents(tmp_path, monkeypatch):
    from peaso.ai import pipeline
    from peaso.storage import SQLiteStore, FileArtifacts
    settings = Settings(state_dir=tmp_path / 'state', identity_dir=tmp_path / 'identity')
    store, artifacts = SQLiteStore(settings.state_dir), FileArtifacts(tmp_path / 'artifacts')
    monkeypatch.delenv('PEASO_AI_ISOLATION_LAUNCHER', raising=False)
    monkeypatch.setattr(pipeline, 'Settings', lambda: settings)
    monkeypatch.setattr('peaso.storage.runtime.stores', lambda settings: (store, artifacts))
    monkeypatch.setattr(pipeline, 'personal_token', lambda *args: ('inert-model-token', 'platform'))
    monkeypatch.setattr('peaso.ai.providers.validate_access', lambda access: access)
    monkeypatch.setattr(pipeline, 'invoke', lambda *args: pytest.fail('Worker must enforce isolation before invoking any agent'))
    report = {'provider': 'aws', 'findings': [{'id': 'original-fail', 'status': 'FAIL'}]}
    before = copy.deepcopy(report)
    result = pipeline.review_scan(report, {}, {}, tenant='alice', artifacts=artifacts)
    assert result['status'] == 'unavailable' and result['reason'] == 'ai_isolation_unavailable'
    assert report == before
