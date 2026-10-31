"""Portable connector authentication, JSON framing and principal-level CLI output."""
import io
import json
import os
import stat
import subprocess
import sys
from types import SimpleNamespace

import pytest

from peaso import cli
from peaso.server.validation import auth_capabilities
from peaso.snapshot import make_snapshot


METHODS = [(provider, method) for provider, methods in auth_capabilities(SimpleNamespace(auth_mode='local')).items() for method in methods]


@pytest.mark.parametrize('provider,method', METHODS)
def test_cli_passes_connector_auth_unchanged(provider, method, tmp_path, monkeypatch, capsys):
    auth = {'method': method, 'synthetic_credential_field': 'private-test-value'}
    path = tmp_path / 'auth.json'
    path.write_text(json.dumps(auth))
    snapshot = make_snapshot(provider, ['fixture'], [{'type': 'fixture', 'scope': 'fixture', 'service': 'test', 'status': 'empty', 'items': []}])
    def collect(request):
        assert request['connector']['auth'] == auth
        assert request['connector']['scopes'] == ['fixture']
        return snapshot
    def evaluate(value, *args, **kwargs):
        assert value['provider'] == provider
        return {'provider': provider, 'stats': {'categories': ['hardening']}, 'findings': []}
    monkeypatch.setattr(cli, 'collect_snapshot', collect)
    monkeypatch.setattr(cli, 'evaluate_snapshot', evaluate)
    assert cli.main(['scan', '--provider', provider, '--auth-file', str(path), '--scopes', 'fixture', '--categories', 'hardening', '--quiet']) == 0
    output = capsys.readouterr()
    assert json.loads(output.out)['provider'] == provider
    assert 'private-test-value' not in output.out + output.err


def test_cli_reads_auth_from_stdin_without_putting_credentials_in_argv(monkeypatch, capsys):
    monkeypatch.setattr(sys, 'stdin', io.StringIO('{"method":"token","token":"synthetic-private-token"}'))
    snapshot = make_snapshot('gcp', ['fixture'], [{'type': 'project', 'scope': 'fixture', 'service': 'test', 'status': 'empty', 'items': []}])
    def collect(request):
        assert request['connector']['auth']['token'] == 'synthetic-private-token'
        return snapshot
    monkeypatch.setattr(cli, 'collect_snapshot', collect)
    monkeypatch.setattr(cli, 'evaluate_snapshot', lambda *args, **kwargs: {'provider': 'gcp', 'stats': {'categories': ['hardening']}, 'findings': []})
    assert cli.main(['scan', '--provider', 'gcp', '--auth-file', '-', '--quiet']) == 0
    result = capsys.readouterr()
    assert json.loads(result.out)['provider'] == 'gcp'
    assert 'synthetic-private-token' not in result.out + result.err


@pytest.mark.parametrize('provider', ['aws', 'gcp', 'azure', 'k8s'])
def test_real_cli_json_and_offline_least_privilege_match(provider, tmp_path):
    snapshot, output, offline = [tmp_path / name for name in ('snapshot.json', 'report.json', 'offline.json')]
    prefix = [sys.executable, '-m', 'peaso.cli']
    env = dict(os.environ)
    result = subprocess.run(prefix + ['scan', '--provider', provider, '--demo', '--categories', 'hardening', 'exposure', 'least_privilege',
                                     '--snapshot-output', str(snapshot), '--output', str(output), '--quiet'], capture_output=True, text=True, timeout=60, env=env)
    assert result.returncode == 0, result.stderr
    assert not result.stdout and not result.stderr
    report = json.loads(output.read_text())
    assert set(report['stats']['categories']) == {'hardening', 'exposure', 'least_privilege'}
    assert set(report['least_privilege']) == {'items', 'total', 'coverage'}
    result = subprocess.run(prefix + ['evaluate', str(snapshot), '--categories', 'hardening', 'exposure', 'least_privilege', '--quiet', '-o', str(offline)], capture_output=True, text=True, timeout=60, env=env)
    assert result.returncode == 0, result.stderr
    assert json.loads(offline.read_text())['least_privilege'] == report['least_privilege']
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    assert stat.S_IMODE(snapshot.stat().st_mode) == 0o600


def test_cli_error_hides_provider_exception_details(monkeypatch, capsys):
    def fail(_):
        raise ValueError('provider rejected synthetic-private-token')
    monkeypatch.setattr(cli, 'collect_snapshot', fail)
    assert cli.main(['scan', '--provider', 'gcp', '--quiet']) == 2
    result = capsys.readouterr()
    assert not result.out
    assert 'synthetic-private-token' not in result.err
    assert 'ValueError' in result.err


@pytest.mark.parametrize('source,expected', [({'profile': 'example'}, {'profile_name': 'example'}),
                                           ({'aws_access_key_id': 'test-key', 'aws_secret_access_key': 'test-secret'}, {'aws_access_key_id': 'test-key', 'aws_secret_access_key': 'test-secret'}), ({}, {})])
def test_aws_assume_role_uses_explicit_source_in_native_collector(source, expected, monkeypatch):
    import boto3
    from peaso.collectors.aws import _session
    calls = []
    credentials = SimpleNamespace(method='fixture', get_frozen_credentials=lambda: SimpleNamespace(access_key='frozen-key', secret_key='frozen-secret', token='frozen-token'))
    session = SimpleNamespace(region_name='us-east-1', get_credentials=lambda: credentials)
    def create(**kwargs):
        calls.append(kwargs)
        return session
    monkeypatch.setattr(boto3, 'Session', create)
    _session(dict(source, method='assume_role', role_arn='arn:aws:iam::123456789012:role/ExampleAudit'), 'us-east-1')
    assert calls[0] == dict(expected, region_name='us-east-1')
    assert len(calls) == 2
