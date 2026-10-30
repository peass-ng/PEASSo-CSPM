"""Small offline parser-to-dispatch tests; no provider or network calls."""
import contextlib
import importlib.util
import json
import os
import sys
from pathlib import Path

import pytest


from peaso import cli
import peaso.secret_evidence as secret_evidence


class Captured:
    def public_snapshot(self, snapshot):
        return snapshot


@pytest.fixture
def route(monkeypatch):
    calls = {}
    monkeypatch.setattr(secret_evidence, 'capture', lambda *a, **kw: contextlib.nullcontext(Captured()))
    monkeypatch.setattr(secret_evidence, 'checks_for_request', lambda request: set(request.get('checks') or []))
    monkeypatch.setattr(cli, 'collect_snapshot', lambda request: calls.setdefault('request', request.copy()) or {'provider': 'aws'})
    monkeypatch.setattr(cli, 'evaluate_snapshot', lambda snapshot, **kw: calls.setdefault('evaluation', kw) or {'stats': {}})
    monkeypatch.setattr(cli, '_write', lambda value, *a, **kw: calls.setdefault('output', value))
    monkeypatch.setattr(cli, 'nothing_readable', lambda snapshot: False)
    return calls


@pytest.mark.parametrize('provider,scope,check,option', [
    ('aws', '123456789012/us-east-1', 'aws.review.s3.selected_source_secret_indicators', 'selected_aws_s3_sources'),
    ('gcp', 'projects/example-project', 'gcp.review.dataproc.selected_job_referenced_source_secret_indicators', 'selected_dataproc_referenced_sources'),
    ('azure', '/subscriptions/00000000-0000-0000-0000-000000000000', 'azure.review.machine_learning.selected_command_job_secret_indicators', 'selected_azure_ml_command_jobs'),
    ('k8s', 'default', 'k8s.review.selected_registry_image_secret_indicators', 'selected_k8s_registry_images'),
])
def test_request_checks_reach_collection_and_evaluation(tmp_path, route, provider, scope, check, option):
    request = {'connector': {'provider': provider, 'name': 'owned', 'scopes': [scope],
                             'auth': {'registry_auth': []},
                             'options': {'content_secret_scans': True, option: [{'target': 'fixture'}]}},
               'checks': [check]}
    file = tmp_path / 'request.json'
    file.write_text(json.dumps(request))
    args = cli.build_parser().parse_args(['scan', '--request', str(file), '--quiet'])
    assert cli._execute(args, {'categories': None, 'checks': None, 'frameworks': None}) == 0
    assert route['request']['checks'] == [check]
    assert route['evaluation']['checks'] == [check]
    assert route['request']['connector']['auth'] == {'registry_auth': []}
    assert route['request']['connector']['options'][option] == [{'target': 'fixture'}]


def test_cli_checks_override_request_for_both_phases(tmp_path, route):
    file = tmp_path / 'request.json'
    file.write_text(json.dumps({'connector': {'provider': 'aws', 'scopes': ['123456789012/us-east-1']},
                                'checks': ['aws.claude_a.vpc.vpcs_in_multiple_regions']}))
    # Selected check IDs are validated against the provider registry, so both are real.
    args = cli.build_parser().parse_args(['scan', '--request', str(file), '--checks',
                                          'aws.claude_a.vpc.nondefault_vpcs_in_multiple_regions', '--quiet'])
    cli._execute(args, {'categories': None, 'checks': args.checks, 'frameworks': None})
    assert route['request']['checks'] == route['evaluation']['checks'] == [
        'aws.claude_a.vpc.nondefault_vpcs_in_multiple_regions']


def test_auth_and_options_files_route_without_enabling_content(tmp_path, route):
    auth = tmp_path / 'auth.json'
    options = tmp_path / 'options.json'
    auth.write_text(json.dumps({'registry_auth': []}))
    options.write_text(json.dumps({'content_secret_scans': False}))
    args = cli.build_parser().parse_args(['collect', '--provider', 'k8s', '--scopes', 'default',
                                          '--auth-file', str(auth), '--options-file', str(options), '--quiet'])
    cli._execute(args, {'categories': None, 'checks': None, 'frameworks': None})
    connector = route['request']['connector']
    assert connector['auth'] == {'registry_auth': []}
    assert connector['options'] == {'content_secret_scans': False}
    assert 'checks' not in route['request']


@pytest.mark.parametrize('bad', [
    {'auth': {'selected_k8s_registry_images': []}},
    {'options': {'registry_auth': []}},
    {'options': {'gke_image_kubernetes': []}},
    {'options': {'aks_workloads': []}},
    {'auth': None},
    {'options': None},
])
def test_misrouted_content_input_rejected_before_dispatch(tmp_path, route, bad):
    file = tmp_path / 'request.json'
    file.write_text(json.dumps({'connector': {'provider': 'k8s', 'scopes': ['default'], **bad}}))
    args = cli.build_parser().parse_args(['scan', '--request', str(file), '--quiet'])
    with pytest.raises(ValueError):
        cli._execute(args, {'categories': None, 'checks': None, 'frameworks': None})
    assert 'request' not in route
