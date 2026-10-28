"""Post-scan contracts, credential boundaries, personal auth and partial failures."""
import base64
import copy
import json
from pathlib import Path
import time
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from peaso.ai import access, auth, pipeline
from peaso.ai.contracts import validate_actions, validate_reviews, validate_network, Reviews, Recommendations, NetworkReview
from peaso.ai.crypto import AICipher
from peaso.auth import CredentialCipher, Identity
from peaso.server import create_app
from peaso.server.config import Settings
from peaso.server.models import ScanCreate
from peaso.storage import SQLiteStore, FileArtifacts

_default_token = auth.default_token


@pytest.fixture(autouse=True)
def mocked_agent_isolation(monkeypatch):
    monkeypatch.setattr('peaso.ai.providers.validate_access', lambda access: access)
    monkeypatch.setattr('peaso.ai.providers.validate_before_launch', lambda access: access)
    # These tests mock the agent subprocess. Production must supply an actual
    # deployment-owned isolation launcher; tests never launch unsandboxed AI.
    monkeypatch.setattr(pipeline.isolation, 'launcher', lambda: '/mock/isolation-launcher')
    monkeypatch.setattr(pipeline.isolation, 'available', lambda: True)
    monkeypatch.setattr(pipeline.isolation, 'wrap_command', lambda argv, workspace: argv)


def token(exp=None):
    claims = {'exp': exp or time.time() + 3600, 'https://api.openai.com/auth': {'chatgpt_account_id': 'test'}}
    return 'header.' + base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip('=') + '.signature'


def finding(ident, category='hardening', check='aws.ec2.imdsv2'):
    return dict(id=ident, check_id=check, category=category, resource_id='r1', scope='123456789012/us-east-1', status='FAIL', provider='aws')


def review(ident, verdict='FAIL'):
    return dict(finding_id=ident, verdict=verdict, reason='' if verdict == 'FAIL' else 'Observed configuration supports this verdict; the original check likely missed effective settings.')


def report():
    return {'provider': 'aws', 'findings': [finding('h1'), finding('e1', 'exposure', 'analysis.internet_exposure')],
        'resources': [{'id': 'r1', 'scope': '123456789012/us-east-1'}], 'graphs': {}}


def action():
    return dict(rank=1, severity='high', effort='low', title='Require IMDSv2', finding_ids=['h1'],
        rationale='HttpTokens is optional. Require tokens to reduce instance role credential theft.', steps=['Assess workload compatibility', 'Require IMDSv2'],
        verification='Read the instance metadata settings')


def test_exact_duplicate_control_only_and_input_is_unchanged():
    original = report()
    original['findings'] += [finding('dup', 'exposure'), finding('pass') | {'status': 'PASS'}]
    before = copy.deepcopy(original)
    hardening, exposure, duplicates = pipeline.inputs(original)
    assert [r['id'] for r in hardening] == ['h1']
    assert [r['id'] for r in exposure] == ['e1']
    assert duplicates == {'dup': 'h1'}
    assert original == before


def test_review_coverage_and_three_field_contract():
    validate_reviews({'items': [review('h1')]}, [finding('h1')])
    for items in ([], [review('unknown')], [review('h1'), review('h1')], [review('h1') | {'evidence': []}]):
        with pytest.raises(ValueError):
            validate_reviews({'items': items}, [finding('h1')])
    with pytest.raises(ValueError):
        validate_reviews({'items': [review('h1', 'unsupported')]}, [finding('h1')])


@pytest.mark.parametrize('patch', [{'rank': 2}, {'depends_on': [1]}, {'resource_ids': ['invented']}, {'finding_ids': ['invented']}, {'scopes': ['other-account']}, {'priority': 'high'}, {'provider': 'gcp'}])
def test_recommendations_reject_bad_order_and_cross_references(patch):
    with pytest.raises(ValueError):
        validate_actions({'actions': [action() | patch], 'limitations': []}, report(), [])


@pytest.mark.parametrize('patch', [
    {'rationale': 'x' * 1001}, {'steps': ['x'] * 6}, {'steps': ['x' * 501]},
    {'steps': ['']}, {'verification': 'x' * 701}, {'steps': []},
])
def test_recommendations_require_brief_useful_actions(patch):
    with pytest.raises(ValidationError):
        validate_actions({'actions': [action() | patch], 'limitations': []}, report(), [])


def test_recommendations_have_assessments_and_keep_ranking_and_references():
    expected = {'rank', 'title', 'finding_ids', 'rationale', 'steps', 'verification', 'severity', 'effort'}
    value = validate_actions({'actions': [action()], 'limitations': []}, report(), [])
    assert set(value['actions'][0]) == expected
    assert set(Recommendations.model_json_schema()['$defs']['Action']['required']) == expected
    with pytest.raises(ValueError, match='invalid_action'):
        validate_actions({'actions': [action(), action() | {'rank': 2}], 'limitations': []}, report(), [])
    with pytest.raises(ValueError, match='action_reference_missing'):
        validate_actions({'actions': [action() | {'finding_ids': []}], 'limitations': []}, report(), [])


@pytest.mark.parametrize("verdict", ["PASS", "NOT_APPLICABLE", "EMPTY", "UNKNOWN", "DENIED", "MANUAL"])
def test_nonfail_conclusions_cannot_be_recommended_and_fewer_than_15_is_valid(verdict):
    assert validate_actions({'actions': [action()], 'limitations': []}, report(), [])['actions'][0]['rank'] == 1
    with pytest.raises(ValueError):
        validate_actions({'actions': [action()], 'limitations': []}, report(), [review('h1', verdict)])
    assert validate_actions({'actions': [], 'limitations': []}, report(), [])['actions'] == []


def test_disabled_ai_does_not_resolve_auth_or_credentials(monkeypatch):
    monkeypatch.setattr(pipeline, 'personal_token', lambda *a: pytest.fail('AI opt out must make no auth call'))
    assert pipeline.review_scan({}, {}, {'ai_enabled': False}, tenant='alice', artifacts=None)['reason'] == 'disabled_for_scan'
    assert ScanCreate(connector_id='x').ai_enabled is True
    with pytest.raises(ValidationError):
        ScanCreate(connector_id='x', ai_enabled='false')


def test_priorities_skip_unobserved_network_unknowns_after_denied_inventory(environment, monkeypatch):
    _, _, artifacts = environment
    monkeypatch.setattr(pipeline, 'invoke_before_deadline',
                        lambda *a, **kw: pytest.fail('no AI task is justified by denied inventory'))
    findings = [dict(id='network-unknown', check_id='azure.network.unknown', category='network',
                     status='UNKNOWN', provider='azure', resource_id='uncollected', scope='subscription')]
    data = {'provider': 'azure', 'findings': findings, 'resources': [], 'graphs': {}}
    result = pipeline.review_scan(data, {}, {}, tenant='alice', artifacts=artifacts)
    assert result['status'] == 'completed'
    assert result['network']['status'] == 'not_available'
    assert result['actions'] == []
    assert any('no actionable finding' in row for row in result['limitations'])


def test_priorities_evidence_keeps_confirmed_and_observed_unknown_paths():
    row = dict(id='path', status='UNKNOWN', category='network')
    assert not pipeline._priorities_have_evidence({'findings': [row]}, [], None)
    assert pipeline._priorities_have_evidence({'findings': [row]}, [], {'inventory': [{}]})
    assert pipeline._priorities_have_evidence({'findings': [dict(row, status='FAIL')]}, [], None)
    assert pipeline._priorities_have_evidence({'findings': [dict(row, category='privesc')]}, [], None)


def network_fixture():
    inventory = [dict(id=ident, native_id='native-' + ident, provider='aws', scope='123456789012/us-east-1',
                      type=kind, data=data) for ident, kind, data in (
        ('r1', 'instance', {'VpcId': 'vpc-a', 'SubnetId': 'subnet-a', 'SecurityGroups': [{'GroupId': 'sg-a'}],
                            'UserData': 'never-give-workload-secret'}),
        ('r2', 'security_group', {'GroupId': 'sg-a', 'VpcId': 'vpc-a', 'IpPermissions': [{'IpProtocol': '-1', 'IpRanges': [{'CidrIp': '10.0.0.0/8'}]}]}),
        ('r3', 'vpc', {'VpcId': 'vpc-a', 'CidrBlock': '10.0.0.0/16'}),
        ('r4', 'subnet', {'SubnetId': 'subnet-a', 'VpcId': 'vpc-a', 'CidrBlock': '10.0.1.0/24'}),
        ('unrelated-iam', 'iam_role', {'policy': 'never-give-unrelated-iam'}))]
    graph = {'semantics': 'Structural references, not effective reachability',
             'nodes': [dict(id='node-' + row['id'], resource_id=row['id'], type=row['type'], scope=row['scope'])
                       for row in inventory[:4]],
             'edges': [dict(id='edge-sg', source='node-r1', target='node-r2', type='attached'),
                       dict(id='edge-subnet', source='node-r1', target='node-r4', type='in_subnet')]}
    data = report() | {'resources': [{key: value for key, value in row.items() if key != 'data'} for row in inventory],
                       'graphs': {'network': graph, 'iam': {'nodes': [], 'edges': [], 'secret': 'never-give-unrelated-iam'}},
                       'coverage': [{'level': 'collection', 'type': 'network_acl', 'status': 'denied'},
                                    {'level': 'collection', 'type': 'iam_role', 'status': 'denied'}]}
    output = {'explanation': 'One VPC contains an application subnet. The workload uses a broad security group; intended tier separation needs owner validation.',
              'findings': [{'title': 'Narrow backend security group sources', 'description': 'The attached SG allows all protocols from 10.0.0.0/8.',
                            'rationale': 'A broad source CIDR weakens the tier boundary; required client flows have not been confirmed.',
                            'resource_id': 'r2', 'severity': 'medium', 'status': 'MANUAL',
                            'evidence': {'summary': 'sg-a admits 10.0.0.0/8 on all protocols.', 'resource_ids': ['r1', 'r2'],
                                         'graph_refs': ['edge-sg'], 'observations': ['IpPermissions[0] has IpProtocol=-1 and CidrIp=10.0.0.0/8.']},
                            'remediation': 'Validate client dependencies, then narrow sources and ports while preserving required flows.',
                            'verification': 'Review effective rules and validate required clients after a staged change.'}]}
    return data, inventory, output


def test_network_input_is_network_only_and_retains_complete_topology(tmp_path):
    import sqlite3
    import subprocess
    import sys
    from peaso.ai.network import prepare, build
    data, inventory, _ = network_fixture()
    # Even a caller passing the full platform is narrowed at file creation.
    build(tmp_path, {'report': data, 'inventory': inventory, 'least_privilege': {'secret': 'never-give'}}, [], pipeline.private_json)
    db = sqlite3.connect(tmp_path / 'context.sqlite')
    try:
        encoded = '\n'.join(row[0] for row in db.execute('SELECT detail FROM records'))
        assert 'never-give' not in encoded and 'iam_role' not in encoded
        assert json.loads(db.execute("SELECT detail FROM records WHERE domain='resources' AND id='r2'").fetchone()[0])['data']['IpPermissions']
    finally:
        db.close()
    topology = json.loads((tmp_path / 'topology.json').read_text())
    assert {row['id'] for row in topology['boundaries']} == {'node-r3', 'node-r4'}
    assert sum(row['count'] for row in topology['node_groups']) == 4
    assert sum(row['count'] for row in topology['edge_groups']) == 2
    brief = json.loads((tmp_path / 'platform.json').read_text())
    assert brief['sections']['iam'] == brief['sections']['privesc'] == brief['sections']['least_privilege'] == []
    assert 'network_acl' in json.dumps(brief['coverage'])
    page = subprocess.run([sys.executable, 'context.py', 'list', 'network_nodes', '--all'], cwd=tmp_path,
                          capture_output=True, text=True, check=True)
    assert json.loads(page.stdout)['total'] == 4


@pytest.mark.parametrize('patch', [
    {'explanation': 'x' * 12001},
    {'findings': [{'resource_id': 'invented'}]},
    {'findings': [{'evidence': {'graph_refs': ['invented']}}]},
    {'findings': [{'evidence': {'resource_ids': ['r1']}}]},
])
def test_network_contract_rejects_overlong_explanation_and_invented_references(patch):
    from peaso.ai.network import prepare
    data, inventory, output = network_fixture()
    if 'explanation' in patch:
        output.update(patch)
    else:
        row_patch = patch['findings'][0]
        for key, value in row_patch.items():
            if key == 'evidence':
                output['findings'][0]['evidence'].update(value)
            else:
                output['findings'][0][key] = value
    with pytest.raises(ValueError):
        validate_network(output, prepare(data, inventory, {}))


def test_network_findings_have_standard_fields_and_publish_without_mutating_scan():
    from peaso.ai.network import prepare, with_findings
    data, inventory, output = network_fixture()
    before = copy.deepcopy(data)
    value = validate_network(output, prepare(data, inventory, {}))
    row = value['findings'][0]
    assert {'id', 'check_id', 'category', 'title', 'description', 'rationale', 'provider', 'service', 'scope',
            'severity', 'status', 'frameworks', 'evidence', 'remediation', 'verification'} <= row.keys()
    assert row['category'] == row['finding_type'] == 'network' and row['evidence']['source'] == 'ai_network_review'
    enriched = with_findings(data, value['findings'])
    assert data == before
    assert enriched['stats']['by_status']['MANUAL'] == 1
    assert len(enriched['findings']) == len(data['findings']) + 1
    assert with_findings(enriched, value['findings']) == enriched
    with pytest.raises(ValueError, match='duplicate_network'):
        validate_network(output | {'findings': output['findings'] * 2}, prepare(data, inventory, {}))


def test_network_review_shares_parallel_limit_and_finishes_before_priorities(environment, monkeypatch):
    import threading
    from concurrent.futures import ThreadPoolExecutor
    data, inventory, output = network_fixture()
    monkeypatch.setattr('peaso.snapshot.resources', lambda _: inventory)
    monkeypatch.setenv('PEASO_AI_MAX_CONCURRENCY', '2')
    monkeypatch.setattr(pipeline, 'available_memory', lambda: 4 * 1024**3)
    network_started, release_network, priorities_started = (threading.Event() for _ in range(3))
    completed = []
    active = peak = 0
    lock = threading.Lock()
    received = []
    def invoke(stage, platform, entries, selected_token, findings, reviews, timeout):
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
        try:
            if stage == 'network':
                network_started.set()
                assert release_network.wait(5)
                return output
            if stage == 'priorities':
                priorities_started.set()
                assert release_network.is_set() and active == 1
                assert platform['network_review']['explanation'] == output['explanation']
                assert platform['network_review']['status'] == 'completed'
                rows = [row for row in platform['report']['findings'] if row.get('category') == 'network']
                assert len(rows) == 1 and rows[0]['evidence']['source'] == 'ai_network_review'
                received.extend(rows)
                return {'actions': [action() | {'title': rows[0]['title'], 'finding_ids': [rows[0]['id']]}], 'limitations': []}
            raise AssertionError('removed reviewer was launched')
        finally:
            with lock:
                active -= 1
    monkeypatch.setattr(pipeline, 'invoke', invoke)
    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(pipeline.review_scan, data, {}, {}, tenant='alice', artifacts=environment[2])
        try:
            # This tests queue overlap, independently of cold evidence imports.
            assert network_started.wait(30)
            assert not priorities_started.is_set() and not future.done()
        finally:
            release_network.set()
        result = future.result(timeout=5)
    assert result['status'] == 'completed' and peak == 1
    assert result['network']['status'] == 'completed' and received == result['network']['findings']
    assert result['actions'][0]['finding_ids'] == [received[0]['id']]


def test_network_failure_preserves_reviews_and_still_runs_priorities(environment, monkeypatch):
    data, inventory, _ = network_fixture()
    monkeypatch.setattr('peaso.snapshot.resources', lambda _: inventory)
    calls = []
    def invoke(stage, platform, entries, selected_token, findings, reviews, timeout):
        calls.append(stage)
        if stage == 'network':
            raise RuntimeError('private-error')
        if stage == 'priorities':
            assert len(reviews) == 2
            return {'actions': [], 'limitations': []}
        return {'items': [review(row['id']) for row in findings]}
    monkeypatch.setattr(pipeline, 'invoke', invoke)
    result = pipeline.review_scan(data, {}, {}, tenant='alice', artifacts=environment[2])
    assert calls == ['network', 'priorities']
    assert result['status'] == 'partial' and result['coverage']['reviewed'] == 2
    assert result['network']['status'] == 'unavailable' and result['network']['findings'] == []
    assert 'private-error' not in json.dumps(result)


def test_priorities_brief_includes_new_network_findings_and_assessment(tmp_path):
    from peaso.ai.briefing import build
    from peaso.ai.network import prepare, with_findings
    data, inventory, output = network_fixture()
    network = validate_network(output, prepare(data, inventory, {}))
    assessment = {'status': 'completed', 'explanation': output['explanation']}
    platform = {'report': with_findings(data, network['findings']), 'inventory': inventory, 'network_review': assessment}
    build(tmp_path, platform, [], [], pipeline.private_json)
    brief = json.loads((tmp_path / 'platform.json').read_text())
    assert brief['network_review'] == assessment
    cases = [case for case in brief['sections']['findings'] if case['facts']['category'] == 'network']
    assert len(cases) == 1 and cases[0]['state'] == 'MANUAL'
    assert cases[0]['example']['id'] == network['findings'][0]['id']


@pytest.mark.parametrize('provider,kind,data', [
    ('aws', 'vpn_connection', {'VpcId': 'vpc', 'CustomerGatewayConfiguration': '<xml>pre-shared-secret</xml>'}),
    ('aws', 'lambda_function', {'VpcConfig': {'SubnetIds': ['subnet']}, 'Environment': {'Variables': {'secret': 'hidden'}}}),
    ('gcp', 'instance', {'networkInterfaces': [{'network': 'n'}], 'metadata': {'startup-script': 'secret'}}),
    ('azure', 'vm', {'properties': {'networkProfile': {'networkInterfaces': ['nic']}, 'osProfile': {'adminPassword': 'secret'}}}),
    ('k8s', 'pod', {'metadata': {'name': 'pod', 'annotations': {'secret': 'hidden'}},
                     'spec': {'hostNetwork': True, 'containers': [{'env': [{'name': 'SECRET', 'value': 'secret'}], 'ports': [{'containerPort': 443}]}]}}),
])
def test_network_native_projection_omits_unrelated_workload_data_and_secrets(provider, kind, data):
    from peaso.ai.network import native_network_resource
    row = {'id': 'r', 'provider': provider, 'scope': 'target', 'type': kind, 'data': data}
    before = copy.deepcopy(row)
    projected = native_network_resource(row)
    assert projected['data'] and 'secret' not in json.dumps(projected).lower()
    assert row == before


def test_network_runner_uses_private_files_and_cleanup(tmp_path, monkeypatch):
    from peaso.ai.network import prepare
    data, inventory, output = network_fixture()
    platform = prepare(data, inventory, {})
    observed = {}
    class Process:
        returncode = 0
        def __init__(self, argv, *, cwd, env, **kwargs):
            root = Path(cwd)
            observed['root'] = root
            assert argv[-1] == 'network'
            assert {path.name for path in root.iterdir()} == {'credentials.json', 'codex-auth.json', 'platform.json', 'context.py', 'context.sqlite', 'topology.json', 'exposure.json'}
            assert all(path.stat().st_mode & 0o777 == 0o600 for path in root.iterdir())
            assert root.stat().st_mode & 0o777 == 0o700
            assert 'private-cloud-token' not in json.dumps(argv) + json.dumps(env)
            assert json.loads((root / 'credentials.json').read_text())['entries'][0]['token'] == 'private-cloud-token'
            (root / 'result.json').write_text(json.dumps(output))
        def wait(self, **kwargs):
            return 0
    monkeypatch.setattr(pipeline.subprocess, 'Popen', Process)
    monkeypatch.setattr(pipeline, 'kill_tree', lambda process: observed.update(cleaned=True))
    result = pipeline.invoke('network', platform, [{'provider': 'gcp', 'format': 'bearer', 'token': 'private-cloud-token'}], 'private-codex-token', [], [], 10)
    assert result == output and observed['cleaned'] and not observed['root'].exists()


def test_network_findings_publish_in_regular_api_and_paginated_ai_result(environment):
    from test_peaso_api_large import completed_job
    from peaso.ai.network import prepare, with_findings
    settings, store, artifacts = environment
    data, inventory, output = network_fixture()
    network = validate_network(output, prepare(data, inventory, {})) | {'status': 'completed'}
    data.update(schema_version='1.0', snapshot_id='fixture', created_at='2026-10-19T10:00:00Z', stats={},
                ai={'status': 'completed', 'actions': [], 'reviews': {}, 'network': network})
    data = with_findings(data, network['findings'])
    ident, bundle = completed_job(store, artifacts, data)
    assert 'network' not in bundle['summary']['ai']
    with TestClient(create_app(settings, store=store, artifacts=artifacts, authenticator=Identities()), base_url='http://127.0.0.1') as client:
        response = client.get(f'/api/scans/{ident}/ai?limit=1')
        assert response.status_code == 200 and 'network' in response.json(), response.text
        result = response.json()['network']
        assert result['total'] == 1 and result['explanation'] == network['explanation']
        assert len(result['findings']) == 1
        assert client.get(f'/api/scans/{ident}/ai?offset=1&limit=1').json()['network']['findings'] == []
        row = network['findings'][0]
        detail = client.get(f'/api/scans/{ident}/findings/{row["id"]}')
        assert detail.status_code == 200, detail.text
        assert detail.json()['remediation'] == row['remediation']
        assert detail.json()['evidence']['source'] == 'ai_network_review'
        assert client.get(f'/api/scans/{ident}/ai', headers={'Authorization': 'Bearer bob'}).status_code == 404


def test_capture_is_opt_in_and_never_exports_permanent_aws_keys():
    access.finish()
    access.bearer('gcp', 'google', 'secret-token')
    assert access.finish() == []
    access.begin()
    access.bearer('azure', 'https://graph.microsoft.com', token())
    assert access.finish()[0]['format'] == 'bearer'
    session = SimpleNamespace(get_credentials=lambda: SimpleNamespace(get_frozen_credentials=lambda: SimpleNamespace(access_key='permanent', secret_key='secret', token=None)))
    access.begin()
    access.aws([(session, {'Account': '123456789012', 'Arn': 'arn'})])
    assert access.finish() == []  # No STS exchange available: never export the keys.


@pytest.fixture
def environment(tmp_path, monkeypatch):
    settings = Settings(state_dir=tmp_path/'state', identity_dir=tmp_path/'identity')
    store, artifacts = SQLiteStore(settings.state_dir), FileArtifacts(tmp_path/'artifacts')
    monkeypatch.setattr(pipeline, 'Settings', lambda: settings)
    monkeypatch.setattr('peaso.storage.runtime.stores', lambda _: (store, artifacts))
    monkeypatch.setattr(auth, 'default_token', lambda: token())
    monkeypatch.setattr('peaso.least_privilege.project', lambda *a, **k: {'items': []})
    monkeypatch.setattr('peaso.snapshot.resources', lambda _: [])
    monkeypatch.setenv('PEASO_AI_MAX_CONCURRENCY', '1')
    monkeypatch.setattr(pipeline, 'available_memory', lambda: 4 * 1024**3)
    return settings, store, artifacts


@pytest.mark.parametrize('provider', ['aws', 'gcp', 'azure', 'k8s'])
def test_native_verdicts_feed_priorities_without_review_agents(provider, environment, monkeypatch):
    data = {'provider': provider, 'findings': [
        dict(finding('hard', 'hardening'), provider=provider),
        dict(finding('exposed', 'exposure', 'analysis.internet_exposure'), provider=provider),
    ], 'graphs': {}}
    calls = []
    def invoke(stage, platform, entries, selected_token, findings, reviews, timeout):
        calls.append(stage)
        assert stage == 'priorities'
        assert {row['id'] for row in findings} == {'hard', 'exposed'}
        assert {row['finding_id'] for row in reviews} == {'hard', 'exposed'}
        assert all(row['verdict'] == 'FAIL' for row in reviews)
        return {'actions': [], 'limitations': []}
    monkeypatch.setattr(pipeline, 'invoke', invoke)
    result = pipeline.review_scan(data, {}, {'ai_network_enabled': False}, tenant='alice',
                                  artifacts=environment[2])
    assert calls == ['priorities']
    assert result['status'] == 'completed'
    assert result['native_final'] == {'hardening': ['hard'], 'exposure': ['exposed']}


def test_pipeline_prioritizes_native_findings_and_redacts(environment, monkeypatch):
    settings, store, artifacts = environment
    calls = []
    def invoke(stage, platform, entries, selected_token, findings, reviews, timeout):
        calls.append(stage)
        assert stage == 'priorities'
        assert platform['report']['graphs'] == {} and 'least_privilege' in platform
        assert {r['finding_id'] for r in reviews} == {'h1', 'e1'}
        return {'actions': [action() | {'rationale': selected_token}], 'limitations': []}
    monkeypatch.setattr(pipeline, 'invoke', invoke)
    result = pipeline.review_scan(report(), {}, {}, tenant='alice', artifacts=artifacts)
    assert calls == ['priorities']
    assert result['status'] == 'completed' and result['coverage']['reviewed'] == 2
    assert result['actions'][0]['rationale'] == '[REDACTED]'


class Identities:
    def authenticate(self, value):
        return Identity('bob' if value == 'Bearer bob' else 'alice')


def test_sign_in_poll_disconnect_and_tenant_isolation(environment, monkeypatch):
    settings, store, artifacts = environment
    calls = []
    def post(path, data, **kw):
        calls.append(path)
        if path.endswith('usercode'):
            return 200, {'device_auth_id': 'device-secret', 'user_code': 'CODE-123', 'interval': '5'}
        if path.endswith('deviceauth/token'):
            return 200, {'authorization_code': 'code', 'code_verifier': 'verifier'}
        return 200, {'access_token': token(), 'refresh_token': 'refresh-secret', 'id_token': 'id-secret'}
    monkeypatch.setattr(auth, 'post', post)
    with TestClient(create_app(settings, store=store, artifacts=artifacts, authenticator=Identities()), base_url='http://127.0.0.1') as client:
        start = client.post('/api/ai/codex/login', json={})
        assert start.status_code == 200 and start.json()['user_code'] == 'CODE-123'
        assert 'device-secret' not in start.text
        assert client.post('/api/ai/codex/login/poll', json={}).json()['status'] == 'connected'
        assert client.get('/api/ai/codex').json()['connected'] is True
        encrypted = store.ai_state('alice', 'auth')
        assert 'refresh-secret' not in encrypted
        assert AICipher(settings.identity_dir).decrypt(encrypted)['refresh_token'] == 'refresh-secret'
        assert client.get('/api/ai/codex', headers={'Authorization': 'Bearer bob'}).json()['connected'] is False
        assert client.delete('/api/ai/codex').status_code == 204
        assert client.get('/api/ai/codex').json()['connected'] is False


def test_auth_compare_and_swap_prevents_refresh_or_disconnect_overwrite(environment):
    _, store, _ = environment
    assert store.set_ai_state('alice', 'auth', 'first')
    assert not store.set_ai_state('alice', 'auth', 'stale')
    assert store.set_ai_state('alice', 'auth', 'second', 'first')
    assert not store.set_ai_state('alice', 'auth', None, 'first')
    assert store.ai_state('alice', 'auth') == 'second'


def test_checked_in_schemas_match_contracts():
    for name, model in [('reviews', Reviews), ('recommendations', Recommendations)]:
        assert json.loads((Path('peaso/ai')/(name + '.schema.json')).read_text()) == model.model_json_schema()


def test_multiple_aws_accounts_get_separate_frozen_credentials():
    def session(key):
        return SimpleNamespace(get_credentials=lambda: SimpleNamespace(get_frozen_credentials=lambda: SimpleNamespace(access_key=key, secret_key='secret', token='temporary-session')))
    access.begin()
    access.aws([(session('one'), {'Account': '111111111111', 'Arn': 'arn-one'}), (session('two'), {'Account': '222222222222', 'Arn': 'arn-two'})])
    entries = access.finish()
    assert {row['account_id']: row['aws_access_key_id'] for row in entries} == {'111111111111': 'one', '222222222222': 'two'}
    assert all(row['aws_session_token'] for row in entries)


def test_personal_auth_failure_never_falls_back_to_platform(environment, monkeypatch):
    settings, store, _ = environment
    cipher = AICipher(settings.identity_dir)
    store.set_ai_state('alice', 'auth', cipher.encrypt({'access_token': token(time.time() - 10), 'refresh_token': 'refresh'}))
    monkeypatch.setattr(auth, 'post', lambda *a, **kw: (401, {}))
    monkeypatch.setattr(auth, 'default_token', lambda: pytest.fail('A broken personal connection must not charge the platform account'))
    with pytest.raises(RuntimeError, match='codex_reconnect_required'):
        auth.personal_token(store, cipher, 'alice')


def test_ai_endpoint_is_tenant_scoped_and_paginates_large_reviews(environment):
    from test_peaso_api_large import completed_job
    settings, store, artifacts = environment
    data = report() | {'schema_version': '1.0', 'snapshot_id': 'fixture', 'created_at': '2026-10-19T10:00:00Z', 'coverage': [], 'stats': {},
                       'ai': {'status': 'completed', 'actions': [], 'reviews': {'hardening': [review(str(i)) for i in range(120)]}}}
    ident, bundle = completed_job(store, artifacts, data)
    assert 'reviews' not in bundle['summary']['ai'] and bundle['ai_review']
    with TestClient(create_app(settings, store=store, artifacts=artifacts, authenticator=Identities()), base_url='http://127.0.0.1') as client:
        response = client.get(f'/api/scans/{ident}/ai?offset=50&limit=20')
        assert response.status_code == 200
        assert response.json()['review_totals']['hardening'] == 120
        assert response.json()['reviews']['hardening'][0]['finding_id'] == '50'
        assert len(response.json()['reviews']['hardening']) == 20
        assert client.get(f'/api/scans/{ident}/ai', headers={'Authorization': 'Bearer bob'}).status_code == 404


def test_dynamo_ai_auth_compare_and_swap():
    moto = pytest.importorskip('moto')
    import boto3
    from peaso.storage.dynamodb import DynamoStore
    with moto.mock_aws():
        client = boto3.client('dynamodb', region_name='us-east-1')
        client.create_table(TableName='ai-test', KeySchema=[{'AttributeName': 'PK', 'KeyType': 'HASH'}, {'AttributeName': 'SK', 'KeyType': 'RANGE'}], AttributeDefinitions=[{'AttributeName': 'PK', 'AttributeType': 'S'}, {'AttributeName': 'SK', 'AttributeType': 'S'}], BillingMode='PAY_PER_REQUEST')
        store = DynamoStore('ai-test', client)
        assert store.set_ai_state('alice', 'auth', 'encrypted')
        assert not store.set_ai_state('alice', 'auth', 'stale')
        assert store.ai_state('bob', 'auth') is None
        assert store.set_ai_state('alice', 'auth', 'new', 'encrypted')
        assert not store.set_ai_state('alice', 'auth', None, 'encrypted')
        assert store.set_ai_state('alice', 'auth', None, 'new')


@pytest.mark.parametrize('provider', ['aws', 'gcp', 'azure', 'k8s'])
def test_worker_persists_captured_access_with_separate_key(provider, environment, monkeypatch):
    import multiprocessing
    # Initialize the real native registry before replacing its collector I/O.
    import peaso.checks
    from peaso.snapshot import make_snapshot
    from peaso.worker import _process
    settings, _, artifacts = environment
    scope, native_kind = {
        'aws': ('123456789012/us-east-1', 'instance'),
        'gcp': ('projects/fixture-project', 'network'),
        'azure': ('/subscriptions/11111111-1111-1111-1111-111111111111', 'resource_group'),
        'k8s': ('fixture-cluster', 'pod'),
    }[provider]
    def collect(_):
        if provider == 'aws':
            access.remember('aws', '123456789012', {'format': 'aws-session', 'account_id': '123456789012',
                            'aws_session_token': 'captured-session-token'})
        else:
            access.bearer(provider, 'fixture-audience', 'captured-session-token')
        return make_snapshot(provider, [scope], [{'type': native_kind, 'scope': scope, 'status': 'collected', 'items': [{'id': 'one'}]}])
    monkeypatch.setattr('peaso.engine.collect_snapshot', collect)
    # This fixture exercises captured-key persistence, not live AWS identity.
    monkeypatch.setattr('peaso.worker._verify_aws_credentials', lambda connector: None)
    context = multiprocessing.get_context('fork')
    parent, child = context.Pipe(duplex=False)
    request = {'artifact_config': {'mode': 'file', 'root': str(artifacts.root)}, 'tenant_id': 'alice', 'scan_id': 'a' * 32,
               'connector': {'provider': provider, 'auth': {}, 'options': {}, 'scopes': [scope]}, 'ai_context': {'identity_dir': str(settings.identity_dir)}}
    process = context.Process(target=_process, args=('collector', request, child))
    try:
        process.start()
        child.close()
        deadline = time.monotonic() + 30
        for _ in range(256):
            remaining = deadline - time.monotonic()
            assert remaining > 0 and parent.poll(remaining), 'Worker did not produce a terminal result'
            event = parent.recv()
            if (isinstance(event, tuple) and len(event) == 2
                    and event[0] in {'__runtime_metrics__', '__progress__'}):
                assert isinstance(event[1], dict)
                continue
            assert isinstance(event, tuple) and len(event) >= 2 and type(event[0]) is bool
            success, reference, *rest = event
            assert success, rest
            break
        else:
            pytest.fail('Worker emitted too many nonterminal frames')
        snapshot = artifacts.get('alice', reference)
        if provider == 'aws':
            # Shared AWS identities are deliberately excluded from shell agents.
            assert 'ai_access_reference' not in snapshot.get('metadata', {})
            assert 'captured-session-token' not in json.dumps(snapshot)
            return
        sealed = artifacts.get('alice', snapshot['metadata']['ai_access_reference'])['sealed']
        entries = AICipher(settings.identity_dir).decrypt(sealed)['entries']
        assert entries[0]['provider'] == provider
        assert entries[0]['token'] == 'captured-session-token'
        assert 'captured-session-token' not in json.dumps(snapshot)
    finally:
        process.join(timeout=2)
        if process.is_alive():
            process.kill()
            process.join()
        parent.close()


def test_reviewer_context_contains_only_exact_batch_resource_references():
    data = report() | {'snapshot_id': 'snapshot', 'created_at': '2026-10-19T10:00:00Z',
                       'least_privilege': {'must_not_leak': True}, 'graphs': {'privesc': {'must_not_leak': True}}}
    batch = [finding('h1') | {'evidence': {'native_resource_ref': 'policy-r1'}}]
    inventory = {'r1': {'id': 'r1', 'data': {'setting': 'relevant'}},
                 'policy-r1': {'id': 'policy-r1', 'data': {'policy': 'referenced'}},
                 'other': {'id': 'other', 'data': {'setting': 'unrelated'}}}
    before = copy.deepcopy((data, inventory, batch))
    context = pipeline.review_context(data, inventory, batch)
    assert set(context) == {'scan', 'resources'}
    assert set(context['scan']) == {'provider', 'snapshot_id', 'created_at'}
    assert {row['id'] for row in context['resources']} == {'r1', 'policy-r1'}
    assert 'must_not_leak' not in json.dumps(context) and 'unrelated' not in json.dumps(context)
    assert (data, inventory, batch) == before


def test_reviewer_aws_access_excludes_unrelated_accounts_and_providers():
    entries = [{'provider': 'aws', 'account_id': '123456789012', 'token': 'allowed'},
               {'provider': 'aws', 'account_id': '222222222222', 'token': 'unrelated'},
               {'provider': 'gcp', 'token': 'another-provider'}]
    assert pipeline.review_credentials(entries, 'aws', [finding('h1')], {'resources': []}) == entries[:1]
    assert pipeline.review_credentials(entries, 'aws', [finding('h1') | {'scope': 'unresolved'}], {'resources': []}) == []
    assert pipeline.review_credentials(entries, 'gcp', [], {}) == entries[2:]


@pytest.mark.parametrize('entry, expected, excluded', [
    ({'provider': 'aws', 'format': 'aws-session', 'aws_secret_access_key': 'never-show-secret'},
     ['AWS sessions', 'boto3.Session', 'account_id'], ['GCP', 'Azure', 'Kubernetes', 'Bearer']),
    ({'provider': 'gcp', 'format': 'bearer', 'token': 'never-show-secret'},
     ['GCP access tokens', 'Bearer'], ['AWS', 'Azure', 'Kubernetes', 'boto3']),
    ({'provider': 'azure', 'format': 'bearer', 'audience': 'https://management.azure.com', 'token': 'never-show-secret'},
     ['Azure access', 'ARM', 'Bearer'], ['AWS', 'GCP', 'Kubernetes', 'Microsoft Graph', 'Key Vault', 'Storage']),
    ({'provider': 'k8s', 'format': 'kubeconfig', 'kubeconfig': {'secret': 'never-show-secret'}},
     ['Kubernetes access', 'new_client_from_config_dict'], ['AWS', 'GCP', 'Azure', 'Bearer', 'boto3']),
])
def test_access_prompt_describes_only_supplied_credential_types(entry, expected, excluded):
    from peaso.ai.prompting import access_instructions
    text = access_instructions([entry])
    for phrase in expected:
        assert phrase in text
    for phrase in excluded + ['never-show-secret']:
        assert phrase not in text
    assert 'entries[0]' in text and 'entries[1]' not in text


def test_access_prompt_lists_only_actual_azure_audiences_and_entry_indices():
    from peaso.ai.prompting import access_instructions
    text = access_instructions([
        {'provider': 'azure', 'format': 'bearer', 'audience': 'https://management.azure.com'},
        {'provider': 'azure', 'format': 'bearer', 'audience': 'https://graph.microsoft.com'},
    ])
    assert 'entries[0] is for ARM' in text and 'entries[1] is for Microsoft Graph' in text
    assert 'Key Vault' not in text and 'Storage' not in text and 'GCP' not in text
    assert 'interchange' in text


def test_no_access_prompt_has_no_irrelevant_cloud_login_instructions():
    from peaso.ai.prompting import access_instructions
    text = access_instructions([])
    assert 'No live cloud access' in text and 'UNKNOWN' in text
    assert not any(word in text for word in ('boto3', 'Bearer', 'kubeconfig', 'AWS', 'Azure', 'GCP'))


@pytest.mark.parametrize('stage', ['network', 'priorities'])
def test_real_chack_yaml_loader_schema_and_dynamic_access_prompt(stage, monkeypatch):
    pytest.importorskip('chack_agent')
    import chack_agent.config as chack_config
    from chack_agent import Chack
    from peaso.ai.prompting import access_instructions, agent_config_path
    # Exercise the actual loader and prompt renderer without resolving remote
    # model catalogs or running a model/tool.
    monkeypatch.setattr(chack_config, 'resolve_config_aliases', lambda config: config)
    config = chack_config.load_config(str(agent_config_path(stage)))
    assert config.model.primary == 'OPENAI_BEST_QUALITY'
    assert config.model.provider == 'codex' and config.model.api_key_type == 'codex'
    assert config.agent.sub_action == stage and config.agent.output_schema_json
    assert config.agent.output_schema_json == {'priorities': Recommendations, 'network': NetworkReview}.get(stage, Reviews).model_json_schema()
    assert 'Good:' in config.system_prompt and 'Bad:' in config.system_prompt
    stub = SimpleNamespace(config=config)
    rendered = Chack._render_user_prompt(stub, context=None, prompt_variables_override={
        'access_instructions': access_instructions([{'provider': 'aws', 'format': 'aws-session'}])})
    assert '{access_instructions}' not in rendered and 'boto3.Session' in rendered
    assert 'Azure' not in rendered and 'GCP' not in rendered and 'Kubernetes' not in rendered
    if stage in ('hardening', 'exposure'):
        assert 'platform.json' not in config.system_prompt and 'supporting_resources' in config.system_prompt
    else:
        assert 'platform.json' in config.system_prompt and 'context.py' in config.system_prompt


def test_prioritizer_receives_compact_overview_and_indexed_details(monkeypatch):
    platform = {'report': {'graphs': {'network': {}, 'privesc': {}}}, 'inventory': [{'id': 'r1'}], 'least_privilege': {}}
    class Process:
        returncode = 0
        def __init__(self, argv, *, cwd, env, **kw):
            root = Path(cwd)
            assert {path.name for path in root.iterdir()} == {'platform.json', 'context.sqlite', 'context.py', 'credentials.json', 'codex-auth.json'}
            overview = json.loads((root/'platform.json').read_text())
            assert 'report' not in overview and overview['counts']['cases']['findings'] == 1
            import sqlite3
            with sqlite3.connect(root/'context.sqlite') as db:
                detail = json.loads(db.execute("SELECT detail FROM records WHERE domain='findings' AND id='h1'").fetchone()[0])
                assert detail['review'] is None
            assert (root/'context.sqlite').stat().st_mode & 0o777 == 0o600
            (root/'result.json').write_text('{"actions": [], "limitations": []}')
        def wait(self, **kw):
            return 0
    monkeypatch.setattr(pipeline.subprocess, 'Popen', Process)
    monkeypatch.setattr(pipeline, 'kill_tree', lambda _: None)
    assert pipeline.invoke('priorities', platform, [], 'token', [finding('h1')], [review('h1')], 10)['actions'] == []


@pytest.mark.parametrize('status', ['PASS', 'FAIL', 'UNKNOWN', 'DENIED', 'MANUAL', 'NOT_APPLICABLE', 'EMPTY'])
def test_review_accepts_existing_finding_statuses_and_only_three_fields(status):
    value = validate_reviews({'items': [review('h1', status)]}, [finding('h1')])['items'][0]
    assert set(value) == {'finding_id', 'verdict', 'reason'}
    assert value['verdict'] == status


def test_review_reason_character_limit_is_enforced():
    value = review('h1', 'PASS') | {'reason': 'x' * 500}
    assert len(validate_reviews({'items': [value]}, [finding('h1')])['items'][0]['reason']) == 500
    for reason in ('', 'x' * 501):
        with pytest.raises(ValidationError):
            validate_reviews({'items': [value | {'reason': reason}]}, [finding('h1')])


@pytest.mark.parametrize('stage', ['priorities'])
@pytest.mark.parametrize('status', ['PASS', 'UNKNOWN', 'DENIED', 'MANUAL', 'NOT_APPLICABLE', 'EMPTY'])
def test_agent_file_boundary_rejects_nonfailed_checks(stage, status, monkeypatch):
    monkeypatch.setattr(pipeline.subprocess, 'Popen', lambda *a, **kw: pytest.fail('Out-of-scope findings must never reach an agent'))
    category = 'hardening' if stage == 'priorities' else stage
    rows = [finding('failed', category), finding('other', category) | {'status': status}]
    with pytest.raises(ValueError, match='ai_findings_out_of_scope'):
        pipeline.invoke(stage, {}, [], 'token', rows, [], 10)


@pytest.mark.parametrize('stage,category', [('priorities', 'privesc')])
def test_agent_file_boundary_rejects_other_categories(stage, category):
    with pytest.raises(ValueError, match='ai_findings_out_of_scope'):
        pipeline.invoke(stage, {}, [], 'token', [finding('wrong-category', category)], [], 10)


@pytest.mark.parametrize('stage', ['hardening', 'exposure'])
def test_removed_agents_reject_direct_launch(stage, monkeypatch):
    monkeypatch.setattr(pipeline.subprocess, 'Popen', lambda *a, **kw: pytest.fail('removed agent launched'))
    with pytest.raises(ValueError, match='unknown_ai_stage'):
        pipeline.invoke(stage, {}, [], 'token', [], [], 10)


def test_every_confirmed_failure_is_returned_with_empty_reason():
    findings = [finding('first'), finding('second')]
    items = [review('first'), review('second')]
    assert validate_reviews({'items': items}, findings)['items'] == [
        {'finding_id': 'first', 'verdict': 'FAIL', 'reason': ''},
        {'finding_id': 'second', 'verdict': 'FAIL', 'reason': ''},
    ]
    with pytest.raises(ValueError, match='review_coverage_mismatch'):
        validate_reviews({'items': items[:1]}, findings)


@pytest.mark.parametrize('reason', [' ', 'The failure is confirmed.'])
def test_confirmed_failure_reason_must_be_exactly_empty(reason):
    with pytest.raises(ValidationError):
        validate_reviews({'items': [review('h1') | {'reason': reason}]}, [finding('h1')])


@pytest.mark.parametrize('verdict', ['PASS', 'UNKNOWN', 'DENIED', 'MANUAL', 'NOT_APPLICABLE', 'EMPTY'])
def test_other_verdicts_still_require_an_explanation(verdict):
    with pytest.raises(ValidationError):
        validate_reviews({'items': [review('h1', verdict) | {'reason': ''}]}, [finding('h1')])


def test_fifty_aws_accounts_keep_fifty_sessions_targets_and_instructions():
    from peaso.ai.prompting import access_instructions
    contexts = []
    scopes = []
    for index in range(50):
        account = str(100000000000 + index)
        creds = SimpleNamespace(access_key=f'private-key-{index}', secret_key=f'private-secret-{index}', token=f'private-token-{index}')
        session = SimpleNamespace(get_credentials=lambda c=creds: SimpleNamespace(get_frozen_credentials=lambda: c))
        contexts.append((session, {'Account': account, 'Arn': f'arn:aws:sts::{account}:assumed-role/Audit/scan'}))
        scopes.extend([account + '/us-east-1', account + '/eu-west-1'])
    access.begin()
    try:
        access.aws(contexts)
    finally:
        captured = access.finish()
    entries = access.bind_targets(captured, {'provider': 'aws', 'scopes': scopes})
    assert len(entries) == 50 and len({e['account_id'] for e in entries}) == 50
    assert all(len(e['target_scopes']) == 2 for e in entries)
    text = access_instructions(entries)
    for index in range(50):
        assert f'entries[{index}]' in text and str(100000000000 + index) in text
    assert 'private-key-' not in text and 'private-secret-' not in text and 'private-token-' not in text
    assert 'GCP' not in text and 'Azure' not in text and 'Kubernetes' not in text
    rows = [finding('target') | {'scope': scopes[-1]}]
    selected = pipeline.review_credentials(entries, 'aws', rows, {})
    assert len(selected) == 1 and selected[0]['account_id'] == str(100000000049)
    assert selected[0]['target_scopes'] == [scopes[-1]]
    global_scope = str(100000000049) + '/global'
    selected = pipeline.review_credentials(entries, 'aws', [finding('global') | {'scope': global_scope}], {})
    assert len(selected) == 1 and selected[0]['target_scopes'] == [global_scope]


def test_one_gcp_access_can_list_fifty_projects_and_narrow_to_a_review_batch():
    from peaso.ai.prompting import access_instructions
    projects = [f'projects/project-{index:02}' for index in range(50)]
    access.begin()
    try:
        for project in projects:
            access.bearer('gcp', 'https://www.googleapis.com/', 'private-final-token', context_id='final', target_scopes=[project], quota_project='billing-project')
    finally:
        captured = access.finish()
    assert len(captured) == 1
    entries = access.bind_targets(captured, {'provider': 'gcp', 'scopes': projects})
    assert entries[0]['target_scopes'] == projects
    text = access_instructions(entries)
    assert all(project in text for project in projects)
    assert 'single token' in text and 'X-Goog-User-Project' in text
    assert 'private-final-token' not in text and 'AWS' not in text and 'Azure' not in text
    rows = [{'id': 'a', 'scope': projects[4]}, {'id': 'b', 'scope': projects[42]}]
    selected = pipeline.review_credentials(entries, 'gcp', rows, {})
    assert len(selected) == 1 and selected[0]['target_scopes'] == [projects[4], projects[42]]


def test_gcp_captures_final_transport_token_not_impersonation_source(monkeypatch):
    from peaso.collectors.gcp import Credentials, Transport
    source = Credentials({'token': 'private-source-token'})
    final = Credentials({'token': 'private-final-token'})
    transport = Transport(final, {'retries': 0})
    payload = {'name': 'projects/one'}
    response = SimpleNamespace(status_code=200, json=lambda: payload,
                               content=json.dumps(payload).encode(), headers={})
    monkeypatch.setattr(transport, '_session', lambda: SimpleNamespace(request=lambda *a, **kw: response))
    access.begin()
    try:
        source.headers()  # Could be called while minting the impersonated token.
        transport.request('GET', 'https://cloudresourcemanager.googleapis.com/v3/projects/one', scope='projects/one')
    finally:
        entries = access.finish()
    assert len(entries) == 1 and entries[0]['token'] == 'private-final-token'
    assert entries[0]['target_scopes'] == ['projects/one']
    assert 'private-source-token' not in json.dumps(entries)


def test_gcp_credentials_with_same_audience_do_not_overwrite_each_other():
    access.begin()
    try:
        for index in range(30):
            access.bearer('gcp', 'https://www.googleapis.com/', f'private-{index}', context_id=f'identity-{index}', target_scopes=[f'projects/p{index}'])
        access.bearer('gcp', 'https://www.googleapis.com/', 'refreshed-private', context_id='identity-0', target_scopes=['projects/extra'])
    finally:
        entries = access.finish()
    assert len(entries) == 30
    first = next(e for e in entries if e['context_id'] == 'identity-0')
    assert first['token'] == 'refreshed-private' and set(first['target_scopes']) == {'projects/p0', 'projects/extra'}
    bound = access.bind_targets(entries, {'provider': 'gcp', 'scopes': [f'projects/p{i}' for i in range(30)] + ['projects/extra']})
    selected = pipeline.review_credentials(bound, 'gcp', [{'scope': 'projects/p20'}], {})
    assert len(selected) == 1 and selected[0]['context_id'] == 'identity-20'


def test_azure_multi_tenant_audiences_and_fifty_subscriptions_remain_bound():
    from peaso.ai.prompting import access_instructions
    subscriptions = [f'/subscriptions/00000000-0000-0000-0000-{index:012}' for index in range(50)]
    tenants = {scope: ('tenant-a' if index < 25 else 'tenant-b') for index, scope in enumerate(subscriptions)}
    access.begin()
    try:
        for tenant in ('tenant-a', 'tenant-b'):
            for audience in ('https://management.azure.com', 'https://graph.microsoft.com'):
                access.bearer('azure', audience, f'private-{tenant}-{audience}', context_id='same-context', tenant_id=tenant)
    finally:
        captured = access.finish()
    assert len(captured) == 4
    entries = access.bind_targets(captured, {'provider': 'azure', 'scopes': subscriptions + ['/tenants/tenant-a', '/tenants/tenant-b'], 'metadata': {'subscription_tenants': tenants}})
    for entry in entries:
        expected = {scope for scope, owner in tenants.items() if owner == entry['tenant_id']}
        assert set(entry['target_scopes']) == expected | {'/tenants/' + entry['tenant_id']}
        assert len(entry['subscription_ids']) == 25
    text = access_instructions(entries)
    assert all(scope in text for scope in subscriptions)
    assert 'tenant-a' in text and 'tenant-b' in text and 'Microsoft Graph' in text and 'ARM' in text
    assert 'private-' not in text and 'Key Vault' not in text and 'Kubernetes' not in text
    selected = pipeline.review_credentials(entries, 'azure', [{'scope': subscriptions[40]}], {})
    assert len(selected) == 2 and all(e['tenant_id'] == 'tenant-b' for e in selected)
    assert all(e['target_scopes'] == [subscriptions[40]] for e in selected)


def test_kubernetes_many_cluster_credentials_and_namespaces_are_distinct():
    from peaso.ai.prompting import access_instructions
    namespaces = [f'namespace-{index:02}' for index in range(30)]
    access.begin()
    try:
        for index in range(20):
            config = SimpleNamespace(host=f'https://cluster-{index}.example', ssl_ca_cert=None, cert_file=None, key_file=None,
                get_api_key_with_prefix=lambda _: 'Bearer private-k8s-token')
            access.k8s(config, cluster_id=f'cluster-{index}', namespaces=namespaces)
    finally:
        entries = access.finish()
    assert len(entries) == 20
    text = access_instructions(entries)
    assert all(f'"cluster-{index}"' in text for index in range(20))
    assert all(namespace in text for namespace in namespaces)
    assert 'private-k8s-token' not in text and 'AWS' not in text and 'Azure' not in text
    selected = pipeline.review_credentials(entries, 'k8s', [{'scope': namespaces[2], 'evidence': {'cluster_id': 'cluster-12'}}], {})
    assert len(selected) == 1 and selected[0]['cluster_id'] == 'cluster-12'
    assert selected[0]['namespaces'] == [namespaces[2]]
    assert pipeline.review_credentials(entries, 'k8s', [{'scope': namespaces[2]}], {}) == []


def test_actual_azure_transport_captures_tenant_audience_expiry_and_resource_endpoints():
    from peaso.collectors.azure import AzureTransport, ARM, GRAPH, VAULT, STORAGE
    from peaso.ai.prompting import access_instructions
    expiration = time.time() + 600
    transports = []
    access.begin()
    try:
        for tenant in ('tenant-a', 'tenant-b'):
            class Credential:
                def get_token(self, scope, tenant=tenant):
                    claims = {'tid': tenant, 'aud': scope.removesuffix('/.default')}
                    value = 'header.' + base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip('=') + '.signature'
                    return SimpleNamespace(token=value, expires_on=expiration)
            transport = AzureTransport({}, credential=Credential())
            transport.allow_vault('https://scanvault.vault.azure.net')
            transport.allow_storage('https://scanstore.blob.core.windows.net', 'scanstore', 'blob')
            for audience in (ARM, GRAPH, VAULT, STORAGE):
                transport.token(audience)
            transports.append(transport)
    finally:
        entries = access.finish()
    assert len(entries) == 8
    for entry in entries:
        assert entry['tenant_id'] in ('tenant-a', 'tenant-b')
        assert entry['expires_at'] == expiration
        expected = {VAULT: ['https://scanvault.vault.azure.net'], STORAGE: ['https://scanstore.blob.core.windows.net']}
        assert entry['endpoints'] == expected.get(entry['audience'], [entry['audience']])
    text = access_instructions([e for e in entries if e['audience'] == VAULT])
    assert 'https://scanvault.vault.azure.net' in text
    assert 'Storage' not in text and 'Microsoft Graph' not in text and 'ARM' not in text
    assert all(e['token'] not in text for e in entries)


def test_captured_kubeconfig_loads_with_the_documented_client_method():
    from kubernetes import config
    configuration = SimpleNamespace(host='https://scan-cluster.example', verify_ssl=False,
        ssl_ca_cert=None, cert_file=None, key_file=None,
        get_api_key_with_prefix=lambda _: 'Bearer private-resolved-token')
    access.begin()
    try:
        access.k8s(configuration, cluster_id='scan-cluster', namespaces=['first', 'second'])
    finally:
        entry, = access.finish()
    client = config.new_client_from_config_dict(entry['kubeconfig'])
    try:
        assert client.configuration.host == configuration.host
        assert client.configuration.verify_ssl is False
        assert client.configuration.get_api_key_with_prefix('authorization') == 'Bearer private-resolved-token'
    finally:
        client.close()


def test_multi_project_targets_survive_the_actual_agent_file_boundary(monkeypatch):
    from peaso.ai.prompting import access_instructions
    projects = [f'projects/target-{i:02}' for i in range(50)]
    entries = access.bind_targets([{'provider': 'gcp', 'format': 'bearer', 'token': 'private-token',
        'context_id': 'selected', 'target_scopes': projects}], {'provider': 'gcp', 'scopes': projects})
    class Process:
        returncode = 0
        def __init__(self, argv, *, cwd, **kwargs):
            root = Path(cwd)
            document = json.loads((root/'credentials.json').read_text())
            assert document['version'] == 2
            assert document['entries'][0]['target_scopes'] == projects
            text = access_instructions(document['entries'])
            assert all(project in text for project in projects)
            assert 'private-token' not in text
            (root/'result.json').write_text('{"items": []}')
        def wait(self, **kwargs):
            return 0
    monkeypatch.setattr(pipeline.subprocess, 'Popen', Process)
    monkeypatch.setattr(pipeline, 'kill_tree', lambda _: None)
    pipeline.invoke('priorities', {}, entries, 'private-codex-token', [], [], 10)


@pytest.mark.parametrize('configured', ['', 'invalid-token', 'expired'])
def test_local_launch_and_schedule_require_usable_codex_access(environment, monkeypatch, configured):
    settings, store, artifacts = environment
    monkeypatch.setattr(auth, 'default_token', _default_token)
    monkeypatch.delenv('CODEX_TOKEN_SECRET_ARN', raising=False)
    monkeypatch.delenv('PEASO_AUTH_MODE', raising=False)
    monkeypatch.setenv('CODEX_ACCESS_TOKEN', token(time.time() - 600) if configured == 'expired' else configured)
    private = CredentialCipher(settings.identity_dir).encrypt({'auth': {'method': 'container'}, 'options': {}})
    connector = store.add_connector('alice', {'name': 'AWS', 'provider': 'aws'}, private)['id']
    with TestClient(create_app(settings, store=store, artifacts=artifacts, authenticator=Identities()), base_url='http://127.0.0.1') as client:
        assert client.get('/api/ai/codex').json()['available'] is False
        for path in ('/api/scans', '/api/schedules'):
            for selection in ({}, {'ai_enabled': True}):
                result = client.post(path, json={'connector_id': connector, **selection})
                assert result.status_code == 409, result.text
                assert 'valid AI configuration' in result.json()['detail']
        schedule = client.post('/api/schedules', json={'connector_id': connector, 'ai_enabled': False})
        assert schedule.status_code == 201, schedule.text
        ident = schedule.json()['id']
        assert client.patch(f'/api/schedules/{ident}', json={'ai_enabled': True}).status_code == 409
        assert client.patch(f'/api/schedules/{ident}', json={'enabled': False}).status_code == 200
        scan = client.post('/api/scans', json={'connector_id': connector, 'ai_enabled': False})
        assert scan.status_code == 201 and scan.json()['ai_enabled'] is False
        monkeypatch.setenv('CODEX_ACCESS_TOKEN', token())
        assert client.post('/api/ai/configuration/validate').status_code == 200
        assert client.get('/api/ai/codex').json()['available'] is True
        assert client.patch(f'/api/schedules/{ident}', json={'ai_enabled': True}).status_code == 200


def test_local_personal_token_is_required_per_launching_user(environment, monkeypatch):
    settings, store, artifacts = environment
    monkeypatch.setattr(auth, 'default_token', lambda: (_ for _ in ()).throw(RuntimeError('no_token')))
    cipher = AICipher(settings.identity_dir)
    store.set_ai_state('alice', 'auth', cipher.encrypt({'access_token': token()}))
    assert auth.codex_available(store, settings.identity_dir, 'alice') is True
    assert auth.codex_available(store, settings.identity_dir, 'bob') is False
    previous = store.ai_state('alice', 'auth')
    assert store.set_ai_state('alice', 'auth', cipher.encrypt({'access_token': token(time.time() - 600), 'refresh_token': 'private-refresh'}), previous)
    monkeypatch.setattr(auth, 'post', lambda *a, **kw: (401, {}))
    assert auth.codex_available(store, settings.identity_dir, 'alice') is False


def test_local_scheduler_does_not_launch_after_codex_access_is_removed(environment, monkeypatch):
    from peaso.worker import Worker
    settings, store, artifacts = environment
    private = CredentialCipher(settings.identity_dir).encrypt({'auth': {'method': 'container'}, 'options': {}})
    connector = store.add_connector('alice', {'name': 'AWS', 'provider': 'aws'}, private)['id']
    store.add_schedule('alice', {'connector_id': connector, 'ai_enabled': True, 'ai_user_id': 'alice', 'interval_hours': 24}, time.time() - 10)
    monkeypatch.setattr(auth, 'default_token', lambda: (_ for _ in ()).throw(RuntimeError('no_token')))
    monkeypatch.setattr(store, 'trigger_schedule', lambda *a, **kw: pytest.fail('An AI-enabled schedule without Codex must not enqueue'))
    worker = Worker('collector', settings, store=store, artifacts=artifacts, authenticator=SimpleNamespace(is_paid=lambda _: False))
    assert worker.schedule_tick() == []


@pytest.mark.parametrize('available_mib,requested,expected', [(4096, 2, 2), (4096, 4, 4), (4096, 6, 6), (2800, 6, 5), (700, 4, 1), (600, 2, 0)])
def test_review_admission_respects_memory_headroom(available_mib, requested, expected, monkeypatch):
    monkeypatch.setenv('PEASO_AI_MAX_CONCURRENCY', str(requested))
    monkeypatch.setattr(pipeline, 'available_memory', lambda: available_mib * 1024**2)
    assert pipeline.review_concurrency() == expected


@pytest.mark.parametrize('available_mib,requested,expected',
    [(8192, 12, 12), (4096, 12, 12), (2048, 12, 7),
     (1100, 6, 3), (600, 6, 1), (200, 6, 0)])
def test_remote_review_admission_reserves_only_local_staging_memory(available_mib, requested, expected, monkeypatch):
    monkeypatch.setenv('PEASO_AI_MAX_CONCURRENCY', str(requested))
    monkeypatch.setenv('PEASO_AI_RUNTIME', 'fargate')
    monkeypatch.setattr(pipeline, 'available_memory', lambda: available_mib * 1024**2)
    assert pipeline.review_concurrency() == expected


def test_available_memory_uses_container_limit_instead_of_host_ram(monkeypatch):
    import psutil
    monkeypatch.setattr(psutil, 'virtual_memory', lambda: SimpleNamespace(available=32 * 1024**3))
    files = {'/sys/fs/cgroup/memory.max': str(4 * 1024**3), '/sys/fs/cgroup/memory.current': str(3 * 1024**3)}
    def read(path, *a, **kw):
        if str(path) in files:
            return files[str(path)]
        raise FileNotFoundError()
    monkeypatch.setattr(Path, 'read_text', read)
    assert pipeline.available_memory() == 1024**3


def test_hosted_priorities_keep_startup_time_when_network_uses_its_budget(environment, monkeypatch):
    clock = [0.0]
    monkeypatch.setattr(pipeline, 'time', SimpleNamespace(monotonic=lambda: clock[0], time=time.time))
    monkeypatch.setattr(pipeline.isolation, 'remote', lambda: True)
    monkeypatch.setenv('PEASO_AI_TIMEOUT_SECONDS', '3000')

    def finish_at_network_deadline(report, entries, token, network, end):
        clock[0] = end
        return {'status': 'completed', 'explanation': '', 'findings': []}, False

    def priorities(stage, platform, entries, token, findings, reviews, timeout):
        assert stage == 'priorities'
        # A large decision brief taking eight minutes including startup fits.
        if timeout < 480:
            raise TimeoutError('task startup and model completion exceeded admission')
        return {'actions': [], 'limitations': []}

    monkeypatch.setattr(pipeline, 'review_network', finish_at_network_deadline)
    monkeypatch.setattr(pipeline, 'invoke', priorities)
    value = pipeline.review_scan(report(), {}, {}, tenant='alice', artifacts=environment[2])
    assert value['status'] == 'completed'


def test_review_queue_rejects_unbounded_concurrency(monkeypatch):
    monkeypatch.setattr(pipeline.isolation, 'remote', lambda: False)
    monkeypatch.setenv('PEASO_AI_MAX_CONCURRENCY', '7')
    with pytest.raises(ValueError, match='invalid_ai_concurrency'):
        pipeline.review_concurrency()
    monkeypatch.setattr(pipeline.isolation, 'remote', lambda: True)
    monkeypatch.setenv('PEASO_AI_MAX_CONCURRENCY', '13')
    with pytest.raises(ValueError, match='invalid_ai_concurrency'):
        pipeline.review_concurrency()


@pytest.mark.parametrize('category,status', [('network','MANUAL'),('network','UNKNOWN'),('privesc','MANUAL'),('privesc','UNKNOWN')])
def test_qualified_actions_can_reference_compact_contextual_findings(category, status):
    data = report()
    data['findings'] = [{'id':'h1','check_id':'contextual','status':status,'resource_id':'r1'}]
    data['check_meta'] = {'contextual': {'category': category}}
    before = copy.deepcopy(data)
    proposed = action() | {'title': 'Review conditional access',
        'rationale': 'The declared control warrants review; required access and effective reachability need owner validation.'}
    assert validate_actions({'actions':[proposed],'limitations':[]}, data, [])['actions'] == [proposed]
    assert data == before


@pytest.mark.parametrize('category,status', [('hardening','MANUAL'),('exposure','UNKNOWN'),('privesc','PASS'),('network','DENIED')])
def test_contextual_reference_support_preserves_rejected_finding_boundaries(category, status):
    data = report()
    data['findings'] = [{'id':'h1','check_id':'contextual','status':status,'resource_id':'r1'}]
    data['check_meta'] = {'contextual': {'category': category}}
    with pytest.raises(ValueError, match='unknown_action_reference'):
        validate_actions({'actions':[action()],'limitations':[]}, data, [])


def test_network_receives_exposure_issue_catalog_after_repeated_projection(tmp_path):
    from peaso.ai.network import prepare, build
    data, inventory, _ = network_fixture()
    exposure = {'id': 'public-sg', 'category': 'exposure', 'resource_id': 'r2',
        'check_id': 'aws.exposure.ssh', 'title': 'World-source SSH rule', 'status': 'FAIL',
        'scope': 'test/us-east-1', 'evidence_summary': 'sg-a permits TCP/22 from 0.0.0.0/0.',
        'evidence': {'policy': 'never-give-unrelated-iam'}, 'description': 'never-give-extra'}
    data['findings'] = [exposure, exposure | {'id': 'passed', 'status': 'PASS'},
        exposure | {'id': 'manual', 'status': 'MANUAL'},
        exposure | {'id': 'iam', 'category': 'hardening'}]
    prepared = prepare(data, inventory, {})
    build(tmp_path, prepared, [], pipeline.private_json)
    issues = json.loads((tmp_path/'exposure.json').read_text())['findings']
    assert {r['id'] for r in issues} == {'public-sg', 'manual'}
    assert issues[0]['evidence_summary'] == exposure['evidence_summary']
    assert all('evidence' not in r and 'description' not in r for r in issues)
    assert 'never-give' not in json.dumps(issues)
    import sqlite3
    with sqlite3.connect(tmp_path/'context.sqlite') as db:
        assert db.execute("SELECT COUNT(*) FROM records WHERE domain='findings'").fetchone()[0] == 0


def test_network_contract_accepts_per_network_paragraphs_without_limitations():
    from peaso.ai.network import prepare
    data, inventory, output = network_fixture()
    output['explanation'] = ('Application VPC 10.0.0.0/16. ' * 60 + '\n\n' +
        'Subnet 10.0.1.0/24 holds the API instances; their SG references connect them to the database tier.')
    assert len(output['explanation']) > 1000
    result = validate_network(output, prepare(data, inventory, {}))
    assert result['explanation'] == output['explanation']
    assert 'limitations' not in result and 'limitations' not in result['findings'][0]['evidence']
    with pytest.raises(ValueError):
        validate_network(output | {'limitations': ['Generic disclaimer']}, prepare(data, inventory, {}))


def test_network_prompt_requires_distinct_segmentation_issue_on_shared_exposure_resource():
    import yaml
    prompt = yaml.safe_load((Path(pipeline.__file__).parent/'agents/network.yaml').read_text())['system_prompt']
    assert 'exposure.json' in prompt
    assert 'same weakness on the same resource' in prompt
    assert 'distinct internal trust boundary' in prompt
    assert 'Do not return public buckets, public URLs/endpoints or world-source ports' in prompt
    assert 'names/tags, workload attachments, dependencies and routes as evidence' in prompt
    assert '### heading for each distinct VPC/VNet/network' in prompt
    assert '#### headings for its subnet tiers' in prompt
    assert 'never put a whole VPC into one long paragraph' in prompt


@pytest.mark.parametrize('provider,kind,data,purpose_key', [
    ('aws', 'lambda_function', {'VpcConfig': {'VpcId': 'vpc-app'}, 'Tags': {'tier': 'api'}, 'Environment': {'Variables': {'TOKEN': 'never-give'}}}, 'Tags'),
    ('gcp', 'instance', {'networkInterfaces': [{'network': 'app'}], 'labels': {'tier': 'api'}, 'metadata': {'startup-script': 'never-give'}}, 'labels'),
    ('azure', 'vm', {'tags': {'tier': 'api'}, 'properties': {'networkProfile': {'networkInterfaces': []}, 'osProfile': {'adminPassword': 'never-give'}}}, 'tags'),
    ('k8s', 'pod', {'metadata': {'labels': {'tier': 'api'}}, 'spec': {'containers': [{'env': [{'value': 'never-give'}]}]}}, 'metadata'),
])
def test_network_purpose_hints_preserve_labels_without_application_settings(provider, kind, data, purpose_key):
    from peaso.ai.network import native_network_resource
    projected = native_network_resource({'id': 'r', 'provider': provider, 'type': kind, 'data': data})
    assert 'api' in json.dumps(projected['data'][purpose_key])
    assert 'never-give' not in json.dumps(projected)

@pytest.mark.parametrize('field', ['title', 'description', 'rationale', 'resource_id', 'remediation', 'verification', 'summary', 'observation'])
def test_network_findings_reject_blank_display_or_evidence_fields(field):
    _, _, output = network_fixture()
    row = output['findings'][0]
    if field == 'summary':
        row['evidence']['summary'] = '   '
    elif field == 'observation':
        row['evidence']['observations'] = ['\n\t']
    else:
        row[field] = '   '
    with pytest.raises(ValueError, match='substantive text'):
        NetworkReview.model_validate(output)


def test_network_display_identity_is_bound_to_the_referenced_inventory():
    from peaso.ai.network import prepare
    data, inventory, output = network_fixture()
    inventory[1].update(name='Backend database control', service='ec2')
    row = validate_network(output, prepare(data, inventory, {}))['findings'][0]
    assert row['resource_name'] == 'Backend database control'
    assert row['native_resource_id'] == 'native-r2'
    assert row['provider'] == 'aws' and row['scope'] == '123456789012/us-east-1' and row['service'] == 'ec2'
    assert row['evidence_summary'] == output['findings'][0]['evidence']['summary']
    for key in ('provider', 'scope', 'service', 'resource_name', 'native_resource_id'):
        with pytest.raises(ValueError):
            NetworkReview.model_validate(output | {'findings': [output['findings'][0] | {key: 'invented'}]})
