"""Offline cross-cloud reader audit: native boundaries, limitations and regressions.

Synthetic unverified detector input only; intended secret stores are excluded.
"""
from copy import deepcopy
import base64
import io
import json
from pathlib import Path
import socket
from types import SimpleNamespace
import pytest
from peaso import collectors, engine, secret_scanning as scanning
from peaso.collectors import aws, azure, k8s
from peaso.collectors import aws_code_log_content_indicators as content
from peaso.collectors import aws_configuration_secret_indicators as config
from peaso.collectors.aws_lambda_environment_metadata import project_response as lambda_project
from peaso.collectors import azure_devops_pipeline_native as devops
from peaso.checks import aws_code_log_content_review_20261019 as content_checks

TOKEN = 'ghp_' + '7mQ2zR9wL4cV8nK1sF6aH3jP5uD0xB2yE9rT'
ACCOUNT, REGION = '123456789012', 'us-east-1'
SCOPE = ACCOUNT + '/' + REGION
COMMIT = 'a' * 40
REPO = {'repositoryName': 'audit', 'Arn': f'arn:aws:codecommit:{REGION}:{ACCOUNT}:audit'}
GROUP = {'logGroupName': 'audit', 'arn': f'arn:aws:logs:{REGION}:{ACCOUNT}:log-group:audit:*'}
CONTENT_IDS = {
    'aws_cis_ec2_userdata_embedded_secrets': 'instance',
    'aws.review.codecommit.default_commit_secret_indicators': 'codecommit_repository',
    'aws.review.cloudwatch.sampled_log_secret_indicators': 'log_group',
    'aws.review.lambda_function.package_content_secret_indicators': 'lambda_function',
    'aws.review.lambda_layer_version.package_content_secret_indicators': 'lambda_layer_version',
    'aws.review.ecr_repository.package_content_secret_indicators': 'ecr_repository',
}


@pytest.fixture(autouse=True)
def no_auth_or_network(monkeypatch):
    def blocked(*args, **kwargs):
        pytest.fail('actual authentication, socket or DNS forbidden in this audit')
    for name in ('connect', 'connect_ex'):
        monkeypatch.setattr(socket.socket, name, blocked)
    for name in ('getaddrinfo', 'create_connection'):
        monkeypatch.setattr(socket, name, blocked)
    monkeypatch.setattr(azure, 'credential_for', blocked)
    monkeypatch.setattr(k8s, '_new_api', blocked)
    monkeypatch.setenv('AWS_EC2_METADATA_DISABLED', 'true')
    scanning._RESULTS.clear()
    yield
    scanning._RESULTS.clear()


@pytest.fixture(scope='module')
def real_detection():
    # Required acceptance, no importorskip: unavailable tools are an explicit failure.
    result = scanning.scan_content(('token=' + TOKEN + '\n').encode(), 'audit.literal')
    assert result['complete'] is True and len(result['leaks']) == 1
    assert {d['engine'] for d in result['leaks'][0]['detectors']} == {'kingfisher', 'trufflehog'}
    assert TOKEN not in json.dumps(result)
    return result


def sdk_content(monkeypatch, mode, *, positive=True, denied=False, path='/config.txt'):
    import boto3
    from botocore.stub import Stubber
    session = boto3.Session(aws_access_key_id='offline-audit', aws_secret_access_key='offline-audit', region_name=REGION)
    service = 'codecommit' if mode == 'repository' else 'logs'
    client = session.client(service, region_name=REGION)
    requests = aws.Requests({'content_secret_scans': True, 'retry_attempts': 1})
    requests._clients[(id(session), service, REGION)] = client
    text = ('token=' + TOKEN + '\n') if positive else 'ready = true\n'
    stub = Stubber(client)
    if mode == 'repository':
        args = {'repositoryName': 'audit'}
        if denied:
            stub.add_client_error('get_repository', service_error_code='AccessDeniedException', expected_params=args)
        else:
            stub.add_response('get_repository', {'repositoryMetadata': {**REPO, 'accountId': ACCOUNT, 'defaultBranch': 'main'}}, args)
            stub.add_response('get_branch', {'branch': {'branchName': 'main', 'commitId': COMMIT}}, {**args, 'branchName': 'main'})
            stub.add_response('get_folder', {'commitId': COMMIT, 'folderPath': '/', 'files': [{'absolutePath': path}]}, {**args, 'commitSpecifier': COMMIT, 'folderPath': '/'})
            stub.add_response('get_file', {'commitId': COMMIT, 'blobId': 'b' * 40, 'filePath': path, 'fileMode': 'NORMAL',
                'fileContent': text.encode(), 'fileSize': len(text.encode())}, {**args, 'commitSpecifier': COMMIT, 'filePath': path})
    else:
        end = int(requests.observed_at.timestamp() * 1000)
        args = {'logGroupName': 'audit', 'startTime': end - 86400000, 'endTime': end, 'limit': content.MAX_MESSAGES}
        if denied:
            stub.add_client_error('filter_log_events', service_error_code='AccessDeniedException', expected_params=args)
        else:
            stub.add_response('filter_log_events', {'events': [{'timestamp': end - 1, 'message': text}]}, args)
    with stub:
        sample = getattr(content, 'scan_' + ('repository' if mode == 'repository' else 'logs'))(requests, session, REGION, REPO if mode == 'repository' else GROUP)
        stub.assert_no_pending_responses()
    kind = 'codecommit_repository' if mode == 'repository' else 'log_group'
    item = {**(REPO if mode == 'repository' else GROUP), 'ContentSecretIndicators': sample}
    index = {'context': {'provider': 'aws', 'Account': ACCOUNT, 'scope': SCOPE},
        'collections': {kind: [{'type': kind, 'scope': SCOPE, 'account_id': ACCOUNT, 'region': REGION, 'status': 'collected', 'items': [item]}]},
        kind: [{'type': kind, 'scope': SCOPE, 'data': item}]}
    return item, index, requests


@pytest.mark.parametrize('mode', ['repository', 'logs'])
@pytest.mark.parametrize('positive', [False, True])
def test_real_native_sdk_projection_to_consumer_and_engine(monkeypatch, mode, positive):
    item, index, requests = sdk_content(monkeypatch, mode, positive=positive)
    result, evidence = getattr(content_checks, mode)(item, index)
    assert result == ('FAIL' if positive else 'PASS') and item['ContentSecretIndicators']['complete'] is True
    if positive:
        leak, = evidence['secret_leaks']
        assert {d['engine'] for d in leak['detectors']} == {'kingfisher', 'trufflehog'}
    from peaso.snapshot import make_snapshot
    snapshot = make_snapshot('aws', [SCOPE], [deepcopy(index['collections'][next(iter(index['collections']))][0])])
    report = engine.evaluate_snapshot(snapshot, checks=[content_checks.IDS[mode]])
    assert {f['status'] for f in report['findings']} == {result}
    cache = [f.result() for f in requests._cache.values() if f.exception() is None]
    assert TOKEN not in json.dumps([item, evidence, snapshot, report, cache], default=str)


@pytest.mark.parametrize('mode', ['repository', 'logs'])
def test_native_denied_content_does_not_prove_absence(monkeypatch, mode):
    item, index, requests = sdk_content(monkeypatch, mode, denied=True)
    assert getattr(content_checks, mode)(item, index)[0] == 'UNKNOWN'
    assert item['ContentSecretIndicators']['complete'] is False


@pytest.mark.parametrize('mode', ['repository', 'logs'])
@pytest.mark.parametrize('failed', ['kingfisher', 'trufflehog'])
def test_missing_engine_negative_is_unknown(monkeypatch, mode, failed):
    monkeypatch.setattr(scanning, '_scan_kingfisher', lambda *args: [])
    monkeypatch.setattr(scanning, '_scan_trufflehog', lambda *args: [])
    def unavailable(*args): raise ImportError('offline optional tool missing')
    monkeypatch.setattr(scanning, '_scan_' + failed, unavailable)
    item, index, requests = sdk_content(monkeypatch, mode, positive=False)
    assert getattr(content_checks, mode)(item, index)[0] == 'UNKNOWN'


@pytest.mark.parametrize('mode', ['repository', 'logs'])
def test_foreign_collection_scope_is_unresolved(monkeypatch, mode):
    monkeypatch.setattr(scanning, '_scan_kingfisher', lambda *args: [])
    monkeypatch.setattr(scanning, '_scan_trufflehog', lambda *args: [])
    item, index, requests = sdk_content(monkeypatch, mode, positive=False)
    index['context']['scope'] = '999999999999/' + REGION
    assert getattr(content_checks, mode)(item, index)[0] == 'UNKNOWN'


@pytest.mark.parametrize('cid,kind', CONTENT_IDS.items())
def test_each_aws_content_kind_requires_exact_named_check(monkeypatch, cid, kind):
    seen = []
    def collect(connector, requirements):
        from peaso.snapshot import make_snapshot
        seen.append(deepcopy(connector))
        return make_snapshot('aws', [SCOPE], [])
    monkeypatch.setattr(collectors, 'collect_live', collect)
    connector = {'provider': 'aws', 'scopes': [SCOPE], 'options': {'regions': [REGION], 'content_secret_scans': True}}
    engine.collect_snapshot({'connector': connector, 'checks': [cid]})
    assert seen.pop()['options']['_content_secret_scan_kinds'] == [kind]
    for selection in ({}, {'categories': ['hardening']}, {'frameworks': ['HackTricks Cloud Best Practices']}):
        engine.collect_snapshot({'connector': connector, **selection})
        assert seen.pop()['options']['_content_secret_scan_kinds'] == []


@pytest.mark.parametrize('provider', ['azure', 'k8s'])
def test_no_functional_content_gate_is_installed_for_azure_or_kubernetes(provider, monkeypatch):
    # Content adapters are now admitted; broad scans still cannot authorize them.
    from tests.aws_k8s_current_native_inputs_20261020 import selected_content_pairs
    pairs = selected_content_pairs(provider)
    assert pairs and all(cid.startswith(provider + '.review.') for cid, _ in pairs)
    observed = []
    def no_content_collect(connector, requirements):
        from peaso.snapshot import make_snapshot
        observed.append((deepcopy(connector), list(requirements)))
        return make_snapshot(provider, connector['scopes'], [])
    monkeypatch.setattr(collectors, 'collect_live', no_content_collect)
    scope = '/subscriptions/11111111-1111-1111-1111-111111111111' if provider == 'azure' else 'team-a'
    for enabled in (False, True):
        req = {'connector': {'provider': provider, 'scopes': [scope],
               'options': {'content_secret_scans': enabled, '_content_secret_scan_kinds': [kind for _, kind in pairs]}}}
        before = deepcopy(req)
        engine.collect_snapshot(req)
        connector, requirements = observed.pop()
        assert connector['options']['_content_secret_scan_kinds'] == []
        assert not set(requirements) & {kind for _, kind in pairs}
        assert not any('grant' in key for key in connector['options'])
        assert req == before



@pytest.mark.parametrize('surface', ['lambda_environment', 'cloudformation_outputs'])
def test_aws_configuration_pattern_negative_is_not_dual_engine_content_absence(surface, real_detection, monkeypatch):
    def forbidden(*args, **kwargs): pytest.fail('configuration pattern adapter unexpectedly invokes external scanner')
    monkeypatch.setattr(scanning, 'scan_content', forbidden)
    if surface == 'lambda_environment':
        result = lambda_project({'FunctionArn': f'arn:aws:lambda:{REGION}:{ACCOUNT}:function:audit',
            'FunctionName': 'audit', 'Environment': {'Variables': {'API_TOKEN': TOKEN}}}, 'get_function_configuration')
    else:
        result = config.project_cloudformation_response({'Stacks': [{'StackId': f'arn:aws:cloudformation:{REGION}:{ACCOUNT}:stack/audit/11111111-2222-3333-4444-555555555555',
            'StackName': 'audit', 'StackStatus': 'CREATE_COMPLETE', 'Outputs': [{'OutputKey': 'ApiToken', 'OutputValue': TOKEN}]}]}, region=REGION)['Stacks'][0]
    marker = result['ConfigurationSecretIndicators']
    assert marker['NativeResponseComplete'] is True and marker['HighConfidenceSecretPresent'] is False
    assert TOKEN not in json.dumps(result) and real_detection['leaks']


def replace_native(value, old):
    if isinstance(value, dict):
        return {k.replace('DB_PASSWORD', 'API_TOKEN').replace('password', 'api_token'): replace_native(v, old) for k, v in value.items()}
    if isinstance(value, list): return [replace_native(v, old) for v in value]
    if isinstance(value, str):
        raw = value.replace(old, TOKEN).replace('DB_PASSWORD', 'API_TOKEN').replace('password', 'api_token')
        try:
            decoded = base64.b64decode(value, validate=True).decode()
            if old in decoded:
                return base64.b64encode(decoded.replace(old, TOKEN).replace('DB_PASSWORD', 'API_TOKEN').replace('password', 'api_token').encode()).decode()
        except (ValueError, UnicodeError): pass
        return raw
    return value


@pytest.mark.parametrize('kind', ['codebuild_project', 'rest_api_stage', 'ecs_task_definition', 'amplify_app',
    'batch_job_definition', 'elastic_beanstalk_environment', 'glue_job', 'glue_connection'])
def test_eight_native_configuration_surfaces_are_partial_patterns(kind, real_detection, monkeypatch):
    from tests import test_aws_additional_secret_review_20261019 as old
    from peaso.collectors import aws_additional_secret_indicators as adapter
    from peaso.collectors.aws_codebuild_redaction import project_batch_get_projects
    monkeypatch.setattr(scanning, 'scan_content', lambda *a, **k: pytest.fail('not a dual-engine adapter'))
    service, operation, args, response, _ = old.fixture(kind)
    response = replace_native(response, old.SECRET)
    projected = project_batch_get_projects(response) if service == 'codebuild' else adapter.project_response(response,
        service=service, operation=operation, arguments=args, region=REGION)
    def markers(v):
        if isinstance(v, dict):
            if 'AdditionalSecretIndicators' in v: yield v['AdditionalSecretIndicators']
            for k, child in v.items():
                if k != 'AdditionalSecretIndicators': yield from markers(child)
        if isinstance(v, list):
            for child in v: yield from markers(child)
    found = list(markers(projected))
    assert found and all(m['NativeResponseComplete'] and not m['HighConfidenceSecretPresent'] for m in found)
    assert TOKEN not in json.dumps(projected) and real_detection['leaks']


@pytest.mark.parametrize('kind', ['ec2_launch_template', 'launch_configuration', 'ssm_document_metadata',
    'sfn_state_machine', 'sagemaker_notebook_instance', 'datapipeline_pipeline'])
def test_six_native_script_surfaces_are_partial_patterns(kind, real_detection, monkeypatch):
    from tests import test_aws_configuration_payload_secret_review_20261019 as old
    from peaso.collectors import aws_configuration_payload_secret_indicators as adapter
    from peaso.collectors.aws_launch_configuration_redaction import project_response as launch
    monkeypatch.setattr(scanning, 'scan_content', lambda *a, **k: pytest.fail('not a dual-engine adapter'))
    service, operation, args, response, _ = old.fixture(kind)
    response = replace_native(response, old.SECRET)
    projected = launch(response) if service == 'autoscaling' else adapter.project_response(response,
        service=service, operation=operation, arguments=args, region=REGION)
    def markers(v):
        if isinstance(v, dict):
            if 'PayloadSecretIndicators' in v: yield v['PayloadSecretIndicators']
            for k, child in v.items():
                if k != 'PayloadSecretIndicators': yield from markers(child)
        if isinstance(v, list):
            for child in v: yield from markers(child)
    found = list(markers(projected))
    assert found and all(m['NativeResponseComplete'] and not m['HighConfidenceSecretPresent'] for m in found)
    assert TOKEN not in json.dumps(projected) and real_detection['leaks']


@pytest.mark.parametrize('field', ['appSettings', 'customData', 'settings'])
def test_native_azure_sensitive_fields_are_omitted_without_scanning(monkeypatch, field):
    monkeypatch.setattr(scanning, 'scan_content', lambda *a, **k: pytest.fail('metadata path must not be called a scanner'))
    raw = {'id': '/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/rg/providers/Microsoft.Web/sites/audit',
           'properties': {field: {'API_TOKEN': TOKEN}}}
    projected = azure._metadata_only(raw)
    assert field not in projected['properties'] and TOKEN not in json.dumps(projected)
    assert not any(k in json.dumps(projected) for k in ('SecretIndicators', 'ContentScan', 'secret_leaks'))


def test_native_azure_container_env_is_redaction_and_pipeline_is_names_only():
    result = azure._metadata_only({'properties': {'containers': [{'properties': {'environmentVariables': [{'name': 'API_TOKEN', 'value': TOKEN}]}}]}})
    variable = result['properties']['containers'][0]['properties']['environmentVariables'][0]
    assert variable == {'name': 'API_TOKEN', 'value': '[REDACTED]'}
    values = devops.variables({'API_TOKEN': {'value': TOKEN, 'isSecret': False}}, 'pipeline', '1')
    assert values == [{'name': 'API_TOKEN', 'source': 'pipeline', 'scopeId': '1', 'isSecret': False}]
    assert TOKEN not in json.dumps([result, values])


@pytest.mark.parametrize('container_kind', ['containers', 'initContainers', 'ephemeralContainers'])
def test_native_pod_literal_values_are_omitted_before_snapshots(monkeypatch, container_kind):
    monkeypatch.setattr(scanning, 'scan_content', lambda *a, **k: pytest.fail('no K8s content adapter installed'))
    raw = {'apiVersion': 'v1', 'kind': 'Pod', 'metadata': {'name': 'audit', 'namespace': 'selected', 'uid': 'pod-uid',
        'resourceVersion': '1'}, 'spec': {container_kind: [{'name': 'app', 'image': 'private.example/a@sha256:' + 'a'*64,
        'env': [{'name': 'API_TOKEN', 'value': TOKEN}, {'name': 'MANAGED', 'valueFrom': {'secretKeyRef': {'name': 'intended-store', 'key': 'token'}}}],
        'command': ['/bin/sh'], 'args': ['token=' + TOKEN]}]}}
    calls = []
    def get_json(path, params):
        calls.append((path, params))
        assert path == '/api/v1/namespaces/selected/pods' and params == {'limit': 100}
        return {'kind': 'PodList', 'apiVersion': 'v1', 'metadata': {'resourceVersion': '1'}, 'items': [raw]}
    reader = SimpleNamespace(page_size=100, budget=SimpleNamespace(max_pages=1), call=lambda fn, *a: fn(*a))
    pages = list(k8s._pages(reader, SimpleNamespace(get_json=get_json), '/api/v1/namespaces/selected/pods', 'pod', 'cluster-a', 'selected', True))
    row = pages[0][0]['spec'][container_kind][0]
    assert row['env'][0] == {'name': 'API_TOKEN', 'value_redacted': True, 'value_length': len(TOKEN)}
    assert row['env'][1]['valueFrom']['secretKeyRef'] == {'name': 'intended-store', 'key': 'token'}
    assert row['command_redacted'] is True and row['args_redacted'] is True
    assert TOKEN not in json.dumps(pages) and len(calls) == 1


def test_kubernetes_configmap_and_secret_lists_are_negotiated_metadata_only():
    accept = {'Accept': 'application/json;as=PartialObjectMetadataList;g=meta.k8s.io;v=v1'}
    for resource in ('secrets', 'configmaps'):
        path = '/api/v1/namespaces/selected/' + resource
        assert k8s._inventory_read_path(path, '', accept) is True
        assert k8s._inventory_read_path(path, '', {'Accept': 'application/json'}) is False
    for subresource in ('log', 'exec', 'attach', 'portforward'):
        assert k8s._inventory_read_path('/api/v1/namespaces/selected/pods/audit/' + subresource, '', {}) is False
    assert k8s._inventory_read_path('/api/v1/namespaces/selected/secrets/intended-store', '', {}) is False


def test_metadata_negotiation_rejects_full_secret_before_consuming_payload():
    raw = b'{"kind":"SecretList","items":[{"data":{"API_TOKEN":"' + TOKEN.encode() + b'"}}]}'
    stream = io.BytesIO(raw); closed = []
    response = SimpleNamespace(read=stream.read, close=lambda: closed.append(True), release_conn=lambda: closed.append(True))
    def call_api(path, method, **kwargs):
        assert path == '/api/v1/namespaces/selected/secrets' and method == 'GET'
        assert kwargs['header_params'] == {'Accept': 'application/json;as=PartialObjectMetadataList;g=meta.k8s.io;v=v1'}
        return response
    api = SimpleNamespace(api_client=SimpleNamespace(call_api=call_api))
    with pytest.raises(k8s.K8sReadError):
        k8s._metadata_get(api, '/api/v1/namespaces/selected/secrets', {'limit': 10}, 'PartialObjectMetadataList')
    assert stream.tell() <= 32 and closed == [True, True]


def test_aws_metadata_heuristics_and_azure_k8s_redaction_do_not_detect_generic_token(real_detection):
    # Concrete coverage gap, not a demand to read any intended secret store.
    assert config.lambda_indicators({'FunctionArn': f'arn:aws:lambda:{REGION}:{ACCOUNT}:function:audit',
        'FunctionName': 'audit', 'Environment': {'Variables': {'API_TOKEN': TOKEN}}}, 'lambda:GetFunctionConfiguration')['HighConfidenceSecretPresent'] is False
    assert real_detection['leaks']


def test_regression_codecommit_detected_secret_in_native_path_must_not_survive_cache(monkeypatch):
    item, index, requests = sdk_content(monkeypatch, 'repository', positive=True, path='/' + TOKEN + '.txt')
    result, evidence = content_checks.repository(item, index)
    assert result == 'FAIL' and evidence['secret_leaks']
    cache = [f.result() for f in requests._cache.values() if f.exception() is None]
    # Do not print the detected synthetic value on expected failure.
    assert not any(TOKEN in json.dumps(v, default=str) for v in [item, evidence, cache]), 'detected value survives native path/binding metadata'
