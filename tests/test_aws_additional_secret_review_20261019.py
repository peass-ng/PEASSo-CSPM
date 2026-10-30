"""Eight value-indicator producer/cache/consumer contracts, without AWS calls."""
from copy import deepcopy
from types import SimpleNamespace
import hashlib
import json
import pytest
from peaso.collectors import aws, aws_additional_secret_indicators as producer
from peaso.collectors.aws_codebuild_redaction import project_batch_get_projects
from peaso.checks import aws_additional_secret_review_20261019 as checks

ACCOUNT, REGION = '123456789012', 'us-east-1'
SECRET = 'Complex123!SyntheticOnly'
KINDS = list(checks.SURFACES)
FUNCTIONS = dict(zip(KINDS, [checks.codebuild, checks.rest_stage, checks.ecs, checks.amplify, checks.batch, checks.beanstalk, checks.glue_job, checks.glue_connection]))


def fixture(kind, detected=True):
    value = SECRET if detected else 'production'
    env = [{'name': 'DB_PASSWORD' if detected else 'STAGE', 'value': value}]
    mapping = {'DB_PASSWORD' if detected else 'STAGE': value}
    arn = lambda service, resource: f'arn:aws:{service}:{REGION}:{ACCOUNT}:{resource}'
    if kind == 'codebuild_project':
        row = {'name': 'project', 'arn': arn('codebuild', 'project/project'), 'environment': {'environmentVariables': [{**env[0], 'type': 'PLAINTEXT'}]}}
        return 'codebuild', 'batch_get_projects', {'names': ['project']}, {'projects': [row]}, {'name': 'project'}
    if kind == 'rest_api_stage':
        row = {'stageName': 'prod', 'variables': mapping}
        return 'apigateway', 'get_stages', {'restApiId': 'abc123'}, {'item': [row]}, {}
    if kind == 'ecs_task_definition':
        ident = arn('ecs', 'task-definition/example:1')
        row = {'taskDefinitionArn': ident, 'containerDefinitions': [{'name': 'main', 'environment': env}]}
        return 'ecs', 'describe_task_definition', {'taskDefinition': ident}, {'taskDefinition': row}, {'taskDefinitionArn': ident}
    if kind == 'amplify_app':
        row = {'appId': 'dexample', 'appArn': arn('amplify', 'apps/dexample'), 'name': 'example', 'environmentVariables': mapping, 'buildSpec': SECRET, 'basicAuthCredentials': SECRET}
        return 'amplify', 'list_apps', {}, {'apps': [row]}, {}
    if kind == 'batch_job_definition':
        ident = arn('batch', 'job-definition/example:1')
        row = {'jobDefinitionArn': ident, 'status': 'ACTIVE', 'containerProperties': {'environment': env, 'command': [SECRET]}}
        return 'batch', 'describe_job_definitions', {'status': 'ACTIVE'}, {'jobDefinitions': [row]}, {}
    if kind == 'elastic_beanstalk_environment':
        row = {'ApplicationName': 'app', 'EnvironmentName': 'prod', 'OptionSettings': [
            {'Namespace': 'aws:elasticbeanstalk:application:environment', 'OptionName': next(iter(mapping)), 'Value': value}]}
        return 'elasticbeanstalk', 'describe_configuration_settings', {'ApplicationName': 'app', 'EnvironmentName': 'prod'}, {'ConfigurationSettings': [row]}, {
            'ApplicationName': 'app', 'EnvironmentName': 'prod', 'EnvironmentArn': arn('elasticbeanstalk', 'environment/app/prod')}
    if kind == 'glue_job':
        row = {'Name': 'job', 'DefaultArguments': mapping, 'NonOverridableArguments': {'--enable-metrics': 'true'}}
        return 'glue', 'get_jobs', {}, {'Jobs': [row]}, {}
    row = {'Name': 'connection', 'ConnectionProperties': {**mapping, 'PASSWORD': 'hidden-provider-value'}, 'AuthenticationConfiguration': {'password': SECRET}, 'PythonProperties': {'unsafe': SECRET}}
    return 'glue', 'get_connections', {'HidePassword': True}, {'ConnectionList': [row]}, {}


def projected(kind, detected=True):
    service, operation, arguments, response, item = fixture(kind, detected)
    result = project_batch_get_projects(response) if service == 'codebuild' else producer.project_response(response, service=service, operation=operation, arguments=arguments, region=REGION)
    if kind == 'codebuild_project':
        item['Configuration'] = {**result, 'collection_status': 'collected'}
    elif kind == 'ecs_task_definition':
        item['Definition'] = {**result, 'collection_status': 'collected'}
    elif kind == 'rest_api_stage':
        item = {**result['item'][0], 'ParentApiId': 'abc123', 'id': f'arn:aws:apigateway:{REGION}::/restapis/abc123/stages/prod'}
    elif kind == 'elastic_beanstalk_environment':
        item['Configuration'] = {**result, 'collection_status': 'collected'}
    else:
        field = {'amplify_app': 'apps', 'batch_job_definition': 'jobDefinitions', 'glue_job': 'Jobs', 'glue_connection': 'ConnectionList'}[kind]
        item = result[field][0]
    return item


def index(kind, item):
    scope = ACCOUNT + '/' + REGION
    return {'context': {'provider': 'aws', 'Account': ACCOUNT, 'scope': scope},
        'collections': {kind: [{'type': kind, 'scope': scope, 'status': 'collected', 'items': [item]}]}}


def marker(kind, item):
    if kind == 'codebuild_project': return item['Configuration']['projects'][0]['AdditionalSecretIndicators']
    if kind == 'ecs_task_definition': return item['Definition']['taskDefinition']['AdditionalSecretIndicators']
    if kind == 'elastic_beanstalk_environment': return item['Configuration']['AdditionalSecretIndicators']
    return item['AdditionalSecretIndicators']


@pytest.mark.parametrize('kind', KINDS)
@pytest.mark.parametrize('detected', [True, False])
def test_every_surface_scans_values_then_emits_only_safe_coherent_metadata(kind, detected):
    item = projected(kind, detected)
    status, evidence = FUNCTIONS[kind](item, index(kind, item))
    assert status == ('FAIL' if detected else 'PASS')
    assert len(evidence['observed']) <= 150
    encoded = json.dumps([item, evidence])
    assert SECRET not in encoded and hashlib.sha256(SECRET.encode()).hexdigest() not in encoded
    assert marker(kind, item)['HighConfidenceSecretPresent'] is detected


@pytest.mark.parametrize('kind', KINDS)
@pytest.mark.parametrize('field,value', [('collection_status', 'empty'), ('NativeResponseComplete', False), ('Region', 'eu-west-1'),
    ('AccountId', '999999999999'), ('ResourceId', 'different'), ('SourceOperation', 'other:GetData'), ('MatchedCategories', ['invalid']),
    ('HighConfidenceSecretPresent', False)])
def test_unreadable_foreign_and_contradictory_markers_never_pass(kind, field, value):
    item = projected(kind)
    marker(kind, item)[field] = value
    assert FUNCTIONS[kind](item, index(kind, item))[0] == 'UNKNOWN'


@pytest.mark.parametrize('kind', KINDS)
@pytest.mark.parametrize('state', ['denied', 'partial', 'empty', 'malformed'])
def test_parent_inventory_is_authoritative(kind, state):
    item = projected(kind, False)
    evidence = index(kind, item)
    evidence['collections'][kind][0]['status'] = state
    assert FUNCTIONS[kind](item, evidence)[0] == 'UNKNOWN'


def test_codebuild_secret_references_are_not_retrieved_and_unknown_type_is_not_clean():
    service, operation, args, response, _ = fixture('codebuild_project')
    response['projects'][0]['environment']['environmentVariables'][0]['type'] = 'SECRETS_MANAGER'
    result = project_batch_get_projects(response)
    assert result['projects'][0]['AdditionalSecretIndicators']['HighConfidenceSecretPresent'] is False
    assert SECRET not in json.dumps(result)
    response['projects'][0]['environment']['environmentVariables'][0]['type'] = 'UNRECOGNIZED'
    result = project_batch_get_projects(response)
    assert result['projects'][0]['AdditionalSecretIndicators']['NativeResponseComplete'] is False


def test_glue_hidden_password_scope_is_explicit_and_other_secret_properties_dropped():
    item = projected('glue_connection', False)
    assert item['AdditionalSecretIndicators']['Coverage'] == 'visible_nonpassword_properties'
    assert 'PASSWORD' not in item['ConnectionProperties']
    assert 'PythonProperties' not in item and 'AuthenticationConfiguration' not in item
    assert 'hidden-provider-value' not in json.dumps(item)


def test_unsupported_batch_variants_and_malformed_env_never_become_clean():
    service, operation, args, response, _ = fixture('batch_job_definition')
    response['jobDefinitions'][0]['ecsProperties'] = {}
    result = producer.project_response(response, service=service, operation=operation, arguments=args, region=REGION)
    assert result['jobDefinitions'][0]['AdditionalSecretIndicators']['NativeResponseComplete'] is False
    service, operation, args, response, _ = fixture('rest_api_stage')
    response['item'][0]['variables'] = SECRET
    result = producer.project_response(response, service=service, operation=operation, arguments=args, region=REGION)
    assert SECRET not in json.dumps(result)
    assert result['item'][0]['AdditionalSecretIndicators']['NativeResponseComplete'] is False


class Client:
    def __init__(self, service, operation, response):
        self.service, self.operation, self.response = service, operation, response
        self.calls = []
    def can_paginate(self, operation): return False
    def __getattr__(self, operation):
        def call(**kwargs):
            self.calls.append((operation, kwargs))
            if operation == self.operation:
                if self.service == 'batch' and kwargs.get('status') == 'INACTIVE': return {'jobDefinitions': []}
                return deepcopy(self.response)
            if operation == 'get_rest_apis': return {'items': [{'id': 'abc123'}]}
            if operation == 'list_backend_environments': return {'backendEnvironments': []}
            if operation == 'list_branches': return {'branches': []}
            raise AssertionError('unexpected operation ' + operation)
        return call


@pytest.mark.parametrize('kind', KINDS)
def test_real_requests_cache_and_existing_producer_consumer_chain(kind):
    from peaso.collectors import aws_b_services as base, aws_facts_ext as ext, aws_facts_swc as swc
    from peaso.collectors import aws_facts_compute_edge as edge, aws_facts_cb_ca as data
    service, operation, args, response, item = fixture(kind)
    client = Client(service, operation, response)
    session = SimpleNamespace(client=lambda *a, **kw: client, get_partition_for_region=lambda r: 'aws')
    requests = aws.Requests({'retry_attempts': 1})
    if kind in {'codebuild_project', 'ecs_task_definition'}:
        item, = base.ENRICHERS[kind](requests, session, REGION, [item])
    elif kind == 'rest_api_stage':
        result = base.FETCHERS[kind](requests, session, REGION, ACCOUNT)
        item, = result.items
    elif kind == 'amplify_app':
        item, = ext.FETCHERS[kind](requests, session, REGION, ACCOUNT).items
    elif kind == 'batch_job_definition':
        rows = swc.FETCHERS[kind](requests, session, REGION, ACCOUNT).items
        item, = swc.ENRICHERS[kind](requests, session, REGION, rows)
    elif kind == 'elastic_beanstalk_environment':
        item, = edge.ENRICHERS[kind](requests, session, REGION, [item])
    elif kind == 'glue_connection':
        item, = data.FETCHERS[kind](requests, session, REGION, ACCOUNT).items
    else:
        rows = requests.pages(session, service, REGION, operation, 'Jobs').items
        item, = data.ENRICHERS[kind](requests, session, REGION, rows)
    assert FUNCTIONS[kind](item, index(kind, item))[0] == 'FAIL'
    cache = [future.result() for future in requests._cache.values()]
    assert SECRET not in json.dumps(cache)
    assert SECRET not in json.dumps(item)
    before = requests.calls
    requests.call(session, service, REGION, operation, **args)
    assert requests.calls == before


def test_admission_runtime_contracts_are_distinct_serializable_and_side_effect_free():
    import importlib
    from peaso.checks import CHECKS
    before = {c.id for c in CHECKS}
    importlib.reload(checks)
    assert {c.id for c in CHECKS} == before
    assert checks.DECLARATIONS and len(checks.DECLARATIONS) == len(checks.RUNTIME_CASES)
    json.dumps(checks.ADMISSION_DATA)
    for declaration, row in zip(checks.DECLARATIONS, checks.ADMISSION_DATA['checks']):
        assert row['requirements'] == []
        function = getattr(checks, declaration['evaluator'])
        cases = checks.RUNTIME_CASES[declaration['id']]
        for state, expected in [('pass', 'PASS'), ('fail', 'FAIL'), ('missing', 'UNKNOWN'), ('malformed', 'UNKNOWN')]:
            result = function(cases[state], cases.get(state + '_index', cases['index']))
            assert result[0] == expected and len(result[1]['observed']) <= 150


@pytest.mark.parametrize('kind', KINDS)
def test_missing_marker_and_foreign_collection_scope_are_unknown(kind):
    item = projected(kind, False)
    marker(kind, item).clear()
    assert FUNCTIONS[kind](item, index(kind, item))[0] == 'UNKNOWN'
    item = projected(kind, False)
    evidence = index(kind, item)
    evidence['collections'][kind][0]['scope'] = ACCOUNT + '/eu-west-1'
    assert FUNCTIONS[kind](item, evidence)[0] == 'UNKNOWN'


def test_reference_variable_malformed_value_is_not_silently_accepted():
    _, _, _, response, _ = fixture('codebuild_project')
    variable = response['projects'][0]['environment']['environmentVariables'][0]
    variable.update(type='SECRETS_MANAGER', value={'raw': SECRET})
    projected_response = project_batch_get_projects(response)
    assert projected_response['projects'][0]['AdditionalSecretIndicators']['NativeResponseComplete'] is False
    assert SECRET not in json.dumps(projected_response)
