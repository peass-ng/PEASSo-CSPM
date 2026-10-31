"""Bounded six-surface payload projection, provenance and real cache chains."""
from copy import deepcopy
from types import SimpleNamespace
import base64
import gzip
import hashlib
import json
import pytest
from peaso.collectors import aws, aws_configuration_payload_secret_indicators as producer
from peaso.collectors.aws_launch_configuration_redaction import project_response as launch_project
from peaso.checks import aws_configuration_payload_secret_review_20261019 as checks

ACCOUNT, REGION = '123456789012', 'us-east-1'
SECRET = 'Complex123!SyntheticOnly'
KINDS = list(checks.SURFACES)
FUNCTIONS = dict(zip(KINDS, [checks.launch_template, checks.launch_configuration, checks.document, checks.state_machine, checks.notebook, checks.pipeline]))


def encoded(text): return base64.b64encode(text.encode()).decode()
def arn(service, resource): return f'arn:aws:{service}:{REGION}:{ACCOUNT}:{resource}'


def fixture(kind, detected=True):
    text = "DB_PASSWORD='" + SECRET + "'" if detected else 'echo ready'
    if kind == 'ec2_launch_template':
        item = {'LaunchTemplateId': 'lt-abc123', 'LatestVersionNumber': 1, 'DefaultVersionNumber': 1}
        response = {'LaunchTemplateVersions': [{'LaunchTemplateId': 'lt-abc123', 'VersionNumber': 1, 'LaunchTemplateData': {'UserData': encoded(text)}}]}
        return 'ec2', 'describe_launch_template_versions', {'LaunchTemplateId': 'lt-abc123'}, response, item
    if kind == 'launch_configuration':
        item = {'LaunchConfigurationARN': arn('autoscaling', 'launchConfiguration:11111111:launchConfigurationName/example'), 'LaunchConfigurationName': 'example', 'UserData': encoded(text)}
        return 'autoscaling', 'describe_launch_configurations', {}, {'LaunchConfigurations': [item]}, {}
    if kind == 'ssm_document_metadata':
        item = {'Name': 'OwnedDocument', 'Owner': ACCOUNT, 'DocumentVersion': '3'}
        content = json.dumps({'schemaVersion': '2.2', 'password': SECRET} if detected else {'schemaVersion': '2.2', 'value': 'ready'})
        response = {'Name': 'OwnedDocument', 'DocumentVersion': '3', 'DocumentFormat': 'JSON', 'Status': 'Active', 'Content': content,
                    'AttachmentsContent': [{'Url': SECRET, 'Hash': SECRET}]}
        return 'ssm', 'get_document', {'Name': 'OwnedDocument', 'DocumentVersion': '3'}, response, item
    if kind == 'sfn_state_machine':
        item = {'stateMachineArn': arn('states', 'stateMachine:example'), 'name': 'example'}
        definition = {'StartAt': 'Start', 'States': {'Start': {'Type': 'Pass', 'End': True, 'Result': {'password': SECRET} if detected else {'stage': 'production'}}}}
        return 'stepfunctions', 'describe_state_machine', {'stateMachineArn': item['stateMachineArn']}, {
            **item, 'status': 'ACTIVE', 'definition': json.dumps(definition)}, item
    if kind == 'sagemaker_notebook_instance':
        item = {'NotebookInstanceArn': arn('sagemaker', 'notebook-instance/example'), 'NotebookInstanceName': 'example'}
        response = {'NotebookInstanceLifecycleConfigName': 'attached', 'NotebookInstanceLifecycleConfigArn': arn('sagemaker', 'notebook-instance-lifecycle-config/attached'),
                    'OnCreate': [{'Content': encoded(text)}], 'OnStart': []}
        return 'sagemaker', 'describe_notebook_instance_lifecycle_config', {'NotebookInstanceLifecycleConfigName': 'attached'}, response, item
    item = {'id': 'df-abc123', 'name': 'example'}
    response = {'pipelineObjects': [{'id': 'Default', 'name': 'Default', 'fields': [{'key': 'password' if detected else 'stage', 'stringValue': SECRET if detected else 'production'}]}],
                'parameterObjects': [], 'parameterValues': []}
    return 'datapipeline', 'get_pipeline_definition', {'pipelineId': 'df-abc123', 'version': 'latest'}, response, item


def projected(kind, detected=True):
    service, operation, args, response, item = fixture(kind, detected)
    result = launch_project(response) if service == 'autoscaling' else producer.project_response(response, service=service, operation=operation, arguments=args, region=REGION)
    if kind == 'ec2_launch_template': item['Versions'] = result['LaunchTemplateVersions']
    elif kind == 'launch_configuration': item = result['LaunchConfigurations'][0]
    elif kind == 'sfn_state_machine': item = result
    else:
        item['PayloadSource'] = {**result, 'collection_status': 'collected'}
        if kind == 'sagemaker_notebook_instance': item['PayloadSource']['LifecycleConfigName'] = 'attached'
    return item


def index(kind, item):
    scope = ACCOUNT + '/' + REGION
    return {'context': {'provider': 'aws', 'Account': ACCOUNT, 'scope': scope},
        'collections': {kind: [{'type': kind, 'scope': scope, 'status': 'collected', 'items': [item]}]}}


def marker(kind, item):
    if kind == 'ec2_launch_template': return item['Versions'][0]['PayloadSecretIndicators']
    if kind in {'launch_configuration', 'sfn_state_machine'}: return item['PayloadSecretIndicators']
    return item['PayloadSource']['PayloadSecretIndicators']


@pytest.mark.parametrize('kind', KINDS)
@pytest.mark.parametrize('detected', [True, False])
def test_positive_and_negative_full_selected_source_coverage(kind, detected):
    item = projected(kind, detected)
    status, evidence = FUNCTIONS[kind](item, index(kind, item))
    assert status == ('FAIL' if detected else 'PASS')
    assert len(evidence['observed']) <= 150
    encoded_output = json.dumps([item, evidence])
    assert SECRET not in encoded_output and hashlib.sha256(SECRET.encode()).hexdigest() not in encoded_output
    assert base64.b64encode(SECRET.encode()).decode() not in encoded_output


@pytest.mark.parametrize('kind', KINDS)
@pytest.mark.parametrize('field,value', [('collection_status', 'empty'), ('NativeResponseComplete', False), ('AccountId', '999999999999'),
    ('Region', 'eu-west-1'), ('ResourceId', 'foreign'), ('SourceOperation', 'other:GetData'), ('SourceVersion', 'wrong'),
    ('HighConfidenceSecretPresent', False), ('MatchedCategories', ['unexpected'])])
def test_incomplete_foreign_and_mismatched_source_never_passes(kind, field, value):
    item = projected(kind)
    marker(kind, item)[field] = value
    assert FUNCTIONS[kind](item, index(kind, item))[0] == 'UNKNOWN'


@pytest.mark.parametrize('kind', KINDS)
@pytest.mark.parametrize('state', ['denied', 'partial', 'empty', 'not_collected'])
def test_parent_collection_is_authoritative(kind, state):
    item = projected(kind, False)
    evidence = index(kind, item)
    evidence['collections'][kind][0]['status'] = state
    assert FUNCTIONS[kind](item, evidence)[0] == 'UNKNOWN'


@pytest.mark.parametrize('payload', ['not base64', None, encoded('x' * 16385), base64.b64encode(b'\xff').decode(),
    base64.b64encode(gzip.compress(b'x' * 1000000, mtime=0)).decode(), base64.b64encode(gzip.compress(b'echo ready', mtime=0)[:-3]).decode()])
def test_decoding_and_compression_bounds_are_fail_closed(payload):
    service, operation, args, response, item = fixture('ec2_launch_template', False)
    response['LaunchTemplateVersions'][0]['LaunchTemplateData']['UserData'] = payload
    result = producer.project_response(response, service=service, operation=operation, arguments=args, region=REGION)
    item['Versions'] = result['LaunchTemplateVersions']
    assert checks.launch_template(item, index('ec2_launch_template', item))[0] == 'UNKNOWN'
    assert 'UserData' not in result['LaunchTemplateVersions'][0]['LaunchTemplateData']


def test_valid_bounded_gzip_and_absent_userdata():
    service, operation, args, response, item = fixture('ec2_launch_template')
    response['LaunchTemplateVersions'][0]['LaunchTemplateData']['UserData'] = base64.b64encode(gzip.compress(("password='" + SECRET + "'").encode())).decode()
    result = producer.project_response(response, service=service, operation=operation, arguments=args, region=REGION)
    assert result['LaunchTemplateVersions'][0]['PayloadSecretIndicators']['HighConfidenceSecretPresent'] is True
    response['LaunchTemplateVersions'][0]['LaunchTemplateData'].pop('UserData')
    result = producer.project_response(response, service=service, operation=operation, arguments=args, region=REGION)
    assert result['LaunchTemplateVersions'][0]['PayloadSecretIndicators']['HighConfidenceSecretPresent'] is False


def test_template_version_partial_filtered_and_duplicates_are_unknown():
    item = projected('ec2_launch_template', False)
    item['LatestVersionNumber'] = 2
    assert checks.launch_template(item, index('ec2_launch_template', item))[0] == 'UNKNOWN'
    item['LatestVersionNumber'] = 1
    item['Versions'].append(deepcopy(item['Versions'][0]))
    assert checks.launch_template(item, index('ec2_launch_template', item))[0] == 'UNKNOWN'
    service, operation, args, response, _ = fixture('ec2_launch_template')
    args['Versions'] = ['$Latest']
    assert producer.project_response(response, service=service, operation=operation, arguments=args, region=REGION)['LaunchTemplateVersions'][0]['PayloadSecretIndicators']['NativeResponseComplete'] is False


def test_launch_configuration_category_complements_existing_keypair_check():
    text = "AWS_ACCESS_KEY_ID=AKIA" + 'A' * 16 + "\nAWS_SECRET_ACCESS_KEY=" + 'z' * 40
    service, operation, args, response, _ = fixture('launch_configuration', False)
    response['LaunchConfigurations'][0]['UserData'] = encoded(text)
    projected_response = launch_project(response)['LaunchConfigurations'][0]
    assert projected_response['UserDataIndicators']['HasAwsKeyPair'] is True
    assert projected_response['PayloadSecretIndicators']['HighConfidenceSecretPresent'] is False
    assert SECRET not in json.dumps(projected_response)


@pytest.mark.parametrize('kind', ['ssm_document_metadata', 'sfn_state_machine'])
def test_malformed_truncated_or_duplicate_json_does_not_receive_negative_scan(kind):
    service, operation, args, response, item = fixture(kind, False)
    field = 'Content' if kind == 'ssm_document_metadata' else 'definition'
    for text in ['{"password":', '{"same":1,"same":2}', 'null']:
        response[field] = text
        result = producer.project_response(response, service=service, operation=operation, arguments=args, region=REGION)
        assert result['PayloadSecretIndicators']['NativeResponseComplete'] is False


class Client:
    def __init__(self, service, operation, response, item): self.service,self.operation,self.response,self.item,self.seen=service,operation,response,item,[]
    def can_paginate(self, operation): return False
    def __getattr__(self, operation):
        def call(**kwargs):
            if operation == self.operation:
                self.seen.append(kwargs)
                return deepcopy(self.response)
            if operation == 'describe_notebook_instance': return {**self.item, 'NotebookInstanceLifecycleConfigName': 'attached'}
            if operation == 'describe_document_permission': return {'AccountIds': []}
            raise AssertionError('unexpected operation ' + operation)
        return call


@pytest.mark.parametrize('kind', KINDS)
def test_actual_requests_cache_and_existing_or_new_enricher_chain(kind):
    from peaso.collectors import aws_facts_cb_ca as data, aws_facts_compute_edge as edge
    service, operation, args, response, item = fixture(kind)
    client = Client(service, operation, response, item)
    session = SimpleNamespace(client=lambda *a, **kw: client)
    requests = aws.Requests({'retry_attempts': 1})
    if kind == 'ec2_launch_template': item, = data.ENRICHERS[kind](requests, session, REGION, [item])
    elif kind == 'launch_configuration':
        rows = requests.pages(session, service, REGION, operation, 'LaunchConfigurations').items
        item, = edge.ENRICHERS[kind](requests, session, REGION, rows)
    elif kind == 'sfn_state_machine': item, = data.ENRICHERS[kind](requests, session, REGION, [item])
    else: item, = producer.ENRICHERS[kind](requests, session, REGION, [item])
    assert FUNCTIONS[kind](item, index(kind, item))[0] == 'FAIL'
    cache = [future.result() for future in requests._cache.values()]
    serialized = json.dumps([cache, item])
    assert SECRET not in serialized
    def payloads(value):
        if isinstance(value, dict):
            for key, child in value.items():
                if key in {'UserData', 'Content', 'definition', 'stringValue'} and isinstance(child, str):
                    yield child
                else:
                    yield from payloads(child)
        elif isinstance(value, list):
            for child in value: yield from payloads(child)
    for raw_payload in payloads(response):
        assert raw_payload not in serialized
        assert hashlib.sha256(raw_payload.encode()).hexdigest() not in serialized
    before = requests.calls
    # Repeat the exact payload read the enricher issued (it may add read-only
    # selectors such as Step Functions includedData); it must be a cache hit.
    sent = client.seen[0]
    assert all(sent[key] == value for key, value in args.items())
    requests.call(session, service, REGION, operation, **sent)
    assert requests.calls == before


def test_six_distinct_admission_and_runtime_contracts_without_registration():
    import importlib
    from peaso.checks import CHECKS
    before = {c.id for c in CHECKS}
    importlib.reload(checks)
    assert {c.id for c in CHECKS} == before
    assert checks.DECLARATIONS and len(checks.DECLARATIONS) == len(checks.RUNTIME_CASES)
    json.dumps(checks.ADMISSION_DATA)
    for declaration, row in zip(checks.DECLARATIONS, checks.ADMISSION_DATA['checks']):
        assert row['requirements'] == []
        function, cases = getattr(checks, declaration['evaluator']), checks.RUNTIME_CASES[declaration['id']]
        for state, expected in [('pass', 'PASS'), ('fail', 'FAIL'), ('missing', 'UNKNOWN'), ('malformed', 'UNKNOWN')]:
            result = function(cases[state], cases.get(state + '_index', cases['index']))
            assert result[0] == expected and len(result[1]['observed']) <= 150


def test_notebook_confirmed_no_attachment_is_negative_but_denied_read_unknown():
    from botocore.exceptions import ClientError
    _, _, _, _, item = fixture('sagemaker_notebook_instance', False)
    client = SimpleNamespace(describe_notebook_instance=lambda **kw: deepcopy(item))
    session = SimpleNamespace(client=lambda *a, **kw: client)
    request = aws.Requests({'retry_attempts': 1})
    row, = producer.notebooks(request, session, REGION, [item])
    assert checks.notebook(row, index('sagemaker_notebook_instance', row))[0] == 'PASS'
    assert request.calls == 1
    def deny(**kwargs):
        raise ClientError({'Error': {'Code': 'AccessDeniedException', 'Message': SECRET}}, 'DescribeNotebookInstance')
    denied = aws.Requests({'retry_attempts': 1})
    session = SimpleNamespace(client=lambda *a, **kw: SimpleNamespace(describe_notebook_instance=deny))
    row, = producer.notebooks(denied, session, REGION, [item])
    assert checks.notebook(row, index('sagemaker_notebook_instance', row))[0] == 'UNKNOWN'
    assert SECRET not in json.dumps(row)
    assert next(iter(denied._cache.values())).exception().__traceback__ is None


def test_ssm_unowned_or_unknown_version_does_not_fetch_content():
    request = SimpleNamespace(detail=lambda *a, **kw: pytest.fail('must not fetch unowned/unknown document'))
    row, = producer.documents(request, object(), REGION, [{'Name': 'AWS-Document', 'Owner': 'Amazon', 'DocumentVersion': '1'}])
    assert row['PayloadSource']['collection_status'] == 'not_collected'
    row, = producer.documents(request, object(), REGION, [{'Name': 'OwnDocument', 'Owner': ACCOUNT, 'DocumentVersion': '$LATEST'}])
    assert row['PayloadSource']['collection_status'] == 'not_collected'


@pytest.mark.parametrize('where', ['objects', 'parameters', 'values'])
def test_data_pipeline_literal_values_are_scanned_and_reference_values_not_downloaded(where):
    service, operation, args, response, item = fixture('datapipeline_pipeline', False)
    if where == 'objects': response['pipelineObjects'][0]['fields'] = [{'key': 'password', 'stringValue': SECRET}]
    if where == 'parameters': response['parameterObjects'] = [{'id': '*password', 'attributes': [{'key': 'password', 'stringValue': SECRET}]}]
    if where == 'values': response['parameterValues'] = [{'id': '*password', 'stringValue': SECRET}]
    safe = producer.project_response(response, service=service, operation=operation, arguments=args, region=REGION)
    assert safe['PayloadSecretIndicators']['HighConfidenceSecretPresent'] is True
    assert SECRET not in json.dumps(safe)
    response = {'pipelineObjects': [{'id': 'A', 'name': 'A', 'fields': [{'key': 'parent', 'refValue': SECRET}]}]}
    safe = producer.project_response(response, service=service, operation=operation, arguments=args, region=REGION)
    assert safe['PayloadSecretIndicators']['HighConfidenceSecretPresent'] is False
    assert SECRET not in json.dumps(safe)


@pytest.mark.parametrize('text', ['{"value":NaN}', '[' * 2000 + '0' + ']' * 2000])
def test_nonstandard_or_excessively_nested_json_is_unknown(text):
    service, operation, args, response, _ = fixture('ssm_document_metadata', False)
    response['Content'] = text
    assert producer.project_response(response, service=service, operation=operation, arguments=args, region=REGION)['PayloadSecretIndicators']['NativeResponseComplete'] is False


def test_yaml_invalid_or_binary_payload_never_certifies_clean():
    service, operation, args, response, _ = fixture('ssm_document_metadata', False)
    response.update(DocumentFormat='YAML', Content='value: [unfinished')
    assert producer.project_response(response, service=service, operation=operation, arguments=args, region=REGION)['PayloadSecretIndicators']['NativeResponseComplete'] is False
    with pytest.raises(ValueError): producer.decode(base64.b64encode(b'p\x00a\x00s\x00s').decode())


class StateMachineClient:
    """DescribeStateMachine as AWS answers it: METADATA_ONLY returns definition "{}"."""
    def __init__(self, response, full_error=None): self.response, self.full_error, self.seen = response, full_error, []
    def can_paginate(self, operation): return False
    def describe_state_machine(self, **kwargs):
        self.seen.append(kwargs)
        if kwargs.get('includedData') == 'METADATA_ONLY': return {**deepcopy(self.response), 'definition': '{}'}
        if self.full_error is not None:
            from botocore.exceptions import ClientError
            raise ClientError({'Error': {'Code': self.full_error, 'Message': 'denied'}}, 'DescribeStateMachine')
        return deepcopy(self.response)


@pytest.mark.parametrize('detected', [True, False])
def test_state_machine_definition_is_read_in_full(detected):
    from peaso.collectors import aws_facts_cb_ca as data
    _, _, _, response, item = fixture('sfn_state_machine', detected)
    client = StateMachineClient(response)
    row, = data.ENRICHERS['sfn_state_machine'](aws.Requests({'retry_attempts': 1}), SimpleNamespace(client=lambda *a, **kw: client), REGION, [item])
    assert checks.state_machine(row, index('sfn_state_machine', row))[0] == ('FAIL' if detected else 'PASS')


def test_unreadable_state_machine_definition_keeps_metadata_and_names_reason():
    from peaso.collectors import aws_facts_cb_ca as data
    _, _, _, response, item = fixture('sfn_state_machine', True)
    client = StateMachineClient(response, full_error='AccessDeniedException')
    row, = data.ENRICHERS['sfn_state_machine'](aws.Requests({'retry_attempts': 1}), SimpleNamespace(client=lambda *a, **kw: client), REGION, [item])
    status, evidence = checks.state_machine(row, index('sfn_state_machine', row))
    assert status == 'UNKNOWN' and evidence['reason'].startswith('state_machine_definition_unreadable')
    assert row['status'] == 'ACTIVE'


def test_bool_version_cannot_impersonate_integer_and_arn_account_is_required():
    item = projected('ec2_launch_template', False)
    marker('ec2_launch_template', item)['SourceVersion'] = True
    assert checks.launch_template(item, index('ec2_launch_template', item))[0] == 'UNKNOWN'
    item = projected('sfn_state_machine', False)
    marker('sfn_state_machine', item)['AccountId'] = None
    assert checks.state_machine(item, index('sfn_state_machine', item))[0] == 'UNKNOWN'
