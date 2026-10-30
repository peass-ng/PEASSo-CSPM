"""Safe configuration projections must redact before Requests cache or snapshots."""
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
import pytest

from peaso.collectors import aws
from peaso.collectors import aws_configuration_secret_indicators as projection
from peaso.collectors.aws_lambda_environment_metadata import project_response as project_lambda
from peaso.checks import aws_configuration_secret_review_20261019 as checks
from test_peaso_aws_bulk_inventory import sdk

ACCOUNT = '123456789012'
REGION = 'us-east-1'
FUNCTION = f'arn:aws:lambda:{REGION}:{ACCOUNT}:function:worker'
STACK = f'arn:aws:cloudformation:{REGION}:{ACCOUNT}:stack/demo/12345678-1234-1234-1234-123456789012'
PRIVATE = 'Complex123!SyntheticCredential'


def configuration(variables=None):
    row = {'FunctionArn': FUNCTION, 'FunctionName': 'worker', 'Runtime': 'python3.13'}
    if variables is not None:
        row['Environment'] = {'Variables': variables}
    return row


def stack(outputs=None, **extra):
    row = {'StackId': STACK, 'StackName': 'demo', 'StackStatus': 'CREATE_COMPLETE',
           'CreationTime': datetime(2026, 1, 1, tzinfo=timezone.utc), **extra}
    if outputs is not None:
        row['Outputs'] = outputs
    return row


def subject(kind, **kwargs):
    if kind == 'lambda_function':
        response = project_lambda(configuration(kwargs.get('variables', {})), 'get_function_configuration')
        response['collection_status'] = 'collected'
        return {'FunctionArn': FUNCTION, 'FunctionName': 'worker', 'Configuration': response}
    return projection.project_cloudformation_response({'Stacks': [stack(kwargs.get('outputs', []))]}, region=REGION)['Stacks'][0]


def index(item, kind):
    return {'context': {'provider': 'aws', 'Account': ACCOUNT, 'scope': ACCOUNT + '/' + REGION},
        'collections': {kind: [{'type': kind, 'scope': ACCOUNT + '/' + REGION, 'status': 'collected', 'items': [item]}]}}


def marker(item, kind):
    return (item['Configuration'] if kind == 'lambda_function' else item)['ConfigurationSecretIndicators']


@pytest.mark.parametrize('kind,function', [('lambda_function', checks.lambda_environment), ('cloudformation_stack', checks.cloudformation_outputs)])
@pytest.mark.parametrize('detected', [True, False])
def test_bounded_positive_and_negative_indicator(kind, function, detected):
    value = PRIVATE if detected else 'production'
    item = subject(kind, variables={'DB_PASSWORD' if detected else 'STAGE': value},
        outputs=[{'OutputKey': 'DB_PASSWORD' if detected else 'Stage', 'OutputValue': value}])
    original = deepcopy(item)
    status, evidence = function(item, index(item, kind))
    assert status == ('FAIL' if detected else 'PASS')
    assert evidence['high_confidence_secret_present'] is detected
    assert item == original
    assert PRIVATE not in json.dumps([item, evidence], default=str)
    assert hashlib.sha256(PRIVATE.encode()).hexdigest() not in json.dumps([item, evidence], default=str)


@pytest.mark.parametrize('variables,category', [
    ({'DATA': '-----BEGIN RSA PRIVATE KEY-----\nSYNTHETIC-NOT-A-REAL-KEY'}, 'private_key'),
    ({'AWS_ACCESS_KEY_ID': 'AKIA' + 'A' * 16, 'AWS_SECRET_ACCESS_KEY': 'z' * 40}, 'cloud_credential'),
    ({'DB_PASSWORD': PRIVATE}, 'password_assignment')])
def test_selected_high_confidence_categories(variables, category):
    indicator = project_lambda(configuration(variables), 'get_function_configuration')['ConfigurationSecretIndicators']
    assert indicator['collection_status'] == 'collected'
    assert category in indicator['MatchedCategories']
    serialized = json.dumps(indicator)
    for value in variables.values():
        assert value not in serialized


@pytest.mark.parametrize('variables', [
    {'PASSTHROUGH_MODE': 'enabled'}, {'KEY_PREFIX': 'public/assets'}, {'TOKEN_ENDPOINT': 'https://example.invalid/token'},
    {'DB_PASSWORD': '${PASSWORD_FROM_OWNER}'}, {'DB_PASSWORD': 'example123!'}, {'DB_PASSWORD': '{{resolve:secretsmanager:example}}'},
    {'PUBLIC_KEY': '-----BEGIN PUBLIC KEY-----\nTEST'}, {'TOKEN': 'short-public-example'}])
def test_benign_names_and_placeholders_are_not_upstream_keyword_false_positives(variables):
    indicator = project_lambda(configuration(variables), 'get_function_configuration')['ConfigurationSecretIndicators']
    assert indicator['HighConfidenceSecretPresent'] is False


@pytest.mark.parametrize('kind,function', [('lambda_function', checks.lambda_environment), ('cloudformation_stack', checks.cloudformation_outputs)])
@pytest.mark.parametrize('state', ['denied', 'partial', 'empty', 'not_collected', 'malformed'])
def test_incomplete_or_fake_empty_parent_inventory_is_unknown(kind, function, state):
    item = subject(kind)
    evidence = index(item, kind)
    evidence['collections'][kind][0]['status'] = state
    assert function(item, evidence)[0] == 'UNKNOWN'


@pytest.mark.parametrize('kind,function', [('lambda_function', checks.lambda_environment), ('cloudformation_stack', checks.cloudformation_outputs)])
@pytest.mark.parametrize('field,value', [
    ('ResourceArn', FUNCTION + '-foreign'), ('Region', 'eu-west-1'), ('AccountId', '999999999999'),
    ('SourceOperation', 'untrusted:GetData'), ('NativeResponseComplete', False),
    ('collection_status', 'empty'), ('Schema', 'unrecognized'), ('HighConfidenceSecretPresent', 'false'),
    ('MatchedCategories', ['arbitrary-value']), ('MatchedCategories', ['private_key']),
    ('HighConfidenceSecretPresent', True)])
def test_indicator_provenance_and_coherence_are_mandatory(kind, function, field, value):
    item = subject(kind)
    marker(item, kind)[field] = value
    assert function(item, index(item, kind))[0] == 'UNKNOWN'


@pytest.mark.parametrize('kind,function', [('lambda_function', checks.lambda_environment), ('cloudformation_stack', checks.cloudformation_outputs)])
def test_foreign_context_membership_and_duplicate_native_identity(kind, function):
    item = subject(kind)
    evidence = index(item, kind)
    evidence['context']['scope'] = '999999999999/' + REGION
    assert function(item, evidence)[0] == 'UNKNOWN'
    evidence = index(item, kind)
    evidence['collections'][kind][0]['items'] = []
    assert function(item, evidence)[0] == 'UNKNOWN'
    evidence['collections'][kind][0]['items'] = [item, deepcopy(item)]
    assert function(item, evidence)[0] == 'UNKNOWN'


@pytest.mark.parametrize('environment', [None, [], {'Variables': []}, {'Variables': {'DB_PASSWORD': 42}},
    {'Error': {'Message': PRIVATE}}, {'Variables': {}, 'Error': {'Message': PRIVATE}}])
def test_unreadable_lambda_environment_marker_is_not_clean(environment):
    raw = configuration()
    raw['Environment'] = environment
    response = project_lambda(raw, 'get_function_configuration')
    assert response['ConfigurationSecretIndicators']['collection_status'] != 'collected'
    assert PRIVATE not in json.dumps(response)


def test_documented_absence_on_success_is_distinct_from_fake_empty_and_listing():
    response = project_lambda(configuration(), 'get_function_configuration')
    assert response['ConfigurationSecretIndicators']['collection_status'] == 'collected'
    assert response['ConfigurationSecretIndicators']['HighConfidenceSecretPresent'] is False
    response = project_lambda({**configuration(), 'collection_status': 'empty'}, 'get_function_configuration')
    assert response['ConfigurationSecretIndicators']['NativeResponseComplete'] is False
    response = project_lambda({'Functions': [configuration({'DB_PASSWORD': PRIVATE})]}, 'list_functions')
    assert response['Functions'][0]['ConfigurationSecretIndicators']['collection_status'] == 'not_collected'
    assert PRIVATE not in json.dumps(response)


@pytest.mark.parametrize('outputs', [None, [], [{'OutputKey': 'Stage', 'OutputValue': 'production'}]])
def test_complete_stack_no_outputs_is_scanned_negative(outputs):
    projected = projection.project_cloudformation_response({'Stacks': [stack(outputs)]}, region=REGION)['Stacks'][0]
    assert checks.cloudformation_outputs(projected, index(projected, 'cloudformation_stack'))[0] == 'PASS'


@pytest.mark.parametrize('outputs', [[{'OutputKey': 'Password'}], [{'OutputKey': 'Password', 'OutputValue': 3}],
    [{'OutputKey': 'Same', 'OutputValue': 'one'}, {'OutputKey': 'Same', 'OutputValue': 'two'}]])
def test_malformed_outputs_are_unknown_without_echoing_provider_content(outputs):
    projected = projection.project_cloudformation_response({'Stacks': [stack(outputs)]}, region=REGION)['Stacks'][0]
    assert checks.cloudformation_outputs(projected, index(projected, 'cloudformation_stack'))[0] == 'UNKNOWN'
    assert 'Outputs' not in projected


def test_stack_response_strips_parameters_output_values_and_freeform_fields():
    raw = {'Stacks': [stack([{'OutputKey': 'DB_PASSWORD', 'OutputValue': PRIVATE, 'Description': PRIVATE, 'ExportName': PRIVATE}],
        Parameters=[{'ParameterKey': 'Password', 'ParameterValue': PRIVATE}], Description=PRIVATE, StackStatusReason=PRIVATE)]}
    baseline = deepcopy(raw)
    result = projection.project_cloudformation_response(raw, region=REGION)
    assert raw == baseline
    assert PRIVATE not in json.dumps(result, default=str)
    assert 'Outputs' not in result['Stacks'][0]
    assert result['Stacks'][0]['ConfigurationSecretIndicators']['HighConfidenceSecretPresent'] is True


def test_bootstrap_preserves_only_validated_numeric_version():
    raw = stack([{'OutputKey': 'BootstrapVersion', 'OutputValue': '25'}, {'OutputKey': 'Other', 'OutputValue': PRIVATE}],
                StackName='CDKToolkit', StackId=STACK.replace('/demo/', '/CDKToolkit/'))
    result = projection.project_cloudformation_response({'Stacks': [raw]}, region=REGION)['Stacks'][0]
    assert result['Outputs'] == [{'OutputKey': 'BootstrapVersion', 'OutputValue': '25'}]
    raw['Outputs'][0]['OutputValue'] = PRIVATE
    result = projection.project_cloudformation_response({'Stacks': [raw]}, region=REGION)['Stacks'][0]
    assert result['Outputs'] == [] and PRIVATE not in json.dumps(result, default=str)


def test_scanner_bounds_and_unknown_fields_are_not_silently_clean():
    huge = configuration({'DB_PASSWORD': 'z' * (projection.MAX_VALUE_BYTES + 1)})
    assert project_lambda(huge, 'get_function_configuration')['ConfigurationSecretIndicators']['collection_status'] == 'malformed'
    item = subject('lambda_function')
    marker(item, 'lambda_function')['unexpected'] = PRIVATE
    assert checks.lambda_environment(item, index(item, 'lambda_function'))[0] == 'UNKNOWN'


def cached(requests):
    return [future.result() for future in requests._cache.values()]


def test_lambda_real_request_and_existing_enricher_chain_redact_before_cache(sdk):
    from peaso.collectors import aws_b_services
    session, add = sdk
    stub = add('lambda')
    stub.add_response('get_function_concurrency', {'ReservedConcurrentExecutions': 10}, {'FunctionName': 'worker'})
    stub.add_response('get_function_configuration', configuration({'DB_PASSWORD': PRIVATE}), {'FunctionName': 'worker'})
    requests = aws.Requests({})
    item, = aws_b_services.ENRICHERS['lambda_function'](requests, session, REGION, [{'FunctionArn': FUNCTION, 'FunctionName': 'worker'}])
    repeated = requests.call(session, 'lambda', REGION, 'get_function_configuration', FunctionName='worker')
    assert repeated['ConfigurationSecretIndicators']['HighConfidenceSecretPresent'] is True
    assert PRIVATE not in json.dumps(cached(requests), default=str)
    assert PRIVATE not in json.dumps(item, default=str)
    assert checks.lambda_environment(item, index(item, 'lambda_function'))[0] == 'FAIL'
    assert requests.calls == 2 and requests.cache_hits == 1
    stub.assert_no_pending_responses()


def test_cloudformation_real_pagination_cache_and_enricher_chain(sdk):
    from peaso.collectors import aws_facts_data_identity
    session, add = sdk
    stub = add('cloudformation')
    first = stack([{'OutputKey': 'DB_PASSWORD', 'OutputValue': PRIVATE}],
                  Parameters=[{'ParameterKey': 'Password', 'ParameterValue': PRIVATE}])
    second = stack([], StackName='other', StackId=STACK.replace('/demo/', '/other/'))
    stub.add_response('describe_stacks', {'Stacks': [first], 'NextToken': 'second'}, {})
    stub.add_response('describe_stacks', {'Stacks': [second]}, {'NextToken': 'second'})
    requests = aws.Requests({})
    result = requests.pages(session, 'cloudformation', REGION, 'describe_stacks', 'Stacks')
    assert result.status == 'collected' and len(result.items) == 2
    assert PRIVATE not in json.dumps(cached(requests), default=str)
    rows = aws_facts_data_identity.ENRICHERS['cloudformation_stack'](requests, session, REGION, result.items)
    assert checks.cloudformation_outputs(rows[0], index(rows[0], 'cloudformation_stack'))[0] == 'FAIL'
    assert checks.cloudformation_outputs(rows[1], index(rows[1], 'cloudformation_stack'))[0] == 'PASS'
    assert PRIVATE not in json.dumps(rows, default=str)
    stub.assert_no_pending_responses()


def test_denied_lambda_response_is_unknown_and_diagnostics_are_content_free(sdk):
    from peaso.collectors import aws_b_services
    session, add = sdk
    stub = add('lambda')
    stub.add_response('get_function_concurrency', {}, {'FunctionName': 'worker'})
    stub.add_client_error('get_function_configuration', 'AccessDeniedException', PRIVATE, expected_params={'FunctionName': 'worker'})
    item, = aws_b_services.ENRICHERS['lambda_function'](aws.Requests({'retry_attempts': 1}), session, REGION,
                                                    [{'FunctionArn': FUNCTION, 'FunctionName': 'worker'}])
    result = checks.lambda_environment(item, index(item, 'lambda_function'))
    assert result[0] == 'UNKNOWN'
    assert PRIVATE not in json.dumps([item, result], default=str)
    stub.assert_no_pending_responses()


def test_admission_and_runtime_cases_are_serializable_complete_and_unregistered():
    import importlib
    from peaso.checks import CHECKS
    before = {row.id for row in CHECKS}
    importlib.reload(checks)
    assert {row.id for row in CHECKS} == before
    json.dumps(checks.ADMISSION_DATA)
    for declaration, row in zip(checks.DECLARATIONS, checks.ADMISSION_DATA['checks']):
        assert row['requirements'] == []
        function = getattr(checks, declaration['evaluator'])
        cases = checks.RUNTIME_CASES[declaration['id']]
        assert function(cases['pass'], cases['pass_index'])[0] == 'PASS'
        assert function(cases['fail'], cases['fail_index'])[0] == 'FAIL'
        assert function(cases['missing'], cases['index'])[0] == 'UNKNOWN'
        assert function(cases['malformed'], cases['index'])[0] == 'UNKNOWN'


@pytest.mark.parametrize('state', ['CREATE_IN_PROGRESS', 'UPDATE_IN_PROGRESS', 'CREATE_FAILED', 'UNRECOGNIZED'])
def test_unsettled_stack_outputs_never_turn_absence_into_clean(state):
    response = projection.project_cloudformation_response({'Stacks': [stack(StackStatus=state)]}, region=REGION)
    item = response['Stacks'][0]
    assert checks.cloudformation_outputs(item, index(item, 'cloudformation_stack'))[0] == 'UNKNOWN'


def test_foreign_region_stack_and_lambda_response_identity_are_unknown():
    item = projection.project_cloudformation_response({'Stacks': [stack()]}, region='eu-west-1')['Stacks'][0]
    assert checks.cloudformation_outputs(item, index(item, 'cloudformation_stack'))[0] == 'UNKNOWN'
    item = subject('lambda_function')
    item['Configuration']['FunctionName'] = 'other'
    assert checks.lambda_environment(item, index(item, 'lambda_function'))[0] == 'UNKNOWN'


def test_bad_unicode_is_omitted_instead_of_copied_into_indicators():
    response = project_lambda(configuration({'DB_PASSWORD': '\ud800'}), 'get_function_configuration')
    assert response['ConfigurationSecretIndicators']['collection_status'] == 'malformed'
    assert '\ud800' not in json.dumps(response)


@pytest.mark.parametrize('status', ['empty', 'partial', 'denied', 'malformed'])
def test_lambda_native_configuration_status_must_be_collected(status):
    item = subject('lambda_function')
    item['Configuration']['collection_status'] = status
    assert checks.lambda_environment(item, index(item, 'lambda_function'))[0] == 'UNKNOWN'


def test_explicit_null_stack_outputs_are_not_documented_omission():
    raw = stack()
    raw['Outputs'] = None
    item = projection.project_cloudformation_response({'Stacks': [raw]}, region=REGION)['Stacks'][0]
    assert checks.cloudformation_outputs(item, index(item, 'cloudformation_stack'))[0] == 'UNKNOWN'


def test_failed_projection_future_retains_no_raw_exception_or_traceback(monkeypatch):
    from types import SimpleNamespace
    requests = aws.Requests({'retry_attempts': 1})
    monkeypatch.setattr(requests, 'client', lambda *args: SimpleNamespace(describe_stacks=lambda **kwargs: {'Stacks': PRIVATE}))
    with pytest.raises(aws.ReadFailure):
        requests.call(object(), 'cloudformation', REGION, 'describe_stacks')
    failure = next(iter(requests._cache.values())).exception()
    assert failure.__traceback__ is None
    assert PRIVATE not in repr(failure.args)
    assert PRIVATE not in repr(vars(failure))


def test_observed_sentences_remain_short_for_each_status():
    for declaration in checks.DECLARATIONS:
        function = getattr(checks, declaration['evaluator'])
        cases = checks.RUNTIME_CASES[declaration['id']]
        for state in ('pass', 'fail', 'missing', 'malformed'):
            result = function(cases[state], cases.get(state + '_index', cases['index']))
            assert len(result[1]['observed']) <= 150
