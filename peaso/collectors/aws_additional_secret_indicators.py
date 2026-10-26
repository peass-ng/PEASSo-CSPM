"""Safe, bounded value indicators for eight configuration API surfaces.

Called at the SDK boundary before redaction/caching. Only booleans, category
names and native identity/coverage metadata are retained; no value fingerprints.
No external scanner, validation request, archive, log or execution is used.
"""
from copy import deepcopy
import json
import re
from .aws_configuration_secret_indicators import MAX_PAIRS, MAX_TOTAL_BYTES, MAX_VALUE_BYTES
from .aws_user_data_secret_indicators import project as inspect_text

SCHEMA = 'additional-configuration-secret-indicators-v1'
OPERATIONS = {('apigateway', 'get_stages'), ('ecs', 'describe_task_definition'),
    ('amplify', 'list_apps'), ('amplify', 'get_app'), ('batch', 'describe_job_definitions'),
    ('elasticbeanstalk', 'describe_configuration_settings'), ('glue', 'get_jobs'), ('glue', 'get_job'),
    ('glue', 'get_connections'), ('glue', 'get_connection')}
SAFE_GLUE_FLAGS = {'--encryption-type', '--enable-continuous-cloudwatch-log', '--enable-continuous-log-filter', '--enable-spark-ui',
    '--enable-metrics', '--enable-observability-metrics', '--enable-job-insights', '--enable-glue-datacatalog', '--job-bookmark-option',
    '--job-language', '--enable-auto-scaling'}
SAFE_GLUE_PROPERTIES = {'JDBC_ENFORCE_SSL', 'KAFKA_SSL_ENABLED', 'SKIP_CUSTOM_JDBC_CERT_VALIDATION', 'KAFKA_SKIP_CUSTOM_CERT_VALIDATION', 'JDBC_ENGINE', 'JDBC_ENGINE_VERSION'}
SAFE_BEANSTALK = {('aws:elasticbeanstalk:cloudwatch:logs', 'StreamLogs'), ('aws:elasticbeanstalk:managedactions', 'ManagedActionsEnabled'),
                 ('aws:elasticbeanstalk:healthreporting:system', 'SystemType'),
                 ('aws:elasticbeanstalk:hostmanager', 'LogPublicationControl'),
                 ('aws:elasticbeanstalk:environment', 'LoadBalancerType')}


NAME_CHECKS = {
    'codebuild_project': {'aws.c2b.codebuild.no_plaintext_sensitive_env_names', 'aws.nist.codebuild_exact_aws_key_env_names',
        'aws.pci.codebuild.aws_key_environment_vars', 'aws_nist_codebuild_project_plaintext_env_variables_no_sensitive_aws_values'},
    'ecs_task_definition': {'aws.c2b.ecs.no_credential_named_env_vars', 'aws_ecs_task_definition_credential_environment_names',
        'aws_nist_ecs_task_definition_container_environment_no_secret'},
}


def _salvage_named(kind, row, region):
    """Strict parsing rejected this resource, yet its environment names stay
    projected and the name checks still report on them. Keep each clear value
    those checks name in private evidence, entry by entry."""
    from peaso.secret_evidence import enabled, named_literal
    if not enabled() or kind not in NAME_CHECKS or not isinstance(row, dict):
        return
    arn = row.get('arn' if kind == 'codebuild_project' else 'taskDefinitionArn')
    match = re.fullmatch(r'arn:(?:aws|aws-cn|aws-us-gov):[a-z0-9-]+:([a-z0-9-]+):([0-9]{12}):.+', arn) if isinstance(arn, str) else None
    if match is None or region is not None and match[1] != region:
        return
    region = match[1]
    if kind == 'codebuild_project':
        environment = row.get('environment')
        groups = [('environment.environmentVariables', environment.get('environmentVariables') if isinstance(environment, dict) else None)]
    else:
        containers = row.get('containerDefinitions')
        groups = [('containerDefinitions[' + str(i) + '].environment', container.get('environment'))
                  for i, container in enumerate(containers[:4096] if isinstance(containers, list) else []) if isinstance(container, dict)]
    for path, entries in groups:
        for entry in entries[:4096] if isinstance(entries, list) else []:
            if (not isinstance(entry, dict) or not isinstance(entry.get('name'), str) or not isinstance(entry.get('value'), str)
                    or 'valueFrom' in entry or kind == 'codebuild_project' and entry.get('type', 'PLAINTEXT') != 'PLAINTEXT'):
                continue
            named_literal(entry['name'], entry['value'], provider='aws', resource_id=arn, scope=match[2] + '/' + region,
                          path=path + '[name=' + json.dumps(entry['name']) + '].value', checks=NAME_CHECKS[kind])


def _bad():
    return {'Schema': SCHEMA, 'collection_status': 'malformed', 'NativeResponseComplete': False}


def _mapping(value):
    if not isinstance(value, dict) or len(value) > MAX_PAIRS:
        raise ValueError('invalid configuration map')
    return list(value.items())


def _environment(value, typed=False):
    if not isinstance(value, list) or len(value) > MAX_PAIRS:
        raise ValueError('invalid environment')
    pairs = []
    for entry in value:
        if not isinstance(entry, dict) or not isinstance(entry.get('name'), str) or not isinstance(entry.get('value'), str):
            raise ValueError('invalid environment entry')
        if typed:
            if entry.get('type') not in {'PLAINTEXT', 'PARAMETER_STORE', 'SECRETS_MANAGER'}:
                raise ValueError('unknown environment type')
            if entry['type'] != 'PLAINTEXT':
                continue  # references are not retrieved secret values
        if 'valueFrom' in entry:
            raise ValueError('unsupported inline environment selector')
        pairs.append((entry['name'], entry.get('value')))
    return pairs


def _scan(kind, resource_id, groups, region, operation, coverage, arn=None, account=None):
    try:
        if not isinstance(resource_id, str) or not resource_id or len(resource_id) > 2048 or not isinstance(region, str):
            raise ValueError('missing resource authority')
        if arn is not None:
            match = re.fullmatch(r'arn:(aws|aws-cn|aws-us-gov):[a-z0-9-]+:([a-z0-9-]+):([0-9]{12}):.+', arn)
            if match is None or match[2] != region:
                raise ValueError('foreign resource region')
            account = match[3]
        if account is not None and not re.fullmatch(r'[0-9]{12}', account):
            raise ValueError('invalid account')
        categories, total = set(), 0
        if not isinstance(groups, list) or len(groups) > MAX_PAIRS:
            raise ValueError('invalid configuration groups')
        for group_index, pairs in enumerate(groups):
            if len(pairs) > MAX_PAIRS:
                raise ValueError('configuration pair limit')
            mapping = {}
            for key, value in pairs:
                if not isinstance(key, str) or not key or key in mapping or not isinstance(value, str):
                    raise ValueError('invalid configuration value')
                total += len(key.encode()) + len(value.encode())
                if len(key) > 4096 or len(value.encode()) > MAX_VALUE_BYTES or total > MAX_TOTAL_BYTES:
                    raise ValueError('configuration size limit')
                mapping[key] = value
            from peaso.secret_evidence import source_context, named_mapping
            authority = arn or resource_id
            group_path = {'codebuild_project': 'environment.environmentVariables',
                'rest_api_stage': 'variables', 'ecs_task_definition': 'containerDefinitions[' + str(group_index) + '].environment',
                'amplify_app': 'environmentVariables', 'batch_job_definition': 'containerProperties.environment',
                'elastic_beanstalk_environment': 'OptionSettings',
                'glue_job': 'DefaultArguments' if group_index == 0 else 'NonOverridableArguments',
                'glue_connection': 'ConnectionProperties'}.get(kind, coverage + '[' + str(group_index) + ']')
            name_checks = NAME_CHECKS.get(kind, set())
            named_mapping(mapping, provider='aws', resource_id=authority,
                          scope=(account + '/' + region) if account else region, path=group_path, checks=name_checks,
                          entry_list=kind in {'codebuild_project', 'ecs_task_definition'})
            with source_context(resource_id=authority, scope=(account + '/' + region) if account else region,
                                check_ids={'aws.review.' + kind + '.configuration_secret_indicators'},
                                path=group_path, source=operation, location_kind='configuration', native=mapping):
                categories.update(inspect_text(json.dumps(mapping), 'unused')['MatchedCategories'])
        return {'Schema': SCHEMA, 'collection_status': 'collected', 'NativeResponseComplete': True,
            'Kind': kind, 'ResourceId': resource_id, 'AccountId': account, 'Region': region, 'SourceOperation': operation,
            'Coverage': coverage, 'HighConfidenceSecretPresent': bool(categories), 'MatchedCategories': sorted(categories)}
    except (ValueError, TypeError, UnicodeError):
        return _bad()


def codebuild_indicator(project, region=None):
    try:
        arn = project['arn']
        match = re.fullmatch(r'arn:(?:aws|aws-cn|aws-us-gov):codebuild:([a-z0-9-]+):[0-9]{12}:project/(.+)', arn)
        if match is None or match[2] != project['name']:
            raise ValueError('invalid project identity')
        region = region or match[1]
        from peaso.secret_evidence import url_credentials
        for field, source in [('source', project.get('source'))] + [('secondarySources[' + str(i) + ']', v) for i, v in enumerate(project.get('secondarySources', []))]:
            if isinstance(source, dict) and source.get('type') == 'BITBUCKET':
                url_credentials(source.get('location'), resource_id=arn, path=field + '.location',
                                check_id='aws.c2b.codebuild.source_url_no_credentials', scope=region)
        environment = project['environment']
        if not isinstance(environment, dict):
            raise ValueError('invalid project environment')
        pairs = _environment(environment.get('environmentVariables', []), typed=True)
        indicator = _scan('codebuild_project', project['name'], [pairs], region, 'codebuild:BatchGetProjects', 'plaintext_environment', arn=arn)
    except (ValueError, TypeError, KeyError):
        indicator = _bad()
    if indicator['collection_status'] != 'collected':
        _salvage_named('codebuild_project', project, region if isinstance(region, str) else None)
    return indicator


def _redact(value):
    """Remove unscanned embedded scripts and plaintext env values recursively."""
    if isinstance(value, list):
        return [_redact(row) for row in value]
    if not isinstance(value, dict):
        return deepcopy(value)
    result = {}
    for key, child in value.items():
        if key in {'AdditionalSecretIndicators', 'buildSpec', 'customHeaders', 'basicAuthCredentials', 'oauthToken', 'accessToken',
                   'command', 'entryPoint', 'userData', 'script', 'password', 'Password', 'AuthenticationConfiguration'}:
            continue
        if key in {'environment', 'environmentVariables', 'environmentVariablesMap', 'env'} and isinstance(child, list):
            result[key] = ([{name: deepcopy(row[name]) for name in ('name', 'type') if name in row} for row in child]
                           if all(isinstance(row, dict) and isinstance(row.get('name'), str) for row in child) else None)
        elif key in {'environment', 'env'}:
            result[key] = None  # unavailable shape, never an invented empty list
        elif key in {'variables', 'environmentVariables', 'PythonProperties', 'AthenaProperties', 'SparkProperties', 'TokenUrlParametersMap'}:
            continue
        elif key in {'DefaultArguments', 'NonOverridableArguments'}:
            result[key] = {k: v for k, v in child.items() if k in SAFE_GLUE_FLAGS and isinstance(v, str)
                and v in {'true', 'false', 'TRUE', 'FALSE', 'sse-kms', 'sse-s3', 'python', 'scala',
                          'job-bookmark-enable', 'job-bookmark-disable', 'job-bookmark-pause'}} if isinstance(child, dict) else []
        elif key == 'ConnectionProperties':
            result[key] = {k: v for k, v in child.items() if k in SAFE_GLUE_PROPERTIES and isinstance(v, str)
                and (v.lower() in {'true', 'false', 'mysql', 'postgresql', 'oracle', 'sqlserver', 'redshift'}
                     or re.fullmatch(r'[0-9.]{1,32}', v))} if isinstance(child, dict) else {}
        elif key == 'OptionSettings':
            from .aws_beanstalk_runtime_metadata import configuration_options_complete
            result['BeanstalkRuntimeOptionsComplete'] = configuration_options_complete(child)
            result[key] = [{k: deepcopy(row[k]) for k in ('Namespace', 'OptionName', 'Value') if k in row}
                for row in child if isinstance(row, dict) and (row.get('Namespace'), row.get('OptionName')) in SAFE_BEANSTALK
                and row.get('Value') in {'true', 'false', 'enhanced', 'basic', 'classic', 'application', 'network'}] if isinstance(child, list) else []
        else:
            result[key] = _redact(child)
    return result


def _containers(rows):
    if not isinstance(rows, list) or not rows or len(rows) > MAX_PAIRS:
        raise ValueError('missing containers')
    groups, names = [], set()
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get('name'), str) or row['name'] in names:
            raise ValueError('invalid container identity')
        names.add(row['name'])
        groups.append(_environment(row.get('environment', [])))
    return groups


def _row(kind, row, region, operation, arguments):
    try:
        if not isinstance(row, dict) or row.get('collection_status', 'collected') != 'collected':
            raise ValueError('incomplete row')
        arn, account = None, None
        if kind == 'rest_api_stage':
            parent, stage = arguments['restApiId'], row['stageName']
            if not isinstance(parent, str) or not re.fullmatch(r'[a-z0-9]{1,32}', parent) or not isinstance(stage, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', stage):
                raise ValueError('invalid stage identity')
            identity, groups, coverage = parent + '/' + stage, [_mapping(row.get('variables', {}))], 'rest_stage_variables'
        elif kind == 'ecs_task_definition':
            identity = arn = row['taskDefinitionArn']
            groups, coverage = _containers(row['containerDefinitions']), 'container_plaintext_environment'
        elif kind == 'amplify_app':
            identity, arn = row['appId'], row['appArn']
            if not isinstance(arn, str) or not arn.endswith('/' + identity):
                raise ValueError('invalid app identity')
            groups, coverage = [_mapping(row.get('environmentVariables', {}))], 'app_environment_only'
        elif kind == 'batch_job_definition':
            identity = arn = row['jobDefinitionArn']
            if 'containerProperties' in row and not any(k in row for k in ('ecsProperties', 'eksProperties', 'nodeProperties')):
                container = row['containerProperties']
                if not isinstance(container, dict):
                    raise ValueError('invalid batch container')
                groups = [_environment(container.get('environment', []))]
            else:
                raise ValueError('unsupported batch variant')
            coverage = 'classic_container_environment_only'
        elif kind == 'elastic_beanstalk_environment':
            if row.get('ApplicationName') != arguments.get('ApplicationName') or row.get('EnvironmentName') != arguments.get('EnvironmentName'):
                raise ValueError('foreign environment configuration')
            identity = row['ApplicationName'] + '/' + row['EnvironmentName']
            options = row['OptionSettings']
            if not isinstance(options, list):
                raise ValueError('missing option settings')
            pairs = [(option['Namespace'] + '_' + option['OptionName'], option['Value']) for option in options if isinstance(option, dict)]
            groups = [pairs]
            if len(pairs) != len(options):
                raise ValueError('malformed options')
            coverage = 'configuration_option_values'
        elif kind == 'glue_job':
            identity = row['Name']
            groups = [_mapping(row.get(field, {})) for field in ('DefaultArguments', 'NonOverridableArguments')]
            coverage = 'default_and_nonoverridable_arguments'
        elif kind == 'glue_connection':
            identity, account = row['Name'], arguments.get('CatalogId')
            # HidePassword=True is the existing collector contract. Hidden
            # password fields are outside this explicitly visible-property scope.
            properties = row['ConnectionProperties']
            if not isinstance(properties, dict):
                raise ValueError('missing visible properties')
            hidden = {'PASSWORD', 'ENCRYPTED_PASSWORD'} if arguments.get('HidePassword') is True else set()
            groups = [[(key, value) for key, value in properties.items() if key not in hidden]]
            coverage = 'visible_nonpassword_properties' if hidden else 'returned_connection_properties'
        else:
            raise ValueError('unknown surface')
        indicator = _scan(kind, identity, groups, region, operation, coverage, arn=arn, account=account)
    except (ValueError, TypeError, KeyError, AttributeError):
        indicator = _bad()
    if indicator['collection_status'] != 'collected':
        _salvage_named(kind, row, region)
    projected = _redact(row) if isinstance(row, dict) else {}
    projected['AdditionalSecretIndicators'] = indicator
    return projected


def project_response(response, *, service, operation, arguments, region):
    """Exact dispatcher contract; preserve SDK pagination for all reviewed APIs."""
    from .aws import ReadFailure
    shapes = {('apigateway', 'get_stages'): ('rest_api_stage', 'item', False),
        ('ecs', 'describe_task_definition'): ('ecs_task_definition', 'taskDefinition', True),
        ('amplify', 'list_apps'): ('amplify_app', 'apps', False), ('amplify', 'get_app'): ('amplify_app', 'app', True),
        ('batch', 'describe_job_definitions'): ('batch_job_definition', 'jobDefinitions', False),
        ('elasticbeanstalk', 'describe_configuration_settings'): ('elastic_beanstalk_environment', 'ConfigurationSettings', False),
        ('glue', 'get_jobs'): ('glue_job', 'Jobs', False), ('glue', 'get_job'): ('glue_job', 'Job', True),
        ('glue', 'get_connections'): ('glue_connection', 'ConnectionList', False), ('glue', 'get_connection'): ('glue_connection', 'Connection', True)}
    if (service, operation) not in shapes or not isinstance(response, dict):
        raise ReadFailure('malformed', 'additional_secret_projection_operation_invalid')
    kind, field, single = shapes[(service, operation)]
    rows = response.get(field)
    if (single and not isinstance(rows, dict)) or (not single and not isinstance(rows, list)):
        raise ReadFailure('malformed', 'additional_secret_projection_shape_invalid')
    result = _redact({key: value for key, value in response.items() if key != field})
    source = service + ':' + ''.join(part.capitalize() for part in operation.split('_'))
    result[field] = _row(kind, rows, region, source, arguments) if single else [_row(kind, row, region, source, arguments) for row in rows]
    # The Beanstalk enricher preserves a response-level marker. More than one
    # setting for an exact environment request cannot establish unique identity.
    if kind == 'elastic_beanstalk_environment':
        result['AdditionalSecretIndicators'] = result[field][0]['AdditionalSecretIndicators'] if len(result[field]) == 1 else _bad()
    return result
