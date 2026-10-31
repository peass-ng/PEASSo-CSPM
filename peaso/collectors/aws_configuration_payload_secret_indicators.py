"""Bounded transient configuration-payload indicators; never cache payload text.

Inspect API-returned text only, without execution, attachments or external reads.
Base64/gzip decoding is bounded before inspection. New enrichers reuse existing
request caches and retain only safe indicators and native identity/version data.
"""
from copy import deepcopy
import base64
import json
import re
import zlib
from .aws_user_data_secret_indicators import project as inspect_text

SCHEMA = 'configuration-payload-secret-indicators-v1'
OPERATIONS = {('ec2', 'describe_launch_template_versions'), ('ssm', 'get_document'),
              ('stepfunctions', 'describe_state_machine'), ('sagemaker', 'describe_notebook_instance_lifecycle_config'),
              ('datapipeline', 'get_pipeline_definition')}
READ_ACTIONS = {('ssm', 'get_document'), ('sagemaker', 'describe_notebook_instance_lifecycle_config'), ('datapipeline', 'get_pipeline_definition')}
SPECS = {'datapipeline_pipeline': ('datapipeline', 'list_pipelines', 'pipelineIdList')}
NATIVE_IDS = {'datapipeline_pipeline': 'id'}
LIMIT = 16384


def bad(reason=None):
    marker = {'Schema': SCHEMA, 'collection_status': 'malformed', 'NativeResponseComplete': False}
    if reason is not None:
        marker['Reason'] = reason
    return marker


def decode(encoded, limit=LIMIT, gzip_ok=False):
    if not isinstance(encoded, str) or len(encoded) > (limit * 4 // 3 + 8) * 2:
        raise ValueError('invalid encoded payload')
    raw = base64.b64decode(encoded.replace('\r', '').replace('\n', ''), validate=True)
    if len(raw) > limit:
        raise ValueError('payload size bound exceeded')
    if raw.startswith(b'\x1f\x8b'):
        if not gzip_ok:
            raise ValueError('unsupported compressed payload')
        inflater = zlib.decompressobj(zlib.MAX_WBITS | 16)
        raw = inflater.decompress(raw, limit + 1)
        if len(raw) > limit or not inflater.eof or inflater.unused_data or inflater.unconsumed_tail:
            raise ValueError('compressed payload incomplete or oversized')
    text = raw.decode('utf-8')
    if any(ord(char) < 32 and char not in '\t\r\n' for char in text):
        raise ValueError('unsupported binary payload')
    return text


def _json(text):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result: raise ValueError('ambiguous duplicate JSON key')
            result[key] = value
        return result
    def invalid_constant(value): raise ValueError('non-JSON numeric constant')
    return json.loads(text, object_pairs_hook=unique, parse_constant=invalid_constant)


def marker(kind, identity, texts, region, operation, coverage, account=None, version=None, selected=None, paths=None):
    try:
        if not isinstance(identity, str) or not identity or len(identity) > 2048 or not isinstance(region, str):
            raise ValueError('resource identity absent')
        if identity.startswith('arn:'):
            match = re.fullmatch(r'arn:(aws|aws-cn|aws-us-gov):[a-z0-9-]+:([a-z0-9-]+):([0-9]{12}):.+', identity)
            if match is None or match[2] != region: raise ValueError('foreign ARN')
            account = match[3]
        if account is not None and not re.fullmatch(r'[0-9]{12}', account): raise ValueError('invalid account')
        total, categories = 0, set()
        if not isinstance(texts, list) or len(texts) > 64: raise ValueError('invalid fragments')
        for part, text in enumerate(texts):
            if not isinstance(text, str): raise ValueError('nontext payload')
            total += len(text.encode('utf-8'))
            if total > 1048576: raise ValueError('payload bound exceeded')
            from peaso.secret_evidence import source_context
            check_kind = {'launch_template': 'ec2_launch_template', 'ssm_document': 'ssm_document_metadata',
                'state_machine': 'sfn_state_machine', 'notebook_lifecycle': 'sagemaker_notebook_instance',
                'data_pipeline': 'datapipeline_pipeline'}.get(kind, kind)
            checks = {'aws.review.' + check_kind + '.payload_secret_indicators'}
            if kind == 'launch_configuration':
                checks.add('aws_autoscaling_userdata_plaintext_aws_key')
            with source_context(resource_id=identity, scope=(account + '/' + region) if account else region,
                                check_ids=checks,
                                path=paths[part] if paths else {'launch_configuration': 'UserData', 'launch_template': 'LaunchTemplateData.UserData', 'ssm_document': 'Content', 'state_machine': 'definition'}.get(kind, coverage + '[' + str(part) + ']'),
                                source=operation + (':' + str(version) if version is not None else '')):
                categories.update(inspect_text(text, 'unused')['MatchedCategories'])
        if selected is not None: categories &= set(selected)
        return {'Schema': SCHEMA, 'collection_status': 'collected', 'NativeResponseComplete': True,
            'Kind': kind, 'ResourceId': identity, 'AccountId': account, 'Region': region,
            'SourceOperation': operation, 'SourceVersion': version, 'Coverage': coverage,
            'HighConfidenceSecretPresent': bool(categories), 'MatchedCategories': sorted(categories)}
    except (ValueError, TypeError, UnicodeError):
        return bad()


def launch_configuration_indicator(row):
    try:
        arn, name = row['LaunchConfigurationARN'], row['LaunchConfigurationName']
        match = re.fullmatch(r'arn:(?:aws|aws-cn|aws-us-gov):autoscaling:([a-z0-9-]+):[0-9]{12}:launchConfiguration:[^:]+:launchConfigurationName/(.+)', arn)
        if match is None or match[2] != name: raise ValueError('configuration identity mismatch')
        text = decode(row['UserData'], gzip_ok=True) if 'UserData' in row else ''
        return marker('launch_configuration', arn, [text], match[1], 'autoscaling:DescribeLaunchConfigurations',
                      'additional_private_key_password_categories', selected={'private_key', 'password_assignment'})
    except (ValueError, TypeError, KeyError, UnicodeError, zlib.error):
        return bad()


def project_response(response, *, service, operation, arguments, region):
    from .aws import ReadFailure
    if not isinstance(response, dict) or (service, operation) not in OPERATIONS:
        raise ReadFailure('malformed', 'payload_projection_shape_invalid')
    if service == 'ec2':
        rows = response.get('LaunchTemplateVersions')
        if not isinstance(rows, list): raise ReadFailure('malformed', 'template_versions_invalid')
        projected = []
        for row in rows:
            if not isinstance(row, dict): raise ReadFailure('malformed', 'template_version_invalid')
            safe = {key: deepcopy(value) for key, value in row.items() if key not in {'LaunchTemplateData', 'PayloadSecretIndicators', 'VersionDescription'}}
            data = row.get('LaunchTemplateData')
            safe['LaunchTemplateData'] = {key: deepcopy(value) for key, value in data.items() if key != 'UserData'} if isinstance(data, dict) else None
            try:
                ident, version = row['LaunchTemplateId'], row['VersionNumber']
                if 'Versions' in arguments or ident != arguments.get('LaunchTemplateId') or not isinstance(ident, str) or not re.fullmatch(r'lt-[a-z0-9]+', ident) or type(version) is not int or version < 1 or not isinstance(data, dict):
                    raise ValueError('template identity incomplete')
                text = decode(data['UserData'], gzip_ok=True) if 'UserData' in data else ''
                safe['PayloadSecretIndicators'] = marker('launch_template', ident, [text], region, 'ec2:DescribeLaunchTemplateVersions', 'all_returned_template_versions', version=version)
            except (ValueError, TypeError, KeyError, UnicodeError, zlib.error):
                safe['PayloadSecretIndicators'] = bad()
            projected.append(safe)
        return {**{key: deepcopy(value) for key, value in response.items() if key not in {'LaunchTemplateVersions', 'ResponseMetadata'}}, 'LaunchTemplateVersions': projected}
    if service == 'datapipeline':
        try:
            identity = arguments['pipelineId']
            if not isinstance(identity, str) or not re.fullmatch(r'df-[A-Za-z0-9]+', identity) or arguments.get('version') != 'latest':
                raise ValueError('pipeline identity missing')
            objects = response['pipelineObjects']
            params = response.get('parameterObjects', [])
            values = response.get('parameterValues', [])
            if any(not isinstance(rows, list) or len(rows) > 256 for rows in (objects, params, values)):
                raise ValueError('pipeline definition shape invalid')
            pairs, total = {}, 0
            def add(key, value):
                nonlocal total
                if not isinstance(key, str) or not key or not isinstance(value, str): raise ValueError('pipeline value malformed')
                total += len(key.encode()) + len(value.encode())
                if len(value.encode()) > 65536 or total > 1048576 or len(pairs) >= 256: raise ValueError('pipeline payload limit')
                pairs[str(len(pairs)) + '_' + key] = value
            for row in objects:
                if not isinstance(row, dict) or not isinstance(row.get('id'), str) or not isinstance(row.get('name'), str) or not isinstance(row.get('fields'), list):
                    raise ValueError('pipeline object malformed')
                for field in row['fields']:
                    if not isinstance(field, dict) or not isinstance(field.get('key'), str) or ('stringValue' in field) == ('refValue' in field):
                        raise ValueError('pipeline field malformed')
                    if 'stringValue' in field: add(field['key'], field['stringValue'])
                    elif not isinstance(field['refValue'], str): raise ValueError('pipeline reference malformed')
            for row in params:
                if not isinstance(row, dict) or not isinstance(row.get('id'), str) or not isinstance(row.get('attributes'), list):
                    raise ValueError('pipeline parameter malformed')
                for field in row['attributes']:
                    if not isinstance(field, dict): raise ValueError('pipeline attribute malformed')
                    add(field.get('key'), field.get('stringValue'))
            for row in values:
                if not isinstance(row, dict): raise ValueError('pipeline parameter value malformed')
                add(row.get('id'), row.get('stringValue'))
            from peaso.secret_evidence import source_context
            with source_context(native=response, location_kind='configuration'):
                indicator = marker('data_pipeline', identity, [json.dumps(pairs)], region, 'datapipeline:GetPipelineDefinition',
                                   'latest_returned_literal_definition_values', version='latest', paths=['DataPipelineDefinition'])
        except (ValueError, TypeError, KeyError, UnicodeError, RecursionError):
            indicator = bad()
        return {'PayloadSecretIndicators': indicator}
    if service == 'ssm':
        safe = {key: deepcopy(response[key]) for key in ('Name', 'DocumentVersion', 'DocumentFormat', 'DocumentType', 'Status') if key in response}
        try:
            name, version, text = response['Name'], response['DocumentVersion'], response['Content']
            if name != arguments.get('Name') or version != arguments.get('DocumentVersion') or not re.fullmatch(r'[1-9][0-9]*', version) or response.get('Status') != 'Active' or not isinstance(text, str) or not text or len(text.encode()) > 65536:
                raise ValueError('document incomplete')
            form = response['DocumentFormat']
            if form == 'JSON':
                if not isinstance(_json(text), dict): raise ValueError('invalid document object')
            elif form == 'YAML':
                import yaml
                try:
                    node = yaml.compose(text)
                except yaml.YAMLError:
                    raise ValueError('invalid YAML document') from None
                if not isinstance(node, yaml.MappingNode): raise ValueError('invalid YAML document')
            elif form != 'TEXT': raise ValueError('unsupported document format')
            safe['PayloadSecretIndicators'] = marker('ssm_document', name, [text], region, 'ssm:GetDocument', 'owned_listed_document_version_content', version=version)
        except (ValueError, TypeError, KeyError, UnicodeError, RecursionError):
            safe['PayloadSecretIndicators'] = bad()
        return safe
    if service == 'stepfunctions':
        fields = ('stateMachineArn', 'name', 'status', 'type', 'roleArn', 'loggingConfiguration', 'tracingConfiguration', 'encryptionConfiguration', 'creationDate')
        safe = {key: deepcopy(response[key]) for key in fields if key in response}
        if arguments.get('includedData') == 'METADATA_ONLY':
            # This read deliberately omits the definition (AWS returns "{}").
            safe['PayloadSecretIndicators'] = {'Schema': SCHEMA, 'collection_status': 'not_collected',
                'NativeResponseComplete': False, 'Reason': 'state_machine_definition_not_requested'}
            return safe
        try:
            arn, text = response['stateMachineArn'], response['definition']
            if arn != arguments.get('stateMachineArn') or not isinstance(text, str) or not text or len(text.encode()) > 1048576 or response.get('status') != 'ACTIVE':
                raise ValueError('definition incomplete')
            parsed = _json(text)
            if not isinstance(parsed, dict) or not isinstance(parsed.get('States'), dict) or parsed.get('StartAt') not in parsed['States']:
                raise ValueError('state machine JSON incomplete')
            safe['PayloadSecretIndicators'] = marker('state_machine', arn, [text], region, 'stepfunctions:DescribeStateMachine', 'returned_state_machine_definition')
        except (ValueError, TypeError, KeyError, UnicodeError, RecursionError):
            safe['PayloadSecretIndicators'] = bad('state_machine_definition_malformed')
        return safe
    safe = {key: deepcopy(response[key]) for key in ('NotebookInstanceLifecycleConfigName', 'NotebookInstanceLifecycleConfigArn', 'CreationTime', 'LastModifiedTime') if key in response}
    try:
        name, arn = response['NotebookInstanceLifecycleConfigName'], response['NotebookInstanceLifecycleConfigArn']
        if name != arguments.get('NotebookInstanceLifecycleConfigName') or not isinstance(arn, str) or not arn.endswith(':notebook-instance-lifecycle-config/' + name):
            raise ValueError('lifecycle identity mismatch')
        texts, paths = [], []
        for field in ('OnCreate', 'OnStart'):
            rows = response.get(field, [])
            if not isinstance(rows, list) or len(rows) > 1: raise ValueError('lifecycle script shape invalid')
            for row in rows:
                if not isinstance(row, dict) or set(row) != {'Content'}: raise ValueError('script incomplete')
                texts.append(decode(row['Content']))
                paths.append(field + '[0].Content')
        safe['PayloadSecretIndicators'] = marker('notebook_lifecycle', arn, texts, region, 'sagemaker:DescribeNotebookInstanceLifecycleConfig', 'attached_oncreate_onstart_scripts', paths=paths)
    except (ValueError, TypeError, KeyError, UnicodeError, zlib.error):
        safe['PayloadSecretIndicators'] = bad()
    return safe


def documents(requests, session, region, items):
    result = []
    for original in items:
        item = deepcopy(original)
        if (isinstance(item.get('Owner'), str) and re.fullmatch(r'[0-9]{12}', item['Owner'])
                and isinstance(item.get('DocumentVersion'), str) and re.fullmatch(r'[1-9][0-9]*', item['DocumentVersion'])):
            item['PayloadSource'] = requests.detail(session, 'ssm', region, 'get_document', Name=item['Name'], DocumentVersion=item['DocumentVersion'])
        else:
            item['PayloadSource'] = {'collection_status': 'not_collected'}
        result.append(item)
    return result


def notebooks(requests, session, region, items):
    result = []
    for original in items:
        item = deepcopy(original)
        source = requests.detail(session, 'sagemaker', region, 'describe_notebook_instance', NotebookInstanceName=item.get('NotebookInstanceName'))
        if (source.get('collection_status') != 'collected' or source.get('NotebookInstanceArn') != item.get('NotebookInstanceArn')
                or source.get('NotebookInstanceName') != item.get('NotebookInstanceName')):
            item['PayloadSource'] = {'collection_status': 'not_collected'}
        elif 'NotebookInstanceLifecycleConfigName' not in source:
            item['PayloadSource'] = {'collection_status': 'collected', 'LifecycleConfigName': None,
                'PayloadSecretIndicators': marker('notebook_lifecycle', item['NotebookInstanceArn'], [], region,
                    'sagemaker:DescribeNotebookInstance', 'complete_no_attached_lifecycle')}
        elif not isinstance(source['NotebookInstanceLifecycleConfigName'], str) or not source['NotebookInstanceLifecycleConfigName']:
            item['PayloadSource'] = {'collection_status': 'malformed'}
        else:
            name = source['NotebookInstanceLifecycleConfigName']
            item['PayloadSource'] = {**requests.detail(session, 'sagemaker', region, 'describe_notebook_instance_lifecycle_config',
                NotebookInstanceLifecycleConfigName=name), 'LifecycleConfigName': name}
        result.append(item)
    return result


def pipelines(requests, session, region, items):
    result = []
    for original in items:
        item = deepcopy(original)
        if isinstance(item.get('id'), str) and re.fullmatch(r'df-[A-Za-z0-9]+', item['id']):
            item['PayloadSource'] = requests.detail(session, 'datapipeline', region, 'get_pipeline_definition', pipelineId=item['id'], version='latest')
        else:
            item['PayloadSource'] = {'collection_status': 'malformed'}
        result.append(item)
    return result


ENRICHERS = {'ssm_document_metadata': documents, 'sagemaker_notebook_instance': notebooks, 'datapipeline_pipeline': pipelines}
