"""Six unregistered bounded payload-secret predicates with explicit coverage."""
import re
from .facts import Unavailable, get, list_of_objects
from .aws_configuration_secret_review_20261019 import _member
from peaso.collectors.aws_configuration_payload_secret_indicators import SCHEMA
from peaso.collectors.aws_configuration_secret_indicators import CATEGORIES

SURFACES = {
 'ec2_launch_template': ('LaunchTemplateId', 'launch_template', 'Launch template'),
 'launch_configuration': ('LaunchConfigurationARN', 'launch_configuration', 'Launch configuration'),
 'ssm_document_metadata': ('Name', 'ssm_document', 'Owned SSM document'),
 'sfn_state_machine': ('stateMachineArn', 'state_machine', 'State machine'),
 'sagemaker_notebook_instance': ('NotebookInstanceArn', 'notebook_lifecycle', 'Notebook lifecycle'),
 'datapipeline_pipeline': ('id', 'data_pipeline', 'Data Pipeline'),
}


def _arn(value, service, account, region):
    partition = 'aws-cn' if region.startswith('cn-') else 'aws-us-gov' if region.startswith('us-gov-') else 'aws'
    if not isinstance(value, str) or not value.startswith(f'arn:{partition}:{service}:{region}:{account}:'):
        raise Unavailable('foreign ARN')


def _marker(value, kind, identity, account, region, operation, coverage, version=None, selected=None):
    expected = {'Schema', 'collection_status', 'NativeResponseComplete', 'Kind', 'ResourceId', 'AccountId', 'Region',
                'SourceOperation', 'SourceVersion', 'Coverage', 'HighConfidenceSecretPresent', 'MatchedCategories'}
    if (not isinstance(value, dict) or set(value) != expected or get(value, 'Schema', str) != SCHEMA
            or get(value, 'collection_status', str) != 'collected' or get(value, 'NativeResponseComplete', bool) is not True
            or get(value, 'Kind', str) != kind or get(value, 'ResourceId', str) != identity
            or value['AccountId'] not in (None, account) or get(value, 'Region', str) != region
            or get(value, 'SourceOperation', str) != operation or get(value, 'Coverage', str) != coverage
            or type(value['SourceVersion']) is not type(version) or value['SourceVersion'] != version):
        raise Unavailable('payload source authority incomplete')
    if identity.startswith('arn:') and value['AccountId'] != account:
        raise Unavailable('ARN account binding missing')
    present = get(value, 'HighConfidenceSecretPresent', bool)
    categories = get(value, 'MatchedCategories', list)
    allowed = set(selected) if selected is not None else CATEGORIES
    if (any(not isinstance(c, str) or c not in allowed for c in categories) or len(set(categories)) != len(categories)
            or present != bool(categories)):
        raise Unavailable('payload categories incoherent')
    return set(categories)


class _Reason(Unavailable):
    """An UNKNOWN whose concrete cause the collector already named."""


def evaluate(kind, item, index):
    try:
        field, source_kind, label = SURFACES[kind]
        context = get(index, 'context', dict)
        account, scope = get(context, 'Account', str), get(context, 'scope', str)
        if (get(context, 'provider', str) != 'aws' or not re.fullmatch(r'[0-9]{12}', account)
                or not scope.startswith(account + '/') or not re.fullmatch(r'[a-z]{2}(?:-[a-z]+)+-[0-9]+', scope.split('/', 1)[1])):
            raise Unavailable('scope authority unavailable')
        region = scope.split('/', 1)[1]
        _member(item, index, kind, field, scope)
        identity = get(item, field, str)
        categories = set()
        if kind == 'ec2_launch_template':
            versions = list_of_objects(get(item, 'Versions', list))
            if not versions: raise Unavailable('no complete version inventory')
            seen = set()
            for version in versions:
                number = get(version, 'VersionNumber', int)
                if number < 1 or number in seen or get(version, 'LaunchTemplateId', str) != identity:
                    raise Unavailable('duplicate or foreign version')
                seen.add(number)
                categories |= _marker(get(version, 'PayloadSecretIndicators', dict), source_kind, identity, account, region,
                    'ec2:DescribeLaunchTemplateVersions', 'all_returned_template_versions', version=number)
            if get(item, 'LatestVersionNumber', int) != max(seen) or get(item, 'DefaultVersionNumber', int) not in seen:
                raise Unavailable('latest/default version coverage incomplete')
        elif kind == 'launch_configuration':
            _arn(identity, 'autoscaling', account, region)
            if not identity.endswith(':launchConfigurationName/' + get(item, 'LaunchConfigurationName', str)):
                raise Unavailable('configuration identity mismatch')
            categories = _marker(get(item, 'PayloadSecretIndicators', dict), source_kind, identity, account, region,
                'autoscaling:DescribeLaunchConfigurations', 'additional_private_key_password_categories', selected={'private_key', 'password_assignment'})
        elif kind == 'sfn_state_machine':
            if get(item, 'status', str) != 'ACTIVE': raise Unavailable('state machine is not active')
            payload = item.get('PayloadSecretIndicators')
            if isinstance(payload, dict) and payload.get('collection_status') != 'collected':
                reason = payload.get('Reason')
                raise _Reason(reason if isinstance(reason, str) and re.fullmatch(r'[a-z_]{1,64}(?:: [a-z_]{1,64})?', reason)
                              else 'state_machine_definition_' + str(payload.get('collection_status') or 'unavailable')[:32])
            _arn(identity, 'states', account, region)
            categories = _marker(get(item, 'PayloadSecretIndicators', dict), source_kind, identity, account, region,
                'stepfunctions:DescribeStateMachine', 'returned_state_machine_definition')
        else:
            source = get(item, 'PayloadSource', dict)
            if get(source, 'collection_status', str) != 'collected': raise Unavailable('source unreadable')
            if kind == 'ssm_document_metadata':
                version = get(item, 'DocumentVersion', str)
                if (get(source, 'Status', str) != 'Active' or get(source, 'DocumentFormat', str) not in {'JSON', 'YAML', 'TEXT'}
                        or get(item, 'Owner', str) != account or get(source, 'Name', str) != identity
                        or get(source, 'DocumentVersion', str) != version or not re.fullmatch(r'[1-9][0-9]*', version)):
                    raise Unavailable('owned document version mismatch')
                categories = _marker(get(source, 'PayloadSecretIndicators', dict), source_kind, identity, account, region,
                    'ssm:GetDocument', 'owned_listed_document_version_content', version=version)
            elif kind == 'sagemaker_notebook_instance':
                _arn(identity, 'sagemaker', account, region)
                lifecycle = get(source, 'LifecycleConfigName')
                if lifecycle is None:
                    categories = _marker(get(source, 'PayloadSecretIndicators', dict), source_kind, identity, account, region,
                        'sagemaker:DescribeNotebookInstance', 'complete_no_attached_lifecycle')
                else:
                    arn = get(source, 'NotebookInstanceLifecycleConfigArn', str)
                    _arn(arn, 'sagemaker', account, region)
                    if (not isinstance(lifecycle, str) or not lifecycle or get(source, 'NotebookInstanceLifecycleConfigName', str) != lifecycle
                            or not arn.endswith(':notebook-instance-lifecycle-config/' + lifecycle)):
                        raise Unavailable('lifecycle attachment mismatch')
                    categories = _marker(get(source, 'PayloadSecretIndicators', dict), source_kind, arn, account, region,
                        'sagemaker:DescribeNotebookInstanceLifecycleConfig', 'attached_oncreate_onstart_scripts')
            else:
                if not re.fullmatch(r'df-[A-Za-z0-9]+', identity): raise Unavailable('pipeline identity invalid')
                categories = _marker(get(source, 'PayloadSecretIndicators', dict), source_kind, identity, account, region,
                    'datapipeline:GetPipelineDefinition', 'latest_returned_literal_definition_values', version='latest')
        observed = label + ' ' + identity.rsplit('/', 1)[-1][:28] + (
            ': a selected secret indicator was observed.' if categories else ': no selected secret indicator was observed.')
        return ('FAIL' if categories else 'PASS'), {'observed': observed, 'resource_id': identity,
            'matched_categories': sorted(categories), 'partial_detector': True}
    except _Reason as reason:
        return 'UNKNOWN', {'observed': 'Complete matching configuration-payload evidence is unavailable.', 'reason': str(reason)}
    except Unavailable as exc:
        return 'UNKNOWN', {'observed': 'Complete matching configuration-payload evidence is unavailable.',
                           'reason': 'payload_evidence_unavailable: ' + str(exc)[:200]}
    except (ValueError, TypeError, KeyError, AttributeError):
        return 'UNKNOWN', {'observed': 'Complete matching configuration-payload evidence is unavailable.',
                           'reason': 'payload_evidence_malformed'}


def launch_template(item, index=None): return evaluate('ec2_launch_template', item, index or {})
def launch_configuration(item, index=None): return evaluate('launch_configuration', item, index or {})
def document(item, index=None): return evaluate('ssm_document_metadata', item, index or {})
def state_machine(item, index=None): return evaluate('sfn_state_machine', item, index or {})
def notebook(item, index=None): return evaluate('sagemaker_notebook_instance', item, index or {})
def pipeline(item, index=None): return evaluate('datapipeline_pipeline', item, index or {})


SOURCE_LINEAGE = {'ec2_launch_template_no_secrets': {'url': 'https://github.com/prowler-cloud/prowler/blob/1783527c1147f584f30b60f2d7ccc8a53b4a63b7/prowler/providers/aws/services/ec2/ec2_launch_template_no_secrets/ec2_launch_template_no_secrets.py',
                                    'sha256': 'a06b2efda81160cce341733d1008cbb0f8f49d5e924ea402cb47f7502de4e1a1'},
 'autoscaling_find_secrets_ec2_launch_configuration': {'url': 'https://github.com/prowler-cloud/prowler/blob/1783527c1147f584f30b60f2d7ccc8a53b4a63b7/prowler/providers/aws/services/autoscaling/autoscaling_find_secrets_ec2_launch_configuration/autoscaling_find_secrets_ec2_launch_configuration.py',
                                                       'sha256': '2a2b862a0570b1961a11c109af88a7d8416b1736ce8dc3ae80e284b89c6f9b1d'},
 'ssm_document_secrets': {'url': 'https://github.com/prowler-cloud/prowler/blob/1783527c1147f584f30b60f2d7ccc8a53b4a63b7/prowler/providers/aws/services/ssm/ssm_document_secrets/ssm_document_secrets.py',
                          'sha256': 'ce1e95652ee2ecab135b4dc54334d978bd7cd27afed726affe5c5eac31cbf239'},
 'stepfunctions_statemachine_no_secrets_in_definition': {'url': 'https://github.com/prowler-cloud/prowler/blob/1783527c1147f584f30b60f2d7ccc8a53b4a63b7/prowler/providers/aws/services/stepfunctions/stepfunctions_statemachine_no_secrets_in_definition/stepfunctions_statemachine_no_secrets_in_definition.py',
                                                         'sha256': 'e6d1c8ad8333a73f80baead6294baf572ac028d6e26f6babe47ddddf032c62d0'},
 'sagemaker_notebook_instance_no_secrets': {'url': 'https://github.com/prowler-cloud/prowler/blob/1783527c1147f584f30b60f2d7ccc8a53b4a63b7/prowler/providers/aws/services/sagemaker/sagemaker_notebook_instance_no_secrets/sagemaker_notebook_instance_no_secrets.py',
                                            'sha256': 'd7da9cdde5cf7755de4922985f619bbea94b90c27bf059ee685471ee43aa10a0'},
 'datapipeline_pipeline_no_secrets_in_definition': {'url': 'https://github.com/prowler-cloud/prowler/blob/1783527c1147f584f30b60f2d7ccc8a53b4a63b7/prowler/providers/aws/services/datapipeline/datapipeline_pipeline_no_secrets_in_definition/datapipeline_pipeline_no_secrets_in_definition.py',
                                                    'sha256': '35efb8528927588657df82d8bb103ab59b7741c9e40497a329c8cf770e75640b'}}

DETAILS = [
 ('ec2_launch_template', 'launch_template', 'ec2_launch_template_no_secrets',
  'Launch-template version user data', 'Versions[].PayloadSecretIndicators and complete latest/default version inventory',
  'Every returned unfiltered available version is inspected with strict base64/UTF8 and bounded gzip decoding, at most 16 KiB decoded per payload; missing, filtered, partial or undecodable source is UNKNOWN. Deleted versions and historic revisions are not certified.',
  'Replace literal launch-template credentials with managed references and roll instances onto a reviewed safe version.'),
 ('launch_configuration', 'launch_configuration', 'autoscaling_find_secrets_ec2_launch_configuration',
  'Additional launch-configuration private-key and password indicators', 'PayloadSecretIndicators bound to LaunchConfigurationARN and name',
  'Only private_key and password_assignment categories complement the existing AWS key-pair detector; the key-pair category is deliberately excluded to avoid duplicating that predicate. Base64/UTF8/gzip decoding is bounded at 16 KiB.',
  'Replace launch configurations containing private keys or literal passwords and rotate verified exposed credentials.'),
 ('ssm_document_metadata', 'document', 'ssm_document_secrets',
  'Owned SSM document version content', 'Owner, DocumentVersion and PayloadSource safe marker/identity/status',
  'Inspects the exact numeric version returned by the existing Owner=Self listing using GetDocument, capped at 64 KiB. Only active valid JSON/YAML/TEXT content is observed; historical versions, attachments and Requires references are not downloaded.',
  'Remove literal credentials from the owned SSM document version and use managed secret references.'),
 ('sfn_state_machine', 'state_machine', 'stepfunctions_statemachine_no_secrets_in_definition',
  'Step Functions current returned definitions', 'stateMachineArn, ACTIVE status and PayloadSecretIndicators',
  'Only the returned active state-machine JSON definition is inspected, capped at 1 MiB and requiring a valid root States/StartAt shape. Execution inputs/outputs, external resources and historical published versions are not fetched.',
  'Remove credentials from state-machine definitions and use supported service integrations or managed references.'),
 ('sagemaker_notebook_instance', 'notebook', 'sagemaker_notebook_instance_no_secrets',
  'Attached notebook lifecycle scripts', 'NotebookInstanceArn, complete attachment read and PayloadSource lifecycle identity',
  'Reuses a complete identity-bound DescribeNotebookInstance to read its current attachment, then decodes both OnCreate and OnStart strictly up to 16 KiB each. A confirmed absent attachment yields a negative observation; denied/unreadable attachment reads are UNKNOWN.',
  'Remove literal credentials from attached notebook lifecycle scripts and rotate any confirmed exposed values.'),
 ('datapipeline_pipeline', 'pipeline', 'datapipeline_pipeline_no_secrets_in_definition',
  'Data Pipeline latest literal definition values', 'listed pipeline id and PayloadSource safe latest-definition marker',
  'Existing-customer Data Pipeline remains usable in maintenance mode. Inspects latest returned pipeline object stringValue fields, parameter attributes and parameter values with 256-value/1 MiB limits; refValue resources and historic definitions are not resolved.',
  'Remove literal credentials from the pipeline definition and parameter values; use managed references supported by the workload.'),
]
DECLARATIONS, ADMISSION_DATA = [], {'schema_version': 1, 'checks': []}
for _kind, _function, _source, _label, _field, _limitation, _remediation in DETAILS:
    _id = 'aws.review.' + _kind + '.payload_secret_indicators'
    _description = {'description': 'Observes selected high-confidence indicators in ' + _label + '. ' + _limitation +
        ' Raw payloads are discarded before shared caching; negative results do not prove absence of all secrets.',
        'evaluated': [_field, 'complete matching native collection with AWS account and region authority'],
        'pass_when': 'Complete bound ' + _label + ' has no selected high-confidence indicator.',
        'fail_when': 'Complete bound ' + _label + ' has a selected high-confidence indicator.',
        'not_applicable_when': 'No automatic exclusion; unavailable, malformed, foreign, partial, truncated or unsupported source is UNKNOWN.'}
    DECLARATIONS.append({'id': _id, 'provider': 'aws', 'kind': _kind, 'evaluator': _function, 'category': 'hardening',
        'severity': 'high', 'control': 'configuration_secrets', 'target': 'resource', 'dependencies': [_kind],
        'title': _label + ' has no observed selected secret indicators', 'remediation': _remediation})
    ADMISSION_DATA['checks'].append({'spec': {'id': _id, 'provider': 'aws', 'resource_kind': _kind,
        'data_source': ', '.join(_description['evaluated']), 'predicate': _description['fail_when'] + ' ' + _description['pass_when'],
        'severity': 'high', 'category': 'hardening', 'title': DECLARATIONS[-1]['title'], 'description': _description['description'],
        'remediation_hint': _remediation}, 'description': _description, 'sources': [SOURCE_LINEAGE[_source]], 'requirements': [],
        'function': 'peaso.checks.aws_configuration_payload_secret_review_20261019:' + _function,
        'review_notes': 'Corrected partial replacement for ' + _source + ': selected bounded categories replace the external scanner; no ignore-pattern, credential-validation or exhaustive scanner equivalence is claimed. ' + _limitation})


def _runtime_fixture(kind, detected):
    account, region = '123456789012', 'us-east-1'
    arn = lambda service, resource: f'arn:aws:{service}:{region}:{account}:{resource}'
    field, source_kind, _ = SURFACES[kind]
    identity = {'ec2_launch_template': 'lt-abc123', 'launch_configuration': arn('autoscaling', 'launchConfiguration:11111111:launchConfigurationName/example'),
        'ssm_document_metadata': 'OwnedDocument', 'sfn_state_machine': arn('states', 'stateMachine:example'),
        'sagemaker_notebook_instance': arn('sagemaker', 'notebook-instance/example'), 'datapipeline_pipeline': 'df-abc123'}[kind]
    item = {field: identity}
    operation, coverage, version, source_identity = {
        'ec2_launch_template': ('ec2:DescribeLaunchTemplateVersions', 'all_returned_template_versions', 1, identity),
        'launch_configuration': ('autoscaling:DescribeLaunchConfigurations', 'additional_private_key_password_categories', None, identity),
        'ssm_document_metadata': ('ssm:GetDocument', 'owned_listed_document_version_content', '3', identity),
        'sfn_state_machine': ('stepfunctions:DescribeStateMachine', 'returned_state_machine_definition', None, identity),
        'sagemaker_notebook_instance': ('sagemaker:DescribeNotebookInstanceLifecycleConfig', 'attached_oncreate_onstart_scripts', None, arn('sagemaker', 'notebook-instance-lifecycle-config/attached')),
        'datapipeline_pipeline': ('datapipeline:GetPipelineDefinition', 'latest_returned_literal_definition_values', 'latest', identity),
    }[kind]
    marker = {'Schema': SCHEMA, 'collection_status': 'collected', 'NativeResponseComplete': True, 'Kind': source_kind,
        'ResourceId': source_identity, 'AccountId': account if source_identity.startswith('arn:') else None,
        'Region': region, 'SourceOperation': operation, 'SourceVersion': version, 'Coverage': coverage,
        'HighConfidenceSecretPresent': detected, 'MatchedCategories': ['password_assignment'] if detected else []}
    if kind == 'ec2_launch_template':
        item.update(LatestVersionNumber=1, DefaultVersionNumber=1, Versions=[{'LaunchTemplateId': identity, 'VersionNumber': 1, 'PayloadSecretIndicators': marker}])
    elif kind == 'launch_configuration': item.update(LaunchConfigurationName='example', PayloadSecretIndicators=marker)
    elif kind == 'sfn_state_machine': item.update(status='ACTIVE', PayloadSecretIndicators=marker)
    else:
        item['PayloadSource'] = {'collection_status': 'collected', 'PayloadSecretIndicators': marker}
        if kind == 'ssm_document_metadata':
            item.update(Owner=account, DocumentVersion='3')
            item['PayloadSource'].update(Name=identity, DocumentVersion='3', Status='Active', DocumentFormat='JSON')
        if kind == 'sagemaker_notebook_instance':
            item['PayloadSource'].update(LifecycleConfigName='attached', NotebookInstanceLifecycleConfigName='attached', NotebookInstanceLifecycleConfigArn=source_identity)
    scope = account + '/' + region
    index = {'context': {'provider': 'aws', 'Account': account, 'scope': scope},
        'collections': {kind: [{'type': kind, 'scope': scope, 'status': 'collected', 'items': [item]}]},
        kind: [{'type': kind, 'scope': scope, 'data': item}]}
    return item, index


RUNTIME_CASES = {}
for _declaration in DECLARATIONS:
    _good, _good_index = _runtime_fixture(_declaration['kind'], False)
    _bad, _bad_index = _runtime_fixture(_declaration['kind'], True)
    RUNTIME_CASES[_declaration['id']] = {'pass': _good, 'index': _good_index, 'pass_index': _good_index,
        'fail': _bad, 'fail_index': _bad_index, 'missing': {}, 'malformed': None}
