"""Credential-free validation for explicit AWS immutable-image CVE inspection."""
from copy import deepcopy
import re

ENABLE = 'image_vulnerability_scans'
OPTION = 'selected_aws_image_vulnerabilities'
CHECK = 'aws.review.ecr.selected_image_vulnerabilities'
KIND = 'ecr_selected_image_vulnerabilities'
MAX_TARGETS = 32
MAX_SELECTED_SCOPES = 8
SCOPE = re.compile(r'([0-9]{12})/([a-z]{2}(?:-[a-z0-9]+)+-[0-9]+)\Z')
REPO = re.compile(r'[a-z0-9]+(?:(?:\.|_|__|-+)[a-z0-9]+)*(?:/[a-z0-9]+(?:(?:\.|_|__|-+)[a-z0-9]+)*)*\Z')
DIGEST = re.compile(r'sha256:[0-9a-f]{64}\Z')
TASK_NAME = re.compile(r'[A-Za-z0-9_-]{1,255}\Z')
NODE_RANGE = re.compile(r'[0-9]+(?::[0-9]*)?\Z')
BATCH_PROFILES = ('container', 'ecs_container', 'eks_container', 'eks_init_container', 'node_container')
MAX_WORKLOAD_TARGETS = 4


def partition(region):
    if '-iso' in region:
        raise ValueError('unsupported_image_partition')
    return 'aws-cn' if region.startswith('cn-') else 'aws-us-gov' if region.startswith('us-gov-') else 'aws'


def selections(options, scopes):
    if type(options) is not dict or type(scopes) is not list:
        raise ValueError('invalid_aws_image_selection')
    if ENABLE in options and type(options[ENABLE]) is not bool:
        raise ValueError('image_vulnerability_scans_must_be_boolean')
    if OPTION not in options and options.get(ENABLE) is not True:
        return []
    targets = options.get(OPTION)
    # The connector can inventory many Regions. Only the content targets, not
    # the metadata allowlist, are limited to eight selected image scopes. A scan can select thirty-two images.
    if (not scopes
            or any(type(s) is not str or not SCOPE.fullmatch(s) for s in scopes)
            or len(set(scopes)) != len(scopes)
            or type(targets) is not list or not 1 <= len(targets) <= MAX_TARGETS
            or any(options.get(k) for k in ('all_accounts', 'all_regions', 'discover_organization', 'organization_role_name'))):
        raise ValueError('exact_aws_image_scopes_and_targets_required')
    seen = set()
    workload_count = 0
    for row in targets:
        if type(row) is not dict or row.get('scope') not in scopes:
            raise ValueError('invalid_aws_image_selection')
        account, region = row['scope'].split('/')
        part = partition(region)
        if set(row) == {'scope', 'repository_name', 'image_digest'}:
            repo, digest = row['repository_name'], row['image_digest']
            if (type(repo) is not str or not 2 <= len(repo) <= 256 or not REPO.fullmatch(repo)
                    or type(digest) is not str or not DIGEST.fullmatch(digest)):
                raise ValueError('exact_ecr_repository_and_digest_required')
            key = row['scope'], repo, digest
        elif set(row) == {'scope', 'function_arn'}:
            arn = row['function_arn']
            if type(arn) is not str or not re.fullmatch(
                    re.escape(f'arn:{part}:lambda:{region}:{account}:function:') + r'[A-Za-z0-9_-]{1,64}', arn):
                raise ValueError('exact_unqualified_lambda_arn_required')
            key = row['scope'], arn
        elif set(row) == {'scope', 'task_definition_arn', 'container_name', 'repository_name', 'image_digest'}:
            arn, container = row['task_definition_arn'], row['container_name']
            if (type(arn) is not str or not re.fullmatch(
                    re.escape(f'arn:{part}:ecs:{region}:{account}:task-definition/') +
                    r'[A-Za-z0-9_-]{1,255}:[1-9][0-9]{0,9}', arn)
                    or type(container) is not str or not TASK_NAME.fullmatch(container)
                    or type(row['repository_name']) is not str or not 2 <= len(row['repository_name']) <= 256
                    or not REPO.fullmatch(row['repository_name'])
                    or type(row['image_digest']) is not str or not DIGEST.fullmatch(row['image_digest'])):
                raise ValueError('exact_ecs_image_revision_required')
            workload_count += 1
            key = row['scope'], arn, container, row['repository_name'], row['image_digest']
        elif set(row) in ({'scope', 'job_definition_arn', 'batch_profile', 'repository_name', 'image_digest'},
                          {'scope', 'job_definition_arn', 'batch_profile', 'container_name', 'repository_name', 'image_digest'},
                          {'scope', 'job_definition_arn', 'batch_profile', 'node_range', 'repository_name', 'image_digest'}):
            arn, profile = row['job_definition_arn'], row['batch_profile']
            expected = ({'scope', 'job_definition_arn', 'batch_profile', 'repository_name', 'image_digest'}
                        if profile == 'container' else
                        {'scope', 'job_definition_arn', 'batch_profile', 'node_range', 'repository_name', 'image_digest'}
                        if profile == 'node_container' else
                        {'scope', 'job_definition_arn', 'batch_profile', 'container_name', 'repository_name', 'image_digest'})
            if (set(row) != expected or type(arn) is not str or not re.fullmatch(
                    re.escape(f'arn:{part}:batch:{region}:{account}:job-definition/') +
                    r'[A-Za-z0-9_-]{1,128}:[1-9][0-9]{0,9}', arn)
                    or profile not in BATCH_PROFILES
                    or type(row['repository_name']) is not str or not 2 <= len(row['repository_name']) <= 256
                    or not REPO.fullmatch(row['repository_name'])
                    or type(row['image_digest']) is not str or not DIGEST.fullmatch(row['image_digest'])
                    or 'container_name' in row and (type(row['container_name']) is not str
                        or not TASK_NAME.fullmatch(row['container_name']))
                    or 'node_range' in row and (type(row['node_range']) is not str
                        or not NODE_RANGE.fullmatch(row['node_range']))):
                raise ValueError('exact_batch_image_revision_required')
            workload_count += 1
            key = row['scope'], arn, profile, row.get('container_name'), row.get('node_range'), row['repository_name'], row['image_digest']
        else:
            raise ValueError('closed_aws_image_target_required')
        if key in seen:
            raise ValueError('duplicate_aws_image_target')
        seen.add(key)
    if len({row['scope'] for row in targets}) > MAX_SELECTED_SCOPES:
        raise ValueError('selected_aws_image_scope_bound')
    if workload_count > MAX_WORKLOAD_TARGETS:
        raise ValueError('selected_aws_workload_image_bound')
    return deepcopy(targets)


def validate_request(connector, request):
    options = connector.get('options', {})
    if OPTION not in options and (connector.get('provider') != 'aws' or ENABLE not in options) and CHECK not in (request.get('checks') or []):
        return
    if connector.get('provider') != 'aws':
        raise ValueError('selected_aws_images_require_aws')
    selections(options, connector.get('scopes', []))
