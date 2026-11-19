"""Conservative evaluation of selected, native-bound offline AWS image scans.

Registration and catalog/source admission are owned by the finite release epoch.
This module never registers itself on import or reads credentials or cloud APIs.
"""
from copy import deepcopy
import hashlib
import json
from peaso.aws_image_selection_20261021 import KIND, OPTION, ENABLE, CHECK, MAX_TARGETS, selections, partition

DECLARATION = {
    'id': CHECK, 'provider': 'aws', 'category': 'hardening', 'kind': KIND,
    'title': 'Selected ECR or workload container image has no HIGH or CRITICAL vulnerabilities',
    'severity': 'high', 'control': 'security_configuration',
    'remediation': 'Update vulnerable packages and select or redeploy a reviewed immutable image digest.',
    'target': 'resource', 'dependencies': (KIND,), 'allow_incomplete_failure': True,
}
DESCRIPTION = {
    'description': 'Inspects an explicitly selected ECR digest or its exact Lambda, ECS task definition, or Batch job definition association with the pinned offline vulnerability scanner. This does not prove execution, reachability or exploitability.',
    'evaluated': ['native caller account and exact ECR digest', 'complete config and layer bytes with matching content digests',
                  'revalidated selected workload revision, container, and immutable digest', 'fresh offline HIGH/CRITICAL vulnerability findings'],
    'pass_when': 'Every native binding and byte check succeeds and the complete fresh scan contains no HIGH or CRITICAL vulnerabilities.',
    'fail_when': 'The bound immutable image scan reports at least one typed HIGH or CRITICAL vulnerability, including when remaining coverage is incomplete.',
    'not_applicable_when': None,
}
READ_ACTIONS = ('sts:GetCallerIdentity', 'lambda:GetFunction', 'ecs:DescribeTaskDefinition',
                'batch:DescribeJobDefinitions', 'ecr:BatchGetImage', 'ecr:GetDownloadUrlForLayer')


def _evaluate_index(row, target, item):
    """Keep selected parent workload proof separate from verified child scans."""
    from peaso import oci_index_20261021 as index_types
    from peaso import container_image_archive_20261020 as archive
    from peaso.image_findings import build_report
    from peaso.collectors import aws_image_vulnerability_native_20261021 as native
    account, region = target['scope'].split('/')
    suffix = 'amazonaws.com.cn' if partition(region) == 'aws-cn' else 'amazonaws.com'
    parent = target['image_digest']; repo = target['repository_name']
    parent_ref = f'{account}.dkr.ecr.{region}.{suffix}/{repo}@{parent}'
    graph = row['index_graph']; children = graph['children']
    if (type(graph) is not dict or set(graph) != {'parent_digest','media_type','children','complete'}
            or graph['parent_digest'] != parent or graph['media_type'] not in index_types.INDEX_TYPES
            or type(graph['complete']) is not bool or type(children) is not list
            or len(children) > index_types.MAX_CHILDREN or type(row.get('parent_binding_stable')) is not bool):
        raise ValueError('index_graph_unavailable')
    asset = target.get('task_definition_arn') or target.get('job_definition_arn')
    expected_asset = asset or f'arn:{partition(region)}:ecr:{region}:{account}:repository/{repo}@{parent}'
    expected_kind = ('ecs_task_definition' if 'task_definition_arn' in target else
                     'batch_job_definition' if 'job_definition_arn' in target else 'ecr_image')
    expected_association = ('ecs_declared_image' if 'task_definition_arn' in target else
                            'batch_declared_image' if 'job_definition_arn' in target else 'selected_immutable_image')
    if ('function_arn' in target or row.get('association') != expected_association
            or row.get('runtime_image_proven') is not False
            or asset and row.get('workload_binding', {}).get('image_uri') != parent_ref):
        raise ValueError('foreign_parent_binding')
    if asset:
        binding = row['workload_binding']
        profile = 'ecs_container' if 'task_definition_arn' in target else target['batch_profile']
        container = (target['container_name'] if 'task_definition_arn' in target else
            'container' if profile == 'container' else
            'taskProperties[0]/' + target['container_name'] if profile == 'ecs_container' else
            'podProperties/' + ('initContainers' if profile == 'eks_init_container' else 'containers') + '/' + target['container_name']
                if profile in ('eks_container','eks_init_container') else 'nodeRange/' + target['node_range'])
        expected_id = (asset + '#container=' + target['container_name'] if 'task_definition_arn' in target else
            asset + '#profile=' + profile + '#container=' + target.get('container_name', target.get('node_range','container')))
        if (type(binding) is not dict or set(binding) != {'asset_arn','revision','container','profile','image_uri'}
                or binding['asset_arn'] != asset or binding['revision'] != int(asset.rsplit(':',1)[1])
                or binding['container'] != container or binding['profile'] != profile
                or binding['image_uri'] != parent_ref or item['id'] != expected_id):
            raise ValueError('foreign_workload_binding')
    else:
        selected_id = 'ecr-image:' + hashlib.sha256(json.dumps(target,
            sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        if item['id'] != selected_id or row.get('workload_binding') is not None:
            raise ValueError('foreign_image_selection')
    ledger = row['source_ledger']
    if (type(ledger) is not list or not ledger or len(ledger) > native.MAX_CALLS * 2
            or any(type(r) is not dict or r.get('status') != 'collected' for r in ledger)
            or any(r.get('account') != account for r in ledger if r['operation'] == 'sts:get_caller_identity')):
        raise ValueError('native_ledger_unavailable')
    manifests = [r for r in ledger if r['operation'] == 'ecr:batch_get_image']
    parent_receipts = [r for r in manifests if r.get('digest') == parent]
    if (len(parent_receipts) < 2 or any(type(r.get('bytes')) is not int or not 0 < r['bytes'] <= archive.MAX_MANIFEST
                                      for r in manifests if 'digest' in r)
            or graph['complete'] and any('digest' not in r for r in manifests)):
        raise ValueError('parent_manifest_receipt_missing')
    if asset:
        operation = 'ecs:describe_task_definition' if 'task_definition_arn' in target else 'batch:describe_job_definitions'
        expected_hash = hashlib.sha256(repr(sorted(row['workload_binding'].items())).encode()).hexdigest()
        binding_receipts = [r for r in ledger if r['operation'] == operation]
        if (len(binding_receipts) < 2 or any(r.get('binding_sha256') != expected_hash or
                type(r.get('request_sha256')) is not str or len(r['request_sha256']) != 64
                for r in binding_receipts)):
            raise ValueError('workload_receipt_missing')
    observations = row['child_observations']
    if (type(observations) is not list or len(observations) > index_types.MAX_CHILDREN
            or len(observations) != len(children)):
        raise ValueError('child_count_mismatch')
    seen = set()
    for child, observed in zip(children, observations):
        if (type(child) is not dict or set(child) != {'digest','size','mediaType','platform','config_digest'}
                or child['mediaType'] not in index_types.LEAF_TYPES
                or type(child['digest']) is not str or archive.DIGEST.fullmatch(child['digest']) is None
                or child['digest'] in seen or type(child['size']) is not int
                or not 0 < child['size'] <= archive.MAX_MANIFEST
                or type(child['config_digest']) is not str
                or archive.DIGEST.fullmatch(child['config_digest']) is None):
            raise ValueError('unsupported_child_descriptor')
        index_types._platform(child['platform'])
        seen.add(child['digest'])
        image = observed['scan']['image']
        child_ref = f'{account}.dkr.ecr.{region}.{suffix}/{repo}@{child["digest"]}'
        if (observed['provider'] != 'aws' or observed['scope'] != target['scope']
                or observed['asset_id'] != expected_asset or observed['asset_kind'] != expected_kind
                or image != {'provider':'aws','scope':target['scope'],'immutable_reference':child_ref,
                             'manifest_digest':child['digest'],'config_digest':child['config_digest']}
                or not any(r.get('digest') == child['digest'] and r.get('bytes') == child['size'] for r in manifests)):
            raise ValueError('foreign_child_scan')
    report = build_report(observations, selected=True)
    if report['invalid_observations'] or report['invalid_vulnerabilities']:
        raise ValueError('invalid_child_scan')
    complete = bool(row['parent_binding_stable'] and graph['complete'] and children
                    and report['complete'])
    status = 'FAIL' if report['rows'] and row['parent_binding_stable'] else 'PASS' if complete else 'UNKNOWN'
    if row.get('status') != status or row.get('complete') is not complete:
        raise ValueError('contradictory_index_result')
    noun = 'task definition' if 'task_definition_arn' in target else 'job definition' if asset else 'selected ECR image'
    first = f'The selected {noun} references ECR index {parent}.'
    second = (f'Child {report["rows"][0]["image_digest"]} has a HIGH or CRITICAL package finding.' if status == 'FAIL' else
              'Every supported child has a complete fresh scan with no HIGH or CRITICAL finding.' if status == 'PASS' else
              'A child manifest or package scan receipt is incomplete.')
    return status, {'observed': first + '\n' + second, 'IndexDigest': parent,
                    'ChildImages': [deepcopy(o['scan']['image']) for o in observations],
                    'Vulnerabilities': report['rows'], 'Coverage': 'COMPLETE' if complete else 'UNKNOWN',
                    'Association': expected_association, 'RuntimeImageProven': False}

def evaluate(item, index):
    from peaso.image_findings import build_report
    try:
        context = index['context']
        metadata, scope = context['metadata'], context['scope']
        if context['provider'] != 'aws' or not isinstance(metadata.get(OPTION), list):
            raise ValueError()
        collection, = [c for c in index['collections'][KIND] if c['scope'] == scope]
        if collection['status'] not in ('collected', 'partial') or item not in collection['items']:
            raise ValueError()
        if len(metadata[OPTION]) > MAX_TARGETS or len(json.dumps(item, allow_nan=False)) > 2_000_000:
            raise ValueError()
        row = deepcopy(item['ImageVulnerabilityReview'])
        target = row['selection']
        selected = deepcopy(metadata[OPTION])
        targets = selections({ENABLE: True, OPTION: selected}, list(dict.fromkeys(t['scope'] for t in selected)))
        if target not in targets or target['scope'] != scope or row.get('runtime_image_proven') is not False:
            raise ValueError()
        if row.get('index_graph') is not None:
            return _evaluate_index(row, target, item)
        observed = row['observation']
        if observed['provider'] != 'aws' or observed['scope'] != target['scope']:
            raise ValueError()
        account, region = scope.split('/')
        suffix = 'amazonaws.com.cn' if partition(region) == 'aws-cn' else 'amazonaws.com'
        if not observed['scan']['image']['immutable_reference'].startswith(
                f'{account}.dkr.ecr.{region}.{suffix}/'):
            raise ValueError()
        if 'function_arn' in target:
            if observed['asset_id'] != target['function_arn'] or observed['asset_kind'] != 'lambda_function':
                raise ValueError()
            binding = row['function_binding']
            if (set(binding) != {'function_arn', 'revision', 'image_uri'}
                    or binding['function_arn'] != target['function_arn'] or not binding['revision']
                    or binding['image_uri'] != observed['scan']['image']['immutable_reference']
                    or row['association'] != 'lambda_resolved_image'):
                raise ValueError()
        elif 'task_definition_arn' in target or 'job_definition_arn' in target:
            reference = f'{account}.dkr.ecr.{region}.{suffix}/' + target['repository_name'] + '@' + target['image_digest']
            asset = target.get('task_definition_arn') or target['job_definition_arn']
            profile = 'ecs_declared_image' if 'task_definition_arn' in target else 'batch_declared_image'
            kind = 'ecs_task_definition' if 'task_definition_arn' in target else 'batch_job_definition'
            binding = row['workload_binding']
            container = (target['container_name'] if 'task_definition_arn' in target else
                'container' if target['batch_profile'] == 'container' else
                'taskProperties[0]/' + target['container_name'] if target['batch_profile'] == 'ecs_container' else
                'podProperties/' + ('initContainers' if target['batch_profile'] == 'eks_init_container' else 'containers')
                    + '/' + target['container_name'] if target['batch_profile'] in ('eks_container', 'eks_init_container') else
                'nodeRange/' + target['node_range'])
            expected_id = (asset + '#container=' + target['container_name'] if 'task_definition_arn' in target
                else asset + '#profile=' + target['batch_profile'] +
                    '#container=' + target.get('container_name', target.get('node_range', 'container')))
            if (item['id'] != expected_id or observed['asset_id'] != asset or observed['asset_kind'] != kind
                    or observed['scan']['image']['manifest_digest'] != target['image_digest']
                    or observed['scan']['image']['immutable_reference'] != reference
                    or row['association'] != profile or type(binding) is not dict
                    or set(binding) != {'asset_arn', 'revision', 'container', 'profile', 'image_uri'}
                    or binding['asset_arn'] != asset or binding['revision'] != int(asset.rsplit(':', 1)[1])
                    or binding['container'] != container or binding['image_uri'] != reference
                    or binding['profile'] != ('ecs_container' if 'task_definition_arn' in target else target['batch_profile'])):
                raise ValueError()
        else:
            reference = f'{account}.dkr.ecr.{region}.{suffix}/' + target['repository_name'] + '@' + target['image_digest']
            if (observed['scan']['image']['manifest_digest'] != target['image_digest']
                    or observed['scan']['image']['immutable_reference'] != reference
                    or observed['asset_kind'] != 'ecr_image' or row['association'] != 'selected_immutable_image'
                    or observed['asset_id'] != f'arn:{partition(region)}:ecr:{region}:{account}:repository/'
                       + target['repository_name'] + '@' + target['image_digest']):
                raise ValueError()
        ledger = row['source_ledger']
        if (type(ledger) is not list or not ledger or any(r.get('status') != 'collected' for r in ledger)
                or not {'sts:get_caller_identity', 'ecr:batch_get_image', 'ecr:get_download_url_for_layer',
                        'ecr:signed_layer_download'} <= {r.get('operation') for r in ledger}):
            raise ValueError()
        if any(r.get('account') != scope.split('/')[0] for r in ledger if r['operation'] == 'sts:get_caller_identity'):
            raise ValueError()
        manifests = [r for r in ledger if r['operation'] == 'ecr:batch_get_image']
        if len(manifests) < 3 or any(r.get('digest') != observed['scan']['image']['manifest_digest'] for r in manifests):
            raise ValueError()
        if 'function_arn' in target:
            bindings = [r for r in ledger if r['operation'] == 'lambda:get_function']
            expected = hashlib.sha256(repr(sorted(row['function_binding'].items())).encode()).hexdigest()
            if len(bindings) < 3 or any(r.get('binding_sha256') != expected for r in bindings):
                raise ValueError()
        elif 'task_definition_arn' in target or 'job_definition_arn' in target:
            op = 'ecs:describe_task_definition' if 'task_definition_arn' in target else 'batch:describe_job_definitions'
            bindings = [r for r in ledger if r.get('operation') == op]
            expected = hashlib.sha256(repr(sorted(row['workload_binding'].items())).encode()).hexdigest()
            if len(bindings) < 3 or any(r.get('binding_sha256') != expected or
                    type(r.get('request_sha256')) is not str or
                    len(r['request_sha256']) != 64 for r in bindings):
                raise ValueError()
        report = build_report([observed], selected=True)
        if report['invalid_observations'] or report['invalid_vulnerabilities']:
            raise ValueError()
        status = 'FAIL' if report['rows'] else 'PASS' if report['complete'] and row.get('scope_complete') is not False else 'UNKNOWN'
        evidence = {'Image': observed['scan']['image'], 'Vulnerabilities': report['rows'],
            'Coverage': report['coverage'], 'Association': row['association'],
            'RuntimeImageProven': False}
        if 'task_definition_arn' in target or 'job_definition_arn' in target:
            noun = 'task definition' if 'task_definition_arn' in target else 'job definition'
            first = 'The selected ' + noun + ' declares this immutable ECR image for its container.'
            evidence['observed'] = (first + '\n' +
                ('The recorded image has a HIGH or CRITICAL package finding.\n'
                 'That flaw may affect people or their data if this image is used.' if status == 'FAIL' else
                 'The complete fresh image scan has no HIGH or CRITICAL package findings.\n'
                 'That lowers the observed risk from known package flaws in this image.' if status == 'PASS' else
                 'The image bytes or scan coverage are incomplete.\n'
                 'A package flaw could remain in the image and may affect people or their data if it is used.'))
        return status, evidence
    except (KeyError, TypeError, ValueError, AttributeError):
        return 'UNKNOWN', {'Reason': 'selected_native_image_vulnerability_evidence_unavailable',
            'observed': 'The selected workload image reference or scan record is missing or inconsistent.\n'
                        'The exact ECR digest or its package findings remain unclear.\n'
                        'A package flaw could remain in the image and may affect people or their data if it is used.'}
