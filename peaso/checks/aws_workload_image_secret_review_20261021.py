"""Pure consumer for an exact selected workload's immutable ECR image."""
import re
from peaso.secret_scanning import merge_leaks
from peaso import oci_index_20261021 as oci_index

from peaso.aws_image_selection_20261021 import DIGEST, REPO, partition
from peaso.collectors.aws_package_content_indicators import SCHEMA, CATEGORIES, _path
from peaso.checks.aws_package_content_review_20261019 import _incomplete
from peaso.collectors.aws_workload_image_secret_native_20261021 import KIND, OPTION, ENABLE, selected

CHECK = 'aws.review.workload.selected_image_secret_indicators'
DECLARATION = {'provider': 'aws', 'category': 'hardening', 'kind': KIND,
    'title': 'Selected workload image has no observed secret indicators',
    'severity': 'high', 'control': 'security_configuration',
    'remediation': 'Remove literal credentials from the image and rotate any exposed value.',
    'target': 'resource', 'dependencies': (KIND,), 'allow_incomplete_failure': True}
DESCRIPTION = {'description': 'Inspects exactly selected Lambda, ECS task definition, or Batch job definition image digests with bounded offline Kingfisher and TruffleHog scans of supported image configuration and regular layer files. The declaration is read before and after content inspection; this does not prove a workload ran.',
    'evaluated': ['exact selected native workload revision and container', 'same-account immutable ECR digest', 'bounded native ECR image configuration and layer bytes', 'two offline secret detector results'],
    'pass_when': 'The native declaration and complete bounded image scan agree and no supported secret indicator is found.',
    'fail_when': 'A bound immutable image has a recorded secret indicator, including when remaining coverage is incomplete.',
    'not_applicable_when': None}


def evaluate(row):
    reason = None
    try:
        target = row['selection']
        account, region = target['scope'].split('/')
        if not re.fullmatch(r'[0-9]{12}', account): raise ValueError()
        part = partition(region)
        image = row['image']
        repo, digest = image['repository_name'], image['image_digest']
        if not REPO.fullmatch(repo) or not DIGEST.fullmatch(digest): raise ValueError()
        if 'function_arn' not in target and (repo != target['repository_name'] or digest != target['image_digest']):
            raise ValueError()
        before, after = row['binding_before'], row['binding_after']
        if type(before) is not dict: raise ValueError()
        expected_uri = f'{account}.dkr.ecr.{region}.' + ('amazonaws.com.cn' if part == 'aws-cn' else 'amazonaws.com') + f'/{repo}@{digest}'
        if 'function_arn' in target:
            if (before.get('function_arn') != target['function_arn'] or not before.get('revision')
                    or before.get('image_uri') != expected_uri): raise ValueError()
        elif (before.get('asset_arn') != target.get('task_definition_arn', target.get('job_definition_arn'))
                or before.get('image_uri') != expected_uri): raise ValueError()
        else:
            if (before.get('revision') != int(before['asset_arn'].rsplit(':', 1)[1])
                    or before.get('profile') != target.get('batch_profile', 'ecs_container')): raise ValueError()
            profile = before['profile']
            location = (target['container_name'] if 'task_definition_arn' in target else
                'container' if profile == 'container' else
                'taskProperties[0]/' + target['container_name'] if profile == 'ecs_container' else
                'podProperties/' + ('initContainers' if profile == 'eks_init_container' else 'containers') + '/' + target['container_name']
                if profile in ('eks_container', 'eks_init_container') else 'nodeRange/' + target['node_range'])
            if before.get('container') != location: raise ValueError()
        source = row['source']
        if (type(source) is not dict or source.get('ImageDigest') != digest or
                source.get('collection_status') not in ('collected', 'partial')):
            raise ValueError()
        marker = source.get('PackageSecretIndicators')
        ident = f'arn:{part}:ecr:{region}:{account}:repository/{repo}@{digest}'
        if (type(marker) is not dict or marker.get('Schema') != SCHEMA or marker.get('ResourceId') != ident
                or marker.get('AccountId') != account or marker.get('Region') != region
                or marker.get('SourceOperation') != 'ecr:batch_get_image'
                or type(marker.get('HighConfidenceSecretPresent')) is not bool
                or type(marker.get('NativeResponseComplete')) is not bool
                or type(marker.get('References')) is not list
                or len(marker['References']) > 5000
                or marker.get('collection_status') != ('collected' if marker['NativeResponseComplete'] else 'partial')
                or not (marker.get('Reason') is None if marker['NativeResponseComplete']
                        else _incomplete(marker.get('Reason'), 'image_content_incomplete'))
                or marker['HighConfidenceSecretPresent'] != bool(marker['References'])): raise ValueError()
        graph = marker.get('IndexGraph')
        children = set()
        if graph is not None:
            if ('function_arn' in target or type(graph) is not dict or
                    set(graph) != {'parent_digest', 'media_type', 'children', 'complete', 'parent_binding_stable'} or
                    graph.get('parent_digest') != digest or
                    graph.get('media_type') not in oci_index.INDEX_TYPES or
                    type(graph.get('complete')) is not bool or
                    type(graph.get('parent_binding_stable')) is not bool or
                    type(graph.get('children')) is not list or
                    not 0 < len(graph['children']) <= oci_index.MAX_CHILDREN or
                    (marker['NativeResponseComplete'] and not graph['complete']) or
                    (marker['NativeResponseComplete'] and not graph['parent_binding_stable'])):
                raise ValueError()
            for child in graph['children']:
                if (type(child) is not dict or set(child) !=
                        {'digest', 'size', 'mediaType', 'platform', 'config_digest'} or
                        not DIGEST.fullmatch(child['digest']) or child['digest'] == digest or
                        child['digest'] in children or type(child['size']) is not int or
                        not 0 < child['size'] <= 256 * 1024 or
                        child['mediaType'] not in oci_index.LEAF_TYPES or
                        not DIGEST.fullmatch(child['config_digest']) or
                        type(child['platform']) is not dict or
                        child['platform'].get('os') != 'linux' or
                        child['platform'].get('architecture') not in ('amd64', 'arm64') or
                        set(child['platform']) - {'os', 'architecture', 'variant'}):
                    raise ValueError()
                children.add(child['digest'])
        for ref in marker['References']:
            expected = {'File', 'Categories', 'LayerDigest'}
            if graph is not None:
                expected.add('ChildManifestDigest')
            if (type(ref) is not dict or set(ref) - {'Leaks'} != expected
                    or type(ref['File']) is not str or _path(ref['File']) != ref['File']
                    or not DIGEST.fullmatch(ref['LayerDigest']) or type(ref['Categories']) is not list
                    or not ref['Categories'] or any(c not in CATEGORIES for c in ref['Categories'])
                    or len(set(ref['Categories'])) != len(ref['Categories'])): raise ValueError()
            if graph is not None and ref['ChildManifestDigest'] not in children:
                raise ValueError()
        leaks=merge_leaks([dict(leak, locations=[dict(loc, layer=ref['LayerDigest']) for loc in leak['locations']])
            for ref in marker['References'] for leak in ref.get('Leaks', [])])
        complete = (row.get('complete') is True and before == after and
            marker['NativeResponseComplete'] and
            (graph is None or graph['complete'] and graph['parent_binding_stable']))
        if marker['HighConfidenceSecretPresent']:
            if graph is not None and (before != after or not graph['parent_binding_stable']):
                raise ValueError('parent_workload_binding_changed')
            return 'FAIL', {'observed': 'The selected image contains a likely secret in a verified child image. Its value is hidden.' if graph else 'A likely secret was found in the immutable image referenced by this workload. Its value is hidden.',
                'source_complete': complete, 'complete': complete, 'references': marker['References'], 'secret_leaks': leaks}
        if not complete and marker.get('Reason'):
            reason = marker['Reason']
        if complete:
            return 'PASS', {'observed': 'The selected image index and every supported child completed without a detected secret.' if graph else 'Both detectors completed without finding a supported secret in the selected immutable ECR image’s supported content.',
                'source_complete': True, 'complete': True, 'references': [], 'secret_leaks': []}
    except (ValueError, KeyError, TypeError, AttributeError, IndexError):
        pass
    return 'UNKNOWN', {'observed': 'The selected workload’s immutable image or its content could not be fully verified.',
        'source_complete': False, 'references': [], **({'reason': reason} if reason else {})}


def evaluate_item(item, index):
    try:
        context = index['context']
        scope, metadata = context['scope'], context['metadata']
        if context['provider'] != 'aws': raise ValueError()
        targets = metadata[OPTION]
        scopes = list(dict.fromkeys(t['scope'] for t in targets))
        targets = selected({ENABLE: True, OPTION: targets}, scopes, [CHECK])
        collection, = [c for c in index['collections'][KIND] if c['scope'] == scope]
        if collection['status'] not in ('collected', 'partial') or item not in collection['items']:
            raise ValueError()
        row = item['WorkloadImageSecretReview']
        if row['selection'] not in targets or row['selection']['scope'] != scope:
            raise ValueError()
        return evaluate(row)
    except (ValueError, KeyError, TypeError, AttributeError, IndexError):
        return evaluate({})


def install(registry):
    from .fixtures import CASES
    from pathlib import Path
    import json
    cases=json.loads(Path(__file__).with_name('aws_workload_image_secret_review_20261021_cases.json').read_text())
    if set(cases)!={CHECK} or CHECK in CASES:
        raise RuntimeError('Selected workload image native fixture collision or absence')
    CASES.update(cases)
    registry.register(CHECK, **DECLARATION)(evaluate_item)
