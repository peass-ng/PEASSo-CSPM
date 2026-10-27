"""Deterministic, read-only target planning for named workload literal checks.

Only completed native inventory rows can authorize an exact content reader. This
module sees identifiers, never environment values or secret-store references.
"""
from dataclasses import dataclass


DENIAL_CODES = frozenset({'AccessDenied', 'AccessDeniedException',
    'UnauthorizedOperation', 'ForbiddenException'})


def record_denial(requests, failure, identity, service, operation):
    """Keep only typed IAM denial and the fixed native operation for auto reads."""
    from .aws import ReadFailure
    if (getattr(requests, 'automatic_workload_environment_active', False) is True
            and isinstance(failure, ReadFailure)
            and getattr(failure, 'status', None) == 'denied'
            and getattr(failure, 'code', None) in DENIAL_CODES):
        getattr(requests, 'automatic_workload_environment_issues', {})[identity] = {
            'status': 'denied', 'code': failure.code,
            'operation': service + ':' + ''.join(part.title() for part in operation.split('_'))}


def native_denial_issues(kind, marker_name, items, metadata):
    """Summarize only bound HTTP 401/403 receipts or K8s native GET denial."""
    issues = {}
    ledger = metadata.get(kind + '_receipts', ())
    for item in items:
        ident, marker = item.get('id'), item.get(marker_name)
        if not isinstance(ident, str) or not isinstance(marker, dict) or marker.get('complete') is not False:
            continue
        if kind == 'k8s_selected_literals':
            if marker.get('reason') == 'native_get_denied' and isinstance(marker.get('kind'), str):
                issues[ident] = {'status': 'denied', 'code': 'native_get_denied',
                    'operation': 'kubernetes:GET ' + marker['kind']}
            continue
        refs = marker.get('source_requests')
        if not isinstance(refs, list) or not isinstance(ledger, list):
            continue
        for receipt in ledger:
            if (not isinstance(receipt, dict) or receipt.get('id') not in refs
                    or receipt.get('identity') != ident or receipt.get('http_status') not in (401, 403)):
                continue
            if kind == 'app_service_selected_settings':
                operation = receipt.get('operation')
                if (receipt.get('host') != 'management.azure.com'
                        or receipt.get('final_route_verified') is not True
                        or operation not in ('identity', 'settings')):
                    continue
                endpoint = ('Microsoft.Web/sites' + ('/slots' if marker.get('slot') else '')
                    + (':GET' if operation == 'identity' else '/config/appsettings:POST'))
            elif kind == 'azure_configuration_selected_content':
                from .azure_selected_configuration_secret_indicators import SURFACES
                surface = marker.get('surface')
                if (surface not in SURFACES or receipt.get('surface') != surface
                        or receipt.get('host') != 'management.azure.com'
                        or receipt.get('method') != 'GET'):
                    continue
                endpoint = SURFACES[surface][0] + ':GET'
            else:
                continue
            issues[ident] = {'status': 'denied', 'code': 'HTTP' + str(receipt['http_status']),
                'operation': endpoint}
            break
    return issues


@dataclass(frozen=True)
class Plan:
    targets: tuple
    discovered: int
    complete: bool
    reason: str


def _plan(collections, source_kinds, make_target, validate, limit, expected_scopes=None):
    candidates = {}
    seen_kinds = set()
    seen_pairs = set()
    complete = True
    for collection in collections:
        if collection.get('type') not in source_kinds:
            continue
        seen_kinds.add(collection['type'])
        seen_pairs.add((collection['type'], collection.get('scope')))
        if collection.get('status') not in ('collected', 'empty'):
            complete = False
        rows = collection.get('items')
        if not isinstance(rows, list):
            complete = False
            continue
        for row in rows:
            try:
                target = make_target(collection, row)
                if target is None:
                    continue
                validate(target)
                key = repr(target)
                if key in candidates:
                    complete = False
                candidates[key] = target
            except (KeyError, ValueError, TypeError, AttributeError):
                complete = False
    ordered = tuple(candidates[key] for key in sorted(candidates))
    expected_pairs = ({(kind, scope) for kind in source_kinds for scope in expected_scopes}
        if expected_scopes is not None else set())
    if not source_kinds <= seen_kinds or not expected_pairs <= seen_pairs:
        complete = False
    reason = ('complete' if complete else
              'source_inventory_unavailable' if not source_kinds <= seen_kinds or not expected_pairs <= seen_pairs else
              'source_inventory_incomplete')
    return Plan(ordered, len(ordered), complete, reason)


def batches(targets, size):
    """Every target exactly once, in native inventory order, with a reader-sized bound."""
    if type(size) is not int or size < 1:
        raise ValueError('invalid_batch_size')
    return tuple(tuple(targets[offset:offset + size])
                 for offset in range(0, len(targets), size))


def target_coverage(targets, identity, collections, kind, marker, issues=None):
    """Opaque, public accounting for every discovered target, including omissions."""
    found = {}
    for collection in collections:
        if collection.get('type') != kind:
            continue
        for row in collection.get('items', ()):
            ident = row.get('id')
            if isinstance(ident, str):
                found.setdefault(ident, []).append(row)
    result = []
    issues = issues or {}
    for target in targets:
        ident = identity(target)
        rows = found.get(ident, ())
        issue = issues.get(ident)
        facts = rows[0].get(marker, {}) if len(rows) == 1 else {}
        facts = facts if isinstance(facts, dict) else {}
        engines = facts.get('engines')
        state = ('uninspected' if not rows else 'inspected'
                 if facts.get('complete') is True else 'denied'
                 if isinstance(issue, dict) and issue.get('status') == 'denied' else
                 'scanner_incomplete' if isinstance(engines, list) and engines and
                 any(engine.get('status') != 'complete' for engine in engines if isinstance(engine, dict))
                 else 'failed')
        entry = {'id': ident, 'status': state}
        if isinstance(issue, dict):
            entry['reason'] = issue['code']
            entry['operation'] = issue['operation']
        result.append(entry)
    return result


def fold_collections(collections, kind, batches):
    """Restore the snapshot's unique type/scope contract after bounded reads."""
    records = {batch['id']: batch for batch in batches}
    grouped = {}
    keep = []
    for collection in collections:
        if collection.get('type') != kind or 'automatic_batch' not in collection:
            keep.append(collection)
            continue
        batch = records[collection.pop('automatic_batch')]
        batch['ids'] = [row['id'] for row in collection['items']]
        batch['status'] = collection['status']
        batch['error'] = collection.get('error')
        scope = collection['scope']
        if scope not in grouped:
            grouped[scope] = collection
            keep.append(collection)
        else:
            parent = grouped[scope]
            parent['items'].extend(collection['items'])
    for scope, parent in grouped.items():
        statuses = [record['status'] for record in batches if record['scope'] == scope]
        complete = all(status in ('collected', 'empty') for status in statuses)
        parent['status'] = ('collected' if parent['items'] else 'empty') if complete else (
            'partial' if parent['items'] else 'unknown')
        if complete:
            parent.pop('error', None)
        else:
            parent['error'] = {'code': 'automatic_content_incomplete'}
            if kind == 'configuration_selected_content':
                expired = {'ExpiredToken', 'ExpiredTokenException', 'RequestExpired'}
                codes = set()
                for record in batches:
                    if record['scope'] != scope:
                        continue
                    error = record.get('error') or {}
                    if error.get('code') in expired:
                        codes.add(error['code'])
                    for item in error.get('additional_errors', ()):
                        if isinstance(item, dict) and item.get('code') in expired:
                            codes.add(item['code'])
                if codes:
                    parent['error']['additional_errors'] = [{'code': code} for code in sorted(codes)]
    collections[:] = keep


def aws_lambda(collections, expected_scopes=None, limit=8):
    from .aws_lambda_environment_secret_indicators import parse
    def target(collection, row):
        arn = row.get('FunctionArn')
        if not isinstance(arn, str) or len(arn.split(':')) < 6 or collection.get('scope') != arn.split(':')[4] + '/' + arn.split(':')[3]:
            raise ValueError('identity_scope_mismatch')
        return arn
    return _plan(collections, {'lambda_function'}, target, parse, limit, expected_scopes)


def aws_ecs(collections, expected_scopes=None, limit=16):
    from .aws_selected_configuration_secret_indicators import parse
    def target(collection, row):
        arn = row.get('taskDefinitionArn')
        if not isinstance(arn, str):
            raise ValueError('missing_native_identity')
        return {'surface': 'ecs_environment', 'scope': collection['scope'], 'resource_id': arn}
    return _plan(collections, {'ecs_task_definition'}, target, parse, limit, expected_scopes)


def aws_configuration(collections, expected_scopes=None, limit=16):
    """Existing selected reader surfaces backed by native workload inventory."""
    from .aws_selected_configuration_secret_indicators import parse
    fields = {'ecs_task_definition': ('ecs_environment', 'taskDefinitionArn'),
              'codebuild_project': ('codebuild_environment', 'name'),
              'batch_job_definition': ('batch_environment', 'jobDefinitionArn'),
              'amplify_app': ('amplify_environment', 'appArn'),
              'glue_job': ('glue_job_arguments', 'Name')}
    def target(collection, row):
        surface, field = fields[collection['type']]
        arn = row.get(field)
        if not isinstance(arn, str):
            raise ValueError('missing_native_identity')
        if collection['type'] in ('glue_job', 'codebuild_project'):
            account, region = collection['scope'].split('/', 1)
            partition = ('aws-cn' if region.startswith('cn-') else
                         'aws-us-gov' if region.startswith('us-gov-') else 'aws')
            prefix = ('glue', 'job') if collection['type'] == 'glue_job' else ('codebuild', 'project')
            arn = f'arn:{partition}:{prefix[0]}:{region}:{account}:{prefix[1]}/{arn}'
        candidate = {'surface': surface, 'scope': collection['scope'], 'resource_id': arn}
        parsed = parse(candidate)
        if parsed[1] + '/' + parsed[2] != collection['scope']:
            raise ValueError('identity_scope_mismatch')
        return candidate
    return _plan(collections, set(fields), target, parse, limit, expected_scopes)


def azure_settings(collections, expected_scopes=None, limit=8):
    from .azure_app_settings_secret_indicators import _RESOURCE
    def target(collection, row):
        rid = row.get('id')
        if not isinstance(rid, str):
            raise ValueError('missing_native_identity')
        match = _RESOURCE.fullmatch(rid)
        if not match or match[1].casefold() != collection.get('scope', '').casefold():
            raise ValueError('identity_scope_mismatch')
        return rid
    return _plan(collections, {'app_service', 'app_service_slot'}, target,
                 lambda value: value if _RESOURCE.fullmatch(value) else (_ for _ in ()).throw(ValueError()), limit, expected_scopes)


def azure_containers(collections, expected_scopes=None, limit=8):
    from .azure_selected_configuration_secret_indicators import parse
    kinds = {'container_group': 'aci_literals', 'container_app': 'container_app_literals'}
    def target(collection, row):
        rid = row.get('id')
        if not isinstance(rid, str):
            raise ValueError('missing_native_identity')
        candidate = {'surface': kinds[collection['type']], 'resource_id': rid}
        if parse(candidate)[1].casefold() != collection.get('scope', '').casefold():
            raise ValueError('identity_scope_mismatch')
        return candidate
    return _plan(collections, set(kinds), target, parse, limit, expected_scopes)


def k8s_workloads(collections, cluster, expected_scopes=None, limit=8):
    from .k8s_literal_secret_indicators import selected_targets
    kinds = {'pod': 'Pod', 'deployment': 'Deployment', 'daemonset': 'DaemonSet',
             'statefulset': 'StatefulSet', 'replicaset': 'ReplicaSet', 'job': 'Job',
             'cronjob': 'CronJob', 'replicationcontroller': 'ReplicationController',
             'podtemplate': 'PodTemplate'}
    def target(collection, row):
        # Operator-supplied metadata cannot authorize a native content GET.
        provenance = row.get('provenance') or {}
        if provenance.get('source') == 'operator-supplied metadata':
            raise ValueError('untrusted_source')
        meta = row.get('metadata') or {}
        name = meta.get('name')
        namespace = meta.get('namespace') or collection.get('scope')
        if not isinstance(name, str) or not isinstance(namespace, str):
            raise ValueError('missing_native_identity')
        if collection.get('scope') != '*' and namespace != collection.get('scope'):
            raise ValueError('identity_scope_mismatch')
        if provenance.get('cluster_id') != cluster or provenance.get('evidence') != 'read-only list':
            raise ValueError('native_inventory_provenance_missing')
        return {'cluster_id': cluster, 'namespace': namespace,
                'kind': kinds[collection['type']], 'name': name}
    def validate(value):
        selected_targets({'selected_k8s_literal_resources': [value]}, [value['namespace']])
    return _plan(collections, set(kinds), target, validate, limit, expected_scopes)
