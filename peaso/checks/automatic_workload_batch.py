"""Project one automatically discovered content batch onto a selected reader.

The original selected evaluator remains the authority for all native receipts.
"""
from copy import deepcopy


def _automatic_issue(item, index, kind, batch, marker_name):
    """Interpret only collector-owned typed failures bound to this batch."""
    if marker_name is None:
        return None
    issues = batch.get('issues', {})
    if not isinstance(issues, dict):
        return None
    issue = issues.get(item.get('id'))
    if not isinstance(issue, dict) or set(issue) != {'status', 'code', 'operation'}:
        return None
    marker = item.get(marker_name)
    meta = batch['metadata']
    scope = index['context']['scope']
    selection = meta.get(kind + '_selection') if isinstance(meta, dict) else None
    if (not isinstance(meta, dict) or not isinstance(marker, dict)
            or marker.get('identity') != item.get('id')
            or marker.get('scope') != scope or marker.get('complete') is not False
            or marker.get('capture') != meta.get(kind + '_capture')
            or not isinstance(selection, dict)
            or item.get('id') not in selection.get(scope, ())):
        return None
    if kind == 'lambda_selected_environment':
        expected = 'lambda:GetFunctionConfiguration'
        request = marker.get('request')
        if (not isinstance(request, dict) or request.get('operation') != expected
                or request.get('status') != 'unavailable'):
            return None
    elif kind == 'configuration_selected_content':
        from peaso.collectors.aws_selected_configuration_secret_indicators import SURFACES
        surface = marker.get('surface')
        if surface not in SURFACES or marker.get('status') != 'unavailable':
            return None
        service, operation = SURFACES[surface][:2]
        expected = service + ':' + ''.join(part.title() for part in operation.split('_'))
    elif kind in ('app_service_selected_settings', 'azure_configuration_selected_content'):
        if (index['context']['provider'] != 'azure'
                or index['context']['metadata'].get('context_binding') != 'scan_local'):
            return None
        refs = marker.get('source_requests')
        ledger = meta.get(kind + '_receipts')
        proof = item.get('_provenance')
        if (not isinstance(refs, list) or not isinstance(ledger, list)
                or not isinstance(proof, dict) or proof.get('source_requests') != refs
                or proof.get('scope') != scope):
            return None
        denied = [receipt for receipt in ledger if isinstance(receipt, dict)
            and receipt.get('id') in refs and receipt.get('identity') == item.get('id')
            and receipt.get('scope') == scope and receipt.get('http_status') in (401, 403)
            and receipt.get('host') == 'management.azure.com']
        if len(denied) != 1 or issue['code'] != 'HTTP' + str(denied[0]['http_status']):
            return None
        receipt = denied[0]
        if kind == 'app_service_selected_settings':
            operation = receipt.get('operation')
            if (operation not in ('identity', 'settings')
                    or receipt.get('method') != ('GET' if operation == 'identity' else 'POST')
                    or receipt.get('route') != 'exact_selected_' + operation
                    or receipt.get('final_route_verified') is not True):
                return None
            expected = ('Microsoft.Web/sites' + ('/slots' if marker.get('slot') else '')
                + (':GET' if operation == 'identity' else '/config/appsettings:POST'))
        else:
            from peaso.collectors.azure_selected_configuration_secret_indicators import SURFACES
            surface = marker.get('surface')
            if (surface not in SURFACES or receipt.get('surface') != surface
                    or receipt.get('method') != 'GET'
                    or receipt.get('capture') != marker.get('capture')):
                return None
            expected = SURFACES[surface][0] + ':GET'
    elif kind == 'k8s_selected_literals':
        from peaso.collectors.k8s_literal_secret_indicators import NATIVE_KINDS
        if (index['context']['provider'] != 'k8s'
                or marker.get('reason') != 'native_get_denied'
                or marker.get('kind') not in NATIVE_KINDS
                or marker.get('cluster_binding') != meta.get(kind + '_cluster_binding')
                or issue['code'] != 'native_get_denied'):
            return None
        expected = 'kubernetes:GET ' + marker['kind']
    else:
        return None
    if issue['operation'] != expected:
        return None
    allowed_codes = ({'AccessDenied', 'AccessDeniedException', 'UnauthorizedOperation', 'ForbiddenException'}
        if kind in ('lambda_selected_environment', 'configuration_selected_content') else
        {'HTTP401', 'HTTP403'} if kind in ('app_service_selected_settings', 'azure_configuration_selected_content')
        else {'native_get_denied'})
    if issue['status'] == 'denied' and issue['code'] in allowed_codes:
        if kind == 'app_service_selected_settings' and expected.endswith('/config/appsettings:POST'):
            # Reading app settings is a list action that Reader does not grant.
            action = 'Microsoft.Web/sites' + ('/slots' if '/slots/' in expected else '') + '/config/list/action'
            return 'DENIED', {'observed': 'The app settings could not be read because the identity lacks '
                + action + ' (' + issue['code'] + ').', 'reason': 'access_denied', 'operation': expected,
                'missing_action': action, 'provider_code': issue['code'], 'complete': False}
        return 'DENIED', {'observed': 'Access denied for ' + expected + ' (' + issue['code'] + ').',
            'reason': 'access_denied', 'operation': expected, 'provider_code': issue['code'],
            'complete': False}
    if kind == 'lambda_selected_environment' and issue['status'] == 'unknown':
        # A function with no variable values has no environment content that could hold a secret.
        if issue['code'] == 'environment_no_literals':
            return 'PASS', {'observed': 'The Lambda function has no environment variables configured, so there was no environment content to scan.',
                'operation': expected, 'complete': True}
        if issue['code'] == 'environment_empty':
            return 'PASS', {'observed': 'Every Lambda environment variable value is empty, so there was no environment content to scan.',
                'operation': expected, 'complete': True}
        if issue['code'] == 'environment_error':
            observed = 'Lambda reported an environment configuration error; no content was scanned.'
        elif issue['code'] == 'environment_unavailable':
            observed = 'The Lambda environment field was unavailable; no content was scanned.'
        elif issue['code'] in {'environment_unsupported', 'native_identity_or_partial',
                'response_bound', 'response_total_bound'}:
            observed = 'The Lambda environment response was unsupported or incomplete.'
        else:
            return None
        return 'UNKNOWN', {'observed': observed, 'reason': issue['code'],
            'operation': expected, 'complete': False}
    return None


def _lambda_detector_issue(item, kind, marker_name, batch):
    if kind != 'lambda_selected_environment' or marker_name is None:
        return None
    marker = item.get(marker_name)
    if (not isinstance(marker, dict) or marker.get('complete') is not False
            or marker.get('identity') != item.get('id')
            or marker.get('capture') != batch['metadata'].get(kind + '_capture')
            or not isinstance(marker.get('request'), dict)
            or marker['request'].get('status') != 'collected'):
        return None
    engines = marker.get('engines')
    if not isinstance(engines, list) or len(engines) != 2:
        return None
    from peaso.secret_scanning import KINGFISHER_VERSION, TRUFFLEHOG_VERSION
    versions = {'kingfisher': KINGFISHER_VERSION, 'trufflehog': TRUFFLEHOG_VERSION}
    if (any(not isinstance(engine, dict) or set(engine) != {'engine', 'version', 'status'}
            or engine.get('version') != versions.get(engine.get('engine'))
            or engine.get('status') not in ('complete', 'unavailable') for engine in engines)
            or {engine['engine'] for engine in engines} != set(versions)):
        return None
    unavailable = [engine['engine'] for engine in engines if engine['status'] == 'unavailable']
    if not unavailable:
        return None
    names = {'kingfisher': 'Kingfisher', 'trufflehog': 'TruffleHog'}
    return 'UNKNOWN', {'observed': ', '.join(names[name] for name in unavailable) +
        ' did not complete the Lambda environment scan.', 'reason': 'scanner_incomplete',
        'failed_detectors': unavailable, 'complete': False}



# Exact registered IDs alone may opt into the automatic batch projection.
AUTO_CHECKS = {
    'aws.review.lambda.selected_environment_secret_indicators':
        ('lambda_selected_environment', 'SelectedLambdaEnvironmentSecretIndicators'),
    'aws.review.configuration.selected_content_secret_indicators':
        ('configuration_selected_content', 'SelectedConfigurationSecretIndicators'),
    'azure.review.app_service.selected_app_settings_secret_indicators':
        ('app_service_selected_settings', 'SelectedAppSettingSecretIndicators'),
    'azure.review.configuration.selected_content_secret_indicators':
        ('azure_configuration_selected_content', 'SelectedArmConfigurationSecretIndicators'),
    'k8s.review.selected_literals.secret_indicators':
        ('k8s_selected_literals', 'SelectedKubernetesLiteralSecretIndicators'),
}


def prepare(index, check_id):
    """Validate one scope's complete partition once and index items in O(batches + items)."""
    route = AUTO_CHECKS.get(check_id)
    if route is None:
        return None
    kind, marker_name = route
    context = index.get('context')
    if not isinstance(context, dict) or not isinstance(context.get('metadata'), dict):
        return None
    metadata = context['metadata']
    grouped = metadata.get('automatic_workload_environment_batches')
    if not isinstance(grouped, dict) or kind not in grouped:
        return None  # Historical selected-only path.
    batches = grouped[kind]
    error = lambda reason: {'route': route, 'error': reason, 'items': {}}
    if not isinstance(batches, list) or not batches:
        return error('Automatic workload content coverage is unbound.')
    scope = context.get('scope')
    if not isinstance(scope, str):
        return error('Automatic workload content scope is unbound.')
    collections = [collection for collection in index.get('collections', {}).get(kind, ())
                   if isinstance(collection, dict) and collection.get('scope') == scope]
    if len(collections) != 1 or not isinstance(collections[0].get('items'), list):
        return error('Automatic workload content batch is missing or ambiguous.')
    collection = collections[0]
    own_items = collection['items']
    item_by_id = {}
    for item in own_items:
        if (not isinstance(item, dict) or not isinstance(item.get('id'), str)
                or item['id'] in item_by_id):
            return error('Automatic workload content items are malformed or duplicated.')
        item_by_id[item['id']] = item
    seen_ids, seen_batches, local = {}, set(), []
    for batch in batches:
        if (not isinstance(batch, dict) or set(batch) not in (
                {'id', 'scope', 'metadata', 'ids', 'status', 'error'},
                {'id', 'scope', 'metadata', 'ids', 'status', 'error', 'issues'})
                or not isinstance(batch.get('id'), str) or batch['id'] in seen_batches
                or not isinstance(batch.get('scope'), str)
                or not isinstance(batch.get('metadata'), dict)
                or not isinstance(batch.get('ids'), list)
                or any(not isinstance(value, str) for value in batch['ids'])
                or ('issues' in batch and not isinstance(batch['issues'], dict))):
            return error('Automatic workload content batch is malformed.')
        seen_batches.add(batch['id'])
        for ident in batch['ids']:
            if ident in seen_ids:
                return error('Automatic workload content item is ambiguously bound.')
            seen_ids[ident] = batch['scope']
        if batch['scope'] == scope:
            local.append(batch)
    if not local or {ident for ident, owner in seen_ids.items() if owner == scope} != set(item_by_id):
        return error('Automatic workload content batch partition is incomplete.')
    prepared = {}
    for batch in local:
        projected_collection = dict(collection)
        try:
            projected_collection['items'] = [item_by_id[ident] for ident in batch['ids']]
        except KeyError:
            return error('Automatic workload content batch partition is incomplete.')
        projected_collection['status'] = batch['status']
        if batch['error'] is None:
            projected_collection.pop('error', None)
        else:
            projected_collection['error'] = batch['error']
        projected = dict(index)
        projected['collections'] = dict(index['collections'])
        projected['collections'][kind] = [projected_collection]
        projected['context'] = dict(context)
        projected['context']['metadata'] = {**metadata, **deepcopy(batch['metadata'])}
        for ident in batch['ids']:
            prepared[ident] = (projected, batch)
    return {'route': (kind, marker_name), 'error': None, 'items': prepared}


def evaluate_prepared(item, index, selected_evaluate, prepared):
    """Call the unchanged registered leaf with its one exact bounded batch."""
    if prepared is None:
        return selected_evaluate(item, index)
    reason = prepared['error']
    if reason is not None:
        return 'UNKNOWN', {'observed': reason}
    if not isinstance(item, dict):
        return 'UNKNOWN', {'observed': 'Automatic workload content item is malformed.'}
    selected = prepared['items'].get(item.get('id'))
    if selected is None:
        return 'UNKNOWN', {'observed': 'Automatic workload content item is missing or ambiguous.'}
    projected, batch = selected
    kind, marker_name = prepared['route']
    status, detail = selected_evaluate(item, projected)
    if status == 'UNKNOWN':
        issue = _automatic_issue(item, index, kind, batch, marker_name)
        if issue is not None:
            return issue
        detector = _lambda_detector_issue(item, kind, marker_name, batch)
        if detector is not None:
            return detector
    # This workload's exact selected receipt proves its own PASS even if a
    # separate target left report-level inventory coverage incomplete.
    return status, detail
