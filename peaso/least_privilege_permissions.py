"""Resolve complete collected high-impact grants and correctly scoped usage facts."""
from datetime import datetime, timezone
from fnmatch import fnmatchcase
from collections import defaultdict
import re

from peaso.analysis.common import as_list, native_id
from peaso.analysis.iam import grants, permission_severity
from peaso.principal_exposure import canonical, RANK, _cluster


def _date(value):
    try:
        result = value if isinstance(value, datetime) else datetime.fromisoformat(str(value).replace('Z', '+00:00'))
        return result if result.tzinfo else None
    except (ValueError, TypeError):
        return None


def _label(row):
    data = row.get('data', {})
    return str(data.get('RoleName') or data.get('UserName') or data.get('PolicyName') or data.get('GroupName')
        or data.get('displayName') or data.get('name') or data.get('Name')
        or data.get('FunctionName') or data.get('taskArn') or data.get('InstanceId')
        or data.get('metadata', {}).get('name') or row.get('native_id') or native_id(row))


def _gcp_condition(value):
    if not isinstance(value, dict):
        return ('', '', '', '')
    return tuple(str(value.get(field) or '') for field in ('expression', 'title', 'description', 'location'))


def _usage_index(provider, rows):
    """Index stored evidence once; rendering principals never reopens cloud logs."""
    indexed = {'insights': defaultdict(list), 'gcp_events': defaultdict(list),
               'gcp_actions': {}, 'azure_events': defaultdict(list), 'azure_actions': defaultdict(list),
               'azure_aliases': defaultdict(set)}
    for row in rows:
        data = row['data']
        if provider == 'gcp':
            if (row['type'] == 'insight' and data.get('insightSubtype') == 'PERMISSIONS_USAGE'
                    and (data.get('stateInfo') or {}).get('state') == 'ACTIVE'):
                content = data.get('content') or {}
                indexed['insights'][(canonical(provider, content.get('member')), row.get('scope'),
                                     content.get('role'))].append(row)
            elif row['type'] in {'activity', 'iam_usage_activity'}:
                email = str(data.get('principalEmail', '')).casefold()
                if not email:
                    continue
                indexed['gcp_events'][email].append(row)
                if data.get('statusCode') not in (None, 0):
                    continue
                when = _date(data.get('timestamp'))
                if when is None:
                    continue
                for check in data.get('authorizationInfo', []):
                    if isinstance(check, dict) and check.get('granted') is True and isinstance(check.get('permission'), str):
                        key = (email, row.get('scope'), check['permission'].casefold())
                        if key not in indexed['gcp_actions'] or when > indexed['gcp_actions'][key]:
                            indexed['gcp_actions'][key] = when
        elif provider == 'azure':
            if row['type'] in {'directory_user', 'directory_service_principal'}:
                identity = str(data.get('id', '')).casefold()
                indexed['azure_aliases'][identity].update(str(data[key]).casefold() for key in
                    ('userPrincipalName', 'mail', 'appId') if data.get(key))
            elif row['type'] in {'activity_log', 'iam_usage_activity'}:
                aliases = {str(data.get(field)).casefold() for field in ('caller', 'principalObjectId', 'appId')
                           if isinstance(data.get(field), str) and data.get(field)}
                for caller in aliases:
                    indexed['azure_events'][caller].append(row)
                if (isinstance(data.get('status'), dict)
                        and str(data['status'].get('value', '')).casefold() == 'succeeded'):
                    action = str(data.get('authorizationAction') or '').casefold()
                    if action:
                        for caller in aliases:
                            indexed['azure_actions'][(caller, action)].append(row)
    return indexed


def enrich(card, provider, resources, observed_at, *, _rows=None, _usage=None):
    """Never expand wildcards or infer individual action usage from service activity."""
    rows = _rows if _rows is not None else [{**r, 'provider': provider} for r in resources if isinstance(r.get('data'), dict)]
    usage = _usage if _usage is not None else _usage_index(provider, rows)
    target = card['principal']
    now = _date(observed_at)
    permissions, unresolved = [], []
    principal_rows = []
    gcp_email = target.split(':', 1)[1].casefold() if provider == 'gcp' and target.startswith(('user:', 'serviceAccount:')) else None
    azure_aliases = ({target.casefold()} | usage['azure_aliases'].get(target.casefold(), set())) if provider == 'azure' else set()
    gcp_activity = usage['gcp_events'].get(gcp_email, []) if gcp_email else []
    azure_activity = [event for alias in azure_aliases for event in usage['azure_events'].get(alias, [])]
    aws_report_cache = usage.setdefault('aws_report_cache', {})
    suggestions_by_permission = defaultdict(list)
    for suggestion in card.get('suggestions', []):
        if (isinstance(suggestion, dict) and suggestion.get('kind') == 'permission'
                and suggestion.get('confidence') == 'provider_recommendation'):
            suggestions_by_permission[str(suggestion.get('value', '')).casefold()].append(suggestion)

    def aws_service(candidate, namespace):
        if candidate is None or not namespace:
            return None
        data = candidate['data']
        if data.get('ServicesLastAccessedStatus', {}).get('collection_status') != 'collected':
            return None
        key = id(candidate)
        cached = aws_report_cache.get(key)
        if cached is None or cached[0] is not candidate:
            services = {}
            for service in data.get('ServicesLastAccessed', []):
                if not isinstance(service, dict):
                    continue
                name = service.get('ServiceNamespace')
                if not isinstance(name, str) or not name:
                    continue
                actions = {}
                for action in service.get('TrackedActionsLastAccessed', []):
                    if (isinstance(action, dict) and isinstance(action.get('ActionName'), str)
                            and action.get('LastAccessedTime')):
                        actions.setdefault(action['ActionName'].casefold(), action)
                unobserved = {action.casefold() for action in service.get('TrackedActionsUnobserved', [])
                              if isinstance(action, str)}
                services.setdefault(name.casefold(), (service, actions, unobserved))
            aws_report_cache[key] = (candidate, services)
        else:
            services = cached[1]
        return services.get(namespace.casefold())

    def same(value):
        return canonical(provider, value) == canonical(provider, target)

    def append(permission, severity, row, *, scope=None, source=None, resources=None, conditions=None, exclusions=None, usage_row=None, group_key=None, group_label=None, access_plane='management'):
        if severity not in {'high', 'critical'}:
            return
        entry = dict(permission=str(permission), severity=severity, scope=scope or row.get('scope', ''),
            source=source or _label(row), resources=resources or [], conditions=conditions, exclusions=exclusions or [],
            group_key=group_key or str(row.get('native_id') or native_id(row)), group_label=group_label or _label(row))
        namespace = str(permission).split(':')[0] if ':' in str(permission) and '*' not in str(permission) else None
        # IAM action reports can identify an action attempted by an identity.
        # A shared policy or group report is aggregate evidence, so label it as
        # such even when its action name exactly matches this permission.
        aws_reports = ((usage_row, 'permission', 'AWS IAM action report'),
                       (row if row.get('type') == 'iam_policy' else None, 'policy', 'AWS IAM policy action report'),
                       (row if row.get('type') == 'iam_group' else None, 'group', 'AWS IAM group action report'))
        if provider == 'aws' and namespace and '*' not in str(permission):
            action_name = str(permission).split(':', 1)[1].casefold()
            principal_status = (usage_row or {}).get('data', {}).get('ServicesLastAccessedStatus', {})
            if principal_status.get('collection_status') == 'collected':
                principal_service = aws_service(usage_row, namespace)
                if principal_service and action_name in principal_service[2]:
                    entry.update(usage_status='not_observed', usage_source='AWS IAM action report',
                                 usage_window_end=principal_status.get('job_completion_date'))
            for candidate, basis, report_source in aws_reports:
                service = aws_service(candidate, namespace)
                action = service[1].get(action_name) if service else None
                if action:
                    entry.update(last_accessed=action['LastAccessedTime'], usage_basis=basis, usage_source=report_source)
                    if basis == 'permission':
                        entry['usage_status'] = 'observed'
                    break
        if 'last_accessed' not in entry:
            for candidate, basis in ((usage_row, 'service'),
                                     (row if row.get('type') == 'iam_policy' else None, 'policy'),
                                     (row if row.get('type') == 'iam_group' else None, 'group')):
                service = aws_service(candidate, namespace)
                if service and service[0].get('LastAuthenticated'):
                    entry.update(last_accessed=service[0]['LastAuthenticated'], usage_basis=basis,
                                 usage_source='AWS IAM service report')
                    break
        # Only an exact per-action provider observation can describe action usage.
        exact = suggestions_by_permission.get(str(permission).casefold(), [])
        if any(s.get('source') == 'AWS IAM Access Analyzer unused access' for s in exact):
            entry['unused_finding'] = True
        if exact:
            latest = max((_date(s.get('last_accessed')) for s in exact), default=None, key=lambda d: d or datetime.min.replace(tzinfo=timezone.utc))
            if latest:
                entry.update(last_accessed=latest.isoformat(), usage_basis='permission',
                             usage_source='AWS IAM Access Analyzer unused access')
                entry['usage_status'] = 'observed'
        if provider == 'gcp':
            for insight in usage['insights'].get((canonical(provider, target), entry['scope'], entry['group_key']), []):
                data = insight['data']; content = data.get('content') or {}
                if (insight.get('scope') != entry['scope'] or not same(content.get('member'))
                        or content.get('role') != entry['group_key']
                        or _gcp_condition(content.get('condition')) != _gcp_condition(entry['conditions'])
                        or not re.fullmatch(r'[1-9][0-9]*s', str(data.get('observationPeriod', '')))
                        or _date(data.get('lastRefreshTime')) is None
                        or not isinstance(content.get('exercisedPermissions'), list)):
                    continue
                exercised = {name.casefold() for item in content['exercisedPermissions']
                    if isinstance(name := (item if isinstance(item, str) else item.get('permission')
                        if isinstance(item, dict) else None), str)}
                entry.update(usage_status='observed' if str(permission).casefold() in exercised else 'not_observed',
                    usage_window_days=int(data['observationPeriod'][:-1]) // 86400,
                    usage_window_end=data['lastRefreshTime'], usage_source='GCP IAM Policy Insight')
                break
            action_date = usage['gcp_actions'].get((gcp_email, entry['scope'], str(permission).casefold()))
            if action_date:
                entry.update(last_accessed=action_date.isoformat(), usage_basis='permission', usage_status='observed',
                    usage_source='GCP Cloud Audit Logs')
        elif provider == 'azure':
            def in_scope(event):
                event_scope = str(event['data'].get('resourceId', '')).casefold().rstrip('/')
                grant_scope = entry['scope'].casefold().rstrip('/')
                return bool(grant_scope) and (event_scope == grant_scope or event_scope.startswith(grant_scope + '/'))
            activity = [r for alias in azure_aliases
                        for r in usage['azure_actions'].get((alias, str(permission).casefold()), []) if in_scope(r)]
            dates = [value for r in activity if (value := _date(r['data'].get('eventTimestamp'))) is not None]
            if dates and access_plane == 'management':
                entry.update(last_accessed=max(dates).isoformat(), usage_basis='permission', usage_source='Azure Activity Log')
            elif access_plane == 'management' and '*' in str(permission):
                # A wildcard grant can match observed actions, but the event
                # cannot prove which of several roles authorized the call.
                compatible = [r for r in azure_activity if in_scope(r)
                    and isinstance(r['data'].get('status'), dict)
                    and r['data']['status'].get('value') == 'Succeeded'
                    and isinstance(r['data'].get('authorizationAction'), str)
                    and fnmatchcase(r['data']['authorizationAction'].casefold(), str(permission).casefold())
                    and not any(fnmatchcase(r['data']['authorizationAction'].casefold(), str(x).casefold())
                                for x in entry['exclusions'])]
                dates = [value for r in compatible if (value := _date(r['data'].get('eventTimestamp'))) is not None]
                if dates:
                    entry.update(last_accessed=max(dates).isoformat(), usage_basis='compatible',
                                 usage_source='Azure Activity Log')
        accessed = _date(entry.get('last_accessed'))
        if now and accessed and accessed <= now:
            entry['days_since_last_access'] = (now - accessed).days
        else:
            for key in ('last_accessed', 'usage_basis'):
                entry.pop(key, None)
        if entry not in permissions:
            permissions.append(entry)

    def declared(row, *, source=None, scope=None, usage_row=None, extra_conditions=None, group_key=None, group_label=None):
        for grant in grants(row):
            if not grant.get('allowed_declaration'):
                continue
            if provider == 'aws' and grant.get('path', '').startswith('PolicySources['):
                # Collector provenance repeats the same inline policy document.
                continue
            native = grant.get('native_grant')
            grant_source = source or _label(row)
            inline = re.match(r'(UserPolicyList|RolePolicyList|GroupPolicyList|PolicySources)\[(\d+)\]', grant.get('path', ''))
            if inline:
                item = row['data'].get(inline[1], [])[int(inline[2])]
                name = item.get('PolicyName') or item.get('PolicyArn') or item.get('name')
                if name:
                    grant_source += ' → ' + str(name)
            grant_key = group_key or str(row['data'].get('Arn') or row['data'].get('name') or row.get('native_id') or native_id(row))
            grant_label = group_label or _label(row)
            if inline:
                grant_key += '#inline:' + str(name or inline[2])
                grant_label = str(name or grant_label)
            if provider == 'aws' and isinstance(native, dict):
                if native.get('NotAction'):
                    append('All actions except ' + ', '.join(as_list(native['NotAction'])), grant['severity'], row,
                        scope=scope, source=grant_source, resources=as_list(native.get('Resource')),
                        conditions=native.get('Condition'), exclusions=as_list(native.get('NotResource')), usage_row=usage_row,
                        group_key=grant_key, group_label=grant_label)
                for action in as_list(native.get('Action')):
                    if not isinstance(action, str):
                        continue
                    severity = permission_severity(provider, action) or ('high' if '*' in action else 'info')
                    append(action, severity, row, scope=scope, source=grant_source, resources=as_list(native.get('Resource')),
                        conditions=native.get('Condition'), exclusions=as_list(native.get('NotResource')), usage_row=usage_row,
                        group_key=grant_key, group_label=grant_label)
            elif provider == 'gcp' and isinstance(native, str):
                append(native, grant['severity'], row, scope=scope, source=grant_source, conditions=extra_conditions,
                       group_key=grant_key, group_label=grant_label)
            elif provider == 'azure' and isinstance(native, dict):
                for key, exclusion in (('actions', 'notActions'), ('dataActions', 'notDataActions')):
                    for action in as_list(native.get(key)):
                        if not isinstance(action, str) or any(fnmatchcase(action.lower(), str(x).lower()) for x in as_list(native.get(exclusion))):
                            continue
                        append(action, permission_severity(provider, action) or ('high' if '*' in action else 'info'), row,
                            scope=scope, source=grant_source, conditions=extra_conditions,
                            exclusions=as_list(native.get(exclusion)), group_key=grant_key, group_label=grant_label,
                            access_plane='data' if key == 'dataActions' else 'management')
            elif provider == 'k8s' and isinstance(native, dict):
                from bluepeass.k8s_risks import PermissionKey, classify_permission
                for verb in as_list(native.get('verbs')):
                    for group in as_list(native.get('apiGroups', [''])):
                        for resource in as_list(native.get('resources')):
                            base, _, sub = resource.partition('/')
                            level, _ = classify_permission(PermissionKey(verb, group=group, resource=base,
                                subresource=sub, namespace=row['data'].get('metadata', {}).get('namespace', '')))
                            append(f'{verb} {group or "core"}/{resource}', level, row, scope=scope, source=grant_source,
                                resources=as_list(native.get('resourceNames')), group_key=grant_key, group_label=grant_label)
                    for url in as_list(native.get('nonResourceURLs')):
                        append(f'{verb} {url}', grant['severity'], row, scope=scope, source=grant_source,
                               group_key=grant_key, group_label=grant_label)

    if provider == 'aws':
        account = target.split(':')[4] if target.startswith('arn:') and len(target.split(':')) > 4 else None
        scoped = [r for r in rows if account and r.get('scope', '').split('/')[0] == account]
        policies = {r['data'].get('Arn'): r for r in scoped if r['type'] == 'iam_policy'}
        groups = {r['data'].get('GroupName'): r for r in scoped if r['type'] == 'iam_group'}
        principal_rows = [r for r in scoped if r['type'] in {'iam_user', 'iam_role', 'iam_group'} and r['data'].get('Arn') == target]
        for principal in principal_rows:
            sources = [principal]
            sources.extend(groups[name] for name in as_list(principal['data'].get('GroupList')) if name in groups)
            for source in sources:
                declared(source, source=_label(source), usage_row=principal)
                for ref in source['data'].get('AttachedManagedPolicies', []):
                    policy = policies.get(ref.get('PolicyArn'))
                    if policy:
                        declared(policy, scope=source.get('scope'), source=f'{_label(source)} → {_label(policy)}', usage_row=principal)
                    else:
                        unresolved.append(ref.get('PolicyArn') or ref.get('PolicyName'))
    elif provider == 'gcp':
        definitions = {r['data'].get('name'): r for r in rows if r['type'] == 'iam_role'}
        for row in rows:
            data = row['data']; policy = data.get('iamPolicy', data.get('policy', data))
            if not isinstance(policy, dict):
                continue
            for binding in policy.get('bindings', []):
                if not any(same(m) for m in binding.get('members', [])):
                    continue
                definition = definitions.get(binding.get('role'))
                if definition:
                    declared(definition, scope=row.get('scope'), source=binding['role'], extra_conditions=binding.get('condition'))
                else:
                    unresolved.append(binding.get('role'))
    elif provider == 'azure':
        definitions = {str(r['data'].get('name', '')).rstrip('/').split('/')[-1].lower(): r for r in rows if r['type'] == 'role_definition'}
        for row in rows:
            props = row['data'].get('properties', {})
            if row['type'] != 'role_assignment' or not same(props.get('principalId')):
                continue
            definition = definitions.get(str(props.get('roleDefinitionId', '')).rstrip('/').split('/')[-1].lower())
            if definition:
                declared(definition, scope=props.get('scope') or row.get('scope'), source=definition['data'].get('properties', {}).get('roleName') or _label(definition), extra_conditions=props.get('condition'))
            else:
                unresolved.append(props.get('roleDefinitionId'))
    elif provider == 'k8s':
        roles = {(_cluster(r), r['type'], r['data'].get('metadata', {}).get('namespace', 'default'), r['data'].get('metadata', {}).get('name')): r
                 for r in rows if r['type'] in {'role', 'clusterrole'}}
        target_cluster = card['id'].split('|', 1)[0] if '|' in card['id'] else None
        for row in rows:
            if row['type'] not in {'rolebinding', 'clusterrolebinding'} or target_cluster and _cluster(row) != target_cluster:
                continue
            data = row['data']; namespace = data.get('metadata', {}).get('namespace', 'default')
            identities = [f"system:serviceaccount:{s.get('namespace', namespace)}:{s.get('name')}" if s.get('kind') == 'ServiceAccount' else s.get('name') for s in data.get('subjects', [])]
            if target not in identities:
                continue
            ref = data.get('roleRef', {}); kind = str(ref.get('kind', '')).lower()
            definition = roles.get((_cluster(row), kind, namespace if kind == 'role' else 'default', ref.get('name')))
            if definition:
                declared(definition, scope=row.get('scope'), source=f"{ref.get('kind')} {ref.get('name')}",
                    group_key='|'.join((_cluster(row), kind, namespace if kind == 'role' else '*', str(ref.get('name')))),
                    group_label=f"{ref.get('kind')} {ref.get('name')}")
            else:
                unresolved.append(ref.get('name'))

    labels = {r['id']: _label(r) for r in rows if r.get('id')}
    exposures = []
    for entry in card.get('exposures', []):
        current = dict(entry)
        for field in ('resource', 'workload_resource', 'endpoint_resource'):
            key = 'resource_id' if field == 'resource' else field
            if current.get(key) in labels:
                current[field + '_label'] = labels[current[key]]
        exposures.append(current)
    identity_last_used = next((r['data'].get('RoleLastUsed', {}).get('LastUsedDate') for r in principal_rows if r['data'].get('RoleLastUsed', {}).get('LastUsedDate')), None)
    if provider in {'gcp', 'azure'}:
        events = gcp_activity if provider == 'gcp' else azure_activity
        field = 'timestamp' if provider == 'gcp' else 'eventTimestamp'
        dates = [value for event in events if (value := _date(event['data'].get(field))) is not None]
        if dates:
            identity_last_used = max(dates).isoformat()
    return dict(card, high_risk_permissions=sorted(permissions, key=lambda p: (RANK[p['severity']], p['permission'], p['scope'], p['source'])),
        permission_definitions_missing=sorted({str(x) for x in unresolved if x}), exposures=exposures,
        observed_at=observed_at, identity_last_used=identity_last_used)


def with_aws_tracked_reviews(projection, resources, observed_at):
    """Augment existing and newly generated cards from the same saved inventory."""
    cards = projection['items']
    if all('tracked_review_count' in card for card in cards):
        return projection
    keep = permission_input_filter('aws', cards)
    rows = [{**row, 'provider': 'aws'} for row in resources if keep(row) and isinstance(row.get('data'), dict)]
    if not any(service.get('TrackedActionsUnobserved') for row in rows if row['type'] in {'iam_role', 'iam_user'}
               for service in row['data'].get('ServicesLastAccessed', []) if isinstance(service, dict)):
        return projection
    usage = _usage_index('aws', rows)
    return dict(projection, items=[with_aws_tracked_card_reviews(card, enrich(card, 'aws', rows, observed_at,
                _rows=rows, _usage=usage)['high_risk_permissions']) for card in cards])


def with_aws_tracked_card_reviews(card, permissions):
    """Use only explicit principal/action observations with a dated report."""
    suggestions = list(card.get('suggestions', []))
    known = {(s['value'].casefold(), s['scope'], s.get('policy')) for s in suggestions if s['kind'] == 'permission'}
    for entry in permissions:
        if entry.get('usage_status') != 'not_observed' or _date(entry.get('usage_window_end')) is None:
            continue
        key = entry['permission'].casefold(), entry['scope'], entry['group_key']
        if key not in known:
            known.add(key)
            suggestions.append({'kind': 'permission', 'value': entry['permission'], 'scope': entry['scope'],
                'policy': entry['group_key'], 'source': 'AWS IAM action report',
                'usage_window_end': entry['usage_window_end'], 'confidence': 'tracked_without_observed_use'})
    return dict(card, suggestions=suggestions, tracked_review_count=sum(
        s['confidence'] == 'tracked_without_observed_use' for s in suggestions))


def permission_input_filter(provider, cards):
    """Keep all AWS grant/usage records and exact exposure-label targets."""
    if provider != 'aws' or cards is None:
        return None
    labels = {entry[field] for card in cards for entry in card.get('exposures', [])
              for field in ('resource_id', 'workload_resource', 'endpoint_resource')
              if isinstance(entry.get(field), str)}
    return lambda row: row.get('type') in {'iam_user', 'iam_role', 'iam_group', 'iam_policy'} or row.get('id') in labels


def grant_groups(cards, provider, resources, observed_at):
    """Build policy/role groups from the same resolved grants used by principal details."""
    groups = {}
    rows = [{**r, 'provider': provider} for r in resources if isinstance(r.get('data'), dict)]
    usage = _usage_index(provider, rows)
    for card in cards:
        for permission in enrich(card, provider, resources, observed_at, _rows=rows, _usage=usage)['high_risk_permissions']:
            key = permission['group_key']
            group = groups.setdefault(key, {'id': key, 'label': permission['group_label'],
                'provider': provider, 'scopes': set(), 'principals': {}, 'permissions': [], 'severity': 'high'})
            group['scopes'].add(permission['scope'])
            group['principals'][card['id']] = {'id': card['id'], 'principal': card['principal'],
                'label': card.get('label') or card['principal'], 'severity': card.get('severity'),
                'exposures': card.get('exposures', []), 'recommendation_count': card.get('recommendation_count', 0)}
            if permission['severity'] == 'critical':
                group['severity'] = 'critical'
            item = {**permission, 'principal_id': card['id'], 'principal': card['principal']}
            if item not in group['permissions']:
                group['permissions'].append(item)
    return [dict(group, scopes=sorted(group['scopes']), principals=sorted(group['principals'].values(),
                 key=lambda item: item['label'].casefold()), permission_count=len(group['permissions']),
                 recommendation_count=sum(item['recommendation_count'] for item in group['principals'].values()))
            for group in groups.values()]


def include_resolved_principals(provider, rows, cards):
    """Keep inherited AWS grants and collected GCP custom roles in the principal list."""
    from peaso.principal_exposure import increased

    def add(identity, source, definitions, label=None):
        levels = [grant['severity'] for definition in definitions for grant in grants(definition)
                  if grant.get('allowed_declaration') and grant.get('severity') in {'high', 'critical'}]
        if not identity or not levels:
            return
        key = canonical(provider, identity)
        item = cards.setdefault(key, dict(principal=identity, label=label or identity, scopes=[], exposures=[],
            base_severity='info', grant_reviews=[]))
        item['base_severity'] = min([item['base_severity'], *levels], key=RANK.get)
        item['severity'] = increased(item['base_severity'], item['exposures'])
        if source.get('scope', '') not in item['scopes']:
            item['scopes'].append(source.get('scope', ''))
        review = {'resource_id': source.get('id'), 'scope': source.get('scope', '')}
        if review not in item['grant_reviews']:
            item['grant_reviews'].append(review)

    if provider == 'aws':
        groups = {(r.get('scope', '').split('/')[0], r['data'].get('GroupName')): r for r in rows if r['type'] == 'iam_group'}
        policies = {(r.get('scope', '').split('/')[0], r['data'].get('Arn')): r for r in rows if r['type'] == 'iam_policy'}
        for row in rows:
            if row['type'] != 'iam_user':
                continue
            account = row.get('scope', '').split('/')[0]
            for name in row['data'].get('GroupList', []):
                group = groups.get((account, name))
                if group:
                    definitions = [group, *[policies[(account, p.get('PolicyArn'))] for p in group['data'].get('AttachedManagedPolicies', []) if (account, p.get('PolicyArn')) in policies]]
                    add(row['data'].get('Arn'), row, definitions, row['data'].get('UserName'))
    elif provider == 'gcp':
        roles = {r['data'].get('name'): r for r in rows if r['type'] == 'iam_role'}
        for row in rows:
            data = row['data']; policy = data.get('iamPolicy', data.get('policy', data))
            if not isinstance(policy, dict):
                continue
            for binding in policy.get('bindings', []):
                definition = roles.get(binding.get('role'))
                if definition:
                    for member in binding.get('members', []):
                        add(member, row, [definition])
    return cards
