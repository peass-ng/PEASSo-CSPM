"""Native Kubernetes identity lifecycle predicates over read-only inventory.

Structural consumers are recorded declarations, not authentication history.
Legacy token inactivity separately uses Kubernetes' tracked last-use metadata.
"""
from __future__ import annotations
from functools import partial

from peaso.iam_usage_evidence import legacy_token_usage

GROUP = 'rbac.authorization.k8s.io'
WORKLOAD_PATHS = {'pod': ('spec',), 'deployment': ('spec', 'template', 'spec'),
    'daemonset': ('spec', 'template', 'spec'), 'statefulset': ('spec', 'template', 'spec'),
    'replicaset': ('spec', 'template', 'spec'), 'replicationcontroller': ('spec', 'template', 'spec'),
    'job': ('spec', 'template', 'spec'), 'cronjob': ('spec', 'jobTemplate', 'spec', 'template', 'spec'),
    'podtemplate': ('template', 'spec')}


class Incomplete(ValueError):
    pass


def _usable_fields(item, fields):
    coverage = item.get('_coverage', {})
    if not isinstance(coverage, dict):
        raise Incomplete('native field coverage is malformed')
    for field in fields:
        if field in coverage:
            marker = coverage[field]
            if not isinstance(marker, dict) or marker.get('status') not in ('collected', 'empty'):
                raise Incomplete('native field is unavailable: ' + field)


def _meta(item):
    if not isinstance(item, dict) or item.get('collection_status', 'collected') not in ('collected', 'empty'):
        raise Incomplete('object metadata is unavailable')
    _usable_fields(item, ('metadata', 'roleRef', 'subjects', 'secrets', 'spec', 'template', 'type'))
    meta = item.get('metadata')
    if not isinstance(meta, dict) or not all(isinstance(meta.get(k), str) and meta[k] for k in ('name', 'uid')):
        raise Incomplete('object name or UID is unavailable')
    _usable_fields(meta, ('name', 'uid', 'namespace', 'labels', 'annotations', 'creationTimestamp'))
    if not isinstance(meta.get('namespace', ''), str):
        raise Incomplete('object namespace is malformed')
    return meta


def _context(index):
    context = index.get('context', {})
    cluster = context.get('metadata', {}).get('cluster_id')
    if context.get('provider') != 'k8s' or not isinstance(context.get('scope'), str) or not isinstance(cluster, str) or not cluster:
        raise Incomplete('Kubernetes capture authority is unavailable')
    return context, cluster


def _rows(index, kind):
    context, cluster = _context(index)
    envelopes = index.get('collections', {}).get(kind)
    if not isinstance(envelopes, list) or len(envelopes) != 1:
        raise Incomplete('complete inventory is unavailable: ' + kind)
    envelope = envelopes[0]
    if (envelope.get('type') != kind or envelope.get('scope') != context['scope']
            or envelope.get('service') != 'kubernetes' or envelope.get('status') not in ('collected', 'empty')):
        raise Incomplete('inventory is incomplete or outside the capture scope: ' + kind)
    if kind in ('clusterrole', 'clusterrolebinding') and context['scope'] != '*':
        raise Incomplete('cluster-wide RBAC inventory is required')
    rows = envelope.get('items')
    projected = index.get(kind)
    if (not isinstance(rows, list) or not isinstance(projected, list)
            or (envelope['status'] == 'empty') != (not rows)
            or any(not isinstance(row, dict) or row.get('type') != kind or row.get('scope') != context['scope'] for row in projected)
            or [row.get('data') for row in projected] != rows):
        raise Incomplete('inventory and resource projection disagree: ' + kind)
    seen = set()
    for row in rows:
        meta = _meta(row)
        proof = row.get('provenance', {})
        if kind not in ('clusterrole', 'clusterrolebinding') and not meta.get('namespace'):
            raise Incomplete('namespaced object has no namespace: ' + kind)
        identity = meta.get('namespace', ''), meta['name']
        if (identity in seen or proof.get('cluster_id') != cluster or proof.get('uid') != meta['uid']
                or proof.get('evidence') != 'read-only list'):
            raise Incomplete('duplicate, foreign or unbound inventory object: ' + kind)
        if meta.get('namespace') and context['scope'] != '*' and meta['namespace'] != context['scope']:
            raise Incomplete('object is outside the selected namespace: ' + kind)
        seen.add(identity)
    return rows


def _current(item, index, kind):
    meta = _meta(item)
    if not any(row == item for row in _rows(index, kind)):
        raise Incomplete('assessed object is not the captured inventory object')
    return meta


def _ref(binding, cluster_binding):
    meta = _meta(binding)
    ref = binding.get('roleRef')
    kinds = ('ClusterRole',) if cluster_binding else ('Role', 'ClusterRole')
    if not isinstance(ref, dict) or ref.get('apiGroup') != GROUP or ref.get('kind') not in kinds or not isinstance(ref.get('name'), str) or not ref['name']:
        raise Incomplete('RBAC role reference is malformed')
    return ref, meta


def _selector_matches(selector, labels):
    if not isinstance(selector, dict) or set(selector) - {'matchLabels', 'matchExpressions'} or not isinstance(labels, dict):
        raise Incomplete('ClusterRole aggregation selector is malformed')
    matches = selector.get('matchLabels', {})
    expressions = selector.get('matchExpressions', [])
    if not isinstance(matches, dict) or not isinstance(expressions, list):
        raise Incomplete('ClusterRole aggregation selector is malformed')
    if any(not isinstance(k, str) or not isinstance(v, str) for k, v in matches.items()):
        raise Incomplete('ClusterRole aggregation matchLabels is malformed')
    result = all(labels.get(k) == v for k, v in matches.items())
    for expression in expressions:
        if not isinstance(expression, dict) or set(expression) - {'key', 'operator', 'values'}:
            raise Incomplete('ClusterRole aggregation expression is malformed')
        key, op, values = expression.get('key'), expression.get('operator'), expression.get('values', [])
        if not isinstance(key, str) or not key or not isinstance(values, list) or any(not isinstance(v, str) for v in values):
            raise Incomplete('ClusterRole aggregation expression is malformed')
        if op in ('In', 'NotIn') and not values or op in ('Exists', 'DoesNotExist') and values:
            raise Incomplete('ClusterRole aggregation expression values are invalid')
        if op == 'In': match = key in labels and labels[key] in values
        elif op == 'NotIn': match = key not in labels or labels[key] not in values
        elif op == 'Exists': match = key in labels
        elif op == 'DoesNotExist': match = key not in labels
        else: raise Incomplete('ClusterRole aggregation operator is unknown')
        result = result and match
    return result


def role_consumers(item, index, *, cluster=False):
    kind = 'clusterrole' if cluster else 'role'
    meta = _current(item, index, kind)
    consumers = []
    for binding_kind in (('rolebinding', 'clusterrolebinding') if cluster else ('rolebinding',)):
        for binding in _rows(index, binding_kind):
            ref, binding_meta = _ref(binding, binding_kind == 'clusterrolebinding')
            if ref['kind'] == ('ClusterRole' if cluster else 'Role') and ref['name'] == meta['name'] and (cluster or binding_meta.get('namespace') == meta.get('namespace')):
                subjects = binding.get('subjects', [])
                if not isinstance(subjects, list):
                    raise Incomplete('RBAC subjects are malformed')
                for subject in subjects:
                    if not isinstance(subject, dict) or not isinstance(subject.get('name'), str) or not subject['name']:
                        raise Incomplete('RBAC consumer subject is malformed')
                    if subject.get('kind') == 'ServiceAccount':
                        namespace = subject.get('namespace') or (binding_meta.get('namespace') if binding_kind == 'rolebinding' else None)
                        if subject.get('apiGroup', '') != '' or not isinstance(namespace, str) or not namespace:
                            raise Incomplete('RBAC consumer ServiceAccount namespace is unavailable')
                    elif subject.get('kind') not in ('User', 'Group') or subject.get('apiGroup') != GROUP:
                        raise Incomplete('RBAC consumer subject kind or API group is malformed')
                if subjects:
                    consumers.append({'kind': binding_kind, 'namespace': binding_meta.get('namespace'), 'name': binding_meta['name']})
    if cluster:
        for other in _rows(index, 'clusterrole'):
            if _meta(other)['uid'] == meta['uid']:
                continue
            aggregation = other.get('aggregationRule')
            if aggregation is not None:
                if not isinstance(aggregation, dict) or not isinstance(aggregation.get('clusterRoleSelectors'), list):
                    raise Incomplete('ClusterRole aggregation rule is malformed')
                for selector in aggregation['clusterRoleSelectors']:
                    if _selector_matches(selector, meta.get('labels', {})):
                        consumers.append({'kind': 'aggregated_clusterrole', 'name': _meta(other)['name']})
                        break
    name = '/'.join(v for v in (meta.get('namespace'), meta['name']) if v)
    return ('PASS' if consumers else 'FAIL'), {'resource_name': name, 'consumers': consumers,
        'reason': 'recorded RBAC consumer exists' if consumers else 'no recorded binding or aggregation consumes this role',
        'summary': f'{kind.title()} {name} has ' + ('a recorded RBAC consumer.' if consumers else 'no recorded RBAC consumer.') +
        ('\nIts permission definition is linked to an existing RBAC declaration.\nThis provides a recorded reason to retain the role.' if consumers else
         '\nIts permission definition remains after any captured consumer is absent.\nA future binding could grant these permissions without creating a new role.')}


def binding_subjects(item, index, *, cluster=False):
    kind = 'clusterrolebinding' if cluster else 'rolebinding'
    meta = _current(item, index, kind)
    _ref(item, cluster)
    subjects = item.get('subjects', [])
    if not isinstance(subjects, list):
        raise Incomplete('RBAC subjects are malformed')
    accounts = {(_meta(row).get('namespace'), _meta(row)['name']) for row in _rows(index, 'serviceaccount')}
    missing, external = [], []
    for subject in subjects:
        if not isinstance(subject, dict) or not isinstance(subject.get('name'), str) or not subject['name']:
            raise Incomplete('RBAC subject identity is malformed')
        if subject.get('kind') == 'ServiceAccount':
            ns = subject.get('namespace') or (None if cluster else meta.get('namespace'))
            if subject.get('apiGroup', '') != '' or not isinstance(ns, str) or not ns:
                raise Incomplete('ServiceAccount subject namespace is unavailable')
            if (ns, subject['name']) not in accounts:
                if _context(index)[0]['scope'] != '*' and ns != _context(index)[0]['scope']:
                    external.append('ServiceAccount:' + ns + '/' + subject['name'])
                else:
                    missing.append(ns + '/' + subject['name'])
        elif subject.get('kind') in ('User', 'Group') and subject.get('apiGroup') == GROUP:
            external.append(subject['kind'] + ':' + subject['name'])
        else:
            raise Incomplete('RBAC subject kind or API group is malformed')
    evidence = {'missing_service_accounts': missing, 'external_subjects': external,
                'subject_count': len(subjects)}
    if not subjects or missing:
        return 'FAIL', {**evidence, 'reason': 'binding has no subjects' if not subjects else 'binding names a missing ServiceAccount',
            'summary': f'Binding {meta["name"]} ' + ('has no subjects.' if not subjects else 'names missing ServiceAccounts: '+', '.join(missing)+'.') +
            '\nIts permission grant remains declared after the intended identity is absent.\nRecreating an identity with a referenced name could restore that grant.'}
    if external:
        return 'UNKNOWN', {**evidence, 'reason': 'external subject existence requires identity-provider inventory',
            'summary': f'Binding {meta["name"]} references external subjects: '+', '.join(external)+'.\nDirectory identity data for those subjects is unavailable.\nIt is unclear whether these grants still belong to active identities.'}
    return 'PASS', {**evidence, 'reason': 'all ServiceAccount subjects exist in the captured scope',
        'summary': f'Binding {meta["name"]} references {len(subjects)} existing ServiceAccount subjects.\nTheir names and namespaces match the current identity inventory.\nNo missing ServiceAccount target was found in this binding.'}


def account_consumers(item, index):
    meta = _current(item, index, 'serviceaccount')
    consumers = []
    for kind, path in WORKLOAD_PATHS.items():
        for workload in _rows(index, kind):
            wm = _meta(workload)
            spec = workload
            for key in path:
                if not isinstance(spec, dict) or key not in spec:
                    raise Incomplete('workload PodSpec is unavailable: ' + kind)
                spec = spec[key]
            if not isinstance(spec, dict):
                raise Incomplete('workload PodSpec is malformed: ' + kind)
            account = spec.get('serviceAccountName', spec.get('serviceAccount', 'default')) or 'default'
            if not isinstance(account, str) or ('serviceAccount' in spec and 'serviceAccountName' in spec and spec['serviceAccount'] != spec['serviceAccountName']):
                raise Incomplete('workload ServiceAccount declaration is malformed')
            if wm.get('namespace') == meta.get('namespace') and account == meta['name']:
                consumers.append({'kind': kind, 'namespace': wm.get('namespace'), 'name': wm['name']})
    for kind in ('rolebinding', 'clusterrolebinding'):
        for binding in _rows(index, kind):
            _ref(binding, kind == 'clusterrolebinding')
            bm = _meta(binding)
            subjects = binding.get('subjects', [])
            if not isinstance(subjects, list):
                raise Incomplete('RBAC subjects are malformed')
            for subject in subjects:
                if not isinstance(subject, dict) or not isinstance(subject.get('name'), str) or not subject['name']:
                    raise Incomplete('RBAC subject identity is malformed')
                matches = False
                if subject.get('kind') == 'ServiceAccount':
                    ns = subject.get('namespace') or (bm.get('namespace') if kind == 'rolebinding' else None)
                    if subject.get('apiGroup', '') != '' or not isinstance(ns, str) or not ns:
                        raise Incomplete('ServiceAccount subject namespace is unavailable')
                    matches = (ns, subject['name']) == (meta.get('namespace'), meta['name'])
                elif subject.get('kind') in ('User', 'Group') and subject.get('apiGroup') == GROUP:
                    matches = (subject['kind'] == 'User' and subject['name'] == 'system:serviceaccount:' + meta.get('namespace', '') + ':' + meta['name'] or
                               subject['kind'] == 'Group' and subject['name'] in ('system:authenticated', 'system:serviceaccounts', 'system:serviceaccounts:' + meta.get('namespace', '')))
                else:
                    raise Incomplete('RBAC subject kind or API group is malformed')
                if matches:
                    consumers.append({'kind': kind, 'namespace': bm.get('namespace'), 'name': bm['name']})
    for secret in _rows(index, 'secret_metadata'):
        sm = _meta(secret)
        annotations = sm.get('annotations', {})
        if not isinstance(annotations, dict):
            raise Incomplete('Secret annotations are malformed')
        if (secret.get('type') == 'kubernetes.io/service-account-token' and sm.get('namespace') == meta.get('namespace')
                and annotations.get('kubernetes.io/service-account.name') == meta['name']
                and annotations.get('kubernetes.io/service-account.uid') == meta['uid']):
            consumers.append({'kind': 'legacy_token', 'name': sm['name']})
    annotations = meta.get('annotations', {})
    if not isinstance(annotations, dict):
        raise Incomplete('ServiceAccount annotations are malformed')
    for key in ('eks.amazonaws.com/role-arn', 'iam.gke.io/gcp-service-account', 'azure.workload.identity/client-id'):
        if isinstance(annotations.get(key), str) and annotations[key]:
            consumers.append({'kind': 'workload_identity_association', 'annotation': key})
    name = meta['namespace'] + '/' + meta['name']
    return ('PASS' if consumers else 'FAIL'), {'resource_name': name, 'consumers': consumers,
        'reason': 'recorded identity consumer exists' if consumers else 'no recorded workload, RBAC, token or cloud-identity consumer',
        'summary': f'ServiceAccount {name} ' + ('has a recorded consumer.' if consumers else 'has no recorded workload, RBAC, token or cloud-identity consumer.') +
        ('\nIts identity is associated with an existing workload, permission grant or credential.\nThat declaration provides a recorded reason to retain the identity.' if consumers else
         '\nAn unreferenced identity can remain after its application has been removed.\nExternal clients may still use this identity; this finding identifies missing configuration references.')}


def token_activity(item, index):
    _current(item, index, 'secret_metadata')
    accounts = _rows(index, 'serviceaccount')
    meta = _meta(item)
    name = meta.get('annotations', {}).get('kubernetes.io/service-account.name')
    account = next((row for row in accounts if _meta(row)['name'] == name and _meta(row).get('namespace') == meta.get('namespace')), None)
    return legacy_token_usage(item, observed_at=_context(index)[0].get('created_at'), service_account=account)


def guarded(function, item, index):
    try:
        return function(item, index)
    except (Incomplete, TypeError, KeyError, AttributeError, ValueError) as exc:
        meta = item.get('metadata', {}) if isinstance(item, dict) else {}
        name = meta.get('name', 'unnamed object') if isinstance(meta, dict) else 'unnamed object'
        return 'UNKNOWN', {'reason': str(exc), 'summary': f'Current identity references for {name} are unresolved: {exc}.\nMissing identity or RBAC inventory prevents a reliable unused-object decision.\nAn obsolete identity or grant could remain after its original consumer is removed.'}


def evaluate_role(item, index):
    return guarded(partial(role_consumers, cluster=False), item, index)


def evaluate_clusterrole(item, index):
    return guarded(partial(role_consumers, cluster=True), item, index)


def evaluate_rolebinding(item, index):
    return guarded(partial(binding_subjects, cluster=False), item, index)


def evaluate_clusterrolebinding(item, index):
    return guarded(partial(binding_subjects, cluster=True), item, index)


def evaluate_account(item, index):
    return guarded(account_consumers, item, index)


def evaluate_token(item, index):
    status, evidence = guarded(token_activity, item, index)
    meta = item.get('metadata', {}) if isinstance(item, dict) else {}
    name = '/'.join(str(meta.get(key, '')) for key in ('namespace', 'name')) if isinstance(meta, dict) else 'unknown'
    if status == 'FAIL':
        evidence['summary'] = f'Legacy token {name} was last used on {evidence["last_used_date"]}.\nThat recorded day is more than 90 days before the captured observation.\nA leftover long-lived token may retain access if it remains valid.'
    elif status == 'PASS':
        evidence['summary'] = f'Legacy token {name} has recorded use on {evidence["last_used_date"]}.\nIt is within the 90-day inactivity threshold.\nIts usage metadata does not indicate an abandoned token in this interval.'
    elif status == 'NOT_APPLICABLE':
        evidence['summary'] = f'Secret {name} has type {item.get("type")}.\nThis identity usage control applies to legacy ServiceAccount tokens.\nThis Secret has a different credential lifecycle.'
    elif 'summary' not in evidence:
        evidence['summary'] = f'Usage for token {name} is unresolved: {evidence.get("reason", "metadata unavailable")}.\nIts last successful authentication cannot be dated from the available metadata.\nA leftover token could retain access if it remains valid.'
    return status, evidence


DECLARATIONS = (
    ('k8s.iam.serviceaccount_has_declared_consumers', 'serviceaccount', 'ServiceAccount has a declared identity consumer', evaluate_account, ('serviceaccount', *WORKLOAD_PATHS, 'rolebinding', 'clusterrolebinding', 'secret_metadata')),
    ('k8s.iam.role_has_declared_consumers', 'role', 'Role has a declared RBAC consumer', evaluate_role, ('role', 'rolebinding')),
    ('k8s.iam.clusterrole_has_declared_consumers', 'clusterrole', 'ClusterRole has a declared binding or aggregation consumer', evaluate_clusterrole, ('clusterrole', 'rolebinding', 'clusterrolebinding')),
    ('k8s.iam.rolebinding_subjects_exist', 'rolebinding', 'RoleBinding has existing subjects', evaluate_rolebinding, ('rolebinding', 'serviceaccount')),
    ('k8s.iam.clusterrolebinding_subjects_exist', 'clusterrolebinding', 'ClusterRoleBinding has existing subjects', evaluate_clusterrolebinding, ('clusterrolebinding', 'serviceaccount')),
    ('k8s.iam.legacy_serviceaccount_token_recently_used', 'secret_metadata', 'Tracked legacy ServiceAccount token was used within 90 days', evaluate_token, ('secret_metadata', 'serviceaccount')),
)


def install(registry):
    """Install through the normal native registrar after source admission."""
    import json
    from pathlib import Path
    from peaso.checks.fixtures import CASES
    raw = Path(__file__).with_name('checks').joinpath('unused_iam_k8s_cases.json').read_bytes()
    cases = json.loads(raw)
    if set(cases) != {row[0] for row in DECLARATIONS}:
        raise ValueError('unused Kubernetes IAM fixture IDs differ from registration')
    for ident, kind, title, predicate, dependencies in DECLARATIONS:
        registry.register(ident, 'k8s', 'hardening', kind, title, 'low', 'AC-2',
            'Confirm the identity or grant owner and remove obsolete objects; replace long-lived tokens with short-lived TokenRequest credentials.',
            dependencies=dependencies)(predicate)
        CASES[ident] = cases[ident]

