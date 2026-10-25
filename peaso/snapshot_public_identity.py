"""Keep trusted native envelope routing identifiers stable across redaction.

Only registered inventory names and canonical scope syntax are exempted. Native
resource payloads and errors still pass through the original privacy callback.
"""
from importlib import import_module
import re


def _known_types(provider):
    if provider not in {'aws', 'gcp', 'azure', 'k8s'}:
        raise ValueError('Unsupported native snapshot provider')
    module = import_module('peaso.collectors.' + provider)
    native = set(getattr(module, 'AWS_TYPES', getattr(module, 'SUPPORTED_TYPES',
                 getattr(module, 'TYPES', ()))))
    # These reviewed post-collection enrichers add usage envelopes after the
    # provider collector's ordinary TYPES inventory has finished.
    if provider in {'gcp', 'azure'}:
        native.add('iam_usage_activity')
    if provider == 'azure':
        # Exact transient Reader.run jobs are checkpointed before their
        # reviewed adapters fold them into public native inventories.
        native.update({'_native_vpn_connection_rg', '_native_access_review_instance',
                       '_native_access_review_decision'})
    from .collectors.bulk_evidence import ALIASES, declared_types
    return frozenset(native | declared_types(provider) | set(ALIASES[provider]))


def _azure_scope(scope):
    # Azure emits canonical resource scopes for diagnostics/routes, and exact
    # Graph parent identities for child inventories, not just subscription IDs.
    if scope in {'/', '*'}:
        return True
    if not isinstance(scope, str) or len(scope) > 8192 or any(
            ord(char) < 32 or ord(char) == 127 for char in scope):
        return False
    if any(segment in {'.', '..'} for segment in scope.split('/')):
        return False
    identity = r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}'
    guid = r'[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}'
    if re.fullmatch(r'/(?i:tenants)/' + identity +
            r'(?:/' + guid + r'|/(?i:servicePrincipals|applications|groups|users|administrativeUnits|directoryRoles|roleDefinitions)/' + guid + r')?', scope):
        return True
    segment = r'[A-Za-z0-9_().%+@=,-]{1,256}'
    root = r'/(?i:subscriptions)/' + identity
    group = r'(?:/(?i:resourceGroups)/' + segment + r')?'
    # Provider namespaces followed by native resource-type/name pairs. Nested
    # provider blocks remain canonical ARM IDs; arbitrary URLs never match.
    resource = r'(?:/(?i:providers)/[A-Za-z][A-Za-z0-9_.-]{0,127}(?:/[A-Za-z][A-Za-z0-9_.-]{0,127}/' + segment + r')+)'
    return re.fullmatch(root + group + r'(?:' + resource + r')*', scope) is not None


def _canonical_scope(provider, scope):
    if not isinstance(scope, str):
        return False
    if provider == 'azure':
        return _azure_scope(scope)
    if provider == 'k8s':
        # Kubernetes identity authority is exact connector membership below.
        return False
    patterns = {
        'aws': r'[0-9]{12}/(?:global|[a-z]{2}(?:-[a-z]+)+-[0-9]+)',
        'gcp': r'(?:\*|(?:projects|organizations|folders)/[A-Za-z0-9][A-Za-z0-9._:-]{0,127})',
    }
    return re.fullmatch(patterns[provider], scope) is not None


def public_snapshot_adapter(callback, *, provider, trusted_scopes=()):
    """Wrap a trusted privacy callback without exempting arbitrary user strings.

    The caller supplies native snapshots, already structurally validated by the
    native builder. The in-repository callback must preserve collection order;
    cardinality changes or provable canonical reordering fail closed.
    Every collection type must also belong to the active native
    or reviewed inventory registry. Canonical native scope syntax is preserved. AWS account-wide rows must
    additionally belong to an account already declared by the snapshot. GCP
    ancestor scopes and Azure directory/root scopes retain their native IDs.
    """
    known_types = _known_types(provider)
    # Kubernetes names may be selected contexts, not DNS namespace labels.
    # Their only authority is exact membership in the validated connector.
    if not isinstance(trusted_scopes, (list, tuple, set, frozenset)) or len(trusted_scopes) > 10000:
        raise ValueError('Invalid trusted native scope collection')
    trusted_scopes = tuple(trusted_scopes)
    if any(not isinstance(scope, str) or not scope or len(scope) > 2048
           or any(ord(char) < 32 or ord(char) == 127 for char in scope)
           for scope in trusted_scopes):
        raise ValueError('Invalid trusted native scope')
    trusted_scopes = frozenset(trusted_scopes)

    def public_snapshot(snapshot):
        if not isinstance(snapshot, dict) or snapshot.get('provider') != provider:
            raise ValueError('Invalid native snapshot provider')
        scopes = snapshot.get('scopes')
        rows = snapshot.get('collections')
        if not isinstance(scopes, list) or not isinstance(rows, list):
            raise ValueError('Invalid native snapshot structure')
        canonical_scopes = tuple(scopes)
        def valid_scope(scope):
            if provider == 'k8s':
                return isinstance(scope, str) and scope in trusted_scopes
            return _canonical_scope(provider, scope)
        if not all(valid_scope(scope) for scope in canonical_scopes):
            raise ValueError('Invalid native snapshot scope')
        accounts = {scope.split('/')[0] for scope in canonical_scopes} if provider == 'aws' else set()
        identities = []
        for row in rows:
            if not isinstance(row, dict) or row.get('type') not in known_types:
                raise ValueError('Unregistered native collection type')
            scope = row.get('scope')
            global_clock = provider == 'k8s' and row['type'] == 'node_clock' and scope == '*'
            if (not valid_scope(scope) and not global_clock) or (provider == 'k8s' and scope not in canonical_scopes and not global_clock) or (provider == 'aws'
                    and scope not in canonical_scopes and not (scope.endswith('/global')
                    and scope.split('/')[0] in accounts)):
                raise ValueError('Native collection scope is outside the snapshot')
            identities.append((row['type'], scope))
        public = callback(snapshot)
        if not isinstance(public, dict) or not isinstance(public.get('collections'), list):
            raise ValueError('Invalid public snapshot structure')
        if len(public['collections']) != len(identities):
            raise ValueError('Privacy callback changed native collection cardinality')
        identity_positions = {identity: index for index, identity in enumerate(identities)}
        for index, row in enumerate(public['collections']):
            if isinstance(row, dict):
                observed = (row.get('type'), row.get('scope'))
                # The in-repository callback preserves order. An unchanged
                # canonical identity at another slot proves that contract broke.
                if observed in identity_positions and identity_positions[observed] != index:
                    raise ValueError('Privacy callback reordered native collections')
        changed = public.get('provider') != provider or public.get('scopes') != list(canonical_scopes)
        for row, (kind, scope) in zip(public['collections'], identities):
            if not isinstance(row, dict):
                raise ValueError('Invalid public collection structure')
            changed |= row.get('type') != kind or row.get('scope') != scope
        if not changed:
            return public
        # Copy only the shallow routing containers before seal owns its normal
        # independent structural copy. Never edit callback-owned/input objects.
        repaired = dict(public)
        repaired['provider'] = provider
        repaired['scopes'] = list(canonical_scopes)
        repaired['collections'] = [dict(row, type=kind, scope=scope)
            for row, (kind, scope) in zip(public['collections'], identities)]
        from .snapshot import seal
        return seal(repaired)

    return public_snapshot
