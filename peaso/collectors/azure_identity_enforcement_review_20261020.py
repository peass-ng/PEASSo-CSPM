"""Native read-only inputs and bounded successor for four signed SW19 controls.

No caller-supplied effective-role or MFA resolution flags are manufactured. The
adapter interprets source-bound API inventories at evaluation time. Unsupported
conditions remain unresolved, including Security Defaults context applicability.
"""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import re
import sys
from urllib.parse import quote, urlencode

from . import azure_sw18_mfa_native as sw18

KIND = 'azure_identity_enforcement_native'
CIS = 'azure.cis.multifactor_auth_status_privileged_users'
DIRECT = 'azure_directory_user_7_2_1_19_28e2aa7'
ALL = 'azure_directory_user_entra_non_privileged_user_has_mfa_b242ca9'
ADMIN = 'azure_directory_user_entra_privileged_user_has_mfa_6f6d584'
IDS = frozenset((CIS, DIRECT, ALL, ADMIN))
GLOBAL_ADMIN = '62e90394-69f5-4237-9190-012177145e10'
GRAPH = 'https://graph.microsoft.com'
ARM = 'https://management.azure.com'
ADAPTER = 'native-identity-enforcement-v1'
GRAPH_READS = {
    'users': '/v1.0/users?$select=id,accountEnabled',
    'registration': '/v1.0/reports/authenticationMethods/userRegistrationDetails?$select=id,isMfaCapable,isMfaRegistered',
    'roles': '/v1.0/roleManagement/directory/roleAssignments',
    'definitions': '/v1.0/roleManagement/directory/roleDefinitions',
    'privilege_definitions': '/beta/roleManagement/directory/roleDefinitions?$select=id,isPrivileged',
    'active': '/v1.0/roleManagement/directory/roleAssignmentScheduleInstances',
    'eligible': '/v1.0/roleManagement/directory/roleEligibilityScheduleInstances',
}
ARM_READS = {'assigned': ('roleAssignments', '2022-04-01'),
             'active': ('roleAssignmentScheduleInstances', '2020-10-01'),
             'eligible': ('roleEligibilityScheduleInstances', '2020-10-01')}
BASE_KINDS = ('directory_user', 'conditional_access_policy', 'directory_security_defaults',
              'user_registration_detail', 'directory_group', 'directory_user_group_membership',
              'authentication_strength', 'conditional_access_group_membership')


def required_types(wanted):
    return set(BASE_KINDS) if KIND in wanted else set()


def _guid(value):
    return sw18._id(value)


def _rows(reader, request, endpoint, *, graph=True, opaque=False):
    """Preserve every page and reject duplicates before shared reader deduplication."""
    audience = GRAPH if graph else ARM
    result, seen = [], set()
    for page in reader.pages(request, audience + endpoint, audience=audience,
                             next_key='@odata.nextLink' if graph else 'nextLink'):
        for row in page:
            rid = sw18._opaque(row.get('id')) if opaque or not graph else _guid(row.get('id'))
            rid = rid.casefold()
            if rid in seen:
                raise ValueError('duplicate native identity')
            seen.add(rid)
            result.append(row)
    return result


def _source_specs(native, scope):
    def read(name, endpoint, *, graph=True, opaque=False, singleton=False):
        return name, endpoint, graph, opaque, singleton
    # These exact SW18 source APIs and its temporal/identity helpers are reused;
    # the raw sources are retained, not its consumer-specific resolved flags.
    for name, endpoint in GRAPH_READS.items():
        yield read(name, endpoint, opaque=name in ('roles', 'active', 'eligible'))
    users = [r for c in native if c.get('type') == 'directory_user' and c.get('scope', '').casefold() == scope
             and c.get('status') in ('collected', 'empty') for r in c['items']]
    groups = [r for c in native if c.get('type') == 'directory_group' and c.get('scope', '').casefold() == scope
              and c.get('status') in ('collected', 'empty') for r in c['items']]
    for group in groups:
        if group.get('isAssignableToRole') is True and isinstance(group.get('id'), str) and sw18.GUID.fullmatch(group['id']):
            yield read('owners:' + _guid(group['id']), '/v1.0/groups/' + _guid(group['id']) + '/owners?$select=id')
    principals = set()
    for row in users + groups:
        try:
            principals.add(_guid(row.get('id')))
        except ValueError:
            continue  # The evaluator rejects the malformed authoritative inventory.
    for uid in sorted({_guid(u['id']) for u in users if isinstance(u.get('id'), str) and sw18.GUID.fullmatch(u['id'])}):
        yield read('requirements:' + uid, '/beta/users/' + uid + '/authentication/requirements', singleton=True)
    for pid in sorted(principals):
        for name in ('eligibilityScheduleInstances', 'assignmentScheduleInstances'):
            yield read('group_' + name + ':' + pid,
                 '/v1.0/identityGovernance/privilegedAccess/group/' + name + '?' + urlencode({'$filter': "principalId eq '" + pid + "'"}), opaque=True)
        for name, (operation, version) in ARM_READS.items():
            # A root principal filter is documented to include at/above/below
            # the scope. Selected-subscription inventories cannot prove absence
            # elsewhere in the tenant. Denial of this root query stays UNKNOWN.
            yield read('arm_' + name + ':' + pid,
                 '/providers/Microsoft.Authorization/' + operation + '?' + urlencode({'api-version': version, '$filter': "principalId eq '" + pid + "'"}), graph=False)


def prefetch(reader, request, wanted, transport):
    """Look ahead at exact late source lists after directory parents settle.

    Each audience has at most64 streams/four producers/one queued page per
    stream. Unscheduled and singleton sources retain their ordinary late read.
    """
    if KIND not in wanted or reader.workers <= 1 or reader.explicit_limits:
        return ()
    try:
        tenant = _guid(getattr(transport, 'verified_tenant', None))
        if _guid(getattr(transport, 'tenant', None)) != tenant:
            return ()
    except ValueError:
        return ()  # The late collector owns the typed unavailable row.
    native = [c for c in reader.collections if c.get('type') in BASE_KINDS]
    from itertools import islice
    from .azure_page_prefetch import PagePrefetch
    managers = []
    try:
        for graph, attribute in ((True, 'identity_graph_prefetch'), (False, 'identity_arm_prefetch')):
            audience = GRAPH if graph else ARM
            specs = _source_specs(native, '/tenants/' + tenant)
            urls = list(islice((audience + endpoint for _, endpoint, is_graph, _, singleton in specs
                               if is_graph == graph and not singleton), 64))
            if not urls:
                continue
            manager = PagePrefetch(reader, request, urls, audience, lookahead=1,
                                   next_key='@odata.nextLink' if graph else 'nextLink')
            managers.append(manager)
            setattr(reader, attribute, manager)
            manager.start()
    except BaseException:
        for manager in managers:
            manager.close()
        raise
    return tuple(managers)


def collect(reader, request, scopes, wanted, transport, credential_context_id, customer_context_id):
    if KIND not in wanted:
        return
    from .azure import _safe_error, ordered_parallel
    tenant = getattr(transport, 'verified_tenant', None)
    try:
        tenant = _guid(tenant)
        if _guid(getattr(transport, 'tenant', None)) != tenant:
            raise ValueError('selected and authenticated tenants differ')
    except ValueError as exc:
        reader.unavailable(KIND, '/tenants/unverified', 'Microsoft.Graph', exc)
        return
    scope = '/tenants/' + tenant
    proof = {'read_only': True, 'tenant_verified': True, 'tenant_id': tenant,
             'credential_context_id': credential_context_id, 'customer_context_id': customer_context_id,
             'adapter': ADAPTER, 'endpoint': 'native-input-projection',
             'observed_at': datetime.now(timezone.utc).isoformat()}
    sources = []
    pending = []
    def fetch(spec):
        name, endpoint, graph, opaque, singleton = spec
        source = {'name': name, 'endpoint': endpoint, 'audience': GRAPH if graph else ARM,
                  'method': 'GET', 'body': None, 'items': [], 'status': 'not_collected'}
        try:
            if singleton:
                value = reader.call(request, source['audience'] + endpoint, audience=source['audience'])
                if not isinstance(value, dict):
                    raise ValueError('malformed native singleton')
                source['items'] = [value]
            else:
                source['items'] = _rows(reader, request, endpoint, graph=graph, opaque=opaque)
            source['status'] = 'collected' if source['items'] else 'empty'
        except Exception as exc:
            source['status'], source['error'] = _safe_error(exc)
        return source
    def read(name, endpoint, *, graph=True, opaque=False, singleton=False):
        pending.append((name, endpoint, graph, opaque, singleton))
    def settle():
        # Independent per-subject reads run bounded in parallel; sources keep
        # the exact serial request order.
        specs = list(pending)
        pending.clear()
        for ok, source in ordered_parallel(reader, fetch, specs):
            if not ok:
                raise source
            sources.append(source)
    native = [deepcopy(c) for c in reader.collections if c.get('type') in BASE_KINDS]
    pending.extend(_source_specs(native, scope))
    settle()
    # Authenticate each returned ARM subscription/management-group scope using
    # a native parent read; never guess a subscription's tenant from the token.
    bound = set()
    for source in list(sources):
        if not source['name'].startswith('arm_') or source['status'] not in ('collected', 'empty'):
            continue
        for row in source['items']:
            actual = row.get('properties', {}).get('scope')
            if not isinstance(actual, str):
                continue
            match = re.match(r'(/subscriptions/[0-9a-f-]{36})(?:/|$)', actual, re.I)
            mg = re.match(r'(/providers/Microsoft.Management/managementGroups/[^/?#]+)(?:/|$)', actual, re.I)
            parent = match.group(1) if match else mg.group(1) if mg else None
            if parent and parent.casefold() not in bound:
                bound.add(parent.casefold())
                read('binding:' + parent.casefold(), parent + '?api-version=' + ('2022-12-01' if match else '2020-05-01'), graph=False, singleton=True)
    settle()
    # The last native source is settled. Stop producer threads and release
    # their buffers/failed frames before snapshot sealing copies native items.
    for attribute in ('identity_graph_prefetch', 'identity_arm_prefetch'):
        manager = getattr(reader, attribute, None)
        if manager is not None:
            manager.close()
    row = {'id': scope + '#identity-enforcement', 'native_collections': native,
           'sources': sources, '_provenance': proof}
    reader.run([(KIND, scope, 'Microsoft.Graph', lambda: iter([[row]]))])
    reader.collections[-1].setdefault('_provenance', {}).update(proof)


def _require(value, message):
    if not value:
        from ..checks.facts import Unavailable
        raise Unavailable(message)


def _unique(rows, *, guid=True):
    _require(isinstance(rows, list) and all(isinstance(r, dict) for r in rows), 'malformed native rows')
    result = {}
    for row in rows:
        try:
            rid = _guid(row.get('id')) if guid else sw18._opaque(row.get('id')).casefold()
        except ValueError as exc:
            _require(False, str(exc))
        _require(rid not in result, 'duplicate native subject')
        result[rid] = row
    return result


def _source(projection, name):
    rows = [s for s in projection['sources'] if s.get('name') == name]
    _require(len(rows) == 1, 'missing or duplicate native source: ' + name)
    source = rows[0]
    if name in GRAPH_READS:
        expected, audience = GRAPH_READS[name], GRAPH
    elif name.startswith('requirements:'):
        expected, audience = '/beta/users/' + _guid(name.split(':', 1)[1]) + '/authentication/requirements', GRAPH
    elif name.startswith('owners:'):
        expected, audience = '/v1.0/groups/' + _guid(name.split(':', 1)[1]) + '/owners?$select=id', GRAPH
    elif name.startswith('group_'):
        operation, pid = name[len('group_'):].split(':', 1)
        _require(operation in ('eligibilityScheduleInstances', 'assignmentScheduleInstances'), 'unknown PIM group source')
        expected, audience = '/v1.0/identityGovernance/privilegedAccess/group/' + operation + '?' + urlencode({'$filter': "principalId eq '" + _guid(pid) + "'"}), GRAPH
    elif name.startswith('arm_'):
        operation, pid = name[len('arm_'):].split(':', 1)
        _require(operation in ARM_READS, 'unknown ARM grant source')
        api, version = ARM_READS[operation]
        expected, audience = '/providers/Microsoft.Authorization/' + api + '?' + urlencode({'api-version': version, '$filter': "principalId eq '" + _guid(pid) + "'"}), ARM
    elif name.startswith('binding:'):
        parent = name.split(':', 1)[1]
        expected, audience = parent + '?api-version=' + ('2022-12-01' if parent.startswith('/subscriptions/') else '2020-05-01'), ARM
    else:
        _require(False, 'unknown native source')
    _require(source.get('endpoint', '').casefold() == expected.casefold() and source.get('audience') == audience, 'native source request scope differs')
    _require(source.get('status') in ('collected', 'empty') and isinstance(source.get('items'), list)
             and (source['status'] == 'empty') == (not source['items']), 'incomplete native source: ' + name)
    _require(source.get('method') == 'GET' and source.get('body') is None, 'native source was not read-only')
    return source['items']


def _native_index(projection, context):
    """Build the same scoped native index accepted by existing source13 helpers."""
    native = projection['native_collections']
    _require(isinstance(native, list), 'native collection projection missing')
    index = {'context': context, 'collections': {}}
    for env in native:
        kind = env.get('type')
        index['collections'].setdefault(kind, []).append(env)
        index.setdefault(kind, []).extend({'type': kind, 'scope': env.get('scope'), 'data': r} for r in env.get('items', []))
    return index


def _source13():
    # Reuse the already admitted registrar namespace; importing the original
    # decorated module would attempt duplicate registration.
    module = sys.modules.get('peaso.checks._bulk_pending_compliance_new_sw13')
    _require(module is not None, 'admitted source13 helper namespace unavailable')
    return module


def _inventory(index, kind, endpoint=None):
    sw13 = _source13()
    rows = sw13.inventory(index, kind, graph=True)
    if endpoint:
        sw13.native_mfa_source_capture(index, kind)
    else:
        metadata = index['context']['metadata']
        for env in index['collections'].get(kind, []):
            for value in [env, *env.get('items', [])]:
                proof = value.get('_provenance', {})
                _require(proof.get('tenant_verified') is True and str(proof.get('tenant_id', '')).casefold() == metadata['tenant_id'].casefold()
                         and all(proof.get(k) == metadata[k] and bool(metadata[k]) for k in ('credential_context_id', 'customer_context_id')),
                         'native inventory capture differs')
    _unique(rows)
    return rows


def _principal_ids(item, index):
    uid = _guid(item['id'])
    groups = _unique(_inventory(index, 'directory_group'))
    memberships = _inventory(index, 'directory_user_group_membership')
    own = [r for r in memberships if str(r.get('id', '')).casefold() == uid]
    _require(len(own) == 1 and str(own[0].get('userId', '')).casefold() == uid
             and own[0].get('_coverage', {}).get('groups', {}).get('status') in ('collected', 'empty'), 'user membership incomplete')
    result = {uid}
    _require(isinstance(own[0].get('groups'), list), 'native user group list missing')
    for group in own[0]['groups']:
        _require(isinstance(group, dict), 'malformed user group reference')
        gid = _guid(group.get('id'))
        _require(gid in groups, 'membership group absent from native inventory')
        raw = groups[gid]
        kinds = raw.get('groupTypes')
        _require(isinstance(kinds, list) and not any(k not in ('Unified',) for k in kinds) and raw.get('visibility') in (None, 'Private', 'Public'), 'hidden, dynamic or malformed membership unresolved')
        result.add(gid)
    return result, groups


def _current(row, now, *, assignments=(), arm=False):
    value = row.get('properties') if arm else row
    _require(isinstance(value, dict), 'missing native schedule properties')
    if arm:
        _require(value.get('status') in ('Provisioned', 'Granted', 'Accepted', 'Revoked', 'Canceled', 'Denied', 'Failed'), 'PIM lifecycle unresolved')
        if value['status'] in ('Revoked', 'Canceled', 'Denied', 'Failed'):
            return False
    try:
        start, end = value.get('startDateTime'), value.get('endDateTime')
        if start is not None and end is not None:
            _require(sw18._time(start) < sw18._time(end), 'PIM interval is empty or inverted')
        return sw18._active(value, now, current_assignment_proven=(not arm and sw18._same_role_assignment(value, assignments)))
    except (ValueError, TypeError) as exc:
        _require(False, str(exc))


def _directory_roles(projection, principals, groups, uid, now):
    definitions = _unique(_source(projection, 'definitions'))
    privileged_defs = _unique(_source(projection, 'privilege_definitions'))
    _require(set(definitions) == set(privileged_defs), 'native role-definition versions differ')
    for d in privileged_defs.values():
        _require(type(d.get('isPrivileged')) is bool, 'native privilege classification missing')
    assigned = _source(projection, 'roles')
    templates, privileged, eligible_admin = set(), False, False
    for name in ('roles', 'active', 'eligible'):
        for row in _unique(_source(projection, name), guid=False).values():
            pid, role = _guid(row.get('principalId')), _guid(row.get('roleDefinitionId'))
            _require(role in definitions, 'assigned directory role definition unavailable')
            directory_scope = row.get('directoryScopeId')
            _require(directory_scope == '/' or isinstance(directory_scope, str) and re.fullmatch(r'/administrativeUnits/[0-9a-f-]{36}', directory_scope, re.I), 'directory assignment scope unresolved')
            _require(row.get('appScopeId') is None, 'app-scoped role assignment unsupported')
            if pid not in principals or name != 'roles' and not _current(row, now, assignments=assigned):
                continue
            definition = definitions[role]
            template = _guid(definition.get('templateId', role) if definition.get('isBuiltIn') is True else role)
            if name == 'eligible' and template == GLOBAL_ADMIN:
                eligible_admin = True
            elif directory_scope == '/':
                templates.add(template)
            privileged |= privileged_defs[role]['isPrivileged']
    # Reuse SW18's conservative PIM-for-Groups rule: future/expired are ignored;
    # active eligible/unexpanded paths and owner paths cannot prove classification.
    for pid in principals:
        for name in ('eligibilityScheduleInstances', 'assignmentScheduleInstances'):
            for row in _unique(_source(projection, 'group_' + name + ':' + pid), guid=False).values():
                _require(_guid(row.get('principalId')) == pid, 'foreign PIM group principal')
                if _current(row, now):
                    _require(name == 'assignmentScheduleInstances' and row.get('accessId') == 'member' and _guid(row.get('groupId')) in principals,
                             'PIM group path requires native expansion')
    for gid, group in groups.items():
        _require(type(group.get('isAssignableToRole')) is bool, 'role-assignable group classification missing')
        if group['isAssignableToRole']:
            _require(uid not in _unique(_source(projection, 'owners:' + gid)), 'role-assignable group ownership unresolved')
    return templates, privileged, eligible_admin


def _arm_scope(row, projection, tenant):
    props = row.get('properties')
    _require(isinstance(props, dict), 'ARM assignment properties missing')
    scope = props.get('scope')
    _require(isinstance(scope, str) and scope == scope.strip() and not any(c in scope for c in ('?', '#', '%')) and not any(v in ('.', '..') for v in scope.split('/')), 'ARM grant scope missing or malformed')
    rid = row.get('id')
    _require(isinstance(rid, str), 'ARM grant identity missing')
    match_id = re.fullmatch(re.escape(scope.rstrip('/')) + r'/providers/Microsoft.Authorization/(roleAssignments|roleAssignmentScheduleInstances|roleEligibilityScheduleInstances)/([0-9a-f-]{36})', rid, re.I)
    _require(match_id is not None and _guid(match_id.group(2)) == _guid(row.get('name'))
             and str(row.get('type', '')).casefold() == ('Microsoft.Authorization/' + match_id.group(1)).casefold(), 'ARM grant identity differs from scope/type/name')
    if scope == '/':
        return props
    match = re.match(r'(/subscriptions/[0-9a-f-]{36})(?:/|$)', scope, re.I)
    mg = re.fullmatch(r'/providers/Microsoft.Management/managementGroups/[^/?#]+', scope, re.I)
    _require(match or mg, 'unsupported ARM hierarchy scope')
    parent = match.group(1) if match else mg.group(0)
    if match:
        _guid(parent.rsplit('/', 1)[1])
    values = _source(projection, 'binding:' + parent.casefold())
    _require(len(values) == 1 and str(values[0].get('id', '')).casefold() == parent.casefold(), 'ARM parent identity differs')
    actual_tenant = values[0].get('tenantId') if match else values[0].get('properties', {}).get('tenantId')
    _require(_guid(actual_tenant) == tenant, 'ARM assignment belongs to another tenant')
    return props


def _direct(projection, item, tenant, now):
    uid = _guid(item['id'])
    found, unresolved = [], []
    for source_name in ('roles', 'active', 'eligible'):
        try:
            for row in _unique(_source(projection, source_name), guid=False).values():
                if _guid(row.get('principalId')) != uid:
                    continue
                _guid(row.get('roleDefinitionId'))
                _require(row.get('appScopeId') is None, 'application-scoped direct role unresolved')
                if source_name != 'roles':
                    _require(row.get('memberType') in ('Direct', 'Group', 'Inherited'), 'PIM membership type unavailable')
                    if row['memberType'] != 'Direct':
                        continue
                ds = row.get('directoryScopeId')
                _require(ds == '/' or isinstance(ds, str) and re.fullmatch(r'/administrativeUnits/[0-9a-f-]{36}', ds, re.I), 'foreign direct directory grant scope')
                if source_name == 'roles' or _current(row, now, assignments=_source(projection, 'roles')):
                    found.append(row['id'])
        except (ValueError, KeyError) as exc:
            unresolved.append(str(exc))
        except Exception as exc:
            from ..checks.facts import Unavailable
            if not isinstance(exc, Unavailable): raise
            unresolved.append(str(exc))
    for name in ARM_READS:
        try:
            for row in _unique(_source(projection, 'arm_' + name + ':' + uid), guid=False).values():
                props = _arm_scope(row, projection, tenant)
                _require(_guid(props.get('principalId')) == uid and props.get('principalType') == 'User', 'foreign ARM direct principal')
                _require(isinstance(props.get('roleDefinitionId'), str) and re.fullmatch(r'.*/providers/Microsoft.Authorization/roleDefinitions/[0-9a-f-]{36}', props['roleDefinitionId'], re.I), 'malformed ARM role reference')
                if name != 'assigned':
                    _require(props.get('memberType') in ('Direct', 'Group', 'Inherited'), 'ARM PIM membership type unavailable')
                    if props['memberType'] != 'Direct':
                        continue
                if name == 'assigned' or _current(row, now, arm=True):
                    found.append(row['id'])
        except Exception as exc:
            from ..checks.facts import Unavailable
            if not isinstance(exc, (Unavailable, ValueError, KeyError)): raise
            unresolved.append(str(exc))
    if found:
        return 'FAIL', {'direct_assignment_ids': sorted(set(found)), 'semantics': 'Native direct active or currently eligible grants; group assignments excluded'}
    _require(not unresolved, 'Direct assignment absence unresolved: ' + '; '.join(unresolved[:2]))
    return 'PASS', {'direct_assignment_count': 0, 'semantics': 'Complete directory/PIM and root principal-filtered ARM grant inventories contain no direct grant'}


def _mfa(projection, item, index, cid, now):
    sw13 = _source13()
    uid = _guid(item['id'])
    _require(type(item.get('accountEnabled')) is bool, 'account enablement unavailable')
    if not item['accountEnabled']:
        return 'NOT_APPLICABLE', {'reason': 'Disabled native user'}
    registration = _unique(_inventory(index, 'user_registration_detail'))
    raw_registration = _unique(_source(projection, 'registration'))
    _require(set(registration) == set(raw_registration) and all(registration[rid].get(k) == raw_registration[rid].get(k) for rid in registration for k in ('isMfaCapable', 'isMfaRegistered')), 'native registration projection contradicts raw source')
    _require(uid in registration and all(type(registration[uid].get(k)) is bool for k in ('isMfaRegistered', 'isMfaCapable')), 'native registration subject unavailable')
    legacy = None
    if cid in (ADMIN, CIS):
        principals, groups = _principal_ids(item, index)
        templates, privileged, eligible_admin = _directory_roles(projection, principals, groups, uid, now)
        if cid == ADMIN:
            _require(not eligible_admin, 'Eligible Global Administrator activation unresolved')
            if GLOBAL_ADMIN not in templates:
                return 'NOT_APPLICABLE', {'reason': 'Complete native directory roles show no active Global Administrator assignment'}
        else:
            requirements = _source(projection, 'requirements:' + uid)
            _require(len(requirements) == 1, 'ambiguous beta requirements')
            req = requirements[0]
            _require('id' not in req or _guid(req['id']) == uid, 'beta requirements subject differs')
            legacy = req.get('perUserMfaState')
            _require(legacy in ('disabled', 'enabled', 'enforced'), 'native legacy MFA state unavailable')
            if privileged and legacy == 'disabled':
                return 'FAIL', {'legacy_per_user_mfa_state': legacy, 'reason': 'Native privileged directory principal has disabled legacy per-user MFA; CA cannot change that field'}
            # A native enabled/enforced state satisfies the stricter legacy
            # requirement regardless of whether ARM writer classification expands.
            if legacy == 'disabled':
                _require(all(not _source(projection, 'arm_' + name + ':' + pid) for pid in principals for name in ARM_READS),
                         'ARM grant/writer classification unresolved for disabled legacy state')
    rules = _inventory(index, 'conditional_access_policy', endpoint=True)
    defaults = _inventory(index, 'directory_security_defaults', endpoint=True)
    _require(len(defaults) == 1 and type(defaults[0].get('isEnabled')) is bool, 'security defaults metadata unavailable')
    _require(defaults[0]['isEnabled'] is False, 'Security Defaults per-context applicability unsupported')
    enabled_ids = {_guid(r['id']) for r in _inventory(index, 'directory_user', endpoint=True) if r.get('accountEnabled') is True}
    covered, uncertain, blocked, policy_ids = False, False, False, []
    for rule in rules:
        _require(rule.get('state') in ('enabled', 'disabled', 'enabledForReportingButNotEnforced'), 'unknown native CA state')
        if rule['state'] != 'enabled':
            continue
        try:
            conditions = rule.get('conditions')
            _require(isinstance(conditions, dict) and sw13.native_mfa_fields_readable(conditions), 'CA selectors missing or unreadable')
            allowed = {'users', 'applications', 'clientAppTypes'}
            _require(all(k in allowed or k.startswith('_') or v in (None, [], {}) for k, v in conditions.items()), 'unsupported native condition context')
            selected = conditions.get('users')
            _require(isinstance(selected, dict), 'CA user selector missing')
            scope = sw13.native_mfa_user_group_scope(selected, enabled_ids, index)
            _require(scope is not None, 'CA user/group/role selector unresolved')
            if uid not in scope:
                continue
            app_scope = sw13.native_mfa_application_client_scope(conditions, None)
            _require(app_scope is not None and app_scope[2], 'Native application/client coverage not universal')
            grant = rule.get('grantControls')
            _require(isinstance(grant, dict) and sw13.native_mfa_fields_readable(grant), 'native grant missing or unreadable')
            _require(all(k in ('operator', 'builtInControls', 'authenticationStrength') or k.startswith('_') or v in (None, [], {}) for k, v in grant.items()), 'custom grant alternatives unresolved')
            controls = grant.get('builtInControls')
            _require(isinstance(controls, list) and all(isinstance(c, str) for c in controls), 'native built-in grants malformed')
            if controls == ['block']:
                blocked = True
                continue
            _require(not set(controls) - {'mfa', 'compliantDevice', 'domainJoinedDevice'}, 'unsupported native grant control')
            strength = []
            if grant.get('authenticationStrength') is not None:
                strength = _inventory(index, 'authentication_strength', endpoint=True)
            _, enforced, _ = sw13.grant(rule, strength, {'device': {'isCompliant': False, 'isHybridJoined': False}, 'application': {}})
            if enforced:
                covered = True
                policy_ids.append(rule['id'])
        except Exception as exc:
            from ..checks.facts import Unavailable
            if not isinstance(exc, (Unavailable, ValueError, KeyError)): raise
            uncertain = True
    if covered:
        _require(not blocked, 'An unconditional Block policy makes the supported sign-in universe unreachable; blocking is not MFA proof')
        return 'PASS', {'native_mfa_policy_ids': policy_ids, 'legacy_per_user_mfa_state': legacy,
                        'semantics': 'Native unconditional all-resource/all-client mandatory MFA covers this enabled subject; registration alone is not enforcement'}
    _require(not uncertain and not blocked, 'Native policies do not resolve every supported context; blocked paths are not MFA proof')
    _require(cid != ADMIN, 'Missing tenant CA mandate does not prove a console bypass: Microsoft platform portal MFA applicability is not captured')
    requirements = _source(projection, 'requirements:' + uid)
    _require(len(requirements) == 1 and ('id' not in requirements[0] or _guid(requirements[0]['id']) == uid)
             and requirements[0].get('perUserMfaState') == 'disabled', 'Missing CA mandate cannot prove a bypass of enabled, enforced or unreadable per-user MFA')
    return 'FAIL', {'native_mfa_policy_ids': [], 'legacy_per_user_mfa_state': legacy,
                    'reason': 'Complete native policies and disabled Security Defaults leave this enabled subject without a mandatory MFA grant for an unrestricted sign-in context'}


def evaluate_native(cid, item, index):
    """Return None only for historical indexes without the successor inventory."""
    if cid not in IDS:
        return None
    envelopes = index.get('collections', {}).get(KIND)
    if envelopes is None:
        return None
    from ..checks.facts import Unavailable
    try:
        context = index.get('context', {})
        metadata = context.get('metadata', {})
        tenant = _guid(metadata.get('tenant_id'))
        _require(context.get('provider') == 'azure' and metadata.get('tenant_verified') is True, 'authenticated native tenant unavailable')
        scope = str(context.get('scope', '')).casefold()
        _require(scope == '/tenants/' + tenant or str(metadata.get('subscription_tenants', {}).get(scope, '')).casefold() == tenant,
                 'selected scope not bound to tenant')
        _require(len(envelopes) == 1, 'native enforcement inventory ambiguous')
        env = envelopes[0]
        _require(env.get('scope', '').casefold() == '/tenants/' + tenant and env.get('service') == 'Microsoft.Graph'
                 and env.get('status') == 'collected' and len(env.get('items', [])) == 1, 'native enforcement inventory incomplete')
        projection = env['items'][0]
        for value in (env, projection):
            proof = value.get('_provenance', {})
            _require(proof.get('adapter') == ADAPTER and proof.get('tenant_verified') is True and proof.get('read_only') is True
                     and _guid(proof.get('tenant_id')) == tenant
                     and all(proof.get(k) == metadata.get(k) and bool(metadata.get(k)) for k in ('credential_context_id', 'customer_context_id')),
                     'native enforcement capture differs')
        _require(projection.get('id') == '/tenants/' + tenant + '#identity-enforcement', 'native projection identity differs')
        native_context = {**context, 'scope': '/tenants/' + tenant}
        native_index = _native_index(projection, native_context)
        users = _unique(_inventory(native_index, 'directory_user', endpoint=True))
        raw_users = _unique(_source(projection, 'users'))
        _require(set(users) == set(raw_users) and all(type(raw_users[rid].get('accountEnabled')) is bool and raw_users[rid]['accountEnabled'] == users[rid].get('accountEnabled') for rid in users), 'native user projection contradicts raw complete source')
        uid = _guid(item.get('id'))
        _require(uid in users and users[uid] == item, 'native user absent or contradicts authoritative source')
        now = sw18._time(projection['_provenance'].get('observed_at'))
        _require(now <= sw18._time(context.get('created_at')), 'native evidence captured after snapshot')
        return _direct(projection, item, tenant, now) if cid == DIRECT else _mfa(projection, item, native_index, cid, now)
    except (Unavailable, ValueError, KeyError, TypeError) as exc:
        return 'UNKNOWN', {'reason': str(exc)}
