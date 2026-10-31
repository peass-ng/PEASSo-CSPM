"""Current custom Entra role definitions without declared assignment/PIM consumers."""
from datetime import timedelta
from pathlib import Path
import json,re
from peaso.azure_unused_role_contract import KIND, SCHEMA, REPORTS, GRAPH, guid
from peaso.unused_iam_azure import EvidenceError, _authority, _bound, _field
from peaso.iam_usage_evidence import instant

CHECK = 'azure.iam.custom_directory_role_has_declared_consumers'
TITLE = 'Custom Entra role has declared assignment or PIM consumers'
ACTIVE = {'Granted', 'PendingAdminDecision', 'PendingApproval', 'PendingProvisioning', 'PendingScheduleCreation', 'Provisioned', 'ScheduleCreated'}
INACTIVE = {'Canceled', 'Denied', 'Failed', 'Revoked'}


def memo(index, key, build):
    from peaso.checks.facts import memoized
    return memoized(index, ('unused_azure_custom_role', key), build)


def collection(index, kind, scope, meta):
    matches = index.get('collections', {}).get(kind)
    rows = index.get(kind)
    if not isinstance(matches, list) or len(matches) != 1 or not isinstance(rows, list):
        raise EvidenceError('unique native '+kind+' inventory is unavailable')
    source = matches[0]
    if (source.get('type') != kind or str(source.get('scope', '')).casefold() != scope
            or source.get('service') != 'Microsoft.Graph' or not _bound(source.get('_provenance'), meta)
            or not isinstance(source.get('items'), list)
            or any(not isinstance(row, dict) or row.get('type') != kind or str(row.get('scope', '')).casefold() != scope for row in rows)
            or [row.get('data') for row in rows] != source['items']):
        raise EvidenceError('directory role source and captured resource projection disagree')
    return source


def current(item, index, scope, meta):
    identity = guid(_field(item, 'id'))
    proof = item.get('_provenance')
    if not _bound(proof, meta, read_only=True) or proof.get('endpoint') != '/v1.0/roleManagement/directory/roleDefinitions':
        raise EvidenceError('custom role native directory authority is unresolved')
    def build():
        source = collection(index, 'directory_role_definition', scope, meta)
        if source.get('status') not in ('collected', 'partial'):
            raise EvidenceError('native role definitions are unavailable', 'DENIED' if source.get('status') == 'denied' else 'UNKNOWN')
        mapping = {}
        for row in source['items']:
            key = guid(row.get('id'))
            if key in mapping: raise EvidenceError('current directory role identity is duplicated')
            mapping[key] = row
        return mapping
    if memo(index, 'current_roles', build).get(identity) != item:
        raise EvidenceError('assessed role differs from current native definition')
    return identity


def reports(index, scope, meta, now):
    def build():
        source = collection(index, KIND, scope, meta)
        if source.get('status') != 'collected':
            raise EvidenceError('role-assignment evidence is unavailable', 'DENIED' if source.get('status') == 'denied' else 'UNKNOWN')
        if len(source['items']) != 1: raise EvidenceError('role-assignment evidence is ambiguous')
        record = source['items'][0];proof = record.get('_provenance')
        if (record.get('schema') != SCHEMA or str(record.get('id', '')).casefold() != scope+'/unusedroleevidence'
                or not _bound(proof, meta, read_only=True) or proof.get('schema') != SCHEMA
                or proof.get('endpoint') != 'native-unused-role-projection'
                or abs(instant(proof.get('observed_at')) - now) > timedelta(days=1)):
            raise EvidenceError('role-assignment capture binding is unavailable')
        data = record.get('reports')
        if not isinstance(data, list) or len(data) != len(REPORTS):
            raise EvidenceError('complete assignment and PIM source set is unavailable')
        mapping = {}
        for report in data:
            name = report.get('name') if isinstance(report, dict) else None
            if name not in REPORTS or name in mapping:
                raise EvidenceError('assignment/PIM source is unknown or duplicated')
            if (report.get('endpoint') != REPORTS[name] or report.get('audience') != GRAPH
                    or report.get('method') != 'GET' or report.get('body', 'missing') is not None
                    or report.get('filter', 'missing') is not None or report.get('projection') != 'full'
                    or not isinstance(report.get('items'), list) or type(report.get('integrity_error')) is not bool):
                raise EvidenceError('unfiltered native assignment/PIM source is unavailable')
            status = report.get('status')
            if (status not in ('collected', 'empty', 'partial', 'denied', 'unknown', 'malformed', 'timeout', 'not_collected')
                    or status == 'empty' and report['items'] or status == 'collected' and not report['items']):
                raise EvidenceError('assignment/PIM source status contradicts its native rows')
            mapping[name] = report
        return mapping
    return memo(index, 'reports', build)


def lifetime(row, now):
    status = _field(row, 'status')
    if status in INACTIVE: return False
    if status not in ACTIVE: raise EvidenceError('PIM schedule status is unavailable')
    schedule = _field(row, 'scheduleInfo')
    if not isinstance(schedule, dict) or not isinstance(schedule.get('expiration'), dict):
        raise EvidenceError('PIM schedule lifetime is unavailable')
    start = instant(schedule.get('startDateTime'))
    expiry = schedule['expiration'];kind = expiry.get('type')
    if kind == 'noExpiration':
        if expiry.get('endDateTime') is not None or expiry.get('duration') is not None:
            raise EvidenceError('permanent PIM schedule has conflicting expiration')
        return True
    if kind == 'afterDateTime':
        end = instant(expiry.get('endDateTime'))
        if expiry.get('duration') is not None: raise EvidenceError('PIM expiration duration conflicts with end date')
    elif kind == 'afterDuration':
        duration = expiry.get('duration')
        match = re.fullmatch(r'P(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+(?:\.\d+)?)S)?)?', duration) if isinstance(duration, str) else None
        if not match or not any(match.groups()) or expiry.get('endDateTime') is not None:
            raise EvidenceError('PIM duration cannot be resolved to a fixed interval')
        days,hours,minutes,seconds = [float(value or 0) for value in match.groups()]
        end = start + timedelta(days=days,hours=hours,minutes=minutes,seconds=seconds)
    else: raise EvidenceError('PIM expiration pattern is unresolved')
    if end <= start: raise EvidenceError('PIM schedule lifetime is contradictory')
    return end > now  # Future assignments are declared consumers too.


def consumers(index, scope, meta, now):
    def build():
        mapping, unresolved, unavailable = {}, [], []
        for name, report in reports(index, scope, meta, now).items():
            if report['integrity_error']:
                unavailable.append(EvidenceError('assignment/PIM source integrity is unresolved: '+name));continue
            if report.get('status') not in ('collected', 'empty'):
                error = report.get('error', {})
                cause = error.get('cause_status', error.get('kind', report.get('status')))
                unavailable.append(EvidenceError('assignment/PIM inventory is incomplete: '+name, 'DENIED' if cause == 'denied' else 'UNKNOWN'))
            seen = set(); source_mapping = {}; duplicated = False
            for row in report['items']:
                try:
                    if not isinstance(row, dict): raise EvidenceError('assignment/PIM row is malformed')
                    rid = _field(row, 'id')
                    if not isinstance(rid, str) or not rid:
                        raise EvidenceError('assignment/PIM row identity is unavailable')
                    if rid in seen:
                        duplicated = True
                        break
                    seen.add(rid)
                    role, principal = guid(_field(row, 'roleDefinitionId')), guid(_field(row, 'principalId'))
                    scopes = [row.get(field) for field in ('directoryScopeId', 'appScopeId') if row.get(field) is not None]
                    if not scopes or any(not isinstance(value, str) or not value.startswith('/') or re.search(r'[\s?#%\\]', value) or any(p in ('.', '..') for p in value.split('/')) for value in scopes):
                        raise EvidenceError('assignment/PIM declared scope is unavailable')
                    if name != 'assignments' and not lifetime(row, now): continue
                    source_mapping.setdefault(role, []).append({'source': name, 'id': rid, 'principal_id': principal,
                        'directory_scope_id': row.get('directoryScopeId'), 'app_scope_id': row.get('appScopeId'),
                        **({'status': row.get('status'), 'schedule': row.get('scheduleInfo')} if name != 'assignments' else {})})
                except (EvidenceError, ValueError, TypeError, KeyError, AttributeError, OverflowError) as exc:
                    unresolved.append(exc)
            if duplicated:
                unavailable.append(EvidenceError('assignment/PIM row identity is duplicated: '+name))
            else:
                for role, rows in source_mapping.items(): mapping.setdefault(role, []).extend(rows)
        return mapping, unresolved, unavailable
    return memo(index, 'consumers', build)


def evaluate(item, index):
    try:
        context, meta, scope = _authority(index);now = instant(context.get('created_at'))
        role = current(item, index, scope, meta)
        built_in = _field(item, 'isBuiltIn');enabled = _field(item, 'isEnabled')
        if type(built_in) is not bool or type(enabled) is not bool:
            raise EvidenceError('native role type or assignment state is unavailable')
        if built_in: return 'NOT_APPLICABLE', {'reason': 'Microsoft built-in role definition'}
        permissions = _field(item, 'rolePermissions')
        if not isinstance(permissions, list): raise EvidenceError('custom role permission declarations are unavailable')
        for block in permissions:
            actions = _field(block, 'allowedResourceActions')
            if not isinstance(actions, list) or any(not isinstance(a, str) or not a for a in actions):
                raise EvidenceError('custom role allowed actions are malformed')
        mapping, unresolved, unavailable = consumers(index, scope, meta, now)
        found = mapping.get(role, [])
        name = item.get('displayName') or role
        evidence = {'role_id': role, 'role_name': name, 'is_enabled': enabled, 'role_permissions': permissions,
            'declared_consumers': found, 'semantics': 'Current declared assignments and nonexpired or future PIM schedules; not action-use history or a safe-deletion assertion.'}
        if found:
            return 'PASS', {**evidence, 'summary': f'Custom Entra role {name} has a captured assignment or PIM consumer.\nThe captured principal and scope identify that declared consumer.\nA scheduled or eligible assignment does not establish recent permission use.'}
        if unavailable: raise next((exc for exc in unavailable if exc.status == 'DENIED'), unavailable[0])
        if unresolved: raise unresolved[0]
        return 'FAIL', {**evidence, 'summary': f'Custom Entra role {name} has no captured assignment or unexpired PIM consumer.\nComplete directory assignments and PIM schedules contain no current or future consumer of this role.\nAn obsolete permission definition adds configuration that still needs maintenance and review.'}
    except (EvidenceError, ValueError, TypeError, KeyError, AttributeError, OverflowError) as exc:
        return getattr(exc, 'status', 'UNKNOWN'), {'reason': str(exc), 'summary': str(exc).rstrip('.')+'.\nThe custom role’s assignment or PIM consumers are unresolved.\nMissing directory evidence cannot establish that a role has no consumers.'}


def install(registry):
    from peaso.checks.fixtures import CASES
    raw = Path(__file__).with_name('checks').joinpath('unused_iam_azure_roles_cases.json').read_bytes()
    cases = json.loads(raw)
    if set(cases) != {CHECK}: raise ValueError('Azure custom-role case IDs changed')
    CASES.update(cases)
    registry.register(CHECK, 'azure', 'hardening', 'directory_role_definition', TITLE, 'low', 'AC-2',
        'Review role ownership, intended assignments and pending requests before removing an obsolete custom Entra role.',
        dependencies=('directory_role_definition', KIND), allow_incomplete_failure=True)(evaluate)
