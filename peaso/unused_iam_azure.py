"""Azure unused IAM evidence: typed native identities and read-only Graph reports."""
from __future__ import annotations
from datetime import timedelta
from functools import partial

from peaso.iam_usage_evidence import instant
from peaso.azure_unused_iam_contract import KIND, SCHEMA, REPORTS, GRAPH, guid, project_native

DAYS = 90


class EvidenceError(ValueError):
    def __init__(self, message, status='UNKNOWN'):
        super().__init__(message)
        self.status = status


def _memo(index, key, build):
    from peaso.checks.facts import memoized
    return memoized(index, ('unused_iam_azure', key), build)


def _authority(index):
    context = index.get('context', {})
    meta = context.get('metadata', {})
    tenant = guid(meta.get('tenant_id'))
    if context.get('provider') != 'azure' or meta.get('tenant_verified') is not True:
        raise EvidenceError('authenticated Azure tenant is unavailable')
    for key in ('credential_context_id', 'customer_context_id'):
        if not isinstance(meta.get(key), str) or not meta[key]:
            raise EvidenceError('scan-local identity authority is unavailable')
    if str(context.get('scope', '')).casefold() != '/tenants/' + tenant:
        raise EvidenceError('directory identity is outside the verified tenant scope')
    return context, meta, '/tenants/' + tenant


def _bound(proof, meta, *, read_only=False):
    return (isinstance(proof, dict) and proof.get('tenant_verified') is True
        and str(proof.get('tenant_id', '')).casefold() == meta['tenant_id'].casefold()
        and all(proof.get(key) == meta[key] for key in ('credential_context_id', 'customer_context_id'))
        and (not read_only or proof.get('read_only') is True))


def _evidence(index):
    def build():
        context, meta, scope = _authority(index)
        collections = index.get('collections', {}).get(KIND)
        if not isinstance(collections, list) or len(collections) != 1:
            raise EvidenceError('native unused-IAM activity evidence was not collected')
        collection = collections[0]
        if (collection.get('type') != KIND or collection.get('scope', '').casefold() != scope
                or collection.get('service') != 'Microsoft.Graph' or not _bound(collection.get('_provenance'), meta)):
            raise EvidenceError('native unused-IAM evidence belongs to another capture')
        if collection.get('status') != 'collected':
            raise EvidenceError('native unused-IAM activity evidence is unavailable', 'DENIED' if collection.get('status') == 'denied' else 'UNKNOWN')
        items = collection.get('items')
        projected = index.get(KIND)
        if (not isinstance(items, list) or len(items) != 1 or not isinstance(projected, list)
                or len(projected) != 1 or projected[0].get('data') != items[0]):
            raise EvidenceError('activity evidence and native resource projection disagree')
        record = items[0]
        if (record.get('schema') != SCHEMA or record.get('id', '').casefold() != scope + '/unusediamevidence'
                or not _bound(record.get('_provenance'), meta, read_only=True)):
            raise EvidenceError('activity evidence schema or authority is unresolved')
        proof = record['_provenance']
        if proof.get('endpoint') != 'native-unused-iam-projection' or proof.get('schema') != SCHEMA:
            raise EvidenceError('activity evidence producer endpoint is unresolved')
        now, captured = instant(context.get('created_at')), instant(proof.get('observed_at'))
        if abs(now-captured) > timedelta(days=1):
            raise EvidenceError('activity evidence is outside the current capture interval')
        if not isinstance(record.get('native_collections'), list) or not isinstance(record.get('reports'), list):
            raise EvidenceError('native activity evidence is malformed')
        return record
    return _memo(index, 'evidence', build)


def _current(item, index, kind):
    context, meta, scope = _authority(index)
    identity = guid(item.get('id'))
    if not _bound(item.get('_provenance'), meta, read_only=True):
        raise EvidenceError('assessed directory identity belongs to another capture')
    if item['_provenance'].get('endpoint') != {'directory_group': '/v1.0/groups',
            'directory_application': '/v1.0/applications', 'directory_service_principal': '/v1.0/servicePrincipals'}[kind]:
        raise EvidenceError('assessed directory identity has an unexpected native endpoint')
    collections = index.get('collections', {}).get(kind, [])
    if (len(collections) != 1 or collections[0].get('scope', '').casefold() != scope
            or collections[0].get('service') != 'Microsoft.Graph' or not _bound(collections[0].get('_provenance'), meta)):
        raise EvidenceError('directory identity inventory authority is unresolved')
    def current_objects():
        projected = index.get(kind, [])
        if not isinstance(projected, list) or [row.get('data') for row in projected] != collections[0].get('items'):
            raise EvidenceError('directory resource projection differs from the native collection')
        mapping = {}
        for resource in projected:
            data = resource.get('data')
            key = guid(data.get('id')) if isinstance(data, dict) else None
            if key in mapping:
                raise EvidenceError('directory object identity is duplicated')
            mapping[key] = data
        return mapping
    if _memo(index, ('current', kind), current_objects).get(identity) != item:
        raise EvidenceError('assessed identity differs from its captured native object')
    coverage = item.get('_coverage', {})
    if not isinstance(coverage, dict):
        raise EvidenceError('directory field coverage is malformed')
    def native_objects():
        source = _native(index, kind, scope)
        mapping = {}
        for row in source['items']:
            key = guid(row.get('id'))
            if key in mapping:
                raise EvidenceError('native activity parent identity is duplicated')
            mapping[key] = row
        return mapping
    if _memo(index, ('native_objects', kind, scope), native_objects).get(identity) != project_native(kind, item):
        raise EvidenceError('assessed identity metadata differs from the native activity capture')
    return identity, context


def _field(item, name):
    coverage = item.get('_coverage', {})
    if name in coverage and (not isinstance(coverage[name], dict) or coverage[name].get('status') not in ('collected', 'empty')):
        raise EvidenceError('directory field is unavailable: ' + name,
                            'DENIED' if isinstance(coverage[name], dict) and coverage[name].get('status') == 'denied' else 'UNKNOWN')
    if name not in item:
        raise EvidenceError('directory field is missing: ' + name)
    return item[name]


def _native(index, kind, scope):
    def sources():
        mapping = {}
        for row in _evidence(index)['native_collections']:
            if not isinstance(row, dict):
                raise EvidenceError('native directory source is malformed')
            mapping.setdefault((row.get('type'), str(row.get('scope', '')).casefold()), []).append(row)
        return mapping
    matches = _memo(index, 'native_sources', sources).get((kind, scope.casefold()), [])
    if len(matches) != 1:
        raise EvidenceError('native directory source is missing or ambiguous: ' + kind)
    source = matches[0]
    if source.get('service') != 'Microsoft.Graph' or not isinstance(source.get('items'), list):
        raise EvidenceError('native directory source is malformed: ' + kind)
    if source.get('status') not in ('collected', 'empty', 'partial', 'denied', 'unknown', 'not_collected', 'malformed', 'timeout'):
        raise EvidenceError('native directory source status is malformed')
    if source.get('status') == 'empty' and source['items']:
        raise EvidenceError('empty directory source contains identities')
    return source


# Tenants that own Microsoft first-party applications.
MICROSOFT_TENANTS = frozenset({'f8cdef31-a31e-4b4a-93e4-5f571e91255a', '72f988bf-86f1-41af-91ab-2d7cd011db47',
                               'cdc5aeea-15c5-4db6-b079-fcadd2505dc2'})


def _unavailable(source, message):
    raise EvidenceError(message, 'DENIED' if source.get('status') == 'denied' else 'UNKNOWN')


def _report(index, name):
    matches = [row for row in _evidence(index)['reports'] if row.get('name') == name]
    if len(matches) != 1:
        raise EvidenceError('native activity report is missing or ambiguous')
    source = matches[0]
    if (source.get('method') != 'GET' or source.get('body') is not None
            or source.get('audience') != GRAPH or source.get('endpoint') != REPORTS[name]
            or source.get('integrity_error') is not False or not isinstance(source.get('items'), list)):
        raise EvidenceError('native activity report authority or identity integrity is unresolved')
    if source.get('status') not in ('collected', 'empty', 'partial', 'denied', 'unknown', 'not_collected', 'malformed', 'timeout'):
        raise EvidenceError('native activity report status is malformed')
    if source.get('status') == 'empty' and source['items']:
        raise EvidenceError('empty activity report contains identities')
    return source


def _report_map(index, name):
    def build():
        source = _report(index, name)
        mapping = {}
        for row in source['items']:
            app = guid(row.get('appId'))
            if name == 'service_principal_activity':
                key = app
            else:
                origin = row.get('credentialOrigin')
                if origin not in ('application', 'servicePrincipal'):
                    raise EvidenceError('credential activity origin is malformed')
                parent = guid(row.get('appObjectId' if origin == 'application' else 'servicePrincipalObjectId'))
                key = origin, parent, app, guid(row.get('keyId'))
            if key in mapping:
                # Do not use an ambiguous identity, or discard independent
                # valid identities elsewhere in a large tenant report.
                mapping[key] = None
            else:
                mapping[key] = row
        return source, mapping
    return _memo(index, name, build)


def _latest_activity(record, field, now):
    activity = record.get(field)
    if not isinstance(activity, dict):
        raise EvidenceError('last sign-in activity metadata is unavailable')
    attempted = instant(activity['lastSignInDateTime']) if activity.get('lastSignInDateTime') else None
    successful = instant(activity['lastSuccessfulSignInDateTime']) if activity.get('lastSuccessfulSignInDateTime') else None
    if attempted is None and successful is None:
        raise EvidenceError('report has no dated activity; absence does not establish unused access')
    if any(value is not None and value > now for value in (attempted, successful)):
        raise EvidenceError('activity date is later than the captured observation')
    if successful is not None and attempted is not None and successful > attempted:
        raise EvidenceError('successful activity is later than the reported latest sign-in')
    cutoff = now - timedelta(days=DAYS)
    if successful is not None:
        return ('FAIL' if successful < cutoff else 'PASS'), successful, 'last_successful_sign_in'
    if attempted < cutoff:
        return 'FAIL', attempted, 'last_recorded_sign_in'
    # The reports share signInActivity semantics: a recent attempt does not
    # establish successful authentication and cannot certify recent use.
    return 'UNKNOWN', attempted, 'recent_attempt_without_success_evidence'


def group_members(item, index):
    identity, context = _current(item, index, 'directory_group')
    scope = '/tenants/' + guid(context['metadata']['tenant_id']) + '/groups/' + identity
    source = _native(index, 'directory_membership', scope)
    members = source['items']
    ids = [guid(row.get('id')) for row in members]
    if len(set(ids)) != len(ids):
        raise EvidenceError('group membership contains duplicate identities')
    if ids:
        return 'PASS', {'group_id': identity, 'member_count': len(ids),
            'summary': f'Group {item.get("displayName", identity)} has {len(ids)} recorded direct members.\nIts membership provides a declared identity consumer.\nThis control does not measure when those members last authenticated.'}
    types = _field(item, 'groupTypes')
    if not isinstance(types, list) or any(not isinstance(value, str) for value in types):
        raise EvidenceError('group membership type is malformed')
    visibility = _field(item, 'visibility')
    if visibility not in ('Private', 'Public', 'HiddenMembership', None):
        raise EvidenceError('group visibility is unrecognized')
    if visibility is None and 'Unified' in types:
        raise EvidenceError('Microsoft 365 group visibility is unavailable')
    if 'DynamicMembership' in types or visibility == 'HiddenMembership':
        raise EvidenceError('dynamic or hidden group membership cannot establish an empty group')
    if source.get('status') != 'empty':
        _unavailable(source, 'complete empty group membership is unavailable')
    if source.get('membership_api') != 'beta' or source.get('endpoint') != '/beta/groups/' + identity + '/members?$select=id':
        raise EvidenceError('complete group membership needs the native beta read, because v1.0 may omit service principals')
    return 'FAIL', {'group_id': identity, 'member_count': 0, 'membership_endpoint': source['endpoint'],
        'summary': f'Group {item.get("displayName", identity)} has no direct members.\nThe complete static membership list contains no identity that consumes this group.\nIts existing grants could become usable if a member is added later.'}


def principal_activity(item, index):
    identity, context = _current(item, index, 'directory_service_principal')
    enabled = _field(item, 'accountEnabled')
    if type(enabled) is not bool:
        raise EvidenceError('service principal enabled state is malformed')
    if not enabled:
        return 'NOT_APPLICABLE', {'reason': 'service principal is disabled'}
    now = instant(context['created_at'])
    created = instant(_field(item, 'createdDateTime'))
    if created > now:
        raise EvidenceError('service principal creation date is later than the capture')
    if created >= now - timedelta(days=DAYS):
        return 'PASS', {'principal_id': identity, 'created_at': created.isoformat(), 'object_age_days': (now-created).days,
            'summary': f'Service principal {item.get("displayName", identity)} was created on {created.date().isoformat()}.\nIt has not existed beyond the 90-day inactivity threshold.\nThis creation date is retained separately from successful-use evidence.'}
    app = guid(_field(item, 'appId'))
    source, mapping = _report_map(index, 'service_principal_activity')
    row = mapping.get(app)
    if row is None:
        if source.get('status') in ('collected', 'empty') and app not in mapping:
            # The report lists only apps with a recorded sign-in; Microsoft
            # first-party apps added to every tenant are usually absent.
            owner = str(item.get('appOwnerOrganizationId') or '').casefold()
            who = ' (a Microsoft first-party app)' if owner in MICROSOFT_TENANTS else ''
            _unavailable(source, 'the servicePrincipalSignInActivities report has no row for this app' + who
                         + '; that report lists only apps with a recorded sign-in, so no use is recorded but the last-use date is unknown')
        _unavailable(source, 'service principal is absent from activity results; usage is unresolved')
    now = instant(context['created_at'])
    status, last, basis = _latest_activity(row, 'lastSignInActivity', now)
    if last < created:
        raise EvidenceError('reported app activity predates the current service principal object')
    # Reject a stale aggregate that contradicts one of its individual flows.
    for flow in ('applicationAuthenticationClientSignInActivity', 'applicationAuthenticationResourceSignInActivity',
                 'delegatedClientSignInActivity', 'delegatedResourceSignInActivity'):
        value = row.get(flow)
        if isinstance(value, dict) and value.get('lastSignInDateTime') and instant(value['lastSignInDateTime']) > last and basis == 'last_recorded_sign_in':
            raise EvidenceError('aggregate sign-in date contradicts an individual authentication flow')
    evidence = {'principal_id': identity, 'app_id': app, basis: last.isoformat(),
                'days_since_recorded_activity': (now-last).days, 'threshold_days': DAYS,
                'report_status': source.get('status'), 'service_principal_type': item.get('servicePrincipalType'),
                'activity_source_endpoint': REPORTS['service_principal_activity']}
    name = item.get('displayName', identity)
    if status == 'FAIL':
        evidence['summary'] = f'Service principal {name} has last recorded activity on {last.date().isoformat()}.\nThat date is more than 90 days before the captured observation.\nIts identity and grants could remain available after its original use ended.'
    elif status == 'PASS':
        evidence['summary'] = f'Service principal {name} has a successful sign-in on {last.date().isoformat()}.\nThat recorded use is within the 90-day inactivity interval.\nIts activity does not indicate an abandoned identity in this interval.'
    else:
        evidence['reason'] = 'the latest recorded sign-in attempt has no successful sign-in date'
        evidence['summary'] = f'Service principal {name} has a sign-in attempt on {last.date().isoformat()}.\nA successful-use timestamp is unavailable for this activity.\nIt is unclear whether the identity still serves an active workload.'
    return status, evidence


def credential_activity(item, index, *, application):
    kind, origin = ('directory_application', 'application') if application else ('directory_service_principal', 'servicePrincipal')
    identity, context = _current(item, index, kind)
    app = guid(_field(item, 'appId'))
    source, mapping = _report_map(index, 'credential_activity')
    now = instant(context['created_at'])
    credentials = []
    for field in ('passwordCredentials', 'keyCredentials'):
        rows = _field(item, field)
        if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
            raise EvidenceError('credential inventory is malformed')
        credentials.extend((field, row) for row in rows)
    stale, unresolved, recent, inactive = [], [], [], []
    seen = set()
    for field, credential in credentials:
        key = guid(credential.get('keyId'))
        if key in seen:
            raise EvidenceError('credential key identifier is duplicated')
        seen.add(key)
        created, expires = instant(credential.get('startDateTime')), instant(credential.get('endDateTime'))
        if expires <= created or created > now:
            raise EvidenceError('credential lifetime metadata is contradictory')
        detail = {'key_id': key, 'credential_type': 'password' if field == 'passwordCredentials' else 'certificate',
                  'created_at': created.isoformat(), 'expires_at': expires.isoformat()}
        if expires <= now:
            inactive.append(detail)
            continue
        if created >= now - timedelta(days=DAYS):
            recent.append({**detail, 'reason': 'credential is newer than the inactivity interval'})
            continue
        report = mapping.get((origin, identity, app, key))
        if report is None:
            unresolved.append({**detail, 'reason': 'no matching credential activity record'})
            continue
        try:
            expected_type = 'clientSecret' if field == 'passwordCredentials' else 'certificate'
            if report.get('keyType') != expected_type:
                raise EvidenceError('credential activity type differs from the current credential')
            if report.get('createdDateTime') is not None and instant(report['createdDateTime']) != created:
                raise EvidenceError('credential activity creation date differs from the current credential')
            if report.get('expirationDateTime') is not None and instant(report['expirationDateTime']) != expires:
                raise EvidenceError('credential activity expiry differs from the current credential')
            status, last, basis = _latest_activity(report, 'signInActivity', now)
            if last < created:
                raise EvidenceError('credential activity predates credential creation')
            detail.update({basis: last.isoformat(), 'days_since_recorded_activity': (now-last).days})
            if status == 'FAIL': stale.append(detail)
            elif status == 'PASS': recent.append(detail)
            else: unresolved.append({**detail, 'reason': 'recent attempt has no successful-use evidence'})
        except (EvidenceError, ValueError) as exc:
            unresolved.append({**detail, 'reason': str(exc)})
    evidence = {'object_id': identity, 'app_id': app, 'credential_origin': origin, 'threshold_days': DAYS,
                'unused_credentials': stale, 'unresolved_credentials': unresolved,
                'recent_credentials': recent, 'expired_credentials': inactive, 'report_status': source.get('status'),
                'activity_source_endpoint': REPORTS['credential_activity']}
    name = item.get('displayName', identity)
    if stale:
        evidence['summary'] = f'{name} has {len(stale)} active credentials with recorded activity older than 90 days.\nTheir key IDs and last recorded dates are listed with this finding.\nThese credentials could retain access after their original workload is removed.'
        return 'FAIL', evidence
    if unresolved:
        evidence['summary'] = f'{name} has {len(unresolved)} credentials without sufficient recent-use evidence.\nThe matching activity record or successful-use timestamp is unavailable.\nIt is unclear which of these credentials still serves an active workload.'
        return ('DENIED' if source.get('status') == 'denied' else 'UNKNOWN'), evidence
    if recent:
        evidence['summary'] = f'{name} has {len(recent)} active credentials with recent successful use or a creation date within 90 days.\nNo active credential has a confirmed older inactivity signal.\nNew creation dates are retained separately from successful authentication dates.'
        return 'PASS', evidence
    return 'NOT_APPLICABLE', {**evidence, 'reason': 'no current unexpired password or certificate credentials'}


def application_consumer(item, index):
    identity, context = _current(item, index, 'directory_application')
    app = guid(_field(item, 'appId'))
    source = _native(index, 'directory_service_principal', '/tenants/' + guid(context['metadata']['tenant_id']))
    matches = [row for row in source['items'] if guid(row.get('appId')) == app]
    if len(matches) > 1:
        raise EvidenceError('application has ambiguous local service principal identities')
    if matches:
        return 'PASS', {'application_id': identity, 'service_principal_id': guid(matches[0].get('id')),
            'summary': f'Application {item.get("displayName", identity)} has a local enterprise application.\nIts app ID matches a current service principal in this tenant.\nThis provides a declared local consumer, without establishing recent authentication.'}
    if source.get('status') not in ('collected', 'empty'):
        _unavailable(source, 'complete local service principal inventory is unavailable')
    if _field(item, 'signInAudience') != 'AzureADMyOrg':
        raise EvidenceError('a multi-tenant application may have consumers in other tenants')
    return 'FAIL', {'application_id': identity, 'app_id': app, 'local_service_principal_count': 0,
        'summary': f'Single-tenant application {item.get("displayName", identity)} has no local enterprise application.\nIts app ID has no service principal in the complete tenant inventory.\nThe registration and its credentials may remain after the intended local application was removed.'}


def guarded(function, item, index):
    try:
        return function(item, index)
    except (EvidenceError, ValueError, TypeError, KeyError, AttributeError) as exc:
        name = item.get('displayName', item.get('id', 'directory identity')) if isinstance(item, dict) else 'directory identity'
        return getattr(exc, 'status', 'UNKNOWN'), {'reason': str(exc),
            'summary': f'Usage evidence for {name} is unresolved: {exc}.\nThe required directory identity or activity source is unavailable or inconsistent.\nIt is unclear whether this identity or its credentials still serve an active consumer.'}


def evaluate_group(item, index): return guarded(group_members, item, index)
def evaluate_principal(item, index): return guarded(principal_activity, item, index)
def evaluate_application_credentials(item, index): return guarded(partial(credential_activity, application=True), item, index)
def evaluate_principal_credentials(item, index): return guarded(partial(credential_activity, application=False), item, index)
def evaluate_application(item, index): return guarded(application_consumer, item, index)

DECLARATIONS = (
    ('azure.iam.static_group_has_members', 'directory_group', 'Static directory group has members', evaluate_group),
    ('azure.iam.service_principal_recent_activity', 'directory_service_principal', 'Service principal has no confirmed activity older than 90 days', evaluate_principal),
    ('azure.iam.application_credentials_recent_activity', 'directory_application', 'Application credentials have no confirmed stale activity', evaluate_application_credentials),
    ('azure.iam.service_principal_credentials_recent_activity', 'directory_service_principal', 'Service principal credentials have no confirmed stale activity', evaluate_principal_credentials),
    ('azure.iam.single_tenant_application_has_consumer', 'directory_application', 'Single-tenant application has a local enterprise application', evaluate_application),
)


def install(registry):
    import json
    from pathlib import Path
    from peaso.checks.fixtures import CASES
    raw = Path(__file__).with_name('checks').joinpath('unused_iam_azure_cases.json').read_bytes()
    cases = json.loads(raw)
    if set(cases) != {row[0] for row in DECLARATIONS}:
        raise ValueError('unused Azure IAM fixture IDs differ from registration')
    for ident, kind, title, predicate in DECLARATIONS:
        registry.register(ident, 'azure', 'hardening', kind, title, 'low', 'AC-2',
            'Confirm identity ownership and remove obsolete groups, applications or credentials; use short-lived or managed identity credentials where practical.',
            dependencies=(kind, KIND), allow_incomplete_failure=True)(predicate)
        CASES[ident] = cases[ident]
    from peaso.unused_iam_azure_roles import install as install_roles
    install_roles(registry)
    from peaso.unused_iam_azure_arm_roles import install as install_arm_roles
    install_arm_roles(registry)
    from peaso.unused_iam_azure_user_completion import install as install_user_success
    install_user_success(registry)

