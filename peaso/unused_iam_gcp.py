"""Bound GCP unused-identity decisions from native authentication and insight data."""
from __future__ import annotations
from datetime import timedelta
from decimal import Decimal
from functools import partial
import re

from peaso.gcp_iam_usage_contract import ACTIVITY_TYPES, INSIGHT_KIND, INSIGHT_TYPE, timestamp

ACCOUNT = 'gcp.claude.service_account.recently_used'
KEY = 'gcp.claude.service_account_key.recently_used'
INSIGHT_CHECK = 'gcp.iam.service_account_no_active_unused_insight'
DAYS = 180
MAX_LAG = timedelta(days=3)


class Unavailable(ValueError):
    def __init__(self, reason, status='UNKNOWN'):
        super().__init__(reason)
        self.status = status


def _field(item, name, default=...):
    if not isinstance(item, dict):
        raise Unavailable('native identity is unavailable')
    cov = item.get('_coverage', {})
    if not isinstance(cov, dict):
        raise Unavailable('native field coverage is malformed')
    if name in cov:
        marker = cov[name]
        if not isinstance(marker, dict) or marker.get('status') not in ('collected', 'empty'):
            raise Unavailable('native field is unavailable: ' + name,
                              'DENIED' if isinstance(marker, dict) and marker.get('status') == 'denied' else 'UNKNOWN')
    if name not in item:
        if default is ...:
            raise Unavailable('native field is missing: ' + name)
        return default
    return item[name]


def _capture(item, index):
    proof = _field(item, '_provenance')
    if not isinstance(proof, dict) or not re.fullmatch(r'projects/[A-Za-z0-9_-]+', proof.get('scope', '')):
        raise Unavailable('native project capture is unavailable')
    context = index.get('context', {})
    if context and (context.get('provider') != 'gcp' or context.get('scope') != proof['scope']):
        raise Unavailable('native identity belongs to another project capture')
    clock = context.get('created_at') or proof.get('collected_at')
    return proof['scope'], timestamp(clock), proof


def _receipt(index, refs, scope, url):
    ledger = index.get('context', {}).get('metadata', {}).get('source_requests')
    if ledger is None:
        # Resource-only offline evaluations still require the native field and
        # parent capture's matching request references. Full snapshots add the
        # exact HTTP endpoint proof below.
        return
    for reference in refs:
        matches = [row for row in ledger if isinstance(row, dict) and row.get('id') == reference]
        if (len(matches) != 1 or matches[0].get('scope') != scope or matches[0].get('method') != 'GET'
                or matches[0].get('url') != url or matches[0].get('status') != 'collected'):
            raise Unavailable('native activity HTTP receipt does not match its source')


def activity(item, index, *, key):
    kind = 'service_account_key' if key else 'service_account'
    scope, now, proof = _capture(item, index)
    disabled = _field(item, 'disabled', False)
    if type(disabled) is not bool:
        raise Unavailable('identity disabled state is malformed')
    if disabled:
        return 'NOT_APPLICABLE', {'reason': 'identity or credential is disabled'}
    if key:
        key_type = _field(item, 'keyType')
        if key_type == 'SYSTEM_MANAGED':
            return 'NOT_APPLICABLE', {'reason': 'key is Google-managed'}
        if key_type != 'USER_MANAGED':
            raise Unavailable('service account key type is unrecognized')
    created = timestamp(_field(item, 'validAfterTime')) if key else None
    if created is not None:
        if created > now:
            raise Unavailable('key creation date is later than its capture')
        if created >= now-timedelta(days=DAYS):
            return 'PASS', {'key_name': _field(item, 'name'), 'created_at': created.isoformat(),
                'object_age_days': (now-created).days, 'threshold_days': DAYS,
                'summary': f'Key {_field(item, "name")} was created on {created.date().isoformat()}.\nIt has not existed beyond the 180-day inactivity threshold.\nThis creation date is separate from successful authentication evidence.'}
    fact = _field(item, '_activity')
    if not isinstance(fact, dict) or fact.get('activity_type') != ACTIVITY_TYPES[kind] or fact.get('project_scope') != scope:
        raise Unavailable('activity observation is not bound to the native identity type and project')
    name = _field(item, 'name')
    suffix = r'/keys/[^/?#]+' if key else ''
    if not isinstance(name, str) or not re.fullmatch(r'projects/[^/?#]+/serviceAccounts/[^/?#]+' + suffix, name):
        raise Unavailable('native identity resource name is malformed')
    resource_name = fact.get('resource_name')
    if (not isinstance(resource_name, str) or not isinstance(name, str)
            or resource_name.split('/', 2)[2:] != name.split('/', 2)[2:]):
        raise Unavailable('activity observation names a different identity')
    coverage = item.get('_coverage', {}).get('_activity', {})
    if not key:
        uid = _field(item, 'uniqueId')
        if not isinstance(uid, str) or fact.get('service_account_id') != uid:
            raise Unavailable('activity refers to a different service account unique ID')
    refs = coverage.get('source_requests') if isinstance(coverage, dict) else None
    parent_refs = proof.get('source_requests')
    if (not isinstance(refs, list) or not refs or any(not isinstance(ref, str) or not ref for ref in refs)
            or not isinstance(parent_refs, list) or not set(refs) <= set(parent_refs)):
        raise Unavailable('activity request references are not bound to the parent identity capture')
    endpoint = f'https://policyanalyzer.googleapis.com/v1/{scope}/locations/global/activityTypes/{ACTIVITY_TYPES[kind]}/activities:query'
    _receipt(index, refs, scope, endpoint)
    start, end = timestamp(fact.get('observationStartTime')), timestamp(fact.get('observationEndTime'))
    if start >= end or end > now or now-end > MAX_LAG:
        raise Unavailable('activity observation interval is contradictory or more than three days behind capture')
    last = timestamp(fact['lastAuthenticatedTime']) if fact.get('lastAuthenticatedTime') is not None else None
    if last is not None and (last > end or created is not None and last < created):
        raise Unavailable('last authentication date is outside the credential lifetime or observation')
    evidence = {'identity_name': name, 'observation_start': start.isoformat(), 'observation_end': end.isoformat(),
                'threshold_days': DAYS, 'activity_source_endpoint': endpoint,
                'reported_last_authentication': last.isoformat() if last else None,
                'timestamp_precision': 'provider calendar day'}
    if last is not None:
        # Provider timestamps identify a calendar day, not the exact API call.
        latest_possible = min(last+timedelta(days=1)-timedelta(microseconds=1), end)
        evidence['days_since_reported_authentication'] = (end-last).days
        if last >= now-timedelta(days=DAYS):
            return 'PASS', {**evidence, 'summary': f'{name} has recorded authentication on {last.date().isoformat()}.\nThat recorded day is within the 180-day inactivity interval.\nIts usage data does not identify an abandoned identity in this interval.'}
        if latest_possible >= end-timedelta(days=DAYS):
            raise Unavailable('calendar-day precision or observation lag straddles the inactivity cutoff')
    if end-start <= timedelta(days=DAYS):
        raise Unavailable('the observed authentication history does not cover more than 180 days')
    if last is None and created is None:
        raise Unavailable('no authentication date or creation age is available; use the explicit unused-service-account insight')
    if created is not None and end-created <= timedelta(days=DAYS):
        raise Unavailable('the key has not existed for the complete inactivity interval')
    evidence['days_without_observed_authentication'] = (end-max(start, created)).days if last is None else None
    description = f'has recorded authentication on {last.date().isoformat()}' if last else f'has no authentication recorded between {start.date().isoformat()} and {end.date().isoformat()}'
    evidence['summary'] = f'{name} {description}.\nThe bound observation covers an inactivity interval longer than 180 days.\nIts persistent identity or credential could retain access after its intended workload is removed.'
    return 'FAIL', evidence


def guarded(function, item, index):
    try:
        return function(item, index)
    except (Unavailable, ValueError, TypeError, KeyError, AttributeError) as exc:
        return getattr(exc, 'status', 'UNKNOWN'), {'reason': str(exc),
            'summary': f'GCP identity usage is unresolved: {exc}.\nThe required resource-bound observation interval or credential metadata is unavailable.\nIt is unclear whether an obsolete identity or credential still retains access.'}


def evaluate_account(item, index): return guarded(partial(activity, key=False), item, index)
def evaluate_key(item, index): return guarded(partial(activity, key=True), item, index)


def _tokens(index, scope):
    tokens = {scope.split('/')[1]}
    binding = index.get('context', {}).get('metadata', {}).get('data_service_project_bindings', {}).get(scope)
    if binding is not None:
        if not isinstance(binding, dict) or binding.get('status') != 'collected' or binding.get('scope') != scope:
            raise Unavailable('project numeric alias binding is unavailable')
        refs = binding.get('source_requests')
        if not isinstance(refs, list) or not refs:
            raise Unavailable('project numeric alias request proof is unavailable')
        _receipt(index, refs, scope, 'https://cloudresourcemanager.googleapis.com/v3/' + scope)
        pid, number = binding.get('project_id'), binding.get('project_number')
        if not isinstance(pid, str) or not re.fullmatch(r'[1-9][0-9]*', str(number)) or not tokens.intersection({pid, str(number)}):
            raise Unavailable('project numeric alias is inconsistent')
        tokens.update((pid, str(number)))
    return tokens


def unused_insight(item, index):
    scope, now, proof = _capture(item, index)
    disabled = _field(item, 'disabled', False)
    if type(disabled) is not bool:
        raise Unavailable('service account disabled state is malformed')
    if disabled:
        return 'NOT_APPLICABLE', {'reason': 'service account is disabled'}
    email, uid = _field(item, 'email'), _field(item, 'uniqueId')
    if not isinstance(email, str) or not isinstance(uid, str) or not re.fullmatch(r'[1-9][0-9]{5,30}', uid):
        raise Unavailable('native service account email or numeric unique ID is unavailable')
    collections = index.get('collections', {}).get(INSIGHT_KIND, [])
    if not isinstance(collections, list) or len(collections) != 1:
        raise Unavailable('unused-service-account insight inventory was not collected')
    collection = collections[0]
    if collection.get('type') != INSIGHT_KIND or collection.get('scope') != scope or collection.get('service') != 'recommender':
        raise Unavailable('service account insight collection belongs to another scope')
    rows = collection.get('items')
    projected = index.get(INSIGHT_KIND, [])
    if not isinstance(rows, list) or not isinstance(projected, list) or [r.get('data') for r in projected] != rows:
        raise Unavailable('service account insight projection differs from its native collection')
    tokens = _tokens(index, scope)
    matching, unresolved, seen = [], [], set()
    for row in rows:
        name = row.get('name') if isinstance(row, dict) else None
        pattern = r'projects/([^/]+)/locations/global/insightTypes/google\.iam\.serviceAccount\.Insight/insights/[^/?#]+'
        match = re.fullmatch(pattern, name or '')
        if not match or match.group(1) not in tokens or name in seen:
            raise Unavailable('foreign, duplicate or malformed service account insight identity')
        seen.add(name)
        record_proof = _field(row, '_provenance')
        refs = record_proof.get('source_requests') if isinstance(record_proof, dict) else None
        if not isinstance(refs, list) or not refs or record_proof.get('scope') != scope:
            raise Unavailable('service account insight request provenance is unavailable')
        _receipt(index, refs, scope, f'https://recommender.googleapis.com/v1/{scope}/locations/global/insightTypes/{INSIGHT_TYPE}/insights')
        content = _field(row, 'content')
        if not isinstance(content, dict):
            raise Unavailable('service account insight content is malformed')
        if str(content.get('serviceAccountId')) != str(uid) or content.get('email') != email:
            continue
        state = _field(row, 'stateInfo')
        if not isinstance(state, dict) or state.get('state') not in ('ACTIVE', 'ACCEPTED', 'DISMISSED'):
            raise Unavailable('service account insight state is unavailable')
        if state['state'] != 'ACTIVE':
            continue
        try:
            if row.get('insightSubtype') != 'SERVICE_ACCOUNT_USAGE' or row.get('category') != 'SECURITY':
                raise Unavailable('service account insight subtype is unrecognized')
            targets = _field(row, 'targetResources')
            if not isinstance(targets, list) or not targets or any(target not in {
                    '//cloudresourcemanager.googleapis.com/projects/' + token for token in tokens} for target in targets):
                raise Unavailable('service account insight targets a different project')
            duration = _field(row, 'observationPeriod')
            if not isinstance(duration, str) or not re.fullmatch(r'[0-9]{1,12}(?:\.[0-9]{1,9})?s', duration):
                raise Unavailable('service account insight observation period is malformed')
            seconds = Decimal(duration[:-1])
            if seconds < 90*86400:
                raise Unavailable('service account insight has less than 90 days of observation')
            refreshed = timestamp(_field(row, 'lastRefreshTime'))
            if refreshed > now or now-refreshed > MAX_LAG:
                raise Unavailable('unused-service-account insight is stale or future dated')
            last = timestamp(content['lastAuthenticatedTime']) if content.get('lastAuthenticatedTime') else None
            if last is not None and refreshed-last < timedelta(days=90):
                raise Unavailable('unused insight conflicts with recent reported authentication')
            # Newer native authentication is a contradiction, not a reason to
            # keep presenting an outdated unused-account failure.
            observed = item.get('_activity', {})
            if isinstance(observed, dict) and observed.get('lastAuthenticatedTime'):
                status, evidence = evaluate_account(item, index)
                if status == 'PASS' and evidence.get('reported_last_authentication') and timestamp(evidence['reported_last_authentication']) >= now-timedelta(days=90):
                    raise Unavailable('unused insight conflicts with bound recent authentication')
            matching.append({'insight_name': name, 'service_account_email': email,
                             'service_account_id': str(uid), 'last_refresh_time': refreshed.isoformat(),
                             'observation_seconds': str(seconds),
                             'reported_last_authentication': last.isoformat() if last else None})
        except (Unavailable, ValueError) as exc:
            unresolved.append({'insight_name': name, 'reason': str(exc)})
    evidence = {'service_account_email': email, 'service_account_id': str(uid),
                'active_unused_insights': matching, 'unresolved_insights': unresolved,
                'activity_source_endpoint': f'https://recommender.googleapis.com/v1/{scope}/locations/global/insightTypes/{INSIGHT_TYPE}/insights'}
    if matching:
        return 'FAIL', {**evidence, 'summary': f'Google reports {email} as an unused service account in an ACTIVE usage insight.\nThe matched insight covers at least 90 days and identifies the current service account unique ID.\nIts cloud permissions could remain available after its original workload is removed.'}
    if unresolved or collection.get('status') not in ('collected', 'empty'):
        raise Unavailable('unused-service-account insight evidence is incomplete or inconsistent',
                          'DENIED' if collection.get('status') == 'denied' else 'UNKNOWN')
    return 'PASS', {**evidence, 'summary': f'{email} has no ACTIVE unused-service-account insight in this project.\nThe complete Recommender result contains no matching inactive-account record.\nAuthentication dates remain separate observations.'}


def evaluate_insight(item, index): return guarded(unused_insight, item, index)


def install(registry):
    from dataclasses import replace
    from peaso.checks.fixtures import CASES
    import json
    from pathlib import Path
    raw = Path(__file__).with_name('checks').joinpath('unused_iam_gcp_cases.json').read_bytes()
    cases = json.loads(raw)
    if set(cases) != {ACCOUNT, KEY, INSIGHT_CHECK}:
        raise ValueError('GCP unused IAM native case IDs changed')
    CASES.update(cases)
    registry.CHECKS[:] = [replace(check, evaluate=evaluate_account if check.id == ACCOUNT else evaluate_key)
                         if check.id in (ACCOUNT, KEY) else check for check in registry.CHECKS]
    registry.register(INSIGHT_CHECK, 'gcp', 'hardening', 'service_account',
        'Service account has no active unused-access insight', 'low', 'AC-2',
        'Confirm service account ownership and workloads before disabling obsolete identities or removing their grants.',
        dependencies=('service_account', INSIGHT_KIND), allow_incomplete_failure=True)(evaluate_insight)
    from peaso.unused_iam_gcp_authorization import install as install_authorization
    install_authorization(registry)
    from peaso.unused_iam_gcp_directory import install as install_directory
    install_directory(registry)
    from peaso.unused_iam_gcp_keys import install as install_keys
    install_keys(registry)
    from peaso.unused_iam_gcp_roles import install as install_roles
    install_roles(registry)



def reviewed_description_successor(check_id, original, predecessor_sha256=None):
    """Return the corrected criteria unchanged when they are already the current text, else None."""
    from copy import deepcopy
    if check_id not in (ACCOUNT, KEY):
        return None
    # Runtime wheels carry the compiled criteria; the two correction rows are
    # retained below to avoid a documentation dependency.
    if original != DESCRIPTION_SUCCESSORS[check_id]['description']:
        return None
    return deepcopy(original)

DESCRIPTION_SUCCESSORS = {'gcp.claude.service_account.recently_used': {'description': {'description': 'Reviews resource-bound Policy '
                                                                             'Analyzer authentication '
                                                                             'observations for a service '
                                                                             'account. A stale-use failure '
                                                                             'requires more than 180 days of '
                                                                             'observation with fresh source '
                                                                             'coverage. Missing '
                                                                             'authentication dates alone '
                                                                             'never establish unused service '
                                                                             'accounts; new keys are '
                                                                             'separated using their creation '
                                                                             'dates. Provider calendar-day '
                                                                             'precision is preserved.',
                                                              'evaluated': ['native identity name, disabled '
                                                                            'state and capture provenance',
                                                                            'Policy Analyzer activity type, '
                                                                            'resource identity and exact '
                                                                            'request source',
                                                                            'observationStartTime and '
                                                                            'observationEndTime with at most '
                                                                            'three days of source lag',
                                                                            'lastAuthenticatedTime '
                                                                            'calendar-day precision'],
                                                              'pass_when': 'A bound authentication date is '
                                                                           'within 180 days of capture.',
                                                              'fail_when': 'A resource-bound complete '
                                                                           'observation interval longer than '
                                                                           '180 days has an older '
                                                                           'authentication day. A missing '
                                                                           'authentication date remains '
                                                                           'UNKNOWN and is evaluated '
                                                                           'separately through explicit '
                                                                           'service-account insights.',
                                                              'not_applicable_when': 'The identity is '
                                                                                     'disabled.'},
                                              'reason': 'Correct resource/window and null-date false '
                                                        'positives while retaining immutable original source '
                                                        'criteria and the native ID; the successor validates '
                                                        'actual native capture, observation coverage and '
                                                        'calendar-day precision.'},
 'gcp.claude.service_account_key.recently_used': {'description': {'description': 'Reviews resource-bound '
                                                                                 'Policy Analyzer '
                                                                                 'authentication '
                                                                                 'observations for a '
                                                                                 'user-managed service '
                                                                                 'account key. A stale-use '
                                                                                 'failure requires more than '
                                                                                 '180 days of observation '
                                                                                 'with fresh source '
                                                                                 'coverage. Missing '
                                                                                 'authentication dates alone '
                                                                                 'never establish unused '
                                                                                 'service accounts; new keys '
                                                                                 'are separated using their '
                                                                                 'creation dates. Provider '
                                                                                 'calendar-day precision is '
                                                                                 'preserved.',
                                                                  'evaluated': ['native identity name, '
                                                                                'disabled state and capture '
                                                                                'provenance',
                                                                                'Policy Analyzer activity '
                                                                                'type, resource identity and '
                                                                                'exact request source',
                                                                                'observationStartTime and '
                                                                                'observationEndTime with at '
                                                                                'most three days of source '
                                                                                'lag',
                                                                                'lastAuthenticatedTime '
                                                                                'calendar-day precision',
                                                                                'keyType and validAfterTime'],
                                                                  'pass_when': 'A bound authentication date '
                                                                               'is within 180 days of '
                                                                               'capture or a user-managed '
                                                                               'key was created within that '
                                                                               'interval.',
                                                                  'fail_when': 'A resource-bound complete '
                                                                               'observation interval longer '
                                                                               'than 180 days has an older '
                                                                               'authentication day or an old '
                                                                               'key has no observed '
                                                                               'authentication throughout '
                                                                               'its known lifetime and '
                                                                               'interval.',
                                                                  'not_applicable_when': 'The identity is '
                                                                                         'disabled or the '
                                                                                         'key is '
                                                                                         'Google-managed.'},
                                                  'reason': 'Correct resource/window and null-date false '
                                                            'positives while retaining immutable original '
                                                            'source criteria and the native ID; the '
                                                            'successor validates actual native capture, '
                                                            'observation coverage and calendar-day '
                                                            'precision.'}}
