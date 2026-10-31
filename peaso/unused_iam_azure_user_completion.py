"""Native successor for the existing Azure successful-user-sign-in control."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path

from peaso.azure_unused_iam_contract import guid
from peaso.azure_unused_iam_user_completion_contract import KIND, SCHEMA, GRAPH, ENDPOINT, digest, project
from peaso.iam_usage_evidence import instant

CHECK = 'azure.claude.entra_user_recent_sign_in'
TITLE = 'Enabled Entra ID user has a recorded successful sign-in within 90 days of the snapshot'
THRESHOLD = timedelta(days=90)
SUCCESS_START = datetime(2023, 12, 1, tzinfo=timezone.utc)


class EvidenceError(ValueError):
    def __init__(self, message, status='UNKNOWN'):
        super().__init__(message)
        self.status = status


def _bound(proof, meta, *, endpoint=None):
    return (isinstance(proof, dict) and proof.get('tenant_verified') is True
            and proof.get('tenant_id') == meta['tenant_id']
            and proof.get('credential_context_id') == meta['credential_context_id']
            and proof.get('customer_context_id') == meta['customer_context_id']
            and (endpoint is None or proof.get('endpoint') == endpoint))


def _collection(index, kind, scope, meta):
    collections = index.get('collections', {}).get(kind)
    projected = index.get(kind)
    if not isinstance(collections, list) or len(collections) != 1 or not isinstance(projected, list):
        raise EvidenceError('unique current Graph inventory is unavailable')
    source = collections[0]
    if (source.get('type') != kind or str(source.get('scope', '')).lower() != scope
            or source.get('service') != 'Microsoft.Graph' or not _bound(source.get('_provenance'), meta)
            or not isinstance(source.get('items'), list)
            or any(not isinstance(row, dict) or row.get('type') != kind
                   or str(row.get('scope', '')).lower() != scope for row in projected)
            or [row.get('data') for row in projected] != source['items']):
        raise EvidenceError('native Graph inventory and resource projection disagree')
    return source


def _current(item, index):
    context = index.get('context', {})
    meta = context.get('metadata', {})
    tenant = guid(meta.get('tenant_id'))
    scope = '/tenants/' + tenant
    if (context.get('provider') != 'azure' or str(context.get('scope', '')).lower() != scope
            or meta.get('tenant_verified') is not True
            or any(not isinstance(meta.get(key), str) or not meta[key] for key in ('credential_context_id', 'customer_context_id'))):
        raise EvidenceError('verified directory capture authority is unavailable')
    now = instant(context.get('created_at'))
    user_id = guid(item.get('id'))
    if not _bound(item.get('_provenance'), meta, endpoint='/v1.0/users') or item['_provenance'].get('read_only') is not True:
        raise EvidenceError('selected user lacks native Graph source binding')
    roster = _collection(index, 'directory_user', scope, meta)
    if roster.get('status') not in ('collected', 'empty'):
        raise EvidenceError('current directory user roster is incomplete', 'DENIED' if roster.get('status') == 'denied' else 'UNKNOWN')
    matches = [row for row in roster['items'] if isinstance(row, dict) and str(row.get('id', '')).lower() == user_id]
    if len(matches) != 1 or matches[0] != item:
        raise EvidenceError('selected user is absent or ambiguous in the current roster')
    return user_id, scope, meta, now


def _receipt(index, scope, meta, now):
    source = _collection(index, KIND, scope, meta)
    if source.get('status') != 'collected' or len(source['items']) != 1:
        raise EvidenceError('native user-success receipt is unavailable')
    record = source['items'][0]
    proof = record.get('_provenance')
    if (record.get('schema') != SCHEMA or str(record.get('id', '')).lower() != scope + '/usersuccessevidence'
            or not _bound(proof, meta, endpoint='native-user-success-projection')
            or proof.get('schema') != SCHEMA or proof.get('read_only') is not True
            or abs(instant(proof.get('observed_at')) - now) > timedelta(days=1)):
        raise EvidenceError('user-success evidence belongs to another capture')
    report = record.get('source')
    if (not isinstance(report, dict) or report.get('endpoint') != ENDPOINT or report.get('audience') != GRAPH
            or report.get('method') != 'GET' or report.get('body', 'missing') is not None
            or not isinstance(report.get('items'), list) or report.get('items_sha256') != digest(report['items'])
            or type(report.get('integrity_error')) is not bool):
        raise EvidenceError('user-success source or immutable projection is unresolved')
    if report.get('status') not in ('collected', 'empty', 'partial', 'denied', 'unknown', 'malformed', 'timeout'):
        raise EvidenceError('user-success source status is invalid')
    if report['status'] == 'empty' and report['items']:
        raise EvidenceError('empty user-success source contains rows')
    if report.get('integrity_error'):
        raise EvidenceError('user-success source identity or continuation is malformed')
    return report


def evaluate(item, index):
    try:
        user_id, scope, meta, now = _current(item, index)
        if item.get('accountEnabled') is False:
            return 'NOT_APPLICABLE', {'reason': 'user account is disabled', 'user_id': user_id}
        if item.get('accountEnabled') is not True:
            raise EvidenceError('user enabled state is unavailable')
        coverage = item.get('_coverage', {}).get('signInActivity', {})
        if coverage and coverage.get('status') not in ('collected', 'empty'):
            raise EvidenceError('Graph sign-in activity was unavailable', 'DENIED' if coverage.get('status') == 'denied' else 'UNKNOWN')
        report = _receipt(index, scope, meta, now)
        if report['status'] not in ('collected', 'empty'):
            raise EvidenceError('complete user-success roster is unavailable', 'DENIED' if report['status'] == 'denied' else 'UNKNOWN')
        rows = report['items']
        if len({guid(row.get('id')) for row in rows}) != len(rows):
            raise EvidenceError('user-success roster has duplicate identities')
        matches = [row for row in rows if row['id'] == user_id]
        if len(matches) != 1:
            raise EvidenceError('current user is absent from the successful-sign-in roster')
        row = matches[0]
        # The separate Graph read must agree with the current directory-user
        # projection. Creation time comes from the explicit success read.
        for field in ('displayName', 'accountEnabled', 'signInActivity'):
            if field not in item or row.get(field) != item[field]:
                raise EvidenceError('current user projection and successful-sign-in read disagree')
        created = instant(row['createdDateTime']) if row.get('createdDateTime') is not None else None
        if created is not None and created > now:
            raise EvidenceError('user creation is later than the capture')
        if now - THRESHOLD < SUCCESS_START:
            raise EvidenceError('successful sign-in field does not cover the full interval')
        activity = row.get('signInActivity')
        if not isinstance(activity, dict) or not activity.get('lastSuccessfulSignInDateTime'):
            raise EvidenceError('no successful sign-in timestamp; absence is not unused proof')
        success = instant(activity['lastSuccessfulSignInDateTime'])
        if success < max(created or SUCCESS_START, SUCCESS_START) or success > now:
            raise EvidenceError('successful sign-in is outside the current user lifetime or capture')
        details = {'user_id': user_id, 'created_at': created.isoformat() if created else None,
                   'last_successful_sign_in': success.isoformat(), 'days_since_success': (now-success).days,
                   'threshold_days': THRESHOLD.days, 'activity_source_endpoint': ENDPOINT}
        name = item.get('displayName', user_id)
        if now - success > THRESHOLD:
            return 'FAIL', {**details, 'summary': f'User {name} last signed in successfully on {success.date().isoformat()}.\nThat success is more than 90 days before this capture.\nReview the account owner before changing access.'}
        return 'PASS', {**details, 'summary': f'User {name} signed in successfully on {success.date().isoformat()}.\nThat recorded success is within 90 days.\nThe account has recent observed authentication.'}
    except (EvidenceError, ValueError, TypeError, KeyError, AttributeError, OverflowError) as exc:
        status = getattr(exc, 'status', 'UNKNOWN')
        return status, {'reason': str(exc), 'summary': f'User successful sign-in is unresolved: {exc}.\nThe required current directory or Graph activity evidence is incomplete.\nNo inactivity claim is made.'}


def install(registry):
    from peaso.checks.fixtures import CASES
    path = Path(__file__).with_name('checks') / 'unused_iam_azure_user_completion_cases.json'
    raw = path.read_bytes()
    cases = json.loads(raw)
    if set(cases) != {CHECK}:
        raise ValueError('Azure user-success case ID differs from registration')
    from dataclasses import replace
    matching = [check for check in registry.CHECKS if check.id == CHECK]
    if len(matching) != 1 or matching[0].provider != 'azure' or matching[0].kind != 'directory_user':
        raise ValueError('Azure successful-user-sign-in predecessor changed')
    registry.CHECKS[:] = [replace(check, evaluate=evaluate,
        declared_dependencies=tuple(dict.fromkeys((*check.dependencies, KIND)))) if check.id == CHECK else check
        for check in registry.CHECKS]
    CASES[CHECK] = cases[CHECK]


