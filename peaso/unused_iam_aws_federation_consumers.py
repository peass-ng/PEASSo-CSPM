"""Declared consumers of native IAM federation providers, not sign-in activity."""
from __future__ import annotations

import fnmatch
import hashlib
import json
import re
from pathlib import Path

from peaso.unused_iam_aws_inline import EvidenceError, authority, field, records

SAML_CHECK = 'aws.iam.saml_provider_has_role_consumer'
OIDC_CHECK = 'aws.iam.oidc_provider_has_role_consumer'
CHECKS = {SAML_CHECK: ('iam_saml_provider', 'saml-provider', 'sts:AssumeRoleWithSAML', 'SAML'),
          OIDC_CHECK: ('iam_oidc_provider', 'oidc-provider', 'sts:AssumeRoleWithWebIdentity', 'OIDC')}
CASES_SHA256 = '12d96f354413dcadddf3fabb6928d74f631fcfad2d5ccd1dccf57b6235046329'


def _arn(value, account, label):
    match = re.fullmatch(r'arn:(aws(?:-[a-z0-9]+)*):iam::([0-9]{12}):' + label + r'/([^\s*?]+)', value) if isinstance(value, str) else None
    if not match or match[2] != account or any(part in ('', '.', '..') for part in match[3].split('/')):
        raise EvidenceError('native IAM ' + label + ' ARN and assessed account disagree')
    return value


def _source_status(source, name):
    if source.get('status') == 'empty' and source.get('items'):
        raise EvidenceError('native ' + name + ' empty status contradicts captured rows')
    if source.get('status') not in ('collected', 'empty'):
        cause = source.get('error', {}).get('cause_status', source.get('status'))
        raise EvidenceError('complete native ' + name + ' inventory is unavailable', 'DENIED' if cause == 'denied' else 'UNKNOWN')


def _provider(item, index, scope, account, kind, label):
    arn = _arn(field(item, 'Arn'), account, label)
    if item.get('AccountId', account) != account:
        raise EvidenceError('provider account binding is malformed')
    rows, source = records(index, kind, scope)
    if source.get('status') == 'empty' and rows:
        raise EvidenceError('native provider empty status contradicts captured rows')
    if source.get('global', True) is not True:
        raise EvidenceError('provider inventory is not global')
    if sum(row is item or row == item for row in rows) != 1:
        raise EvidenceError('assessed provider is missing or duplicated in native inventory')
    if sum(isinstance(row, dict) and row.get('Arn') == arn for row in rows) != 1:
        raise EvidenceError('provider ARN is duplicated in native inventory')
    # These list APIs do not attach per-row provenance. The scoped IAM collection
    # and exact row projection are the native source binding.
    proof = item.get('_provenance')
    operation = 'iam:ListSAMLProviders' if kind == 'iam_saml_provider' else 'iam:ListOpenIDConnectProviders'
    if proof is not None and (not isinstance(proof, dict) or proof.get('operation') != operation
                              or proof.get('native_response_complete') is not True):
        raise EvidenceError('provider native provenance is malformed')
    return arn, source


def _role_identity(role, account):
    name, stable, arn = field(role, 'RoleName'), field(role, 'RoleId'), field(role, 'Arn')
    if not isinstance(name, str) or not re.fullmatch(r'[\w+=,.@-]{1,64}', name, re.ASCII) or not isinstance(stable, str) or not re.fullmatch(r'AROA[A-Z0-9]{12,124}', stable):
        raise EvidenceError('native IAM role identity is malformed')
    _arn(arn, account, 'role')
    if arn.rsplit('/', 1)[-1] != name or role.get('AccountId', account) != account:
        raise EvidenceError('native IAM role identity and ARN disagree')
    proof = role.get('_provenance')
    if not isinstance(proof, dict) or proof.get('operation') != 'iam:GetAccountAuthorizationDetails' or proof.get('native_response_complete') is not True:
        raise EvidenceError('complete native IAM role authorization response is unavailable')
    return name, stable, arn


def _values(value):
    values = [value] if isinstance(value, str) else value
    if not isinstance(values, list) or not values or any(not isinstance(v, str) or not v for v in values):
        raise EvidenceError('role trust clause is malformed')
    return values


def _trust(role, targets):
    document = field(role, 'AssumeRolePolicyDocument')
    if not isinstance(document, dict):
        raise EvidenceError('role trust document is unavailable')
    statements = document.get('Statement')
    statements = [statements] if isinstance(statements, dict) else statements
    if not isinstance(statements, list) or not statements:
        raise EvidenceError('role trust statements are unavailable')
    found = set()
    for statement in statements:
        if not isinstance(statement, dict) or statement.get('Effect') not in ('Allow', 'Deny'):
            raise EvidenceError('role trust statement is malformed')
        if 'Condition' in statement and not isinstance(statement['Condition'], dict):
            raise EvidenceError('role trust condition is malformed')
        if ('Action' in statement) == ('NotAction' in statement) or ('Principal' in statement) == ('NotPrincipal' in statement):
            raise EvidenceError('role trust action or principal is unsupported')
        actions = _values(statement.get('Action', statement.get('NotAction')))
        principal = statement.get('Principal', statement.get('NotPrincipal'))
        if statement['Effect'] == 'Deny':
            continue
        if 'NotAction' in statement or 'NotPrincipal' in statement or principal == '*':
            raise EvidenceError('role trust wildcard or negative semantics cannot prove provider absence')
        if not isinstance(principal, dict):
            raise EvidenceError('role trust principal is malformed')
        federated = principal.get('Federated', [])
        federated = [] if federated == [] else _values(federated)
        if any('*' in value or '?' in value for value in federated):
            raise EvidenceError('role trust federated wildcard cannot prove provider absence')
        for key, value in principal.items():
            if key not in ('Federated', 'AWS', 'Service', 'CanonicalUser'):
                raise EvidenceError('role trust principal type is unsupported')
            values = _values(value)
            if key != 'Federated' and any('*' in candidate or '?' in candidate for candidate in values):
                raise EvidenceError('role trust principal wildcard cannot prove provider absence')
        for target, action in targets.items():
            if target in federated and any(fnmatch.fnmatchcase(action.lower(), pattern.lower()) for pattern in actions):
                found.add(target)
    return found


def _roles(index, scope, account, targets):
    from peaso.checks.facts import memoized
    def build():
        rows, source = records(index, 'iam_role', scope)
        consumers = {arn: [] for arn in targets}
        unresolved = []
        # A conflicting duplicate must not leave the first row certified as a
        # consumer. Count raw native identity keys before accepting any trust;
        # malformed unrelated roles still do not invalidate a unique consumer.
        identity_counts = {'RoleId': {}, 'Arn': {}}
        for role in rows:
            if isinstance(role, dict):
                for field_name, counts in identity_counts.items():
                    value = role.get(field_name)
                    if isinstance(value, str):
                        counts[value] = counts.get(value, 0) + 1
        for role in rows:
            try:
                name, stable, arn = _role_identity(role, account)
                if identity_counts['RoleId'][stable] != 1 or identity_counts['Arn'][arn] != 1:
                    raise EvidenceError('native IAM role identity is duplicated')
                for target in _trust(role, targets):
                    consumers[target].append({'role_arn': arn, 'role_id': stable, 'role_name': name})
            except EvidenceError as exc:
                unresolved.append(exc)
        return consumers, unresolved, source
    return memoized(index, ('unused_aws_federation_role_trusts', scope), build)


def evaluate(item, index, check_id):
    kind, label, action, family = CHECKS[check_id]
    try:
        scope, account = authority(index)
        arn, source = _provider(item, index, scope, account, kind, label)
        if source.get('status') not in ('collected', 'partial'):
            _source_status(source, family + ' provider')
        # The same role scan supplies both provider families. A target is derived
        # only from validated, current native provider rows in this exact scope.
        targets = {}
        for provider_kind, provider_label, assume_action, _ in CHECKS.values():
            try:
                provider_rows, _ = records(index, provider_kind, scope)
            except EvidenceError:
                continue
            for provider in provider_rows:
                try:
                    target = _arn(field(provider, 'Arn'), account, provider_label)
                    targets[target] = assume_action
                except EvidenceError:
                    continue
        targets[arn] = action
        consumers, unresolved, roles = _roles(index, scope, account, targets)
        found = consumers.get(arn, [])
        evidence = {'provider_arn': arn, 'role_consumers': found,
                    'semantics': 'Declared role trust, not authentication or provider sign-in history.'}
        if found:
            return 'PASS', {**evidence, 'summary': f'{family} provider {arn} is declared by {len(found)} IAM role trust policy.\nThe role is a current structural consumer.\nAuthentication activity is not inferred.'}
        _source_status(source, family + ' provider')
        _source_status(roles, 'IAM role trust')
        if unresolved:
            raise unresolved[0]
        return 'FAIL', {**evidence, 'summary': f'{family} provider {arn} has no declaring IAM role trust policy.\nThe account-wide native role trust inventory is complete.\nReview the provider before removal; authentication activity is not inferred.'}
    except (EvidenceError, ValueError, TypeError, KeyError, AttributeError) as exc:
        status = getattr(exc, 'status', 'UNKNOWN')
        return status, {'reason': str(exc), 'summary': str(exc).rstrip('.') + '.\nThe provider’s current role trust consumers are unresolved.'}


def install(registry):
    from peaso.checks.fixtures import CASES
    raw = Path(__file__).with_name('checks').joinpath('unused_iam_aws_federation_consumers_cases.json').read_bytes()
    if hashlib.sha256(raw).hexdigest() != CASES_SHA256:
        raise ValueError('AWS federation consumer native cases changed')
    cases = json.loads(raw)
    if set(cases) != set(CHECKS):
        raise ValueError('AWS federation consumer native case IDs changed')
    for check_id, (kind, _, _, family) in CHECKS.items():
        CASES[check_id] = cases[check_id]
        registry.register(check_id, 'aws', 'hardening', kind, family + ' provider has a role consumer', 'low', 'AC-2',
            'Review provider ownership and remove obsolete federation providers after confirming intended consumers.',
            dependencies=(kind, 'iam_role'), allow_incomplete_failure=True)(
                lambda item, index, check_id=check_id: evaluate(item, index, check_id))
