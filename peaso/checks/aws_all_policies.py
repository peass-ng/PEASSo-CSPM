"""Pinned Steampipe IAM wildcard controls over customer-managed default policies."""
from __future__ import annotations
import json
from collections import Counter
import re
from pathlib import Path
from . import register, result, unknown
from .facts import Unavailable, complete_items, get, list_of_objects, memoized
from .aws_policy_source_correction import CORRECTIONS
from .aws_policy_boundary_usage import boundary_only

MODES = {
    'aws.nist.all_iam_policies_no_star_star': 'star',
    'aws.nist.all_managed_policies_no_service_wildcard': 'service',
    'aws_nist_iam_policy_no_star_star': 'star',
    'aws_nist_iam_all_policy_no_service_wild_card': 'service',
    'aws_g6_iam_all_policy_star_star': 'star',
    'aws_g6_iam_all_policy_service_wildcard': 'service',
}
# Historical proposal bytes remain unchanged as signed ancestry.
SPECS = json.loads(Path(__file__).with_suffix('.json').read_text())


def _rows(index, account):
    kind = 'iam_customer_policy'
    rows = complete_items(index, kind)
    envelopes = get(index, 'collections', dict)[kind]
    expected = []
    for envelope in envelopes:
        if get(envelope, 'scope', str) != account+'/global' or get(envelope, 'type', str) != kind:
            raise Unavailable('foreign global IAM collection')
        expected.extend(list_of_objects(get(envelope, 'items', list)))
    wrappers = get(index, kind, list)
    encode = lambda value: json.dumps(value, sort_keys=True, separators=(',', ':'))
    if Counter(map(encode, expected)) != Counter(map(encode, rows)) or len(wrappers) != len(rows) or any(
            get(w, 'scope', str) != account+'/global' or get(w, 'type', str) != kind for w in wrappers):
        raise Unavailable('IAM wrappers do not match complete native collection')
    return rows


def _statements(document):
    statements = get(document, 'Statement')
    return list_of_objects([statements] if isinstance(statements, dict) else statements)


def _documents(index):
    context = get(index, 'context', dict)
    account = get(context, 'Account', str)
    if (get(context, 'provider', str) != 'aws' or not re.fullmatch(r'[0-9]{12}', account)
            or not re.fullmatch(re.escape(account)+r'/(?:global|[a-z0-9-]+)', get(context, 'scope', str))):
        raise Unavailable('global IAM account authority missing')
    out, seen = [], set()
    for row in _rows(index, account):
        arn = get(row, 'Arn', str)
        if not re.fullmatch(r'arn:(aws|aws-cn|aws-us-gov):iam::'+account+r':policy/.+', arn) or arn in seen:
            raise Unavailable('foreign or duplicate customer policy')
        seen.add(arn)
        provenance = get(row, '_provenance', dict)
        if (provenance.get('operation') != 'iam:ListPolicies' or provenance.get('managed_scope') != 'Local'
                or provenance.get('only_attached') is not False or provenance.get('account_id') != account
                or provenance.get('default_operation') != 'iam:GetPolicyVersion'):
            raise Unavailable('customer policy universe unproven')
        detail = get(row, 'DefaultDocument', dict)
        if get(detail, 'VersionId', str) != get(row, 'DefaultVersionId', str):
            raise Unavailable('default policy version mismatch')
        if boundary_only(row):
            continue  # A permissions boundary only limits access; it grants nothing.
        out.extend((arn, statement) for statement in _statements(get(detail, 'Document', dict)))
    return out


def _strings(value):
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list) or not value or any(not isinstance(v, str) or not v for v in value):
        raise Unavailable('malformed IAM action/resource')
    return value


def scan(index, mode):
    documents = memoized(index, 'customer_managed_default_documents', lambda: _documents(index))
    hits, unresolved = [], False
    for source, statement in documents:
        effect = get(statement, 'Effect', str)
        if effect not in ('Allow', 'Deny'):
            raise Unavailable('unknown IAM statement effect')
        if effect == 'Deny':
            continue
        if 'NotAction' in statement or 'NotResource' in statement:
            unresolved = True
            continue
        actions, resources = _strings(get(statement, 'Action')), _strings(get(statement, 'Resource'))
        if '*' not in resources:
            continue
        if mode == 'star':
            match = any(action in ('*', '*:*') for action in actions)
        else:
            # SQL: action LIKE '%:*' OR action = '*'. Resource must be literal '*'.
            match = any(action == '*' or action.endswith(':*') for action in actions)
        if match:
            hits.append(source)
    if unresolved and not hits:
        return unknown('NotAction/NotResource cannot establish the pinned literal-action predicate', matching_policy_sources=[])
    return result(bool(hits), matching_policy_sources=sorted(set(hits)), scanned_statements=len(documents),
                  semantics='Customer-managed default policies, attached or unattached; pinned Steampipe literal wildcard SQL')


for ident, mode in MODES.items():
    spec = CORRECTIONS[ident]['spec']
    def evaluate(item, index, mode=mode):
        context = get(index, 'context', dict)
        if get(item, 'scope', str) != get(context, 'scope', str):
            raise Unavailable('scope target mismatch')
        return scan(index, mode)
    register(ident, 'aws', 'hardening', spec['resource_kind'], spec['title'], spec['severity'], 'AC-6', spec['remediation_hint'],
             target='scope', dependencies=['iam_customer_policy'])(evaluate)

from .fixtures import CASES
CASES.update(json.loads(Path(__file__).with_name('aws_all_policies_fixtures.json').read_text()))
