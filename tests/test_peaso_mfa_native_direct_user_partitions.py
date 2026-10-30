"""Native direct-user MFA coverage via actual collector and registered engine."""
import copy
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit, parse_qs

from peaso.collectors import azure, collect_live
from peaso.engine import evaluate_snapshot, plan_collection
from peaso.snapshot import validate
from tests.test_peaso_mfa_native_combined_consistency import CombinedAPI, SUB, SCOPE, CHECKS, ADMIN
from tests.test_peaso_azure_conditional_access_native import STRENGTH

U1 = 'aaaaaaaa-1111-2222-3333-111111111111'
U2 = 'bbbbbbbb-1111-2222-3333-222222222222'
DISABLED = 'cccccccc-1111-2222-3333-333333333333'


def selector(include, exclude=()):
    return {'users': {'includeUsers': include, 'excludeUsers': list(exclude),
        'includeGroups': [], 'excludeGroups': [], 'includeRoles': [], 'excludeRoles': []},
        'applications': {'includeApplications': ['All'], 'excludeApplications': []},
        'clientAppTypes': ['all']}


def row(rid, include, exclude=(), **changes):
    return rid, {'conditions': selector(include, exclude), **changes}


class PartitionAPI(CombinedAPI):
    def request(self, url, *, body=None, audience=azure.ARM):
        path = urlsplit(url).path
        if path == '/v1.0/users' and self.mode in ('denied-users', 'partial-users'):
            if self.mode == 'denied-users' or '$skiptoken' in parse_qs(urlsplit(url).query):
                self.calls.append((url, audience, body))
                raise azure.AzureReadError('inert_native_directory_denied', 403)
        result = super().request(url, body=body, audience=audience)
        if path == '/v1.0/users':
            result = {'value': [{'id': uid, 'accountEnabled': enabled, 'userType': 'Member'}
                for uid, enabled in [(U1, True), (U2, True), (DISABLED, False)]]}
            if self.mode == 'partial-users':
                result['@odata.nextLink'] = azure.GRAPH + path + '?$skiptoken=next'
        return result


def collect(monkeypatch, rows, mode='complete'):
    api = PartitionAPI(rows, mode)
    monkeypatch.setattr(azure, 'AzureTransport', lambda auth: api);monkeypatch.setattr(azure,'AzureTransportExposure',lambda auth: api)
    now = datetime.now(timezone.utc)
    owner = {'status': 'collected', 'scope': SCOPE, 'authorized_by': 'security-owner',
        'document_id': 'mfa-obligation', 'observed_at': (now-timedelta(hours=1)).isoformat(),
        'expires_at': (now+timedelta(hours=1)).isoformat(),
        'checks': {cid.replace('.', '|'): {'userScope': 'administrative' if cid == ADMIN else 'all',
            'designatedGroups': ['admin-group'], 'designatedRoles': [],
            'requiredApplications': ['app-1'], 'requiredClientAppTypes': ['browser']} for cid in CHECKS}}
    connector = {'provider': 'azure', 'scopes': [SUB],
        'options': {'retries': 0, 'compliance_policy': {'sw13': owner}}}
    snap = collect_live(connector, plan_collection({'connector': connector, 'checks': CHECKS}))
    assert all(body is None for url, audience, body in api.calls)
    assert snap['metadata']['compliance_policy']['sw13'] == owner
    return snap


def assert_status(snap, expected, policy_ids=None):
    report = evaluate_snapshot(snap, checks=CHECKS, include_not_applicable=True)
    actual = {cid: {f['status'] for f in report['findings'] if f['check_id'] == cid} for cid in CHECKS}
    assert actual == {cid: {expected} for cid in CHECKS}, actual
    if policy_ids is not None:
        # Evidence contains policy identifiers and counts, never principal IDs.
        import json
        for finding in report['findings']:
            if finding['check_id'] not in CHECKS:
                continue
            encoded = json.dumps(finding['evidence'])
            assert U1 not in encoded and U2 not in encoded and DISABLED not in encoded
            assert all(rid in encoded for rid in policy_ids)


def test_split_direct_user_policies_cover_complete_enabled_universe(monkeypatch):
    rows = [row('mfa-a', [U1]), row('mfa-b', [U2.upper()])]
    assert_status(collect(monkeypatch, rows), 'PASS', ['mfa-a', 'mfa-b'])


def test_one_explicit_full_user_list_and_grant_and_cover_universe(monkeypatch):
    controls = {'operator': 'AND', 'builtInControls': ['mfa', 'compliantDevice'],
        'authenticationStrength': None, 'customAuthenticationFactors': [], 'termsOfUse': []}
    assert_status(collect(monkeypatch, [row('explicit-full', [U1, U2], grantControls=controls)]),
        'PASS', ['explicit-full'])


def test_direct_exclusion_is_recovered_by_separate_mfa_strength_policy(monkeypatch):
    controls = {'operator': 'OR', 'builtInControls': [], 'authenticationStrength': {'id': STRENGTH},
        'customAuthenticationFactors': [], 'termsOfUse': []}
    rows = [row('all-except-b', ['All'], [U2]), row('strength-b', [U2], grantControls=controls)]
    assert_status(collect(monkeypatch, rows, mode='strength'), 'PASS', ['all-except-b', 'strength-b'])


def test_uncovered_enabled_user_is_unknown_not_false_gap_fail(monkeypatch):
    assert_status(collect(monkeypatch, [row('only-a', [U1])]), 'UNKNOWN')


def test_exclusion_overrides_direct_inclusion_and_cannot_cover_itself(monkeypatch):
    rows = [row('except-b', ['All'], [U2]), row('b-excluded-again', [U2], [U2])]
    assert_status(collect(monkeypatch, rows), 'UNKNOWN')


def test_report_only_or_disabled_rules_do_not_fill_union_gap(monkeypatch):
    for state in ('enabledForReportingButNotEnforced', 'disabled'):
        rows = [row('a-enforced', [U1]), row('b-unenforced', [U2], state=state)]
        assert_status(collect(monkeypatch, rows), 'UNKNOWN')


def test_or_device_bypass_does_not_require_mfa_for_second_principal(monkeypatch):
    controls = {'operator': 'OR', 'builtInControls': ['mfa', 'compliantDevice'],
        'authenticationStrength': None, 'customAuthenticationFactors': [], 'termsOfUse': []}
    rows = [row('a-enforced', [U1]), row('b-bypass', [U2], grantControls=controls)]
    assert_status(collect(monkeypatch, rows), 'UNKNOWN')


def test_unsupported_selector_or_context_never_contributes_coverage(monkeypatch):
    variants = []
    for field, value in [('includeGroups', [U2]), ('excludeRoles', [U2]),
                         ('includeGuestsOrExternalUsers', {'guestOrExternalUserTypes': 'b2bCollaborationGuest'})]:
        condition = selector([U2]); condition['users'][field] = value; variants.append(condition)
    variants += [selector(['All', U2]), selector(['GuestsOrExternalUsers']), selector(['not-an-id'])]
    for field, value in [('signInRiskLevels', ['high']), ('locations', {'includeLocations': ['All']}),
                         ('devices', {'deviceFilter': {'mode': 'exclude', 'rule': 'inert'}})]:
        condition = selector([U2]); condition[field] = value; variants.append(condition)
    for condition in variants:
        rows = [row('a-enforced', [U1]), ('unsupported-b', {'conditions': condition})]
        assert_status(collect(monkeypatch, rows), 'UNKNOWN')


def test_denied_or_partial_directory_blocks_otherwise_complete_union(monkeypatch):
    for mode in ('denied-users', 'partial-users'):
        assert_status(collect(monkeypatch, [row('mfa-a', [U1]), row('mfa-b', [U2])], mode), 'UNKNOWN')


def test_invalid_foreign_duplicate_identity_and_defaults_never_prove_union(monkeypatch):
    rows = [row('mfa-a', [U1]), row('mfa-b', [U2])]
    for mutation in ('invalid-id', 'foreign-tenant', 'duplicate-id', 'defaults-enabled'):
        snap = collect(monkeypatch, rows)
        if mutation == 'defaults-enabled':
            next(e for e in snap['collections'] if e['type'] == 'directory_security_defaults')['items'][0]['isEnabled'] = True
        else:
            env = next(e for e in snap['collections'] if e['type'] == 'directory_user')
            if mutation == 'invalid-id':
                env['items'][0]['id'] = 'not-native-guid'
            elif mutation == 'foreign-tenant':
                env['items'][0]['_provenance']['tenant_id'] = 'dddddddd-1111-2222-3333-444444444444'
            else:
                env['items'].append(copy.deepcopy(env['items'][0]))
        snap.pop('snapshot_id')
        assert_status(validate(snap), 'UNKNOWN')


def test_conflicting_directory_pages_cannot_hide_enabled_uncovered_user(monkeypatch):
    original = PartitionAPI.request
    def conflicting(self, url, *, body=None, audience=azure.ARM):
        response = original(self, url, body=body, audience=audience)
        if urlsplit(url).path == '/v1.0/users':
            if '$skiptoken' in parse_qs(urlsplit(url).query):
                return {'value': [{'id': U2, 'accountEnabled': True, 'userType': 'Member'}]}
            for user in response['value']:
                if user['id'] == U2:
                    user['accountEnabled'] = False
            response['@odata.nextLink'] = azure.GRAPH + '/v1.0/users?$skiptoken=second'
        return response
    monkeypatch.setattr(PartitionAPI, 'request', conflicting)
    assert_status(collect(monkeypatch, [row('only-a', [U1])]), 'UNKNOWN')
