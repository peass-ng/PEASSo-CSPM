"""Approved app/client Cartesian coverage through actual native HTTP collection."""
import copy
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

from peaso.collectors import azure, collect_live
from peaso.engine import evaluate_snapshot, plan_collection
from tests.test_peaso_mfa_native_risk_consumer import RiskAPI, RISK, risk_row
from tests.test_peaso_mfa_native_group_consumer import P1, P2, G1, group_row
from tests.test_peaso_mfa_native_direct_user_partitions import U1, U2, DISABLED, CHECKS, row
from tests.test_peaso_azure_conditional_access_native import SUB, SCOPE, ADMIN, STRENGTH

A1 = '11111111-1111-aaaa-bbbb-111111111111'
A2 = '22222222-2222-aaaa-bbbb-222222222222'
P3 = '33333333-dddd-eeee-ffff-333333333333'


def scoped(pid, apps=('All',), clients=('all',), include=('All',), exclude=(), levels=None):
    pid, value = row(pid, list(include))
    value['conditions']['applications'] = {'includeApplications': list(apps), 'excludeApplications': list(exclude)}
    value['conditions']['clientAppTypes'] = list(clients)
    if levels is not None: value['conditions']['signInRiskLevels'] = list(levels)
    return pid, value


def collected(monkeypatch, rows, apps=(A1, A2), clients=('browser',), mode='complete', groups=None, deny_strength=False, user_count=None):
    api = RiskAPI(rows, mode, groups)
    if deny_strength:
        native_request = api.request
        def request(url, *, body=None, audience=azure.ARM):
            if urlsplit(url).path == '/v1.0/policies/authenticationStrengthPolicies':
                api.calls.append((url, audience, body)); raise azure.AzureReadError('inert_strength_denied', 403)
            return native_request(url, body=body, audience=audience)
        api.request = request
    if user_count is not None:
        user_request = api.request
        def many_users(url, *, body=None, audience=azure.ARM):
            response = user_request(url, body=body, audience=audience)
            if urlsplit(url).path == '/v1.0/users':
                return {'value': [{'id': f'{i:08x}-1111-2222-3333-123456789abc',
                    'accountEnabled': True, 'userType': 'Member'} for i in range(user_count)]}
            return response
        api.request = many_users
    monkeypatch.setattr(azure, 'AzureTransportExposure', lambda auth: api)
    now = datetime.now(timezone.utc)
    owner = {'status': 'collected', 'scope': SCOPE, 'authorized_by': 'security-owner',
        'document_id': 'explicit-application-client-obligation',
        'observed_at': (now-timedelta(hours=1)).isoformat(), 'expires_at': (now+timedelta(hours=1)).isoformat(),
        'checks': {cid.replace('.', '|'): {'userScope': 'administrative' if cid == ADMIN else 'all',
            'designatedGroups': ['admin-group'], 'designatedRoles': [],
            'requiredApplications': list(apps), 'requiredClientAppTypes': list(clients)} for cid in CHECKS}}
    connector = {'provider': 'azure', 'scopes': [SUB],
        'options': {'retries': 0, 'compliance_policy': {'sw13': owner}}}
    snap = collect_live(connector, plan_collection({'connector': connector, 'checks': CHECKS}))
    assert snap['metadata']['compliance_policy']['sw13'] == owner
    assert all(body is None for _, _, body in api.calls)
    return snap


def assert_status(snap, expected='PASS', ordinary=None):
    report = evaluate_snapshot(snap, checks=CHECKS, include_not_applicable=True)
    actual = {cid: {f['status'] for f in report['findings'] if f['check_id'] == cid} for cid in CHECKS}
    assert actual == {cid: {ordinary if ordinary is not None and cid != RISK else expected} for cid in CHECKS}, actual
    if expected == 'PASS':
        import json
        for finding in report['findings']:
            if finding['check_id'] in CHECKS:
                evidence = json.dumps(finding['evidence'])
                assert U1 not in evidence and U2 not in evidence and DISABLED not in evidence


def test_two_app_specific_mfa_policies_cover_approved_application_universe(monkeypatch):
    assert_status(collected(monkeypatch, [scoped(P1, [A1]), scoped(P2, [A2])]))


def test_client_type_partitions_cover_every_approved_client(monkeypatch):
    rows = [scoped(P1, [A1], ['browser']), scoped(P2, [A1], ['mobileAppsAndDesktopClients'])]
    assert_status(collected(monkeypatch, rows, apps=[A1], clients=['browser', 'mobileAppsAndDesktopClients']))


def test_cartesian_group_user_apps_clients_and_both_risks(monkeypatch):
    first = group_row(P1, include=[G1])
    second = scoped(P2, [A1, A2], ['browser', 'mobileAppsAndDesktopClients'], include=[U2], levels=['medium', 'high'])
    snap = collected(monkeypatch, [first, second], clients=['browser', 'mobileAppsAndDesktopClients'],
                     mode='only-u2', groups={G1: [U1]})
    assert_status(snap, ordinary='UNKNOWN')


def test_missing_required_application_or_client_never_yields_native_fail(monkeypatch):
    for apps, clients, required_apps, required_clients in [([A1], ['all'], [A1, A2], ['browser']),
            ([A1], ['browser'], [A1], ['browser', 'mobileAppsAndDesktopClients'])]:
        assert_status(collected(monkeypatch, [scoped(P1, apps, clients)],
            apps=required_apps, clients=required_clients), 'UNKNOWN')


def test_explicit_app_exclusion_can_be_recovered_by_independent_policy(monkeypatch):
    rows = [scoped(P1, exclude=[A2]), scoped(P2, [A2])]
    assert_status(collected(monkeypatch, rows))


def test_missing_or_unreadable_app_exclusions_are_not_assumed_empty(monkeypatch):
    for mutation in ('missing', 'unreadable'):
        pid, value = scoped(P1)
        app = value['conditions']['applications']
        if mutation == 'missing': del app['excludeApplications']
        else: app['_coverage'] = {'excludeApplications': {'status': 'denied'}}
        assert_status(collected(monkeypatch, [(pid, value)]), 'UNKNOWN')


def test_one_app_with_mfa_or_device_bypass_leaves_unproved_context(monkeypatch):
    pid, value = scoped(P2, [A2])
    value['grantControls'] = {'operator': 'OR', 'builtInControls': ['mfa', 'compliantDevice'],
        'authenticationStrength': None, 'customAuthenticationFactors': [], 'termsOfUse': []}
    assert_status(collected(monkeypatch, [scoped(P1, [A1]), (pid, value)]), 'UNKNOWN')


def test_required_all_cannot_be_replaced_by_finite_apps_or_known_client_enum_list(monkeypatch):
    assert_status(collected(monkeypatch, [scoped(P1, [A1, A2])], apps=['All']), 'UNKNOWN')
    assert_status(collected(monkeypatch, [scoped(P1, [A1],
        ['browser', 'mobileAppsAndDesktopClients', 'exchangeActiveSync', 'other'])],
        apps=[A1], clients=['all']), 'UNKNOWN')


def test_app_filters_actions_bundles_contexts_and_unknown_clients_are_unsupported(monkeypatch):
    variants = []
    for key, value in [('includeApplications', ['Office365']), ('includeApplications', ['All', A1]),
            ('excludeApplications', ['MicrosoftAdminPortals']),
            ('applicationFilter', {'mode': 'include', 'rule': 'inert'}),
            ('includeUserActions', ['urn:user:registerdevice']), ('includeAuthenticationContextClassReferences', ['c1'])]:
        pid, rule_value = scoped(P1, [A1, A2]); rule_value['conditions']['applications'][key] = value
        variants.append((pid, rule_value))
    variants += [scoped(P1, [A1, A2], ['futureClient']), scoped(P1, [A1, A2], ['easSupported'])]
    for variant in variants: assert_status(collected(monkeypatch, [variant]), 'UNKNOWN')


def test_approved_axis_must_be_guid_or_exact_all_and_supported_client(monkeypatch):
    for apps, clients in [(['unknown-app'], ['browser']), ([A1, A1.upper()], ['browser']), ([A1], ['futureClient'])]:
        assert_status(collected(monkeypatch, [scoped(P1, [A1])], apps=apps, clients=clients), 'UNKNOWN')


def test_context_hard_limit_refuses_cartesian_expansion(monkeypatch):
    apps = [f'{i:08x}-1234-5678-9abc-123456789abc' for i in range(65)]
    clients = ['browser', 'mobileAppsAndDesktopClients', 'exchangeActiveSync', 'other']
    # 65users *65apps *4clients =16900, with owner JSON below the hosted limit.
    assert_status(collected(monkeypatch, [scoped(P1, ['All'], clients)],
                            apps=apps, clients=clients, user_count=65), 'UNKNOWN')


def test_independent_complete_context_proof_survives_unrelated_unreadable_strength(monkeypatch):
    pid, value = scoped(P3, [A1])
    value['grantControls'] = {'operator': 'AND', 'builtInControls': [], 'authenticationStrength': {'id': STRENGTH},
        'customAuthenticationFactors': [], 'termsOfUse': []}
    assert_status(collected(monkeypatch, [scoped(P1, [A1]), scoped(P2, [A2]), (pid, value)], deny_strength=True))


def test_partition_proof_requires_current_ca_and_defaults_source_authority(monkeypatch):
    from peaso.snapshot import validate
    for kind in ('conditional_access_policy', 'directory_security_defaults'):
        for mutation in ('envelope-capture', 'row-customer', 'row-endpoint', 'row-readonly'):
            snap = collected(monkeypatch, [scoped(P1, [A1]), scoped(P2, [A2])])
            env = next(e for e in snap['collections'] if e['type'] == kind)
            proof = env['_provenance'] if mutation == 'envelope-capture' else env['items'][0]['_provenance']
            key, value = {'envelope-capture': ('credential_context_id', 'previous-capture'),
                'row-customer': ('customer_context_id', 'other-customer'),
                'row-endpoint': ('endpoint', '/v1.0/unrelated'),
                'row-readonly': ('read_only', False)}[mutation]
            proof[key] = value
            snap.pop('snapshot_id')
            assert_status(validate(snap), 'UNKNOWN')


def test_finite_scope_strength_requires_current_native_capture(monkeypatch):
    from peaso.snapshot import validate
    for mutation in ('envelope-capture', 'row-customer', 'row-readonly', 'row-operation'):
        pid, value = scoped(P1, [A1, A2])
        value['grantControls'] = {'operator': 'AND', 'builtInControls': [],
            'authenticationStrength': {'id': STRENGTH}, 'customAuthenticationFactors': [], 'termsOfUse': []}
        snap = collected(monkeypatch, [(pid, value)])
        assert_status(snap)  # Actual projected strength is sufficient before deliberate mutation.
        env = next(e for e in snap['collections'] if e['type'] == 'authentication_strength')
        proof = env['_provenance'] if mutation == 'envelope-capture' else env['items'][0]['_provenance']
        key, change = {'envelope-capture': ('credential_context_id', 'previous-capture'),
            'row-customer': ('customer_context_id', 'other-customer'),
            'row-readonly': ('read_only', False),
            'row-operation': ('source_operation', 'Unrelated_List')}[mutation]
        proof[key] = change
        snap.pop('snapshot_id')
        assert_status(validate(snap), 'UNKNOWN')


def test_independent_unrestricted_all_rule_does_not_borrow_directory_capture(monkeypatch):
    from peaso.snapshot import validate
    snap = collected(monkeypatch, [scoped(P1)])
    env = next(e for e in snap['collections'] if e['type'] == 'directory_user')
    env['_provenance']['credential_context_id'] = 'previous-capture'
    snap.pop('snapshot_id')
    assert_status(validate(snap))


def test_unread_optional_candidate_cannot_poison_independent_finite_proof(monkeypatch):
    from peaso.snapshot import validate
    for field in ('locations', 'platforms', 'excludeUsers', 'excludeGroups', 'futureCondition'):
        snap = collected(monkeypatch, [scoped(P1, [A1]), scoped(P2, [A2]), scoped(P3)])
        env = next(e for e in snap['collections'] if e['type'] == 'conditional_access_policy')
        conditions = next(r for r in env['items'] if r['id'] == P3)['conditions']
        container = conditions['users'] if field.startswith('exclude') else conditions
        container.setdefault('_coverage', {})[field] = {'status': 'denied'}
        snap.pop('snapshot_id')
        assert_status(validate(snap))


def test_coverage_only_absent_future_condition_cannot_be_unrestricted(monkeypatch):
    from peaso.snapshot import validate
    for status in ('denied', 'partial', 'not_collected'):
        snap = collected(monkeypatch, [scoped(P1)])
        env = next(e for e in snap['collections'] if e['type'] == 'conditional_access_policy')
        env['items'][0]['conditions']['_coverage'] = {'futureCondition': {'status': status}}
        snap.pop('snapshot_id')
        assert_status(validate(snap), 'UNKNOWN')
