from copy import deepcopy
from types import SimpleNamespace

import pytest

from peaso import unused_iam_azure as subject
from peaso.collectors import azure_unused_iam_20261021 as producer

TENANT = '11111111-1111-4111-8111-111111111111'
OBJECT = '22222222-2222-4222-8222-222222222222'
APP = '33333333-3333-4333-8333-333333333333'
KEY = '44444444-4444-4444-8444-444444444444'
OTHER = '55555555-5555-4555-8555-555555555555'
SCOPE = '/tenants/' + TENANT
NOW = '2026-10-21T12:00:00Z'


def proof(endpoint=None):
    output = {'tenant_id': TENANT, 'tenant_verified': True, 'credential_context_id': 'capture-one', 'customer_context_id': 'customer-one'}
    if endpoint: output.update(endpoint=endpoint, read_only=True)
    return output


def identity(kind='directory_service_principal', **changes):
    endpoint = {'directory_service_principal': '/v1.0/servicePrincipals',
                'directory_application': '/v1.0/applications', 'directory_group': '/v1.0/groups'}[kind]
    output = {'id': OBJECT, 'appId': APP, 'displayName': 'Synthetic identity', 'accountEnabled': True,
              'servicePrincipalType': 'Application', 'createdDateTime': '2025-01-01T00:00:00Z', 'visibility': 'Private', 'signInAudience': 'AzureADMyOrg', 'groupTypes': [],
              'passwordCredentials': [], 'keyCredentials': [], '_provenance': proof(endpoint)}
    output.update(changes)
    return output


def report(name, rows=None, status=None):
    rows = rows or []
    return {'name': name, 'endpoint': producer.REPORTS[name], 'audience': producer.GRAPH,
            'method': 'GET', 'body': None, 'items': rows,
            'status': status or ('collected' if rows else 'empty'), 'integrity_error': False}


def principal_record(when='2026-01-01T00:00:00Z', **changes):
    return {'id': 'opaque-principal-report', 'appId': APP,
            'lastSignInActivity': {'lastSignInDateTime': when}, **changes}


def credential_record(application=True, when='2026-01-01T00:00:00Z', **changes):
    return {'id': 'opaque-credential-report', 'appId': APP, 'keyId': KEY, 'keyType': 'clientSecret',
            'credentialOrigin': 'application' if application else 'servicePrincipal',
            'appObjectId': OBJECT if application else OTHER,
            'servicePrincipalObjectId': OTHER if application else OBJECT,
            'signInActivity': {'lastSignInDateTime': when}, **changes}


def credential(**changes):
    return {'keyId': KEY, 'startDateTime': '2025-01-01T00:00:00Z',
            'endDateTime': '2027-01-01T00:00:00Z', **changes}


def native(kind, rows=None, scope=SCOPE, status=None):
    rows = rows or []
    result = {'type': kind, 'scope': scope, 'service': 'Microsoft.Graph',
            'status': status or ('collected' if rows else 'empty'), 'items': rows}
    if kind == 'directory_membership':
        result.update(membership_api='beta', endpoint='/beta/groups/'+scope.rsplit('/',1)[-1]+'/members?$select=id')
    return result


def capture(item, kind='directory_service_principal', *, reports=None, extra_native=None):
    original = native(kind, [item])
    original['_provenance'] = proof()
    bound_proof = {**proof('native-unused-iam-projection'), 'schema': producer.SCHEMA, 'observed_at': NOW}
    record = {'id': SCOPE + '/unusedIamEvidence', 'schema': producer.SCHEMA,
              'native_collections': [native(kind, [producer.project_native(kind, item)]), *(extra_native or [])],
              'reports': reports if reports is not None else [report(name) for name in producer.REPORTS],
              '_provenance': bound_proof}
    envelope = {'type': producer.KIND, 'scope': SCOPE, 'service': 'Microsoft.Graph',
                'status': 'collected', 'items': [record], '_provenance': dict(bound_proof)}
    index = {'context': {'provider': 'azure', 'scope': SCOPE, 'created_at': NOW, 'metadata': proof()},
             'collections': {kind: [original], producer.KIND: [envelope]},
             kind: [{'type': kind, 'scope': SCOPE, 'data': item}],
             producer.KIND: [{'type': producer.KIND, 'scope': SCOPE, 'data': record}]}
    return index


def test_static_empty_group_is_a_hardening_failure():
    item = identity('directory_group')
    index = capture(item, 'directory_group', extra_native=[native('directory_membership', scope=SCOPE+'/groups/'+OBJECT)])
    status, evidence = subject.evaluate_group(item, index)
    assert status == 'FAIL'
    assert evidence['member_count'] == 0


@pytest.mark.parametrize('changes', [{'groupTypes': ['DynamicMembership']}, {'visibility': 'HiddenMembership'}])
def test_dynamic_or_hidden_empty_group_is_not_assumed_unused(changes):
    item = identity('directory_group', **changes)
    index = capture(item, 'directory_group', extra_native=[native('directory_membership', scope=SCOPE+'/groups/'+OBJECT)])
    assert subject.evaluate_group(item, index)[0] == 'UNKNOWN'


def test_partial_positive_membership_is_not_empty():
    item = identity('directory_group')
    index = capture(item, 'directory_group', extra_native=[native('directory_membership', [{'id': OTHER}],
        scope=SCOPE+'/groups/'+OBJECT, status='partial')])
    assert subject.evaluate_group(item, index)[0] == 'PASS'


def test_denied_empty_membership_is_denied_not_unused():
    item = identity('directory_group')
    index = capture(item, 'directory_group', extra_native=[native('directory_membership', scope=SCOPE+'/groups/'+OBJECT, status='denied')])
    assert subject.evaluate_group(item, index)[0] == 'DENIED'


def test_old_recorded_principal_activity_fails_with_exact_date_and_days():
    item = identity()
    index = capture(item, reports=[report('service_principal_activity', [principal_record()])])
    status, evidence = subject.evaluate_principal(item, index)
    assert status == 'FAIL'
    assert evidence['days_since_recorded_activity'] == 293
    assert evidence['last_recorded_sign_in'] == '2026-01-01T00:00:00+00:00'
    assert 'last_successful_sign_in' not in evidence


def test_recent_attempt_cannot_be_reported_as_successful_use():
    item = identity()
    index = capture(item, reports=[report('service_principal_activity', [principal_record('2026-10-20T12:00:00Z')])])
    assert subject.evaluate_principal(item, index)[0] == 'UNKNOWN'


def test_successful_recent_use_passes():
    item = identity()
    row = principal_record('2026-10-20T12:00:00Z')
    row['lastSignInActivity']['lastSuccessfulSignInDateTime'] = '2026-10-20T11:00:00Z'
    assert subject.evaluate_principal(item, capture(item, reports=[report('service_principal_activity', [row])]))[0] == 'PASS'


@pytest.mark.parametrize('rows', [[], [principal_record(appId=OTHER)], [principal_record(lastSignInActivity={})]])
def test_missing_or_unmatched_activity_is_unknown_not_unused(rows):
    item = identity()
    assert subject.evaluate_principal(item, capture(item, reports=[report('service_principal_activity', rows)]))[0] == 'UNKNOWN'


def test_malformed_aggregate_cannot_hide_more_recent_flow():
    item = identity()
    row = principal_record(delegatedResourceSignInActivity={'lastSignInDateTime': '2026-10-20T12:00:00Z'})
    assert subject.evaluate_principal(item, capture(item, reports=[report('service_principal_activity', [row])]))[0] == 'UNKNOWN'


def test_disabled_principal_does_not_require_activity_query():
    item = identity(accountEnabled=False)
    assert subject.evaluate_principal(item, capture(item, reports=[]))[0] == 'NOT_APPLICABLE'


@pytest.mark.parametrize('application', [True, False])
def test_current_credential_origin_parent_app_and_key_must_all_match(application):
    kind = 'directory_application' if application else 'directory_service_principal'
    evaluate = subject.evaluate_application_credentials if application else subject.evaluate_principal_credentials
    item = identity(kind, passwordCredentials=[credential()])
    row = credential_record(application)
    index = capture(item, kind, reports=[report('credential_activity', [row])])
    status, evidence = evaluate(item, index)
    assert status == 'FAIL'
    assert evidence['unused_credentials'][0]['key_id'] == KEY
    for field, value in [('appId', OTHER), ('keyId', OTHER),
                         ('appObjectId' if application else 'servicePrincipalObjectId', OTHER),
                         ('credentialOrigin', 'servicePrincipal' if application else 'application')]:
        changed = dict(row, **{field: value})
        assert evaluate(item, capture(item, kind, reports=[report('credential_activity', [changed])]))[0] == 'UNKNOWN'


def test_credential_type_and_lifetime_must_match():
    item = identity('directory_application', passwordCredentials=[credential()])
    for changes in [{'keyType': 'certificate'}, {'createdDateTime': '2024-01-01T00:00:00Z'},
                    {'expirationDateTime': '2028-01-01T00:00:00Z'}]:
        row = credential_record(**changes)
        assert subject.evaluate_application_credentials(item, capture(item, 'directory_application', reports=[report('credential_activity', [row])]))[0] == 'UNKNOWN'


def test_known_old_credential_survives_unrelated_unresolved_credential():
    item = identity('directory_application', passwordCredentials=[credential(), credential(keyId=OTHER)])
    index = capture(item, 'directory_application', reports=[report('credential_activity', [credential_record()], status='partial')])
    status, evidence = subject.evaluate_application_credentials(item, index)
    assert status == 'FAIL'
    assert len(evidence['unused_credentials']) == 1 and len(evidence['unresolved_credentials']) == 1


def test_new_credential_without_usage_does_not_fail_inactivity():
    item = identity('directory_application', passwordCredentials=[credential(startDateTime='2026-10-20T00:00:00Z')])
    index = capture(item, 'directory_application', reports=[report('credential_activity', status='denied')])
    status, evidence = subject.evaluate_application_credentials(item, index)
    assert status == 'PASS'
    assert 'last_successful_sign_in' not in evidence['recent_credentials'][0]


def test_expired_credential_is_not_reported_as_active_unused_access():
    item = identity('directory_application', passwordCredentials=[credential(endDateTime='2026-01-01T00:00:00Z')])
    assert subject.evaluate_application_credentials(item, capture(item, 'directory_application'))[0] == 'NOT_APPLICABLE'


def test_single_tenant_application_without_enterprise_application_fails():
    item = identity('directory_application')
    index = capture(item, 'directory_application', extra_native=[native('directory_service_principal')])
    assert subject.evaluate_application(item, index)[0] == 'FAIL'
    item['signInAudience'] = 'AzureADMultipleOrgs'
    assert subject.evaluate_application(item, index)[0] == 'UNKNOWN'


def test_application_local_consumer_is_matched_by_app_id_not_display_name():
    item = identity('directory_application')
    principal = identity(id=OTHER, displayName='Different label')
    index = capture(item, 'directory_application', extra_native=[native('directory_service_principal', [principal])])
    assert subject.evaluate_application(item, index)[0] == 'PASS'


@pytest.mark.parametrize('mutation', ['tenant', 'credential_context', 'customer_context', 'scope', 'projection', 'date', 'method', 'integrity'])
def test_activity_authority_and_native_capture_binding_cannot_be_bypassed(mutation):
    item = identity()
    index = capture(item, reports=[report('service_principal_activity', [principal_record()])])
    record = index[producer.KIND][0]['data']
    if mutation == 'tenant': record['_provenance']['tenant_id'] = OTHER
    elif mutation == 'credential_context': record['_provenance']['credential_context_id'] = 'foreign'
    elif mutation == 'customer_context': record['_provenance']['customer_context_id'] = 'foreign'
    elif mutation == 'scope': index['collections'][producer.KIND][0]['scope'] = '/tenants/' + OTHER
    elif mutation == 'projection': index[producer.KIND] = []
    elif mutation == 'date': record['_provenance']['observed_at'] = '2025-01-01T00:00:00Z'
    elif mutation == 'method': record['reports'][0]['method'] = 'POST'
    elif mutation == 'integrity': record['reports'][0]['integrity_error'] = True
    assert subject.evaluate_principal(item, index)[0] == 'UNKNOWN'


def test_evaluation_does_not_mutate_captured_evidence():
    item = identity()
    index = capture(item, reports=[report('service_principal_activity', [principal_record()])])
    before = deepcopy(index)
    subject.evaluate_principal(item, index)
    assert before == index


def test_collector_uses_only_report_get_pages_and_strips_secret_values():
    class Reader:
        def __init__(self): self.collections = [native('directory_application', [identity('directory_application', passwordCredentials=[dict(credential(), secretText='DO_NOT_COPY')])])]; self.calls = []
        def pages(self, request, url, **kwargs):
            self.calls.append((url, kwargs))
            if 'servicePrincipalSignInActivities' in url:
                yield [dict(principal_record(), token='DO_NOT_COPY')]
            else:
                yield [dict(credential_record(), secretText='DO_NOT_COPY')]
        def unavailable(self, *args): raise AssertionError(args)
    reader = Reader()
    producer.collect(reader, object(), [], {producer.KIND}, SimpleNamespace(tenant=TENANT, verified_tenant=TENANT), 'capture-one', 'customer-one')
    result = reader.collections[-1]
    assert result['status'] == 'collected'
    assert len(reader.calls) == 2
    assert all(call[1] == {'audience': producer.GRAPH, 'next_key': '@odata.nextLink'} for call in reader.calls)
    assert 'DO_NOT_COPY' not in str(result)


def test_collector_does_not_read_reports_when_not_requested():
    producer.collect(SimpleNamespace(), None, [], set(), SimpleNamespace(), None, None)


def test_collector_retains_valid_first_page_when_later_page_is_denied():
    class Denied(Exception): status_code = 403
    class Reader:
        def __init__(self): self.collections = []
        def pages(self, request, url, **kwargs):
            if 'servicePrincipalSignInActivities' in url:
                yield [principal_record()]
            raise Denied('DO_NOT_COPY')
        def unavailable(self, *args): raise AssertionError(args)
    reader = Reader()
    producer.collect(reader, object(), [], {producer.KIND}, SimpleNamespace(tenant=TENANT, verified_tenant=TENANT), 'capture-one', 'customer-one')
    sources = reader.collections[-1]['items'][0]['reports']
    assert sources[0]['status'] == 'partial' and len(sources[0]['items']) == 1
    assert sources[1]['status'] == 'denied' and sources[1]['items'] == []
    assert 'DO_NOT_COPY' not in str(sources)


def test_v1_empty_membership_does_not_prove_group_empty():
    item = identity('directory_group')
    membership = native('directory_membership', scope=SCOPE+'/groups/'+OBJECT)
    membership.pop('membership_api')
    index = capture(item, 'directory_group', extra_native=[membership])
    assert subject.evaluate_group(item, index)[0] == 'UNKNOWN'


def test_collector_rechecks_v1_empty_group_using_beta_and_detects_service_principal_member():
    class Reader:
        def __init__(self):
            self.collections = [native('directory_group', [identity('directory_group')]),
                native('directory_membership', scope=SCOPE+'/groups/'+OBJECT)]
            self.calls = []
        def pages(self, request, url, **kwargs):
            self.calls.append(url)
            if '/beta/groups/' in url: yield [{'id': OTHER, '@odata.type': '#microsoft.graph.servicePrincipal'}]
            else: yield []
        def unavailable(self, *args): raise AssertionError(args)
    reader = Reader()
    producer.collect(reader, object(), [], {producer.KIND}, SimpleNamespace(tenant=TENANT, verified_tenant=TENANT), 'capture-one', 'customer-one')
    record = reader.collections[-1]['items'][0]
    membership = next(c for c in record['native_collections'] if c['type'] == 'directory_membership')
    assert membership['membership_api'] == 'beta'
    assert membership['status'] == 'collected'
    assert membership['items'] == [{'id': OTHER}]
    assert len(reader.calls) == 3


def test_other_capture_identity_metadata_cannot_match_only_by_guid():
    item = identity()
    index = capture(item, reports=[report('service_principal_activity', [principal_record()])])
    item['appId'] = OTHER
    assert subject.evaluate_principal(item, index)[0] == 'UNKNOWN'


def test_real_reader_follows_report_pages_with_get_only():
    from peaso.collectors.azure import _Reader
    reader = _Reader({'retries': 0})
    calls = []
    def request(url, *, audience, body=None):
        calls.append((url, audience, body))
        assert audience == producer.GRAPH and body is None
        if 'servicePrincipalSignInActivities' in url:
            if '$skiptoken=' in url:
                return {'value': [principal_record(appId=OTHER, id='second-principal-report')]}
            return {'value': [principal_record()], '@odata.nextLink': url + '?$skiptoken=next-page'}
        return {'value': [credential_record()]}
    producer.collect(reader, request, [], {producer.KIND}, SimpleNamespace(tenant=TENANT, verified_tenant=TENANT), 'capture-one', 'customer-one')
    sources = reader.collections[-1]['items'][0]['reports']
    assert len(sources[0]['items']) == 2 and sources[0]['status'] == 'collected'
    assert len(sources[1]['items']) == 1 and sources[1]['status'] == 'collected'
    assert len(calls) == 3 and reader.budget.calls == 3


def test_real_reader_rejects_cross_origin_report_continuation():
    from peaso.collectors.azure import _Reader
    reader = _Reader({'retries': 0})
    calls = []
    def request(url, *, audience, body=None):
        calls.append(url)
        assert url.startswith(producer.GRAPH + '/')
        if 'servicePrincipalSignInActivities' in url:
            return {'value': [principal_record()], '@odata.nextLink': 'https://attacker.invalid/steal'}
        return {'value': []}
    producer.collect(reader, request, [], {producer.KIND}, SimpleNamespace(tenant=TENANT, verified_tenant=TENANT), 'capture-one', 'customer-one')
    sources = reader.collections[-1]['items'][0]['reports']
    assert sources[0]['status'] == 'partial'
    assert not sources[0]['integrity_error']
    assert len(calls) == 2



def test_new_service_principal_is_not_made_unused_by_old_app_activity():
    item = identity(createdDateTime='2026-10-20T00:00:00Z')
    status, evidence = subject.evaluate_principal(item, capture(item, reports=[report('service_principal_activity', [principal_record()])]))
    assert status == 'PASS'
    assert evidence['object_age_days'] == 1
    assert 'last_recorded_sign_in' not in evidence




def test_new_evidence_inventory_expands_existing_directory_inputs():
    from peaso.collectors.azure import _selected, TYPES
    assert producer.KIND in TYPES
    selected = _selected({}, [producer.KIND])
    assert {producer.KIND, *producer.BASE_KINDS} <= selected


def test_registered_native_cases_and_hacktricks_membership():
    from peaso.checks import CHECKS
    from peaso.checks.fixtures import CASES
    by_id = {check.id: check for check in CHECKS}
    for ident, kind, title, predicate in subject.DECLARATIONS:
        check = by_id[ident]
        case = CASES[ident]
        assert check.category == 'hardening'
        assert producer.KIND in check.dependencies
        assert 'HackTricks Cloud Best Practices' in check.frameworks
        assert check.evaluate(case['pass'], deepcopy(case['pass_index']))[0] == 'PASS', ident
        assert check.evaluate(case['fail'], deepcopy(case['fail_index']))[0] == 'FAIL', ident
        assert check.evaluate({}, deepcopy(case['index']))[0] == 'UNKNOWN', ident


@pytest.mark.parametrize('ident', [row[0] for row in subject.DECLARATIONS])
def test_normal_engine_emits_unused_iam_hardening_finding(ident):
    from peaso.checks.fixtures import CASES
    from peaso.engine import evaluate_snapshot, hydrate_frameworks
    from peaso.snapshot import make_snapshot
    case = CASES[ident]
    index = case['fail_index']
    collections = [deepcopy(row) for rows in index['collections'].values() for row in rows]
    snapshot = make_snapshot('azure', [SCOPE], collections, created_at=NOW, metadata=proof())
    report = hydrate_frameworks(evaluate_snapshot(snapshot, categories=['hardening'], checks=[ident]))
    findings = [row for row in report['findings'] if row['check_id'] == ident]
    assert len(findings) == 1
    assert findings[0]['category'] == 'hardening'
    assert findings[0]['status'] == 'FAIL', findings[0]
    assert 'HackTricks Cloud Best Practices' in findings[0]['frameworks']




def test_native_memo_index_reuses_join_data_without_mutating_the_snapshot():
    from peaso.checks.facts import MemoIndex
    item = identity()
    original = capture(item, reports=[report('service_principal_activity', [principal_record()])])
    before = deepcopy(original)
    index = MemoIndex(original)
    assert subject.evaluate_principal(item, index)[0] == 'FAIL'
    assert subject.evaluate_principal(item, index)[0] == 'FAIL'
    assert original == before


def test_managed_identity_service_principal_uses_bound_activity_when_available():
    item = identity(servicePrincipalType='ManagedIdentity')
    status, evidence = subject.evaluate_principal(item, capture(item, reports=[report('service_principal_activity', [principal_record()])]))
    assert status == 'FAIL'
    assert evidence['service_principal_type'] == 'ManagedIdentity'


def test_duplicate_report_for_another_app_does_not_hide_bound_stale_principal():
    item = identity()
    rows = [principal_record(), principal_record(appId=OTHER, id='other-1'), principal_record(appId=OTHER, id='other-2')]
    assert subject.evaluate_principal(item, capture(item, reports=[report('service_principal_activity', rows)]))[0] == 'FAIL'
    rows.append(principal_record(id='duplicate-current'))
    assert subject.evaluate_principal(item, capture(item, reports=[report('service_principal_activity', rows)]))[0] == 'UNKNOWN'



def test_empty_group_with_unavailable_visibility_is_not_assumed_static_and_visible():
    item = identity('directory_group')
    del item['visibility']
    index = capture(item, 'directory_group', extra_native=[native('directory_membership', scope=SCOPE+'/groups/'+OBJECT)])
    assert subject.evaluate_group(item, index)[0] == 'UNKNOWN'


def test_normal_azure_collector_dispatches_activity_and_beta_membership_reads():
    from datetime import datetime, timedelta, timezone
    from urllib.parse import urlsplit
    from peaso.collectors import azure
    from peaso.engine import evaluate_snapshot, hydrate_frameworks
    now = datetime.now(timezone.utc)
    group_id = OTHER
    app_object = '66666666-6666-4666-8666-666666666666'
    subscription = '/subscriptions/77777777-7777-4777-8777-777777777777'
    principal = identity(createdDateTime=(now-timedelta(days=400)).isoformat())
    group = identity('directory_group', id=group_id)
    application = identity('directory_application', id=app_object)
    activity = principal_record((now-timedelta(days=200)).isoformat())
    class Transport:
        tenant = TENANT
        verified_tenant = TENANT
        def __init__(self): self.calls = []
        def request(self, url, *, audience=azure.ARM, body=None):
            assert body is None and audience == producer.GRAPH
            self.calls.append(url)
            path = urlsplit(url).path
            if path == '/v1.0/groups': return {'value': [deepcopy(group)]}
            if path == '/v1.0/servicePrincipals': return {'value': [deepcopy(principal)]}
            if path == '/v1.0/applications': return {'value': [deepcopy(application)]}
            if path in ('/v1.0/groups/'+group_id+'/members', '/beta/groups/'+group_id+'/members'):
                return {'value': []}
            if path == producer.REPORTS['service_principal_activity']: return {'value': [activity]}
            if path == producer.REPORTS['credential_activity']: return {'value': []}
            raise AssertionError('unexpected native read: ' + path)
    transport = Transport()
    snapshot = azure.collect({'provider': 'azure', 'scopes': [subscription], 'auth': {'tenant_id': TENANT},
                              'options': {'inventories': [producer.KIND], 'concurrency': 1, 'retries': 0}}, transport=transport)
    evidence = next(row for row in snapshot['collections'] if row['type'] == producer.KIND)
    assert evidence['status'] == 'collected'
    assert any('/beta/groups/'+group_id+'/members' in url for url in transport.calls)
    assert any('createdDateTime' in url for url in transport.calls if '/servicePrincipals?' in url)
    ids = ['azure.iam.static_group_has_members', 'azure.iam.service_principal_recent_activity']
    result = hydrate_frameworks(evaluate_snapshot(snapshot, categories=['hardening'], checks=ids))
    findings = {row['check_id']: row for row in result['findings']}
    assert {ident: findings[ident]['status'] for ident in ids} == {ident: 'FAIL' for ident in ids}
    assert all('HackTricks Cloud Best Practices' in findings[ident]['frameworks'] for ident in ids)


def test_empty_group_compliance_mappings_keep_partial_assurance():
    from peaso.checks.catalog import requirement_tags_for
    tags = requirement_tags_for('azure.iam.static_group_has_members')
    selected = [tag for tag in tags if tag['framework_id'] == 'pci_4.0_azure']
    assert {tag['requirement_id'] for tag in selected} == {'7.2.5.1.1', '8.2.6.1'}
    assert all(tag['decision'] == 'PARTIAL' and tag['runtime_status'] == 'partial' for tag in selected)


@pytest.mark.parametrize('owner,first_party', [(None, False), ('f8cdef31-a31e-4b4a-93e4-5f571e91255a', True)])
def test_principal_missing_from_a_complete_report_names_the_report_and_owner(owner, first_party):
    item = identity(**({} if owner is None else {'appOwnerOrganizationId': owner}))
    index = capture(item, reports=[report('service_principal_activity', [principal_record(appId=OTHER)])])
    status, evidence = subject.evaluate_principal(item, index)
    assert status == 'UNKNOWN'
    assert 'servicePrincipalSignInActivities report has no row' in evidence['reason']
    assert ('Microsoft first-party' in evidence['reason']) is first_party


def test_recent_attempt_without_success_states_its_reason():
    item = identity()
    index = capture(item, reports=[report('service_principal_activity', [principal_record('2026-10-20T12:00:00Z')])])
    status, evidence = subject.evaluate_principal(item, index)
    assert status == 'UNKNOWN' and 'no successful sign-in date' in evidence['reason']
