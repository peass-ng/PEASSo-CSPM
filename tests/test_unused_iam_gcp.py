from copy import deepcopy
import pytest

from peaso import unused_iam_gcp as subject
from peaso.gcp_iam_usage_contract import project_activity, ACTIVITY_TYPES, INSIGHT_KIND

SCOPE = 'projects/usage-project'
NOW = '2026-10-21T12:00:00Z'
EMAIL = 'worker@usage-project.iam.gserviceaccount.com'
UID = '123456789012345678901'
NAME = SCOPE + '/serviceAccounts/' + EMAIL


def identity(key=False, last='2025-01-01T07:00:00Z', start='2024-01-01T07:00:00Z', end='2026-10-20T07:00:00Z'):
    kind = 'service_account_key' if key else 'service_account'
    name = NAME + '/keys/synthetic-key' if key else NAME
    body = {'lastAuthenticatedTime': last} if last else {}
    body['serviceAccount'] = {'serviceAccountId': UID}
    fact = project_activity({'activityType': ACTIVITY_TYPES[kind], 'fullResourceName': '//iam.googleapis.com/'+name,
        'observationPeriod': {'startTime': start, 'endTime': end}, 'activity': body}, SCOPE, kind, {'usage-project'})
    item = {'name': name, 'email': EMAIL, 'uniqueId': UID, 'disabled': False,
            '_activity': fact, '_coverage': {'_activity': {'status': 'collected', 'source_requests': ['activity-read']}},
            '_provenance': {'scope': SCOPE, 'collected_at': NOW, 'source_requests': ['identity-read', 'activity-read']}}
    if key: item.update(keyType='USER_MANAGED', validAfterTime='2024-01-01T07:00:00Z')
    return item


def insight(last='2025-01-01T07:00:00Z', **changes):
    content = {'email': EMAIL, 'serviceAccountId': UID}
    if last: content['lastAuthenticatedTime'] = last
    return {'name': SCOPE+'/locations/global/insightTypes/google.iam.serviceAccount.Insight/insights/synthetic',
            'insightSubtype': 'SERVICE_ACCOUNT_USAGE', 'category': 'SECURITY', 'content': content,
            'lastRefreshTime': '2026-10-20T07:00:00Z', 'observationPeriod': '15552000s',
            'stateInfo': {'state': 'ACTIVE'}, 'targetResources': ['//cloudresourcemanager.googleapis.com/'+SCOPE],
            '_provenance': {'scope': SCOPE, 'source_requests': ['insight-read']}, **changes}


def capture(item, rows=None, status='collected'):
    kind = 'service_account_key' if 'keyType' in item else 'service_account'
    activity_url = f'https://policyanalyzer.googleapis.com/v1/{SCOPE}/locations/global/activityTypes/{ACTIVITY_TYPES[kind]}/activities:query'
    ledger = [{'id': 'activity-read', 'scope': SCOPE, 'method': 'GET', 'status': 'collected', 'url': activity_url},
        {'id': 'insight-read', 'scope': SCOPE, 'method': 'GET', 'status': 'collected',
         'url': 'https://recommender.googleapis.com/v1/'+SCOPE+'/locations/global/insightTypes/google.iam.serviceAccount.Insight/insights'}]
    rows = [insight()] if rows is None else rows
    return {'context': {'provider': 'gcp', 'scope': SCOPE, 'created_at': NOW, 'metadata': {'source_requests': ledger}},
        kind: [{'type': kind, 'scope': SCOPE, 'data': item}],
        INSIGHT_KIND: [{'type': INSIGHT_KIND, 'scope': SCOPE, 'data': row} for row in rows],
        'collections': {INSIGHT_KIND: [{'type': INSIGHT_KIND, 'scope': SCOPE, 'service': 'recommender',
                                     'status': status if rows else 'empty', 'items': rows}]}}


@pytest.mark.parametrize('key', [False, True])
def test_bound_old_authentication_fails_only_with_full_observation(key):
    item = identity(key)
    evaluate = subject.evaluate_key if key else subject.evaluate_account
    status, evidence = evaluate(item, capture(item))
    assert status == 'FAIL'
    assert evidence['observation_start'] and evidence['observation_end']
    item['_activity']['observationStartTime'] = '2026-10-01T07:00:00Z'
    assert evaluate(item, capture(item))[0] == 'UNKNOWN'


@pytest.mark.parametrize('key', [False, True])
def test_recent_positive_authentication_does_not_need_180_days_of_history(key):
    item = identity(key, last='2026-10-19T07:00:00Z', start='2026-10-01T07:00:00Z')
    evaluate = subject.evaluate_key if key else subject.evaluate_account
    assert evaluate(item, capture(item))[0] == 'PASS'


def test_no_date_is_not_automatically_unused_for_a_service_account():
    item = identity(last=None)
    assert subject.evaluate_account(item, capture(item))[0] == 'UNKNOWN'
    assert subject.evaluate_insight(item, capture(item, [insight(last=None)]))[0] == 'FAIL'


def test_old_key_without_recorded_authentication_can_fail_with_creation_and_full_window():
    item = identity(True, last=None)
    status, evidence = subject.evaluate_key(item, capture(item))
    assert status == 'FAIL'
    assert evidence['reported_last_authentication'] is None
    assert evidence['days_without_observed_authentication'] > 180


def test_new_key_does_not_fail_on_a_missing_usage_timestamp():
    item = identity(True, last=None)
    item['validAfterTime'] = '2026-10-20T07:00:00Z'
    assert subject.evaluate_key(item, capture(item))[0] == 'PASS'


@pytest.mark.parametrize('mutation', ['future', 'stale', 'type', 'resource', 'project', 'receipt', 'partial'])
def test_unbound_or_unavailable_activity_cannot_produce_a_stale_identity_failure(mutation):
    item = identity()
    index = capture(item)
    if mutation == 'future': item['_activity']['observationEndTime'] = '2027-01-01T07:00:00Z'
    elif mutation == 'stale': item['_activity']['observationEndTime'] = '2026-10-01T07:00:00Z'
    elif mutation == 'type': item['_activity']['activity_type'] = ACTIVITY_TYPES['service_account_key']
    elif mutation == 'resource': item['_activity']['resource_name'] = SCOPE+'/serviceAccounts/other'
    elif mutation == 'project': item['_activity']['project_scope'] = 'projects/other'
    elif mutation == 'receipt': index['context']['metadata']['source_requests'][0]['method'] = 'POST'
    else: item['_coverage']['_activity']['status'] = 'partial'
    assert subject.evaluate_account(item, index)[0] == 'UNKNOWN'


def test_denied_activity_is_access_denied():
    item = identity()
    item['_coverage']['_activity']['status'] = 'denied'
    assert subject.evaluate_account(item, capture(item))[0] == 'DENIED'


def test_provider_calendar_day_at_threshold_is_unresolved():
    item = identity(last='2026-04-23T07:00:00Z')
    assert subject.evaluate_account(item, capture(item))[0] == 'UNKNOWN'


def test_active_insight_matches_unique_id_not_only_reusable_email():
    item = identity()
    index = capture(item)
    assert subject.evaluate_insight(item, index)[0] == 'FAIL'
    index[INSIGHT_KIND][0]['data']['content']['serviceAccountId'] = '999999999999999999999'
    assert subject.evaluate_insight(item, index)[0] == 'PASS'


def test_recent_native_authentication_contradicts_unused_insight():
    item = identity(last='2026-10-19T07:00:00Z')
    assert subject.evaluate_insight(item, capture(item))[0] == 'UNKNOWN'


def test_authentication_150_days_ago_does_not_contradict_90_day_unused_insight():
    item = identity(last='2026-05-23T07:00:00Z')
    assert subject.evaluate_insight(item, capture(item))[0] == 'FAIL'


@pytest.mark.parametrize('changes', [
    {'lastRefreshTime': '2026-01-01T07:00:00Z'}, {'lastRefreshTime': '2027-01-01T07:00:00Z'},
    {'observationPeriod': '10s'}, {'insightSubtype': 'UNKNOWN_TYPE'},
    {'targetResources': ['//cloudresourcemanager.googleapis.com/projects/other']},
])
def test_invalid_or_stale_unused_insights_are_unknown(changes):
    item = identity()
    assert subject.evaluate_insight(item, capture(item, [insight(**changes)]))[0] == 'UNKNOWN'


def test_accepted_insight_does_not_count_as_an_active_finding():
    item = identity()
    assert subject.evaluate_insight(item, capture(item, [insight(stateInfo={'state': 'ACCEPTED'})]))[0] == 'PASS'


def test_valid_positive_insight_survives_unrelated_partial_inventory():
    item = identity()
    assert subject.evaluate_insight(item, capture(item, status='partial'))[0] == 'FAIL'
    index = capture(item, [])
    index['collections'][INSIGHT_KIND][0]['status'] = 'denied'
    assert subject.evaluate_insight(item, index)[0] == 'DENIED'


def test_evaluation_does_not_modify_native_evidence():
    item = identity()
    index = capture(item)
    before = deepcopy(index)
    subject.evaluate_account(item, index)
    subject.evaluate_insight(item, index)
    assert index == before


def test_registered_cases_preserve_native_ids_and_hardening_membership():
    from peaso.checks import CHECKS
    from peaso.checks.fixtures import CASES
    registry = {check.id: check for check in CHECKS}
    for ident in (subject.ACCOUNT, subject.KEY, subject.INSIGHT_CHECK):
        check = registry[ident]
        assert check.category == 'hardening'
        assert 'HackTricks Cloud Best Practices' in check.frameworks
        case = CASES[ident]
        assert check.evaluate(case['pass'], deepcopy(case['pass_index']))[0] == 'PASS', ident
        assert check.evaluate(case['fail'], deepcopy(case['fail_index']))[0] == 'FAIL', ident
        assert check.evaluate({}, deepcopy(case['index']))[0] == 'UNKNOWN', ident


def test_insight_check_runs_through_normal_hardening_engine_and_json_output():
    import json
    from peaso.engine import evaluate_snapshot, hydrate_frameworks
    from peaso.snapshot import make_snapshot
    item = identity(last=None)
    index = capture(item)
    collections = [deepcopy(row) for rows in index['collections'].values() for row in rows]
    collections.append({'type': 'service_account', 'scope': SCOPE, 'service': 'iam', 'status': 'collected', 'items': [item]})
    snapshot = make_snapshot('gcp', [SCOPE], collections, created_at=NOW, metadata=index['context']['metadata'])
    report = hydrate_frameworks(evaluate_snapshot(snapshot, categories=['hardening'], checks=[subject.INSIGHT_CHECK]))
    result = json.loads(json.dumps(report))
    finding = next(row for row in result['findings'] if row['check_id'] == subject.INSIGHT_CHECK)
    assert finding['category'] == 'hardening'
    assert finding['status'] == 'FAIL', finding
    assert finding['evidence']['service_account_id'] == UID
    assert 'HackTricks Cloud Best Practices' in finding['frameworks']


def test_corrected_public_criteria_are_published():
    from peaso.checks import CHECKS
    for ident in (subject.ACCOUNT, subject.KEY):
        check = next(row for row in CHECKS if row.id == ident)
        public = check.public()
        assert 'observation' in public['description'].lower()
        current = deepcopy(subject.DESCRIPTION_SUCCESSORS[ident]['description'])
        assert subject.reviewed_description_successor(ident, current) == current


def test_authentication_for_deleted_recreated_email_cannot_mark_current_account_unused():
    item = identity()
    item['_activity']['service_account_id'] = '999999999999999999999'
    assert subject.evaluate_account(item, capture(item))[0] == 'UNKNOWN'
