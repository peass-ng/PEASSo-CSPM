"""Every registered/historical GCP ID and recorded fixture branch is reviewed."""
import copy
import json
from pathlib import Path

import pytest

from peaso.checks import CHECKS
from peaso.checks.fixtures import CASES
from peaso.checks.gcp_evidence_explanations import CATALOG, evidence_summary, reviewed_explanation
from tests.gcp_clarity_combined_successor_20261020 import current_missing_observation
from peaso.checks import CHECKS, CHECK_ALIASES

ROOT = Path(__file__).resolve().parents[1]
CHECK_BY_ID = {check.id: check for check in CHECKS if check.provider == 'gcp'}
SUPPLEMENTAL = json.loads((ROOT / 'tests/fixtures/gcp-reviewed-evidence.json').read_text())
LEDGER = json.loads((ROOT / 'docs/evidence-reviews/gcp.json').read_text())
LABELS = ('pass', 'fail', 'unknown', 'missing', 'malformed', 'manual', 'not_applicable', 'empty', 'denied')
CURRENT_SOURCE_REVIEWS = {
    'gcp.iam.api_key_recent_recorded_successful_requests',
    'gcp.iam.custom_role_has_declared_grants',
    'gcp.iam.directory_user_recent_recorded_login',
    'gcp.iam.hmac_key_recent_recorded_successful_requests',
    'gcp.iam.role_grant_has_observed_permission_use',
    'gcp.iam.service_account_no_active_unused_insight',
    'gcp.iam.static_group_has_members',
    'gcp.iam.workforce_pool_has_enabled_provider',
    'gcp.iam.workload_identity_pool_has_enabled_provider',
    'gcp.network.address_reserved_without_users',
    'gcp.network.backend_service_has_members',
    'gcp.network.endpoint_group_without_endpoints',
    'gcp.network.firewall_policy_without_associations',
    'gcp.network.http_proxy_forwarding_rule_reference',
    'gcp.network.https_proxy_forwarding_rule_reference',
    'gcp.review.app_engine_flex.selected_version_image_high_vulnerabilities',
    'gcp.review.app_engine_flex.selected_version_image_secret_indicators',
    'gcp.review.artifact_image.selected_image_vulnerabilities',
    'gcp.review.cloud_run.selected_job_image_vulnerabilities',
    'gcp.review.cloudrun_worker_pool.selected_revision_image_secret_indicators',
    'gcp.review.developerconnect.selected_repository_file_secret_indicators',
    'gcp.review.gke.selected_pod_image_high_vulnerabilities',
    'gcp.review.gke.selected_pod_image_secret_indicators',
}


def test_enrollment_alone_does_not_explain_enforced_mfa():
    summary = evidence_summary({'provider': 'gcp', 'check_id': 'gcp.identity.non_service_account_mfa',
                                'status': 'FAIL', 'evidence': {'isEnrolledIn2Sv': True, 'isEnforcedIn2Sv': False}})
    assert 'enrollment is enabled and enforcement is disabled' in summary
    assert evidence_summary({'provider': 'gcp', 'check_id': 'gcp.identity.non_service_account_mfa',
                             'status': 'PASS', 'evidence': {'isEnrolledIn2Sv': True}}).startswith(
                                 CATALOG['gcp.identity.non_service_account_mfa']['missing_observation'])


def test_inherited_bucket_read_grant_is_explained_directly():
    summary = evidence_summary({'provider': 'gcp', 'check_id': 'gcp_pci_bucket_157fb0c69361',
                                'status': 'FAIL', 'evidence': {'inherited_public_read_grants': [
                                    {'scope': 'organizations/123', 'role': 'roles/storage.objectViewer'}]}})
    assert summary.startswith('An ancestor IAM policy grants public read access to this bucket.')


def findings():
    for cid, check in CHECK_BY_ID.items():
        case = CASES.get(cid, {})
        for label in LABELS:
            if label in case:
                status, evidence = check.evaluate(copy.deepcopy(case[label]), copy.deepcopy(case.get(label + '_index', case.get('index', {}))))
                yield pytest.param(dict(provider='gcp', check_id=cid, status=status, evidence=evidence), id=cid + '-' + label)
        for i, captured in enumerate(SUPPLEMENTAL.get(cid, [])):
            yield pytest.param(dict(provider='gcp', check_id=cid, **captured), id=cid + '-native-' + str(i))


@pytest.mark.parametrize('finding', list(findings()))
def test_every_recorded_branch_has_a_brief_observation_and_specific_interpretation(finding):
    original = copy.deepcopy(finding)
    summary = evidence_summary(finding)
    assert isinstance(summary, str) and summary.strip(), finding
    assert CATALOG[finding['check_id']]['purpose'] in summary
    assert '\n' not in summary
    assert '{"' not in summary and "{'" not in summary
    assert len(summary.split()) <= 100, summary
    if finding['status'] in ('PASS', 'FAIL'):
        assert not summary.startswith(CATALOG[finding['check_id']]['missing_observation']), finding
    assert finding == original
    assert reviewed_explanation(finding['check_id'], summary, finding['status']) == summary


@pytest.mark.parametrize('cid', sorted(CHECK_BY_ID))
@pytest.mark.parametrize('status', ['PASS', 'FAIL', 'UNKNOWN', 'DENIED', 'MANUAL', 'NOT_APPLICABLE', 'EMPTY'])
def test_absent_evidence_never_creates_a_setting_or_grant(cid, status):
    summary = evidence_summary(dict(provider='gcp', check_id=cid, status=status, evidence={}))
    assert summary
    if status in ('UNKNOWN', 'DENIED'):
        assert summary.startswith(current_missing_observation(cid, CATALOG))
    if status in ('PASS', 'FAIL') and not summary.startswith(CATALOG[cid]['missing_observation']):
        assert not any(claim in summary.split(CATALOG[cid]['purpose'])[0] for claim in (' is enabled', ' is disabled', 'grants roles/', ' permits unencrypted'))


@pytest.mark.parametrize('cid', sorted(CURRENT_SOURCE_REVIEWS))
def test_current_review_rejects_unbound_observation_text(cid):
    for status in ('PASS', 'FAIL'):
        for evidence in ({}, {'summary': 'A grant is active.'},
                         {'observed': 'The setting is enabled.'},
                         {'Observed': 'No vulnerability was found.'}):
            summary = evidence_summary(dict(provider='gcp', check_id=cid,
                                            status=status, evidence=evidence))
            assert summary.startswith(CATALOG[cid]['missing_observation'])


@pytest.mark.parametrize('cid', ('gcp.claude.service_account.recently_used',
                                 'gcp.claude.service_account_key.recently_used'))
def test_historical_activity_requires_bound_native_observation(cid):
    for status in ('PASS', 'FAIL'):
        summary = evidence_summary(dict(provider='gcp', check_id=cid, status=status,
                                        evidence={'threshold_days': 180,
                                                  'summary': 'Authentication is confirmed.'}))
        assert summary.startswith(CATALOG[cid]['missing_observation'])


def test_public_identity_explains_who_can_use_the_declared_grant():
    finding = dict(provider='gcp', check_id='gcp.storage.no_public_iam', status='FAIL', evidence={'public_bindings': [{'role': 'roles/storage.objectViewer', 'members': ['allUsers']}]})
    summary = evidence_summary(finding)
    assert 'allUsers (anyone, including anonymous users)' in summary
    assert 'roles/storage.objectViewer' in summary
    assert 'other access controls still affect access' in summary


def test_failed_scalar_is_read_from_the_recorded_value_and_field():
    finding = dict(provider='gcp', check_id='gcp.compute.secure_boot', status='FAIL', evidence={'field': 'shieldedInstanceConfig.enableSecureBoot', 'configured': False})
    assert evidence_summary(finding).startswith('Secure Boot is disabled.')
    finding['evidence']['configured'] = True
    assert evidence_summary(finding).startswith('Secure Boot is enabled.')
    finding['evidence']['configured'] = 'false'
    assert 'Secure Boot is disabled.' not in evidence_summary(finding)
    finding['evidence'] = {'field': 'unrelated', 'configured': True}
    assert 'Secure Boot is enabled.' not in evidence_summary(finding)


@pytest.mark.parametrize('field', ['observation_start', 'observation_end', 'reported_last_authentication'])
def test_mixed_timezone_activity_evidence_does_not_break_presentation(field):
    from peaso.checks.gcp_evidence_explanations import _historical_activity_observation
    evidence = {'threshold_days': 180, 'identity_name': 'projects/example/serviceAccounts/test@example.iam.gserviceaccount.com',
                'activity_source_endpoint': 'https://policyanalyzer.googleapis.com/v1/projects/example/locations/global/activityTypes/serviceAccountLastAuthentication/activities:query',
                'observation_start': '2026-01-01T00:00:00+00:00', 'observation_end': '2026-10-01T00:00:00+00:00',
                'reported_last_authentication': '2026-09-01T00:00:00+00:00', 'days_since_reported_authentication': 30}
    evidence[field] = evidence[field].replace('+00:00', '')
    assert _historical_activity_observation('gcp.claude.service_account.recently_used', 'PASS', evidence) is None
