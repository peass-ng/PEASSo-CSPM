"""Replay native Azure witnesses and check the observed-evidence explanations they produce."""
from copy import deepcopy
from datetime import datetime, timezone
import gzip
import json
from pathlib import Path
import re

import pytest


from peaso.checks import CHECKS
from peaso.checks.fixtures import CASES as NATIVE_CASES
from peaso.checks.azure_evidence_explanations import ROWS, evidence_summary, reviewed_explanation
from peaso.checks.azure_native_evidence_observations import evidence_summary as native_observation
from tests.azure_native_successor_inputs_20261020 import _native_rows

ROOT = Path(__file__).resolve().parents[1]
CHECK_BY_ID = {check.id: check for check in CHECKS if check.provider == 'azure'}
LEDGER = json.loads((ROOT / 'docs/evidence-reviews/azure.json').read_text())
CASES = json.loads(gzip.decompress((ROOT / 'tests/fixtures/azure_evidence_review.json.gz').read_bytes()))
ASSESSMENT_SUCCESSOR = json.loads((ROOT / 'docs/check-review/azure-defender-assessment-four-current-binding-20261021.json').read_text())
CURRENT_RELEASE_BINDINGS = json.loads((ROOT / 'docs/evidence-reviews/azure-current-22-binding-20261022.json').read_text())
CURRENT_WITNESS_SUCCESSORS = CURRENT_RELEASE_BINDINGS['witness_successors']
CURRENT_NATIVE_OUTCOMES = CURRENT_RELEASE_BINDINGS['current_native_outcomes']
RELEASE_RETIRED_AZURE_IDS = frozenset({'azure.claude.aks_authorized_ip_ranges'})
# Historical witness -> current native input that replaces it: [native case, expected status].
NATIVE_WITNESS_SUCCESSORS = {'azure.claude.databricks_subnet_nsg|0': ['fail', 'FAIL'],
 'azure.claude.databricks_subnet_nsg|2': ['pass', 'PASS'],
 'azure.claude.entra_ca_mfa_admin_portals|0': ['fail', 'FAIL'],
 'azure.claude.entra_ca_mfa_admin_portals|2': ['pass', 'PASS'],
 'azure.claude.entra_ca_mfa_management_api|0': ['fail', 'FAIL'],
 'azure.claude.entra_ca_mfa_management_api|1': ['pass', 'PASS'],
 'azure.claude.entra_non_privileged_user_mfa|0': ['fail', 'FAIL'],
 'azure.claude.entra_non_privileged_user_mfa|2': ['pass', 'PASS'],
 'azure.claude.entra_privileged_user_mfa|0': ['fail', 'FAIL'],
 'azure.claude.entra_privileged_user_mfa|2': ['pass', 'PASS'],
 'azure.claude.entra_vm_access_user_mfa|0': ['fail', 'FAIL'],
 'azure.claude.entra_vm_access_user_mfa|2': ['pass', 'PASS'],
 'azure.claude.iam_custom_role_administers_locks|0': ['lock-successor/permissions-fd8b3f00a4', 'FAIL'],
 'azure.claude.iam_custom_role_administers_locks|1': ['lock-successor/permissions-c2efb060b4', 'PASS'],
 'azure.claude.managed_hsm_audit_logging|1': ['positive', 'UNKNOWN'],
 'azure.claude.recovery_vault_backup_retention_30_days|1': ['negative', 'FAIL'],
 'azure.claude.recovery_vault_backup_retention_30_days|3': ['positive', 'PASS'],
 'azure.claude.servicefabric_cluster_encrypt_and_sign|0': ['services2/tests/test_azure_remaining_services_2_native_review_20261020.py::test_native_contract[opposite-azure.claude.servicefabric_cluster_encrypt_and_sign]',
                                                           'FAIL'],
 'azure.claude.servicefabric_cluster_encrypt_and_sign|1': ['services2/tests/test_azure_remaining_services_2_native_review_20261020.py::test_native_contract[positive-azure.claude.servicefabric_cluster_encrypt_and_sign]',
                                                           'PASS'],
 'azure.claude.servicefabric_cluster_entra_auth|1': ['services2/tests/test_azure_remaining_services_2_native_review_20261020.py::test_native_contract[positive-azure.claude.servicefabric_cluster_entra_auth]',
                                                     'PASS'],
 'azure.claude.sql_database_va_findings_resolved|0': ['database2/negative', 'FAIL'],
 'azure.claude.sql_database_va_findings_resolved|3': ['database2/positive', 'PASS'],
 'azure.claude.storage_access_keys_rotated_90|0': ['fail_90_days_plus_microsecond', 'FAIL'],
 'azure.claude.storage_access_keys_rotated_90|1': ['unknown_empty_metadata', 'UNKNOWN'],
 'azure.claude.storage_access_keys_rotated_90|2': ['pass_exact_90_days', 'PASS'],
 'azure.claude.storage_access_keys_rotated_90|3': ['unknown_empty_metadata', 'UNKNOWN'],
 'azure.claude.storage_vhd_accounts_cmk|0': ['fail_bound_platform_key', 'FAIL'],
 'azure.claude.storage_vhd_accounts_cmk|2': ['pass_bound_cmk', 'PASS'],
 'azure.claude.storage_vhd_accounts_cmk|3': ['unknown_foreign_blob_host', 'UNKNOWN'],
 'azure.claude.synapse_workspace_vulnerability_assessment|0': ['fail', 'FAIL'],
 'azure.claude.synapse_workspace_vulnerability_assessment|1': ['pass', 'PASS'],
 'azure.claude.synapse_workspace_vulnerability_assessment|2': ['unknown', 'UNKNOWN'],
 'azure.claude.vm_windows_secure_boot|2': ['windows-native-linux', 'NOT_APPLICABLE'],
 'azure.claude2.app_gateway_min_tls_12|4': ['tests/test_azure_network_platform_1_native_review_20261020.py::test_each_assigned_native_contract[positive-azure.claude2.app_gateway_min_tls_12]',
                                            'PASS'],
 'azure.claude2.app_gateway_waf_enabled|1': ['tests/test_azure_network_platform_1_native_review_20261020.py::test_each_assigned_native_contract[positive-azure.claude2.app_gateway_waf_enabled]',
                                             'PASS'],
 'azure.claude2.function_app_restrict_public_access|0': ['fail', 'FAIL'],
 'azure.claude2.function_app_restrict_public_access|1': ['pass', 'PASS'],
 'azure.claude2.nsg_flow_logs_to_log_analytics|0': ['tests/test_azure_network_platform_1_native_review_20261020.py::test_disabled_native_flow_or_analytics_cannot_prove_log_delivery_configuration[flow_disabled-azure.claude2.nsg_flow_logs_to_log_analytics]',
                                                    'FAIL'],
 'azure.claude2.nsg_flow_logs_to_log_analytics|2': ['tests/test_azure_network_platform_1_native_review_20261020.py::test_each_assigned_native_contract[positive-azure.claude2.nsg_flow_logs_to_log_analytics]',
                                                    'PASS'],
 'azure.claude2.nsg_flow_logs_to_log_analytics|3': ['tests/test_azure_network_platform_1_native_review_20261020.py::test_flow_analytics_exact_native_target_and_flags[unresolved_local_target-azure.claude2.nsg_flow_logs_to_log_analytics]',
                                                    'UNKNOWN'],
 'azure.claude2.vnet_flow_logs_to_log_analytics|0': ['tests/test_azure_network_platform_1_native_review_20261020.py::test_disabled_native_flow_or_analytics_cannot_prove_log_delivery_configuration[flow_disabled-azure.claude2.vnet_flow_logs_to_log_analytics]',
                                                     'FAIL'],
 'azure.claude2.vnet_flow_logs_to_log_analytics|2': ['tests/test_azure_network_platform_1_native_review_20261020.py::test_each_assigned_native_contract[positive-azure.claude2.vnet_flow_logs_to_log_analytics]',
                                                     'PASS'],
 'azure.claude2.vnet_flow_logs_to_log_analytics|3': ['tests/test_azure_network_platform_1_native_review_20261020.py::test_flow_analytics_exact_native_target_and_flags[unresolved_local_target-azure.claude2.vnet_flow_logs_to_log_analytics]',
                                                     'UNKNOWN'],
 'azure.gap.compute_vm_remote_access_restricted_all_ports|0': ['fail_native_declared_configuration', 'FAIL'],
 'azure.gap.compute_vm_remote_access_restricted_all_ports|1': ['pass_native_declared_configuration', 'PASS'],
 'azure.sql.minimum_tls|0': ['database2/negative', 'FAIL'],
 'azure.sql.minimum_tls|1': ['database2/positive', 'PASS'],
 'azure.sql.minimum_tls|2': ['retained-uncertain-input', 'UNKNOWN'],
 'azure_aks_cluster_7_2_1_6_93c4fab|0': ['aks-native/fail', 'FAIL'],
 'azure_aks_cluster_7_2_1_6_93c4fab|1': ['aks-native/pass', 'PASS'],
 'azure_aks_cluster_7_2_1_6_93c4fab|2': ['aks-native/unknown', 'UNKNOWN'],
 'azure_aks_cluster_aks_cluster_rbac_enabled_db12524|0': ['aks-native/fail', 'FAIL'],
 'azure_aks_cluster_aks_cluster_rbac_enabled_db12524|1': ['aks-native/unknown', 'UNKNOWN'],
 'azure_aks_cluster_aks_cluster_rbac_enabled_db12524|2': ['aks-native/pass', 'PASS'],
 'azure_aks_cluster_aks_cluster_rbac_enabled_db12524|3': ['aks-native/unknown', 'UNKNOWN'],
 'azure_application_gateway_11_5_1_1_1_f56bdc2|0': ['edge-successor/53/0/inline_candidate_detection', 'FAIL'],
 'azure_application_gateway_11_5_1_1_1_f56bdc2|2': ['edge-successor/51/0/inline_candidate_prevention',
                                                    'PASS'],
 'azure_application_gateway_app_http_logs_enabled_2de0361|0': ['edge-successor/43/0/gateway_logging_candidate_empty_diagnostics',
                                                               'FAIL'],
 'azure_application_gateway_app_http_logs_enabled_2de0361|1': ['edge-successor/41/0/gateway_logging_candidate_positive',
                                                               'PASS']}
# Neutral copy for these checks is check-specific and does not embed the label.
CHECK_SPECIFIC_NEUTRAL = {'azure.encryption.automation_cmk_declared',
 'azure.encryption.log_analytics_cluster_cmk_declared',
 'azure.encryption.stream_analytics_job_storage_cmk_declared',
 'azure.logging.aci_log_analytics_declared',
 'azure.logging.aks_supported_log_categories_destination_declared',
 'azure.logging.managed_hsm_audit_destination_declared',
 'azure.network.acr_public_ip_ranges_restricted',
 'azure.review.acr.selected_image_secret_indicators',
 'azure.review.ai_services.audit_logging',
 'azure.review.ai_services.managed_identity',
 'azure.review.ai_services.outbound_restriction',
 'azure.review.ai_services.prompt_shield',
 'azure.review.app_configuration.selected_value_secret_indicators',
 'azure.review.app_service.selected_app_settings_secret_indicators',
 'azure.review.application_insights.selected_trace_sample_secret_indicators',
 'azure.review.configuration.selected_content_secret_indicators',
 'azure.review.data_factory.selected_declaration_secret_indicators',
 'azure.review.databricks.selected_notebook_source_secret_indicators',
 'azure.review.devops.selected_content_secret_indicators',
 'azure.review.devops.visible_clone_urls_without_userinfo',
 'azure.review.function.application_insights_setting_declared',
 'azure.review.function.runtime_major4_update_channel_declared',
 'azure.review.log_analytics.query_storage_cmk_declared',
 'azure.review.log_analytics.selected_message_sample_secret_indicators',
 'azure.review.machine_learning.selected_code_file_secret_indicators',
 'azure.review.machine_learning.selected_command_job_secret_indicators',
 'azure.review.machine_learning.selected_environment_conda_secret_indicators',
 'azure.review.managed_hsm.audit_storage_destination',
 'azure.review.network.perimeter_association_enforced',
 'azure.review.storage.blocking_sas_expiry_policy_declared',
 'azure.review.storage.selected_source_secret_indicators',
 'azure.review.synapse.selected_pipeline_secret_indicators'}
# Later admissions whose neutral copy is slightly above the 240 character cap.
LONG_NEUTRAL = {'azure.encryption.log_analytics_cluster_cmk_declared',
 'azure.logging.aci_log_analytics_declared',
 'azure.review.app_configuration.selected_value_secret_indicators',
 'azure.review.data_factory.selected_declaration_secret_indicators',
 'azure.review.devops.selected_content_secret_indicators',
 'azure.review.storage.selected_source_secret_indicators',
 'azure.review.synapse.selected_pipeline_secret_indicators'}
MISSING_NEUTRAL_FIELDS = {'azure.review.acr.selected_image_secret_indicators': ['manual_observation', 'not_applicable_observation'],
 'azure.review.app_service.selected_app_settings_secret_indicators': ['manual_observation',
                                                                      'not_applicable_observation'],
 'azure.review.function.selected_package_source_secret_indicators': ['manual_observation',
                                                                     'not_applicable_observation']}
SQL_ROUTE_SUCCESSOR_ID = 'azure.htbp.sql.entra_only_authentication'
GATEWAY_CIDR_SUCCESSOR_ID = 'azure.other.gateway_api_cidr_allowlist'
GATEWAY_CIDR_SUCCESSOR_FIELDS = {'approved_cidrs', 'approved_cidr_count', 'outside_approved_ranges_empty',
                                 'effective_paths', 'effective_path_count'}


def _sql_route_successor(historical):
    """The check reads azureADOnlyAuthentications/Default, not the flag on the
    administrator row. Move only the recorded flag to that child; the
    historical verdict and evidence must stay exactly the same."""
    row = deepcopy(historical)
    item = row['item']
    admin, = item['serverAdministrators']
    flag = admin['properties'].pop('azureADOnlyAuthentication')
    assert type(flag) is bool and flag is (historical['status'] == 'PASS')
    item['azureADOnlyAuthentications'] = [{
        'id': item['id'] + '/azureADOnlyAuthentications/Default', 'name': 'Default',
        'type': 'Microsoft.Sql/servers/azureADOnlyAuthentications',
        'properties': {'azureADOnlyAuthentication': flag}}]
    return row


def _current_case(cid, number, historical):
    """Return the input and expected verdict; 'evidence' is present only when the historical evidence still applies."""
    if cid == SQL_ROUTE_SUCCESSOR_ID and historical['status'] in ('PASS', 'FAIL'):
        return _sql_route_successor(historical)
    witness = CURRENT_WITNESS_SUCCESSORS.get(cid + '|' + str(number))
    if witness is not None:
        branch = witness['native_branch']
        if witness['input_source'] == 'registered_native_cases':
            native = NATIVE_CASES[cid]
            item = native[branch]
            index = native.get(branch + '_index', native.get('index', {}))
        else:
            item, index = historical['item'], historical['index']
        return {'item': item, 'index': index, 'status': witness['current_status']}
    if cid in ASSESSMENT_SUCCESSOR['records']:
        update = ASSESSMENT_SUCCESSOR['historical_fixture_successors'].get(cid + '|' + str(number))
        if update is not None:
            return {'item': historical['item'], 'index': historical['index'], 'status': update['current_status']}
    reference = NATIVE_WITNESS_SUCCESSORS.get(cid + '|' + str(number))
    if reference is None:
        return historical
    name, status = reference
    if name == 'retained-uncertain-input':
        row = historical
    elif name == 'windows-native-linux':
        row = deepcopy(historical)
        row['item']['properties']['storageProfile']['osDisk']['osType'] = 'Linux'
    elif name.startswith('aks-native/'):
        branch = name.split('/', 1)[1]
        cases = json.loads((ROOT / 'peaso/checks/azure_aks_legacy_projection_review_20261020_fixtures.json').read_text())[cid]
        row = {'item': cases[branch], 'index': cases.get(branch + '_index', cases.get('index', {}))}
    else:
        row = _native_rows()[cid][name]
    if cid == 'azure.claude.managed_hsm_audit_logging' and historical['status'] != status:
        # A retired diagnostic retention cannot prove the audit archive is kept.
        assert row['evidence']['diagnostic_retention_retired_on'] == '2025-09-30'
        assert row['evidence']['audit_archive_declared'] is True
    return {'item': row['item'], 'index': row['index'], 'status': status}


def test_retired_aks_authorized_ranges_alias_selects_the_active_check():
    from peaso.checks import CHECK_ALIASES
    from peaso.engine import _selection
    retired, = RELEASE_RETIRED_AZURE_IDS
    active = 'azure.aks.api_server_restricted'
    assert CHECK_ALIASES[retired] == active and retired not in CHECK_BY_ID
    _, selected = _selection('azure', None, [retired], None)
    assert [check.id for check in selected] == [active]
    case = NATIVE_CASES[active]
    for branch, expected in (('pass', 'PASS'), ('fail', 'FAIL'), ('unknown', 'UNKNOWN')):
        assert CHECK_BY_ID[active].evaluate(deepcopy(case[branch]), deepcopy(case.get(branch + '_index', case.get('index', {}))))[0] == expected


@pytest.mark.parametrize('cid', sorted(CASES.keys() - RELEASE_RETIRED_AZURE_IDS))
def test_native_witnesses_replay_their_verdicts_evidence_and_explanations(cid, monkeypatch):
    if cid == 'azure.claude.storage_access_keys_rotated_90':
        # Replay the retained ages at their capture date, rather than letting
        # this evidence fixture age by another day on every CI run.
        from peaso.checks import claude_azure_data

        class CapturedClock(datetime):
            @classmethod
            def now(cls, tz=None):
                captured = datetime(2026, 10, 19, 12, tzinfo=timezone.utc)
                return captured.astimezone(tz) if tz else captured.replace(tzinfo=None)
        monkeypatch.setattr(claude_azure_data, 'datetime', CapturedClock)
    if cid in CURRENT_NATIVE_OUTCOMES:
        for branch, expected in CURRENT_NATIVE_OUTCOMES[cid].items():
            if cid == 'azure_storage_account_10_3_4_7_02943e9':
                from tests.test_peaso_azure_storage_recovery_metadata_native import capture
                finding, _, _ = capture('storage', branch, options={})
                status, evidence = finding['status'], finding['evidence']
            else:
                native = NATIVE_CASES[cid]
                index = native.get(branch + '_index', native.get('index', {}))
                status, evidence = CHECK_BY_ID[cid].evaluate(deepcopy(native[branch]), deepcopy(index))
            assert status == expected['status'], (cid, branch, status, evidence)
    for number, historical in enumerate(CASES[cid]):
        case = _current_case(cid, number, historical)
        item, index = deepcopy((case['item'], case['index']))
        before = deepcopy((item, index))
        status, evidence = CHECK_BY_ID[cid].evaluate(item, index)
        assert status == case['status'], (cid, case['status'], status, evidence)
        assert (item, index) == before, cid
        observed = json.loads(json.dumps(evidence, sort_keys=True))
        if case is historical and cid != GATEWAY_CIDR_SUCCESSOR_ID:
            assert observed == case['evidence']
        elif case is historical:
            # The successor keeps the historical evidence and only appends the WAF facts behind that verdict.
            assert {key: observed.get(key) for key in case['evidence']} == case['evidence']
            assert set(observed) - set(case['evidence']) <= GATEWAY_CIDR_SUCCESSOR_FIELDS
        finding = {'provider': 'azure', 'check_id': cid, 'status': status, 'evidence': evidence}
        before = deepcopy(finding)
        summary = evidence_summary(finding)
        assert finding == before
        if summary:
            assert '{' not in summary
            lines = summary.split('\n')
            if len(lines) == 1:
                # Retained reviewed one-line summaries: purpose and limit.
                assert status in {'PASS', 'FAIL'}
                assert ROWS[cid]['purpose'] in summary and ROWS[cid]['limit'] in summary
                assert reviewed_explanation(cid, summary, status) == summary
            else:
                # Observed evidence: 3-5 short plain lines (AGENTS.md) for every supported status.
                assert status in {'PASS', 'FAIL', 'UNKNOWN', 'NOT_APPLICABLE'}
                assert 3 <= len(lines) <= 5
                assert all(line and line.strip() == line for line in lines)
        elif status not in {'PASS', 'FAIL'}:
            assert native_observation(finding) is None



def test_unrecognized_native_shapes_and_uncertain_statuses_do_not_become_positive_claims():
    for cid in ('azure.other.gateway_vmss_autoscale', 'azure_search_service_10_6_3_27_ba08488'):
        for status in ('PASS', 'FAIL', 'UNKNOWN', 'MANUAL', 'NOT_APPLICABLE'):
            assert evidence_summary({'provider': 'azure', 'check_id': cid, 'status': status, 'evidence': {}}) is None
    assert evidence_summary({'provider': 'aws', 'check_id': 'azure.storage.https_only', 'status': 'FAIL', 'evidence': {'supports_https_traffic_only': False}}) is None
    assert reviewed_explanation('azure.unreviewed', 'An unreviewed fact.') is None


def test_scalar_observation_uses_actual_value_and_does_not_claim_runtime_access():
    summary = evidence_summary({'provider': 'azure', 'check_id': 'azure.storage.no_shared_key', 'status': 'FAIL',
                                'evidence': {'field': 'properties.allowSharedKeyAccess', 'configured': True}})
    lines = summary.split('\n')
    assert 'Shared Key access is enabled' in lines[0]
    assert 3 <= len(lines) <= 5
    # Possible impact only; no claim that a key was used or access happened.
    assert all(word in summary for word in ('may', 'could'))
    assert evidence_summary({'provider': 'azure', 'check_id': 'azure.storage.no_shared_key', 'status': 'FAIL',
                             'evidence': {'field': 'properties.allowSharedKeyAccess', 'configured': 'true'}}) is None


def test_native_shape_rules_explain_every_interpretable_witness():
    from peaso.checks.azure_native_evidence_observations import ROWS as NATIVE_ROWS
    for cid in NATIVE_ROWS:
        for case in CASES[cid]:
            if case['status'] in {'PASS', 'FAIL'}:
                assert native_observation(dict(case, provider='azure', check_id=cid)), (cid, case['status'], case['evidence'])


def test_count_only_success_reports_its_evidence_limit_instead_of_inventing_configuration():
    finding = {'provider': 'azure', 'check_id': 'azure.gap.asset_inventory_required_metadata', 'status': 'PASS', 'evidence': {'evaluated': 7}}
    assert '7 resources' in native_observation(finding)
    finding['evidence']['evaluated'] = True
    assert native_observation(finding) is None


def test_every_registered_check_rejects_empty_and_unrelated_positive_witnesses():
    for cid in ROWS:
        for status in ('PASS', 'FAIL', 'UNKNOWN', 'DENIED', 'MANUAL', 'NOT_APPLICABLE', 'EMPTY'):
            for evidence in ({}, {'unrelated': True}):
                assert evidence_summary({'provider': 'azure', 'check_id': cid, 'status': status, 'evidence': evidence}) is None, (cid, status, evidence)


def test_unknown_manual_and_inapplicable_copy_is_check_bound_brief_and_neutral():
    for cid, row in ROWS.items():
        for key in ('missing_observation', 'manual_observation', 'not_applicable_observation'):
            if key not in row:
                assert key in MISSING_NEUTRAL_FIELDS.get(cid, ()), (cid, key)
                status = {'manual_observation': 'MANUAL', 'not_applicable_observation': 'NOT_APPLICABLE'}[key]
                assert status not in {branch['status'] for branch in LEDGER[cid]['branch_coverage']}
                assert evidence_summary({'provider': 'azure', 'check_id': cid, 'status': status, 'evidence': {}}) is None
                continue
            text = reviewed_explanation(cid, row[key])
            assert len(text) <= (300 if cid in LONG_NEUTRAL else 240), (cid, key, text)
            if cid not in CHECK_SPECIFIC_NEUTRAL:
                assert row['label'] in text if 'label' in row else (text.startswith(row[key]) and row['purpose'] in text)
            assert '{' not in text and '\n' not in text


def test_rsa_observation_uses_actual_weak_modulus_and_rejects_a_nonweak_failure_witness():
    cid = 'azure_vault_3_7_1_2_532ecd2'
    case = deepcopy(next(row for row in CASES[cid] if row['status'] == 'FAIL'))
    finding = dict(case, provider='azure', check_id=cid)
    assert '1024-bit RSA' in evidence_summary(finding)
    assert '1024-bit RSA' in native_observation(finding)
    for row in finding['evidence']['outcomes']:
        if row.get('status') == 'FAIL':
            row['measured_rsa_modulus_bits'] = 4096
    assert native_observation(finding) is None
    assert evidence_summary(finding) is None


def test_native_explanations_are_sentences_instead_of_field_codes_and_flag_dumps():
    from peaso.checks.azure_native_evidence_observations import ROWS as NATIVE_ROWS
    for cid in NATIVE_ROWS:
        for case in CASES[cid]:
            if case['status'] not in {'PASS', 'FAIL'}:
                continue
            observed = native_observation(dict(case, provider='azure', check_id=cid))
            assert observed and observed.endswith('.'), (cid, observed)
            assert not re.search(r'\b\w+_\w+\b|\b(?:True|False|NonCompliant|Compliant)\b', observed), (cid, observed)
            assert not re.search(r'\b(?:present|enabled|configured|password|mfa)\s*:\s*[01]\b', observed, re.I), (cid, observed)
            assert not re.search(r'\([^)]*:\s*(?:\d+|enabled|disabled)\)', observed), (cid, observed)


def test_numeric_boolean_flags_are_not_reinterpreted_as_observed_settings():
    finding = {'provider': 'azure', 'check_id': 'azure.claude.keyvault_audit_and_alllogs_groups',
               'status': 'FAIL', 'evidence': {'all_logs_group': 0, 'audit_group': 0}}
    assert native_observation(finding) is None
    finding['evidence'] = {'all_logs_group': False, 'audit_group': False}
    assert 'audit' in native_observation(finding)
