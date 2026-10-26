"""Replay current native witnesses and bind every Azure explanation to its source."""
from copy import deepcopy
from datetime import datetime, timezone
import gzip
import hashlib
import inspect
import json
from pathlib import Path
import re

import pytest

from peaso.checks import CHECKS
from peaso.checks.fixtures import CASES as NATIVE_CASES
from peaso.checks.catalog import description_for
from peaso.checks.azure_evidence_explanations import ROWS, evidence_summary, reviewed_explanation
from peaso.checks.azure_native_evidence_observations import evidence_summary as native_observation
from tests.test_gcp_current_source_reconciliation_20261020 import _bound_functions
from tests.azure_native_successor_inputs_20261020 import _native_rows
from tests.test_native_admission_cpu_successor_20261020 import REVIEWED_CURRENT_CHANGES, EPOCH, EPOCH_SHA256

ROOT = Path(__file__).resolve().parents[1]
CHECK_BY_ID = {check.id: check for check in CHECKS if check.provider == 'azure'}
LEDGER = json.loads((ROOT / 'docs/evidence-reviews/azure.json').read_text())
CASES = json.loads(gzip.decompress((ROOT / 'tests/fixtures/azure_evidence_review.json.gz').read_bytes()))
ASSESSMENT_SUCCESSOR_RAW = (ROOT / 'docs/check-review/azure-defender-assessment-four-current-binding-20261021.json').read_bytes()
assert hashlib.sha256(ASSESSMENT_SUCCESSOR_RAW).hexdigest() == '588a29f9bb3dc8e4ac7a0d1f16e58b94b0ae4f834327e236d92800084728e855'
ASSESSMENT_SUCCESSOR = json.loads(ASSESSMENT_SUCCESSOR_RAW)
CURRENT_RELEASE_BINDINGS = json.loads((ROOT / 'docs/evidence-reviews/azure-current-22-binding-20261022.json').read_text())
CURRENT_SOURCE_BINDINGS = CURRENT_RELEASE_BINDINGS['source_bindings']
CURRENT_WITNESS_SUCCESSORS = CURRENT_RELEASE_BINDINGS['witness_successors']
CURRENT_NATIVE_OUTCOMES = CURRENT_RELEASE_BINDINGS['current_native_outcomes']
assert CURRENT_RELEASE_BINDINGS['schema_version'] == 1
assert CURRENT_RELEASE_BINDINGS['staged_tree'] == '373efff118667cce912309e31681160eae8ef7cd'
assert set(CURRENT_SOURCE_BINDINGS) == {
    'azure.aks.api_server_restricted',
    *(f'azure.claude.activity_log_alert_{kind}_{action}'
      for kind in ('nsg', 'policy_assignment', 'public_ip', 'security_solution', 'sql_firewall_rule')
      for action in ('delete', 'write')),
    'azure.claude.activity_log_alert_subscription_security_solution_delete',
    'azure.claude.activity_log_alert_subscription_security_solution_write',
    'azure.claude.entra_user_recent_sign_in',
    'azure.review.acr.selected_image_secret_indicators',
    'azure.review.databricks.selected_notebook_source_secret_indicators',
    'azure.review.machine_learning.selected_code_file_secret_indicators',
    'azure.review.machine_learning.selected_command_job_secret_indicators',
    'azure.review.machine_learning.selected_environment_conda_secret_indicators',
    'azure_storage_account_10_3_4_7_02943e9',
}
assert set(CURRENT_NATIVE_OUTCOMES) == {
    'azure.claude.activity_log_alert_subscription_security_solution_delete',
    'azure.claude.activity_log_alert_subscription_security_solution_write',
    'azure.claude.entra_user_recent_sign_in',
    'azure_storage_account_10_3_4_7_02943e9',
}
assert set(CURRENT_WITNESS_SUCCESSORS) == {
    cid + '|' + str(number) for cid in CURRENT_NATIVE_OUTCOMES for number in range(len(CASES[cid]))
}

RELEASE_ADDED_AZURE_IDS = frozenset({
    'azure.iam.application_credentials_recent_activity',
    'azure.iam.custom_arm_role_has_declared_consumers',
    'azure.iam.custom_directory_role_has_declared_consumers',
    'azure.iam.service_principal_credentials_recent_activity',
    'azure.iam.service_principal_recent_activity',
    'azure.iam.single_tenant_application_has_consumer',
    'azure.iam.static_group_has_members',
    'azure.network.load_balancer_backend_pools_have_declaration_or_consumer',
    'azure.network.nic_has_owner_reference',
    'azure.network.public_ip_has_network_reference',
    'azure.network.route_table_has_subnet_reference',
    'azure.network.subnet_has_consumer_or_reservation_reference',
    'azure.review.acr.selected_image_high_critical_vulnerabilities',
    'azure.review.aks.selected_pod_image_high_vulnerabilities',
    'azure.review.aks.selected_pod_image_secret_indicators',
    'azure.review.app_service.runtime_support_declared',
    'azure.review.function.configured_deployment_container_archives_secret_indicators',
    'azure.review.synapse.selected_notebook_source_secret_indicators',
})
RELEASE_RETIRED_AZURE_IDS = frozenset({'azure.claude.aks_authorized_ip_ranges'})
RELEASE_SOURCE_SHA256 = {
    'peaso/checks/azure_acr_image_vulnerabilities_20261021.py': '65765fa530d831b39dd37414fc79502eec10e77971cfd58daa447c54d76606f7',
    'peaso/checks/azure_flex_deployment_archives_review_20261021.py': '04654eb038e8198385714093e6111a5692b5d8f2f9fc8983b75572b66b79f04b',
    'peaso/checks/azure_selected_aks_image_review_20261021.py': 'fe55e2cde5ba2a542a2fb8aca460aa9a65f5d5592c2d1aa79b1aede0f6c1ecd5',
    'peaso/checks/azure_synapse_selected_notebook_secret_review_20261021.py': '65bc8db47e617f13d22de4548e8eb4dffc447e10fbd70b1232a0c6799f322f77',
    'peaso/checks/provider_group_install_20261021.py': '50fb8eeacf4facdc950ffe251b341c5c0b691f566dcf863ef713998bf403c907',
    'peaso/unused_iam_azure.py': '23a89805c07a6ef8bc28f5b60f95b1f71779304599e183526b885c5213683be6',
    'peaso/unused_iam_azure_arm_roles.py': '3a67ae42f5b29a12ea65350e477e2b04597625361f87db643948f1fd4c5d2674',
    'peaso/unused_iam_azure_roles.py': '282d9d380c5cd7c9b20cd964351ef65a57a202ec0e24b802548e74bbf3bfffd8',
    'peaso/unused_network_azure_20261021.py': '8bc5856d984908fe88f1b7f38d3d22b6283479bb2d3a5fb45908a6a14ca2e5c4',
}


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def _checked_json(path):
    raw = (ROOT / path).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == PINNED_SUCCESSOR_INPUTS[path], path
    return json.loads(gzip.decompress(raw) if path.endswith('.gz') else raw)


@pytest.fixture(scope='module', autouse=True)
def _preserve_all_successor_sources_and_historical_inputs():
    def verify():
        archive = (ROOT / EPOCH).read_bytes()
        assert hashlib.sha256(archive).hexdigest() == EPOCH_SHA256
        predecessors = json.loads(gzip.decompress(archive))['files']
        for path, expected in PINNED_SUCCESSOR_INPUTS.items():
            raw = (ROOT / path).read_bytes()
            current = hashlib.sha256(raw).hexdigest()
            if path == ASSESSMENT_SUCCESSOR['evaluator_source']:
                assert expected == ASSESSMENT_SUCCESSOR['evaluator_predecessor_sha256']
                assert current == ASSESSMENT_SUCCESSOR['evaluator_current_sha256']
            elif current != expected:
                change = REVIEWED_CURRENT_CHANGES[path]
                assert set(change) == {'before_sha256', 'after_sha256', 'after_size'}
                assert expected == predecessors[path]['sha256'] == change['before_sha256']
                assert current == change['after_sha256'] and len(raw) == change['after_size']
            else:
                assert current == expected, path
        for path, expected in ASSESSMENT_SUCCESSOR['immutable_predecessor_files_sha256'].items():
            assert hashlib.sha256((ROOT / path).read_bytes()).hexdigest() == expected, path
    verify()
    yield
    verify()


def _reviewed_source_digest(cid, function):
    row = LEDGER[cid]
    if cid in CURRENT_SOURCE_BINDINGS:
        binding = CURRENT_SOURCE_BINDINGS[cid]
        assert binding['historical_source_sha256'] == row.get('source_sha256')
        assert binding['historical_predicate_sha256'] == row.get('predicate_sha256')
        assert binding['historical_description_sha256'] == row.get('description_contract_sha256')
        assert Path(inspect.getsourcefile(function)).resolve().relative_to(ROOT).as_posix() == binding['source']
        assert hashlib.sha256((ROOT / binding['source']).read_bytes()).hexdigest() == binding['current_source_sha256']
        assert hashlib.sha256(inspect.getsource(function).encode()).hexdigest() == binding['current_evaluator_sha256']
        assert _digest(ROWS[cid]) == binding['current_observed_text_sha256']
        assert _digest(description_for(cid)) == binding['current_description_sha256']
        return binding['current_evaluator_sha256']
    if cid in ASSESSMENT_SUCCESSOR['records']:
        update = ASSESSMENT_SUCCESSOR['records'][cid]
        assert row['predicate_sha256'] == update['historical_body_sha256']
        assert row['source_sha256'] == update['historical_wrapper_sha256']
        inner, = [f for f in _bound_functions(CHECK_BY_ID[cid].evaluate)
                  if f.__qualname__ == '_assessment_check.<locals>.evaluate']
        assert Path(inspect.getsourcefile(inner)).relative_to(ROOT).as_posix() == update['source']
        assert hashlib.sha256(inspect.getsource(inner).encode()).hexdigest() == update['current_body_sha256']
    actual = hashlib.sha256(inspect.getsource(function).encode()).hexdigest()
    if actual == row.get('source_sha256'):
        return row['source_sha256']
    if actual == row.get('predicate_sha256'):
        # Later admission schemas distinguish module bytes from predicate text.
        assert hashlib.sha256((ROOT / row['source']).read_bytes()).hexdigest() == row['source_sha256']
        return row['predicate_sha256']
    successor = SOURCE_SUCCESSORS[cid]
    assert successor['historical_body_sha256'] == row.get('predicate_sha256', row.get('source_sha256'))
    audit = _checked_json('docs/check-review/azure-k8s-current-predicate-bindings-20261020.json')
    accepted, = [record for record in audit['checks'] if record['id'] == cid]
    assert accepted['current_source'] == successor['source']
    assert Path(inspect.getsourcefile(function)).relative_to(ROOT).as_posix() == successor['source']
    assert accepted['current_body_sha256'] == successor['current_body_sha256']
    assert accepted['review_receipt'] == successor['review_receipt']
    _checked_json(successor['review_receipt'])
    if not accepted['matches_reviewed_predicate']:
        errata = _checked_json('docs/check-review/azure-master-predicate-attestation-errata-20261020.json')
        correction, = [record for record in errata['records'] if record['id'] == cid]
        assert correction['master_column_body_sha256'] == accepted['expected_body_sha256']
        assert correction['current_body_sha256'] == successor['current_body_sha256']
        assert correction['matching_individual_reviews']
        for proof in correction['matching_individual_reviews']:
            raw = (ROOT / proof['path']).read_bytes()
            assert hashlib.sha256(raw).hexdigest() == proof['sha256']
            node = json.loads(raw)
            for part in proof['record_path']:
                node = node[part]
            assert node.get('id', node.get('check_id')) == cid
            bound = proof['current_evaluator']
            assert bound.get('source_text_sha256', bound.get('sha256')) == successor['current_body_sha256']
    return successor['current_body_sha256']


def _reviewed_description_digest(cid, description):
    if cid in CURRENT_SOURCE_BINDINGS:
        return CURRENT_SOURCE_BINDINGS[cid]['current_description_sha256']
    if cid not in CURRENT_DESCRIPTION_CONTRACTS:
        return LEDGER[cid]['description_contract_sha256']
    successor = CURRENT_DESCRIPTION_CONTRACTS[cid]
    assert successor['historical_contract_sha256'] == LEDGER[cid].get('description_contract_sha256')
    assert description == successor['current']
    return _digest(successor['current'])


def _current_case(cid, number, historical):
    witness = CURRENT_WITNESS_SUCCESSORS.get(cid + '|' + str(number))
    if witness is not None:
        assert _digest(historical) == witness['historical_case_sha256']
        assert historical['status'] == witness['historical_status']
        branch = witness['native_branch']
        if witness['input_source'] == 'registered_native_cases':
            assert branch in {'pass', 'fail'}
            native = NATIVE_CASES[cid]
            item = native[branch]
            index = native.get(branch + '_index', native.get('index', {}))
        else:
            assert witness['input_source'] == 'historical_fixture' and branch is None
            item, index = historical['item'], historical['index']
        assert _digest({'item': item, 'index': index}) == witness['current_input_sha256']
        return {'item': item, 'index': index, 'status': witness['current_status'],
                'expected_evidence_sha256': witness['current_evidence_sha256']}
    if cid in ASSESSMENT_SUCCESSOR['records']:
        update = ASSESSMENT_SUCCESSOR['historical_fixture_successors'].get(cid + '|' + str(number))
        if update is not None:
            assert _digest(historical) == update['historical_case_sha256']
            assert historical['status'] == update['historical_status']
            return {'item': historical['item'], 'index': historical['index'],
                    'status': update['current_status'],
                    'expected_evidence_sha256': update['current_evidence_sha256']}
    reference = NATIVE_WITNESS_SUCCESSORS.get(cid + '|' + str(number))
    if reference is None:
        return historical
    assert _digest(historical) == reference['historical_case_sha256']
    assert historical['status'] == reference['historical_status']
    name = reference['native_case']
    if name == 'retained-uncertain-input':
        assert historical['status'] == reference['status'] == 'UNKNOWN'
        row = historical
    elif name == 'windows-native-linux':
        assert cid == 'azure.claude.vm_windows_secure_boot'
        row = deepcopy(historical)
        row['item']['properties']['storageProfile']['osDisk']['osType'] = 'Linux'
    elif name.startswith('aks-native/'):
        assert cid in {'azure_aks_cluster_7_2_1_6_93c4fab', 'azure_aks_cluster_aks_cluster_rbac_enabled_db12524'}
        branch = name.split('/', 1)[1]
        cases = _checked_json('peaso/checks/azure_aks_legacy_projection_review_20261020_fixtures.json')[cid]
        row = {'item': cases[branch], 'index': cases.get(branch + '_index', cases.get('index', {}))}
    else:
        row = _native_rows()[cid][name]
        assert row['status'] == reference['status']
    if historical['status'] != reference['status']:
        assert reference['status'] == 'UNKNOWN'
        assert cid in {'azure.claude.managed_hsm_audit_logging', 'azure.claude.storage_access_keys_rotated_90',
                       'azure_aks_cluster_aks_cluster_rbac_enabled_db12524'}
        if cid == 'azure.claude.managed_hsm_audit_logging':
            assert historical['status'] == 'PASS'
            assert row['evidence']['diagnostic_retention_retired_on'] == '2025-09-30'
            assert row['evidence']['audit_archive_declared'] is True
            assert 'effective retention is unresolved' in row['evidence']['reason']
            _reviewed_source_digest(cid, inspect.unwrap(CHECK_BY_ID[cid].evaluate))
        else:
            assert historical['status'] == 'NOT_APPLICABLE'
    return {'item': row['item'], 'index': row['index'], 'status': reference['status'],
            'expected_evidence_sha256': reference['evidence_sha256']}


def test_every_registered_azure_check_has_a_reviewed_explicit_explanation_and_fixtures():
    assert len(CASES) == 969
    assert len(ADMITTED_DESCRIPTOR_CONTRACTS) == 33
    assert not CASES.keys() & ADMITTED_DESCRIPTOR_CONTRACTS.keys()
    assert set(ROWS) == set(LEDGER) == CASES.keys() | ADMITTED_DESCRIPTOR_CONTRACTS.keys()
    assert len(ROWS) == 1002
    assert set(ROWS) - set(CHECK_BY_ID) == RELEASE_RETIRED_AZURE_IDS
    assert set(CHECK_BY_ID) - set(ROWS) == RELEASE_ADDED_AZURE_IDS
    assert set(CHECK_BY_ID) == (set(ROWS) - RELEASE_RETIRED_AZURE_IDS) | RELEASE_ADDED_AZURE_IDS
    used_sources = set()
    for cid in RELEASE_ADDED_AZURE_IDS:
        check = CHECK_BY_ID[cid]
        function = inspect.unwrap(check.evaluate)
        source = Path(inspect.getsourcefile(function)).resolve().relative_to(ROOT).as_posix()
        assert function.__module__ == source.removesuffix('.py').replace('/', '.')
        assert function.__globals__ is vars(__import__(function.__module__, fromlist=['']))
        assert hashlib.sha256((ROOT / source).read_bytes()).hexdigest() == RELEASE_SOURCE_SHA256[source]
        used_sources.add(source)
        assert description_for(cid)
        cases = NATIVE_CASES[cid]
        for branch, expected in (('pass', 'PASS'), ('fail', 'FAIL')):
            index = cases.get(branch + '_index', cases.get('index', {}))
            assert check.evaluate(deepcopy(cases[branch]), deepcopy(index))[0] == expected
    assert used_sources == set(RELEASE_SOURCE_SHA256)
    for cid, row in ROWS.items():
        if cid in ADMITTED_DESCRIPTOR_CONTRACTS:
            assert row == ADMITTED_DESCRIPTOR_CONTRACTS[cid]
            assert row['purpose']
            assert isinstance(row['limit'], str)
            assert (ROOT / LEDGER[cid]['fixture_source']).is_file()
        else:
            assert row['purpose'] and row['limit'] and row['label']
        assert len((row['purpose'] + ' ' + row['limit']).split()) <= 30
        if 'missing_fixtures' in LEDGER[cid]:
            assert LEDGER[cid]['missing_fixtures'] == []
        else:
            assert cid in {'azure.review.app_service.selected_app_settings_secret_indicators',
                           'azure.review.acr.selected_image_secret_indicators'}
            native = _checked_json(LEDGER[cid]['fixture_source'])[cid]
            assert {'pass', 'fail', 'unknown'} <= native.keys()
            assert all(branch + '_index' in native or 'index' in native for branch in ('pass', 'fail', 'unknown'))
        assert LEDGER[cid]['branch_coverage']
        assert CASES[cid] if cid in CASES else _checked_json(LEDGER[cid]['fixture_source'])


@pytest.mark.parametrize('cid', sorted(CHECK_BY_ID))
def test_each_explanation_is_bound_to_the_current_exact_evaluator_and_contract(cid):
    if cid in RELEASE_ADDED_AZURE_IDS:
        function = inspect.unwrap(CHECK_BY_ID[cid].evaluate)
        source = Path(inspect.getsourcefile(function)).resolve().relative_to(ROOT).as_posix()
        assert hashlib.sha256((ROOT / source).read_bytes()).hexdigest() == RELEASE_SOURCE_SHA256[source]
        assert description_for(cid) and cid in NATIVE_CASES
        return
    function = inspect.unwrap(CHECK_BY_ID[cid].evaluate)
    assert hashlib.sha256(inspect.getsource(function).encode()).hexdigest() == _reviewed_source_digest(cid, function)
    encoded = json.dumps(description_for(cid), sort_keys=True, separators=(',', ':')).encode()
    assert hashlib.sha256(encoded).hexdigest() == _reviewed_description_digest(cid, description_for(cid))
    assert LEDGER[cid]['interpretation'] == ROWS[cid]['purpose']
    assert LEDGER[cid]['evidence_limit'] == ROWS[cid]['limit']


def test_retired_aks_authorized_ranges_archive_and_active_alias():
    from peaso.checks import CHECK_ALIASES
    from peaso.engine import _selection
    retired, = RELEASE_RETIRED_AZURE_IDS
    active = 'azure.aks.api_server_restricted'
    assert CHECK_ALIASES[retired] == active and retired not in CHECK_BY_ID
    for path in ('docs/evidence-reviews/azure.json', 'tests/fixtures/azure_evidence_review.json.gz'):
        assert hashlib.sha256((ROOT / path).read_bytes()).hexdigest() == PINNED_SUCCESSOR_INPUTS[path]
    assert LEDGER[retired]['source'] == 'peaso/checks/claude_azure_identity.py'
    assert LEDGER[retired]['source_sha256'] == '478f1dd3f0ca38ecabed31c4b4772ea3ffbc0b584bee165cb93d87f1577ce5fc'
    assert {row['status'] for row in CASES[retired]} == {'PASS', 'FAIL', 'UNKNOWN', 'NOT_APPLICABLE'}
    assert ROWS[retired]['purpose'] == LEDGER[retired]['interpretation']
    _, selected = _selection('azure', None, [retired], None)
    assert [check.id for check in selected] == [active]
    case = NATIVE_CASES[active]
    for branch, expected in (('pass', 'PASS'), ('fail', 'FAIL'), ('unknown', 'UNKNOWN')):
        assert CHECK_BY_ID[active].evaluate(deepcopy(case[branch]), deepcopy(case.get(branch + '_index', case.get('index', {}))))[0] == expected


GATEWAY_CIDR_SUCCESSOR_ID = 'azure.other.gateway_api_cidr_allowlist'
GATEWAY_CIDR_SUCCESSOR_FIELDS = {'approved_cidrs', 'approved_cidr_count', 'outside_approved_ranges_empty',
                                 'effective_paths', 'effective_path_count'}


@pytest.mark.parametrize('cid', sorted(CASES.keys() - RELEASE_RETIRED_AZURE_IDS))
def test_actual_native_positive_negative_unknown_manual_and_inapplicable_witnesses(cid, monkeypatch):
    if cid == 'azure.claude.storage_access_keys_rotated_90':
        # Replay the retained ages at their capture date, rather than letting
        # this immutable evidence fixture age by another day on every CI run.
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
                item = native[branch]
                index = native.get(branch + '_index', native.get('index', {}))
                assert _digest({'item': item, 'index': index}) == expected['input_sha256']
                status, evidence = CHECK_BY_ID[cid].evaluate(deepcopy(item), deepcopy(index))
            assert status == expected['status'], (cid, branch, status, evidence)
            assert _digest(evidence) == expected['evidence_sha256']
    for number, historical in enumerate(CASES[cid]):
        case = _current_case(cid, number, historical)
        item, index = deepcopy((case['item'], case['index']))
        status, evidence = CHECK_BY_ID[cid].evaluate(item, index)
        assert status == case['status'], (cid, case['status'], status, evidence)
        if 'expected_evidence_sha256' in case:
            assert _digest(json.loads(json.dumps(evidence, sort_keys=True))) == case['expected_evidence_sha256']
        elif cid == GATEWAY_CIDR_SUCCESSOR_ID:
            # The reviewed successor keeps the historical verdict and evidence
            # exactly and only appends the WAF facts behind that verdict.
            observed = json.loads(json.dumps(evidence, sort_keys=True))
            assert {key: observed.get(key) for key in case['evidence']} == case['evidence']
            assert set(observed) - set(case['evidence']) <= GATEWAY_CIDR_SUCCESSOR_FIELDS
        else:
            assert json.loads(json.dumps(evidence, sort_keys=True)) == case['evidence']
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
                assert ROWS[cid]['purpose'] in summary
                assert ROWS[cid]['limit'] in summary
                assert reviewed_explanation(cid, summary, status) == summary
            else:
                # Current observed evidence: 3-5 short plain lines (AGENTS.md),
                # with one shared structure for every supported status.
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
    assert lines[0] == 'Shared Key access is enabled for this storage account.'
    assert 3 <= len(lines) <= 5
    # Possible impact only; no claim that a key was used or access happened.
    assert all(word in summary for word in ('may', 'could'))
    assert evidence_summary({'provider': 'azure', 'check_id': 'azure.storage.no_shared_key', 'status': 'FAIL',
                             'evidence': {'field': 'properties.allowSharedKeyAccess', 'configured': 'true'}}) is None


def test_native_legacy_identifiers_follow_actual_predicate_instead_of_the_title():
    expectations = {
        'azure_search_service_10_6_3_27_ba08488': 'Access boundaries',
        'azure_application_gateway_app_ensure_http_is_redirected_to_https_debad63': 'Validated HTTPS',
        'azure.gap.network_security_group_rdp_access_restricted': 'Guest user rights',
        'azure.other.ml_sensitive_terminal_disabled': 'terminals',
        'azure_vm_8_2_1_1_712e1ad': 'historical profile prefers no bootstrap SSH keys',
    }
    for cid, text in expectations.items():
        assert text.lower() in ROWS[cid]['purpose'].lower()
    assert 'does not automatically expire' in ROWS['azure.claude.storage_key_expiration_policy_max_90']['limit']
    assert 'regardless of next-hop' in ROWS['azure_route_table_network_http_internet_access_restricted_5cd2484']['limit']


def test_all_new_native_shape_rules_replay_both_interpretable_statuses_and_remain_source_bound():
    from peaso.checks.azure_native_evidence_observations import ROWS as NATIVE_ROWS
    assert len(NATIVE_ROWS) == 477
    for cid, rules in NATIVE_ROWS.items():
        encoded = json.dumps(rules, sort_keys=True, separators=(',', ':')).encode()
        assert hashlib.sha256(encoded).hexdigest() == LEDGER[cid]['native_observation_rules_sha256']
        for case in CASES[cid]:
            finding = dict(case, provider='azure', check_id=cid)
            if case['status'] in {'PASS', 'FAIL'}:
                assert native_observation(finding), (cid, case['status'], case['evidence'])


def test_count_only_success_reports_its_evidence_limit_instead_of_inventing_configuration():
    finding = {'provider': 'azure', 'check_id': 'azure.gap.asset_inventory_required_metadata', 'status': 'PASS', 'evidence': {'evaluated': 7}}
    observed = native_observation(finding)
    assert observed == 'The check assessed 7 resources; individual inventory tags were not retained.'
    finding['evidence']['evaluated'] = True
    assert native_observation(finding) is None


def test_measured_native_access_checks_follow_the_evidence_rather_than_the_legacy_title():
    for cid, expected in [
        ('azure.other.database_default_login_restricted', 'default database credentials'),
        ('azure_search_service_10_6_3_27_ba08488', 'index or query authorization'),
        ('azure.other.ml_compute_file_download_restricted', 'file downloads'),
    ]:
        case = next(row for row in CASES[cid] if row['status'] == 'FAIL')
        assert expected in native_observation(dict(case, provider='azure', check_id=cid))


def test_every_registered_check_rejects_empty_and_unrelated_positive_witnesses():
    for cid in ROWS:
        for status in ('PASS', 'FAIL', 'UNKNOWN', 'DENIED', 'MANUAL', 'NOT_APPLICABLE', 'EMPTY'):
            for evidence in ({}, {'unrelated': True}):
                assert evidence_summary({'provider': 'azure', 'check_id': cid, 'status': status, 'evidence': evidence}) is None, (cid, status, evidence)


def test_unknown_manual_and_inapplicable_copy_is_check_bound_brief_and_neutral():
    assert len(LATER_NATIVE_NEUTRAL_LENGTHS) == 7
    assert LATER_NATIVE_NEUTRAL_LENGTHS.keys() <= ADMITTED_DESCRIPTOR_CONTRACTS.keys()
    assert not LATER_NATIVE_NEUTRAL_LENGTHS.keys() & CASES.keys()
    for lengths in LATER_NATIVE_NEUTRAL_LENGTHS.values():
        assert set(lengths) == {'missing_observation', 'manual_observation'}
    for cid, row in ROWS.items():
        for key in ('missing_observation', 'manual_observation', 'not_applicable_observation'):
            if key not in row:
                assert cid in MISSING_NEUTRAL_FIELDS and key in MISSING_NEUTRAL_FIELDS[cid]
                status = {'manual_observation': 'MANUAL', 'not_applicable_observation': 'NOT_APPLICABLE'}[key]
                assert status not in {branch['status'] for branch in LEDGER[cid]['branch_coverage']}
                assert evidence_summary({'provider': 'azure', 'check_id': cid, 'status': status, 'evidence': {}}) is None
                continue
            text = reviewed_explanation(cid, row[key])
            if key in LATER_NATIVE_NEUTRAL_LENGTHS.get(cid, {}):
                # These seven later admissions retain exact reviewed copy, not a global cap change.
                assert len(text) == LATER_NATIVE_NEUTRAL_LENGTHS[cid][key], (cid, key, text)
                assert _digest(text) == NEUTRAL_EXPLANATION_CONTRACTS[cid][key]
            else:
                assert len(text) <= 240, (cid, key, text)
            if cid in NEUTRAL_EXPLANATION_CONTRACTS:
                assert _digest(text) == NEUTRAL_EXPLANATION_CONTRACTS[cid][key]
            elif cid in ADMITTED_DESCRIPTOR_CONTRACTS and 'label' not in row:
                assert text.startswith(row[key]) and row['purpose'] in text
            else:
                assert row['label'] in text
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
    assert native_observation(finding) == 'The vault disables both the required audit-log and complete-log category groups.'


SOURCE_SUCCESSORS = json.loads(r'''
{
  "azure.aks.api_server_restricted": {
    "current_body_sha256": "f80b127dd71d787809aceaffbe313a8e060cc2f85aaef96c8529e19377dd0231",
    "historical_body_sha256": "a2dcbdaea63ab9fe87a5a1fe1e83cfeb1d508ebcda856b43ce236f5f7999c7a6",
    "review_receipt": "docs/check-review/azure-four-cohort-integration-20261020.json",
    "source": "peaso/checks/exposure_endpoints.py"
  },
  "azure.claude.acr_vnet_service_endpoint": {
    "current_body_sha256": "0634e4f4d4e8702fff3908d4e445015eb2c5122e3d84e6565153cd617aa97fd5",
    "historical_body_sha256": "3a480ee5da58defd8eca1b931b55952cece908e8b7d5021e2671062726c26576",
    "review_receipt": "docs/check-review/azure-application-compute-1-native-review-20261020.json",
    "source": "peaso/checks/claude_azure_compute.py"
  },
  "azure.claude.aks_authorized_ip_ranges": {
    "current_body_sha256": "c60305b934e0be7d21a4eecf61458f7c301148c34bb929f78198b3b154667417",
    "historical_body_sha256": "478f1dd3f0ca38ecabed31c4b4772ea3ffbc0b584bee165cb93d87f1577ce5fc",
    "review_receipt": "docs/check-review/azure-four-cohort-integration-20261020.json",
    "source": "peaso/checks/claude_azure_identity.py"
  },
  "azure.claude.databricks_subnet_nsg": {
    "current_body_sha256": "57b448a250ec1e9fc9c781376dcdd212c32737927e0932227702e3e504425c18",
    "historical_body_sha256": "48077dba43ebf45de53afc1907c6386bd0d01b6e55e8bf12eca8638b3de26c6e",
    "review_receipt": "docs/check-review/azure-application-compute-1-native-review-20261020.json",
    "source": "peaso/checks/claude_azure_compute.py"
  },
  "azure.claude.entra_ca_mfa_admin_portals": {
    "current_body_sha256": "e751ba9b623809bfe38225ddf8ca2a9076a379a03b204cac2eb80527196ab19e",
    "historical_body_sha256": "4a6f8c24c39c0f2af77646cc81f9f5be973e64bfa9cbc6ed5fbecb4c574b9c42",
    "review_receipt": "docs/check-review/azure-identity-integration-20261020.json",
    "source": "peaso/checks/claude_azure_identity.py"
  },
  "azure.claude.entra_ca_mfa_management_api": {
    "current_body_sha256": "e751ba9b623809bfe38225ddf8ca2a9076a379a03b204cac2eb80527196ab19e",
    "historical_body_sha256": "4a6f8c24c39c0f2af77646cc81f9f5be973e64bfa9cbc6ed5fbecb4c574b9c42",
    "review_receipt": "docs/check-review/azure-identity-integration-20261020.json",
    "source": "peaso/checks/claude_azure_identity.py"
  },
  "azure.claude.iam_custom_role_administers_locks": {
    "current_body_sha256": "686ecf2e2f0c7ae554f79e68502695c71c35a413c4cdabcbc15418486a55c455",
    "historical_body_sha256": "340eb08f284ac6715b17747755048010dbfb9860f3fb89495dd399a396ff4269",
    "review_receipt": "docs/check-review/azure-final-services-integration-20261020.json",
    "source": "peaso/checks/claude_azure_identity.py"
  },
  "azure.claude.managed_hsm_audit_logging": {
    "current_body_sha256": "79f2eda13c77a5da077a289f01f36a7558f052a3cace71e19471107dc9ff2356",
    "historical_body_sha256": "07888abdfaad847f8c34aef80bc4b3a6a06f292ad943a636ebd86e2bbe38c100",
    "review_receipt": "docs/check-review/azure-network-audit-admission-20261020.json",
    "source": "peaso/checks/claude_azure_identity.py"
  },
  "azure.claude.mssql_managed_instance_vulnerability_assessment": {
    "current_body_sha256": "96d1239e7308deaaad08e2cf224e31a39da6926433e2b01dc3615128d6a4aa68",
    "historical_body_sha256": "25edb61bb56c9da9406f69cbd212657c607a6f00b806fa581de4cf9231c39e70",
    "review_receipt": "docs/check-review/azure-final-services-integration-20261020.json",
    "source": "peaso/checks/claude_azure_network.py"
  },
  "azure.claude.recovery_vault_backup_retention_30_days": {
    "current_body_sha256": "292b45c69eba1bb6917b81bb6584ea056feff2dc1ab1a2d8a224b7e26d43a40c",
    "historical_body_sha256": "f5db468f3869c0260630cfd41decf1617071dc594d4e518dc610373ac2c4591e",
    "review_receipt": "docs/check-review/azure-four-cohort-integration-20261020.json",
    "source": "peaso/checks/claude_azure_network.py"
  },
  "azure.claude.servicefabric_cluster_encrypt_and_sign": {
    "current_body_sha256": "dccd9c560c48daa7de97516707d14dc03f702977c63d9fc3bc797cb18034166e",
    "historical_body_sha256": "2c2d8b5b101c237adef59f7e9e2144ea258cdb610d7d0b78a480c0fc289fbc84",
    "review_receipt": "docs/check-review/azure-final-services-integration-20261020.json",
    "source": "peaso/checks/claude_azure_data.py"
  },
  "azure.claude.servicefabric_cluster_entra_auth": {
    "current_body_sha256": "dd498770c32cf5dd62c3c7d3aba2f2095c25fccb227404e98c153479371f06f3",
    "historical_body_sha256": "a1984e92139d34288b77892aeb3feb7db421d8c6afb936421d55f3d536f8a524",
    "review_receipt": "docs/check-review/azure-final-services-integration-20261020.json",
    "source": "peaso/checks/claude_azure_data.py"
  },
  "azure.claude.sql_database_va_findings_resolved": {
    "current_body_sha256": "df58e255b50215c0b5d15f3ad8d57def90b04a7effc15e6a565ea39485f1985f",
    "historical_body_sha256": "bc983e337e91eb434019b704323495d467020fb8d36718e5bfc4d42fe8f15748",
    "review_receipt": "docs/check-review/azure-four-cohort-integration-20261020.json",
    "source": "peaso/checks/claude_azure_data.py"
  },
  "azure.claude.storage_access_keys_rotated_90": {
    "current_body_sha256": "94557aa97b6fd222ae52286e17aa496ccede3363b7882901819d352fcb81e325",
    "historical_body_sha256": "e8b3e3863a763a1a0f7643ca49b67a5c2405cbdeba5e49ed357173eaa7146d79",
    "review_receipt": "docs/check-review/azure-storage-compute-integration-20261020.json",
    "source": "peaso/checks/claude_azure_data.py"
  },
  "azure.claude.synapse_workspace_vulnerability_assessment": {
    "current_body_sha256": "3ea515442164cb65161fd26929a4d2604e69897258b63444d5e8bbd8dd7bc4b1",
    "historical_body_sha256": "6840aae30ee78791225493b32fb261152623fc674326dc3310c7889f01341267",
    "review_receipt": "docs/check-review/azure-application-compute-1-native-review-20261020.json",
    "source": "peaso/checks/claude_azure_data.py"
  },
  "azure.claude.vm_windows_secure_boot": {
    "current_body_sha256": "703e3a64273858988f61d70fe8cc9ac80d5b4ed256e559b1df4c2f2d032544b9",
    "historical_body_sha256": "cf70d91b6261fd58a82f926e90697ebf44baf7741a7e5ac8e0ee9723074662dc",
    "review_receipt": "docs/check-review/azure-storage-compute-integration-20261020.json",
    "source": "peaso/checks/claude_azure_compute.py"
  },
  "azure.claude.vmss_not_empty": {
    "current_body_sha256": "ab87a7931218c06a8acd714de05710e7ae6f8703a4669391c97dfd4ae143d5f4",
    "historical_body_sha256": "03924ebea965cf1bb4211870a0b0b06357eed7b4a3d49d1bef6efd96a7234157",
    "review_receipt": "docs/check-review/azure-application-compute-1-native-review-20261020.json",
    "source": "peaso/checks/claude_azure_compute.py"
  },
  "azure.claude2.app_gateway_min_tls_12": {
    "current_body_sha256": "bf9df7e9745a68b1553614e8bc54e3889f7fa62d5bf917d0736569d9c8d846c6",
    "historical_body_sha256": "a56e166fbbb938cec1c9c4e3e87f2f67744cd8626097984331e79a20e062866c",
    "review_receipt": "docs/check-review/azure-four-cohort-integration-20261020.json",
    "source": "peaso/checks/claude2_azure_network.py"
  },
  "azure.claude2.app_gateway_waf_enabled": {
    "current_body_sha256": "23bfbe980c83b953d999b51d9ab7d86dc47516bef584c61bc35faa23cc8652ee",
    "historical_body_sha256": "3f6ef09b9f9305fcbf4342b89328c74b1dc22de4fb26812c57c4d10d2c2ae190",
    "review_receipt": "docs/check-review/azure-four-cohort-integration-20261020.json",
    "source": "peaso/checks/claude2_azure_network.py"
  },
  "azure.claude2.nsg_flow_log_configured": {
    "current_body_sha256": "9ae4d89aa07006d8df0807d66459dd01118d8e254bfbb903b9d844a105eaa0fc",
    "historical_body_sha256": "f44218681113d74c6734f55c783a04c6326f388df240ad0c89f71dccaca8c419",
    "review_receipt": "docs/check-review/azure-storage-compute-integration-20261020.json",
    "source": "peaso/checks/claude2_azure_network.py"
  },
  "azure.review.acr.selected_image_secret_indicators": {
    "current_body_sha256": "c94a43122917226864b694f67d20ae2b86f71b32843297af55e83a9a761bac39",
    "historical_body_sha256": null,
    "review_receipt": "docs/check-review/azure-acr-image-secret-implementation-20261020.json",
    "source": "peaso/checks/azure_acr_image_secret_review_20261020.py"
  },
  "azure.review.app_service.selected_app_settings_secret_indicators": {
    "current_body_sha256": "18af090279eb93d9be3bb3ad5eab74ba3efb7cdab979c009925ed11fc245ddbd",
    "historical_body_sha256": null,
    "review_receipt": "docs/check-review/azure-app-settings-secret-implementation-20261020.json",
    "source": "peaso/checks/azure_app_settings_secret_review_20261020.py"
  },
  "azure.sql.minimum_tls": {
    "current_body_sha256": "c8298bfe4106fd7539d6d725c5f3834d60baea184180396f67da36c422718fc6",
    "historical_body_sha256": "41601f6110d325d3038ad5c33f860e2b339851037de4c1760e4b64a9c0132324",
    "review_receipt": "docs/check-review/azure-four-cohort-integration-20261020.json",
    "source": "peaso/checks/azure.py"
  },
  "azure_aks_cluster_7_2_1_6_93c4fab": {
    "current_body_sha256": "90f1e43816a146dde1c4f0f6ea63e52db552195e6283587811e99c8b643197c5",
    "historical_body_sha256": "ef7b992d7276bf5ba86ff0e337b9cb92f1fc938187ac89796a1fa2979f603719",
    "review_receipt": "docs/check-review/azure-final-services-integration-20261020.json",
    "source": "peaso/checks/azure_aks_legacy_projection_review_20261020.py"
  },
  "azure_aks_cluster_aks_cluster_rbac_enabled_db12524": {
    "current_body_sha256": "eececf75a0dd6ff06b650959de4d7ab22f4fb4732378492015a4175f697bf80a",
    "historical_body_sha256": "145cd00154f8a701c093147ffa74fd90b8198bb44d5718906c0af28f1ae4bb22",
    "review_receipt": "docs/check-review/azure-final-services-integration-20261020.json",
    "source": "peaso/checks/azure_aks_legacy_projection_review_20261020.py"
  },
  "azure_application_gateway_11_5_1_1_1_f56bdc2": {
    "current_body_sha256": "e0a1b976e2b1bd5340512534e881562a391e7a4030c56780b78ba25908249d48",
    "historical_body_sha256": "237723d0f6042e9bc1fbecd0ea96d918be0e6a9bac3b5314f511ccf65a78fa25",
    "review_receipt": "docs/check-review/azure-provider-integration-acceptance-20261020.json",
    "source": "peaso/checks/azure_public_edge_config_review_20261020.py"
  },
  "azure_application_gateway_app_http_logs_enabled_2de0361": {
    "current_body_sha256": "8c3d71c83ebbc8dd3154f310a6023491f54114a7e3882d4f6e3c3850daefb92c",
    "historical_body_sha256": "a4927de5baf9dcd0574ec2970095c00ae0cd67511787c1ef8f7cc08e03a4b84e",
    "review_receipt": "docs/check-review/azure-provider-integration-acceptance-20261020.json",
    "source": "peaso/checks/azure_gateway_logging_review_20261020.py"
  }
}
''')


CURRENT_DESCRIPTION_CONTRACTS = json.loads(r'''
{
  "azure.claude.acr_vnet_service_endpoint": {
    "current": {
      "description": "Checks for deny-by-default registry network rules with at least one VNet rule. Allowed IP ranges and public network access are evaluated separately.",
      "evaluated": [
        "properties.networkRuleSet.defaultAction",
        "properties.networkRuleSet.virtualNetworkRules[].id"
      ],
      "fail_when": "FAIL when the registry default action is Allow or it has no virtual network rule IDs.",
      "not_applicable_when": null,
      "pass_when": "PASS when default action is Deny and at least one virtual network rule has a subnet ID."
    },
    "historical_contract_sha256": "5427b0ab002b062227eafc87b0b1319788cff0597be3295e504499b9cb2c532f"
  },
  "azure.claude.aks_authorized_ip_ranges": {
    "current": {
      "description": "Checks public API authorized CIDRs for a restricted address union. Empty ranges or rules covering the Internet fail; malformed ranges remain unresolved. Azure’s special outbound-IP selector is preserved.",
      "evaluated": [
        "properties.apiServerAccessProfile.enablePrivateCluster",
        "properties.apiServerAccessProfile.authorizedIPRanges"
      ],
      "fail_when": "Authorized ranges are empty or their union allows every source.",
      "not_applicable_when": "The AKS API endpoint is private.",
      "pass_when": "The authorized IP ranges are valid and their union does not allow every source."
    },
    "historical_contract_sha256": "2c2913ee998e492b659fc073899419b7b9118e298156fa3057a6d220f16b7cde"
  },
  "azure.claude.iam_custom_role_administers_locks": {
    "current": {
      "description": "Checks whether a custom role in the selected assignable scope declares both resource-lock write and delete, combining permission blocks after subtracting each block’s NotActions. This does not establish any user’s effective access.",
      "evaluated": [
        "name",
        "role_definition.properties.permissions[].actions[]"
      ],
      "fail_when": "Complete native role definitions contain no such custom role.",
      "not_applicable_when": null,
      "pass_when": "A native custom role declares both lock write and delete after its exclusions."
    },
    "historical_contract_sha256": "22a628c01d4a30340a853ce58de1ef122b0b7115420d451588a084fa3ff9f13b"
  },
  "azure.claude.managed_hsm_audit_logging": {
    "current": {
      "description": "Checks declared HSM AuditEvent storage logging. Legacy diagnostic retention stopped applying in September 2025, so an archive declaration alone leaves this combined retention requirement unresolved.",
      "evaluated": [
        "diagnosticSettings[].properties.storageAccountId",
        "diagnosticSettings[].properties.logs[].category",
        "diagnosticSettings[].properties.logs[].enabled",
        "diagnosticSettings[].properties.logs[].retentionPolicy.days"
      ],
      "fail_when": "No diagnostic setting declares enabled AuditEvent logging to a storage account destination.",
      "not_applicable_when": null,
      "pass_when": "No current native PASS: legacy diagnostic retention fields do not establish current retention."
    },
    "historical_contract_sha256": "9ec7d41fa2f94c137b427a818e9dd4b0cdab372275d4d21baed933d301c2faba"
  },
  "azure.claude.recovery_vault_backup_retention_30_days": {
    "current": {
      "description": "Checks each daily backup policy’s native retention duration and unit against 30 days. One calendar month is unresolved; missing or invalid units cannot pass.",
      "evaluated": [
        "backupPolicies[].properties.retentionPolicy.dailySchedule.retentionDuration.count",
        "backupPolicies[].properties.retentionPolicy.dailySchedule.retentionDuration.durationType"
      ],
      "fail_when": "FAIL when any collected daily backup policy retains recovery points for fewer than 30 days.",
      "not_applicable_when": "Policies exist but none has a daily retention schedule. An empty policy inventory fails.",
      "pass_when": "PASS when all applicable daily policies retain recovery points for at least 30 days."
    },
    "historical_contract_sha256": "7d4a58251b8255d0c8caed2ff969ee8480f62fedd08602ef543a94a822d7e550"
  },
  "azure.claude.sql_database_va_findings_resolved": {
    "current": {
      "description": "Checks the latest completed database vulnerability scan’s failed-check count. Execution errors, missing completion state or contradictory counts remain unresolved; an unexecuted scan with zero findings cannot pass.",
      "evaluated": [
        "name",
        "vulnerabilityAssessmentScans[].properties.endTime",
        "vulnerabilityAssessmentScans[].properties.numberOfFailedSecurityChecks"
      ],
      "fail_when": "The latest scan completed with Failed state and a positive failed-check count.",
      "not_applicable_when": "The database name is master. With no scans on another database, the evaluator returns MANUAL.",
      "pass_when": "The latest scan completed with Passed state and zero failed security checks."
    },
    "historical_contract_sha256": "3e7c77d7d1b734028df411598af6edd9e801c1ffbcf5ff3f2170f8b29984979c"
  },
  "azure.claude.storage_access_keys_rotated_90": {
    "current": {
      "description": "Checks both native storage-key creation times against the captured scan time. Either key older than 90 days fails; incomplete, future or malformed times remain unresolved.",
      "evaluated": [
        "properties.keyCreationTime"
      ],
      "fail_when": "At least one of the two valid native key creation times is more than 90 days before the captured scan time.",
      "not_applicable_when": "No automatic exclusion; absent, incomplete, future or malformed key creation times remain UNKNOWN.",
      "pass_when": "Both key1 and key2 have valid creation times no more than 90 days before the captured scan time."
    },
    "historical_contract_sha256": "d2a6e4ab5f7ab6885a666e766abe40c34bd047235b07fc2f885b933104abbabc"
  },
  "azure.claude.storage_vhd_accounts_cmk": {
    "current": {
      "description": "Matches unmanaged OS-disk HTTPS VHD URLs to the native Blob endpoint of a collected storage account, then checks that account’s encryption key source. Foreign or unresolved endpoints cannot establish compliance.",
      "evaluated": [
        "scope",
        "vm[].properties.storageProfile.osDisk.vhd.uri",
        "storage_account[].name",
        "storage_account[].properties.encryption.keySource"
      ],
      "fail_when": "FAIL when a VM unmanaged OS VHD resolves to a storage account whose encryption.keySource is Microsoft.Storage.",
      "not_applicable_when": "NOT_APPLICABLE when the anchor is not a subscription.",
      "pass_when": "PASS when every resolved VHD host account uses a non-platform key source."
    },
    "historical_contract_sha256": "50fecc7343c4e0115c9020bd9e822748f8df1f6ada528490c8a2bd2453ea91a6"
  },
  "azure.claude.synapse_workspace_vulnerability_assessment": {
    "current": {
      "description": "Checks the workspace SQL server vulnerability-assessment policy for recurring scans. SQL pool policies and completed scan results are separate.",
      "evaluated": [
        "sqlVulnerabilityAssessments[].properties.recurringScans.isEnabled"
      ],
      "fail_when": "FAIL when no SQL vulnerability assessment has recurringScans.isEnabled true.",
      "not_applicable_when": null,
      "pass_when": "PASS when at least one assessment has recurring scans enabled."
    },
    "historical_contract_sha256": "837864b0a7caafaef6c9bc6b99dbfa8f572ed3830032a31b63d6c17db2068ecf"
  },
  "azure.claude.vm_windows_secure_boot": {
    "current": {
      "description": "Uses the native Windows OS type, including SQL and custom images, to check the security profile and UEFI Secure Boot flag. Standard profiles or explicitly disabled Secure Boot fail.",
      "evaluated": [
        "properties.storageProfile.osDisk.osType",
        "properties.storageProfile.imageReference.offer",
        "properties.securityProfile.securityType",
        "properties.securityProfile.uefiSettings.secureBootEnabled"
      ],
      "fail_when": "FAIL when its security profile is Standard or uefiSettings.secureBootEnabled is false.",
      "not_applicable_when": "The native OS type is Linux. Missing or contradictory OS facts and unrecognized security capabilities remain UNKNOWN.",
      "pass_when": "PASS when a supported security profile enables UEFI secure boot."
    },
    "historical_contract_sha256": "303e9f316bbc5deb022a870a5bea4e056a65ff73a36cf36c07754c08ab1f50e7"
  },
  "azure.claude.vmss_not_empty": {
    "current": {
      "description": "Checks whether the scale set declares nonzero capacity in sku.capacity. This does not count running or healthy VM instances.",
      "evaluated": [
        "sku.capacity"
      ],
      "fail_when": "FAIL when sku.capacity is zero.",
      "not_applicable_when": null,
      "pass_when": "PASS when capacity is positive."
    },
    "historical_contract_sha256": "65f46a008a8a525771434205e97db3f69a0701ce9d630f39a2185665b2703d30"
  },
  "azure.claude2.app_gateway_min_tls_12": {
    "current": {
      "description": "Resolves the explicit TLS minimum or recognized predefined policy. If no explicit policy exists, uses the returned default policy name; missing or unknown defaults remain unresolved.",
      "evaluated": [
        "properties.sslPolicy.minProtocolVersion",
        "properties.sslPolicy.policyName",
        "properties.sslPolicy.policyType"
      ],
      "fail_when": "The explicit or native reported default policy permits TLS1.0 or TLS1.1.",
      "not_applicable_when": null,
      "pass_when": "The explicit or native reported default policy requires TLS1.2 or newer."
    },
    "historical_contract_sha256": "92da953c0b76bae0fa225cce08fac9b81f031ad7aad2dd329d02a8efc3c00eaf"
  },
  "azure.claude2.app_gateway_waf_enabled": {
    "current": {
      "description": "Checks enabled inline WAF configuration or resolves the gateway’s attached WAF policy and its enabled state. A policy reference alone is insufficient; missing or ambiguous policy evidence remains unresolved.",
      "evaluated": [
        "properties.firewallPolicy.id",
        "properties.webApplicationFirewallConfiguration.enabled"
      ],
      "fail_when": "Complete native configuration has no WAF declaration or the resolved protection is disabled.",
      "not_applicable_when": null,
      "pass_when": "Inline WAF is enabled or the exact attached policy resolves to an enabled native policy."
    },
    "historical_contract_sha256": "2c753d7b9236277d940fb8218ea86aa7e78b99ef0541a38c5084a75ef68ddbc1"
  },
  "azure.claude2.nsg_flow_log_configured": {
    "current": {
      "description": "For an attached NSG, checks for an enabled matching NSG flow log or an enabled VNet flow log covering its NIC, subnet or VNet. A reference alone cannot satisfy this check.",
      "evaluated": [
        "id",
        "properties.subnets",
        "properties.networkInterfaces",
        "properties.flowLogs",
        "flow_log[].properties.targetResourceId",
        "flow_log[].properties.enabled"
      ],
      "fail_when": "Complete native inventories contain no enabled matching NSG or covering VNet flow log.",
      "not_applicable_when": "NOT_APPLICABLE when the NSG has no subnet or NIC attachment.",
      "pass_when": "An enabled native NSG flow log targets the NSG, or an enabled VNet flow log covers a related NIC, subnet or VNet."
    },
    "historical_contract_sha256": "3841af8ffcea7202dff01c806a6352ca094b9089cf55da89447b488c9f0da6f6"
  },
  "azure.claude2.nsg_flow_logs_to_log_analytics": {
    "current": {
      "description": "Checks for enabled NSG or VNet flow logging with Traffic Analytics enabled and a workspace reference. Each target must resolve in the selected subscription’s network inventory.",
      "evaluated": [
        "scope",
        "flow_log[].properties.targetResourceId",
        "flow_log[].properties.flowAnalyticsConfiguration.networkWatcherFlowAnalyticsConfiguration.enabled",
        "flow_log[].properties.flowAnalyticsConfiguration.networkWatcherFlowAnalyticsConfiguration.workspaceId"
      ],
      "fail_when": "Complete applicable network and flow inventories contain no such enabled configuration.",
      "not_applicable_when": "NOT_APPLICABLE when the subscription inventory has neither NSGs nor VNets.",
      "pass_when": "An enabled matching flow log has enabled Traffic Analytics and a workspace reference."
    },
    "historical_contract_sha256": "22d49588da01e4304c4be7292f2d1035078c9bfc0dca575df5f3ebc22cb87fab"
  },
  "azure.claude2.vnet_flow_logs_to_log_analytics": {
    "current": {
      "description": "Checks for enabled VNet flow logging with Traffic Analytics enabled and a workspace reference. Each target must resolve in the selected subscription’s network inventory.",
      "evaluated": [
        "scope",
        "flow_log[].properties.targetResourceId",
        "flow_log[].properties.flowAnalyticsConfiguration.networkWatcherFlowAnalyticsConfiguration.enabled",
        "flow_log[].properties.flowAnalyticsConfiguration.networkWatcherFlowAnalyticsConfiguration.workspaceId"
      ],
      "fail_when": "Complete applicable network and flow inventories contain no such enabled configuration.",
      "not_applicable_when": "NOT_APPLICABLE when the subscription has no VNet.",
      "pass_when": "An enabled matching VNet flow log has enabled Traffic Analytics and a workspace reference."
    },
    "historical_contract_sha256": "7c20a2930f8aac81969adb5ae3977550d91a4b6015ee8b0b6fbe03915ee9d973"
  },
  "azure.encryption.automation_cmk_declared": {
    "current": {
      "description": "Inspect a complete native Automation key-reference and attached system-identity declaration. Key existence, authorization, connectivity and cryptographic use are separate assessments.",
      "evaluated": [
        "properties.state",
        "properties.encryption.keySource and keyVaultProperties",
        "identity.type, principalId and tenantId"
      ],
      "fail_when": "The account declares a platform-managed key, explicitly incomplete key reference or no attached identity.",
      "not_applicable_when": null,
      "pass_when": "A complete customer-managed key reference and attached system-assigned identity are declared."
    },
    "historical_contract_sha256": "95511474b9388481f084b8d1c86aa9add4a020d6713abf9761f105931e122862"
  },
  "azure.encryption.log_analytics_cluster_cmk_declared": {
    "current": {
      "description": "Checks the native cluster CMK reference and assigned managed identity. It does not verify key access, availability or encryption of stored data.",
      "evaluated": [
        "Native log_analytics_cluster configuration",
        "Source-bound declared dependencies: log_analytics_cluster"
      ],
      "fail_when": "The complete native configuration explicitly lacks the required declaration.",
      "not_applicable_when": null,
      "pass_when": "The complete native configuration satisfies the specific declared setting described above."
    },
    "historical_contract_sha256": null
  },
  "azure.encryption.stream_analytics_job_storage_cmk_declared": {
    "current": {
      "description": "For jobs selecting external job storage, resolves the account within the selected subscription and checks its CMK declaration and assigned encryption identity. Built-in storage and effective key use are outside this check.",
      "evaluated": [
        "Native stream_analytics_job configuration",
        "Source-bound declared dependencies: stream_analytics_job, storage_account"
      ],
      "fail_when": "The complete native configuration explicitly lacks the required declaration.",
      "not_applicable_when": null,
      "pass_when": "The complete native configuration satisfies the specific declared setting described above."
    },
    "historical_contract_sha256": null
  },
  "azure.logging.aci_log_analytics_declared": {
    "current": {
      "description": "Inspect a complete native container-group Log Analytics workspace customer UUID and supported log type declaration. Workspace existence, access and log ingestion or delivery are separate assessments.",
      "evaluated": [
        "properties.provisioningState",
        "properties.diagnostics.logAnalytics.workspaceId",
        "properties.diagnostics.logAnalytics.logType"
      ],
      "fail_when": "The complete configuration has no Log Analytics declaration or explicitly returns an empty workspace UUID.",
      "not_applicable_when": null,
      "pass_when": "A valid workspace customer UUID and supported log type are declared."
    },
    "historical_contract_sha256": "0ccab2919dc0024c893f5d95398a67c15123151847f87bd0b2001cf7078f325c"
  },
  "azure.logging.aks_supported_log_categories_destination_declared": {
    "current": {
      "description": "Inspect actual supported log categories and enabled native diagnostic destination declarations. Resource existence, authorization, ingestion and retention are separate assessments.",
      "evaluated": [
        "Native aks_cluster configuration",
        "Source-bound declared dependencies: aks_cluster, aks_diagnostic_declaration"
      ],
      "fail_when": "The complete native configuration explicitly lacks the required declaration.",
      "not_applicable_when": null,
      "pass_when": "The complete native configuration satisfies the specific declared setting described above."
    },
    "historical_contract_sha256": null
  },
  "azure.logging.managed_hsm_audit_destination_declared": {
    "current": {
      "description": "Inspect enabled AuditEvent diagnostic settings with valid native Storage or Log Analytics resource references. Enabled category groups are resolved through complete bound native HSM category metadata; unresolved optional category reads do not affect an explicit AuditEvent declaration.",
      "evaluated": [
        "Native managed_hsm configuration",
        "Source-bound declared dependencies: managed_hsm, hsm_audit_destination_declaration"
      ],
      "fail_when": "The complete native configuration explicitly lacks the required declaration.",
      "not_applicable_when": null,
      "pass_when": "The complete native configuration satisfies the specific declared setting described above."
    },
    "historical_contract_sha256": null
  },
  "azure.network.acr_public_ip_ranges_restricted": {
    "current": {
      "description": "Checks declared registry public IPv4 filtering. Enabled public access with default Allow or a rule union covering every IPv4 address fails; trusted Azure service bypass is reported separately.",
      "evaluated": [
        "selected registry identity and exact full GET source",
        "properties.publicNetworkAccess",
        "properties.networkRuleSet.defaultAction and ipRules",
        "properties.networkRuleBypassOptions"
      ],
      "fail_when": "Enabled public access uses default Allow or IP rules whose union covers every IPv4 address.",
      "not_applicable_when": null,
      "pass_when": "Public access is disabled, or default Deny IP rules do not cover every IPv4 address."
    },
    "historical_contract_sha256": null
  },
  "azure.review.acr.selected_image_secret_indicators": {
    "current": {
      "description": "Inspect only explicitly selected immutable ACR images with both offline detectors after binding native registry identity, repository pull authorization and content digests. Only selected image content is assessed, with detected values hidden and repeated leaks merged.",
      "evaluated": [
        "selected native content",
        "exact scope and resource identity",
        "bounded read and both offline secret detectors"
      ],
      "fail_when": "A likely secret was detected in a selected immutable ACR image. The value is hidden; offline detection did not validate the credential.",
      "not_applicable_when": "No clean result is inferred from disabled, missing or unsupported content.",
      "pass_when": "Both offline detectors completed without detecting a supported secret in the selected immutable ACR image."
    },
    "historical_contract_sha256": null
  },
  "azure.review.ai_services.audit_logging": {
    "current": {
      "description": "AI Services configures supported audit logs to a destination. Evaluate only complete native ARM configuration for the selected subscription and account.",
      "evaluated": [
        "selected subscription/account identity",
        "complete native ARM configuration and required child inventories"
      ],
      "fail_when": "No diagnostic setting enables supported Audit logs with a destination.",
      "not_applicable_when": "Only explicitly established resource or deployment applicability exclusions apply.",
      "pass_when": "A diagnostic setting enables supported Audit logs with a destination. Delivery and retention were not tested."
    },
    "historical_contract_sha256": null
  },
  "azure.review.ai_services.managed_identity": {
    "current": {
      "description": "AI Services declares a managed identity. Evaluate only complete native ARM configuration for the selected subscription and account.",
      "evaluated": [
        "selected subscription/account identity",
        "complete native ARM configuration and required child inventories"
      ],
      "fail_when": "The account has no managed identity declaration.",
      "not_applicable_when": "Only explicitly established resource or deployment applicability exclusions apply.",
      "pass_when": "The account declares a supported managed identity type. Role assignments were not assessed."
    },
    "historical_contract_sha256": null
  },
  "azure.review.ai_services.outbound_restriction": {
    "current": {
      "description": "AI Services declares restricted outbound network access. Evaluate only complete native ARM configuration for the selected subscription and account.",
      "evaluated": [
        "selected subscription/account identity",
        "complete native ARM configuration and required child inventories"
      ],
      "fail_when": "The account declares outbound restrictions disabled.",
      "not_applicable_when": "Only explicitly established resource or deployment applicability exclusions apply.",
      "pass_when": "The account declares outbound restrictions enabled. Destinations and traffic were not tested."
    },
    "historical_contract_sha256": null
  },
  "azure.review.ai_services.prompt_shield": {
    "current": {
      "description": "Text deployments explicitly configure blocking Prompt Shields. Evaluate only complete native ARM configuration for the selected subscription and account.",
      "evaluated": [
        "selected subscription/account identity",
        "complete native ARM configuration and required child inventories"
      ],
      "fail_when": "A supported text deployment explicitly references a policy without enabled blocking Jailbreak filtering on prompts.",
      "not_applicable_when": "Only explicitly established resource or deployment applicability exclusions apply.",
      "pass_when": "Supported text deployments explicitly reference policies with enabled blocking Jailbreak filtering on prompts. Traffic was not tested."
    },
    "historical_contract_sha256": null
  },
  "azure.review.app_configuration.selected_value_secret_indicators": {
    "current": {
      "description": "Scans the selected App Configuration key and label after confirming the store identity and stable ETag. Key Vault references are not followed.",
      "evaluated": [
        "Exact selected native declaration identity and supported public literals",
        "Both pinned offline detectors and bounded source coverage"
      ],
      "fail_when": "A likely secret was detected in the selected public literals. The value is hidden and was not validated.",
      "not_applicable_when": "No selected supported public literal was returned; protected and referenced content is not assessed.",
      "pass_when": "Both offline detectors completed without detecting a supported secret in the selected public literals. Coverage is limited to these declarations."
    },
    "historical_contract_sha256": null
  },
  "azure.review.app_service.selected_app_settings_secret_indicators": {
    "current": {
      "description": "Inspect literal application settings only for explicitly selected App Service/Azure Function sites or deployment slots using both offline detectors. Only observed selected literals are assessed, with detected values hidden and repeated leaks merged.",
      "evaluated": [
        "selected native content",
        "exact scope and resource identity",
        "bounded read and both offline secret detectors"
      ],
      "fail_when": "A likely secret was detected in selected literal app settings. The value is hidden; offline detection did not validate the credential.",
      "not_applicable_when": "No clean result is inferred from disabled, missing or unsupported content.",
      "pass_when": "Both offline detectors completed without detecting a supported secret in selected literal app settings."
    },
    "historical_contract_sha256": null
  },
  "azure.review.application_insights.selected_trace_sample_secret_indicators": {
    "current": {
      "description": "Scans up to 100 trace messages from the selected Application Insights component from the preceding hour with both offline detectors. Other telemetry, older messages and credential validity are not assessed.",
      "evaluated": [
        "Native tenant, subscription and workspace/component identity",
        "Fixed table/time window and both pinned offline detectors"
      ],
      "fail_when": "A likely secret was detected in the selected message sample. Its value is hidden and was not validated.",
      "not_applicable_when": "No supported selected message sample was collected; unscanned messages remain unresolved.",
      "pass_when": "Both offline detectors completed without detecting a supported secret in the selected message sample. This result covers only the returned sample from the fixed preceding hour."
    },
    "historical_contract_sha256": null
  },
  "azure.review.configuration.selected_content_secret_indicators": {
    "current": {
      "description": "Inspect explicitly selected Azure ARM configuration and source literals with two offline secret detectors. Matched values are hidden; no credential is validated and coverage does not extend to referenced or encrypted stores.",
      "evaluated": [
        "Explicit selected native source identity and literal content",
        "Both pinned offline detectors; detected values hidden"
      ],
      "fail_when": "A likely secret was detected in selected Azure configuration literals. Its value is hidden and was not validated.",
      "not_applicable_when": "No selected supported literal content was returned; referenced or hidden content is not assessed.",
      "pass_when": "Both offline detectors completed without detecting a supported secret in the selected Azure configuration literals."
    },
    "historical_contract_sha256": null
  },
  "azure.review.data_factory.selected_declaration_secret_indicators": {
    "current": {
      "description": "Scans public literals in the selected Data Factory pipeline or dataflow definition. Linked services, protected values and referenced code are excluded.",
      "evaluated": [
        "Exact selected native declaration identity and supported public literals",
        "Both pinned offline detectors and bounded source coverage"
      ],
      "fail_when": "A likely secret was detected in the selected public literals. The value is hidden and was not validated.",
      "not_applicable_when": "No selected supported public literal was returned; protected and referenced content is not assessed.",
      "pass_when": "Both offline detectors completed without detecting a supported secret in the selected public literals. Coverage is limited to these declarations."
    },
    "historical_contract_sha256": null
  },
  "azure.review.databricks.selected_notebook_source_secret_indicators": {
    "current": {
      "description": "Scans SOURCE bytes exported from the selected Databricks notebook with both offline detectors after binding its workspace and native object. Notebook execution, outputs and immutable cell revisions are not verified.",
      "evaluated": [
        "Native subscription tenant, assigned workspace principal and exact selected notebook object",
        "Captured SOURCE bytes with both pinned offline detectors"
      ],
      "fail_when": "A supported credential-like literal is detected in the selected captured notebook source.",
      "not_applicable_when": "No coherent selected notebook source was readable; absent sample coverage remains UNKNOWN.",
      "pass_when": "Both detectors complete without finding a supported secret in the selected captured notebook source."
    },
    "historical_contract_sha256": null
  },
  "azure.review.devops.selected_content_secret_indicators": {
    "current": {
      "description": "Inspect only selected Azure DevOps Git files at immutable commits and selected pipeline definition literals using both pinned offline detectors.",
      "evaluated": [
        "Explicit selected native source identity and literal content",
        "Both pinned offline detectors; detected values hidden"
      ],
      "fail_when": "A likely secret was detected in selected Azure DevOps literals. The value is hidden and was not validated.",
      "not_applicable_when": "No selected supported literal content was returned; referenced or hidden content is not assessed.",
      "pass_when": "Both offline detectors completed without detecting a supported secret in the selected Azure DevOps literals. Coverage is limited to the selected file commit and pipeline definition revision."
    },
    "historical_contract_sha256": null
  },
  "azure.review.devops.visible_clone_urls_without_userinfo": {
    "current": {
      "description": "Reviews clone URL metadata returned by the read-only API for explicitly selected projects. Hidden repositories and other projects are outside this result.",
      "evaluated": [
        "API-visible selected project repository clone URL metadata",
        "Native per-project paging and credential context"
      ],
      "fail_when": "Userinfo is observed in at least one visible selected clone URL; values are redacted.",
      "not_applicable_when": "No visible selected repository URL metadata was returned; this does not prove hidden repositories absent.",
      "pass_when": "Complete visible clone URL metadata for selected projects contains no userinfo. Hidden repositories remain unassessed."
    },
    "historical_contract_sha256": null
  },
  "azure.review.function.application_insights_setting_declared": {
    "current": {
      "description": "Checks the declared presence of at least one literal Application Insights connection setting on explicitly selected Functions. Telemetry delivery and destination validity are not tested.",
      "evaluated": [
        "Native subscription tenant and selected Function identity",
        "Supported declared hosting model and literal setting value"
      ],
      "fail_when": "Neither supported Application Insights setting is nonempty.",
      "not_applicable_when": "The native site is not a Function app.",
      "pass_when": "A literal Application Insights connection string or instrumentation key is nonempty."
    },
    "historical_contract_sha256": null
  },
  "azure.review.function.runtime_major4_update_channel_declared": {
    "current": {
      "description": "Checks the classic Function FUNCTIONS_EXTENSION_VERSION declaration for the automatic major4 update channel. Flex Consumption and custom container host versions use separate mechanisms; the resolved build is not tested.",
      "evaluated": [
        "Native subscription tenant and selected Function identity",
        "Supported declared hosting model and literal setting value"
      ],
      "fail_when": "The supported classic Function has no automatic major4 channel, uses a retired major or pins a specific build.",
      "not_applicable_when": "The native site is not a Function, or Flex/custom-container hosting uses another host-version mechanism.",
      "pass_when": "The supported classic Function declares ~4."
    },
    "historical_contract_sha256": null
  },
  "azure.review.log_analytics.query_storage_cmk_declared": {
    "current": {
      "description": "Joins the workspace Query-linked stores to native Storage accounts and checks for a valid declared customer-managed key and account-scoped Table encryption. Key authorization, usability and effective cryptography are not tested.",
      "evaluated": [
        "Complete Query link inventory and exact owned Storage account joins",
        "Account keySource, valid customer-managed key reference and Table keyType"
      ],
      "fail_when": "A coherent Query-linked store declares a provider-managed account key or Service-scoped Table key.",
      "not_applicable_when": "The complete native workspace link list has no Query link.",
      "pass_when": "Every existing Query-linked store declares Microsoft.Keyvault, a valid key reference and Table keyType Account."
    },
    "historical_contract_sha256": null
  },
  "azure.review.log_analytics.selected_message_sample_secret_indicators": {
    "current": {
      "description": "Scans up to 100 selected AppTraces or FunctionAppLogs messages from the preceding hour with both offline detectors. Other tables, older messages and credential validity are not assessed.",
      "evaluated": [
        "Native tenant, subscription and workspace/component identity",
        "Fixed table/time window and both pinned offline detectors"
      ],
      "fail_when": "A likely secret was detected in the selected message sample. Its value is hidden and was not validated.",
      "not_applicable_when": "No supported selected message sample was collected; unscanned messages remain unresolved.",
      "pass_when": "Both offline detectors completed without detecting a supported secret in the selected message sample. This result covers only the returned sample from the fixed preceding hour."
    },
    "historical_contract_sha256": null
  },
  "azure.review.machine_learning.selected_code_file_secret_indicators": {
    "current": {
      "description": "Scans the exact selected plain file after joining its native ML code asset, datastore and storage account. Folder contents, executed code and original asset-creation bytes are not established.",
      "evaluated": [
        "Exact selected asset and native subscription/workspace identity",
        "Captured text with both pinned offline detectors"
      ],
      "fail_when": "A supported credential-like literal is detected in the selected captured text.",
      "not_applicable_when": "No applicable asset was selected; unreadable, unsupported or incomplete selected content stays UNKNOWN.",
      "pass_when": "Both detectors complete without a supported secret in the selected captured text."
    },
    "historical_contract_sha256": null
  },
  "azure.review.machine_learning.selected_command_job_secret_indicators": {
    "current": {
      "description": "Scans returned command text and literal environment variables from the selected Machine Learning Command job with both offline detectors. Referenced code, images and actual execution are not inspected.",
      "evaluated": [
        "Native subscription tenant, workspace identity and exact selected Command job",
        "Returned command and explicit environment literals with both pinned offline detectors"
      ],
      "fail_when": "A supported credential-like literal is detected in the selected returned command or environment values.",
      "not_applicable_when": "No supported selected Command declaration was readable; absence of inspected content remains UNKNOWN.",
      "pass_when": "Both detectors complete without finding a supported secret in the selected returned literals."
    },
    "historical_contract_sha256": null
  },
  "azure.review.machine_learning.selected_environment_conda_secret_indicators": {
    "current": {
      "description": "Scans returned inline Conda text from the exact selected ML environment version with both offline detectors. Package references, builds and images are not inspected.",
      "evaluated": [
        "Exact selected asset and native subscription/workspace identity",
        "Captured text with both pinned offline detectors"
      ],
      "fail_when": "A supported credential-like literal is detected in the selected captured text.",
      "not_applicable_when": "No applicable asset was selected; unreadable, unsupported or incomplete selected content stays UNKNOWN.",
      "pass_when": "Both detectors complete without a supported secret in the selected captured text."
    },
    "historical_contract_sha256": null
  },
  "azure.review.managed_hsm.audit_storage_destination": {
    "current": {
      "description": "Checks native diagnostic settings for enabled Managed HSM AuditEvent logging to an Azure Storage destination. This is configuration evidence; delivery and retention are separate.",
      "evaluated": [
        "native Managed HSM and diagnostic setting identities",
        "complete diagnosticSettings inventory",
        "logs[].enabled and category=AuditEvent",
        "properties.storageAccountId"
      ],
      "fail_when": "Complete native settings contain no enabled AuditEvent/storage destination declaration.",
      "not_applicable_when": null,
      "pass_when": "An enabled AuditEvent log category declares an Azure Storage destination."
    },
    "historical_contract_sha256": null
  },
  "azure.review.network.perimeter_association_enforced": {
    "current": {
      "description": "Joins a complete native Storage perimeter association to its exact profile and protected Storage account, then checks its declared Enforced mode and provisioning. Access rules and effective reachability are not tested.",
      "evaluated": [
        "Same-subscription Storage association, profile and native provisioning",
        "Declared accessMode"
      ],
      "fail_when": "The coherent provisioned Storage association declares Learning or Audit.",
      "not_applicable_when": "No supported Storage association was inventoried; unbound or unsupported evidence stays UNKNOWN.",
      "pass_when": "The supported native association is provisioned, has no reported provisioning issues and declares Enforced."
    },
    "historical_contract_sha256": null
  },
  "azure.review.storage.blocking_sas_expiry_policy_declared": {
    "current": {
      "description": "Reads sasPolicy from the full storage-account GET and checks for Block with a supported positive validity interval. It does not inspect issued tokens or prove enforcement for exempt SAS types.",
      "evaluated": [
        "Native storage-account identity, complete full GET and policy field coverage",
        "SAS expiration action and supported positive DD.HH:MM:SS interval"
      ],
      "fail_when": "The full GET shows no SAS policy or the Log action, including its documented default.",
      "not_applicable_when": "No applicable storage account was collected; missing or malformed native evidence remains unresolved.",
      "pass_when": "The full GET declares Block and a supported positive validity interval."
    },
    "historical_contract_sha256": null
  },
  "azure.review.storage.selected_source_secret_indicators": {
    "current": {
      "description": "Inspect explicitly selected Azure Blob/File source objects, using coherent current reads or an optional native version/snapshot and both offline detectors.",
      "evaluated": [
        "Explicit selected native source identity and literal content",
        "Both pinned offline detectors; detected values hidden"
      ],
      "fail_when": "A likely secret was detected in the selected stored source. Its value is hidden; offline detection did not validate it.",
      "not_applicable_when": "No selected supported literal content was returned; referenced or hidden content is not assessed.",
      "pass_when": "Both offline detectors completed without detecting a supported secret in the selected stored source object. Coverage is limited to the captured supported text files."
    },
    "historical_contract_sha256": null
  },
  "azure.review.synapse.selected_pipeline_secret_indicators": {
    "current": {
      "description": "Scans public literals in the selected Synapse pipeline after binding its workspace and tenant. Protected values and referenced code are excluded.",
      "evaluated": [
        "Exact selected native declaration identity and supported public literals",
        "Both pinned offline detectors and bounded source coverage"
      ],
      "fail_when": "A likely secret was detected in the selected public literals. The value is hidden and was not validated.",
      "not_applicable_when": "No selected supported public literal was returned; protected and referenced content is not assessed.",
      "pass_when": "Both offline detectors completed without detecting a supported secret in the selected public literals. Coverage is limited to these declarations."
    },
    "historical_contract_sha256": null
  },
  "azure_application_gateway_11_5_1_1_1_f56bdc2": {
    "current": {
      "description": "Checks declared DDoS protection for public IPs and applicable Prevention-mode WAF configuration. Native associations include gateway listener/path overrides and Front Door policy bindings; unresolved routes remain unknown.",
      "evaluated": [
        "Paged Application Gateway, Front Door, Load Balancer and Public IP inventories; Public IP GET ddosSettings.protectionMode and plan; protected VNet association where inherited; effective App Gateway/Front Door WAF policy linkage, state and mode. Resolve WAF policy state defaults from the documented schema.",
        "Complete inventories: application_gateway, load_balancer, public_ip, frontdoor, frontdoor_profile, public_edge_binding"
      ],
      "fail_when": "Complete evidence conclusively violates the signed predicate: For every scoped public App Gateway, Front Door, Load Balancer and Public IP, verify applicable DDoS protection by exact public IP/plan or supported inherited VNet protection; for App Gateway and Front Door also verify an effective WAF policy in Prevention mode, treating omitted policy/custom-rule state as Enabled only where the API documents that default. PASS only when all applicable protections are measured; FAIL on a proven missing protection; UNKNOWN for unsupported product-level DDoS mapping, public frontend, inherited VNet, plan, WAF policy/default or incomplete inventory. No public resources is NOT_APPLICABLE.",
      "not_applicable_when": null,
      "pass_when": "Complete evidence satisfies the signed predicate: For every scoped public App Gateway, Front Door, Load Balancer and Public IP, verify applicable DDoS protection by exact public IP/plan or supported inherited VNet protection; for App Gateway and Front Door also verify an effective WAF policy in Prevention mode, treating omitted policy/custom-rule state as Enabled only where the API documents that default. PASS only when all applicable protections are measured; FAIL on a proven missing protection; UNKNOWN for unsupported product-level DDoS mapping, public frontend, inherited VNet, plan, WAF policy/default or incomplete inventory. No public resources is NOT_APPLICABLE."
    },
    "historical_contract_sha256": "ebb7c93fe3a2c8979898f34a8d218c731bb69cd18ecb437b052ddbed32db3a97"
  },
  "azure_application_gateway_app_http_logs_enabled_2de0361": {
    "current": {
      "description": "Checks whether Application Gateway declares enabled HTTP access-log export to an inventoried workspace or storage account. Layer4 Load Balancer health logs are a separate criterion.",
      "evaluated": [
        "Collector peaso/collectors/azure.py: application_gateway and load_balancer are collected; diagnostic_setting GET {resourceId}/providers/Microsoft.Insights/diagnosticSettings?api-version=2021-05-01-preview is collected per resource. New GET diagnosticSettingsCategories at the same resource to determine supported category names; page settings and categories, require approved destination IDs and logs[].enabled=true.",
        "Complete inventories: application_gateway, load_balancer, diagnostic_setting, diagnostic_category, log_analytics_workspace, storage_account"
      ],
      "fail_when": "At least one applicable gateway lacks that configured access-log export.",
      "not_applicable_when": "Complete selected inventories contain no Application Gateway.",
      "pass_when": "Applicable gateways declare enabled ApplicationGatewayAccessLog export to an inventoried destination."
    },
    "historical_contract_sha256": "26ce366edb994f8eae29955a4d21d47233ece0a56c06f7279d9b7f7bb6143f67"
  }
}
''')


NATIVE_WITNESS_SUCCESSORS = json.loads(r'''
{
  "azure.claude.databricks_subnet_nsg|0": {
    "evidence_sha256": "495db5ca480055b59810d6acc138f693c6ff590fd2c6bd16bc51bae56c1419f5",
    "historical_case_sha256": "53181c918424eb435eab63ac7de71795d29303ea37ce556c8265c4f14c3ade7b",
    "historical_status": "FAIL",
    "native_case": "fail",
    "status": "FAIL"
  },
  "azure.claude.databricks_subnet_nsg|2": {
    "evidence_sha256": "9f21fa27d119ea8ae982d448a38fcb91259420ed5710ecb37ae390aa8cc63d83",
    "historical_case_sha256": "49e5c3b620171f7cbdcf49de93b346502347ab105dae55200352c162d1767b21",
    "historical_status": "PASS",
    "native_case": "pass",
    "status": "PASS"
  },
  "azure.claude.entra_ca_mfa_admin_portals|0": {
    "evidence_sha256": "37b6d3e2f85ed699bb7ef69d4baa64d304be2f1583c4abce297423ebd57bc3b0",
    "historical_case_sha256": "4d3534c49a1dafe4806ef729078f8b13d3662f6826bb6bd7d2f35a5fa0b9cfb7",
    "historical_status": "FAIL",
    "native_case": "fail",
    "status": "FAIL"
  },
  "azure.claude.entra_ca_mfa_admin_portals|2": {
    "evidence_sha256": "7b8d65a77cc7db9f851f01e1fce1892ecdf53820feda71c7cb84ad8dfa073bc9",
    "historical_case_sha256": "7a0e0776ec1781bf452f046bb59bded2b141523da8d77405cc903bc1f6740716",
    "historical_status": "PASS",
    "native_case": "pass",
    "status": "PASS"
  },
  "azure.claude.entra_ca_mfa_management_api|0": {
    "evidence_sha256": "37b6d3e2f85ed699bb7ef69d4baa64d304be2f1583c4abce297423ebd57bc3b0",
    "historical_case_sha256": "b3ce706c010d7190e349fa84d7eab2addc1f269eed0b8f570c2199a5f2c92a1f",
    "historical_status": "FAIL",
    "native_case": "fail",
    "status": "FAIL"
  },
  "azure.claude.entra_ca_mfa_management_api|1": {
    "evidence_sha256": "7b8d65a77cc7db9f851f01e1fce1892ecdf53820feda71c7cb84ad8dfa073bc9",
    "historical_case_sha256": "3332b81dd5243b1c2881afa564c4fb5ca4199e88d390134a866e58cc39c635ba",
    "historical_status": "PASS",
    "native_case": "pass",
    "status": "PASS"
  },
  "azure.claude.entra_non_privileged_user_mfa|0": {
    "evidence_sha256": "f44defdf9bf614a9dcfeaf81682fe0f09047fae27349c8fb75ca3dce6b5a32e9",
    "historical_case_sha256": "2dba59b1b024ed8b46e071ed8260c54502b4e058850f66b9efea3b26e14ced31",
    "historical_status": "FAIL",
    "native_case": "fail",
    "status": "FAIL"
  },
  "azure.claude.entra_non_privileged_user_mfa|2": {
    "evidence_sha256": "7419010df6cf8e9343f546384f1665db9adc20ee913338dbe0cb540f599530af",
    "historical_case_sha256": "015adb949b67e945e8944a022bd1b61a70157ba3cbc5dac5d39df8454f498e47",
    "historical_status": "PASS",
    "native_case": "pass",
    "status": "PASS"
  },
  "azure.claude.entra_privileged_user_mfa|0": {
    "evidence_sha256": "f44defdf9bf614a9dcfeaf81682fe0f09047fae27349c8fb75ca3dce6b5a32e9",
    "historical_case_sha256": "1551a1c00b8aa1c7931c7bdd4dc286565a73796d312981846e0a7a54e4ab1001",
    "historical_status": "FAIL",
    "native_case": "fail",
    "status": "FAIL"
  },
  "azure.claude.entra_privileged_user_mfa|2": {
    "evidence_sha256": "7419010df6cf8e9343f546384f1665db9adc20ee913338dbe0cb540f599530af",
    "historical_case_sha256": "145e2cdaec03084d3c43e7a00b8553a6ed981024ba3c5c861118e610958a3359",
    "historical_status": "PASS",
    "native_case": "pass",
    "status": "PASS"
  },
  "azure.claude.entra_vm_access_user_mfa|0": {
    "evidence_sha256": "1003ce38e0c2492bf01a1e2667e6e899c6c5d6e836f3f2382152bcb04511fec5",
    "historical_case_sha256": "46289a00068beb95b1775dda14af6a1365a738152eb8ee09f1886df5ada205b5",
    "historical_status": "FAIL",
    "native_case": "fail",
    "status": "FAIL"
  },
  "azure.claude.entra_vm_access_user_mfa|2": {
    "evidence_sha256": "a38e53bbfa1298b0d405185f34254dfd63cd18e1dae97380f5d23d031b77cff1",
    "historical_case_sha256": "bc5744caeca2bc21d531aca4cb826898843c6520f1674d3c70df062f03c02150",
    "historical_status": "PASS",
    "native_case": "pass",
    "status": "PASS"
  },
  "azure.claude.iam_custom_role_administers_locks|0": {
    "evidence_sha256": "a340647c736d9421a3657507d61233739829b3e18cc68436230f4ef1c2c90dae",
    "historical_case_sha256": "14e5ddc1a3631b74a54c39d0bcf04da5185a06ac11e7b1039b989520abbd3a8a",
    "historical_status": "FAIL",
    "native_case": "lock-successor/permissions-fd8b3f00a4",
    "status": "FAIL"
  },
  "azure.claude.iam_custom_role_administers_locks|1": {
    "evidence_sha256": "c0b89a908859b5e8ce5b5cdb0c30414642dc73f604513d1bb3b09a8fb986bd55",
    "historical_case_sha256": "6baa258df027b2e4d206e57a08515c3d645a86284e30f2bc554464b9d1b740bf",
    "historical_status": "PASS",
    "native_case": "lock-successor/permissions-c2efb060b4",
    "status": "PASS"
  },
  "azure.claude.managed_hsm_audit_logging|1": {
    "evidence_sha256": "f7d8bb93127f7380d7517a0bfea365581a5b0ada6a02ba80aedb103c0ca38615",
    "historical_case_sha256": "504ef8bb2fd7f670e3682e9afda4ffcaefe02a974cc58cedd89aa2b9cbdf2a9a",
    "historical_status": "PASS",
    "native_case": "positive",
    "status": "UNKNOWN"
  },
  "azure.claude.recovery_vault_backup_retention_30_days|1": {
    "evidence_sha256": "283f96f968464432f9eaecbde21b8fafc562a659c27c4993d2bf3c954bb567a0",
    "historical_case_sha256": "eeaf27d6daa4b99fdcf1cc052d950103e39fa39aafb9ae56d3d57eb09301ecf4",
    "historical_status": "FAIL",
    "native_case": "negative",
    "status": "FAIL"
  },
  "azure.claude.recovery_vault_backup_retention_30_days|3": {
    "evidence_sha256": "c3b4adbd419e3790dba207808e08b5d8cdf413ab6e1c81b9ec7cd9a707016d17",
    "historical_case_sha256": "262eea74b1e9036cc278dfe28564e2d547b3f09536eda5edfe89b51092066274",
    "historical_status": "PASS",
    "native_case": "positive",
    "status": "PASS"
  },
  "azure.claude.servicefabric_cluster_encrypt_and_sign|0": {
    "evidence_sha256": "1c03520cadc57e4093d2c13107e75109f503d51ecba552cc78c63d1eeaeefc2d",
    "historical_case_sha256": "c00faf0062d7b810cf4c9fdac42aefffad564fafa7b6b37aba1da7eebf8bd52a",
    "historical_status": "FAIL",
    "native_case": "services2/tests/test_azure_remaining_services_2_native_review_20261020.py::test_native_contract[opposite-azure.claude.servicefabric_cluster_encrypt_and_sign]",
    "status": "FAIL"
  },
  "azure.claude.servicefabric_cluster_encrypt_and_sign|1": {
    "evidence_sha256": "c67265a45559091b81bae47585383bf74bad61e03993eda80b352100703efae6",
    "historical_case_sha256": "2b6dd86d74adfc9a1938e9a87ed170c012ab0619635e40742fbc2ec9a41e88ce",
    "historical_status": "PASS",
    "native_case": "services2/tests/test_azure_remaining_services_2_native_review_20261020.py::test_native_contract[positive-azure.claude.servicefabric_cluster_encrypt_and_sign]",
    "status": "PASS"
  },
  "azure.claude.servicefabric_cluster_entra_auth|1": {
    "evidence_sha256": "db7d01651d4bd373aa16568fa4d27d29730519b1e382fd547dee221cc7d8f2da",
    "historical_case_sha256": "34b022d63eba8568024220b68f04ba8d11522c46c922b90d9f6482740619b46a",
    "historical_status": "PASS",
    "native_case": "services2/tests/test_azure_remaining_services_2_native_review_20261020.py::test_native_contract[positive-azure.claude.servicefabric_cluster_entra_auth]",
    "status": "PASS"
  },
  "azure.claude.sql_database_va_findings_resolved|0": {
    "evidence_sha256": "681bf2a5f741eab3e02eab078bf9d678576eccfcb76f1846c89ccdf4d5620d94",
    "historical_case_sha256": "3b3d9b1bcf536df64bc4ed30e1eed9b1032d61f5d3a8fbe42243938be7e773c8",
    "historical_status": "FAIL",
    "native_case": "database2/negative",
    "status": "FAIL"
  },
  "azure.claude.sql_database_va_findings_resolved|3": {
    "evidence_sha256": "b17adf33af3f97347dd9c51faffa19efaeaca16ddf45b884158353a6cc66004f",
    "historical_case_sha256": "4e3844f9eba541c4af6fa342c1b7312cac560cdfa8185a19b500692c1d39a2ff",
    "historical_status": "PASS",
    "native_case": "database2/positive",
    "status": "PASS"
  },
  "azure.claude.storage_access_keys_rotated_90|0": {
    "evidence_sha256": "a7c7b6d432eab88484fe27da8c85a7b67ce58cc9b231c8cd2a4e9da814565b85",
    "historical_case_sha256": "29fc1162c1f63fe17c732b95715778efbdb370fbe6342939ae530e3cc8fe3abd",
    "historical_status": "FAIL",
    "native_case": "fail_90_days_plus_microsecond",
    "status": "FAIL"
  },
  "azure.claude.storage_access_keys_rotated_90|1": {
    "evidence_sha256": "5a5d91f2c7a9165527b2258b7dbfdf49e29897ad78b80f542af31fb245e3edd2",
    "historical_case_sha256": "d19a2772d1133f9b7c2bc56bb3ea90aa735e296bbcea44d0f5809f9b9855cf59",
    "historical_status": "NOT_APPLICABLE",
    "native_case": "unknown_empty_metadata",
    "status": "UNKNOWN"
  },
  "azure.claude.storage_access_keys_rotated_90|2": {
    "evidence_sha256": "71508f71add5f1dd57f6180a3e5893093aa1c49d2aa11624c753f090ec8e497a",
    "historical_case_sha256": "46017459a91736bc945e2672fd8ae236ff4c311ebc5075e0f14f5c40e50fa79d",
    "historical_status": "PASS",
    "native_case": "pass_exact_90_days",
    "status": "PASS"
  },
  "azure.claude.storage_access_keys_rotated_90|3": {
    "evidence_sha256": "5a5d91f2c7a9165527b2258b7dbfdf49e29897ad78b80f542af31fb245e3edd2",
    "historical_case_sha256": "574a75c3ebc3559eff327286a15c33968fb5c313246a9f6530ff4d209ae655bd",
    "historical_status": "UNKNOWN",
    "native_case": "unknown_empty_metadata",
    "status": "UNKNOWN"
  },
  "azure.claude.storage_vhd_accounts_cmk|0": {
    "evidence_sha256": "74f9f7dcd38fd6908a492b0bcb7e48ab45b896b3a94f3acf2b04ac73dd020d4a",
    "historical_case_sha256": "8e3fc54729ad543b59ca6a68e26f7f04f31daa1b68d624656cc9da3320e44d27",
    "historical_status": "FAIL",
    "native_case": "fail_bound_platform_key",
    "status": "FAIL"
  },
  "azure.claude.storage_vhd_accounts_cmk|2": {
    "evidence_sha256": "7dc660e77a8f627b96c1a17468e856006f12906d151428f94433744a8f3ebb1f",
    "historical_case_sha256": "6b959eea0cc87e6b5a4d1256f65d3c90796bd333222c27e3744db70f8de120b8",
    "historical_status": "PASS",
    "native_case": "pass_bound_cmk",
    "status": "PASS"
  },
  "azure.claude.storage_vhd_accounts_cmk|3": {
    "evidence_sha256": "54fda33bdd85dfd11711e425e82a9b3dadde44547da8d92fc25d84e49d988561",
    "historical_case_sha256": "67b8e9088f19b011059b68eed87ba13199f4263fb585429ea7133ddcbf0f6a1f",
    "historical_status": "UNKNOWN",
    "native_case": "unknown_foreign_blob_host",
    "status": "UNKNOWN"
  },
  "azure.claude.synapse_workspace_vulnerability_assessment|0": {
    "evidence_sha256": "fbe43024eb8f8a26781aa9141951462606ce0260679b2f91a40ae47a776043e2",
    "historical_case_sha256": "11c70f175aaf1a87eaa458996e1fe5259e5a02fa6bb65351401ea723ef6f897d",
    "historical_status": "FAIL",
    "native_case": "fail",
    "status": "FAIL"
  },
  "azure.claude.synapse_workspace_vulnerability_assessment|1": {
    "evidence_sha256": "ca1b5acb4e0724a093098e197a0a5b70d26ddf40595e61e6b91cbffee5f18aa2",
    "historical_case_sha256": "3d8a8dadb237ebcce05752b398bfc15282e001b0e083a3d7127f37da85118055",
    "historical_status": "PASS",
    "native_case": "pass",
    "status": "PASS"
  },
  "azure.claude.synapse_workspace_vulnerability_assessment|2": {
    "evidence_sha256": "853a39234d234f583d149755260f6b1d9c978622cb9939973a5a503f6b971f2d",
    "historical_case_sha256": "6c1e7808d85862381eb356b0da0d49c2e4a0b66b3bb0580fd60a12994fac6c33",
    "historical_status": "UNKNOWN",
    "native_case": "unknown",
    "status": "UNKNOWN"
  },
  "azure.claude.vm_windows_secure_boot|2": {
    "evidence_sha256": "2378ce48e7bcbd422e314ad00bbb7173d512fccc933524cf8553d1175fd239e3",
    "historical_case_sha256": "0fa608dcf2496886e811b09aa604a76ebdec02e213bcb298b8f2b4898e3e59db",
    "historical_status": "NOT_APPLICABLE",
    "native_case": "windows-native-linux",
    "status": "NOT_APPLICABLE"
  },
  "azure.claude2.app_gateway_min_tls_12|4": {
    "evidence_sha256": "608560ea1788179a5a516a1108c1006d32be743ff400a4ff670275666632bdd8",
    "historical_case_sha256": "f1fe21d86914051a2679196932df834221f750aa29378d6ad1bf84c422ee41ff",
    "historical_status": "PASS",
    "native_case": "tests/test_azure_network_platform_1_native_review_20261020.py::test_each_assigned_native_contract[positive-azure.claude2.app_gateway_min_tls_12]",
    "status": "PASS"
  },
  "azure.claude2.app_gateway_waf_enabled|1": {
    "evidence_sha256": "745a15434aaa0d4d7a707e7b8708cf86c502dbba1f4927805aa8164202b5b4cc",
    "historical_case_sha256": "ed801584a47e4222b438d887b2bab78eaa5e88478fa61a8aded1fd80a7cb6a91",
    "historical_status": "PASS",
    "native_case": "tests/test_azure_network_platform_1_native_review_20261020.py::test_each_assigned_native_contract[positive-azure.claude2.app_gateway_waf_enabled]",
    "status": "PASS"
  },
  "azure.claude2.function_app_restrict_public_access|0": {
    "evidence_sha256": "b46e01590f794b919bbc89565e6d542c944c2c51c8706b5379dcbd5b2d7888a1",
    "historical_case_sha256": "071e3ab298d882210001fbf5a2521e5e595360f0c9cc1a9241b91b364f54e69a",
    "historical_status": "FAIL",
    "native_case": "fail",
    "status": "FAIL"
  },
  "azure.claude2.function_app_restrict_public_access|1": {
    "evidence_sha256": "ef9efebc66349dc967cb5e51671f587c313b519134f3262d06427a0dac835863",
    "historical_case_sha256": "d8a14877b6c2e8a41118176d916bafddf3cad74d7998b78f94ce84c98d87016e",
    "historical_status": "PASS",
    "native_case": "pass",
    "status": "PASS"
  },
  "azure.claude2.nsg_flow_logs_to_log_analytics|0": {
    "evidence_sha256": "8468df880e220cd780dce8af53a2025662cd2cbda1d6029c9466f3844d071419",
    "historical_case_sha256": "ca84e40d794daaec910ce8f4010adb06b3300a6ea41224b87162c7c4af2fe86d",
    "historical_status": "FAIL",
    "native_case": "tests/test_azure_network_platform_1_native_review_20261020.py::test_disabled_native_flow_or_analytics_cannot_prove_log_delivery_configuration[flow_disabled-azure.claude2.nsg_flow_logs_to_log_analytics]",
    "status": "FAIL"
  },
  "azure.claude2.nsg_flow_logs_to_log_analytics|2": {
    "evidence_sha256": "2626d3cd4de21a8dc2c3648829d0fbd16b25ec71037bce3c95bd0eb8db796335",
    "historical_case_sha256": "442622577ed3c26510a8493e31e9e70ab1f61f707e3ec1d2e4ea05c78cde6b31",
    "historical_status": "PASS",
    "native_case": "tests/test_azure_network_platform_1_native_review_20261020.py::test_each_assigned_native_contract[positive-azure.claude2.nsg_flow_logs_to_log_analytics]",
    "status": "PASS"
  },
  "azure.claude2.nsg_flow_logs_to_log_analytics|3": {
    "evidence_sha256": "e98f35e0aa0963333334e73a47b5882476b4ecd57fcbed5fa539de6b1d0c74ab",
    "historical_case_sha256": "e4d1e45823f503835cd84ebf52a7b9a565e8381d90061e4022f6a66a937e4231",
    "historical_status": "UNKNOWN",
    "native_case": "tests/test_azure_network_platform_1_native_review_20261020.py::test_flow_analytics_exact_native_target_and_flags[unresolved_local_target-azure.claude2.nsg_flow_logs_to_log_analytics]",
    "status": "UNKNOWN"
  },
  "azure.claude2.vnet_flow_logs_to_log_analytics|0": {
    "evidence_sha256": "8468df880e220cd780dce8af53a2025662cd2cbda1d6029c9466f3844d071419",
    "historical_case_sha256": "934936c6b2a9b2fd27f3eb4d9d66e6299d6bb507ffb27b82913d1f846c99ea62",
    "historical_status": "FAIL",
    "native_case": "tests/test_azure_network_platform_1_native_review_20261020.py::test_disabled_native_flow_or_analytics_cannot_prove_log_delivery_configuration[flow_disabled-azure.claude2.vnet_flow_logs_to_log_analytics]",
    "status": "FAIL"
  },
  "azure.claude2.vnet_flow_logs_to_log_analytics|2": {
    "evidence_sha256": "2626d3cd4de21a8dc2c3648829d0fbd16b25ec71037bce3c95bd0eb8db796335",
    "historical_case_sha256": "c04623a8f6cddf4cf19e62038d17aaa3dc3cd9125d4dcf8d4639e53001ce8d98",
    "historical_status": "PASS",
    "native_case": "tests/test_azure_network_platform_1_native_review_20261020.py::test_each_assigned_native_contract[positive-azure.claude2.vnet_flow_logs_to_log_analytics]",
    "status": "PASS"
  },
  "azure.claude2.vnet_flow_logs_to_log_analytics|3": {
    "evidence_sha256": "e98f35e0aa0963333334e73a47b5882476b4ecd57fcbed5fa539de6b1d0c74ab",
    "historical_case_sha256": "f7db3cc7eebde5f1b29e6b6292f067e10fbbf8f4aef95e08e91f6368bb203a1f",
    "historical_status": "UNKNOWN",
    "native_case": "tests/test_azure_network_platform_1_native_review_20261020.py::test_flow_analytics_exact_native_target_and_flags[unresolved_local_target-azure.claude2.vnet_flow_logs_to_log_analytics]",
    "status": "UNKNOWN"
  },
  "azure.gap.compute_vm_remote_access_restricted_all_ports|0": {
    "evidence_sha256": "d007325fc95e1c02053f56c8c6096c74916a32e7aba4b23a1b9b59b08cf96397",
    "historical_case_sha256": "e6350c9df2e90b0b7b7a7d89a956c1339775d15a3b384077886a8ad88814617e",
    "historical_status": "FAIL",
    "native_case": "fail_native_declared_configuration",
    "status": "FAIL"
  },
  "azure.gap.compute_vm_remote_access_restricted_all_ports|1": {
    "evidence_sha256": "f2dbead3ad8f59131411554f6b26c3d98fc30a8b9dac2d9e7f29edf6ffd5c6f9",
    "historical_case_sha256": "c95d5e690e6ee2a7f66c77ff9b087a9aca00b5a640eedaca8b7bffd12b69104a",
    "historical_status": "PASS",
    "native_case": "pass_native_declared_configuration",
    "status": "PASS"
  },
  "azure.sql.minimum_tls|0": {
    "evidence_sha256": "bae17bde04d712180c1ff638e2028d60f6f7f42957ea238764e33970907e85b0",
    "historical_case_sha256": "296d28d7355ee464fce5530d777099d85f99810e0f3bc283814c22389b60673e",
    "historical_status": "FAIL",
    "native_case": "database2/negative",
    "status": "FAIL"
  },
  "azure.sql.minimum_tls|1": {
    "evidence_sha256": "7c47dc5adb4b45583ed91f3199eb426cc365bfcff6aba4d3d41710b86fe9c302",
    "historical_case_sha256": "ac61408d7260bc1438655a480a6c26cd5ecafe3b603f507a1726c1f49f57396b",
    "historical_status": "PASS",
    "native_case": "database2/positive",
    "status": "PASS"
  },
  "azure.sql.minimum_tls|2": {
    "evidence_sha256": "342ea47d000ef972f1a258dc8cbd04b432f8be0d0c94adc33f65f074a32510af",
    "historical_case_sha256": "4f534432afda0cd211c1a19eb76a58538f43451d535f83057d426664a1be8fed",
    "historical_status": "UNKNOWN",
    "native_case": "retained-uncertain-input",
    "status": "UNKNOWN"
  },
  "azure_aks_cluster_7_2_1_6_93c4fab|0": {
    "evidence_sha256": "f834968abf72921abe74c10a0a66e7b3d8525d30b0708e404b2dd01e1e43bcaf",
    "historical_case_sha256": "dffcdf2d47d823435d01ea1830741e2b1c36fa537c425d68494f4d2524e7cf95",
    "historical_status": "FAIL",
    "native_case": "aks-native/fail",
    "status": "FAIL"
  },
  "azure_aks_cluster_7_2_1_6_93c4fab|1": {
    "evidence_sha256": "a904bc5fbc1b346127506391226c0a542d1498dae43954164051b6a144a64cc8",
    "historical_case_sha256": "171d98a90fce1a5fc74eb710d413092f3e91f5a5776137c8b6eee8a0ede22f5b",
    "historical_status": "PASS",
    "native_case": "aks-native/pass",
    "status": "PASS"
  },
  "azure_aks_cluster_7_2_1_6_93c4fab|2": {
    "evidence_sha256": "d1100d4ca97ef092cff5e00cdfaa71be05d84bb09c0e5fe351577010f63e4c21",
    "historical_case_sha256": "af3abd218db927b787ce127dcdffde4b46894419452939d7cf35ad8a4ae8e28a",
    "historical_status": "UNKNOWN",
    "native_case": "aks-native/unknown",
    "status": "UNKNOWN"
  },
  "azure_aks_cluster_aks_cluster_rbac_enabled_db12524|0": {
    "evidence_sha256": "45d84a7a0adbd967b3b7917365f6754f147d2546fb38daa18919ecb716c15c54",
    "historical_case_sha256": "a95805b1ae758168034fa1d4971515c62d75f0a8b88b9d22e71cbf58d3c2662d",
    "historical_status": "FAIL",
    "native_case": "aks-native/fail",
    "status": "FAIL"
  },
  "azure_aks_cluster_aks_cluster_rbac_enabled_db12524|1": {
    "evidence_sha256": "77f4fdca9448c10f4eaecb7bcc34261fb6819006b5f15affc0731cacb20d709b",
    "historical_case_sha256": "08724dd5efdbfd28b695babadd60be7891ae0c25cab58b09d926ad3b020a5c62",
    "historical_status": "NOT_APPLICABLE",
    "native_case": "aks-native/unknown",
    "status": "UNKNOWN"
  },
  "azure_aks_cluster_aks_cluster_rbac_enabled_db12524|2": {
    "evidence_sha256": "daf312aef92391e977b7fed4afda138d87ed3a3f30bff3a31297a50a03d0ac42",
    "historical_case_sha256": "dd867c98ec43f1b223a5c1722d61bbb5e71f827290241262b27130c43ba999fb",
    "historical_status": "PASS",
    "native_case": "aks-native/pass",
    "status": "PASS"
  },
  "azure_aks_cluster_aks_cluster_rbac_enabled_db12524|3": {
    "evidence_sha256": "77f4fdca9448c10f4eaecb7bcc34261fb6819006b5f15affc0731cacb20d709b",
    "historical_case_sha256": "af3abd218db927b787ce127dcdffde4b46894419452939d7cf35ad8a4ae8e28a",
    "historical_status": "UNKNOWN",
    "native_case": "aks-native/unknown",
    "status": "UNKNOWN"
  },
  "azure_application_gateway_11_5_1_1_1_f56bdc2|0": {
    "evidence_sha256": "d743fde6c7689dd1592a4cd223aa3560978b68594232cc18acf0c3b31d516716",
    "historical_case_sha256": "cf6ef531fa4a83b2486e3ec76404e06e43762dfa6cbf2414ad5ee4b9437fdb6a",
    "historical_status": "FAIL",
    "native_case": "edge-successor/53/0/inline_candidate_detection",
    "status": "FAIL"
  },
  "azure_application_gateway_11_5_1_1_1_f56bdc2|2": {
    "evidence_sha256": "1f4cf94621fc6695a2b2cff3f1482058352ce1d00ebe1a5606f48184775c6d6a",
    "historical_case_sha256": "e5f45150cef212b305fca4517012cbeb075a13dc240bdc19a55f0d8aed92fa0a",
    "historical_status": "PASS",
    "native_case": "edge-successor/51/0/inline_candidate_prevention",
    "status": "PASS"
  },
  "azure_application_gateway_app_http_logs_enabled_2de0361|0": {
    "evidence_sha256": "0b126f9338b13aa85ddb61d10644f1fa290fd469e9fb64120c655d65d2caf36a",
    "historical_case_sha256": "197b7c464f439710eaec49c82299a584a819bdbc3a66bbb023430579485fe472",
    "historical_status": "FAIL",
    "native_case": "edge-successor/43/0/gateway_logging_candidate_empty_diagnostics",
    "status": "FAIL"
  },
  "azure_application_gateway_app_http_logs_enabled_2de0361|1": {
    "evidence_sha256": "2877336bcedc68f3c79a54afed3820dff55b67c7bf11ee751502d21f0807c419",
    "historical_case_sha256": "9a1d3dbc03f1f3e00d6b085162662f1cb43eede203b8e660601a43d6cec7b831",
    "historical_status": "PASS",
    "native_case": "edge-successor/41/0/gateway_logging_candidate_positive",
    "status": "PASS"
  }
}
''')


PINNED_SUCCESSOR_INPUTS = json.loads(r'''
{
  "docs/check-review/azure-acr-image-secret-implementation-20261020.json": "8c77fa3e50d19ecd6d9953c386e52a21c1718e06bf5f9176c088b1f0a19a63d3",
  "docs/check-review/azure-app-settings-secret-implementation-20261020.json": "48d79c43d29afbdf2d6cb8f958312f6aaa23ec8b660445129226a026a791e956",
  "docs/check-review/azure-application-compute-1-native-review-20261020.json": "77087255c47861528d9620e27c71d07ed2e6126b82137ba31ee4f771aeded268",
  "docs/check-review/azure-compute-network-native-review-20261020.json": "46266c3118574f5555b1542c59976119555e3fcdb6d129dc031387916b581909",
  "docs/check-review/azure-current-attestation-nine-native-recheck-20261020.json": "f5dc2bda45da7f5a55876ae545280184331bfdd5597e9d867ae79432f93ad1c1",
  "docs/check-review/azure-final-services-integration-20261020.json": "7a1226051a412b325babf472f3e14a074564aad8233911618daaab026274a951",
  "docs/check-review/azure-four-cohort-integration-20261020.json": "ace6e7fd159643568092c1ead2b314b32df9f3da04b8de746dfa9d6ee16e57ad",
  "docs/check-review/azure-identity-integration-20261020.json": "dafccab1f1aa7ca11a04d526745b827322b631cd2e7b48291570084375c7e526",
  "docs/check-review/azure-identity-native-review-20261020.json": "912f4e70c3cf8df5159fc61c885ba68a7d76c2febc004774b2b5aad90f5893ac",
  "docs/check-review/azure-k8s-current-predicate-bindings-20261020.json": "23ab6679ae1f7a4a35a86da7477c7427126bc668b3067ddc678d442d58bb8799",
  "docs/check-review/azure-master-predicate-attestation-errata-20261020.json": "1de6ceb284293f23a530e382bb08a46d08a667290a5cc84f7ef9cfcb0cfe8fcb",
  "docs/check-review/azure-network-audit-admission-20261020.json": "daba95114a8c9f6af5d60e27f6195d7464d071d5cda2e2ad85a0bb5890db7b9c",
  "docs/check-review/azure-provider-integration-acceptance-20261020.json": "38e933aacafdc11eb01980cb22e0cb632ff06a21b683c358d8e566c6d2ad733f",
  "docs/check-review/azure-storage-compute-integration-20261020.json": "aa1527f425d7875ea2ab3f9d29207010c7207b2d436e1d0c4584b6b5997ebfbc",
  "docs/evidence-reviews/azure.json": "a37c5a120a5dc97df42976815ddb8ddfd880430992be068d6d544c0839800ff7",
  "peaso/checks/azure.py": "616d104fce5d17c8ec66f74b62855b56a04678f1f224cf15d2d79e7c2dfcdd4e",
  "peaso/checks/azure_acr_image_secret_review_20261020.py": "11821a6a2d2366602d993d79c58844d6f0c14b1a766ffd19c43894bef8f2dd39",
  "peaso/checks/azure_acr_image_secret_review_20261020_fixtures.json": "6920da6da7d3ef871ecccfd06bf3db9326891d6bcfdc0c37799dbcf9e6580af7",
  "peaso/checks/azure_acr_public_ip_review_20261020.py": "11f14a2636df38e643292f69ae88a44d1e1676d905cf12c9227ac06450669883",
  "peaso/checks/azure_ai_services_review_20261020.py": "7308ea804ff2890a463105842422c2e4050149e0ba626a877933609f9fb097a8",
  "peaso/checks/azure_aks_legacy_projection_review_20261020.py": "d2aac095ecf0da4019853fb86c4be7129e5f2f75578c1484414bb8b17cfac633",
  "peaso/checks/azure_aks_legacy_projection_review_20261020_fixtures.json": "7e4233f962bc14aa19ddeb4cf9f9c0d3d26a78ca0f600dde3600fa372e06e3a6",
  "peaso/checks/azure_app_settings_secret_review_20261020.py": "4ef3432a8394dd6a61cf8b4bc145527cc1e552aa0bcd4a90b2d4ddd77d3a9f93",
  "peaso/checks/azure_app_settings_secret_review_20261020_fixtures.json": "82007dd44ad28a70ee753c1c49b1d4c9b4392b3474e904e09cf0c08a925bf29c",
  "peaso/checks/azure_automation_aci_metadata_review_20261020.py": "a70eaf5b81e76f044e2a65b0deee5f9a3dd30d2b86c6f3146670fd59bbe59e9a",
  "peaso/checks/azure_bulk_clarity_reviewed.py": "6c36caa185c2b483eb94185110aa8b514ddebefe56188e2d9e0dc1f921967d22",
  "peaso/checks/azure_databricks_notebook_secret_review_20261020.py": "ffba8f894df00f9d6d014a19a2fc03158e84363610266abbf171d4c878e2f7ec",
  "peaso/checks/azure_databricks_notebook_secrets_admission_20261020_fixtures.json": "e97136868f594a964d4b39a9d604713e1ebc363baf22b2aedb9261823410a6fa",
  "peaso/checks/azure_declaration_secrets_admission_20261020_fixtures.json": "362d198f41941df134a601e17cf1b1a4122df5346bce4ee80cf9f3bf8a3f88b3",
  "peaso/checks/azure_devops_selected_content_secret_review_20261020.py": "3cf90c69336a559bc48fdf755a468f3d1c03cc9862753549ee310a5b459b033d",
  "peaso/checks/azure_devops_selected_content_secret_review_20261020_fixtures.json": "2c0ea070dab332ffd56e919d37760e591eaafdc9ebacc7bc3390175db1c890d5",
  "peaso/checks/azure_devops_visible_urls_review_20261020.py": "ad7cfe76a9b284f2934db24f7341048c563f69c7d6e5156573f2b24e15c059e5",
  "peaso/checks/azure_evidence_explanations.json": "cedb2234ba1d9452b2581d5cac4bef60df9673cf7b56405309a1fdf50fa7dee5",
  "peaso/checks/azure_finding_clarity_reviewed.py": "747074079138e16c5c795a779a85bb59d8263981f7a3c88547be6a8df95a070d",
  "peaso/checks/azure_function_package_integrated_consumer_20261020.py": "277b1e6115a683b72c7fbcebbde6eb163dff34196359a61af0c1b78e05de1129",
  "peaso/checks/azure_function_package_integration_cases_20261020.json": "0d6e8528501d483c8c76027d255a2d21d4196faf82a79dd0420e4f59663ba2f5",
  "peaso/checks/azure_function_settings_runtime_cases_20261020.json": "581eb4d108d819e389658ed72d13884ff870b54f04d52b76cfffbfab857a99d7",
  "peaso/checks/azure_function_settings_runtime_consumer_20261020.py": "411689c7e89c3f70baa29eb3a235b1ee0ecffbdb6d8fbc6b2543be269c23451c",
  "peaso/checks/azure_gateway_logging_review_20261020.py": "c6898ab3ad1145494615329dcc2d12d938a2a75f7d0332ce9ce413ac248c0c4b",
  "peaso/checks/azure_hsm_audit_destination_review_20261020.py": "bd46c2f53e4e7def85f390662c20bc1599d7dd9c5a0fcfcbecd5fdac5e064ca2",
  "peaso/checks/azure_hsm_audit_review_20261020.py": "b86d0b08d1a6b2ac30478393940cf5fd93427ecc0a4ff50377d005117f01c034",
  "peaso/checks/azure_log_samples_admission_20261020_fixtures.json": "6a66e323b4ee2ff7505f1997279790ec6c4fe15497ccc69e616f78a4522c1c3f",
  "peaso/checks/azure_ml_asset_secrets_admission_20261020_fixtures.json": "4f61349c1b83a9e2b62fb16e0de693287e4fadc17fdd89f8c82bcc8233b10e0e",
  "peaso/checks/azure_ml_job_secrets_admission_20261020_fixtures.json": "2840b0e2bafc61a25771b49d29bda2fd2ef25890e8763caaec5691fe0afeba69",
  "peaso/checks/azure_ml_selected_asset_secret_review_20261020.py": "4c66fc194c7c94537581f240ee6999ee87e6677c6deeb5e65b510c4eddf6f472",
  "peaso/checks/azure_ml_selected_job_secret_review_20261020.py": "20536cbdc302fdbee0565304aca63314e9ada62c769e17e383b3c3dc00798bd1",
  "peaso/checks/azure_native_contract_closure_20261020.py": "4f05044102b87c56f4da90aaa9917d2c17587569675632f3f98ecf6db29b1a61",
  "peaso/checks/azure_native_review_copy_20261020.py": "89a6fc92ac9861a088960e7736dfe05aa69ee778289b5b8c3e005a6f4b218393",
  "peaso/checks/azure_nsp_query_cmk_production_cases_20261020.json": "0ba1cb3e3b5b670d056ab2f15090131a98cf802e14e872f54678347fbd361ca0",
  "peaso/checks/azure_nsp_query_cmk_runtime_review_20261020.py": "f18440a1a6c796dcc2d97b4194497ecf4023d881c73371d8a737a8b89fc4891f",
  "peaso/checks/azure_public_edge_config_review_20261020.py": "1e5f8ca3e560adbece0529428e945888789f729a6b71e99188053b92b5305263",
  "peaso/checks/azure_sas_expiry_policy_declaration_native_cases_20261020.json": "a015b2c2e123b5ecab5dfbb6f0d32152706c0ffd51607ec23acf8974794055c6",
  "peaso/checks/azure_sas_expiry_policy_declaration_proposal_20261020.py": "3da44b2f1ce9727abb44b0b382bef83f01886244ce16a4c4b76fe91605e0748e",
  "peaso/checks/azure_selected_configuration_secret_review_20261020.py": "7f91025d84506fa752ee9f5455ddd34ea2439a2ec86dafed6a3c634eaebdabf0",
  "peaso/checks/azure_selected_configuration_secret_review_20261020_native_fixtures.json": "f054ef190b01383809ed1fe0e9b360af75fa6843d82711cf832c33faef60f908",
  "peaso/checks/azure_selected_declaration_secret_review_20261020.py": "450fd027e844998211f439e82f62c2882f78b720cc491ea661ec3c97688ee956",
  "peaso/checks/azure_selected_log_sample_secret_review_20261020.py": "6a0cf1b45d2dd8143d7d78ab83de242bf688e3261c1b8053b8aa2710e58728b5",
  "peaso/checks/azure_selected_storage_secret_review_20261020.py": "6f750b36c51f37c18d6f666e11f8d73c05a20bb1f060f858517270e46a780971",
  "peaso/checks/azure_selected_storage_secret_review_20261020_fixtures.json": "fbc1e530e63805d4cf19af69e9c79e638d559c17aa25ac5803f94d8685180e99",
  "peaso/checks/catalog.py": "c24821bee09ad54f650825c43886bd69e9c7b3143b75f380fef370857fac4568",
  "peaso/checks/claude2_azure_common.py": "3e0a702be14e9ee590ca20e182cfe967e8857c3fca5ea19e5b5def3cb131cf7b",
  "peaso/checks/claude2_azure_network.py": "49e5d6a1907d4fd9405b82eb413256f73fbb23134652d19615319b460643f1cb",
  "peaso/checks/claude_azure_compute.py": "9b21de8a6af39dd5a08dc46fa9e6f2d891375b575fba50f1e96697fe07f042e1",
  "peaso/checks/claude_azure_data.py": "d4013488f1536f9be4425a690d3cb87ef73ae35c08e02b356d1ff1324c00d472",
  "peaso/checks/claude_azure_identity.py": "0279457a6e88216e84bc36188362def0480e86013cc790fdb8d143ca751d5acf",
  "peaso/checks/claude_azure_network.py": "5cafa8d926a058366a0a1e2119735a061d267ca284b2cf46906cce8d138e254b",
  "peaso/checks/exposure_endpoints.py": "fcb83aabf932385e03b9ae39279b986d5956bb07d42c074ceeb9a8de9128cb10",
  "peaso/rulepacks/check_descriptions.json": "e9efda68fd352ec174d406b66d17525a8df3d0e217427cb0cca063b9e232d096",
  "tests/azure_native_successor_inputs_20261020.py": "88e8f03a54b829fc88cf34a1d3b03fafc17d6bced2c598e1e55e1cee44135445",
  "tests/fixtures/azure-ai-evidence-review-20261020.json": "84b95bdd081a971ae222fed4f1f88041197d246f88add2ff38f4417c733ae4f0",
  "tests/fixtures/azure-automation-aci-evidence-review-20261020.json": "334b2cc476fcbbf7bda7d551ceef66d3cb12f50b6ad8cb40a57f36b6f8eda0a3",
  "tests/fixtures/azure-final-native-evidence-review-20261020.json": "6366504d3f49594ee4ebf0dd1ca244598dfde04db4f9621172a95d9627eafc71",
  "tests/fixtures/azure-network-audit-evidence-review-20261020.json": "555d7b736f5a70e4edb57285df6e03abfe11e8af934075509c354f7b9ea90e38",
  "tests/fixtures/azure_application_compute_2_native_successors_20261020.json": "6987925bd50161b345e4af9147ae371c62795a2db8e62394f6f33d79af676fd3",
  "tests/fixtures/azure_application_compute_native_successors_20261020.json": "734b729df1232d6588080dbb72894b982970a61e7a4d8f1eebe9ebb9c912929d",
  "tests/fixtures/azure_database_crypto_backup_2_evaluator_inputs_20261020.json": "1c29a99df697adb2ae09ab46a62ac3627be0786fcad926d41cd9dd3300a15f27",
  "tests/fixtures/azure_database_native_evaluator_inputs_20261020.json": "fffe69c4a4c7bfd5b155783f82e908e590a92af13c621e47ccc78da1d51b2eb8",
  "tests/fixtures/azure_edge_native_current_inputs_20261020.json.gz": "8fd363d85f247f9586e544808088c6652b0b142bfc3513a63c0820ac785d0ebd",
  "tests/fixtures/azure_evidence_review.json.gz": "5a012535b59e82e6a7b0d3b93d1acac93661448130f3556571fdef0f5d831812",
  "tests/fixtures/azure_function_role_native_successors_20261020.json": "fffbb2d1d0b74dcac8a03cb9a12fd4d809a3eff9dbf5d9690d0744a879a1df0b",
  "tests/fixtures/azure_identity_enforcement_native_successors_20261020.json": "83c17c059b9f7fcfabf9810c277c657f051e198a993ccfe892cc63a9fadd99ae",
  "tests/fixtures/azure_identity_native_successors_20261020.json": "aa0ff70196a8c4ca5316535ba241742a5160e554d7d62bc0b6f60799ce6da3a8",
  "tests/fixtures/azure_network_native_evaluator_inputs_20261020.json": "84d1e943bdc7280f98a539b58a55fff19b194c98233a1ef655198adf64762830",
  "tests/fixtures/azure_services1_native_evaluator_inputs_20261020.json.gz": "dd8f5099b70b5042af97e0dcd5c8b79217ca3bd8ed9c45791e0f1ae2f62d73ef",
  "tests/fixtures/azure_services2_native_evaluator_inputs_20261020.json.gz": "b014bfcae225cb6921963107cd1d534d455037887c3715c343915560ea1cac1c",
  "tests/fixtures/azure_services3_native_evaluator_inputs_20261020.json.gz": "a972e55d611340f8e343e64828628b05e011fc56f43bbc6aac75e924ed7d19a8",
  "tests/fixtures/azure_storage_native_fixes_20261020.json": "3725868ab78ba8a1b6467a74123a5ab86bb2ec2a93c15255b5edb146bdd9a896"
}
''')


NEUTRAL_EXPLANATION_CONTRACTS = json.loads(r'''
{
  "azure.encryption.automation_cmk_declared": {
    "manual_observation": "931c46b03e7e1214c7fcb88da1a2f39ba1c62314e9474ec26e65f78b69dc410c",
    "missing_observation": "931c46b03e7e1214c7fcb88da1a2f39ba1c62314e9474ec26e65f78b69dc410c",
    "not_applicable_observation": "d782f646c0bcfac0d5ca295f5779c4a526caeec19506d8eb3fba9f998480d28b"
  },
  "azure.encryption.log_analytics_cluster_cmk_declared": {
    "manual_observation": "299f3480ac608e329d1904a22921d3c5133fe5c9eea1a966959ddfb54a0b5735",
    "missing_observation": "299f3480ac608e329d1904a22921d3c5133fe5c9eea1a966959ddfb54a0b5735",
    "not_applicable_observation": "090943ce3aabadf180fe9812e435ff1de400159e08ef883cd00750dcc7891665"
  },
  "azure.encryption.stream_analytics_job_storage_cmk_declared": {
    "manual_observation": "3e5e8b638110912407bd5a39cc27f1fe60fa66d951d55f642105a7b4bc55b0c0",
    "missing_observation": "3e5e8b638110912407bd5a39cc27f1fe60fa66d951d55f642105a7b4bc55b0c0",
    "not_applicable_observation": "d029c49824247a3256e15f20c526c38264603802456284030e98e1bd07df76df"
  },
  "azure.logging.aci_log_analytics_declared": {
    "manual_observation": "e509052c3c34df59758240792c84f481420d401b5a42ef46ae29dc3ffb5030a0",
    "missing_observation": "e509052c3c34df59758240792c84f481420d401b5a42ef46ae29dc3ffb5030a0",
    "not_applicable_observation": "e75f7148d4604ba3e4a22f0d144aebd0ddace95fd7237d219583d66b31ec47a3"
  },
  "azure.logging.aks_supported_log_categories_destination_declared": {
    "manual_observation": "2a3523dbe8ff6e1e8d4b8a68cd66cefa88a7386223c739e7c81469a3a5f07fd9",
    "missing_observation": "2a3523dbe8ff6e1e8d4b8a68cd66cefa88a7386223c739e7c81469a3a5f07fd9",
    "not_applicable_observation": "e8dfe028f4437cc614e2974035109659ab892d4b5f4dfc40cf1d93174c86803b"
  },
  "azure.logging.managed_hsm_audit_destination_declared": {
    "manual_observation": "2a3523dbe8ff6e1e8d4b8a68cd66cefa88a7386223c739e7c81469a3a5f07fd9",
    "missing_observation": "2a3523dbe8ff6e1e8d4b8a68cd66cefa88a7386223c739e7c81469a3a5f07fd9",
    "not_applicable_observation": "e8dfe028f4437cc614e2974035109659ab892d4b5f4dfc40cf1d93174c86803b"
  },
  "azure.network.acr_public_ip_ranges_restricted": {
    "manual_observation": "27cb05e107204731fa1f71ca44a0ff540e66948ae9f51f5f29bfd53e03fd2217",
    "missing_observation": "77784deaa2e5bc81f5521a3e288126d0d8ef71ec81433069fb96debfb4f002b3",
    "not_applicable_observation": "b76c483f0e9489c476a8ec5c2b00b79f8a693cdaede1c65b034063b123188541"
  },
  "azure.review.acr.selected_image_secret_indicators": {
    "missing_observation": "55d3a1297112a834702d232769283c29afe83a370ae323d13bb1695a4fad958d"
  },
  "azure.review.ai_services.audit_logging": {
    "manual_observation": "941610c17c0170563fe0f180e4115bb53a89ecdefdad7b811ae57c378b1ddd4f",
    "missing_observation": "14a6d3ea27cde89eecbc157fc43ac77bd55b6057787433a656e93eaa72087576",
    "not_applicable_observation": "9f8628dd240988d861d51b7f7567c62a68c886d6835bb080f895b089fd9f37bd"
  },
  "azure.review.ai_services.managed_identity": {
    "manual_observation": "e134a42b4cf2c14a179d7ffbc911e69bcab32da0f4630771f15a4db9627b7aa9",
    "missing_observation": "9b5b966dd2a7e526d8e3467b20ee9d5da89dd69967af750c08ac094bf0f7af84",
    "not_applicable_observation": "3160bde8c528c8f3037f6178c00c849c1384604396b8fcc4c8985842c93aacac"
  },
  "azure.review.ai_services.outbound_restriction": {
    "manual_observation": "c5cff49beb2e48300a3f1480b089f7f1066a4c52c80120316c5008e8344de3e2",
    "missing_observation": "b9e9d543e5b65e61622328d18876974b6b63cea74b149e5afdd00722546980c1",
    "not_applicable_observation": "5ac8e51c46681126cebfe4c501c89bbc372dc25e433f761572a33ef141904f5e"
  },
  "azure.review.ai_services.prompt_shield": {
    "manual_observation": "86c759051b915d9617f339475db983db97a49db4ce1c0c97f57d8322ff4c81f7",
    "missing_observation": "b27be3fdc8abe9e9492af2c7ae0f8b91bbc6a76a0ded1dfea7ff8b788e6b286f",
    "not_applicable_observation": "cbf067c5ed07a19fd1e6424027677fe22fcd6ba56342f525eb075782e379e686"
  },
  "azure.review.app_configuration.selected_value_secret_indicators": {
    "manual_observation": "d662205310d892ce7cf6d87ab70b4f567821a75167534fbb55642e9e15fda031",
    "missing_observation": "d662205310d892ce7cf6d87ab70b4f567821a75167534fbb55642e9e15fda031",
    "not_applicable_observation": "a7e0909b629abe38f57c722b1c6313e0e419a06a841c4a7be3dc0d426ebbd536"
  },
  "azure.review.app_service.selected_app_settings_secret_indicators": {
    "missing_observation": "50611e6fb102de8de67d1e22c7e365bcfb21577995cead1c9aa58498a39d792c"
  },
  "azure.review.application_insights.selected_trace_sample_secret_indicators": {
    "manual_observation": "87889141b2d402e08c53bc69b333dab571902267eb573637abeed56126c45e8e",
    "missing_observation": "87889141b2d402e08c53bc69b333dab571902267eb573637abeed56126c45e8e",
    "not_applicable_observation": "36c00d4e5d7a4d9e49811c57487bce1aa15026e7dec59b5292d816c068d343e8"
  },
  "azure.review.configuration.selected_content_secret_indicators": {
    "manual_observation": "32cc1fc648d5c3d778bb567411927404209ded9a98ca512041066b43c98df05f",
    "missing_observation": "32cc1fc648d5c3d778bb567411927404209ded9a98ca512041066b43c98df05f",
    "not_applicable_observation": "a62116511c759308bac223f221a0d7c322121e56a7fdcf1d128c34cd3c2b9bd4"
  },
  "azure.review.data_factory.selected_declaration_secret_indicators": {
    "manual_observation": "9e00d5a18f4b6f76ac55a5804c43177fba662bad6bd84f564a7f500fc067a148",
    "missing_observation": "9e00d5a18f4b6f76ac55a5804c43177fba662bad6bd84f564a7f500fc067a148",
    "not_applicable_observation": "4c5f9c75d9d13bec3df47395d4548ee68af598fe801e1b38b27ec7219f7cccdc"
  },
  "azure.review.databricks.selected_notebook_source_secret_indicators": {
    "manual_observation": "fb74c3dc25195a6e4c0a89742ca6f2c6e11d9a606cd6e37cbe797ca146f70ffa",
    "missing_observation": "fb74c3dc25195a6e4c0a89742ca6f2c6e11d9a606cd6e37cbe797ca146f70ffa",
    "not_applicable_observation": "9aa11a187d08eda07e506e1f6b6f00d2bba55ad85c3da97013fa2c2c88326236"
  },
  "azure.review.devops.selected_content_secret_indicators": {
    "manual_observation": "78253d945268c0312e5105067c59709fcf8589bb84f7c43546a3237189be92f1",
    "missing_observation": "78253d945268c0312e5105067c59709fcf8589bb84f7c43546a3237189be92f1",
    "not_applicable_observation": "1e2da6461b5938a28860632d449f88ea9c7d34e44b2881d30afe4df782a9543d"
  },
  "azure.review.devops.visible_clone_urls_without_userinfo": {
    "manual_observation": "729fe90fc24f0786c1681f37093fcc74976e72d3ac9596db709058554a11837d",
    "missing_observation": "729fe90fc24f0786c1681f37093fcc74976e72d3ac9596db709058554a11837d",
    "not_applicable_observation": "ab45b872a7bbfb52b49d54c0b0a6fb00983e13646b83b29fc142e1f1c40b98e3"
  },
  "azure.review.function.application_insights_setting_declared": {
    "manual_observation": "bd5f79b8fbe314feaf73e0c89771d5344d99d7cff8e73ea78fe01d215e60a3ae",
    "missing_observation": "bd5f79b8fbe314feaf73e0c89771d5344d99d7cff8e73ea78fe01d215e60a3ae",
    "not_applicable_observation": "c39a2340c5f9e66d80f76f1738e28bfcbcbe64484dc99144f2f02f6f6b15449b"
  },
  "azure.review.function.runtime_major4_update_channel_declared": {
    "manual_observation": "bd5f79b8fbe314feaf73e0c89771d5344d99d7cff8e73ea78fe01d215e60a3ae",
    "missing_observation": "bd5f79b8fbe314feaf73e0c89771d5344d99d7cff8e73ea78fe01d215e60a3ae",
    "not_applicable_observation": "c39a2340c5f9e66d80f76f1738e28bfcbcbe64484dc99144f2f02f6f6b15449b"
  },
  "azure.review.log_analytics.query_storage_cmk_declared": {
    "manual_observation": "e7bebabd02b959b27677ff5254f1de4053328ddba6611fd08ae6eca034bc6f57",
    "missing_observation": "e7bebabd02b959b27677ff5254f1de4053328ddba6611fd08ae6eca034bc6f57",
    "not_applicable_observation": "2d9cd8e3ccf076e8abc4997a8bd8410ac5d9b66cae2bafcf08075f9855baed33"
  },
  "azure.review.log_analytics.selected_message_sample_secret_indicators": {
    "manual_observation": "87889141b2d402e08c53bc69b333dab571902267eb573637abeed56126c45e8e",
    "missing_observation": "87889141b2d402e08c53bc69b333dab571902267eb573637abeed56126c45e8e",
    "not_applicable_observation": "36c00d4e5d7a4d9e49811c57487bce1aa15026e7dec59b5292d816c068d343e8"
  },
  "azure.review.machine_learning.selected_code_file_secret_indicators": {
    "manual_observation": "433377122ef5418dd0c7b5acb58f191c252a83a800cd02e36e9f4951ddafcf3b",
    "missing_observation": "433377122ef5418dd0c7b5acb58f191c252a83a800cd02e36e9f4951ddafcf3b",
    "not_applicable_observation": "d00378175b64cb9bc32cba4c3a8efcf99ad230a0d1aa3115efe2bec1ccda70d9"
  },
  "azure.review.machine_learning.selected_command_job_secret_indicators": {
    "manual_observation": "53de667f2f5fb577afd9ae482b0c87233eadacc8f7af5c8d50b729f1fb3c52a1",
    "missing_observation": "53de667f2f5fb577afd9ae482b0c87233eadacc8f7af5c8d50b729f1fb3c52a1",
    "not_applicable_observation": "fa662dfd5b319ceec6a72f568494b37192a56d4659efc313cce25db22f659870"
  },
  "azure.review.machine_learning.selected_environment_conda_secret_indicators": {
    "manual_observation": "4905ce95b7d76b1b31bf2884305059d794ebfdbbee5531110f1690f72857361c",
    "missing_observation": "4905ce95b7d76b1b31bf2884305059d794ebfdbbee5531110f1690f72857361c",
    "not_applicable_observation": "0fa2fa39bc926516aeab9fe5369a9a00f925bac76d05ca3b22b5007a41eacb4a"
  },
  "azure.review.managed_hsm.audit_storage_destination": {
    "manual_observation": "7d17efe920eb5c13c05bd05304d9a59fad475fa464c504ee4ad9cb35c851a08f",
    "missing_observation": "84ace35a75653f19f5053db86efd00650191c88120222497064fb04c8bd66c59",
    "not_applicable_observation": "d0a50ad9308cc4c8f7119b510d239b4f3ebbda4e4a09f529bf1ff68dc803335e"
  },
  "azure.review.network.perimeter_association_enforced": {
    "manual_observation": "1c6d2aa48cba65708faefcaf6ee3ada7751d2cc8513c1d841d330cbb830e1195",
    "missing_observation": "1c6d2aa48cba65708faefcaf6ee3ada7751d2cc8513c1d841d330cbb830e1195",
    "not_applicable_observation": "83bf7fb138966f767b64a26a6b8ea97b344f0694b6ff1dfefc407603da7879fa"
  },
  "azure.review.storage.blocking_sas_expiry_policy_declared": {
    "manual_observation": "de886bd2e0c8b9b8f8124dde349005058b16635d580facabdb911cacc6c1db47",
    "missing_observation": "de886bd2e0c8b9b8f8124dde349005058b16635d580facabdb911cacc6c1db47",
    "not_applicable_observation": "998c15424cbd3fa1960aafbf68af098df43cac51b5abef39e310f268680af804"
  },
  "azure.review.storage.selected_source_secret_indicators": {
    "manual_observation": "f53b540799e1ed84091094308d8c8e433da3f5430de68e2dcc33221a10370d7c",
    "missing_observation": "f53b540799e1ed84091094308d8c8e433da3f5430de68e2dcc33221a10370d7c",
    "not_applicable_observation": "032dce97c7652370f7179451e8d6da615abe4118fee31668dcc69cd0aba38ba5"
  },
  "azure.review.synapse.selected_pipeline_secret_indicators": {
    "manual_observation": "04eb4d3af0054e3f730138f2e24b8cbfe709a4c8ce7e2eaf9f42347928f3b256",
    "missing_observation": "04eb4d3af0054e3f730138f2e24b8cbfe709a4c8ce7e2eaf9f42347928f3b256",
    "not_applicable_observation": "3b9e893a9e84bcb0dd0602523c1c695970bc98961c1536d3f99b41566210ef4f"
  }
}
''')


MISSING_NEUTRAL_FIELDS = json.loads(r'''
{
  "azure.review.acr.selected_image_secret_indicators": [
    "manual_observation",
    "not_applicable_observation"
  ],
  "azure.review.app_service.selected_app_settings_secret_indicators": [
    "manual_observation",
    "not_applicable_observation"
  ],
  "azure.review.function.selected_package_source_secret_indicators": [
    "manual_observation",
    "not_applicable_observation"
  ]
}
''')


ADMITTED_DESCRIPTOR_CONTRACTS = json.loads(r'''
{
  "azure.encryption.automation_cmk_declared": {
    "label": "Automation declares a customer-managed key reference and attached system identity",
    "limit": "Key authorization and cryptographic use were not tested.",
    "manual_observation": "Complete native CMK reference and attached identity metadata was unavailable, unsupported or unbound.",
    "missing_observation": "Complete native CMK reference and attached identity metadata was unavailable, unsupported or unbound.",
    "not_applicable_observation": "No applicable resource was found.",
    "purpose": "The reference selects the intended asset-encryption key.",
    "review_group": "encryption"
  },
  "azure.encryption.log_analytics_cluster_cmk_declared": {
    "label": "Log Analytics cluster declares a customer-managed key and managed identity",
    "limit": "Declared configuration only; effective access and delivery were not tested.",
    "manual_observation": "Complete native resource configuration and source binding were unavailable.",
    "missing_observation": "Complete native resource configuration and source binding were unavailable.",
    "not_applicable_observation": "No applicable resource was found.",
    "purpose": "Key and identity declarations identify the intended customer-managed encryption configuration.",
    "review_group": "encryption"
  },
  "azure.encryption.stream_analytics_job_storage_cmk_declared": {
    "label": "External Stream Analytics job storage declares customer-managed encryption",
    "limit": "Key access and stored-data encryption were not tested.",
    "manual_observation": "Complete native resource configuration and source binding were unavailable.",
    "missing_observation": "Complete native resource configuration and source binding were unavailable.",
    "not_applicable_observation": "No applicable resource was found.",
    "purpose": "The job selects this account for content storage.",
    "review_group": "encryption"
  },
  "azure.logging.aci_log_analytics_declared": {
    "label": "Container groups declare a Log Analytics customer UUID and supported log type",
    "limit": "Workspace existence, access, ingestion and log delivery were not tested.",
    "manual_observation": "Complete native workspace customer UUID and log type metadata was unavailable, unsupported or unbound.",
    "missing_observation": "Complete native workspace customer UUID and log type metadata was unavailable, unsupported or unbound.",
    "not_applicable_observation": "No applicable resource was found.",
    "purpose": "Log Analytics settings identify the intended destination for container-group logs.",
    "review_group": "logging"
  },
  "azure.logging.aks_supported_log_categories_destination_declared": {
    "label": "AKS declares supported log categories to diagnostic destinations",
    "limit": "Declared configuration only; effective access and delivery were not tested.",
    "manual_observation": "Complete native diagnostic configuration and source binding were unavailable or unsupported.",
    "missing_observation": "Complete native diagnostic configuration and source binding were unavailable or unsupported.",
    "not_applicable_observation": "No applicable resource was found.",
    "purpose": "Control-plane logging declares where audit events should go.",
    "review_group": "logging"
  },
  "azure.logging.managed_hsm_audit_destination_declared": {
    "label": "Managed HSM declares AuditEvent logging to Storage or Log Analytics",
    "limit": "Declared configuration only; effective access and delivery were not tested.",
    "manual_observation": "Complete native diagnostic configuration and source binding were unavailable or unsupported.",
    "missing_observation": "Complete native diagnostic configuration and source binding were unavailable or unsupported.",
    "not_applicable_observation": "No applicable resource was found.",
    "purpose": "Control-plane logging declares where audit events should go.",
    "review_group": "logging"
  },
  "azure.network.acr_public_ip_ranges_restricted": {
    "label": "ACR public network rules do not allow every IPv4 address",
    "limit": "Authentication, private routing and effective access were not tested.",
    "manual_observation": "The native configuration is unresolved.",
    "missing_observation": "Complete bound native configuration was unavailable.",
    "not_applicable_observation": "No applicable resource was found.",
    "purpose": "VNet rules can coexist with unrestricted public IP exceptions.",
    "review_group": "network"
  },
  "azure.review.acr.selected_image_secret_indicators": {
    "label": "Selected immutable ACR images have no detected secrets",
    "limit": "Only selected content was inspected; credentials were not tested.",
    "missing_observation": "The selected ACR image could not be completely read, bound and scanned with both offline detectors.",
    "purpose": "Offline checks detect potential credential leaks.",
    "review_group": "secrets"
  },
  "azure.review.ai_services.audit_logging": {
    "label": "AI Services configures supported audit logs to a destination",
    "limit": "Delivery and retention were not tested.",
    "manual_observation": "Configuration applicability requires review.",
    "missing_observation": "Required account configuration could not be completely read.",
    "not_applicable_observation": "No supported applicable deployment was found.",
    "purpose": "Audit logging supports investigation.",
    "review_group": "logging"
  },
  "azure.review.ai_services.managed_identity": {
    "label": "AI Services declares a managed identity",
    "limit": "Role assignments were not assessed.",
    "manual_observation": "Configuration applicability requires review.",
    "missing_observation": "Required account configuration could not be completely read.",
    "not_applicable_observation": "No supported applicable deployment was found.",
    "purpose": "Managed identities avoid stored application credentials.",
    "review_group": "permissions"
  },
  "azure.review.ai_services.outbound_restriction": {
    "label": "AI Services declares restricted outbound network access",
    "limit": "Allowed destinations and traffic were not tested.",
    "manual_observation": "Configuration applicability requires review.",
    "missing_observation": "Required account configuration could not be completely read.",
    "not_applicable_observation": "No supported applicable deployment was found.",
    "purpose": "Restricted egress limits external connections.",
    "review_group": "network"
  },
  "azure.review.ai_services.prompt_shield": {
    "label": "Text deployments explicitly configure blocking Prompt Shields",
    "limit": "Actual prompt traffic was not tested.",
    "manual_observation": "Configuration applicability requires review.",
    "missing_observation": "Required account configuration could not be completely read.",
    "not_applicable_observation": "No supported applicable deployment was found.",
    "purpose": "Prompt Shields filter supported prompt attacks.",
    "review_group": "workload_hardening"
  },
  "azure.review.app_configuration.selected_value_secret_indicators": {
    "label": "Selected App Configuration literal values have no detected secrets",
    "limit": "Key Vault references and unselected keys are not inspected.",
    "manual_observation": "Selected public literals were unavailable, unbound, protected or incompletely inspected. A clean result cannot be established.",
    "missing_observation": "Selected public literals were unavailable, unbound, protected or incompletely inspected. A clean result cannot be established.",
    "not_applicable_observation": "No selected supported public literal was returned.",
    "purpose": "Only the selected App Configuration key and label are scanned.",
    "review_group": "secrets"
  },
  "azure.review.app_service.selected_app_settings_secret_indicators": {
    "binding": null,
    "label": "Selected App Service and Function literal app settings have no detected secrets",
    "limit": "Only selected content was inspected; credentials were not tested.",
    "missing_observation": "Selected supported literal settings could not be completely read, bound and scanned with both offline detectors.",
    "purpose": "Offline checks detect potential credential leaks.",
    "renderer": "native",
    "review_group": "secrets",
    "title": "Selected App Service and Function literal app settings have no detected secrets"
  },
  "azure.review.application_insights.selected_trace_sample_secret_indicators": {
    "label": "Selected Application Insights trace samples have no detected secrets",
    "limit": "",
    "manual_observation": "The selected message sample was unavailable, empty, unbound or incompletely inspected. A clean sample result cannot be established.",
    "missing_observation": "The selected message sample was unavailable, empty, unbound or incompletely inspected. A clean sample result cannot be established.",
    "not_applicable_observation": "No selected supported public literal was returned.",
    "purpose": "Only the selected preceding-hour message sample is covered.",
    "review_group": "secrets"
  },
  "azure.review.configuration.selected_content_secret_indicators": {
    "label": "Selected Azure ARM configuration and code literals have no detected secrets",
    "limit": "Protected, encrypted and referenced content is excluded.",
    "manual_observation": "The selected Azure content could not be completely read, identity-bound and scanned.",
    "missing_observation": "The selected Azure content could not be completely read, identity-bound and scanned.",
    "not_applicable_observation": "No selected supported literal content was returned.",
    "purpose": "Only explicitly selected source or configuration literals are scanned.",
    "review_group": "secrets"
  },
  "azure.review.data_factory.selected_declaration_secret_indicators": {
    "label": "Selected Data Factory inline declarations have no detected secrets",
    "limit": "Protected values, linked services and referenced code are not inspected.",
    "manual_observation": "Selected public literals were unavailable, unbound, protected or incompletely inspected. A clean result cannot be established.",
    "missing_observation": "Selected public literals were unavailable, unbound, protected or incompletely inspected. A clean result cannot be established.",
    "not_applicable_observation": "No selected supported public literal was returned.",
    "purpose": "Only the selected Data Factory inline declarations are scanned.",
    "review_group": "secrets"
  },
  "azure.review.databricks.selected_notebook_source_secret_indicators": {
    "label": "Selected Databricks notebook source has no detected secrets",
    "limit": "",
    "manual_observation": "The selected notebook source could not be fully inspected; no clean result is established.",
    "missing_observation": "The selected notebook source could not be fully inspected; no clean result is established.",
    "not_applicable_observation": "No supported selected notebook source were inspected.",
    "purpose": "Only the selected point-in-time notebook export is covered.",
    "review_group": "secrets"
  },
  "azure.review.devops.selected_content_secret_indicators": {
    "label": "Selected Azure DevOps source and pipeline literals have no detected secrets",
    "limit": "Only selected file commits and pipeline revisions are assessed.",
    "manual_observation": "Selected Azure DevOps literal content was unavailable, unbound or incompletely inspected. A clean result cannot be established.",
    "missing_observation": "Selected Azure DevOps literal content was unavailable, unbound or incompletely inspected. A clean result cannot be established.",
    "not_applicable_observation": "No selected supported literal content was returned.",
    "purpose": "Only explicitly selected source or configuration literals are scanned.",
    "review_group": "secrets"
  },
  "azure.review.devops.visible_clone_urls_without_userinfo": {
    "label": "Visible selected Azure DevOps clone URLs do not contain userinfo",
    "limit": "Hidden repositories and credential validity were not assessed.",
    "manual_observation": "Complete selected-project clone URL metadata was unavailable.",
    "missing_observation": "Complete selected-project clone URL metadata was unavailable.",
    "not_applicable_observation": "No visible selected repository URL metadata was returned.",
    "purpose": "Only selected projects and visible URL metadata are assessed.",
    "review_group": "secrets"
  },
  "azure.review.function.application_insights_setting_declared": {
    "label": "Selected Function declares an Application Insights setting",
    "limit": "",
    "manual_observation": "The selected Function configuration could not be established.",
    "missing_observation": "The selected Function configuration could not be established.",
    "not_applicable_observation": "This Function hosting model does not use the assessed declaration.",
    "purpose": "Only the selected Function configuration is assessed.",
    "review_group": "monitoring"
  },
  "azure.review.function.runtime_major4_update_channel_declared": {
    "label": "Selected classic Function declares the automatic major4 runtime update channel",
    "limit": "",
    "manual_observation": "The selected Function configuration could not be established.",
    "missing_observation": "The selected Function configuration could not be established.",
    "not_applicable_observation": "This Function hosting model does not use the assessed declaration.",
    "purpose": "Only the selected Function configuration is assessed.",
    "review_group": "patching"
  },
  "azure.review.function.selected_package_source_secret_indicators": {
    "limit": "executed app bytes remain unknown.",
    "missing_observation": "The selected configured package could not be completely read, identity-bound and scanned.",
    "purpose": "This covers stored ZIP text;"
  },
  "azure.review.log_analytics.query_storage_cmk_declared": {
    "label": "Query-linked workspace storage declares customer-managed Table encryption",
    "limit": "",
    "manual_observation": "The required native configuration could not be established.",
    "missing_observation": "The required native configuration could not be established.",
    "not_applicable_observation": "No existing supported association or Query-linked store was collected.",
    "purpose": "Only existing Query-linked storage declarations are assessed.",
    "review_group": "encryption"
  },
  "azure.review.log_analytics.selected_message_sample_secret_indicators": {
    "label": "Selected Log Analytics message samples have no detected secrets",
    "limit": "",
    "manual_observation": "The selected message sample was unavailable, empty, unbound or incompletely inspected. A clean sample result cannot be established.",
    "missing_observation": "The selected message sample was unavailable, empty, unbound or incompletely inspected. A clean sample result cannot be established.",
    "not_applicable_observation": "No selected supported public literal was returned.",
    "purpose": "Only the selected preceding-hour message sample is covered.",
    "review_group": "secrets"
  },
  "azure.review.machine_learning.selected_code_file_secret_indicators": {
    "label": "Selected ML code source files have no detected secrets",
    "limit": "",
    "manual_observation": "The selected ML asset text could not be fully inspected; no clean result is established.",
    "missing_observation": "The selected ML asset text could not be fully inspected; no clean result is established.",
    "not_applicable_observation": "No supported selected ML asset text was inspected.",
    "purpose": "Only the selected captured code file is covered.",
    "review_group": "secrets"
  },
  "azure.review.machine_learning.selected_command_job_secret_indicators": {
    "label": "Selected Machine Learning Command-job literals have no detected secrets",
    "limit": "",
    "manual_observation": "The selected Command-job literals could not be fully inspected; no clean result is established.",
    "missing_observation": "The selected Command-job literals could not be fully inspected; no clean result is established.",
    "not_applicable_observation": "No supported selected Command-job literals were inspected.",
    "purpose": "Only returned Command-job literals are covered.",
    "review_group": "secrets"
  },
  "azure.review.machine_learning.selected_environment_conda_secret_indicators": {
    "label": "Selected ML environment Conda literals have no detected secrets",
    "limit": "",
    "manual_observation": "The selected ML asset text could not be fully inspected; no clean result is established.",
    "missing_observation": "The selected ML asset text could not be fully inspected; no clean result is established.",
    "not_applicable_observation": "No supported selected ML asset text was inspected.",
    "purpose": "Only returned inline Conda text is covered.",
    "review_group": "secrets"
  },
  "azure.review.managed_hsm.audit_storage_destination": {
    "label": "Managed HSM declares AuditEvent logging to Azure Storage",
    "limit": "Destination existence, delivery and retention were not tested.",
    "manual_observation": "The native configuration is unresolved.",
    "missing_observation": "Complete bound native configuration was unavailable.",
    "not_applicable_observation": "No applicable resource was found.",
    "purpose": "AuditEvent logging supports investigation of Managed HSM access.",
    "review_group": "logging"
  },
  "azure.review.network.perimeter_association_enforced": {
    "label": "Storage resource declares an enforced network perimeter association",
    "limit": "",
    "manual_observation": "The required native configuration could not be established.",
    "missing_observation": "The required native configuration could not be established.",
    "not_applicable_observation": "No existing supported association or Query-linked store was collected.",
    "purpose": "Only the declared Storage perimeter association is assessed.",
    "review_group": "network"
  },
  "azure.review.storage.blocking_sas_expiry_policy_declared": {
    "label": "Storage account declares a blocking SAS expiration policy",
    "limit": "",
    "manual_observation": "The storage-account read or SAS policy fields could not be established.",
    "missing_observation": "The storage-account read or SAS policy fields could not be established.",
    "not_applicable_observation": "No applicable storage account was collected.",
    "purpose": "This checks the declared policy, not issued tokens or SAS types exempt from its enforcement.",
    "review_group": "secrets"
  },
  "azure.review.storage.selected_source_secret_indicators": {
    "label": "Selected Azure stored source objects have no detected secrets",
    "limit": "Only the captured supported text files are assessed.",
    "manual_observation": "Selected stored source content was unavailable, unbound, unsupported or incompletely inspected. A clean result cannot be established.",
    "missing_observation": "Selected stored source content was unavailable, unbound, unsupported or incompletely inspected. A clean result cannot be established.",
    "not_applicable_observation": "No selected supported literal content was returned.",
    "purpose": "Only explicitly selected source or configuration literals are scanned.",
    "review_group": "secrets"
  },
  "azure.review.synapse.selected_pipeline_secret_indicators": {
    "label": "Selected Synapse pipeline inline declarations have no detected secrets",
    "limit": "Protected values and referenced code are not inspected.",
    "manual_observation": "Selected public literals were unavailable, unbound, protected or incompletely inspected. A clean result cannot be established.",
    "missing_observation": "Selected public literals were unavailable, unbound, protected or incompletely inspected. A clean result cannot be established.",
    "not_applicable_observation": "No selected supported public literal was returned.",
    "purpose": "Only the selected Synapse pipeline declarations are scanned.",
    "review_group": "secrets"
  }
}
''')


# Coordinator-approved exact successor contract; historical 969 IDs retain <=240.
LATER_NATIVE_NEUTRAL_LENGTHS = {'azure.encryption.log_analytics_cluster_cmk_declared': {'missing_observation': 246, 'manual_observation': 246}, 'azure.logging.aci_log_analytics_declared': {'missing_observation': 258, 'manual_observation': 258}, 'azure.review.app_configuration.selected_value_secret_indicators': {'missing_observation': 249, 'manual_observation': 249}, 'azure.review.data_factory.selected_declaration_secret_indicators': {'missing_observation': 263, 'manual_observation': 263}, 'azure.review.devops.selected_content_secret_indicators': {'missing_observation': 262, 'manual_observation': 262}, 'azure.review.storage.selected_source_secret_indicators': {'missing_observation': 257, 'manual_observation': 257}, 'azure.review.synapse.selected_pipeline_secret_indicators': {'missing_observation': 243, 'manual_observation': 243}}
