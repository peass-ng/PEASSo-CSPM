"""Plain Azure copy must be tied to the reviewed native witness."""

import gzip
import json
from pathlib import Path

from peaso.checks.azure_evidence_explanations import _plain_observation


ROOT = Path(__file__).resolve().parents[1]
RULES = json.loads((ROOT / 'peaso/checks/azure_observed_evidence_rules.json').read_text())
FIXTURES = json.loads(gzip.open(ROOT / 'tests/fixtures/azure_evidence_review.json.gz', 'rt').read())
FIXTURES.update(json.loads((ROOT / 'tests/fixtures/azure-functions-declaration-evidence-review-20261020.json').read_text()))
FIXTURES.update(json.loads((ROOT / 'tests/fixtures/azure-nsp-query-declaration-evidence-review-20261020.json').read_text()))


def test_plain_rule_needs_its_exact_recorded_field():
    check_id = 'azure.claude.servicefabric_cluster_encrypt_and_sign'
    expected = RULES[check_id]['fail']
    finding = {'check_id': check_id, 'status': 'FAIL',
               'evidence': {'cluster_protection_level': 'None'}}
    assert _plain_observation(finding) == '\n'.join(expected)
    assert _plain_observation({**finding, 'evidence': {}}) is None


def test_browser_and_server_use_the_same_reviewed_copy():
    frontend = ROOT / 'frontend/src/azureObservedEvidenceRules.json'
    assert json.loads(frontend.read_text()) == RULES


def test_common_missing_fact_paths_name_the_recorded_field():
    labels = json.loads((ROOT / 'peaso/checks/azure_missing_fact_labels.json').read_text())
    browser = json.loads((ROOT / 'frontend/src/azureMissingFactLabels.json').read_text())
    assert labels == browser
    for path, first_line in labels.items():
        summary = _plain_observation({'check_id': 'azure.any', 'status': 'UNKNOWN',
                                      'evidence': {'reason': 'missing fact: ' + path}})
        assert summary.splitlines()[0] == first_line
        assert len(summary.splitlines()) == 3


def test_related_resource_copy_names_the_recorded_dependency():
    labels = json.loads((ROOT / 'peaso/checks/azure_dependency_labels.json').read_text())
    browser = json.loads((ROOT / 'frontend/src/azureDependencyLabels.json').read_text())
    assert labels == browser
    for key, label in labels.items():
        for prefix in ('dependency incomplete or unavailable: ', 'dependency not collected: '):
            summary = _plain_observation({'check_id': 'azure.any', 'status': 'UNKNOWN',
                                          'evidence': {'reason': prefix + key}})
            assert summary.splitlines()[0].startswith('The related ' + label + ' record ')
            assert len(summary.splitlines()) == 3


def test_not_applicable_copy_uses_an_exact_recorded_reason():
    reasons = json.loads((ROOT / 'peaso/checks/azure_not_applicable_evidence.json').read_text())
    browser = json.loads((ROOT / 'frontend/src/azureNotApplicableEvidence.json').read_text())
    assert reasons == browser
    for reason, lines in reasons.items():
        assert len(lines) == 3
        assert _plain_observation({'check_id': 'azure.any', 'status': 'NOT_APPLICABLE',
                                   'evidence': {'reason': reason}}) == '\n'.join(lines)
    assert _plain_observation({'check_id': 'azure.any', 'status': 'NOT_APPLICABLE',
                               'evidence': {'reason': 'other reason'}}) is None


def test_incomplete_copy_uses_only_recorded_reason_classes():
    reasons = json.loads((ROOT / 'peaso/checks/azure_incomplete_evidence_reasons.json').read_text())
    browser = json.loads((ROOT / 'frontend/src/azureIncompleteEvidenceReasons.json').read_text())
    assert reasons == browser
    for reason in reasons['exact']:
        summary = _plain_observation({'check_id': 'azure.any', 'status': 'UNKNOWN',
                                      'evidence': {'reason': reason}})
        assert summary.splitlines()[0] == reasons['exact'][reason]
        assert len(summary.splitlines()) == 3
        assert ' may ' not in summary and ' could ' not in summary.replace('could not', 'was unable to')
    for prefix in reasons['prefixes']:
        summary = _plain_observation({'check_id': 'azure.any', 'status': 'UNKNOWN',
                                      'evidence': {'reason': prefix + 'record ID'}})
        assert summary.splitlines()[0] == reasons['prefixes'][prefix]
        assert len(summary.splitlines()) == 3
        assert _plain_observation({'check_id': 'azure.any', 'status': 'UNKNOWN',
                                   'evidence': {'reason': prefix}}) is None


def test_native_applicability_copy_uses_recorded_vm_or_disk_type():
    cases = [
        ({'applies_to': 'Windows', 'os_type': 'Linux'}, 'This VM runs Linux.'),
        ({'applies_to': 'Linux', 'os_type': 'Windows'}, 'This VM runs Windows.'),
        ({'applies_to': 'attached', 'disk_state': 'Unattached'}, 'This disk is unattached.'),
        ({'applies_to': 'unattached', 'disk_state': 'Attached'}, 'This disk is attached.'),
    ]
    for evidence, first_line in cases:
        summary = _plain_observation({'check_id': 'azure.any', 'status': 'NOT_APPLICABLE',
                                      'evidence': evidence})
        assert summary.splitlines()[0] == first_line
        assert len(summary.splitlines()) == 3
    assert _plain_observation({'check_id': 'azure.any', 'status': 'NOT_APPLICABLE',
                               'evidence': {'applies_to': 'Linux', 'os_type': 'Linux'}}) is None


def test_activity_alert_copy_uses_exact_id_and_native_alert_witness():
    alerts = json.loads((ROOT / 'peaso/checks/azure_activity_alert_evidence.json').read_text())
    browser = json.loads((ROOT / 'frontend/src/azureActivityAlertEvidence.json').read_text())
    assert alerts == browser
    assert len(alerts) == 25
    for check_id in alerts:
        for row in FIXTURES[check_id]:
            if row['status'] not in ('PASS', 'FAIL'):
                continue
            summary = _plain_observation({'check_id': check_id, 'status': row['status'],
                                          'evidence': row['evidence']})
            assert summary and len(summary.splitlines()) == 3
            assert _plain_observation({'check_id': check_id, 'status': row['status'],
                                       'evidence': {'alert': '/wrong/path'}}) is None


def test_servicebus_network_copy_keeps_distinct_native_states():
    branches = json.loads((ROOT / 'peaso/checks/azure_servicebus_network_evidence.json').read_text())
    browser = json.loads((ROOT / 'frontend/src/azureServicebusNetworkEvidence.json').read_text())
    assert branches == browser
    check_id = 'azure.claude.servicebus_namespace_network_restricted'
    for row in FIXTURES[check_id]:
        if row['status'] not in ('PASS', 'FAIL'):
            continue
        finding = {'check_id': check_id, 'status': row['status'], 'evidence': row['evidence']}
        summary = _plain_observation(finding)
        if (row['status'] == 'FAIL' and row['evidence'].get('default_action') == 'Deny'
                and row['evidence'].get('ip_rule_count') == 0
                and row['evidence'].get('virtual_network_rule_count') == 0):
            assert summary is None
        else:
            assert summary and len(summary.splitlines()) == 3
    no_allow = next(item for item in branches if item['status'] == 'PASS'
                    and item['required'].get('default_action') == 'Deny')
    assert 'no allow rules' in no_allow['lines'][0]
    assert 'unwanted attempts' not in '\n'.join(no_allow['lines'])
