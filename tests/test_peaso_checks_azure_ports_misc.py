"""Exact small service declarations and reused WAF/certificate metadata predicates."""
import copy
import json
from pathlib import Path
import re

import pytest

from peaso.checks import CHECKS, azure_ports_misc as ports
from peaso.checks.fixtures import CASES

ROOT = Path(__file__).resolve().parent.parent
REVIEWS = json.loads((ROOT / 'peaso/rulepacks/reviewed_azure_ports_misc.json').read_text())
REGISTRY = {c.id: c for c in CHECKS}
PROOFS = {r['source_review']['query_id']: r['source_review'] for r in REVIEWS.values()}


@pytest.mark.parametrize('query', ports.SOURCE_QUERIES)
def test_native_misc_supported_and_reused_pass_fail_unknown_denied_malformed_purity(query):
    cid = ports.SOURCE_QUERIES[query]
    fixtures = CASES[cid]
    for label, expected in (('pass', 'PASS'), ('fail', 'FAIL')):
        item = copy.deepcopy(fixtures[label]); before = copy.deepcopy(item)
        assert REGISTRY[cid].evaluate(item, {})[0] == expected
        assert item == before
    for item in ({}, None, [], {'collection_status': 'denied'}, {'collection_status': 'partial'}):
        assert REGISTRY[cid].evaluate(item, {})[0] == 'UNKNOWN'


@pytest.mark.parametrize('query', [q for q in PROOFS if q != 'web_application_firewall_policy_bot_protection_enabled'])
def test_pinned_scalar_condition_truth(query):
    duckdb = pytest.importorskip('duckdb')
    case = PROOFS[query]['status_case_sql'][0]
    case = re.sub(r'\b(?:a|p|b|batch|ag|sub)\.(\w+)\b', r'\1', case)
    case = re.sub(r"(\([^\n]+?\))::(?:bool|int)", r'CAST(\1 AS INTEGER)' if 'validity_months' in case else r'CAST(\1 AS BOOLEAN)', case)
    case = re.sub(r"(\w+(?:\s*->>?\s*'[^']+')+)\s*(=|is\s+not\s+null|in)", r'(\1) \2', case, flags=re.I)
    for good in (True, False):
        if query == 'application_gateway_http2_enabled': cols = {'enable_http2': good}
        elif query == 'batch_account_encrypted_with_cmk': cols = {'encryption': {'keySource': 'Microsoft.KeyVault' if good else 'Microsoft.Batch'}}
        elif query == 'apimanagement_service_client_certificate_enabled': cols = {'enable_client_certificate': good}
        elif query == 'batch_account_identity_provider_enabled': cols = {'identity': {'type': 'SystemAssigned' if good else 'None'}}
        elif query == 'application_insights_linked_to_log_analytics_workspace': cols = {'type': 'microsoft.insights/components', 'workspace_resource_id': '/workspace' if good else None}
        elif query == 'application_gateway_min_tls_1_2': cols = {'ssl_policy': {'minProtocolVersion': 'TLSv1_3' if good else 'TLSv1_1'}}
        elif query == 'keyvault_certificate_validity_period_less_equal_12_months': cols = {'x509_certificate_properties': {'validity_months': 12 if good else 13}}
        else: cols = {'policy_settings': {'requestBodyCheck': good}}
        defs, values = [], []
        for name, value in cols.items():
            defs.append('?' + ('::JSON' if isinstance(value, dict) else '') + ' AS ' + name)
            values.append(json.dumps(value) if isinstance(value, dict) else value)
        with duckdb.connect(':memory:') as db:
            assert db.execute('SELECT ' + case + ' FROM (SELECT ' + ','.join(defs) + ')', values).fetchone()[0] == ('ok' if good else 'alarm')


def test_bot_source_exact_sets_overrides_and_disabled_state_do_not_merge_other_rulesets():
    check = REGISTRY[ports.SOURCE_QUERIES['web_application_firewall_policy_bot_protection_enabled']]
    item = {'properties': {'managedRules': {'managedRuleSets': [{'ruleSetType': 'Microsoft_BotManagerRuleSet', 'ruleGroupOverrides': [{'rules': [{'state': 'Disabled', 'ruleId': '100'}]}]}]}}}
    assert check.evaluate(item, {})[0] == 'FAIL'
    item['properties']['managedRules']['managedRuleSets'][0]['ruleGroupOverrides'][0]['rules'][0]['state'] = 'Enabled'
    assert check.evaluate(item, {})[0] == 'PASS'


def test_default_tls_and_unrecognized_provider_metadata_cannot_pass_source_null_assumption():
    check = REGISTRY[ports.SOURCE_QUERIES['application_gateway_min_tls_1_2']]
    assert check.evaluate({'properties': {'sslPolicy': None}}, {})[0] == 'UNKNOWN'
    assert check.evaluate({'properties': {'sslPolicy': {'policyType': 'Predefined'}}}, {})[0] == 'UNKNOWN'
    assert check.evaluate({'properties': {'sslPolicy': {'minProtocolVersion': 'Future'}}}, {})[0] == 'UNKNOWN'
    workspace = REGISTRY[ports.SOURCE_QUERIES['application_insights_linked_to_log_analytics_workspace']]
    assert workspace.evaluate({'type': 'microsoft.insights/components', 'properties': {'_coverage': {'WorkspaceResourceId': {'status': 'denied'}}}}, {})[0] == 'UNKNOWN'
