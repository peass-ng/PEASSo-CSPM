"""SQL source-condition truth, exact parent IDs and known-empty configuration boundaries."""
import copy
import json
from pathlib import Path
import re

import pytest

from peaso.checks import CHECKS, azure_ports_sql as ports
from peaso.checks.fixtures import CASES

ROOT = Path(__file__).resolve().parent.parent
REVIEWS = json.loads((ROOT / 'peaso/rulepacks/reviewed_azure_ports_sql.json').read_text())
REGISTRY = {check.id: check for check in CHECKS}
PROOFS = {r['source_review']['query_id']: r['source_review'] for r in REVIEWS.values()}


@pytest.mark.parametrize('cid', ports.CHECK_IDS)
def test_sql_native_pass_fail_unknown_denied_malformed_and_purity(cid):
    fixture = CASES[cid]
    for label, expected in (('pass', 'PASS'), ('fail', 'FAIL')):
        item = copy.deepcopy(fixture[label]); original = copy.deepcopy(item)
        assert REGISTRY[cid].evaluate(item, {})[0] == expected
        assert item == original
    for item in ({}, None, [], {'collection_status': 'denied'}, {'collection_status': 'partial'}):
        assert REGISTRY[cid].evaluate(item, {})[0] == 'UNKNOWN'
    item = copy.deepcopy(fixture['pass']); field = next(key for key in item if key != 'id')
    item['_coverage'] = {field: {'status': 'denied'}}
    assert REGISTRY[cid].evaluate(item, {})[0] == 'UNKNOWN'


@pytest.mark.parametrize('query', PROOFS)
def test_pinned_sql_case_and_current_native_condition_truth(query):
    duckdb = pytest.importorskip('duckdb')
    case = re.sub(r'\b[a-z_]+\.(\w+)\b', r'\1', PROOFS[query]['status_case_sql'])
    case = re.sub(r"(\w+)\s*@>\s*('(?:[^']*)')", r'json_contains(\1, \2::JSON)', case)
    case = re.sub(r"(\w+(?:\s*->>?\s*'[^']+')+)\s*(=|is\s+not\s+null)", r'(\1) \2', case, flags=re.I)
    for good in (True, False):
        if query == 'sql_db_active_directory_admin_configured': cols = {'server_azure_ad_administrator': {} if good else None}
        elif query == 'sql_server_tde_protector_cmk_encrypted': cols = {'encryption': {'kind': 'azurekeyvault' if good else 'servicemanaged'}}
        elif query == 'sql_database_allow_internet_access': cols = {'firewall_rules': [{'properties': {'startIpAddress': '10.0.0.1' if good else '0.0.0.0', 'endIpAddress': '10.0.0.1' if good else '0.0.0.0'}}]}
        elif query == 'sql_server_atp_enabled': cols = {'security': {'properties': {'state': 'Enabled' if good else 'Disabled'}}}
        else: cols = {'public_network_access': 'Disabled' if good else 'Enabled'}
        defs, values = [], []
        for field, value in cols.items():
            defs.append('?' + ('::JSON' if isinstance(value, (dict, list)) else '') + ' AS ' + field)
            values.append(json.dumps(value) if isinstance(value, (dict, list)) else value)
        with duckdb.connect(':memory:') as db:
            assert db.execute('SELECT ' + case + ' FROM (SELECT ' + ','.join(defs) + ')', values).fetchone()[0] == ('ok' if good else 'alarm')


@pytest.mark.parametrize('cid', ports.CHECK_IDS)
def test_sql_foreign_parent_child_and_same_name_scope_never_certify_configuration(cid):
    item = copy.deepcopy(CASES[cid]['pass'])
    field = next(key for key in item if key != 'id')
    child = item[field][0] if isinstance(item[field], list) else item[field]
    child['id'] = child['id'].replace('/group/', '/other/')
    assert REGISTRY[cid].evaluate(item, {})[0] == 'UNKNOWN'
    item = copy.deepcopy(CASES[cid]['pass'])
    item['id'] = '/subscriptions/sub/resourceGroups/group/providers/Microsoft.Sql/managedInstances/server'
    assert REGISTRY[cid].evaluate(item, {})[0] == 'UNKNOWN'


def test_complete_empty_firewall_exclusion_passes_but_enabled_policy_empty_stays_unknown():
    firewall = REGISTRY[ports.SOURCE_QUERIES['sql_database_allow_internet_access']]
    alert = REGISTRY[ports.SOURCE_QUERIES['sql_server_atp_enabled']]
    assert firewall.evaluate({'id': ports.SERVER, 'firewallRules': []}, {})[0] == 'PASS'
    assert alert.evaluate({'id': ports.SERVER, 'securityAlertPolicies': []}, {})[0] == 'UNKNOWN'
    data = copy.deepcopy(CASES[alert.id]['pass']); data['securityAlertPolicies'][0]['properties']['state'] = 'FutureState'
    assert alert.evaluate(data, {})[0] == 'UNKNOWN'


def test_both_exact_firewall_sentinels_fail_and_malformed_intervals_are_unknown():
    check = REGISTRY[ports.SOURCE_QUERIES['sql_database_allow_internet_access']]
    item = copy.deepcopy(CASES[check.id]['fail']); props = item['firewallRules'][0]['properties']
    for end in ('0.0.0.0', '255.255.255.255'):
        props['endIpAddress'] = end
        assert check.evaluate(item, {})[0] == 'FAIL'
    props.update(startIpAddress='bad', endIpAddress='10.0.0.1')
    assert check.evaluate(item, {})[0] == 'UNKNOWN'
    props.update(startIpAddress='10.0.0.2', endIpAddress='10.0.0.1')
    assert check.evaluate(item, {})[0] == 'UNKNOWN'


def test_protector_portal_kind_and_key_type_cannot_disagree_or_use_historical_identity():
    check = REGISTRY[ports.SOURCE_QUERIES['sql_server_tde_protector_cmk_encrypted']]
    item = copy.deepcopy(CASES[check.id]['pass'])
    item['encryptionProtector']['properties']['serverKeyType'] = 'ServiceManaged'
    assert check.evaluate(item, {})[0] == 'UNKNOWN'
    item = copy.deepcopy(CASES[check.id]['pass']); item['encryptionProtector']['id'] += '-old'
    assert check.evaluate(item, {})[0] == 'UNKNOWN'


def test_duplicate_administrator_metadata_is_ambiguous_and_source_reviews_are_exclusive():
    check = REGISTRY[ports.SOURCE_QUERIES['sql_db_active_directory_admin_configured']]
    item = copy.deepcopy(CASES[check.id]['pass']); item['serverAdministrators'].append(copy.deepcopy(item['serverAdministrators'][0]))
    assert check.evaluate(item, {})[0] == 'UNKNOWN'


def test_documented_security_alert_policy_default_id_without_name_suffix_is_authoritative():
    check = REGISTRY[ports.SOURCE_QUERIES['sql_server_atp_enabled']]
    item = {'id': ports.SERVER, 'securityAlertPolicies': [{'id': ports.SERVER + '/securityAlertPolicies', 'name': 'Default', 'properties': {'state': 'Enabled'}}]}
    assert check.evaluate(item, {})[0] == 'PASS'
    item['securityAlertPolicies'][0]['name'] = 'foreign'
    assert check.evaluate(item, {})[0] == 'UNKNOWN'
