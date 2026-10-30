"""Literal legacy/VNet retention boundaries, scope completeness and pinned SQL truth."""
import copy
import json
from pathlib import Path
import re

import pytest

from peaso.checks import CHECKS, azure_ports_network as ports
from peaso.checks.fixtures import CASES

ROOT = Path(__file__).resolve().parent.parent
REVIEWS = json.loads((ROOT / 'peaso/rulepacks/reviewed_azure_ports_network.json').read_text())
REGISTRY = {check.id: check for check in CHECKS}
PROOFS = {row['source_review']['query_id']: row['source_review'] for row in REVIEWS.values()}


@pytest.mark.parametrize('cid', ports.CHECK_IDS)
def test_native_network_pass_fail_missing_denied_partial_malformed_and_purity(cid):
    fixture = CASES[cid]
    for label, expected in (('pass', 'PASS'), ('fail', 'FAIL')):
        item, index = copy.deepcopy(fixture[label]), copy.deepcopy(fixture.get(label + '_index', {}))
        before = copy.deepcopy((item, index))
        assert REGISTRY[cid].evaluate(item, index)[0] == expected
        assert (item, index) == before
    for item in ({}, None, [], {'collection_status': 'denied'}, {'collection_status': 'partial'}):
        assert REGISTRY[cid].evaluate(item, {})[0] == 'UNKNOWN'
    if 'pass_index' in fixture:
        index = copy.deepcopy(fixture['pass_index'])
        for state in ('denied', 'partial', 'malformed', 'not_collected'):
            for envelopes in index['collections'].values(): envelopes[0]['status'] = state
            assert REGISTRY[cid].evaluate(fixture['pass'], index)[0] == 'UNKNOWN'


@pytest.mark.parametrize('query', PROOFS)
def test_source_sql_case_truth_matches_distinct_retention_and_presence_rules(query):
    duckdb = pytest.importorskip('duckdb')
    case = PROOFS[query]['status_case_sql'].replace('fl.id', 'flow_id').replace('i.subscription_id', 'host_subscription')
    case = re.sub(r'\b[a-z_]+\.(\w+)\b', r'\1', case)
    for label in ('pass', 'fail'):
        if query == 'network_bastion_host_min_1': columns = {'host_subscription': 'sub' if label == 'pass' else None}
        elif query.startswith('network_sg_'): columns = {'flow_id': ports.FLOW_ID, 'enabled': True, 'retention_policy_days': 90 if label == 'pass' else 89}
        else: columns = {'target_resource_id': ports.VNET_ID, 'enabled': True, 'retention_policy_days': 0 if label == 'pass' else 89}
        with duckdb.connect(':memory:') as db:
            assert db.execute('SELECT ' + case + ' FROM (SELECT ' + ','.join('? AS ' + key for key in columns) + ')', list(columns.values())).fetchone()[0] == ('ok' if label == 'pass' else 'alarm')


def test_zero_retention_is_source_distinct_not_a_broad_merge_or_future_retirement_rejection():
    nsg = REGISTRY[ports.SOURCE_QUERIES['network_sg_flowlog_retention_period_greater_than_90']]
    vnet = REGISTRY[ports.SOURCE_QUERIES['network_virtual_network_watcher_flow_log_retention_90_days']]
    for days, nsg_expected, vnet_expected in ((0, 'FAIL', 'PASS'), (89, 'FAIL', 'FAIL'), (90, 'PASS', 'PASS'), (365, 'PASS', 'PASS'), (-1, 'UNKNOWN', 'UNKNOWN'), (True, 'UNKNOWN', 'UNKNOWN')):
        assert nsg.evaluate({'id': ports.NSG_ID}, ports._fixture('flow_log', [ports._flow(ports.NSG_ID, days)]))[0] == nsg_expected
        assert vnet.evaluate(ports._flow(ports.VNET_ID, days), {})[0] == vnet_expected
    assert nsg.evaluate({'id': ports.NSG_ID}, ports._fixture('flow_log', [], 'empty'))[0] == 'FAIL'
    assert vnet.evaluate(ports._flow(ports.NSG_ID), {})[0] == 'NOT_APPLICABLE'


def test_full_target_ids_prevent_same_name_flow_join_and_all_joined_rows_must_satisfy_source():
    check = REGISTRY[ports.SOURCE_QUERIES['network_sg_flowlog_retention_period_greater_than_90']]
    foreign = ports._flow(ports.NSG_ID.replace('/group/', '/other/'))
    assert check.evaluate({'id': ports.NSG_ID}, ports._fixture('flow_log', [foreign]))[0] == 'FAIL'
    first, second = ports._flow(ports.NSG_ID, 90), ports._flow(ports.NSG_ID, 30)
    second['id'] += '2'
    assert check.evaluate({'id': ports.NSG_ID}, ports._fixture('flow_log', [first, second]))[0] == 'FAIL'
    assert check.evaluate({'id': ports.NSG_ID}, ports._fixture('flow_log', [ports._flow(ports.NSG_ID, 90, False)]))[0] == 'FAIL'


def test_bastion_anchor_excludes_tenants_and_denies_foreign_subscription_rows():
    check = REGISTRY[ports.SOURCE_QUERIES['network_bastion_host_min_1']]
    assert check.evaluate({'scope': '/tenants/tenant'}, {})[0] == 'NOT_APPLICABLE'
    assert check.evaluate({'scope': ports.SUB}, ports._fixture('bastion_host', [{'id': '/subscriptions/other/resourceGroups/g/providers/Microsoft.Network/bastionHosts/b'}]))[0] == 'UNKNOWN'
