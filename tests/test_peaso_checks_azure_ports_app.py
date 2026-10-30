"""App kind/FTPS/category boundaries; no secret-containing configuration calls."""
import copy
import json
from pathlib import Path
import re

import pytest

from peaso.checks import CHECKS, azure_ports_app as ports
from peaso.checks.fixtures import CASES

ROOT = Path(__file__).resolve().parent.parent
REVIEWS = json.loads((ROOT / 'peaso/rulepacks/reviewed_azure_ports_app.json').read_text())
REGISTRY = {c.id: c for c in CHECKS}
PROOFS = {r['source_review']['query_id']: r['source_review'] for r in REVIEWS.values() if 'status_case_sql' in r['source_review']}


@pytest.mark.parametrize('cid', ports.CHECK_IDS)
def test_app_native_pass_fail_unavailable_denied_partial_malformed_and_purity(cid):
    for label, expected in (('pass', 'PASS'), ('fail', 'FAIL')):
        item = copy.deepcopy(CASES[cid][label]); original = copy.deepcopy(item)
        assert REGISTRY[cid].evaluate(item, {})[0] == expected
        assert item == original
    for item in ({}, None, [], {'collection_status': 'denied'}, {'collection_status': 'partial'}):
        assert REGISTRY[cid].evaluate(item, {})[0] == 'UNKNOWN'
    item = copy.deepcopy(CASES[cid]['pass'])
    field = 'authSettingsV2' if 'authSettingsV2' in item else 'configuration' if 'configuration' in item else 'diagnosticSettings' if 'diagnosticSettings' in item else 'properties'
    item['_coverage'] = {field: {'status': 'denied'}}
    assert REGISTRY[cid].evaluate(item, {})[0] == 'UNKNOWN'


@pytest.mark.parametrize('query', PROOFS)
def test_source_status_case_truth_for_exact_app_declarations(query):
    duckdb = pytest.importorskip('duckdb')
    for original in PROOFS[query]['status_case_sql']:
        case = original.replace('ds.id', 'matching_diag_id')
        case = re.sub(r'\b[a-z_]+\.(\w+)\b', r'\1', case)
        case = re.sub(r"(\w+(?:\s*->>?\s*'[^']+')+)\s*=", r'(\1) =', case)
        for good in (True, False):
            if query == 'appservice_web_app_incoming_client_cert_on': cols = {'client_cert_enabled': good}
            elif query == 'appservice_ftp_deployment_disabled': cols = {'configuration': {'properties': {'ftpsState': 'FtpsOnly' if good else 'AllAllowed'}}}
            elif query == 'appservice_web_app_remote_debugging_disabled': cols = {'kind': 'app', 'configuration': {'properties': {'remoteDebuggingEnabled': not good}}}
            else: cols = {'matching_diag_id': '/diagnostic' if good else None}
            defs, values = [], []
            for key, value in cols.items():
                defs.append('?' + ('::JSON' if isinstance(value, dict) else '') + ' AS ' + key)
                values.append(json.dumps(value) if isinstance(value, dict) else value)
            with duckdb.connect(':memory:') as db:
                assert db.execute('SELECT ' + case + ' FROM (SELECT ' + ','.join(defs) + ')', values).fetchone()[0] == ('ok' if good else 'alarm')


def test_exact_kind_filters_are_not_prefix_or_comma_token_merges():
    cert = REGISTRY[ports.SOURCE_QUERIES['appservice_web_app_incoming_client_cert_on']]
    assert cert.evaluate({'kind': 'functionapp'}, {})[0] == 'NOT_APPLICABLE'
    assert cert.evaluate({'kind': 'functionapp,linux', 'properties': {'clientCertEnabled': True}}, {})[0] == 'PASS'
    debug = REGISTRY[ports.SOURCE_QUERIES['appservice_web_app_remote_debugging_disabled']]
    assert debug.evaluate({'kind': 'api'}, {})[0] == 'NOT_APPLICABLE'
    assert debug.evaluate({'kind': 'api,linux', 'configuration': {'properties': {'remoteDebuggingEnabled': True}}}, {})[0] == 'FAIL'
    ftp = REGISTRY[ports.SOURCE_QUERIES['appservice_ftp_deployment_disabled']]
    for kind in ('app', 'api', 'functionapp', 'functionapp,linux'):
        assert ftp.evaluate({'kind': kind, 'configuration': {'properties': {'ftpsState': 'Disabled'}}}, {})[0] == 'PASS'


def test_http_category_group_is_not_literal_category_and_foreign_ids_or_denied_logs_are_unknown():
    check = REGISTRY[ports.SOURCE_QUERIES['appservice_web_app_diagnostic_log_category_http_log_enabled']]
    item = copy.deepcopy(CASES[check.id]['pass'])
    log = item['diagnosticSettings'][0]['properties']['logs'][0]
    log.clear(); log.update(categoryGroup='allLogs', enabled=True)
    assert check.evaluate(item, {})[0] == 'FAIL'
    log.update(category='AppServiceHTTPLogs', _coverage={'category': {'status': 'denied'}})
    assert check.evaluate(item, {})[0] == 'UNKNOWN'
    item = copy.deepcopy(CASES[check.id]['pass'])
    item['diagnosticSettings'][0]['id'] = item['diagnosticSettings'][0]['id'].replace('/group/', '/other/')
    assert check.evaluate(item, {})[0] == 'UNKNOWN'


def test_pinned_auth_module_scope_and_flag_do_not_claim_request_enforcement():
    check = REGISTRY[ports.SOURCE_QUERIES['prowler_app_auth_platform_enabled']]
    assert check.evaluate({'kind': 'api'}, {})[0] == 'NOT_APPLICABLE'
    item = {'kind': 'app,linux', 'authSettingsV2': {'properties': {'platform': {'enabled': True}, 'globalValidation': {'requireAuthentication': False}}}}
    assert check.evaluate(item, {})[0] == 'PASS'
    item['authSettingsV2']['properties']['platform']['enabled'] = False
    assert check.evaluate(item, {})[0] == 'FAIL'
    assert 'app_ensure_auth_is_set_up' in next(r['source_review']['pinned_evaluator'] for r in REVIEWS.values() if r['source_review']['query_id'] == 'app_ensure_auth_is_set_up')
