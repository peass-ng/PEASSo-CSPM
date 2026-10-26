"""Focused local ledger acceptance; retained snapshots never authorize cloud reads."""
from copy import deepcopy
import hashlib
import inspect
import json
from pathlib import Path
import re
import socket
import subprocess

import pytest
from peaso import engine
from peaso.checks import CHECKS
from peaso.checks.azure_evidence_explanations import ROWS, evidence_summary
from peaso.checks.catalog import description_for
from peaso.checks.native_only import exclusions
from peaso.checks import azure_function_package_integration_admission_20261020 as admission

ROOT = Path(__file__).resolve().parents[3]
CID = 'azure.review.function.selected_package_source_secret_indicators'
PREFIX = 'docs/check-review/azure-function-package-'
LEDGER = ROOT / (PREFIX + 'final-ledger-20261020.json')
CHECK = next(check for check in CHECKS if check.id == CID)


def read(path):
    return json.loads((ROOT / path).read_text())


def digest(value):
    return hashlib.sha256(value).hexdigest()


def verify_binding(binding):
    assert digest((ROOT / binding['path']).read_bytes()) == binding['sha256']


@pytest.fixture(autouse=True)
def prohibit_external_operations(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError('ledger acceptance cannot use network, cloud auth or scanners')
    for name in ('socket', 'create_connection', 'getaddrinfo'):
        monkeypatch.setattr(socket, name, forbidden)
    monkeypatch.setattr(subprocess, 'Popen', forbidden)


def test_current_predicate_public_brief_and_source_bound_branches():
    ledger = json.loads(LEDGER.read_text())
    row, = ledger['checks']
    evidence = read('docs/evidence-reviews/azure.json')[CID]
    function = inspect.unwrap(CHECK.evaluate)
    predicate = row['predicate']
    assert predicate['qualname'] == function.__module__ + '.' + function.__qualname__
    assert predicate['body_sha256'] == digest(inspect.getsource(function).encode()) == evidence['predicate_sha256']
    assert predicate['source_file_sha256'] == digest((ROOT / predicate['path']).read_bytes()) == evidence['source_sha256']
    assert row['kind'] == CHECK.kind == evidence['kind'] == 'azure_function_package_portable_20261020'
    assert row['category'] == CHECK.category == evidence['category'] == 'hardening'
    assert row['severity'] == CHECK.severity == evidence['severity'] == 'high'
    assert row['public_brief'] == ROWS[CID]
    assert evidence['interpretation'] == 'This covers stored ZIP text;'
    assert evidence['evidence_limit'] == 'executed app bytes remain unknown.'
    assert row['description_contract'] == description_for(CID)
    assert evidence['description_contract_sha256'] == digest(json.dumps(description_for(CID), sort_keys=True, separators=(',', ':')).encode())
    assert {branch['status'] for branch in evidence['branch_coverage']} == {'PASS', 'FAIL', 'UNKNOWN'}
    for branch in evidence['branch_coverage']:
        verify_binding(branch['receipt'])
        node = read(branch['receipt']['path'])
        for component in branch['record_path']:
            node = node[component]
        assert node['check_id'] == CID and node['status'] == branch['status']
        assert sorted(node['evidence']) == branch['evidence_fields']
        assert branch['predicate_sha256'] == predicate['body_sha256']


def test_existing_1001_rows_2017_bindings_and_26_errata_are_preserved():
    ledger = json.loads(LEDGER.read_text())
    evidence = read('docs/evidence-reviews/azure.json')
    del evidence[CID]
    conservation = ledger['conservation']
    assert len(evidence) == conservation['prior_azure_rows'] == 1001
    assert digest(json.dumps(evidence, sort_keys=True, separators=(',', ':')).encode()) == conservation['prior_azure_rows_canonical_sha256']
    for binding in conservation['preserved_inputs']:
        verify_binding(binding)
    old = read(conservation['preserved_inputs'][0]['path'])
    errata = read(old['current_master_attestation_errata'])
    assert len(old['checks']) == conservation['existing_azure_k8s_rows'] == 2017
    assert len(errata['records']) == conservation['explicit_master_errata'] == 26
    assert not conservation['historical_bindings_extended'] and not conservation['historical_binding_test_changed']
    azure = {check.id for check in CHECKS if check.provider == 'azure'}
    assert azure == evidence.keys() | {CID}
    assert ledger['counts'] == {'azure_registered_before': 1001, 'azure_registered': len(azure),
                               'azure_active': len(azure - exclusions().keys()),
                               'azure_excluded': len(azure & exclusions().keys())}
    assert ledger['counts']['azure_active'] == 713 and ledger['counts']['azure_excluded'] == 289


def test_final_acceptance_retains_exact_worker_proofs_and_separate_root_gates():
    acceptance = read(PREFIX + 'final-acceptance-20261020.json')
    verify_binding(acceptance['ledger'])
    ledger = json.loads(LEDGER.read_text())
    assert acceptance['checks'] == ledger['checks']
    for binding in ledger['evidence']:
        verify_binding(binding)
    worker = read(PREFIX + 'head3-current-acceptance-20261020.json')
    assert ledger['evidence'][0]['sha256'] == 'f469e368c07efb9c30b007d7b01e7d71651a5baf355f1d42d7a9e9e5f9b349c2'
    assert worker['acceptance']['distinct_passing_nodes'] == ledger['native_acceptance']['distinct_passing_nodes'] == 92
    assert worker['source_proof']['native_executing_function_bindings'] == 265
    assert worker['source_proof']['native_source_hash_count'] == 28
    assert ledger['native_acceptance']['test_counts_are_historical_witnesses_not_rerun_here']
    assert acceptance['root_remaining_gates'] and not acceptance['full_goal_complete'] and not acceptance['published_or_live']
    assert ledger['authorization']['default_off'] and ledger['authorization']['exact_named_check_required'] == CID
    assert ledger['authorization']['blob_data_actions'] == ['Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read']
    setup = (ROOT / 'docs/peaso-azure-selected-package-sources.md').read_text()
    for text in ('Accepted locally', 'off by default', CID, 'Microsoft.Web/sites/read',
                 'Microsoft.Web/sites/config/list/action', 'DataAction', 'supplied_snapshot_assertions',
                 'not_established', 'Kudu', 'mounted or executed'):
        assert text in setup


CAPTURES = read(PREFIX + 'integrated-public-native-20261020.json')['captures']


@pytest.mark.parametrize('capture', CAPTURES, ids=lambda capture: capture['name'])
def test_actual_public_capture_replays_json_only_and_keeps_brief_limits(capture):
    before = deepcopy(capture)
    snapshot = json.loads(json.dumps(capture['snapshot']))
    findings = engine.evaluate_snapshot(snapshot, checks=[CID])['findings']
    assert sorted(f['status'] for f in findings) == sorted(f['status'] for f in capture['findings'])
    for finding in findings:
        assert finding['check_id'] == CID
        evidence = finding['evidence']
        assertions = evidence.get('package_source_assertions', [evidence])
        for assertion in assertions:
            if 'context_provenance' in assertion:
                assert assertion['context_provenance'] == 'supplied_snapshot_assertions'
                assert assertion['cloud_authenticity'] == 'not_established'
                assert assertion['runtime_bytes'] == assertion['continuous_immutability'] == 'unknown'
        text = evidence_summary(finding)
        if finding['status'] in ('PASS', 'FAIL'):
            assert text and len(re.split(r'[.!?] +', text)) <= 3
        if finding['status'] == 'FAIL':
            assert 'not validated' in text
            if evidence.get('complete') is False:
                assert 'incomplete' in text
    assert capture == before


CASES = read('peaso/checks/azure_function_package_integration_cases_20261020.json')


@pytest.mark.parametrize('case', CASES, ids=lambda case: case['name'])
def test_nine_preserved_native_cases_bind_the_current_registered_predicate(case):
    item, index = admission.native_case(case)
    status, evidence = CHECK.evaluate(item, index)
    assert status == case['expected_status']
    if status in ('PASS', 'FAIL'):
        assert evidence['runtime_bytes'] == 'unknown'
        assert evidence['context_provenance'] == 'native_owner_retained_context'


def test_two_secret_dtos_keep_only_their_own_original_source_parts():
    capture = read(PREFIX + 'integrated-two-secret-native-20261020.json')['capture']
    original = {part['path']: part for collection in capture['snapshot']['collections']
                for item in collection['items'] for part in item['parts']}
    positives = capture['findings']
    assert len(positives) == len({f['secret_fingerprint'] for f in positives}) == 2
    for finding in positives:
        fingerprint = finding['secret_fingerprint']
        assert finding['status'] == 'FAIL' and len(finding['evidence']['secret_leaks']) == 1
        assertion, = finding['evidence']['package_source_assertions']
        for part in assertion['parts']:
            expected = deepcopy(original[part['path']])
            expected['leaks'] = [leak for leak in expected['leaks'] if leak['fingerprint'] == fingerprint]
            assert part == expected
            assert {leak['fingerprint'] for leak in part['leaks']} == {fingerprint}
        assert 'not validated' in evidence_summary(finding)
