"""Conserve pinned source dispositions and their current individual native receipts.

This is source accounting, not a substitute for the native response matrices it
references. No historical source, fixture, predicate or review is rewritten.
"""
import csv
import hashlib
import inspect
import importlib
from copy import deepcopy

import pytest
import json
from collections import Counter
from pathlib import Path
import socket

from peaso.checks import CHECKS
from peaso.checks.native_only import exclusions
from tests.test_gcp_workbench_current_acceptance_20261020 import (
    JOB_ID, THEMATIC_IDS, current_thematic_admissions, checked_thematic_reference)

ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / 'docs/gcp-review/recheck-20261020/current-source-reconciliation-20261020.json'
REPORT_SHA256 = '603b9e467d9bc7eda42ad11228c0078c9b98101aa049e81217da363f659f444b'
CURRENT_RECEIPT = ROOT / 'docs/check-review/gcp-current-ledger-source-conservation-20261020.json'
CURRENT_RECEIPT_SHA256 = '3272cbf2d02fddd10ad9f2d1675ebba2e457e05d55efb6dabf22920cf1f9bc2c'
FUNCTION_ID = 'gcp.review.function.literal_environment_secret_indicators'


def _checked_json(reference):
    raw = (ROOT / reference['path']).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == reference['sha256'], reference['path']
    return json.loads(raw)


def current_conservation():
    raw = CURRENT_RECEIPT.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == CURRENT_RECEIPT_SHA256
    return json.loads(raw)


def _validate_current_function(erratum, check):
    assert erratum['check_id'] == check.id == FUNCTION_ID
    predicate = erratum['predicate']
    fn = inspect.unwrap(check.evaluate)
    assert predicate['qualname'] == fn.__module__ + '.' + fn.__qualname__
    assert predicate['body_sha256'] == hashlib.sha256(inspect.getsource(fn).encode()).hexdigest()
    assert predicate['file_sha256'] == hashlib.sha256((ROOT / predicate['path']).read_bytes()).hexdigest()
    _checked_json(erratum['integration_receipt'])
    _checked_json(erratum['current_public_dtos'])
    return fn



def _bound_functions(value, seen=None):
    """Follow actual wrappers/closed dispatch maps without executing a predicate."""
    seen = set() if seen is None else seen
    if inspect.isfunction(value):
        value = inspect.unwrap(value)
    if id(value) in seen:
        return
    seen.add(id(value))
    if inspect.isfunction(value):
        yield value
        for part in (*(value.__defaults__ or ()), *(value.__kwdefaults__ or {}).values()):
            yield from _bound_functions(part, seen)
        for cell in value.__closure__ or ():
            try:
                part = cell.cell_contents
            except ValueError:
                continue
            yield from _bound_functions(part, seen)
    elif isinstance(value, dict):
        for part in value.values():
            yield from _bound_functions(part, seen)
    elif isinstance(value, (list, tuple)):
        for part in value:
            yield from _bound_functions(part, seen)


def test_pinned_gcp_sources_current_native_bindings_and_individual_receipts_conserve(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError('source accounting must not access network or cloud authentication')

    for name in ('socket', 'create_connection', 'getaddrinfo'):
        monkeypatch.setattr(socket, name, forbidden)
    monkeypatch.setenv('AWS_EC2_METADATA_DISABLED', 'true')

    assert hashlib.sha256(REPORT.read_bytes()).hexdigest() == REPORT_SHA256
    report = json.loads(REPORT.read_text())
    inventory_path = ROOT / report['inputs']['pinned_inventory']['path']
    assert hashlib.sha256(inventory_path.read_bytes()).hexdigest() == report['inputs']['pinned_inventory']['sha256']
    inventory = json.loads(inventory_path.read_text())
    historical = {row['check_id']: row for row in inventory['checks']}
    upstream = {row['id']: row for row in report['upstream_records']}
    assert len(upstream) == len(report['upstream_records']) == len(historical) == 766
    assert upstream.keys() == historical.keys()
    assert Counter(row['status'] for row in upstream.values()) == {
        'mapped-active': 692, 'mapped-only-archived': 24, 'rejected': 50,
    } == report['counts']['upstream_dispositions']
    assert Counter(row['repository'] for row in upstream.values()) == report['counts']['by_repository']
    queries = [query for source in inventory['sources'] for query in source.get('query_inventory', [])]
    assert len(queries) == report['counts']['independent_query_definitions'] == 202
    assert all(query['control_ids'] and set(query['control_ids']) <= upstream.keys() for query in queries)
    assert report['pinned_sources'] == [
        {key: source[key] for key in ('repository', 'revision', 'corpus_sha256')}
        | {'file_count': len(source['files'])} for source in inventory['sources']
    ]

    current_native = {check.id: check for check in CHECKS if check.provider == 'gcp'}
    rows = {row['id']: row for row in report['native_records']}
    # Preserve all exact529 historical rows; each of the six later IDs has
    # its own source-bound acceptance rather than extending the old report.
    conservation = current_conservation()
    successor_receipts = {cid: r['path'] for cid, r in conservation['prior_admissions'].items()}
    successor_receipts.update({cid: r['receipt'] for cid, r in conservation['head_admissions'].items()})
    thematic = current_thematic_admissions()
    job_reference = thematic['thematic_admissions'][JOB_ID]
    successor_receipts[JOB_ID] = job_reference['path']
    successor_ids = successor_receipts.keys()
    assert current_native.keys() - rows.keys() == successor_ids
    assert len(current_native) == 536
    assert len(current_native.keys() - exclusions().keys()) == 429
    native = {cid: check for cid, check in current_native.items() if cid in rows}
    archived = native.keys() & exclusions().keys()
    assert len(native) == len(rows) == len(report['native_records']) == 529
    assert native.keys() == rows.keys()
    assert len(archived) == report['counts']['excluded_native_ids'] == 107
    assert len(native.keys() - archived) == report['counts']['active_native_ids'] == 422
    with (ROOT / 'docs/check-review/checks.csv').open() as handle:
        current_master = {row['check_id']: row for row in csv.DictReader(handle) if row['provider'] == 'gcp'}
    assert current_master.keys() == current_native.keys()
    for cid, path in successor_receipts.items():
        assert current_master[cid]['current_goal_receipt'] == path
        receipt = json.loads((ROOT / path).read_text())
        if cid in conservation['head_admissions']:
            registered, = [r for r in receipt['registered_predicates'] if r['id'] == cid]
            individual = {'id': cid, 'check_id': cid, 'kind': registered['kind'], 'active': True,
                          'predicate': conservation['head_admissions'][cid]['predicate']}
            assert registered['body_sha256'] == individual['predicate']['body_sha256']
        else:
            _checked_json(job_reference if cid == JOB_ID else conservation['prior_admissions'][cid])
            individual, = receipt['checks']
        assert individual['id'] == individual['check_id'] == cid
        assert individual['kind'] == current_native[cid].kind and individual['active'] is True
        function = inspect.unwrap(current_native[cid].evaluate)
        assert individual['predicate']['qualname'] == function.__module__ + '.' + function.__qualname__
        assert individual['predicate']['body_sha256'] == hashlib.sha256(inspect.getsource(function).encode()).hexdigest()
    master = {cid: row for cid, row in current_master.items() if cid in rows}
    assert master.keys() == native.keys()
    documents = {}
    for path, receipt in report['native_receipts'].items():
        raw = (ROOT / path).read_bytes()
        assert hashlib.sha256(raw).hexdigest() == receipt['sha256'], path
        documents[path] = json.loads(raw)

    for cid, row in rows.items():
        assert row['active'] == (cid not in archived) == (master[cid]['active'].lower() == 'true')
        assert row['kind'] == native[cid].kind
        assert row['current_receipt'] == master[cid]['current_goal_receipt']
        assert row['current_review_status'] == master[cid]['current_goal_status']
        assert row['limits'] and row['receipt_basis']
        record = documents[row['individual_receipt']]
        for part in row['individual_record_path']:
            record = record[part]
        assert isinstance(record, dict) and (record.get('id') == cid or record.get('check_id') == cid
                                             or row['individual_record_path'][-1] == cid), cid
        assert row['directed_test_modules'], cid
        assert all((ROOT / path).is_file() for path in row['directed_test_modules'])
        predicate = row['predicate']
        if cid == FUNCTION_ID:
            erratum = _checked_json(conservation['current_predicate_errata'][cid])
            _validate_current_function(erratum, native[cid])
            assert erratum['historical_predicate'] == {k: predicate[k] for k in ('path', 'qualname', 'body_sha256')}
            module, _, attribute = predicate['qualname'].rpartition('.')
            old_function = getattr(importlib.import_module(module), attribute)
            bound = [old_function]
        else:
            bound = [fn for fn in _bound_functions(native[cid].evaluate)
                 if f'{fn.__module__}.{fn.__qualname__}' == predicate['qualname']]
        assert len(bound) == 1, cid
        actual = bound[0]
        assert str(Path(inspect.getsourcefile(actual)).relative_to(ROOT)) == predicate['path']
        assert hashlib.sha256(inspect.getsource(actual).encode()).hexdigest() == predicate['body_sha256']
        assert predicate['body_sha256'] == master[cid]['current_bound_predicate_sha256']
        assert predicate['qualname'] == master[cid]['bound_predicate_qualname']
        assert row['upstream_ids'] == sorted(sid for sid, source in historical.items() if cid in source['native_checks'])

    for sid, row in upstream.items():
        old = historical[sid]
        assert row['status'] == old['status'] and row['repository'] == old['repository']
        assert row['evaluator_sha256'] == old['upstream_evaluator']['sha256']
        assert row['resolved_sha256'] == old['upstream_evaluator'].get('resolved_sha256', row['evaluator_sha256'])
        direct = set(old['native_checks'])
        assert direct <= native.keys()
        assert row['native_ids'] == sorted(direct)
        assert row['active_native_ids'] == sorted(direct - archived)
        assert row['excluded_native_ids'] == sorted(direct & archived)
        assert row['semantic_equivalence'] == 'not_inferred_from_mapping_or_receipt_presence'
        related = set(old.get('review', {}).get('related_native_ids', []))
        successor = old.get('review', {}).get('current_native_reconciliation')
        if successor:
            related.add(successor['native_id'])
            assert successor['native_id'] in native.keys() - archived
            assert successor['full_upstream_equivalence'] is False
        assert row['related_native_ids'] == sorted(related) and related <= native.keys()
        if row['status'] != 'mapped-active':
            assert old['review']['assessment'] and old['review']['classification']
            assert sid in report['nonmapped_contract_families'][row['review_family']]['source_ids']

    nonmapped = [sid for family in report['nonmapped_contract_families'].values() for sid in family['source_ids']]
    assert len(nonmapped) == len(set(nonmapped)) == 74
    assert set(nonmapped) == {sid for sid, row in upstream.items() if row['status'] != 'mapped-active'}
    baseline = json.loads((ROOT / report['inputs']['native_baseline']['path']).read_text())['checks']
    assert native.keys() - {row['id'] for row in baseline} == set(report['baseline_delta']['new_native_ids']) == {
        'gcp.review.cloudtasks.selected_payload_secret_indicators',
        'gcp.review.bigquery.selected_routine_secret_indicators',
        'gcp.review.dataproc.selected_job_referenced_source_secret_indicators',
        'gcp.review.dataproc.selected_initialization_referenced_source_secret_indicators',
    }
    assert {row['id'] for row in baseline if row['active'] and row['id'] in archived} == set(
        report['baseline_delta']['newly_excluded_existing_ids'])
    assert all(not value for key, value in report['findings'].items() if isinstance(value, list))
    # Accounted limitations and potential advisory work must not be erased by a
    # green accounting result, or mislabeled as a full upstream implementation.
    assert {sid for row in report['remaining_bounded_upstream_candidates'] for sid in row['source_ids']} == {
        'gcp-compliance.control.cis_v300_7_4', 'gcp-compliance.control.cis_v400_7_4',
    }
    assert any(row['status'] == 'remaining_native_association_gap' for row in report['secret_surface_reconciliation'])


def test_pinned766_and_head769_are_separate_exact_conserved_source_epochs():
    current = current_conservation()
    assert current['counts'] == {
        'historical_native': 529, 'prior_admissions': 3, 'head_admissions': 3,
        'registered_native': 535, 'active_native': 428, 'excluded_native': 107,
        'historical_source_rows': 766, 'head_added_source_rows': 3, 'head_source_rows': 769,
    }
    historical = _checked_json(current['historical_source_report'])
    inventory = _checked_json(current['pinned_source_inventory'])
    audit = _checked_json(current['head_audit'])
    accounting = _checked_json(current['head_source_accounting'])
    runtime = _checked_json(current['head_runtime_admission'])
    old_ids = {r['check_id'] for r in inventory['checks']}
    assert len(old_ids) == len(inventory['checks']) == 766
    assert current['historical_dispositions'] == historical['counts']['upstream_dispositions']
    assert current['head_source_successors'] == accounting['source_rows']
    additions = {r['source_id']: r for r in current['head_source_successors']}
    queue = {r['source_id']: r for r in audit['new_candidate_queue']}
    assert additions.keys() == queue.keys()
    assert not old_ids & additions.keys()
    assert len(old_ids | additions.keys()) == 769
    assert len(additions) == len(current['head_admissions']) == 3
    assert {r['native_id'] for r in additions.values()} == current['head_admissions'].keys()
    prowler, = [r for r in audit['repositories'] if r['repository'] == 'prowler-cloud/prowler']
    assert prowler['head_commit'] == '4980ded0ae30cb93a251688b24ce55e5bd0ad466'
    for sid, successor in additions.items():
        cid = successor['native_id']
        assert successor['revision'] == prowler['head_commit']
        assert successor['full_upstream_semantic_equivalence'] is False
        assert queue[sid]['proposed_native_id'] == cid
        assert successor['registered_body_sha256'] == current['head_admissions'][cid]['predicate']['body_sha256']
        assert successor['limit']
    assert set(runtime['registered_ids']) == current['head_admissions'].keys()
    assert runtime['unique_passing_nodes'] == 50
    # Root/public metadata successors reuse their existing unchanged predicates.
    native = {c.id: c for c in CHECKS if c.provider == 'gcp'}
    old_native = {r['id']: r for r in historical['native_records']}
    assert len(audit['metadata_only_existing_ids']) == 2
    for row in audit['metadata_only_existing_ids']:
        cid = row['proposed_successor_native_id']
        assert cid == row['preserved_old_native_ids'] and cid in old_native
        assert row['source_evaluator_unchanged'] is True
        fn = inspect.unwrap(native[cid].evaluate)
        assert hashlib.sha256(inspect.getsource(fn).encode()).hexdigest() == old_native[cid]['predicate']['body_sha256']
    assert current['production_accepted'] is current['deployed'] is False
    assert current['root_owned_remaining']


def test_function_erratum_preserves_old_proof_and_binds_current_native_dtos():
    from peaso.checks.fixtures import CASES

    current = current_conservation()
    erratum = _checked_json(current['current_predicate_errata'][FUNCTION_ID])
    check, = [c for c in CHECKS if c.id == FUNCTION_ID]
    fn = _validate_current_function(erratum, check)
    ledger = json.loads((ROOT / 'docs/evidence-reviews/gcp.json').read_text())
    old_row = deepcopy(ledger['checks'][FUNCTION_ID])
    assert old_row.pop('current_erratum') == current['current_predicate_errata'][FUNCTION_ID]['path']
    assert hashlib.sha256(json.dumps(old_row, sort_keys=True).encode()).hexdigest() == erratum['historical_ledger_record_sha256']
    assert old_row['evaluator_sha256'] == erratum['historical_predicate']['body_sha256']
    assert old_row['evaluator_sha256'] != erratum['predicate']['body_sha256']
    integration = _checked_json(erratum['integration_receipt'])
    assert integration['check_id'] == FUNCTION_ID
    assert len(erratum['corrections']) == 3
    dtos = _checked_json(erratum['current_public_dtos'])
    expected = {'full_clean': ['PASS'], 'full_positive': ['FAIL'],
                'partial_positive': ['FAIL'], 'asymmetric': ['FAIL'],
                'partial_clean': ['UNKNOWN'], 'partial_inventory_positive': ['UNKNOWN', 'FAIL'],
                'partial_inventory_clean': ['UNKNOWN', 'UNKNOWN'],
                'partial_inventory_and_detector_positive': ['UNKNOWN', 'FAIL']}
    assert {r['case']: [f['status'] for f in r['public_findings']] for r in dtos['records']} == expected
    for record in dtos['records']:
        findings = record['public_findings']
        summary = erratum['native_cases'][record['case']]
        assert summary['statuses'] == expected[record['case']]
        assert summary['inventory_status'] == record['ordinary_inventory_status']
        assert summary['findings_sha256'] == hashlib.sha256(json.dumps(findings, sort_keys=True).encode()).hexdigest()
        for finding in findings:
            assert finding['check_id'] == FUNCTION_ID
            if finding['status'] == 'FAIL':
                evidence = finding['evidence']
                assert evidence['credential_validation'] == 'not_attempted'
                assert evidence['secret_leaks'] and evidence['function_secret_pairs']
                assert all(pair['secret_leaks'] for pair in evidence['function_secret_pairs'])
                if record['case'] != 'full_positive':
                    assert evidence['complete'] is False
            if record['case'].startswith('partial_inventory'):
                assert record['ordinary_inventory_status'] == 'partial'
        if record['case'].startswith('partial_inventory'):
            assert findings[0]['status'] == 'UNKNOWN'
            assert findings[0]['evidence']['collection_status'] == 'partial'
    for branch, expected_status in [('pass', 'PASS'), ('fail', 'FAIL'), ('partial', 'FAIL'),
                                    ('asymmetric', 'FAIL'), ('unknown', 'UNKNOWN'),
                                    ('partial_inventory', 'FAIL'), ('partial_inventory_clean', 'UNKNOWN')]:
        case = CASES[FUNCTION_ID]
        status, evidence = fn(deepcopy(case[branch]), deepcopy(case.get(branch + '_index', case['index'])))
        assert status == expected_status, (branch, status, evidence)
        if branch in {'partial', 'asymmetric', 'partial_inventory'}:
            assert evidence['complete'] is False


@pytest.mark.parametrize('field', ['check_id', 'qualname', 'body_sha256', 'file_sha256',
                                   'integration_receipt', 'current_public_dtos'])
def test_exact_function_erratum_rejects_modified_identity_body_source_or_receipt(field):
    current = current_conservation()
    erratum = _checked_json(current['current_predicate_errata'][FUNCTION_ID])
    check, = [c for c in CHECKS if c.id == FUNCTION_ID]
    altered = deepcopy(erratum)
    if field == 'check_id':
        altered[field] += '.unreviewed'
    elif field in {'integration_receipt', 'current_public_dtos'}:
        altered[field]['sha256'] = '0' * 64
    else:
        altered['predicate'][field] = 'unreviewed' if field == 'qualname' else '0' * 64
    with pytest.raises(AssertionError):
        _validate_current_function(altered, check)


@pytest.mark.parametrize('artifact', ['historical_source_report', 'pinned_source_inventory',
                                      'head_audit', 'head_source_accounting', 'head_runtime_admission'])
def test_conserved_source_artifacts_reject_changed_sha256(artifact):
    reference = deepcopy(current_conservation()[artifact])
    reference['sha256'] = '0' * 64
    with pytest.raises(AssertionError):
        _checked_json(reference)


def test_new_job_native_thematic_addition_preserves_exact766_and769_source_epochs():
    current = current_thematic_admissions()
    historical = current_conservation()
    assert _checked_json(current['historical_gcp_conservation']) == historical
    assert current['counts']['gcp_registered_before'] == historical['counts']['registered_native'] == 535
    assert current['counts']['gcp_registered'] == 536
    assert current['counts']['gcp_active'] == 429
    assert current['counts']['gcp_excluded'] == historical['counts']['excluded_native'] == 107
    assert current['counts']['historical_upstream_source_rows'] == historical['counts']['historical_source_rows'] == 766
    assert current['counts']['head_source_rows'] == historical['counts']['head_source_rows'] == 769
    assert current['counts']['new_upstream_source_rows'] == 0
    assert current['historical_function_erratum'] == historical['current_predicate_errata'][FUNCTION_ID]
    assert _checked_json(current['historical_function_erratum'])['check_id'] == FUNCTION_ID
    accepted = checked_thematic_reference(current['thematic_admissions'][JOB_ID])
    assert accepted['source_epoch'].startswith('Separate native thematic addition')
    assert current['upstream_semantic_equivalence_claimed'] is False
    assert current['production_accepted'] is current['deployed'] is current['full_goal_complete'] is False
    assert current['root_owned_remaining']
    source = _checked_json(historical['historical_source_report'])
    assert JOB_ID not in {r['id'] for r in source['native_records']}
    assert not any(JOB_ID in r['native_ids'] for r in source['upstream_records'])
    assert JOB_ID not in historical['prior_admissions'] and JOB_ID not in historical['head_admissions']


@pytest.mark.parametrize('reference', ['historical_gcp_conservation', 'historical_function_erratum'])
def test_new_thematic_source_conservation_rejects_historical_receipt_drift(reference):
    altered = deepcopy(current_thematic_admissions()[reference])
    altered['sha256'] = '0' * 64
    with pytest.raises(AssertionError):
        _checked_json(altered)
