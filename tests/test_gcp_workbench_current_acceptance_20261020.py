"""Six exact admissions and one explicit erratum conserve the529-ID review."""
from copy import deepcopy
import csv
import gzip
import hashlib
import inspect
import io
import json
from pathlib import Path
import pytest
from peaso.checks import CHECKS
from peaso.checks.fixtures import CASES
from peaso.checks.catalog import description_for, proposal_provenance_for
from peaso.checks.gcp_evidence_explanations import CATALOG, evidence_summary
from peaso.finding_types import type_for
from peaso.check_services import service_for
from tests.retained_evidence_ledgers_20261022 import REPINNED, ledger_bytes

CID='gcp.review.workbench.selected_referenced_source_secret_indicators_20261020'
RECEIPT=Path('docs/check-review/workbench-current-acceptance-20261020.json')
ADMISSIONS = {
    CID: RECEIPT,
    'gcp.review.dataflow.selected_package_referenced_source_secret_indicators': Path('docs/check-review/dataflow-current-acceptance-20261020.json'),
    'gcp.review.batch.selected_mounted_script_source_secret_indicators': Path('docs/check-review/batch-current-acceptance-20261020.json'),
}
HEAD_RECEIPT = 'docs/check-review/gcp-workbench-head3-runtime-20261020-admission.json'
HEAD_IDS = {
    'gcp.review.workbench.terminal_access_disabled',
    'gcp.review.workbench.file_download_disabled',
    'gcp.review.workbench.auto_upgrade_schedule_declared',
}
ALL_ADMISSIONS = set(ADMISSIONS) | HEAD_IDS
CURRENT_ARCHIVE = Path('tests/fixtures/gcp_current_ledger_head3_predecessors_20261020.json.gz')
CURRENT_ARCHIVE_SHA256 = '7cb8172e9b89000b5ea38723fcb964f1c0d3ea944e81f7986468f0dc670cd354'
FUNCTION_ID = 'gcp.review.function.literal_environment_secret_indicators'
AWS_COMMAND_ID = 'aws.review.workload.selected_command_literal_secret_indicators'
JOB_ID = 'gcp.review.cloudrun_job.declared_image_secret_indicators'
THEMATIC_IDS = {AWS_COMMAND_ID, JOB_ID}
THEMATIC_RECEIPT = Path('docs/check-review/commands-job-current-ledger-source-conservation-20261020.json')
THEMATIC_RECEIPT_SHA256 = '316b65f30ac782876af87da7e3fed055876f11bbbb48fe6cdcd8c8b4897468da'
THEMATIC_PREDECESSORS = Path('tests/fixtures/commands_job_current_acceptance_predecessors_20261020.json.gz')
THEMATIC_PREDECESSORS_SHA256 = '0cb85c904f2ac18b7755bccc8bc5c7a2e6ba3971cfb89130d98d244fbdfd71af'


def current_thematic_admissions():
    raw = THEMATIC_RECEIPT.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == THEMATIC_RECEIPT_SHA256
    receipt = json.loads(raw)
    assert set(receipt['new_ids']) == set(receipt['thematic_admissions']) == THEMATIC_IDS
    assert receipt['counts']['new_upstream_source_rows'] == 0
    assert receipt['upstream_semantic_equivalence_claimed'] is False
    return receipt


def thematic_predecessors():
    raw = THEMATIC_PREDECESSORS.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == THEMATIC_PREDECESSORS_SHA256
    archive = json.loads(gzip.decompress(raw))
    assert set(archive['sources']) == {
        'docs/check-review/checks.csv', 'docs/evidence-reviews/aws.json',
        'docs/evidence-reviews/gcp.json',
        'tests/test_gcp_workbench_current_acceptance_20261020.py',
        'tests/test_gcp_current_source_reconciliation_20261020.py',
    }
    for row in archive['sources'].values():
        assert hashlib.sha256(row['content'].encode()).hexdigest() == row['sha256']
    return archive


def checked_thematic_reference(reference):
    raw = ledger_bytes('.', reference['path'], reference['sha256'])
    assert hashlib.sha256(raw).hexdigest() == reference['sha256'], reference['path']
    return json.loads(raw)


def recorded_runtime_log(path, expected_sha256):
    """Verify a retained proof file when available; .log files are ignored."""
    assert Path(path).suffix in {'.log', '.txt'}
    assert len(expected_sha256) == 64 and all(c in '0123456789abcdef' for c in expected_sha256)
    if Path(path).is_file():
        assert hashlib.sha256(Path(path).read_bytes()).hexdigest() == expected_sha256




def current_predecessors():
    raw = CURRENT_ARCHIVE.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == CURRENT_ARCHIVE_SHA256
    archived = json.loads(gzip.decompress(raw))
    assert set(archived['sources']) == {
        'docs/evidence-reviews/gcp.json',
        'tests/test_gcp_workbench_current_acceptance_20261020.py',
        'tests/test_gcp_current_source_reconciliation_20261020.py',
    }
    for row in archived['sources'].values():
        assert hashlib.sha256(row['content'].encode()).hexdigest() == row['sha256']
    return archived


ARCHIVE = Path('tests/fixtures/gcp_source_acceptance_accounting_pre_dataflow_batch_20261020.json.gz')
ARCHIVE_SHA256 = 'cab4d6bcf64a07753bac072469b58f9a24ca208eaf6e4edaf72db4bd89ee1c0d'


def preserved_accounting():
    raw = ARCHIVE.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == ARCHIVE_SHA256
    archived = json.loads(gzip.decompress(raw))
    for row in archived['sources'].values():
        assert hashlib.sha256(row['content'].encode()).hexdigest() == row['sha256']
    return archived


@pytest.mark.parametrize('cid,receipt', ADMISSIONS.items())
def test_exact_workbench_predicate_and_master_receipt_close_current_id(cid, receipt):
    current={c.id:c for c in CHECKS if c.provider=='gcp'}
    baseline=json.loads(Path('docs/gcp-review/recheck-20261020/current-source-reconciliation-20261020.json').read_text())
    # Later admissions may extend the current catalog without changing this
    # archived admission or any of its predecessor rows.
    assert ALL_ADMISSIONS | {JOB_ID} <= current.keys()-{r['id']for r in baseline['native_records']}
    rows={r['check_id']:r for r in csv.DictReader(open('docs/check-review/checks.csv'))if r['provider']=='gcp'}
    assert cid in rows and cid in current
    report=json.loads(receipt.read_text());row,=report['checks'];check=current[cid];fn=inspect.unwrap(check.evaluate)
    assert row['id']==cid and rows[cid]['current_goal_receipt']==str(receipt)
    assert rows[cid]['current_goal_status']=='accepted_local_bounded_native_review'
    assert row['predicate']['qualname']==fn.__module__+'.'+fn.__qualname__
    assert hashlib.sha256(inspect.getsource(fn).encode()).hexdigest()==row['predicate']['body_sha256']==rows[cid]['current_bound_predicate_sha256']
    assert hashlib.sha256(Path(row['predicate']['path']).read_bytes()).hexdigest()==rows[cid]['source_sha256']
    if cid != CID:
        assert row['predicate']['file_sha256'] == rows[cid]['source_sha256']
        runtime = report['runtime_receipt']; raw = Path(runtime['path']).read_bytes()
        assert hashlib.sha256(raw).hexdigest() == runtime['sha256']
        native = json.loads(raw)
        assert runtime['unique_passing_nodes'] == native['tests']['unique_passing_nodes'] == 540
        proof = Path(native['tests']['artifact']).read_bytes()
        assert hashlib.sha256(proof).hexdigest() == native['tests']['sha256']
        recorded = json.loads(gzip.decompress(proof))
        nodes = {n['nodeid']: n['status'] for group in recorded.values()
                 if isinstance(group, dict) for n in group.get('nodes', [])}
        assert sum(status == 'PASS' for status in nodes.values()) == 540
        assert {node for node, status in nodes.items() if status == 'FAIL'} == set(native['tests']['expected_red'])


def test_workbench_signed_description_type_service_and_source_rating():
    check=next(c for c in CHECKS if c.id==CID)
    assert type_for(CID)=='secrets'
    assert service_for('gcp',check.kind)==service_for('gcp','workbench_instance')=='notebooks'
    assert check.severity=='high' and check.category=='exposure'
    assert proposal_provenance_for(CID)['signed_resource_kind']==check.kind
    description=description_for(CID)
    assert 'Cached or previously executed bytes are not established.' in description['description']
    assert len(description['description'].split('. '))==3


def test_canonical_admission_preserves_all_previous_supplemental_descriptions():
    old=json.loads(gzip.decompress(Path('tests/fixtures/workbench_canonical_description_predecessor_20261020.json.gz').read_bytes()))
    assert hashlib.sha256(old['source'].encode()).hexdigest()==old['sha256']
    baseline=json.loads(old['source']);current=json.loads(Path(old['path']).read_text())
    assert len(baseline) == 1000
    later={'aws.review.codebuild.selected_inline_buildspec_secret_indicators': ('aws', 'codebuild_selected_inline_buildspec'),
           'azure.review.function.selected_package_source_secret_indicators': ('azure', 'azure_function_package_portable_20261020'),
           AWS_COMMAND_ID: ('aws', 'aws_selected_workload_command_literals'),
           JOB_ID: ('gcp', 'cloudrun_job_declared_image')}
    assert ALL_ADMISSIONS | later.keys() <= current.keys()-baseline.keys()
    assert {k:current[k] for k in baseline} == baseline
    for cid, (provider, kind) in later.items():
        check=next(c for c in CHECKS if c.id==cid)
        assert check.provider==provider and check.kind==kind
        assert proposal_provenance_for(cid)['signed_resource_kind']==check.kind
        assert current[cid]['description']==description_for(cid)['description']


def test_master_append_preserves_every_preexisting_row_and_exact_bytes():
    archive = preserved_accounting()
    previous = archive['sources']['docs/check-review/checks.csv']['content']
    current = Path('docs/check-review/checks.csv').read_bytes()
    assert current.startswith(previous.encode())
    old = list(csv.DictReader(io.StringIO(previous)))
    rows = list(csv.DictReader(io.StringIO(current.decode())))
    current_rows = rows
    rows = [row for row in current_rows if row['check_id'] not in THEMATIC_IDS]
    assert len(current_rows) == 2557 and len(rows) == 2555
    assert rows[:len(old)] == old
    later = {'aws.review.codebuild.selected_inline_buildspec_secret_indicators': 'aws',
             'azure.review.function.selected_package_source_secret_indicators': 'azure'}
    assert {r['check_id'] for r in rows[len(old):]} == (ALL_ADMISSIONS - {CID}) | later.keys()
    assert len(rows) == len(old) + 7 == 2555
    # The coordinator finalized exactly the pending Azure append; preserve its
    # full prior master bytes and prove every other row and its order survived.
    finalization_raw = Path('docs/check-review/azure-package-master-finalization-20261020.json').read_bytes()
    assert hashlib.sha256(finalization_raw).hexdigest() == '5cbaf8b04f2e619f052c29e4339f5f2299d7b234a71e94efe19c33cab2802e07'
    finalization = json.loads(finalization_raw)
    archive_raw = Path(finalization['archive']).read_bytes()
    assert hashlib.sha256(archive_raw).hexdigest() == finalization['archive_sha256']
    pending = json.loads(gzip.decompress(archive_raw))
    assert pending['path'] == 'docs/check-review/checks.csv'
    assert hashlib.sha256(pending['content'].encode()).hexdigest() == pending['sha256']
    pending_rows = list(csv.DictReader(io.StringIO(pending['content'])))
    finalized_id = 'azure.review.function.selected_package_source_secret_indicators'
    assert finalization['check_id'] == finalized_id
    assert len(pending_rows) == len(rows) == finalization['master_count'] == 2555
    assert [r['check_id'] for r in pending_rows] == [r['check_id'] for r in rows]
    assert [r for r in pending_rows if r['check_id'] != finalized_id] == [r for r in rows if r['check_id'] != finalized_id]
    before, = [r for r in pending_rows if r['check_id'] == finalized_id]
    after, = [r for r in rows if r['check_id'] == finalized_id]
    assert before == pending['pending_row'] == finalization['before']
    assert after == finalization['after']
    assert before['current_goal_status'] == 'native_integration_final_gate_pending'
    assert after['current_goal_status'] == 'accepted_local_bounded_native_review'
    assert finalization['native_receipt'] == after['current_goal_receipt']
    for cid, provider in later.items():
        successor, = [r for r in rows[len(old):] if r['check_id'] == cid]
        assert successor['provider'] == provider
        assert successor['current_goal_status'] in {'native_integration_final_gate_pending', 'accepted_local_bounded_native_review'}
        registered, = [check for check in CHECKS if check.id == cid]
        function = inspect.unwrap(registered.evaluate)
        assert successor['bound_predicate_qualname'] == function.__module__ + '.' + function.__qualname__
        assert successor['current_bound_predicate_sha256'] == hashlib.sha256(inspect.getsource(function).encode()).hexdigest()
        assert hashlib.sha256(Path(successor['source']).read_bytes()).hexdigest() == successor['source_sha256']



@pytest.mark.parametrize('cid', sorted(ALL_ADMISSIONS))
def test_six_new_evidence_rows_use_actual_runtime_branches(cid):
    document = json.loads(Path('docs/evidence-reviews/gcp.json').read_text())
    row = document['checks'][cid]
    check = next(check for check in CHECKS if check.id == cid)
    function = inspect.unwrap(check.evaluate)
    assert row['evaluator_sha256'] == hashlib.sha256(inspect.getsource(function).encode()).hexdigest()
    assert row['purpose'] == CATALOG[cid]['purpose']
    assert row['review_receipt'] == (HEAD_RECEIPT if cid in HEAD_IDS else str(ADMISSIONS[cid]))
    for status in ('PASS', 'FAIL', 'UNKNOWN'):
        branch = status.lower(); case = CASES[cid]
        actual, evidence = function(deepcopy(case[branch]), deepcopy(case[branch + '_index']))
        assert actual == status
        recorded = row['branch_coverage'][status]
        assert recorded['evidence_keys'] == list(evidence)
        assert recorded['example'] == evidence_summary(dict(provider='gcp', check_id=cid, status=actual, evidence=evidence))
        assert CATALOG[cid]['purpose'] in recorded['example']


def test_evidence_ledger_preserves_all_prior_records_and_adds_current_successor():
    previous = json.loads(preserved_accounting()['sources']['docs/evidence-reviews/gcp.json']['content'])
    current = json.loads(Path('docs/evidence-reviews/gcp.json').read_text())
    current_reviews = set(json.loads(Path('peaso/checks/gcp_evidence_explanations_current_20261023.json').read_text()))
    assert len(current_reviews) == 23
    assert current['registered_check_count'] == 559
    assert current['checks'].keys() - previous['checks'].keys() == ALL_ADMISSIONS | {JOB_ID} | current_reviews
    preserved = deepcopy(current['checks'])
    erratum = preserved[FUNCTION_ID].pop('current_erratum')
    assert erratum == 'docs/check-review/gcp-function-current-ledger-erratum-20261020.json'
    assert {k: v for k, v in preserved.items() if k not in ALL_ADMISSIONS and k != JOB_ID and k not in current_reviews} == previous['checks']
    assert len(current['checks']) == 559 + current['alias_count']
    immediate = json.loads(current_predecessors()['sources']['docs/evidence-reviews/gcp.json']['content'])
    assert current['checks'].keys() - immediate['checks'].keys() == HEAD_IDS | {JOB_ID} | current_reviews
    assert {k: v for k, v in preserved.items() if k not in HEAD_IDS and k != JOB_ID and k not in current_reviews} == immediate['checks']
    assert {k: v for k, v in current.items() if k not in {'checks', 'registered_check_count', 'current_source_conservation'}} == {k: v for k, v in immediate.items() if k not in {'checks', 'registered_check_count'}}


@pytest.mark.parametrize('cid', sorted(HEAD_IDS))
def test_head3_actual_predicates_master_rows_and_runtime50_proof(cid):
    from xml.etree import ElementTree
    current = {c.id: c for c in CHECKS if c.provider == 'gcp'}
    receipt = json.loads(Path(HEAD_RECEIPT).read_text())
    assert set(receipt['registered_ids']) == HEAD_IDS
    assert receipt['unique_passing_nodes'] == 50
    assert receipt['failed_nodes'] == receipt['skipped_nodes'] == 0
    nodes = set()
    for proof in receipt['tests']:
        raw = Path(proof['path']).read_bytes()
        assert hashlib.sha256(raw).hexdigest() == proof['sha256']
        cases = ElementTree.fromstring(raw).findall('.//testcase')
        assert len(cases) == proof['passing_nodes']
        assert all(not list(case) for case in cases)
        assert len(proof['nodes']) == proof['passing_nodes']
        assert all(node['status'] == 'PASS' for node in proof['nodes'])
        nodes.update(node['nodeid'] for node in proof['nodes'])
    assert len(nodes) == 50
    proof, = [r for r in receipt['registered_predicates'] if r['id'] == cid]
    function = inspect.unwrap(current[cid].evaluate)
    assert proof['qualname'] == function.__module__ + '.' + function.__qualname__
    assert proof['body_sha256'] == hashlib.sha256(inspect.getsource(function).encode()).hexdigest()
    assert proof['source_sha256'] == hashlib.sha256(Path(proof['source_path']).read_bytes()).hexdigest()
    assert proof['finding_type'] == type_for(cid) and proof['service'] == service_for('gcp', current[cid].kind)
    assert proof['severity'] == current[cid].severity
    rows = [r for r in csv.DictReader(open('docs/check-review/checks.csv')) if r['check_id'] == cid]
    row, = rows
    assert row['current_goal_receipt'] == HEAD_RECEIPT
    assert row['current_goal_status'] == 'accepted_local_bounded_native_review'
    assert row['current_bound_predicate_sha256'] == proof['body_sha256']
    assert row['bound_predicate_qualname'] == proof['qualname']
    # checks.csv rows are frozen; a reviewed later re-pin of this source is recorded in REPINNED.
    repinned = {after: before for before, after, _ in REPINNED['docs/evidence-reviews/gcp.json']}
    assert row['source_sha256'] == repinned.get(proof['source_sha256'], proof['source_sha256'])
    assert description_for(cid)['description']
    assert proposal_provenance_for(cid)['signed_resource_kind'] == current[cid].kind


def test_current_archive_pins_exact_modified_predecessors():
    archive = current_predecessors()
    assert archive['sources']['tests/test_gcp_workbench_current_acceptance_20261020.py']['content'].startswith('"""Three exact native admissions')
    assert 'REPORT_SHA256' in archive['sources']['tests/test_gcp_current_source_reconciliation_20261020.py']['content']


def test_exact_two_current_admissions_preserve_all_prior_master_rows_and_ledgers():

    receipt = current_thematic_admissions()
    archive = thematic_predecessors()
    master_ref = receipt['master_finalization']
    raw = Path(master_ref['path']).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == master_ref['sha256']
    transition = json.loads(gzip.decompress(raw))
    assert transition['before'] == archive['sources']['docs/check-review/checks.csv']
    assert transition['before_count'] == 2556 and transition['after_count'] == 2557
    before = list(csv.DictReader(io.StringIO(transition['before']['content'])))
    current_raw = Path('docs/check-review/checks.csv').read_bytes()
    assert transition['after']['content'].encode() == current_raw
    assert transition['after']['sha256'] == hashlib.sha256(current_raw).hexdigest()
    after = list(csv.DictReader(io.StringIO(current_raw.decode())))
    assert len(before) == 2556 and len(after) == 2557
    assert [row for row in before if row['check_id'] not in THEMATIC_IDS] == [
        row for row in after if row['check_id'] not in THEMATIC_IDS]
    assert len([row for row in before if row['check_id'] not in THEMATIC_IDS]) == 2555
    assert [row['check_id'] for row in after[:-1]] == [row['check_id'] for row in before]
    pending, = [row for row in before if row['check_id'] == AWS_COMMAND_ID]
    finalized, = [row for row in after if row['check_id'] == AWS_COMMAND_ID]
    assert pending == transition['before_pending_row']
    assert pending['current_goal_status'] == 'native_integration_final_gate_pending'
    assert finalized == transition['after_aws_row']
    assert finalized['current_goal_status'] == 'accepted_local_bounded_native_review'
    assert after[-1] == transition['appended_gcp_row'] and after[-1]['check_id'] == JOB_ID
    assert not any(row['check_id'] == JOB_ID for row in before)
    assert len({row['check_id'] for row in after}) == len(after)
    for provider, new_id, count in [('aws', AWS_COMMAND_ID, 1561), ('gcp', JOB_ID, 536)]:
        ledger = checked_thematic_reference(receipt['ledgers'][provider])
        old = json.loads(archive['sources']['docs/evidence-reviews/' + provider + '.json']['content'])
        assert ledger['checks'].keys() - old['checks'].keys() == {new_id}
        assert {cid: row for cid, row in ledger['checks'].items() if cid != new_id} == old['checks']
        registered = {check.id for check in CHECKS if check.provider == provider}
        # This signed ledger records the admission at its own boundary. New
        # registered checks and aliases belong to later ledgers.
        assert new_id in registered and new_id in ledger['checks']
        assert ledger['registered_check_count'] == count
        assert len(ledger['checks']) == count + ledger['alias_count']
        if provider == 'aws':
            assert ledger['active_check_count'] == 1409
        else:
            assert ledger['current_source_conservation'] == str(THEMATIC_RECEIPT)
        assert {k: v for k, v in ledger.items() if k not in {
            'checks', 'registered_check_count', 'active_check_count', 'current_source_conservation'}} == {
            k: v for k, v in old.items() if k not in {
            'checks', 'registered_check_count', 'active_check_count', 'current_source_conservation'}}
    for name in ('tests/test_gcp_workbench_current_acceptance_20261020.py',
                 'tests/test_gcp_current_source_reconciliation_20261020.py'):
        assert archive['sources'][name]['content'] != Path(name).read_text()


@pytest.mark.parametrize('cid', sorted(THEMATIC_IDS))
def test_exact_current_thematic_predicate_catalog_runtime_status_and_ledger_binding(cid):
    from peaso.engine import evaluate_snapshot

    extension = current_thematic_admissions()
    accepted = checked_thematic_reference(extension['thematic_admissions'][cid])
    check, = [check for check in CHECKS if check.id == cid]
    function = inspect.unwrap(check.evaluate)
    row, = accepted['checks']
    predicate = row['predicate']
    assert accepted['status'] == 'accepted_local_bounded_native_review'
    assert accepted['full_goal_complete'] is accepted['published'] is accepted['live_cloud_validation'] is False
    assert row['id'] == row['check_id'] == cid and row['active'] is True
    assert row['kind'] == check.kind and row['target'] == check.target == 'resource'
    assert row['category'] == check.category and row['severity'] == check.severity == 'high'
    assert row['finding_type'] == type_for(cid) == 'secrets'
    assert row['service'] == service_for(check.provider, check.kind)
    assert predicate['qualname'] == function.__module__ + '.' + function.__qualname__
    assert predicate['body_sha256'] == hashlib.sha256(inspect.getsource(function).encode()).hexdigest()
    assert predicate['file_sha256'] == hashlib.sha256(Path(predicate['path']).read_bytes()).hexdigest()
    assert row['catalog'] == description_for(cid)
    assert row['catalog_sha256'] == hashlib.sha256(json.dumps(row['catalog'], sort_keys=True).encode()).hexdigest()
    current_provenance = proposal_provenance_for(cid)
    assert {key: value for key, value in row['proposal_provenance'].items()
            if key != 'source_manifest_sha256'} == {
                key: value for key, value in current_provenance.items()
                if key != 'source_manifest_sha256'}
    native = checked_thematic_reference(row['runtime_receipt'])
    if cid == AWS_COMMAND_ID:
        assert row['runtime_unique_passing_nodes'] == native['verification']['total_directed_green_nodes'] == 37
        proof = native['verification']['new_runtime']
        assert proof['passed'] == 34
        recorded_runtime_log(proof['log'], proof['log_sha256'])
    else:
        assert row['runtime_unique_passing_nodes'] == native['pytest']['passed'] == 55
        assert native['runtime_integrated'] is True and native['outcome'] == 'succeeded'
        assert native['pytest']['failed'] == native['pytest']['skipped'] == []
        recorded_runtime_log(native['proof_log'], native['proof_log_sha256'])
        assert checked_thematic_reference(accepted['proposal_native_root_acceptance'])['native_passed'] == 112
    ledger = checked_thematic_reference(extension['ledgers'][check.provider])['checks'][cid]
    assert ledger['review_receipt'] == extension['thematic_admissions'][cid]['path']
    assert ledger['evaluator_sha256'] == predicate['body_sha256']
    assert ledger['source_sha256'] == predicate['file_sha256']
    assert ledger['catalog'] == row['catalog'] and ledger['branch_coverage'] == row['native_status_contracts']
    assert set(ledger['status_coverage']) == set(row['native_status_contracts']) == {'PASS', 'FAIL', 'UNKNOWN'}
    status, evidence = check.evaluate({}, {})
    assert status == 'UNKNOWN' and evidence == row['native_status_contracts']['UNKNOWN']['evidence']
    reference = row['native_replay_witnesses']
    raw = Path(reference['path']).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == reference['sha256']
    recorded = json.loads(gzip.decompress(raw))
    assert recorded['check_id'] == cid
    seen = set()
    for witness in recorded['witnesses']:
        current = [finding for finding in evaluate_snapshot(witness['snapshot'], checks=[cid])['findings']
                   if finding['check_id'] == cid]
        assert [(f['status'], f['evidence']) for f in current] == [
            (f['status'], f['evidence']) for f in witness['findings']]
        assert witness['status'] in {finding['status'] for finding in current}
        seen.add(witness['status'])
    assert seen == ({'FAIL'} if cid == AWS_COMMAND_ID else {'PASS', 'FAIL'})


@pytest.mark.parametrize('field', ['body_sha256', 'file_sha256', 'qualname', 'runtime_receipt'])
def test_current_thematic_binding_rejects_altered_predicate_or_runtime_receipt(field):
    accepted = checked_thematic_reference(current_thematic_admissions()['thematic_admissions'][JOB_ID])
    row = deepcopy(accepted['checks'][0])
    check, = [c for c in CHECKS if c.id == JOB_ID]
    fn = inspect.unwrap(check.evaluate)
    if field == 'runtime_receipt':
        row[field]['sha256'] = '0' * 64
        with pytest.raises(AssertionError):
            checked_thematic_reference(row[field])
    else:
        row['predicate'][field] = 'unreviewed' if field == 'qualname' else '0' * 64
        actual = {'body_sha256': hashlib.sha256(inspect.getsource(fn).encode()).hexdigest(),
                  'file_sha256': hashlib.sha256(Path(inspect.getsourcefile(fn)).read_bytes()).hexdigest(),
                  'qualname': fn.__module__ + '.' + fn.__qualname__}
        with pytest.raises(AssertionError):
            assert row['predicate'][field] == actual[field]
