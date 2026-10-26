"""Current loaded predicates must match an individual, source-bound review."""
import hashlib
import inspect
import json
import csv
from pathlib import Path
from peaso.checks import CHECKS
from tests.test_gcp_current_source_reconciliation_20261020 import _bound_functions

# The four-assessment successor record keeps the predecessor bytes it reviewed in
# ``immutable_predecessor_files_sha256``.  Files that were later changed by
# reviewed edits are pinned here as current successors, outside the frozen record.
ASSESSMENT_PREDECESSOR_SUCCESSORS = {
    'docs/evidence-reviews/azure.json': {
        'before_sha256': '394f162863c92b9734fbd92305bc45cb12f99ff582aae0f0c3cb4b72b0905090',
        'after_sha256': '7df9f94e2f34738d498bbe2a3cdcbf19275e5e089936750fdbd949340873645f',
    },
}


def assessment_predecessor_matches(path, expected, current):
    successor = ASSESSMENT_PREDECESSOR_SUCCESSORS.get(path)
    if successor is None:
        return current == expected
    return expected == successor['before_sha256'] and current == successor['after_sha256']


def test_all_current_azure_k8s_bodies_have_exact_existing_or_erratum_receipts():
    root=Path(__file__).resolve().parents[1]
    audit=json.loads((root/'docs/check-review/azure-k8s-current-predicate-bindings-20261020.json').read_text())
    successor_raw=(root/'docs/check-review/azure-defender-assessment-four-current-binding-20261021.json').read_bytes()
    assert hashlib.sha256(successor_raw).hexdigest()=='495d31b83d1586a453b4aa325d4f287d694c950a389e0fa0fdbde6a27f6fe02d'
    successor=json.loads(successor_raw)
    assert set(successor['scope_ids'])==set(successor['records'])=={
        'azure.claude.defender_assessment_endpoint_protection',
        'azure.claude.defender_assessment_vulnerability_solution',
        'azure.claude.defender_assessment_running_images_vulnerabilities',
        'azure.claude.defender_assessment_system_updates',
    }
    for path, expected in successor['immutable_predecessor_files_sha256'].items():
        assert assessment_predecessor_matches(path, expected, hashlib.sha256((root/path).read_bytes()).hexdigest()), path
    assert hashlib.sha256((root/successor['evaluator_source']).read_bytes()).hexdigest()==successor['evaluator_current_sha256']
    latest_raw=(root/'docs/check-review/azure-k8s-current-binding-successors-20261023.json').read_bytes()
    assert hashlib.sha256(latest_raw).hexdigest()=='cfd149088c465534c624be722aa9fe4dc3e95ec14e45f6ad1899b3a87e80f23a'
    latest=json.loads(latest_raw)
    assert latest['schema']=='azure-k8s-current-binding-successors/v1'
    assert latest['historical_review_sha256']==hashlib.sha256((root/'docs/check-review/azure-k8s-current-predicate-bindings-20261020.json').read_bytes()).hexdigest()
    assert len(latest['records'])==15
    for updated in latest['records'].values():
        assert hashlib.sha256((root/updated['current_source']).read_bytes()).hexdigest()==updated['current_source_file_sha256']
    err=json.loads((root/audit['current_master_attestation_errata']).read_text())
    rows={r['id']:r for r in audit['checks']};fixes={r['id']:r for r in err['records']}
    current={c.id:c for c in CHECKS if c.provider in ('azure','k8s')}
    added='azure.review.function.selected_package_source_secret_indicators'
    # This receipt covers its original 2017 bodies. Later checks are outside
    # that historical set; the retired AKS check is no longer active.
    assert len(rows)==2017
    assert rows.keys()-current.keys()=={'azure.claude.aks_authorized_ip_ranges'}
    assert set(latest['records']) <= rows.keys() & current.keys()
    new=current[added]
    assert new.provider=='azure' and new.kind=='azure_function_package_portable_20261020'
    master,=[r for r in csv.DictReader((root/'docs/check-review/checks.csv').open()) if r['check_id']==added]
    function=inspect.unwrap(new.evaluate)
    assert master['current_goal_status'] in {'native_integration_final_gate_pending','accepted_local_bounded_native_review'}
    assert master['current_bound_predicate_sha256']==hashlib.sha256(inspect.getsource(function).encode()).hexdigest()
    assert master['source_sha256']==hashlib.sha256((root/master['source']).read_bytes()).hexdigest()
    current={cid:c for cid,c in current.items()if cid in rows}
    assert set(fixes)==set(audit['master_attestation_mismatches']) and len(fixes)==26
    assert not audit['current_unresolved_reviewed_bindings'] and not err['unresolved_ids']
    bodies={}
    for cid,check in current.items():
        row=rows[cid]
        updated=latest['records'].get(cid)
        expected_source=updated['current_source'] if updated else row['current_source']
        expected_body=(updated['current_body_sha256'] if updated else
                       successor['records'][cid]['current_body_sha256'] if cid in successor['records'] else
                       row['current_body_sha256'])
        fn=next((f for f in _bound_functions(check.evaluate)
                             if str(Path(inspect.getsourcefile(f)).relative_to(root))==expected_source
                             and hashlib.sha256(inspect.getsource(f).encode()).hexdigest()==(
                                 expected_body)), None)
        bodies[cid]=fn
    assert not [cid for cid, fn in bodies.items() if fn is None], ', '.join(cid for cid, fn in bodies.items() if fn is None)
    for cid,check in current.items():
        row=rows[cid];fn=bodies[cid]
        assert fn and (root/row['review_receipt']).is_file()
        if cid in latest['records']:
            assert row['current_body_sha256']==latest['records'][cid]['historical_body_sha256']
        if cid in successor['records']:
            update=successor['records'][cid]
            assert row['expected_body_sha256']==row['current_body_sha256']==update['historical_body_sha256']
            assert row['source_file_sha256_at_review']==update['historical_source_file_sha256']
            assert row['current_source']==update['source']==successor['evaluator_source']
            assert row['review_receipt']==update['historical_review_receipt']
            assert update['current_source_file_sha256']==successor['evaluator_current_sha256']
            assert cid not in fixes
            continue
        if cid not in fixes:
            assert row['current_body_sha256']==row['expected_body_sha256']
            continue
        fix=fixes[cid]
        assert fix['master_column_body_sha256']==row['expected_body_sha256']
        assert fix['current_body_sha256']==row['current_body_sha256']
        assert fix['matching_individual_reviews']
        for proof in fix['matching_individual_reviews']:
            raw=(root/proof['path']).read_bytes()
            assert hashlib.sha256(raw).hexdigest()==proof['sha256']
            node=json.loads(raw)
            for part in proof['record_path']:node=node[part]
            assert node.get('id',node.get('check_id'))==cid
            bound=proof['current_evaluator']
            assert bound.get('source_text_sha256',bound.get('sha256'))==row['current_body_sha256']
