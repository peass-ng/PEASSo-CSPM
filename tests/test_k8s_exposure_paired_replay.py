"""Offline replay diversity and model release fence."""
import pytest

from peaso.ai.pipeline import inputs
from peaso.engine import evaluate_snapshot
from peaso.snapshot import resources
from scripts.prepare_k8s_exposure_paired_replay import CATEGORIES, fixture
from scripts import run_k8s_exposure_paired_replay as runner


def test_fixture_has_uncertain_controller_and_firewall_fail_candidates():
    snapshot = fixture()
    report = evaluate_snapshot(snapshot, categories=CATEGORIES, include_not_applicable=False)
    names = {row['id']: row['native_id'] for row in resources(snapshot)}
    native = {(names.get(row['resource_id']), row['check_id']): row['status']
              for row in report['findings']}
    assert native[('apps/pending-controller-lb', 'analysis.internet_exposure')] == 'UNKNOWN'
    assert native[('apps/pending-controller-lb', 'k8s.service.review_public_type')] == 'FAIL'
    assert native[('apps/nodeport', 'analysis.internet_exposure')] == 'UNKNOWN'
    assert native[('apps/nodeport', 'k8s.service.review_public_type')] == 'FAIL'
    assert native[('apps/public-ingress', 'analysis.internet_exposure')] == 'FAIL'
    assert native[('apps/external-ip', 'analysis.internet_exposure')] == 'UNKNOWN'
    assert native[('_cluster/anonymous-secrets', 'analysis.principal_exposure')] == 'FAIL'
    assert native[('apps/edge', 'analysis.internet_exposure')] == 'UNKNOWN'
    hardening, exposure, duplicates = inputs(report)
    assert not hardening and not duplicates
    assert len(exposure) == 8
    assert {row['id'] for row in exposure} == {row['id'] for row in report['findings']
                                               if row['status'] == 'FAIL'}


def test_model_arm_refuses_without_root_release_before_preflight(tmp_path, monkeypatch):
    monkeypatch.setattr(runner, 'ROOT_RELEASE', tmp_path / 'absent-root-release')
    monkeypatch.setattr(runner, 'preflight', lambda: pytest.fail('preflight ran before root release'))
    with pytest.raises(PermissionError, match='root model slot release absent'):
        runner.launch()


def test_comparison_preserves_unreviewed_unknown_and_exact_transitions():
    manifest = {'review_finding_ids': ['fail-a', 'fail-b'], 'native_findings': [
        {'id': 'unknown', 'check_id': 'c', 'resource_id': 'r1',
         'native_resource_id': 'pod/one', 'status': 'UNKNOWN'},
        {'id': 'fail-a', 'check_id': 'c', 'resource_id': 'r2',
         'native_resource_id': 'service/two', 'status': 'FAIL'},
        {'id': 'fail-b', 'check_id': 'c', 'resource_id': 'r3',
         'native_resource_id': 'service/three', 'status': 'FAIL'}]}
    ai = [{'finding_id': 'fail-a', 'verdict': 'FAIL', 'reason': ''},
          {'finding_id': 'fail-b', 'verdict': 'UNKNOWN', 'reason': 'Cloud firewall absent.'}]
    rows = runner.comparison_rows(manifest, ai)
    assert [row['transition'] for row in rows] == [
        'UNKNOWN->NOT_REVIEWED', 'FAIL->FAIL', 'FAIL->UNKNOWN']
    assert rows[0]['ai_reason'] is None
    assert rows[2]['ai_claims_absent_from_snapshot'] is None
    assert rows[2]['absent_fact_review'] == 'pending'
    with pytest.raises(ValueError, match='review IDs drift'):
        runner.comparison_rows(manifest, ai[:1])
