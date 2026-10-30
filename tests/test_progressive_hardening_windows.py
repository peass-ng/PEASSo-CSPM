"""Whole-group Hardening windows remain bounded as native kinds settle."""

from types import SimpleNamespace
import json
import threading
import time

import pytest

from peaso.ai import progressive_kinds
from peaso.ai import pipeline
from peaso import progressive_analyzer
from tests.test_progressive_poll_cost import Artifacts, Stopper
from tests.test_progressive_analyzer_20261022 import FakeStore


def _row(index, kind):
    return {'id': f'f{index}', 'check_id': f'check.{kind}', 'provider': 'aws',
            'scope': '123456789012/us-east-1', 'category': 'hardening',
            'status': 'FAIL', 'resource_id': f'resource-{index}',
            'evidence': {'index': index}}


def test_closed_kinds_pack_full_windows_without_extra_initial_calls(monkeypatch):
    from peaso import engine
    monkeypatch.setattr(engine, '_selection', lambda *a, **kw: (None, [
        SimpleNamespace(id=f'check.{kind}', kind=kind, dependencies=(), category='hardening')
        for kind in ('kind_a', 'kind_b')]))
    report = {'provider': 'aws', 'findings': [_row(i, 'kind_a' if i < 45 else 'kind_b')
            for i in range(80)]}
    snapshot = {'provider': 'aws', 'metadata': {'requested_scopes': ['123456789012/us-east-1'],
        'incremental': {'phase': 'collecting'}}, 'collections': [
            {'type': 'kind_a', 'scope': '123456789012/us-east-1', 'status': 'collected'}]}
    first = progressive_kinds.full_windows(report,
        progressive_kinds.candidate_kinds(report, snapshot, {}))
    assert len(first) == 1 and len(first[0][1]) == 40
    assert all(ident.startswith('f') for ident in first[0][2])
    snapshot['collections'].append({'type': 'kind_b', 'scope': '123456789012/us-east-1',
                                    'status': 'collected'})
    second = progressive_kinds.full_windows(report,
        progressive_kinds.candidate_kinds(report, snapshot, {}), first[0][2])
    assert len(second) == 1 and len(second[0][1]) == 40
    assert not first[0][2] & second[0][2]
    assert first[0][2] | second[0][2] == {row['id'] for row in report['findings']}


def test_group_signature_changes_when_a_later_member_joins():
    first = [_row(0, 'kind_a')]
    joined = [first[0], dict(_row(1, 'kind_a'), evidence={'index': 0})]
    before = progressive_kinds.review_group_signatures(first)
    after = progressive_kinds.review_group_signatures(joined)
    assert before['f0'] != after['f0']


def test_final_merger_accepts_only_complete_revision_bound_window():
    ids = [f'f{index}' for index in range(40)]
    result = {'status': 'completed', 'stage_inputs': {'hardening': ids},
        'review_fingerprints': {'hardening': {ident: 'a' * 64 for ident in ids}},
        'review_group_signatures': {'hardening': {ident: 'b' * 64 for ident in ids}},
        'reviews': {'hardening': [{'finding_id': ident, 'verdict': 'FAIL', 'reason': ''}
                                  for ident in ids]}}
    artifact = {'stage': 'hardening_w_0000', 'data_revision': 0, 'source_revision': 7,
        'checkpoint_snapshot_id': 'sha256:sealed', 'leader_ids': ids, 'result': result}

    class Artifacts:
        def get(self, tenant, ref):
            assert tenant == 'tenant' and ref == 'ref'
            return artifact

    stages = {'hardening_w_0000': {'data_revision': 0, 'result_ref': 'ref'}}
    sections = {'hardening': {'status': 'complete', 'data_revision': 9}}
    merged = progressive_kinds.reusable_windows(Artifacts(), 'tenant', sections, stages)
    assert merged['early_kind'] and len(merged['reviews']['hardening']) == 40
    artifact['data_revision'] = 1
    assert progressive_kinds.reusable_windows(Artifacts(), 'tenant', sections, stages) is None


def test_watcher_launches_no_hardening_window_even_when_windows_flag_is_set(monkeypatch, tmp_path):
    # Hardening verdicts are native-final; the former progressive window flag starts no model stage.
    artifacts, store = Artifacts(), FakeStore()
    report = artifacts.values['report-json']
    report.update(provider='aws', snapshot_id='sha256:partial',
                  findings=[_row(index, 'kind_a') for index in range(120)])
    report['publication']['sections']['hardening'] = {'status': 'complete', 'data_revision': 1}
    artifacts.values['partial-report']['summary'] = {'publication': report['publication']}
    artifacts.values['partial-snapshot'] = {'provider': 'aws', 'snapshot_id': 'sha256:partial',
        'metadata': {'incremental': {'phase': 'collecting', 'sequence': 7}}}
    store.row['data'] = json.dumps({'ai_enabled': True})
    launches = []

    class Stage:
        def __init__(self, worker, tenant, ident, stage, revision, job, selectors):
            launches.append(stage)
            raise AssertionError('no progressive Hardening stage may start')

    monkeypatch.setattr(progressive_analyzer, '_StageProcess', Stage)
    monkeypatch.setattr(progressive_analyzer, 'review_concurrency', lambda: 3)
    monkeypatch.setattr(progressive_kinds, 'candidate_kinds',
                        lambda report, snapshot, selectors: {'kind_a': {'check.kind_a'}})
    monkeypatch.setenv('PEASO_AI_PROGRESSIVE_HARDENING_WINDOWS', '1')
    finals = []

    def final(*args, **kwargs):
        finals.append(kwargs)
        assert store.stage_results('tenant', 'scan') == {}
        store.row['status'] = 'completed'

    worker = SimpleNamespace(role='analyzer', store=store, artifacts=artifacts,
        settings=SimpleNamespace(state_dir=tmp_path, identity_dir=tmp_path, lease_seconds=30),
        stopping=Stopper(8, lambda tick: store.row.update(status='collected') if tick == 3 else None),
        run_once=final)
    assert progressive_analyzer.run_progressive(worker, 'tenant', 'scan', poll_seconds=0) == 'completed'
    assert launches == [] and finals == [{}]


def test_network_is_one_model_call_without_reviewer_batches(monkeypatch):
    assert not hasattr(pipeline, 'review_batches')
    calls = []

    def invoke_before_deadline(stage, platform, access, token, findings, reviews, end, limit, **kwargs):
        calls.append((stage, findings, reviews))
        return {'explanation': '', 'findings': []}

    monkeypatch.setattr(pipeline, 'invoke_before_deadline', invoke_before_deadline)
    monkeypatch.setattr(pipeline, 'review_concurrency', lambda: 2)
    monkeypatch.setattr(pipeline, 'review_credentials', lambda *args: [])
    monkeypatch.setattr(pipeline, 'validate_network', lambda data, network: dict(data))
    network = {'inventory': [], 'findings': []}
    output, failed = pipeline.review_network({'provider': 'aws'}, [], None, network,
                                             time.monotonic() + 30)
    assert not failed and output['status'] == 'completed'
    assert calls == [('network', [], [])]


def test_hardening_only_stage_selection_starts_no_model_review(monkeypatch, tmp_path):
    from tests.test_progressive_analyzer_20261022 import _exact_reuse_fixture
    calls = _exact_reuse_fixture(monkeypatch, tmp_path)
    rows = [_row(index, f'kind_{index}') for index in range(40)]
    report = {'provider': 'aws', 'snapshot_id': 'sha256:captured',
              'created_at': '2026-10-27T13:00:00Z', 'findings': rows, 'graphs': {}}
    output = pipeline.review_scan(report, {}, {}, tenant='tenant', artifacts=None,
                                  stages=('hardening', 'exposure'))
    assert output['status'] == 'skipped' and output['reason'] == 'no_ai_sections_selected'
    assert calls == []


def test_final_hardening_rows_are_native_final_and_ignore_early_reuse(monkeypatch, tmp_path):
    from tests.test_progressive_analyzer_20261022 import _exact_reuse_fixture
    calls = _exact_reuse_fixture(monkeypatch, tmp_path)
    first = dict(_row(0, 'kind_a'), evidence={'same': True})
    later = dict(_row(1, 'kind_a'), evidence={'same': True})
    base = {'provider': 'aws', 'snapshot_id': 'sha256:captured',
            'created_at': '2026-10-27T13:00:00Z', 'findings': [first, later], 'graphs': {}}
    prior = {'status': 'completed', 'early_kind': True,
             'reviews': {'hardening': [{'finding_id': 'f0', 'verdict': 'PASS', 'reason': 'Stale.'}]}}
    final = pipeline.review_scan(base, {}, {}, tenant='tenant', artifacts=None,
        stages=('priorities',), reused_stages={'hardening': prior})
    assert [stage for stage, _, _ in calls if stage in {'hardening', 'exposure'}] == []
    assert final['native_final']['hardening'] == ['f0', 'f1']
    assert [row['finding_id'] for row in final['reviews']['hardening']] == ['f0', 'f1']
    assert final['stage_inputs'] == {'hardening': [], 'exposure': []}
    assert final['coverage']['model_reviewed'] == 0


def test_watcher_starts_no_native_checkpoint_stage_for_hardening_or_exposure(monkeypatch, tmp_path):
    artifacts, store = Artifacts(), FakeStore()
    sections = artifacts.values['partial-report']['summary']['publication']['sections']
    for stage in ('hardening', 'exposure'):
        sections[stage] = {'status': 'complete', 'data_revision': 1,
                           'settled_kinds': True, 'settled_revision': 1}
    launched = []

    class Stage:
        def __init__(self, worker, tenant, ident, stage, revision, job, selectors):
            launched.append(stage)
            raise AssertionError('no Hardening or Exposure stage may start')

    monkeypatch.setattr(progressive_analyzer, '_StageProcess', Stage)
    monkeypatch.setattr(progressive_analyzer, 'review_concurrency', lambda: 2)
    finals = []

    def final(*args, **kwargs):
        finals.append(kwargs)
        assert store.stage_results('tenant', 'scan') == {}
        store.row['status'] = 'completed'

    worker = SimpleNamespace(role='analyzer', store=store, artifacts=artifacts,
        settings=SimpleNamespace(state_dir=tmp_path, identity_dir=tmp_path, lease_seconds=30),
        stopping=Stopper(8, lambda tick: store.row.update(status='collected') if tick == 2 else None),
        run_once=final)
    assert progressive_analyzer.run_progressive(worker, 'tenant', 'scan', poll_seconds=0) == 'completed'
    assert launched == [] and finals == [{}]


def test_native_child_accepts_only_analyzing_phase_and_revision():
    artifacts = Artifacts()
    artifacts.values['native-report'] = {'publication': {'state': 'partial', 'phase': 'analyzing',
        'sections': {'hardening': {'status': 'complete', 'data_revision': 9}}}}
    artifacts.values['native-snapshot'] = {'snapshot_id': 'sha256:native'}
    refs = {'partial_report': 'native-report', 'partial_snapshot': 'native-snapshot'}
    assert progressive_analyzer._ready(refs, artifacts, 'tenant') is None
    assert progressive_analyzer._ready(refs, artifacts, 'tenant', phase='analyzing')[2][
        'hardening']['data_revision'] == 9
    artifacts.values['native-report']['publication']['phase'] = 'completed'
    assert progressive_analyzer._ready(refs, artifacts, 'tenant', phase='analyzing') is None


@pytest.mark.parametrize('stage', ['hardening', 'exposure', 'hardening_w_0000'])
def test_stage_child_rejects_every_non_network_stage(monkeypatch, stage):
    artifacts = Artifacts()
    sections = artifacts.values['report-json']['publication']['sections']
    sections[stage] = {'status': 'complete', 'data_revision': 5,
                       'settled_kinds': True, 'settled_revision': 5}
    monkeypatch.setattr(progressive_analyzer, 'FileArtifacts', lambda path: artifacts)
    monkeypatch.setattr(progressive_analyzer.signal, 'signal', lambda *args: None)
    monkeypatch.setattr(progressive_analyzer, 'review_scan',
                        lambda *a, **kw: pytest.fail('non-Network stage reviewed'))
    sent = []
    connection = SimpleNamespace(send=sent.append, close=lambda: None)
    progressive_analyzer._stage_child({'mode': 'file', 'root': '/unused'}, 'tenant', 'scan', stage, 5,
        'partial-report', 'partial-snapshot', {}, time.time() + 10, {}, threading.Event(), connection)
    assert sent == []
