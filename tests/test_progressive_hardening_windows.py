"""Whole-group Hardening windows remain bounded as native kinds settle."""

from types import SimpleNamespace
import json
import threading
import time

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


def test_watcher_admits_one_full_window_while_section_runs(monkeypatch, tmp_path):
    artifacts, store = Artifacts(), FakeStore()
    report = artifacts.values['report-json']
    report.update(provider='aws', snapshot_id='sha256:partial',
                  findings=[_row(index, 'kind_a') for index in range(120)])
    artifacts.values['partial-report']['summary'] = {'publication': report['publication']}
    artifacts.values['partial-snapshot'] = {'provider': 'aws', 'snapshot_id': 'sha256:partial',
        'metadata': {'incremental': {'phase': 'collecting', 'sequence': 7}}}
    store.row['data'] = json.dumps({'ai_enabled': True})
    launches = []

    class Stage:
        def __init__(self, worker, tenant, ident, stage, revision, job, selectors, wave=None):
            self.stage, self.revision, self.wave = stage, revision, wave
            self.process = self
            launches.append(self)
        def start(self): pass
        def poll(self):
            if self.wave is None:
                return progressive_analyzer._PENDING
            ids = self.wave['selected_ids']
            result = {'status': 'completed', 'stage_inputs': {'hardening': ids},
                'reviews': {'hardening': [{'finding_id': ident, 'verdict': 'FAIL', 'reason': ''}
                                          for ident in ids]}}
            return artifacts.put('tenant', 'scan', 'ai-review', {
                'stage': self.stage, 'data_revision': self.revision,
                'leader_ids': self.wave['leader_ids'], 'result': result})
        def close(self): pass
        def request_stop(self): pass
        def join(self, timeout=None): pass
        def is_alive(self): return False

    monkeypatch.setattr(progressive_analyzer, '_StageProcess', Stage)
    monkeypatch.setattr(progressive_analyzer, 'review_concurrency', lambda: 3)
    monkeypatch.setattr(progressive_kinds, 'candidate_kinds',
                        lambda report, snapshot, selectors: {'kind_a': {'check.kind_a'}})
    monkeypatch.setenv('PEASO_AI_PROGRESSIVE_HARDENING_WINDOWS', '1')

    def final(*args, stage_poll=None):
        assert stage_poll is None or stage_poll(store.job('tenant', 'scan'))
        assert store.stage_results('tenant', 'scan')['hardening_w_0000']['data_revision'] == 0
        store.row['status'] = 'completed'

    worker = SimpleNamespace(role='analyzer', store=store, artifacts=artifacts,
        settings=SimpleNamespace(state_dir=tmp_path, identity_dir=tmp_path, lease_seconds=30),
        stopping=Stopper(8, lambda tick: store.row.update(status='collected') if tick == 3 else None),
        run_once=final)
    assert progressive_analyzer.run_progressive(worker, 'tenant', 'scan', poll_seconds=0) == 'completed'
    assert len(launches) == 1 and launches[0].stage == 'hardening_w_0000'
    assert len(launches[0].wave['leader_ids']) == 120


def test_early_window_rechecks_share_one_full_call(monkeypatch):
    rows = [_row(index, f'kind_{index}') for index in range(80)]
    for offset, leader in ((80, 0), (100, 40)):
        rows.extend(dict(_row(index, f'kind_{leader}'), evidence={'index': leader})
                    for index in range(offset, offset + 20))
    calls = []

    def invoke(stage, platform, entries, token, findings, reviews, timeout):
        calls.append([row['id'] for row in findings])
        return {'items': [{'finding_id': row['id'],
            'verdict': 'PASS' if row['id'] in {'f0', 'f40'} else 'FAIL',
            'reason': 'Verified.' if row['id'] in {'f0', 'f40'} else ''}
            for row in findings]}

    monkeypatch.setattr(pipeline, 'invoke', invoke)
    monkeypatch.setattr(pipeline, 'review_concurrency', lambda: 2)
    output, failed = pipeline.review_batches({'provider': 'aws'}, {}, [], None,
        rows, [], time.monotonic() + 30, stages={'hardening'}, coalesce_rechecks=True)
    assert not failed and len(output['hardening']) == len(rows)
    assert sorted(map(len, calls)) == [40, 40, 40]
    assert len({row['finding_id'] for row in output['hardening']}) == len(rows)


def test_final_reuse_rechecks_a_group_whose_members_changed(monkeypatch, tmp_path):
    from tests.test_progressive_analyzer_20261022 import _exact_reuse_fixture
    calls = _exact_reuse_fixture(monkeypatch, tmp_path)
    first = dict(_row(0, 'kind_a'), evidence={'same': True})
    later = dict(_row(1, 'kind_a'), evidence={'same': True})
    base = {'provider': 'aws', 'snapshot_id': 'sha256:captured',
            'created_at': '2026-10-27T13:00:00Z', 'findings': [first], 'graphs': {}}
    prior = pipeline.review_scan(base, {}, {}, tenant='tenant', artifacts=None,
                                 stages=('hardening',))
    prior['early_kind'] = True
    calls.clear()
    final = pipeline.review_scan(dict(base, findings=[first, later]), {}, {},
        tenant='tenant', artifacts=None, stages=('hardening',),
        reused_stages={'hardening': prior})
    assert [ids for stage, ids, _ in calls if stage == 'hardening'] == [['f0']]
    assert [row['finding_id'] for row in final['reviews']['hardening']] == ['f0', 'f1']


def test_final_reuse_keeps_exact_early_rows_and_reviews_only_new_input(monkeypatch, tmp_path):
    from tests.test_progressive_analyzer_20261022 import _exact_reuse_fixture
    calls = _exact_reuse_fixture(monkeypatch, tmp_path)
    rows = [_row(index, f'kind_{index}') for index in range(40)]
    report = {'provider': 'aws', 'snapshot_id': 'sha256:captured',
              'created_at': '2026-10-27T13:00:00Z', 'findings': rows, 'graphs': {}}
    prior = pipeline.review_scan(report, {}, {}, tenant='tenant', artifacts=None,
                                 stages=('hardening',), early_kind_window=True)
    prior['early_kind'] = True
    calls.clear()
    final = pipeline.review_scan(dict(report, findings=[*rows, _row(40, 'new_kind')]),
        {}, {}, tenant='tenant', artifacts=None, stages=('hardening',),
        reused_stages={'hardening': prior})
    assert [ids for stage, ids, _ in calls if stage == 'hardening'] == [['f40']]
    assert [row['finding_id'] for row in final['reviews']['hardening']] == [
        *[f'f{index}' for index in range(40)], 'f40']


def test_final_native_hardening_starts_while_exposure_is_active(monkeypatch, tmp_path):
    artifacts, store = Artifacts(), FakeStore()
    report = artifacts.values['report-json']
    report['publication']['sections']['exposure'] = {'status': 'complete', 'data_revision': 1,
        'settled_kinds': True, 'settled_revision': 1}
    artifacts.values['partial-report']['summary']['publication']['sections'][
        'exposure'] = {'status': 'complete', 'data_revision': 1,
            'settled_kinds': True, 'settled_revision': 1}
    artifacts.values['native-report'] = {'publication': {'state': 'partial', 'phase': 'analyzing',
        'sections': {'hardening': {'status': 'complete', 'data_revision': 9}}}}
    artifacts.values['native-snapshot'] = {'snapshot_id': 'sha256:native'}
    tasks = {}
    original_claim = store.claim_stage

    def claim_after_native(*args):
        with store.lock:
            status = store.row['status']
            store.row['status'] = 'collecting'
        try:
            return original_claim(*args)
        finally:
            with store.lock:
                store.row['status'] = status

    store.claim_stage = claim_after_native

    class Stage:
        def __init__(self, worker, tenant, ident, stage, revision, job, selectors,
                     wave=None, native_final=False):
            self.stage, self.revision = stage, revision
            self.native_final = native_final
            self.refs = job['partial_report'], job['partial_snapshot']
            self.done = False
            self.process = self
            tasks[stage] = self
        def start(self): pass
        def poll(self): return f'{self.stage}-ref' if self.done else progressive_analyzer._PENDING
        def close(self): pass
        def request_stop(self): pass
        def join(self, timeout=None): pass
        def is_alive(self): return not self.done
        def kill(self): self.done = True

    monkeypatch.setattr(progressive_analyzer, '_StageProcess', Stage)
    monkeypatch.setattr(progressive_analyzer, 'review_concurrency', lambda: 2)

    def final(*args, stage_poll=None):
        assert stage_poll is not None and 'exposure' in tasks
        with store.lock:
            store.row['status'] = 'analyzing'
        native = {'report_ref': 'native-report', 'snapshot_ref': 'native-snapshot',
            'sections': {'hardening': {'status': 'complete', 'data_revision': 9}}}
        assert not stage_poll(store.job('tenant', 'scan'), native_checkpoint=native)
        assert tasks['hardening'].native_final
        assert tasks['hardening'].refs == ('native-report', 'native-snapshot')
        assert tasks['exposure'].refs == ('partial-report', 'partial-snapshot')
        tasks['exposure'].done = tasks['hardening'].done = True
        assert stage_poll(store.job('tenant', 'scan'))
        assert set(store.stage_results('tenant', 'scan')) == {'exposure', 'hardening'}
        with store.lock:
            store.row['status'] = 'completed'

    worker = SimpleNamespace(role='analyzer', store=store, artifacts=artifacts,
        settings=SimpleNamespace(state_dir=tmp_path, identity_dir=tmp_path, lease_seconds=30),
        stopping=Stopper(8, lambda tick: store.row.update(status='collected') if tick == 2 else None),
        run_once=final)
    assert progressive_analyzer.run_progressive(worker, 'tenant', 'scan', poll_seconds=0) == 'completed'


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


def test_exposure_needs_revision_bound_kind_seal_during_collect():
    section = {'status': 'complete', 'data_revision': 7}
    assert not progressive_analyzer._exposure_stable(section)
    section.update(settled_kinds=True, settled_revision=6)
    assert not progressive_analyzer._exposure_stable(section)
    section['settled_revision'] = 7
    assert progressive_analyzer._exposure_stable(section)


def test_unsealed_exposure_waits_and_starts_from_native_checkpoint(monkeypatch, tmp_path):
    artifacts, store = Artifacts(), FakeStore()
    artifacts.values['partial-report']['summary']['publication']['sections']['exposure'] = {
        'status': 'complete', 'data_revision': 1}
    launched = []
    active_tasks = []

    class Stage:
        def __init__(self, worker, tenant, ident, stage, revision, job, selectors,
                     wave=None, native_final=False):
            assert native_final
            launched.append(stage)
            self.stage = stage
            self.process = self
            self.done = False
            active_tasks.append(self)
        def start(self): pass
        def poll(self): return f'{self.stage}-ref' if self.done else progressive_analyzer._PENDING
        def close(self): pass
        def request_stop(self): self.done = True
        def join(self, timeout=None): pass
        def is_alive(self): return not self.done
        def kill(self): self.done = True

    monkeypatch.setattr(progressive_analyzer, '_StageProcess', Stage)
    monkeypatch.setattr(progressive_analyzer, 'review_concurrency', lambda: 2)
    original_claim = store.claim_stage

    def claim_after_native(*args):
        with store.lock:
            status = store.row['status']
            store.row['status'] = 'collecting'
        try:
            return original_claim(*args)
        finally:
            with store.lock:
                store.row['status'] = status

    store.claim_stage = claim_after_native

    def final(*args, stage_poll=None):
        assert stage_poll is not None and not launched
        with store.lock:
            store.row['status'] = 'analyzing'
        payload = {'report_ref': 'native-report', 'snapshot_ref': 'native-snapshot',
            'sections': {stage: {'status': 'complete', 'data_revision': 9}
                         for stage in ('hardening', 'exposure')}}
        assert not stage_poll(store.job('tenant', 'scan'), native_checkpoint=payload)
        assert launched == ['hardening', 'exposure']
        for task in active_tasks:
            task.done = True
        assert stage_poll(store.job('tenant', 'scan'))
        with store.lock:
            store.row['status'] = 'completed'

    worker = SimpleNamespace(role='analyzer', store=store, artifacts=artifacts,
        settings=SimpleNamespace(state_dir=tmp_path, identity_dir=tmp_path, lease_seconds=30),
        stopping=Stopper(8, lambda tick: store.row.update(status='collected') if tick == 2 else None),
        run_once=final)
    assert progressive_analyzer.run_progressive(worker, 'tenant', 'scan', poll_seconds=0) == 'completed'
