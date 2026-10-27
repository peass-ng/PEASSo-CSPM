"""Watcher-wide artifact reads, revisions, claims, and final handoff."""
import copy
import json
from types import SimpleNamespace

import pytest
from peaso import progressive_analyzer as watcher
from tests.test_progressive_analyzer_20261022 import FakeArtifacts, FakeStore


class Artifacts(FakeArtifacts):
    def __init__(self, *, summary=True):
        super().__init__()
        self.reads = []
        if summary:
            self.values['partial-report']['summary'] = copy.deepcopy(self.values['report-json'])
    def get(self, tenant, reference):
        self.reads.append(reference)
        return copy.deepcopy(super().get(tenant, reference))


class Stopper:
    def __init__(self, count, advance):
        self.count, self.advance, self.ticks = count, advance, 0
    def is_set(self):
        return self.ticks >= self.count
    def wait(self, _):
        self.ticks += 1
        self.advance(self.ticks)


class Stage:
    launched = []
    def __init__(self, worker, tenant, ident, stage, revision, job, selectors):
        self.launched.append((stage, revision, job['partial_report'], job['partial_snapshot']))
        self.process = self
    def start(self): pass
    def poll(self): return 'stage-result'
    def close(self): pass
    def request_stop(self): pass
    def join(self, timeout=None): pass
    def is_alive(self): return False


def run(monkeypatch, *, artifacts=None, enabled=True, advance=None, polls=20):
    store = FakeStore()
    store.result_reads = 0
    original_results = store.stage_results
    def saved_results(*args):
        store.result_reads += 1
        return original_results(*args)
    store.stage_results = saved_results
    store.row['data'] = json.dumps({'ai_enabled': enabled})
    artifacts = artifacts or Artifacts()
    finals = []
    def final(*args):
        finals.append(args)
        store.row['status'] = 'completed'
    worker = SimpleNamespace(role='analyzer', store=store, artifacts=artifacts,
        settings=SimpleNamespace(lease_seconds=30), run_once=final)
    worker.stopping = Stopper(polls, lambda tick: advance(store, artifacts, tick) if advance else None)
    Stage.launched = []
    monkeypatch.setattr(watcher, '_StageProcess', Stage)
    monkeypatch.setattr(watcher, 'review_concurrency', lambda: 2)
    watcher.run_progressive(worker, 'tenant', 'scan')
    return artifacts, store, finals


def test_unchanged_bundle_uses_one_small_read_for_entire_watcher(monkeypatch):
    artifacts, store, _ = run(monkeypatch)
    assert artifacts.reads == ['partial-report']
    assert store.result_reads == 0


def test_legacy_report_fallback_is_cached_without_snapshot_read(monkeypatch):
    artifacts, _, _ = run(monkeypatch, artifacts=Artifacts(summary=False))
    assert artifacts.reads == ['partial-report', 'report-json']


def test_disabled_ai_does_no_artifact_reads_and_runs_final_analyzer(monkeypatch):
    def advance(store, artifacts, tick):
        if tick == 5:
            store.row['status'] = 'collected'
    artifacts, _, finals = run(monkeypatch, enabled=False, advance=advance)
    assert artifacts.reads == [] and len(finals) == 1


def test_new_reference_pair_starts_newly_completed_section_immediately(monkeypatch):
    def advance(store, artifacts, tick):
        if tick == 3:
            new = copy.deepcopy(artifacts.values['partial-report'])
            new['summary']['publication']['sections']['network'].update(status='complete', data_revision=2)
            artifacts.values['new-report'] = new
            store.row.update(partial_report='new-report', partial_snapshot='new-snapshot')
    artifacts, store, _ = run(monkeypatch, advance=advance)
    assert artifacts.reads == ['partial-report', 'new-report']
    assert Stage.launched == [('network', 2, 'new-report', 'new-snapshot')]
    assert store.results['network']['data_revision'] == 2


def test_snapshot_reference_change_reloads_pair_and_preserves_stage_claim(monkeypatch):
    artifacts = Artifacts()
    artifacts.values['partial-report']['summary']['publication']['sections']['hardening']['status'] = 'complete'
    def advance(store, artifacts, tick):
        if tick == 3:
            store.row['partial_snapshot'] = 'next-snapshot'
    artifacts, store, _ = run(monkeypatch, artifacts=artifacts, advance=advance)
    assert artifacts.reads == ['partial-report', 'partial-report']
    assert len(Stage.launched) == 1 and store.results['hardening']['data_revision'] == 1


def test_stage_capacity_is_revisited_without_new_artifact_read(monkeypatch):
    artifacts = Artifacts()
    for stage in watcher.STAGES:
        artifacts.values['partial-report']['summary']['publication']['sections'][stage] = {
            'status': 'complete', 'data_revision': 1}
    artifacts, store, _ = run(monkeypatch, artifacts=artifacts)
    assert artifacts.reads == ['partial-report']
    assert {row[0] for row in Stage.launched} == set(watcher.STAGES)
    assert set(store.results) == set(watcher.STAGES)
    assert store.result_reads == 2


def test_last_checkpoint_ready_at_collected_handoff_starts_before_final(monkeypatch):
    artifacts = Artifacts()
    store = FakeStore()
    store.row['data'] = json.dumps({'ai_enabled': True})
    original_claim = store.claim_stage

    def claim_at_handoff(tenant, ident, stage, revision, owner, lease_seconds):
        # The durable stores admit stage claims in collected as well as collecting.
        with store.lock:
            store.row['status'] = 'collecting'
        try:
            return original_claim(tenant, ident, stage, revision, owner, lease_seconds)
        finally:
            with store.lock:
                store.row['status'] = 'collected'

    store.claim_stage = claim_at_handoff
    final_seen = []

    def final(*args, stage_poll=None):
        final_seen.append((list(Stage.launched), stage_poll is not None))
        while stage_poll is not None and not stage_poll(store.job('tenant', 'scan')):
            pass
        assert store.stage_results('tenant', 'scan')['network']['data_revision'] == 7
        store.row['status'] = 'completed'

    worker = SimpleNamespace(role='analyzer', store=store, artifacts=artifacts,
        settings=SimpleNamespace(lease_seconds=30), run_once=final,
        stopping=Stopper(10, lambda tick: advance(tick)))

    def advance(tick):
        if tick == 2:
            store.row['partial_report'] = 'last-report'
            artifacts.values['last-report'] = copy.deepcopy(artifacts.values['partial-report'])
            artifacts.values['last-report']['summary']['publication']['sections']['network'] = {
                'status': 'complete', 'data_revision': 7}
            store.row['status'] = 'collected'

    Stage.launched = []
    monkeypatch.setattr(watcher, '_StageProcess', Stage)
    monkeypatch.setattr(watcher, 'review_concurrency', lambda: 2)
    watcher.run_progressive(worker, 'tenant', 'scan', poll_seconds=0)
    assert final_seen == [([('network', 7, 'last-report', 'partial-snapshot')], True)]


@pytest.mark.parametrize('publication', [None, [], {'state': 'final', 'phase': 'completed'},
    {'state': 'partial', 'phase': 'collecting', 'sections': []}])
def test_invalid_or_final_readiness_never_launches_review(monkeypatch, publication):
    artifacts = Artifacts(summary=False)
    artifacts.values['report-json']['publication'] = publication
    run(monkeypatch, artifacts=artifacts)
    assert Stage.launched == []


def test_child_reloads_full_snapshot_and_report_after_parent_summary():
    artifacts = Artifacts()
    job = {'partial_report': 'partial-report', 'partial_snapshot': 'partial-snapshot'}
    assert watcher._ready_sections(job, artifacts, 'tenant')
    report, snapshot, sections = watcher._ready(job, artifacts, 'tenant')
    assert snapshot['metadata']['ai_access_reference'] == 'captured'
    assert sections == report['publication']['sections']
    assert artifacts.reads == ['partial-report', 'partial-report', 'report-json', 'partial-snapshot']


def test_stage_child_rejects_summary_readiness_without_full_report_proof(monkeypatch):
    import threading
    import time
    artifacts = Artifacts()
    artifacts.values['partial-report']['summary']['publication']['sections']['network'].update(
        status='complete', data_revision=5)
    assert watcher._ready_sections({'partial_report': 'partial-report',
        'partial_snapshot': 'partial-snapshot'}, artifacts, 'tenant')['network']['status'] == 'complete'
    monkeypatch.setattr(watcher, 'FileArtifacts', lambda path: artifacts)
    monkeypatch.setattr(watcher.signal, 'signal', lambda *args: None)
    monkeypatch.setattr(watcher, 'review_scan', lambda *a, **kw: pytest.fail('unproven section reviewed'))
    sent = []
    connection = SimpleNamespace(send=sent.append, close=lambda: None)
    watcher._stage_child({'mode': 'file', 'root': '/unused'}, 'tenant', 'scan', 'network', 5,
        'partial-report', 'partial-snapshot', {}, time.time()+10, {}, threading.Event(), connection)
    assert sent == []
    assert artifacts.reads[-3:] == ['partial-report', 'report-json', 'partial-snapshot']
