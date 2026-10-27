"""Advancing sections cannot orphan live reviewer processes."""
import json
import threading
import time
from types import SimpleNamespace

import pytest
from peaso import progressive_analyzer as analyzer


@pytest.mark.parametrize('cancel', [False, True])
def test_advancing_revision_keeps_every_child_owned(monkeypatch, cancel):
    tasks, finishes = [], []

    class Store:
        tick = 0
        lease = None
        results = {}
        done = False

        def job(self, tenant, ident):
            self.tick += 1
            assert self.tick < 20, 'watcher did not settle'
            status = ('completed' if self.done else
                      'cancelled' if cancel and self.tick >= 4 else
                      'collected' if self.tick >= 6 else 'collecting')
            revision = min(self.tick, 3)
            return dict(status=status, deadline=time.time() + 100,
                        partial_report=f'report-{revision}', partial_snapshot='snapshot',
                        data=json.dumps({'ai_enabled': True}))

        def stage_results(self, *args):
            return dict(self.results)

        def claim_stage(self, tenant, ident, stage, revision, owner, seconds):
            # Real SQLite/Dynamo stores allow a NEWER revision to supersede a
            # live claim. The watcher must retain ownership of its old child.
            if self.lease and self.lease[0] >= revision:
                return False
            self.lease = revision, owner
            return True

        def heartbeat_stage(self, tenant, ident, stage, revision, owner, seconds):
            return self.lease == (revision, owner)

        def finish_stage(self, tenant, ident, stage, revision, owner, reference):
            if self.lease != (revision, owner):
                return False
            self.results[stage] = dict(data_revision=revision, result_ref=reference)
            finishes.append(revision)
            self.lease = None
            return True

    store = Store()

    class Task:
        def __init__(self, worker, tenant, ident, stage, revision, job, selectors):
            self.revision = revision
            self.closed = self.stopped = False
            self.process = self
            tasks.append(self)

        def start(self):
            pass

        def poll(self):
            if not cancel and store.tick >= (4 if self.revision == 1 else 5):
                return f'result-{self.revision}'
            return analyzer._PENDING

        def close(self):
            self.closed = True

        def request_stop(self):
            self.stopped = True

        def join(self, timeout=None):
            pass

        def is_alive(self):
            return not self.stopped

        def kill(self):
            self.stopped = True

    def ready(job, artifacts, tenant):
        return {'hardening': {'status': 'complete',
                             'data_revision': int(job['partial_report'].split('-')[-1])}}

    def final(*args, stage_poll=None):
        assert finishes == [1, 3]
        assert all(task.closed for task in tasks)
        store.done = True

    worker = SimpleNamespace(role='analyzer', store=store, artifacts=None,
        settings=SimpleNamespace(lease_seconds=30), stopping=threading.Event(), run_once=final)
    monkeypatch.setattr(analyzer, '_ready_sections', ready)
    monkeypatch.setattr(analyzer, '_StageProcess', Task)
    monkeypatch.setattr(analyzer, 'review_concurrency', lambda: 2)
    status = analyzer.run_progressive(worker, 'tenant', 'scan', poll_seconds=0)
    assert status == ('cancelled' if cancel else 'completed')
    assert [task.revision for task in tasks] == ([1] if cancel else [1, 3])
    assert all(task.closed for task in tasks)
    if cancel:
        assert all(task.stopped for task in tasks)
        assert not finishes
