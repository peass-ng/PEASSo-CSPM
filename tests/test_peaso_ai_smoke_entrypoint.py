"""The deployed analyzer entrypoint can run acceptance without polling tenant jobs."""
from unittest.mock import Mock
import pytest
from peaso import worker
from peaso.ai import smoke


def test_smoke_runs_before_worker_or_store_initialization(monkeypatch):
    run = Mock()
    monkeypatch.setattr(smoke, 'main', run)
    monkeypatch.setattr(worker, 'Worker', Mock(side_effect=AssertionError('must not initialize tenant worker')))
    monkeypatch.setattr('sys.argv', ['worker', 'analyzer', '--ai-smoke'])
    worker.main()
    run.assert_called_once_with()


@pytest.mark.parametrize('arguments', [
    ['collector', '--ai-smoke'], ['analyzer', '--ai-smoke', '--once'],
    ['analyzer', '--ai-smoke', '--tenant-id', 't', '--scan-id', 's'],
])
def test_smoke_rejects_collection_or_scan_selection(monkeypatch, arguments):
    monkeypatch.setattr('sys.argv', ['worker', *arguments])
    with pytest.raises(SystemExit) as error:
        worker.main()
    assert error.value.code == 2


def test_live_acceptance_requires_the_complete_pipeline(monkeypatch):
    from peaso.ai import pipeline
    completed = {'status': 'completed', 'network': {'status': 'completed'},
                 'actions': [], 'native_final': {'hardening': ['hard'], 'exposure': ['exposed']},
                 'reviews': {'hardening': [{}], 'exposure': [{}]},
                 'stage_inputs': {'hardening': [], 'exposure': []}, 'coverage': {'total': 2}}
    def review(report, snapshot, selectors, **kwargs):
        assert {r['category'] for r in report['findings']} == {'hardening', 'exposure'}
        assert all(r['status'] == 'FAIL' for r in report['findings'])
        assert snapshot['metadata']['not_live_cloud_evidence'] is True
        assert selectors == {'ai_enabled': True}
        assert kwargs['artifacts'] is None
        return completed
    monkeypatch.setattr(pipeline, 'review_scan', review)
    smoke.main()
    completed['network']['status'] = 'unavailable'
    with pytest.raises(RuntimeError, match='pipeline_smoke_failed'):
        smoke.main()
