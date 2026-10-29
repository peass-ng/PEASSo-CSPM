"""Stage attribution preserves invocation arguments, retries and cancellation."""
from concurrent.futures import CancelledError
import json
from types import SimpleNamespace

import pytest

from peaso import runtime_metrics
from peaso.ai import fargate, pipeline


@pytest.mark.parametrize('stage', ['network', 'priorities'])
@pytest.mark.parametrize('failure', [None, 'startup', 'cancelled', 'invalid'])
def test_stage_metrics_preserve_inputs_deadline_and_failure(monkeypatch, stage, failure):
    events, calls, clock = [], [], [0.0]
    platform = {'exact': ['private-input-must-not-be-logged']}
    entries, findings, reviews = [], [{'exact': 'finding'}], [{'exact': 'review'}]
    token, cancellation, result = object(), object(), {'exact': 'output'}
    monkeypatch.setattr(pipeline, 'time', SimpleNamespace(monotonic=lambda: clock[0]))
    monkeypatch.setattr(runtime_metrics.time, 'monotonic', lambda: clock[0])

    def invoke(*args, **kwargs):
        calls.append(args)
        assert args[:6] == (stage, platform, entries, token, findings, reviews)
        assert args[1] is platform and args[3] is token
        assert kwargs == {'cancel_event': cancellation}
        # The heartbeat sees the active stage before an invocation finishes.
        runtime_metrics.flush()
        assert events[-1][1]['active'] == [
            {'stage': 'ai.' + stage, 'count': 1, 'oldest_ms': int(clock[0] * 1000)}]
        clock[0] += 2
        if failure == 'startup' and len(calls) == 1:
            raise fargate.TaskStartupError('private-startup-body')
        if failure == 'cancelled':
            raise CancelledError('private-cancellation-body')
        if failure == 'invalid':
            raise ValueError('private-validation-body')
        return result

    monkeypatch.setattr(pipeline, 'invoke', invoke)
    runtime_metrics.configure(events.append, role='analyzer', interval_seconds=60)
    try:
        def run():
            return pipeline.invoke_before_deadline(stage, platform, entries, token,
                findings, reviews, 5, 4, cancel_event=cancellation)
        if failure in {'cancelled', 'invalid'}:
            with pytest.raises(CancelledError if failure == 'cancelled' else ValueError):
                run()
        else:
            assert run() is result
        runtime_metrics.flush()
        frame = events[-1][1]
        assert runtime_metrics.validate(frame)
        assert frame['active'] == []
        assert len(frame['rows']) == 1
        row = frame['rows'][0]
        assert (row['stage'], row['count'], row['wall_ms'], row['errors']) == (
            'ai.' + stage, 1, 4000 if failure == 'startup' else 2000,
            int(failure in {'cancelled', 'invalid'}))
        assert [call[-1] for call in calls] == ([4, 3] if failure == 'startup' else [4])
        assert 'private-' not in json.dumps(events)
    finally:
        runtime_metrics.close()
