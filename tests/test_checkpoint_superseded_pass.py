"""A finished collection stops an unforced cumulative checkpoint pass; forced flushes still publish."""
from peaso import engine
from peaso.incremental import CheckpointSession

SCOPE = '111111111111/us-east-1'
REQUEST = {'connector': {'provider': 'aws', 'scopes': [SCOPE]}, 'categories': ['hardening'],
           'checks': ['aws.ec2.imdsv2']}


def _session(monkeypatch):
    monkeypatch.setattr(CheckpointSession, '_background', lambda self: None)
    publications = []
    session = CheckpointSession(REQUEST, lambda *row: publications.append(row), lambda snapshot: snapshot,
        interval=0, collection_stride=1, batch_size=10000, batch_interval=10**9, min_report_interval=0,
        clock=lambda: 0)
    session.on_collection({'type': 'instance', 'scope': SCOPE, 'status': 'collected',
        'items': [{'InstanceId': 'i-1', 'MetadataOptions': {'HttpTokens': 'optional'}}]})
    with session.lock:
        session._flush_pending()
    return session, publications


def _reports(publications):
    return [row for row in publications if row[1] is not None]


def test_unforced_pass_publishes_while_collection_runs(monkeypatch):
    session, publications = _session(monkeypatch)
    assert session._maybe_publish() is not None
    assert len(_reports(publications)) == 1
    session.close()


def test_finish_during_evaluation_drops_the_obsolete_pass(monkeypatch):
    session, publications = _session(monkeypatch)
    real = engine.evaluate_snapshot
    calls = []

    def finishing(*args, **kwargs):
        calls.append(1)
        session.collection_finished = True  # the collector finishes mid-pass
        return real(*args, **kwargs)
    monkeypatch.setattr(engine, 'evaluate_snapshot', finishing)
    assert session._maybe_publish() is None
    assert calls == [1] and _reports(publications) == []
    assert session.error is None and session.last_published == 0
    # An unforced pass never starts after the finish; an explicit flush does.
    assert session._maybe_publish() is None and calls == [1]
    monkeypatch.setattr(engine, 'evaluate_snapshot', real)
    assert session.flush() is not None
    assert len(_reports(publications)) == 1
    session.close()


def test_superseded_pass_records_no_engine_span_failure(monkeypatch):
    from peaso import runtime_metrics
    session, _ = _session(monkeypatch)
    real, inventory = engine.evaluate_snapshot, engine.resources
    stopped = []

    def finishing_inside_spans(snapshot):
        # Finish while the timed validate/resources spans are already open.
        session.collection_finished = True
        return inventory(snapshot)

    def evaluating(*args, **kwargs):
        try:
            return real(*args, **kwargs)
        except BaseException as exc:
            stopped.append(type(exc).__name__)
            raise
    monkeypatch.setattr(engine, 'resources', finishing_inside_spans)
    monkeypatch.setattr(engine, 'evaluate_snapshot', evaluating)
    frames = []
    runtime_metrics.configure(frames.append, role='collector', interval_seconds=3600)
    try:
        assert session._maybe_publish() is None
    finally:
        runtime_metrics.close()
    assert stopped == ['_Superseded']
    rows = {row['stage']: row for row in frames[-1][1]['rows']}
    assert {'engine.validate', 'engine.resources', 'engine.native_checks'} <= set(rows)
    assert all(row['errors'] == 0 for row in rows.values())
    session.close()
