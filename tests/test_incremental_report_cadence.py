"""Full batch durability and immediate sections with bounded cumulative reports."""
import threading

from tests.test_incremental_checkpoint import _session, SCOPE, TENANT


def manual_session(monkeypatch, tmp_path, **options):
    # Initialize provider imports before the shared fixture replaces analysis.
    import peaso.collectors
    session, artifacts, refs, _ = _session(monkeypatch, tmp_path,
        batch_interval=100, **options)
    session.stop = True
    session.wake.set()
    session.thread.join(2)
    now = [0.0]
    session.clock = lambda: now[0]
    session.interval = session.min_report_interval = 8.0
    return session, artifacts, refs, now


def commit(session, start, count=64):
    for i in range(start, start + count):
        session.on_collection({'type': 'bucket' if i == 0 else 'other',
            'scope': SCOPE if i == 0 else f'scope-{i}',
            'status': 'empty', 'items': []})


def test_fast_batches_are_durable_without_repeating_cumulative_reports(monkeypatch, tmp_path):
    session, artifacts, refs, now = manual_session(monkeypatch, tmp_path)
    try:
        commit(session, 0)
        assert session._maybe_publish() is not None
        for index, moment in enumerate((0.5, 1.0, 7.99), start=1):
            now[0] = moment
            commit(session, index * 64)
            assert session._maybe_publish() is None
        assert [seq for seq, _, report in refs if report is None] == [64, 128, 192, 256]
        assert [seq for seq, _, report in refs if report] == [64]
        now[0] = 8.0
        assert session._maybe_publish() is not None
        assert [seq for seq, _, report in refs if report] == [64, 256]
        session.on_collection({'type': 'other', 'scope': 'final', 'status': 'empty', 'items': []})
        session.flush()
        assert refs[-1][0] == 257 and refs[-1][2]
        latest = artifacts.get(TENANT, refs[-1][1])
        assert len(latest['collections']) == 257
    finally:
        session.close()


def test_aws_content_tail_keeps_batches_and_defers_terminal_report(monkeypatch, tmp_path):
    session, artifacts, refs, now = manual_session(monkeypatch, tmp_path)
    try:
        commit(session, 0)
        assert session._maybe_publish() is not None
        session.on_content_tail(True)
        now[0] = 30.0
        commit(session, 64)
        assert session._maybe_publish() is None
        commit(session, 128)
        assert session._maybe_publish() is None
        assert [seq for seq, _, report in refs if report is None] == [64, 128, 192]
        assert [seq for seq, _, report in refs if report] == [64]
        assert session.on_content_tail(False) is None
        assert session._maybe_publish() is None
        assert [seq for seq, _, report in refs if report] == [64]
        session.finish_collection(final_metadata={"complete": True})
        assert [seq for seq, _, report in refs if report] == [64]
        assert len(session.collections) == 192
        latest = artifacts.get(TENANT, refs[-1][1])
        assert latest['metadata']['complete'] is True
    finally:
        session.close()


def test_aws_content_tail_explicit_flush_and_error_cleanup(monkeypatch, tmp_path):
    session, _, refs, _ = manual_session(monkeypatch, tmp_path)
    try:
        commit(session, 0)
        session.on_content_tail(True)
        assert session.flush() is not None
        assert [seq for seq, _, report in refs if report] == [64]
        commit(session, 64)
        try:
            raise RuntimeError('collector cancelled')
        finally:
            # The worker's collector finally closes the active tail before
            # closing an interrupted checkpoint session.
            if session.content_tail_active:
                session.on_content_tail(False)
    except RuntimeError as exc:
        assert str(exc) == 'collector cancelled'
        assert not session.content_tail_active
        assert [seq for seq, _, report in refs if report] == [64]
    finally:
        session.close()
    assert [seq for seq, _, report in refs if report] == [64, 128]


def test_new_section_publishes_immediately_with_same_ready_category(monkeypatch, tmp_path):
    session, _, refs, now = manual_session(monkeypatch, tmp_path)
    session.section_dependencies['leaks'] = {'secret'}
    try:
        commit(session, 0)
        session._maybe_publish()
        now[0] = 0.01
        session.on_collection({'type': 'secret', 'scope': SCOPE, 'status': 'empty', 'items': []})
        with session.lock:
            session._flush_pending()
        assert session._maybe_publish() is not None
        assert 'leaks' in session.published_sections
        assert len([row for row in refs if row[2]]) == 2
    finally:
        session.close()


def test_new_category_is_published_before_minimum_interval(monkeypatch, tmp_path):
    session, _, refs, now = manual_session(monkeypatch, tmp_path, second=True)
    try:
        commit(session, 0)
        session._maybe_publish()
        now[0] = 0.01
        session.on_collection({'type': 'image', 'scope': SCOPE, 'status': 'empty', 'items': []})
        with session.lock:
            session._flush_pending()
        report = session._maybe_publish()
        assert report and len(report['findings']) == 2
        assert len([row for row in refs if row[2]]) == 2
    finally:
        session.close()


def test_explicit_short_minimum_retains_collection_stride_option(monkeypatch, tmp_path):
    session, _, _, now = manual_session(monkeypatch, tmp_path)
    session.min_report_interval = 0.5
    try:
        commit(session, 0)
        session._maybe_publish()
        commit(session, 64)
        now[0] = 0.49
        assert session._maybe_publish() is None
        now[0] = 0.5
        assert session._maybe_publish() is not None
    finally:
        session.close()


def test_slow_publication_does_not_consume_next_report_interval(monkeypatch, tmp_path):
    session, _, _, now = manual_session(monkeypatch, tmp_path)
    checkpoint = session.on_checkpoint
    def slow(snapshot, report, sequence):
        checkpoint(snapshot, report, sequence)
        if report:
            now[0] += 12.0
    session.on_checkpoint = slow
    try:
        commit(session, 0)
        session._maybe_publish()
        assert session.last_time == 12.0
        commit(session, 64)
        assert session._maybe_publish() is None
        now[0] = 20.0
        assert session._maybe_publish() is not None
    finally:
        session.close()


def test_cumulative_snapshot_does_not_hold_collector_lock(monkeypatch, tmp_path):
    session, artifacts, refs, _ = manual_session(monkeypatch, tmp_path)
    copying, release, settled = threading.Event(), threading.Event(), threading.Event()
    errors = []
    original = session._snapshot
    def delayed(value, *args, **kwargs):
        if kwargs.get('sections') is not None:
            copying.set()
            assert release.wait(5)
        return original(value, *args, **kwargs)
    def publish():
        try:
            session._maybe_publish()
        except BaseException as exc:
            errors.append(exc)
    try:
        commit(session, 0)
        monkeypatch.setattr(session, '_snapshot', delayed)
        publisher = threading.Thread(target=publish)
        publisher.start()
        assert copying.wait(2)
        collector = threading.Thread(target=lambda: (session.on_collection({
            'type': 'bucket', 'scope': SCOPE, 'status': 'collected',
            'items': [{'id': 'new'}]}), settled.set()))
        collector.start()
        try:
            assert settled.wait(1), 'collector blocked on cumulative snapshot construction'
        finally:
            release.set()
            publisher.join(5)
            collector.join(5)
        assert not errors
        prior = artifacts.get(TENANT, [ref for _, ref, report in refs if report][0])
        assert prior['metadata']['incremental']['sequence'] == 64
        assert next(row for row in prior['collections'] if row['type'] == 'bucket')['items'] == []
        session.flush()
        latest = artifacts.get(TENANT, refs[-1][1])
        assert latest['metadata']['incremental']['sequence'] == 65
        assert next(row for row in latest['collections'] if row['type'] == 'bucket')['items'] == [{'id': 'new'}]
    finally:
        release.set()
        session.close()


def test_expensive_publication_coalesces_reports_but_keeps_every_raw_batch(monkeypatch, tmp_path):
    from peaso import incremental
    session, artifacts, refs, now = manual_session(monkeypatch, tmp_path)
    cpu = [100.0]
    monkeypatch.setattr(incremental.time, 'thread_time', lambda: cpu[0])
    checkpoint = session.on_checkpoint
    def expensive(snapshot, report, sequence):
        checkpoint(snapshot, report, sequence)
        if report:
            cpu[0] += 12.0
    session.on_checkpoint = expensive
    try:
        commit(session, 0)
        assert session._maybe_publish() is not None
        assert session.last_report_cpu == 12.0
        # 12 CPU-s needs a 48s quiet period and, in total, 120s of session
        # time under the 10% share; every raw batch is still committed.
        for start, moment in ((64, 8.0), (128, 47.99), (192, 48.0), (256, 119.99)):
            now[0] = moment
            commit(session, start)
            assert session._maybe_publish() is None
        assert [seq for seq, _, report in refs if report is None] == [64, 128, 192, 256, 320]
        now[0] = 120.0
        assert session._maybe_publish() is not None
        assert [seq for seq, _, report in refs if report] == [64, 320]
        assert session.report_cpu_total == 24.0
        session.on_collection({'type': 'other', 'scope': 'final', 'status': 'empty', 'items': []})
        session.flush()
        assert refs[-1][0] == 321 and refs[-1][2]
        assert len(artifacts.get(TENANT, refs[-1][1])['collections']) == 321
    finally:
        session.close()


def test_new_section_bypasses_cpu_quiet_period(monkeypatch, tmp_path):
    session, _, refs, now = manual_session(monkeypatch, tmp_path)
    session.section_dependencies['leaks'] = {'secret'}
    try:
        commit(session, 0)
        session._maybe_publish()
        session.last_report_cpu = 1000.0
        now[0] = 0.01
        session.on_collection({'type': 'secret', 'scope': SCOPE, 'status': 'empty', 'items': []})
        with session.lock:
            session._flush_pending()
        assert session._maybe_publish() is not None
        assert 'leaks' in session.published_sections
        assert len([ref for ref in refs if ref[2]]) == 2
    finally:
        session.close()


def test_cpu_quiet_period_is_capped_at_five_minutes(monkeypatch, tmp_path):
    session, _, _, now = manual_session(monkeypatch, tmp_path)
    try:
        commit(session, 0)
        session._maybe_publish()
        session.last_report_cpu = 1000.0
        commit(session, 64)
        now[0] = 299.99
        assert session._maybe_publish() is None
        now[0] = 300.0
        assert session._maybe_publish() is not None
    finally:
        session.close()


def test_explicit_minimum_opts_out_of_adaptive_quiet_period(monkeypatch, tmp_path):
    session, _, _, now = manual_session(monkeypatch, tmp_path, min_report_interval=0.5)
    session.min_report_interval = 0.5
    try:
        commit(session, 0)
        session._maybe_publish()
        session.last_report_cpu = 1000.0
        commit(session, 64)
        now[0] = 0.5
        assert session._maybe_publish() is not None
    finally:
        session.close()


def test_cumulative_cpu_share_bounds_routine_passes_but_not_new_sections(monkeypatch, tmp_path):
    from peaso import incremental
    session, _, refs, now = manual_session(monkeypatch, tmp_path)
    session.section_dependencies['leaks'] = {'secret'}
    cpu = [0.0]
    monkeypatch.setattr(incremental.time, 'thread_time', lambda: cpu[0])
    checkpoint = session.on_checkpoint
    def costly(snapshot, report, sequence):
        checkpoint(snapshot, report, sequence)
        if report:
            cpu[0] += 2.0
    session.on_checkpoint = costly
    try:
        commit(session, 0)
        assert session._maybe_publish() is not None
        # A section completing at once still publishes; its 2 CPU-s count too.
        now[0] = 0.01
        session.on_collection({'type': 'secret', 'scope': SCOPE, 'status': 'empty', 'items': []})
        with session.lock:
            session._flush_pending()
        assert session._maybe_publish() is not None
        assert session.report_cpu_total == 4.0
        # Past the 8s quiet period, routine passes wait until 4 CPU-s <= 10%.
        commit(session, 64)
        now[0] = 39.99
        assert session._maybe_publish() is None
        now[0] = 40.0
        assert session._maybe_publish() is not None
        assert len([ref for ref in refs if ref[2]]) == 3
        # An explicit flush is never delayed by the share.
        commit(session, 128)
        assert session.flush() is not None
    finally:
        session.close()


def test_new_section_publishes_immediately_during_active_content_tail(monkeypatch, tmp_path):
    session, artifacts, refs, now = manual_session(monkeypatch, tmp_path)
    session.section_dependencies['leaks'] = {'secret'}
    try:
        commit(session, 0)
        session._maybe_publish()
        session.on_content_tail(True)
        session.last_report_cpu = 1000.0
        now[0] = 0.01
        session.on_collection({'type': 'secret', 'scope': SCOPE, 'status': 'empty', 'items': []})
        with session.lock:
            session._flush_pending()
        assert session._maybe_publish() is not None
        assert session.content_tail_active
        assert 'leaks' in session.published_sections
        assert len([row for row in refs if row[2]]) == 2
        latest = artifacts.get(TENANT, refs[-1][1])
        assert latest['metadata']['incremental']['sequence'] == 65
        assert any(row['type'] == 'secret' for row in latest['collections'])
    finally:
        session.close()


def test_large_aws_content_tail_defers_routine_markdown_but_keeps_explicit_partial(monkeypatch, tmp_path):
    session, _, refs, now = manual_session(monkeypatch, tmp_path)
    try:
        commit(session, 0)
        assert session._maybe_publish() is not None
        session.on_content_tail(True)
        for start in (64, 128, 192, 256):
            commit(session, start)
        session.section_dependencies['leaks'] = {'secret'}
        now[0] = 100.0
        session.on_collection({'type': 'secret', 'scope': SCOPE, 'status': 'empty', 'items': []})
        with session.lock:
            session._flush_pending()
        assert len(session.collections) >= 256
        assert session._maybe_publish() is None
        assert len([row for row in refs if row[2]]) == 1
        assert session.flush() is not None
        assert len([row for row in refs if row[2]]) == 2
    finally:
        session.close()
