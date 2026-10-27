"""A single remaining section must not serialize independent AI batches."""
import threading
import time


def test_single_section_uses_existing_two_review_slots(monkeypatch):
    from peaso.ai import pipeline
    barrier = threading.Barrier(2)
    monkeypatch.setattr(pipeline, 'review_concurrency', lambda: 2)
    monkeypatch.setattr(pipeline.isolation, 'remote', lambda: True)
    def invoke(stage, platform, entries, token, findings, reviews, end, limit):
        barrier.wait(timeout=2)
        return {'items': [{'finding_id': row['id'], 'verdict': 'FAIL',
                           'reason': ''} for row in findings]}
    monkeypatch.setattr(pipeline, 'invoke_before_deadline', invoke)
    findings = [{'id': f'finding-{i}', 'check_id': 'example', 'scope': 'scope',
                 'category': 'hardening', 'status': 'FAIL'} for i in range(80)]
    result, failed = pipeline.review_batches({'provider': 'aws'}, {}, [], None,
        findings, [], time.monotonic() + 5, stages=('hardening',))
    assert failed is False
    assert len(result['hardening']) == 80
    assert all(row['verdict'] == 'FAIL' for row in result['hardening'])


def test_progressive_sections_share_agent_permits_without_changing_results(monkeypatch):
    from peaso.ai import pipeline
    monkeypatch.setattr(pipeline, 'review_concurrency', lambda: 6)
    monkeypatch.setattr(pipeline.isolation, 'remote', lambda: True)
    permits = threading.BoundedSemaphore(2)
    barrier = threading.Barrier(2)
    lock = threading.Lock()
    active = peak = calls = 0

    def invoke(stage, platform, entries, token, findings, reviews, end, limit):
        nonlocal active, peak, calls
        with lock:
            active += 1
            calls += 1
            peak = max(peak, active)
        try:
            if calls <= 2:
                barrier.wait(timeout=2)
            time.sleep(.01)
            return {'items': [{'finding_id': row['id'], 'verdict': 'FAIL', 'reason': ''}
                              for row in findings]}
        finally:
            with lock:
                active -= 1

    monkeypatch.setattr(pipeline, 'invoke_before_deadline', invoke)
    def section(stage):
        findings = [{'id': f'{stage}-{i}', 'check_id': 'example', 'scope': 'scope',
                     'category': stage, 'status': 'FAIL'} for i in range(80)]
        result, failed = pipeline.review_batches({'provider': 'aws'}, {}, [], None,
            findings if stage == 'hardening' else [],
            findings if stage == 'exposure' else [], time.monotonic() + 5,
            stages=(stage,), agent_semaphore=permits)
        assert not failed
        return [row['finding_id'] for row in result[stage]]

    with ThreadPoolExecutor(max_workers=2) as executor:
        hard = executor.submit(section, 'hardening')
        exposure = executor.submit(section, 'exposure')
        assert hard.result(timeout=5) == [f'hardening-{i}' for i in range(80)]
        assert exposure.result(timeout=5) == [f'exposure-{i}' for i in range(80)]
    assert calls == 4 and peak == 2


def test_cancelled_wait_for_shared_permit_uses_review_fallback(monkeypatch):
    from peaso.ai import pipeline
    monkeypatch.setattr(pipeline, 'review_concurrency', lambda: 1)
    monkeypatch.setattr(pipeline.isolation, 'remote', lambda: True)
    monkeypatch.setattr(pipeline, 'invoke_before_deadline',
                        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError('agent launched')))
    permits = threading.BoundedSemaphore(1)
    permits.acquire()
    cancelled = threading.Event()
    row = {'id': 'finding', 'check_id': 'example', 'scope': 'scope',
           'category': 'hardening', 'status': 'FAIL'}
    try:
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(pipeline.review_batches, {'provider': 'aws'}, {}, [], None,
                [row], [], time.monotonic() + 3, stages=('hardening',),
                cancel_event=cancelled, agent_semaphore=permits)
            cancelled.set()
            result, failed = future.result(timeout=1)
        assert failed and result['hardening'][0]['verdict'] == 'UNKNOWN'
    finally:
        permits.release()


def test_hosted_final_pool_admits_twelve_without_changing_order(monkeypatch):
    from peaso.ai import pipeline
    monkeypatch.setattr(pipeline, 'review_concurrency', lambda: 12)
    monkeypatch.setattr(pipeline.isolation, 'remote', lambda: True)
    barrier = threading.Barrier(12)
    lock = threading.Lock()
    active = peak = calls = 0

    def invoke(stage, platform, entries, token, findings, reviews, end, limit):
        nonlocal active, peak, calls
        with lock:
            active += 1
            calls += 1
            peak = max(peak, active)
        try:
            barrier.wait(timeout=3)
            return {'items': [{'finding_id': row['id'], 'verdict': 'FAIL', 'reason': ''}
                              for row in findings]}
        finally:
            with lock:
                active -= 1

    monkeypatch.setattr(pipeline, 'invoke_before_deadline', invoke)
    rows = [{'id': f'h{i}', 'check_id': 'example', 'scope': 'scope',
             'category': 'hardening', 'status': 'FAIL'} for i in range(480)]
    result, failed = pipeline.review_batches({'provider': 'aws'}, {}, [], None,
        rows, [], time.monotonic() + 5, stages=('hardening',))
    assert not failed and calls == peak == 12
    assert [row['finding_id'] for row in result['hardening']] == [row['id'] for row in rows]


def test_hosted_refill_does_not_add_running_tasks_to_memory_capacity(monkeypatch):
    from peaso.ai import pipeline
    monkeypatch.setattr(pipeline.isolation, 'remote', lambda: True)
    admissions = 0
    def headroom():
        nonlocal admissions
        admissions += 1
        return 12 if admissions == 1 else 6
    monkeypatch.setattr(pipeline, 'review_concurrency', headroom)
    barrier = threading.Barrier(6)
    release = threading.Event()
    seventh = threading.Event()
    lock = threading.Lock()
    calls = 0

    def invoke(stage, platform, entries, token, findings, reviews, end, limit):
        nonlocal calls
        with lock:
            index = calls
            calls += 1
            if calls == 7:
                seventh.set()
        if index < 6:
            barrier.wait(timeout=3)
        if index != 0:
            assert release.wait(3)
        return {'items': [{'finding_id': row['id'], 'verdict': 'FAIL', 'reason': ''}
                          for row in findings]}

    monkeypatch.setattr(pipeline, 'invoke_before_deadline', invoke)
    rows = [{'id': f'h{i}', 'check_id': 'example', 'scope': 'scope',
             'category': 'hardening', 'status': 'FAIL'} for i in range(480)]
    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(pipeline.review_batches, {'provider': 'aws'}, {}, [], None,
            rows, [], time.monotonic() + 5, stages=('hardening',))
        try:
            assert seventh.wait(2)
            time.sleep(.05)
            with lock:
                assert calls == 7
        finally:
            release.set()
        result, failed = future.result(timeout=5)
    assert not failed and calls == 12 and len(result['hardening']) == 480


def test_twelve_slots_keep_the_same_batches_and_verdicts_as_six(monkeypatch):
    from peaso.ai import pipeline
    monkeypatch.setattr(pipeline.isolation, 'remote', lambda: True)
    rows = [{'id': f'h{i}', 'check_id': 'example', 'scope': 'scope',
             'category': 'hardening', 'status': 'FAIL'} for i in range(480)]
    signatures = []
    lock = threading.Lock()

    def invoke(stage, platform, entries, token, findings, reviews, end, limit):
        with lock:
            signatures.append(tuple(row['id'] for row in findings))
        return {'items': [{'finding_id': row['id'], 'verdict': 'FAIL', 'reason': ''}
                          for row in findings]}

    monkeypatch.setattr(pipeline, 'invoke_before_deadline', invoke)
    observed = []
    for limit in (6, 12):
        monkeypatch.setattr(pipeline, 'review_concurrency', lambda limit=limit: limit)
        signatures.clear()
        result, failed = pipeline.review_batches({'provider': 'aws'}, {}, [], None,
            rows, [], time.monotonic() + 5, stages=('hardening',))
        assert not failed
        observed.append((result, sorted(signatures)))
    assert observed[0] == observed[1]
    assert len(observed[0][1]) == 12
