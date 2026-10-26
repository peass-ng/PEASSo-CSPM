"""Collector-local bounded detector cohorts; never retain native SDK responses."""
import threading
import time


class ContentCohort:
    def __init__(self, members, deadline, *, max_bytes, gather_seconds=.25, prepare_seconds=30, cancelled=None):
        self.members = frozenset(members)
        if not self.members or len(self.members) > 8:
            raise ValueError('content cohort bound')
        self.deadline, self.max_bytes = deadline, max_bytes
        self.cancelled = cancelled
        self.gather_seconds, self.prepare_seconds = gather_seconds, prepare_seconds
        self.condition = threading.Condition()
        self.serial = threading.Lock()
        self.pending, self.results, self.finished = {}, {}, set()
        self.running = self.closed = False
        self.first = None

    def remaining(self):
        if self.cancelled is not None and self.cancelled.is_set():
            raise TimeoutError('scanner cohort cancelled')
        left = self.deadline - time.monotonic()
        if left <= 0:
            raise TimeoutError('scanner cohort deadline')
        return left

    def finish(self, member):
        with self.condition:
            self.finished.add(member)
            self.pending.pop(member, None)
            self.results.pop(member, None)
            self.condition.notify_all()

    def close(self):
        with self.condition:
            self.closed = True
            self.pending.clear()
            self.results.clear()
            self.condition.notify_all()

    def output(self, member, payload, path):
        from .secret_scanning_batch import _prepare_trufflehog_batch
        if member not in self.members or member != path or not isinstance(payload, bytes):
            raise ValueError('content cohort identity')
        with self.condition:
            if self.closed or member in self.finished or member in self.pending:
                raise RuntimeError('scanner cohort unavailable')
            if sum(len(item[0]) for item in self.pending.values()) + len(payload) > self.max_bytes:
                raise ValueError('content cohort bound')
            # Exact clean-byte facts never bypass identity, state, capacity or
            # the original absolute lease; source parsing stays on this caller.
            self.remaining()
            from .secret_scan_clean import known_clean
            if known_clean(payload):
                from .runtime_metrics import span
                with span('secret.trufflehog.cohort_clean'):
                    return b''
            self.pending[member] = (payload, path)
            if self.first is None:
                self.first = time.monotonic()
            self.condition.notify_all()
        while True:
            jobs = None
            with self.condition:
                if self.closed:
                    raise RuntimeError('scanner cohort unavailable')
                if member in self.results:
                    ready, output = self.results.pop(member)
                    self.pending.pop(member, None)
                    break
                remaining = self.remaining()
                arrived = self.finished | set(self.pending)
                gather_left = self.gather_seconds - (time.monotonic() - self.first)
                if not self.running and (arrived == self.members or gather_left <= 0):
                    jobs = {key: item for key, item in self.pending.items() if key not in self.results}
                    self.running = True
                else:
                    self.condition.wait(min(remaining, max(.001, gather_left) if not self.running else .1))
            if jobs is not None:
                outputs = None
                try:
                    from .runtime_metrics import span
                    with span('secret.trufflehog.cohort_prepare'):
                        outputs = _prepare_trufflehog_batch(list(jobs.values()), min(self.prepare_seconds, self.remaining()))
                except Exception:
                    # Share only a fixed failure state, never exception/tracebacks.
                    pass
                finally:
                    with self.condition:
                        if not self.closed:
                            for key, item in jobs.items():
                                if key not in self.finished:
                                    self.results[key] = (outputs is not None, outputs.get(item) if outputs is not None else None)
                        self.running = False
                        self.first = time.monotonic()
                        self.condition.notify_all()
        if ready and output is not None:
            return output
        # Existing parser/private capture stays on the original caller thread.
        # A failed batch cannot start eight simultaneous fallback processes.
        from . import secret_scanning as scanning
        with self.serial:
            self.remaining()
            executable = scanning._trufflehog()
            return scanning._run([executable, 'stdin', '--json', '--no-verification',
                '--no-update', '--log-level=-1', '--concurrency=1', '--force-skip-archives',
                '--no-verification-cache', '--fail-on-scan-errors'], payload, min(60, self.remaining()))
