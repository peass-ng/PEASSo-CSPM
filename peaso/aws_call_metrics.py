"""Opt-in bounded AWS SDK telemetry; no request or response content is retained.

Install before collector clients are constructed. A reversible Session factory
shim only registers ordinary botocore events on every subsequently created
client, including clients from independently created and pre-existing sessions.
No API method, arguments, result, retries, caches or network settings are changed.
"""
from functools import wraps
import os
import re
import threading
import time
import weakref

MAX_KEYS = 4096
MAX_ROWS = 64
MAX_NUMBER = 2**63 - 1
INTERVAL_SECONDS = 30
_FRAME = '__aws_metrics__'
_CONTEXT = '_peaso_aws_call_metrics_v1'
_NUMBERS = frozenset({'calls', 'completed', 'errors', 'sdk_retries', 'throttle_attempts',
    'attempt_errors', 'response_declared_bytes', 'responses_with_length', 'wall_ms', 'max_ms', 'inflight'})
_ROW_KEYS = _NUMBERS | {'service', 'operation'}
_EVENT_KEYS = frozenset({'schema', 'sequence', 'reason', 'uptime_ms', 'rows'})
_SERVICE = re.compile(r'[a-z][a-z0-9-]{0,63}\Z')
_OPERATION = re.compile(r'[A-Z][A-Za-z0-9]{0,127}\Z')
_THROTTLE = frozenset({'Throttling', 'ThrottlingException', 'ThrottledException',
    'RequestThrottledException', 'TooManyRequestsException', 'ProvisionedThroughputExceededException',
    'TransactionInProgressException', 'RequestLimitExceeded', 'BandwidthLimitExceeded',
    'LimitExceededException', 'RequestThrottled', 'SlowDown', 'EC2ThrottledException'})
_INSTALL_LOCK = threading.Lock()
_ACTIVE = None


def safe_metrics(event):
    """Validate an exact bounded frame before it reaches the supervisor logger."""
    if type(event) is not dict or event.keys() != _EVENT_KEYS:
        return None
    if type(event['schema']) is not int or event['schema'] != 1:
        return None
    if type(event['reason']) is not str or event['reason'] not in {'periodic', 'manual', 'final'}:
        return None
    if any(type(event[key]) is not int or not 0 <= event[key] <= MAX_NUMBER
           for key in ('sequence', 'uptime_ms')):
        return None
    rows = event['rows']
    if type(rows) is not list or not 1 <= len(rows) <= MAX_ROWS:
        return None
    clean = []
    for row in rows:
        if type(row) is not dict or row.keys() != _ROW_KEYS:
            return None
        if (type(row['service']) is not str or not _SERVICE.fullmatch(row['service'])
                or type(row['operation']) is not str or not _OPERATION.fullmatch(row['operation'])):
            return None
        if any(type(row[key]) is not int or not 0 <= row[key] <= MAX_NUMBER for key in _NUMBERS):
            return None
        if (row['completed'] > row['calls'] or row['errors'] > row['completed']
                or row['inflight'] != row['calls'] - row['completed']
                or row['max_ms'] > row['wall_ms']):
            return None
        clean.append(dict(row))
    return dict(event, rows=clean)


def record_metrics(event, logger):
    """Log only known identifiers and numeric aggregates; diagnostics cannot fail a scan."""
    event = safe_metrics(event)
    if event is None:
        return False
    try:
        for row in event['rows']:
            logger.info('aws_sdk_metrics sequence=%d reason=%s uptime_ms=%d service=%s operation=%s '
                'calls=%d completed=%d inflight=%d wall_ms=%d max_ms=%d errors=%d '
                'sdk_retries=%d throttle_attempts=%d attempt_errors=%d '
                'response_declared_bytes=%d responses_with_length=%d',
                event['sequence'], event['reason'], event['uptime_ms'], row['service'], row['operation'],
                row['calls'], row['completed'], row['inflight'], row['wall_ms'], row['max_ms'],
                row['errors'], row['sdk_retries'], row['throttle_attempts'], row['attempt_errors'],
                row['response_declared_bytes'], row['responses_with_length'])
    except Exception:
        return False
    return True


def _bounded(value):
    return min(MAX_NUMBER, max(0, value))


def _http_facts(response, parsed):
    """Read only status and a numeric declared size; never read/serialize the body."""
    status = getattr(response, 'status_code', None)
    failed = type(status) is int and status >= 300
    throttled = status == 429
    if type(parsed) is dict:
        error = parsed.get('Error')
        if type(error) is dict:
            code = error.get('Code')
            throttled = throttled or type(code) is str and code in _THROTTLE
    headers = getattr(response, 'headers', {})
    size = headers.get('content-length') if hasattr(headers, 'get') else None
    if type(size) is str and 1 <= len(size) <= 19 and size.isascii() and size.isdecimal():
        count = int(size)
        if count <= MAX_NUMBER:
            return int(failed), int(throttled), count, 1
    return int(failed), int(throttled), 0, 0


class Metrics:
    def __init__(self, sink, *, interval=INTERVAL_SECONDS, clock=time.monotonic):
        self.sink, self.clock = sink, clock
        self.started = clock()
        self.pid = os.getpid()
        self.lock = threading.Lock()
        self.flush_lock = threading.Lock()
        self.stop = threading.Event()
        self.rows, self.dirty = {}, set()
        self.clients = weakref.WeakSet()
        self.sequence = 0
        self.original = self.wrapper = self.session_class = None
        self.closed = False
        self.interval = max(INTERVAL_SECONDS, interval)
        self.thread = None

    def _key(self, model):
        service = model.service_model.service_name
        operation = model.name
        if (type(service) is not str or not _SERVICE.fullmatch(service)
                or type(operation) is not str or not _OPERATION.fullmatch(operation)):
            return None
        return service, operation

    def _row(self, key):
        if key not in self.rows:
            # Reserve the final slot for an explicit overflow aggregate. Never
            # retain request identities or an unbounded set of operation names.
            if len(self.rows) >= MAX_KEYS - 1:
                key = ('other', 'Other')
            if key not in self.rows:
                self.rows[key] = dict.fromkeys(_NUMBERS - {'inflight'}, 0)
        return key, self.rows[key]

    def _before(self, model=None, context=None, **_):
        try:
            if self.closed or type(context) is not dict or _CONTEXT in context:
                return None
            key = self._key(model)
            if key is None:
                return None
            start = self.clock()
            with self.lock:
                key, row = self._row(key)
                row['calls'] = _bounded(row['calls'] + 1)
                self.dirty.add(key)
            # This SDK request context is local protocol state, not API params.
            context[_CONTEXT] = [self, key, start, 0, 0, 0, 0, 0]
        except Exception:
            pass
        return None

    def _retry(self, request_dict=None, attempts=None, response=None, **_):
        try:
            context = request_dict.get('context', {}) if type(request_dict) is dict else {}
            state = context.get(_CONTEXT)
            if type(state) is not list or state[0] is not self:
                return None
            if type(attempts) is int and 1 <= attempts <= 10000:
                state[3] = max(state[3], attempts)
            if type(response) is tuple and len(response) == 2:
                failed, throttled, size, known = _http_facts(*response)
                state[4] += failed
                state[5] += throttled
                state[6] += size
                state[7] += known
            elif response is None:
                state[4] += 1  # An attempt ended with an SDK transport exception.
        except Exception:
            pass
        # Returning None is essential: this handler never chooses retry policy.
        return None

    def _finish(self, context, response=None, parsed=None, failed=False):
        if type(context) is not dict:
            return
        state = context.pop(_CONTEXT, None)
        if type(state) is not list or state[0] is not self:
            return
        _, key, start, attempts, errors, throttles, size, known = state
        if attempts == 0 and response is not None:
            errors, throttles, size, known = _http_facts(response, parsed)
        retry_count = max(0, attempts - 1)
        if type(parsed) is dict:
            metadata = parsed.get('ResponseMetadata')
            retries = metadata.get('RetryAttempts') if type(metadata) is dict else None
            if type(retries) is int and 0 <= retries <= 10000:
                retry_count = max(retry_count, retries)
        elapsed = _bounded(int(max(0, self.clock() - start) * 1000))
        with self.lock:
            _, row = self._row(key)
            for field, value in (('completed', 1), ('errors', int(failed)), ('sdk_retries', retry_count),
                    ('throttle_attempts', throttles), ('attempt_errors', errors),
                    ('response_declared_bytes', size), ('responses_with_length', known), ('wall_ms', elapsed)):
                row[field] = _bounded(row[field] + value)
            row['max_ms'] = max(row['max_ms'], elapsed)
            self.dirty.add(key)

    def _after(self, context=None, http_response=None, parsed=None, **_):
        try:
            status = getattr(http_response, 'status_code', None)
            self._finish(context, http_response, parsed, type(status) is int and status >= 300)
        except Exception:
            pass
        return None

    def _error(self, context=None, **_):
        try:
            self._finish(context, failed=True)
        except Exception:
            pass
        return None

    def attach(self, client):
        """Attach once; accepts SDK clients only, never reconfigures their transport."""
        try:
            with self.lock:
                if client in self.clients or self.closed:
                    return
                self.clients.add(client)
            events = client.meta.events
            for event, handler, suffix in (('before-call', self._before, 'before'),
                    ('needs-retry', self._retry, 'retry'), ('after-call', self._after, 'after'),
                    ('after-call-error', self._error, 'error')):
                events.register_first(event + '.*.*', handler, unique_id='peaso-aws-metrics-' + suffix)
        except Exception:
            pass

    def flush(self, reason='manual'):
        """Emit cumulative changed rows, or every row at final flush; never throw."""
        if reason not in {'manual', 'periodic', 'final'}:
            return False
        if not self.flush_lock.acquire(timeout=.25):
            return False
        try:
            with self.lock:
                keys = sorted(self.rows if reason == 'final' else self.dirty)
                rows = [dict(self.rows[key], service=key[0], operation=key[1],
                             inflight=self.rows[key]['calls'] - self.rows[key]['completed']) for key in keys]
                self.dirty.difference_update(keys)
            emitted = True
            for offset in range(0, len(rows), MAX_ROWS):
                self.sequence += 1
                event = dict(schema=1, sequence=self.sequence, reason=reason,
                    uptime_ms=_bounded(int(max(0, self.clock() - self.started) * 1000)),
                    rows=rows[offset:offset + MAX_ROWS])
                clean = safe_metrics(event)
                if clean is None:
                    emitted = False
                    continue
                try:
                    self.sink((_FRAME, clean))
                except Exception:
                    emitted = False
            return emitted
        except Exception:
            return False
        finally:
            self.flush_lock.release()

    def _periodic(self):
        while not self.stop.wait(self.interval):
            self.flush('periodic')

    def close(self):
        global _ACTIVE
        if self.closed:
            return
        self.stop.set()
        try:
            if (self.thread is not None and self.thread is not threading.current_thread()
                    and self.thread.ident is not None):
                self.thread.join(timeout=.25)
        except Exception:
            # Diagnostics must still flush and restore the SDK factory when
            # background-thread cleanup fails. Preserve control-flow signals.
            pass
        self.flush('final')
        self.closed = True
        try:
            with _INSTALL_LOCK:
                if self.session_class is not None and self.session_class.create_client is self.wrapper:
                    self.session_class.create_client = self.original
                if _ACTIVE is self:
                    _ACTIVE = None
            for client in list(self.clients):
                for event, suffix in (('before-call', 'before'), ('needs-retry', 'retry'),
                        ('after-call', 'after'), ('after-call-error', 'error')):
                    client.meta.events.unregister(event + '.*.*', unique_id='peaso-aws-metrics-' + suffix)
        except Exception:
            pass


def install(sink, *, interval=INTERVAL_SECONDS):
    """Install once before AWS collection; caller chooses the trusted IPC sink.

    Returns None if diagnostics cannot initialize. The worker remains responsible
    for calling close() before its terminal result frame and for opting in via
    platform runtime configuration, rather than any cloud resource field.
    """
    global _ACTIVE
    if not callable(sink):
        return None
    try:
        import botocore.session
        with _INSTALL_LOCK:
            if _ACTIVE is not None and _ACTIVE.pid == os.getpid() and not _ACTIVE.closed:
                return _ACTIVE
            metrics = Metrics(sink, interval=interval)
            cls = botocore.session.Session
            original = cls.create_client
            if (_ACTIVE is not None and _ACTIVE.pid != os.getpid()
                    and original is _ACTIVE.wrapper):
                original = _ACTIVE.original
            @wraps(original)
            def create_client(session, *args, **kwargs):
                client = original(session, *args, **kwargs)
                metrics.attach(client)
                return client
            metrics.original, metrics.wrapper, metrics.session_class = original, create_client, cls
            cls.create_client = create_client
            _ACTIVE = metrics
            metrics.thread = threading.Thread(target=metrics._periodic, name='aws-sdk-metrics', daemon=True)
            metrics.thread.start()
            return metrics
    except Exception:
        candidate = locals().get('metrics')
        if candidate is not None:
            candidate.close()
        return None
