"""Bounded transient performance counters. Never part of findings or evidence.

Wall and thread CPU totals are additive per stage; nested/concurrent stages
may overlap. Process CPU and RSS are whole-process measurements, not exclusive
attribution. Only registered code-owned labels and numeric measurements leave
this process. Diagnostics never change a scan verdict or propagate sink errors.
"""
from contextlib import contextmanager
import json
import math
try:
    import resource
except ImportError:  # Windows/local installs keep diagnostics optional.
    resource = None
import sys
import threading
import time

_STAGES = frozenset("""
aws.rate_limit.cloudtrail aws.rate_limit.iam aws.retry_wait
image.database.acquire image.database.download
secret.kingfisher.lock_wait secret.kingfisher.native secret.trufflehog.prepared_process
secret.trufflehog.cohort_clean secret.trufflehog.cohort_prepare secret.trufflehog.ecs_queue_wait
worker.startup worker.collect worker.evaluate worker.redact worker.private_checkpoint
worker.public_checkpoint worker.final_snapshot worker.ai worker.final_publish
worker.iam_usage worker.checkpoint.finish worker.checkpoint.close worker.private_document
engine.validate engine.resources engine.index engine.native_checks engine.analysis
engine.graphs engine.privesc engine.finalize collection.job collection.queue_wait collection.automatic_content_scope
publication.normalize.private publication.normalize.reviews publication.normalize.group
publication.inventory publication.expand_native publication.markdown
publication.chunk.findings publication.chunk.coverage publication.chunk.resources
publication.projection.least_privilege publication.projection.graphs
publication.projection.network_snapshot publication.manifest.commit
artifact.serialize artifact.compress artifact.s3.put artifact.batch.wait artifact.file.write
""".split())
_FIELDS = frozenset({'stage','count','wall_ms','thread_cpu_ms','process_cpu_ms','max_wall_ms','errors','bytes'})
_recorder = None


def _rss():
    try:
        value = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return int(value if sys.platform == 'darwin' else value * 1024)
    except (AttributeError, OSError, ValueError):
        return 0


def _children_cpu_ms():
    try:
        usage = resource.getrusage(resource.RUSAGE_CHILDREN)
        return int((usage.ru_utime + usage.ru_stime) * 1000)
    except (AttributeError, OSError, ValueError):
        return 0


class Recorder:
    def __init__(self, sink, role, interval):
        self.sink, self.role = sink, role
        self.lock = threading.Lock()
        self.rows, self.active = {}, {}
        self.started, self.cpu_started = time.monotonic(), time.process_time()
        self.children_started = _children_cpu_ms()
        self.stop = threading.Event()
        self.interval = max(1.0, min(60.0, interval))
        self.thread = threading.Thread(target=self._heartbeat, name='peaso-runtime-metrics', daemon=True)
        self.thread.start()

    def _heartbeat(self):
        while not self.stop.wait(self.interval):
            self.flush()

    def flush(self):
        try:
            now = time.monotonic()
            with self.lock:
                rows = [dict(v) for _,v in sorted(self.rows.items())]
                active = {}
                for stage, started in self.active.values():
                    row = active.setdefault(stage, {'stage':stage,'count':0,'oldest_ms':0})
                    row['count'] += 1
                    row['oldest_ms'] = max(row['oldest_ms'], int((now-started)*1000))
            event = {'version':1,'role':self.role,'elapsed_ms':int((now-self.started)*1000),
                'process_cpu_ms':int((time.process_time()-self.cpu_started)*1000),
                'peak_rss_bytes':_rss(), 'rows':rows,'active':list(active.values()),
                'completed_children_cpu_ms':max(0, _children_cpu_ms()-self.children_started)}
            # One bounded frame, at most the fixed stage roster, no per-call log.
            if validate(event):
                self.sink(('__runtime_metrics__', event))
        except Exception:
            pass

    def row(self, stage):
        return self.rows.setdefault(stage,dict(stage=stage,count=0,wall_ms=0,
            thread_cpu_ms=0,process_cpu_ms=0,max_wall_ms=0,errors=0,bytes=0))


def configure(sink, *, role, interval_seconds=30):
    global _recorder
    close()
    if (callable(sink) and type(role) is str and role in {'collector','analyzer'}
            and type(interval_seconds) in (int, float) and 0 <= interval_seconds <= 3600
            and math.isfinite(interval_seconds)):
        try:
            _recorder = Recorder(sink, role, interval_seconds)
        except Exception:
            _recorder = None


def flush():
    if _recorder is not None:
        _recorder.flush()


def close():
    global _recorder
    recorder, _recorder = _recorder, None
    if recorder is not None:
        recorder.stop.set()
        if threading.current_thread() is not recorder.thread:
            try:
                recorder.thread.join(timeout=0.2)
            except (RuntimeError, OSError):
                pass
        recorder.flush()


@contextmanager
def span(stage):
    recorder = _recorder
    if recorder is None or type(stage) is not str or stage not in _STAGES:
        yield
        return
    try:
        wall, thread_cpu, process_cpu = time.monotonic(), time.thread_time(), time.process_time()
    except Exception:
        yield
        return
    token = object()
    with recorder.lock:
        recorder.active[token] = (stage, wall)
    failed = False
    try:
        yield
    except BaseException:
        failed = True
        raise
    finally:
        try:
            elapsed = max(0,int((time.monotonic()-wall)*1000))
            thread_elapsed = max(0,int((time.thread_time()-thread_cpu)*1000))
            process_elapsed = max(0,int((time.process_time()-process_cpu)*1000))
            with recorder.lock:
                row = recorder.row(stage)
                row['count'] += 1
                row['wall_ms'] += elapsed
                row['thread_cpu_ms'] += thread_elapsed
                row['process_cpu_ms'] += process_elapsed
                row['max_wall_ms'] = max(row['max_wall_ms'], elapsed)
                row['errors'] += int(failed)
        except Exception:
            pass
        finally:
            with recorder.lock:
                recorder.active.pop(token, None)


def add_bytes(stage, count):
    recorder = _recorder
    if recorder is not None and type(stage) is str and stage in _STAGES and type(count) is int and 0 <= count <= 10**18:
        with recorder.lock:
            recorder.row(stage)['bytes'] += count


def validate(event):
    required = {'version','role','elapsed_ms','process_cpu_ms','peak_rss_bytes','rows','active'}
    if type(event) is not dict or set(event) not in (required, required | {'completed_children_cpu_ms'}):
        return False
    if (type(event['version']) is not int or event['version'] != 1
            or type(event['role']) is not str or event['role'] not in {'collector','analyzer'}):
        return False
    numeric = lambda x: type(x) is int and 0 <= x <= 10**18
    if ('completed_children_cpu_ms' in event and not numeric(event['completed_children_cpu_ms'])):
        return False
    if not all(numeric(event[k]) for k in ('elapsed_ms','process_cpu_ms','peak_rss_bytes')):
        return False
    for key, fields in (('rows', _FIELDS),('active', frozenset({'stage','count','oldest_ms'}))):
        if type(event[key]) is not list or len(event[key]) > len(_STAGES):
            return False
        seen = set()
        for row in event[key]:
            if type(row) is not dict or set(row) != fields or type(row['stage']) is not str or row['stage'] not in _STAGES or row['stage'] in seen:
                return False
            seen.add(row['stage'])
            if not all(numeric(v) for k,v in row.items() if k != 'stage'):
                return False
    return True


def record(event, logger):
    if not validate(event):
        return False
    try:
        logger.info('peaso runtime metrics: %s',json.dumps(event,sort_keys=True,separators=(',',':')))
        return True
    except Exception:
        return False
