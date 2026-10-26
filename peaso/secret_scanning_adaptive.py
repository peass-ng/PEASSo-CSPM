"""Isolated proposal: caller must consume each yielded prepared group in place."""
import threading
import time
import math
from contextlib import contextmanager


class AdaptiveTH:
    def __init__(self, prepare, stdout_bound, *, output_limit=4*1024*1024,
                 max_items=2048, max_bytes=64*1024*1024, clock=time.monotonic,
                 small_timeout=60, min_probe_seconds=5):
        if (type(output_limit)is not int or not 0<output_limit<=4*1024*1024
                or type(max_items)is not int or not 1<=max_items<=2048
                or type(max_bytes)is not int or not 0<max_bytes<=64*1024*1024):
            raise ValueError('adaptive policy bound')
        self.prepare, self.stdout_bound, self.clock = prepare, stdout_bound, clock
        self.output_limit, self.max_items, self.max_bytes = output_limit, max_items, max_bytes
        if not 0<small_timeout<=60 or not 0<min_probe_seconds<=60:
            raise ValueError('adaptive timeout bound')
        self.small_timeout,self.min_probe_seconds=small_timeout,min_probe_seconds
        self.large_lock = threading.Lock()
        self.large_disabled = False
        self.metrics = dict(large_attempts=0, stdout_bounds=0, small_attempts=0,
                            consumed_sources=0, peak_retained_output_bytes=0,
                            reserve_skips=0)

    @contextmanager
    def prepared_groups(self, items, *, deadline, cancelled=None):
        iterator=self.groups(items,deadline=deadline,cancelled=cancelled)
        try:yield iterator
        finally:iterator.close()

    def groups(self, items, *, deadline, cancelled=None):
        if (type(deadline)not in (int,float) or not math.isfinite(deadline)):
            raise ValueError('adaptive deadline bound')
        if (type(items) is not list or len(items)>self.max_items
                or any(type(item) is not tuple or len(item)!=2
                       or not isinstance(item[0],bytes) or not isinstance(item[1],str) for item in items)
                or sum(len(item[0]) for item in items)>self.max_bytes):
            raise ValueError('adaptive input bound')
        def remaining():
            if cancelled is not None and cancelled.is_set():
                raise TimeoutError('adaptive cancelled')
            value=deadline-self.clock()
            if not math.isfinite(value)or value<=0:raise TimeoutError('adaptive deadline')
            return value
        def invoke(group, timeout=None):
            budget=min(self.small_timeout,remaining()) if timeout is None else min(timeout,remaining())
            result=self.prepare(group,budget)
            if (not isinstance(result,dict) or set(result)!=set(group)
                    or any(not isinstance(value,bytes)for value in result.values())):
                if isinstance(result,dict):result.clear()
                raise RuntimeError('adaptive preparation incomplete')
            # Sharing identical NDJSON across exact payload aliases is allowed;
            # distinct output bytes never exceed one invocation's retained cap.
            retained=sum(len(value) for value in {id(v):v for v in result.values()}.values())
            if retained>self.output_limit:
                result.clear()
                raise ValueError('adaptive retained output bound')
            try:remaining()
            except BaseException:
                result.clear()
                raise
            self.metrics['peak_retained_output_bytes']=max(self.metrics['peak_retained_output_bytes'],retained)
            return result
        prepared=None
        fallback_reserve=((len(items)+511)//512)*self.small_timeout
        admission=(len(items)>512 and not self.large_disabled
            and remaining()>=fallback_reserve+self.min_probe_seconds)
        if len(items)>512 and not self.large_disabled and not admission:
            self.metrics['reserve_skips']+=1
        if admission:
            # Serialize large attempts so one scan cannot race several oversized
            # invocations before the first observed stdout-bound transition.
            while not self.large_lock.acquire(timeout=min(.05,remaining())):
                pass
            try:
                remaining()
                # A failed speculative probe must not consume the legacy
                # preparation allowance of every original <=512 subgroup.
                # This is the caller's existing absolute lease, never a new
                # deadline. Consumer work still shares that same lease.
                fallback_reserve=((len(items)+511)//512)*self.small_timeout
                probe_budget=min(self.small_timeout,remaining()-fallback_reserve)
                if not self.large_disabled and probe_budget>=self.min_probe_seconds:
                    self.metrics['large_attempts']+=1
                    try:prepared=invoke(items,probe_budget)
                    except Exception as error:
                        if not self.stdout_bound(error):raise
                        self.large_disabled=True
                        self.metrics['stdout_bounds']+=1
                elif not self.large_disabled:
                    self.metrics['reserve_skips']+=1
            finally:self.large_lock.release()
        if prepared is not None:
            try:
                remaining()
                yield items,prepared
                self.metrics['consumed_sources']+=len(items)
            finally:prepared.clear()
            return
        for offset in range(0,len(items),512):
            group=items[offset:offset+512]
            self.metrics['small_attempts']+=1
            prepared=invoke(group)
            try:
                remaining()
                yield group,prepared
                self.metrics['consumed_sources']+=len(group)
            finally:prepared.clear()


def archive_batch_items(requests):
    """Use only the existing archive lease; absent/short leases keep legacy512."""
    from .collection_lease import effective_deadline
    deadline=effective_deadline(requests)
    if getattr(getattr(requests,'_archive_adaptive_th',None),'large_disabled',False):return 512
    if type(deadline)not in (int,float)or not math.isfinite(deadline):return 512
    return 2048 if deadline-time.monotonic()>=245 else 512


@contextmanager
def prepared_archive_batches(rows,requests):
    """Consume exact native rows within one caller-owned archive/image only."""
    from . import secret_scanning_batch as batch
    from .secret_scanning_errors import ScannerStdoutBound
    if (type(rows)is not list or len(rows)>2048
            or any(type(row)is not tuple or len(row)<2 or not isinstance(row[0],bytes)
                or not isinstance(row[1],str)for row in rows)
            or sum(len(row[0])for row in rows)>batch.MAX_BATCH_BYTES):
        raise ValueError('adaptive archive input bound')
    from .collection_lease import effective_deadline
    deadline=effective_deadline(requests)
    finite=type(deadline)in (int,float)and math.isfinite(deadline)
    items=[(row[0],row[1])for row in rows]
    from .collection_lease import check as check_lease
    def legacy(start=0):
        for offset in range(start,len(rows),512):
            group=rows[offset:offset+512]
            check_lease(requests)
            with batch.prepared_content_batch([(row[0],row[1])for row in group],timeout=60):
                yield group
    def adaptive():
        # State is scoped to this native Requests/scan. It retains no payload,
        # prepared map, source name or result; only bounded policy/counters.
        with requests._lock:
            state=getattr(requests,'_archive_adaptive_th',None)
            if state is None:
                state=AdaptiveTH(batch._prepare_trufflehog_batch,lambda error:type(error)is ScannerStdoutBound)
                requests._archive_adaptive_th=state
        offset=0;started=time.monotonic()
        with state.prepared_groups(items,deadline=deadline,cancelled=getattr(requests,'cancel_event',None))as groups:
            while True:
                try:group,prepared=next(groups)
                except StopIteration:break
                except Exception:
                    # Preserve the existing per-source engines/partial-positive
                    # behavior on unavailable or malformed preparation. This
                    # catches preparation only, never original consumer errors.
                    groups.close()
                    yield from legacy(offset)
                    return
                check_lease(requests)
                count=len(group)
                if group!=items[offset:offset+count]:raise RuntimeError('adaptive archive source order')
                original=rows[offset:offset+count];offset+=count
                metrics=None
                if batch._METRICS_SENDER is not None:
                    unique=set(payload for payload,_ in group)
                    metrics=dict(schema=1,batch=next(batch._METRICS_SEQUENCE),items=count,
                        input_bytes=sum(len(payload)for payload,_ in group),unique_payloads=len(unique),
                        unique_bytes=sum(map(len,unique)),prepared=1,reason='none',
                        preparation_ms=max(0,int((time.monotonic()-started)*1000)),consumer_ms=0,
                        lookups=0,prepared_reads=0,serial_lookups=0,consumer_failed=0)
                token=batch._PREPARED_BATCH.set(prepared);mtoken=batch._BATCH_METRICS.set(metrics)
                consumed=time.monotonic()
                try:yield original
                except BaseException:
                    if metrics is not None:metrics['consumer_failed']=1
                    raise
                finally:
                    if metrics is not None:metrics['consumer_ms']=max(0,int((time.monotonic()-consumed)*1000))
                    batch._BATCH_METRICS.reset(mtoken);batch._PREPARED_BATCH.reset(token)
                    if metrics is not None:batch._metric_emit(metrics)
                started=time.monotonic()
        if offset!=len(rows):raise RuntimeError('adaptive archive sources omitted')
    iterator=adaptive()if finite and len(rows)>512 else legacy()
    try:yield iterator
    finally:iterator.close()
