"""Bounded overlap of independent selected ACR image vulnerability reads.

Each target owns a private receipt list; the caller numbers receipts afterwards
in selection order, so output is identical to a serial run. Registry reads,
layer downloads and the offline scanner subprocess wait on I/O, which two
workers overlap without adding scanner processes beyond the selection.
"""
from concurrent.futures import ThreadPoolExecutor
from contextvars import copy_context

MAX_PARALLEL_IMAGES = 2


def scan_targets(jobs, scan, workers=MAX_PARALLEL_IMAGES):
    """Yield (row, private receipts) in job order; the first failure propagates."""
    def run(job):
        receipts = []
        return scan(job[0], job[1], receipts), receipts
    workers = max(1, min(int(workers), len(jobs)))
    if workers == 1:
        for job in jobs:
            yield run(job)
        return
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix='peaso-acr-image') as pool:
        futures = [pool.submit(copy_context().run, run, job) for job in jobs]
        try:
            for future in futures:
                yield future.result()
        finally:
            for future in futures:
                future.cancel()
