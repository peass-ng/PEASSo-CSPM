"""Synthetic diagnostic-overhead check; no provider calls or scanner workload."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import resource
import sys
import time

from peaso import collection_job_metrics as jobs, runtime_metrics as metrics


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', choices=('baseline', 'instrumented'), required=True)
    parser.add_argument('--jobs', type=int, default=1352)
    args = parser.parse_args()
    counts = {'job_events': 0, 'summary_events': 0, 'diagnostic_bytes': 0}
    def sink(message):
        tag, event = message
        if tag == '__collection_job_metrics__':
            counts['summary_events' if 'summary' in event else 'job_events'] += 1
            counts['diagnostic_bytes'] += len(jobs.MARKER) + len(json.dumps(
                event, sort_keys=True, separators=(',', ':')).encode()) + 1
    metrics.configure(sink, role='collector', interval_seconds=60)
    # Exclude first-use roster loading from the repeated-job measurement.
    jobs.roster()
    def read(index):
        kwargs = {} if args.mode == 'baseline' else {
            'job_kind': 'vpc', 'job_scope': 'synthetic-scope-' + str(index % 16)}
        with metrics.span('collection.job', **kwargs):
            return {'ordinal': index, 'status': 'empty', 'items': []}
    start_wall, start_cpu = time.monotonic(), time.process_time()
    with ThreadPoolExecutor(max_workers=16) as pool:
        output = list(pool.map(read, range(args.jobs)))
    metrics.close()
    wall, cpu = time.monotonic() - start_wall, time.process_time() - start_cpu
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    print(json.dumps(dict(mode=args.mode, jobs=args.jobs, wall_s=wall, cpu_s=cpu,
        peak_rss_bytes=peak if sys.platform == 'darwin' else peak * 1024,
        output_sha256=hashlib.sha256(json.dumps(output, sort_keys=True,
            separators=(',', ':')).encode()).hexdigest(), **counts), sort_keys=True))


if __name__ == '__main__':
    main()
