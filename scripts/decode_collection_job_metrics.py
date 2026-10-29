#!/usr/bin/env python3
"""Decode hashed inventory labels from saved job diagnostics, entirely offline."""
import argparse
import hashlib
import json
from pathlib import Path

from peaso.collection_job_metrics import (MARKER, MAX_RETAINED_JOBS, MAX_STREAMED_JOBS,
                                        ROSTER_SHA256, JobRetention, roster,
                                        validate, validate_job)


def decode(events):
    retained = JobRetention()
    for event in events:
        message = event.get('message', '')
        retained.accept(message)
    return decode_retained(retained.result())


def decode_retained(result):
    fields = {'version', 'roster_sha256', 'jobs', 'summary', 'invalid_events', 'overflow_events'}
    if (type(result) is not dict or result.keys() != fields or result['version'] != 1
            or result['roster_sha256'] != ROSTER_SHA256 or type(result['jobs']) is not list
            or len(result['jobs']) > MAX_STREAMED_JOBS + MAX_RETAINED_JOBS
            or any(type(result[k]) is not int or result[k] < 0 for k in ('invalid_events', 'overflow_events'))
            or any(not validate_job(row) for row in result['jobs'])
            or len({row['job'] for row in result['jobs']}) != len(result['jobs'])
            or (result['summary'] is not None and not validate(result['summary']))):
        raise ValueError('invalid saved job retention envelope')
    labels = roster()
    rows = [dict(row, inventory_kind=labels[row['kind_sha256']]) for row in result['jobs']]
    return {**result, 'captured_job_count': len(rows), 'unknown_kind_count': 0,
            'longest_jobs': sorted(rows, key=lambda r: (-r['wall_ms'], r['job']))[:20],
            'jobs': sorted(rows, key=lambda r: r['job']),
            'limit': 'Completed events only; scope hashes are opaque within-run bindings. Input completeness needs the final collection.job count; this decoder cannot prove log completeness.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--events', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--scan-id')
    args = parser.parse_args()
    raw = args.events.read_bytes()
    retained = None
    try:
        saved = json.loads(raw)
    except ValueError:
        events = [{'message': line} for line in raw.decode().splitlines()]
    else:
        if isinstance(saved, dict) and 'roles' in saved:
            if args.scan_id is not None and saved.get('scan_id') != args.scan_id:
                parser.error('saved scan does not match --scan-id')
            roles = [r for r in saved['roles'] if r.get('role') == 'collector'
                     and 'collection_job_metrics' in r]
            if len(roles) != 1:
                parser.error('compact saved receipt lacks retained collection_job_metrics')
            retained = roles[0]['collection_job_metrics']
        elif isinstance(saved, dict) and 'scans' in saved:
            tasks = [t for s in saved['scans'] if args.scan_id is None or s['scan_id'] == args.scan_id
                     for t in s.get('tasks', []) if t.get('role') == 'collector'
                     and 'collection_job_metrics' in t]
            if len(tasks) != 1:
                parser.error('select exactly one saved collector with retained job metrics using --scan-id')
            retained = tasks[0]['collection_job_metrics']
        else:
            events = saved['events'] if isinstance(saved, dict) else saved
    result = {'schema': 'collection-job-timing-decode-v1',
              'source_sha256': hashlib.sha256(raw).hexdigest(),
              **(decode_retained(retained) if retained is not None else decode(events))}
    args.output.write_text(json.dumps(result, sort_keys=True, indent=2) + '\n')


if __name__ == '__main__':
    main()
