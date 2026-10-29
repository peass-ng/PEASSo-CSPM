"""Profile numeric startup from saved receipts; never contacts cloud services."""
import argparse
from datetime import datetime
import hashlib
import json
from pathlib import Path


def timestamp(value):
    if isinstance(value, (float, int)):
        return datetime.fromtimestamp(value, tz=__import__('datetime').timezone.utc)
    return datetime.fromisoformat(value.replace('Z', '+00:00'))


def profile(receipt, task=None):
    queued = timestamp(receipt['times_utc']['queued'])
    workflow = timestamp(receipt['workflow']['start_utc'])
    collect = timestamp(receipt['times_utc']['collecting'])
    if not queued <= workflow <= collect:
        raise ValueError('Startup timestamps are not chronological')
    seconds = {
        'queued_to_workflow': (workflow - queued).total_seconds(),
        'workflow_to_collect': (collect - workflow).total_seconds(),
        'queued_to_collect': (collect - queued).total_seconds(),
    }
    # The pre-workflow interval includes dispatch/auth/admission, not just polling.
    # Even eliminating ALL of it cannot save more than this observed duration.
    seconds['dispatch_elimination_upper_bound'] = seconds['queued_to_workflow']
    if task:
        points = [workflow]
        for key in ['CreatedAt', 'PullStartedAt', 'PullStoppedAt', 'StartedAt']:
            value = task.get(key, task.get(key[0].lower() + key[1:]))
            if value is None:
                raise ValueError('Missing ECS task timestamp: ' + key)
            points.append(timestamp(value))
        points.append(collect)
        if points != sorted(points):
            raise ValueError('ECS timestamps are not chronological')
        keys = ['workflow_to_task_created', 'created_to_pull_start', 'image_pull',
                'pull_stop_to_started', 'started_to_collect']
        seconds.update({key: (end - start).total_seconds()
                        for key, start, end in zip(keys, points, points[1:])})
    return {'provider': receipt['provider'], 'scan_id': receipt['scan_id'],
            'seconds': {key: round(value, 6) for key, value in seconds.items()},
            'ecs_decomposition_available': task is not None}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('receipts', nargs='+', type=Path)
    args = parser.parse_args()
    rows = []
    for path in args.receipts:
        raw = path.read_bytes()
        row = profile(json.loads(raw))
        row['source_sha256'] = hashlib.sha256(raw).hexdigest()
        rows.append(row)
    print(json.dumps({'scans': rows, 'cloud_calls': 0, 'model_calls': 0,
                      'limitation': 'Pre-workflow includes admission/auth/dispatch; '
                                    'post-workflow is not image-pull time alone.'},
                     indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
