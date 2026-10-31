"""Full privilege queries over a cached graph index; synthetic, no cloud calls."""
import argparse
import hashlib
import json
import random
import statistics
import time
import tracemalloc
from peaso.privesc import queries


def fixture(size):
    names = [f'p-{i:08}' for i in range(size)]
    random.Random(42).shuffle(names)
    nodes = [{'id': p, 'kind': 'principal', 'label': p, 'type': 'role'} for p in names]
    nodes.append({'id': 'admin', 'kind': 'entity', 'type': 'aws_account_admin'})
    edges = [{'id': f'e-{i}', 'source': p, 'target': 'admin', 'confidence': ['derived', 'conditional', 'unknown'][i % 3]} for i, p in enumerate(names)]
    return {'nodes': nodes, 'edges': edges}


def reference(index, query, offset, limit, **kwargs):
    rows = getattr(queries, query)(index, **kwargs)
    selected = rows[offset:offset + limit]
    more = offset + len(selected) < len(rows)
    return {'items': selected, 'offset': offset, 'limit': limit, 'total': len(rows),
            'has_more': more, 'next_offset': offset + len(selected) if more else None}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--size', type=int, default=50000)
    args = parser.parse_args()
    index = queries.GraphIndex(fixture(args.size))
    output = {}
    for query in ['reach_admin', 'broad_reach']:
        methods = {'baseline': lambda: reference(index, query, 0, 100, include_unknown=True),
                   'candidate': lambda: getattr(queries, query + '_page')(index, offset=0, limit=100, include_unknown=True)}
        expected = methods['baseline']()
        assert methods['candidate']() == expected
        cpu, wall = {k: [] for k in methods}, {k: [] for k in methods}
        for name in ['baseline', 'candidate', 'candidate', 'baseline'] * 2:
            started_cpu, started_wall = time.process_time(), time.perf_counter()
            result = methods[name]()
            cpu[name].append(time.process_time() - started_cpu)
            wall[name].append(time.perf_counter() - started_wall)
            assert result == expected
        output[query] = {}
        for name, method in methods.items():
            tracemalloc.start()
            result = method()
            _, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()
            assert result == expected
            output[query][name] = {'cpu_seconds': statistics.median(cpu[name]),
                'wall_seconds': statistics.median(wall[name]), 'peak_allocated_bytes': peak}
        output[query]['response_sha256'] = hashlib.sha256(json.dumps(expected, sort_keys=True).encode()).hexdigest()
    print(json.dumps(output, indent=2))


if __name__ == '__main__':
    main()
