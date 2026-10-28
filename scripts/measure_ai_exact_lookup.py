#!/usr/bin/env python3
"""Measure one exact local lookup; emit metrics only, never source values."""
import contextlib
import io
import json
import os
from pathlib import Path
import resource
import runpy
import sys
import time

root, *arguments = sys.argv[1:]
os.chdir(root)
sys.argv = ['context.py', *arguments]
output = io.StringIO()
wall, cpu = time.perf_counter(), time.process_time()
with contextlib.redirect_stdout(output):
    runpy.run_path('context.py', run_name='__main__')
result = json.loads(output.getvalue())
peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
if sys.platform != 'darwin':
    peak *= 1024
metrics = {'wall_seconds': round(time.perf_counter()-wall, 6),
           'cpu_seconds': round(time.process_time()-cpu, 6), 'process_peak_rss_bytes': peak,
           'output_bytes': len(output.getvalue().encode()),
           'error': result.get('error') if isinstance(result, dict) else None,
           'total': result.get('total') if isinstance(result, dict) else None,
           'returned_items': len(result.get('items', [])) if isinstance(result, dict) else None}
for name in ('memory.max', 'memory.peak'):
    path = Path('/sys/fs/cgroup')/name
    if path.exists():
        metrics['cgroup_'+name] = path.read_text().strip()
print(json.dumps(metrics, sort_keys=True))
