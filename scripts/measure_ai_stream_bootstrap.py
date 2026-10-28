#!/usr/bin/env python3
"""Offline memory measurement of a download larger than its container's RAM."""
import hashlib
import json
from pathlib import Path
import resource
import tempfile
import time
import sys
sys.path.insert(0, '/app')
import requests
from peaso.ai import task_runtime

SIZE = 192 * 1024 * 1024
CHUNK = b'cached-snapshot-evidence-' * 2048
CHUNK = (CHUNK + b'x' * 65536)[:65536]
class Response:
    status_code = 200
    def __enter__(self): return self
    def __exit__(self, *args): pass
    def iter_content(self, size):
        assert size == 65536
        for _ in range(SIZE // size):
            yield CHUNK
class Session:
    def __enter__(self): return self
    def __exit__(self, *args): pass
    def request(self, *args, **kwargs):
        assert kwargs['stream'] is True
        return Response()
requests.Session = Session
wall, cpu = time.perf_counter(), time.process_time()
with tempfile.TemporaryFile(dir='/scratch') as sink:
    assert task_runtime.relay_request('GET', '/input', 'synthetic', sink=sink, limit=SIZE) is None
    assert sink.tell() == SIZE
    sink.seek(0)
    digest = hashlib.sha256()
    while chunk := sink.read(65536):
        assert chunk == CHUNK
        digest.update(chunk)
    result = {'download_bytes': SIZE, 'chunk_bytes': len(CHUNK), 'exact_bytes_verified': SIZE,
              'sha256': digest.hexdigest(), 'cloud_api_calls': 0, 'network': 'none',
              'wall_seconds': round(time.perf_counter()-wall, 3),
              'cpu_seconds': round(time.process_time()-cpu, 3),
              'process_peak_rss_bytes': resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024}
for name in ('memory.max', 'memory.peak'):
    result['cgroup_'+name] = (Path('/sys/fs/cgroup')/name).read_text().strip()
print(json.dumps(result, sort_keys=True))
