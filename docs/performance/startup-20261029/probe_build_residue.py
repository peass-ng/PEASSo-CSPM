"""Offline probe; run only in a disposable worker container as root.

Deletes /app/build in that container. Hashes retained application/installed
package files, verifies imports, and measures removed logical/tar/gzip bytes.
The gzip result is a proxy, not an OCI registry-layer measurement.
"""
import gzip
import hashlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import time


def inventory():
    digest = hashlib.sha256()
    count = size = 0
    roots = [Path('/app'), Path('/usr/local/lib/python3.12/site-packages')]
    for root in roots:
        for path in sorted(root.rglob('*')):
            if Path('/app/build') in path.parents or path == Path('/app/build'):
                continue
            if not path.is_file():
                continue
            content = path.read_bytes()
            digest.update(str(path).encode() + b'\0' + hashlib.sha256(content).digest())
            count += 1
            size += len(content)
    return {'files': count, 'bytes': size, 'sha256': digest.hexdigest()}


def smoke():
    # Fresh interpreter per arm prevents sys.modules from hiding a dependency
    # on the removed tree. -c from /app matches the worker's module search path.
    code = '''
import importlib, importlib.metadata, json, sys
names = ['peaso', 'peaso.worker', 'peaso.engine', 'peaso.checks',
         'peaso.ai.runner', 'peaso.server.scheduler_handler']
result = {name: importlib.import_module(name).__file__ for name in names}
assert all(value.startswith('/app/peaso/') for value in result.values()), result
result['distribution_version'] = importlib.metadata.version('hacktricks-cspm')
assert not any('/app/build' in entry for entry in sys.path)
print(json.dumps(result))
'''
    return json.loads(subprocess.check_output([sys.executable, '-c', code], cwd='/app'))


def main():
    start = time.monotonic()
    build = Path('/app/build')
    assert build.is_dir()
    files = [path for path in build.rglob('*') if path.is_file()]
    raw_bytes = sum(path.stat().st_size for path in files)
    tar_buffer = io.BytesIO()
    with tarfile.open(fileobj=tar_buffer, mode='w') as archive:
        archive.add(build, arcname='app/build')
    tar_bytes = tar_buffer.getvalue()
    compressed_bytes = len(gzip.compress(tar_bytes, compresslevel=6, mtime=0))
    before = inventory()
    imported_before = smoke()
    shutil.rmtree(build)
    after = inventory()
    imported_after = smoke()
    assert before == after
    assert imported_before == imported_after
    print(json.dumps({
        'removed_files': len(files), 'removed_file_bytes': raw_bytes,
        'removed_tar_bytes': len(tar_bytes), 'gzip6_tar_proxy_bytes': compressed_bytes,
        'retained_before': before, 'retained_after': after,
        'imports': imported_after, 'retained_bytes_equal': True,
        'network': 'none (container launch)', 'cloud_calls': 0, 'model_calls': 0,
        'elapsed_seconds': time.monotonic() - start,
        'limitation': 'Existing image probe; no OCI layer or production latency claim.',
    }, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
