"""Offline ABBA of complete-context listing; emits only numeric/hash receipts.

Uses private disposable copies. Never imports an agent, SDK or credentials.
The source database is opened read-only and its file hash is checked unchanged.
"""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import sqlite3
import tempfile
import time


INDEX_SQL = 'CREATE INDEX record_all_order ON records(domain,risk,id)'


def file_hash(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def content(db):
    """Hash every cell of every source table, including complete native values."""
    result = {}
    tables = db.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name").fetchall()
    for (name,) in tables:
        digest = hashlib.sha256()
        count = 0
        quoted = '"' + name.replace('"', '""') + '"'
        for row in db.execute('SELECT * FROM ' + quoted + ' ORDER BY rowid'):
            count += 1
            digest.update(b'row:')
            for value in row:
                data = value if isinstance(value, bytes) else str(value).encode('utf-8')
                digest.update(type(value).__name__.encode() + b':' + str(len(data)).encode() + b':')
                digest.update(data)
        result[name] = {'rows': count, 'sha256': digest.hexdigest()}
    return result


def workload(db):
    measurements = []
    # Representative actual reader SQL, not a claim about observed model tools.
    for domain in ('resources', 'findings', 'decision_findings'):
        for offset in (0, 200):
            for candidates in (False, True):
                where = 'domain=?' + (' AND candidate=1' if candidates else '')
                cpu, start = time.process_time(), time.perf_counter()
                total = db.execute('SELECT COUNT(*) FROM records WHERE ' + where, (domain,)).fetchone()[0]
                rows = db.execute('SELECT summary FROM records WHERE ' + where +
                                  ' ORDER BY risk,id LIMIT ? OFFSET ?', (domain, 8, offset)).fetchall()
                wall = time.perf_counter() - start
                cpu = time.process_time() - cpu
                rendered = json.dumps({'total': total, 'offset': offset,
                                       'items': [json.loads(row[0]) for row in rows]},
                                      ensure_ascii=False, default=str).encode()
                measurements.append({'domain': domain, 'offset': offset, 'candidates': candidates,
                                     'wall_s': wall, 'cpu_s': cpu,
                                     'result_sha256': hashlib.sha256(rendered).hexdigest()})
    return measurements


def transport(source, directory):
    """Production gzip settings, with exact expanded-byte verification."""
    packed, expanded = Path(directory) / 'transport.gz', Path(directory) / 'expanded.sqlite'
    start, cpu = time.perf_counter(), time.process_time()
    with source.open('rb') as inp, packed.open('wb') as raw:
        with gzip.GzipFile(filename='', mode='wb', fileobj=raw, compresslevel=1, mtime=0) as out:
            shutil.copyfileobj(inp, out, 1024 * 1024)
    result = {'compress_wall_s': time.perf_counter() - start,
              'compress_cpu_s': time.process_time() - cpu, 'packed_bytes': packed.stat().st_size}
    start, cpu = time.perf_counter(), time.process_time()
    digest = hashlib.sha256()
    with gzip.open(packed, 'rb') as inp, expanded.open('wb') as out:
        while chunk := inp.read(1024 * 1024):
            out.write(chunk)
            digest.update(chunk)
    result.update(expand_and_hash_wall_s=time.perf_counter() - start,
                  expand_and_hash_cpu_s=time.process_time() - cpu,
                  expanded_bytes=expanded.stat().st_size, expanded_sha256=digest.hexdigest())
    assert result['expanded_sha256'] == file_hash(source), 'transport_bytes_changed'
    packed.unlink()
    expanded.unlink()
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('database', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--transport', action='store_true', help='Also time exact gzip/expansion on each copy')
    args = parser.parse_args()
    before = file_hash(args.database)
    with sqlite3.connect(args.database.resolve().as_uri() + '?mode=ro', uri=True) as db:
        expected = content(db)
    runs = []
    with tempfile.TemporaryDirectory(prefix='peaso-ai-context-abba-') as directory:
        for candidate in (False, True, True, False):
            path = Path(directory) / 'context.sqlite'
            shutil.copyfile(args.database, path)
            os.chmod(path, 0o600)
            with sqlite3.connect(path) as db:
                db.execute('PRAGMA cache_size=-2048')
                db.execute('PRAGMA temp_store=FILE')
                original_size = path.stat().st_size
                cpu, start = time.process_time(), time.perf_counter()
                if candidate:
                    db.execute(INDEX_SQL)
                    db.commit()
                build_wall = time.perf_counter() - start
                build_cpu = time.process_time() - cpu
                measurements = workload(db)
                # Validate all cells once after indexing, outside timed queries.
                if candidate and len(runs) == 1:
                    assert content(db) == expected, 'complete_source_content_changed'
                run = {'candidate': candidate, 'index_build_wall_s': build_wall,
                             'index_build_cpu_s': build_cpu,
                             'index_bytes': path.stat().st_size - original_size,
                             'queries': measurements,
                       'query_wall_s': sum(row['wall_s'] for row in measurements)}
                if args.transport:
                    run['transport'] = transport(path, directory)
                runs.append(run)
            path.unlink()
    reference = [row['result_sha256'] for row in runs[0]['queries']]
    assert all([row['result_sha256'] for row in run['queries']] == reference for run in runs)
    assert file_hash(args.database) == before, 'saved_source_modified'
    result = {'version': 1, 'source_file_sha256': before, 'source_bytes': args.database.stat().st_size,
              'python': platform.python_version(), 'sqlite': sqlite3.sqlite_version,
              'runs': runs, 'complete_table_content': expected, 'complete_content_equal': True,
              'query_outputs_equal': True, 'saved_source_unchanged': True,
              'provider_calls': 0, 'model_calls': 0, 'access_analyzer_calls': 0,
              'limitations': ['Historical AWS saved context, not one of the four current scans.',
                              'Representative lookup workload; actual model tool count is unavailable.',
                              'Warm operating-system cache; no production latency or model quality claim.']}
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(result, stream, indent=2, sort_keys=True)
        stream.write('\n')
    print(json.dumps({'complete_content_equal': True, 'query_outputs_equal': True,
                      'runs_query_wall_s': [run['query_wall_s'] for run in runs]}))


if __name__ == '__main__':
    main()
