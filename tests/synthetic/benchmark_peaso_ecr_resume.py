"""Loopback HTTP recovery replay; no cloud calls or workload contents.

The transport adapter maps a synthetic allowed S3 URL to the local fixture.
Production endpoint validation and response checks still execute. This tests
real HTTP truncation/Range framing, not AWS TLS or live transfer throughput.
"""
import argparse
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import json
from pathlib import Path
import socket
import tempfile
import threading
import time
from types import SimpleNamespace
from urllib.request import Request, build_opener

URL = 'https://fixture.s3.us-east-1.amazonaws.com/layer?private=synthetic-canary'
REGION = 'us-east-1'


class LocalFixture:
    def __init__(self, payload, *, prefix=None, mode='recover', delay=0):
        self.payload = payload
        self.prefix = len(payload)//2 if prefix is None else prefix
        self.mode, self.delay = mode, delay
        self.requests, self.bytes_sent = [], 0
        self.lock = threading.Lock()
        fixture = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.0'

            def log_message(self, *args):
                pass

            def do_GET(self):
                requested = self.headers.get('Range')
                with fixture.lock:
                    fixture.requests.append(requested)
                    attempt = len(fixture.requests)
                offset = int(requested[6:-1]) if requested else 0
                total = len(fixture.payload)
                status = 206 if requested else 200
                if requested and fixture.mode == 'ignored_range':
                    status, offset = 200, 0
                if requested and fixture.mode == 'redirect':
                    self.send_response(302)
                    self.send_header('Location', 'http://127.0.0.1:1/denied')
                    self.end_headers()
                    return
                self.send_response(status)
                if requested:
                    start = offset+1 if fixture.mode == 'wrong_start' else offset
                    end = total-2 if fixture.mode == 'wrong_end' else total-1
                    declared = total+1 if fixture.mode == 'wrong_total' else total
                    self.send_header('Content-Range', f'bytes {start}-{end}/{declared}')
                    if fixture.mode == 'gzip':
                        self.send_header('Content-Encoding', 'gzip')
                if fixture.mode != 'extra' or not requested:
                    length = total-offset+(1 if requested and fixture.mode == 'wrong_length' else 0)
                    self.send_header('Content-Length', str(length))
                self.end_headers()
                body = fixture.payload[offset:]
                if fixture.mode != 'clean' and attempt == 1:
                    body = body[:fixture.prefix]
                elif requested and fixture.mode == 'always_short':
                    body = body[:max(1, len(body)//2)]
                if requested and fixture.mode == 'corrupt':
                    body = bytes([body[0] ^ 1])+body[1:]
                if requested and fixture.mode == 'extra':
                    body += b'extra'
                try:
                    for position in range(0, len(body), 65536):
                        chunk = body[position:position+65536]
                        self.wfile.write(chunk)
                        self.wfile.flush()
                        with fixture.lock:
                            fixture.bytes_sent += len(chunk)
                        if fixture.delay:
                            time.sleep(fixture.delay)
                except (BrokenPipeError, ConnectionResetError):
                    pass
                self.close_connection = True
                try:
                    self.connection.shutdown(socket.SHUT_WR)
                except OSError:
                    pass

        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       kwargs={'poll_interval': .01})

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *args):
        self.server.shutdown()
        self.thread.join()
        self.server.server_close()

    def opener(self, *handlers):
        original = build_opener(*handlers)
        local = f'http://127.0.0.1:{self.server.server_port}/layer'

        class Response:
            def __init__(self, response):
                self.response = response
            def __getattr__(self, name):
                return getattr(self.response, name)
            def geturl(self):
                return URL
            def __enter__(self):
                self.response.__enter__()
                return self
            def __exit__(self, *args):
                return self.response.__exit__(*args)

        class Opener:
            def open(self, request, **kwargs):
                headers = request.headers if isinstance(request, Request) else {}
                if isinstance(request, Request):
                    assert request.full_url == URL and request.get_method() == 'GET'
                else:
                    assert request == URL
                return Response(original.open(Request(local, headers=headers), **kwargs))

        return Opener()


def requests():
    return SimpleNamespace(_lock=threading.RLock(), max_calls=None, calls=0,
        check_deadline=lambda: None, deadline=None, timeout=3)


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def measure(module, payload, mode, restart):
    from peaso.collectors import aws_package_content_indicators as content
    original = content.build_opener
    digest = 'sha256:'+hashlib.sha256(payload).hexdigest()
    try:
        with tempfile.TemporaryDirectory(prefix='peaso-http-recovery-') as folder:
            path = Path(folder)/'layer'
            Path(folder).chmod(0o700)
            with LocalFixture(payload, prefix=3*len(payload)//4, mode=mode, delay=.001) as server:
                content.build_opener = server.opener
                state = requests()
                start = time.perf_counter()
                failures = 0
                try:
                    module.download_blob_path(state, URL, REGION, digest, len(payload), path)
                except ValueError:
                    failures += 1
                    assert restart and not path.exists()
                    module.download_blob_path(state, URL, REGION, digest, len(payload), path)
                elapsed = time.perf_counter()-start
                assert path.read_bytes() == payload
                result = dict(wall_seconds=elapsed, http_attempts=state.calls,
                    transferred_bytes=server.bytes_sent, external_restarts=failures,
                    range_requests=sum(value is not None for value in server.requests),
                    file_sha256=digest, file_mode=oct(path.stat().st_mode & 0o777))
        return result
    finally:
        content.build_opener = original


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('baseline', type=Path)
    parser.add_argument('candidate', type=Path)
    parser.add_argument('--mib', type=int, default=32)
    args = parser.parse_args()
    assert 1 <= args.mib <= 128
    before = load(args.baseline, 'peaso.collectors._ecr_before')
    after = load(args.candidate, 'peaso.collectors._ecr_after')
    payload = (b'owned-layer-fixture-'*((args.mib*1024*1024)//20+1))[:args.mib*1024*1024]
    # Warm the common validator/archive imports and both function paths equally.
    measure(before, payload[:1024*1024], 'clean', restart=False)
    measure(after, payload[:1024*1024], 'clean', restart=False)
    output = []
    for mode in ('clean', 'recover'):
        old = measure(before, payload, mode, restart=True)
        new = measure(after, payload, mode, restart=False)
        assert old['file_sha256'] == new['file_sha256'] and old['file_mode'] == new['file_mode']
        output.append(dict(mode=mode, before=old, after=new))
    print(json.dumps(dict(cloud_calls=0, fixture='loopback HTTP, controlled truncation and1ms/64KiB delay',
                          results=output), indent=2))
