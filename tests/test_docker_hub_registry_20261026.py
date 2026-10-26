import hashlib
import json

import pytest

from peaso.collectors import docker_hub_registry_20261026 as hub
from peaso.collectors import k8s_selected_registry_image_20261021 as image

BLOB = b'layer-bytes'
DIGEST = 'sha256:' + hashlib.sha256(BLOB).hexdigest()
CDN = ('https://production.cloudfront.docker.com/registry-v2/docker/registry/v2/blobs/sha256/'
       + DIGEST[7:9] + '/' + DIGEST[7:] + '/data?expires=1&signature=x')
CDN_PATH = '/registry-v2/docker/registry/v2/blobs/sha256/' + DIGEST[7:9] + '/' + DIGEST[7:] + '/data'


class Response:
    def __init__(self, status, body=b'', headers=None):
        self.status, self.body = status, body
        self.headers = {'Content-Length': str(len(body)), **(headers or {})}

    def read(self, n=-1):
        out, self.body = (self.body, b'') if n < 0 else (self.body[:n], self.body[n:])
        return out

    def close(self):
        pass


class Conn:
    def close(self):
        pass


def wire(routes, log):
    def open_https(host, path, headers, timeout):
        log.append((host, path.split('?')[0], headers.get('Authorization')))
        return Conn(), routes[(host, path.split('?')[0])]()
    return open_https


def token(body=None, status=200):
    raw = json.dumps(body if body is not None else {'token': 'tok', 'access_token': 'tok'}).encode()
    return lambda: Response(status, raw, {'Content-Type': 'application/json'})


def read(reader):
    return reader.get('blobs', DIGEST, 1024, size=len(BLOB))


def test_docker_hub_uses_registry_1_with_anonymous_pull_token_and_digest_bound_cdn():
    log = []
    routes = {('auth.docker.io', '/token'): token(),
              ('registry-1.docker.io', '/v2/library/nginx/blobs/' + DIGEST): lambda: Response(307, b'', {'Location': CDN}),
              ('production.cloudfront.docker.com', CDN_PATH): lambda: Response(200, BLOB)}
    reader = image.RegistryReader('docker.io', 'library/nginx', lambda: None, open_https=wire(routes, log))
    assert read(reader) == BLOB
    assert read(reader) == BLOB
    assert log[0] == ('auth.docker.io', '/token', None)
    assert [entry[0] for entry in log].count('auth.docker.io') == 1
    assert log[1] == ('registry-1.docker.io', '/v2/library/nginx/blobs/' + DIGEST, 'Bearer tok')
    assert log[2][0] == 'production.cloudfront.docker.com' and log[2][2] is None
    assert [r['status'] for r in reader.receipts] == ['collected', 'collected']


def test_token_request_scope_and_basic_credential():
    seen = []
    def open_https(host, path, headers, timeout):
        seen.append((host, path, headers.get('Authorization')))
        return Conn(), token()()
    assert hub.pull_token(open_https, 'library/python', 'Basic dXNlcjpwdw==', 1, image.Incomplete) == 'Bearer tok'
    assert seen == [('auth.docker.io', '/token?service=registry.docker.io&scope=repository%3Alibrary%2Fpython%3Apull',
                     'Basic dXNlcjpwdw==')]
    assert not hub.uses_token('docker.io', 'Bearer given') and hub.uses_token('docker.io', None)
    assert not hub.uses_token('ghcr.io', None)


@pytest.mark.parametrize('body,status', [({'token': 'bad token'}, 200), ({}, 200), ({'token': 'x'}, 500), ({'token': 'x'}, 401)])
def test_bad_token_responses_fail_closed(body, status):
    open_https = lambda host, path, headers, timeout: (Conn(), token(body, status)())
    with pytest.raises(image.Incomplete):
        hub.pull_token(open_https, 'library/nginx', None, 1, image.Incomplete)


def test_manifest_redirect_still_refused_on_docker_hub():
    log = []
    routes = {('auth.docker.io', '/token'): token(),
              ('registry-1.docker.io', '/v2/library/nginx/manifests/' + DIGEST): lambda: Response(301, b'', {'Location': CDN})}
    reader = image.RegistryReader('docker.io', 'library/nginx', lambda: None, open_https=wire(routes, log))
    with pytest.raises(image.Incomplete, match='redirect_unsupported'):
        reader.get('manifests', DIGEST, 1024)


@pytest.mark.parametrize('location', [
    CDN.replace(DIGEST[7:], 'a' * 64),
    CDN.replace('production.cloudfront.docker.com', 'evil.example.com'),
    CDN.replace('https://', 'http://'),
    CDN.replace('.com/', '.com:8443/'),
    CDN.replace('/data?', '/data/../x?'),
    'https://www.docker.com/',
    '/v2/library/nginx/blobs/' + DIGEST,
])
def test_cdn_redirect_only_for_exact_blob(location):
    with pytest.raises(image.Incomplete, match='redirect_unsupported'):
        hub.blob_redirect(location, DIGEST, image.Incomplete)


def test_second_cdn_hop_refused():
    log = []
    routes = {('auth.docker.io', '/token'): token(),
              ('registry-1.docker.io', '/v2/library/nginx/blobs/' + DIGEST): lambda: Response(307, b'', {'Location': CDN}),
              ('production.cloudfront.docker.com', CDN_PATH): lambda: Response(307, b'', {'Location': CDN})}
    reader = image.RegistryReader('docker.io', 'library/nginx', lambda: None, open_https=wire(routes, log))
    with pytest.raises(image.Incomplete, match='redirect_unsupported'):
        read(reader)


def test_other_registries_unchanged():
    log = []
    routes = {('ghcr.io', '/v2/org/app/blobs/' + DIGEST): lambda: Response(307, b'', {'Location': CDN})}
    reader = image.RegistryReader('ghcr.io', 'org/app', lambda: None, open_https=wire(routes, log))
    with pytest.raises(image.Incomplete, match='redirect_unsupported'):
        read(reader)
    assert log == [('ghcr.io', '/v2/org/app/blobs/' + DIGEST, None)]
