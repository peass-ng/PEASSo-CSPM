"""Docker Hub endpoints for the selected registry image reader, as the Docker client uses them.

Image references name the registry ``docker.io`` (``index.docker.io`` is already
normalized to it, and one-part names to ``library/``). Its v2 API is served by
``registry-1.docker.io``: requests go there directly instead of following
docker.io's redirect, so the general no-redirect policy for manifests stays.
Pull tokens come only from the fixed realm ``https://auth.docker.io/token`` for
service ``registry.docker.io`` and the selected repository's pull scope. A blob
may be redirected once to Docker's blob CDN, only for that exact blob digest;
the reader still drops credentials across hosts and verifies size and digest.
"""
import json
import re
from urllib.parse import quote, urlsplit

REGISTRY = 'docker.io'
API_HOST = 'registry-1.docker.io'
AUTH_HOST = 'auth.docker.io'
SERVICE = 'registry.docker.io'
CDN_HOSTS = frozenset(('production.cloudfront.docker.com', 'production.cloudflare.docker.com'))
MAX_TOKEN_RESPONSE = 64 * 1024
MAX_TOKEN = 8192
_REPOSITORY = re.compile(r'[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*(?:/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)+\Z')
_PRINTABLE = re.compile(r'[\x21-\x7e]{1,%d}\Z' % MAX_TOKEN)


def api_host(registry):
    """The host that serves this registry's v2 API."""
    return API_HOST if registry == REGISTRY else registry


def uses_token(registry, authorization):
    """Docker Hub needs a pull token unless the connector supplied a bearer token."""
    return registry == REGISTRY and not (type(authorization) is str and authorization.startswith('Bearer '))


def pull_token(open_https, repository, authorization, timeout, incomplete):
    """Return 'Bearer <token>' for pulling `repository` (anonymous or with Basic credentials)."""
    if type(repository) is not str or len(repository) > 255 or not _REPOSITORY.fullmatch(repository):
        raise incomplete('registry_token_unavailable')
    path = ('/token?service=' + SERVICE + '&scope=' +
            quote('repository:' + repository + ':pull', safe=''))
    headers = {'Accept': 'application/json', 'Accept-Encoding': 'identity', 'Cache-Control': 'no-store'}
    if type(authorization) is str and authorization.startswith('Basic '):
        headers['Authorization'] = authorization
    connection = response = None
    try:
        connection, response = open_https(AUTH_HOST, path, headers, timeout)
        if response.status != 200:
            raise incomplete('registry_denied' if response.status in (401, 403) else 'registry_token_unavailable')
        if (response.headers.get('Content-Encoding', 'identity').lower() != 'identity'
                or response.headers.get('Content-Type', '').split(';')[0].strip().lower() != 'application/json'):
            raise incomplete('registry_token_unavailable')
        body = response.read(MAX_TOKEN_RESPONSE + 1)
        if type(body) is not bytes or len(body) > MAX_TOKEN_RESPONSE:
            raise incomplete('registry_token_unavailable')
        document = json.loads(body.decode('utf-8'))
        token = document.get('token') or document.get('access_token') if type(document) is dict else None
        if type(token) is not str or not _PRINTABLE.fullmatch(token):
            raise incomplete('registry_token_unavailable')
        return 'Bearer ' + token
    except (ValueError, UnicodeError):
        raise incomplete('registry_token_unavailable') from None
    finally:
        if response is not None:
            response.close()
        if connection is not None:
            connection.close()


def blob_redirect(location, digest, incomplete):
    """Accept one redirect to Docker's blob CDN object for exactly `digest`."""
    if type(location) is not str or len(location) > 8192 or type(digest) is not str:
        raise incomplete('redirect_unsupported')
    try:
        url = urlsplit(location)
        port = url.port
    except (ValueError, TypeError):
        raise incomplete('redirect_unsupported') from None
    hexdigest = digest[7:] if digest.startswith('sha256:') else ''
    expected = '/registry-v2/docker/registry/v2/blobs/sha256/' + hexdigest[:2] + '/' + hexdigest + '/data'
    if (url.scheme != 'https' or url.hostname not in CDN_HOSTS or url.netloc != url.hostname
            or port not in (None, 443) or url.username is not None or url.password is not None
            or url.fragment or not re.fullmatch(r'[0-9a-f]{64}', hexdigest) or url.path != expected
            or '\\' in location or any(ord(ch) < 33 or ord(ch) > 126 for ch in location)):
        raise incomplete('redirect_unsupported')
    return url.hostname, url.path + ('?' + url.query if url.query else '')
