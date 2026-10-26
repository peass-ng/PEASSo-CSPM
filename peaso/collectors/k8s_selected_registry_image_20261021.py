"""Explicit Pod-bound OCI inspection; no Kubernetes Secret or Docker access."""
import base64
from copy import deepcopy
from contextlib import ExitStack
import hashlib
import http.client
import ipaddress
import json
from pathlib import Path
import re
import socket
import ssl
import tempfile
import time
from urllib.parse import quote, unquote, urlsplit
from uuid import uuid4

from peaso import container_image_archive_20261020 as archive
from peaso import oci_index_20261021 as oci_index
from peaso.secret_evidence import scan_with_source, source_context
from peaso.secret_scanning import scan_content, merge_leaks
from peaso.secret_scanning_batch import prepared_content_batch, MAX_BATCH_ITEMS, MAX_BATCH_BYTES
from peaso import k8s_image_source_association_20261020 as association
from peaso import k8s_image_source_association_current_20261023 as current_association

SECRET_KIND = 'k8s_selected_registry_image_secrets'
VULN_KIND = 'k8s_selected_registry_image_vulnerabilities'
SECRET_CHECK = 'k8s.review.selected_registry_image_secret_indicators'
VULN_CHECK = 'k8s.review.selected_registry_image_high_vulnerabilities'
OPTION = 'selected_k8s_registry_images'
ALLOWLIST = 'selected_registry_hosts'
SCHEMA = 'k8s-selected-registry-image-v1'
MAX_TARGETS = 2
MAX_SECONDS = 600
MAX_CALLS = 70
MAX_BLOB_REDIRECTS = 2
MAX_TOTAL = archive.MAX_COMPRESSED + archive.MAX_MANIFEST
MAX_FILE_SCAN = 32 * 1024 * 1024
MAX_SCAN = 256 * 1024 * 1024
MAX_REDACTION_VALUES = 512
MAX_REDACTION_BYTES = 65536
WINDOW = 1024 * 1024
OVERLAP = 4096
HOST = re.compile(r'[a-z0-9](?:[a-z0-9.-]{1,251}[a-z0-9])\Z')
LABEL = re.compile(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z')
POD = re.compile(r'[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?\Z')
TOKEN = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z')
FIELDS = {'cluster_id', 'namespace', 'pod', 'uid', 'resource_version', 'container_type', 'container_name', 'image'}
AUTH_FIELD = 'registry_auth'


class Incomplete(ValueError):
    """Stable local reason; never includes URL, response, token or content."""


class RedactionOverflow(BaseException):
    """Abort snapshot output when detected values cannot all be redacted."""


def redaction_callback(matches):
    """Keep the full bounded plaintext union only until snapshot finalization."""
    def add(values):
        if type(values) not in (set, frozenset):
            raise RedactionOverflow('redaction_ledger_bound')
        try:
            fresh = values - matches
            if (any(type(value) is not str or not value or len(value.encode('utf-8')) > 8192
                    for value in fresh) or len(matches) + len(fresh) > MAX_REDACTION_VALUES
                    or sum(len(value.encode('utf-8')) for value in matches) +
                       sum(len(value.encode('utf-8')) for value in fresh) > MAX_REDACTION_BYTES):
                raise RedactionOverflow('redaction_ledger_bound')
        except (TypeError, UnicodeError):
            raise RedactionOverflow('redaction_ledger_bound') from None
        matches.update(fresh)
    return add


def _host(value):
    if (type(value) is not str or not HOST.fullmatch(value) or '.' not in value
            or '..' in value or value.endswith(('.local', '.internal', '.localhost', '.test', '.invalid'))
            or value.startswith(('localhost.', 'metadata.', '169.254.'))):
        raise Incomplete('unsupported_registry_host')
    try:
        ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        raise Incomplete('ip_literal_registry_unsupported')
    if any(not LABEL.fullmatch(part) for part in value.split('.')):
        raise Incomplete('unsupported_registry_host')
    return value


def selected_targets(options, scopes, named=()):
    """Validate all supplied selectors and host grants before any credentials or I/O."""
    if type(options) is not dict or ('content_secret_scans' in options and type(options['content_secret_scans']) is not bool) or ('image_vulnerability_scans' in options and type(options['image_vulnerability_scans']) is not bool):
        raise Incomplete('invalid_selection')
    if any(key in options for key in ('trivy_db_cache', 'trivy_cli')):
        raise Incomplete('trivy_runtime_configuration_is_not_a_request_option')
    if any(key in options for key in (AUTH_FIELD, 'registry_auth_document', 'image_pull_secret')):
        raise Incomplete('registry_credentials_must_be_separate')
    active = ((options.get('content_secret_scans') is True and SECRET_CHECK in named)
              or (options.get('image_vulnerability_scans') is True and VULN_CHECK in named))
    if OPTION not in options and ALLOWLIST not in options and not active:
        return []
    targets, hosts = options.get(OPTION), options.get(ALLOWLIST)
    if (type(scopes) is not list or not 1 <= len(scopes) <= 4 or any(type(s) is not str or not LABEL.fullmatch(s) for s in scopes)
            or type(targets) is not list or not 1 <= len(targets) <= MAX_TARGETS
            or type(hosts) is not list or not 1 <= len(hosts) <= 4
            or any(type(h) is not str for h in hosts) or len(set(hosts)) != len(hosts)):
        raise Incomplete('invalid_selection')
    for host in hosts:
        _host(host)
    seen = set()
    for target in targets:
        if type(target) is not dict or set(target) != FIELDS:
            raise Incomplete('invalid_selection')
        cluster, namespace, pod = (target[k] for k in ('cluster_id', 'namespace', 'pod'))
        if (type(cluster) is not str or not 1 <= len(cluster) <= 512 or not cluster.isascii()
                or any(ord(c) < 33 or ord(c) > 126 for c in cluster)
                or type(namespace) is not str or namespace not in scopes or not LABEL.fullmatch(namespace)
                or type(pod) is not str or not POD.fullmatch(pod)
                or any(not LABEL.fullmatch(part) for part in pod.split('.'))
                or any(type(target[k]) is not str or not TOKEN.fullmatch(target[k]) for k in ('uid', 'resource_version'))
                or target['container_type'] not in ('regular', 'init', 'ephemeral')
                or type(target['container_name']) is not str or not LABEL.fullmatch(target['container_name'])):
            raise Incomplete('invalid_selection')
        try:
            image = association.parse_image_reference(target['image'])
        except Exception:
            raise Incomplete('invalid_selection') from None
        if (image.digest is None or not image.explicit_registry or image.tag is not None
                or image.immutable_reference != target['image'] or _host(image.registry) not in hosts):
            raise Incomplete('invalid_selection')
        key = (cluster, namespace, pod, target['uid'], target['container_type'], target['container_name'])
        if key in seen:
            raise Incomplete('duplicate_selection')
        seen.add(key)
    return deepcopy(targets)


def registry_credentials(auth, targets, allowed_hosts):
    """Validate explicit encrypted connector auth against selected digest repositories."""
    if type(auth) is not dict:
        raise Incomplete('invalid_registry_auth')
    entries = auth.get(AUTH_FIELD, [])
    if type(entries) is not list or len(entries) > MAX_TARGETS:
        raise Incomplete('invalid_registry_auth')
    selected = set()
    for target in targets:
        image = association.parse_image_reference(target['image'])
        selected.add((image.registry, image.repository))
    credentials = {}
    for entry in entries:
        if type(entry) is not dict or entry.get('method') not in ('basic', 'bearer'):
            raise Incomplete('invalid_registry_auth')
        method = entry['method']
        expected = {'host', 'repository', 'method', 'token'} if method == 'bearer' else {'host', 'repository', 'method', 'username', 'password'}
        if set(entry) != expected:
            raise Incomplete('invalid_registry_auth')
        host, repository = entry['host'], entry['repository']
        if (type(host) is not str or _host(host) != host or host not in allowed_hosts
                or type(repository) is not str or (host, repository) not in selected
                or (host, repository) in credentials):
            raise Incomplete('foreign_registry_auth')
        if method == 'bearer':
            token = entry['token']
            if (type(token) is not str or not 1 <= len(token) <= 8192 or not token.isascii()
                    or any(ord(c) < 33 or ord(c) > 126 for c in token)):
                raise Incomplete('invalid_registry_auth')
            header = 'Bearer ' + token
        else:
            username, password = entry['username'], entry['password']
            if (type(username) is not str or not 1 <= len(username) <= 512 or ':' in username
                    or type(password) is not str or not 1 <= len(password) <= 8192
                    or not username.isascii() or not password.isascii()
                    or any(ord(c) < 33 or ord(c) > 126 for c in username + password)):
                raise Incomplete('invalid_registry_auth')
            header = 'Basic ' + base64.b64encode((username + ':' + password).encode()).decode()
        credentials[(host, repository)] = (method, header)
    return credentials


def enabled(options, named):
    return (options.get('content_secret_scans') is True and SECRET_CHECK in named,
            options.get('image_vulnerability_scans') is True and VULN_CHECK in named)


def identity(target):
    return 'k8s-registry-image:' + hashlib.sha256(json.dumps(target, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def bind_pod(target, pod):
    selection = {'cluster_id': target['cluster_id'], 'api_version': 'v1', 'kind': 'Pod',
                 'namespace': target['namespace'], 'name': target['pod'], 'uid': target['uid'],
                 'container_type': target['container_type'], 'container_name': target['container_name']}
    result = current_association.resolve_image_source(selection, pod, cluster_id=target['cluster_id'])
    native = result.get('pod', {})
    if (result.get('status') != 'associated' or result.get('immutable_reference') != target['image']
            or native.get('resource_version') != target['resource_version']):
        raise Incomplete('pod_image_binding')
    return result


def _open_https(host, path, headers, timeout):
    """Resolve once, reject every non-global address, pin chosen IP for TLS/SNI."""
    addresses = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    if not addresses or len(addresses) > 16:
        raise Incomplete('registry_dns_unavailable')
    for record in addresses:
        if not ipaddress.ip_address(record[4][0]).is_global:
            raise Incomplete('nonpublic_registry_address')
    address = addresses[0][4][0]
    raw = socket.create_connection((address, 443), timeout=timeout)
    try:
        tls = ssl.create_default_context().wrap_socket(raw, server_hostname=host)
    except BaseException:
        raw.close()
        raise
    connection = http.client.HTTPConnection(host, timeout=timeout)
    connection.sock = tls
    try:
        connection.request('GET', path, headers={**headers, 'Host': host})
        return connection, connection.getresponse()
    except BaseException:
        connection.close()
        raise


def _gar_blob_redirect(host, repository, location):
    """One provider-issued same-origin GAR path bound to the selected repository.

    Mirrors the native GCP reader's relative /artifacts-downloads contract.
    The ordinary public-IP/TLS transport, byte limit and digest check still run.
    """
    if (type(repository) is not str or len(repository) > 1024
            or type(location) is not str or len(location) > 2048
            or '\\' in location or any(ord(c) < 33 or ord(c) > 126 for c in location)):
        raise Incomplete('redirect_unsupported')
    parts = repository.split('/')
    if (len(parts) < 3 or not re.fullmatch(r'[a-z][a-z0-9-]{4,61}[a-z0-9]', parts[0])
            or not re.fullmatch(r'[a-z0-9][a-z0-9._-]{0,127}', parts[1])):
        raise Incomplete('redirect_unsupported')
    prefix = '/artifacts-downloads/namespaces/' + parts[0] + '/repositories/' + parts[1] + '/downloads/'
    if not location.startswith(prefix):
        raise Incomplete('redirect_unsupported')
    try:
        target = urlsplit(location)
        decoded = unquote(location, errors='strict')
    except (UnicodeError, ValueError):
        raise Incomplete('redirect_unsupported') from None
    if (target.scheme or target.netloc or target.query or target.fragment
            or target.path != location or not decoded.startswith(prefix)
            or decoded.count('/') != location.count('/')
            or '\\' in decoded or any(c in decoded for c in ('%', '?', '#'))
            or any(ord(c) < 33 or ord(c) > 126 for c in decoded)
            or any(part in ('', '.', '..') for part in decoded[1:].split('/'))):
        raise Incomplete('redirect_unsupported')
    return host, location


def _blob_redirect(host, location, repository=None):
    if type(host) is str and re.fullmatch(r'[a-z][a-z0-9-]*-docker\.pkg\.dev', host):
        return _gar_blob_redirect(host, repository, location)
    """Accept only MCR's public regional blob CDN, never arbitrary registry redirects."""
    if host != 'mcr.microsoft.com' or type(location) is not str or len(location) > 8192:
        raise Incomplete('redirect_unsupported')
    try:
        url = urlsplit(location)
        cdn = _host(url.hostname)
        port = url.port
    except (ValueError, TypeError):
        raise Incomplete('redirect_unsupported') from None
    if (url.scheme != 'https' or port not in (None, 443) or url.username is not None
            or url.password is not None or url.fragment or not cdn.endswith('.data.mcr.microsoft.com')
            or cdn == 'data.mcr.microsoft.com' or not url.path.startswith('/')
            or '\\' in location or any(ord(ch) < 33 or ord(ch) > 126 for ch in location)):
        raise Incomplete('redirect_unsupported')
    return cdn, url.path + ('?' + url.query if url.query else '')


class RegistryReader:
    def __init__(self, host, repository, check, *, authorization=None, open_https=_open_https):
        self.host, self.repository, self.cancel, self.open_https = _host(host), repository, check, open_https
        self.authorization = authorization
        self.end, self.calls, self.total, self.receipts = time.monotonic() + MAX_SECONDS, 0, 0, []

    def check(self):
        self.cancel()
        if time.monotonic() >= self.end:
            raise Incomplete('registry_deadline')

    def get(self, category, digest, cap, *, size=None, destination=None):
        self.check()
        if (time.monotonic() >= self.end or self.calls >= MAX_CALLS or category not in ('manifests', 'blobs')
                or type(digest) is not str or not archive.DIGEST.fullmatch(digest)
                or type(cap) is not int or not 0 < cap <= archive.MAX_LAYER
                or size is not None and (type(size) is not int or not 0 < size <= cap)):
            raise Incomplete('registry_read_bound')
        path = '/v2/' + '/'.join(quote(part, safe='') for part in self.repository.split('/')) + '/' + category + '/' + digest
        record = {'id': 'registry-read-' + uuid4().hex, 'method': 'GET', 'category': category,
                  'digest': digest, 'status': 'unavailable', 'bytes': 0}
        self.receipts.append(record)
        connection = response = None
        try:
            headers = {'Accept': ', '.join((archive.OCI, archive.DOCKER, oci_index.OCI_INDEX, oci_index.DOCKER_LIST)) if category == 'manifests' else 'application/octet-stream',
                       'Accept-Encoding': 'identity', 'Cache-Control': 'no-store'}
            if self.authorization is not None:
                headers['Authorization'] = self.authorization
            current_host, current_path = self.host, path
            for hop in range(MAX_BLOB_REDIRECTS + 1):
                self.check()
                if self.calls >= MAX_CALLS:
                    raise Incomplete('registry_read_bound')
                self.calls += 1
                connection, response = self.open_https(current_host, current_path, headers,
                                                        min(10, max(.1, self.end-time.monotonic())))
                status = response.status
                if status not in (301, 302, 303, 307, 308):
                    break
                if category != 'blobs' or hop >= MAX_BLOB_REDIRECTS:
                    raise Incomplete('redirect_unsupported')
                if re.fullmatch(r'[a-z][a-z0-9-]*-docker\.pkg\.dev', self.host) and (status != 302 or hop != 0
                        or response.headers.get('Content-Encoding', 'identity') != 'identity'
                        or response.headers.get('WWW-Authenticate') is not None):
                    raise Incomplete('redirect_unsupported')
                next_host, next_path = _blob_redirect(self.host, response.headers.get('Location'), self.repository)
                response.close()
                connection.close()
                response = connection = None
                if next_host != current_host:
                    headers.pop('Authorization', None)
                    headers.pop('Cookie', None)
                current_host, current_path = next_host, next_path
            if status != 200:
                if status in (401, 403):
                    record['status'] = 'denied'
                raise Incomplete('registry_denied' if status in (401, 403) else 'redirect_unsupported' if 300 <= status < 400 else 'registry_unavailable')
            headers = response.headers
            length = headers.get('Content-Length')
            if (type(length) is not str or not length.isascii() or not length.isdecimal()
                    or not 0 < int(length) <= cap or size is not None and int(length) != size
                    or headers.get('Content-Encoding', 'identity').lower() != 'identity'
                    or headers.get('Content-Range') is not None or headers.get('Transfer-Encoding') is not None):
                raise Incomplete('registry_framing')
            if category == 'manifests' and headers.get('Content-Type', '').split(';')[0].lower() not in oci_index.ALL_MANIFEST_TYPES:
                raise Incomplete('unsupported_manifest')
            if headers.get('Docker-Content-Digest', digest) != digest:
                raise Incomplete('registry_digest_header')
            if destination is not None and (not isinstance(destination, Path) or not destination.is_absolute()):
                raise Incomplete('owned_destination_required')
            checksum, count, chunks = hashlib.sha256(), 0, []
            with destination.open('xb') if destination is not None else _NullWriter() as output:
                while True:
                    self.check()
                    chunk = response.read(min(65536, int(length) + 1 - count))
                    if type(chunk) is not bytes:
                        raise Incomplete('registry_stream')
                    if not chunk:
                        break
                    count += len(chunk)
                    self.total += len(chunk)
                    if count > int(length) or self.total > MAX_TOTAL:
                        raise Incomplete('registry_byte_bound')
                    checksum.update(chunk)
                    if destination is not None:
                        output.write(chunk)
                    else:
                        chunks.append(chunk)
            if count != int(length) or 'sha256:' + checksum.hexdigest() != digest:
                raise Incomplete('registry_truncated_or_digest')
            record.update(status='collected', bytes=count)
            return destination if destination is not None else b''.join(chunks)
        except Incomplete:
            raise
        except Exception as exc:
            if getattr(exc, 'code', None) in ('collection_cancelled', 'intentional_scan_deadline', 'deadline_exceeded'):
                raise
            raise Incomplete('registry_unavailable') from None
        finally:
            if response is not None:
                response.close()
            if connection is not None:
                connection.close()


class _NullWriter:
    def __enter__(self): return self
    def __exit__(self, *_): return False


def _scan(raw, path, source, check, leaks, parts, *, redact_values=None):
    check()
    result = scan_with_source(scan_content, raw, path, source=source, timeout=15,
                              _redact_values=redact_values)
    leaks.extend(result['leaks'])
    parts.append({'part': path, 'bytes': len(raw), 'complete': result['complete'], 'engines': result['engines']})
    if len(leaks) > 256 or sum(len(v['locations']) for v in leaks) > 2000:
        raise Incomplete('finding_bound')
    if result['complete'] is not True:
        raise Incomplete('detectors_incomplete')
    check()


def inspect(target, pod_get, *, allowed_hosts=(), credentials=None, registry_factory=RegistryReader, scanner=_scan, cancel=lambda: None,
            secret_enabled=True,
            trivy_enabled=False, trivy_runner=None, trivy_db=None, trivy_cli=None,
            redact_values=None):
    """Inspect every supported child of the exact native Pod image digest."""
    ident = identity(target)
    parent_digest = target['image'].rsplit('@', 1)[1]
    marker = {'schema': SCHEMA, 'identity': ident, 'status': 'UNKNOWN', 'complete': False,
              'reason': 'unavailable', 'manifest_digest': parent_digest,
              'native_before': None, 'native_after': None, 'parts': [], 'leaks': [],
              'status_image_id': None, 'registry_receipts': [], 'vulnerability': None,
              'auth_mode': 'anonymous',
              'graph': {'parent_digest': parent_digest, 'media_type': None, 'children': [], 'complete': False},
              'child_vulnerability_scans': []}
    secrets, parts, reader, before = [], marker['parts'], None, None
    vulnerability_results = []
    is_index = False
    scanned = [0]
    secret_gaps = set()
    pending, pending_bytes = [], 0
    def scan(raw, path, source):
        reader.check()
        if len(parts) >= 8192:
            raise Incomplete('detector_part_bound')
        try:
            if redact_values is None:
                scanner(raw, path, source, reader.check, secrets, parts)
            else:
                scanner(raw, path, source, reader.check, secrets, parts, redact_values=redact_values)
        except Incomplete as exc:
            if str(exc) != 'detectors_incomplete':
                raise
            secret_gaps.add('detectors_incomplete')
    def flush():
        nonlocal pending, pending_bytes
        if not pending:
            return
        reader.check()
        timeout = min(60, max(.001, reader.end - time.monotonic() - 1))
        with prepared_content_batch([(raw, path) for raw, path, _ in pending], timeout=timeout):
            for raw, path, source in pending:
                scan(raw, path, source)
        pending, pending_bytes = [], 0
    def queue(raw, path, source):
        nonlocal pending_bytes
        if scanner is not _scan:
            scan(raw, path, source)
            return
        reader.check()
        if pending and (len(parts) + len(pending) >= 8192
                        or len(pending) >= MAX_BATCH_ITEMS
                        or pending_bytes + len(raw) > MAX_BATCH_BYTES):
            flush()
        if len(parts) >= 8192:
            raise Incomplete('detector_part_bound')
        pending.append((raw, path, source))
        pending_bytes += len(raw)
    def bind_again():
        current = bind_pod(target, pod_get(target))
        if (current['pod'] != before['pod'] or current.get('status_image_id') != before.get('status_image_id')
                or current.get('container_instance') != before.get('container_instance')):
            raise Incomplete('pod_image_changed')
        return current
    try:
        before = bind_pod(target, pod_get(target))
        marker['native_before'] = before['pod']
        marker['status_image_id'] = before['status_image_id']
        image = association.parse_image_reference(target['image'])
        if type(allowed_hosts) not in (tuple, list) or image.registry not in allowed_hosts or _host(image.registry) != image.registry:
            raise Incomplete('registry_not_allowlisted')
        credential = (credentials or {}).get((image.registry, image.repository))
        marker['auth_mode'] = credential[0] if credential else 'anonymous'
        reader = registry_factory(image.registry, image.repository, cancel,
                                  authorization=credential[1] if credential else None)
        parent = reader.get('manifests', image.digest, archive.MAX_MANIFEST)
        document = archive.decode(parent)
        archive.require(type(document) is dict and document.get('mediaType') in oci_index.ALL_MANIFEST_TYPES,
                        'unsupported_manifest')
        marker['graph']['media_type'] = document['mediaType']
        is_index = document['mediaType'] in oci_index.INDEX_TYPES
        parent_source = {'resource_id': ident, 'scope': target['cluster_id'],
                         'image_digest': parent_digest}
        if is_index and secret_enabled:
            scan(parent, ident + '.index', {**parent_source, 'location_kind': 'image_index'})
        def fetch_child(digest, size, media_type):
            return reader.get('manifests', digest, archive.MAX_MANIFEST, size=size)
        for child in oci_index.children(parent, parent_digest, fetch_child, check=reader.check):
            digest, manifest = child['digest'], child['raw']
            decoded = archive.decode(manifest)
            conf = archive.descriptor(decoded.get('config'), archive.CONFIGS, archive.MAX_CONFIG)
            descriptors = decoded.get('layers')
            archive.require(type(descriptors) is list and 1 <= len(descriptors) <= archive.MAX_LAYERS,
                            'all_layers_required')
            descriptors = [archive.descriptor(d, archive.LAYERS, archive.MAX_LAYER) for d in descriptors]
            archive.require(sum(d['size'] for d in descriptors) + conf['size'] <= archive.MAX_COMPRESSED,
                            'compressed_image_bound')
            config = reader.get('blobs', conf['digest'], archive.MAX_CONFIG, size=conf['size'])
            if is_index:
                platform = child['platform']
                config_identity = archive.decode(config)
                if (type(config_identity) is not dict or config_identity.get('os') != platform['os']
                        or config_identity.get('architecture') != platform['architecture']
                        or 'variant' in platform and config_identity.get('variant') != platform['variant']):
                    raise Incomplete('child_platform_config_mismatch')
            image_identity = {'provider': 'k8s', 'scope': target['cluster_id'],
                'immutable_reference': image.registry + '/' + image.repository + '@' + digest,
                'manifest_digest': digest, 'config_digest': conf['digest']}
            archive.identity(image_identity)
            prefix = ident + ('.child-' + digest[7:23] if is_index else '')
            marker['graph']['children'].append({'digest': digest, 'size': child['size'],
                'mediaType': child['mediaType'], 'platform': child['platform'],
                'config_digest': conf['digest']})
            with tempfile.TemporaryDirectory(prefix='peaso-k8s-registry-') as directory:
                layers = [reader.get('blobs', desc['digest'], archive.MAX_LAYER,
                                     size=desc['size'], destination=Path(directory) / ('layer-' + str(i)))
                          for i, desc in enumerate(descriptors)]
                def visit(name, stream, length, layer):
                    if length > MAX_FILE_SCAN or scanned[0] + length > MAX_SCAN:
                        raise Incomplete('file_scan_bound')
                    path = prefix + '.layer-' + str(layer + 1) + '.file-' + str(len(parts) + len(pending) + 1)
                    origin = {**parent_source, 'source': digest, 'layer': descriptors[layer]['digest'],
                              'path': name}
                    queue(name.encode('utf-8'), path + '.name', origin)
                    offset, overlap = 0, b''
                    while offset < length:
                        chunk = stream.read(min(WINDOW, length - offset))
                        if type(chunk) is not bytes or not chunk:
                            raise Incomplete('file_truncated')
                        if offset == 0 and (chunk.startswith((b'PK\x03\x04', b'\x1f\x8b', b'BZh', b'7z\xbc\xaf'))
                                            or chunk[257:262] == b'ustar'):
                            secret_gaps.add('nested_archive_uninspected')
                            return
                        offset += len(chunk); scanned[0] += len(chunk)
                        queue(overlap + chunk, path + '.chunk-' + str(offset), origin)
                        try:
                            text = chunk.decode('utf-8')
                        except UnicodeError:
                            secret_gaps.add('binary_file_uninspected')
                            return
                        if any(ord(c) < 32 and c not in '\t\r\n' or ord(c) == 127 for c in text):
                            secret_gaps.add('binary_file_uninspected')
                            return
                        overlap = (overlap + chunk)[-OVERLAP:]
                if secret_enabled:
                    scan(manifest, prefix + '.manifest',
                         {**parent_source, 'source': digest, 'location_kind': 'manifest'})
                    scan(config, prefix + '.config',
                         {**parent_source, 'source': digest, 'layer': conf['digest'],
                          'location_kind': 'configuration'})
                    config_strings, stack, count, size = [], [archive.decode(config)], 0, 0
                    while stack:
                        reader.check(); value = stack.pop(); count += 1
                        if count > 20000:
                            raise Incomplete('config_json_bound')
                        if type(value) is str:
                            raw = value.encode('utf-8'); size += len(raw) + 1
                            if size > archive.MAX_CONFIG * 2:
                                raise Incomplete('config_json_bound')
                            config_strings.append(raw)
                        elif type(value) is dict:
                            stack.extend(reversed(list(value.keys())))
                            stack.extend(reversed(list(value.values())))
                        elif type(value) is list:
                            stack.extend(reversed(value))
                    if config_strings:
                        scan(b'\n'.join(config_strings), prefix + '.config-strings',
                             {**parent_source, 'source': digest, 'layer': conf['digest'],
                              'location_kind': 'configuration'})
                    try:
                        archive.visit_files(image_identity, manifest, config, layers,
                                            lambda *_: None, reader.check, partial_callback=visit)
                    except Exception as exc:
                        if isinstance(exc, TimeoutError) or getattr(exc, 'code', None) in (
                                'collection_cancelled', 'intentional_scan_deadline', 'deadline_exceeded') or (
                                type(exc) is Incomplete and str(exc) == 'registry_deadline'):
                            raise
                        flush()  # Retain earlier verified positives before an ordinary archive error.
                        raise
                    flush()
                else:
                    archive.validate(image_identity, manifest, config, layers, reader.check)
                if trivy_enabled:
                    if trivy_runner is None:
                        from peaso import trivy_container_runner_20261020 as trivy
                        runner, default_cli = trivy.scan_image, trivy.DEFAULT_CLI
                    else:
                        runner, default_cli = trivy_runner, '/usr/local/bin/trivy'
                    def verify():
                        bind_again()
                        return image_identity
                    result = runner(image_identity, manifest, config, layers,
                        native_verifier=verify, enabled=True, db_cache=trivy_db,
                        cli=trivy_cli or default_cli, cancel=reader.check,
                        # Pinned Trivy reads an --input tar only in docker-save layout;
                        # an OCI layout tar fails ("index.json: not a directory").
                        archive_format='docker')
                    if type(result) is not dict or type(result.get('findings')) is not list:
                        raise Incomplete('vulnerability_result_unavailable')
                    vulnerability_results.append(result)
                    marker['child_vulnerability_scans'].append(deepcopy(result))
        marker['graph']['complete'] = True
        after = bind_again()
        marker['native_after'] = after['pod']
        marker['complete'] = bool(secret_enabled and not secret_gaps and parts and all(p.get('complete') is True for p in parts))
        marker['reason'] = sorted(secret_gaps)[0] if secret_gaps else 'complete' if marker['complete'] else 'partial'
    except Exception as exc:
        if getattr(exc, 'code', None) in ('collection_cancelled', 'intentional_scan_deadline', 'deadline_exceeded'):
            raise
        marker['reason'] = str(exc) if type(exc) is Incomplete else 'inspection_unavailable'
        marker['complete'] = False
        if marker['native_before'] is not None and reader is not None and before is not None:
            try:
                marker['native_after'] = bind_again()['pod']
            except Exception:
                pass
    finally:
        merged = merge_leaks(secrets)
        bounded, locations = [], 0
        for leak in merged:
            if len(bounded) >= 256 or locations >= 2000:
                break
            row = deepcopy(leak)
            row['locations'] = row['locations'][:2000-locations]
            if row['locations']:
                bounded.append(row); locations += len(row['locations'])
        marker['leaks'] = merge_leaks(bounded)
        if len(merged) != len(bounded) or sum(len(v['locations']) for v in merged) > locations:
            marker['reason'] = 'finding_bound'; marker['complete'] = False
        native_bound = marker['native_before'] is not None and marker['native_before'] == marker['native_after']
        if marker['leaks'] and native_bound:
            marker['status'] = 'FAIL'
        elif marker['complete'] and marker['graph']['complete'] and native_bound:
            marker['status'] = 'PASS'
        if trivy_enabled and vulnerability_results:
            if is_index:
                findings = [deepcopy(f) for result in vulnerability_results for f in result.get('findings', [])]
                overflow = len(findings) > 10000
                findings = findings[:10000]
                fully_scanned = (marker['graph']['complete'] and native_bound and not overflow and
                    len(vulnerability_results) == len(marker['graph']['children']) and
                    all(v.get('status') in ('PASS', 'FAIL') and
                        v.get('complete') is True and v.get('scan_complete') is True and
                        v.get('coverage_status') == 'COMPLETE' and
                        v.get('database', {}).get('fresh') is True for v in vulnerability_results))
                marker['vulnerability'] = {'status': 'FAIL' if findings and native_bound else 'PASS' if fully_scanned else 'UNKNOWN',
                    'findings': findings, 'complete': fully_scanned, 'scan_complete': fully_scanned,
                    'coverage_status': 'COMPLETE' if fully_scanned else 'UNKNOWN',
                    'database': {'fresh': fully_scanned},
                    'children': [{'digest': c['digest'], 'status': v.get('status'),
                                  'complete': v.get('complete') is True}
                        for c, v in zip(marker['graph']['children'], vulnerability_results)]}
                if overflow:
                    marker['reason'] = 'finding_bound'
            else:
                marker['vulnerability'] = vulnerability_results[0]
        if reader is not None:
            marker['registry_receipts'] = list(reader.receipts)
    return marker

def collect(reader, api, options, scopes, cluster, auth):
    """Native hook: exact Pod GET via existing bounded Kubernetes transport."""
    named = options.get('_registry_image_named_checks', [])
    named = named if type(named) is list else []
    targets = selected_targets(options, scopes, named)
    credentials = registry_credentials(auth, targets, options.get(ALLOWLIST, []))
    secret_on, vuln_on = enabled(options, named)
    if not (secret_on or vuln_on):
        return {}, set()
    from . import k8s_selected_log_sample_secret_indicators as native
    client, pool, _, _, _ = native._context(api, cluster)
    prior = pool.literal_paths
    paths = {'/api/v1/namespaces/' + t['namespace'] + '/pods/' + t['pod'] for t in targets}
    pool.literal_paths = frozenset(set(prior) | paths)
    metadata = {SECRET_KIND + '_authorized': secret_on, VULN_KIND + '_authorized': vuln_on,
                OPTION: deepcopy(targets)}
    matches = set()
    add_redactions = redaction_callback(matches)
    grouped = {}
    from . import selected_image_trivy_database_20261021 as database
    lease_stack = ExitStack()
    try:
        db_cache = database.acquire(lease_stack, enabled=vuln_on, cancel=reader.check_cancelled)
        for target in targets:
            if target['cluster_id'] != cluster:
                continue
            path = '/api/v1/namespaces/' + target['namespace'] + '/pods/' + target['pod']
            state = {'deadline': time.monotonic() + MAX_SECONDS, 'calls': 0, 'bytes': 0, 'context': None}
            planned_items = sum(len(values) for values in grouped.values()) + int(secret_on) + int(vuln_on)
            if reader.budget.max_items is not None and reader.total + planned_items > reader.budget.max_items:
                raise Incomplete('resource_limit')
            def pod_get(_):
                value, _, _ = native._read(reader, api, cluster, path, {}, state)
                return value
            marker = inspect(target, pod_get, allowed_hosts=options[ALLOWLIST], credentials=credentials,
                             cancel=reader.check_cancelled, secret_enabled=secret_on,
                             trivy_enabled=vuln_on and db_cache is not None, trivy_db=db_cache,
                             redact_values=add_redactions if secret_on else None)
            for kind in (SECRET_KIND, VULN_KIND):
                if kind == SECRET_KIND and not secret_on or kind == VULN_KIND and not vuln_on:
                    continue
                item = {'id': identity(target), 'name': identity(target),
                        'SelectedRegistryImage': deepcopy(marker)}
                grouped.setdefault((kind, target['namespace']), []).append(item)
        for (kind, scope), items in grouped.items():
            complete = all((item['SelectedRegistryImage']['complete'] if kind == SECRET_KIND else
                            (item['SelectedRegistryImage'].get('vulnerability') or {}).get('complete') is True)
                           for item in items)
            reader.collections.append({'type': kind, 'scope': scope, 'service': 'kubernetes',
                'status': 'collected' if complete else 'partial', 'items': items})
            reader.total += len(items)
    except Exception as exc:
        if matches:
            matches.clear()
            if getattr(exc, 'code', None) in ('collection_cancelled', 'intentional_scan_deadline', 'deadline_exceeded'):
                raise
            raise RedactionOverflow('redaction_ledger_unavailable') from None
        raise
    except BaseException:
        matches.clear()
        raise
    finally:
        try:
            pool.literal_paths = prior
            client.last_response = None
        finally:
            lease_stack.close()
    return metadata, matches
