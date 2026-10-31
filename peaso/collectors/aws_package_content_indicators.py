"""Opt-in package inspection. No payloads or URLs survive projection.

Kingfisher and TruffleHog inspect bounded content offline. The three existing
resource kinds are enriched. ECR blobs use private temporary files; no package
is executed or extracted into the host filesystem.
"""
from peaso.secret_evidence import source_context, reuse_image_layer
import base64
from concurrent.futures import ThreadPoolExecutor
from contextlib import nullcontext
from contextvars import copy_context
from copy import deepcopy
import hashlib
import io
import json
from pathlib import Path
import re
import stat
import struct
import tarfile
import tempfile
import time
import threading
from urllib.parse import urlsplit
from urllib.request import build_opener, HTTPRedirectHandler, ProxyHandler
import zipfile
import zlib
from .aws_user_data_secret_indicators import project as inspect_text

PROFILE = 'aws-package-content-indicators-v1'
SCHEMA = PROFILE
PROJECTION_OPERATIONS = {('lambda', 'get_function'), ('lambda', 'get_layer_version'),
                         ('ecr', 'batch_get_image'), ('ecr', 'get_download_url_for_layer')}
READ_ACTIONS = PROJECTION_OPERATIONS | {('ecr', 'describe_images')}
ZIP_LIMIT = 8 * 1024 * 1024
LAYER_LIMIT = 16 * 1024 * 1024
IMAGE_LIMIT = 32 * 1024 * 1024
EXPANDED_LIMIT = 64 * 1024 * 1024
ECR_LAYER_LIMIT = 2 * 1024 * 1024 * 1024
ECR_IMAGE_LIMIT = 4 * 1024 * 1024 * 1024
ECR_EXPANDED_LIMIT = 8589934592  # 8 GiB; literal remains verifiable by the finite source checker.
CONTENT_LIMIT = 512 * 1024 * 1024
FILE_LIMIT = 64 * 1024 * 1024
SCAN_WINDOW = 1024 * 1024
SCAN_OVERLAP = 4096
REFERENCE_LIMIT = 5000
OUTPUT_LIMIT = 4 * 1024 * 1024
MEMBER_LIMIT = 5000
BATCH_ITEMS = 512
BATCH_BYTES = 64 * 1024 * 1024
BATCH_TARGET_BYTES = 16 * 1024 * 1024
MANIFEST_LIMIT = 1024 * 1024
OCI = 'application/vnd.oci.image.manifest.v1+json'
DOCKER = 'application/vnd.docker.distribution.manifest.v2+json'
TAR_TYPES = {'application/vnd.oci.image.layer.v1.tar', 'application/vnd.oci.image.layer.v1.tar+gzip',
             'application/vnd.docker.image.rootfs.diff.tar.gzip'}
CONFIG_TYPES = {'application/vnd.oci.image.config.v1+json', 'application/vnd.docker.container.image.v1+json'}
CATEGORIES = {'private_key', 'cloud_credential', 'password_assignment', 'secret'}


def _failure(code='package_content_unavailable'):
    from .aws import ReadFailure
    return ReadFailure('not_collected', code)


class Unsupported(ValueError):
    """A specific, provider-text-free reason bounded package content cannot be assessed."""
    def __init__(self, code):
        super().__init__(code)
        self.code = code


# Inner read failures whose code already names the honest cause.
_PRESERVED_CODES = {'package_download_unavailable', 'call_limit', 'content_secret_scans_disabled'}


def _projection_code(exc):
    if isinstance(exc, Unsupported):
        return exc.code
    if getattr(exc, 'code', None) in _PRESERVED_CODES:
        return exc.code
    return 'package_projection_unavailable'


def incomplete_reason(base, causes):
    """Partial-content reason: the stable base code plus the concrete causes observed."""
    causes = sorted(c for c in set(causes) if isinstance(c, str) and re.fullmatch(r'[a-z_]+', c))
    return base + (': ' + ', '.join(causes) if causes else '')


def _digest(value):
    return isinstance(value, str) and re.fullmatch(r'sha256:[0-9a-f]{64}', value) is not None


def _partition(region):
    if not isinstance(region, str) or not re.fullmatch(r'[a-z]{2}(?:-[a-z0-9]+)+-[0-9]', region):
        raise ValueError('invalid region')
    return 'aws-cn' if region.startswith('cn-') else 'aws-us-gov' if region.startswith('us-gov-') else 'aws'


def _arn(value, service, region):
    match = re.fullmatch(r'arn:' + _partition(region) + ':' + service + ':' + re.escape(region) + r':([0-9]{12}):(.+)', value if isinstance(value, str) else '')
    if match is None: raise ValueError('foreign resource')
    return match[1], match[2]


def _json(value):
    def unique(pairs):
        out = {}
        for key, val in pairs:
            if key in out: raise ValueError('duplicate JSON key')
            out[key] = val
        return out
    def invalid(value): raise ValueError('non-JSON constant')
    return json.loads(value, object_pairs_hook=unique, parse_constant=invalid)


def _context(context):
    if not isinstance(context, tuple) or len(context) != 2: raise ValueError('missing request context')
    requests, session = context
    if getattr(requests, 'content_secret_scans', False) is not True: raise _failure('content_secret_scans_disabled')
    requests.check_deadline()
    return requests, session


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs): return None


def validate_url(url, region):
    """Only regional AWS S3 virtual-host presigned locations, never arbitrary hosts."""
    partition = _partition(region)
    if not isinstance(url, str) or len(url) > 32768 or any(ord(c) <= 32 or ord(c) >= 127 for c in url):
        raise ValueError('invalid package URL')
    parsed = urlsplit(url)
    suffix = 'amazonaws.com.cn' if partition == 'aws-cn' else 'amazonaws.com'
    # Do not accept unregional s3.amazonaws.com or arbitrary *.amazonaws.com.
    host = r'[a-z0-9][a-z0-9.-]*\.s3[.-]' + re.escape(region) + r'\.' + re.escape(suffix)
    if (parsed.scheme != 'https' or parsed.username is not None or parsed.password is not None
            or parsed.port is not None or parsed.fragment or not re.fullmatch(host, parsed.hostname or '')
            or not parsed.path.startswith('/') or not parsed.query):
        raise ValueError('package URL outside regional AWS S3 allowlist')
    return url


def download(requests, url, region, cap, expected_size=None, budget=None):
    """Stream actual bytes under one shared call budget and a ten-second deadline."""
    try:
        validate_url(url, region)
        if budget is not None:
            cap = min(cap, budget[0])
            if cap <= 0: raise ValueError('image stream budget exhausted')
        with requests._lock:
            requests.check_deadline()
            if requests.max_calls is not None and requests.calls >= requests.max_calls: raise _failure('call_limit')
            requests.calls += 1
        end = min(time.monotonic() + 10, requests.deadline if requests.deadline is not None else float('inf'))
        opener = build_opener(ProxyHandler({}), _NoRedirect())
        with opener.open(url, timeout=min(3, requests.timeout, max(0.001, end - time.monotonic()))) as response:
            if response.status != 200 or response.geturl() != url or response.headers.get('Content-Encoding', 'identity') != 'identity':
                raise ValueError('unexpected HTTP response')
            length = response.headers.get('Content-Length')
            if length is not None and (not length.isdecimal() or int(length) > cap or expected_size is not None and int(length) != expected_size):
                raise ValueError('invalid HTTP length')
            result = bytearray()
            while True:
                requests.check_deadline()
                if time.monotonic() >= end: raise ValueError('download deadline')
                chunk = response.read(min(65536, cap + 1 - len(result)))
                if not isinstance(chunk, bytes): raise ValueError('invalid stream')
                if not chunk: break
                if budget is not None: budget[0] = max(0, budget[0] - len(chunk))
                result.extend(chunk)
                if len(result) > cap: raise ValueError('actual stream limit')
            requests.check_deadline()
            if time.monotonic() >= end or length is not None and len(result) != int(length) or expected_size is not None and len(result) != expected_size:
                raise ValueError('truncated or expired stream')
            return bytes(result)
    except Exception:
        # Do not propagate provider/urllib exception text, URL, traceback or body.
        raise _failure('package_download_unavailable') from None


def download_layer(requests, url, region, path, digest, expected_size, budget):
    """Use the shared bounded native ECR stream writer for immutable blobs."""
    from .aws_image_vulnerability_native_20261021 import download_blob_path
    if (not isinstance(path, Path) or not path.is_absolute() or not _digest(digest)
            or type(expected_size) is not int or not 0 < expected_size <= ECR_LAYER_LIMIT
            or budget[0] < expected_size):
        raise _failure('package_download_unavailable')
    # Reserve the descriptor size before I/O, including failed reads. A failed
    # layer cannot be retried past the image's shared compressed-byte budget.
    budget[0] -= expected_size
    try:
        return download_blob_path(requests, url, region, digest, expected_size, path,
                                  check=requests.check_deadline)
    except Exception:
        raise _failure('package_download_unavailable') from None

def _path(value):
    if (not isinstance(value, str) or not value or len(value) > 256 or not re.fullmatch(r'[A-Za-z0-9_./@+ -]+', value)
            or value.startswith('/') or any(piece in ('', '.', '..') for piece in value.rstrip('/').split('/'))):
        raise ValueError('unsafe archive path')
    return value.rstrip('/')


def _scan(raw, name, requests):
    from peaso.secret_scanning import scan_content
    from peaso.collection_lease import check as check_lease
    check_lease(requests)
    with source_context(path=name):
        outcome = scan_content(bytes(raw), name)
        categories = inspect_text(raw.decode('latin-1'), 'unused')['MatchedCategories']
    if outcome['leaks']:
        categories = sorted(set(categories) | {'secret'})
    safe_name = outcome['leaks'][0]['locations'][0]['path'] if outcome['leaks'] else name
    refs = [{'File': safe_name, 'Categories': categories, 'Leaks': outcome['leaks']}] if categories else []
    check_lease(requests)
    if not outcome['complete']:
        raise PartialArchive(refs, 0, 0)
    return refs


_DEFAULT_SCAN = _scan


def _archive_batch_items(requests):
    from peaso.secret_scanning_adaptive import archive_batch_items
    return archive_batch_items(requests)


def _archive_prepared_groups(items,requests):
    from peaso.secret_scanning_adaptive import prepared_archive_batches
    return prepared_archive_batches(items,requests)


def _batch_flush_before(count, size, next_size, requests):
    return (count >= _archive_batch_items(requests) or size + next_size > BATCH_BYTES or
            (count >= 512 and size + next_size > BATCH_TARGET_BYTES))


def _prepared_batch(items):
    """Keep the old per-content path when the batch adapter is unavailable."""
    from peaso import secret_scanning
    prepare = getattr(secret_scanning, 'prepared_content_batch', None)
    return prepare(items, timeout=60) if prepare is not None else nullcontext()


def _scan_progress(requests, count, label):
    """Report only a local file/window count, never a native path or payload."""
    from peaso.progress import PHASES, current_callback, emit_progress
    callback = getattr(requests, 'progress_callback', None) or current_callback()
    phase = 'scanning_images' if label == 'image' else 'scanning_content'
    emit_progress(callback, phase=phase if phase in PHASES else 'collecting',
                  provider=getattr(requests, 'progress_provider', 'aws'),
                  completed=count, total=None, dynamic_total=True)


def _download_image_layers(requests, session, region, account, repo, digest,
                           identity, descriptors, root, state):
    """Fetch at most two independently bound ECR blobs at a time, in descriptor order."""
    def fetch(index):
        ld, size = descriptors[index]
        path = root / f'blob-{index:04}'
        def load(path):
            # The provider projection binds its stream writer through this
            # thread-local descriptor; every consumer validates its manifest.
            state.active, state.budget = (ld, size, path), [size]
            try:
                with source_context(resource_id=identity, scope=account + '/' + region,
                                    image_digest=digest, layer=ld,
                                    check_ids={'aws.review.ecr_repository.package_content_secret_indicators'}):
                    safe = requests.detail(session, 'ecr', region, 'get_download_url_for_layer',
                                           _metadata_profile=PROFILE, _cache_refresh=True,
                                           registryId=account, repositoryName=repo, layerDigest=ld)
                if (safe.get('collection_status') != 'collected' or safe.get('LayerDigest') != ld or
                        safe.get('RegistryId') != account or safe.get('RepositoryName') != repo or
                        safe.get('CompressedBytes') != size or not path.is_file() or path.stat().st_size != size):
                    raise ValueError('layer incomplete')
                return path
            finally:
                del state.active, state.budget
        from .aws_image_capture_20261022 import shared_blob
        return shared_blob(requests, session, account, region, repo, digest,
                           ld, size, load, path)

    paths = []
    # An image may list the same layer blob more than once. Download it once and
    # reuse that file: two concurrent reads of one digest would share a single
    # provider read and leave one of the two destination files unwritten.
    first = {}
    for index, (ld, _) in enumerate(descriptors):
        first.setdefault(ld, index)
    def submit(index):
        if first[descriptors[index][0]] == index:
            pending[index] = pool.submit(copy_context().run, fetch, index)
    with ThreadPoolExecutor(max_workers=2, thread_name_prefix='peaso-ecr-layer') as pool:
        pending = {}
        for index in range(min(2, len(descriptors))):
            submit(index)
        for index in range(len(descriptors)):
            requests.check_deadline()
            original = first[descriptors[index][0]]
            paths.append(pending.pop(index).result() if original == index else paths[original])
            next_index = index + 2
            if next_index < len(descriptors):
                submit(next_index)
    return paths


class PartialArchive(ValueError):
    """Carries safe observations only; caught before the projection boundary."""
    def __init__(self, refs, expanded, members):
        super().__init__('archive incomplete after proven observation')
        self.refs, self.expanded, self.members = refs, expanded, members


def scan_zip(raw, requests):
    """Preflight central directory and read each member in memory with actual bounds."""
    if not isinstance(raw, bytes) or not raw.startswith(b'PK\x03\x04') or len(raw) > ZIP_LIMIT: raise ValueError('ZIP size bound')
    end = raw.rfind(b'PK\x05\x06')
    if end < 0 or end + 22 > len(raw) or end + 22 + int.from_bytes(raw[end + 20:end + 22], 'little') != len(raw):
        raise ValueError('ZIP trailing or missing directory')
    disk, directory_disk, disk_count, count, directory_size, directory_offset = struct.unpack_from('<4H2I', raw, end + 4)
    if (disk or directory_disk or disk_count != count or not 1 <= count <= MEMBER_LIMIT
            or directory_offset + directory_size != end or directory_offset < 4):
        raise ValueError('unsupported ZIP directory or member bound')
    refs, total, names = [], 0, set()
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        members = archive.infolist()
        if not members or len(members) > MEMBER_LIMIT: raise ValueError('ZIP member bound')
        for member in members:
            requests.check_deadline()
            name = _path(member.filename)
            mode = member.external_attr >> 16
            if (name in names or member.flag_bits & 0x41 or member.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
                    or stat.S_ISLNK(mode) or stat.S_IFMT(mode) not in (0, stat.S_IFREG, stat.S_IFDIR)):
                raise ValueError('unsupported ZIP member')
            names.add(name)
            total += member.file_size
            if total > EXPANDED_LIMIT or member.file_size > max(1024, member.compress_size * 200): raise ValueError('ZIP expansion bound')
        actual, pending, pending_bytes, scanned_files = 0, [], 0, 0
        def flush():
            nonlocal pending, pending_bytes, scanned_files
            if not pending: return
            items, pending, pending_bytes = pending, [], 0
            requests.check_deadline()
            with _archive_prepared_groups(items,requests) as groups:
                for group in groups:
                    for payload, name in group:
                        refs.extend(_scan(payload, name, requests))
                        if len(refs) > MEMBER_LIMIT: raise ValueError('too many observations')
                        scanned_files += 1
            _scan_progress(requests, scanned_files, 'package')
        try:
            for member in members:
                if member.is_dir(): continue
                with archive.open(member) as source:
                    payload = bytearray()
                    while True:
                        requests.check_deadline()
                        chunk = source.read(min(65536, EXPANDED_LIMIT - actual + 1))
                        if not chunk: break
                        actual += len(chunk)
                        if actual > EXPANDED_LIMIT: raise ValueError('ZIP actual expansion bound')
                        payload.extend(chunk)
                    if len(payload) != member.file_size: raise ValueError('truncated ZIP member')
                    if _scan is _DEFAULT_SCAN:
                        payload = bytes(payload)
                        if pending and _batch_flush_before(len(pending), pending_bytes, len(payload), requests):
                            flush()
                        pending.append((payload, _path(member.filename)))
                        pending_bytes += len(payload)
                    else:
                        refs.extend(_scan(payload, _path(member.filename), requests))
                        if len(refs) > MEMBER_LIMIT: raise ValueError('too many observations')
            flush()
        except Exception as exc:
            if isinstance(exc, PartialArchive): refs.extend(exc.refs)
            if pending:
                try: flush()
                except PartialArchive as partial: refs.extend(partial.refs)
                except Exception: pass
            if refs: raise PartialArchive(refs, actual, len(members)) from None
            raise
    return refs, actual, len(members)


def scan_tar(raw, media_type, requests, budget=None):
    """Only regular files/directories; one gzip member, no links/devices/extraction."""
    expanded, count = budget or (0, 0)
    if not isinstance(raw, bytes) or len(raw) > LAYER_LIMIT or media_type not in TAR_TYPES: raise ValueError('unsupported layer')
    if media_type.endswith('gzip'):
        inflater = zlib.decompressobj(zlib.MAX_WBITS | 16)
        raw = inflater.decompress(raw, EXPANDED_LIMIT - expanded + 1)
        if len(raw) > EXPANDED_LIMIT - expanded or not inflater.eof or inflater.unused_data or inflater.unconsumed_tail:
            raise ValueError('layer expansion bound')
    if len(raw) + expanded > EXPANDED_LIMIT or len(raw) % 512 or len(raw) < 1024 or raw[-1024:] != bytes(1024):
        raise ValueError('truncated or oversized tar')
    expanded += len(raw)
    refs, names, offset, ended = [], set(), 0, False
    pending, pending_bytes, scanned_files = [], 0, 0
    def flush():
        nonlocal pending, pending_bytes, scanned_files
        if not pending: return
        items, pending, pending_bytes = pending, [], 0
        requests.check_deadline()
        with _archive_prepared_groups(items,requests) as groups:
            for group in groups:
                for payload, name in group:
                    refs.extend(_scan(payload, name, requests))
                    if len(refs) > MEMBER_LIMIT: raise ValueError('too many observations')
                    scanned_files += 1
        _scan_progress(requests, scanned_files, 'image')
    try:
        while offset + 512 <= len(raw):
            requests.check_deadline()
            block = raw[offset:offset + 512]
            if block == bytes(512):
                if offset + 1024 > len(raw) or any(raw[offset:]): raise ValueError('invalid tar terminator')
                ended = True
                break
            member = tarfile.TarInfo.frombuf(block, 'utf-8', 'strict')
            name = _path(member.name)
            count += 1
            if (count > MEMBER_LIMIT or name in names or member.type not in (tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE)
                    or member.size < 0 or member.isdir() and member.size != 0):
                raise ValueError('unsupported tar member')
            names.add(name)
            offset += 512
            end = offset + member.size
            next_offset = offset + ((member.size + 511) // 512) * 512
            if end > len(raw) or next_offset > len(raw): raise ValueError('truncated tar member')
            if member.isfile():
                payload = raw[offset:end]
                if _scan is _DEFAULT_SCAN:
                    if pending and _batch_flush_before(len(pending), pending_bytes, len(payload), requests):
                        flush()
                    pending.append((payload, name))
                    pending_bytes += len(payload)
                    if len(pending) >= _archive_batch_items(requests): flush()
                else:
                    refs.extend(_scan(payload, name, requests))
            offset = next_offset
        if not ended: raise ValueError('tar missing terminator')
        flush()
    except Exception as exc:
        if isinstance(exc, PartialArchive): refs.extend(exc.refs)
        if pending:
            try: flush()
            except PartialArchive as partial: refs.extend(partial.refs)
            except Exception: pass
        if refs: raise PartialArchive(refs, expanded, count) from None
        raise
    return refs, expanded, count


def marker(identity, account, region, operation, refs, *, complete=True, code=None):
    return {'Schema': SCHEMA, 'ResourceId': identity, 'AccountId': account, 'Region': region,
            'SourceOperation': operation, 'NativeResponseComplete': complete,
            'collection_status': 'collected' if complete else 'partial', 'References': refs,
            'HighConfidenceSecretPresent': bool(refs), 'Reason': code}


def _lambda(response, operation, arguments, requests, region):
    if operation == 'get_function':
        identity = arguments['FunctionName']
        account, resource = _arn(identity, 'lambda', region)
        configuration = response['Configuration']
        version = arguments['Qualifier']
        if isinstance(configuration, dict) and configuration.get('PackageType') == 'Image':
            raise Unsupported('lambda_image_package')
        # GetFunction with a Qualifier answers with the qualified ARN
        # (name:$LATEST or name:N); the unqualified form is also accepted.
        if (not re.fullmatch(r'function:[A-Za-z0-9_-]{1,64}', resource)
                or not isinstance(configuration, dict) or not isinstance(version, str)
                or configuration.get('FunctionArn') not in (identity, identity + ':' + version)
                or configuration.get('Version') != version or not isinstance(version, str)
                or not re.fullmatch(r'(?:\$LATEST|[1-9][0-9]*)', version) or configuration.get('PackageType') != 'Zip'):
            raise ValueError('function identity/version/format mismatch')
        code, size, expected = response['Code'], configuration['CodeSize'], configuration['CodeSha256']
        if code.get('RepositoryType') != 'S3': raise ValueError('unsupported function code location')
    else:
        base, version = arguments['LayerName'], arguments['VersionNumber']
        account, resource = _arn(base, 'lambda', region)
        if not re.fullmatch(r'layer:[A-Za-z0-9_-]{1,140}', resource) or type(version) is not int or version < 1:
            raise ValueError('invalid layer identity')
        identity = base + ':' + str(version)
        if response.get('LayerVersionArn') != identity or response.get('LayerArn') != base or response.get('Version') != version:
            raise ValueError('layer identity/version mismatch')
        code = response['Content']
        size, expected = code['CodeSize'], code['CodeSha256']
    if type(size) is int and size > ZIP_LIMIT: raise Unsupported('package_size_bound')
    if type(size) is not int or not 0 < size <= ZIP_LIMIT or not isinstance(expected, str): raise ValueError('package size/hash missing')
    expected_digest = base64.b64decode(expected, validate=True)
    if len(expected_digest) != 32: raise ValueError('package hash malformed')
    raw = download(requests, code['Location'], region, ZIP_LIMIT, size)
    if hashlib.sha256(raw).digest() != expected_digest: raise ValueError('package hash mismatch')
    complete = True
    try:
        with source_context(resource_id=identity, scope=account + '/' + region, source='lambda:' + operation + ':' + str(version),
                            check_ids={'aws.review.' + ('lambda_function' if operation == 'get_function' else 'lambda_layer_version') + '.package_content_secret_indicators'}):
            refs, _, _ = scan_zip(raw, requests)
    except PartialArchive as partial:
        refs, complete = partial.refs, False
    return {'PackageSecretIndicators': marker(identity, account, region, 'lambda:' + operation, refs, complete=complete,
            code=None if complete else incomplete_reason('package_content_incomplete', {'engine_incomplete'})),
            'SourceVersion': version}


def _ecr_arguments(arguments):
    account, repo = arguments['registryId'], arguments['repositoryName']
    if (not isinstance(account, str) or not re.fullmatch(r'[0-9]{12}', account) or not isinstance(repo, str)
            or not 2 <= len(repo) <= 256 or not re.fullmatch(r'[a-z0-9]+(?:(?:\.|_|__|-+)[a-z0-9]+)*(?:/[a-z0-9]+(?:(?:\.|_|__|-+)[a-z0-9]+)*)*', repo)):
        raise ValueError('invalid ECR identity')
    return account, repo


def _scan_reader(reader, size, name, requests, remaining, enqueue=None, causes=None):
    """Scan a regular file in overlapping, bounded windows through private capture.

    When ``causes`` is a set, the concrete reason a file stays uncovered is added to it.
    """
    causes = set() if causes is None else causes
    if not isinstance(name, str) or len(name) > 256:
        causes.add('path_bound'); return [], False
    if size > FILE_LIMIT:
        causes.add('file_size_bound'); return [], False
    if remaining[0] < size:
        causes.add('content_budget_bound'); return [], False
    refs, overlap, consumed = [], b'', 0
    while consumed < size:
        requests.check_deadline()
        chunk = reader.read(min(SCAN_WINDOW, size - consumed))
        if not isinstance(chunk, bytes) or not chunk:
            raise ValueError('truncated validated file')
        consumed += len(chunk)
        remaining[0] -= len(chunk)
        if b'\0' in chunk:
            causes.add('binary_member'); return refs, False
        payload = overlap + chunk
        if enqueue is not None:
            if not enqueue(payload, name):
                causes.add('engine_incomplete'); return refs, False
        else:
            try:
                found = _scan(payload, name, requests)
                if len(refs) + len(found) > REFERENCE_LIMIT:
                    causes.add('reference_bound'); return refs, False
                refs.extend(found)
            except PartialArchive as partial:
                refs.extend(partial.refs)
                causes.add('engine_incomplete'); return refs, False
        overlap = payload[-SCAN_OVERLAP:]
    return refs, True


def _layer(response, arguments, requests, region):
    account, repo = _ecr_arguments(arguments)
    digest = arguments['layerDigest']
    if not _digest(digest) or response.get('layerDigest') != digest:
        raise ValueError('foreign layer digest')
    state = getattr(requests, '_package_scan_local', None)
    active = getattr(state, 'active', None) if state is not None else None
    if active is None or active[0] != digest:
        raise ValueError('unbound layer request')
    size, path = active[1], active[2]
    download_layer(requests, response['downloadUrl'], region, path, digest, size, state.budget)
    return {'LayerDigest': digest, 'RegistryId': account, 'RepositoryName': repo,
            'CompressedBytes': size}


def _image(response, arguments, requests, session, region):
    from peaso.container_image_archive_20261020 import visit_files
    from peaso import container_image_archive_20261020 as image_archive
    from peaso import oci_index_20261021 as oci_index
    account, repo = _ecr_arguments(arguments)
    ids = arguments['imageIds']
    if not isinstance(ids, list) or len(ids) != 1 or set(ids[0]) != {'imageDigest'} or not _digest(ids[0]['imageDigest']):
        raise ValueError('exact image digest required')
    digest = ids[0]['imageDigest']
    identity = f'arn:{_partition(region)}:ecr:{region}:{account}:repository/{repo}@{digest}'
    from .aws_ecr_manifest_aliases import select_digest_image
    image = select_digest_image(response.get('images'), response.get('failures'), account, repo, digest)
    raw = image['imageManifest']
    if (image.get('registryId') != account or image.get('repositoryName') != repo or
            image.get('imageId', {}).get('imageDigest') != digest or not isinstance(raw, str) or
            len(raw.encode()) > MANIFEST_LIMIT or 'sha256:' + hashlib.sha256(raw.encode()).hexdigest() != digest):
        raise ValueError('image manifest binding mismatch')
    manifest = _json(raw)
    if (not isinstance(manifest, dict) or len(raw.encode()) > 256 * 1024 or
            type(manifest.get('schemaVersion')) is not int or
            manifest['schemaVersion'] != 2 or manifest.get('mediaType') not in oci_index.ALL_MANIFEST_TYPES or
            image.get('imageManifestMediaType') != manifest['mediaType']):
        raise Unsupported('unsupported_image_manifest')
    if manifest['mediaType'] in oci_index.INDEX_TYPES:
        from .aws_image_vulnerability_native_20261021 import Reader
        def _require_index(ok):
            if not ok:
                raise ValueError('index_binding_unavailable')
        reader = Reader(requests, session, account, region)
        graph = {'parent_digest': digest, 'media_type': manifest['mediaType'],
                 'children': [], 'complete': False, 'parent_binding_stable': False}
        refs, total_compressed, output_bytes, stable = [], 0, 0, False
        def fetch(child_digest, size, media_type):
            child_raw, child_doc = reader.manifest(repo, child_digest)
            _require_index(len(child_raw) == size and child_doc['mediaType'] == media_type)
            return child_raw
        def rebind():
            reader.caller()
            again, _ = reader.manifest(repo, digest, allow_index=True)
            _require_index(again == raw.encode())
        try:
            reader.caller()
            for child in oci_index.children(raw.encode(), digest, fetch, check=reader.check):
                child_digest = child['digest']
                document = image_archive.decode(child['raw'])
                config_desc = image_archive.descriptor(document['config'], image_archive.CONFIGS,
                                                       image_archive.MAX_CONFIG)
                configuration = image_archive.decode(reader.blob(repo, config_desc,
                    image_digest=child_digest))
                platform = child['platform']
                _require_index(type(configuration) is dict and
                    configuration.get('os') == platform['os'] and
                    configuration.get('architecture') == platform['architecture'] and
                    ('variant' not in platform or configuration.get('variant') == platform['variant']))
                layers_desc = document['layers']
                _require_index(type(layers_desc) is list and 1 <= len(layers_desc) <= image_archive.MAX_LAYERS)
                layers_desc = [image_archive.descriptor(d, image_archive.LAYERS, image_archive.MAX_LAYER)
                               for d in layers_desc]
                total_compressed += config_desc['size'] + sum(d['size'] for d in layers_desc)
                _require_index(total_compressed <= ECR_IMAGE_LIMIT)
                source = requests.detail(session, 'ecr', region, 'batch_get_image',
                    _metadata_profile=PROFILE, registryId=account, repositoryName=repo,
                    imageIds=[{'imageDigest': child_digest}], acceptedMediaTypes=[OCI, DOCKER])
                selected = source.get('PackageSecretIndicators') if type(source) is dict else None
                expected = f'arn:{_partition(region)}:ecr:{region}:{account}:repository/{repo}@{child_digest}'
                _require_index(type(selected) is dict and source.get('ImageDigest') == child_digest
                    and selected.get('ResourceId') == expected and selected.get('AccountId') == account
                    and selected.get('Region') == region and type(selected.get('References')) is list
                    and type(selected.get('NativeResponseComplete')) is bool)
                graph['children'].append({'digest': child_digest, 'size': child['size'],
                    'mediaType': child['mediaType'], 'platform': child['platform'],
                    'config_digest': config_desc['digest']})
                for ref in selected['References']:
                    projected = {**ref, 'ChildManifestDigest': child_digest}
                    cost = len(json.dumps(projected, separators=(',', ':')).encode())
                    _require_index(len(refs) < REFERENCE_LIMIT and output_bytes + cost <= OUTPUT_LIMIT)
                    refs.append(projected); output_bytes += cost
                    if ref.get('Leaks'):
                        reuse_image_layer(ref['Leaks'], resource_id=identity, scope=account + '/' + region,
                            image_digest=digest, source=child_digest, layer=ref['LayerDigest'])
                _require_index(selected['NativeResponseComplete'] is True)
            graph['complete'] = True
            rebind(); stable = True
        except Exception as exc:
            if getattr(exc, 'code', None) in ('collection_cancelled', 'deadline_exceeded', 'intentional_scan_deadline'):
                raise
            try:
                rebind(); stable = True
            except Exception:
                stable = False
        finally:
            if not reader.close():
                stable = False
        graph['parent_binding_stable'] = stable
        complete = bool(graph['complete'] and stable)
        result = marker(identity, account, region, 'ecr:batch_get_image', refs,
            complete=complete, code=None if complete else 'image_content_incomplete')
        result['IndexGraph'] = graph
        return {'PackageSecretIndicators': result, 'ImageDigest': digest}
    layers, config = manifest.get('layers'), manifest.get('config')
    if not isinstance(layers, list) or not layers or len(layers) > MEMBER_LIMIT or not isinstance(config, dict):
        raise Unsupported('unsupported_image_manifest')
    descriptors, seen, compressed = [], set(), 0
    for descriptor in [config] + layers:
        ld, size, typ = descriptor['digest'], descriptor['size'], descriptor['mediaType']
        # Identical layers may repeat in one image (for example an empty or a
        # re-applied layer); every occurrence is a valid, ordered descriptor.
        # Only the config digest must stay distinct from the layers.
        if (set(descriptor) - {'digest', 'size', 'mediaType', 'annotations'} or not _digest(ld) or
                (descriptor is not config and ld == config.get('digest')) or type(size) is not int or
                typ not in (CONFIG_TYPES if descriptor is config else TAR_TYPES)):
            raise Unsupported('unsupported_image_layer')
        if not 0 < size <= (1024 * 1024 if descriptor is config else ECR_LAYER_LIMIT):
            raise Unsupported('image_size_bound')
        seen.add(ld); compressed += size
        if compressed > ECR_IMAGE_LIMIT: raise Unsupported('image_size_bound')
        descriptors.append((ld, size))
    with requests._lock:
        if not hasattr(requests, '_package_scan_local'):
            requests._package_scan_local = threading.local()
    state = requests._package_scan_local
    state.budget = [ECR_IMAGE_LIMIT]
    refs, complete, paths, output_bytes, causes = [], True, [], [0], set()
    def add_refs(found, ld):
        nonlocal complete
        for ref in found:
            projected = {**ref, 'LayerDigest': ld}
            size = len(json.dumps(projected, separators=(',', ':')).encode())
            if len(refs) >= REFERENCE_LIMIT or output_bytes[0] + size > OUTPUT_LIMIT:
                complete = False
                causes.add('reference_bound')
                return
            refs.append(projected)
            output_bytes[0] += size
    pending, pending_bytes, failed_files, file_counts = [], 0, set(), {}
    scanned_windows = 0
    def flush_pending():
        nonlocal pending, pending_bytes, complete, scanned_windows
        if not pending: return
        windows, pending, pending_bytes = pending, [], 0
        requests.check_deadline()
        with _archive_prepared_groups(windows,requests) as groups:
            for group in groups:
                for payload, name, ld, file_key in group:
                    if file_key in failed_files: continue
                    requests.check_deadline()
                    with source_context(resource_id=identity, scope=account + '/' + region,
                                        image_digest=digest, layer=ld,
                                        check_ids={'aws.review.ecr_repository.package_content_secret_indicators'}):
                        try:
                            found = _scan(payload, name, requests)
                        except PartialArchive as partial:
                            add_refs(partial.refs, ld)
                            failed_files.add(file_key)
                            complete = False
                            causes.add('engine_incomplete')
                            continue
                    count = file_counts.get(file_key, 0) + len(found)
                    if count > REFERENCE_LIMIT:
                        failed_files.add(file_key)
                        complete = False
                        causes.add('reference_bound')
                        continue
                    file_counts[file_key] = count
                    add_refs(found, ld)
                    scanned_windows += 1
        _scan_progress(requests, scanned_windows, 'image')
    def enqueue_window(payload, name, ld, file_key):
        nonlocal pending_bytes
        if file_key in failed_files: return False
        if pending and _batch_flush_before(len(pending), pending_bytes, len(payload), requests):
            flush_pending()
            if file_key in failed_files: return False
        pending.append((payload, name, ld, file_key))
        pending_bytes += len(payload)
        if len(pending) >= _archive_batch_items(requests): flush_pending()
        return file_key not in failed_files
    with tempfile.TemporaryDirectory(prefix='peaso-ecr-secret-') as directory:
        root = Path(directory)
        try:
            paths = _download_image_layers(requests, session, region, account, repo,
                digest, identity, descriptors, root, state)
            config_raw = paths[0].read_bytes()
            if len(config_raw) > 1024 * 1024: raise ValueError('config size bound')
            document = _json(config_raw.decode('utf-8'))
            if not isinstance(document, dict): raise ValueError('config object required')
            config_values, history = document.get('config'), document.get('history')
            if not isinstance(config_values, dict) or not isinstance(history, list):
                raise ValueError('incomplete config')
            env = config_values.get('Env', [])
            if not isinstance(env, list) or any(not isinstance(v, str) for v in env):
                raise ValueError('invalid environment')
            texts = []
            for value in env:
                key, separator, val = value.partition('=')
                if not separator or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', key):
                    raise ValueError('invalid variable')
                texts.append(key + '=' + json.dumps(val))
            for entry in history:
                if not isinstance(entry, dict) or not isinstance(entry.get('created_by'), str):
                    raise ValueError('invalid build history')
                texts.append(entry['created_by'])
            with source_context(resource_id=identity, scope=account + '/' + region,
                                image_digest=digest, layer=descriptors[0][0], native=document,
                                location_kind='configuration', path='image-config',
                                check_ids={'aws.review.ecr_repository.package_content_secret_indicators'}):
                add_refs(_scan('\n'.join(texts).encode(), 'image-config', requests), descriptors[0][0])
            remaining = [CONTENT_LIMIT]
            def observe(name, reader, size, layer_index):
                nonlocal complete
                ld = descriptors[layer_index + 1][0]
                file_key = object()
                with source_context(resource_id=identity, scope=account + '/' + region,
                                    image_digest=digest, layer=ld,
                                    check_ids={'aws.review.ecr_repository.package_content_secret_indicators'}):
                    found, covered = _scan_reader(reader, size, name, requests, remaining,
                        enqueue=lambda payload, path: enqueue_window(payload, path, ld, file_key),
                        causes=causes)
                add_refs(found, ld)
                if not covered: complete = False
            suffix = 'amazonaws.com.cn' if _partition(region) == 'aws-cn' else 'amazonaws.com'
            image_identity = {'provider': 'aws', 'scope': account + '/' + region,
                              'immutable_reference': f'{account}.dkr.ecr.{region}.{suffix}/{repo}@{digest}',
                              'manifest_digest': digest, 'config_digest': descriptors[0][0]}
            result = visit_files(image_identity, raw.encode(), config_raw, paths[1:],
                                 lambda *args: None, check=requests.check_deadline,
                                 partial_callback=observe)
            flush_pending()
            if result['expanded_bytes'] > ECR_EXPANDED_LIMIT:
                complete = False; causes.add('expanded_size_bound')
            if result.get('links_skipped', 0):
                complete = False; causes.add('symlink_members')
            if result.get('partial', False):
                complete = False; causes.add('archive_partial')
        except PartialArchive as partial:
            add_refs(partial.refs, descriptors[0][0])
            complete = False; causes.add('engine_incomplete')
        except Exception as exc:
            complete = False
            causes.add(exc.code if isinstance(exc, Unsupported) else
                       'layer_download_unavailable' if getattr(exc, 'code', None) == 'package_download_unavailable'
                       else 'image_archive_unreadable')
        finally:
            try: flush_pending()
            except Exception:
                complete = False; causes.add('engine_incomplete')
            if hasattr(state, 'active'): del state.active
    requests.check_deadline()
    for ld, _ in descriptors[1:]:
        reuse_image_layer([leak for ref in refs if ref.get('LayerDigest') == ld
                           for leak in ref.get('Leaks', [])],
                          resource_id=identity, scope=account + '/' + region,
                          image_digest=digest, layer=ld)
    return {'PackageSecretIndicators': marker(identity, account, region, 'ecr:batch_get_image', refs,
            complete=complete, code=None if complete else incomplete_reason('image_content_incomplete', causes)),
            'ImageDigest': digest}

def project_response(response, service, operation, arguments, *, request_context=None, region=None):
    """Root dispatcher invokes before Future.set_result; never return raw SDK data."""
    try:
        requests, session = _context(request_context)
        if (service, operation) not in PROJECTION_OPERATIONS or not isinstance(response, dict): raise ValueError('invalid projection operation')
        _partition(region)
        own = _own_account(requests, session, region)
        candidate = (_arn(arguments.get('FunctionName') if operation == 'get_function' else arguments.get('LayerName'), 'lambda', region)[0]
                     if service == 'lambda' else arguments.get('registryId'))
        if candidate != own: raise ValueError('foreign content request')
        if service == 'lambda': return _lambda(response, operation, arguments, requests, region)
        if operation == 'get_download_url_for_layer': return _layer(response, arguments, requests, region)
        return _image(response, arguments, requests, session, region)
    except Exception as exc:
        raise _failure(_projection_code(exc)) from None
    finally:
        # Budgets retain integers only; erase at the outer image boundary.
        if service == 'ecr' and operation == 'batch_get_image' and isinstance(request_context, tuple) and len(request_context) == 2:
            state = getattr(request_context[0], '_package_scan_local', None)
            if state is not None and hasattr(state, 'budget'): del state.budget


def _own_account(requests, session, region):
    identity = requests.detail(session, 'sts', region, 'get_caller_identity')
    account = identity.get('Account')
    partition = _partition(region)
    if (identity.get('collection_status') != 'collected' or not isinstance(account, str) or not re.fullmatch(r'[0-9]{12}', account)
            or not re.fullmatch(r'arn:' + partition + r':(?:sts|iam)::' + account + r':.+', identity.get('Arn', ''))):
        raise ValueError('own account authority unavailable')
    return account


def enrich(kind, requests, session, region, items):
    enabled = getattr(requests, 'content_secret_scans', False) is True
    try: account = _own_account(requests, session, region) if enabled else None
    except Exception: account = None
    output = []
    for original in items:
        item = deepcopy(original)
        source = {'collection_status': 'not_collected', 'error': {'code': 'content_secret_scans_disabled' if not enabled else 'package_binding_unavailable'}}
        try:
            if not enabled or account is None: raise ValueError('optout or authority unavailable')
            if kind == 'lambda_function':
                identity, resource = item['FunctionArn'], item['FunctionName']
                own, native = _arn(identity, 'lambda', region)
                version = item['Version']
                if own != account or native != 'function:' + resource or not isinstance(version, str) or not re.fullmatch(r'(?:\$LATEST|[1-9][0-9]*)', version):
                    raise ValueError('foreign function')
                # Container-image functions have no ZIP package (their image is
                # reviewed through its ECR repository) and oversized ZIPs exceed
                # the bound; neither needs a GetFunction call to know that.
                if item.get('PackageType') == 'Image':
                    source = {'collection_status': 'not_collected', 'error': {'code': 'lambda_image_package'}}
                    raise Unsupported('lambda_image_package')
                if type(item.get('CodeSize')) is int and item['CodeSize'] > ZIP_LIMIT:
                    source = {'collection_status': 'not_collected', 'error': {'code': 'package_size_bound'}}
                    raise Unsupported('package_size_bound')
                source = requests.detail(session, 'lambda', region, 'get_function', _metadata_profile=PROFILE, FunctionName=identity, Qualifier=version)
            elif kind == 'lambda_layer_version':
                identity, version = item['LayerVersionArn'], item['Version']
                own, native = _arn(identity, 'lambda', region)
                if own != account or type(version) is not int or version < 1 or native != 'layer:' + item['LayerName'] + ':' + str(version) or item.get('LayerArn') != identity.rsplit(':', 1)[0]:
                    raise ValueError('foreign layer')
                source = requests.detail(session, 'lambda', region, 'get_layer_version', _metadata_profile=PROFILE, LayerName=item['LayerArn'], VersionNumber=version)
            else:
                own, native = _arn(item['repositoryArn'], 'ecr', region)
                repo = item['repositoryName']
                if own != account or item.get('registryId') != account or native != 'repository/' + repo: raise ValueError('foreign repository')
                inventory = requests.pages(session, 'ecr', region, 'describe_images', 'imageDetails', registryId=account, repositoryName=repo)
                if inventory.status != 'collected' or not inventory.items or len(inventory.items) > 5000: raise ValueError('incomplete image inventory')
                images, digests = [], set()
                from datetime import datetime
                for row in inventory.items:
                    digest, pushed = row['imageDigest'], row['imagePushedAt']
                    if (not _digest(digest) or digest in digests or not isinstance(pushed, datetime) or pushed.tzinfo is None
                            or row.get('registryId') != account or row.get('repositoryName') != repo): raise ValueError('image inventory binding incomplete')
                    digests.add(digest); images.append((pushed, digest))
                images.sort()
                if len(images) > 1 and images[-1][0] == images[-2][0]: raise ValueError('ambiguous latest image')
                digest = images[-1][1]
                source = requests.detail(session, 'ecr', region, 'batch_get_image', _metadata_profile=PROFILE,
                    registryId=account, repositoryName=repo, imageIds=[{'imageDigest': digest}])
                source['SelectedImageDigest'] = digest
        except Exception:
            pass
        item['PackageContentSource'] = source
        output.append(item)
    return output


ENRICHERS = {kind: (lambda requests, session, region, items, k=kind: enrich(k, requests, session, region, items))
             for kind in ('lambda_function', 'lambda_layer_version', 'ecr_repository')}
