"""Owned OCI/Docker archives from independently native-bound immutable bytes.

No paths, image tags, Docker daemon, registry clients or credentials are inputs.
The collector must independently reconstruct the exact identity at the runner's
native-verifier seam; this module verifies every content descriptor locally.
"""
import contextlib
import hashlib
import io
import mmap
import os
import posixpath
import stat
import tempfile
from pathlib import Path
import json
from pathlib import PurePosixPath
import re
import shutil
import tarfile
import zlib

from peaso.image_content_memo_20261026 import BoundedMemo, StagedScratch
from peaso.image_tar_header_20261026 import header as _header

MAX_MANIFEST = 256 * 1024
MAX_CONFIG = 1024 * 1024
MAX_COMPRESSED = 1024 * 1024 * 1024
MAX_EXPANDED = 4 * 1024 * 1024 * 1024
MAX_LAYER = 512 * 1024 * 1024
MAX_LAYERS = 64
MAX_MEMBERS = 200000
MAX_ARCHIVE = 5 * 1024 * 1024 * 1024
OCI = 'application/vnd.oci.image.manifest.v1+json'
DOCKER = 'application/vnd.docker.distribution.manifest.v2+json'
CONFIGS = {'application/vnd.oci.image.config.v1+json', 'application/vnd.docker.container.image.v1+json'}
LAYERS = {'application/vnd.oci.image.layer.v1.tar', 'application/vnd.oci.image.layer.v1.tar+gzip',
          'application/vnd.docker.image.rootfs.diff.tar.gzip'}
DIGEST = re.compile(r'sha256:[0-9a-f]{64}\Z')
IDENTITY_KEYS = {'provider', 'scope', 'immutable_reference', 'manifest_digest', 'config_digest'}


def require(ok, code):
    if not ok:
        raise ValueError(code)


def sha(raw):
    return 'sha256:' + hashlib.sha256(raw).hexdigest()


def decode(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'duplicate_json_key')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique,
                      parse_constant=lambda _: require(False, 'non_json_constant'))


def identity(value):
    require(type(value) is dict and set(value) == IDENTITY_KEYS, 'closed_native_image_identity_required')
    require(value['provider'] in ('aws', 'azure', 'gcp', 'k8s'), 'supported_native_provider_required')
    require(type(value['scope']) is str and re.fullmatch(r'[A-Za-z0-9:/_.-]{1,512}', value['scope']),
            'exact_native_scope_required')
    for key in ('manifest_digest', 'config_digest'):
        require(type(value[key]) is str and DIGEST.fullmatch(value[key]), 'exact_sha256_required')
    reference = value['immutable_reference']
    require(type(reference) is str and len(reference) <= 512 and re.fullmatch(
        r'[a-z0-9][a-z0-9.-]+(?::[0-9]+)?/[a-z0-9][a-z0-9/_.-]*@sha256:[0-9a-f]{64}', reference),
        'literal_immutable_registry_reference_required')
    require(reference.rsplit('@', 1)[1] == value['manifest_digest'] and
            all(part not in ('', '.', '..') for part in reference.split('@')[0].split('/')),
            'immutable_image_digest_mismatch')
    return dict(value)


def descriptor(item, types, cap):
    from peaso.oci_descriptor_data_20261026 import embedded_matches
    require(type(item) is dict and not set(item) - {'mediaType', 'digest', 'size', 'annotations', 'data'}
            and item.get('mediaType') in types and type(item.get('size')) is int
            and 0 < item['size'] <= cap and type(item.get('digest')) is str
            and DIGEST.fullmatch(item['digest'])
            and ('data' not in item or embedded_matches(item)), 'unsupported_descriptor')
    return item



CHUNK = 64 * 1024
MAX_LINKS = 40
MAX_PAX = 64 * 1024
MAX_PATH = 4096
MAX_PATH_BYTES = 64 * 1024 * 1024
MIN_FREE_DISK = 256 * 1024 * 1024
DISK_CHECK_STEP = 64 * 1024 * 1024
STANDARD_CHAR_DEVICES = {
    'dev/console': (5, 1),
    'dev/null': (1, 3),
    'dev/random': (1, 8),
    'dev/urandom': (1, 9),
    'dev/zero': (1, 5),
}


def _source(value, expected_size):
    if type(value) is bytes:
        require(len(value) == expected_size, 'layer_descriptor_mismatch')
        return io.BytesIO(value)
    require(isinstance(value, Path) and value.is_absolute(), 'owned_regular_layer_required')
    try:
        fd = os.open(value, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    except OSError as exc:
        raise ValueError('owned_regular_layer_required') from exc
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_size != expected_size or info.st_uid != os.getuid():
        os.close(fd)
        raise ValueError('owned_regular_layer_required')
    return os.fdopen(fd, 'rb')


def _expand(raw, desc, diff, output, budget, check):
    compressed_hash, expanded_hash = hashlib.sha256(), hashlib.sha256()
    compressed_size = expanded_size = 0
    gzip = desc['mediaType'].endswith('gzip')
    inflater = zlib.decompressobj(zlib.MAX_WBITS | 16) if gzip else None
    def emit(data):
        nonlocal expanded_size
        if data:
            if expanded_size // DISK_CHECK_STEP != (expanded_size + len(data)) // DISK_CHECK_STEP:
                require(shutil.disk_usage(output.name).free >= MIN_FREE_DISK + len(data),
                        'scratch_disk_bound')
            expanded_size += len(data)
            require(expanded_size + budget[0] <= MAX_EXPANDED, 'expanded_image_bound')
            expanded_hash.update(data)
            output.write(data)
    with _source(raw, desc['size']) as source:
        while True:
            check()
            part = source.read(CHUNK)
            if not part:
                break
            compressed_size += len(part)
            require(compressed_size <= desc['size'], 'layer_descriptor_mismatch')
            compressed_hash.update(part)
            if gzip:
                require(not inflater.eof, 'layer_compression_bound')
                pending = part
                while pending:
                    check()
                    before = len(pending)
                    produced = inflater.decompress(pending, CHUNK)
                    emit(produced)
                    require(not inflater.unused_data, 'layer_compression_bound')
                    pending = inflater.unconsumed_tail
                    require(produced or len(pending) < before or inflater.eof, 'layer_compression_bound')
                    if inflater.eof:
                        require(not pending, 'layer_compression_bound')
                        break
            else:
                emit(part)
    require(compressed_size == desc['size'] and 'sha256:' + compressed_hash.hexdigest() == desc['digest'],
            'layer_descriptor_mismatch')
    if gzip:
        require(inflater.eof and not inflater.unused_data and not inflater.unconsumed_tail,
                'layer_compression_bound')
        emit(inflater.flush())
    require('sha256:' + expanded_hash.hexdigest() == diff, 'rootfs_digest_or_expansion_mismatch')
    return expanded_size


def _normalize(value, base='', *, allow_absolute=False):
    require(type(value) is str and value and '\\' not in value and '\x00' not in value,
            'unsafe_image_path')
    require(allow_absolute or not value.startswith('/'), 'unsafe_image_path')
    parts = [] if value.startswith('/') else [p for p in base.split('/') if p]
    for part in value.split('/'):
        if part in ('', '.'):
            continue
        if part == '..':
            require(bool(parts), 'image_path_escape')
            parts.pop()
        else:
            parts.append(part)
    require(bool(parts), 'unsafe_image_path')
    result = '/'.join(parts)
    require(len(result.encode('utf-8')) <= MAX_PATH, 'image_path_bound')
    return result


def _resolve(value, nodes):
    return _resolve_hops(value, nodes)[0]


class _Parents:
    """Memo of parent paths whose every prefix is not a symlink.

    Such a path resolves to itself. Only a later symlink at one of its prefixes
    can change that, so adding one there drops the memo.
    """

    def __init__(self, nodes):
        self.nodes, self.plain, self.prefixes = nodes, set(), set()

    def resolve(self, value):
        if value in self.plain:
            return value
        result, hops = _resolve_hops(value, self.nodes)
        if not hops:
            self.plain.add(value)
            at = value.find('/')
            while at != -1:
                self.prefixes.add(value[:at])
                at = value.find('/', at + 1)
            self.prefixes.add(value)
        return result

    def symlink_added(self, name):
        if name in self.prefixes:
            self.plain.clear()
            self.prefixes.clear()


def _resolve_hops(value, nodes):
    parts = value.split('/')
    resolved = []
    hops = 0
    while parts:
        part = parts.pop(0)
        candidate = '/'.join(resolved + [part])
        node = nodes.get(candidate)
        if node and node[0] == 'symlink':
            hops += 1
            require(hops <= MAX_LINKS, 'image_link_cycle')
            target = _normalize(node[1], '/'.join(resolved), allow_absolute=True)
            resolved, parts = [], target.split('/') + parts
        else:
            resolved.append(part)
    result = '/'.join(resolved)
    require(len(result.encode('utf-8')) <= MAX_PATH, 'image_path_bound')
    return result, hops


def _pax(raw):
    require(len(raw) <= MAX_PAX, 'tar_metadata_bound')
    result = {}
    at = 0
    while at < len(raw):
        space = raw.find(b' ', at)
        require(space > at and space - at <= 8, 'invalid_pax')
        size = int(raw[at:space])
        record = raw[space + 1:at + size]
        require(size > space - at + 2 and at + size <= len(raw) and record.endswith(b'\n')
                and b'=' in record, 'invalid_pax')
        key, value = record[:-1].split(b'=', 1)
        require(not key.startswith(b'GNU.sparse') and key not in (b'SCHILY.realsize', b'size'),
                'unsupported_sparse_tar')
        if key in (b'path', b'linkpath'):
            result[key.decode()] = value.decode('utf-8', 'strict')
        at += size
    return result


class _Mapped:
    """read/seek/tell over a read-only map of a finished private layer file.

    Header reads hop between members; slicing a map avoids a syscall and a
    discarded read buffer per member while returning the same bytes.
    """

    def __init__(self, handle, base=0, length=None):
        self.handle, self.map, self.at = handle, None, 0
        self.base, self.length = base, length

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        if self.map is not None:
            self.map.close()

    def tell(self):
        return self.at

    def read(self, size):
        if self.map is None:
            self.map = mmap.mmap(self.handle.fileno(), 0, access=mmap.ACCESS_READ)
            if self.length is None:
                self.length = len(self.map) - self.base
        start = self.base + self.at
        data = self.map[start:min(start + size, self.base + self.length)]
        self.at += len(data)
        return data

    def seek(self, offset, whence):
        require(whence == os.SEEK_CUR, 'unsupported_seek')
        self.at += offset
        return self.at


def _tar_members(path, nodes, count, check, layer_index, path_budget, start=0, length=None):
    """Index one expanded layer: the whole file, or `length` bytes at `start`."""
    seen, pending, global_pax = set(), {}, {}
    prior = set(nodes)
    parents = _Parents(nodes)
    headers = 0
    with path.open('rb') as handle, _Mapped(handle, start, length) as source:
        size = path.stat().st_size - start if length is None else length
        require(size >= 1024 and size % 512 == 0, 'truncated_tar')
        while True:
            check()
            block = source.read(512)
            require(len(block) == 512, 'tar_terminator_required')
            if block == bytes(512):
                require(source.read(512) == bytes(512), 'tar_terminator_required')
                while True:
                    check()
                    tail = source.read(CHUNK)
                    if not tail:
                        break
                    require(not any(tail), 'tar_trailing_content')
                require(not pending, 'dangling_tar_metadata')
                return count
            headers += 1
            require(headers <= 2 * MAX_MEMBERS, 'tar_member_bound')
            try:
                member = _header(block)
            except (tarfile.TarError, UnicodeError, ValueError) as exc:
                raise ValueError('invalid_tar_header') from exc
            require(member.size >= 0 and member.size <= MAX_EXPANDED and
                    member.size <= size - source.tell(), 'truncated_tar_member')
            if member.type in (tarfile.XHDTYPE, tarfile.XGLTYPE,
                               tarfile.GNUTYPE_LONGNAME, tarfile.GNUTYPE_LONGLINK):
                require(member.size <= MAX_PAX, 'tar_metadata_bound')
                data = source.read(member.size)
                if member.type in (tarfile.XHDTYPE, tarfile.XGLTYPE):
                    parsed = _pax(data)
                    if member.type == tarfile.XGLTYPE:
                        global_pax.update(parsed)
                    else:
                        pending.update(parsed)
                else:
                    key = 'path' if member.type == tarfile.GNUTYPE_LONGNAME else 'linkpath'
                    pending[key] = data.rstrip(b'\x00').decode('utf-8', 'strict')
            else:
                name = pending.get('path', global_pax.get('path', member.name))
                linkname = pending.get('linkpath', global_pax.get('linkpath', member.linkname))
                pending = {}
                # GNU/Debian image layers commonly use './' and a root directory
                # marker. Canonicalize only that leading prefix, before duplicate
                # and traversal checks; never extract or create the root marker.
                require(type(name) is str and bool(name) and len(name.encode('utf-8')) <= MAX_PATH,
                        'image_path_bound')
                while name.startswith('./'):
                    name = name[2:]
                if name in ('', '.'):
                    require(member.type == tarfile.DIRTYPE and member.size == 0 and not linkname,
                            'unsafe_image_path')
                    require('.' not in seen, 'duplicate_tar_member')
                    seen.add('.')
                    count += 1
                    require(count <= MAX_MEMBERS, 'tar_member_bound')
                    continue
                require(name and not name.startswith('/') and '\\' not in name and
                        all(part not in ('', '.', '..') for part in name.rstrip('/').split('/')),
                        'unsafe_image_path')
                name = _normalize(name)
                path_budget[0] += len(name.encode('utf-8')) + len(linkname.encode('utf-8'))
                require(path_budget[0] <= MAX_PATH_BYTES, 'image_paths_bound')
                require(name not in seen, 'duplicate_tar_member')
                seen.add(name)
                count += 1
                require(count <= MAX_MEMBERS, 'tar_member_bound')
                parent = posixpath.dirname(name)
                resolved = parents.resolve(parent) if parent else ''
                actual = '/'.join(filter(None, (resolved, posixpath.basename(name))))
                require(actual != '', 'unsafe_image_path')
                if member.type in (tarfile.REGTYPE, tarfile.AREGTYPE):
                    basename = posixpath.basename(actual)
                    if basename == '.wh..wh..opq':
                        prefix = posixpath.dirname(actual)
                        prefix = prefix + '/' if prefix else ''
                        for old in prior:
                            if old.startswith(prefix):
                                nodes.pop(old, None)
                    elif basename.startswith('.wh.'):
                        victim = '/'.join(filter(None, (posixpath.dirname(actual), basename[4:])))
                        require(basename[4:] not in ('', '.', '..'), 'unsafe_whiteout')
                        for old in prior:
                            if old == victim or old.startswith(victim + '/'):
                                nodes.pop(old, None)
                    else:
                        nodes[actual] = ('file', (path, start + source.tell(), member.size, layer_index))
                elif member.type == tarfile.DIRTYPE:
                    require(member.size == 0, 'unsupported_tar_member')
                    nodes[actual] = ('directory', '')
                elif member.type == tarfile.SYMTYPE:
                    require(member.size == 0, 'unsupported_tar_member')
                    _normalize(linkname, posixpath.dirname(actual), allow_absolute=True)
                    nodes[actual] = ('symlink', linkname)
                    parents.symlink_added(actual)
                elif member.type == tarfile.LNKTYPE:
                    require(member.size == 0, 'unsupported_tar_member')
                    candidates = []
                    bases = (posixpath.dirname(actual), '') if linkname.startswith('.') else ('', posixpath.dirname(actual))
                    for base in bases:
                        try:
                            target = _resolve(_normalize(linkname, base, allow_absolute=True), nodes)
                        except ValueError:
                            continue
                        if target not in candidates:
                            candidates.append(target)
                    targets = [candidate for candidate in candidates
                               if nodes.get(candidate, (None,))[0] in ('file', 'hardlink')]
                    require(bool(targets), 'unsafe_hardlink_target')
                    nodes[actual] = ('hardlink', nodes[targets[0]][1])
                elif member.type == tarfile.CHRTYPE:
                    require(member.size == 0 and name == actual and
                            STANDARD_CHAR_DEVICES.get(actual) == (member.devmajor, member.devminor),
                            'unsupported_tar_member')
                    nodes[actual] = ('device', '')
                else:
                    raise ValueError('unsupported_tar_member')
            pad = ((member.size + 511) // 512) * 512 - member.size
            if member.type not in (tarfile.XHDTYPE, tarfile.XGLTYPE,
                                   tarfile.GNUTYPE_LONGNAME, tarfile.GNUTYPE_LONGLINK):
                source.seek(member.size, os.SEEK_CUR)
            require(len(source.read(pad)) == pad, 'truncated_tar_member')


def _graph(image_identity, manifest_raw, config_raw, layers):
    """Bounded descriptor graph checks that precede any layer byte access."""
    checked = identity(image_identity)
    require(type(manifest_raw) is bytes and 0 < len(manifest_raw) <= MAX_MANIFEST
            and sha(manifest_raw) == checked['manifest_digest'], 'manifest_digest_or_size_mismatch')
    require(type(config_raw) is bytes and 0 < len(config_raw) <= MAX_CONFIG
            and sha(config_raw) == checked['config_digest'], 'config_digest_or_size_mismatch')
    manifest, config = decode(manifest_raw), decode(config_raw)
    require(type(manifest) is dict and not set(manifest) -
            {'schemaVersion', 'mediaType', 'config', 'layers', 'annotations'}
            and type(manifest.get('schemaVersion')) is int and manifest['schemaVersion'] == 2
            and manifest.get('mediaType') in (OCI, DOCKER), 'single_platform_manifest_required')
    conf = descriptor(manifest['config'], CONFIGS, MAX_CONFIG)
    require(conf['digest'] == checked['config_digest'] and conf['size'] == len(config_raw),
            'config_descriptor_mismatch')
    descs = manifest.get('layers')
    require(type(descs) is list and 1 <= len(descs) <= MAX_LAYERS
            and type(layers) in (list, tuple) and len(layers) == len(descs), 'all_layers_required')
    descs = [descriptor(d, LAYERS, MAX_LAYER) for d in descs]
    require(sum(d['size'] for d in descs) + len(config_raw) <= MAX_COMPRESSED,
            'compressed_image_bound')
    require(type(config) is dict and config.get('os') == 'linux' and config.get('architecture') in ('amd64', 'arm64')
            and type(config.get('rootfs')) is dict and config['rootfs'].get('type') == 'layers',
            'supported_platform_rootfs_required')
    diffs = config['rootfs'].get('diff_ids')
    require(type(diffs) is list and len(diffs) == len(descs)
            and all(type(d) is str and DIGEST.fullmatch(d) for d in diffs), 'rootfs_diff_ids_required')
    return manifest, descs, diffs


# Successful full validations, keyed by the exact compressed/expanded digest
# chain and config size (the only inputs the layer walk depends on). A hit is
# admitted only after the current compressed bytes re-hash to that chain.
_PROVEN = BoundedMemo(1024)
# Expanded layer files of the latest full validation, handed to the next
# archive build of the same chain instead of decompressing every layer again.
# They are re-hashed against their diff_ids while copied into the archive.
_STAGED = StagedScratch(1024 * 1024 * 1024, 300)


def _park(config_raw, descs, diffs, scratch, expanded, budget, stage):
    if not stage:
        shutil.rmtree(scratch, ignore_errors=True)
        return
    _STAGED.park(_chain(config_raw, descs, diffs), scratch, expanded,
                 budget[0] - len(config_raw))


def release_staged(image_identity, manifest_raw, config_raw, layers):
    """Remove expanded layers a caller staged for this image and did not archive."""
    try:
        _, descs, diffs = _graph(image_identity, manifest_raw, config_raw, layers)
    except ValueError:
        return
    staged = _STAGED.take(_chain(config_raw, descs, diffs))
    if staged is not None:
        shutil.rmtree(staged[0], ignore_errors=True)


def _chain(config_raw, descs, diffs):
    limits = (MAX_EXPANDED, MAX_MEMBERS, MAX_PATH, MAX_PATH_BYTES, MAX_LINKS, MAX_PAX,
              tuple(sorted(STANDARD_CHAR_DEVICES.items())))
    return limits, (len(config_raw), tuple((d['mediaType'], d['digest'], d['size'], diff)
                                   for d, diff in zip(descs, diffs)))


def _verify_compressed(raw, desc, check):
    digest, size = hashlib.sha256(), 0
    with _source(raw, desc['size']) as source:
        while True:
            check()
            part = source.read(1024 * 1024)
            if not part:
                break
            size += len(part)
            require(size <= desc['size'], 'layer_descriptor_mismatch')
            digest.update(part)
    require(size == desc['size'] and 'sha256:' + digest.hexdigest() == desc['digest'],
            'layer_descriptor_mismatch')


def _proven(config_raw, descs, diffs, layers, check):
    """Return (layer sizes, members) for already-proven content, else None."""
    known = _PROVEN.get(_chain(config_raw, descs, diffs))
    if known is None:
        return None
    for desc, raw in zip(descs, layers):
        check()
        _verify_compressed(raw, desc, check)
    return known


class _Expanded:
    """One proven layer streamed straight into an archive member, re-verified."""

    def __init__(self, raw, desc, diff, size, check):
        self.raw, self.desc, self.diff, self.size, self.check = raw, desc, diff, size, check

    def stream(self):
        return _ExpandingReader(self, _source(self.raw, self.desc['size']))


class _ExpandingReader:
    def __init__(self, layer, source):
        self.layer, self.source = layer, source
        self.inflater = (zlib.decompressobj(zlib.MAX_WBITS | 16)
                         if layer.desc['mediaType'].endswith('gzip') else None)
        self.tail, self.done = b'', False
        self.compressed, self.expanded = hashlib.sha256(), hashlib.sha256()
        self.compressed_size = self.expanded_size = 0

    def _next(self, limit=CHUNK):
        self.layer.check()
        part = self.source.read(limit)
        self.compressed_size += len(part)
        require(self.compressed_size <= self.layer.desc['size'], 'layer_changed_during_archive')
        self.compressed.update(part)
        return part

    def read(self, size=-1):
        size = CHUNK if size is None or size < 0 else size
        out = bytearray()
        while len(out) < size and not self.done:
            if self.inflater is None:
                part = self._next(min(CHUNK, size - len(out)))
                if not part:
                    self.done = True
                out += part
                continue
            if not self.tail:
                if self.inflater.eof:
                    require(not self._next(), 'layer_changed_during_archive')
                    self.done = True
                    break
                self.tail = self._next()
                if not self.tail:
                    out += self.inflater.flush()
                    self.done = True
                    break
            out += self.inflater.decompress(self.tail, size - len(out))
            require(not self.inflater.unused_data, 'layer_changed_during_archive')
            self.tail = self.inflater.unconsumed_tail
        data = bytes(out[:size])
        require(len(out) <= size, 'layer_changed_during_archive')
        self.expanded_size += len(data)
        require(self.expanded_size <= self.layer.size, 'layer_changed_during_archive')
        self.expanded.update(data)
        return data

    def finish(self):
        require(not self.read(CHUNK), 'layer_changed_during_archive')
        require(self.compressed_size == self.layer.desc['size']
                and 'sha256:' + self.compressed.hexdigest() == self.layer.desc['digest']
                and (self.inflater is None or (self.inflater.eof and not self.inflater.unused_data))
                and self.expanded_size == self.layer.size
                and 'sha256:' + self.expanded.hexdigest() == self.layer.diff,
                'layer_changed_during_archive')

    def close(self):
        self.source.close()


def _member_header(name, size):
    # The exact header tarfile.addfile writes for write_archive's members.
    member = tarfile.TarInfo(name)
    member.size, member.mode, member.mtime = size, 0o600, 0
    return member.tobuf(tarfile.USTAR_FORMAT, tarfile.ENCODING, 'surrogateescape')


def _docker_manifest(config_name, count):
    return json.dumps([{'Config': config_name, 'RepoTags': [],
                        'Layers': [f'layer-{n}/layer.tar' for n in range(count)]}]).encode()


class _Built:
    """A docker archive written by one validation, byte-identical to write_archive's."""

    def __init__(self, path, config_digest, check=lambda: None):
        info = path.lstat()
        self.path, self.config_digest = path, config_digest
        self.identity = (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)
        require(info.st_size <= MAX_ARCHIVE, 'owned_archive_bound')
        self.digest = self._digest(path, check)

    def _digest(self, path, check):
        digest, size = hashlib.sha256(), 0
        with _source(path, self.identity[2]) as source:
            while True:
                check()
                part = source.read(1024 * 1024)
                if not part:
                    break
                size += len(part)
                require(size <= self.identity[2], 'layer_changed_during_archive')
                digest.update(part)
        require(size == self.identity[2], 'layer_changed_during_archive')
        return digest.digest()

    def place(self, target, check=lambda: None):
        info = os.lstat(self.path)
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.getuid()
                and (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns) == self.identity,
                'layer_changed_during_archive')
        try:
            os.link(self.path, target)
        except FileExistsError:
            raise
        except OSError:
            # No hard link across file systems: copy the same private bytes.
            require(shutil.disk_usage(target.parent).free >= info.st_size + MIN_FREE_DISK,
                    'scratch_disk_bound')
            with _source(self.path, info.st_size) as source, target.open('xb') as output:
                shutil.copyfileobj(source, output, 1024 * 1024)
        require(target.stat().st_size == info.st_size, 'layer_changed_during_archive')
        # Same-size writes can share an mtime tick, or restore the old mtime.
        # Check the bytes actually handed to the scanner, including copy fallback.
        require(self._digest(target, check) == self.digest, 'layer_changed_during_archive')


def _validate(image_identity, manifest_raw, config_raw, layers, root, check, partial_callback=None,
              ready=None):
    """Expand and index every layer straight into the docker archive members.

    The archive is written in write_archive's exact docker layout (manifest.json,
    config, then each expanded layer); each layer is indexed in place.
    """
    manifest, descs, diffs = _graph(image_identity, manifest_raw, config_raw, layers)
    budget, nodes, path_budget = (len(config_raw), 0), {}, [0]
    sizes = []
    archive = root / 'docker-archive.tar'
    config_name = image_identity['config_digest'][7:] + '.json'
    with archive.open('xb') as output:
        for name, data in (('manifest.json', _docker_manifest(config_name, len(descs))),
                           (config_name, config_raw)):
            output.write(_member_header(name, len(data)) + data + bytes(-len(data) % 512))
        for index, (desc, raw, diff) in enumerate(zip(descs, layers, diffs)):
            if ready is not None:
                raw = ready(index)
            check()
            require(shutil.disk_usage(root).free >= MIN_FREE_DISK + DISK_CHECK_STEP,
                    'scratch_disk_bound')
            header_at = output.tell()
            output.write(bytes(512))
            size = _expand(raw, desc, diff, output, budget, check)
            output.write(bytes(-size % 512))
            output.seek(header_at)
            output.write(_member_header(f'layer-{index}/layer.tar', size))
            output.seek(0, os.SEEK_END)
            output.flush()
            count = _tar_members(archive, nodes, budget[1], check, index, path_budget,
                                 header_at + 512, size)
            if partial_callback is not None:
                for name, node in sorted(nodes.items()):
                    if node[0] in ('file', 'hardlink') and node[1][3] == index:
                        _visit_node(name, node, partial_callback, check)
            budget = size + budget[0], count
            sizes.append(size)
        # tarfile's end of archive: two zero blocks, padded to a full record.
        end = output.tell() + 2 * tarfile.BLOCKSIZE
        output.write(bytes(2 * tarfile.BLOCKSIZE + (-end % tarfile.RECORDSIZE)))
    _PROVEN.put(_chain(config_raw, descs, diffs), (tuple(sizes), budget[1]))
    return manifest, _Built(archive, image_identity['config_digest'], check), budget, nodes


def validate(image_identity, manifest_raw, config_raw, layers, check=lambda: None, *, stage=False,
             ready=None):
    """Validate a content graph; expanded layers live only in private scratch.

    With `stage=True` (the caller archives this image next), the expanded layers
    stay in that scratch for one write_archive, which re-hashes them.
    With `ready`, `layers` only fixes the count and `ready(index)` returns each
    layer once it is available (still downloading layers are waited for).
    """
    manifest, descs, diffs = _graph(image_identity, manifest_raw, config_raw, layers)
    if ready is None:
        known = _proven(config_raw, descs, diffs, layers, check)
    elif _PROVEN.get(_chain(config_raw, descs, diffs)) is not None:
        layers = [ready(index) for index in range(len(descs))]
        known = _proven(config_raw, descs, diffs, layers, check)
    else:
        known = None
    if known is not None:
        return manifest, [], (len(config_raw) + sum(known[0]), known[1])
    scratch = Path(tempfile.mkdtemp(prefix='peaso-image-validate-'))
    try:
        manifest, expanded, budget, _ = _validate(image_identity, manifest_raw, config_raw, layers,
                                               scratch, check, ready=ready)
    except BaseException:
        shutil.rmtree(scratch, ignore_errors=True)
        raise
    _park(config_raw, descs, diffs, scratch, expanded, budget, stage)
    return manifest, [], budget


class _BoundedReader:
    def __init__(self, source, size, check):
        self.source, self.remaining, self.check = source, size, check

    def read(self, size=-1):
        self.check()
        if size is None or size < 0:
            size = self.remaining
        data = self.source.read(min(size, self.remaining))
        self.remaining -= len(data)
        return data


def _visit_node(name, node, callback, check):
    file_path, offset, size, layer_index = node[1]
    with file_path.open('rb') as source:
        source.seek(offset)
        callback(name, _BoundedReader(source, size, check), size, layer_index)


def visit_files(image_identity, manifest_raw, config_raw, layers, callback,
                check=lambda: None, *, partial_callback=None, stage=False):
    """Visit final regular files after all layers validate; optionally report each verified layer."""
    require(callable(callback) and (partial_callback is None or callable(partial_callback)),
            'file_callback_required')
    manifest, descs, diffs = _graph(image_identity, manifest_raw, config_raw, layers)
    scratch = Path(tempfile.mkdtemp(prefix='peaso-image-visit-'))
    try:
        _, expanded, budget, nodes = _validate(image_identity, manifest_raw, config_raw, layers,
                                               scratch, check, partial_callback)
        visited = 0
        for name, node in sorted(nodes.items()):
            check()
            if node[0] not in ('file', 'hardlink'):
                continue
            _visit_node(name, node, callback, check)
            visited += 1
    except BaseException:
        shutil.rmtree(scratch, ignore_errors=True)
        raise
    _park(config_raw, descs, diffs, scratch, expanded, budget, stage)
    return {'expanded_bytes': budget[0], 'members': budget[1], 'visited_files': visited,
            'links_seen': sum(node[0] in ('symlink', 'hardlink') for node in nodes.values()),
            'links_skipped': sum(node[0] == 'symlink' for node in nodes.values())}


class _CheckedReader:
    def __init__(self, source, check):
        self.source, self.check = source, check
        self.hash = hashlib.sha256()
        self.count = 0

    def read(self, size):
        self.check()
        data = self.source.read(size)
        self.hash.update(data)
        self.count += len(data)
        return data


def write_archive(path, image_identity, manifest_raw, config_raw, layers, *, archive_format='oci', check=lambda: None):
    """Write a bounded OCI or Docker archive using file-backed validated layers."""
    require(archive_format in ('oci', 'docker'), 'explicit_archive_format_required')
    require(isinstance(path, Path) and path.is_absolute(), 'private_archive_path_required')
    try:
        with tempfile.TemporaryDirectory(prefix='peaso-image-layers-', dir=path.parent) as scratch, \
                contextlib.ExitStack() as stack:
            manifest, descs, diffs = _graph(image_identity, manifest_raw, config_raw, layers)
            known = _proven(config_raw, descs, diffs, layers, check)
            staged = None if known is None else _STAGED.take(_chain(config_raw, descs, diffs))
            if staged is not None:
                stack.callback(shutil.rmtree, staged[0], True)
            built = None
            if known is None:
                manifest, built, budget, _ = _validate(image_identity, manifest_raw, config_raw, layers,
                                                    Path(scratch), check)
            elif (staged is not None and type(staged[1]) is _Built
                    and staged[1].config_digest == image_identity['config_digest']):
                # The caller's validation of these same bytes already wrote this
                # exact docker archive in private scratch.
                budget = len(config_raw) + sum(known[0]), known[1]
                built = staged[1]
            if built is None:
                # Already-proven bytes: decompress each layer directly into its
                # archive member instead of staging a second expanded copy.
                budget = len(config_raw) + sum(known[0]), known[1]
                expanded = [_Expanded(raw, desc, diff, size, check)
                            for raw, desc, diff, size in zip(layers, descs, diffs, known[0])]
            if archive_format == 'oci':
                require(manifest['mediaType'] == OCI and
                        manifest['config']['mediaType'] == 'application/vnd.oci.image.config.v1+json'
                        and all(d['mediaType'].startswith('application/vnd.oci.image.layer.') for d in manifest['layers']),
                        'mixed_oci_docker_archive_unsupported')
            total = 10240
            require(shutil.disk_usage(path.parent).free >= MIN_FREE_DISK + DISK_CHECK_STEP,
                    'scratch_disk_bound')
            if archive_format == 'docker' and built is not None:
                require(built.identity[2] <= MAX_ARCHIVE, 'owned_archive_bound')
                built.place(path, check)
            else:
                with path.open('xb') as output:
                    with tarfile.open(fileobj=output, mode='w', format=tarfile.USTAR_FORMAT) as tar:
                        def add(name, value, expected_digest=None):
                            nonlocal total
                            check()
                            size = (len(value) if type(value) is bytes else value.size
                                    if type(value) is _Expanded else value.stat().st_size)
                            total += 512 + ((size + 511) // 512) * 512
                            require(total <= MAX_ARCHIVE, 'owned_archive_bound')
                            require(shutil.disk_usage(path.parent).free >= size + MIN_FREE_DISK,
                                    'scratch_disk_bound')
                            member = tarfile.TarInfo(name)
                            member.size, member.mode, member.mtime = size, 0o600, 0
                            if type(value) is bytes:
                                tar.addfile(member, io.BytesIO(value))
                            elif type(value) is _Expanded:
                                reader = value.stream()
                                try:
                                    tar.addfile(member, reader)
                                    reader.finish()
                                finally:
                                    reader.close()
                            else:
                                with _source(value, size) as source:
                                    reader = _CheckedReader(source, check)
                                    tar.addfile(member, reader)
                                    require(reader.count == size and (expected_digest is None or
                                        'sha256:' + reader.hash.hexdigest() == expected_digest),
                                        'layer_changed_during_archive')
                        if archive_format == 'oci':
                            add('oci-layout', b'{"imageLayoutVersion":"1.0.0"}')
                            index = {'schemaVersion': 2, 'mediaType': 'application/vnd.oci.image.index.v1+json',
                                     'manifests': [{'mediaType': manifest['mediaType'],
                                        'digest': image_identity['manifest_digest'], 'size': len(manifest_raw),
                                        'platform': {'os': decode(config_raw)['os'],
                                                     'architecture': decode(config_raw)['architecture']}}]}
                            add('index.json', json.dumps(index, separators=(',', ':')).encode())
                            seen = set()
                            for digest, value in [(image_identity['manifest_digest'], manifest_raw),
                                                  (image_identity['config_digest'], config_raw)] + [
                                                      (d['digest'], raw) for d, raw in zip(manifest['layers'], layers)]:
                                if digest not in seen:
                                    add('blobs/sha256/' + digest[7:], value, digest)
                                    seen.add(digest)
                        else:
                            config_name = image_identity['config_digest'][7:] + '.json'
                            names = [f'layer-{n}/layer.tar' for n in range(len(expanded))]
                            add('manifest.json', json.dumps([{'Config': config_name,
                                'RepoTags': [], 'Layers': names}]).encode())
                            add(config_name, config_raw)
                            for name, value in zip(names, expanded):
                                add(name, value)
        require(path.stat().st_size <= MAX_ARCHIVE, 'archive_disk_bound')
        return {'format': archive_format, 'bytes': path.stat().st_size,
                'expanded_bytes': budget[0], 'members': budget[1],
                'manifest_digest': image_identity['manifest_digest'],
                'config_digest': image_identity['config_digest']}
    except Exception:
        path.unlink(missing_ok=True)
        raise
