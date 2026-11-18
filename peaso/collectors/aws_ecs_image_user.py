"""Image USER for ECS containers whose task definition declares no user.

Docker runs a container as its image config's ``User`` when the task
definition sets none, and as root when that is empty too. For an immutable
(digest-pinned) private ECR image this module reads that config through the
existing native ECR reader and records the user beside the task definition.

A named user is resolved to its UID from the image's ``/etc/passwd`` (the
topmost layer that holds the file wins, as in the container's root
filesystem). That needs the layers above the file, so it is bounded per image
and per scan; past the bound, the user stays unresolved by name.

Read-only and opt-in: it runs only when the scan already permits ECR image
content reads (``content_secret_scans`` with the ECR repository content kind).
Every manifest, config and layer is read at most once per scan: configs and
layer facts are cached by their verified content digest, images by digest and
session. Nothing is executed or extracted to the host filesystem.
"""
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from pathlib import Path
import re
import tarfile
import tempfile
import threading

KIND = 'ecs_task_definition'
FIELD = 'ImageUsers'
CONTENT_KIND = 'ecr_repository'
MAX_IMAGES = 128
IMAGE_LAYER_BUDGET = 256 * 1024 * 1024
SCAN_LAYER_BUDGET = 2 * 1024 * 1024 * 1024
ACCOUNT_FILE_LIMIT = 1024 * 1024
MAX_PLATFORMS = 8
_CANCEL = ('collection_cancelled', 'deadline_exceeded', 'intentional_scan_deadline')
_IMAGE = re.compile(r'([0-9]{12})\.dkr\.ecr\.([a-z]{2}(?:-[a-z0-9]+)+-[0-9]+)\.amazonaws\.com(?:\.cn)?/([^@]{2,256})@(sha256:[0-9a-f]{64})\Z')
_ARCHITECTURES = {'X86_64': 'amd64', 'ARM64': 'arm64'}
_ETC = 'etc/'


class _State:
    def __init__(self):
        self.lock = threading.Lock()
        self.images, self.configs, self.layers = {}, {}, {}
        self.layer_bytes = 0


def _state(requests):
    with requests._lock:
        state = getattr(requests, '_ecs_image_user_state', None)
        if state is None:
            state = requests._ecs_image_user_state = _State()
        return state


def enabled(requests):
    """Image reads follow the scan's existing ECR image content opt-in."""
    return (getattr(requests, 'content_secret_scans', False) is True
            and CONTENT_KIND in getattr(requests, 'content_secret_scan_kinds', ()))


def _reason(exc):
    code = getattr(exc, 'code', None)
    if isinstance(code, str) and re.fullmatch(r'[a-z_]{1,64}', code):
        return code
    text = str(exc)
    return text if re.fullmatch(r'[a-z_]{1,64}', text) else 'image_config_unavailable'


def _once(requests, state, table, key, compute, *, limit=None):
    """Single-flight per scan: the first caller computes, others wait."""
    with state.lock:
        slot = table.get(key)
        owner = slot is None
        if owner:
            if limit is not None and len(table) >= limit:
                return {'status': 'not_collected', 'reason': 'image_user_scan_bound'}
            slot = table[key] = {'event': threading.Event()}
    if owner:
        try:
            slot['value'] = compute()
        except Exception as exc:
            if getattr(exc, 'code', None) in _CANCEL:
                slot['value'] = {'status': 'not_collected', 'reason': 'collection_cancelled'}
                raise
            slot['value'] = {'status': 'not_collected', 'reason': _reason(exc)}
        finally:
            slot['event'].set()
    else:
        while not slot['event'].wait(0.1):
            requests.check_deadline()
    return slot['value']


def parse_reference(image):
    """(registry, region, repository, digest) for a digest-pinned private ECR image."""
    from peaso.aws_image_selection_20261021 import REPO
    match = _IMAGE.fullmatch(image) if isinstance(image, str) else None
    if match is None or not REPO.fullmatch(match.group(3)):
        return None
    return match.groups()


def _account_entry(content, name):
    """First ``/etc/passwd`` entry for ``name`` (the libc/runc lookup order)."""
    for line in content.decode('utf-8', 'replace').splitlines():
        fields = line.split(':')
        if len(fields) >= 4 and fields[0] == name:
            uid = fields[2]
            if uid.isascii() and uid.isdecimal() and len(uid.lstrip('0')) <= 10:
                return int(uid)
            return None
    return None


def _layer_fact(requests, reader, repo, image_digest, desc):
    """What one layer says about /etc/passwd, read once per scan per digest."""
    state = _state(requests)

    def compute():
        with state.lock:
            if state.layer_bytes + desc['size'] > SCAN_LAYER_BUDGET:
                return {'status': 'not_collected', 'reason': 'image_layer_scan_budget'}
            state.layer_bytes += desc['size']
        with tempfile.TemporaryDirectory(prefix='peaso-ecs-user-') as directory:
            Path(directory).chmod(0o700)
            path = reader.blob(repo, desc, path=Path(directory) / 'layer', image_digest=image_digest)
            return _scan_layer(requests, path, desc)
    return _once(requests, state, state.layers, desc['digest'], compute)


def _scan_layer(requests, path, desc):
    from peaso import container_image_archive_20261020 as archive
    mode = 'r|gz' if desc['mediaType'].endswith('gzip') else 'r|'
    entry, content, members, expanded = None, None, 0, 0
    with tarfile.open(name=str(path), mode=mode) as layer:
        for member in layer:
            requests.check_deadline()
            members += 1
            expanded += max(member.size, 0)
            if members > archive.MAX_MEMBERS or expanded > archive.MAX_EXPANDED:
                raise ValueError('image_layer_bound')
            name = member.name
            while name.startswith(('./', '/')):
                name = name[2:] if name.startswith('./') else name[1:]
            if name in ('etc', 'etc/') and not member.isdir():
                entry, content = 'other', None
            elif name in ('.wh.etc', 'etc/.wh.passwd'):
                entry, content = 'removed', None
            elif name == 'etc/.wh..wh..opq' and entry is None:
                entry = 'opaque'
            elif name == 'etc/passwd':
                if member.isfile() and 0 <= member.size <= ACCOUNT_FILE_LIMIT:
                    source = layer.extractfile(member)
                    entry, content = 'file', source.read(member.size + 1)
                    if len(content) != member.size:
                        raise ValueError('image_layer_unreadable')
                else:
                    entry, content = 'other', None
    return {'status': 'collected', 'entry': entry, 'content': content}


def _resolve_name(requests, reader, repo, image_digest, document, name):
    """UID of ``name`` from the topmost layer holding /etc/passwd, or a reason."""
    from peaso import container_image_archive_20261020 as archive
    layers = document.get('layers')
    if type(layers) is not list or not 1 <= len(layers) <= archive.MAX_LAYERS:
        return {'reason': 'unsupported_image_manifest'}
    try:
        layers = [archive.descriptor(d, archive.LAYERS, archive.MAX_LAYER) for d in layers]
    except ValueError:
        return {'reason': 'unsupported_image_layer'}
    spent = 0
    for desc in reversed(layers):
        spent += desc['size']
        if spent > IMAGE_LAYER_BUDGET:
            return {'reason': 'image_layer_budget'}
        fact = _layer_fact(requests, reader, repo, image_digest, desc)
        if fact.get('status') != 'collected':
            return {'reason': fact.get('reason', 'image_layer_unavailable')}
        if fact['entry'] == 'file':
            uid = _account_entry(fact['content'], name)
            if uid is None:
                return {'reason': 'user_not_in_image_account_file', 'layer': desc['digest']}
            return {'uid': uid, 'layer': desc['digest']}
        if fact['entry'] is not None:
            return {'reason': 'image_account_file_unavailable', 'layer': desc['digest']}
    return {'reason': 'image_account_file_absent'}


def _user_name(user):
    """The name part of a non-numeric, non-root ``user[:group]``, else None."""
    identity = user.partition(':')[0]
    if not identity or identity == 'root' or (identity.isascii() and identity.isdecimal()):
        return None
    return identity


def _platform_user(requests, reader, repo, digest, document):
    from peaso import container_image_archive_20261020 as archive
    state = _state(requests)
    conf = archive.descriptor(document.get('config'), archive.CONFIGS, archive.MAX_CONFIG)

    def config():
        raw = reader.blob(repo, conf, image_digest=digest)
        value = archive.decode(raw)
        settings = value.get('config') if type(value) is dict else None
        if settings is None:
            settings = {}
        user = settings.get('User', '') if type(settings) is dict else None
        if user is None:
            user = ''
        if type(user) is not str or len(user) > 256:
            return {'status': 'not_collected', 'reason': 'image_config_user_malformed'}
        return {'status': 'collected', 'user': user,
                'os': value.get('os') if type(value.get('os')) is str else None}
    found = _once(requests, state, state.configs, conf['digest'], config)
    if found.get('status') != 'collected':
        return {**found, 'config_digest': conf['digest']}
    row = {'status': 'collected', 'user': found['user'], 'manifest_digest': digest,
           'config_digest': conf['digest']}
    name = _user_name(found['user'])
    if name is not None:
        resolved = _resolve_name(requests, reader, repo, digest, document, name)
        if 'uid' in resolved:
            row.update(uid=resolved['uid'], uid_source='image /etc/passwd', uid_layer=resolved['layer'])
        else:
            row['uid_unresolved'] = resolved['reason']
    return row


def _read_image(requests, session, registry, region, repo, digest, architecture):
    from peaso import oci_index_20261021 as oci_index
    from .aws_image_vulnerability_native_20261021 import Reader
    reader = Reader(requests, session, registry, region)
    try:
        raw, document = reader.manifest(repo, digest, allow_index=True)
        if document['mediaType'] in oci_index.INDEX_TYPES:
            entries = document.get('manifests')
            if type(entries) is not list or not 1 <= len(entries) <= oci_index.MAX_CHILDREN:
                return {'status': 'not_collected', 'reason': 'unsupported_image_index'}
            platforms = []
            for entry in entries:
                platform = entry.get('platform') if type(entry) is dict else None
                # Attestation and other non-Linux entries never run on ECS Linux.
                if type(platform) is not dict or platform.get('os') != 'linux':
                    continue
                if architecture is not None and platform.get('architecture') != architecture:
                    continue
                if (entry.get('mediaType') not in oci_index.LEAF_TYPES or type(entry.get('size')) is not int
                        or type(entry.get('digest')) is not str or len(platforms) >= MAX_PLATFORMS):
                    return {'status': 'not_collected', 'reason': 'unsupported_image_index'}
                child_raw, child = reader.manifest(repo, entry['digest'])
                if len(child_raw) != entry['size']:
                    return {'status': 'not_collected', 'reason': 'image_index_binding_mismatch'}
                row = _platform_user(requests, reader, repo, entry['digest'], child)
                row['platform'] = platform.get('architecture')
                platforms.append(row)
            if not platforms:
                return {'status': 'not_collected', 'reason': 'image_platform_not_found'}
        else:
            platforms = [_platform_user(requests, reader, repo, digest, document)]
    finally:
        reader.close()
    failed = [row for row in platforms if row.get('status') != 'collected']
    if failed:
        return {'status': 'not_collected', 'reason': failed[0].get('reason', 'image_config_unavailable')}
    users = {(row['user'], row.get('uid'), row.get('uid_unresolved')) for row in platforms}
    if len(users) != 1:
        return {'status': 'not_collected', 'reason': 'image_platform_users_differ',
                'platform_users': {row.get('platform'): row['user'] for row in platforms}}
    result = dict(platforms[0])
    result.pop('platform', None)
    if len(platforms) > 1:
        result['manifest_digests'] = [row['manifest_digest'] for row in platforms]
        result['config_digests'] = [row['config_digest'] for row in platforms]
        result.pop('manifest_digest', None)
        result.pop('config_digest', None)
    return result


def _architecture(definition):
    platform = definition.get('runtimePlatform')
    value = platform.get('cpuArchitecture') if isinstance(platform, dict) else None
    return _ARCHITECTURES.get(value)


def _image_user(requests, session, region, image, architecture):
    parsed = parse_reference(image)
    if parsed is None:
        reason = ('mutable_image_reference' if isinstance(image, str) and '@sha256:' not in image
                  else 'image_not_private_ecr_digest')
        return {'status': 'not_collected', 'reason': reason, 'image': image}
    registry, image_region, repo, digest = parsed
    from peaso.aws_image_selection_20261021 import partition
    try:
        if partition(image_region) != partition(region):
            return {'status': 'not_collected', 'reason': 'image_partition_mismatch', 'image': image}
    except ValueError:
        return {'status': 'not_collected', 'reason': 'image_partition_unsupported', 'image': image}
    from .aws_image_capture_20261022 import _authority
    state = _state(requests)
    key = (id(_authority(session)), registry, image_region, repo, digest, architecture)
    found = _once(requests, state, state.images, key,
                  lambda: _read_image(requests, session, registry, image_region, repo, digest, architecture),
                  limit=MAX_IMAGES)
    return {**deepcopy(found), 'image': image, 'image_digest': digest}


def _targets(item):
    """(container name, image) for each container that declares no user."""
    detail = item.get('Definition') if isinstance(item, dict) else None
    definition = detail.get('taskDefinition') if isinstance(detail, dict) else None
    rows = definition.get('containerDefinitions') if isinstance(definition, dict) else None
    if not isinstance(rows, list):
        return definition, []
    return definition, [(row['name'], row.get('image')) for row in rows
                        if isinstance(row, dict) and isinstance(row.get('name'), str)
                        and row.get('user') in (None, '')]


def _latest_first(items):
    """Families' latest revisions first, so the scan bound keeps what runs next."""
    latest = {}
    for position, item in enumerate(items):
        arn = item.get('taskDefinitionArn') if isinstance(item, dict) else None
        family, _, revision = (arn or '').rpartition(':')
        if revision.isdecimal():
            latest[family] = max(latest.get(family, (0, position)), (int(revision), position))
    first = {position for _, position in latest.values()}
    return sorted(range(len(items)), key=lambda position: position not in first)


def enrich(requests, session, region, items):
    if not enabled(requests) or not isinstance(items, list):
        return items
    output = list(items)

    def one(position):
        item = items[position]
        definition, targets = _targets(item)
        if not targets:
            return
        architecture = _architecture(definition)
        containers = {}
        for name, image in targets:
            containers[name] = _image_user(requests, session, region, image, architecture)
        enriched = deepcopy(item)
        enriched[FIELD] = {'collection_status': 'collected', 'containers': containers}
        output[position] = enriched

    order = _latest_first(items)
    workers = max(1, min(4, getattr(requests, 'workers', 1)))
    if workers == 1 or len(order) < 2:
        for position in order:
            one(position)
    else:
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix='aws-ecs-image-user') as pool:
            list(pool.map(one, order))
    return output


ENRICHERS = {KIND: enrich}
