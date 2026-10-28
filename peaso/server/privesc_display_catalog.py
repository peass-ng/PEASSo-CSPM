"""Bounded, build-verified privilege display metadata for stored API reports."""
from copy import deepcopy
from functools import lru_cache
import gzip
import hashlib
import io
import json
from pathlib import Path
import zlib

PACK = Path(__file__).resolve().parents[1] / 'rulepacks'
MAX_GZIP_BYTES = 4 * 1024 * 1024
MAX_JSON_BYTES = 32 * 1024 * 1024
BINDING_SCHEMA = 'privesc-catalog-binding-v1'
FROZEN_SOURCES = frozenset({'peaso/privesc/schema.py', 'peaso/privesc/versioned_catalog.py',
                            'risk_rules/hacktricks-privesc-source.json'})
# Rewritten by the offline display builder after it verifies engine catalogs.
PINNED_GZIP_SHA256 = 'd56fa76032c6a8e93405424c36cd110025037b1950c7c2d4bbd020a275ef2064'


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError('duplicate display key')
        result[key] = value
    return result


def _json(raw):
    return json.loads(raw, object_pairs_hook=_pairs)


@lru_cache(maxsize=1)
def _load():
    try:
        manifest_raw = (PACK / 'api_privesc_display_manifest.json').read_bytes()
        if len(manifest_raw) > 4096:
            raise ValueError('display manifest budget')
        manifest = _json(manifest_raw)
        if manifest['schema_version'] != 1 or not 0 < manifest['json_bytes'] <= MAX_JSON_BYTES:
            raise ValueError('display manifest schema')
        raw = (PACK / 'api_privesc_display.json.gz').read_bytes()
        if (not 0 < len(raw) <= MAX_GZIP_BYTES or hashlib.sha256(raw).hexdigest() != manifest['gzip_sha256']
                or manifest['gzip_sha256'] != PINNED_GZIP_SHA256):
            raise ValueError('display gzip identity')
        with gzip.GzipFile(fileobj=io.BytesIO(raw)) as stream:
            document = stream.read(MAX_JSON_BYTES + 1)
        if (len(document) != manifest['json_bytes'] or
                hashlib.sha256(document).hexdigest() != manifest['json_sha256']):
            raise ValueError('display document identity')
        data = _json(document)
        if (data['schema_version'] != 1 or data['catalog_document_sha256'] != manifest['catalog_document_sha256']
                or not isinstance(data['details'], list) or not isinstance(data['bindings'], list)
                or len(data['bindings']) > 256 or len(data['details']) > 10000):
            raise ValueError('display document schema')
        detail_digests = []
        for detail in data['details']:
            if not isinstance(detail, dict) or not isinstance(detail.get('id'), str):
                raise ValueError('display detail row')
            detail_digests.append(hashlib.sha256(json.dumps(detail, ensure_ascii=False, sort_keys=True,
                                                             separators=(',', ':'), allow_nan=False).encode()).hexdigest())
        if len(detail_digests) != len(set(detail_digests)):
            raise ValueError('duplicate display detail row')
        identities = data['catalog_source_identities']
        if (not isinstance(identities, dict) or set(identities) != FROZEN_SOURCES
                or any(not isinstance(digest, str) or len(digest) != 64 for digest in identities.values())):
            raise ValueError('display frozen source identities')
        by_binding = {}
        for row in data['bindings']:
            if (not isinstance(row, list) or len(row) != 5 or
                    not isinstance(row[4], dict) or len(row[4]) > 5000):
                raise ValueError('display binding schema')
            manifest_id, tree, revision, status, entries = row
            if (not isinstance(manifest_id, str) or not isinstance(revision, str)
                    or tree is not None and not isinstance(tree, str) or not isinstance(status, str)):
                raise ValueError('display binding identity')
            key = (manifest_id, tree, revision)
            if key in by_binding:
                raise ValueError('duplicate display binding')
            if any(not isinstance(ident, str) or type(index) is not int
                   or not 0 <= index < len(data['details']) or data['details'][index]['id'] != ident
                   for ident, index in entries.items()):
                raise ValueError('display detail reference')
            by_binding[key] = (status, entries)
        current = data['current_binding']
        if (not isinstance(current, dict) or current.get('schema') != BINDING_SCHEMA or
                (current.get('manifest_sha256'), current.get('effective_tree_sha256'),
                 current.get('source_revision')) not in by_binding):
            raise ValueError('display current binding')
        data['_by_binding'] = by_binding
        return data
    except (OSError, ValueError, TypeError, KeyError, AttributeError, EOFError, zlib.error):
        raise ValueError('API privilege display index unavailable') from None


def current_binding(catalog_manifest):
    data = _load()
    if data['catalog_document_sha256'] != catalog_manifest['document_sha256']:
        raise ValueError('display catalog generation mismatch')
    if any(data['catalog_source_identities'][name] != catalog_manifest['sources'][name]
           for name in FROZEN_SOURCES):
        raise ValueError('display frozen source generation mismatch')
    if data['current_binding']['manifest_sha256'] != catalog_manifest['sources']['risk_rules/hacktricks-privesc-source.json']:
        raise ValueError('display source generation mismatch')
    return deepcopy(data['current_binding'])


def lookup_details(technique_ids, binding=None, *, tenant_id=None):
    """Return display rows with the engine's exact binding and unknown statuses."""
    ids = tuple(dict.fromkeys(technique_ids))
    if binding is None:
        key = None
        override = 'legacy_unversioned_fallback'
    elif not isinstance(binding, dict) or binding.get('schema') != BINDING_SCHEMA:
        return {}, 'invalid_catalog_binding'
    elif tenant_id is not None and binding.get('tenant_id') != tenant_id:
        return {}, 'tenant_binding_mismatch'
    else:
        key = (binding.get('manifest_sha256'), binding.get('effective_tree_sha256'),
               binding.get('source_revision'))
        override = None
    try:
        data = _load()
    except ValueError:
        return {}, 'catalog_unavailable'
    if key is None:
        key = (data['legacy_manifest'], None, data['legacy_revision'])
    elif key[0] == data['legacy_manifest']:
        key = (key[0], None, key[2])
    if (not isinstance(key[0], str) or not isinstance(key[2], str)
            or key[1] is not None and not isinstance(key[1], str)):
        return {}, 'unknown_catalog_manifest'
    match = data['_by_binding'].get(key)
    if match is None:
        return {}, 'unknown_catalog_manifest'
    status, entries = match
    status = override or status
    details = {ident: dict(deepcopy(data['details'][entries[ident]]), catalog_lookup_status=status)
               for ident in ids if ident in entries}
    return details, status


def card_technique_ids(card, principal_id):
    """Select IDs only from edges bound to the requested card principal."""
    ids = set()
    aggregates = set(card.get('member_of_aggregates') or [])
    for edge in card.get('outgoing') or []:
        if edge.get('source') == principal_id:
            ids.update(edge.get('techniques') or [])
    for edge in card.get('incoming') or []:
        target = edge.get('target')
        if target == principal_id or (target in aggregates and edge.get('via_aggregate') == target):
            ids.update(edge.get('techniques') or [])
    return sorted(ident for ident in ids if isinstance(ident, str))
