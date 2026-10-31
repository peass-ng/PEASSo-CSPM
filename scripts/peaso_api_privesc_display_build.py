"""Build API-only privilege display rows from the engine catalogs.

This script runs in the engine build environment; its output file is the only
privilege history data needed by the API package.
"""
import ast
import gzip
import hashlib
import inspect
import json
from pathlib import Path
import struct
import sys
import zlib

from peaso import engine
from peaso.privesc import versioned_catalog as catalog

ROOT = Path(__file__).resolve().parents[1]
PACK = ROOT / 'peaso/rulepacks'


def deterministic_gzip(data):
    """Platform-independent gzip member, matching peaso_compliance_materialize.

    gzip.compress(mtime=0) lets zlib stamp its build's OS byte (macOS 19, Unix 3),
    so identical content produced different bytes on macOS and Linux. The header is fixed (no name, mtime 0, XFL 2, OS 255).
    """
    compressor = zlib.compressobj(9, zlib.DEFLATED, -zlib.MAX_WBITS, 8, zlib.Z_DEFAULT_STRATEGY)
    body = compressor.compress(data) + compressor.flush()
    return (b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\xff" + body
            + struct.pack("<II", zlib.crc32(data), len(data) & 0xFFFFFFFF))


def encoded(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def binding_cases():
    """Extract all exact binding branches from the engine's own dispatcher."""
    tree = ast.parse(inspect.getsource(catalog.lookup_entries))
    cases = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.If):
            continue
        assignments = [part for part in node.body if isinstance(part, ast.Assign)]
        version_status = next((part for part in assignments if len(part.targets) == 1
                               and isinstance(part.targets[0], ast.Tuple)
                               and [n.id for n in part.targets[0].elts] == ['version', 'status']), None)
        if version_status is None:
            continue
        version, status = ast.literal_eval(version_status.value)
        if version == 'legacy' and status == 'legacy_unversioned_fallback':
            continue
        values = {}
        for part in ast.walk(node.test):
            if (isinstance(part, ast.Compare) and len(part.ops) == 1 and isinstance(part.ops[0], ast.Eq)
                    and isinstance(part.left, ast.Call) and isinstance(part.left.func, ast.Attribute)
                    and isinstance(part.left.func.value, ast.Name) and part.left.func.value.id == 'binding'
                    and part.left.func.attr == 'get' and len(part.left.args) == 1
                    and isinstance(part.left.args[0], ast.Constant)
                    and isinstance(part.comparators[0], ast.Name)):
                values[part.left.args[0].value] = getattr(catalog, part.comparators[0].id)
        if set(values) not in ({'manifest_sha256', 'effective_tree_sha256', 'source_revision'},
                               {'manifest_sha256', 'source_revision'}):
            raise ValueError(f'unrecognized binding branch: {version}')
        cases.append((version, status, values))
    # A source repin can make a historical branch identical to current again.
    # lookup_entries chooses the first branch, so keep the same reachable binding.
    seen = set()
    reachable = []
    for version, status, values in cases:
        identity = (values['manifest_sha256'], values.get('effective_tree_sha256'),
                    values['source_revision'])
        if identity in seen:
            if (version, status) != ('cloud_source_685_previous', 'exact_previous_current') or identity != (
                catalog.CURRENT_MANIFEST, catalog.CURRENT_TREE, catalog.V4_REVISION
            ):
                raise ValueError(f'duplicate versioned binding: {version}')
            continue
        seen.add(identity)
        reachable.append((version, status, values))
    if len(reachable) < 100:
        raise ValueError('versioned binding branches changed')
    return reachable


def archived_loaders():
    tree = ast.parse(inspect.getsource(catalog.lookup_entries))
    loaders = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.If) or not isinstance(node.test, ast.Compare):
            continue
        test = node.test
        if (not isinstance(test.left, ast.Name) or test.left.id != 'version'
                or len(test.comparators) != 1 or not isinstance(test.comparators[0], ast.Constant)):
            continue
        version = test.comparators[0].value
        for part in node.body:
            if isinstance(part, ast.Assign) and isinstance(part.value, ast.Call) and isinstance(part.value.func, ast.Name):
                name = part.value.func.id
                if name.startswith('_verified_') and not part.value.args:
                    loaders[version] = getattr(catalog, name)
                    break
    return loaders


def _existing():
    """Read the current display artifact for incremental rebuilds."""
    previous = json.loads(gzip.decompress((PACK / 'api_privesc_display.json.gz').read_bytes()))
    if previous['schema_version'] != 1 or len(previous['bindings']) < 100:
        raise ValueError('previous display schema mismatch')
    return previous


def _compact(document):
    """Use sorted unique detail rows and bounded integer references."""
    details = document['details']
    if isinstance(details, dict):
        keys = sorted(details)
        if len(keys) != len(details) or len(keys) > 10000:
            raise ValueError('display detail count')
        for digest, row in details.items():
            if not isinstance(row, dict) or hashlib.sha256(encoded(row)).hexdigest() != digest:
                raise ValueError('display detail identity mismatch')
        positions = {digest: index for index, digest in enumerate(keys)}
        document['details'] = [details[digest] for digest in keys]
        for binding in document['bindings']:
            binding[4] = {ident: positions[digest] for ident, digest in binding[4].items()}
    elif not isinstance(details, list):
        raise ValueError('display details shape')
    if len(document['details']) > 10000:
        raise ValueError('display detail count')
    if any(not isinstance(row, dict) or not isinstance(row.get('id'), str)
           for row in document['details']):
        raise ValueError('display detail row')
    identities = [hashlib.sha256(encoded(row)).hexdigest() for row in document['details']]
    if len(identities) != len(set(identities)):
        raise ValueError('duplicate display detail row')
    for binding in document['bindings']:
        if not isinstance(binding[4], dict) or len(binding[4]) > 5000:
            raise ValueError('display reference map shape')
        for ident, index in binding[4].items():
            if (not isinstance(ident, str) or type(index) is not int
                    or not 0 <= index < len(document['details'])
                    or document['details'][index].get('id') != ident):
                raise ValueError('display reference mismatch')
    return document


def _incremental_current_documents(current, cases, previous_manifest, previous_tree):
    """Reuse existing history when only the previous and new current bindings change."""
    previous = _compact(_existing())
    old_current = previous['current_binding']
    if (old_current['manifest_sha256'] != previous_manifest
            or old_current['effective_tree_sha256'] != previous_tree
            or old_current['source_revision'] != catalog.V4_REVISION):
        raise ValueError('previous display binding changed')
    identity = lambda row: (row[0], row[1], row[2], row[3])
    old = {identity(row): row for row in previous['bindings']}
    wanted = {(values['manifest_sha256'], values.get('effective_tree_sha256'),
               values['source_revision'], status) for _, status, values in cases}
    old_current_key = (previous_manifest,
                       previous_tree,
                       catalog.V4_REVISION, 'exact_strict_privesc')
    new_current_key = (catalog.CURRENT_MANIFEST, catalog.CURRENT_TREE,
                       catalog.V4_REVISION, 'exact_strict_privesc')
    archive_key = (previous_manifest,
                   previous_tree,
                   catalog.V4_REVISION, 'exact_previous_current')
    removed, added = set(old) - wanted, wanted - set(old)
    if (len(old) != len(previous['bindings']) or removed != {old_current_key}
            or added != {new_current_key, archive_key}):
        raise ValueError(f'display changed outside two reviewed bindings: {removed!r}, {added!r}')
    prior_details = previous['details']
    details = {hashlib.sha256(encoded(row)).hexdigest(): row for row in prior_details}
    if len(details) != len(prior_details):
        raise ValueError('previous display detail identities changed')
    current_ids = {row['id'] for row in engine.get_catalog()['privesc_techniques']}
    prior, _ = catalog._verified_prior()
    legacy = catalog._verified_history(str(catalog.LEGACY_DELTA))
    common_ids = current_ids | set(prior) | set(legacy['legacy_ids']) | set(legacy['old_entries'])
    loaders = archived_loaders()
    bindings = []
    for version, status, values in cases:
        key = (values['manifest_sha256'], values.get('effective_tree_sha256'),
               values['source_revision'], status)
        if key in old:
            references = {ident: hashlib.sha256(encoded(prior_details[index])).hexdigest()
                          for ident, index in old[key][4].items()}
        else:
            ids = set(common_ids)
            loader = loaders.get(version)
            if loader is not None:
                ids.update(loader())
            bound = dict(schema=catalog.BINDING_SCHEMA, tenant_id='display-build', **values)
            rows = engine.privesc_technique_details(sorted(ids), catalog_binding=bound,
                                                    tenant_id='display-build')
            references = {}
            for ident, row in rows.items():
                if row.get('unknown'):
                    continue
                if row['catalog_lookup_status'] != status:
                    raise ValueError(f'lookup status drift: {version}')
                payload = dict(row)
                payload.pop('catalog_lookup_status')
                digest = hashlib.sha256(encoded(payload)).hexdigest()
                details.setdefault(digest, payload)
                references[ident] = digest
            if loader is not None and hasattr(loader, 'cache_clear'):
                loader.cache_clear()
            print(version, len(references), len(details), flush=True)
        if not references:
            raise ValueError(f'empty verified catalog: {version}')
        bindings.append([*key, references])
    document = {'schema_version': 1, 'current_binding': current, 'legacy_manifest': catalog.LEGACY_MANIFEST,
                'legacy_revision': catalog.LEGACY_REVISION, 'bindings': bindings, 'details': details}
    return _documents(_compact(document))


def render_documents():
    current = catalog.current_binding()
    cases = binding_cases()
    if sys.argv[1:] == ['--incremental-apim-anchor-685']:
        return _incremental_current_documents(current, cases,
                                              catalog.APIM_ANCHOR_685_PREVIOUS_MANIFEST,
                                              catalog.APIM_ANCHOR_685_PREVIOUS_TREE)
    if sys.argv[1:] == ['--incremental-appstream']:
        return _incremental_current_documents(current, cases,
                                              catalog.APPSTREAM_RESOURCE_700_PREVIOUS_MANIFEST,
                                              catalog.APPSTREAM_RESOURCE_700_PREVIOUS_TREE)
    if sys.argv[1:] == ['--incremental-reviewed-685']:
        return _incremental_current_documents(current, cases,
                                              catalog.REVIEWED_685_PREVIOUS_MANIFEST,
                                              catalog.REVIEWED_685_PREVIOUS_TREE)
    if sys.argv[1:] == ['--incremental-beanstalk-685']:
        return _incremental_current_documents(current, cases,
                                              catalog.BEANSTALK_685_PREVIOUS_MANIFEST,
                                              catalog.BEANSTALK_685_PREVIOUS_TREE)
    if sys.argv[1:] == ['--incremental-cloud-source-685']:
        return _incremental_current_documents(current, cases,
                                              catalog.CLOUD_SOURCE_685_PREVIOUS_MANIFEST,
                                              catalog.CLOUD_SOURCE_685_PREVIOUS_TREE)
    if sys.argv[1:] == ['--incremental-ecs-register-685']:
        return _incremental_current_documents(current, cases,
                                              catalog.ECS_REGISTER_685_PREVIOUS_MANIFEST,
                                              catalog.ECS_REGISTER_685_PREVIOUS_TREE)
    if sys.argv[1:]:
        raise ValueError('unsupported privilege display build mode')
    loaders = archived_loaders()
    current_ids = {row['id'] for row in engine.get_catalog()['privesc_techniques']}
    prior, _ = catalog._verified_prior()
    legacy = catalog._verified_history(str(catalog.LEGACY_DELTA))
    common_ids = current_ids | set(prior) | set(legacy['legacy_ids']) | set(legacy['old_entries'])
    details, bindings = {}, []
    for version, status, identity in cases:
        ids = set(common_ids)
        loader = loaders.get(version)
        if loader is not None:
            ids.update(loader())
        bound = dict(schema=catalog.BINDING_SCHEMA, tenant_id='display-build', **identity)
        rows = engine.privesc_technique_details(sorted(ids), catalog_binding=bound,
                                                tenant_id='display-build')
        references = {}
        for ident, row in rows.items():
            if row.get('unknown'):
                continue
            if row['catalog_lookup_status'] != status:
                raise ValueError(f'lookup status drift: {version}')
            payload = dict(row)
            payload.pop('catalog_lookup_status')
            raw = encoded(payload)
            digest = hashlib.sha256(raw).hexdigest()
            details.setdefault(digest, payload)
            references[ident] = digest
        if not references:
            raise ValueError(f'empty verified catalog: {version}')
        bindings.append([identity['manifest_sha256'], identity.get('effective_tree_sha256'),
                         identity['source_revision'], status, references])
        if loader is not None and hasattr(loader, 'cache_clear'):
            loader.cache_clear()
        print(version, len(references), len(details), flush=True)
    if (current['manifest_sha256'], current['effective_tree_sha256'], current['source_revision']) not in {
            (row[0], row[1], row[2]) for row in bindings}:
        raise ValueError('current binding absent from display index')
    document = {'schema_version': 1, 'current_binding': current, 'legacy_manifest': catalog.LEGACY_MANIFEST,
                'legacy_revision': catalog.LEGACY_REVISION, 'bindings': bindings, 'details': details}
    return _documents(_compact(document))


def _documents(document):
    raw = encoded(document)
    compressed = deterministic_gzip(raw)
    if gzip.decompress(compressed) != raw:
        raise ValueError('display gzip round trip differs')
    return {PACK / 'api_privesc_display.json.gz': compressed}


if __name__ == '__main__':
    for path, body in render_documents().items():
        path.write_bytes(body)
        print(path, len(body), flush=True)
