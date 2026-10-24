"""Practical selected GCP image secret inspection using verified streamed layers.

This proposal is not installed into the collector registry yet. It preserves
default-off selection and native project/repository binding via the existing
enricher, while replacing only image download and layer parsing.
"""
from copy import deepcopy
from pathlib import Path
import tempfile
import time

from . import gcp_image_secret_indicators as native
from .gcp_image_stream_reader_20261021 import Reader, MAX_IMAGE, MAX_LAYER
from peaso.container_image_archive_20261020 import visit_files, MAX_LAYERS, MAX_EXPANDED, MAX_MEMBERS
from peaso import oci_index_20261021 as oci_index
from peaso.secret_scanning_batch import prepared_content_batch, MAX_BATCH_ITEMS, MAX_BATCH_BYTES

WINDOW = 1024 * 1024
OVERLAP = 4096
MAX_FILE = 64 * 1024 * 1024
MAX_SCANNED = 512 * 1024 * 1024


def _interrupt(exc):
    """Keep typed collection cancellation and deadlines visible to the owner."""
    if isinstance(exc, TimeoutError):
        return True
    code = getattr(exc, 'code', None)
    error = getattr(exc, 'error', None)
    if type(error) is dict:
        code = error.get('code', code)
    return code in {'collection_cancelled', 'cancelled', 'intentional_scan_deadline',
                    'deadline_exceeded', 'execution_deadline'} or str(exc) in {
                    'collection_cancelled', 'intentional_scan_deadline', 'deadline_exceeded',
                    'explicit collection deadline exceeded'}


def source_reports(leaks):
    reports = {}
    for leak in leaks:
        for loc in leak['locations']:
            reports[(loc['layer'], loc['path'], leak['fingerprint'])] = {'layer': loc['layer'], 'path': loc['path'],
                'fingerprint': leak['fingerprint'], 'engines': [
                    {'engine': engine, 'status': 'complete'}
                    for engine in sorted({item['engine'] for item in leak['detectors']})]}
    return [reports[key] for key in sorted(reports)]


def decoded_config_strings(decoded, check, max_bytes):
    """Bounded decoded JSON strings, including OCI Env/Cmd/Labels/history."""
    strings, stack, nodes, size = [], [decoded], 0, 0
    while stack:
        check()
        value = stack.pop()
        nodes += 1
        if nodes > 20000:
            raise ValueError('decoded config node bound')
        if type(value) is str:
            raw = value.encode('utf-8')
            size += len(raw) + 1
            if size > max_bytes:
                raise ValueError('decoded config byte bound')
            strings.append(raw)
        elif type(value) is dict:
            stack.extend(reversed(list(value.keys())))
            stack.extend(reversed(list(value.values())))
        elif type(value) is list:
            stack.extend(reversed(value))
    return b'\n'.join(strings)


def _inspect_leaf(uri, repo, digest, raw, scope, reader, source_resource_id,
                  *, platform=None, match_callback=None):
    leaks, engines = [], None
    image_fields, inspected, scanned = None, [], []
    partial_bytes = 0
    files, complete = 0, True
    try:
        manifest = native._json(raw)
        if (type(manifest) is not dict or set(manifest) - {'schemaVersion', 'mediaType', 'config', 'layers', 'annotations'}
                or type(manifest.get('schemaVersion')) is not int or manifest['schemaVersion'] != 2
                or manifest.get('mediaType') not in (native.OCI, native.DOCKER)):
            raise ValueError('single-platform manifest required')
        config = native._descriptor(manifest['config'], native.CONFIG_TYPES, native.MAX_CONFIG)
        layers = manifest.get('layers')
        if type(layers) is not list or not 1 <= len(layers) <= MAX_LAYERS:
            raise ValueError('bounded image layers required')
        layers = [native._descriptor(layer, native.TAR_TYPES, MAX_LAYER) for layer in layers]
        if sum(item['size'] for item in [config] + layers) > MAX_IMAGE:
            raise ValueError('compressed image bound')
        config_raw = reader.get(uri, 'blobs', config['digest'], native.MAX_CONFIG, config['size'])
        decoded = native._json(config_raw)
        if (type(decoded) is not dict or decoded.get('os') != 'linux'
                or decoded.get('architecture') not in ('amd64', 'arm64')
                or platform is not None and (decoded.get('os') != platform['os']
                    or decoded.get('architecture') != platform['architecture']
                    or 'variant' in platform and decoded.get('variant') != platform['variant'])
                or type(decoded.get('rootfs')) is not dict or decoded['rootfs'].get('type') != 'layers'
                or type(decoded['rootfs'].get('diff_ids')) is not list
                or len(decoded['rootfs']['diff_ids']) != len(layers)
                or any(type(value) is not str or not native.DIGEST.fullmatch(value)
                       for value in decoded['rootfs']['diff_ids'])):
            raise ValueError('supported platform and rootfs required')

        def scan(payload, path, layer, line_offset=0, document=None):
            nonlocal engines, complete
            native.Deadline(reader).check_deadline()
            try:
                outcome = native.scan_with_source(native.scan_content, payload, path,
                    source={'resource_id': source_resource_id, 'scope': scope, 'image_digest': digest,
                            'source': uri, 'layer': layer,
                            'location_kind': 'configuration' if document is not None else 'file'},
                    native=document, timeout=15, _redact_values=match_callback)
            except Exception as exc:
                if _interrupt(exc):
                    raise
                complete = False
                return
            if (type(outcome) is not dict or type(outcome.get('engines')) is not list
                    or type(outcome.get('leaks')) is not list):
                complete = False
                return
            if engines is None or (type(outcome.get('engines')) is list and
                    all(e.get('status') == 'complete' for e in outcome['engines'])):
                engines = outcome['engines']
            for leak in outcome['leaks']:
                locations = []
                for location in leak['locations']:
                    projected = dict(location, layer=layer)
                    if type(projected.get('line')) is int:
                        projected['line'] += line_offset
                    locations.append(projected)
                leaks.append(dict(leak, locations=locations))
            if len(leaks) > native.MAX_LEAKS or sum(len(item['locations']) for item in leaks) > native.MAX_LOCATIONS:
                raise ValueError('indicator bound')
            if outcome['complete'] is not True:
                complete = False

        image_fields = {'uri': uri, 'repository': repo, 'manifest_digest': digest,
                        'descriptors': deepcopy([config] + layers)}
        partial_bytes = len(config_raw)
        inspected.append(config['digest'])
        scan(config_raw, 'image-config.json', config['digest'], document=decoded)
        # OCI config strings may be JSON-escaped. Scan their decoded values as
        # well as the exact verified bytes so an escaped credential cannot
        # turn a clean image into a false PASS.
        config_strings = decoded_config_strings(decoded, reader.check, native.MAX_CONFIG * 2)
        if config_strings:
            scan(config_strings, 'image-config-decoded.txt', config['digest'], document=decoded)
        files, scanned_bytes = 0, 0
        pending, pending_bytes = [], 0

        def flush():
            nonlocal pending, pending_bytes
            if not pending:
                return
            native.Deadline(reader).check_deadline()
            timeout = min(60, reader.end - time.monotonic() - 31)
            if timeout <= 0:
                raise TimeoutError('insufficient remaining dual-detector time')
            items = [(payload, path) for payload, path, _, _ in pending]
            # The helper uses volatile local storage only on supported Linux
            # hosts and falls back to the original serial detector on error.
            with prepared_content_batch(items, timeout=timeout):
                for payload, path, layer, line_offset in pending:
                    reader.check()
                    scan(payload, path, layer, line_offset)
            pending, pending_bytes = [], 0

        def queue(payload, path, layer, line_offset=0):
            nonlocal pending_bytes
            reader.check()
            if pending and (len(pending) == MAX_BATCH_ITEMS
                            or pending_bytes + len(payload) > MAX_BATCH_BYTES):
                flush()
            pending.append((payload, path, layer, line_offset))
            pending_bytes += len(payload)

        def observe(name, stream, size, layer_index):
            nonlocal files, scanned_bytes, complete, inspected, scanned, partial_bytes
            files += 1
            path = 'member-' + str(files)
            layer = layers[layer_index]['digest']
            scanned = [value['digest'] for value in layers[:layer_index]]
            inspected = [config['digest']] + scanned + [layer]
            partial_bytes += size
            # Scan names as content, never retain provider-controlled filenames
            # in detector caches or public locations.
            with native.source_context(resource_id=source_resource_id, scope=scope,
                                       image_digest=digest, source=uri,
                                       layer=layer):
                native.alias_path(path, name)
                queue(name.encode('utf-8'), path + '-name', layer)
            if size > MAX_FILE or scanned_bytes + size > MAX_SCANNED:
                complete = False
                return
            overlap, consumed, prior_lines = b'', 0, 0
            while consumed < size:
                reader.check()
                chunk = stream.read(min(WINDOW, size - consumed))
                if type(chunk) is not bytes or not chunk:
                    raise ValueError('truncated verified image file')
                if consumed == 0 and (chunk.startswith((b'PK\x03\x04', b'\x1f\x8b', b'BZh', b'\xfd7zXZ',
                        b'7z\xbc\xaf', b'Rar!', b'\x28\xb5\x2f\xfd')) or chunk[257:262] == b'ustar'):
                    # Scanning the compressed bytes cannot establish absence in
                    # an unexpanded nested archive. Keep any prior positive,
                    # but never label this image complete and clean.
                    complete = False
                    return
                consumed += len(chunk)
                scanned_bytes += len(chunk)
                queue(overlap + chunk, path, layer, prior_lines - overlap.count(b'\n'))
                prior_lines += chunk.count(b'\n')
                overlap = (overlap + chunk)[-OVERLAP:]
            if size == 0:
                queue(b'', path, layer)

        image_identity = {'provider': 'gcp', 'scope': scope,
            'immutable_reference': uri.removeprefix('https://').rsplit('@', 1)[0] + '@' + digest,
            'manifest_digest': digest, 'config_digest': config['digest']}
        with tempfile.TemporaryDirectory(prefix='peaso-gcp-image-') as directory:
            root, paths = Path(directory), []
            for index, descriptor in enumerate(layers):
                reader.check()
                path = root / ('blob-' + str(index))
                reader.get_layer(uri, descriptor, path)
                paths.append(path)
            try:
                result = visit_files(image_identity, raw, config_raw, paths, lambda *args: None,
                                     check=reader.check, partial_callback=observe)
            except Exception as exc:
                if _interrupt(exc):
                    raise
                flush()
                raise
            flush()
        reader.check()
        if result.get('links_skipped', 0):
            complete = False
        leaks = native.merge_leaks(leaks)
        return {'schema': native.SCHEMA, 'status': 'collected' if complete else 'partial',
            'complete': complete, 'uri': uri, 'repository': repo, 'manifest_digest': digest,
            'descriptors': deepcopy([config] + layers),
            'layers_scanned': [layer['digest'] for layer in layers],
            'expanded_bytes': result['expanded_bytes'], 'members': result['members'],
            'regular_files': files, 'engines': engines, 'leaks': leaks,
            'verification': 'not_attempted', **({} if complete else {
                'inspected_digests': [config['digest']] + [value['digest'] for value in layers],
                'source_reports': source_reports(leaks)})}
    except Exception as exc:
        if _interrupt(exc):
            raise
        # A later layer/engine failure cannot erase already observed leaks. Only
        # config/layers whose hashes/rootfs were verified may retain witnesses.
        if image_fields is not None and leaks:
            try:
                safe = native.merge_leaks(leaks)
                if (len(safe) <= native.MAX_LEAKS
                        and sum(len(item['locations']) for item in safe) <= native.MAX_LOCATIONS
                        and all(loc.get('layer') in inspected for leak in safe for loc in leak['locations'])):
                    return {'schema': native.SCHEMA, 'status': 'partial', 'complete': False,
                        **image_fields, 'layers_scanned': scanned, 'inspected_digests': inspected,
                        'expanded_bytes': partial_bytes, 'members': files, 'regular_files': files,
                        'engines': engines or [], 'leaks': safe, 'source_reports': source_reports(safe),
                        'verification': 'not_attempted'}
            except (TypeError, ValueError, KeyError, AttributeError):
                pass
        return {'schema': native.SCHEMA, 'status': 'unavailable', 'complete': False, 'leaks': []}


def inspect_image(row, scope, repositories, projects, reader, *, match_callback=None,
                  capture_resource_id=None):
    """Inspect every bounded leaf of one natively selected immutable digest."""
    try:
        uri, repo, parent_digest = native.bind_image(row, scope, repositories, projects)
        if capture_resource_id is not None and (type(capture_resource_id) is not str
                or not capture_resource_id or len(capture_resource_id) > 1024):
            raise ValueError('invalid selected image capture identity')
        source_resource_id = capture_resource_id or uri
        parent_raw = reader.get(uri, 'manifests', parent_digest, native.MAX_MANIFEST)
        parent = native._json(parent_raw)
        if type(parent) is not dict:
            raise ValueError('invalid parent image manifest')
        if parent.get('mediaType') in oci_index.LEAF_TYPES:
            return _inspect_leaf(uri, repo, parent_digest, parent_raw, scope, reader,
                source_resource_id, match_callback=match_callback)
        if parent.get('mediaType') not in oci_index.INDEX_TYPES:
            raise ValueError('unsupported parent image format')
        graph = {'parent_digest': parent_digest, 'media_type': parent['mediaType'],
                 'children': [], 'complete': False}
        children, leaks, expanded, members, files = [], [], 0, 0, 0
        try:
            def fetch(digest, size, _media_type):
                return reader.get(uri, 'manifests', digest, native.MAX_MANIFEST, size)
            for child in oci_index.children(parent_raw, parent_digest, fetch, check=reader.check):
                leaf = _inspect_leaf(uri, repo, child['digest'], child['raw'], scope, reader,
                    source_resource_id, platform=child['platform'], match_callback=match_callback)
                if leaf.get('status') == 'unavailable':
                    raise ValueError('child image unavailable')
                descriptor = {key: child[key] for key in ('digest', 'size', 'mediaType', 'platform')}
                config = leaf.get('descriptors', [{}])[0]
                descriptor['config_digest'] = config.get('digest')
                next_leaks = leaks + leaf.get('leaks', [])
                if (expanded + leaf.get('expanded_bytes', 0) > MAX_EXPANDED
                        or members + leaf.get('members', 0) > MAX_MEMBERS
                        or files + leaf.get('regular_files', 0) > MAX_MEMBERS
                        or len(next_leaks) > native.MAX_LEAKS
                        or sum(len(item['locations']) for item in next_leaks) > native.MAX_LOCATIONS):
                    raise ValueError('index aggregate bound')
                graph['children'].append(descriptor)
                children.append(leaf)
                leaks = next_leaks
                expanded += leaf.get('expanded_bytes', 0)
                members += leaf.get('members', 0)
                files += leaf.get('regular_files', 0)
            graph['complete'] = True
        except Exception as exc:
            if _interrupt(exc):
                raise
            pass  # Earlier child positives remain bound; an incomplete index cannot pass.
        safe = native.merge_leaks(leaks)
        complete = graph['complete'] and len(children) == len(graph['children']) and all(
            child.get('complete') is True for child in children)
        if not safe and not complete:
            return {'schema': native.SCHEMA, 'status': 'unavailable', 'complete': False,
                'leaks': [], 'graph': graph, 'children': children}
        return {'schema': native.SCHEMA, 'status': 'collected' if complete else 'partial',
            'complete': complete, 'uri': uri, 'repository': repo,
            'manifest_digest': parent_digest, 'graph': graph, 'children': children,
            'expanded_bytes': expanded, 'members': members, 'regular_files': files,
            'engines': children[0].get('engines', []) if children else [], 'leaks': safe,
            'verification': 'not_attempted', **({} if complete else {
                'source_reports': source_reports(safe)})}
    except Exception as exc:
        if _interrupt(exc):
            raise
        return {'schema': native.SCHEMA, 'status': 'unavailable', 'complete': False, 'leaks': []}


def enrich(collector, *, reader_factory=None):
    """Preserve selected native routing and surface typed cancellation to the owner."""
    reader_factory = Reader if reader_factory is None else reader_factory
    options = collector.options
    kinds = options.get('_content_secret_scan_kinds', [])
    if (options.get('content_secret_scans') is not True or not isinstance(kinds, (list, tuple))
            or 'artifact_image' not in kinds):
        return
    from peaso.gcp_image_selection_20261021 import OPTION, grouped_selections
    selected_groups = (grouped_selections({**options, OPTION: options['selected_artifact_images']}, collector.scopes)
                       if 'selected_artifact_images' in options else {})
    for scope in collector.scopes:
        if not selected_groups.get(scope) and 'selected_cloudrun_services' not in options:
            continue
        images = collector.collections.get(('artifact_image', scope))
        if not isinstance(images, dict):
            continue
        selected_rows, reader = [], None
        try:
            repos = collector.collections.get(('artifact_repository', scope), {})
            projects = collector.collections.get(('project', scope), {})
            if any(c.get('status') != 'collected' or not isinstance(c.get('items'), list)
                   for c in (images, repos, projects)):
                raise ValueError('native parent inventories incomplete')
            run_proof, run_plan = None, None
            requested = list(selected_groups.get(scope, []))
            if 'selected_cloudrun_services' in options:
                from . import gcp_cloudrun_image_inspection as run_sources
                run_plan, run_proof = run_sources.prepare(collector, scope, images['items'],
                    repos['items'], projects['items'])
                requested = list(dict.fromkeys(requested + run_plan['selected_artifact_images']))
            selected = native.normalize_selected(requested, scope)
            for row in images['items']:
                if row.get('uri') in selected:
                    selected_rows.append(row)
                    native.bind_image(row, scope, repos['items'], projects['items'])
            if {row['uri'] for row in selected_rows} != set(selected) or len(selected_rows) != len(selected):
                raise ValueError('selected image missing or duplicated in native inventory')
            reader = reader_factory(collector.transport)
            for row in selected_rows:
                before = len(reader.request_ids)
                row[native.MARKER] = inspect_image(row, scope, repos['items'], projects['items'], reader)
                receipts = reader.request_ids[before:]
                provenance = row.setdefault('_provenance', {})
                provenance['source_requests'] = sorted(set(provenance.get('source_requests', [])) | set(receipts))
                provenance.setdefault('scope', scope)
                images['source_requests'] = sorted(set(images.get('source_requests', [])) | set(receipts))
                row.setdefault('_coverage', {})[native.MARKER] = {
                    'status': 'collected' if row[native.MARKER]['complete'] else
                        'partial' if row[native.MARKER]['status'] == 'partial' else 'unavailable',
                    'source_requests': receipts}
            if run_proof is not None:
                completed = run_sources.finish(collector, run_proof)
                refs = [r['source_request'] for r in completed['reads'] + completed['revalidation']]
                for row in selected_rows:
                    if row['uri'].removeprefix('https://') in run_plan['selected_artifact_images']:
                        row[run_sources.MARKER] = deepcopy(completed)
                        row['_provenance']['source_requests'] = sorted(set(row['_provenance']['source_requests']) | set(refs))
                images['source_requests'] = sorted(set(images.get('source_requests', [])) | set(refs))
        except Exception as exc:
            if _interrupt(exc):
                raise
            for row in selected_rows:
                row[native.MARKER] = {'schema': native.SCHEMA, 'status': 'unavailable',
                    'complete': False, 'leaks': []}
            images.update(status='partial', coverage_status='partial',
                          error={'code': 'selected_image_content_unavailable'})
        finally:
            if reader is not None:
                reader.close()
