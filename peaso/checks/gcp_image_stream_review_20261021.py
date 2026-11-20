"""Existing immutable-image predicate with practical verified archive capacities.

No verdict, evidence or binding logic changes. The collector validates compressed
digests/rootfs hashes against the same archive limits before emitting witnesses.
Installation into the registered catalog is a separate integration transaction.
"""
from types import FunctionType
from copy import deepcopy
from . import gcp_image_secret_review_20261019 as predecessor
from peaso import container_image_archive_20261020 as archive
from peaso import oci_index_20261021 as oci_index
from peaso.collectors import gcp_image_secret_indicators as native
from peaso.secret_scanning import merge_leaks
from peaso.secret_scanning import KINGFISHER_VERSION, TRUFFLEHOG_VERSION


def evaluate_index_content(content, uri, repo, digest, scope, *, receipts=None):
    """Validate a selected parent and all bounded child witnesses, without native reads."""
    unknown = ('UNKNOWN', {'observed':
        'The selected image index has missing or unverified child content.'})
    try:
        graph = content['graph']; children = content['children']
        if (type(graph) is not dict or set(graph) != {'parent_digest','media_type','children','complete'}
                or graph['parent_digest'] != digest or graph['media_type'] not in oci_index.INDEX_TYPES
                or type(graph['complete']) is not bool or type(graph['children']) is not list
                or not 1 <= len(graph['children']) <= oci_index.MAX_CHILDREN
                or type(children) is not list or len(children) > len(graph['children'])
                or content.get('schema') != native.SCHEMA or content.get('uri') != uri
                or content.get('repository') != repo or content.get('manifest_digest') != digest
                or content.get('verification') != 'not_attempted'):
            return unknown
        if graph['complete'] and len(children) != len(graph['children']):
            return unknown
        all_leaks, expected_reads, complete, seen = [], [('manifests', digest)], graph['complete'], set()
        expanded = members = files = 0
        for descriptor, leaf in zip(graph['children'], children):
            if (type(descriptor) is not dict or set(descriptor) !=
                    {'digest','size','mediaType','platform','config_digest'}
                    or descriptor['mediaType'] not in oci_index.LEAF_TYPES
                    or type(descriptor['digest']) is not str or not archive.DIGEST.fullmatch(descriptor['digest'])
                    or descriptor['digest'] in seen or type(descriptor['size']) is not int
                    or not 0 < descriptor['size'] <= archive.MAX_MANIFEST):
                return unknown
            seen.add(descriptor['digest'])
            oci_index._platform(descriptor['platform'])
            if (type(leaf) is not dict or leaf.get('schema') != native.SCHEMA
                    or leaf.get('uri') != uri or leaf.get('repository') != repo
                    or leaf.get('manifest_digest') != descriptor['digest']
                    or leaf.get('status') not in ('collected','partial')
                    or type(leaf.get('complete')) is not bool):
                return unknown
            parts = leaf.get('descriptors')
            if type(parts) is not list or not 2 <= len(parts) <= archive.MAX_LAYERS + 1:
                return unknown
            for ordinal, part in enumerate(parts):
                native._descriptor(part, native.CONFIG_TYPES if ordinal == 0 else native.TAR_TYPES,
                    native.MAX_CONFIG if ordinal == 0 else archive.MAX_LAYER)
            if parts[0]['digest'] != descriptor['config_digest'] or sum(p['size'] for p in parts) > archive.MAX_COMPRESSED:
                return unknown
            expected_reads.append(('manifests', descriptor['digest']))
            expected_reads.extend(('blobs', part['digest']) for part in parts)
            scanned = leaf.get('layers_scanned')
            layer_digests = [part['digest'] for part in parts[1:]]
            if type(scanned) is not list or scanned != layer_digests[:len(scanned)]:
                return unknown
            inspected = ([part['digest'] for part in parts] if leaf['complete'] else
                leaf.get('inspected_digests'))
            if type(inspected) is not list or inspected[:1] != [parts[0]['digest']]:
                return unknown
            leaks = merge_leaks(leaf.get('leaks'))
            if any(location.get('layer') not in inspected for leak in leaks for location in leak['locations']):
                return unknown
            versions = {'kingfisher': KINGFISHER_VERSION, 'trufflehog': TRUFFLEHOG_VERSION}
            engines = leaf.get('engines')
            if (type(engines) is not list or len(engines) != 2
                    or {e.get('engine') for e in engines if type(e) is dict} != set(versions)
                    or any(type(e) is not dict or e.get('version') != versions.get(e.get('engine'))
                        or e.get('status') not in ('complete', 'unavailable') for e in engines)
                    or leaf['complete'] and any(e['status'] != 'complete' for e in engines)):
                return unknown
            expanded += leaf.get('expanded_bytes', 0)
            members += leaf.get('members', 0)
            files += leaf.get('regular_files', 0)
            all_leaks.extend(leaks)
            complete = complete and leaf['complete']
        merged = merge_leaks(all_leaks) if all_leaks else []
        if (merged != content.get('leaks') or type(content.get('complete')) is not bool
                or content['complete'] != complete or content.get('status') != (
                    'collected' if complete else 'partial' if merged else 'unavailable')
                or any(type(v) is not int for v in (expanded, members, files))
                or expanded > archive.MAX_EXPANDED or members > archive.MAX_MEMBERS
                or files > archive.MAX_MEMBERS or len(merged) > native.MAX_LEAKS
                or sum(len(leak['locations']) for leak in merged) > native.MAX_LOCATIONS
                or (content.get('expanded_bytes'), content.get('members'),
                    content.get('regular_files')) != (expanded, members, files)):
            return unknown
        if receipts is not None:
            if type(receipts) is not list or len(receipts) < 3 or len(receipts) > len(expected_reads) + 1:
                return unknown
            for position, receipt in enumerate(receipts):
                if (type(receipt) is not dict or receipt.get('method') != 'GET'
                        or receipt.get('scope') != scope or
                        receipt.get('category') not in ('manifests', 'blobs')):
                    return unknown
                if position < len(expected_reads):
                    if (receipt.get('category'), receipt.get('digest')) != expected_reads[position]:
                        return unknown
                elif (graph['complete'] or receipt.get('category') != 'manifests'
                        or receipt.get('status') == 'collected'):
                    return unknown
                if receipt.get('status') != 'collected' and position != len(receipts) - 1:
                    return unknown
            if complete and (len(receipts) != len(expected_reads) or any(
                    r.get('status') != 'collected' or r.get('http_status') != 200 for r in receipts)):
                return unknown
        if merged:
            return 'FAIL', {'observed':
                'A likely secret was found in a verified child of the selected image. Its value is hidden.',
                'secret_leaks': deepcopy(merged), 'complete': complete}
        if complete:
            return 'PASS', {'observed':
                'Both detectors found no supported secret in the verified content of every supported image child.',
                'secret_leaks': [], 'complete': True}
    except (KeyError, TypeError, ValueError, AttributeError, IndexError):
        pass
    return unknown

_globals = {**vars(predecessor), 'MAX_LAYER': archive.MAX_LAYER,
            'MAX_IMAGE': archive.MAX_COMPRESSED, 'MAX_EXPANDED': archive.MAX_EXPANDED,
            'MAX_LAYERS': archive.MAX_LAYERS, 'MAX_MEMBERS': archive.MAX_MEMBERS}
_leaf_evaluate = FunctionType(predecessor.evaluate.__code__, _globals, 'evaluate',
                        predecessor.evaluate.__defaults__, predecessor.evaluate.__closure__)
_leaf_evaluate.__kwdefaults__ = dict(predecessor.evaluate.__kwdefaults__ or {})


def evaluate(item, index):
    marker = item.get(native.MARKER) if isinstance(item, dict) else None
    context = index.get('context', {})
    selected = context.get('metadata', {}).get('artifact_image_secret_selections', {}).get(context.get('scope'), {})
    uris = selected.get('uris')
    if (marker is None and isinstance(uris, list) and uris and isinstance(item, dict)
            and isinstance(item.get('uri'), str) and item['uri'] not in uris):
        return 'NOT_APPLICABLE', {'observed': 'This immutable image was outside the selected content scope.'}
    if type(marker) is not dict or 'graph' not in marker:
        return _leaf_evaluate(item, index)
    try:
        scope = index['context']['scope']
        if index['context']['provider'] != 'gcp':
            raise ValueError('foreign provider')
        def rows(kind):
            collection, = [c for c in index['collections'][kind] if c.get('scope') == scope]
            if collection.get('status') != 'collected':
                raise ValueError('native inventory incomplete')
            return collection['items']
        images, repositories, projects = rows('artifact_image'), rows('artifact_repository'), rows('project')
        if item not in images or sum(r.get('uri') == item.get('uri') for r in images) != 1:
            raise ValueError('native image ambiguous')
        uri, repo, digest = native.bind_image(item, scope, repositories, projects)
        predecessor.guard(item)
        from peaso.collectors.gcp_cloudrun_image_inspection import MARKER as RUN_MARKER, validate_proof
        run_paths = validate_proof(item, index, images, repositories, projects) if RUN_MARKER in item else None
        status, evidence = evaluate_index_content(marker, uri, repo, digest, scope)
        if run_paths is not None and status != 'UNKNOWN':
            evidence = {**evidence, 'cloudrun_deployment_paths': run_paths}
        return status, evidence
    except (predecessor.Unavailable, KeyError, TypeError, ValueError, AttributeError):
        return 'UNKNOWN', {'observed': 'The selected image index lacks matching native image ownership.'}


def install():
    """Replace only the existing image predicate after the grouped integration."""
    from dataclasses import replace
    from . import CHECKS, register
    matches = [index for index, check in enumerate(CHECKS) if check.id == predecessor.CHECK_ID]
    if len(matches) != 1:
        raise RuntimeError('one existing selected GCP image check required')
    index = matches[0]
    check = CHECKS[index]
    if getattr(check.evaluate, '__wrapped__', None) is evaluate:
        return
    if (check.provider != 'gcp' or check.kind != 'artifact_image'
            or getattr(check.evaluate, '__wrapped__', None) is not predecessor.evaluate):
        raise RuntimeError('unexpected selected GCP image predicate')
    # Build the ordinary register() safety wrapper in a private output list.
    # Replacing the registry row with a bare predicate would bypass its native
    # fact guard/exception normalization; mutating the shared list during wrapper
    # creation would expose transient duplicate/missing entries to readers.
    prepared = []
    registrar = FunctionType(register.__code__, {**register.__globals__, 'CHECKS': prepared},
                             register.__name__, register.__defaults__, register.__closure__)
    registrar.__kwdefaults__ = dict(register.__kwdefaults__ or {})
    registrar(check.id, check.provider, check.category, check.kind, check.title,
              check.severity, check.control, check.remediation, target=check.target,
              dependencies=check.declared_dependencies,
              allow_incomplete_failure=check.allow_incomplete_failure,
              empty_applicability_dependencies=check.empty_applicability_dependencies)(evaluate)
    CHECKS[index] = replace(check, evaluate=prepared[0].evaluate)
