"""Pure evidence projection for explicitly selected Pod-bound OCI images."""
import json
from pathlib import Path
import re
from peaso.collectors import k8s_selected_registry_image_20261021 as source
from peaso.snapshot import FrozenDict, thaw

DECLARATIONS = (
    {'id': source.SECRET_CHECK, 'kind': source.SECRET_KIND, 'category': 'exposure',
     'finding_type': 'secrets', 'ui_group': 'Secrets', 'severity': 'high',
     'requirements': [],
     'title': 'Selected Pod image content has no detected secrets'},
    {'id': source.VULN_CHECK, 'kind': source.VULN_KIND, 'category': 'hardening',
     'finding_type': 'vulnerabilities', 'ui_group': 'Vulnerabilities', 'severity': 'high',
     'requirements': [],
     'title': 'Selected Pod image has no HIGH or CRITICAL package vulnerabilities'},
)


def evaluate(item, index, kind):
    """Require native parent binding and exact child receipts before a clean verdict."""
    unknown = ('UNKNOWN', {'observed': 'The selected Pod could not be matched to its recorded identity and image digest.'})
    try:
        ctx = index['context']; meta = ctx['metadata']; scope = ctx['scope']
        if ctx['provider'] != 'k8s' or meta[kind + '_authorized'] is not True:
            return unknown
        target, = [t for t in meta[source.OPTION] if source.identity(t) == item['id']]
        if target['namespace'] != scope or item.get('name') != item['id']:
            return unknown
        collection, = [c for c in index['collections'][kind]
                       if c.get('scope') == scope and item in c.get('items', [])]
        if collection.get('status') not in ('collected', 'partial'):
            return unknown
        marker = item['SelectedRegistryImage']
        # Engine snapshots expose native JSON as immutable views. Convert only
        # that trusted view before the exact schema and receipt checks below.
        if type(marker) is FrozenDict:
            marker = thaw(marker)
        missing = {
            'registry_denied': 'The selected registry denied a manifest or layer byte read.',
            'registry_truncated_or_digest': 'A selected manifest or layer has a missing or mismatched SHA-256 byte receipt.',
            'pod_image_changed': 'The selected Pod image or container instance changed between native reads.',
            'child_platform_config_mismatch': 'A child manifest platform differs from its verified image configuration.',
            'nested_archive_uninspected': 'A selected image layer contains a nested archive whose bytes remain uninspected.',
            'binary_file_uninspected': 'A selected image layer contains binary file bytes that remain uninspected.',
            'detectors_incomplete': 'One offline detector did not finish on selected image bytes.',
            'file_scan_bound': 'Selected image file bytes exceed the bounded text inspection limit.',
        }.get(marker.get('reason'), 'A complete child-manifest and layer byte receipt is missing for the selected Pod image.')
        unknown = ('UNKNOWN', {'observed': missing})
        parent_digest = target['image'].rsplit('@', 1)[1]
        if (marker.get('schema') != source.SCHEMA or marker.get('identity') != item['id']
                or marker.get('auth_mode') not in ('anonymous', 'basic', 'bearer')
                or marker.get('manifest_digest') != parent_digest
                or marker.get('status_image_id') != target['image']
                or type(marker.get('native_before')) is not dict
                or marker.get('native_before') != marker.get('native_after')
                or marker['native_before'].get('uid') != target['uid']
                or marker['native_before'].get('resource_version') != target['resource_version']):
            return unknown
        graph = marker.get('graph')
        if graph is None:  # Accepted pre-index leaf witness.
            child_digests = {parent_digest}; graph_complete = True; is_index = False
        else:
            if (type(graph) is not dict or set(graph) != {'parent_digest','media_type','children','complete'}
                    or graph.get('parent_digest') != parent_digest
                    or graph.get('media_type') not in source.oci_index.ALL_MANIFEST_TYPES
                    or type(graph.get('children')) is not list
                    or len(graph['children']) > source.oci_index.MAX_CHILDREN
                    or type(graph.get('complete')) is not bool):
                return unknown
            is_index = graph['media_type'] in source.oci_index.INDEX_TYPES
            child_digests = set()
            for child in graph['children']:
                if (type(child) is not dict or set(child) != {'digest','size','mediaType','platform','config_digest'}
                        or child.get('mediaType') not in source.oci_index.LEAF_TYPES
                        or type(child.get('digest')) is not str
                        or source.archive.DIGEST.fullmatch(child['digest']) is None
                        or child['digest'] in child_digests
                        or type(child.get('size')) is not int
                        or not 0 < child['size'] <= source.archive.MAX_MANIFEST
                        or type(child.get('config_digest')) is not str
                        or source.archive.DIGEST.fullmatch(child['config_digest']) is None):
                    return unknown
                if is_index:
                    try: source.oci_index._platform(child.get('platform'))
                    except ValueError: return unknown
                elif child.get('platform') is not None or child['digest'] != parent_digest:
                    return unknown
                child_digests.add(child['digest'])
            if graph['complete'] and not child_digests:
                return unknown
            if not is_index and (len(graph['children']) != 1 or graph['children'][0]['digest'] != parent_digest):
                return unknown
            graph_complete = graph['complete']
        receipts = marker.get('registry_receipts')
        if (type(receipts) is not list or not receipts or len(receipts) > source.MAX_CALLS
                or receipts[0].get('category') != 'manifests'
                or receipts[0].get('digest') != parent_digest
                or receipts[0].get('status') != 'collected'
                or len({r.get('id') for r in receipts if type(r) is dict}) != len(receipts)
                or any(type(r) is not dict or set(r) != {'id','method','category','digest','status','bytes'}
                       or re.fullmatch(r'registry-read-[0-9a-f]{32}', str(r.get('id'))) is None
                       or r.get('method') != 'GET' or r.get('status') not in ('collected','denied','unavailable')
                       or type(r.get('bytes')) is not int or not 0 <= r['bytes'] <= source.archive.MAX_LAYER
                       or type(r.get('digest')) is not str or source.archive.DIGEST.fullmatch(r['digest']) is None
                       or r.get('category') not in ('manifests','blobs') for r in receipts)):
            return unknown
        manifests = [r for r in receipts if r['category'] == 'manifests' and r['status'] == 'collected']
        if graph is not None and (len(manifests) != 1 + (len(child_digests) if is_index else 0)
                or {r['digest'] for r in manifests[1:]} != (child_digests if is_index else set())
                or any(r['bytes'] != c['size'] for c in graph['children'] for r in manifests[1:]
                       if r['digest'] == c['digest'])):
            return unknown
        stable = graph_complete and all(r['status'] == 'collected' for r in receipts)
        if kind == source.SECRET_KIND:
            leaks = marker.get('leaks'); parts = marker.get('parts')
            if (type(leaks) is not list or len(leaks) > 256 or type(parts) is not list
                    or not 1 <= len(parts) <= 8192 or any(
                        type(leak) is not dict or not re.fullmatch('[0-9a-f]{64}', str(leak.get('fingerprint')))
                        or not leak.get('locations') or not leak.get('detectors') for leak in leaks)):
                return unknown
            versions = {'kingfisher': '1.4.0', 'trufflehog': '3.92.5'}
            completed = {(part.get('part'), engine.get('engine')) for part in parts
                         if type(part) is dict for engine in part.get('engines', [])
                         if type(engine) is dict and engine.get('engine') in versions
                         and engine.get('status') == 'complete'
                         and engine.get('version') == versions[engine['engine']]}
            # Deduplication merges engine and location sets independently. Each
            # location needs a completed reporting engine, not their Cartesian product.
            if any(any(not any((loc.get('path'), detector.get('engine')) in completed
                               for detector in leak['detectors']) for loc in leak['locations'])
                   or any(not any((loc.get('path'), detector.get('engine')) in completed
                                  for loc in leak['locations']) for detector in leak['detectors'])
                   for leak in leaks):
                return unknown
            if leaks:
                return 'FAIL', {'observed': 'A likely secret was found in the selected Pod image. Its value is hidden.',
                    'secret_leaks': leaks, 'complete': stable and marker.get('complete') is True,
                    'verified_child_manifest_digests': sorted(child_digests)}
            blobs = [r for r in receipts if r['category'] == 'blobs']
            # Each clean leaf needs a configuration and at least one layer.
            if (stable and len(blobs) >= 2 * len(child_digests)
                    and all(r['status'] == 'collected' and r['bytes'] > 0 for r in blobs)
                    and (graph is None or all(any(r['digest'] == child['config_digest']
                        for r in blobs) for child in graph['children']))
                    and marker.get('status') == 'PASS' and marker.get('complete') is True
                    and all(type(p) is dict and p.get('complete') is True
                            and type(p.get('bytes')) is int and p['bytes'] > 0
                            and {e.get('engine') for e in p.get('engines', [])} == set(versions)
                            and all(type(e) is dict and e.get('status') == 'complete'
                                    and e.get('version') == versions[e['engine']]
                                    for e in p['engines']) for p in parts)):
                return 'PASS', {'observed': 'Both detectors found no supported secret in the selected Pod image.', 'complete': True}
            return unknown
        vuln = marker.get('vulnerability')
        if type(vuln) is not dict or type(vuln.get('findings')) is not list:
            return unknown
        findings = vuln['findings']
        if (len(findings) > 10000 or any(type(f) is not dict
                or f.get('severity') not in ('HIGH','CRITICAL')
                or f.get('image_digest') not in child_digests for f in findings)):
            return unknown
        if is_index:
            scans = marker.get('child_vulnerability_scans'); reported = vuln.get('children')
            if (type(scans) is not list or len(scans) > source.oci_index.MAX_CHILDREN
                    or type(reported) is not list or len(reported) != len(scans)
                    or len(reported) > source.oci_index.MAX_CHILDREN
                    or stable and len(reported) != len(child_digests)):
                return unknown
            from peaso import trivy_container_runner_20261020 as trivy
            parsed = source.association.parse_image_reference(target['image'])
            for child, scan, report in zip(graph['children'], scans, reported):
                expected_image = {'provider': 'k8s', 'scope': target['cluster_id'],
                    'immutable_reference': parsed.registry + '/' + parsed.repository + '@' + child['digest'],
                    'manifest_digest': child['digest'], 'config_digest': child['config_digest']}
                if (type(scan) is not dict or scan.get('schema') != trivy.SCHEMA
                        or scan.get('image') != expected_image
                        or type(scan.get('findings')) is not list
                        or type(report) is not dict
                        or set(report) != {'digest','status','complete'}
                        or report['digest'] != child['digest']
                        or report['status'] not in ('PASS','FAIL','UNKNOWN')
                        or type(report['complete']) is not bool
                        or report['status'] != scan.get('status')
                        or report['complete'] != (scan.get('complete') is True)
                        or any(type(f) is not dict or f.get('image_digest') != child['digest']
                               for f in scan['findings'])):
                    return unknown
            if findings != [f for scan in scans for f in scan['findings']][:10000]:
                return unknown
        if findings and vuln.get('status') in ('FAIL', 'PASS', 'UNKNOWN'):
            child = findings[0]['image_digest']
            # Native image/finding bindings above remain valid when a summary
            # status contradicts recorded positives; only completeness is lost.
            contradiction = vuln.get('status') != 'FAIL'
            return 'FAIL', {'observed': 'Trivy found HIGH or CRITICAL package vulnerabilities in the selected Pod image.',
                'vulnerabilities': findings, 'complete': stable and vuln.get('complete') is True and not contradiction,
                **({'coverage_status': 'UNKNOWN'} if contradiction else {})}
        if (stable and vuln.get('status') == 'PASS' and vuln.get('complete') is True
                and vuln.get('scan_complete') is True and vuln.get('coverage_status') == 'COMPLETE'
                and vuln.get('database', {}).get('fresh') is True):
            return 'PASS', {'observed': 'Trivy found no HIGH or CRITICAL package vulnerabilities in the selected Pod image using a fresh database.', 'complete': True}
        return unknown
    except (KeyError, TypeError, ValueError, AttributeError, IndexError):
        return unknown

def install(register):
    from .fixtures import CASES
    cases = json.loads(Path(__file__).with_name('k8s_selected_registry_image_review_20261021_cases.json').read_text())
    if set(cases) != {d['id'] for d in DECLARATIONS} or set(cases) & set(CASES):
        raise ValueError('Selected registry image fixture collision or missing case')
    for declaration in DECLARATIONS:
        kind = declaration['kind']
        @register(declaration['id'], 'k8s', declaration['category'], kind,
                  declaration['title'], declaration['severity'], 'security_configuration',
                  'Inspect the image source and rebuild a new immutable digest after removing confirmed findings.',
                  dependencies=(kind,), allow_incomplete_failure=True)
        def selected_image(item, index, kind=kind):
            return evaluate(item, index, kind)
    CASES.update(cases)
