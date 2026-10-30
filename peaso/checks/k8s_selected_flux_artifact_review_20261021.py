"""Evidence projection for an exact native Flux artifact and source-controller Service."""
import json
from pathlib import Path
import re
from peaso.collectors import k8s_selected_flux_artifact_20261021 as source
from peaso.secret_scanning import KINGFISHER_VERSION, TRUFFLEHOG_VERSION, merge_leaks

DECLARATION = {'id': source.CHECK, 'provider': 'k8s', 'category': 'exposure',
    'kind': source.KIND, 'finding_type': 'secrets', 'ui_group': 'Secrets', 'severity': 'high',
    'requirements': [], 'title': 'Selected Flux artifact has no detected secrets',
    'description': 'Review one selected GitRepository or HelmChart artifact whose digest and source-controller Service are bound to native Kubernetes reads.',
    'references': ['https://fluxcd.io/flux/components/source/gitrepositories/',
                   'https://fluxcd.io/flux/components/source/helmcharts/',
                   'https://kubernetes.io/docs/reference/kubernetes-api/core/service-v1/']}


def evaluate(item, index):
    unknown = ('UNKNOWN', {'observed': 'A verified artifact content record is missing for this selected Flux source. Its contents could not be assessed.'})
    try:
        ctx = index['context']; meta = ctx['metadata']; scope = ctx['scope']
        if ctx['provider'] != 'k8s' or meta[source.KIND + '_authorized'] is not True:
            return unknown
        target, = [t for t in meta[source.OPTION] if source.identity(t) == item['id']]
        if target['namespace'] != scope or item.get('name') != item['id']:
            return unknown
        collection, = [c for c in index['collections'][source.KIND]
                       if c.get('scope') == scope and item in c.get('items', [])]
        if collection.get('status') not in ('collected', 'partial'):
            return unknown
        marker = item['SelectedFluxArtifact']
        first = {
            'artifact_denied': 'The selected source-controller Service denied the artifact bytes.',
            'artifact_redirect': 'The selected artifact route returned a redirect.',
            'artifact_truncated': 'The selected artifact bytes were incomplete.',
            'artifact_digest_mismatch': 'The selected artifact bytes differed from the native SHA-256 digest.',
            'flux_source_unbound': 'The selected Flux source identity or artifact status did not match.',
            'flux_service_unbound': 'The selected source-controller Service identity did not match.',
            'flux_binding_changed': 'The selected Flux source or Service changed between native reads.',
            'nested_or_binary_member': 'The selected artifact contains an unsupported nested or binary member.',
            'binary_member_uninspected': 'The selected artifact contains a binary member whose bytes were not inspected.',
        }.get(marker.get('reason'), 'The selected Flux artifact lacks complete verified text content.')
        unknown = ('UNKNOWN', {'observed': first + '\nIts artifact may contain a secret.\nAccess to workloads or their data remains unclear.'})
        if (marker.get('schema') != source.SCHEMA or marker.get('identity') != item['id']
                or marker.get('digest') != target['artifact_digest']
                or marker.get('revision') != target['artifact_revision']
                or marker.get('native_before') != marker.get('native_after')
                or marker.get('service_before') != marker.get('service_after')
                or marker.get('native_before', {}).get('uid') != target['uid']
                or marker.get('native_before', {}).get('resource_version') != target['resource_version']
                or marker.get('service_before', {}).get('uid') != target['service_uid']
                or marker.get('service_before', {}).get('resource_version') != target['service_resource_version']):
            return unknown
        read = marker.get('read')
        if (type(read) is not dict or read.get('method') != 'GET'
                or read.get('path') != source.proxy_path(target)
                or read.get('digest') != target['artifact_digest']
                or read.get('size') != target['artifact_size'] or read.get('status') != 'collected'):
            return unknown
        leaks, parts = marker.get('leaks'), marker.get('parts')
        if (type(leaks) is not list or len(leaks) > 256 or type(parts) is not list or len(parts) > source.MAX_MEMBERS
                or any(type(l) is not dict or not re.fullmatch('[0-9a-f]{64}', str(l.get('fingerprint')))
                       or not l.get('locations') or not l.get('detectors') for l in leaks)):
            return unknown
        # A positive must be a canonical secret observation, so saved secret
        # findings keep the same detectors, locations and per-secret summary.
        merge_leaks(leaks)
        expected_engines = {'kingfisher': KINGFISHER_VERSION, 'trufflehog': TRUFFLEHOG_VERSION}
        completed = {(part.get('part'), engine.get('engine')) for part in parts
                     if type(part) is dict and type(part.get('engines')) is list
                     for engine in part['engines'] if type(engine) is dict and engine.get('status') == 'complete'
                     and engine.get('version') == expected_engines.get(engine.get('engine'))}
        if any((location.get('path'), detector.get('engine')) not in completed
               for leak in leaks for location in leak['locations'] for detector in leak['detectors']):
            return unknown
        if leaks:
            return 'FAIL', {'observed': 'The selected Flux source reported this verified artifact digest.\nIts text content contains a likely secret whose value is hidden.\nThat secret may allow access to services or data if it is still valid.',
                            'secret_leaks': leaks, 'complete': marker.get('complete') is True}
        # A clean result needs the complete selected inventory; a partial
        # collection can retain a positive but cannot prove absence.
        if collection.get('status') != 'collected':
            return 'UNKNOWN', {'observed': 'The selected Flux artifact had no detected secret, but its Kubernetes inventory was incomplete.\nOther members or sources in that inventory may still contain a secret.\nAccess to workloads or their data remains unclear.'}
        if (marker.get('status') == 'PASS' and marker.get('complete') is True and parts
                and all(p.get('complete') is True and type(p.get('engines')) is list
                        and len(p['engines']) == 2
                        and {e.get('engine') for e in p['engines']} == set(expected_engines)
                        and all(e.get('status') == 'complete' and
                                e.get('version') == expected_engines[e['engine']] for e in p['engines'])
                        for p in parts)):
            return 'PASS', {'observed': 'The selected Flux source reported this verified artifact digest.\nBoth offline detectors inspected its supported text members.\nNo supported secret was found in those bytes.', 'complete': True}
        return unknown
    except (KeyError, TypeError, ValueError, AttributeError, IndexError):
        return unknown


def install(register):
    from .fixtures import CASES
    cases = json.loads(Path(__file__).with_name('k8s_selected_flux_artifact_review_20261021_cases.json').read_text())
    if set(cases) != {source.CHECK} or source.CHECK in CASES:
        raise ValueError('Flux artifact fixture collision or missing cases')
    register(source.CHECK, 'k8s', 'exposure', source.KIND, DECLARATION['title'], 'high',
             'security_configuration',
             'Remove confirmed credential material from the source artifact and rotate affected credentials.',
             dependencies=(source.KIND,), allow_incomplete_failure=True)(evaluate)
    CASES.update(cases)
