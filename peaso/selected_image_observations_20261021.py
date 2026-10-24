"""Present evaluated selected-image scans in the existing tenant-owned image artifact.

This module performs no collection or check evaluation. A matching evaluated
finding is required before a new collection row can contribute an observation.
"""
from copy import deepcopy
import re

from peaso.image_findings import MAX_OBSERVATIONS, _asset, _scan, _vulnerability
from peaso.snapshot import FrozenDict, digest, resource_id, thaw


# kind: provider, evaluated check, marker path, scan path within that marker
SOURCES = {
    'k8s_selected_registry_image_vulnerabilities': (
        'k8s', 'k8s.review.selected_registry_image_high_vulnerabilities',
        ('SelectedRegistryImage',), ('vulnerability',)),
    'azure_selected_aks_pod_image_vulnerabilities': (
        'azure', 'azure.review.aks.selected_pod_image_high_vulnerabilities',
        ('SelectedAksImage',), ('image', 'vulnerability')),
    'gke_selected_pod_image_vulnerabilities': (
        'gcp', 'gcp.review.gke.selected_pod_image_high_vulnerabilities',
        ('SelectedGkePodImage',), ('image', 'vulnerability')),
    'appengine_flex_selected_version_image_vulnerabilities': (
        'gcp', 'gcp.review.app_engine_flex.selected_version_image_high_vulnerabilities',
        ('SelectedAppEngineFlexVersionImage',), ('row', 'vulnerability', 'record')),
    'ecr_public_selected_image_content': (
        'aws', 'aws.review.ecr_public.selected_image_high_vulnerabilities',
        ('ECRPublicImageContent',), ('vulnerability',)),
    'acr_selected_image_vulnerabilities': (
        'azure', 'azure.review.acr.selected_image_high_critical_vulnerabilities',
        ('AcrSelectedImageVulnerabilities',), ('observation', 'scan')),
}


def _at(value, path):
    for key in path:
        value = value[key]
    return value


def _canonical_scan(raw, provider, scope, *, pod=False):
    scan = deepcopy(raw)
    if not isinstance(scan, dict):
        raise ValueError('missing_selected_image_scan')
    # The Flex producer stores the same scan as a deliberately narrow record.
    if 'database_fresh' in scan:
        scan['database'] = {'fresh': scan['database_fresh']}
    image = scan['image']
    if not isinstance(image, dict):
        raise ValueError('missing_selected_image_identity')
    original_provider, original_scope = image.get('provider'), image.get('scope')
    if pod:
        if original_provider != 'k8s' or not isinstance(original_scope, str) or not original_scope:
            raise ValueError('foreign_pod_image_identity')
        if provider == 'gcp' and not original_scope.startswith(scope + '/locations/'):
            raise ValueError('foreign_gke_project')
        if provider == 'azure' and not original_scope.casefold().startswith(scope.casefold() + '/resourcegroups/'):
            raise ValueError('foreign_aks_subscription')
    elif original_provider != provider or original_scope != scope:
        raise ValueError('foreign_selected_image_identity')
    # GKE/AKS reuse the Pod scanner. Its enclosing evaluated check establishes
    # the cloud/cluster association; do not change its immutable bytes identity.
    image['provider'], image['scope'] = provider, scope
    return scan


def _preserve_evaluated_pod_positive(scan):
    """Keep exact typed positives from an evaluated FAIL; drop clean coverage."""
    if (type(scan) is not dict or scan.get('status') not in ('PASS', 'UNKNOWN')
            or type(scan.get('findings')) is not list or not scan['findings']):
        return scan
    # Called only after an exact evaluated Pod/cloud-Pod FAIL association and
    # immutable child-image binding. Validate the full existing presentation
    # schema before normalizing the contradictory summary, never its findings.
    candidate = dict(scan, status='FAIL', complete=False, scan_complete=False,
                     coverage_status='UNKNOWN')
    image = candidate['image']
    _, _, identity, findings, _ = _scan({'provider': image['provider'],
        'scope': image['scope'], 'scan': candidate})
    for finding in findings:
        _vulnerability(finding, identity['manifest_digest'])
    return candidate


def _child_scans(marker, provider, scope, kind):
    """Project only children bound to the evaluated native index marker."""
    holder = marker.get('image') if kind in (
        'azure_selected_aks_pod_image_vulnerabilities',
        'gke_selected_pod_image_vulnerabilities') else marker
    if type(holder) is not dict:
        return [None]
    graph = holder.get('graph')
    if graph is None and 'child_vulnerability_scans' not in holder:
        return None  # Pre-index leaf witness.
    scans = holder.get('child_vulnerability_scans')
    selected = marker.get('selection') if kind == 'ecr_public_selected_image_content' else None
    expected_parent = (selected.get('image_digest') if type(selected) is dict else None
        ) if kind == 'ecr_public_selected_image_content' else holder.get('manifest_digest')
    if (type(graph) is not dict or type(scans) is not list or
            type(graph.get('children')) is not list or
            type(graph.get('complete')) is not bool or
            not 1 <= len(graph['children']) <= 8 or len(scans) > len(graph['children']) or
            graph.get('parent_digest') != expected_parent):
        return [None]
    if kind == 'ecr_public_selected_image_content':
        if (type(selected) is not dict or selected.get('image_digest') != graph['parent_digest'] or
                type(selected.get('registry_alias')) is not str or
                type(selected.get('repository_name')) is not str):
            return [None]
        prefix = ('public.ecr.aws/' + selected['registry_alias'] + '/' +
                  selected['repository_name'] + '@')
    else:
        parent = holder.get('status_image_id')
        if type(parent) is not str or not parent.endswith('@' + graph['parent_digest']):
            return [None]
        prefix = parent.rsplit('@', 1)[0] + '@'
    output, seen = [], set()
    for child, raw in zip(graph['children'], scans):
        try:
            if type(child) is not dict or type(raw) is not dict:
                raise ValueError('invalid_index_child')
            child_digest, config_digest = child['digest'], child['config_digest']
            if child_digest in seen:
                raise ValueError('duplicate_index_child')
            seen.add(child_digest)
            image = raw['image']
            if (type(image) is not dict or image.get('manifest_digest') != child_digest or
                    image.get('config_digest') != config_digest or
                    image.get('immutable_reference') != prefix + child_digest):
                raise ValueError('foreign_index_child')
            scan = _canonical_scan(raw, provider, scope, pod=kind in (
                'k8s_selected_registry_image_vulnerabilities',
                'azure_selected_aks_pod_image_vulnerabilities',
                'gke_selected_pod_image_vulnerabilities'))
            output.append(scan if scan.get('status') in ('PASS', 'FAIL') or
                scan.get('status') == 'UNKNOWN' and scan.get('findings') else None)
        except (KeyError, TypeError, ValueError, AttributeError):
            output.append(None)
    if len(scans) != len(graph['children']) or graph['complete'] is not True:
        output.append(None)
    return output or [None]


def _acr_scans(marker, scope):
    """Associate only the selected ACR digest's verified child scan records."""
    selected = marker.get('selection')
    if type(selected) is not dict or set(selected) != {'registry_id', 'repository', 'digest'}:
        return [None]
    registry, repository, parent = (selected[key] for key in
        ('registry_id', 'repository', 'digest'))
    if (type(registry) is not str or type(repository) is not str or
            type(parent) is not str or not registry.casefold().startswith(scope.casefold() + '/') or
            not re.fullmatch(r'sha256:[0-9a-f]{64}', parent) or
            not re.fullmatch(r'[a-z0-9._/-]{1,256}', repository) or
            '..' in repository.split('/')):
        return [None]
    match = re.search(r'/registries/([a-z0-9]{5,50})$', registry, re.I)
    if match is None:
        return [None]
    host = match.group(1).lower()
    asset_id = registry + '/repositories/' + repository + '@' + parent
    graph = marker.get('graph')
    if graph is None:
        observed = marker.get('observation')
        if (type(observed) is not dict or observed.get('provider') != 'azure' or
                observed.get('scope') != scope or observed.get('asset_id') != asset_id or
                observed.get('asset_kind') != 'acr_image'):
            return [None]
        try:
            scan = _canonical_scan(observed['scan'], 'azure', scope)
            image = scan['image']
            ref = image['immutable_reference']
            image_host, suffix = ref.split('/', 1)
            if (image['manifest_digest'] != parent or
                    not re.fullmatch(re.escape(host) + r'(?:-[a-z0-9]{5,32})?\.azurecr\.io', image_host) or
                    suffix != repository + '@' + parent):
                return [None]
            return [scan] if scan.get('status') in ('PASS', 'FAIL') else [None]
        except (KeyError, TypeError, ValueError, AttributeError):
            return [None]
    scans = marker.get('child_vulnerability_scans')
    if (type(graph) is not dict or type(scans) is not list or
            type(graph.get('children')) is not list or
            type(graph.get('complete')) is not bool or
            graph.get('parent_digest') != parent or
            not 1 <= len(graph['children']) <= 8 or len(scans) > len(graph['children'])):
        return [None]
    output, seen = [], set()
    for child, raw in zip(graph['children'], scans):
        try:
            if type(child) is not dict or type(raw) is not dict:
                raise ValueError('invalid_acr_child')
            child_digest = child['digest']
            if child_digest in seen or not re.fullmatch(r'sha256:[0-9a-f]{64}', child_digest):
                raise ValueError('invalid_acr_child_digest')
            seen.add(child_digest)
            scan = _canonical_scan(raw, 'azure', scope)
            image = scan['image']
            image_host, suffix = image['immutable_reference'].split('/', 1)
            if (image['manifest_digest'] != child_digest or
                    image['config_digest'] != child['config_digest'] or
                    not re.fullmatch(re.escape(host) + r'(?:-[a-z0-9]{5,32})?\.azurecr\.io', image_host) or
                    suffix != repository + '@' + child_digest):
                raise ValueError('foreign_acr_child')
            output.append(scan if scan.get('status') in ('PASS', 'FAIL') else None)
        except (KeyError, TypeError, ValueError, AttributeError):
            output.append(None)
    if len(scans) != len(graph['children']) or graph['complete'] is not True:
        output.append(None)
    return output or [None]


def metadata_for_report(snapshot, report):
    """Merge current evaluated selected-image observations without mutating inputs.

    Unknown, absent, contradictory or malformed scan evidence contributes a gap,
    never a fabricated clean result. Existing native image observations survive.
    """
    metadata = snapshot.get('metadata', {})
    prior = metadata.get('image_vulnerability_scan') if isinstance(metadata, dict) else None
    provider = snapshot.get('provider')
    # ACR collector metadata precedes evaluation. Once an ACR selected source
    # exists, only its evaluated item may restore ACR observations below.
    acr_selected = provider == 'azure' and any(
        type(c) is dict and c.get('type') == 'acr_selected_image_vulnerabilities'
        for c in snapshot.get('collections', []))
    if acr_selected and isinstance(prior, dict) and prior.get('selected') is True:
        clean_prior = deepcopy(prior)
        rows = prior.get('observations')
        clean_prior['observations'] = [deepcopy(row) for row in rows
            if row is None or type(row) is not dict or not (
                row.get('provider') == 'azure' and row.get('asset_kind') == 'acr_image')
        ] if isinstance(rows, list) else [None]
        prior = clean_prior
    if report.get('provider') not in (None, provider) or (
            acr_selected and report.get('snapshot_id') is not None and
            report.get('snapshot_id') != snapshot.get('snapshot_id')):
        if acr_selected:
            observations = (deepcopy(prior.get('observations', []))
                if isinstance(prior, dict) and prior.get('selected') is True else [])
            observations.append(None)
            return {'selected': True, 'observations': observations}
        return deepcopy(prior)
    accepted = {}
    checks = {value[1] for value in SOURCES.values() if value[0] == provider}
    for row in report.get('findings', []):
        if type(row) is not dict or row.get('check_id') not in checks or row.get('provider') != provider:
            continue
        if type(row.get('scope')) is not str or type(row.get('resource_id')) is not str:
            continue
        key = (row.get('check_id'), row.get('scope'), row.get('resource_id'))
        # Duplicate evaluated rows cannot give an unambiguous association.
        accepted[key] = None if key in accepted else row.get('scanner_status', row.get('status'))
    if not accepted:
        if acr_selected:
            observations = (deepcopy(prior.get('observations', []))
                if isinstance(prior, dict) and prior.get('selected') is True else [])
            observations.append(None)
            return {'selected': True, 'observations': observations}
        return deepcopy(prior)
    observations = []
    if isinstance(prior, dict) and prior.get('selected') is True:
        existing = prior.get('observations')
        observations = deepcopy(existing) if isinstance(existing, list) else [None]
    remaining = set(accepted)
    for collection in snapshot.get('collections', []):
        source = SOURCES.get(collection.get('type'))
        if source is None or source[0] != provider:
            continue
        _, check, marker_path, scan_path = source
        scope = collection.get('scope')
        for item in collection.get('items', []):
            native_id = resource_id(provider, collection['type'], scope, item)
            ident = digest([provider, scope, collection['type'], native_id])
            key = (check, scope, ident)
            if key not in remaining:
                continue
            remaining.remove(key)
            if len(observations) >= MAX_OBSERVATIONS:
                observations.append(None)
                return {'selected': True, 'observations': observations}
            try:
                if accepted[key] not in ('PASS', 'FAIL'):
                    raise ValueError('unresolved_native_association')
                marker = _at(item, marker_path)
                # Report storage receives the engine's immutable native view;
                # retain the existing exact child/scan validators on plain JSON.
                if type(marker) is FrozenDict:
                    marker = thaw(marker)
                if (collection['type'] == 'acr_selected_image_vulnerabilities' and
                        marker.get('status') != accepted[key]):
                    raise ValueError('acr_marker_evaluation_mismatch')
                child_scans = (_acr_scans(marker, scope)
                    if collection['type'] == 'acr_selected_image_vulnerabilities'
                    else _child_scans(marker, provider, scope, collection['type']))
                if child_scans is None:
                    raw = _at(marker, scan_path)
                    child_scans = [_canonical_scan(raw, provider, scope,
                        pod=collection['type'] in ('k8s_selected_registry_image_vulnerabilities',
                            'azure_selected_aks_pod_image_vulnerabilities', 'gke_selected_pod_image_vulnerabilities'))]
                if (accepted[key] == 'FAIL' and collection['type'] in (
                        'k8s_selected_registry_image_vulnerabilities',
                        'azure_selected_aks_pod_image_vulnerabilities',
                        'gke_selected_pod_image_vulnerabilities')):
                    child_scans = [_preserve_evaluated_pod_positive(scan)
                                   if scan is not None else None for scan in child_scans]
                if (accepted[key] == 'PASS' and any(s is None or s.get('status') != 'PASS' for s in child_scans)
                        or accepted[key] == 'FAIL' and not any(s is not None and s.get('status') == 'FAIL' for s in child_scans)):
                    raise ValueError('scan_and_evaluated_status_differ')
                for scan in child_scans:
                    if scan is None:
                        observations.append(None)
                        continue
                    observation = {'provider': provider, 'scope': scope, 'asset_id': ident,
                                   'asset_kind': collection['type'], 'scan': scan}
                    if provider == 'k8s':
                        observation['namespace'] = scope
                    _asset(observation)
                    _, _, image, vulnerabilities, _ = _scan(observation)
                    for vulnerability in vulnerabilities:
                        _vulnerability(vulnerability, image['manifest_digest'])
                    observations.append(observation)
            except (KeyError, TypeError, ValueError, AttributeError):
                observations.append(None)
    # Evaluated selected resources missing from the supplied snapshot are gaps.
    observations.extend(None for _ in range(min(len(remaining), MAX_OBSERVATIONS)))
    return {'selected': True, 'observations': observations}
