"""Persist only the safe image observation schema under the owning scan."""
from copy import deepcopy
import re

from peaso.image_findings import (_observation, _reason, _vulnerability, rejected,
                            MAX_OBSERVATIONS, MAX_TOTAL_VULNERABILITIES)
from peaso.image_findings import SCHEMA


def safe_observations(observations):
    if type(observations) is not list:
        return [None]
    safe, count = [], 0
    for observation in observations[:MAX_OBSERVATIONS]:
        try:
            asset, provider, scope, image, vulnerabilities, _ = _observation(observation)
        except (KeyError, TypeError, ValueError) as exc:
            # Keep only a bounded reason code so the report can say why.
            reason = _reason(exc, 'invalid_observation')
            safe.append(None if reason == 'missing_observation' else rejected(reason))
            continue
        scan = observation['scan']
        row = {'provider': provider, 'scope': scope, 'asset_id': asset['resource_id'],
               'asset_kind': asset['kind'], 'scan': {
                   'image': deepcopy(image), 'status': scan['status'], 'complete': scan['complete'],
                   'scan_complete': scan['scan_complete'], 'coverage_status': scan['coverage_status'],
                   'database': {'fresh': scan['database']['fresh']}, 'findings': []}}
        if 'namespace' in asset:
            row['namespace'] = asset['namespace']
        for vulnerability in vulnerabilities:
            count += 1
            if count > MAX_TOTAL_VULNERABILITIES:
                break
            try:
                projected = deepcopy(_vulnerability(vulnerability, image['manifest_digest']))
            except (KeyError, TypeError, ValueError):
                projected = None
                row['scan'].update(complete=False, scan_complete=False, coverage_status='UNKNOWN')
            row['scan']['findings'].append(projected)
        # A truncated positive scan must stay a positive or unresolved partial
        # result; append one invalid observation rather than certify completeness.
        safe.append(row)
        if count > MAX_TOTAL_VULNERABILITIES:
            row['scan'].update(status='FAIL' if row['scan']['findings'] else 'UNKNOWN',
                               complete=False, scan_complete=False, coverage_status='UNKNOWN')
            safe.append(None)
            break
    if len(observations) > MAX_OBSERVATIONS:
        safe.append(None)
    return safe


def attach_to_manifest(manifest, artifacts, tenant, scan_id, metadata=None):
    """Return a new manifest; keep full metadata/canaries out of report summaries."""
    if type(manifest) is not dict or type(scan_id) is not str or re.fullmatch(r'[a-f0-9]{32}', scan_id) is None:
        raise ValueError('valid_manifest_and_scan_required')
    result = dict(manifest)
    result.pop('image_vulnerability_scan', None)
    if type(metadata) is not dict or metadata.get('selected') is not True:
        return result
    reference = artifacts.put(tenant, scan_id, 'detail', {
        'schema': SCHEMA, 'scan_id': scan_id,
        'observations': safe_observations(metadata.get('observations'))})
    result['image_vulnerability_scan'] = {'selected': True, 'artifact': reference}
    return result
