"""Retain only validated matching Functions pairs after global value dedup.

The input findings are ordinary pre-dedup JSON DTOs. The output keeps the final
one-finding-per-secret identity, assets, scopes and check links unchanged; only
whitelisted, fingerprint-specific paired evidence is added to matching GCP
secret DTOs. No global dedup behavior or other provider is changed.
"""
from copy import deepcopy
import json

CHECK_ID = 'gcp.review.function.literal_environment_secret_indicators'
FIELD = 'function_secret_pairs'


def _validated_pairs(finding):
    from peaso.checks import gcp_function_secret_paired_review_20261020 as consumer
    from peaso.collectors import gcp_function_secret_pairs_20261020 as producer
    if (finding.get('provider') != 'gcp' or finding.get('check_id') != CHECK_ID
            or finding.get('status') != 'FAIL'):
        return []
    evidence = finding.get('evidence')
    if (not isinstance(evidence, dict)
            or evidence.get('function_secret_projection_schema') != producer.SCHEMA
            or evidence.get('credential_validation') != 'not_attempted'):
        return []
    name = finding.get('native_resource_id') or finding.get('resource_id')
    scope = finding.get('scope')
    marker = {'schema': producer.SCHEMA, 'identity': name, 'scope': scope,
              'status': 'collected' if evidence.get('complete') is True else 'incomplete',
              'complete': evidence.get('complete'), 'verification': 'not_attempted',
              'surfaces': evidence.get('surfaces'), 'leaks': evidence.get('secret_leaks')}
    row = {'name': name, producer.MARKER: marker}
    index = {'context': {'provider': 'gcp', 'scope': scope}, 'collections': {'function': [
        {'scope': scope, 'status': 'collected', 'items': [row]}]}}
    if consumer._evaluate(row, index)[0] != 'FAIL':
        return []
    pairs = []
    for surface in marker['surfaces']:
        for leak in surface['leaks']:
            pairs.append({'schema': producer.SCHEMA, 'check_id': CHECK_ID,
                'scope': scope, 'resource_id': name, 'surface': surface['surface'],
                'complete': surface['complete'], 'engines': deepcopy(surface['engines']),
                'secret_leaks': [deepcopy(leak)]})
    return pairs


def retain_function_secret_pairs(pre_dedup_findings, final_findings):
    """Return final JSON findings with only matching, source-validated pairs."""
    # All-provider evaluations without this exact control remain byte-for-byte
    # semantically unchanged and do not require the GCP source guard.
    relevant = [finding for finding in pre_dedup_findings if isinstance(finding, dict)
                and finding.get('provider') == 'gcp' and finding.get('check_id') == CHECK_ID
                and finding.get('status') == 'FAIL']
    if not relevant:
        return final_findings
    by_fingerprint = {}
    for finding in relevant:
        for pair in _validated_pairs(finding):
            fingerprint = pair['secret_leaks'][0]['fingerprint']
            by_fingerprint.setdefault(fingerprint, []).append(pair)
    output = []
    for finding in final_findings:
        if (finding.get('provider') != 'gcp' or finding.get('status') != 'FAIL'
                or CHECK_ID not in finding.get('linked_check_ids', [])):
            output.append(finding)
            continue
        fingerprint = finding.get('secret_fingerprint')
        leaks = finding.get('evidence', {}).get('secret_leaks')
        if (not isinstance(leaks, list) or len(leaks) != 1
                or leaks[0].get('fingerprint') != fingerprint):
            output.append(finding)
            continue
        final_locations = leaks[0].get('locations', [])
        accepted = []
        for pair in by_fingerprint.get(fingerprint, []):
            # Attach only occurrences actually present in this final DTO. A
            # matching fingerprint alone cannot transplant an asset or scope.
            if all(dict(location, scope=pair['scope'], resource_id=pair['resource_id']) in final_locations
                   for location in pair['secret_leaks'][0]['locations']):
                accepted.append(pair)
        if not accepted:
            output.append(finding)
            continue
        row = deepcopy(finding)
        unique = {json.dumps(pair, sort_keys=True): pair for pair in accepted}
        row['evidence'][FIELD] = [unique[key] for key in sorted(unique)]
        # JSON serialization is the persistence contract; retain no tuples,
        # native objects, private source fields or other-fingerprint evidence.
        output.append(json.loads(json.dumps(row)))
    return output
