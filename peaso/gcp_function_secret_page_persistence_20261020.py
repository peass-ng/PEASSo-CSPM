"""Retain source-bound Functions pairs, including intact reads in partial inventory.

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
    from peaso.checks import gcp_function_secret_partial_page_20261020 as consumer
    from peaso import gcp_function_secret_pair_persistence_20261020 as predecessor
    normalized = consumer.portable_source(finding)
    if normalized is None:
        return []
    pairs = predecessor._validated_pairs(normalized)
    if finding.get('evidence', {}).get('inventory_complete') is False:
        for pair in pairs:
            pair.update(inventory_complete=False, incomplete=True)
            pair['source_request'] = deepcopy(finding['evidence']['function_secret_native_read'])
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
        if any(pair.get('inventory_complete') is False for pair in accepted):
            row['evidence'].update(complete=False, incomplete=True, inventory_complete=False,
                inventory_status='partial', coverage='incomplete')
        # JSON serialization is the persistence contract; retain no tuples,
        # native objects, private source fields or other-fingerprint evidence.
        output.append(json.loads(json.dumps(row)))
    return output
