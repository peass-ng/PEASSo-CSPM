"""One finding per secret, independent of detector/check/asset.

Found values are shown in clear text so the tenant can rotate them.
"""
from copy import deepcopy
import re
from .secret_scanning import FOUND_VALUE_FIELDS, merge_leaks


def _secret_location_resource(finding):
    """Keep the ECR evaluator's bound image identity through secret grouping."""
    native = finding.get('native_resource_id') or finding['resource_id']
    if finding.get('check_id') != 'aws.review.ecr_repository.package_content_secret_indicators':
        return native
    source = finding.get('evidence', {}).get('resource_id')
    if (isinstance(native, str) and isinstance(source, str)
            and re.fullmatch(re.escape(native) + r'@sha256:[0-9a-f]{64}', source)):
        return source
    return native


def _observed(evidence):
    leak = evidence['secret_leaks'][0]
    text = 'The same secret was detected in %d scanned location(s).' % len(leak['locations'])
    if 'value' in leak:
        text += ' Its matched value is shown in clear text so it can be rotated'
        text += ' (first %d characters).' % len(leak['value']) if leak.get('value_truncated') else '.'
    else:
        text += ' This scan did not retain its matched value.'
    if evidence.get('complete') is False:
        text += ' Coverage is incomplete.'
    return text


def deduplicate_secret_findings(findings, secret_values=None):
    """Group FAIL findings by found value.

    ``secret_values`` maps a fingerprint to its clear-text ``value`` (and
    ``value_truncated``/``context``), as the collecting scan published it.
    """
    secret_values = secret_values or {}
    output, grouped = [], {}
    for finding in findings:
        evidence = finding.get('evidence', {})
        leaks = evidence.get('secret_leaks') if isinstance(evidence, dict) else None
        if finding.get('status') != 'FAIL' or not isinstance(leaks, list) or not leaks:
            output.append(finding)
            continue
        try:
            merged = merge_leaks(leaks)
        except (KeyError, TypeError, ValueError):
            output.append(dict(finding, status='UNKNOWN', evidence={
                'observed': 'Secret detector evidence is malformed; this result could not be assessed.'}))
            continue
        for leak in merged:
            key = (finding['provider'], leak['fingerprint'])
            row = grouped.get(key)
            locations = [dict(loc, resource_id=_secret_location_resource(finding),
                              scope=finding['scope']) for loc in leak['locations']]
            found = dict(leak, locations=locations)
            known = secret_values.get(leak['fingerprint']) or {}
            found.update({field: known[field] for field in FOUND_VALUE_FIELDS if field in known})
            if row is None:
                row = deepcopy(finding)
                row.update(id='secret-' + leak['fingerprint'], secret_fingerprint=leak['fingerprint'],
                           title='Exposed secret in scanned content', linked_check_ids=[],
                           resource_id='secret:' + leak['fingerprint'],
                           resource_name='Exposed secret')
                row.pop('native_resource_id', None)
                row['evidence'] = {'secret_leaks': [], 'credential_validation': 'not_attempted'}
                grouped[key] = row
            row['evidence']['secret_leaks'] = merge_leaks(row['evidence']['secret_leaks'] + [found])
            if evidence.get('complete') is False:
                # A trusted positive is still decisive when another detector
                # could not finish. Grouping must preserve that coverage limit.
                row['evidence']['complete'] = False
                row['evidence']['coverage'] = 'incomplete'
            row['frameworks'] = sorted(set(row.get('frameworks', [])) | set(finding.get('frameworks', [])))
            row['linked_check_ids'] = sorted(set(row['linked_check_ids']) | {finding['check_id']})
            row['evidence']['observed'] = _observed(row['evidence'])
            row['evidence_summary'] = row['evidence']['observed']
    return output + [grouped[key] for key in sorted(grouped)]
