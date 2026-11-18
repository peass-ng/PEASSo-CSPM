"""Pure presentation for already-collected immutable-image vulnerability scans.

No credential, network, native registry, engine or analysis imports. Callers must
supply only observations belonging to the authenticated workspace and scan.
"""
from copy import deepcopy
from hashlib import sha256
import json
import re

SCHEMA = 'peaso-immutable-image-observations-v1'
MAX_OBSERVATIONS = 5000
MAX_VULNERABILITIES = 1000
MAX_ROWS = 5000
MAX_TOTAL_VULNERABILITIES = 20000
MAX_ASSETS_PER_ROW = 512
_DIGEST = re.compile(r'sha256:[0-9a-f]{64}\Z')
_SCOPE = re.compile(r'[A-Za-z0-9:/_.-]{1,512}\Z')
_REF = re.compile(r'[a-z0-9][a-z0-9.-]+(?::[0-9]+)?/[a-z0-9][a-z0-9/_.-]*@sha256:[0-9a-f]{64}\Z')
_TEXT = re.compile(r'[A-Za-z0-9@._:+/~%=-]{1,256}\Z')
_VULN = re.compile(r'(?:CVE-[0-9]{4}-[0-9]{4,}|GHSA-[a-z0-9-]{4,64}|[A-Z][A-Z0-9-]{1,120}-[0-9]{2,})\Z')
_FIX = re.compile(r'(?:[<>]=?|[~^]=?|=)?\s*[0-9][A-Za-z0-9.*+_:-]*(?:\s*(?:\|\||[<>]=?|[~^]=?|=)\s*[0-9][A-Za-z0-9.*+_:-]*)*\Z')
_FIX_STATUSES = {'unknown', 'not_affected', 'affected', 'fixed', 'under_investigation',
                 'will_not_fix', 'fix_deferred', 'end_of_life'}


def _string(value, pattern):
    if type(value) is not str or pattern.fullmatch(value) is None:
        raise ValueError('invalid_field')
    return value


def _asset(observation):
    asset = {'resource_id': observation['asset_id'], 'kind': observation['asset_kind']}
    if (type(asset['resource_id']) is not str or not 0 < len(asset['resource_id']) <= 2048 or
        any(ord(c) < 32 for c in asset['resource_id'])):
        raise ValueError('invalid_asset')
    _string(asset['kind'], _TEXT)
    if 'namespace' in observation:
        asset['namespace'] = _string(observation['namespace'], _TEXT)
    return asset


def _scan(observation):
    provider, scope = observation['provider'], _string(observation['scope'], _SCOPE)
    if provider not in ('aws', 'gcp', 'azure', 'k8s'):
        raise ValueError('invalid_provider')
    scan = observation['scan']
    if type(scan) is not dict or type(scan.get('image')) is not dict:
        raise ValueError('missing_image')
    image = scan['image']
    if set(image) != {'provider', 'scope', 'immutable_reference', 'manifest_digest', 'config_digest'}:
        raise ValueError('image_schema')
    digest = _string(image['manifest_digest'], _DIGEST)
    _string(image['config_digest'], _DIGEST)
    reference = _string(image['immutable_reference'], _REF)
    if (image['provider'] != provider or image['scope'] != scope or
        reference.rsplit('@', 1)[-1] != digest or
        any(p in ('', '.', '..') for p in reference.split('@')[0].split('/'))):
        raise ValueError('foreign_image')
    if (scan.get('status') not in ('PASS', 'FAIL', 'UNKNOWN') or
        type(scan.get('complete')) is not bool or type(scan.get('scan_complete')) is not bool or
        scan.get('coverage_status') not in ('COMPLETE', 'UNKNOWN') or
        type(scan.get('database')) is not dict or type(scan['database'].get('fresh')) is not bool):
        raise ValueError('invalid_scan_state')
    vulns = scan.get('findings')
    if type(vulns) is not list or len(vulns) > MAX_VULNERABILITIES:
        raise ValueError('invalid_vulnerabilities')
    if (scan['status'] == 'FAIL') != bool(vulns):
        raise ValueError('contradictory_scan_status')
    complete = (scan['complete'] is True and scan['scan_complete'] is True and
                scan['coverage_status'] == 'COMPLETE' and scan['database']['fresh'] is True)
    if (scan['status'] == 'PASS' and not complete or
        scan['status'] == 'UNKNOWN' and (scan['complete'] or vulns) or
        scan['complete'] and not complete):
        raise ValueError('contradictory_coverage')
    return provider, scope, image, vulns, complete


def _vulnerability(value, digest):
    required = {'vulnerability_id', 'severity', 'package_types', 'package', 'version',
                'fixed_in', 'fix_status', 'classes', 'image_digest'}
    if type(value) is not dict or set(value) != required or value.get('image_digest') != digest:
        raise ValueError('foreign_vulnerability')
    if value['severity'] not in ('HIGH', 'CRITICAL') or value['fix_status'] not in _FIX_STATUSES:
        raise ValueError('invalid_vulnerability_status')
    _string(value['vulnerability_id'], _VULN)
    _string(value['package'], _TEXT)
    _string(value['version'], _TEXT)
    for field in ('package_types', 'classes'):
        if type(value[field]) is not list or not 0 < len(value[field]) <= 128:
            raise ValueError('invalid_package_types')
    if any(c not in ('os-pkgs', 'lang-pkgs') for c in value['classes']):
        raise ValueError('invalid_package_classes')
    for package_type in value['package_types']:
        _string(package_type, _TEXT)
    fixes = value['fixed_in']
    if type(fixes) is not list or len(fixes) > 64:
        raise ValueError('invalid_fix_list')
    for fix in fixes:
        if type(fix) is not str or len(fix) > 256 or _FIX.fullmatch(fix) is None:
            raise ValueError('invalid_fix')
    return value


_REASON = re.compile(r'[a-z][a-z0-9_]{0,63}\Z')


def _reason(exc, default):
    """Bounded, code-only rejection reason; never echoes input values."""
    if type(exc) is ValueError and exc.args and type(exc.args[0]) is str and _REASON.fullmatch(exc.args[0]):
        return exc.args[0]
    return {KeyError: 'missing_field', TypeError: 'invalid_type'}.get(type(exc), default)


def rejected(reason):
    """Stored placeholder that keeps why an observation was withheld."""
    return {'rejected': reason if type(reason) is str and _REASON.fullmatch(reason) else 'invalid_observation'}


def _observation(observation):
    if observation is None:
        raise ValueError('missing_observation')
    if type(observation) is not dict:
        raise ValueError('invalid_observation')
    if set(observation) == {'rejected'}:
        raise ValueError(rejected(observation['rejected'])['rejected'])
    return (_asset(observation),) + _scan(observation)


def _count(counts, reason):
    counts[reason] = counts.get(reason, 0) + 1


def build_report(observations, *, selected=False):
    """Deduplicate identical image/package/version/advisory across asset references.

    Incomplete scans retain independently reported HIGH/CRITICAL positives. Empty
    output proves no selected finding only when every supplied scan is complete.
    This formatter never certifies provenance or that the image is running.
    ``invalid_reasons`` counts each unusable observation by reason code;
    ``missing_observation`` is a collector/storage gap (an unscanned target, an
    incomplete scope, or an observation withheld by an upstream validator).
    """
    report = {'rows': [], 'coverage': 'NOT_SCANNED', 'complete': False,
              'observations': 0, 'invalid_observations': 0, 'invalid_vulnerabilities': 0, 'truncated': False,
              'invalid_reasons': {}, 'invalid_vulnerability_reasons': {},
              'association': 'declared_or_selected_immutable_image'}
    if selected is not True:
        return report
    report['coverage'] = 'UNKNOWN'
    if type(observations) is not list or not observations:
        return report
    grouped, all_complete = {}, True
    if len(observations) > MAX_OBSERVATIONS:
        report['truncated'], all_complete = True, False
    count = 0
    for observation in observations[:MAX_OBSERVATIONS]:
        report['observations'] += 1
        try:
            asset, provider, scope, image, vulns, complete = _observation(observation)
        except (KeyError, TypeError, ValueError) as exc:
            _count(report['invalid_reasons'], _reason(exc, 'invalid_observation'))
            report['invalid_observations'] += 1
            all_complete = False
            continue
        all_complete = all_complete and complete
        for raw in vulns:
            count += 1
            if count > MAX_TOTAL_VULNERABILITIES:
                report['truncated'], all_complete = True, False
                break
            try:
                v = _vulnerability(raw, image['manifest_digest'])
            except (KeyError, TypeError, ValueError) as exc:
                _count(report['invalid_vulnerability_reasons'], _reason(exc, 'invalid_vulnerability'))
                report['invalid_vulnerabilities'] += 1
                all_complete = False
                continue
            key = (provider, scope, image['manifest_digest'], v['package'], v['version'], v['vulnerability_id'])
            if key not in grouped:
                if len(grouped) >= MAX_ROWS:
                    report['truncated'], all_complete = True, False
                    continue
                grouped[key] = {'id': sha256(json.dumps(key, separators=(',', ':')).encode()).hexdigest(),
                    'provider': provider, 'scope': scope, 'image_reference': image['immutable_reference'],
                    'image_digest': image['manifest_digest'], 'severity': v['severity'],
                    'vulnerability_id': v['vulnerability_id'], 'package': v['package'],
                    'installed_version': v['version'], 'fixed_versions': sorted(set(v['fixed_in'])),
                    'affected_assets': [], 'coverage': 'COMPLETE' if complete else 'UNKNOWN'}
            row = grouped[key]
            if v['severity'] == 'CRITICAL': row['severity'] = 'CRITICAL'
            if not complete: row['coverage'] = 'UNKNOWN'
            combined_fixes = sorted(set(row['fixed_versions']) | set(v['fixed_in']))
            if len(combined_fixes) > 64:
                report['truncated'], all_complete, row['coverage'] = True, False, 'UNKNOWN'
            row['fixed_versions'] = combined_fixes[:64]
            # Same bytes can have multiple registry aliases; make chosen label stable.
            row['image_reference'] = min(row['image_reference'], image['immutable_reference'])
            if asset not in row['affected_assets']:
                if len(row['affected_assets']) >= MAX_ASSETS_PER_ROW:
                    report['truncated'], all_complete, row['coverage'] = True, False, 'UNKNOWN'
                else:
                    row['affected_assets'].append(deepcopy(asset))
        if count > MAX_TOTAL_VULNERABILITIES:
            break
    for row in grouped.values():
        row['affected_assets'].sort(key=lambda asset: (asset['resource_id'], asset['kind'], asset.get('namespace', '')))
    report['rows'] = sorted(grouped.values(), key=lambda row: (
        0 if row['severity'] == 'CRITICAL' else 1, row['provider'], row['scope'],
        row['image_digest'], row['vulnerability_id'], row['package'], row['installed_version']))
    report.update(complete=all_complete, coverage='COMPLETE' if all_complete else 'UNKNOWN')
    return report
