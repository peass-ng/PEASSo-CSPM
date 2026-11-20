"""Safe, structured summaries of captured image and secret findings."""
from collections import Counter, defaultdict

LEVELS = ('critical', 'high', 'medium')


def _text(value):
    return ' '.join(value.split()) if isinstance(value, str) else ''


def image_details(findings):
    groups = {}
    for finding in findings:
        evidence = finding.get('evidence') or {}
        image = evidence.get('Image')
        image = image if isinstance(image, dict) else {}
        digest = _text(evidence.get('image_digest') or image.get('manifest_digest'))
        scope = _text(finding.get('scope'))
        resource = _text(finding.get('native_resource_id') or finding.get('resource_id'))

        attached = False

        def group(asset, version):
            nonlocal attached
            attached = True
            return groups.setdefault((scope, asset, version), {'counts': {}, 'packages': {}, 'sources': set()})

        counts = evidence.get('severity_counts')
        if isinstance(counts, dict):
            entry = group(resource, digest)
            entry['sources'].add(finding['id'])
            normalized = {k.lower(): v for k, v in counts.items() if isinstance(k, str) and type(v) is int and v >= 0}
            for level in LEVELS:
                entry['counts'][level] = max(entry['counts'].get(level, 0), normalized.get(level, 0))
        rows = evidence.get('Vulnerabilities', evidence.get('vulnerabilities', []))
        for row in rows if isinstance(rows, list) else []:
            if not isinstance(row, dict):
                continue
            severity = _text(row.get('severity')).lower()
            if severity not in LEVELS:
                continue
            version = _text(row.get('image_digest')) or digest
            sources = row.get('affected_assets') or []
            assets = {_text(asset.get('resource_id')) for asset in sources if isinstance(asset, dict)} - {''}
            for asset in assets or {resource or _text(row.get('image_reference'))}:
                entry = group(asset, version)
                entry['sources'].add(finding['id'])
                key = (_text(row.get('vulnerability_id')), _text(row.get('package')),
                       _text(row.get('installed_version') or row.get('version')))
                previous = entry['packages'].get(key, severity)
                entry['packages'][key] = min(previous, severity, key=LEVELS.index)
        if not attached:
            group(resource, digest)['sources'].add(finding['id'])
    results = []
    for (scope, asset, digest), entry in sorted(groups.items()):
        counted = Counter(entry['packages'].values())
        counts = {}
        for level in LEVELS:
            if level in entry['counts'] or level in counted or level != 'medium' and entry['packages']:
                counts[level] = max(entry['counts'].get(level, 0), counted[level])
        results.append({'asset': asset, 'scope': scope, 'digest': digest, 'counts': counts,
                        'finding_ids': sorted(entry['sources'])})
    return results


def leak_details(findings):
    groups = defaultdict(lambda: {'locations': set(), 'detectors': set(), 'finding_ids': set(), 'assets': set()})
    for finding in findings:
        evidence = finding.get('evidence') or {}
        native = _text(finding.get('native_resource_id') or finding.get('resource_id'))
        if native.startswith('secret:'):
            native = ''
        records = evidence.get('secret_leaks') or [{}]
        for leak in records:
            fingerprint = _text(leak.get('fingerprint') or finding.get('secret_fingerprint')) or finding['id']
            scope = _text(finding.get('scope'))
            row = groups[fingerprint]
            row['finding_ids'].add(finding['id'])
            for detector in leak.get('detectors', []):
                rule = _text(detector.get('rule'))
                if rule:
                    row['detectors'].add(rule)
            for location in leak.get('locations') or [{}]:
                asset = _text(location.get('resource_id')) or native
                path = _text(location.get('path'))
                line = location.get('line')
                if path and type(line) is int and line > 0:
                    path += f':{line}'
                label = ' · '.join(dict.fromkeys(filter(None, (_text(location.get('scope')) or scope, asset, path))))
                if label:
                    row['locations'].add(label)
                if asset:
                    row['assets'].add(asset)
    return [dict({key: sorted(value) for key, value in row.items()}, label=f'Leak {index + 1}')
            for index, (_, row) in enumerate(sorted(groups.items()))]


def prose(kind, details):
    """Keep a short description; the complete rows are available in the issue."""
    if kind == 'image_cves':
        if not details:
            return ('Vulnerable packages in container images',
                    'The captured image scans reported vulnerable packages. Open the source findings for the affected image and advisory details.')
        title = 'Critical or high package vulnerabilities in container images' if any(
            row['counts'].get(level, 0) for row in details for level in ('critical', 'high')) else 'Vulnerable packages in container images'
        intro = ('Some container images include software with known security flaws. '
                 'The breakdown shows how many findings the scan reported for each image.')
        lines = []
        for row in details:
            counts = ', '.join(f"{row['counts'][level]} {level}" for level in LEVELS if row['counts'].get(level, 0) > 0)
            if counts:
                lines.append(f"- `{(row['asset'] or row['digest'] or row['scope'])[:180]}` · {counts}")
    else:
        title = 'Credentials and secrets found in scanned content'
        intro = ('The scan found plaintext values that matched credential or secret patterns. '
                 'Open the evidence for each match to see the value and where it appeared.')
        lines = [f"- **{row['label']}** · {(row['locations'][0] if row['locations'] else 'Location unavailable')[:220]}"
                 for row in details]
    preview = lines[:5]
    description = intro + ('\n\n' + '\n'.join(preview) if preview else '')
    if len(lines) > len(preview):
        description += f"\n\nSee the full breakdown for {len(lines) - len(preview)} additional entries."
    return title, description
