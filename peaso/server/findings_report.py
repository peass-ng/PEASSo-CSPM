"""Bounded, tenant-owned compiled report presentation."""
from peaso.report_asset_ids import guardduty_detector_arn, is_detector_id


def detector_asset_ids(issues):
    return {asset for issue in issues for asset in issue.get('affected_assets', ()) if is_detector_id(asset)}


def resolve_detector_assets(issues, findings, wanted):
    """Resolve archived asset IDs only when the source scope identifies one detector."""
    from collections import defaultdict
    matches = defaultdict(set)
    for row in findings:
        native_id = row.get('native_resource_id') or row.get('resource_id')
        if native_id in wanted and (arn := guardduty_detector_arn(native_id, row)):
            matches[native_id].add(arn)
    replacements = {ident: next(iter(arns)) for ident, arns in matches.items() if len(arns) == 1}
    return [
        dict(issue, affected_assets=sorted({replacements.get(asset, asset) for asset in issue['affected_assets']}))
        if replacements.keys() & set(issue.get('affected_assets', ())) else issue
        for issue in issues
    ]


def page(report, *, offset=0, limit=25, search='', severity='', exclusion_offset=0):
    term = search.casefold().strip()
    rows = [row for row in report.get('issues', []) if
            (not severity or row['severity'] == severity) and
            (not term or term in ' '.join(str(row.get(key, '')) for key in
                ('title', 'description', 'impact', 'recommendation', 'verification', 'kind')).casefold())]
    exclusions = report.get('exclusions', [])
    public = {key: value for key, value in report.items() if key != 'running_images'}
    return dict(public, issues=rows[offset:offset + limit], total=len(rows),
                exclusions=exclusions[exclusion_offset:exclusion_offset + limit], exclusion_count=len(exclusions),
                offset=offset, limit=limit)
