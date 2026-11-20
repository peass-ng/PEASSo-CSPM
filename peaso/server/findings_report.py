"""Bounded, tenant-owned compiled report presentation."""
def page(report, *, offset=0, limit=25, search='', severity='', exclusion_offset=0):
    term = search.casefold().strip()
    rows = [row for row in report.get('issues', []) if
            (not severity or row['severity'] == severity) and
            (not term or term in ' '.join(str(row.get(key, '')) for key in
                ('title', 'description', 'impact', 'recommendation', 'verification', 'kind')).casefold())]
    exclusions = report.get('exclusions', [])
    return dict(report, issues=rows[offset:offset + limit], total=len(rows),
                exclusions=exclusions[exclusion_offset:exclusion_offset + limit], exclusion_count=len(exclusions),
                offset=offset, limit=limit)
