"""Tenant/scan-scoped, bounded API presentation for optional image observations."""
from copy import deepcopy
import json
from fastapi import Depends, HTTPException, Query

from peaso.image_findings import build_report, SCHEMA

MAX_PAGE_BYTES = 1_000_000


def page_report(report, offset, limit):
    page = {key: deepcopy(value) for key, value in report.items() if key != 'rows'}
    page.update(rows=[], total=len(report['rows']), offset=offset, next_offset=None,
                vulnerability_count=len({row['vulnerability_id'] for row in report['rows']}),
                image_count=len({(row['provider'], row['scope'], row['image_digest']) for row in report['rows']}))
    for row in report['rows'][offset:offset + limit]:
        item = deepcopy(row)
        assets = item['affected_assets']
        item.update(affected_asset_count=len(assets), affected_assets=assets[:10],
                    assets_truncated=len(assets) > 10)
        candidate = dict(page, rows=page['rows'] + [item])
        if len(json.dumps(candidate, separators=(',', ':'), ensure_ascii=True).encode()) > MAX_PAGE_BYTES - 64:
            break
        page['rows'].append(item)
    consumed = offset + len(page['rows'])
    if consumed < len(report['rows']):
        page['next_offset'] = consumed
    return page


def install_routes(app, *, identity, owned_bundle, artifacts):
    """Reuse existing workspace authorization before reading any image artifact."""
    def report_for(tenant, ident):
        from peaso.storage.artifacts import job_prefix, check_reference
        _, bundle = owned_bundle(tenant, ident)
        metadata = bundle.get('image_vulnerability_scan')
        if metadata is None:
            return build_report([], selected=False)
        if type(metadata) is not dict or metadata.get('selected') is not True:
            return build_report([], selected=False)
        reference = metadata.get('artifact')
        if not isinstance(reference, str) or not reference.startswith(job_prefix(tenant, ident)):
            raise HTTPException(409, 'Image evidence is unavailable for this scan')
        try:
            check_reference(tenant, reference)
        except ValueError:
            raise HTTPException(409, 'Image evidence is unavailable for this scan') from None
        value = artifacts.get(tenant, reference)
        if (type(value) is not dict or value.get('schema') != SCHEMA or
            value.get('scan_id') != ident or type(value.get('observations')) is not list):
            raise HTTPException(409, 'Image evidence is unavailable for this scan')
        return build_report(value['observations'], selected=True)

    @app.get('/api/scans/{ident}/exposed-containers')
    def exposed_containers(ident: str, image_scan_id: str | None = None,
                           offset: int = Query(default=0, ge=0), limit: int = Query(default=20, ge=1, le=50),
                           user=Depends(identity)):
        from peaso.ai.special_report_details import running_images
        from peaso.container_exposure import RESOURCE_TYPES, enrich_runtime
        from peaso.snapshot import resources
        from peaso.storage.artifacts import check_reference, job_prefix
        from collections import defaultdict

        tenant = user.tenant_id
        row, bundle = owned_bundle(tenant, ident)
        images = report_for(tenant, image_scan_id or ident)
        snapshot_ref = row.get('snapshot')
        result = {'items': [], 'total': 0, 'next_offset': None, 'image_coverage': images['coverage'],
                  'image_findings_present': bool(images['rows']), 'workload_evidence_available': False}
        if not images['rows'] or row['status'] != 'completed' or not isinstance(snapshot_ref, str):
            return result
        if not snapshot_ref.startswith(job_prefix(tenant, ident)):
            raise HTTPException(409, 'Workload evidence is unavailable for this scan')
        try:
            check_reference(tenant, snapshot_ref)
        except ValueError:
            raise HTTPException(409, 'Workload evidence is unavailable for this scan') from None
        snapshot = artifacts.get(tenant, snapshot_ref)
        inventory = resources(dict(snapshot, collections=[
            collection for collection in snapshot['collections'] if collection['type'] in RESOURCE_TYPES
        ]))
        runtime = running_images(inventory)
        if not runtime:
            return result
        result['workload_evidence_available'] = True
        report = artifacts.get(tenant, bundle['report_json']) if bundle.get('bundle_version') == 1 else bundle
        counts = defaultdict(lambda: {'HIGH': set(), 'CRITICAL': set()})
        for cve in images['rows']:
            key = (cve['vulnerability_id'], cve['package'], cve['installed_version'])
            counts[cve['image_digest']][cve['severity']].add(key)
        matches = []
        for running in enrich_runtime(runtime, inventory, report.get('findings', ())):
            digest = running['digest']
            if not running.get('exposure_routes') or digest not in counts:
                continue
            high, critical = counts[digest]['HIGH'], counts[digest]['CRITICAL']
            matches.append({**running, 'counts': {'critical': len(critical), 'high': len(high - critical)}})
        end = offset + limit
        return dict(result, items=matches[offset:end], total=len(matches),
                    next_offset=end if end < len(matches) else None)

    @app.get('/api/scans/{ident}/image-findings')
    def image_findings(ident: str, offset: int = Query(default=0, ge=0),
                       limit: int = Query(default=100, ge=1, le=100),
                       image_digest: str | None = None, user=Depends(identity)):
        report = report_for(user.tenant_id, ident)
        if image_digest:
            report = dict(report, rows=[row for row in report['rows'] if row['image_digest'] == image_digest])
        return page_report(report, offset, limit)

    @app.get('/api/scans/{ident}/image-findings/{finding_id}/assets')
    def image_assets(ident: str, finding_id: str, offset: int = Query(default=0, ge=0),
                     limit: int = Query(default=50, ge=1, le=50), user=Depends(identity)):
        report = report_for(user.tenant_id, ident)
        row = next((row for row in report['rows'] if row['id'] == finding_id), None)
        if row is None:
            raise HTTPException(404, 'Image finding not found')
        assets = row['affected_assets']
        selected = assets[offset:offset + limit]
        consumed = offset + len(selected)
        return {'items': selected, 'total': len(assets), 'offset': offset,
                'next_offset': consumed if consumed < len(assets) else None,
                'coverage': row['coverage']}
