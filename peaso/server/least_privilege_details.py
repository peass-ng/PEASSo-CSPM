"""Read principal permission details from tenant-owned immutable inventory."""
from concurrent.futures import ThreadPoolExecutor
from peaso.least_privilege_permissions import enrich, permission_input_filter, with_aws_tracked_card_reviews


def resource_rows(artifacts, tenant, bundle, *, cards=None):
    provider = bundle.get('summary', bundle).get('provider')
    wanted = permission_input_filter(provider, cards)
    def select(rows):
        return [row for row in rows if wanted is None or wanted(row)]
    reference = bundle.get('least_privilege_permission_inputs')
    if wanted is not None and reference:
        # The compact input is bound to the same immutable scan publication.
        principal_ref = bundle.get('least_privilege')
        if (not isinstance(reference, str) or not isinstance(principal_ref, str)
                or reference.rsplit('/', 1)[0] != principal_ref.rsplit('/', 1)[0]):
            raise ValueError('Permission inputs escaped scan publication')
        value = artifacts.get(tenant, reference)
        if (not isinstance(value, dict) or value.get('provider') != provider
                or value.get('snapshot_id') != bundle.get('summary', bundle).get('snapshot_id')
                or not isinstance(value.get('items'), list)):
            raise ValueError('Permission inputs do not match snapshot')
        return select(value['items'])
    chunks = bundle.get('resource_chunks', [])
    if chunks:
        def read(chunk):
            # Discard unrelated large inventories before another native chunk
            # can finish. Keep only a bounded wave of decoded S3 responses live.
            return select(artifacts.get(tenant, chunk['reference'])['items'])
        rows = []
        with ThreadPoolExecutor(max_workers=min(8, len(chunks))) as pool:
            for start in range(0, len(chunks), 8):
                for group in pool.map(read, chunks[start:start + 8]):
                    rows.extend(group)
    else:
        rows = bundle.get('resources', [])
        if not rows and bundle.get('report_json'):
            rows = artifacts.get(tenant, bundle['report_json']).get('resources', [])
        rows = select(rows)
    return rows


def principal_detail(artifacts, tenant, bundle, card):
    summary = bundle.get('summary', bundle)
    provider = summary.get('provider', card.get('provider'))
    detail = enrich(card, provider, resource_rows(artifacts, tenant, bundle, cards=[card]), summary.get('created_at'))
    return with_aws_tracked_card_reviews(detail, detail['high_risk_permissions']) if provider == 'aws' else detail
