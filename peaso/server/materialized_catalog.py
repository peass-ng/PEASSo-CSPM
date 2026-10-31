"""Materialized API metadata; never import or execute native scan code.

Full metadata uses offset/limit pagination (1..500 checks, default 100). Each
page and individual check detail is capped at 4 MiB of UTF-8 JSON. next_offset
is authoritative when the byte cap returns fewer than the requested limit.
"""
from copy import deepcopy
from functools import lru_cache
import gzip
import hashlib
import io
import json
from pathlib import Path
import zlib

from fastapi import HTTPException, Response

ROOT = Path(__file__).resolve().parents[1]
PACK = ROOT / 'rulepacks'
MAX_WIRE_BYTES = 4 * 1024 * 1024
MAX_ENVELOPE_BYTES = 6 * 1024 * 1024
MAX_COMPRESSED_BYTES = 8 * 1024 * 1024
MAX_DOCUMENT_BYTES = 48 * 1024 * 1024
MAX_LIMIT = 500
def _encoded(value):
    return json.dumps(value, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode()


def wire_fits(body):
    # Lambda serializes the JSON response body again inside its return envelope.
    # Reserve 16 KiB for Mangum status/headers, including middleware headers.
    return (len(body) <= MAX_WIRE_BYTES
            and len(json.dumps(body.decode(), ensure_ascii=True).encode()) + 16384 <= MAX_ENVELOPE_BYTES)


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError('duplicate catalog key')
        result[key] = value
    return result


def _json(raw):
    return json.loads(raw, object_pairs_hook=_pairs,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError('nonfinite catalog value')))


def _unavailable():
    return HTTPException(503, 'Materialized catalog unavailable; rebuild the API catalog')


@lru_cache(maxsize=1)
def _load():
    try:
        path = PACK / 'api_catalog.json.gz'
        if not 0 < path.stat().st_size <= MAX_COMPRESSED_BYTES:
            raise ValueError('compressed catalog budget')
        with path.open('rb') as stream:
            raw = stream.read(MAX_COMPRESSED_BYTES + 1)
        if len(raw) > MAX_COMPRESSED_BYTES:
            raise ValueError('compressed catalog budget')
        with gzip.GzipFile(fileobj=io.BytesIO(raw)) as stream:
            document = stream.read(MAX_DOCUMENT_BYTES + 1)
        if len(document) > MAX_DOCUMENT_BYTES:
            raise ValueError('catalog document budget')
        value = _json(document)
        if value['schema_version'] != 1:
            raise ValueError('catalog envelope schema')
        full = value['full']
        checks = full['checks']
        if not isinstance(checks, list) or not 0 < len(checks) <= 20000:
            raise ValueError('catalog checks budget')
        ids = [row['id'] for row in checks]
        if len(ids) != len(set(ids)) or any(not isinstance(cid, str) for cid in ids):
            raise ValueError('catalog check identities')
        providers = full['providers']
        if set(value['selectors']) != set(providers) or set(providers) != {'aws', 'azure', 'gcp', 'k8s'}:
            raise ValueError('catalog providers')
        for provider, index in value['selectors'].items():
            if set(index) != {'categories', 'checks', 'frameworks'}:
                raise ValueError('selector schema')
            for entries in index.values():
                if (not isinstance(entries, list) or len(entries) > 20000
                        or any(not isinstance(entry, str) or len(entry) > 4096 for entry in entries)
                        or len(entries) != len(set(entries))):
                    raise ValueError('selector values')
        if ([row['id'] for row in value['summary']['checks']] != ids
                or value['summary']['view'] != 'summary' or value['frameworks']['view'] != 'frameworks'
                or value['summary']['privesc_catalog'] != full['privesc_catalog']):
            raise ValueError('catalog view parity')
        if any(not wire_fits(_encoded(value[name])) for name in ('summary', 'frameworks')):
            raise ValueError('compact catalog wire budget')
        if not isinstance(full['privesc_catalog'], dict):
            raise ValueError('privilege catalog binding schema')
        if (not isinstance(value['descriptions'], dict)
                or not isinstance(value['framework_expansion'], dict)
                or not isinstance(value['framework_display'], dict)
                or not isinstance(value['framework_aliases'], dict)):
            raise ValueError('reviewed presentation lookup schema')
        aliases = value.get('remediation_aliases')
        if (not isinstance(aliases, dict) or len(aliases) > 1000
                or any(not isinstance(cid, str) or cid not in value['descriptions']
                       or not isinstance(row, dict) or row.get('review_status') != 'approved'
                       for cid, row in aliases.items())):
            raise ValueError('archived remediation alias schema')
        kinds = value['native_kinds']
        if (not isinstance(kinds, dict) or not 0 < len(kinds) <= 20000
                or any(not isinstance(cid, str) or cid not in value['descriptions']
                       or not isinstance(pair, list) or len(pair) != 2
                       or pair[0] not in providers
                       or not isinstance(pair[1], str) or not 0 < len(pair[1]) <= 256
                       for cid, pair in kinds.items())):
            raise ValueError('native service kind schema')
        value['_native_kinds'] = {cid: tuple(pair) for cid, pair in kinds.items()}
        value['_by_id'] = dict(zip(ids, checks))
        value['_selector_sets'] = {provider: {key: frozenset(entries) for key, entries in index.items()}
                                   for provider, index in value['selectors'].items()}
        return value
    except (OSError, ValueError, TypeError, KeyError, AttributeError, EOFError, zlib.error):
        raise _unavailable() from None


def summary():
    return deepcopy(_load()['summary'])


def frameworks_view():
    return deepcopy(_load()['frameworks'])


def full_page(offset=0, limit=100):
    if type(offset) is not int or type(limit) is not int or offset < 0 or not 1 <= limit <= MAX_LIMIT:
        raise HTTPException(422, 'Invalid catalog pagination')
    full = _load()['full']
    total = len(full['checks'])
    if offset > total:
        raise HTTPException(422, 'Catalog offset exceeds total')
    result = {key: value for key, value in full.items() if key != 'checks'}
    result.update(checks=[], pagination={'offset': offset, 'limit': limit, 'returned': 0,
                                         'total': total, 'next_offset': None})
    used = len(_encoded(result)) + 256
    if used > MAX_WIRE_BYTES:
        raise _unavailable()
    for row in full['checks'][offset:offset + limit]:
        size = len(_encoded(row)) + 1
        if used + size > MAX_WIRE_BYTES:
            break
        result['checks'].append(row)
        used += size
    while result['checks'] and not wire_fits(_encoded(result)):
        result['checks'].pop()
    count = len(result['checks'])
    if count == 0 and offset < total:
        raise _unavailable()
    result['pagination'].update(returned=count, next_offset=offset + count if offset + count < total else None)
    if not wire_fits(_encoded(result)):
        raise _unavailable()
    return deepcopy(result)


def check_detail(check_id):
    row = _load()['_by_id'].get(check_id)
    if row is None:
        raise HTTPException(404, 'Unknown catalog check')
    if not wire_fits(_encoded(row)):
        raise _unavailable()
    return deepcopy(row)


def validate_selectors(request, provider):
    index = _load()['_selector_sets'].get(provider)
    if index is None:
        raise HTTPException(422, 'Unknown scan provider')
    if any(value not in index['categories'] for value in request.get('categories', [])):
        raise HTTPException(422, 'Unsupported scan category')
    if any(value not in index['checks'] for value in request.get('checks', [])):
        raise HTTPException(422, 'Unknown check for selected provider')
    if any(value not in index['frameworks'] and str(value).lower() not in index['frameworks']
           for value in request.get('frameworks', [])):
        raise HTTPException(422, 'Unsupported framework')


def bounded_response(request, value):
    body = _encoded(value)
    if not wire_fits(body):
        raise _unavailable()
    etag = '"' + hashlib.sha256(body).hexdigest()[:32] + '"'
    headers = {'ETag': etag, 'Cache-Control': 'private, no-cache'}
    if etag in {tag.strip() for tag in request.headers.get('if-none-match', '').split(',')}:
        return Response(status_code=304, headers=headers)
    return Response(body, media_type='application/json', headers=headers)


def description_for(check_id):
    """Exact build-time reviewed prose, including archived known checks."""
    return deepcopy(_load()['descriptions'].get(check_id))


def framework_aliases():
    return dict(_load()['framework_aliases'])


def expand_framework_selectors(values):
    value = _load()
    expanded = set(values)
    for selector in values:
        for framework_id in value['framework_expansion'].get(str(selector).lower(), ()):
            expanded.add(framework_id)
            expanded.add(value['framework_display'][framework_id])
    return expanded


def native_kinds():
    """Exact build-time registrar kinds, including archived native checks."""
    return dict(_load()['_native_kinds'])


def install_service_kinds():
    from peaso import check_services
    check_services._check_kinds = native_kinds


def finding_service(finding):
    from .service_labels_static_20261020 import finding_service as service_for_finding
    return service_for_finding(finding)

_GCP_CLOUDSQL_CORRECTED_TEMPLATE = {'review_status': 'approved', 'summary': "Establish the full in-scope authentication-account inventory and approved lockout or rate-limiting controls. For supported managed MySQL built-in accounts, review instance password-policy enablement and each user's passwordPolicy.enableFailedAttemptsCheck and positive allowedFailedAttempts; verify other authentication paths separately without inferring a violation from missing metadata.", 'steps': ['Bind the complete in-scope customer login-account universe and each authentication path.', 'Review documented managed user lockout policies and independent rate limiting for unsupported paths.'], 'caveats': ['API-visible user policy is configuration evidence, not complete principal scope or an observed login test.'], 'references': [{'title': 'Cloud SQL user password policy API', 'url': 'https://docs.cloud.google.com/sql/docs/mysql/admin-api/rest/v1beta4/users'}], 'source_correction': {'version': 'peaso-source-correction-v1', 'status': 'source_erratum_successor', 'prior_frozen_signed_spec_sha256': 'e8a00a7a5e39d325f24a58ee7d6d5068554e680193c1447bdc3e803ed686f6ef', 'prior_frozen_status': 'historical_superseded_for_this_check', 'current_canonical_spec_sha256': '7f007ab89daf6fcd67916ec56fdd29b35aff32d0770f3317d33c809e83a16c1d', 'current_predicate_sha256': '057392fce746b44c8ea9af339e86aae1899e0270808f050e7a3dfb0eac0eb8f5', 'source_url': 'https://docs.cloud.google.com/sql/docs/mysql/admin-api/rest/v1beta4/users', 'framework_id': 'ccc_gcp', 'requirement_ids': ['CCC.RDMS.CN02.AR01'], 'original_requirement': 'When repeated failed login attempts are made in a short timeframe, the account must be locked out or rate-limited to prevent further login attempts.', 'criterion_scope': 'Original account lockout or rate limiting: configured PASS is limited to the explicitly approved customer-account boundary, exactly matched to the complete API-visible roster; native witness alone does not establish that boundary or provider-internal/runtime protection'}}
_AZURE_SSH_WRONG_PROVIDER_FALLBACK = {'caveats': ['This corrected historical source profile prefers no bootstrap keys; key presence is not a vulnerability or a guest-runtime observation.'], 'cli': [], 'field_binding': {'fields': ['Complete paged Microsoft.Compute/virtualMachines GET and instanceView: properties.storageProfile.osDisk.osType, properties.osProfile.linuxConfiguration.ssh.publicKeys[] and PowerState status.', 'Complete scoped vm inventory and explicit ssh.publicKeys array'], 'kind': 'vm', 'target': 'resource'}, 'references': [{'title': 'Azure VM SSH keys', 'url': 'https://learn.microsoft.com/azure/virtual-machines/linux/ssh-from-windows'}], 'review_status': 'approved', 'steps': ['Review the configured bootstrap public keys under this legacy profile; preserve a working administrative access method.'], 'summary': 'Review the configured bootstrap public keys under this legacy profile; preserve a working administrative access method.'}


@lru_cache(maxsize=1)
def _archived_remediation_rows():
    value = _load()
    path = PACK / 'native_catalog.json'
    try:
        document = _json(path.read_bytes())
        rows = document['archived_checks']
        if not isinstance(rows, list) or len(rows) > 20000:
            raise ValueError('archived remediation rows')
        result = {row['id']: row for row in rows}
        if len(result) != len(rows):
            raise ValueError('duplicate archived remediation ID')
        if set(result) != set(value['native_kinds']) - set(value['_by_id']):
            raise ValueError('archived remediation universe')
        return result
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        raise _unavailable() from None


@lru_cache(maxsize=1)
def _analysis_remediation_rules():
    path = PACK / 'remediation_curated.json'
    try:
        if path.stat().st_size > 16 * 1024 * 1024:
            raise ValueError('analysis remediation budget')
        document = _json(path.read_bytes())
        if not isinstance(document, dict):
            raise ValueError('analysis remediation schema')
        return {key: value for key, value in document.items() if key.startswith('analysis.')}
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        raise _unavailable() from None


def template_for(check_id, provider=None):
    """Native-free approved template for current finding presentation.

    The catalog's remediation_details are the exact build-time `details_for`
    projection. `review_status` is restored solely for the pure presentation
    validator. Historical report details and commands remain archived in the
    report and are never replaced by this lookup.
    """
    if not isinstance(check_id, str):
        return None
    value = _load()
    if check_id == 'gcp_cloudsql_failed_attempts_lockout':
        return deepcopy(_GCP_CLOUDSQL_CORRECTED_TEMPLATE) if provider in (None, 'gcp') else None
    if check_id == 'azure_vm_8_2_1_1_712e1ad' and provider not in (None, 'azure'):
        return deepcopy(_AZURE_SSH_WRONG_PROVIDER_FALLBACK)
    if check_id.startswith('analysis.'):
        rules = _analysis_remediation_rules()
        candidate = rules.get(check_id + '@' + provider) if provider else None
        if candidate is None:
            candidate = rules.get(check_id)
        return deepcopy(candidate) if isinstance(candidate, dict) and candidate.get('review_status') == 'approved' else None
    row = value['_by_id'].get(check_id)
    if row is None and check_id in value['native_kinds']:
        row = _archived_remediation_rows().get(check_id)
    if row is None:
        alias = value.get('remediation_aliases', {}).get(check_id)
        if isinstance(alias, dict) and alias.get('review_status') == 'approved':
            return deepcopy(alias)
    details = row.get('remediation_details') if isinstance(row, dict) else None
    if not isinstance(details, dict):
        return None
    return {'review_status': 'approved', **deepcopy(details)}
