"""One bounded registry transaction for the four provider candidates.

The caller supplies the already loaded native modules. This module does not
authorize collection.
"""
from copy import deepcopy
from dataclasses import replace
from functools import wraps
from pathlib import Path
import json
import re
from urllib.parse import urlsplit

STORAGE = 'azure_storage_account_10_3_4_7_02943e9'
RUNTIME = 'azure.review.app_service.runtime_support_declared'
GCP = 'gcp.review.cloud_run.selected_job_image_vulnerabilities'
AWS = 'aws.review.ecr.selected_image_vulnerabilities'
IDS = (STORAGE, RUNTIME, GCP, AWS)
NEW_DESCRIPTIONS = {
    RUNTIME: {
        'description': 'For a selected Linux App Service web app, compares its exact declared linuxFxVersion with complete regional Microsoft.Web webAppStacks lifecycle metadata. It does not test the running process, application compatibility, or patch level.',
        'evaluated': ['Microsoft.Web/sites GET kind/properties.reserved', 'Microsoft.Web/sites/config/web GET properties.linuxFxVersion', 'regional Microsoft.Web/locations/webAppStacks GET pages and lifecycle flags'],
        'pass_when': 'Exactly one matching, non-preview runtime explicitly declares isDeprecated=false and has no past endOfLifeDate after complete native reads.',
        'fail_when': 'The exact matching runtime is explicitly deprecated or past its endOfLifeDate.',
        'not_applicable_when': None,
    },
    GCP: {
        'description': 'For an explicitly selected Cloud Run Job desired immutable image digest, reviews a complete fresh offline image scan for HIGH or CRITICAL vulnerability findings. This does not prove that the image executed or that the running workload is vulnerable.',
        'evaluated': ['selected Cloud Run Job declared immutable image digest', 'read-only native image descriptor and blob receipts', 'fresh offline Trivy HIGH/CRITICAL findings and scan coverage'],
        'pass_when': 'A complete, fresh, exact-digest scan has no HIGH or CRITICAL findings and all native source receipts are bound.',
        'fail_when': 'A bound selected immutable image scan reports at least one typed HIGH or CRITICAL finding.',
        'not_applicable_when': None,
    },
}
def _default_cases():
    """Read the three captured reproduction cases."""
    cases = json.loads(Path(__file__).with_name('provider_group_native_cases_20261021.json').read_bytes())
    if type(cases) is not dict or set(cases) != {RUNTIME, GCP, AWS}:
        raise RuntimeError('provider group default native fixture IDs changed')
    return cases


def deployed_sources(root):
    """Kept for the registry call site; installed sources are no longer pinned."""
    return None


def _preflight(checks, storage, runtime, gcp, aws):
    from peaso.checks import CHECK_ALIASES
    from peaso.checks.fixtures import CASES
    if aws.DECLARATION.get('id') != AWS or aws.DECLARATION.get('provider') != 'aws':
        raise RuntimeError('provider group AWS declaration changed')
    if storage.CHECK_ID != STORAGE or runtime.support.CHECK_ID != RUNTIME:
        raise RuntimeError('provider group Azure check ID changed')
    if len([c for c in checks if c.id == STORAGE]) != 1:
        raise RuntimeError('provider group requires one SW23 predecessor')
    if any(c.id in (RUNTIME, GCP, AWS) for c in checks) or any(cid in CHECK_ALIASES for cid in IDS):
        raise RuntimeError('provider group ID already registered or aliased')
    if any(cid in CASES for cid in (RUNTIME, GCP, AWS)):
        raise RuntimeError('provider group fixture ID already present')
    old = next(c for c in checks if c.id == STORAGE)
    if old.declared_dependencies != ('storage_account', 'storage_immutability_evidence'):
        raise RuntimeError('provider group predecessor dependencies changed')
    return old


def _runtime_evaluate(item, index, native):
    """Evaluate only a selected native read receipt; no HTTP call here."""
    context = index.get('context') if isinstance(index, dict) else None
    if (not isinstance(item, dict) or not isinstance(context, dict) or
            context.get('provider') != 'azure' or type(context.get('scope')) is not str):
        return 'UNKNOWN', {'reason': 'selected native runtime scope unavailable'}
    receipt = item.get('runtime_support_native')
    if not isinstance(receipt, dict) or receipt.get('schema') != native.SCHEMA or receipt.get('check_id') != RUNTIME:
        return 'UNKNOWN', {'reason': 'selected native runtime receipt unavailable'}
    if receipt.get('asset_id') != item.get('id') or receipt.get('scope') != context['scope']:
        return 'UNKNOWN', {'reason': 'native runtime receipt identity unresolved'}
    reads = receipt.get('source_requests')
    if not isinstance(reads, list) or not 3 <= len(reads) <= 2 + native.bounds.MAX_PAGES or any(
            not isinstance(r, dict) or r.get('method') != 'GET' or
            r.get('status') != 'collected' or r.get('read_only') is not True or
            r.get('scope') != receipt['scope'] or
            re.fullmatch('[0-9a-f]{64}', str(r.get('projection_sha256'))) is None
            for r in reads):
        return 'UNKNOWN', {'reason': 'native HTTP read provenance incomplete'}
    if (reads[0].get('operation') != 'site' or
            reads[0].get('url') != native.bounds._url(item['id']) or
            reads[1].get('operation') != 'config' or
            reads[1].get('url') != native.bounds._url(item['id'] + '/config/web') or
            any(r.get('operation') != 'regional_web_app_stacks' or r.get('page') != page or
                re.fullmatch('/providers/Microsoft.Web/locations/[a-z0-9]+/webAppStacks',
                    urlsplit(str(r.get('url'))).path, re.I) is None or
                not native.bounds._valid_url(r.get('url'), urlsplit(str(r.get('url'))).path,
                                             continuation=page > 1)
                for page, r in enumerate(reads[2:], 1))):
        return 'UNKNOWN', {'reason': 'native HTTP route provenance incomplete'}
    status = receipt.get('status')
    if status not in ('PASS', 'FAIL') or receipt.get('complete') is not True:
        return 'UNKNOWN', {'reason': receipt.get('reason') or 'native runtime read unresolved'}
    if type(receipt.get('runtime')) is not str or native._RUNTIME.fullmatch(receipt['runtime']) is None:
        return 'UNKNOWN', {'reason': 'native runtime declaration unresolved'}
    if type(receipt.get('evidence')) is not str or not receipt['evidence']:
        return 'UNKNOWN', {'reason': 'native runtime lifecycle witness missing'}
    # The native reviewer emits a fixed PASS/FAIL explanation. A marker status
    # without the corresponding lifecycle explanation cannot certify anything.
    lifecycle = {
        'PASS': ('not deprecated and any stated end of life date is in the future. '
                 'Its patch level and application compatibility were not tested.'),
        'FAIL': ('deprecated or past its stated end of life date. '
                 'This is provider lifecycle evidence, not an application compatibility test.'),
    }
    expected = ('The Linux web app declares ' + receipt['runtime'] +
                '; its exact regional stack is ' + lifecycle[status])
    if receipt['evidence'] != expected:
        return 'UNKNOWN', {'reason': 'native runtime status and lifecycle witness disagree'}
    return status, {'runtime': receipt['runtime'], 'lifecycle': receipt['evidence'],
                    'source_requests': deepcopy(reads), 'read_only': True}


def _gcp_evaluate(item, index, native):
    """Bind a collected Job row to the selected scope and native read ledger."""
    try:
        if not isinstance(item, dict) or not isinstance(index, dict):
            raise ValueError('native Job row missing')
        context = index['context']
        metadata = context['metadata']
        scope = context['scope']
        if not isinstance(context, dict) or not isinstance(metadata, dict) or context['provider'] != 'gcp' or type(scope) is not str:
            raise ValueError('foreign Job scope')
        collection, = [c for c in index['collections']['cloud_run_selected_job_image_vulnerabilities']
                       if c['scope'] == scope]
        if collection['status'] not in ('collected', 'partial') or item not in collection['items']:
            raise ValueError('unbound Job collection row')
        marker = item['JobImageVulnerabilityReview']
        record = marker['vulnerability_record']
        if not isinstance(marker, dict) or not isinstance(record, dict) or record['selection'] != marker['selection']:
            raise ValueError('native vulnerability witness absent')
        selection = record['selection']
        identity = selection['resource_name'] + '#container=' + selection['container_name']
        if (item['name'] != identity or item['_resource_id'] != identity or item['native_id'] != identity or
                record['scope'] != scope or
                set(marker['source_requests']) != set(record['source_requests'])):
            raise ValueError('native Job identity or source mismatch')
        ledger = marker['source_ledger']
        selections = metadata['selected_cloudrun_job_declared_images']
        if (not isinstance(ledger, list) or len(ledger) > 2048 or
                not isinstance(selections, list) or len(selections) > 256 or
                not isinstance(record.get('findings'), list) or len(record['findings']) > 1000 or
                not isinstance(record.get('source_requests'), list) or len(record['source_requests']) > 2048 or
                not set(record['source_requests']) <= {
                receipt['id'] for receipt in ledger if isinstance(receipt, dict) and 'id' in receipt}):
            raise ValueError('native Job source ledger incomplete')
        # These are the only three copied values. Size checks precede deepcopy;
        # the scoped MemoIndex and unrelated frozen collection rows stay shared.
        if any(len(json.dumps(value, allow_nan=False)) > limit for value, limit in (
                (record, 2_000_000), (selections, 256_000), (ledger, 2_000_000))):
            raise ValueError('native Job witness exceeds bounded review size')
        return native.evaluate(deepcopy(record), {'scope': scope,
            'selections': deepcopy(selections), 'source_requests': deepcopy(ledger)})
    except (KeyError, ValueError, TypeError, IndexError, AttributeError, OverflowError):
        return 'UNKNOWN', {'reason': 'selected native Job vulnerability evidence unavailable'}


def install(*, storage, runtime, gcp, aws, root=None, source_paths=None, runtime_cases=None, gcp_cases=None, aws_cases=None):
    """Validate the predecessor, then commit all IDs or none.

    root and source_paths are accepted for the existing call site and unused.
    Omitted fixture cases use the captured native receipts.
    """
    from peaso import checks as registry
    from peaso.checks.fixtures import CASES
    from peaso.checks import catalog
    checks = registry.CHECKS
    old = _preflight(checks, storage, runtime, gcp, aws)
    if runtime_cases is None or gcp_cases is None or aws_cases is None:
        defaults = _default_cases()
        if runtime_cases is None:
            runtime_cases = defaults[RUNTIME]
        if gcp_cases is None:
            gcp_cases = defaults[GCP]
        if aws_cases is None:
            aws_cases = defaults[AWS]
    for name, cases in (('runtime', runtime_cases), ('gcp', gcp_cases), ('aws', aws_cases)):
        if cases is not None and (type(cases) is not dict or not {'pass', 'fail', 'unknown', 'pass_index', 'fail_index', 'unknown_index'} <= set(cases)):
            raise RuntimeError('provider group ' + name + ' witnesses incomplete')
    before = tuple(checks)
    case_before = dict(CASES)
    original_description = catalog.description_for
    original_frameworks = catalog.framework_names_for
    original_mappings = catalog.mappings_for
    if getattr(original_description, '_provider_group_20261021', False):
        raise RuntimeError('provider group description overlay already installed')
    try:
        # register rejects duplicate IDs. Keep the predecessor's exact
        # position and every unrelated Check field, including aliases.
        position = checks.index(old)
        checks.remove(old)
        registry.register(old.id, old.provider, old.category, old.kind, storage.TITLE,
            old.severity, old.control, storage.REMEDIATION, target=old.target,
            dependencies=old.declared_dependencies,
            allow_incomplete_failure=old.allow_incomplete_failure,
            empty_applicability_dependencies=old.empty_applicability_dependencies)(storage.evaluate)
        checks.insert(position, checks.pop())
        def runtime_evaluate(item, index):
            return _runtime_evaluate(item, index, runtime)
        registry.register(RUNTIME, 'azure', 'hardening', 'app_service',
            'Linux App Service runtime is not deprecated', 'medium', 'security_configuration',
            'Select a currently supported runtime after checking application compatibility.',
            target='resource', dependencies=('app_service',))(runtime_evaluate)
        def gcp_evaluate(item, index):
            return _gcp_evaluate(item, index, gcp)
        registry.register(GCP, 'gcp', 'hardening', 'cloud_run_selected_job_image_vulnerabilities',
            'Selected Cloud Run Job image has no HIGH or CRITICAL vulnerabilities', 'high',
            'security_configuration', 'Review the selected immutable image digest and update vulnerable packages.',
            target='resource', dependencies=('cloud_run_selected_job_image_vulnerabilities',))(gcp_evaluate)
        declaration = dict(aws.DECLARATION)
        aws_id = declaration.pop('id')
        registry.register(aws_id, **declaration)(aws.evaluate)
        CASES[AWS] = deepcopy(aws_cases)
        CASES[RUNTIME] = deepcopy(runtime_cases)
        CASES[GCP] = deepcopy(gcp_cases)
        @wraps(original_description)
        def description_for(check_id):
            original = original_description(check_id)
            if check_id == STORAGE:
                return {**(original or {}), 'description': storage.DESCRIPTION}
            if check_id == AWS:
                return {**(original or {}), **deepcopy(aws.DESCRIPTION)}
            if check_id in NEW_DESCRIPTIONS:
                return {**(original or {}), **NEW_DESCRIPTIONS[check_id]}
            return original
        description_for._provider_group_20261021 = True
        catalog.description_for = description_for
        @wraps(original_frameworks)
        def framework_names_for(check_id):
            if check_id in (RUNTIME, GCP, AWS):
                return [registry.HACKTRICKS]
            return original_frameworks(check_id)
        @wraps(original_mappings)
        def mappings_for(check_id, category, control):
            if check_id in (RUNTIME, GCP, AWS):
                return {registry.HACKTRICKS: {'control': category,
                    'reference': registry.HACKTRICKS_URL, 'assurance': 'thematic'}}
            return original_mappings(check_id, category, control)
        catalog.framework_names_for = framework_names_for
        catalog.mappings_for = mappings_for
    except BaseException:
        checks[:] = before
        CASES.clear()
        CASES.update(case_before)
        catalog.description_for = original_description
        catalog.framework_names_for = original_frameworks
        catalog.mappings_for = original_mappings
        raise
    return {'replaced': (STORAGE,), 'added': (RUNTIME, GCP, AWS), 'total': len(checks)}
