"""One bounded registry transaction for the four reviewed provider candidates.

The caller supplies the already loaded, hash-checked native modules. This module
does not import a proposal, authorize collection, or rewrite a signed receipt.
"""
from copy import deepcopy
from dataclasses import replace
from functools import wraps
from hashlib import sha256
from pathlib import Path
import inspect
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
BASE_HASHES = {
    'peaso/checks/compliance_new_sw23.py': '43074e9025001581fb2e0f99b65c8d17ef2f6deb1b0cd62216535ffac4800bdd',
}
INITIALIZER_HASHES = {
    '165cc568d072e9cbeb2b00c7bc6155c18f9fb5ec344539419f55ccfb56dd53ec',
    '9e30d82d62313b05b8b0c8c83b4c3bb1de339563dd8976fc2d59929cce4587ae',
    '5f439d17c930ac2c7a1aee7c1e57d05cb4d446dc184e430c2b44ff50fc00163c',
    'daf9caff7a8690b65477f2d45d9dab12cf28c70c6a90be9e08ed37357d42bfdb',
    'ded9ac527c13d868469a465d7f30e4aa0b43b04adaba651cab8d038d148af7d9',
    'ec7a07be2ec474b98096199868629250d7f16fa17835787bcc377c54d41a64d8',
    'f5b674c85eafa49ce509b31ebb0041fb4414d348a417da7ab75b7c315d599f50',
}
PROPOSAL_HASHES = {
    'storage': '31b21a2429529c58cfd9667b6934d37d1f426b4e4268d07c6f854211f7e3b1be',
    'runtime': 'b744f009c3b6d2094b119bb38535dc5ac68945246e7b2296d79c70516fed391f',
    'runtime_support': '0edb428c76390cb1ec5137692c3cbaa7c8b6248c6781c90d3beb6353071eb8af',
    'runtime_routes': 'c7325569ced0a12f56bc3c2ca1a2c3d50f5f9b69a0c83db07b1bbc932712a0a5',
    'gcp': '368e0f3c7af3491f07a0cfd5905413f306452d2bcff4f9a99d66d3c85a126990',
}
# The deployed package copy differs from the reviewed staged runtime in exactly
# its two sibling imports. Both byte sequences are explicit admission inputs.
DEPLOYED_RUNTIME_HASH = '36d8f9e692172161fb15421185d9d180b37caa4380868f7f052eda0a9f5a721c'
STORAGE_SOURCE = Path('/tmp/peaso-azure-immutability-presentation-20261021/storage_immutability_native_successor.py')
RUNTIME_SOURCE = Path('/tmp/peaso-azure-runtime-native-adapter-20261021/runtime_native.py')
SUPPORT_SOURCE = RUNTIME_SOURCE.with_name('runtime_support.py')
ROUTES_SOURCE = RUNTIME_SOURCE.with_name('runtime_routes.py')
GCP_SOURCE = Path('/tmp/peaso-gcp-trivy-grant-20261021/peaso/checks/gcp_job_trivy_vulnerability_review_20261020.py')
GCP_DEPENDENCIES = {'peaso/collectors/gcp_job_image_vulnerability_native_20261021.py': 'e8d3606f8005e998671c21bd57dcd04ab00807f39f243a3452f75535d7dbde50', 'peaso/collectors/gcp_job_image_vulnerability_runtime_20261021.py': 'f7ceab1fca38c7b050ac24c528ae9fbefa82e7c295479dad0fba98ec342231a3', 'peaso/collectors/gcp_job_trivy_capture_20261020.py': '9e04cdd8368087e1d733400d4fe2a60a549af99460d5f9c5cb3306a718e06a34', 'peaso/container_image_archive_20261020.py': '3d6ba0510c797bd38e0cea352b4bf1f0dfc786cb492030af31e22b97835807ba', 'peaso/container_scan_process_20261020.py': '21876eb14edfa92d4613c28fd3781014aed05b14ba3d1d6d8409c768ed29a1a3', 'peaso/trivy_container_runner_20261020.py': '6f82c71f3cd273a1fa2a79a9c7ce1b45a262072669e73921c43a6b0b751698f4'}
CURRENT_DEPENDENCIES = {'peaso/aws_image_selection_20261021.py': 'd918cbdb2477d72cdacc1d8f2097e4e987f5977971d96b77c2ba32a7f9764389',
 'peaso/checks/aws_image_vulnerabilities_20261021.py': 'd0174d668b9f10e679d9fc54c5e0e674cb82ca61daf19b19f850c32be0355674',
 'peaso/collectors/aws_image_vulnerability_native_20261021.py': 'b38a64e8a07eb568cc371f8a337a08e4d2b7c18eab5fb348445c05e43dbf864d',
 'peaso/collectors/aws_image_vulnerability_runtime_20261021.py': '7052fc2bd34a25fb74cbf0e3778a5f921c4f42e828b1c6eb3af5034b3b6c030f',
 'peaso/collectors/aws_package_content_indicators.py': '03a62985743638498b5c7c4b8ecdb2e3622ad1209c254b474e1e435b1b4c9dd3',
 'peaso/collectors/gcp_job_image_vulnerability_native_20261021.py': 'de7ff579c5d79bbf9564f3b9c9883e352939e91264ebf6898235e9322cc2c93f',
 'peaso/collectors/gcp_job_image_vulnerability_runtime_20261021.py': '508873aecc2006e1680949ec25ce9a59f5937d4c08c0d2a6e65f456a4e0f2cec',
 'peaso/container_image_archive_20261020.py': '3cd3c282253738452b5e8be8f4547b56d7ee737f8cf873d9ad73208e66e582e5'}
AWS_DEPENDENCIES = {'peaso/aws_image_selection_20261021.py': '1f9ba632715d237fbbe297a452c590850a5624d3d5c4b85f430bb215b96c120d', 'peaso/collectors/aws_image_vulnerability_native_20261021.py': '0122d3199b1be2a077cda4fe70898b4abf584011b7cf15a88df607cc4eac5bcf', 'peaso/collectors/aws_image_vulnerability_runtime_20261021.py': '398e866a21e3641bc0eb812dcabe1d5412d0fe95c78051c09a89e7faf0d6571d', 'peaso/checks/aws_image_vulnerabilities_20261021.py': 'ae64470182e6cd2cf89ec65ff63965c42912b28046b2153201c264bfa7be5912', 'peaso/container_image_archive_20261020.py': '3d6ba0510c797bd38e0cea352b4bf1f0dfc786cb492030af31e22b97835807ba', 'peaso/container_scan_process_20261020.py': '21876eb14edfa92d4613c28fd3781014aed05b14ba3d1d6d8409c768ed29a1a3', 'peaso/trivy_container_runner_20261020.py': '6f82c71f3cd273a1fa2a79a9c7ce1b45a262072669e73921c43a6b0b751698f4', 'peaso/trivy_database_20261021.py': '5e3686c4712175557ab4b1182e2bb82d155a78e4f39aa6c28ec0373860fe5987', 'peaso/image_findings.py': '1a5e81f9a02a7262e4be384dd3d5bc0c4deb6db00eeea2994602f493b08e4b85', 'peaso/collectors/aws_package_content_indicators.py': '368f52e8d782d68a879b8badcdfd3fba02bee6b8d5c24f1b483e18a9d3584433'}
AWS_DEPENDENCIES = {**AWS_DEPENDENCIES, 'peaso/collectors/aws_ecr_manifest_aliases.py': '3281dd7764dea750e1e9c2b557c58d41932e16ce54b291ffde90f49dcb256c94'}
AWS_DEPENDENCIES = {**AWS_DEPENDENCIES, 'peaso/secret_scanning_batch.py': 'cc9c5125f146b010af5ccf6906288c3be25c45d561ae77c5fd9c7a8aa0490480'}
WITNESS_HASHES = {
    STORAGE_SOURCE.with_name('spec-successor.json'): '972dd7ee516f51e7c95b34f3bf8aa18fbb5744096696c525eb83ca69d0e89bb6',
    STORAGE_SOURCE.with_name('test_storage_immutability_native_successor.py'): '8b4969c3cd082693ae0ea7d9154dd04a5d0bf50f9b24b5afb8fd0b0b993bd78b',
    STORAGE_SOURCE.with_name('test_storage_immutability_presentation.py'): '7b9cb780e96593ddef45038a246ee47c126d60b44e5f160f3cbd95d895e07ab4',
    RUNTIME_SOURCE.with_name('spec.json'): '96194ccdc2705fde34d7fa7a0a2e86996e4cc0321643f727384ee6fce6c94e81',
    RUNTIME_SOURCE.with_name('test_runtime_native.py'): 'e7ba5b81c06b9bd2ff6b86757d5a56fa87a2e75f5046b854a9643ef897ef7255',
    RUNTIME_SOURCE.with_name('test_runtime_existing_transport.py'): 'd28061814003e4aa4f81c42f4ff196fa4fae15d1b6ad49726dc278678d9e7779',
    GCP_SOURCE.parents[2] / 'tests/test_gcp_job_image_vulnerability_product_20261021.py': 'addfca8b8b2a53c44cd1ece9909bc1c5894e5a1485eb175b4f99799d82d9f835',
}
DEFAULT_CASES_SHA256 = 'a9a3209c81bf2088fc9284c85aea1ca18f208c479173413e775a163dccec1781'


def _default_cases():
    """Read only the three captured, source-ledger-bound reproduction cases."""
    path = Path(__file__).with_name('provider_group_native_cases_20261021.json')
    data = path.read_bytes()
    if sha256(data).hexdigest() != DEFAULT_CASES_SHA256:
        raise RuntimeError('provider group default native fixtures changed: ' + str(path))
    cases = json.loads(data)
    if type(cases) is not dict or set(cases) != {RUNTIME, GCP, AWS}:
        raise RuntimeError('provider group default native fixture IDs changed')
    return cases


def _digest(path):
    path = Path(path)
    root = Path(__file__).resolve().parents[2]
    raw = path.read_bytes()
    if path.resolve() in (root / 'peaso/collectors/aws_image_vulnerability_native_20261021.py',
                          root / 'peaso/collectors/aws_package_content_indicators.py',
                          root / 'peaso/secret_scanning_batch.py',
                          root / 'peaso/trivy_container_runner_20261020.py',
                          root / 'peaso/trivy_database_20261021.py'):
        from . import private_secret_shared_source_successor_20261021 as image_source
        image_source._private_self()
        relative = str(path.resolve().relative_to(root))
        row = image_source._private_receipt()['image_capture_admission']['files'][relative]
        if sha256(raw).hexdigest() != row['current_sha256']:
            raise RuntimeError('Image capture current dependency changed')
        raw = image_source._reverse(raw.decode('utf-8'), row).encode('utf-8')
        if sha256(raw).hexdigest() != row['predecessor_sha256']:
            raise RuntimeError('Image capture historical dependency changed')
    return sha256(raw).hexdigest()


def staged_sources():
    paths = {'storage': STORAGE_SOURCE, 'runtime': RUNTIME_SOURCE,
             'runtime_support': SUPPORT_SOURCE, 'runtime_routes': ROUTES_SOURCE,
             'gcp': GCP_SOURCE}
    paths.update({relative: GCP_SOURCE.parents[2] / relative for relative in GCP_DEPENDENCIES})
    paths.update({str(path): path for path in WITNESS_HASHES})
    paths.update({relative: Path(__file__).resolve().parents[2] / relative for relative in AWS_DEPENDENCIES})
    return paths


def deployed_sources(root):
    """Exact destination whitelist for the one coordinated source epoch."""
    root = Path(root).resolve()
    checks = root / 'peaso/checks'
    paths = {'storage': checks / 'storage_immutability_native_successor.py',
             'runtime': checks / 'azure_app_service_runtime_native_20261021.py',
             'runtime_support': checks / 'runtime_support.py',
             'runtime_routes': checks / 'runtime_routes.py',
             'gcp': checks / 'gcp_job_trivy_vulnerability_review_20261020.py'}
    paths.update({relative: root / relative for relative in GCP_DEPENDENCIES})
    paths.update({relative: root / relative for relative in AWS_DEPENDENCIES})
    paths.update({str(path): checks / 'provider_group_witnesses_20261021' / path.name
                  for path in WITNESS_HASHES})
    return paths


def _preflight(checks, storage, runtime, gcp, aws, root, source_paths):
    from peaso.checks import CHECK_ALIASES
    from peaso.checks.fixtures import CASES
    root = Path(root).resolve()
    paths = staged_sources() if source_paths is None else source_paths
    expected_keys = set(staged_sources())
    if type(paths) is not dict or set(paths) != expected_keys:
        raise RuntimeError('provider group source whitelist incomplete or broadened')
    initializer = root / 'peaso/checks/__init__.py'
    if _digest(initializer) not in INITIALIZER_HASHES:
        raise RuntimeError('provider group initializer changed: ' + str(initializer))
    for relative, expected in BASE_HASHES.items():
        path = root / relative
        if _digest(path) != expected:
            raise RuntimeError('provider group base source changed: ' + str(path))
    for label in PROPOSAL_HASHES:
        path = paths[label]
        expected = (PROPOSAL_HASHES[label] if label != 'runtime' or
                    Path(path).resolve() == RUNTIME_SOURCE.resolve() else DEPLOYED_RUNTIME_HASH)
        if _digest(path) != expected:
            raise RuntimeError('provider group reviewed proposal changed: ' + str(path))
    for relative, expected in GCP_DEPENDENCIES.items():
        path = paths[relative]
        if _digest(path) not in (expected, CURRENT_DEPENDENCIES.get(relative)):
            raise RuntimeError('provider group GCP dependency changed: ' + str(path))
    for relative, expected in AWS_DEPENDENCIES.items():
        if _digest(paths[relative]) not in (expected, CURRENT_DEPENDENCIES.get(relative)):
            raise RuntimeError('provider group AWS dependency changed: ' + relative)
    if aws.DECLARATION.get('id') != AWS or aws.DECLARATION.get('provider') != 'aws':
        raise RuntimeError('provider group AWS declaration changed')
    if Path(inspect.getsourcefile(aws.evaluate)).resolve() != Path(paths['peaso/checks/aws_image_vulnerabilities_20261021.py']).resolve():
        raise RuntimeError('provider group AWS evaluator identity changed')
    for original, expected in WITNESS_HASHES.items():
        path = paths[str(original)]
        if _digest(path) != expected:
            raise RuntimeError('provider group reviewed witness changed: ' + str(path))
    # Module identity is checked as well as disk bytes: a caller cannot supply
    # a different evaluator while leaving the reviewed files in place.
    for function, path in ((storage.evaluate, paths['storage']), (runtime.collect, paths['runtime']),
                           (runtime.support.evaluate, paths['runtime_support']),
                           (runtime.bounds._valid_url, paths['runtime_routes']),
                           (gcp.evaluate, paths['gcp'])):
        if Path(inspect.getsourcefile(function)).resolve() != Path(path).resolve():
            raise RuntimeError('provider group evaluator identity changed: ' + str(path))
    if storage.CHECK_ID != STORAGE or runtime.support.CHECK_ID != RUNTIME:
        raise RuntimeError('provider group Azure check ID changed')
    if len([c for c in checks if c.id == STORAGE]) != 1:
        raise RuntimeError('provider group requires one signed SW23 predecessor')
    if any(c.id in (RUNTIME, GCP, AWS) for c in checks) or any(cid in CHECK_ALIASES for cid in IDS):
        raise RuntimeError('provider group ID already registered or aliased')
    if any(cid in CASES for cid in (RUNTIME, GCP, AWS)):
        raise RuntimeError('provider group fixture ID already present')
    old = next(c for c in checks if c.id == STORAGE)
    signed = inspect.unwrap(old.evaluate)
    if Path(inspect.getsourcefile(signed)).resolve() != (root / 'peaso/checks/compliance_new_sw23.py').resolve():
        raise RuntimeError('provider group predecessor evaluator source changed')
    if sha256(inspect.getsource(signed).encode()).hexdigest() != 'decfb8acc630520deb963941f88d1a34b55c4cf006602bbe96a616c5fc046a23':
        raise RuntimeError('provider group predecessor evaluator changed')
    if old.declared_dependencies != ('storage_account', 'storage_immutability_evidence'):
        raise RuntimeError('provider group predecessor dependencies changed')
    storage.reviewed_source()
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


def install(*, storage, runtime, gcp, aws, root, source_paths=None, runtime_cases=None, gcp_cases=None, aws_cases=None):
    """Validate every source and predecessor, then commit all IDs or none.

    Modules are explicit inputs so source-bound import blockers stay visible to
    the caller. Omitted fixture cases use the exact captured native receipts.
    """
    from peaso import checks as registry
    from peaso.checks.fixtures import CASES
    from peaso.checks import catalog
    checks = registry.CHECKS
    old = _preflight(checks, storage, runtime, gcp, aws, root, source_paths)
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
        # register rejects duplicate IDs. Keep the signed predecessor's exact
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
