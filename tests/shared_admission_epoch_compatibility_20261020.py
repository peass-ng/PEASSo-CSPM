"""Finite test-only source ancestry; no production guards or receipts are patched."""
from copy import deepcopy
import ast
import gzip
import hashlib
import inspect
import importlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ORIGINAL_TESTS = 'tests/fixtures/shared_admission_original_tests_20261020.json.gz'
ORIGINAL_TESTS_SHA256 = 'b6dc973b3351d0979686171a4d0ba7313bf2edc7726d76dbac77d2cbe235daf9'
RECEIPTS = {
    'azure_jit_parent_type_shared_successor_20261020': 'bf2cefbc561808e7001f3a0391f0b48e3e24b085c4cfae91c9c98dceb99943f7',
    'aws_deployed_ai_shared_successor_20261020': 'ffc024b6908fb5b9ae5330f327eda5634897ed45845db62ccd6637539e1b8f06',
    'aws_workload_command_shared_successor_20261020': '204e853cea9dfddaf2fa23c44a441c028fafcc9a1f28d4718aef485f0c35dea1',
    'azure_function_package_shared_successor_20261020': '9bd4b45c79ae86af77ee58853bfe05692d5cf244a11c916756906f281e5f1c99',
    'aws_codebuild_buildspec_shared_successor_20261020': '3f850167f2dfc92c78222f38ae48b7bedb0b102e13578a9bb9508df0000cdcce',
    'gcp_dataflow_batch_shared_hook_successor_20261020': 'c6085a12b2468c039c605d314748f02a4963ee01cdf2edbc072f254aa73dc460',
    'gcp_workbench_shared_hook_successor_20261020': 'd6dc0461e17473bc437eb9a9f68c7e39103c6e6dcdccbc84ef469eda88002593',
    'gcp_dataflow_batch_source_runtime_admission_20261020': '8277fadb5c0f67131c47755e10ac06f48454e40730088aba09234b92dd3451a1',
    'gcp_workbench_source_runtime_admission_20261020': '5ef240b2946f092bc36e20d8a4bac421b9c4544b6e7ad2f21d6d6eb0c9fbd87e',
}


def digest(raw):
    return hashlib.sha256(raw if isinstance(raw, bytes) else raw.encode()).hexdigest()


def original_tests():
    raw = (ROOT / ORIGINAL_TESTS).read_bytes()
    assert digest(raw) == ORIGINAL_TESTS_SHA256
    archive = json.loads(gzip.decompress(raw))
    assert archive['git_commit'] == '332f1f4825ab5ec17305f60dc85e6d2bffe99f6b'
    for row in archive['files'].values():
        assert digest(row['text']) == row['sha256'] and len(row['text'].encode()) == row['bytes']
    return archive['files']


def receipt(name):
    raw = (ROOT / 'peaso/checks' / (name + '.json')).read_bytes()
    assert digest(raw) == RECEIPTS[name], 'Immutable source receipt changed: ' + name
    return json.loads(raw)


def active_shared():
    # The package explicitly publishes its admitted successor at this stable alias.
    from peaso.checks import azure_function_package_shared_successor_20261020 as current
    known = {
        'peaso.checks.azure_jit_parent_type_shared_successor_20261020': RECEIPTS['azure_jit_parent_type_shared_successor_20261020'],
        'peaso.checks.native_admission_cpu_shared_successor_20261020': '93a723d84bf4a11cc69f22e0ae924c20c1f1da96c5f6f7f77f148f27b35a0374',
        'peaso.checks.collector_noop_authorization_shared_successor_20261020': '5709994cbe4aa84b8546c21807952dd8873bbca0c6bd354b99459090dccc7be1',
        'peaso.checks.azure_metadata_only_shared_successor_20261020': '4dfa99f4f0903bc99037f8a9e9d860f84ce0c0ce686a8e891f8277c054bdafa7',
        'peaso.checks.gcp_positive_conservation_shared_source_successor_20261020': '4dfa99f4f0903bc99037f8a9e9d860f84ce0c0ce686a8e891f8277c054bdafa7',
        'peaso.checks.private_secret_shared_source_successor_20261021': '4dfa99f4f0903bc99037f8a9e9d860f84ce0c0ce686a8e891f8277c054bdafa7',
    }
    assert current.__name__ in known, 'Unknown shared admission source epoch'
    assert current is importlib.import_module(current.__name__), 'Shared admission alias pointer changed'
    if current.__name__ == 'peaso.checks.private_secret_shared_source_successor_20261021':
        current._private_self()  # Real current source/code/receipt checks; never alter historical receipts.
        assert current._private_canonical is importlib.import_module('peaso.checks.gcp_positive_conservation_shared_source_successor_20261020')
        private = (ROOT / 'peaso/checks/private_secret_shared_source_successor_20261021.json').read_bytes()
        assert digest(private) == current._PRIVATE_RECEIPT_SHA256
    if current.__name__ in ('peaso.checks.gcp_positive_conservation_shared_source_successor_20261020',
                            'peaso.checks.private_secret_shared_source_successor_20261021'):
        historical = importlib.import_module('peaso.checks.azure_metadata_only_shared_successor_20261020')
        assert current.historical_bridge is historical
        assert current.RECEIPT == historical.RECEIPT == 'azure_metadata_only_shared_successor_20261020.json'
    else:
        assert current.RECEIPT == current.__name__.rsplit('.', 1)[1] + '.json'
    raw = (ROOT / 'peaso/checks' / current.RECEIPT).read_bytes()
    assert digest(raw) == known[current.__name__] == current.RECEIPT_SHA256
    if current.__name__.endswith('native_admission_cpu_shared_successor_20261020'):
        proof = json.loads(raw)
        assert proof['prior_bridge_receipt_sha256'] == RECEIPTS['azure_jit_parent_type_shared_successor_20261020']
        assert current.prior_bridge.__name__ == 'peaso.checks.azure_jit_parent_type_shared_successor_20261020'
        # Exact executing-code and closure verification stays in the real gate.
        # This verifies only which independently bound successor may be routed.
    if current.__name__.endswith('collector_noop_authorization_shared_successor_20261020'):
        _noop_native_parent(current, json.loads(raw))
    if current.__name__.endswith(('azure_metadata_only_shared_successor_20261020',
                                  'gcp_positive_conservation_shared_source_successor_20261020')):
        _metadata_noop_parent(current, json.loads(raw))
    if current.__name__.endswith('private_secret_shared_source_successor_20261021'):
        _metadata_noop_parent(current.historical_bridge, json.loads(raw))
    return current


def _metadata_noop_parent(current, proof):
    """Finite metadata-only alias over the immutable 168-row no-op epoch."""
    latest = importlib.import_module('peaso.checks.private_secret_shared_source_successor_20261021')
    noop = importlib.import_module('peaso.checks.collector_noop_authorization_shared_successor_20261020')
    noop_sha = '5709994cbe4aa84b8546c21807952dd8873bbca0c6bd354b99459090dccc7be1'
    assert proof['accepted_noop_receipt_sha256'] == noop_sha, 'Metadata-only no-op receipt ancestry changed'
    assert current.accepted_noop is noop, 'Metadata-only no-op parent pointer changed'
    assert noop.RECEIPT == 'collector_noop_authorization_shared_successor_20261020.json'
    raw = (ROOT / 'peaso/checks' / noop.RECEIPT).read_bytes()
    assert digest(raw) == noop_sha == noop.RECEIPT_SHA256, 'No-op parent receipt changed'
    parent = json.loads(raw)
    assert len(parent['functions']) == 168
    assert all(proof['functions'].get(name) == row for name, row in parent['functions'].items()), 'No-op function rows changed'
    for section in ('shared_functions', 'integration_functions', 'azure_collect',
                    'file_deltas', 'parent_file_deltas', 'integration_file_deltas',
                    'prior_epoch_file_deltas', 'native_epoch_file_deltas',
                    'producer_file_deltas', 'producer_functions'):
        assert proof[section] == parent[section], 'No-op historical delta section changed'
    expected_noop = {name for name in parent['functions'] if name.startswith(noop.__name__ + ':')}
    assert set(current._NOOP_FUNCTIONS) == expected_noop, 'No-op callable snapshot names changed'
    assert current._NOOP_FUNCTIONS == noop._FUNCTIONS, 'No-op callable snapshot changed'
    _noop_native_parent(noop, parent)
    _noop_native_parent(current, proof)
    assert set(proof['metadata_only_epoch_file_deltas']) == {
        'peaso/checks/__init__.py', 'peaso/collectors/azure.py'}
    for relative, row in proof['metadata_only_epoch_file_deltas'].items():
        content = (ROOT / relative).read_bytes()
        if relative == 'peaso/checks/__init__.py':
            if digest(content) == latest._private_receipt()['initializer_after_sha256']:
                content = latest._initialization_predecessor(content)
            from tests.gcp_positive_conservation_epoch_20261020 import metadata_initializer_bytes
            content = metadata_initializer_bytes(content)
        elif relative == 'peaso/collectors/azure.py':
            content = latest._private_before(relative, content, ROOT)
        _reverse(content.decode(), row)
    assert proof['metadata_only_epoch_file_deltas']['peaso/collectors/azure.py']['predecessor_sha256'] == 'b69db967e65722174e847116620b63c7de4f0da835e3edde1a882456dc37afea'
    from peaso.collectors import azure
    restored = latest.predecessor_azure_collect(inspect.getsource(azure.collect), ROOT)
    assert digest(restored) == parent['azure_collect']['current_sha256']
    # Execute the real source, callable and sentinel-class identity proof.
    latest.verify_metadata_only(ROOT)
    return noop


def _noop_native_parent(current, proof):
    """Only the final no-op receipt may route the exact canonical CPU parent."""
    native = importlib.import_module('peaso.checks.native_admission_cpu_shared_successor_20261020')
    jit = importlib.import_module('peaso.checks.azure_jit_parent_type_shared_successor_20261020')
    cpu_sha = '93a723d84bf4a11cc69f22e0ae924c20c1f1da96c5f6f7f77f148f27b35a0374'
    assert proof['accepted_native_receipt_sha256'] == cpu_sha, 'No-op native receipt ancestry changed'
    assert proof['prior_bridge_receipt_sha256'] == RECEIPTS['azure_jit_parent_type_shared_successor_20261020'], 'No-op JIT receipt ancestry changed'
    assert current.accepted_native is native, 'No-op native parent pointer changed'
    assert current.prior_bridge is jit and native.prior_bridge is jit, 'No-op JIT parent pointer changed'
    assert native.RECEIPT == 'native_admission_cpu_shared_successor_20261020.json'
    raw = (ROOT / 'peaso/checks' / native.RECEIPT).read_bytes()
    assert digest(raw) == cpu_sha == native.RECEIPT_SHA256, 'CPU parent receipt changed'
    parent = json.loads(raw)
    assert parent['prior_bridge_receipt_sha256'] == RECEIPTS['azure_jit_parent_type_shared_successor_20261020']
    assert len(parent['functions']) == 137
    assert all(proof['functions'].get(name) == row for name, row in parent['functions'].items()), 'CPU function rows changed'
    receipt('azure_jit_parent_type_shared_successor_20261020')


def snapshot_cases(value):
    """Copy all mutable content while retaining the actual opaque trust witness.

    _Admitted intentionally uses object identity. deepcopy creates an unequal
    unauthenticated witness, so comparing it with a live registry is invalid.
    Its identity is retained; every ordinary nested container is still copied.
    """
    from peaso.azure_function_package_index_20261020 import _Admitted
    memo, seen = {}, set()
    def visit(item):
        if id(item) in seen:
            return
        seen.add(id(item))
        if type(item) is _Admitted:
            memo[id(item)] = item
        elif isinstance(item, dict):
            for key, child in item.items():
                visit(key); visit(child)
        elif isinstance(item, (list, tuple, set, frozenset)):
            for child in item:
                visit(child)
    visit(value)
    return deepcopy(value, memo)


def _reverse(text, row):
    if digest(text) != row['current_sha256']:
        raise RuntimeError('Unreviewed shared source changed')
    for before, after in row.get('exact_replacements', []):
        if text.count(after) != 1:
            raise RuntimeError('Reviewed shared replacement changed')
        text = text.replace(after, before, 1)
    for addition in row.get('exact_additions', []):
        if text.count(addition) != 1:
            raise RuntimeError('Reviewed shared addition changed')
        text = text.replace(addition, '', 1)
    expected = row.get('predecessor_sha256', row.get('predecessor', {}).get('sha256'))
    if digest(text) != expected:
        raise RuntimeError('Reviewed shared predecessor changed')
    return text


def source_at_epoch(function, name, expected):
    """Reconstruct an exact pinned body through a finite signed delta chain."""
    text = inspect.getsource(inspect.unwrap(function))
    rows = []
    qualified = {'engine': 'peaso.engine', 'validation': 'peaso.server.validation',
                 'aws': 'peaso.collectors.aws'}[name.split('.')[0]] + ':' + name.split('.')[1]
    for module in RECEIPTS:
        proof = receipt(module)
        if qualified in proof.get('integration_functions', {}):
            rows.append(proof['integration_functions'][qualified])
        if name in proof.get('shared_functions', {}):
            rows.append(proof['shared_functions'][name])
    current = active_shared()
    if current.__name__.endswith('private_secret_shared_source_successor_20261021'):
        transition = current._private_receipt()['provider_group_callables'].get(qualified.split(':')[0].replace('.', '/') + '.py:' + qualified.split(':')[1])
        if transition is not None:
            rows.append(transition)
    permitted = {row['current_sha256'] for row in rows} | {
        row.get('predecessor_sha256', row.get('predecessor', {}).get('sha256')) for row in rows}
    if expected not in permitted:
        raise RuntimeError('Unknown requested shared source epoch')
    for _ in range(len(rows) + 1):
        if digest(text) == expected:
            return text
        candidates = [row for row in rows if row['current_sha256'] == digest(text)]
        for row in candidates:
            restored = _reverse(text, row)
            if restored != text:
                text = restored
                break
        else:
            raise RuntimeError('Unreviewed shared source changed')
    raise RuntimeError('Shared source lineage exceeded finite bound')


def sealed_ast(tree):
    """3.13's sealed AST form, preserving every populated field and source hash."""
    if isinstance(tree, ast.AST):
        fields = []
        for name, value in ast.iter_fields(tree):
            if isinstance(value, list) and not value or value is None and getattr(type(tree), name, ...) is None:
                continue
            fields.append(name + '=' + sealed_ast(value))
        return type(tree).__name__ + '(' + ', '.join(fields) + ')'
    if isinstance(tree, list):
        return '[' + ', '.join(sealed_ast(value) for value in tree) + ']'
    return repr(tree)


def azure_predecessor_tree(destination):
    """Real isolated predecessor files, never fake module roots or guard patches."""
    import shutil
    destination = Path(destination)
    for name in ('peaso', 'tests', 'scripts', 'bluepeass', 'risk_rules', 'docs'):
        shutil.copytree(ROOT / name, destination / name,
                        ignore=shutil.ignore_patterns('__pycache__', '*.pyc', '.pytest_cache'))
    shutil.copyfile(ROOT / 'pyproject.toml', destination / 'pyproject.toml')
    active = active_shared()
    if active.__name__ == 'peaso.checks.gcp_positive_conservation_shared_source_successor_20261020':
        from tests.gcp_positive_conservation_epoch_20261020 import restore_content_predecessors
        restore_content_predecessors(destination)
    if active.__name__ in {'peaso.checks.azure_metadata_only_shared_successor_20261020',
                           'peaso.checks.gcp_positive_conservation_shared_source_successor_20261020'}:
        # Canonical no-op ancestry is already checked; restore the same three
        # producers before the pinned archive restores the older Azure file.
        active = active.accepted_noop
    if active.__name__ == 'peaso.checks.collector_noop_authorization_shared_successor_20261020':
        raw = (ROOT / 'peaso/checks' / active.RECEIPT).read_bytes()
        assert digest(raw) == '5709994cbe4aa84b8546c21807952dd8873bbca0c6bd354b99459090dccc7be1'
        proof = json.loads(raw)
        assert set(proof['producer_file_deltas']) == {
            'peaso/collectors/aws_workload_command_runtime_20261020.py',
            'peaso/collectors/aws_codebuild_buildspec_runtime_20261020.py',
            'peaso/collectors/azure_function_package_integration_20261020.py'}
        # Only isolated historical files are restored. Live guards and every
        # signed predecessor receipt remain byte-identical and execute normally.
        for relative, row in proof['producer_file_deltas'].items():
            target = destination / relative
            target.write_text(_reverse(target.read_text(), row))
    current = receipt('azure_jit_parent_type_shared_successor_20261020')
    workload = receipt('aws_workload_command_shared_successor_20261020')
    # Restore unchanged pre-AI/pre-workload AWS dependencies used by that epoch's
    # real CodeBuild/S3 registry. Every reversal must match both pinned hashes.
    for relative in ('peaso/collectors/aws.py', 'peaso/collectors/aws_facts_swc.py'):
        text = _reverse((ROOT / relative).read_text(), current['integration_file_deltas'][relative])
        if relative in workload['file_deltas']:
            text = _reverse(text, workload['file_deltas'][relative])
        (destination / relative).write_text(text)
    archive_path = ROOT / 'peaso/checks/azure_function_package_integration_predecessors_20261020.json.gz'
    raw = archive_path.read_bytes()
    assert digest(raw) == 'eac8ca72282644847f2cedae0c87f7f45bd7c895cb7116f57ac4bf287096d6c6'
    predecessors = json.loads(gzip.decompress(raw))['files']
    for relative, row in predecessors.items():
        content = bytes.fromhex(row['hex'])
        assert digest(content) == row['sha256']
        target = destination / relative
        assert target.resolve().is_relative_to(destination.resolve())
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
        assert digest(target.read_bytes()) == row['sha256']
    # Run the original historical assertions without changing a single byte.
    relative = 'tests/test_azure_function_package_runtime_20261020.py'
    original = original_tests()[relative]
    (destination / relative).write_text(original['text'])
    assert digest((destination / relative).read_bytes()) == original['sha256']
    assert digest((destination / 'peaso/collectors/azure.py').read_bytes()) == '06f920ae74c65ce07911e3748dd336eae6b770ad2cead2131036564bcb35bde8'
    return destination


def copy_workbench_inputs(destination, original_receipt):
    """Finite complete disk guard closure, including the admitted Job successor."""
    import shutil
    from peaso.checks import gcp_cloudrun_job_image_workbench_source_successor_20261020 as successor
    raw = (ROOT / 'peaso/checks' / successor.RECEIPT).read_bytes()
    assert digest(raw) == successor.RECEIPT_SHA256
    delta = json.loads(raw)
    from peaso.checks import gcp_workbench_head3_admission_20261020 as original
    relatives = (set(original_receipt['sources']) | set(delta['sources']) |
                 {'peaso/checks/' + original.RECEIPT, 'peaso/checks/' + successor.RECEIPT, delta['collector_delta']})
    for relative in relatives:
        target = Path(destination) / relative
        assert target.resolve().is_relative_to(Path(destination).resolve())
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, target)


def workbench_file_at_epoch(relative, expected):
    data = (ROOT / relative).read_bytes()
    if digest(data) == expected:
        return data
    if relative == 'tests/test_gcp_workbench_head3_proposal_20261020.py':
        archived = (ROOT / 'tests/fixtures/gcp_head3_proposal_test_pre_admission_20261020.json.gz').read_bytes()
        assert digest(archived) == '8e605e818fde2532b80e67c4eaa9aeba009909d119b48b038e27c1a290614620'
        historical = json.loads(gzip.decompress(archived))
        assert historical['sha256'] == expected and digest(historical['content']) == expected
        return historical['content'].encode()
    assert relative == 'peaso/collectors/gcp.py', 'No reviewed whole-file successor for ' + relative
    from peaso.checks import gcp_cloudrun_job_image_workbench_source_successor_20261020 as successor
    raw = (ROOT / 'peaso/checks' / successor.RECEIPT).read_bytes()
    assert digest(raw) == successor.RECEIPT_SHA256
    receipt_data = json.loads(raw)
    delta_raw = (ROOT / receipt_data['collector_delta']).read_bytes()
    # The successor verifies the source and delta against its immutable receipt.
    reconstructed = successor._reviewed_delta(ROOT)
    assert digest(reconstructed) == expected
    return reconstructed


from contextlib import contextmanager


@contextmanager
def historical_ast_format():
    """Only sealed AST values receive Python 3.13's omission of empty fields.

    This historical test process keeps every guard/source byte unchanged. It
    does not normalize a novel or tampered AST: only exact strings already in
    five independently hash-verified original receipts are admitted. All
    unknown nodes and alternate ast.dump options retain ordinary 3.12 behavior.
    """
    allowed = set()
    for name in ('gcp_workbench_shared_hook_successor_20261020',
                 'gcp_dataflow_batch_shared_hook_successor_20261020',
                 'aws_codebuild_buildspec_shared_successor_20261020',
                 'gcp_dataflow_batch_source_runtime_admission_20261020',
                 'gcp_workbench_source_runtime_admission_20261020'):
        proof = receipt(name)
        for section in ('shared_functions', 'prepared_functions', 'gcp_function_deltas'):
            allowed.update(row['predecessor_ast'] for row in proof.get(section, {}).values())
    original = ast.dump
    observations = []
    def dump(node, annotate_fields=True, include_attributes=False, *, indent=None, **kwargs):
        if annotate_fields and not include_attributes and indent is None and not kwargs:
            rendered = sealed_ast(node)
            if rendered in allowed:
                ordinary = original(node, annotate_fields=True, include_attributes=False)
                observations.append({'python312_ast_sha256': digest(ordinary),
                                     'sealed313_ast_sha256': digest(rendered),
                                     'different_format': ordinary != rendered})
                return rendered
        return original(node, annotate_fields=annotate_fields,
                        include_attributes=include_attributes, indent=indent, **kwargs)
    ast.dump = dump
    try:
        yield observations
    finally:
        assert ast.dump is dump, 'Historical AST adapter was substituted'
        ast.dump = original


def s3_historical_policy_before():
    """Retain the historical capture; never depend on a shared /tmp cache."""
    packed = (ROOT / 'tests/fixtures/aws_s3_historical_policy_before_20261020.json.gz').read_bytes()
    assert digest(packed) == '890c5e6569b224b9a57a4727a1d9600d3086c65d6d4c3789c333fd042f5392f7'
    raw = gzip.decompress(packed)
    assert digest(raw) == '9915a4080cb926a5c25b490cb83c1ae92bcdb675d6dd524f6d3dbf3106ab738f'
    historical = json.loads(raw)
    for name, row in historical.items():
        if name != 'default_policy':
            assert digest(row['body']) == row['sha256']
    return historical


def historical_metadata_catalog():
    """Exact 3,496-entry public metadata from its retained original commit."""
    packed = (ROOT / 'tests/fixtures/shared_metadata_catalog_3496_20261020.json.gz').read_bytes()
    assert digest(packed) == '0dce27dc4658e393d9ee370eb7f19f81dcb0df7e5a85c0a63669ac824fb94f33'
    raw = gzip.decompress(packed)
    assert digest(raw) == '55e4ef383df3d4408654b95b46789264d024bb8eb4197ca926f37b7eb0d7a718'
    catalog = json.loads(raw)
    assert len(catalog['checks']) == 3496
    # Every historical identity remains registered, explicitly archived, or a
    # reviewed alias; never present the old metadata fixture as a live scan.
    from peaso.checks import CHECKS, CHECK_ALIASES
    from peaso.analysis import ANALYSIS_CHECKS, MANUAL_ONLY_ANALYSIS_CHECK_IDS
    known = {c.id for c in CHECKS} | set(CHECK_ALIASES) | MANUAL_ONLY_ANALYSIS_CHECK_IDS | {c['id'] for c in ANALYSIS_CHECKS}
    assert {c['id'] for c in catalog['checks']} <= known
    return catalog
