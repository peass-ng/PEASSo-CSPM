"""Exact portable sentinel and signed source-artifact successor over the immutable Azure epoch.

Only the parent package aliases this bridge. Canonical historical modules,
receipts, callable objects, grant identities and native witnesses stay intact.
"""
from copy import deepcopy
from contextvars import ContextVar
import ast
import gzip
import hashlib
import hmac
import inspect
import importlib
import json
import linecache
import marshal
import os
from pathlib import Path
import re
import sys
import textwrap
import types
from . import azure_function_package_shared_successor_20261020 as predecessor
from . import azure_metadata_only_shared_successor_20261020 as historical_bridge
original = predecessor.original
PREDECESSOR_REVIEWED_INPUTS = predecessor.PREDECESSOR_REVIEWED_INPUTS
historical = importlib.import_module(__package__ + '.aws_workload_command_shared_successor_20261020')
accepted = importlib.import_module(__package__ + '.aws_deployed_ai_shared_successor_20261020')
_ACCEPTED_FUNCTIONS = dict(accepted._FUNCTIONS)
prior_bridge = importlib.import_module(__package__ + '.azure_jit_parent_type_shared_successor_20261020')
_PRIOR_FUNCTIONS = dict(prior_bridge._FUNCTIONS)
_PACKAGE_SUCCESSOR = importlib.import_module(__package__ + '.collector_noop_package_admission_successor_20261020')
_PACKAGE_FUNCTIONS = dict(_PACKAGE_SUCCESSOR._FUNCTIONS)
accepted_native = importlib.import_module(__package__ + '.native_admission_cpu_shared_successor_20261020')
_NATIVE_FUNCTIONS = dict(accepted_native._FUNCTIONS)
_NATIVE_PACKAGE = importlib.import_module(__package__ + '.azure_function_package_callable_cpu_successor_20261020')
_NATIVE_PACKAGE_FUNCTIONS = dict(_NATIVE_PACKAGE._FUNCTIONS)
_COMMAND_SUCCESSOR = importlib.import_module(__package__ + '.collector_noop_command_admission_successor_20261020')
_CODEBUILD_SUCCESSOR = importlib.import_module(__package__ + '.collector_noop_codebuild_admission_successor_20261020')
_AUTHORIZATION_SUCCESSORS = (_COMMAND_SUCCESSOR, _CODEBUILD_SUCCESSOR, _PACKAGE_SUCCESSOR)
_AUTHORIZATION_FUNCTIONS = {name: fn for module in _AUTHORIZATION_SUCCESSORS for name, fn in module._FUNCTIONS.items()}
_HISTORICAL_FUNCTIONS = dict(historical._FUNCTIONS)
accepted_noop = importlib.import_module(__package__ + '.collector_noop_authorization_shared_successor_20261020')
_NOOP_FUNCTIONS = dict(accepted_noop._FUNCTIONS)
_METADATA_AZURE = importlib.import_module('peaso.collectors.azure')
_METADATA_COLLECT = _METADATA_AZURE.collect
_METADATA_CLASS = _METADATA_AZURE._MetadataOnlyCollection
_METADATA_WEAKREF = vars(_METADATA_CLASS)['__weakref__']
_METADATA_TDE = importlib.import_module(__package__ + '.azure_metadata_only_tde_admission_successor_20261020')
_METADATA_TDE_FUNCTIONS = dict(_METADATA_TDE._FUNCTIONS)
_COMPILED_TRANSACTION = ContextVar('deployed_ai_compiled_transaction', default=None)
_TRANSACTION_CONTEXT = _COMPILED_TRANSACTION
_DATAFLOW_ADMISSION = importlib.import_module(__package__ + '.gcp_dataflow_batch_source_runtime_admission_20261020')
_DATAFLOW_FUNCTIONS = dict(_DATAFLOW_ADMISSION._FUNCTIONS)
_DATAFLOW_REVIEWED_INPUTS = _DATAFLOW_FUNCTIONS[_DATAFLOW_ADMISSION.__name__ + ':reviewed_inputs']
RECEIPT = 'azure_metadata_only_shared_successor_20261020.json'
RECEIPT_SHA256 = '4dfa99f4f0903bc99037f8a9e9d860f84ce0c0ce686a8e891f8277c054bdafa7'
BRIDGE_RECEIPT_SHA256 = 'da2c2b52467ea97ff0d54a146556fa6b64239f8d70b847641b85cf65969d251c'
_CURRENT_INIT_SHA256 = '0fa143a274905e52dad14d6eecfb641fdc98ebbd17db90d54d9908594b458e08'
_PREDECESSOR_INIT_SHA256 = 'e828e145917364fcd20a5a2d6de7e24eb304eee5698fea1cb1bed8669fef01c6'



from peaso import private_secret_source_epoch_20261021 as _private_source_epoch
from peaso import source_attestation_mode as _attestation_mode
from peaso import private_reviewed_collector_successor_20261022 as _reviewed_epoch
from . import gcp_positive_conservation_shared_source_successor_20261020 as _private_canonical
_PRIVATE_SOURCE_RECORDS = (('peaso/collectors/aws_additional_secret_indicators.py', 'e2cfc9bcd839b1a7a803580b549b3d02d8a67757274551a0afc4130e5d184787', ('_scan', 'codebuild_indicator')), ('peaso/collectors/aws_code_log_content_indicators.py', '06fd10cdc45542e15e31d4e735256fa62b3733c805dc5eb1865b7e3923013355', ('project_response',)), ('peaso/collectors/aws_codebuild_buildspec_source_20261020.py', '4890d8a97cd86cdcee0df334956531432ae26ec2f6a1758f1ecb858e7f778bce', ('collect',)), ('peaso/collectors/aws_configuration_payload_secret_indicators.py', 'eef6d7241cc5f09f9560c427fa9f336a636d1996130f0eb5b05d17377883fdc9', ('marker', 'project_response')), ('peaso/collectors/aws_configuration_secret_indicators.py', 'cbeb631ac665dea0c221a3ad370d21000b8c458a33072b4f0d5c855bedbc147c', ('_indicators', 'lambda_indicators')), ('peaso/collectors/aws_lambda_environment_secret_indicators.py', '2fce27977e83ba4f9abc6baa6ac78d4ff5e0e4a2b8b27d52d333a0458e67f289', ('project_response',)), ('peaso/collectors/aws_package_content_indicators.py', 'ce459d4b5ed0ae991591f09f61b462f7841f0977d5935579e561409c0117e7e6', ('_image', '_lambda', '_layer', '_scan')), ('peaso/collectors/aws_s3_selected_source_secret_indicators.py', 'b040a3b23746561fe913b1bd985669a0820fdde72b12fd864c5f6b5b894e3053', ('_scan_part', 'collect_selected')), ('peaso/collectors/aws_selected_configuration_secret_indicators.py', 'c7a87afb1fc02740979a34efa2a03141d4e0daddbfdda1e45c604507c31c450f', ('collect_selected', 'project_response')), ('peaso/collectors/aws_user_data_secret_indicators.py', '077b5d258d6728c0b712935d34899c0feb27e3d11f758a81e793a6a240016205', ('project', 'scan_selected_content')), ('peaso/collectors/aws_workload_command_source_20261020.py', 'c5c5c24b7fbd4b696903d38b6e84a02ad3ebfa35616e6378a67afb97b8ae757e', ('collect',)), ('peaso/collectors/azure.py', 'd27a5f2b861fef622c20bff80bf5e8f559d7f5d70604606643eb9267254101e5', ('AzureTransport',)), ('peaso/collectors/azure_acr_image_secret_indicators.py', '8e9c55f0fcee045b9c283554e7e5908f8ef1aff5225bfd3eb6a4e037b1a0995d', ('_scan_bytes', '_scan_json', 'inspect_image')), ('peaso/collectors/azure_app_settings_secret_indicators.py', 'f7fed346ff359f463e72cff63f4de9e1971e2aeef2223ed8b338c91c7520248b', ('_scan',)), ('peaso/collectors/azure_databricks_notebook_secret_indicators.py', '6eed83bf1d6b6e8055dabb1c0cee052f1b7c636121c742e74b8727bc23b4b222', ('_scan',)), ('peaso/collectors/azure_devops_git_native.py', '7b01f9f26acae14414d33b42095caad14adaf4644b3706fde2120e170b4c2c63', ('collect', 'project_response')), ('peaso/collectors/azure_devops_selected_content_secret_indicators.py', '3def2355bfad985b1543022cc14443677dd6ed37928a4d1109eeffb741fb5434', ('_part', '_scan')), ('peaso/collectors/azure_ml_selected_asset_secret_indicators.py', 'e5d98f9692035b60342526497ca70076a06cdafd3dbf8bfc0aa706ea70f2486f', ('_one',)), ('peaso/collectors/azure_ml_selected_job_secret_indicators.py', 'a0644628612d680fea88a9dcedca7541f1560278fc5d4ea116710739035143c3', ('_scan',)), ('peaso/collectors/azure_selected_configuration_secret_indicators.py', '570bf399805ef12cd647007d43ea450f1138244d58c4326972842c42281d7604', ('_scan',)), ('peaso/collectors/azure_selected_declaration_secret_indicators.py', '31b9a452cc530f4ceee89b1ca5b6892217eeea82d1699b9c86126e3fd9bdc6f2', ('_scan',)), ('peaso/collectors/azure_selected_log_sample_secret_indicators.py', 'fd07ef51f86ef4ed6889c62c532de732f69f7c76e568c08db6d39271094718f8', ('_scan',)), ('peaso/collectors/azure_selected_storage_secret_indicators.py', '59db1280c49909db57368b7e4e61e846f5f2c8ee1b323c6b2204f2110646beda', ('_inspect', '_scan')), ('peaso/collectors/gcp.py', 'f7554a0e905d712242bfd2826866517bbc410b1a4aa9e3ef195c75c07df37e96', ('Transport',)), ('peaso/collectors/gcp_additional_literal_secret_indicators.py', '0bfb934509a3ae9cd00f826371bbc1d7a7999d755d62a2234f1da650cc9ca492', ('scan_row',)), ('peaso/collectors/gcp_appengine_source_secret_indicators.py', '5f0dc6ceb82d853f10f4af47858504ae09b266e50800f49ecf8724238385ad61', ('collect_sources',)), ('peaso/collectors/gcp_artifact_file_secret_indicators.py', 'da4edfdac77dda5c80891ac7d812c1859e536e4786360b8d5656f64af289d4ff', ('_inspect',)), ('peaso/collectors/gcp_batch_referenced_source_20261020.py', 'c0bb32c6b0f8aaa0975ec3ed28875b2618ab8c2a674e16b41173e21ba4082921', ('collect',)), ('peaso/collectors/gcp_cloudrun_v2_job_declared_images_20261020.py', '91e6118e969286fd577eea11c65f5f2129e4711604c45414f601fbeb71ed0f51', ('_inspect',)), ('peaso/collectors/gcp_composer_source_secret_indicators.py', '2b357152018fc33b6cf31bba99ac52c2bd5bd9390a9c9c60233c26b66915f903', ('collect_sources',)), ('peaso/collectors/gcp_configuration_secret_indicators.py', '8c573da30b8bf20c1dfa88d450e44caf0935aa68f831fef941ef58f832901549', ('project_response',)), ('peaso/collectors/gcp_dataflow_referenced_source_20261020.py', 'c638e6ad782b475e9d6bc2ee93aed1bc57da67281bbb53ffa364935f84c6ad59', ('inspect_payload',)), ('peaso/collectors/gcp_dataform_secret_indicators.py', 'ca02f4a3025442421b25433a7930f157cb9ffd01295c8a07b8dce1d8a9428a70', ('collect_selected_files',)), ('peaso/collectors/gcp_dataproc_referenced_source_secret_indicators.py', '75f3bb777dd00bb154f24de0f459994fefbced29262c91ec17967618f54801f0', ('collect_sources',)), ('peaso/collectors/gcp_function_secret_indicators.py', 'f0107e484b39ca361710b0c838c07eb861fe8701239f79e91b41230a211b58c3', ('_scan_function',)), ('peaso/collectors/gcp_function_secret_pairs_20261020.py', 'e6f344088f0fbbbb50ff782852495cc9c23a874448e9b732543027e01e068598', ('_scan_function',)), ('peaso/collectors/gcp_gke_literal_secret_indicators.py', '9939b98e6393d33fc105d9f1f6ece556f697d19a69f6064149fcbbc0b52a3def', ('project_resource',)), ('peaso/collectors/gcp_image_secret_indicators.py', '2022bbd2816bfe82679b160c12b90d674c12746e14d95138bb3bb236dc0514c3', ('_tar', 'inspect_image')), ('peaso/collectors/gcp_job_literal_secret_indicators.py', 'afe4305155c2350cab0faa3f00d8a2a1431de0d23f890fe3780075abd77c8055', ('project_row',)), ('peaso/collectors/gcp_log_secret_indicators.py', '7600114140eef746787981f73b18b47910c0d82797662050f2a6944306b7b161', ('project_page',)), ('peaso/collectors/gcp_notebook_airflow_secret_indicators.py', '70d808587cca4847f5979f7ed9eb6452b6f332c6996d68157c7af00cf3278118', ('project_response',)), ('peaso/collectors/gcp_selected_archive_secret_indicators.py', '4dc9fd5feb8b193f5a119ee7b2f2b387d5eaf9f3c04fe2502c5df7e7ed07a4d3', ('_parse', 'collect_selected_archives')), ('peaso/collectors/gcp_selected_object_secret_indicators.py', 'fb9d1c2837660501bd87ab9642519f4caadfc395eee3193d1ccefd1bb2517959', ('collect_selected_objects',)), ('peaso/collectors/gcp_selected_task_routine_secret_indicators.py', '393720df111585dfd41e586f548ce35140a01e86dd980564805552b1b085cc66', ('collect_sources',)), ('peaso/collectors/gcp_sourcerepo_secret_indicators.py', 'ba809b97f9e9b36674b2938c74a1f9ee874e3121cbef947008db66091dbaf9e4', ('collect_sources',)), ('peaso/collectors/gcp_workbench_referenced_source_20261020.py', '3c8a3b4dcaf51c6f1544dd1d4465d8a60c00ec1d605a3d808e7590b0ce219b73', ('collect_sources',)), ('peaso/collectors/k8s.py', '86eca83f116bc8fe4a2b28d5ced1ae6612507c5cc3f53968fe6ec28df14a15f1', ('_native',)), ('peaso/collectors/k8s_literal_secret_indicators.py', '1ee91c6b52cf142d30ef58f55dd11f8e1688d129791c869a1a6783e7a80aa47b', ('collect',)), ('peaso/collectors/k8s_selected_log_sample_secret_indicators.py', '0fe2d51cb83f4126994f1bfaf1eff50c96469c3b1e285c44d78825f48328e9c0', ('collect',)), ('peaso/secret_scanning.py', '3897b64c134f88e7ad17c3c1f31df2b5497d34df6c1340d04e536313652f94f6', ('_scan_kingfisher', '_scan_trufflehog', 'scan_content')))
_PRIVATE_SOURCE_PATHS = frozenset(record[0] for record in _PRIVATE_SOURCE_RECORDS)
_PRIVATE_RECEIPT = 'peaso/checks/private_secret_shared_source_successor_20261021.json'
_PRIVATE_RECEIPT_SHA256 = 'e4aad924742e84af3e33af626de33765d20bbf06e7f9c3d1b8ae8a38a76d06c1'


def _private_binding_equal(actual, expected):
    # The inherited function maps have exact string keys. Check each field
    # without the quadratic arbitrary-key matching used for general literals.
    if type(actual) is not type(expected):
        return False
    if type(actual) is dict and all(type(key) is str for key in actual) and all(type(key) is str for key in expected):
        return (actual.keys() == expected.keys()
                and all(_private_binding_equal(actual[key], expected[key]) for key in expected))
    if type(actual) in (tuple, list):
        return len(actual) == len(expected) and all(_private_binding_equal(a, b) for a, b in zip(actual, expected))
    return _private_source_epoch._same(actual, expected)


def _private_receipt(parse=True):
    proven = _PRIVATE_PROVEN.get('_private_receipt')
    if not _attestation_mode.repeat(proven):
        return marshal.loads(proven) if parse else None
    raw = (Path(__file__).resolve().parents[2] / _PRIVATE_RECEIPT).read_bytes()
    if hashlib.sha256(raw).hexdigest() != _PRIVATE_RECEIPT_SHA256:
        raise RuntimeError('Private shared receipt changed')
    if parse:
        _PRIVATE_PROVEN['_private_receipt'] = marshal.dumps(json.loads(raw))
    return json.loads(raw) if parse else None


# BEGIN PRIVATE SELF CODE CACHE FACTORY
def _private_code_cache_factory():
    """Keep only authenticated, immutable code and source metadata."""
    import builtins as local_builtins
    import hashlib as local_hashlib
    import hmac as local_hmac
    import marshal as local_marshal
    import os as local_os
    import sys as local_sys
    import types as local_types

    entries = {}
    secret = local_os.urandom(32)

    def lookup(path, raw):
        if local_os is not local_sys.modules.get('os'):
            raise local_builtins.ValueError('Private cache random source changed')
        key = (local_builtins.str(path), local_builtins.str(path.resolve(strict=True)),
               local_hashlib.sha256(raw).digest(), local_sys.implementation.cache_tag,
               local_sys.flags.optimize)
        entry = entries.get(key)
        if entry is None:
            return None
        if (local_builtins.type(entry) is not local_builtins.tuple
                or local_builtins.len(entry) != 3
                or local_builtins.type(entry[0]) is not local_types.CodeType
                or local_builtins.type(entry[2]) is not local_builtins.bytes
                or not local_hmac.compare_digest(entry[2], local_hmac.digest(secret,
                    local_marshal.dumps((key, local_builtins.id(entry[0]), entry[1]), 2),
                    'sha256'))):
            raise local_builtins.ValueError('Private cache artifact changed')
        return entry[0], entry[1]

    return lookup
# END PRIVATE SELF CODE CACHE FACTORY


_PRIVATE_CODE_CACHE = _private_code_cache_factory()
_PRIVATE_CODE_CACHE_ANCHOR = _PRIVATE_CODE_CACHE
_PRIVATE_CODE_CACHE_STORAGE = _PRIVATE_CODE_CACHE.__closure__[0].cell_contents


_PRIVATE_SELF_PROVEN = []
_PRIVATE_PROVEN = {}


def _private_self():
    if not _attestation_mode.repeat(_PRIVATE_SELF_PROVEN):
        return
    receipt = _private_receipt(parse=True)
    path = Path(__file__).resolve()
    raw = path.read_bytes()
    normalized, count = re.subn(rb"(?m)^_PRIVATE_RECEIPT_SHA256 = '[0-9a-f]{64}'$", b"_PRIVATE_RECEIPT_SHA256 = '" + b'0' * 64 + b"'", raw)
    if count != 1 or hashlib.sha256(normalized).hexdigest() != receipt['source_sha256']:
        raise RuntimeError('Private shared source changed')
    root = path.parents[2]
    image_receipt = receipt['image_capture_admission']
    for relative, row in image_receipt['files'].items():
        current = (root / relative).read_bytes()
        if hashlib.sha256(current).hexdigest() != row['current_sha256']:
            raise RuntimeError('Image capture admitted source changed: ' + relative)
        prior = _reverse(current.decode('utf-8'), row).encode('utf-8')
        if hashlib.sha256(prior).hexdigest() != row['predecessor_sha256']:
            raise RuntimeError('Image capture exact inverse changed: ' + relative)
    # This is a finite extension of the existing private owner, not a new
    # admission layer.  The source bytes, live module, imports, constants,
    # class roster and executing method code must all agree.
    for relative, proof in receipt['runtime_helper_admission']['modules'].items():
        source_path = (root / relative).resolve()
        if not source_path.is_relative_to(root / 'peaso'):
            raise RuntimeError('Content cohort source location escaped package')
        source = source_path.read_bytes()
        if hashlib.sha256(source).hexdigest() != proof['sha256']:
            raise RuntimeError('Content cohort source changed: ' + relative)
        module_name = relative.removesuffix('.py').replace('/', '.')
        module = importlib.import_module(module_name)
        if sys.modules.get(module_name) is not module or Path(module.__file__).resolve() != source_path:
            raise RuntimeError('Content cohort module location changed: ' + relative)
        tree = ast.parse(source, filename=str(source_path))
        compiled_source = compile(source, str(source_path), 'exec',
                                  dont_inherit=True, optimize=sys.flags.optimize)
        for node in tree.body:
            if isinstance(node, ast.Import):
                for alias in node.names:
                    binding = alias.asname or alias.name.split('.')[0]
                    expected = sys.modules.get(alias.name if alias.asname else alias.name.split('.')[0])
                    if expected is None or vars(module).get(binding) is not expected:
                        raise RuntimeError('Content cohort import changed: ' + binding)
            elif isinstance(node, ast.ImportFrom):
                owner = importlib.import_module('.' * node.level + (node.module or ''), module.__package__)
                for alias in node.names:
                    binding = alias.asname or alias.name
                    if vars(module).get(binding) is not getattr(owner, alias.name):
                        raise RuntimeError('Content cohort from import changed: ' + binding)
        for name, expected in proof['constants'].items():
            if vars(module).get(name) != expected:
                raise RuntimeError('Content cohort constant changed: ' + name)
        if relative == 'peaso/secret_scanning_batch.py':
            for name, context_name in proof['contextvars'].items():
                value = vars(module).get(name)
                if type(value) is not ContextVar or value.name != context_name:
                    raise RuntimeError('Content cohort context changed: ' + name)
        declared_classes = {node.name for node in tree.body if isinstance(node, ast.ClassDef)}
        if relative not in ('peaso/collectors/aws_lambda_environment_secret_indicators.py',
                            'peaso/collectors/aws_image_vulnerability_native_20261021.py') and declared_classes != set(proof['classes']):
            raise RuntimeError('Content cohort class roster changed: ' + relative)
        if relative in ('peaso/secret_scanning_batch.py',
                        'peaso/collectors/aws_image_layer_pipeline_20261022.py'):
            declared_functions = {node.name for node in tree.body if isinstance(node, ast.FunctionDef)}
            if declared_functions != set(proof['functions']):
                raise RuntimeError('Content cohort batch callable roster changed')
        for class_name, class_proof in proof['classes'].items():
            owner = vars(module).get(class_name)
            class_node = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == class_name)
            class_source = b''.join(source.splitlines(keepends=True)[class_node.lineno - 1:class_node.end_lineno])
            methods = {node.name for node in class_node.body if isinstance(node, ast.FunctionDef)}
            if (type(owner) is not type or owner.__module__ != module_name
                    or owner.__qualname__ != class_name or owner.__bases__ != (object,)
                    or hashlib.sha256(class_source).hexdigest() != class_proof['sha256']
                    or methods != set(class_proof['methods'])
                    or set(vars(owner)) - {'__module__', '__doc__', '__dict__', '__weakref__',
                                            '__firstlineno__', '__static_attributes__'} != methods):
                raise RuntimeError('Content cohort class binding changed: ' + class_name)
        for qualified, callable_proof in proof['functions'].items():
            parts = qualified.split('.')
            nodes = tree.body
            expected_code = compiled_source
            target = module
            for part in parts:
                node = next(node for node in nodes if isinstance(node, (ast.ClassDef, ast.FunctionDef)) and node.name == part)
                expected_code = _private_source_epoch._code_from(expected_code, part)
                target = getattr(target, part)
                nodes = node.body
            if relative == 'peaso/secret_scanning_batch.py' and qualified in (
                    'prepared_content_batch', 'prepared_content_member'):
                _private_source_epoch._check_contextmanager_helper(
                    target, module, qualified, source_path, source)
            function = inspect.unwrap(target)
            start = min([node.lineno] + [decorator.lineno for decorator in node.decorator_list])
            fragment = b''.join(source.splitlines(keepends=True)[start - 1:node.end_lineno])
            if (relative == 'peaso/collectors/aws_lambda_environment_secret_indicators.py'
                    and qualified == 'collect_selected') or (
                    relative == 'peaso/collectors/aws_image_vulnerability_native_20261021.py'
                    and qualified == '_scan_bound'):
                transition = receipt['provider_group_callables'][relative + ':' + qualified]
                previous = _reverse(fragment.decode('utf-8'), transition).encode('utf-8')
                if hashlib.sha256(previous).hexdigest() != callable_proof['predecessor_sha256']:
                    raise RuntimeError('Content cohort Lambda predecessor changed')
            if (type(function) is not types.FunctionType
                    or function.__globals__ is not vars(module)
                    or function.__module__ != module_name or function.__qualname__ != qualified
                    or function.__closure__ is not None
                    or function.__code__.co_filename != str(source_path)
                    or not _private_source_epoch._code_equal(function.__code__, expected_code)
                    or hashlib.sha256(fragment).hexdigest() != callable_proof['sha256']
                    or inspect.getsource(function).encode() != fragment
                    or repr(function.__defaults__) != callable_proof['defaults']
                    or repr(function.__kwdefaults__) != callable_proof['kwdefaults']):
                raise RuntimeError('Content cohort executing callable changed: ' + qualified)
    capture_path = root / image_receipt['capture_path']
    capture_raw = capture_path.read_bytes()
    if hashlib.sha256(capture_raw).hexdigest() != image_receipt['capture_sha256']:
        raise RuntimeError('Image capture helper source changed')
    capture_module = sys.modules.get('peaso.collectors.aws_image_capture_20261022')
    if capture_module is not None:
        if Path(capture_module.__file__).resolve() != capture_path:
            raise RuntimeError('Image capture helper module location changed')
        capture_tree = ast.parse(capture_raw)
        capture_constants = _private_source_epoch._constants(capture_tree, str(capture_path))
        for key, value in image_receipt['constants'].items():
            if not _private_source_epoch._same(vars(capture_module).get(key), value):
                raise RuntimeError('Image capture helper bound changed: ' + key)
        for key, value in capture_constants.items():
            if not _private_source_epoch._same(vars(capture_module).get(key), value):
                raise RuntimeError('Image capture helper constant changed: ' + key)
        for node in capture_tree.body:
            if isinstance(node, ast.Import):
                for alias in node.names:
                    binding = alias.asname or alias.name.split('.')[0]
                    expected = sys.modules.get(alias.name if alias.asname else alias.name.split('.')[0])
                    if expected is None or vars(capture_module).get(binding) is not expected:
                        raise RuntimeError('Image capture helper import changed: ' + binding)
            elif isinstance(node, ast.ImportFrom):
                owner = sys.modules.get(node.module)
                for alias in node.names:
                    binding = alias.asname or alias.name
                    if owner is None or vars(capture_module).get(binding) is not getattr(owner, alias.name):
                        raise RuntimeError('Image capture helper from import changed: ' + binding)
        capture_class = capture_module._Capture
        if (type(capture_class) is not type or capture_class.__module__ != capture_module.__name__
                or capture_class.__qualname__ != '_Capture' or capture_class.__bases__ != (object,)
                or set(vars(capture_class)) - {'__firstlineno__', '__static_attributes__'} !=
                    {'__module__', '__init__', 'blob', 'close', '__dict__', '__weakref__', '__doc__'}):
            raise RuntimeError('Image capture helper class binding changed')
        _private_source_epoch._check_contextmanager_helper(capture_module.capture_scope,
            capture_module, 'capture_scope', capture_path, capture_raw)
        capture_compiled = compile(capture_raw, capture_module._authority.__code__.co_filename,
                                   'exec', dont_inherit=True, optimize=sys.flags.optimize)
        for qualified in image_receipt['callables']:
            function = capture_module
            for part in qualified.split('.'):
                function = getattr(function, part)
            function = inspect.unwrap(function)
            if (not isinstance(function, types.FunctionType)
                    or function.__globals__ is not vars(capture_module)
                    or function.__module__ != capture_module.__name__
                    or function.__qualname__ != qualified or function.__closure__ is not None):
                raise RuntimeError('Image capture helper callable binding changed: ' + qualified)
            expected = capture_compiled
            nodes = capture_tree.body
            owner = None
            for part in qualified.split('.'):
                expected = _private_source_epoch._code_from(expected, part)
                node = next(n for n in nodes if isinstance(n, (ast.ClassDef, ast.FunctionDef)) and n.name == part)
                nodes = node.body
            if not _private_source_epoch._code_equal(function.__code__, expected):
                raise RuntimeError('Image capture helper callable body changed: ' + qualified)
            _private_source_epoch._check_defaults(function, node, capture_constants,
                                                  function.__code__.co_filename, owner)
    # Existing finite owner also attests both new automatic workload helpers.
    workload_receipt = receipt['workload_environment_admission']
    for relative, proof in workload_receipt['helpers'].items():
        helper_path = (root / relative).resolve()
        if not helper_path.is_relative_to(root / 'peaso'):
            raise RuntimeError('Workload helper location escaped package')
        helper_raw = helper_path.read_bytes()
        if hashlib.sha256(helper_raw).hexdigest() != proof['sha256']:
            raise RuntimeError('Workload helper source changed: ' + relative)
        module_name = relative.removesuffix('.py').replace('/', '.')
        helper_module = importlib.import_module(module_name)
        if (sys.modules.get(module_name) is not helper_module
                or Path(helper_module.__file__).resolve() != helper_path):
            raise RuntimeError('Workload helper module binding changed: ' + relative)
        tree = ast.parse(helper_raw, filename=str(helper_path))
        compiled = compile(helper_raw, str(helper_path), 'exec',
                           dont_inherit=True, optimize=sys.flags.optimize)
        declared = {node.name: node for node in tree.body
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}
        actual = {name for name, value in vars(helper_module).items()
                  if type(value) is types.FunctionType
                  and value.__module__ == module_name}
        if set(proof['functions']) != set(declared) or actual != set(declared):
            raise RuntimeError('Workload helper callable roster changed: ' + relative)
        for name, row in proof['functions'].items():
            function = vars(helper_module)[name]
            node = declared[name]
            source = b''.join(helper_raw.splitlines(keepends=True)[
                min([node.lineno] + [part.lineno for part in node.decorator_list]) - 1:node.end_lineno])
            expected_code = _private_source_epoch._code_from(compiled, name)
            if (function.__globals__ is not vars(helper_module)
                    or function.__qualname__ != name or function.__closure__ is not None
                    or function.__code__.co_filename != str(helper_path)
                    or not _private_source_epoch._code_equal(function.__code__, expected_code)
                    or hashlib.sha256(source).hexdigest() != row['sha256']
                    or inspect.getsource(function).encode() != source
                    or repr(function.__defaults__) != row['defaults']
                    or repr(function.__kwdefaults__) != row['kwdefaults']):
                raise RuntimeError('Workload helper executing callable changed: ' + name)
        if module_name == 'peaso.collectors.workload_environment_discovery':
            import dataclasses
            cls = vars(helper_module).get('Plan')
            if (not isinstance(cls, type) or cls.__module__ != module_name
                    or cls.__qualname__ != 'Plan' or not dataclasses.is_dataclass(cls)
                    or not cls.__dataclass_params__.frozen
                    or tuple(field.name for field in dataclasses.fields(cls)) !=
                       ('targets', 'discovered', 'complete', 'reason')
                    or helper_module.dataclass is not dataclasses.dataclass
                    or helper_module.DENIAL_CODES != frozenset(workload_receipt['denial_codes'])):
                raise RuntimeError('Workload planner class or constant changed')
        elif module_name == 'peaso.checks.automatic_workload_batch':
            from copy import deepcopy
            if helper_module.deepcopy is not deepcopy:
                raise RuntimeError('Workload batch import binding changed')
            routes = _private_source_epoch._constants(tree, str(helper_path))['AUTO_CHECKS']
            if not _private_source_epoch._same(helper_module.AUTO_CHECKS, routes):
                raise RuntimeError('Workload batch routes changed')
    original_path = root / receipt['canonical_path']
    if hashlib.sha256(original_path.read_bytes()).hexdigest() != receipt['canonical_sha256']:
        raise RuntimeError('Private shared canonical predecessor changed')
    if (sys.modules.get('peaso.private_secret_source_epoch_20261021') is not _private_source_epoch
            or Path(_private_source_epoch.__file__).resolve() != root / 'peaso/private_secret_source_epoch_20261021.py'
            or hashlib.sha256(Path(_private_source_epoch.__file__).read_bytes()).hexdigest() != receipt['common_source_sha256']):
        raise RuntimeError('Private shared common attestor changed')
    _private_source_epoch.source_rows()
    # Current KMS state correction is the only new recheck-module delta.
    # Reconstruct the unchanged historical source and bind its live constants;
    # the runtime-helper proof above checks every import and callable body.
    kms_proof = receipt['aws_kms_recheck_admission']
    kms_relative = 'peaso/checks/aws_ai_recheck_corrections_20261020.py'
    if (kms_proof['source_path'] != kms_relative
            or set(kms_proof) != {'source_path', 'predecessor_sha256', 'ids',
                                  'policy_use', 'boundary_applicability'}):
        raise RuntimeError('KMS recheck admission shape changed')
    kms_transition = receipt['provider_group_files'][kms_relative]
    kms_raw = (root / kms_relative).read_bytes()
    if (hashlib.sha256(kms_raw).hexdigest() != kms_transition['current_sha256']
            or kms_proof['predecessor_sha256'] != kms_transition['predecessor_sha256']
            or hashlib.sha256(_reverse(kms_raw.decode('utf-8'), kms_transition).encode()).hexdigest()
            != kms_proof['predecessor_sha256']):
        raise RuntimeError('KMS recheck exact source predecessor changed')
    kms_module = importlib.import_module('peaso.checks.aws_ai_recheck_corrections_20261020')
    kms_functions = {name for name, value in vars(kms_module).items()
                     if type(value) is types.FunctionType and value.__module__ == kms_module.__name__}
    if (sys.modules.get(kms_module.__name__) is not kms_module
            or Path(kms_module.__file__).resolve() != root / kms_relative
            or kms_functions != set(receipt['runtime_helper_admission']['modules'][kms_relative]['functions'])
            or any(type(getattr(kms_module, name.upper())) is not set
                   or sorted(getattr(kms_module, name.upper())) != kms_proof[name]
                   for name in ('ids', 'policy_use', 'boundary_applicability'))):
        raise RuntimeError('KMS recheck live module or IDs changed')
    override_transition = receipt['provider_group_callables'][kms_relative + ':_override']
    override_source = inspect.getsource(kms_module._override)
    if (hashlib.sha256(override_source.encode()).hexdigest() != override_transition['current_sha256']
            or hashlib.sha256(_reverse(override_source, override_transition).encode()).hexdigest()
            != override_transition['predecessor_sha256']):
        raise RuntimeError('KMS recheck callable predecessor changed')
    # Admit the one new engine-local factory through this existing finite
    # owner. The file transition above still reconstructs its historical
    # predecessor, and the live factory must match the signed current source.
    engine_proof = receipt['engine_finding_factory_admission']
    if set(engine_proof) != {'source_sha256', 'fragment_sha256', 'defaults',
                             'kwdefaults', 'lazy_imports', 'original_finding_sha256',
                             'factory_span', 'original_finding_span'}:
        raise RuntimeError('Engine factory admission shape changed')
    engine_path = (root / 'peaso/engine.py').resolve()
    engine_raw = engine_path.read_bytes()
    if (hashlib.sha256(engine_raw).hexdigest() != engine_proof['source_sha256']
            or engine_proof['source_sha256'] !=
            receipt['provider_group_files']['peaso/engine.py']['current_sha256']):
        raise RuntimeError('Engine factory source changed')
    engine_module = importlib.import_module('peaso.engine')
    if (sys.modules.get('peaso.engine') is not engine_module
            or Path(engine_module.__file__).resolve() != engine_path
            or engine_module.digest is not importlib.import_module('peaso.snapshot').digest):
        raise RuntimeError('Engine factory module or digest binding changed')
    engine_lines = engine_raw.splitlines(keepends=True)
    def engine_fragment(span):
        if (type(span) is not list or len(span) != 2
                or any(type(line) is not int for line in span)
                or not 1 <= span[0] <= span[1] <= len(engine_lines)):
            raise RuntimeError('Engine factory source span changed')
        return b''.join(engine_lines[span[0] - 1:span[1]])
    factory_fragment = engine_fragment(engine_proof['factory_span'])
    original_fragment = engine_fragment(engine_proof['original_finding_span'])
    factory_tree = ast.parse(factory_fragment, filename=str(engine_path))
    factory = next((node for node in factory_tree.body
                    if isinstance(node, ast.FunctionDef) and node.name == '_finding_factory'), None)
    if factory is None or len(factory_tree.body) != 1 or not original_fragment.startswith(b'def _finding('):
        raise RuntimeError('Engine factory or original finding missing')
    lazy_imports = [[node.level, node.module,
                     [[alias.name, alias.asname] for alias in node.names]]
                    for node in ast.walk(factory) if isinstance(node, ast.ImportFrom)]
    function = vars(engine_module).get('_finding_factory')
    first = engine_proof['factory_span'][0]
    expected_source = b'from __future__ import annotations\n' + b'\n' * (first - 2) + factory_fragment
    try:
        expected_code = _private_source_epoch._code_from(
            _private_source_epoch._BOOTSTRAP_ARTIFACT(expected_source, str(engine_path), 0),
            '_finding_factory')
    except ValueError as exc:
        raise RuntimeError('Engine factory cached source artifact changed') from exc
    if (type(function) is not types.FunctionType
            or function.__globals__ is not vars(engine_module)
            or function.__module__ != 'peaso.engine'
            or function.__qualname__ != '_finding_factory'
            or function.__closure__ is not None
            or function.__code__.co_filename != str(engine_path)
            or not _private_source_epoch._code_equal(function.__code__, expected_code)
            or hashlib.sha256(factory_fragment).hexdigest() != engine_proof['fragment_sha256']
            or hashlib.sha256(original_fragment).hexdigest() !=
                engine_proof['original_finding_sha256']
            or inspect.getsource(function).encode() != factory_fragment
            or repr(function.__defaults__) != engine_proof['defaults']
            or repr(function.__kwdefaults__) != engine_proof['kwdefaults']
            or lazy_imports != engine_proof['lazy_imports']):
        raise RuntimeError('Engine factory executing source changed')
    sw46_proof = receipt['sw46_join_admission']
    if set(sw46_proof) != {'files', 'callables', 'ids'} or set(sw46_proof['files']) != {
            'peaso/checks/bulk_pending.py', 'peaso/checks/compliance_new_sw46.py'} or (
            set(sw46_proof['callables']) != set(sw46_proof['files'])
            or set(sw46_proof['callables']['peaso/checks/bulk_pending.py']) !=
                {'_reviewed_source_admitted'}
            or set(sw46_proof['callables']['peaso/checks/compliance_new_sw46.py']) !=
                {'_context', '_items', '_validated_items', '_resource_lookup', '_resource'}):
        raise RuntimeError('SW46 finite admission shape changed')
    for relative, transition in sw46_proof['files'].items():
        source_path = (root / relative).resolve()
        source = source_path.read_bytes()
        if hashlib.sha256(source).hexdigest() != transition['current_sha256']:
            raise RuntimeError('SW46 admitted source changed: ' + relative)
        previous = _reverse(source.decode('utf-8'), transition).encode('utf-8')
        if hashlib.sha256(previous).hexdigest() != transition['predecessor_sha256']:
            raise RuntimeError('SW46 signed predecessor changed: ' + relative)
    bulk_module = importlib.import_module('peaso.checks.bulk_pending')
    sw46_module = sys.modules.get('peaso.checks._bulk_pending_compliance_new_sw46')
    if sw46_module is None:
        raise RuntimeError('SW46 registered module missing')
    facts_module = importlib.import_module('peaso.checks.facts')
    for module, relative in ((bulk_module, 'peaso/checks/bulk_pending.py'),
                             (sw46_module, 'peaso/checks/compliance_new_sw46.py')):
        source_path = (root / relative).resolve()
        source = source_path.read_bytes()
        if Path(module.__file__).resolve() != source_path or sys.modules.get(module.__name__) is not module:
            raise RuntimeError('SW46 module location changed: ' + relative)
        try:
            compiled = _private_source_epoch._BOOTSTRAP_ARTIFACT(source, str(source_path), 0)
        except ValueError as exc:
            raise RuntimeError('SW46 cached source artifact changed: ' + relative) from exc
        lines = source.splitlines(keepends=True)
        expected_names = set(sw46_proof['callables'][relative])
        if expected_names != ({'_reviewed_source_admitted'} if relative.endswith('bulk_pending.py')
                              else {'_context', '_items', '_validated_items',
                                    '_resource_lookup', '_resource'}):
            raise RuntimeError('SW46 admitted helper roster changed: ' + relative)
        for name, proof in sw46_proof['callables'][relative].items():
            span = proof['span']
            if (set(proof) != {'sha256', 'span', 'defaults', 'kwdefaults'}
                    or type(span) is not list or len(span) != 2
                    or any(type(line) is not int for line in span)
                    or not 1 <= span[0] <= span[1] <= len(lines)):
                raise RuntimeError('SW46 admitted helper source span changed: ' + name)
            fragment = b''.join(lines[span[0] - 1:span[1]])
            if not fragment.startswith(('def ' + name + '(').encode()):
                raise RuntimeError('SW46 admitted helper definition changed: ' + name)
            function = vars(module).get(name)
            expected_code = _private_source_epoch._code_from(compiled, name)
            if (type(function) is not types.FunctionType
                    or function.__globals__ is not vars(module)
                    or function.__module__ != module.__name__ or function.__qualname__ != name
                    or function.__closure__ is not None
                    or function.__code__.co_filename != str(source_path)
                    or not _private_source_epoch._code_equal(function.__code__, expected_code)
                    or hashlib.sha256(fragment).hexdigest() != proof['sha256']
                    or inspect.getsource(function).encode() != fragment
                    or repr(function.__defaults__) != proof['defaults']
                    or repr(function.__kwdefaults__) != proof['kwdefaults']):
                raise RuntimeError('SW46 executing helper changed: ' + name)
    if (vars(sw46_module).get('MemoIndex') is not facts_module.MemoIndex
            or vars(sw46_module).get('memoized') is not facts_module.memoized
            or vars(sw46_module).get('Unavailable') is not facts_module.Unavailable
            or vars(sw46_module).get('complete_items') is not facts_module.complete_items
            or vars(sw46_module).get('get') is not facts_module.get
            or vars(sw46_module).get('re') is not re
            or vars(bulk_module).get('hashlib') is not hashlib
            or vars(bulk_module).get('json') is not json
            or vars(bulk_module).get('Path') is not Path):
        raise RuntimeError('SW46 scan-local memo imports changed')
    registry = importlib.import_module('peaso.checks')
    if any(vars(sw46_module).get(name) is not getattr(registry, name)
           for name in ('CHECKS', 'result', 'unknown')):
        raise RuntimeError('SW46 registered imports changed')
    if vars(sw46_module).get('_IDS') != sw46_proof['ids']:
        raise RuntimeError('SW46 identity map changed')
    registered = next((check for check in registry.CHECKS
                       if check.id == 'aws_ec2_instance_time_offset_monitored'), None)
    callback = None if registered is None else registered.evaluate
    seen = set()
    while callback is not None and id(callback) not in seen:
        if getattr(callback, '__globals__', None) is vars(sw46_module):
            break
        seen.add(id(callback))
        callback = getattr(callback, '__wrapped__', None)
    if callback is None or getattr(callback, '__globals__', None) is not vars(sw46_module):
        raise RuntimeError('SW46 registered callback is not the admitted module')
    lines = raw.splitlines(keepends=True)
    begin = [i for i, line in enumerate(lines) if line == b'# BEGIN PRIVATE SELF CODE CACHE FACTORY\n']
    end = [i for i, line in enumerate(lines) if line == b'# END PRIVATE SELF CODE CACHE FACTORY\n']
    if len(begin) != 1 or len(end) != 1 or end[0] <= begin[0] + 1:
        raise RuntimeError('Private cache factory source changed')
    fragment = b'\n' * (begin[0] + 1) + b''.join(lines[begin[0] + 1:end[0]])
    boot_code = compile(fragment, __file__, 'exec', dont_inherit=True, optimize=sys.flags.optimize)
    factory_code = [code for code in boot_code.co_consts
                    if type(code) is types.CodeType and code.co_name == '_private_code_cache_factory']
    if len(factory_code) != 1:
        raise RuntimeError('Private cache factory ambiguous')
    lookup_code = [code for code in factory_code[0].co_consts
                   if type(code) is types.CodeType and code.co_name == 'lookup']
    factory = globals().get('_private_code_cache_factory')
    lookup = globals().get('_PRIVATE_CODE_CACHE')
    if (len(lookup_code) != 1 or type(factory) is not types.FunctionType
            or factory.__globals__ is not globals() or factory.__closure__ is not None
            or factory.__defaults__ is not None or factory.__kwdefaults__ is not None
            or factory.__module__ != __name__ or factory.__qualname__ != '_private_code_cache_factory'
            or not _private_source_epoch._immutable_code_constants(factory.__code__)
            or not _private_source_epoch._code_equal(factory.__code__, factory_code[0])
            or type(lookup) is not types.FunctionType or lookup is not _PRIVATE_CODE_CACHE_ANCHOR
            or lookup.__globals__ is not globals() or lookup.__module__ != __name__
            or lookup.__qualname__ != '_private_code_cache_factory.<locals>.lookup'
            or lookup.__defaults__ is not None or lookup.__kwdefaults__ is not None
            or not _private_source_epoch._immutable_code_constants(lookup.__code__)
            or not _private_source_epoch._code_equal(lookup.__code__, lookup_code[0])
            or lookup.__closure__ is None):
        raise RuntimeError('Private cache binding changed')
    cells = dict(zip(lookup.__code__.co_freevars, (cell.cell_contents for cell in lookup.__closure__)))
    if (set(cells) != {'entries', 'local_builtins', 'local_hashlib', 'local_hmac',
                       'local_marshal', 'local_os', 'local_sys', 'local_types', 'secret'}
            or cells['entries'] is not _PRIVATE_CODE_CACHE_STORAGE
            or type(_PRIVATE_CODE_CACHE_STORAGE) is not dict
            or type(cells['secret']) is not bytes or len(cells['secret']) != 32
            or cells['local_builtins'] is not sys.modules.get('builtins')
            or cells['local_hashlib'] is not hashlib or cells['local_hmac'] is not hmac
            or cells['local_marshal'] is not marshal or cells['local_os'] is not os
            or cells['local_sys'] is not sys or cells['local_types'] is not types):
        raise RuntimeError('Private cache closure changed')
    try:
        artifact = lookup(path, raw)
    except (ValueError, TypeError, AttributeError) as exc:
        raise RuntimeError('Private cache artifact changed') from exc
    if artifact is None:
        tree = ast.parse(raw, filename=__file__)
        pinned_records = next(ast.literal_eval(node.value) for node in tree.body
                              if isinstance(node, ast.Assign) and len(node.targets) == 1
                              and isinstance(node.targets[0], ast.Name) and node.targets[0].id == '_PRIVATE_SOURCE_RECORDS')
        literal_bindings = {node.targets[0].id: ast.literal_eval(node.value) for node in tree.body
                            if isinstance(node, ast.Assign) and len(node.targets) == 1
                            and isinstance(node.targets[0], ast.Name)
                            and node.targets[0].id in ('_PRIVATE_RECEIPT', '_PRIVATE_RECEIPT_SHA256')}
        compiled = compile(raw, __file__, 'exec', dont_inherit=True, optimize=sys.flags.optimize)
        metadata = (pinned_records, tuple(sorted(literal_bindings.items())))
    else:
        compiled, metadata = artifact
        if (type(metadata) is not tuple or len(metadata) != 2
                or type(metadata[0]) is not tuple or type(metadata[1]) is not tuple):
            raise RuntimeError('Private cache metadata changed')
        pinned_records, bindings = metadata
        literal_bindings = dict(bindings)
    def immutable(value):
        if type(value) is types.CodeType:
            return all(immutable(item) for item in value.co_consts)
        if type(value) in (tuple, frozenset):
            return all(immutable(item) for item in value)
        return value is None or value is Ellipsis or type(value) in (
            bool, int, float, complex, str, bytes)
    if not immutable(compiled) or not immutable(metadata):
        raise RuntimeError('Private cache artifact is mutable')
    if (not _private_source_epoch._same(_PRIVATE_SOURCE_RECORDS, pinned_records)
            or type(_PRIVATE_SOURCE_PATHS) is not frozenset
            or _PRIVATE_SOURCE_PATHS != frozenset(record[0] for record in pinned_records)):
        raise RuntimeError('Private shared finite source roster binding changed')
    if (sys.modules.get('peaso.checks.gcp_positive_conservation_shared_source_successor_20261020') is not _private_canonical
            or Path(_private_canonical.__file__).resolve() != original_path.resolve()):
        raise RuntimeError('Private shared canonical module binding changed')
    for key, expected in vars(_private_canonical).items():
        if key.startswith('__') or key in ('_COMPILED_TRANSACTION', '_TRANSACTION_CONTEXT'):
            continue
        if isinstance(expected, types.FunctionType) and expected.__globals__ is vars(_private_canonical):
            continue
        if key not in globals() or not _private_binding_equal(globals()[key], expected):
            raise RuntimeError('Private shared inherited binding changed: ' + key)
    module = sys.modules.get(__name__)
    if module is None or vars(module) is not globals():
        raise RuntimeError('Private shared live module changed')
    if (literal_bindings.get('_PRIVATE_RECEIPT') != _PRIVATE_RECEIPT
            or literal_bindings.get('_PRIVATE_RECEIPT_SHA256') != _PRIVATE_RECEIPT_SHA256):
        raise RuntimeError('Private shared receipt literal binding changed')
    expected_functions = {code.co_name: code for code in compiled.co_consts if type(code) is types.CodeType}
    functions = {name: value for name, value in globals().items()
                 if isinstance(value, types.FunctionType) and value.__globals__ is globals()
                 and name not in ('_PRIVATE_CODE_CACHE', '_PRIVATE_CODE_CACHE_ANCHOR')}
    if set(functions) != set(receipt['functions']):
        raise RuntimeError('Private shared live roster changed')
    for name, function in functions.items():
        expected_code = expected_functions.get(name)
        row = receipt['functions'][name]
        if (expected_code is None or function.__module__ != __name__ or function.__qualname__ != name
                or inspect.unwrap(function) is not function
                or not _private_source_epoch._code_equal(function.__code__, expected_code)
                or function.__closure__ is not None
                or repr(function.__defaults__) != row['defaults']
                or repr(function.__kwdefaults__) != row['kwdefaults']):
            raise RuntimeError('Private shared live callable changed: ' + name)
    if artifact is None:
        key = (str(path), str(path.resolve(strict=True)), hashlib.sha256(raw).digest(),
               sys.implementation.cache_tag, sys.flags.optimize)
        signature = hmac.digest(cells['secret'], marshal.dumps((key, id(compiled), metadata), 2), 'sha256')
        if len(_PRIVATE_CODE_CACHE_STORAGE) >= 4:
            _PRIVATE_CODE_CACHE_STORAGE.clear()
        _PRIVATE_CODE_CACHE_STORAGE[key] = (compiled, metadata, signature)
    _PRIVATE_SELF_PROVEN.append(True)



def _private_before(relative, raw, root):
    if relative == 'peaso/collectors/aws_package_content_indicators.py':
        return rawv2_package_source(raw, 'ce459d4b5ed0ae991591f09f61b462f7841f0977d5935579e561409c0117e7e6', root)
    if relative == 'peaso/collectors/aws_facts_swc.py':
        transition = _private_source_epoch._receipt()[0]['current_reviewed_files'][relative]
        return _private_source_epoch.predecessor_bytes(relative, raw, transition['predecessor_sha256'], root)
    if relative in ('peaso/engine.py', 'peaso/collectors/bulk_evidence.py', 'peaso/collectors/aws.py', 'peaso/server/validation.py', 'peaso/collectors/aws_workload_command_runtime_20261020.py', 'peaso/collectors/azure_function_package_source_20261020.py', 'peaso/checks/azure_metadata_only_tde_admission_successor_20261020.py', 'peaso/checks/azure_acr_image_secret_review_20261020.py', 'peaso/checks/gcp_cloudbuild_log_secret_review_20261019.py', 'peaso/checks/k8s_literal_secret_review_20261020.py', 'peaso/checks/k8s_ports_components.py', 'peaso/collectors/gcp_cloudbuild_log_secret_indicators.py', 'peaso/collectors/gcp_cloudrun_content_sources.py', 'peaso/collectors/gcp_job_image_vulnerability_runtime_20261021.py', 'peaso/server/image_selection_options_20261021.py', 'peaso/collectors/azure_selected_secret_integration_20261020.py', 'peaso/checks/k8s_selected_metadata_secret_admission_20261020.py', 'peaso/snapshot.py', 'peaso/collectors/azure_function_settings_declarations_20261020.py', 'peaso/collectors/azure_apim_operation_window_20261020.py', 'peaso/checks/aws_ai_recheck_corrections_20261020.py', 'peaso/secret_findings.py'):
        transition = _private_receipt()['provider_group_files'][relative]
        _private_self()
        if relative == 'peaso/checks/azure_metadata_only_tde_admission_successor_20261020.py':
            raw = _reviewed_epoch.previous_guard_source(relative, raw, root)
        if relative != 'peaso/checks/azure_metadata_only_tde_admission_successor_20261020.py' and raw != (root / relative).read_bytes():
            raise RuntimeError('Provider group source bytes differ from disk')
        restored = _reverse(raw.decode('utf-8'), transition).encode('utf-8')
        if hashlib.sha256(restored).hexdigest() != transition['predecessor_sha256']:
            raise RuntimeError('Provider group source predecessor changed')
        return restored
    if relative not in _PRIVATE_SOURCE_PATHS:
        return raw
    before = next(row[1] for row in _PRIVATE_SOURCE_RECORDS if row[0] == relative)
    return _reviewed_epoch.predecessor_bytes(relative, raw, before, root)


def _private_row(function, row, root):
    if ((row.get('path') == 'peaso/collectors/aws_package_content_indicators.py'
             and function.__qualname__ in ('_image', '_lambda', '_layer', '_scan'))
            or (row.get('path') == 'peaso/collectors/azure_selected_storage_secret_indicators.py'
                and function.__qualname__ in ('_inspect', '_scan'))):
        return rawv2_current_content_projection(function, row, root)
    path = row.get('path')
    if path == 'peaso/collectors/gcp.py' and function.__qualname__ == 'GCPCollector.envelope':
        _private_before(path, (root / path).read_bytes(), root)
        current_fragment = inspect.getsource(function)
        epoch_fragment = _reviewed_epoch.previous_gcp_method_source('envelope', current_fragment, root)
        if hashlib.sha256(epoch_fragment.encode()).hexdigest() != row['sha256']:
            raise RuntimeError('GCP collector envelope predecessor changed')
        return dict(row, sha256=hashlib.sha256(current_fragment.encode()).hexdigest())
    if path not in _PRIVATE_SOURCE_PATHS and path not in ('peaso/engine.py', 'peaso/collectors/bulk_evidence.py', 'peaso/collectors/aws.py', 'peaso/server/validation.py', 'peaso/collectors/aws_workload_command_runtime_20261020.py', 'peaso/collectors/azure_function_package_source_20261020.py', 'peaso/checks/azure_metadata_only_tde_admission_successor_20261020.py', 'peaso/checks/azure_acr_image_secret_review_20261020.py', 'peaso/checks/gcp_cloudbuild_log_secret_review_20261019.py', 'peaso/checks/k8s_literal_secret_review_20261020.py', 'peaso/checks/k8s_ports_components.py', 'peaso/collectors/gcp_cloudbuild_log_secret_indicators.py', 'peaso/collectors/gcp_cloudrun_content_sources.py', 'peaso/collectors/gcp_job_image_vulnerability_runtime_20261021.py', 'peaso/snapshot.py', 'peaso/server/image_selection_options_20261021.py', 'peaso/collectors/azure_selected_secret_integration_20261020.py', 'peaso/checks/k8s_selected_metadata_secret_admission_20261020.py', 'peaso/collectors/azure_function_settings_declarations_20261020.py', 'peaso/collectors/azure_apim_operation_window_20261020.py', 'peaso/checks/aws_ai_recheck_corrections_20261020.py', 'peaso/secret_findings.py'):
        _private_receipt(parse=False)
        return row
    key = str(path) + ':' + function.__qualname__
    transition = _private_receipt()['provider_group_callables'].get(key)
    if transition is not None and not (path == 'peaso/collectors/azure.py' and function.__qualname__ == 'collect'):
        if row.get('sha256') != transition['predecessor_sha256'] or row.get('qualname') != function.__qualname__:
            raise RuntimeError('Provider group callable predecessor row changed')
        _private_before(path, (root / path).read_bytes(), root)
        if path == 'peaso/collectors/gcp.py' and function.__qualname__.startswith('GCPCollector.'):
            method = function.__qualname__.split('.', 1)[1]
            if method in ('__init__', 'collect', 'dependent_jobs', 'finish', 'scope_jobs', 'workspace_directory'):
                current_fragment = inspect.getsource(function)
                epoch_fragment = _reviewed_epoch.previous_gcp_method_source(method, current_fragment, root)
                if hashlib.sha256(epoch_fragment.encode()).hexdigest() != transition['current_sha256']:
                    raise RuntimeError('GCP collector method epoch successor changed: ' + method)
                return dict(row, sha256=hashlib.sha256(current_fragment.encode()).hexdigest(), defaults=transition.get('defaults', row.get('defaults')), kwdefaults=transition.get('kwdefaults', row.get('kwdefaults')))
        if path == 'peaso/collectors/k8s.py' and function.__qualname__ == 'collect':
            current_fragment = inspect.getsource(function)
            epoch_fragment = _reviewed_epoch.previous_function_source(path, 'collect', current_fragment, root)
            if hashlib.sha256(epoch_fragment.encode()).hexdigest() != transition['current_sha256']:
                raise RuntimeError('Kubernetes collect epoch successor changed')
            return dict(row, sha256=hashlib.sha256(current_fragment.encode()).hexdigest(), defaults=transition.get('defaults', row.get('defaults')), kwdefaults=transition.get('kwdefaults', row.get('kwdefaults')))
        if path == 'peaso/collectors/azure.py' and function.__qualname__ == '_selected':
            current_fragment = inspect.getsource(function)
            epoch_fragment = _reviewed_epoch.previous_function_source(path, '_selected', current_fragment, root)
            if hashlib.sha256(epoch_fragment.encode()).hexdigest() != transition['current_sha256']:
                raise RuntimeError('Provider group Azure selected epoch successor changed')
            return dict(row, sha256=hashlib.sha256(current_fragment.encode()).hexdigest(), defaults=transition.get('defaults', row.get('defaults')), kwdefaults=transition.get('kwdefaults', row.get('kwdefaults')))
        if path == 'peaso/checks/azure_metadata_only_tde_admission_successor_20261020.py' and function.__qualname__ == 'reviewed_inputs':
            current_fragment = inspect.getsource(function)
            prior_fragment = _reviewed_epoch.previous_guard_function_source(path, 'reviewed_inputs', current_fragment, root)
            if hashlib.sha256(prior_fragment.encode()).hexdigest() != transition['current_sha256']:
                raise RuntimeError('Azure TDE reviewed callable predecessor changed')
            return dict(row, sha256=hashlib.sha256(current_fragment.encode()).hexdigest(), defaults=transition.get('defaults', row.get('defaults')), kwdefaults=transition.get('kwdefaults', row.get('kwdefaults')))
        return dict(row, sha256=transition['current_sha256'], defaults=transition.get('defaults', row.get('defaults')), kwdefaults=transition.get('kwdefaults', row.get('kwdefaults')))
    if path == 'peaso/collectors/azure.py' and function.__qualname__ == 'collect':
        transition = _private_receipt()['provider_group_azure_collect']
        if row.get('qualname') != 'collect' or row.get('sha256') != transition['predecessor_sha256']:
            raise RuntimeError('Provider group Azure collect predecessor row changed')
        _private_before(path, (root / path).read_bytes(), root)
        current_fragment = inspect.getsource(function)
        epoch_fragment = _reviewed_epoch.previous_function_source(path, 'collect', current_fragment, root)
        if hashlib.sha256(epoch_fragment.encode()).hexdigest() != transition['current_sha256']:
            raise RuntimeError('Provider group Azure collect epoch successor changed')
        return dict(row, sha256=hashlib.sha256(current_fragment.encode()).hexdigest(), defaults=transition.get('defaults', row.get('defaults')), kwdefaults=transition.get('kwdefaults', row.get('kwdefaults')))
    if path not in _PRIVATE_SOURCE_PATHS:
        return row
    if path == 'peaso/secret_scanning.py':
        from peaso.rawv2_private_source_successor_20261021 import producer_row
        return producer_row(function, row, root)
    names = next(record[2] for record in _PRIVATE_SOURCE_RECORDS if record[0] == path)
    if function.__qualname__ not in names:
        if function.__qualname__ not in ('AzureTransport.request', 'Transport.request'):
            _private_before(path, (root / path).read_bytes(), root)
            return row
    if path in ('peaso/checks/gcp_artifact_file_secret_review_20261019.py', 'peaso/checks/gcp_composer_source_secret_review_20261019.py', 'peaso/checks/gcp_image_secret_review_20261019.py', 'peaso/checks/gcp_selected_archive_secret_review_20261019.py', 'peaso/checks/gcp_sourcerepo_secret_review_20261019.py', 'peaso/checks/gcp_task_routine_secret_review_20261020.py', 'peaso/collectors/gcp_artifact_file_secret_indicators.py', 'peaso/collectors/gcp_composer_source_secret_indicators.py', 'peaso/collectors/gcp_image_secret_indicators.py', 'peaso/collectors/gcp_selected_archive_secret_indicators.py', 'peaso/collectors/gcp_selected_task_routine_secret_indicators.py', 'peaso/collectors/gcp_sourcerepo_secret_indicators.py'):
        # The retained positive-conservation guard binds this older row to
        # its exact 12-leaf predecessor. Prove the private-current function
        # separately; do not mislabel the older row as the private predecessor.
        _private_source_epoch.trusted_definition(function, root)
        return row
    if 'line' in row:
        before = _private_before(path, (root / path).read_bytes(), root)
        matches = [(record, code) for record, code in _compiled_source(before, str(root / path), sys.flags.optimize)
                   if record['qualname'] == row.get('qualname')]
        if (len(matches) != 1 or type(row['line']) is not int
                or row['line'] != matches[0][1].co_firstlineno):
            raise RuntimeError('Private historical callable line changed')
        projected = _private_source_epoch.callable_projection(function, {key: value for key, value in row.items() if key != 'line'}, root)
        return dict(projected, line=inspect.unwrap(function).__code__.co_firstlineno)
    return _private_source_epoch.callable_projection(function, row, root)

def _admitted_scanner_bytes(name, raw, expected, root):
    if name == 'peaso/checks/k8s_selected_metadata_secret_admission_20261020.py':
        live = (root / name).read_bytes()
        if raw != original.prepared._self(live):
            raise RuntimeError('Metadata admission self normalization changed')
        transition = _private_source_epoch._receipt()[0]['current_reviewed_files'][name]
        predecessor = _private_source_epoch.predecessor_bytes(name, live, transition['predecessor_sha256'], root)
        raw = original.prepared._self(predecessor)
    if name in ('peaso/engine.py', 'peaso/collectors/aws.py', 'peaso/server/validation.py', 'peaso/collectors/aws_workload_command_runtime_20261020.py', 'peaso/collectors/azure_function_package_source_20261020.py', 'peaso/checks/azure_metadata_only_tde_admission_successor_20261020.py', 'peaso/checks/azure_acr_image_secret_review_20261020.py', 'peaso/checks/gcp_cloudbuild_log_secret_review_20261019.py', 'peaso/checks/k8s_literal_secret_review_20261020.py', 'peaso/checks/k8s_ports_components.py', 'peaso/collectors/gcp_cloudbuild_log_secret_indicators.py', 'peaso/collectors/gcp_cloudrun_content_sources.py', 'peaso/collectors/gcp_job_image_vulnerability_runtime_20261021.py', 'peaso/server/image_selection_options_20261021.py', 'peaso/collectors/azure_selected_secret_integration_20261020.py', 'peaso/snapshot.py', 'peaso/collectors/azure_function_settings_declarations_20261020.py', 'peaso/collectors/azure_apim_operation_window_20261020.py', 'peaso/checks/aws_ai_recheck_corrections_20261020.py', 'peaso/secret_findings.py'):
        raw = _private_before(name, raw, root)
    from peaso.rawv2_private_source_successor_20261021 import source_bytes
    reviewed_row = _reviewed_epoch._receipt()["sources"].get(name)
    if reviewed_row is not None and expected == reviewed_row["epoch_before_sha256"]:
        return _reviewed_epoch.predecessor_bytes(name, raw, expected, root)
    return source_bytes(name, raw, expected, root)


def _published_initialization_predecessor(raw):
    if hashlib.sha256(raw).hexdigest() != _CURRENT_INIT_SHA256:
        raise RuntimeError('GCP positive conservation initializer changed')
    rawv2_edits = (
        (b'collector_noop_authorization_shared_successor_20261020 = aws_workload_command_shared_successor_20261020\n', b''),
        (b'_rawv2_source.install_admission("gcp_dataproc_source_runtime_admission_20261020")\n', b'gcp_dataproc_source_runtime_admission_20261020.install()\n'),
        (b'_rawv2_source.install_admission("azure_declaration_secrets_admission_20261020")\n', b'azure_declaration_secrets_admission_20261020.install()\n'),
        (b'from peaso import rawv2_public_source_successor_20261021 as _rawv2_source\n', b''),
        (b'_rawv2_source.install_selected_aws()\n', b'aws_selected_configuration_admission_20261020.install()\n'),
        (b'_rawv2_source.install_selected_azure()\n', b'azure_selected_secrets_admission_20261020.install()\n'),
        (b'_rawv2_source.install_admission("azure_log_samples_admission_20261020")\n', b'azure_log_samples_admission_20261020.install()\n'),
        (b'_rawv2_source.install_admission("azure_ml_job_secrets_admission_20261020")\n', b'azure_ml_job_secrets_admission_20261020.install()\n'),
        (b'_rawv2_source.install_admission("azure_databricks_notebook_secrets_admission_20261020")\n', b'azure_databricks_notebook_secrets_admission_20261020.install()\n'),
        (b'_rawv2_source.install_admission("azure_ml_asset_secrets_admission_20261020")\n', b'azure_ml_asset_secrets_admission_20261020.install()\n'),
        (b'_rawv2_source.install_admission("azure_function_settings_runtime_admission_20261020")\n', b'azure_function_settings_runtime_admission_20261020.install()\n'),
    )
    for after, before in rawv2_edits:
        if raw.count(after) != 1:
            raise RuntimeError('RawV2 initializer successor delta changed')
        raw = raw.replace(after, before, 1)
    edits = (
        (b'from . import gcp_positive_conservation_shared_source_successor_20261020 as _positive_shared_source\n', b''),
        (b'aws_workload_command_shared_successor_20261020 = _positive_shared_source\n',
         b'aws_workload_command_shared_successor_20261020 = _deployed_ai_shared_source\n'),
        (b'from peaso import gcp_positive_conservation_source_admission_successor_20261020 as _positive_source\n'
         b'gcp_function_secret_page_admission_20261020.source_inputs = _positive_source.reviewed_inputs\n', b''),
    )
    for after, before in edits:
        if raw.count(after) != 1:
            raise RuntimeError('GCP positive conservation initializer delta ambiguous')
        raw = raw.replace(after, before, 1)
    if hashlib.sha256(raw).hexdigest() != _PREDECESSOR_INIT_SHA256:
        raise RuntimeError('GCP positive conservation initializer predecessor changed')
    return raw


def _initialization_predecessor(raw):
    _private_self()
    receipt = _private_receipt()
    if hashlib.sha256(raw).hexdigest() != receipt['initializer_after_sha256']:
        raise RuntimeError('Private source initializer changed')
    for before, after in reversed(receipt['initializer_edits']):
        before, after = before.encode(), after.encode()
        if raw.count(after) != 1:
            raise RuntimeError('Private source initializer edit changed')
        raw = raw.replace(after, before, 1)
    if hashlib.sha256(raw).hexdigest() != _CURRENT_INIT_SHA256:
        raise RuntimeError('Private source initializer predecessor changed')
    return _published_initialization_predecessor(raw)


def _self(raw):
    value, count = re.subn(rb"(?m)^RECEIPT_SHA256 = '[0-9a-f]{64}'$", b"RECEIPT_SHA256 = '" + b'0' * 64 + b"'", raw)
    if count != 1:
        raise RuntimeError('AWS command successor self binding changed')
    return value


def _reverse(text, row):
    for transition in (() if hashlib.sha256(text.encode()).hexdigest() == row['current_sha256'] else _private_receipt()['provider_group_callables'].values()):
        if row != transition and hashlib.sha256(text.encode()).hexdigest() == transition['current_sha256']:
            text = _reverse(text, transition)
            if hashlib.sha256(text.encode()).hexdigest() != transition['predecessor_sha256']:
                raise RuntimeError('Provider group callable predecessor changed')
            break
    if hashlib.sha256(text.encode()).hexdigest() != row['current_sha256']:
        raise RuntimeError('Deployed AI current source changed: expected=' + row['current_sha256'] + ' observed=' + hashlib.sha256(text.encode()).hexdigest())
    if 'exact_delta_zlib' in row:
        import base64, zlib
        delta = json.loads(zlib.decompress(base64.b64decode(row['exact_delta_zlib'], validate=True)))
        row = dict(row, exact_additions=delta['exact_additions'], exact_replacements=delta['exact_replacements'])
    for before, after in row.get('exact_replacements', []):
        if text.count(after) != 1:
            raise RuntimeError('Deployed AI exact replacement changed')
        text = text.replace(after, before, 1)
    for addition in row['exact_additions']:
        if text.count(addition) != 1:
            raise RuntimeError('Deployed AI exact addition changed')
        text = text.replace(addition, '', 1)
    return text


def _compiled_source(raw, filename, optimize):
    """Compile locally without computing the historical unused AST digest."""
    text = raw.decode('utf-8')
    lines = text.splitlines(keepends=True)
    definitions = {}

    def visit(node, prefix=''):
        child_prefix = prefix
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            name = prefix + node.name
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                start = min([node.lineno] + [d.lineno for d in node.decorator_list])
                key = (node.name, start)
                if key in definitions:
                    raise RuntimeError('Ambiguous annotation source definition')
                definitions[key] = {
                    'qualname': name,
                    'source_sha256': hashlib.sha256(''.join(lines[start - 1:node.end_lineno]).encode()).hexdigest(),
                    'source': ''.join(lines[start - 1:node.end_lineno]),
                }
                child_prefix = name + '.<locals>.'
            else:
                child_prefix = name + '.'
        for child in ast.iter_child_nodes(node):
            # Definitions occur only in statement suites, exception handlers
            # and match cases; expression subtrees cannot introduce one.
            if isinstance(child, (ast.stmt, ast.excepthandler, ast.match_case)):
                visit(child, child_prefix)

    tree = ast.parse(text, filename=filename, type_comments=True)
    visit(tree)
    del visit
    records = []

    def walk(code):
        definition = definitions.get((code.co_name, code.co_firstlineno))
        if definition is not None:
            records.append((definition, code))
        for member in code.co_consts:
            if isinstance(member, types.CodeType):
                walk(member)

    walk(compile(tree, filename, 'exec', dont_inherit=True, optimize=optimize))
    del walk
    return records


def _transaction_compiler():
    """Keep only signed immutable compiled artifacts for one install wave."""
    cache = {}
    secret = os.urandom(32)
    source_bytes = 0
    source_cache = {}
    code_cache = {}
    code_bytes = 0

    def immutable(value):
        # Exact builtins only: a tuple/bytes subclass can have mutable methods.
        if type(value) is types.CodeType:
            return all(immutable(item) for item in value.co_consts)
        if type(value) in (tuple, frozenset):
            return all(immutable(item) for item in value)
        if type(value) is slice:
            return all(immutable(item) for item in (value.start, value.stop, value.step))
        return value is None or value is Ellipsis or type(value) in (str, int, bool, float, bytes, complex)

    def normalized(key, code):
        nonlocal code_bytes
        artifact_key = (key, id(code))
        entry = code_cache.get(artifact_key)
        if entry is None:
            if not immutable(code):
                raise RuntimeError('Mutable native code artifact refused')
            value = json.dumps(original.proof._code(code), sort_keys=True)
            signature = hmac.digest(secret, marshal.dumps((artifact_key, value), 2), 'sha256')
            entry = (code, value, signature)
            if len(code_cache) < 4096 and code_bytes + len(value.encode()) <= 4 * 1024 * 1024:
                code_cache[artifact_key] = entry
                code_bytes += len(value.encode())
        saved, value, signature = entry
        # This is a serialization artifact, never a live-function verdict.
        # Exact recursive immutability was checked before retaining this code.
        # The signed key contains its identity; holding the code prevents ID
        # reuse. Replacing live __code__ gets a new key and fresh serialization.
        if (saved is not code or not hmac.compare_digest(signature,
                hmac.digest(secret, marshal.dumps((artifact_key, value), 2), 'sha256'))):
            raise RuntimeError('Normalized code artifact changed')
        return value

    def lookup(key, raw, qualname, native=None, want_source=False):
        nonlocal source_bytes, code_bytes
        if key != (key[0], hashlib.sha256(raw).hexdigest(), sys.flags.optimize):
            raise RuntimeError('Deployed AI compiled cache source binding changed')
        if key not in cache:
            rows = tuple((record['qualname'], record['source_sha256'], code, record['source'])
                         for record, code in _compiled_source(raw, key[0], key[2]))
            # Version 2 has no reference-sharing flags, so holding another
            # reference to an immutable code object cannot change its digest.
            signed = tuple((record, hmac.digest(secret, marshal.dumps((key, record), 2), 'sha256'))
                           for record in rows)
            artifact_bytes = len(raw) + sum(len(row[3].encode()) for row in rows)
            if len(cache) >= 128 or source_bytes + artifact_bytes > 16 * 1024 * 1024:
                cache.clear()
                source_cache.clear()
                code_cache.clear()
                source_bytes = code_bytes = 0
            if artifact_bytes <= 16 * 1024 * 1024:
                cache[key] = signed
                source_bytes += artifact_bytes
        else:
            signed = cache[key]
        matches = []
        source_fragment = None
        for record, signature in signed:
            if record[0] == qualname:
                if not hmac.compare_digest(signature, hmac.digest(secret, marshal.dumps((key, record), 2), 'sha256')):
                    raise RuntimeError('Deployed AI compiled cache artifact changed')
                matches.append(({'qualname': record[0], 'source_sha256': record[1],
                                 'compiled_code_json': normalized(key, record[2])}, record[2]))
                source_fragment = record[3]
        if native is None:
            return matches
        filename = inspect.getsourcefile(native)
        if (not isinstance(filename, str)
                or filename != key[0] and Path(filename).resolve() != Path(key[0])):
            raise RuntimeError('Native CPU inspect source identity changed')
        # Preserve inspect's linecache view as well as the independently reread
        # disk bytes. Mutable cached source lines never share a successful key.
        linecache.checkcache(filename)
        cached_lines = linecache.getlines(filename, native.__globals__)
        line_digest = hashlib.sha256(''.join(cached_lines).encode()).hexdigest()
        code = native.__code__
        source_key = (key, id(code), native.__module__, native.__qualname__,
                      code.co_filename, code.co_firstlineno, line_digest)
        # Validate recursive immutability before retaining an identity artifact.
        live_json = normalized(key, code)
        entry = source_cache.get(source_key)
        if entry is None:
            digest = original.prepared._hash(inspect.getsource(native).encode())
            payload = (source_key, digest)
            signature = hmac.digest(secret, marshal.dumps(payload, 2), 'sha256')
            entry = (code, digest, signature)
            if key in cache and len(source_cache) < 4096:
                source_cache[source_key] = entry
        saved_code, digest, signature = entry
        if (saved_code is not code or not hmac.compare_digest(signature,
                hmac.digest(secret, marshal.dumps((source_key, digest), 2), 'sha256'))):
            raise RuntimeError('Native CPU source cache artifact changed')
        for record, _ in matches:
            record['live_code_json'] = live_json
        return (matches, digest, source_fragment) if want_source else (matches, digest)

    return lookup


def _check_function(fn, row, root, compiled):
    """Check each live input; a finite batch proves GCP source at both boundaries."""
    proof_key = None if row is None else (
        '_check_function', id(fn), json.dumps(row, sort_keys=True, default=repr), str(root))
    if proof_key is not None and not _attestation_mode.repeat(proof_key in _PRIVATE_PROVEN):
        return
    batch = row is None
    if batch:
        if (type(fn) is not tuple or not 1 <= len(fn) <= 256
                or any(type(entry) is not tuple or len(entry) != 3
                       or not isinstance(entry[1], dict) or not isinstance(entry[2], str)
                       for entry in fn)):
            raise RuntimeError('Invalid finite callable proof batch')
        from peaso.gcp_private_source_successor_20261021 import _source_delta
        checked_rows = _source_delta(root)
        entries = fn
    else:
        checked_rows = None
        entries = ((fn, row, None),)
    for fn, row, label in entries:
        try:
            row = current_producer_row(fn, row, root)
            native = inspect.unwrap(fn)
            path = (root / row['path']).resolve()
            if not path.is_relative_to(root):
                raise RuntimeError('metadata runtime source escaped package')
            raw = path.read_bytes()
            key = (str(path), hashlib.sha256(raw).hexdigest(), sys.flags.optimize)
            compiler = _COMPILED_TRANSACTION.get()
            if compiler is None:
                if key not in compiled:
                    compiled[key] = _compiled_source(raw, str(path), sys.flags.optimize)
                matches = [(record, code) for record, code in compiled[key] if record['qualname'] == row['qualname']]
                source_digest = original.prepared._hash(inspect.getsource(native).encode())
            else:
                expected = next(code for code in _transaction_compiler.__code__.co_consts
                                if isinstance(code, types.CodeType) and code.co_name == 'lookup')
                if (not isinstance(compiler, types.FunctionType) or compiler.__code__ is not expected
                        or compiler.__globals__ is not globals()):
                    raise RuntimeError('Deployed AI compiled cache callable changed')
                matches, source_digest = compiler(key, raw, row['qualname'], native)
            expected_source_sha = row['sha256']
            if row['path'].startswith(('peaso/collectors/gcp_', 'peaso/checks/gcp_')):
                from peaso.gcp_private_source_successor_20261021 import _source_delta, _source_hash
                source_rows = checked_rows if checked_rows is not None else _source_delta(root)
                if row['path'] in source_rows:
                    _source_hash(row['path'], raw, source_rows[row['path']]['before_sha256'], source_rows)
                    if len(matches) != 1:
                        raise RuntimeError('GCP positive callable source ambiguous')
                    expected_source_sha = matches[0][0]['source_sha256']
            live_json = matches[0][0].get('live_code_json') if len(matches) == 1 else None
            expected_json = matches[0][0].get('compiled_code_json') if len(matches) == 1 else None
            if live_json is None:
                live_json = json.dumps(original.proof._code(native.__code__), sort_keys=True)
            if expected_json is None and len(matches) == 1:
                expected_json = json.dumps(original.proof._code(matches[0][1]), sort_keys=True)
            if (len(matches) != 1 or matches[0][0]['source_sha256'] != expected_source_sha
                    or source_digest != expected_source_sha
                    or live_json != expected_json
                    or native.__globals__ is not vars(sys.modules[native.__module__])
                    or json.dumps(native.__defaults__, sort_keys=True) != json.dumps(row['defaults'], sort_keys=True)
                    or json.dumps(native.__kwdefaults__, sort_keys=True) != json.dumps(row['kwdefaults'], sort_keys=True)):
                raise RuntimeError('metadata runtime executing callable changed: ' + native.__module__ + ':' + native.__qualname__)
        except RuntimeError as exc:
            if label is None:
                raise
            raise RuntimeError('AWS command executing callable changed: ' + label) from exc
    if batch:
        _source_delta(root)
    if proof_key is not None:
        _PRIVATE_PROVEN[proof_key] = fn


def _verify_bridge(root):
    """Run the unmodified bridge proof and bind the exact initializer delta."""
    if not _attestation_mode.repeat(('_verify_bridge', str(root)) in _PRIVATE_PROVEN):
        return
    _private_self()
    if _COMPILED_TRANSACTION is not _TRANSACTION_CONTEXT:
        raise RuntimeError('GCP positive conservation compiled transaction carrier changed')
    from peaso.gcp_private_source_successor_20261021 import _bridge_source
    _bridge_source(root)
    # Preserve the historical proof, but send its immutable callable rows
    # through this wave's signed artifact cache instead of recompiling the
    # same module once per nested admission. No verification result is cached.
    if historical_bridge._COMPILED_TRANSACTION is not historical_bridge._TRANSACTION_CONTEXT:
        raise RuntimeError('Deployed AI compiled transaction carrier changed')
    raw = (root / 'peaso/checks' / historical_bridge.RECEIPT).read_bytes()
    if hashlib.sha256(raw).hexdigest() != historical_bridge.RECEIPT_SHA256:
        raise RuntimeError('Deployed AI bridge receipt changed')
    receipt = json.loads(raw)
    helper = 'peaso/checks/azure_metadata_only_shared_successor_20261020.py'
    if hashlib.sha256(historical_bridge._self((root / helper).read_bytes())).hexdigest() != receipt['sources'][helper]['sha256']:
        raise RuntimeError('Deployed AI bridge self source changed')
    if historical_bridge._FUNCTIONS != _FUNCTIONS:
        raise RuntimeError('Deployed AI bridge callable snapshot changed')
    compiled = {}
    for qualified, function in _FUNCTIONS.items():
        name = qualified.split(':')[1]
        if vars(historical_bridge).get(name) is not function:
            raise RuntimeError('Deployed AI bridge executing callable replaced: ' + name)
        _check_function(function, receipt['functions'][qualified], root, compiled)
    _initialization_predecessor((root / 'peaso/checks/__init__.py').read_bytes())
    _PRIVATE_PROVEN[('_verify_bridge', str(root))] = True


def reviewed_delta(root=None):
    root = Path(root or Path(__file__).resolve().parents[2]).resolve()
    proven = _PRIVATE_PROVEN.get(('reviewed_delta', str(root)))
    if not _attestation_mode.repeat(proven):
        return marshal.loads(proven)
    _verify_bridge(root)
    verify_metadata_only(root)
    raw = (root / 'peaso/checks' / RECEIPT).read_bytes()
    if hashlib.sha256(raw).hexdigest() != RECEIPT_SHA256:
        raise RuntimeError('AWS command successor receipt changed')
    receipt = json.loads(raw)
    native_raw = (root / 'peaso/checks' / accepted_native.RECEIPT).read_bytes()
    if (hashlib.sha256(native_raw).hexdigest() != accepted_native.RECEIPT_SHA256
            or receipt['accepted_native_receipt_sha256'] != accepted_native.RECEIPT_SHA256):
        raise RuntimeError('No-op native predecessor receipt changed')
    for name, row in receipt['native_epoch_file_deltas'].items():
        restored = _reverse(predecessor_epoch_bytes(name, (root / name).read_bytes(), root).decode('utf-8'), row)
        if hashlib.sha256(restored.encode()).hexdigest() != row['predecessor_sha256']:
            raise RuntimeError('No-op native whole-file epoch changed')
    for name, row in receipt['producer_file_deltas'].items():
        predecessor_producer_bytes(name, (root / name).read_bytes(), root)
    if receipt['accepted_receipt_sha256'] != historical.RECEIPT_SHA256:
        raise RuntimeError('Deployed AI historical receipt binding changed')
    if receipt['accepted_bridge_receipt_sha256'] != accepted.RECEIPT_SHA256:
        raise RuntimeError('JIT READY bridge receipt binding changed')
    prior_raw = (root / 'peaso/checks' / prior_bridge.RECEIPT).read_bytes()
    if (receipt['prior_bridge_receipt_sha256'] != prior_bridge.RECEIPT_SHA256
            or hashlib.sha256(prior_raw).hexdigest() != prior_bridge.RECEIPT_SHA256):
        raise RuntimeError('Native CPU predecessor bridge receipt changed')
    prior_receipt = json.loads(prior_raw)
    for name, row in receipt['prior_epoch_file_deltas'].items():
        restored = _reverse(predecessor_epoch_bytes(name, (root / name).read_bytes(), root).decode('utf-8'), row)
        if hashlib.sha256(restored.encode()).hexdigest() != row['predecessor_sha256']:
            raise RuntimeError('Native CPU whole predecessor epoch changed')
        for section in ('parent_file_deltas', 'integration_file_deltas', 'file_deltas'):
            if name in prior_receipt[section] and row['predecessor_sha256'] != prior_receipt[section][name]['current_sha256']:
                raise RuntimeError('Native CPU predecessor file binding changed')
    accepted_receipt = json.loads((root / 'peaso/checks' / accepted.RECEIPT).read_bytes())
    for name, row in receipt['parent_file_deltas'].items():
        restored = _reverse(predecessor_epoch_bytes(name, (root / name).read_bytes(), root).decode('utf-8'), row)
        if hashlib.sha256(restored.encode()).hexdigest() != row['predecessor_sha256']:
            raise RuntimeError('JIT READY whole-file reconstruction changed: ' + name)
        if name in accepted_receipt['integration_file_deltas']:
            prior = accepted_receipt['integration_file_deltas'][name]
            prior_source = _reverse(restored, prior)
            if hashlib.sha256(prior_source.encode()).hexdigest() != prior['predecessor_sha256']:
                raise RuntimeError('JIT READY historical integration reversal changed: ' + name)
    # This unchanged predecessor verifies WB/DF/CodeBuild historical source,
    # receipts, helpers, the isolated K8s router and prepared native contracts.
    predecessor.predecessor.reviewed_delta(root)
    for name, row in receipt['sources'].items():
        data = (root / name).read_bytes()
        if row['normalization'] == 'self':
            data = _self(data)
        data = _admitted_scanner_bytes(name, data, row['sha256'], root)
        if hashlib.sha256(data).hexdigest() != row['sha256']:
            raise RuntimeError('AWS command successor source changed: ' + name)
    sealed = json.loads((root / 'peaso/checks' / historical.RECEIPT).read_bytes())
    # First reconstruct the *entire* accepted AWS-command epoch. Then the
    # unchanged epoch's exact reversals below reconstruct its own predecessor.
    for name, row in receipt['integration_file_deltas'].items():
        restored = _reverse(predecessor_epoch_bytes(name, (root / name).read_bytes(), root).decode('utf-8'), row)
        if hashlib.sha256(restored.encode()).hexdigest() != row['predecessor_sha256']:
            raise RuntimeError('Deployed AI whole-file historical reconstruction changed: ' + name)
        if name in sealed['file_deltas'] and row['predecessor_sha256'] != sealed['file_deltas'][name]['current_sha256']:
            raise RuntimeError('Deployed AI historical file binding changed: ' + name)
        if name in sealed['file_deltas']:
            previous = _reverse(restored, sealed['file_deltas'][name])
            if hashlib.sha256(previous.encode()).hexdigest() != sealed['file_deltas'][name]['predecessor_sha256']:
                raise RuntimeError('Deployed AI sealed historical reversal changed: ' + name)
        if name == 'peaso/collectors/azure.py':
            azure_receipt = json.loads((root / 'peaso/checks' / predecessor.RECEIPT).read_bytes())
            ancestor = azure_receipt['file_deltas'][name]
            previous = _reverse(restored, ancestor)
            if hashlib.sha256(previous.encode()).hexdigest() != ancestor['predecessor_sha256']:
                raise RuntimeError('JIT sealed Azure package reversal changed')
    compiled = {}
    for qualified, row in receipt['integration_functions'].items():
        owner, name = qualified.split(':')
        function = getattr(importlib.import_module(owner), name)
        if function is not _INTEGRATION_FUNCTIONS[qualified]:
            raise RuntimeError('Deployed AI shared callable replaced: ' + qualified)
        if qualified == 'peaso.collectors.aws_facts_swc:_event_rule':
            facts = importlib.import_module(owner)
            if (function.__closure__ is not _EVENT_RULE_CLOSURE
                    or len(function.__closure__) != 1
                    or function.__closure__[0].cell_contents is not _EVENT_RULE_INNER
                    or facts.ENRICHERS.get('eventbridge_rule') is not function
                    or facts.ENRICHERS.get('event_rule') is not function):
                raise RuntimeError('Deployed AI event-rule wrapper/closure binding changed')
            _check_function(function, row['wrapper'], root, compiled)
            function = _EVENT_RULE_INNER
        try:
            restored = _reverse(inspect.getsource(inspect.unwrap(function)), row)
        except RuntimeError as exc:
            raise RuntimeError('Deployed AI shared source changed: ' + qualified) from exc
        if hashlib.sha256(restored.encode()).hexdigest() != row['predecessor_sha256']:
            raise RuntimeError('Deployed AI shared callable historical reconstruction changed: ' + qualified)
        _check_function(function, row['current'], root, compiled)
    for name, row in receipt['file_deltas'].items():
        restored = predecessor_epoch_bytes(name, (root / name).read_bytes(), root).decode('utf-8')
        for before, after in row.get('exact_replacements', []):
            if restored.count(after) != 1:
                raise RuntimeError('AWS command exact entrypoint changed')
            restored = restored.replace(after, before, 1)
        for addition in row['exact_additions']:
            if restored.count(addition) != 1:
                raise RuntimeError('AWS command exact source addition changed')
            restored = restored.replace(addition, '', 1)
        if hashlib.sha256(restored.encode()).hexdigest() != row['predecessor_sha256']:
            raise RuntimeError('AWS command changed outside admitted source additions')
        # Re-run the previous epoch's exact whole-file reconstruction, on the
        # just-proven previous bytes, without mutating files or guard globals.
        historical_receipt = json.loads((root / 'peaso/checks' / predecessor.RECEIPT).read_bytes())
        if name in historical_receipt['file_deltas']:
            prior = historical_receipt['file_deltas'][name]
            for before, after in prior.get('exact_replacements', []):
                if restored.count(after) != 1:
                    raise RuntimeError('AWS command historical entrypoint changed')
                restored = restored.replace(after, before, 1)
            for addition in prior['exact_additions']:
                if restored.count(addition) != 1:
                    raise RuntimeError('AWS command historical file delta changed')
                restored = restored.replace(addition, '', 1)
            if hashlib.sha256(restored.encode()).hexdigest() != prior['predecessor_sha256']:
                raise RuntimeError('AWS command historical whole-file source changed')
    verified_functions = []
    for qualified, row in receipt['functions'].items():
        module_name, name = qualified.split(':')
        module = importlib.import_module(module_name)
        function = module
        for part in name.split('.'):
            function = getattr(function, part)
        if qualified == 'peaso.checks.gcp_workbench_head3_admission_20261020:reviewed_inputs':
            historical_function = module._ORIGINALS[qualified]
            successor = importlib.import_module('peaso.checks.gcp_cloudrun_job_image_workbench_source_successor_20261020')
            if function not in (historical_function, successor.reviewed_inputs):
                current_source = importlib.import_module('peaso.checks.gcp_private_workbench_head3_source_successor_20261021')
                if function is not current_source.reviewed_inputs:
                    raise RuntimeError('Workbench shared admission alias changed')
                current_source._private_self(root)
            function = historical_function
        if qualified == 'peaso.gcp_function_secret_page_source_20261020:reviewed_inputs':
            successor = importlib.import_module('peaso.gcp_cloudrun_job_image_function_source_successor_20261020')
            historical_function = successor._HISTORICAL_PAGE_REVIEWED_INPUTS
            if function not in (historical_function, successor.reviewed_inputs):
                current_source = importlib.import_module('peaso.gcp_private_source_successor_20261021')
                if function is not current_source.reviewed_inputs:
                    raise RuntimeError('Functions shared runtime admission alias changed')
                current_source._private_receipt(root)
            function = historical_function
        if qualified in _NOOP_FUNCTIONS and function is not _NOOP_FUNCTIONS[qualified]:
            raise RuntimeError('Azure metadata-only canonical no-op callable replaced')
        if qualified in _NATIVE_FUNCTIONS and function is not _NATIVE_FUNCTIONS[qualified]:
            raise RuntimeError('No-op canonical native callable replaced')
        if qualified in _NATIVE_PACKAGE_FUNCTIONS and function is not _NATIVE_PACKAGE_FUNCTIONS[qualified]:
            raise RuntimeError('No-op canonical package CPU callable replaced')
        if qualified in _AUTHORIZATION_FUNCTIONS and function is not _AUTHORIZATION_FUNCTIONS[qualified]:
            raise RuntimeError('No-op current authorization callable replaced')
        if qualified in _PRIOR_FUNCTIONS and function is not _PRIOR_FUNCTIONS[qualified]:
            raise RuntimeError('Native CPU predecessor canonical callable replaced')
        if qualified in _PACKAGE_FUNCTIONS and function is not _PACKAGE_FUNCTIONS[qualified]:
            raise RuntimeError('Native CPU package successor callable replaced')
        if qualified in _ACCEPTED_FUNCTIONS and function is not _ACCEPTED_FUNCTIONS[qualified]:
            raise RuntimeError('JIT READY canonical callable replaced: ' + qualified)
        if qualified in _HISTORICAL_FUNCTIONS and function is not _HISTORICAL_FUNCTIONS[qualified]:
            raise RuntimeError('Deployed AI canonical historical callable replaced: ' + qualified)
        if qualified in _FUNCTIONS and function is not _FUNCTIONS[qualified]:
            raise RuntimeError('AWS command successor callable replaced')
        verified_functions.append((function, row, qualified))
    _check_function(tuple(verified_functions), None, root, compiled)
    historical_receipt = json.loads((root / 'peaso/checks' / predecessor.RECEIPT).read_bytes())
    # Existing consumers require the unchanged Azure collection binding.
    receipt['azure_collect'] = historical_receipt['azure_collect']
    transition = _private_receipt()['provider_group_azure_collect']
    current_fragment = inspect.getsource(_METADATA_COLLECT)
    epoch_fragment = _reviewed_epoch.previous_function_source('peaso/collectors/azure.py', 'collect', current_fragment, root)
    if hashlib.sha256(epoch_fragment.encode()).hexdigest() != transition['current_sha256']:
        raise RuntimeError('Azure collect reviewed successor changed')
    current_sha = hashlib.sha256(current_fragment.encode()).hexdigest()
    receipt['metadata_only_collect']['current_sha256'] = current_sha
    receipt['metadata_only_collect']['current']['sha256'] = current_sha
    receipt['metadata_only_collect']['exact_additions'] += transition['exact_additions']
    _PRIVATE_PROVEN[('reviewed_delta', str(root))] = marshal.dumps(receipt)
    return receipt


def check_shared(fn, historical, name, root, compiled, receipt):
    current = receipt['shared_functions'][name]
    restored = inspect.getsource(inspect.unwrap(fn))
    transition = _private_receipt()['provider_group_callables'].get(fn.__module__.replace('.', '/') + '.py:' + fn.__qualname__)
    if transition is not None:
        restored = _reverse(restored, transition)
        if hashlib.sha256(restored.encode()).hexdigest() != transition['predecessor_sha256']:
            raise RuntimeError('Provider group shared callable predecessor changed')
    layers = [current]
    for module in (predecessor, predecessor.predecessor,
                   predecessor.predecessor.predecessor,
                   predecessor.predecessor.predecessor.predecessor):
        layers.append(json.loads((root / 'peaso/checks' / module.RECEIPT).read_bytes())['shared_functions'][name])
    for row in layers:
        if hashlib.sha256(restored.encode()).hexdigest() != row['current_sha256']:
            raise RuntimeError('AWS command shared executing source changed')
        for addition in row['exact_additions']:
            if restored.count(addition) != 1:
                raise RuntimeError('AWS command inherited source addition changed')
            restored = restored.replace(addition, '', 1)
        if hashlib.sha256(restored.encode()).hexdigest() != row.get('predecessor_sha256', row.get('predecessor', {}).get('sha256')):
            raise RuntimeError('AWS command inherited source epoch changed')
    if hashlib.sha256(restored.encode()).hexdigest() != historical['sha256']:
        raise RuntimeError('AWS command original callable source changed')
    _check_function(fn, dict(historical, sha256=current['current_sha256']), root, compiled)


def _prepared_ast(node):
    """Emit the sealed 3.13 AST format without interpreter dump defaults.

    Only empty list fields and optional None fields are omitted. Every node,
    populated field, literal and ordering remains part of the comparison;
    exact reconstructed source bytes are checked independently first.
    """
    if isinstance(node, ast.AST):
        fields = []
        for name, value in ast.iter_fields(node):
            if (isinstance(value, list) and not value
                    or value is None and getattr(type(node), name, ...) is None):
                continue
            fields.append(name + '=' + _prepared_ast(value))
        return type(node).__name__ + '(' + ', '.join(fields) + ')'
    if isinstance(node, list):
        return '[' + ', '.join(_prepared_ast(value) for value in node) + ']'
    return repr(node)


def _check_prepared_shared(fn, historical, name, root, compiled, successor):
    row = successor['prepared_functions'][name]
    if row['predecessor'] != historical:
        raise RuntimeError('Deployed AI prepared predecessor changed')
    source = inspect.getsource(inspect.unwrap(fn))
    if hashlib.sha256(source.encode()).hexdigest() != row['current_sha256']:
        raise RuntimeError('Deployed AI prepared current source changed')
    restored = source
    for addition in row['exact_additions']:
        if restored.count(addition) != 1:
            raise RuntimeError('Deployed AI prepared exact addition changed')
        restored = restored.replace(addition, '', 1)
    if (hashlib.sha256(restored.encode()).hexdigest() != historical['sha256']
            or _prepared_ast(ast.parse(textwrap.dedent(restored))) != row['predecessor_ast']):
        raise RuntimeError('Deployed AI prepared historical source changed')
    _check_function(fn, dict(historical, sha256=row['current_sha256']), root, compiled)


def prepared_inputs(root, compiled, successor):
    """Retain every sealed prepared guard with portable AST serialization."""
    from . import gcp_workbench_shared_hook_successor_20261020 as workbench
    successor = workbench.reviewed_delta(root)
    prepared, proof = original.prepared, original.proof
    raw = (root / 'peaso/checks' / prepared.RECEIPT).read_bytes()
    if prepared._hash(raw) != prepared.RECEIPT_SHA256:
        raise RuntimeError('metadata predecessor receipt changed')
    receipt = json.loads(raw, object_pairs_hook=proof._pairs)
    if json.dumps(receipt['schema'], sort_keys=True) != json.dumps(prepared._schema(), sort_keys=True):
        raise RuntimeError('metadata predecessor schema changed')
    for relative, expected in receipt['sources'].items():
        path = (root / relative).resolve()
        raw = path.read_bytes()
        if relative == receipt['helper_path']:
            raw = prepared._self(raw)
        raw = _admitted_scanner_bytes(relative, raw, expected, root)
        if not path.is_relative_to(root) or prepared._hash(raw) != expected:
            raise RuntimeError('metadata predecessor source changed')
    assets = json.loads(gzip.decompress((root / 'peaso/checks' / original.ASSETS).read_bytes()), object_pairs_hook=proof._pairs)
    required = [row for row in receipt['fixtures'] if row['path'].startswith('peaso/checks/')
                or row['path'].endswith('/k8s_selected_metadata_secret_native_20261020.json.gz')]
    if set(assets) != {row['path'] for row in required}:
        raise RuntimeError('metadata packaged predecessor assets changed')
    for row in required:
        entry = assets[row['path']]
        if entry['sha256'] != row['sha256'] or prepared._hash(bytes.fromhex(entry['hex'])) != row['sha256']:
            raise RuntimeError('metadata packaged predecessor fixture changed')
    current = prepared._runtime()
    if set(current) != set(prepared._ORIGINALS) or set(current) != set(receipt['functions']):
        raise RuntimeError('metadata predecessor callable set changed')
    for name, fn in current.items():
        if fn is not prepared._ORIGINALS[name] or inspect.unwrap(fn) is not prepared._INNERS[name]:
            raise RuntimeError('metadata predecessor callable replacement')
        if name in successor['prepared_functions']:
            _check_prepared_shared(fn, receipt['functions'][name], name, root, compiled, successor)
        else:
            _check_function(fn, receipt['functions'][name], root, compiled)
        if isinstance(fn, types.FunctionType) and (fn.__code__ is not prepared._CODES[name] or fn.__closure__ != prepared._CLOSURES[name]):
            raise RuntimeError('metadata predecessor wrapper replacement')
    prepared._clone_bindings()
    from peaso.collectors import k8s_network_extensions as network
    if (json.dumps(network.RESOURCES, sort_keys=True) != json.dumps(successor['network_resources'], sort_keys=True)
            or network.BY_ENDPOINT != {(group, plural): kind for kind, (groups, plural, ns) in network.RESOURCES.items() for group in groups}):
        raise RuntimeError('metadata network router map changed')
    _check_function(network.match, successor['network_matcher'], root, compiled)
    for kind, (version, plural, _) in prepared.producer.NATIVE_KINDS.items():
        prefix = '/api/v1' if version == 'v1' else '/apis/' + version
        for path in (prefix + '/namespaces/review/' + plural,
                     prefix + '/namespaces/review/' + plural + '/selected-name'):
            if network.match(path) is not None:
                raise RuntimeError('metadata selected routes overlap network router')


def reviewed_inputs(root=None):
    root = Path(root or Path(__file__).resolve().parents[2]).resolve()
    _verify_bridge(root)
    successor = reviewed_delta(root)
    raw = (root / 'peaso/checks' / original.RECEIPT).read_bytes()
    if original.prepared._hash(raw) != original.RECEIPT_SHA256:
        raise RuntimeError('metadata runtime receipt changed')
    receipt = json.loads(raw, object_pairs_hook=original.proof._pairs)
    compiled = {}
    runtime = original.runtime
    if (receipt['check'] != original.CHECK or runtime.CHECK != original.CHECK
            or runtime.KIND != original.prepared.producer.KIND or runtime.OPTION != original.prepared.producer.OPTION
            or runtime.GRANT != '_k8s_selected_metadata_grant'
            or json.dumps(receipt['declaration'], sort_keys=True) != json.dumps(original.candidate.DECLARATION, sort_keys=True)
            or runtime._Grant is not original._GRANT_CLASS or runtime._TOKEN is not original._TOKEN
            or runtime.source is not original.prepared.producer or original.candidate is not original.prepared.candidate
            or original.k8s.TYPES.count(runtime.KIND) != 1 or runtime.KIND in original.k8s.ENDPOINTS
            or runtime.KIND not in original.engine.BULK_STREAM_TYPES['k8s'] or runtime.OPTION not in original.validation.OPTIONS):
        raise RuntimeError('metadata runtime metadata/binding changed')
    for name, expected in receipt['sources'].items():
        path = (root / name).resolve()
        raw = path.read_bytes()
        if name == receipt['helper_path']:
            raw = original._self(raw)
        raw = _admitted_scanner_bytes(name, raw, expected, root)
        if not path.is_relative_to(root) or original.prepared._hash(raw) != expected:
            raise RuntimeError('metadata runtime source changed')
    for row in receipt['fixtures']:
        path = (root / row['path']).resolve()
        if not path.is_relative_to(root / 'peaso/checks') or original.prepared._hash(path.read_bytes()) != row['sha256']:
            raise RuntimeError('metadata packaged runtime fixture changed')
    prepared_inputs(root, compiled, successor)
    current = original._runtime()
    alias = original.__name__ + ':reviewed_inputs'
    if original.reviewed_inputs is reviewed_inputs:
        if alias in current:
            raise RuntimeError('metadata runtime successor alias changed')
        current[alias] = PREDECESSOR_REVIEWED_INPUTS
    elif original.reviewed_inputs not in (accepted.reviewed_inputs, PREDECESSOR_REVIEWED_INPUTS, historical.reviewed_inputs, predecessor.reviewed_inputs, predecessor.predecessor.reviewed_inputs, predecessor.predecessor.predecessor.reviewed_inputs, predecessor.predecessor.predecessor.predecessor.reviewed_inputs):
        raise RuntimeError('metadata runtime successor alias replaced')
    if set(current) != set(original._ORIGINALS) or set(current) != set(receipt['functions']):
        raise RuntimeError('metadata runtime callable set changed')
    for name, fn in current.items():
        if fn is not original._ORIGINALS[name]:
            raise RuntimeError('metadata runtime callable replacement')
        if name in successor['shared_functions']:
            check_shared(fn, receipt['functions'][name], name, root, compiled, successor)
        else:
            _check_function(fn, receipt['functions'][name], root, compiled)
    cases = json.loads((root / 'peaso/checks' / original.CASES).read_bytes(), object_pairs_hook=original.proof._pairs)
    if set(cases) != {original.CHECK}:
        raise RuntimeError('metadata runtime CASES changed')
    for branch in ('pass', 'fail', 'unknown'):
        if original.candidate.evaluate(deepcopy(cases[original.CHECK][branch]), deepcopy(cases[original.CHECK][branch + '_index']))[0] != branch.upper():
            raise RuntimeError('metadata runtime native witness changed')
    return receipt, cases, deepcopy(original.candidate.DECLARATION), original.candidate.evaluate


def install():
    from . import CHECKS, CHECK_ALIASES, register
    from .fixtures import CASES as store
    receipt, cases, declaration, function = reviewed_inputs()
    # The immutable authorize/collect functions import this original module path.
    # Route only its reviewed-input entrypoint; the historical object is retained
    # and attested separately, while this actual successor source is self-pinned.
    original.reviewed_inputs = reviewed_inputs
    ident = original.CHECK
    if ident in CHECK_ALIASES or ident in CHECK_ALIASES.values():
        raise RuntimeError('metadata runtime alias collision')
    found = [check for check in CHECKS if check.id == ident]
    if found:
        if len(found) != 1 or not original._INSTALLED:
            raise RuntimeError('metadata runtime collision')
        original._verify(found[0], receipt)
        if json.dumps(store.get(ident), sort_keys=True) != json.dumps(cases[ident], sort_keys=True):
            raise RuntimeError('metadata runtime CASES replacement')
        return
    if ident in store:
        raise RuntimeError('metadata runtime CASES collision')
    before = tuple(CHECKS)
    try:
        register(ident, 'k8s', declaration['category'], original.runtime.KIND, declaration['title'], declaration['severity'],
                 'security_configuration', declaration['remediation'], dependencies=[original.runtime.KIND], allow_incomplete_failure=True)(function)
        check = CHECKS[-1]
        setattr(check.evaluate, original.MARK, ident)
        original._verify(check, receipt)
        store[ident] = deepcopy(cases[ident])
        original._INSTALLED = (check.evaluate, original.proof._bindings(check.evaluate)['checked'])
    except Exception:
        CHECKS[:] = before
        store.pop(ident, None)
        raise


def _dataflow_gcp_delta(root, receipt):
    """Retain exact sealed GCP branches using explicit portable AST output."""
    from peaso.collectors import gcp
    archive = json.loads(gzip.decompress((root / receipt['hook_predecessor']).read_bytes()))
    prior = archive['peaso/collectors/gcp.py']
    if hashlib.sha256(prior['content'].encode()).hexdigest() != prior['sha256']:
        raise RuntimeError('Selected job GCP predecessor changed')
    source = (root / 'peaso/collectors/gcp.py').read_text()
    for delta in receipt['gcp_global_additions']:
        if source.count(delta) != 1:
            raise RuntimeError('Selected job GCP global hook changed')
    for name, row in receipt['gcp_function_deltas'].items():
        function = getattr(gcp.GCPCollector, name)
        restored = inspect.getsource(function)
        transition = _private_receipt()['provider_group_callables'].get('peaso/collectors/gcp.py:GCPCollector.' + name)
        if name == 'envelope':
            restored = _reviewed_epoch.previous_gcp_method_source(name, restored, root)
        if transition is not None:
            if hashlib.sha256(restored.encode()).hexdigest() != transition['current_sha256']:
                restored = _reviewed_epoch.previous_gcp_method_source(name, restored, root)
            restored = _reverse(restored, transition)
        for addition in row['exact_additions']:
            if restored.count(addition) != 1:
                raise RuntimeError('Selected job GCP exact branch changed')
            restored = restored.replace(addition, '', 1)
        if (hashlib.sha256(restored.encode()).hexdigest() != row['predecessor_sha256']
                or _prepared_ast(ast.parse(textwrap.dedent(restored))) != row['predecessor_ast']):
            raise RuntimeError('Selected job GCP non-selected-source branch changed')


def dataflow_reviewed_inputs(root=None):
    """Explicit portable entrypoint; all canonical Dataflow code stays sealed."""
    root = Path(root or Path(__file__).resolve().parents[2]).resolve()
    _verify_bridge(root)
    admission = _DATAFLOW_ADMISSION
    if (sys.modules.get(admission.__name__) is not admission
            or admission.reviewed_inputs not in (_DATAFLOW_REVIEWED_INPUTS, dataflow_reviewed_inputs)
            or admission._FUNCTIONS != _DATAFLOW_FUNCTIONS
            or _DATAFLOW_REVIEWED_INPUTS is not _DATAFLOW_FUNCTIONS[admission.__name__ + ':reviewed_inputs']):
        raise RuntimeError('Deployed AI Dataflow admission entrypoint changed')
    if admission.shared not in (historical, predecessor.predecessor.predecessor, predecessor.predecessor, predecessor, sys.modules[__name__]):
        raise RuntimeError('Deployed AI Dataflow shared alias replaced')
    runtime, candidate = admission.runtime, admission.candidate
    raw = (root / 'peaso/checks' / admission.RECEIPT).read_bytes()
    if hashlib.sha256(raw).hexdigest() != admission.RECEIPT_SHA256:
        raise RuntimeError('Selected job admission receipt changed')
    receipt = json.loads(raw)
    from peaso.gcp_private_source_successor_20261021 import _source_delta, _source_hash
    source_rows = _source_delta(root)
    if (receipt['schema_version'] != 1 or tuple(d['id'] for d in receipt['declarations']) != runtime.CHECKS
            or receipt['declarations'] != candidate.DECLARATIONS
            or runtime._Grant is not admission._GRANT or runtime._SEAL is not admission._SEAL
            or candidate.runtime is not runtime or candidate.dataflow.predecessor.source is not runtime.dataflow
            or candidate.batch.source is not runtime.batch):
        raise RuntimeError('Selected job admission metadata/binding changed')
    for name, digest in receipt['sources'].items():
        path = (root / name).resolve()
        if not path.is_relative_to(root / 'peaso'):
            raise RuntimeError('Selected job admission dependency outside package')
        raw = path.read_bytes()
        if name == receipt['helper_path']:
            raw = admission._self(raw)
        _source_hash(name, raw, digest, source_rows)
    if any(actual is not expected for actual, expected in admission._bindings()):
        raise RuntimeError('Selected job admission imported binding changed')
    public_profiles = {name: {k: p[k] for k in ('check', 'kind', 'marker')} for name, p in runtime.PROFILES.items()}
    if public_profiles != receipt['profiles'] or any(p['source'] is not (runtime.dataflow if name == 'dataflow' else runtime.batch) for name, p in runtime.PROFILES.items()):
        raise RuntimeError('Selected job admission profile changed')
    _dataflow_gcp_delta(root, receipt)
    reviewed_inputs(root)
    compiled = {}
    for qualified, row in receipt['runtime_functions'].items():
        owner_name, attribute = qualified.split(':'); owner = importlib.import_module(owner_name)
        function = owner
        for part in attribute.split('.'):
            function = getattr(function, part)
        if qualified == admission.__name__ + ':reviewed_inputs':
            if function not in (_DATAFLOW_REVIEWED_INPUTS, dataflow_reviewed_inputs):
                raise RuntimeError('Deployed AI Dataflow admission entrypoint replaced')
            function = _DATAFLOW_REVIEWED_INPUTS
        if qualified in _DATAFLOW_FUNCTIONS and function is not _DATAFLOW_FUNCTIONS[qualified]:
            raise RuntimeError('Selected job admission callable replaced')
        _check_function(function, row, root, compiled)
    path = (root / 'peaso/checks' / admission.CASES).resolve()
    if not path.is_relative_to(root / 'peaso/checks') or hashlib.sha256(path.read_bytes()).hexdigest() != receipt['cases_sha256']:
        raise RuntimeError('Selected job native cases changed')
    cases = json.loads(path.read_bytes())
    if set(cases) != set(runtime.CHECKS):
        raise RuntimeError('Selected job native case identities changed')
    declarations = []
    for profile, declaration in zip(runtime.PROFILES, candidate.DECLARATIONS):
        function = getattr(candidate, profile + '_source'); case = cases[declaration['id']]
        for branch in ('pass', 'fail', 'unknown', 'partial', 'missing', 'malformed'):
            status, details = function(deepcopy(case[branch]), deepcopy(case.get(branch + '_index', case['index'])))
            expected = 'FAIL' if branch == 'partial' else branch.upper() if branch in ('pass', 'fail') else 'UNKNOWN'
            if status != expected or branch == 'partial' and details.get('complete') is not False:
                raise RuntimeError('Selected job native branch changed')
        declarations.append((declaration, function))
    return receipt, cases, declarations


def install_dataflow(admission):
    """Publish one checked entrypoint alias, retaining every original function."""
    reviewed_delta()
    if admission is not _DATAFLOW_ADMISSION:
        raise RuntimeError('Deployed AI Dataflow admission module replaced')
    dataflow_reviewed_inputs()
    old_shared, old_reviewed = admission.shared, admission.reviewed_inputs
    admission.shared = sys.modules[__name__]
    admission.reviewed_inputs = dataflow_reviewed_inputs
    try:
        admission.install()
    except Exception:
        admission.shared, admission.reviewed_inputs = old_shared, old_reviewed
        raise


def install_bundle():
    """Release this wave's compilation cache on success and every exception."""
    root = Path(__file__).resolve().parents[2]
    _verify_bridge(root)
    from peaso import gcp_positive_conservation_source_admission_successor_20261020 as canonical_artifacts
    # _verify_bridge freshly proves the canonical provider source, executing
    # functions and defaults before either artifact context is established.
    canonical_context = canonical_artifacts._MODULE_ARTIFACTS
    if (canonical_context is not canonical_artifacts._MODULE_CONTEXT
            or not isinstance(canonical_context, ContextVar)):
        raise RuntimeError('GCP canonical module artifact context changed')
    from peaso import gcp_private_source_successor_20261021 as source_artifacts
    artifact_context = source_artifacts._MODULE_ARTIFACTS
    canonical_token = canonical_context.set(canonical_artifacts._module_compiler())
    try:
        artifact_token = artifact_context.set(source_artifacts._module_compiler())
        try:
            token = _COMPILED_TRANSACTION.set(_transaction_compiler())
            try:
                return _install_bundle()
            finally:
                _COMPILED_TRANSACTION.reset(token)
        finally:
            artifact_context.reset(artifact_token)
    finally:
        canonical_context.reset(canonical_token)



def _install_bundle():
    """Preflight before registry/alias mutation, then roll back this whole wave."""
    _verify_bridge(Path(__file__).resolve().parents[2])
    from . import CHECKS
    from .fixtures import CASES
    from . import gcp_workbench_source_runtime_admission_20261020 as workbench
    from . import gcp_dataflow_batch_source_runtime_admission_20261020 as dataflow
    from . import collector_noop_codebuild_admission_successor_20261020 as codebuild_successor
    codebuild = codebuild_successor.original
    from . import collector_noop_package_admission_successor_20261020 as package
    from . import azure_metadata_only_tde_admission_successor_20261020 as tde
    from . import gcp_function_secret_page_admission_20261020 as function_pairs
    # This validation has no registry or shared-alias writes.
    from . import collector_noop_command_admission_successor_20261020 as commands
    if _attestation_mode.ALWAYS:
        # Each install below re-runs the same proof before its first write and
        # any failure restores the whole wave, so outside CI the preflight is
        # a second identical proof.
        commands.reviewed_inputs()
        package.reviewed_inputs()
        codebuild_successor.reviewed_inputs()
        tde.reviewed_inputs()
        function_pairs.reviewed_inputs()
    ids = {commands.runtime.CHECK, original.CHECK, *workbench.CHECK_IDS, *dataflow.runtime.CHECKS, codebuild.runtime.CHECK, package.runtime.CHECK, *tde.IDS, function_pairs.original.CHECK_ID}
    before = tuple(CHECKS)
    old_cases = {ident: CASES[ident] for ident in ids if ident in CASES}
    old_reviewed, old_installed, old_shared = original.reviewed_inputs, original._INSTALLED, dataflow.shared
    old_dataflow_reviewed = dataflow.reviewed_inputs
    old_package, old_tde = package._INSTALLED, dict(tde.original._INSTALLED)
    old_codebuild_reviewed = codebuild.reviewed_inputs
    old_command_reviewed = commands.runtime.source.reviewed_sources
    old_command_inputs = commands.original.reviewed_inputs
    old_package_inputs = package.original.reviewed_inputs
    try:
        tde.install()
        install()
        from peaso.rawv2_private_source_successor_20261021 import install_admission
        install_admission('gcp_workbench_source_runtime_admission_20261020')
        install_dataflow(dataflow)
        codebuild_successor.install()
        package.install()
        function_pairs.install()
        commands.install()
    except Exception:
        CHECKS[:] = before
        for ident in ids:
            if ident in old_cases:
                CASES[ident] = old_cases[ident]
            else:
                CASES.pop(ident, None)
        original.reviewed_inputs, original._INSTALLED, dataflow.shared = old_reviewed, old_installed, old_shared
        dataflow.reviewed_inputs = old_dataflow_reviewed
        package._INSTALLED = old_package
        package.original._INSTALLED = old_package
        package.original.reviewed_inputs = old_package_inputs
        commands.original.reviewed_inputs = old_command_inputs
        codebuild.reviewed_inputs = old_codebuild_reviewed
        commands.runtime.source.reviewed_sources = old_command_reviewed
        tde.original._INSTALLED.clear()
        tde.original._INSTALLED.update(old_tde)
        raise


def check_aws(function, expected):
    from . import aws_s3_selected_source_admission_20261020 as s3
    receipt = reviewed_delta()
    row = receipt['shared_functions']['aws.collect']
    restored = inspect.getsource(function)
    transition = _private_receipt()['provider_group_callables'].get(function.__module__.replace('.', '/') + '.py:' + function.__qualname__)
    if transition is not None:
        restored = _reverse(restored, transition)
    for layer in (row, json.loads(Path(predecessor.predecessor.__file__).with_suffix('.json').read_bytes())['shared_functions']['aws.collect']):
        if hashlib.sha256(restored.encode()).hexdigest() != layer['current_sha256']:
            raise RuntimeError('AWS command collector source epoch changed')
        for addition in layer['exact_additions']:
            if restored.count(addition) != 1:
                raise RuntimeError('AWS command collector addition changed')
            restored = restored.replace(addition, '', 1)
    if hashlib.sha256(restored.encode()).hexdigest() != expected['sha256']:
        raise RuntimeError('AWS command original S3 collector changed')
    if s3.proof(function) != dict(expected, sha256=transition['current_sha256'] if transition is not None else row['current_sha256']):
        raise RuntimeError('AWS command native collector code changed')


def s3_reviewed_inputs():
    from . import aws_s3_selected_source_admission_20261020 as original
    root = Path(__file__).resolve().parents[2]
    _verify_bridge(root)
    receipt = json.loads((root / 'peaso/checks' / original.RECEIPT).read_bytes())
    reviewed_delta(root)
    for name, digest in receipt['source_hashes'].items():
        path = (root / name).resolve()
        data = _admitted_scanner_bytes(name, path.read_bytes(), digest, root)
        if not path.is_relative_to(root) or hashlib.sha256(data).hexdigest() != digest:
            raise RuntimeError('Selected S3 unchanged source changed')
    for expected in receipt['callables']:
        function = importlib.import_module(expected['module'])
        for name in expected['qualname'].split('.'):
            function = getattr(function, name)
        if expected['module'] == 'peaso.collectors.aws' and expected['qualname'] == 'collect':
            check_aws(function, expected)
        elif expected['module'] == 'peaso.secret_scanning':
            from peaso.rawv2_private_source_successor_20261021 import verify_callable_proof
            verify_callable_proof(function, expected, original.proof(function), root)
        else:
            transition = _private_receipt()['provider_group_callables'].get(function.__module__.replace('.', '/') + '.py:' + function.__qualname__)
            if transition is not None:
                _check_function(function, dict(expected, defaults=None, kwdefaults=None), root, {})
                if original.proof(function) != dict(expected, sha256=transition['current_sha256']):
                    raise RuntimeError('Selected S3 current scope-selection proof changed')
            else:
                from peaso.rawv2_private_source_successor_20261021 import verify_callable_proof
                verify_callable_proof(function, expected, original.proof(function), root)
    from peaso.collectors import aws_s3_selected_source_secret_indicators as producer
    if original.schema(producer) != dict(receipt['producer_schema'], **_private_receipt()['provider_group_s3_schema_additions']):
        raise RuntimeError('Selected S3 producer schema changed')
    for binding in receipt['bindings']:
        left = importlib.import_module(binding['module'])
        right = importlib.import_module(binding['origin_module'])
        if getattr(left, binding['name']) is not getattr(right, binding['origin_name']):
            raise RuntimeError('Selected S3 unchanged imported binding changed')
    fixture = receipt['fixture']
    path = (root / fixture['path']).resolve()
    if not path.is_relative_to(root / 'peaso/checks') or hashlib.sha256(path.read_bytes()).hexdigest() != fixture['sha256']:
        raise RuntimeError('Selected S3 packaged native fixture changed')
    cases = json.loads(path.read_bytes())
    from .aws_s3_selected_source_secret_review_20261020 import CHECK, evaluate
    if set(cases) != {CHECK}:
        raise RuntimeError('Selected S3 native identities changed')
    for branch in ('pass', 'fail', 'unknown'):
        if evaluate(cases[CHECK][branch], cases[CHECK][branch + '_index'])[0] != branch.upper():
            raise RuntimeError('Selected S3 native branch changed')
    return cases


def install_s3():
    # This installer runs before install_bundle; use the same bounded signed
    # artifacts for its own nested proof calls and always release the wave.
    root = Path(__file__).resolve().parents[2]
    from peaso.gcp_private_source_successor_20261021 import _bridge_source
    _bridge_source(root)
    from peaso import gcp_positive_conservation_source_admission_successor_20261020 as canonical_artifacts
    canonical_context = canonical_artifacts._MODULE_ARTIFACTS
    if (canonical_context is not canonical_artifacts._MODULE_CONTEXT
            or not isinstance(canonical_context, ContextVar)):
        raise RuntimeError('GCP canonical module artifact context changed')
    from peaso import gcp_private_source_successor_20261021 as source_artifacts
    artifact_context = source_artifacts._MODULE_ARTIFACTS
    canonical_token = canonical_context.set(canonical_artifacts._module_compiler())
    try:
        artifact_token = artifact_context.set(source_artifacts._module_compiler())
        try:
            token = _COMPILED_TRANSACTION.set(_transaction_compiler())
            try:
                from . import CHECKS,register
                from .fixtures import CASES
                from . import aws_s3_selected_source_secret_review_20261020 as reviewed
                cases=s3_reviewed_inputs();declaration,=reviewed.DECLARATIONS
                old=[c for c in CHECKS if c.id==reviewed.CHECK]
                if old:
                    if len(old)!=1 or inspect.unwrap(old[0].evaluate) is not reviewed.evaluate or old[0].kind!=declaration['kind']:
                        raise RuntimeError('Selected S3 registration collision')
                    if CASES.get(reviewed.CHECK)!=cases[reviewed.CHECK]:raise RuntimeError('Selected S3 registered fixture changed')
                    return
                before=tuple(CHECKS);had_case=reviewed.CHECK in CASES;previous=deepcopy(CASES.get(reviewed.CHECK))
                try:
                    register(reviewed.CHECK,'aws',declaration['category'],declaration['kind'],declaration['title'],'high',
                        'security_configuration',declaration['remediation'],dependencies=declaration['dependencies'],
                        allow_incomplete_failure=True)(reviewed.evaluate)
                    CASES[reviewed.CHECK]=deepcopy(cases[reviewed.CHECK])
                except Exception:
                    CHECKS[:]=before
                    if had_case:CASES[reviewed.CHECK]=previous
                    else:CASES.pop(reviewed.CHECK,None)
                    raise
            finally:
                _COMPILED_TRANSACTION.reset(token)
        finally:
            artifact_context.reset(artifact_token)
    finally:
        canonical_context.reset(canonical_token)




def verify_package_successor(root):
    """Attest every additive helper before its equivalent compiler dispatch."""
    _verify_bridge(root)
    raw = (root / 'peaso/checks' / RECEIPT).read_bytes()
    if hashlib.sha256(raw).hexdigest() != RECEIPT_SHA256:
        raise RuntimeError('Native CPU package bridge receipt changed')
    receipt = json.loads(raw)
    helper = 'peaso/checks/collector_noop_package_admission_successor_20261020.py'
    if (sys.modules.get(_PACKAGE_SUCCESSOR.__name__) is not _PACKAGE_SUCCESSOR
            or hashlib.sha256((root / helper).read_bytes()).hexdigest() != receipt['sources'][helper]['sha256']
            or _PACKAGE_SUCCESSOR.original is not importlib.import_module('peaso.checks.azure_function_package_integration_admission_20261020')):
        raise RuntimeError('Native CPU package successor source/binding changed')
    original_package = _PACKAGE_SUCCESSOR.original
    for name in _PACKAGE_SUCCESSOR.BINDINGS:
        if getattr(_PACKAGE_SUCCESSOR, name) is not getattr(original_package, name):
            raise RuntimeError('Native CPU package historical imported binding changed')
    if _PACKAGE_SUCCESSOR.BINDINGS != tuple(receipt['package_bindings']):
        raise RuntimeError('Native CPU package binding set changed')
    if _PACKAGE_SUCCESSOR._FUNCTIONS != _PACKAGE_FUNCTIONS:
        raise RuntimeError('Native CPU package callable set changed')
    compiled = {}
    for qualified, function in _PACKAGE_FUNCTIONS.items():
        if getattr(_PACKAGE_SUCCESSOR, qualified.split(':')[1]) is not function:
            raise RuntimeError('Native CPU package executing callable replaced')
        _check_function(function, receipt['functions'][qualified], root, compiled)



def predecessor_producer_bytes(relative, raw, root):
    """Reconstruct exactly three former source files; no source reader is changed."""
    if relative != 'peaso/secret_scanning.py':
        raw = _private_before(relative, raw, root)
    if relative == 'peaso/secret_scanning.py':
        from peaso.rawv2_private_source_successor_20261021 import source_bytes, SCANNER_BEFORE
        return source_bytes(relative, raw, SCANNER_BEFORE, root)
    paths = ('peaso/collectors/aws_workload_command_runtime_20261020.py',
             'peaso/collectors/aws_codebuild_buildspec_runtime_20261020.py',
             'peaso/collectors/azure_function_package_integration_20261020.py')
    if relative not in paths:
        return raw
    receipt_raw = (root / 'peaso/checks' / RECEIPT).read_bytes()
    if hashlib.sha256(receipt_raw).hexdigest() != RECEIPT_SHA256:
        raise RuntimeError('No-op producer receipt changed')
    receipt = json.loads(receipt_raw)
    if set(receipt['producer_file_deltas']) != set(paths):
        raise RuntimeError('No-op producer source set changed')
    row = receipt['producer_file_deltas'][relative]
    restored = _reverse(raw.decode('utf-8'), row).encode()
    if hashlib.sha256(restored).hexdigest() != row['predecessor_sha256']:
        raise RuntimeError('No-op producer predecessor source changed')
    return restored


def current_producer_row(function, historical_row, root):
    """Bind only three current authorizers to their exact historical callable rows."""
    if historical_row.get('path') == 'peaso/secret_scanning.py':
        from peaso.rawv2_private_source_successor_20261021 import producer_row
        return producer_row(function, historical_row, root)
    historical_row = _private_row(function, historical_row, root)
    qualified = function.__module__ + ':' + function.__qualname__
    names = ('peaso.collectors.aws_workload_command_runtime_20261020:authorize_collector',
             'peaso.collectors.aws_codebuild_buildspec_runtime_20261020:authorize_collector',
             'peaso.collectors.azure_function_package_integration_20261020:authorize')
    if qualified not in names:
        return historical_row
    raw = (root / 'peaso/checks' / RECEIPT).read_bytes()
    if hashlib.sha256(raw).hexdigest() != RECEIPT_SHA256:
        raise RuntimeError('No-op producer callable receipt changed')
    row = json.loads(raw)['producer_functions'][qualified]
    if historical_row != row['predecessor']:
        raise RuntimeError('No-op historical callable proof changed')
    if function is not _PRODUCER_FUNCTIONS[qualified]:
        raise RuntimeError('No-op producer callable identity changed')
    predecessor_producer_bytes(historical_row['path'], (root / historical_row['path']).read_bytes(), root)
    source = inspect.getsource(inspect.unwrap(function))
    restored = _reverse(source, row)
    if hashlib.sha256(restored.encode()).hexdigest() != historical_row['sha256']:
        raise RuntimeError('No-op producer callable predecessor changed')
    return dict(historical_row, sha256=row['current_sha256'])


def verify_authorization_successors(root):
    """Attest all added owners, their executing functions and canonical bindings."""
    _verify_bridge(root)
    raw = (root / 'peaso/checks' / RECEIPT).read_bytes()
    if hashlib.sha256(raw).hexdigest() != RECEIPT_SHA256:
        raise RuntimeError('No-op authorization successor receipt changed')
    receipt = json.loads(raw)
    compiled = {}
    if set(_PRODUCER_FUNCTIONS) != set(receipt['producer_functions']):
        raise RuntimeError('No-op producer callable set changed')
    for qualified, function in _PRODUCER_FUNCTIONS.items():
        owner, name = qualified.split(':')
        if getattr(importlib.import_module(owner), name) is not function:
            raise RuntimeError('No-op producer executing callable replaced')
        _check_function(function, receipt['producer_functions'][qualified]['predecessor'], root, compiled)
    for module in _AUTHORIZATION_SUCCESSORS:
        if sys.modules.get(module.__name__) is not module:
            raise RuntimeError('No-op authorization successor module changed')
        expected_grant = getattr(module.original, '_GRANT', getattr(module.original, '_GRANT_CLASS', None))
        if module.runtime._Grant is not expected_grant or module.runtime._TOKEN is not module.original._TOKEN:
            raise RuntimeError('No-op typed grant identity changed')
        expected_functions = {name: function for name, function in _AUTHORIZATION_FUNCTIONS.items()
                              if name.startswith(module.__name__ + ':')}
        if module._FUNCTIONS != expected_functions:
            raise RuntimeError('No-op authorization successor callable set changed')
        path = str(Path(module.__file__).resolve().relative_to(root))
        if hashlib.sha256((root / path).read_bytes()).hexdigest() != receipt['sources'][path]['sha256']:
            raise RuntimeError('No-op authorization successor source changed')
        if module.BINDINGS != tuple(receipt['authorization_bindings'][module.__name__]):
            raise RuntimeError('No-op authorization binding set changed')
        for name in module.BINDINGS:
            if getattr(module, name) is not getattr(module.original, name):
                raise RuntimeError('No-op authorization original binding changed')
        if module.original.reviewed_inputs not in (module.HISTORICAL_REVIEWED_INPUTS, module.reviewed_inputs):
            raise RuntimeError('No-op authorization canonical entrypoint changed')
        for qualified, function in module._FUNCTIONS.items():
            if (function is not _AUTHORIZATION_FUNCTIONS[qualified]
                    or getattr(module, qualified.split(':')[1]) is not function):
                raise RuntimeError('No-op authorization successor callable changed')
            _check_function(function, receipt['functions'][qualified], root, compiled)



def predecessor_epoch_bytes(relative, raw, root):
    """Apply the finite initializer delta, then run the old epoch proof."""
    if relative == 'peaso/checks/__init__.py':
        raw = _initialization_predecessor(raw)
    else:
        raw = _private_before(relative, raw, root)
    return historical_bridge.predecessor_epoch_bytes(relative, raw, root)


def predecessor_azure_collect(source, root):
    """Prove the complete current callable then reconstruct its fixed predecessor."""
    _private_self()
    transition = _private_receipt()['provider_group_azure_collect']
    if hashlib.sha256(source.encode()).hexdigest() != transition['current_sha256']:
        source = _reviewed_epoch.previous_function_source('peaso/collectors/azure.py', 'collect', source, root)
    source = _reverse(source, transition)
    receipt_raw = (root / 'peaso/checks' / RECEIPT).read_bytes()
    if hashlib.sha256(receipt_raw).hexdigest() != RECEIPT_SHA256:
        raise RuntimeError('Azure metadata-only collect receipt changed')
    receipt = json.loads(receipt_raw)
    row = receipt['metadata_only_collect']
    restored = _reverse(source, row)
    if hashlib.sha256(restored.encode()).hexdigest() != row['predecessor_sha256']:
        raise RuntimeError('Azure metadata-only collect predecessor changed')
    return restored


def verify_metadata_only(root):
    """Bind class identity/attributes and every executing function to exact source."""
    if not _attestation_mode.repeat(('verify_metadata_only', str(root)) in _PRIVATE_PROVEN):
        return
    _verify_bridge(root)
    receipt_raw = (root / 'peaso/checks' / RECEIPT).read_bytes()
    if hashlib.sha256(receipt_raw).hexdigest() != RECEIPT_SHA256:
        raise RuntimeError('Azure metadata-only receipt changed')
    receipt = json.loads(receipt_raw)
    prior_raw = (root / 'peaso/checks' / accepted_noop.RECEIPT).read_bytes()
    if (hashlib.sha256(prior_raw).hexdigest() != accepted_noop.RECEIPT_SHA256
            or receipt['accepted_noop_receipt_sha256'] != accepted_noop.RECEIPT_SHA256):
        raise RuntimeError('Azure metadata-only fixed no-op receipt changed')
    prior = json.loads(prior_raw)
    expected_self = {name for name in receipt['functions'] if name.startswith(historical_bridge.__name__ + ':')}
    expected_noop = {name for name in prior['functions'] if name.startswith(accepted_noop.__name__ + ':')}
    if (set(_FUNCTIONS) != expected_self or set(_NOOP_FUNCTIONS) != expected_noop
            or accepted_noop._FUNCTIONS != _NOOP_FUNCTIONS):
        raise RuntimeError('Azure metadata-only callable snapshot carrier changed')
    for key in ('shared_functions', 'integration_functions', 'azure_collect',
                'file_deltas', 'parent_file_deltas', 'integration_file_deltas',
                'prior_epoch_file_deltas', 'native_epoch_file_deltas',
                'producer_file_deltas', 'producer_functions'):
        if receipt[key] != prior[key]:
            raise RuntimeError('Azure metadata-only historical proof row changed')
    if any(receipt['functions'].get(name) != row for name, row in prior['functions'].items()):
        raise RuntimeError('Azure metadata-only historical callable row changed')
    for relative in ('peaso/checks/__init__.py', 'peaso/collectors/azure.py'):
        predecessor_epoch_bytes(relative, (root / relative).read_bytes(), root)
    if (sys.modules.get('peaso.collectors.azure') is not _METADATA_AZURE
            or _METADATA_AZURE.collect is not _METADATA_COLLECT
            or _METADATA_AZURE._MetadataOnlyCollection is not _METADATA_CLASS
            or _METADATA_COLLECT.__globals__ is not vars(_METADATA_AZURE)):
        raise RuntimeError('Azure metadata-only collector/class/global identity changed')
    cls = _METADATA_CLASS
    expected = receipt['metadata_only_class']
    attributes = vars(cls)
    class_keys = {'__module__', '__doc__', '__weakref__'}
    if sys.version_info >= (3, 13):
        class_keys |= {'__firstlineno__', '__static_attributes__'}
        current_source = (root / 'peaso/collectors/azure.py').read_bytes()
        current_row = _reviewed_epoch._receipt()['sources']['peaso/collectors/azure.py']
        if hashlib.sha256(current_source).hexdigest() != current_row['current_sha256']:
            raise RuntimeError('Portable sentinel current source changed')
        class_nodes = [node for node in ast.parse(current_source).body
                       if isinstance(node, ast.ClassDef) and node.name == '_MetadataOnlyCollection']
        if (len(class_nodes) != 1
                or receipt['portable_class_source']['firstlineno'] != 1820
                or type(attributes.get('__firstlineno__')) is not int
                or attributes['__firstlineno__'] != class_nodes[0].lineno
                or type(attributes.get('__static_attributes__')) is not tuple
                or attributes['__static_attributes__'] != ()):
            raise RuntimeError('Portable sentinel interpreter attributes changed')
    if (cls.__bases__ != (Exception,) or cls.__mro__ != (cls, Exception, BaseException, object)
            or set(attributes) != class_keys
            or cls.__module__ != expected['module'] or cls.__qualname__ != expected['qualname']
            or cls.__doc__ != expected['doc'] or attributes['__weakref__'] is not _METADATA_WEAKREF
            or _METADATA_WEAKREF.__objclass__ is not cls
            or cls.__new__ is not Exception.__new__ or cls.__init__ is not Exception.__init__
            or class_source_digest(cls, root, receipt) != expected['source_sha256']):
        raise RuntimeError('Azure metadata-only sentinel class behavior changed')
    compiled = {}
    row = receipt['metadata_only_collect']
    _, _, source_fragment = native_artifacts(_METADATA_COLLECT, root / row['current']['path'])
    _check_function(_METADATA_COLLECT, row['current'], root, compiled)
    previous_fragment = _reviewed_epoch.previous_function_source('peaso/collectors/azure.py', 'collect', source_fragment, root)
    restored = predecessor_azure_collect(previous_fragment, root)
    if hashlib.sha256(restored.encode()).hexdigest() != prior['azure_collect']['current_sha256']:
        raise RuntimeError('Azure metadata-only exact prior collect row changed')
    if sys.modules.get(_METADATA_TDE.__name__) is not _METADATA_TDE:
        raise RuntimeError('Azure metadata-only TDE module identity changed')
    original_tde = importlib.import_module('peaso.checks.azure_nsp_query_cmk_production_tde_successor_20261020')
    if _METADATA_TDE.original is not original_tde:
        raise RuntimeError('Azure metadata-only TDE predecessor identity changed')
    for name in receipt['metadata_only_tde_bindings']:
        if getattr(_METADATA_TDE, name) is not getattr(original_tde, name):
            raise RuntimeError('Azure metadata-only TDE imported binding changed')
    expected_tde = {name.split(':')[1] for name in receipt['functions'] if name.startswith(_METADATA_TDE.__name__ + ':')}
    if _METADATA_TDE._FUNCTIONS != _METADATA_TDE_FUNCTIONS or set(_METADATA_TDE_FUNCTIONS) != expected_tde:
        raise RuntimeError('Azure metadata-only TDE function set changed')
    for name, function in _METADATA_TDE_FUNCTIONS.items():
        if getattr(_METADATA_TDE, name) is not function:
            raise RuntimeError('Azure metadata-only TDE function identity changed')
        _check_function(function, receipt['functions'][function.__module__ + ':' + name], root, compiled)
    _PRIVATE_PROVEN[('verify_metadata_only', str(root))] = True

def native_artifacts(native, path, raw=None):
    """Read fresh source; reuse only signed compiled/source artifacts in one wave."""
    path = path.resolve()
    raw = path.read_bytes() if raw is None else raw
    key = (str(path), hashlib.sha256(raw).hexdigest(), sys.flags.optimize)
    compiler = _COMPILED_TRANSACTION.get()
    if compiler is None:
        records = _compiled_source(raw, str(path), sys.flags.optimize)
        matches = [(record, code) for record, code in records if record['qualname'] == native.__qualname__]
        source = inspect.getsource(native)
        return matches, hashlib.sha256(source.encode()).hexdigest(), source
    expected = next(code for code in _transaction_compiler.__code__.co_consts
                    if isinstance(code, types.CodeType) and code.co_name == 'lookup')
    if (not isinstance(compiler, types.FunctionType) or compiler.__code__ is not expected
            or compiler.__globals__ is not globals()):
        raise RuntimeError('Portable signed source compiler callable changed')
    return compiler(key, raw, native.__qualname__, native, want_source=True)


def class_source_digest(cls, root, receipt):
    """Recheck full disk and linecache bytes; slice only the pinned AST class span."""
    row = receipt['portable_class_source']
    path = (root / row['path']).resolve()
    filename = inspect.getsourcefile(cls)
    if not isinstance(filename, str) or Path(filename).resolve() != path:
        raise RuntimeError('Portable class source file identity changed')
    raw = path.read_bytes()
    before = _private_before(row['path'], raw, root)
    if hashlib.sha256(before).hexdigest() != receipt['metadata_only_epoch_file_deltas'][row['path']]['current_sha256']:
        raise RuntimeError('Portable class disk source changed')
    linecache.checkcache(filename)
    cached = ''.join(linecache.getlines(filename, vars(_METADATA_AZURE))).encode()
    if cached != raw:
        raise RuntimeError('Portable class linecache source changed')
    lines = before.decode().splitlines(keepends=True)
    return hashlib.sha256(''.join(lines[row['firstlineno'] - 1:row['endlineno']]).encode()).hexdigest()

_FUNCTIONS = historical_bridge._FUNCTIONS

# Capture executing objects before any bridge installer can publish aliases.
_INTEGRATION_FUNCTIONS = {
    'peaso.collectors.azure:_arm_parent_native_type': importlib.import_module('peaso.collectors.azure')._arm_parent_native_type,
    'peaso.collectors.aws:collect': importlib.import_module('peaso.collectors.aws').collect,
    'peaso.collectors.aws:_safe': importlib.import_module('peaso.collectors.aws')._safe,
    'peaso.engine:collect_snapshot': importlib.import_module('peaso.engine').collect_snapshot,
    'peaso.collectors.aws_facts_swc:_event_rule': importlib.import_module('peaso.collectors.aws_facts_swc')._event_rule,
}
_EVENT_RULE_CLOSURE = _INTEGRATION_FUNCTIONS['peaso.collectors.aws_facts_swc:_event_rule'].__closure__
_EVENT_RULE_INNER = _EVENT_RULE_CLOSURE[0].cell_contents

_PRODUCER_FUNCTIONS = {name: getattr(importlib.import_module(name.split(':')[0]), name.split(':')[1]) for name in (
    'peaso.collectors.aws_workload_command_runtime_20261020:authorize_collector',
    'peaso.collectors.aws_codebuild_buildspec_runtime_20261020:authorize_collector',
    'peaso.collectors.azure_function_package_integration_20261020:authorize')}


def rawv2_bootstrap_source(raw, expected, root):
    """Prove only the current RawV2 helper against its immutable ancestor."""
    _private_self()
    package_root = Path(__file__).resolve().parents[2]
    if Path(root).resolve(strict=True) != package_root:
        raise RuntimeError('RawV2 bootstrap root changed')
    relative = 'peaso/rawv2_private_source_successor_20261021.py'
    path = package_root / relative
    if (path.is_symlink() or path.resolve(strict=True) != path
            or type(raw) is not bytes or raw != path.read_bytes()
            or expected not in ('3ef9840685cc94829a12c7c54693da901ac6ddb691f493e53290255c5224d940',
                                'adb16873adf517a30c11a280c94c748b90ba405f46b5219630eef877a4aabf67')):
        raise RuntimeError('RawV2 bootstrap live source changed')
    receipt = _private_receipt(parse=True)
    row = receipt['image_capture_admission']['files'][relative]
    prior = _reverse(raw.decode('utf-8'), row).encode('utf-8')
    ancestor = _private_source_epoch._receipt()[0]['current_reviewed_files'][relative]
    if (hashlib.sha256(prior).hexdigest() != row['predecessor_sha256']
            or row['predecessor_sha256'] != ancestor['current_sha256']
            or ancestor['predecessor_sha256'] != '3ef9840685cc94829a12c7c54693da901ac6ddb691f493e53290255c5224d940'):
        raise RuntimeError('RawV2 bootstrap ancestor binding changed')
    result = _reverse(prior.decode('utf-8'), ancestor).encode('utf-8')
    if hashlib.sha256(result).hexdigest() != ancestor['predecessor_sha256']:
        raise RuntimeError('RawV2 bootstrap ancestor changed')
    if expected == row['predecessor_sha256']:
        return prior
    return result


def rawv2_package_source(raw, expected, root):
    """Prove the finite package512 transition to the historical package128."""
    _private_self()
    package_root = Path(__file__).resolve().parents[2]
    if Path(root).resolve(strict=True) != package_root:
        raise RuntimeError('RawV2 package root changed')
    relative = 'peaso/collectors/aws_package_content_indicators.py'
    path = package_root / relative
    if (path.is_symlink() or path.resolve(strict=True) != path
            or type(raw) is not bytes or raw != path.read_bytes()
            or expected != 'ce459d4b5ed0ae991591f09f61b462f7841f0977d5935579e561409c0117e7e6'):
        raise RuntimeError('RawV2 package live source changed')
    receipt = _private_receipt(parse=True)
    row = receipt['rawv2_package128_admission']
    epoch, sources = _private_source_epoch._receipt()
    historical = sources[relative]
    if (row['current_sha256'] != receipt['image_capture_admission']['files'][relative]['current_sha256']
            or row['predecessor_sha256'] != historical['after_sha256']
            or expected != historical['before_sha256']):
        raise RuntimeError('RawV2 package ancestor binding changed')
    result = _reverse(raw.decode('utf-8'), row).encode('utf-8')
    if hashlib.sha256(result).hexdigest() != historical['after_sha256']:
        raise RuntimeError('RawV2 package ancestor changed')
    import zipfile
    archive = Path(_private_source_epoch.__file__).with_name('private_secret_source_epoch_20261021.zip')
    if hashlib.sha256(archive.read_bytes()).hexdigest() != epoch['before_archive_sha256']:
        raise RuntimeError('RawV2 package original archive changed')
    with zipfile.ZipFile(archive) as bundle:
        if sorted(bundle.namelist()) != sorted(sources):
            raise RuntimeError('RawV2 package original archive roster changed')
        before = bundle.read(relative)
    if hashlib.sha256(before).hexdigest() != expected:
        raise RuntimeError('RawV2 package original predecessor changed')
    return before


def rawv2_current_content_definition(function, root):
    """Attest only six unchanged producers under their exact reviewed sources."""
    _private_self()
    module_name = getattr(function, '__module__', '')
    name = getattr(function, '__qualname__', '')
    if (module_name, name) not in (
            ('peaso.collectors.aws_package_content_indicators', '_image'),
            ('peaso.collectors.aws_package_content_indicators', '_lambda'),
            ('peaso.collectors.aws_package_content_indicators', '_layer'),
            ('peaso.collectors.aws_package_content_indicators', '_scan'),
            ('peaso.collectors.azure_selected_storage_secret_indicators', '_inspect'),
            ('peaso.collectors.azure_selected_storage_secret_indicators', '_scan')):
        raise RuntimeError('RawV2 current content producer is not reviewed')
    relative = module_name.replace('.', '/') + '.py'
    source_path = Path(__file__).resolve().parents[2] / relative
    if Path(root).resolve(strict=True) != source_path.parents[2]:
        raise RuntimeError('RawV2 package callable root changed')
    source = source_path.read_bytes()
    if module_name == 'peaso.collectors.aws_package_content_indicators':
        rawv2_package_source(source, 'ce459d4b5ed0ae991591f09f61b462f7841f0977d5935579e561409c0117e7e6', root)
    else:
        _reviewed_epoch.predecessor_bytes(relative, source,
            '59db1280c49909db57368b7e4e61e846f5f2c8ee1b323c6b2204f2110646beda', root)
    epoch = _private_source_epoch
    row = epoch.source_rows()[relative]
    module = sys.modules.get(module_name)
    if (type(function) is not types.FunctionType or type(module) is not types.ModuleType
            or function.__module__ != module.__name__ or function.__globals__ is not vars(module)
            or '.' in name or name != function.__name__ or vars(module).get(name) is not function
            or Path(module.__file__).resolve(strict=True) != source_path
            or Path(function.__code__.co_filename).resolve(strict=True) != source_path):
        raise RuntimeError('RawV2 package callable binding changed')
    tree = ast.parse(source, filename=str(source_path))
    nodes = [node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name]
    definitions = [item for item in row['definitions'] if item['name'] == name]
    if len(nodes) != 1 or len(definitions) != 1:
        raise RuntimeError('RawV2 package callable roster changed')
    node, definition = nodes[0], definitions[0]
    hashes = definition
    if relative == 'peaso/collectors/aws_package_content_indicators.py' and name == '_image':
        successors = _private_receipt()['rawv2_package128_admission']['current_definitions']
        if set(successors) != {'_image'}:
            raise RuntimeError('ECR package definition roster changed')
        successor = successors[name]
        if (successor['predecessor_sha256'] != definition['after']
                or successor['predecessor_ast_sha256'] != definition['after_ast_sha256']):
            raise RuntimeError('ECR package retained definition witness changed')
        fragment = b''.join(source.splitlines(keepends=True)[node.lineno - 1:node.end_lineno]).decode('utf-8')
        if (hashlib.sha256(fragment.encode()).hexdigest() != successor['current_sha256']
                or epoch._ast_hash(node) != successor['current_ast_sha256']):
            raise RuntimeError('ECR package current definition source changed')
        previous = _reverse(fragment, successor)
        prior_tree = ast.parse(previous)
        if (len(prior_tree.body) != 1 or type(prior_tree.body[0]) is not ast.FunctionDef
                or prior_tree.body[0].name != name
                or hashlib.sha256(previous.encode()).hexdigest() != definition['after']
                or epoch._ast_hash(prior_tree.body[0]) != definition['after_ast_sha256']):
            raise RuntimeError('ECR package definition inverse changed')
        hashes = dict(definition, after=successor['current_sha256'], after_ast_sha256=successor['current_ast_sha256'])
    compiled = epoch._expected_helper_code(source_path, source, function.__code__.co_filename)
    constants = epoch._constants(tree, str(source_path))
    if (epoch._source_hash(source, node) != hashes['after']
            or epoch._ast_hash(node) != hashes['after_ast_sha256']
            or not epoch._code_equal(function.__code__, epoch._code_from(compiled, name))):
        raise RuntimeError('RawV2 package executing callable changed')
    epoch._check_defaults(function, node, constants, function.__code__.co_filename)
    epoch._check_globals(function, tree, compiled, constants, module, root)
    return {
        'current': {'path': relative, 'name': name, 'module': module.__name__,
                    'file_sha256': hashlib.sha256(source).hexdigest(),
                    'source_sha256': hashes['after'], 'ast_sha256': hashes['after_ast_sha256']},
        'historical': {'path': relative, 'name': name, 'module': module.__name__,
                       'file_sha256': row['before_sha256'],
                       'source_sha256': definition['before'], 'ast_sha256': definition['before_ast_sha256']}}


def rawv2_current_content_projection(function, row, root):
    """Reuse the immutable row projector with only the six finite content producers."""
    _private_self()
    _private_source_epoch._self()
    namespace = dict(vars(_private_source_epoch), trusted_definition=rawv2_current_content_definition)
    projector = types.FunctionType(_private_source_epoch.callable_projection.__code__, namespace,
                                   'callable_projection', _private_source_epoch.callable_projection.__defaults__)
    return projector(function, row, root)
