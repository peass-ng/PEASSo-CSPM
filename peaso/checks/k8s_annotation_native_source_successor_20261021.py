"""Finite source successor for the five historical annotation admissions.

The historical module and its function globals remain untouched. The historical
installer runs from a private module namespace with one narrower source attestor.
"""
import ast
import dis
import hashlib
import importlib
import json
from pathlib import Path
import sys
import sysconfig
import types
from urllib.parse import quote

from . import k8s_annotation_native_admission_20261020 as historical
from peaso import private_secret_source_epoch_20261021 as source_epoch
from peaso import private_reviewed_collector_successor_20261022 as reviewed_epoch

ROOT = Path(__file__).resolve().parents[2]
GUARD = ROOT / 'peaso/checks/k8s_annotation_native_admission_20261020.py'
COLLECTOR = ROOT / 'peaso/collectors/k8s.py'
HELPER = ROOT / 'peaso/secret_evidence.py'
RECEIPT = Path(__file__).with_suffix('.json')
GUARD_SHA = '73cecf776d322c3f81293b342e09127465383a3b2cfcdcebaf276b62f3fa11f8'
BEFORE_SHA = '86eca83f116bc8fe4a2b28d5ced1ae6612507c5cc3f53968fe6ec28df14a15f1'
AFTER_SHA = '3dd3f487e84101f7f72c164e817e95ff8b3e4e5296cde2dbd102f01f96c5cf18'
HELPER_SHA = '15092e316c2331e03fdae7fad4dda5ed92310a1c15a827b0009fbcd54a11693a'
SNAPSHOT_SHA = '6dcf7d4953c1b1b17e8669cb5f44960a4340ea8d6e9f93fb356d4df52d570919'
INSERTION = (b"    from peaso.secret_evidence import pod_environment\n"
             b"    pod_environment(item, kind=kind, resource_id='k8s://' + '/'.join(quote(str(x), safe='') for x in (cluster, kind, namespace, meta.get('uid') or name)), scope=namespace if scope == '*' else scope)\n")
NAMES = ('_sanitize', '_native', '_pages', 'collect')
_RUNTIME_DEPENDENCIES = ('_component_config', '_env_entry', '_sanitize')
_HISTORICAL_CODE_SHA256 = {
    '_component_config': 'e70dfb3708d5b91f084e3a20c1872d85fc91d1231ca3276d3cfb17b16515a5c3',
    '_env_entry': '9b4f60781c8c0f2006d7062c3f098ff846056d4fc247cc33e70db62815d6ac28',
    '_sanitize': 'd1e09bd88af613ca32ddc0d22f874ca1918f1a7d53b0c3db1387f27353c66297',
}
_PRIVATE_NAME = 'peaso.checks._k8s_annotation_native_source_successor_20261021_namespace'


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _shape(code):
    return json.dumps(historical._code(code), sort_keys=True, separators=(',', ':'), allow_nan=False)


def _binding(value):
    if isinstance(value, types.ModuleType):
        if sys.modules.get(value.__name__) is not value:
            raise RuntimeError('Successor global module identity changed')
        return {'module': value.__name__}
    if isinstance(value, (types.FunctionType, type)):
        owner = sys.modules.get(value.__module__)
        if owner is None or getattr(owner, value.__qualname__.split('.')[0], None) is not value:
            raise RuntimeError('Successor global callable identity changed')
        result = {'callable': value.__module__ + ':' + value.__qualname__}
        if isinstance(value, types.FunctionType):
            result['code_sha256'] = _sha(_shape(value.__code__).encode())
            result['defaults'] = repr(value.__defaults__)
            result['kwdefaults'] = repr(value.__kwdefaults__)
        return result
    if isinstance(value, (str, int, float, bool)) or value is None:
        return {'type': type(value).__name__, 'value': value}
    if isinstance(value, (tuple, list, set, frozenset)):
        members = [_binding(v) for v in value]
        if isinstance(value, (set, frozenset)):
            members.sort(key=lambda v: json.dumps(v, sort_keys=True))
        return {'type': type(value).__name__, 'items': members}
    if isinstance(value, dict):
        return {'dict': sorted([[_binding(k), _binding(v)] for k, v in value.items()],
                               key=lambda pair: json.dumps(pair[0], sort_keys=True))}
    raise RuntimeError('Unrecognized successor global binding')


def _global_proofs(function):
    names = set()
    def visit(code):
        names.update(i.argval for i in dis.get_instructions(code) if i.opname in ('LOAD_GLOBAL', 'LOAD_NAME'))
        for member in code.co_consts:
            if isinstance(member, types.CodeType):
                visit(member)
    visit(function.__code__)
    return {name: _binding(function.__globals__[name]) for name in sorted(names)
            if name in function.__globals__}


def _self_proof():
    receipt = json.loads(RECEIPT.read_text(), object_pairs_hook=historical._pairs)
    required = {'schema', 'successor_source_sha256', 'source_epoch_sha256',
                'source_epoch_receipt_sha256', 'source_epoch_archive_sha256',
                'historical_guard_sha256', 'historical_receipt_sha256',
                'collector_before_sha256', 'collector_after_sha256', 'helper_sha256',
                'snapshot_sha256',
                'ids', 'capture_enabled', 'collector_globals', 'engine_plan_admission'}
    if (set(receipt) != required or receipt['schema'] != 'finite-k8s-annotation-successor-v1'
            or receipt['ids'] != list(historical.IDS) or receipt['capture_enabled'] is not False
            or receipt['historical_guard_sha256'] != GUARD_SHA
            or receipt['collector_before_sha256'] != BEFORE_SHA
            or receipt['collector_after_sha256'] != AFTER_SHA
            or receipt['helper_sha256'] != HELPER_SHA
            or receipt['snapshot_sha256'] != SNAPSHOT_SHA
            or _sha(Path(__file__).read_bytes()) != receipt['successor_source_sha256']
            or sys.modules.get('peaso.private_secret_source_epoch_20261021') is not source_epoch
            or Path(source_epoch.__file__).resolve() != ROOT / 'peaso/private_secret_source_epoch_20261021.py'
            or _sha(Path(source_epoch.__file__).read_bytes()) != receipt['source_epoch_sha256']
            or _sha((ROOT / 'peaso/private_secret_source_epoch_20261021.json').read_bytes()) != receipt['source_epoch_receipt_sha256']
            or _sha((ROOT / 'peaso/private_secret_source_epoch_20261021.zip').read_bytes()) != receipt['source_epoch_archive_sha256']
            or _sha((ROOT / 'peaso/checks/k8s_annotation_native_admission_selected_metadata_successor_20261020.json').read_bytes()) != receipt['historical_receipt_sha256']):
        raise RuntimeError('Successor source or receipt changed')
    for row in receipt['collector_globals'].values():
        for name, digest in _HISTORICAL_CODE_SHA256.items():
            if name in row and row[name].get('code_sha256') != digest:
                raise RuntimeError('Successor historical code witness changed: ' + name)
    caller = (ROOT / 'peaso/checks/__init__.py').read_text()
    hunk = ('from . import k8s_annotation_native_source_successor_20261021\n'
            'k8s_annotation_native_source_successor_20261021.install()')
    if caller.count(hunk) != 1:
        raise RuntimeError('Successor initializer call changed')
    module = sys.modules[__name__]
    compiled = historical._compiled_source(Path(__file__).read_bytes(), str(Path(__file__)), sys.flags.optimize)
    for name, function in vars(module).items():
        if not isinstance(function, types.FunctionType) or function.__globals__ is not vars(module):
            continue
        matches = [(record, code) for record, code in compiled if record['qualname'] == name]
        if len(matches) != 1 or _shape(function.__code__) != _shape(matches[0][1]):
            raise RuntimeError('Successor installer live function changed: ' + name)


def _source_proofs():
    raw = COLLECTOR.read_bytes()
    before = reviewed_epoch.predecessor_bytes('peaso/collectors/k8s.py', raw, BEFORE_SHA, ROOT)
    if _sha(before) != BEFORE_SHA:
        raise RuntimeError('Successor predecessor reconstruction changed')
    if _sha(source_epoch.predecessor_bytes('peaso/secret_evidence.py', HELPER.read_bytes(), HELPER_SHA, ROOT)) != HELPER_SHA:
        raise RuntimeError('Successor private evidence helper changed')
    reviewed_epoch.verify_k8s_literal_current(importlib.import_module('peaso.collectors.k8s'), ROOT)
    return raw, before


def _helper_proof():
    # _native imports this callable inside its body.  The collector's module
    # globals therefore cannot attest that late binding.
    module = sys.modules.get('peaso.secret_evidence')
    if (not isinstance(module, types.ModuleType)
            or Path(getattr(module, '__file__', '')).resolve() != HELPER
            or _sha(source_epoch.predecessor_bytes('peaso/secret_evidence.py', HELPER.read_bytes(), HELPER_SHA, ROOT)) != HELPER_SHA):
        raise RuntimeError('Successor helper module changed')
    for name in ('pod_environment', 'enabled', 'named_environment', 'named_literal'):
        value = vars(module).get(name)
        if not isinstance(value, types.FunctionType) or value.__closure__ is not None:
            raise RuntimeError('Successor helper callable binding changed: ' + name)
        source_epoch._check_helper_import(value, module, name, ROOT)
    if (module.NAMED_CHECKS.get('k8s') != {
            'k8s.claude.pod.no_literal_secret_env', 'azure_aks_cluster_3_5_1_14_247ebcd'}
            or module._active is not None or module.enabled() is not False):
        raise RuntimeError('Successor helper configuration changed')


def _current_functions(raw):
    module = importlib.import_module('peaso.collectors.k8s')
    if Path(module.__file__).resolve() != COLLECTOR or sys.modules.get(module.__name__) is not module:
        raise RuntimeError('Successor collector module identity changed')
    compiled = historical._compiled_source(raw, str(COLLECTOR), sys.flags.optimize)
    expected_globals = json.loads(RECEIPT.read_text())['collector_globals']
    tree = ast.parse(raw, filename=str(COLLECTOR))
    runtime_digests = {}
    collector_dependencies = {name for row in expected_globals.values() for name, proof in row.items()
                              if proof.get('callable') == module.__name__ + ':' + name
                              and 'code_sha256' in proof}
    for dependency in sorted(collector_dependencies | set(_RUNTIME_DEPENDENCIES)):
        value = vars(module).get(dependency)
        nodes = [node for node in tree.body
                 if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == dependency]
        matches = [code for record, code in compiled if record['qualname'] == dependency]
        if (len(nodes) != 1 or len(matches) != 1 or type(value) is not types.FunctionType
                or value.__module__ != module.__name__ or value.__qualname__ != dependency
                or value.__globals__ is not vars(module) or value.__closure__ is not None
                or not source_epoch._immutable_code_constants(value.__code__)
                or not source_epoch._code_equal(value.__code__, matches[0])):
            raise RuntimeError('Successor dependency source or live code changed: ' + dependency)
        if dependency in _RUNTIME_DEPENDENCIES:
            node = nodes[0]
            defaults = tuple(ast.literal_eval(arg) for arg in node.args.defaults) or None
            kwdefaults = {arg.arg: ast.literal_eval(expr) for arg, expr in
                          zip(node.args.kwonlyargs, node.args.kw_defaults) if expr is not None} or None
            if value.__defaults__ != defaults or value.__kwdefaults__ != kwdefaults:
                raise RuntimeError('Successor dependency defaults changed: ' + dependency)
        runtime_digests[dependency] = _sha(_shape(matches[0]).encode())
    stdlib_parse = sys.modules.get('urllib.parse')
    stdlib_path = (Path(sysconfig.get_path('stdlib')).resolve(strict=True) / 'urllib/parse.py').resolve(strict=True)
    if (stdlib_parse is None or vars(stdlib_parse).get('quote') is not quote
            or Path(stdlib_parse.__file__).resolve(strict=True) != stdlib_path
            or quote.__globals__ is not vars(stdlib_parse) or quote.__closure__ is not None):
        raise RuntimeError('Successor stdlib quote binding changed')
    stdlib_code = compile(stdlib_path.read_bytes(), quote.__code__.co_filename, 'exec',
                          dont_inherit=True, optimize=sys.flags.optimize)
    stdlib_matches = [code for code in stdlib_code.co_consts
                      if type(code) is types.CodeType and code.co_name == 'quote']
    if (len(stdlib_matches) != 1 or not source_epoch._immutable_code_constants(quote.__code__)
            or not source_epoch._code_equal(quote.__code__, stdlib_matches[0])):
        raise RuntimeError('Successor stdlib quote code changed')
    runtime_digests['quote'] = _sha(_shape(stdlib_matches[0]).encode())
    epoch_sources = source_epoch.source_rows()
    external = {
        'peaso.collectors.azure': (ROOT / 'peaso/collectors/azure.py',
                                    reviewed_epoch._receipt()['sources']['peaso/collectors/azure.py']['current_sha256']),
        'peaso.snapshot': (ROOT / 'peaso/snapshot.py', SNAPSHOT_SHA),
    }
    for owner_name, (source_path, source_sha) in external.items():
        owner = sys.modules.get(owner_name)
        source_path = source_path.resolve(strict=True)
        source = source_path.read_bytes()
        if owner_name == 'peaso.snapshot':
            from . import private_secret_shared_source_successor_20261021 as shared_source
            before = shared_source._private_before('peaso/snapshot.py', source, ROOT)
            if _sha(before) != SNAPSHOT_SHA:
                raise RuntimeError('Successor snapshot predecessor changed')
            source_sha = shared_source._private_receipt()['provider_group_files']['peaso/snapshot.py']['current_sha256']
        if (not isinstance(owner, types.ModuleType)
                or Path(getattr(owner, '__file__', '')).resolve(strict=True) != source_path
                or _sha(source) != source_sha):
            raise RuntimeError('Successor external source changed: ' + owner_name)
        expected_names = {name for row in expected_globals.values() for name, proof in row.items()
                          if proof.get('callable') == owner_name + ':' + name
                          and 'code_sha256' in proof}
        compiled_owner = compile(source, str(source_path), 'exec',
                                 dont_inherit=True, optimize=sys.flags.optimize)
        for dependency in expected_names:
            value = vars(owner).get(dependency)
            matches = [code for code in compiled_owner.co_consts
                       if type(code) is types.CodeType and code.co_name == dependency]
            if (len(matches) != 1 or type(value) is not types.FunctionType
                    or value.__module__ != owner_name or value.__qualname__ != dependency
                    or value.__globals__ is not vars(owner) or value.__closure__ is not None
                    or not source_epoch._immutable_code_constants(value.__code__)
                    or not source_epoch._code_equal(value.__code__, matches[0])):
                raise RuntimeError('Successor external dependency changed: ' + dependency)
            runtime_digests[dependency] = _sha(_shape(matches[0]).encode())
    actual = {}
    for name in NAMES:
        function = vars(module).get(name)
        if (not isinstance(function, types.FunctionType) or function.__globals__ is not vars(module)
                or function.__module__ != module.__name__ or function.__closure__ is not None):
            raise RuntimeError('Successor collector global or closure changed: ' + name)
        matches = [(record, code) for record, code in compiled if record['qualname'] == name]
        if (len(matches) != 1 or not source_epoch._immutable_code_constants(function.__code__)
                or not source_epoch._code_equal(function.__code__, matches[0][1])):
            raise RuntimeError('Successor collector executing code changed: ' + name)
        node, = (n for n in tree.body
                 if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name)
        defaults = tuple(ast.literal_eval(n) for n in node.args.defaults) or None
        kwdefaults = {arg.arg: ast.literal_eval(value) for arg, value in
                      zip(node.args.kwonlyargs, node.args.kw_defaults) if value is not None} or None
        if function.__defaults__ != defaults or function.__kwdefaults__ != kwdefaults:
            raise RuntimeError('Successor collector defaults changed: ' + name)
        expected = expected_globals[name]
        for dependency, digest in runtime_digests.items():
            if dependency in expected:
                expected[dependency]['code_sha256'] = digest
        if _global_proofs(function) != expected:
            raise RuntimeError('Successor collector globals changed: ' + name + str([key for key in set(expected) | set(_global_proofs(function)) if expected.get(key) != _global_proofs(function).get(key)]))
        actual[name] = function
    # The newly introduced identity path, and its recursive sanitizer, must
    # resolve to the attested module functions and the reviewed stdlib import.
    if module._native.__globals__.get('_sanitize') is not actual['_sanitize'] or module._native.__globals__.get('quote') is not quote:
        raise RuntimeError('Successor collector global binding changed')
    if module._pages.__globals__.get('_native') is not actual['_native']:
        raise RuntimeError('Successor collector page binding changed')
    return actual


def _namespace():
    raw = GUARD.read_bytes()
    if _sha(raw) != GUARD_SHA:
        raise RuntimeError('Historical annotation guard changed')
    if _PRIVATE_NAME in sys.modules:
        raise RuntimeError('Historical annotation private namespace already occupied')
    module = types.ModuleType(_PRIVATE_NAME)
    module.__file__ = str(GUARD)
    module.__package__ = 'peaso.checks'
    sys.modules[_PRIVATE_NAME] = module
    try:
        exec(compile(raw, str(GUARD), 'exec'), vars(module))
        for name, value in vars(historical).items():
            if isinstance(value, types.FunctionType) and value.__globals__ is vars(historical):
                cloned = vars(module).get(name)
                if (not isinstance(cloned, types.FunctionType) or _shape(cloned.__code__) != _shape(value.__code__)
                        or cloned.__defaults__ != value.__defaults__ or cloned.__kwdefaults__ != value.__kwdefaults__):
                    raise RuntimeError('Historical annotation function clone changed: ' + name)
        return module
    except BaseException:
        sys.modules.pop(_PRIVATE_NAME, None)
        raise


def _engine_plan_source():
    """Authenticate one reviewed planner successor through the existing owner."""
    row = json.loads(RECEIPT.read_text(), object_pairs_hook=historical._pairs)['engine_plan_admission']
    if set(row) != {'current_fragment_sha256', 'predecessor_fragment_sha256',
                    'predecessor_source', 'defaults', 'kwdefaults'}:
        raise RuntimeError('Annotation engine planner receipt changed')
    path = ROOT / 'peaso/engine.py'
    raw = path.read_bytes()
    owner = importlib.import_module('peaso.checks.private_secret_shared_source_successor_20261021')
    if (sys.modules.get(owner.__name__) is not owner
            or Path(owner.__file__).resolve() != ROOT / 'peaso/checks/private_secret_shared_source_successor_20261021.py'):
        raise RuntimeError('Annotation engine source owner changed')
    # This verifies current whole-file bytes and reconstructs its immutable
    # predecessor using the already admitted, exact current transition.
    owner._private_before('peaso/engine.py', raw, ROOT)
    text = raw.decode('utf-8'); lines = text.splitlines(keepends=True)
    nodes = [node for node in ast.parse(text).body
             if isinstance(node, ast.FunctionDef) and node.name == 'plan_collection']
    if len(nodes) != 1:
        raise RuntimeError('Annotation engine planner source is ambiguous')
    node = nodes[0]
    current = ''.join(lines[node.lineno - 1:node.end_lineno])
    prior = row['predecessor_source']
    expected = historical._source_receipt()['compiled_sources']['peaso/engine.py']
    if (_sha(current.encode()) != row['current_fragment_sha256']
            or _sha(prior.encode()) != row['predecessor_fragment_sha256']
            or row['predecessor_fragment_sha256'] != expected['functions']['plan_collection']['source_sha256']
            or text.count(current) != 1):
        raise RuntimeError('Annotation engine planner exact transition changed')
    previous = text.replace(current, prior, 1).encode('utf-8')
    scoped = historical._verified_source('peaso/engine.py', previous, expected)
    return row, raw, scoped


def install():
    _self_proof()
    raw, before = _source_proofs()
    current_functions = _current_functions(raw)
    _helper_proof()
    historical_receipt = historical._source_receipt()
    expected_source = historical_receipt['compiled_sources']['peaso/collectors/k8s.py']
    exact_before = reviewed_epoch.predecessor_bytes('peaso/collectors/k8s.py', raw, BEFORE_SHA, ROOT)
    if before != exact_before:
        raise RuntimeError('Successor exact predecessor bytes changed')
    # The reviewed source receipt pins the complete current collector bytes.
    # _current_functions proves the live callable code and globals against them.
    historical_row = {'path': 'peaso/collectors/k8s.py',
                      'sha256': expected_source['functions']['_native']['source_sha256']}
    current_matches = [(record, code) for record, code in
                       historical._compiled_source(raw, str(COLLECTOR), sys.flags.optimize)
                       if record['qualname'] == '_native']
    previous_matches = [(record, code) for record, code in
                        historical._compiled_source(before, str(COLLECTOR), sys.flags.optimize)
                        if record['qualname'] == '_native']
    if (len(current_matches) != 1 or len(previous_matches) != 1
            or previous_matches[0][0]['source_sha256'] != historical_row['sha256']
            or not source_epoch._code_equal(current_functions['_native'].__code__, current_matches[0][1])):
        raise RuntimeError('Successor shared source epoch changed')
    old_source = historical._verified_source('peaso/collectors/k8s.py', before, expected_source)
    namespace = _namespace()
    original_attestor = namespace._trusted_definition
    original_source_view = namespace._verified_source
    old_records = [(record, code) for record, code in
                   historical._compiled_source(old_source, str(COLLECTOR), sys.flags.optimize)
                   if record['qualname'] in NAMES]
    if len(old_records) != len(NAMES) or {record['qualname'] for record, _ in old_records} != set(NAMES):
        raise RuntimeError('Historical collector definitions ambiguous')
    old_definitions = {record['qualname']: record for record, _ in old_records}

    def source_view(relative, candidate_raw, expected):
        if relative == 'peaso/collectors/k8s.py':
            current_raw, historical_raw = _source_proofs()
            _current_functions(current_raw)
            _helper_proof()
            if candidate_raw != current_raw or historical_raw != before:
                raise RuntimeError('Successor collector source view changed')
            return original_source_view(relative, historical_raw, expected)
        if relative == 'peaso/engine.py':
            _, current_raw, previous_source = _engine_plan_source()
            if candidate_raw != current_raw:
                raise RuntimeError('Annotation engine source view changed')
            return original_source_view(relative, previous_source, expected)
        return original_source_view(relative, candidate_raw, expected)

    def trusted_definition(function):
        if (isinstance(function, types.FunctionType)
                and function.__globals__.get('__name__') == 'peaso.collectors.k8s'
                and function.__name__ in NAMES):
            current = _current_functions(_source_proofs()[0])
            _helper_proof()
            if function is not current[function.__name__]:
                raise RuntimeError('Successor collector callable binding changed')
            return 'peaso/collectors/k8s.py', old_definitions[function.__name__]
        if (isinstance(function, types.FunctionType)
                and function.__globals__.get('__name__') == 'peaso.engine'
                and function.__qualname__ == 'plan_collection'):
            row, current_raw, previous_source = _engine_plan_source()
            module = sys.modules.get('peaso.engine')
            current = [(record, code) for record, code in historical._compiled_source(
                current_raw, str(ROOT / 'peaso/engine.py'), sys.flags.optimize)
                if record['qualname'] == 'plan_collection']
            previous = [(record, code) for record, code in historical._compiled_source(
                previous_source, str(ROOT / 'peaso/engine.py'), sys.flags.optimize)
                if record['qualname'] == 'plan_collection']
            if (module is None or function is not vars(module).get('plan_collection')
                    or function.__globals__ is not vars(module) or function.__closure__ is not None
                    or function.__module__ != 'peaso.engine'
                    or function.__code__.co_filename != str(ROOT / 'peaso/engine.py')
                    or len(current) != 1 or len(previous) != 1
                    or _shape(function.__code__) != _shape(current[0][1])
                    or repr(function.__defaults__) != row['defaults']
                    or repr(function.__kwdefaults__) != row['kwdefaults']):
                raise RuntimeError('Annotation engine planner live binding changed')
            return 'peaso/engine.py', previous[0][0]
        return original_attestor(function)

    namespace._verified_source = source_view
    namespace._trusted_definition = trusted_definition
    try:
        namespace.install()
    except BaseException:
        sys.modules.pop(_PRIVATE_NAME, None)
        raise
    return namespace
