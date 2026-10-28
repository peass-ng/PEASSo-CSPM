"""Finite public RawV2 source successor for early selected AWS/Azure admissions."""
import ast
import hashlib
import importlib
import inspect
import json
import marshal
from pathlib import Path
import re
import sys
import types

from peaso import secret_scanning as _scanner
_SCANNER_CLASS = _scanner._DetectorMatches
_KINGFISHER_WRAPPER = _scanner._kingfisher
_TRUFFLEHOG_WRAPPER = _scanner._trufflehog

SCANNER = 'peaso/secret_scanning.py'
SCANNER_BEFORE = '72aaf391e3b168d9b8f7a10603a5763c04137b5e7807fef320b4fc22fa1a9d19'
SCANNER_AFTER = '3897b64c134f88e7ad17c3c1f31df2b5497d34df6c1340d04e536313652f94f6'
RECEIPT = 'peaso/checks/rawv2_public_source_successor_20261021.json'
RECEIPT_SHA256 = '456498168e86c267dff6c4bd0a1a3310ef47306d8eaba1d965a2238353563e6c'
BRIDGE_RECEIPT_SHA256 = '086ee0b691fd95a8ca3e7f4a83d025c167f78cd971a0ad918c395017cc9a16a7'


def _compiled(raw, path):
    # The existing wave cache stores signed immutable compilation artifacts.
    # Every call below still re-reads and hashes its source and live bindings.
    artifacts = sys.modules.get('peaso.gcp_positive_conservation_source_admission_successor_20261020')
    context = getattr(artifacts, '_MODULE_ARTIFACTS', None)
    if context is not None and context.get() is not None:
        return artifacts._compiled_module(Path(path), raw)
    return compile(raw, str(path), 'exec', dont_inherit=True, optimize=sys.flags.optimize)


def _same_code(actual, expected):
    return (type(actual) is types.CodeType and type(expected) is types.CodeType
            and marshal.dumps(actual, 2) == marshal.dumps(expected, 2))


def _digest(raw):
    return hashlib.sha256(raw).hexdigest()


def _root(root=None):
    return Path(root or Path(__file__).resolve().parents[1]).resolve()


def _receipt(root):
    root = _root(root)
    raw = (root / RECEIPT).read_bytes()
    if _digest(raw) != RECEIPT_SHA256:
        raise RuntimeError('RawV2 successor receipt changed')
    receipt = json.loads(raw)
    path = (root / 'peaso/rawv2_public_source_successor_20261021.py').resolve()
    if not path.is_relative_to(root / 'peaso') or Path(__file__).resolve() != path:
        raise RuntimeError('RawV2 successor helper path changed')
    source = path.read_bytes()
    normalized, count = re.subn(
        rb"(?m)^(RECEIPT_SHA256|BRIDGE_RECEIPT_SHA256) = '[0-9a-f]{64}'$",
        lambda match: match.group(1) + b" = '" + b'0' * 64 + b"'", source)
    if count != 2 or _digest(normalized) != receipt['helper_source_sha256']:
        raise RuntimeError('RawV2 successor helper source changed')
    module = sys.modules.get(__name__)
    if module is None or vars(module) is not globals():
        raise RuntimeError('RawV2 successor helper module changed')
    compiled = _codes(_compiled(source, __file__))
    functions = {name: value for name, value in globals().items()
                 if inspect.isfunction(value) and value.__module__ == __name__}
    if set(functions) != set(receipt['helper_functions']):
        raise RuntimeError('RawV2 successor helper callable roster changed')
    for name, function in functions.items():
        row = receipt['helper_bindings'][name]
        if (function.__globals__ is not globals() or function.__qualname__ != name
                or function.__closure__ is not None or inspect.unwrap(function) is not function
                or not _same_code(function.__code__, compiled.get(name))
                or repr(function.__defaults__) != row['defaults']
                or repr(function.__kwdefaults__) != row['kwdefaults']):
            raise RuntimeError('RawV2 successor helper callable changed: ' + name)
    return receipt


def _function_sources(raw):
    text = raw.decode('utf-8')
    lines = text.splitlines(keepends=True)
    tree = ast.parse(text)
    found = {}
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            start = min((decorator.lineno for decorator in node.decorator_list), default=node.lineno)
            found[node.name] = ''.join(lines[start - 1:node.end_lineno]).encode()
        elif isinstance(node, ast.ClassDef):
            found[node.name] = ''.join(lines[node.lineno - 1:node.end_lineno]).encode()
            for method in node.body:
                if isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    found[node.name + '.' + method.name] = ''.join(lines[method.lineno - 1:method.end_lineno]).encode()
    return found


def _codes(code):
    result = {}
    def walk(value):
        for child in value.co_consts:
            if isinstance(child, types.CodeType):
                result[child.co_qualname] = child
                walk(child)
    walk(code)
    return result


def _scanner_function(module, name):
    value = vars(module).get(name.split('.')[0])
    for part in name.split('.')[1:]:
        value = vars(value).get(part)
    return value


def verify_scanner(root=None):
    root = _root(root)
    return _verify_scanner(root, _receipt(root))


def _verify_scanner(root, receipt):
    if receipt['scanner'] != SCANNER or receipt['before_sha256'] != SCANNER_BEFORE or receipt['after_sha256'] != SCANNER_AFTER:
        raise RuntimeError('RawV2 scanner source relation changed')
    path = (root / SCANNER).resolve()
    if not path.is_relative_to(root / 'peaso'):
        raise RuntimeError('RawV2 scanner escaped package')
    current = path.read_bytes()
    if _digest(current) != SCANNER_AFTER:
        raise RuntimeError('RawV2 scanner current source changed')
    old = current
    for edit in reversed(receipt['edits']):
        before, after = edit['before'].encode(), edit['after'].encode()
        if old.count(after) != 1:
            raise RuntimeError('RawV2 scanner literal delta changed')
        old = old.replace(after, before, 1)
    if _digest(old) != SCANNER_BEFORE:
        raise RuntimeError('RawV2 scanner predecessor changed')
    # The sealed before/after file hashes above and pinned receipt bind these
    # reviewed source fragments. Live code/default/global/roster proof follows
    # on every invocation; no successful verification result is memoized.
    module = importlib.import_module('peaso.secret_scanning')
    if sys.modules.get(module.__name__) is not module or Path(module.__file__).resolve() != path:
        raise RuntimeError('RawV2 scanner module changed')
    compiled = _codes(_compiled(current, module.__file__))
    exposed = {name for name, value in vars(module).items() if inspect.isfunction(value) and value.__module__ == module.__name__}
    classes = {name for name, value in vars(module).items() if inspect.isclass(value) and value.__module__ == module.__name__}
    if (exposed != set(receipt['top_functions']) or classes != set(receipt['classes'])
            or module._DetectorMatches is not _SCANNER_CLASS
            or module._DetectorMatches.__bases__ != (list,)
            or module._DetectorMatches.__module__ != module.__name__
            or module._DetectorMatches.__qualname__ != '_DetectorMatches'
            or set(vars(module._DetectorMatches)) - {'__firstlineno__', '__static_attributes__'} != set(receipt['detector_class_keys'])):
        raise RuntimeError('RawV2 scanner exposed roster changed')
    namespace = vars(module._DetectorMatches)
    if ('__firstlineno__' in namespace and (type(namespace['__firstlineno__']) is not int
            or namespace['__firstlineno__'] != receipt['detector_class_lineno'])
            or '__static_attributes__' in namespace and (type(namespace['__static_attributes__']) is not tuple
                or namespace['__static_attributes__'] != tuple(receipt['detector_class_static_attributes']))):
        raise RuntimeError('RawV2 scanner class metadata changed')
    for name in receipt['live_functions']:
        value = _scanner_function(module, name)
        if name in ('_kingfisher', '_trufflehog'):
            value = getattr(value, '__wrapped__', None)
        if not inspect.isfunction(value):
            raise RuntimeError('RawV2 scanner callable changed')
        if value.__globals__ is not vars(module) or value.__module__ != module.__name__ or value.__qualname__ != name:
            raise RuntimeError('RawV2 scanner callable binding changed')
        if not _same_code(value.__code__, compiled.get(name)):
            raise RuntimeError('RawV2 scanner executing code changed')
        if value.__code__.co_freevars:
            if (name != '_DetectorMatches.__init__' or value.__code__.co_freevars != ('__class__',)
                    or value.__closure__ is None or len(value.__closure__) != 1
                    or value.__closure__[0].cell_contents is not module._DetectorMatches):
                raise RuntimeError('RawV2 scanner closure binding changed')
        elif value.__closure__ is not None:
            raise RuntimeError('RawV2 scanner closure binding changed')
        row = receipt['live_functions'][name]
        if repr(value.__defaults__) != row['defaults'] or repr(value.__kwdefaults__) != row['kwdefaults']:
            raise RuntimeError('RawV2 scanner callable defaults changed')
    for name, original in (('_kingfisher', _KINGFISHER_WRAPPER), ('_trufflehog', _TRUFFLEHOG_WRAPPER)):
        wrapper = vars(module)[name]
        if (wrapper is not original or not hasattr(wrapper, '__wrapped__')
                or not _same_code(wrapper.__wrapped__.__code__, compiled[name])
                or wrapper.__wrapped__.__globals__ is not vars(module)
                or wrapper.cache_parameters() != {'maxsize': 1, 'typed': False}):
            raise RuntimeError('RawV2 scanner decorated callable changed')
    return old


def source_bytes(name, raw, expected, root=None):
    """Return exact old scanner bytes only for the one pinned transition."""
    if name == SCANNER:
        if expected != SCANNER_BEFORE or _digest(raw) != SCANNER_AFTER or raw != (_root(root) / SCANNER).read_bytes():
            raise RuntimeError('RawV2 scanner source pin changed')
        return verify_scanner(root)
    if _digest(raw) != expected:
        raise RuntimeError('Immutable source changed: ' + name)
    return raw


def producer_row(fn, row, root=None):
    """Translate only changed scanner function source hashes from old to current."""
    qualified = fn.__module__ + ':' + fn.__qualname__
    if fn.__module__ != 'peaso.secret_scanning':
        return row
    receipt = _receipt(_root(root))
    name = fn.__qualname__
    if name not in receipt['after_functions'] or qualified != 'peaso.secret_scanning:' + name:
        raise RuntimeError('Unknown RawV2 scanner producer')
    old = receipt['before_functions'].get(name)
    if row.get('path') != SCANNER or row.get('sha256') != old or old is None:
        raise RuntimeError('RawV2 scanner historical producer row changed')
    _verify_scanner(_root(root), receipt)
    module = importlib.import_module('peaso.secret_scanning')
    if _scanner_function(module, name) is not fn:
        raise RuntimeError('RawV2 scanner producer identity changed')
    return dict(row, sha256=receipt['after_functions'][name])


def verify_callable_proof(fn, expected, actual, root=None):
    """Accept only the scanner's exact old to current callable descriptor."""
    if not isinstance(expected, dict) or not isinstance(actual, dict) or set(actual) != set(expected):
        raise RuntimeError('RawV2 callable proof shape changed')
    if fn.__module__ != 'peaso.secret_scanning':
        if actual != expected:
            raise RuntimeError('Unchanged callable proof changed')
        return True
    root = _root(root)
    receipt = _receipt(root)
    name = fn.__qualname__
    if (name not in receipt['before_functions'] or name not in receipt['after_functions']
            or expected.get('module') != 'peaso.secret_scanning' or expected.get('qualname') != name
            or expected.get('sha256') != receipt['before_functions'][name]):
        raise RuntimeError('Unknown RawV2 historical callable proof')
    if 'path' in expected and expected['path'] != SCANNER:
        raise RuntimeError('RawV2 historical callable path changed')
    if 'module_sha256' in expected and expected['module_sha256'] != SCANNER_BEFORE:
        raise RuntimeError('RawV2 historical module proof changed')
    _verify_scanner(_root(root), receipt)
    module = importlib.import_module('peaso.secret_scanning')
    if _scanner_function(module, name) is not fn:
        raise RuntimeError('RawV2 callable proof identity changed')
    allowed = dict(expected, sha256=receipt['after_functions'][name])
    if 'module_sha256' in allowed:
        allowed['module_sha256'] = SCANNER_AFTER
    if actual != allowed:
        raise RuntimeError('RawV2 current callable proof changed')
    return True


def _selected_source(name, expected, root):
    path = (root / name).resolve()
    if not path.is_relative_to(root):
        raise RuntimeError('Selected source escaped root')
    source_bytes(name, path.read_bytes(), expected, root)


def _admitted_source_digest(name, path, expected, root):
    if not path.is_relative_to(root):
        raise RuntimeError('Selected source escaped root')
    return _digest(source_bytes(name, path.read_bytes(), expected, root))


def _verify_guard(module, root):
    receipt = _receipt(root)
    name = module.__name__.replace('.', '/') + '.py'
    row = receipt['guards'].get(name)
    if row is None or Path(module.__file__).resolve() != (root / name).resolve():
        raise RuntimeError('Selected guard identity changed')
    source = (root / name).read_bytes()
    if _digest(source) != row['source_sha256']:
        raise RuntimeError('Selected guard source changed')
    old_receipt = (root / row['receipt']).read_bytes()
    if _digest(old_receipt) != row['receipt_sha256']:
        raise RuntimeError('Selected guard receipt changed')
    compiled = _codes(_compiled(source, module.__file__))
    actual_functions = {name for name, fn in vars(module).items()
                        if inspect.isfunction(fn) and fn.__globals__ is vars(module)}
    if actual_functions != set(row['function_bindings']):
        raise RuntimeError('Selected guard callable roster changed')
    for function_name in row['function_bindings']:
        function = vars(module).get(function_name)
        if (not inspect.isfunction(function) or function.__globals__ is not vars(module)
                or function.__module__ != module.__name__
                or not _same_code(function.__code__, compiled.get(function_name))
                or function.__closure__ is not None
                or repr(function.__defaults__) != row['function_bindings'][function_name]['defaults']
                or repr(function.__kwdefaults__) != row['function_bindings'][function_name]['kwdefaults']):
            raise RuntimeError('Selected guard callable changed')


def _aws_reviewed_inputs():
    from peaso.checks import aws_selected_configuration_admission_20261020 as original
    root = _root()
    _verify_guard(original, root)
    receipt = json.loads((root / 'peaso/checks/aws_selected_configuration_secret_review_20261020_admission.json').read_bytes())
    for name, digest in receipt['source_hashes'].items():
        _selected_source(name, digest, root)
    fixture = receipt['fixture']
    path = (root / fixture['path']).resolve()
    if not path.is_relative_to(root) or _digest(path.read_bytes()) != fixture['sha256']:
        raise RuntimeError('Selected AWS content native fixtures changed')
    from peaso.checks.aws_selected_configuration_secret_review_20261020 import CHECK, evaluate
    cases = json.loads(path.read_text())
    if set(cases) != {CHECK} or not {'pass', 'fail', 'unknown', 'pass_index', 'fail_index', 'unknown_index'} <= set(cases[CHECK]):
        raise RuntimeError('Selected AWS content native branches missing')
    for branch in ('pass', 'fail', 'unknown'):
        if evaluate(cases[CHECK][branch], cases[CHECK][branch + '_index'])[0] != branch.upper():
            raise RuntimeError('Selected AWS content native branch changed')
    return cases


def _azure_reviewed_inputs(root=None):
    from peaso.checks import azure_selected_secrets_admission_20261020 as original
    root = _root(root)
    _verify_guard(original, root)
    raw = (root / 'peaso/checks/azure_selected_secrets_admission_20261020.json').read_bytes()
    if _digest(raw) != original.RECEIPT_SHA256:
        raise RuntimeError('Selected Azure admission receipt changed')
    receipt = json.loads(raw)
    if receipt.get('schema_version') != 1 or tuple(row['module'] for row in receipt['checks']) != original.MODULES:
        raise RuntimeError('Selected Azure admission declarations changed')
    for name, digest in receipt['sources'].items():
        _selected_source(name, digest, root)
    fixture = receipt['fixture']
    path = (root / fixture['path']).resolve()
    if not path.is_relative_to(root / 'peaso/checks') or _digest(path.read_bytes()) != fixture['sha256']:
        raise RuntimeError('Selected Azure native fixture changed')
    cases = json.loads(path.read_text()); declarations = []
    if set(cases) != {row['declaration']['id'] for row in receipt['checks']}:
        raise RuntimeError('Selected Azure native fixture identities changed')
    for row in receipt['checks']:
        module = importlib.import_module('peaso.checks.' + row['module'])
        function = module.evaluate; metadata = module.DECLARATIONS[0]
        if (function is not inspect.unwrap(function) or metadata != row['declaration']
                or _digest(inspect.getsource(function).encode()) != row['predicate_sha256']):
            raise RuntimeError('Selected Azure evaluator changed')
        case = cases[metadata['id']]
        if not {'pass', 'pass_index', 'fail', 'fail_index', 'unknown', 'unknown_index', 'missing', 'malformed', 'index'} <= set(case):
            raise RuntimeError('Selected Azure native branches missing')
        for branch in ('pass', 'fail', 'unknown'):
            if function(case[branch], case[branch + '_index'])[0] != branch.upper():
                raise RuntimeError('Selected Azure native branch changed')
        for branch in ('missing', 'malformed'):
            if function(case[branch], case['index'])[0] != 'UNKNOWN':
                raise RuntimeError('Selected Azure malformed native branch changed')
        declarations.append((metadata, function))
    return receipt, cases, declarations


def _clone_install(module, reviewed):
    namespace = dict(vars(module), reviewed_inputs=reviewed)
    original = module.install
    if original.__closure__:
        raise RuntimeError('Selected installer closure changed')
    clone = types.FunctionType(original.__code__, namespace, original.__name__, original.__defaults__)
    clone.__kwdefaults__ = original.__kwdefaults__
    return clone()


def _with_artifacts(function, *args):
    """Bound immutable compilation artifacts to this one installer call."""
    from peaso import gcp_positive_conservation_source_admission_successor_20261020 as artifacts
    root = _root()
    context = artifacts._MODULE_ARTIFACTS
    if context is not artifacts._MODULE_CONTEXT:
        raise RuntimeError('RawV2 module artifact context changed')
    # Bootstrap the provider afresh before trusting its signed artifact factory.
    # No successful source, receipt, callable or evaluator verdict is retained.
    path = root / 'peaso/gcp_positive_conservation_source_admission_successor_20261020.py'
    raw = path.read_bytes()
    bridge = (root / 'peaso/checks/gcp_positive_conservation_source_bridge_20261020.json').read_bytes()
    if _digest(bridge) != BRIDGE_RECEIPT_SHA256:
        raise RuntimeError('RawV2 artifact bridge changed')
    normalized, count = re.subn(rb"(?m)^BRIDGE_RECEIPT_SHA256 = '[0-9a-f]{64}'$",
        b"BRIDGE_RECEIPT_SHA256 = '" + b'0' * 64 + b"'", raw)
    if (count != 1 or _digest(normalized) != json.loads(bridge)['normalized_sources'][str(path.relative_to(root))]
            or Path(artifacts.__file__).resolve() != path
            or sys.modules.get(artifacts.__name__) is not artifacts):
        raise RuntimeError('RawV2 artifact provider source changed')
    compiled = _codes(compile(raw, str(path), 'exec', optimize=sys.flags.optimize))
    for name in ('_module_compiler', '_compiled_module'):
        value = vars(artifacts)[name]
        if (not inspect.isfunction(value) or value.__globals__ is not vars(artifacts)
                or value.__module__ != artifacts.__name__ or value.__qualname__ != name
                or not _same_code(value.__code__, compiled[name]) or value.__closure__ is not None
                or value.__defaults__ is not None or value.__kwdefaults__ is not None):
            raise RuntimeError('RawV2 artifact provider callable changed')
    _receipt(root)
    if context.get() is not None:
        return function(*args)
    token = context.set(artifacts._module_compiler())
    try:
        return function(*args)
    finally:
        context.reset(token)


def install_selected_aws():
    return _with_artifacts(_install_selected_aws)


def _install_selected_aws():
    from peaso.checks import aws_selected_configuration_admission_20261020 as original
    verify_scanner()
    _verify_guard(original, _root())
    return _clone_install(original, _aws_reviewed_inputs)


def install_selected_azure():
    return _with_artifacts(_install_selected_azure)


def _install_selected_azure():
    from peaso.checks import azure_selected_secrets_admission_20261020 as original
    verify_scanner()
    _verify_guard(original, _root())
    return _clone_install(original, _azure_reviewed_inputs)


_LATER_ADMISSIONS = (
    'gcp_workbench_source_runtime_admission_20261020',
    'gcp_dataproc_source_runtime_admission_20261020',
    'azure_declaration_secrets_admission_20261020',
    'azure_log_samples_admission_20261020',
    'azure_ml_job_secrets_admission_20261020',
    'azure_databricks_notebook_secrets_admission_20261020',
    'azure_ml_asset_secrets_admission_20261020',
    'azure_function_settings_runtime_admission_20261020',
)


def _validate_dataproc_proposal():
    from copy import deepcopy
    from peaso.checks import gcp_dataproc_referenced_source_proposal_20261020 as proposal
    root = _root()
    row = _receipt(root)['dataproc_proposal']
    path = (root / row['path']).resolve()
    source = path.read_bytes()
    if path != Path(proposal.__file__).resolve() or _digest(source) != row['source_sha256']:
        raise RuntimeError('Dataproc proposal source changed')
    function = proposal.validate_proposal
    code = _codes(_compiled(source, path))['validate_proposal']
    if (not inspect.isfunction(function) or function.__globals__ is not vars(proposal)
            or not _same_code(function.__code__, code) or function.__closure__ is not None
            or function.__defaults__ is not None or function.__kwdefaults__ is not None):
        raise RuntimeError('Dataproc proposal callable changed')
    receipt_path = root / row['receipt']
    if _digest(receipt_path.read_bytes()) != row['receipt_sha256']:
        raise RuntimeError('Dataproc proposal receipt changed')
    data = json.loads(receipt_path.read_bytes())
    if data.get('registration') != 'unregistered_proposal_only':
        raise ValueError('proposal status')
    for relative, expected in data['files'].items():
        _selected_source(relative, expected, root)
    for qualified, expected in data['dependencies'].items():
        module, name = qualified.split(':')
        bound = getattr(importlib.import_module(module), name)
        fn = inspect.unwrap(bound)
        if module == 'peaso.secret_scanning':
            expected = producer_row(bound, {'path': SCANNER, 'sha256': expected}, root)['sha256']
        if _digest(inspect.getsource(fn).encode()) != expected:
            raise ValueError('proposal dependency changed: ' + qualified)
    return deepcopy(data)


def install_admission(name):
    return _with_artifacts(_install_admission, name)


def _install_admission(name):
    """Run one immutable later installer with a finite local source view."""
    if name not in _LATER_ADMISSIONS:
        raise RuntimeError('Unreviewed RawV2 admission')
    root = _root()
    verify_scanner(root)
    module = importlib.import_module('peaso.checks.' + name)
    _verify_guard(module, root)
    row = _receipt(root)['clones'][name]
    source = inspect.getsource(module.reviewed_inputs)
    if _digest(source.encode()) != row['before_sha256']:
        raise RuntimeError('Selected admission predecessor body changed')
    variants = {
        'hashlib.sha256(path.read_bytes()).hexdigest() != digest':
            '_admitted_source_digest(name, path, digest, root) != digest',
        'hashlib.sha256(path.read_bytes()).hexdigest()!=digest':
            '_admitted_source_digest(name,path,digest,root)!=digest',
    }
    old, new = row['before'], row['after']
    if variants.get(old) != new or source.count(old) != 1:
        raise RuntimeError('Selected admission finite source delta changed')
    transformed = source.replace(old, new, 1)
    if name == 'gcp_dataproc_source_runtime_admission_20261020':
        import_line = '    from .gcp_dataproc_referenced_source_proposal_20261020 import validate_proposal\n'
        if transformed.count(import_line) != 1 or transformed.count('    validate_proposal()\n') != 1:
            raise RuntimeError('Dataproc finite proposal entrypoint changed')
        transformed = transformed.replace(import_line, '', 1).replace(
            '    validate_proposal()\n', '    _validate_dataproc_proposal()\n', 1)
    if _digest(transformed.encode()) != row['after_sha256']:
        raise RuntimeError('Selected admission successor body changed')
    namespace = dict(vars(module), _admitted_source_digest=_admitted_source_digest,
                     _validate_dataproc_proposal=_validate_dataproc_proposal)
    exec(compile(transformed, str(module.__file__), 'exec'), namespace)
    clone = namespace['reviewed_inputs']
    if clone.__defaults__ != module.reviewed_inputs.__defaults__ or clone.__kwdefaults__ != module.reviewed_inputs.__kwdefaults__:
        raise RuntimeError('Selected admission callable defaults changed')
    return _clone_install(module, clone)
