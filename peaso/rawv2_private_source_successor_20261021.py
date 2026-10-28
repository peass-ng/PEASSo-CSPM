"""Finite private RawV2 successor after the published public scanner epoch."""
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
from peaso import rawv2_public_source_successor_20261021 as _published
from peaso import private_secret_source_epoch_20261021 as _private_epoch
_SCANNER_CLASS = _scanner._DetectorMatches
_KINGFISHER_WRAPPER = _scanner._kingfisher
_TRUFFLEHOG_WRAPPER = _scanner._trufflehog

SCANNER = 'peaso/secret_scanning.py'
PRIVATE_HELPER = 'peaso/secret_evidence.py'
PRIVATE_HELPER_SHA256 = '15092e316c2331e03fdae7fad4dda5ed92310a1c15a827b0009fbcd54a11693a'
SCANNER_BEFORE = '72aaf391e3b168d9b8f7a10603a5763c04137b5e7807fef320b4fc22fa1a9d19'
SCANNER_MIDDLE = '3897b64c134f88e7ad17c3c1f31df2b5497d34df6c1340d04e536313652f94f6'
SCANNER_PERFORMANCE_PREDECESSOR = 'a1c7163c021ac85b945f3b4289a5fa45f4e641bc22e302c51c9014ec7531c322'
SCANNER_AFTER = 'ca58353421e0994bb82c28372a16197f0c0ba0edd7da2638357fc45996adacbd'
RECEIPT = 'peaso/checks/rawv2_private_source_successor_20261021.json'
RECEIPT_SHA256 = 'abc04c21f51d744f0ae86294d40f194ef17e28e6609841d85f577ec1fc0f54cb'
BRIDGE_RECEIPT_SHA256 = '07bcbbab2f541b10e79ed09ff9ae646d8ce80f8f0c35af3fde9c7a3f24f6b259'


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


_RECEIPT_PROVEN = {}


def _receipt(root):
    from peaso.source_attestation_mode import repeat
    root = _root(root)
    proven = _RECEIPT_PROVEN.get(str(root))
    if not repeat(proven):
        return marshal.loads(proven)
    raw = (root / RECEIPT).read_bytes()
    if _digest(raw) != RECEIPT_SHA256:
        raise RuntimeError('RawV2 successor receipt changed')
    receipt = json.loads(raw)
    if receipt['published_receipt_sha256'] != _digest((root / receipt['published_receipt']).read_bytes()):
        raise RuntimeError('Published RawV2 receipt changed')
    published = _published._receipt(root)
    if published['after_sha256'] != SCANNER_MIDDLE or published['before_sha256'] != SCANNER_BEFORE:
        raise RuntimeError('Published RawV2 receipt semantics changed')
    projected = {'schema', 'after_sha256', 'after_functions', 'detector_class_lineno', 'helper_source_sha256', 'helper_functions', 'helper_bindings'}
    if any(receipt.get(name) != value for name, value in published.items() if name not in projected):
        raise RuntimeError('Published RawV2 receipt projection changed')
    if (set(receipt['helper_functions']) != set(published['helper_functions']) | {'_verify_private_helper'}
            or any(receipt['helper_bindings'].get(name) != row for name, row in published['helper_bindings'].items())):
        raise RuntimeError('Published RawV2 helper callable projection changed')
    path = (root / 'peaso/rawv2_private_source_successor_20261021.py').resolve()
    if not path.is_relative_to(root / 'peaso') or Path(__file__).resolve() != path:
        raise RuntimeError('RawV2 successor helper path changed')
    source = path.read_bytes()
    from peaso.checks import private_secret_shared_source_successor_20261021 as current
    current._private_self()
    predecessor = current.rawv2_bootstrap_source(
        source, '3ef9840685cc94829a12c7c54693da901ac6ddb691f493e53290255c5224d940', root)
    normalized, count = re.subn(
        rb"(?m)^(RECEIPT_SHA256|BRIDGE_RECEIPT_SHA256) = '[0-9a-f]{64}'$",
        lambda match: match.group(1) + b" = '" + b'0' * 64 + b"'", predecessor)
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
    _RECEIPT_PROVEN[str(root)] = marshal.dumps(receipt)
    return receipt


def _verify_private_helper(root, receipt):
    """Fresh live proof for the sealed private capture dependency."""
    path = (root / PRIVATE_HELPER).resolve()
    if not path.is_relative_to(root / 'peaso'):
        raise RuntimeError('Private helper escaped package')
    source = path.read_bytes()
    historical_source = _private_epoch.predecessor_bytes(
        PRIVATE_HELPER, source, PRIVATE_HELPER_SHA256, root)
    if (_digest(historical_source) != PRIVATE_HELPER_SHA256
            or receipt['private_helper_source_sha256'] != PRIVATE_HELPER_SHA256):
        raise RuntimeError('Private helper source changed')
    module = importlib.import_module('peaso.secret_evidence')
    if (sys.modules.get(module.__name__) is not module
            or Path(module.__file__).resolve() != path):
        raise RuntimeError('Private helper module changed')
    namespace = vars(module)
    functions = {name: value for name, value in namespace.items()
                 if inspect.isfunction(value) and value.__module__ == module.__name__}
    classes = {name: value for name, value in namespace.items()
               if inspect.isclass(value) and value.__module__ == module.__name__}
    if (set(functions) != set(receipt['private_helper_functions'])
            or set(classes) != set(receipt['private_helper_classes'])):
        raise RuntimeError('Private helper live roster changed')
    compiled = _codes(_compiled(source, module.__file__))
    contextlib = importlib.import_module('contextlib')
    wrapper_codes = [member for member in contextlib.contextmanager.__code__.co_consts
                     if isinstance(member, types.CodeType) and member.co_name == 'helper']
    if len(wrapper_codes) != 1:
        raise RuntimeError('Private helper decorator changed')
    for name, bound in functions.items():
        value = bound
        if name in ('capture', 'source_context'):
            value = getattr(bound, '__wrapped__', None)
            if (not inspect.isfunction(value) or inspect.unwrap(bound) is not value
                    or not _same_code(bound.__code__, wrapper_codes[0])
                    or bound.__globals__ is not contextlib.contextmanager.__globals__
                    or bound.__closure__ is None or len(bound.__closure__) != 1
                    or bound.__closure__[0].cell_contents is not value):
                raise RuntimeError('Private helper decorator binding changed: ' + name)
        elif inspect.unwrap(bound) is not bound:
            raise RuntimeError('Private helper unexpected decorator: ' + name)
        row = receipt['private_helper_functions'][name]
        if (not inspect.isfunction(value) or value.__globals__ is not namespace
                or value.__module__ != module.__name__ or value.__qualname__ != name
                or value.__closure__ is not None
                or not _same_code(value.__code__, compiled.get(name))
                or repr(value.__defaults__) != row['defaults']
                or repr(value.__kwdefaults__) != row['kwdefaults']):
            raise RuntimeError('Private helper live callable changed: ' + name)
    for name, cls in classes.items():
        row = receipt['private_helper_classes'][name]
        members = vars(cls)
        optional = {'__firstlineno__', '__static_attributes__'}
        expected = {'__module__', '__doc__', '__dict__', '__weakref__'} | set(row['methods'])
        if (type(cls) is not type or cls.__bases__ != (object,)
                or cls.__module__ != module.__name__ or cls.__qualname__ != name
                or set(members) - optional != expected):
            raise RuntimeError('Private helper live class changed: ' + name)
        # The finite predecessor proof above admits the exact current helper.
        # Keep the historical receipt line while checking current class layout.
        class_code = compiled.get(name)
        if ('__firstlineno__' in members and
                (type(members['__firstlineno__']) is not int
                 or not isinstance(class_code, types.CodeType)
                 or members['__firstlineno__'] != class_code.co_firstlineno)):
            raise RuntimeError('Private helper class line changed: ' + name)
        if ('__static_attributes__' in members and
                (type(members['__static_attributes__']) is not tuple
                 or members['__static_attributes__'] != tuple(row['static_attributes']))):
            raise RuntimeError('Private helper class attributes changed: ' + name)
        for method_name, proof in row['methods'].items():
            value = members[method_name]
            if (not inspect.isfunction(value) or value.__globals__ is not namespace
                    or value.__module__ != module.__name__
                    or value.__qualname__ != name + '.' + method_name
                    or value.__closure__ is not None
                    or not _same_code(value.__code__, compiled.get(name + '.' + method_name))
                    or repr(value.__defaults__) != proof['defaults']
                    or repr(value.__kwdefaults__) != proof['kwdefaults']):
                raise RuntimeError('Private helper live method changed: ' + name + '.' + method_name)
    # The redactor is a second exact reviewed dependency of this helper.
    auth_path = root / 'peaso/auth/secrets.py'
    auth_source = auth_path.read_bytes()
    auth_before = _private_epoch.predecessor_bytes(
        'peaso/auth/secrets.py', auth_source,
        'fef5439e9a3aa359f61ecdc8685428c2ffe72ee902f4002946a98901f796060b', root)
    if _digest(auth_before) != 'fef5439e9a3aa359f61ecdc8685428c2ffe72ee902f4002946a98901f796060b':
        raise RuntimeError('Private redactor predecessor changed')
    auth = importlib.import_module('peaso.auth.secrets')
    if (sys.modules.get(auth.__name__) is not auth
            or Path(auth.__file__).resolve() != auth_path):
        raise RuntimeError('Private redactor module changed')
    auth_codes = _codes(_compiled(auth_source, auth_path))
    for name in ('_literal_matcher', 'redact', 'Redactor.__init__', 'Redactor.__call__'):
        value = vars(auth).get(name.split('.')[0])
        for part in name.split('.')[1:]:
            value = vars(value).get(part)
        if (not inspect.isfunction(value)
                or value.__module__ != auth.__name__
                or value.__globals__ is not vars(auth)
                or not _same_code(value.__code__, auth_codes.get(name))):
            raise RuntimeError('Private redactor live callable changed: ' + name)
    return True


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
    if (receipt['scanner'] != SCANNER or receipt['before_sha256'] != SCANNER_BEFORE
            or receipt['middle_sha256'] != SCANNER_MIDDLE or receipt['after_sha256'] != SCANNER_AFTER):
        raise RuntimeError('RawV2 scanner source relation changed')
    path = (root / SCANNER).resolve()
    if not path.is_relative_to(root / 'peaso'):
        raise RuntimeError('RawV2 scanner escaped package')
    current = path.read_bytes()
    if _digest(current) != SCANNER_AFTER:
        raise RuntimeError('RawV2 scanner current source changed')
    # One exact current successor precedes the unchanged retained private edits.
    transition = receipt['current_scanner_transition']
    if (transition['current_sha256'] != SCANNER_AFTER
            or transition['predecessor_sha256'] != 'bb45ff48726fd209bcb4201a9951a1b6d0d931cdf72aa8cb794dc9ebc0b92ec9'):
        raise RuntimeError('RawV2 adaptive scanner relation changed')
    old = current
    for before, after in transition['exact_replacements']:
        before, after = before.encode(), after.encode()
        if old.count(after) != 1:
            raise RuntimeError('RawV2 adaptive scanner exact inverse changed')
        old = old.replace(after, before, 1)
    for addition in transition['exact_additions']:
        addition = addition.encode()
        if old.count(addition) != 1:
            raise RuntimeError('RawV2 adaptive scanner addition changed')
        old = old.replace(addition, b'', 1)
    if _digest(old) != transition['predecessor_sha256']:
        raise RuntimeError('RawV2 adaptive scanner predecessor changed')
    if (receipt['performance_predecessor_sha256'] != SCANNER_PERFORMANCE_PREDECESSOR
            or receipt['performance_private_edit_count'] != 1):
        raise RuntimeError('RawV2 performance predecessor relation changed')
    performance = receipt['private_edits'][-1]
    if (performance['after'].encode() != old
            or _digest(performance['before'].encode()) != SCANNER_PERFORMANCE_PREDECESSOR):
        raise RuntimeError('RawV2 performance exact predecessor changed')
    for edit in reversed(receipt['private_edits']):
        before, after = edit['before'].encode(), edit['after'].encode()
        if old.count(after) != 1:
            raise RuntimeError('Private RawV2 scanner literal delta changed')
        old = old.replace(after, before, 1)
    if _digest(old) != SCANNER_MIDDLE:
        raise RuntimeError('Private RawV2 scanner predecessor changed')
    if _private_epoch.predecessor_bytes(SCANNER, current, SCANNER_MIDDLE, root) != old:
        raise RuntimeError('Private RawV2 manifest predecessor changed')
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
    _verify_private_helper(root, receipt)
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
        if expected not in (SCANNER_BEFORE, SCANNER_MIDDLE) or _digest(raw) != SCANNER_AFTER or raw != (_root(root) / SCANNER).read_bytes():
            raise RuntimeError('RawV2 scanner source pin changed')
        historical = verify_scanner(root)
        if expected == SCANNER_BEFORE:
            return historical
        return _private_epoch.predecessor_bytes(SCANNER, raw, SCANNER_MIDDLE, _root(root))
    if _digest(raw) == expected:
        return raw
    if (name == 'peaso/collectors/aws_package_content_indicators.py'
            and expected == 'ce459d4b5ed0ae991591f09f61b462f7841f0977d5935579e561409c0117e7e6'):
        from peaso.checks import private_secret_shared_source_successor_20261021 as current
        current._private_self()
        return current.rawv2_package_source(raw, expected, _root(root))
    if (name == 'peaso/collectors/azure_selected_storage_secret_indicators.py'
            and expected == '59db1280c49909db57368b7e4e61e846f5f2c8ee1b323c6b2204f2110646beda'):
        from peaso import private_reviewed_collector_successor_20261022 as reviewed
        return reviewed.predecessor_bytes(name, raw, expected, _root(root))
    return _private_epoch.predecessor_bytes(name, raw, expected, _root(root))


def producer_row(fn, row, root=None):
    """Translate only changed scanner function source hashes from old to current."""
    qualified = fn.__module__ + ':' + fn.__qualname__
    if fn.__module__ != 'peaso.secret_scanning':
        if fn.__module__ + ':' + fn.__qualname__ not in _receipt(_root(root))['private_definitions']:
            return row
        return _private_epoch.callable_projection(fn, row, _root(root))
    receipt = _receipt(_root(root))
    name = fn.__qualname__
    if name not in receipt['after_functions'] or qualified != 'peaso.secret_scanning:' + name:
        raise RuntimeError('Unknown RawV2 scanner producer')
    old = receipt['before_functions'].get(name)
    middle = receipt['middle_functions'].get(name)
    if row.get('path') != SCANNER or row.get('sha256') not in (old, middle) or row.get('sha256') is None:
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
        if fn.__module__ + ':' + fn.__qualname__ in _receipt(_root(root))['private_definitions']:
            if actual != _private_epoch.callable_projection(fn, expected, _root(root)):
                raise RuntimeError('Private current callable proof changed')
            return True
        if actual != expected:
            raise RuntimeError('Unchanged callable proof changed')
        return True
    root = _root(root)
    receipt = _receipt(root)
    name = fn.__qualname__
    if (name not in receipt['after_functions']
            or expected.get('module') != 'peaso.secret_scanning' or expected.get('qualname') != name
            or expected.get('sha256') not in (receipt['before_functions'].get(name), receipt['middle_functions'].get(name))
            or expected.get('sha256') is None):
        raise RuntimeError('Unknown RawV2 historical callable proof')
    if 'path' in expected and expected['path'] != SCANNER:
        raise RuntimeError('RawV2 historical callable path changed')
    if 'module_sha256' in expected:
        allowed_epoch = set()
        if expected['sha256'] == receipt['before_functions'].get(name):
            allowed_epoch.add(SCANNER_BEFORE)
        if expected['sha256'] == receipt['middle_functions'].get(name):
            allowed_epoch.add(SCANNER_MIDDLE)
        if expected['module_sha256'] not in allowed_epoch:
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
    code = _codes(_compiled(source, proposal.__file__))['validate_proposal']
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
        if qualified in _receipt(root)['private_definitions']:
            proof = _private_epoch.trusted_definition(bound, root)
            if proof['historical']['source_sha256'] != expected:
                raise ValueError('proposal dependency predecessor changed: ' + qualified)
            expected = proof['current']['source_sha256']
        if _digest(inspect.getsource(fn).encode()) != expected:
            raise ValueError('proposal dependency changed: ' + qualified)
    return deepcopy(data)


def install_admission(name):
    if name not in {
            'azure_function_settings_admission_20261020',
            'azure_apim_operation_window_admission_20261020'}:
        return _with_artifacts(_install_admission, name)

    def verify_proposal():
        """Bind the old proposal rows to their exact current source epoch."""
        root = _root()
        _receipt(root)
        kind = ('function' if name == 'azure_function_settings_admission_20261020'
                else 'apim')
        raw = (root / 'peaso/checks' / (name + '.json')).read_bytes()
        receipt = json.loads(raw)
        if kind == 'function':
            if receipt.get('schema') != 'azure-selected-function-source-receipt-v1' or receipt.get('registered') is not False:
                raise ValueError('function_proposal_source_mismatch')
            file_rows = receipt['new_modules'] + [receipt['native_cases'], receipt['descriptions']]
        else:
            if (receipt.get('schema') != 'azure-apim-operation-window-source-v1'
                    or receipt.get('registered') is not False or receipt.get('research_only') is not True
                    or receipt.get('admission_recommended') is not False):
                raise ValueError('apim_proposal_source_mismatch')
            file_rows = receipt['modules'] + [receipt['native_cases'], receipt['descriptions']]
        for row in file_rows:
            path = (root / row['path']).resolve()
            if (not path.is_relative_to(root)
                    or _digest(source_bytes(row['path'], path.read_bytes(), row['sha256'], root)) != row['sha256']):
                raise ValueError(kind + '_proposal_source_mismatch')
        changed = {
            ('peaso/collectors/azure_selected_secret_integration_20261020.py', 'final_snapshot'),
            ('peaso/collectors/azure_function_settings_declarations_20261020.py', 'collect_proposal'),
            ('peaso/collectors/azure_apim_operation_window_20261020.py', 'collect_proposal'),
        }
        for row in receipt['callables']:
            value = importlib.import_module(row['module'])
            for part in row['qualname'].split('.'):
                value = getattr(value, part)
            value = inspect.unwrap(value)
            if str(Path(inspect.getsourcefile(value)).resolve().relative_to(root)) != row['path']:
                raise ValueError(kind + '_proposal_source_mismatch')
            digest = _digest(inspect.getsource(value).encode())
            if digest == row['sha256']:
                continue
            key = (row['path'], row['qualname'])
            if key in changed:
                from peaso.checks import private_secret_shared_source_successor_20261021 as shared
                shared._check_function(value, dict(row, defaults=None,
                    kwdefaults={'credential': None} if row['qualname'] == 'collect_proposal' else None), root, {})
            if key == ('peaso/collectors/azure_selected_secret_integration_20261020.py', 'final_snapshot'):
                owner = importlib.import_module(value.__module__)
                expected = {
                    'arm': 'peaso.collectors.azure_selected_configuration_secret_indicators',
                    'storage': 'peaso.collectors.azure_selected_storage_secret_indicators',
                    'devops': 'peaso.collectors.azure_devops_selected_content_secret_indicators',
                }
                if (owner.final_snapshot is not value or owner.MAX_UNION_VALUES != 5000
                        or any(vars(owner).get(binding) is not importlib.import_module(module)
                               for binding, module in expected.items())):
                    raise ValueError(kind + '_proposal_source_mismatch')
            elif key not in changed:
                raise ValueError(kind + '_proposal_source_mismatch')
        return receipt

    return _with_artifacts(verify_proposal)


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
    if name == 'azure_function_settings_runtime_admission_20261020':
        old = '    predecessor.validate_proposal()\n'
        if transformed.count(old) != 1:
            raise RuntimeError('Function proposal entrypoint changed')
        transformed = transformed.replace(old, '    _validate_function_proposal(root)\n', 1)
    if name in {
            'azure_databricks_notebook_secrets_admission_20261020',
            'azure_ml_job_secrets_admission_20261020',
            'azure_ml_asset_secrets_admission_20261020',
            'gcp_dataproc_source_runtime_admission_20261020'}:
        old = "hashlib.sha256(inspect.getsource(module._evaluate).encode()).hexdigest() != row['reachable_helper_sha256']"
        new = "_admitted_callable_digest(module._evaluate, row['reachable_helper_sha256'], root) != row['reachable_helper_sha256']"
        if transformed.count(old) != 1:
            raise RuntimeError('Selected admission helper proof changed')
        transformed = transformed.replace(old, new, 1)
    if name in {
            'azure_databricks_notebook_secrets_admission_20261020',
            'azure_ml_job_secrets_admission_20261020',
            'azure_ml_asset_secrets_admission_20261020',
            'gcp_dataproc_source_runtime_admission_20261020'}:
        old = 'any(metadata.get(key) != row.get(key) for key in metadata)'
        new = '_admitted_metadata(metadata, row, root)'
        if transformed.count(old) != 1:
            raise RuntimeError('Selected admission metadata proof changed')
        transformed = transformed.replace(old, new, 1)
    if name == 'azure_ml_job_secrets_admission_20261020':
        old = "function(case[branch], case[branch + '_index'])[0]"
        new = "_historical_ml_fixture_branch(function, case[branch], case[branch + '_index'], root)[0]"
        if transformed.count(old) != 1:
            raise RuntimeError('Selected ML historical branch proof changed')
        transformed = transformed.replace(old, new, 1)
        old = "function(case[branch], case['index'])[0]"
        new = "_historical_ml_fixture_branch(function, case[branch], case['index'], root)[0]"
        if transformed.count(old) != 1:
            raise RuntimeError('Selected ML historical malformed proof changed')
        transformed = transformed.replace(old, new, 1)
    def _admitted_callable_digest(fn, historical_sha256, root):
        """Prove a reviewed current helper and its unchanged historical source."""
        root = _root(root)
        name = fn.__module__.replace('.', '/') + '.py'
        path = root / name
        current = path.read_bytes()
        receipt, _ = _private_epoch._receipt()
        transition = receipt['current_reviewed_files'].get(name)
        if transition is None:
            raise RuntimeError('Unreviewed current helper')
        before = _private_epoch.predecessor_bytes(
            name, current, transition['predecessor_sha256'], root)
        def definition(raw):
            matches = [node for node in ast.parse(raw).body
                       if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                       and node.name == fn.__name__]
            if len(matches) != 1:
                raise RuntimeError('Reviewed helper definition changed')
            node, = matches
            return b''.join(raw.splitlines(keepends=True)[
                min([node.lineno] + [item.lineno for item in node.decorator_list]) - 1:node.end_lineno])
        source = definition(current)
        compiled = _codes(_compiled(current, str(path)))
        if (fn.__module__ != name.removesuffix('.py').replace('/', '.')
                or _digest(definition(before)) != historical_sha256
                or inspect.getsource(fn).encode() != source
                or not _same_code(fn.__code__, compiled.get(fn.__name__))):
            raise RuntimeError('Reviewed current helper changed')
        return historical_sha256

    def _admitted_metadata(metadata, row, root):
        receipt, _ = _private_epoch._receipt()
        current = receipt['current_reviewed_metadata'].get(name)
        if current is None:
            raise RuntimeError('Unreviewed current metadata')
        path = current['path']
        transition = receipt['current_reviewed_files'][path]
        _private_epoch.predecessor_bytes(
            path, (_root(root) / path).read_bytes(), transition['predecessor_sha256'], root)
        for key in metadata:
            expected = row.get(key)
            overrides = current.get('overrides', {}) | current.get('overrides_by_id', {}).get(row['id'], {})
            if key in overrides:
                before, after = overrides[key]
                if expected != before:
                    raise RuntimeError('Reviewed metadata predecessor changed')
                expected = after
            if metadata[key] != expected:
                return True
        return False

    def _validate_function_proposal(root):
        """Keep the signed proposal roster with one reviewed current callable."""
        receipt_path = _root(root) / 'peaso/checks/azure_function_settings_admission_20261020.json'
        data = json.loads(receipt_path.read_bytes())
        if data.get('schema') != 'azure-selected-function-source-receipt-v1' or data.get('registered') is not False:
            raise RuntimeError('Function proposal receipt changed')
        for item in data['new_modules']:
            path = (_root(root) / item['path']).resolve()
            if (not path.is_relative_to(_root(root))
                    or _digest(source_bytes(item['path'], path.read_bytes(), item['sha256'], root)) != item['sha256']):
                raise RuntimeError('Function proposal module changed')
        for item in data['callables']:
            value = importlib.import_module(item['module'])
            for part in item['qualname'].split('.'):
                value = getattr(value, part)
            value = inspect.unwrap(value)
            if (str(Path(inspect.getsourcefile(value)).relative_to(_root(root))) != item['path']):
                raise RuntimeError('Function proposal callable location changed')
            if (item['path'], item['qualname']) == (
                    'peaso/collectors/azure_selected_secret_integration_20261020.py', 'final_snapshot'):
                from peaso.checks import private_secret_shared_source_successor_20261021 as shared
                shared._check_function(value, dict(item, defaults=None, kwdefaults=None), _root(root), {})
            elif (item['path'], item['qualname']) == (
                    'peaso/collectors/azure_function_settings_declarations_20261020.py', 'collect_proposal'):
                from peaso.checks import private_secret_shared_source_successor_20261021 as shared
                shared._check_function(value, dict(item, defaults=None,
                    kwdefaults={'credential': None}), _root(root), {})
            elif _digest(inspect.getsource(value).encode()) != item['sha256']:
                raise RuntimeError('Function proposal callable changed')
        for key in ('native_cases', 'descriptions'):
            row = data[key]
            path = (_root(root) / row['path']).resolve()
            if not path.is_relative_to(_root(root)) or _digest(path.read_bytes()) != row['sha256']:
                raise RuntimeError('Function proposal artifact changed')
        return data

    historical_ml_evaluator = None

    def _historical_ml_fixture_branch(current, item, index, root):
        """Run the immutable fixture against its exact predecessor evaluator."""
        nonlocal historical_ml_evaluator
        check_module = importlib.import_module('peaso.checks.azure_ml_selected_job_secret_review_20261020')
        if current is not check_module.evaluate:
            raise RuntimeError('Selected ML current evaluator identity changed')
        if historical_ml_evaluator is None:
            historical = {}
            for relative, expected in (
                ('peaso/checks/azure_ml_selected_job_secret_review_20261020.py',
                 '20536cbdc302fdbee0565304aca63314e9ada62c769e17e383b3c3dc00798bd1'),
                ('peaso/collectors/azure_ml_selected_job_secret_indicators.py',
                 'a0644628612d680fea88a9dcedca7541f1560278fc5d4ea116710739035143c3')):
                path = _root(root) / relative
                historical[relative] = _private_epoch.predecessor_bytes(
                    relative, path.read_bytes(), expected, root)
            producer_name = 'peaso/collectors/azure_ml_selected_job_secret_indicators.py'
            producer = dict(__name__='peaso.collectors.azure_ml_selected_job_secret_indicators',
                            __package__='peaso.collectors')
            exec(compile(historical[producer_name], str(_root(root) / producer_name), 'exec'), producer)
            check_name = 'peaso/checks/azure_ml_selected_job_secret_review_20261020.py'
            raw = historical[check_name]
            nodes = {node.name: node for node in ast.parse(raw).body
                     if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                     and node.name in {'_evaluate', 'evaluate'}}
            if set(nodes) != {'_evaluate', 'evaluate'}:
                raise RuntimeError('Selected ML historical evaluator roster changed')
            signed = _receipt(root)['clones'][name]
            admission = json.loads((_root(root) / 'peaso/checks/azure_ml_job_secrets_admission_20261020.json').read_bytes())
            check, = admission['checks']
            for fn_name, digest in (('_evaluate', check['reachable_helper_sha256']),
                                    ('evaluate', check['predicate_sha256'])):
                node = nodes[fn_name]
                source_bytes = b''.join(raw.splitlines(keepends=True)[node.lineno - 1:node.end_lineno])
                if _digest(source_bytes) != digest:
                    raise RuntimeError('Selected ML historical callable source changed')
            if signed['before_sha256'] != _digest(inspect.getsource(module.reviewed_inputs).encode()):
                raise RuntimeError('Selected ML historical admission changed')
            legacy = dict(vars(check_module), source=types.SimpleNamespace(**producer))
            tree = ast.Module(body=[nodes['_evaluate'], nodes['evaluate']], type_ignores=[])
            exec(compile(ast.fix_missing_locations(tree), str(_root(root) / check_name), 'exec'), legacy)
            historical_ml_evaluator = legacy['evaluate']
        return historical_ml_evaluator(item, index)

    namespace = dict(vars(module), _admitted_source_digest=_admitted_source_digest,
                     _admitted_callable_digest=_admitted_callable_digest,
                     _admitted_metadata=_admitted_metadata,
                     _historical_ml_fixture_branch=_historical_ml_fixture_branch,
                     _validate_function_proposal=_validate_function_proposal,
                     _validate_dataproc_proposal=_validate_dataproc_proposal)
    exec(compile(transformed, str(module.__file__), 'exec'), namespace)
    clone = namespace['reviewed_inputs']
    if clone.__defaults__ != module.reviewed_inputs.__defaults__ or clone.__kwdefaults__ != module.reviewed_inputs.__kwdefaults__:
        raise RuntimeError('Selected admission callable defaults changed')
    if name in {'azure_ml_job_secrets_admission_20261020',
                'azure_databricks_notebook_secrets_admission_20261020'}:
        from copy import deepcopy
        epoch, _ = _private_epoch._receipt()
        witness = epoch['current_native_cases'][name]
        expected_path = {
            'azure_ml_job_secrets_admission_20261020': 'peaso/checks/azure_ml_job_variants_native_cases_20261021.json',
            'azure_databricks_notebook_secrets_admission_20261020': 'peaso/checks/azure_databricks_current_native_cases_20261021.json',
        }[name]
        if witness['path'] != expected_path:
            raise RuntimeError('Selected current native fixture path changed')
        raw = (_root(root) / expected_path).read_bytes()
        if _digest(raw) != witness['sha256']:
            raise RuntimeError('Selected current native fixture bytes changed')
        cases = json.loads(raw)
        signed = json.loads((_root(root) / 'peaso/checks' / (name + '.json')).read_bytes())
        check_module = importlib.import_module('peaso.checks.' + signed['module'])
        if set(cases) != {module.CHECK_ID}:
            raise RuntimeError('Selected current native fixture identity changed')
        case = cases[module.CHECK_ID]
        for branch in ('pass', 'fail', 'unknown'):
            if check_module.evaluate(deepcopy(case[branch]), deepcopy(case[branch + '_index']))[0] != branch.upper():
                raise RuntimeError('Selected current native branch changed')
        if name == 'azure_ml_job_secrets_admission_20261020':
            if check_module.evaluate(deepcopy(case['missing']), deepcopy(case['missing_index']))[0] != 'UNKNOWN':
                raise RuntimeError('Selected current missing branch changed')
    return _clone_install(module, clone)
