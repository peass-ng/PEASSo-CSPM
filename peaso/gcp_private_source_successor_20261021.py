"""Finite private source successor over the sealed GCP twelve-leaf guard.

The historical receipts stay pinned. Reviewed private bytes first project to
the cc762 source epoch, then the older GCP leaf and scanner epochs.
"""
import gzip
from contextvars import ContextVar
import hmac
import marshal
import os
import hashlib
import importlib
import json
from pathlib import Path
import types
import inspect
import re
import sys

from peaso import gcp_function_secret_pair_source_20261020 as predecessor
from peaso import gcp_function_secret_page_source_20261020 as page_predecessor
from peaso import gcp_cloudrun_job_image_function_source_successor_20261020 as job_predecessor
from peaso import gcp_positive_conservation_source_admission_successor_20261020 as canonical_source
from peaso import secret_evidence as private_helper
from peaso import private_secret_source_epoch_20261021 as private_source
from peaso import private_reviewed_collector_successor_20261022 as reviewed_source

_HISTORICAL_PAGE_REVIEWED_INPUTS = job_predecessor._HISTORICAL_PAGE_REVIEWED_INPUTS

RECEIPT_SHA256 = 'f71fbc8297c9499e3f02fba9fd6bbee49a9b3cea1c6aadbbce04589da6741f93'
RECEIPT = 'peaso/checks/gcp_cloudrun_job_image_function_source_successor_20261020.json'
PAGE_RECEIPT = 'peaso/checks/gcp_function_secret_page_admission_20261020.json'
PAGE_RECEIPT_SHA256 = '0753f397b3028f4e5eed1da1edf850f8bf9c2bf8c8fab77e2df9c23dbb6822f9'
SOURCE_DELTA = 'peaso/checks/gcp_positive_conservation_source_delta_20261020.json'
SOURCE_DELTA_SHA256 = '6f803d15053fdccf982ab20883b76a72a821ef98f703192eba25c3a05695d6d6'
BRIDGE_RECEIPT = 'peaso/checks/gcp_positive_conservation_source_bridge_20261020.json'
BRIDGE_RECEIPT_SHA256 = 'da2c2b52467ea97ff0d54a146556fa6b64239f8d70b847641b85cf65969d251c'
PRIVATE_RECEIPT = 'peaso/checks/gcp_private_source_successor_20261021.json'
PRIVATE_RECEIPT_SHA256 = '46242a100a27f9f18f4a6c0a3bfb698f36f84e67dccba4eaaaafba2ccdb6c525'


_MODULE_ARTIFACTS = ContextVar('gcp_positive_module_artifacts', default=None)
_MODULE_CONTEXT = _MODULE_ARTIFACTS


def _module_compiler():
    """Signed immutable module code only; never a source/live-binding verdict."""
    cache = {}
    secret = os.urandom(32)
    size = 0

    def lookup(path, raw):
        nonlocal size
        key = (str(path), hashlib.sha256(raw).hexdigest(), sys.flags.optimize)
        entry = cache.get(key)
        if entry is None:
            code = compile(raw, str(path), 'exec', optimize=sys.flags.optimize)
            # compile() creates exact immutable builtin constants/code. This
            # retained code cannot mutate; signing its identity avoids repeated
            # whole-module serialization while still rejecting replacements.
            payload = marshal.dumps((key, id(code)), 2)
            entry = (code, hmac.digest(secret, payload, 'sha256'))
            if len(cache) >= 128 or size + len(payload) > 4 * 1024 * 1024:
                cache.clear()
                size = 0
            if len(payload) <= 4 * 1024 * 1024:
                cache[key] = entry
                size += len(payload)
        code, signature = entry
        if not isinstance(code, types.CodeType) or not hmac.compare_digest(signature,
                hmac.digest(secret, marshal.dumps((key, id(code)), 2), 'sha256')):
            raise RuntimeError('GCP module artifact changed')
        return code

    return lookup


def _compiled_module(path, raw):
    compiler = _MODULE_ARTIFACTS.get()
    if compiler is None:
        return compile(raw, str(path), 'exec', optimize=sys.flags.optimize)
    expected = next(code for code in _module_compiler.__code__.co_consts
                    if isinstance(code, types.CodeType) and code.co_name == 'lookup')
    if (not isinstance(compiler, types.FunctionType) or compiler.__code__ is not expected
            or compiler.__globals__ is not globals()):
        raise RuntimeError('GCP module compiler callable changed')
    return compiler(path, raw)


def _bridge_source(root):
    root = Path(root).resolve()
    _private_receipt(root)
    if _MODULE_ARTIFACTS is not _MODULE_CONTEXT:
        raise RuntimeError('GCP module artifact context changed')
    raw = (root / BRIDGE_RECEIPT).read_bytes()
    if hashlib.sha256(raw).hexdigest() != BRIDGE_RECEIPT_SHA256:
        raise RuntimeError('GCP positive conservation bridge receipt changed')
    receipt = json.loads(raw)
    if receipt['delta_sha256'] != SOURCE_DELTA_SHA256:
        raise RuntimeError('GCP positive conservation bridge delta changed')
    # Freshly compile and attest this small bootstrap before any cached code.
    names = sorted(receipt['normalized_sources'], key=lambda name: (name != 'peaso/gcp_positive_conservation_source_admission_successor_20261020.py', name))
    for name in names:
        digest = receipt['normalized_sources'][name]
        path = (root / name).resolve()
        if not path.is_relative_to(root / 'peaso'):
            raise RuntimeError('GCP positive conservation bridge source escaped package')
        data = path.read_bytes()
        data, count = re.subn(rb"(?m)^BRIDGE_RECEIPT_SHA256 = '[0-9a-f]{64}'$",
            b"BRIDGE_RECEIPT_SHA256 = '" + b'0' * 64 + b"'", data)
        if count != 1 or hashlib.sha256(data).hexdigest() != digest:
            raise RuntimeError('GCP positive conservation bridge source changed: ' + name)
        module_name = name.removeprefix('peaso/').removesuffix('.py').replace('/', '.')
        module_name = 'peaso.' + module_name
        module = sys.modules.get(module_name)
        if module is None:
            raise RuntimeError('GCP positive conservation bridge module absent: ' + name)
        raw_code = path.read_bytes()
        module_code = (compile(raw_code, str(path), 'exec', optimize=sys.flags.optimize)
                       if module is sys.modules[__name__] else _compiled_module(path, raw_code))
        compiled = {code.co_qualname: code for code in predecessor._codes(module_code)}
        expected_functions = receipt['live_functions'][name]
        actual_functions = {key for key, value in vars(module).items()
            if isinstance(value, types.FunctionType) and value.__globals__ is vars(module)}
        if actual_functions != set(expected_functions):
            raise RuntimeError('GCP positive conservation bridge callable roster changed: ' + name)
        for key, row in expected_functions.items():
            function = vars(module)[key]
            if (inspect.unwrap(function) is not function or function.__module__ != module.__name__
                    or function.__code__ != compiled.get(key) or function.__closure__ is not None
                    or json.dumps(function.__defaults__, sort_keys=True) != row['defaults']
                    or json.dumps(function.__kwdefaults__, sort_keys=True) != row['kwdefaults']):
                raise RuntimeError('GCP positive conservation executing callable changed: ' + name + ':' + key)
    return receipt


def _private_receipt(root, source_requests=None):
    """Bind this derivative to the immutable old receipts and finite epoch."""
    root = Path(root).resolve()
    raw = (root / PRIVATE_RECEIPT).read_bytes()
    if hashlib.sha256(raw).hexdigest() != PRIVATE_RECEIPT_SHA256:
        raise RuntimeError('GCP private source receipt changed')
    receipt = json.loads(raw)
    own = (root / 'peaso/gcp_private_source_successor_20261021.py').resolve()
    if not own.is_relative_to(root / 'peaso') or own != Path(__file__).resolve():
        raise RuntimeError('GCP private source location changed')
    own_raw = own.read_bytes()
    normalized, count = re.subn(rb"(?m)^PRIVATE_RECEIPT_SHA256 = '[0-9a-f]{64}'$",
        b"PRIVATE_RECEIPT_SHA256 = '" + b'0' * 64 + b"'", own_raw)
    if count != 1 or hashlib.sha256(normalized).hexdigest() != receipt['normalized_module_sha256']:
        raise RuntimeError('GCP private source module changed')
    if source_requests is None:
        private_roster = sorted(private_source.source_rows())
    else:
        private_roster, predecessors = private_source.predecessor_bundle(source_requests, root)
    if (receipt['canonical_bridge_sha256'] != BRIDGE_RECEIPT_SHA256
            or receipt['canonical_delta_sha256'] != SOURCE_DELTA_SHA256
            or receipt['private_manifest_sha256'] != private_source._RECEIPT_SHA256
            or receipt['private_roster'] != private_roster):
        raise RuntimeError('GCP private source chain changed')
    dependencies = {
        'predecessor': 'peaso.gcp_function_secret_pair_source_20261020',
        'page_predecessor': 'peaso.gcp_function_secret_page_source_20261020',
        'job_predecessor': 'peaso.gcp_cloudrun_job_image_function_source_successor_20261020',
        'canonical_source': 'peaso.gcp_positive_conservation_source_admission_successor_20261020',
        'private_source': 'peaso.private_secret_source_epoch_20261021',
        'private_helper': 'peaso.secret_evidence',
    }
    for binding, module_name in dependencies.items():
        imported = globals().get(binding)
        expected_path = root / (module_name.replace('.', '/') + '.py')
        if (sys.modules.get(module_name) is not imported
                or not isinstance(imported, types.ModuleType)
                or Path(imported.__file__).resolve() != expected_path):
            raise RuntimeError('GCP private source dependency changed: ' + binding)
    if _HISTORICAL_PAGE_REVIEWED_INPUTS is not job_predecessor._HISTORICAL_PAGE_REVIEWED_INPUTS:
        raise RuntimeError('GCP historical page binding changed')
    module = sys.modules.get(__name__)
    if module is None or vars(module) is not globals():
        raise RuntimeError('GCP private source module replaced')
    # The artifact provider is small enough to compile freshly on each proof.
    # Prove it from this exact read before consulting any retained module code.
    stop = own_raw.index(b'def _bridge_source(root):')
    bootstrap = compile(own_raw[:stop], __file__, 'exec', optimize=sys.flags.optimize)
    bootstrap_codes = {code.co_name: code for code in bootstrap.co_consts
                       if isinstance(code, types.CodeType)}
    if (set(bootstrap_codes) != {'_module_compiler', '_compiled_module'}
            or _MODULE_ARTIFACTS is not _MODULE_CONTEXT
            or not isinstance(_MODULE_ARTIFACTS, ContextVar)):
        raise RuntimeError('GCP private module artifact bootstrap changed')
    for name, expected in bootstrap_codes.items():
        function = globals().get(name)
        if (not isinstance(function, types.FunctionType)
                or function.__globals__ is not globals()
                or function.__code__ != expected
                or function.__closure__ is not None
                or function.__defaults__ is not None
                or function.__kwdefaults__ is not None):
            raise RuntimeError('GCP private module artifact provider changed: ' + name)
    compiler = _MODULE_ARTIFACTS.get()
    if compiler is not None:
        expected_lookup = next((code for code in bootstrap_codes['_module_compiler'].co_consts
                                if isinstance(code, types.CodeType) and code.co_name == 'lookup'), None)
        if (not isinstance(compiler, types.FunctionType)
                or compiler.__code__ != expected_lookup
                or compiler.__globals__ is not globals()
                or compiler.__name__ != 'lookup'
                or compiler.__qualname__ != '_module_compiler.<locals>.lookup'
                or compiler.__module__ != __name__
                or compiler.__defaults__ is not None
                or compiler.__kwdefaults__ is not None
                or compiler.__closure__ is None):
            raise RuntimeError('GCP private module artifact lookup changed')
        cells = dict(zip(compiler.__code__.co_freevars,
                         (cell.cell_contents for cell in compiler.__closure__)))
        if (set(cells) != {'cache', 'secret', 'size'}
                or type(cells['cache']) is not dict
                or type(cells['secret']) is not bytes or len(cells['secret']) != 32
                or type(cells['size']) is not int or cells['size'] < 0):
            raise RuntimeError('GCP private module artifact closure changed')
    compiled = {code.co_qualname: code for code in predecessor._codes(
        _compiled_module(Path(__file__), own_raw))}
    actual = {key: value for key, value in globals().items()
              if isinstance(value, types.FunctionType) and value.__module__ == __name__}
    if set(actual) != set(receipt['live_functions']):
        raise RuntimeError('GCP private source callable roster changed')
    for key, function in actual.items():
        row = receipt['live_functions'][key]
        if (function.__globals__ is not globals() or function.__qualname__ != key
                or inspect.unwrap(function) is not function or function.__closure__ is not None
                or function.__code__ != compiled.get(key)
                or repr(function.__defaults__) != row['defaults']
                or repr(function.__kwdefaults__) != row['kwdefaults']):
            raise RuntimeError('GCP private source callable changed: ' + key)
    return (receipt, predecessors) if source_requests is not None else receipt


def _live_helper(root):
    """Rebuild the exact helper in isolation and compare its live definitions."""
    root = Path(root).resolve()
    path = (root / 'peaso/secret_evidence.py').resolve()
    if not path.is_relative_to(root / 'peaso') or Path(private_helper.__file__).resolve() != path:
        raise RuntimeError('Private helper location changed')
    raw = path.read_bytes()
    if hashlib.sha256(reviewed_source.predecessor_bytes('peaso/secret_evidence.py', raw,
            private_source._HELPER_SHA256, root)).hexdigest() != private_source._HELPER_SHA256:
        raise RuntimeError('Private helper source changed')
    if sys.modules.get('peaso.secret_evidence') is not private_helper:
        raise RuntimeError('Private helper module replaced')
    expected = {'__name__': private_helper.__name__, '__file__': str(path),
                '__package__': 'peaso'}
    exec(compile(raw, private_helper.__file__, 'exec', optimize=sys.flags.optimize), expected)

    def same(left, right):
        if type(left) is not type(right):
            return False
        if isinstance(left, types.FunctionType):
            if (left.__code__ != right.__code__ or not same(left.__defaults__, right.__defaults__)
                    or not same(left.__kwdefaults__, right.__kwdefaults__)
                    or (left.__globals__ is not vars(private_helper)
                        and left.__globals__ is not right.__globals__)
                    or left.__module__ != right.__module__ or left.__qualname__ != right.__qualname__):
                return False
            if (left.__closure__ is None) != (right.__closure__ is None):
                return False
            if left.__closure__ is not None:
                if len(left.__closure__) != len(right.__closure__):
                    return False
                for a, b in zip(left.__closure__, right.__closure__):
                    if not same(a.cell_contents, b.cell_contents):
                        return False
            if hasattr(left, '__wrapped__') or hasattr(right, '__wrapped__'):
                return hasattr(left, '__wrapped__') and hasattr(right, '__wrapped__') and same(left.__wrapped__, right.__wrapped__)
            return True
        if isinstance(left, type):
            if (left.__module__ != right.__module__ or left.__qualname__ != right.__qualname__
                    or left.__bases__ != right.__bases__):
                return False
            a, b = vars(left), vars(right)
            automatic = {'__dict__', '__weakref__'}
            return (a.keys() == b.keys()
                    and all(type(a[k]) is type(b[k]) if k in automatic else same(a[k], b[k])
                            for k in a))
        if isinstance(left, (staticmethod, classmethod)):
            return same(left.__func__, right.__func__)
        if isinstance(left, types.ModuleType):
            return left is right
        if isinstance(left, re.Pattern):
            return (left.pattern, left.flags) == (right.pattern, right.flags)
        if isinstance(left, dict):
            return left.keys() == right.keys() and all(same(left[k], right[k]) for k in left)
        if isinstance(left, (tuple, list)):
            return len(left) == len(right) and all(same(a, b) for a, b in zip(left, right))
        if isinstance(left, (set, frozenset)):
            return left == right and all(any(same(a, b) for b in right) for a in left)
        return left == right

    live = vars(private_helper)
    for name, value in expected.items():
        if name.startswith('__') or name in ('_lock', '_active', '_source'):
            continue
        if name not in live or not same(live[name], value):
            raise RuntimeError('Private helper live binding changed: ' + name)
    if any(name not in expected and not name.startswith('__') for name in live):
        raise RuntimeError('Private helper live roster changed')


def _source_delta(root):
    root = Path(root).resolve()
    raw = (root / SOURCE_DELTA).read_bytes()
    if hashlib.sha256(raw).hexdigest() != SOURCE_DELTA_SHA256:
        raise RuntimeError('GCP positive conservation source delta changed')
    rows = json.loads(raw)['files']
    if len(rows) != 12 or any(set(row) != {'before_sha256', 'after_sha256'} for row in rows.values()):
        raise RuntimeError('GCP positive conservation source roster changed')
    observed = {}
    requests = []
    for name, row in rows.items():
        path = (root / name).resolve()
        if not path.is_relative_to(root / 'peaso'):
            raise RuntimeError('GCP positive conservation source escaped package: ' + name)
        observed[name] = path.read_bytes()
        if name.startswith('peaso/collectors/'):
            requests.append((name, observed[name], row['after_sha256']))
    private_contract, predecessors = _private_receipt(root, tuple(requests))
    if {name for name, _, _ in requests} != set(rows).intersection(private_contract['private_roster']):
        raise RuntimeError('GCP positive conservation private source request roster changed')
    for name, row in rows.items():
        if (root / name).read_bytes() != observed[name]:
            raise RuntimeError('GCP positive conservation source changed during proof: ' + name)
        data = predecessors.get(name, observed[name])
        if hashlib.sha256(data).hexdigest() != row['after_sha256']:
            raise RuntimeError('GCP positive conservation source changed: ' + name)
    return rows


def _source_hash(name, data, expected, rows, root=None):
    root = Path(root or Path(__file__).resolve().parents[1]).resolve()
    if name == 'peaso/secret_scanning.py':
        from peaso.rawv2_private_source_successor_20261021 import source_bytes
        source_bytes(name, data, expected, root)
        return
    private_rows = private_source.source_rows()
    if name in private_rows:
        before = reviewed_source.predecessor_bytes(name, (root / name).read_bytes(),
            private_rows[name]['before_sha256'], root)
        if hashlib.sha256(data).hexdigest() == private_rows[name]['after_sha256']:
            data = reviewed_source.predecessor_bytes(name, data,
                private_rows[name]['before_sha256'], root)
    if name in rows:
        if expected != rows[name]['before_sha256'] or hashlib.sha256(data).hexdigest() != rows[name]['after_sha256']:
            raise RuntimeError('GCP positive conservation predecessor/successor changed: ' + name)
    elif hashlib.sha256(data).hexdigest() != expected:
        raise RuntimeError('GCP positive conservation immutable source changed: ' + name)


def _live_leaf(root, rows):
    """Bind every changed leaf's exposed callable to its exact compiled bytes."""
    root = Path(root).resolve()
    receipt = _bridge_source(root)
    if set(receipt['leaf_functions']) != set(rows):
        raise RuntimeError('GCP positive conservation callable source roster changed')
    for name, functions in receipt['leaf_functions'].items():
        path = (root / name).resolve()
        _source_hash(name, path.read_bytes(), rows[name]['before_sha256'], rows, root)
        module_name = 'peaso.' + name.removeprefix('peaso/').removesuffix('.py').replace('/', '.')
        module = importlib.import_module(module_name)
        if sys.modules.get(module_name) is not module:
            raise RuntimeError('GCP positive conservation leaf module replaced: ' + name)
        compiled = {code.co_qualname: code for code in predecessor._codes(
            _compiled_module(path, path.read_bytes()))}
        changed = {entry['name'] for entry in private_source.source_rows().get(name, {}).get('definitions', ())}
        for qualified, row in functions.items():
            parts = qualified.split('.')
            value = vars(module)[parts[0]]
            for part in parts[1:]:
                value = vars(value)[part]
            if isinstance(value, (staticmethod, classmethod)):
                value = value.__func__
            closure_valid = (value.__closure__ is None if isinstance(value, types.FunctionType)
                and not value.__code__.co_freevars else
                isinstance(value, types.FunctionType) and len(parts) == 2
                and value.__code__.co_freevars == ('__class__',)
                and isinstance(value.__closure__, tuple) and len(value.__closure__) == 1
                and value.__closure__[0].cell_contents is vars(module)[parts[0]])
            if qualified in changed:
                proof = reviewed_source.trusted_definition(value, root)
                if proof['historical']['file_sha256'] != rows[name]['after_sha256']:
                    raise RuntimeError('GCP positive conservation private leaf predecessor changed: ' + name + ':' + qualified)
                continue
            if (not isinstance(value, types.FunctionType) or inspect.unwrap(value) is not value
                    or value.__module__ != module_name or value.__globals__ is not vars(module)
                    or value.__code__ != compiled.get(qualified) or not closure_valid
                    or json.dumps(value.__defaults__, sort_keys=True) != row['defaults']
                    or json.dumps(value.__kwdefaults__, sort_keys=True) != row['kwdefaults']):
                raise RuntimeError('GCP positive conservation live leaf changed: ' + name + ':' + qualified)


def reviewed_inputs(root=None):
    root = Path(root or Path(__file__).resolve().parents[1]).resolve()
    _bridge_source(root)
    _live_helper(root)
    rows = _source_delta(root)
    _live_leaf(root, rows)
    for module_name, class_name in (('peaso.collectors.azure', 'AzureTransport'),
                                    ('peaso.collectors.gcp', 'Transport')):
        module = importlib.import_module(module_name)
        owner = vars(module).get(class_name)
        if not isinstance(owner, type):
            raise RuntimeError('Private transport class missing: ' + module_name)
        proof = reviewed_source.trusted_definition(vars(owner)['request'], root)
        if proof['historical']['path'] != module_name.replace('.', '/') + '.py':
            raise RuntimeError('Private transport source changed: ' + module_name)
    raw = (root / RECEIPT).read_bytes()
    if hashlib.sha256(raw).hexdigest() != RECEIPT_SHA256:
        raise RuntimeError('Functions partial-page successor receipt changed')
    delta = json.loads(raw)
    page_raw = (root / PAGE_RECEIPT).read_bytes()
    if hashlib.sha256(page_raw).hexdigest() != PAGE_RECEIPT_SHA256:
        raise RuntimeError('Functions page predecessor receipt changed')
    receipt = json.loads(page_raw)
    current = (root / 'peaso/collectors/gcp.py').read_bytes()
    current = reviewed_source.predecessor_bytes('peaso/collectors/gcp.py', current,
        private_source.source_rows()['peaso/collectors/gcp.py']['before_sha256'], root)
    if hashlib.sha256(current).hexdigest() != delta['collector_after_sha256']:
        raise RuntimeError('Job image collector successor changed')
    restored = current
    for edit in reversed(delta['edits']):
        before, after = edit['before'].encode(), edit['after'].encode()
        if restored.count(after) != 1:
            raise RuntimeError('Job image collector exact delta ambiguous')
        restored = restored.replace(after, before, 1)
    if hashlib.sha256(restored).hexdigest() != delta['collector_before_sha256']:
        raise RuntimeError('Job image collector predecessor changed')
    for name, expected in delta['sources'].items():
        data = (root / name).read_bytes()
        if name == 'peaso/gcp_cloudrun_job_image_function_source_successor_20261020.py':
            data = predecessor._self(data)
        _source_hash(name, data, expected, rows, root)
    old_raw = (root / predecessor.RECEIPT).read_bytes()
    if (hashlib.sha256(old_raw).hexdigest() != receipt['predecessor_receipt_sha256']
            or receipt['predecessor_receipt_sha256'] != predecessor.RECEIPT_SHA256):
        raise RuntimeError('Functions paired predecessor receipt changed')
    old = json.loads(old_raw)
    for name, row in old['sources'].items():
        if name == 'peaso/collectors/gcp.py':
            continue
        data = (root / name).read_bytes()
        if row.get('normalization') == 'self':
            data = predecessor._self(data)
        _source_hash(name, data, row['sha256'], rows, root)
    archive_raw = (root / old['predecessors']['path']).read_bytes()
    if hashlib.sha256(archive_raw).hexdigest() != old['predecessors']['sha256']:
        raise RuntimeError('Functions inherited archive changed')
    archive = json.loads(gzip.decompress(archive_raw))
    for name, row in archive['files'].items():
        data = bytes.fromhex(row['hex'])
        if hashlib.sha256(data).hexdigest() != row['sha256']:
            raise RuntimeError('Functions inherited predecessor bytes changed')
        if name.startswith('peaso/') and name not in {'peaso/collectors/gcp.py', 'peaso/checks/__init__.py'}:
            actual = (root / name).read_bytes()
            if name in rows:
                if hashlib.sha256(data).hexdigest() != rows[name]['before_sha256']:
                    raise RuntimeError('Functions inherited positive source changed: ' + name)
                _source_hash(name, actual, rows[name]['before_sha256'], rows, root)
            elif name == 'peaso/secret_scanning.py':
                from peaso.rawv2_private_source_successor_20261021 import source_bytes
                if source_bytes(name, actual, row['sha256'], root) != data:
                    raise RuntimeError('Functions inherited scanner predecessor changed')
            elif name in private_source.source_rows():
                before = reviewed_source.predecessor_bytes(name, actual,
                    private_source.source_rows()[name]['before_sha256'], root)
                if before != data:
                    raise RuntimeError('Functions inherited private predecessor changed: ' + name)
            elif actual != data:
                raise RuntimeError('Functions inherited predecessor source changed')
    original = bytes.fromhex(archive['files']['peaso/collectors/gcp.py']['hex'])
    before, after = (old['gcp_import_delta'][key].encode() for key in ('before', 'after'))
    if original.count(before) != 1:
        raise RuntimeError('Functions inherited native import ambiguous')
    accepted = original.replace(before, after, 1)
    if hashlib.sha256(accepted).hexdigest() != old['sources']['peaso/collectors/gcp.py']['sha256']:
        raise RuntimeError('Functions accepted native epoch changed')
    current = restored
    addition = receipt['workbench_scalar_exact_addition'].encode()
    if current.count(addition) != 1 or current.replace(addition, b'', 1) != accepted:
        raise RuntimeError('Workbench scalar changed outside its exact additive hook')
    for name, row in receipt['sources'].items():
        path = (root / name).resolve()
        if not path.is_relative_to(root / 'peaso'):
            raise RuntimeError('Functions successor source outside package')
        data = restored if name == 'peaso/collectors/gcp.py' else path.read_bytes()
        if row.get('normalization') == 'self':
            data = predecessor._self(data)
        _source_hash(name, data, row['sha256'], rows, root)
    compiled = {}
    for qualified, row in {**old['functions'], **receipt['functions']}.items():
        if row['path'] in rows:
            raise RuntimeError('GCP positive source entered old callable roster')
        module, function = predecessor._resolve(qualified)
        if qualified == page_predecessor.__name__ + ':reviewed_inputs':
            if function not in (job_predecessor.reviewed_inputs, reviewed_inputs):
                raise RuntimeError('Job image Functions runtime source alias replaced')
            function = _HISTORICAL_PAGE_REVIEWED_INPUTS
        path = (root / row['path']).resolve()
        if path not in compiled:
            compiled[path] = {code.co_qualname: code for code in predecessor._codes(
                compile(path.read_bytes(), str(path), 'exec', optimize=__import__('sys').flags.optimize))}
        finite = private_source.source_rows().get(row['path'])
        if finite is not None:
            names = {definition['name'] for definition in finite['definitions']}
            if row['path'] == 'peaso/secret_scanning.py':
                from peaso import rawv2_private_source_successor_20261021 as scanner_proof
                scanner_proof.verify_scanner(root)
            elif row['qualname'] in names or (row['path'] == 'peaso/collectors/gcp.py' and row['qualname'] == 'Transport.request'):
                current_proof = reviewed_source.trusted_definition(function, root)
                if current_proof['historical']['file_sha256'] != finite['before_sha256']:
                    raise RuntimeError('Functions private callable predecessor changed: ' + qualified)
        if (not isinstance(function, types.FunctionType) or inspect.unwrap(function) is not function
                or function.__module__ != module.__name__ or function.__globals__ is not vars(module)
                or function.__code__ != compiled[path].get(row['qualname']) or function.__closure__ is not None
                or json.dumps(function.__defaults__) != json.dumps(row['defaults'])
                or json.dumps(function.__kwdefaults__, sort_keys=True) != json.dumps(row['kwdefaults'], sort_keys=True)):
            raise RuntimeError('Functions successor executing callable changed: ' + qualified)
    for actual, expected in [*old['bindings'], *receipt['bindings']]:
        if any(name.removeprefix('peaso/').removesuffix('.py').replace('/', '.') in actual + expected
               for name in rows):
            raise RuntimeError('GCP positive source entered old binding roster')
        actual_function = predecessor._resolve(actual)[1]
        if actual == 'peaso.checks.gcp_function_secret_page_admission_20261020:source_inputs':
            if actual_function not in (reviewed_inputs, canonical_source.reviewed_inputs):
                raise RuntimeError('Job image Functions admission alias replaced')
            continue
        if actual_function is not predecessor._resolve(expected)[1]:
            raise RuntimeError('Functions successor imported binding changed')
    for actual, expected_module in receipt['module_bindings']:
        if predecessor._resolve(actual)[1] is not __import__('importlib').import_module(expected_module):
            raise RuntimeError('Functions successor imported module replaced')
    for qualified, value in {**old['constants'], **receipt['constants']}.items():
        if json.dumps(predecessor._resolve(qualified)[1], sort_keys=True) != json.dumps(value, sort_keys=True):
            raise RuntimeError('Functions successor native schema changed')
    return receipt
