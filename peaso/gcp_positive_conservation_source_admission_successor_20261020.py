"""Finite source successor over the sealed Job-image and Functions guards.

The old receipts and executable code remain byte-for-byte unchanged. Exactly
the twelve manifest-listed source-only leaves may have successor bytes.
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

_HISTORICAL_PAGE_REVIEWED_INPUTS = job_predecessor._HISTORICAL_PAGE_REVIEWED_INPUTS

RECEIPT_SHA256 = 'f71fbc8297c9499e3f02fba9fd6bbee49a9b3cea1c6aadbbce04589da6741f93'
RECEIPT = 'peaso/checks/gcp_cloudrun_job_image_function_source_successor_20261020.json'
PAGE_RECEIPT = 'peaso/checks/gcp_function_secret_page_admission_20261020.json'
PAGE_RECEIPT_SHA256 = '0753f397b3028f4e5eed1da1edf850f8bf9c2bf8c8fab77e2df9c23dbb6822f9'
SOURCE_DELTA = 'peaso/checks/gcp_positive_conservation_source_delta_20261020.json'
SOURCE_DELTA_SHA256 = '6f803d15053fdccf982ab20883b76a72a821ef98f703192eba25c3a05695d6d6'
BRIDGE_RECEIPT = 'peaso/checks/gcp_positive_conservation_source_bridge_20261020.json'
BRIDGE_RECEIPT_SHA256 = 'cf58e171e2aac6ada6a70473dc56f2b95d46e807cbc7bbf5f977510afee999e5'


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


def _source_delta(root):
    raw = (root / SOURCE_DELTA).read_bytes()
    if hashlib.sha256(raw).hexdigest() != SOURCE_DELTA_SHA256:
        raise RuntimeError('GCP positive conservation source delta changed')
    rows = json.loads(raw)['files']
    if len(rows) != 12 or any(set(row) != {'before_sha256', 'after_sha256'}
                              for row in rows.values()):
        raise RuntimeError('GCP positive conservation source roster changed')
    for name, row in rows.items():
        path = (root / name).resolve()
        if not path.is_relative_to(root / 'peaso') or hashlib.sha256(path.read_bytes()).hexdigest() != row['after_sha256']:
            raise RuntimeError('GCP positive conservation source changed: ' + name)
    return rows


def _source_hash(name, data, expected, rows):
    if name == 'peaso/secret_scanning.py':
        from peaso.rawv2_public_source_successor_20261021 import source_bytes
        source_bytes(name, data, expected, Path(__file__).resolve().parents[1])
        return
    if name in rows:
        if expected != rows[name]['before_sha256'] or hashlib.sha256(data).hexdigest() != rows[name]['after_sha256']:
            raise RuntimeError('GCP positive conservation predecessor/successor changed: ' + name)
    elif hashlib.sha256(data).hexdigest() != expected:
        raise RuntimeError('GCP positive conservation immutable source changed: ' + name)


def _live_leaf(root, rows):
    """Bind every changed leaf's exposed callable to its exact compiled bytes."""
    receipt = _bridge_source(root)
    if set(receipt['leaf_functions']) != set(rows):
        raise RuntimeError('GCP positive conservation callable source roster changed')
    for name, functions in receipt['leaf_functions'].items():
        path = (root / name).resolve()
        _source_hash(name, path.read_bytes(), rows[name]['before_sha256'], rows)
        module_name = 'peaso.' + name.removeprefix('peaso/').removesuffix('.py').replace('/', '.')
        module = importlib.import_module(module_name)
        if sys.modules.get(module_name) is not module:
            raise RuntimeError('GCP positive conservation leaf module replaced: ' + name)
        compiled = {code.co_qualname: code for code in predecessor._codes(
            _compiled_module(path, path.read_bytes()))}
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
            if (not isinstance(value, types.FunctionType) or inspect.unwrap(value) is not value
                    or value.__module__ != module_name or value.__globals__ is not vars(module)
                    or value.__code__ != compiled.get(qualified) or not closure_valid
                    or json.dumps(value.__defaults__, sort_keys=True) != row['defaults']
                    or json.dumps(value.__kwdefaults__, sort_keys=True) != row['kwdefaults']):
                raise RuntimeError('GCP positive conservation live leaf changed: ' + name + ':' + qualified)


def reviewed_inputs(root=None):
    root = Path(root or Path(__file__).resolve().parents[1]).resolve()
    _bridge_source(root)
    rows = _source_delta(root)
    _live_leaf(root, rows)
    raw = (root / RECEIPT).read_bytes()
    if hashlib.sha256(raw).hexdigest() != RECEIPT_SHA256:
        raise RuntimeError('Functions partial-page successor receipt changed')
    delta = json.loads(raw)
    page_raw = (root / PAGE_RECEIPT).read_bytes()
    if hashlib.sha256(page_raw).hexdigest() != PAGE_RECEIPT_SHA256:
        raise RuntimeError('Functions page predecessor receipt changed')
    receipt = json.loads(page_raw)
    current = (root / 'peaso/collectors/gcp.py').read_bytes()
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
        _source_hash(name, data, expected, rows)
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
        _source_hash(name, data, row['sha256'], rows)
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
                _source_hash(name, actual, rows[name]['before_sha256'], rows)
            elif name == 'peaso/secret_scanning.py':
                from peaso.rawv2_public_source_successor_20261021 import source_bytes
                if source_bytes(name, actual, row['sha256'], root) != data:
                    raise RuntimeError('Functions inherited scanner predecessor changed')
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
        _source_hash(name, data, row['sha256'], rows)
    compiled = {}
    for qualified, row in {**old['functions'], **receipt['functions']}.items():
        if row['path'] in rows:
            raise RuntimeError('GCP positive source entered old callable roster')
        module, function = predecessor._resolve(qualified)
        if qualified == page_predecessor.__name__ + ':reviewed_inputs':
            if function is not job_predecessor.reviewed_inputs:
                raise RuntimeError('Job image Functions runtime source alias replaced')
            function = _HISTORICAL_PAGE_REVIEWED_INPUTS
        path = (root / row['path']).resolve()
        if path not in compiled:
            compiled[path] = {code.co_qualname: code for code in predecessor._codes(
                compile(path.read_bytes(), str(path), 'exec', optimize=__import__('sys').flags.optimize))}
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
            if actual_function is not reviewed_inputs:
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
