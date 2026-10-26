"""Package-only source and executing-callable guard for Functions pairing.

This is source conservation for an existing authorized read, not an additional
credential, grant, or user authorization layer.
"""
import hashlib
import importlib
import inspect
import json
from pathlib import Path
import re
import types

RECEIPT_SHA256 = '2db48941c86ab55512285eb22f591eb17bf50be7b1a1cf099d7bd134d9393622'
RECEIPT = 'peaso/checks/gcp_function_secret_paired_admission_20261020.json'


def _self(raw):
    normalized, count = re.subn(rb"(?m)^RECEIPT_SHA256 = '[0-9a-f]{64}'$",
        b"RECEIPT_SHA256 = '" + b'0' * 64 + b"'", raw)
    if count != 1:
        raise RuntimeError('Functions source guard self binding changed')
    return normalized


def _codes(code):
    yield code
    for constant in code.co_consts:
        if isinstance(constant, types.CodeType):
            yield from _codes(constant)


def _resolve(qualified):
    module_name, attribute = qualified.split(':')
    module = importlib.import_module(module_name)
    value = module
    for name in attribute.split('.'):
        value = getattr(value, name)
    return module, value


def reviewed_inputs(root=None):
    root = Path(root or Path(__file__).resolve().parents[1]).resolve()
    raw = (root / RECEIPT).read_bytes()
    if hashlib.sha256(raw).hexdigest() != RECEIPT_SHA256:
        raise RuntimeError('Functions paired admission receipt changed')
    receipt = json.loads(raw)
    if receipt['check_id'] != 'gcp.review.function.literal_environment_secret_indicators':
        raise RuntimeError('Functions paired check identity changed')
    for name, row in receipt['sources'].items():
        path = (root / name).resolve()
        if not path.is_relative_to(root / 'peaso'):
            raise RuntimeError('Functions paired source outside package')
        data = path.read_bytes()
        if row.get('normalization') == 'self':
            data = _self(data)
        if hashlib.sha256(data).hexdigest() != row['sha256']:
            raise RuntimeError('Functions paired source changed: ' + name)
    from peaso.checks.gcp_function_secret_paired_source_successor_20261020 import reviewed_delta
    reviewed_delta(root, receipt)
    compiled = {}
    for qualified, row in receipt['functions'].items():
        module, function = _resolve(qualified)
        path = (root / row['path']).resolve()
        if path not in compiled:
            compiled[path] = {code.co_qualname: code for code in _codes(
                compile(path.read_bytes(), str(path), 'exec', optimize=__import__('sys').flags.optimize))}
        expected = compiled[path].get(row['qualname'])
        if (not isinstance(function, types.FunctionType) or function is not inspect.unwrap(function)
                or function.__module__ != module.__name__ or function.__globals__ is not vars(module)
                or function.__code__ != expected or function.__closure__ is not None
                or json.dumps(function.__defaults__) != json.dumps(row['defaults'])
                or json.dumps(function.__kwdefaults__, sort_keys=True) != json.dumps(row['kwdefaults'], sort_keys=True)):
            raise RuntimeError('Functions paired executing callable changed: ' + qualified)
    for actual, expected in receipt['bindings']:
        if _resolve(actual)[1] is not _resolve(expected)[1]:
            raise RuntimeError('Functions paired imported binding changed: ' + actual)
    for qualified, expected in receipt['constants'].items():
        if json.dumps(_resolve(qualified)[1], sort_keys=True) != json.dumps(expected, sort_keys=True):
            raise RuntimeError('Functions paired schema changed: ' + qualified)
    return receipt
