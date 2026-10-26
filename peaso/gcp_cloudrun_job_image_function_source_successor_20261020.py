"""Exact Job-image collector successor over immutable Functions page guards.

Source-derived guard: historical modules/callables remain loaded and attested.
Only the listed reversible collector edits and one admission alias are accepted.
"""
import gzip
import hashlib
import json
from pathlib import Path
import types
import inspect

from peaso import gcp_function_secret_pair_source_20261020 as predecessor
from peaso import gcp_function_secret_page_source_20261020 as page_predecessor

_HISTORICAL_PAGE_REVIEWED_INPUTS = page_predecessor.reviewed_inputs

RECEIPT_SHA256 = 'f71fbc8297c9499e3f02fba9fd6bbee49a9b3cea1c6aadbbce04589da6741f93'
RECEIPT = 'peaso/checks/gcp_cloudrun_job_image_function_source_successor_20261020.json'
PAGE_RECEIPT = 'peaso/checks/gcp_function_secret_page_admission_20261020.json'
PAGE_RECEIPT_SHA256 = '0753f397b3028f4e5eed1da1edf850f8bf9c2bf8c8fab77e2df9c23dbb6822f9'


def reviewed_inputs(root=None):
    root = Path(root or Path(__file__).resolve().parents[1]).resolve()
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
        if hashlib.sha256(data).hexdigest() != expected:
            raise RuntimeError('Job image successor immutable source changed: ' + name)
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
        if hashlib.sha256(data).hexdigest() != row['sha256']:
            raise RuntimeError('Functions paired immutable source changed: ' + name)
    archive_raw = (root / old['predecessors']['path']).read_bytes()
    if hashlib.sha256(archive_raw).hexdigest() != old['predecessors']['sha256']:
        raise RuntimeError('Functions inherited archive changed')
    archive = json.loads(gzip.decompress(archive_raw))
    for name, row in archive['files'].items():
        data = bytes.fromhex(row['hex'])
        if hashlib.sha256(data).hexdigest() != row['sha256']:
            raise RuntimeError('Functions inherited predecessor bytes changed')
        if name.startswith('peaso/') and name not in {'peaso/collectors/gcp.py', 'peaso/checks/__init__.py'}:
            if (root / name).read_bytes() != data:
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
        if hashlib.sha256(data).hexdigest() != row['sha256']:
            raise RuntimeError('Functions successor source changed: ' + name)
    compiled = {}
    for qualified, row in {**old['functions'], **receipt['functions']}.items():
        module, function = predecessor._resolve(qualified)
        if qualified == page_predecessor.__name__ + ':reviewed_inputs':
            if function is not reviewed_inputs:
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
