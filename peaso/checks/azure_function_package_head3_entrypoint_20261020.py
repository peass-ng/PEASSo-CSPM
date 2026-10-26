"""Exact two-line HEAD3 entrypoint successor over the completed package epoch."""
import gzip
import hashlib
import json
from pathlib import Path
import re
import types

RECEIPT = 'azure_function_package_head3_entrypoint_20261020.json'
RECEIPT_SHA256 = 'a4f778f1c366589e38ea6675d6b65591ec1796d75c3259a916b99d7b1c5bfff0'


def _self(raw):
    result, count = re.subn(rb"(?m)^RECEIPT_SHA256 = '[0-9a-f]{64}'$", b"RECEIPT_SHA256 = '" + b'0' * 64 + b"'", raw)
    if count != 1:
        raise RuntimeError('HEAD3 entrypoint self binding changed')
    return result


def reviewed_entrypoint(root=None):
    root = Path(root or Path(__file__).resolve().parents[2]).resolve()
    raw = (root / 'peaso/checks' / RECEIPT).read_bytes()
    if hashlib.sha256(raw).hexdigest() != RECEIPT_SHA256:
        raise RuntimeError('HEAD3 entrypoint receipt changed')
    receipt = json.loads(raw)
    packed = (root / receipt['archive']['path']).read_bytes()
    if hashlib.sha256(packed).hexdigest() != receipt['archive']['sha256']:
        raise RuntimeError('HEAD3 entrypoint predecessor archive changed')
    archive = json.loads(gzip.decompress(packed))
    for name, row in archive.items():
        if hashlib.sha256(bytes.fromhex(row['hex'])).hexdigest() != row['sha256']:
            raise RuntimeError('HEAD3 entrypoint original bytes changed')
    for name, digest in receipt['sources'].items():
        data = (root / name).read_bytes()
        if name == receipt['helper']:
            data = _self(data)
        if hashlib.sha256(data).hexdigest() != digest:
            raise RuntimeError('HEAD3 entrypoint reviewed source changed')
    for name, addition in receipt['exact_additions'].items():
        current = (root / name).read_bytes()
        if name.endswith('azure_function_package_shared_successor_20261020.py'):
            current = _self(current)
            before = _self(bytes.fromhex(archive[name]['hex']))
        else:
            before = bytes.fromhex(archive[name]['hex'])
        if current.count(addition.encode()) != 1 or current.replace(addition.encode(), b'', 1) != before:
            raise RuntimeError('HEAD3 changed outside exact reviewed entrypoint additions')
    return receipt


_FUNCTIONS = {name: fn for name, fn in tuple(globals().items())
              if isinstance(fn, types.FunctionType) and fn.__globals__ is globals()}
