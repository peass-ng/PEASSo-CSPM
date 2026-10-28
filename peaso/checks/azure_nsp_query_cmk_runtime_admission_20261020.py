"""Prepared source-bound successor inputs only; intentionally no install hook."""
from copy import deepcopy
import inspect
import json
from pathlib import Path
import sys
import types

from . import azure_nsp_query_cmk_metadata_admission_20261020 as predecessor
from . import azure_nsp_query_cmk_runtime_review_20261020 as candidate
from peaso.collectors import azure_nsp_query_cmk_runtime_20261020 as producer

RECEIPT = 'azure_nsp_query_cmk_runtime_admission_20261020.json'
RECEIPT_SHA256 = '4427d5d11f1767cfa74d9fc9b74dd4c65e806622648e809f17228a6023df6653'
CASES_FILE = 'azure_nsp_query_cmk_runtime_cases_20261020.json'


def _runtime():
    values = {}
    for module in (producer, candidate, sys.modules[__name__]):
        for name, value in vars(module).items():
            if isinstance(value, types.FunctionType) and value.__module__ == module.__name__:
                values[module.__name__ + ':' + name] = value
    for name, value in vars(producer.ParentCapture).items():
        if isinstance(value, types.FunctionType):
            values[producer.__name__ + ':ParentCapture.' + name] = value
    return values


def reviewed_inputs(root=None):
    """Return (prepared receipt, native CASES, (declaration, successor)s)."""
    predecessor.reviewed_inputs(root)  # Preserve original immutable source lineage.
    root = Path(root or Path(__file__).resolve().parents[2]).resolve()
    try:
        raw = (root / 'peaso/checks' / RECEIPT).read_bytes()
        if predecessor._hash(raw) != RECEIPT_SHA256:
            raise RuntimeError('runtime successor receipt changed')
        receipt = json.loads(raw, object_pairs_hook=predecessor._pairs)
        expected_schema = {'schema': producer.SCHEMA, 'metadata_key': producer.METADATA_KEY,
                           'adapter': producer.ADAPTER, 'kinds': list(producer.KINDS),
                           'subscription_version': producer.SUBSCRIPTION_VERSION,
                           'declarations': candidate.DECLARATIONS}
        if (receipt['schema_version'] != 1 or receipt['ids'] != list(candidate.IDS)
                or not candidate._same(receipt['schema'], expected_schema)):
            raise RuntimeError('runtime successor metadata changed')
        compiled = {}
        for relative, expected in receipt['sources'].items():
            path = (root / relative).resolve()
            if not path.is_relative_to(root):
                raise RuntimeError('runtime successor source escaped repository')
            source = path.read_bytes()
            if relative == receipt['helper_path']:
                source = predecessor._self_source(source)
            if predecessor._hash(source) != expected:
                raise RuntimeError('runtime successor source changed')
            compiled[relative] = predecessor._compiled(source, str(path))
        for fixture in receipt['fixtures']:
            path = (root / fixture['path']).resolve()
            if not path.is_relative_to(root) or predecessor._hash(path.read_bytes()) != fixture['sha256']:
                raise RuntimeError('runtime successor fixture changed')
        functions = _runtime()
        if (set(functions) != set(receipt['functions']) or set(functions) != set(_ORIGINALS)
                or producer.ParentCapture is not _PARENT_CAPTURE
                or producer.ParentCapture.__bases__ != (producer.native.Capture,)
                or candidate.runtime is not producer or candidate.native is not producer.native
                or candidate.original is not predecessor.candidate):
            raise RuntimeError('runtime successor helper identity changed')
        for name, function in functions.items():
            definition = receipt['functions'][name]
            module = sys.modules.get(function.__module__)
            trusted = compiled[definition['path']].get(definition['qualname'], [])
            closure = predecessor._bindings(function)
            if (function is not _ORIGINALS[name] or module is None or function.__globals__ is not vars(module)
                    or function.__qualname__ != definition['qualname']
                    or predecessor._hash(inspect.getsource(function).encode()) != definition['source_sha256']
                    or len(trusted) != 1 or predecessor._code(function.__code__) != predecessor._code(trusted[0])
                    or json.dumps(function.__defaults__, sort_keys=True) != json.dumps(definition['defaults'], sort_keys=True)
                    or json.dumps(function.__kwdefaults__, sort_keys=True) != json.dumps(definition['kwdefaults'], sort_keys=True)
                    or closure not in ({}, {'__class__': producer.ParentCapture})):
                raise RuntimeError('runtime successor executing callable changed')
        cases = json.loads((root / 'peaso/checks' / CASES_FILE).read_bytes(), object_pairs_hook=predecessor._pairs)
        if set(cases) != set(candidate.IDS):
            raise RuntimeError('runtime successor CASES identities changed')
        declarations = []
        for spec, function in zip(candidate.DECLARATIONS, (candidate.nsp, candidate.query)):
            case = cases[spec['id']]
            for branch in ('pass', 'fail', 'unknown'):
                if function(deepcopy(case[branch]), deepcopy(case[branch + '_index']))[0] != branch.upper():
                    raise RuntimeError('runtime successor native decision changed')
            for branch in ('missing', 'malformed'):
                if function(deepcopy(case[branch]), deepcopy(case['index']))[0] != 'UNKNOWN':
                    raise RuntimeError('runtime successor unavailable decision changed')
            if 'not_applicable' in case and function(deepcopy(case['not_applicable']), deepcopy(case['not_applicable_index']))[0] != 'NOT_APPLICABLE':
                raise RuntimeError('runtime successor absent Query decision changed')
            declarations.append((deepcopy(spec), function))
        return receipt, cases, declarations
    except RuntimeError:
        raise
    except (OSError, KeyError, ValueError, TypeError, AttributeError, IndexError):
        raise RuntimeError('malformed runtime successor inputs') from None


_ORIGINALS = _runtime()
_PARENT_CAPTURE = producer.ParentCapture
