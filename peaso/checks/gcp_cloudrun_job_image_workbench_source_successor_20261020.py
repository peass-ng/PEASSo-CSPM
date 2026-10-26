"""Exact Job collector source successor for unchanged Workbench predicates.

Original declarations, wrappers, callable identities, CASES and receipts remain.
Only the reviewed_inputs alias and three reversed collector additions differ.
"""
from copy import deepcopy
import hashlib
import inspect
import json
from pathlib import Path
import re
import sys
from . import gcp_workbench_head3_admission_20261020 as original
from .gcp_workbench_head3_admission_20261020 import (
    _runtime, _lookup, _compiled_functions, _constants, _self,
    _ORIGINALS, _CODES, _DEFAULTS, _KWDEFAULTS, _CLOSURES, _CELLS,
    _IMPORTS, _IMPORT_CODES, _CANDIDATE_FUNCTIONS, candidate, EVALUATORS, CHECK_IDS,
)
RECEIPT = 'gcp_cloudrun_job_image_workbench_source_successor_20261020.json'
RECEIPT_SHA256 = '2ed55a5426abb32446e4a182e2542fb4754075cb99256c71cb40d4071ac0ebda'


def _reviewed_delta(root):
    raw = (root / 'peaso/checks' / RECEIPT).read_bytes()
    if hashlib.sha256(raw).hexdigest() != RECEIPT_SHA256:
        raise RuntimeError('Job image Workbench successor receipt changed')
    receipt = json.loads(raw)
    for name, expected in receipt['sources'].items():
        data = (root / name).read_bytes()
        if name.endswith('gcp_cloudrun_job_image_workbench_source_successor_20261020.py'):
            data = _self(data)
        if hashlib.sha256(data).hexdigest() != expected:
            raise RuntimeError('Job image Workbench successor source changed')
    delta = json.loads((root / receipt['collector_delta']).read_bytes())
    current = (root / 'peaso/collectors/gcp.py').read_bytes()
    if hashlib.sha256(current).hexdigest() != delta['collector_after_sha256']:
        raise RuntimeError('Job image Workbench collector source changed')
    for edit in reversed(delta['edits']):
        before, after = edit['before'].encode(), edit['after'].encode()
        if current.count(after) != 1:
            raise RuntimeError('Job image Workbench collector exact delta changed')
        current = current.replace(after, before, 1)
    if hashlib.sha256(current).hexdigest() != delta['collector_before_sha256']:
        raise RuntimeError('Job image Workbench collector predecessor changed')
    return current


def _verify_runtime(root, receipt):
    for module, name, expected_import in _IMPORTS:
        if getattr(module, name) is not expected_import:
            raise RuntimeError('Workbench native import binding changed')
    for function, code in _IMPORT_CODES:
        if function.__code__ is not code:
            raise RuntimeError('Workbench native imported callable changed')
    current = _runtime()
    alias = original.__name__ + ":reviewed_inputs"
    if _lookup(alias) is not reviewed_inputs:
        raise RuntimeError("Job image Workbench admission alias changed")
    current[alias] = reviewed_inputs
    if set(current) != set(_ORIGINALS) or set(current) != set(receipt['functions']):
        raise RuntimeError('Workbench native callable set changed')
    compiled = {}
    for qualified, historical in _ORIGINALS.items():
        function = current[qualified]
        looked_up = _lookup(qualified)
        if qualified == alias:
            function = looked_up = original._ORIGINALS[qualified]
        row = receipt['functions'][qualified]
        if (function is not historical or looked_up is not historical
                or inspect.unwrap(function) is not function
                or function.__globals__ is not vars(sys.modules[function.__module__])
                or function.__code__ is not _CODES[qualified]
                or function.__defaults__ is not _DEFAULTS[qualified]
                or function.__kwdefaults__ is not _KWDEFAULTS[qualified]
                or function.__closure__ is not _CLOSURES[qualified]):
            raise RuntimeError('Workbench native executing function identity changed')
        cells = tuple(cell.cell_contents for cell in function.__closure__ or ())
        if len(cells) != len(_CELLS[qualified]) or any(
                value is not prior for value, prior in zip(cells, _CELLS[qualified])):
            raise RuntimeError('Workbench native closure binding changed')
        path = (root / row['path']).resolve()
        if row['path'] not in compiled:
            compiled[row['path']] = _compiled_functions(path.read_bytes(), function.__code__.co_filename)
        if (function.__code__ != compiled[row['path']].get(function.__qualname__)
                or hashlib.sha256(inspect.getsource(function).encode()).hexdigest() != row['body_sha256']
                or function.__module__ != row['module'] or function.__qualname__ != row['qualname']):
            raise RuntimeError('Workbench native executing function body changed')
    if (json.dumps(_constants(), sort_keys=True) != json.dumps(receipt['constants'], sort_keys=True)
            or tuple(candidate.EVALUATORS) != CHECK_IDS
            or tuple(EVALUATORS) != CHECK_IDS or tuple(_CANDIDATE_FUNCTIONS) != CHECK_IDS
            or any(candidate.EVALUATORS[cid] is not _CANDIDATE_FUNCTIONS[cid]
                   or _CANDIDATE_FUNCTIONS[cid] is not _ORIGINALS[candidate.__name__ + ':' + cid.rsplit('.', 1)[1]]
                   or EVALUATORS[cid] is not _ORIGINALS[original.__name__ + ':' + cid.rsplit('.', 1)[1]]
                   for cid in CHECK_IDS)):
        raise RuntimeError('Workbench native declaration or scalar grammar changed')


def reviewed_inputs(root=None, *, verify_cases=True):
    root = Path(root or Path(__file__).resolve().parents[2]).resolve()
    delta = _reviewed_delta(root)
    raw = (root / 'peaso/checks' / original.RECEIPT).read_bytes()
    if hashlib.sha256(raw).hexdigest() != original.RECEIPT_SHA256:
        raise RuntimeError('Workbench native admission receipt changed')
    receipt = json.loads(raw)
    if receipt.get('schema') != 'workbench-head3-runtime-admission-v1' or tuple(receipt['check_ids']) != CHECK_IDS:
        raise RuntimeError('Workbench native admission identities changed')
    for name, digest in receipt['sources'].items():
        path = (root / name).resolve()
        if not path.is_relative_to(root / 'peaso'):
            raise RuntimeError('Workbench native source escaped package')
        data = delta if name == 'peaso/collectors/gcp.py' else path.read_bytes()
        if name == receipt['admission_path']:
            data = _self(data)
        if hashlib.sha256(data).hexdigest() != digest:
            raise RuntimeError('Workbench native reviewed source changed')
    _verify_runtime(root, receipt)
    cases = json.loads((root / receipt['cases_path']).read_bytes())
    if set(cases) != set(CHECK_IDS):
        raise RuntimeError('Workbench native CASES identities changed')
    if verify_cases:
        for cid in CHECK_IDS:
            case = cases[cid]
            for branch, expected in (('pass', 'PASS'), ('fail', 'FAIL'), ('unknown', 'UNKNOWN'),
                                     ('deleted', 'NOT_APPLICABLE'), ('missing', 'UNKNOWN'), ('malformed', 'UNKNOWN')):
                actual = _CANDIDATE_FUNCTIONS[cid](deepcopy(case[branch]),
                    deepcopy(case.get(branch + '_index', case['index'])))[0]
                if actual != expected:
                    raise RuntimeError('Workbench native CASES branch changed')
    return receipt, cases
