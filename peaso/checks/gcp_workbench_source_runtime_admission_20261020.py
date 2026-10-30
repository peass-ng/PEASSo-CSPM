"""Atomic admission of the sealed Workbench source consumer with package-only guards."""
from copy import deepcopy
import hashlib
import importlib
import inspect
import json
import sys
from pathlib import Path

RECEIPT_SHA256 = 'fe6b2cc40cf9ecdf07e2e556b90a1658ea6e5b454061f87635e81022d655b39e'
CHECK_IDS = ('gcp.review.workbench.selected_referenced_source_secret_indicators_20261020',)


def reviewed_inputs(root=None):
    root = Path(root or Path(__file__).resolve().parents[2]).resolve()
    raw = (root / 'peaso/checks/gcp_workbench_source_runtime_admission_20261020.json').read_bytes()
    if hashlib.sha256(raw).hexdigest() != RECEIPT_SHA256:
        raise RuntimeError('Workbench source admission receipt changed')
    receipt = json.loads(raw)
    if (receipt.get('schema_version') != 1 or receipt.get('module') != 'gcp_workbench_source_runtime_consumer_20261020'
            or tuple(row['id'] for row in receipt['checks']) != CHECK_IDS):
        raise RuntimeError('Workbench source admission identities changed')
    if any(not name.startswith(('peaso/checks/', 'peaso/collectors/', 'peaso/secret_scanning.py')) for name in receipt['sources']):
        raise RuntimeError('Workbench source admission has non-package dependency')
    for name, digest in receipt['sources'].items():
        path = (root / name).resolve()
        if not path.is_relative_to(root) or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise RuntimeError('Workbench source reviewed source changed')
    fixture = receipt['fixture']; path = (root / fixture['path']).resolve()
    if not path.is_relative_to(root / 'peaso/checks') or hashlib.sha256(path.read_bytes()).hexdigest() != fixture['sha256']:
        raise RuntimeError('Workbench source native fixture changed')
    cases = json.loads(path.read_text()); declarations = []
    if set(cases) != {row['id'] for row in receipt['checks']}:
        raise RuntimeError('Workbench source native identities changed')
    module = importlib.import_module('.' + receipt['module'], __package__)
    from peaso.collectors import gcp_workbench_source_runtime_20261020 as runtime
    from peaso.collectors import gcp_workbench_referenced_source_20261020 as producer
    if (runtime.source is not producer or module.source is not producer
            or runtime._Grant is not _RUNTIME_CLASS or runtime._SEAL is not _RUNTIME_SEAL):
        raise RuntimeError('Workbench source runtime binding changed')
    if tuple(row['id'] for row in module.DECLARATIONS) != CHECK_IDS:
        raise RuntimeError('Workbench source metadata changed')
    from .k8s_selected_metadata_runtime_admission_20261020 import proof
    for qualified, row in receipt['runtime_functions'].items():
        module_name, name = qualified.split(':')
        owner = importlib.import_module(module_name)
        function = owner
        for part in name.split('.'):
            function = getattr(function, part)
        path = root / row['path']
        compiled = [(record, code) for record, code in proof._compiled_source(path.read_bytes(), str(path), sys.flags.optimize) if record['qualname'] == name]
        if (len(compiled) != 1 or function.__module__ != module_name
                or inspect.unwrap(function) is not function or function.__globals__ is not vars(owner)
                or hashlib.sha256(inspect.getsource(function).encode()).hexdigest() != row['sha256']
                or compiled[0][0]['source_sha256'] != row['sha256']
                or proof._code(function.__code__) != proof._code(compiled[0][1])):
            raise RuntimeError('Workbench source executing runtime callable changed')
    for row in receipt['checks']:
        function_name = row['evaluate'].rsplit(':', 1)[1]
        function = getattr(module, function_name)
        metadata, = [d for d in module.DECLARATIONS if d['id'] == row['id']]
        if (function is not getattr(module, function_name) or function is not inspect.unwrap(function)
                or function.__name__ != function_name or function.__module__ != module.__name__
                or any(metadata.get(key) != row.get(key) for key in metadata)
                or function.__globals__.get('_evaluate') is not module._evaluate
                or hashlib.sha256(inspect.getsource(function).encode()).hexdigest() != row['predicate_sha256']
                or hashlib.sha256(inspect.getsource(module._evaluate).encode()).hexdigest() != row['reachable_helper_sha256']):
            raise RuntimeError('Workbench source evaluator identity changed')
        case = cases[row['id']]
        if not {'pass','pass_index','fail','fail_index','unknown','unknown_index','missing','malformed','index'} <= set(case):
            raise RuntimeError('Workbench source native branches missing')
        for branch in ('pass', 'fail', 'unknown'):
            if function(case[branch], case[branch + '_index'])[0] != branch.upper():
                raise RuntimeError('Workbench source native branch changed')
        for branch in ('missing', 'malformed'):
            if function(case[branch], case['index'])[0] != 'UNKNOWN':
                raise RuntimeError('Workbench source malformed native branch changed')
        declarations.append((metadata, function))
    return receipt, cases, declarations


def _signature(check):
    return (check.provider, check.category, check.kind, check.title, check.severity, check.control,
        check.remediation, tuple(check.dependencies), check.allow_incomplete_failure)


def install():
    from . import CHECKS, register
    from .fixtures import CASES
    receipt, cases, declarations = reviewed_inputs()
    for metadata, function in declarations:
        ident = metadata['id']; matches = [c for c in CHECKS if c.id == ident]
        expected = ('gcp', metadata['category'], metadata['kind'], metadata['title'], metadata['severity'],
            'security_configuration', metadata['remediation'], tuple(metadata['dependencies']), True)
        if len(matches) > 1 or matches and (inspect.unwrap(matches[0].evaluate) is not function or _signature(matches[0]) != expected):
            raise RuntimeError('Workbench source registration collision')
        if ident in CASES and CASES[ident] != cases[ident]:
            raise RuntimeError('Workbench source native fixture collision')
    before = tuple(CHECKS); previous = {ident: deepcopy(CASES[ident]) for ident in cases if ident in CASES}
    try:
        for metadata, function in declarations:
            ident = metadata['id']
            if not any(c.id == ident for c in CHECKS):
                register(ident, 'gcp', metadata['category'], metadata['kind'], metadata['title'], metadata['severity'],
                    'security_configuration', metadata['remediation'], dependencies=metadata['dependencies'],
                    allow_incomplete_failure=True)(function)
            CASES[ident] = deepcopy(cases[ident])
    except Exception:
        CHECKS[:] = before
        for ident in cases:
            if ident in previous: CASES[ident] = previous[ident]
            else: CASES.pop(ident, None)
        raise

from peaso.collectors import gcp_workbench_source_runtime_20261020 as _runtime
_RUNTIME_CLASS, _RUNTIME_SEAL = _runtime._Grant, _runtime._SEAL
