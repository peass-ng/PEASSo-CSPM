"""Transactional, source-bound admission of three Workbench declarations.

Accepted proposal bytes remain unchanged. The separate runtime declaration
records root's explicit metadata decision; no numbered mapping is installed.
"""
import ast
import builtins
import copy
from copy import deepcopy
import hashlib
import inspect
import json
from pathlib import Path
import re
import sys
import types

from . import facts
from . import gcp_workbench_head3_proposal_20261020 as candidate
from peaso.collectors import gcp_workbench_head3_projection_20261020 as projection
from peaso.collectors import gcp

RECEIPT = 'gcp_workbench_head3_admission_20261020.json'
RECEIPT_SHA256 = '2315a7a8e7d7d28ac87953852e91fcf8cc63e42de85fecf7d10f9a8a01e1ec13'
CHECK_IDS = (
    'gcp.review.workbench.terminal_access_disabled',
    'gcp.review.workbench.file_download_disabled',
    'gcp.review.workbench.auto_upgrade_schedule_declared',
)
DECLARATIONS = tuple(json.loads((Path(__file__).with_name(
    'gcp_workbench_head3_admission_declarations_20261020.json')).read_bytes())['declarations'])


def _self(raw):
    value, count = re.subn(rb"(?m)^RECEIPT_SHA256 = '[0-9a-f]{64}'$",
                          b"RECEIPT_SHA256 = '" + b'0' * 64 + b"'", raw)
    if count != 1:
        raise RuntimeError('Workbench admission self binding changed')
    return value


def _compiled_functions(raw, filename):
    """Compile current immutable source on this interpreter; no code execution."""
    records = {}

    def visit(node, prefix=''):
        child_prefix = prefix
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            name = prefix + node.name
            line = min([node.lineno] + [d.lineno for d in node.decorator_list])
            records[(node.name, line)] = name
            child_prefix = name + '.<locals>.'
        elif isinstance(node, ast.ClassDef):
            child_prefix = prefix + node.name + '.'
        for child in ast.iter_child_nodes(node):
            visit(child, child_prefix)

    visit(ast.parse(raw))
    output = {}

    def walk(code):
        key = (code.co_name, code.co_firstlineno)
        if key in records:
            output[records[key]] = code
        for value in code.co_consts:
            if isinstance(value, types.CodeType):
                walk(value)

    walk(compile(raw, filename, 'exec', dont_inherit=True, optimize=sys.flags.optimize))
    return output


def _runtime():
    output = {}
    for module in (sys.modules[__name__], candidate, projection):
        for name, function in vars(module).items():
            if isinstance(function, types.FunctionType) and function.__globals__ is vars(module):
                output[module.__name__ + ':' + name] = function
    for name in ('guard', 'get', 'complete_items', '_complete_items', 'memoized', 'list_of_objects'):
        output[facts.__name__ + ':' + name] = getattr(facts, name)
    output[facts.__name__ + ':MemoIndex.__init__'] = facts.MemoIndex.__init__
    for name in ('scope_jobs', 'pages', 'envelope', 'collect'):
        function = getattr(gcp.GCPCollector, name)
        output[function.__module__ + ':' + function.__qualname__] = function
    return output


def _lookup(qualified):
    module, name = qualified.split(':', 1)
    value = sys.modules[module]
    for part in name.split('.'):
        value = getattr(value, part)
    return value


def _constants():
    return {
        'ids': list(CHECK_IDS), 'declarations': DECLARATIONS,
        'candidate_prefix': candidate.PREFIX, 'candidate_kind': candidate.KIND,
        'candidate_states': sorted(candidate.STATES), 'candidate_key': candidate.KEY,
        'projection_key': projection.KEY, 'projection_max': projection.MAX_SCHEDULE_BYTES,
        'projection_fields': projection._FIELDS,
        'projection_months': projection._MONTHS, 'projection_days': projection._DAYS,
    }


def _verify_runtime(root, receipt):
    for module, name, original in _IMPORTS:
        if getattr(module, name) is not original:
            raise RuntimeError('Workbench native import binding changed')
    for function, code in _IMPORT_CODES:
        if function.__code__ is not code:
            raise RuntimeError('Workbench native imported callable changed')
    current = _runtime()
    if set(current) != set(_ORIGINALS) or set(current) != set(receipt['functions']):
        raise RuntimeError('Workbench native callable set changed')
    compiled = {}
    for qualified, original in _ORIGINALS.items():
        function = current[qualified]
        row = receipt['functions'][qualified]
        if (function is not original or _lookup(qualified) is not original
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
                   or EVALUATORS[cid] is not _ORIGINALS[__name__ + ':' + cid.rsplit('.', 1)[1]]
                   for cid in CHECK_IDS)):
        raise RuntimeError('Workbench native declaration or scalar grammar changed')


def reviewed_inputs(root=None, *, verify_cases=True):
    root = Path(root or Path(__file__).resolve().parents[2]).resolve()
    raw = (root / 'peaso/checks' / RECEIPT).read_bytes()
    if hashlib.sha256(raw).hexdigest() != RECEIPT_SHA256:
        raise RuntimeError('Workbench native admission receipt changed')
    receipt = json.loads(raw)
    if receipt.get('schema') != 'workbench-head3-runtime-admission-v1' or tuple(receipt['check_ids']) != CHECK_IDS:
        raise RuntimeError('Workbench native admission identities changed')
    for name, digest in receipt['sources'].items():
        path = (root / name).resolve()
        if not path.is_relative_to(root / 'peaso'):
            raise RuntimeError('Workbench native source escaped package')
        data = path.read_bytes()
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


def _checked(cid, item, index):
    try:
        from peaso.source_attestation_mode import prove_once
        prove_once(reviewed_inputs, verify_cases=False)
        return _CANDIDATE_FUNCTIONS[cid](item, index)
    except Exception:
        return 'UNKNOWN', {'observed': 'The reviewed Workbench configuration predicate or its source bindings were unavailable.'}


def terminal_access_disabled(item, index):
    return _checked(CHECK_IDS[0], item, index)


def file_download_disabled(item, index):
    return _checked(CHECK_IDS[1], item, index)


def auto_upgrade_schedule_declared(item, index):
    return _checked(CHECK_IDS[2], item, index)


def _signature(check):
    return (check.id, check.provider, check.category, check.kind, check.title, check.severity,
            check.control, check.remediation, check.target, tuple(check.declared_dependencies),
            check.allow_incomplete_failure, tuple(check.empty_applicability_dependencies))


def install_bundle():
    from . import CHECKS, CHECK_ALIASES, register
    from .fixtures import CASES
    receipt, cases = reviewed_inputs()
    if tuple(row['id'] for row in DECLARATIONS) != CHECK_IDS:
        raise RuntimeError('Workbench registration declaration set changed')
    for row in DECLARATIONS:
        cid = row['id']
        matches = [check for check in CHECKS if check.id == cid]
        expected = (cid, 'gcp', 'hardening', 'workbench_instance', row['title'], row['severity'],
                    'security_configuration', row['remediation'], 'resource', ('workbench_instance',), False, ())
        if (cid in CHECK_ALIASES or cid in CHECK_ALIASES.values() or len(matches) > 1
                or matches and (_signature(matches[0]) != expected
                    or inspect.unwrap(matches[0].evaluate) is not EVALUATORS[cid])):
            raise RuntimeError('Workbench registration collision')
        if cid in CASES and CASES[cid] != cases[cid]:
            raise RuntimeError('Workbench registration CASES collision')
    before = tuple(CHECKS)
    old_cases = {cid: CASES[cid] for cid in CHECK_IDS if cid in CASES}
    prior_cases = {cid: value for cid, value in CASES.items() if cid not in CHECK_IDS}
    aliases = dict(CHECK_ALIASES)
    try:
        for row in DECLARATIONS:
            cid = row['id']
            if not any(check.id == cid for check in CHECKS):
                register(cid, 'gcp', 'hardening', 'workbench_instance', row['title'], row['severity'],
                         'security_configuration', row['remediation'], dependencies=['workbench_instance'])(EVALUATORS[cid])
            if cid not in CASES:
                CASES[cid] = deepcopy(cases[cid])
        retained = tuple(check for check in CHECKS if check.id not in CHECK_IDS)
        if (retained != tuple(check for check in before if check.id not in CHECK_IDS)
                or any(actual is not prior for actual, prior in zip(retained,
                    (check for check in before if check.id not in CHECK_IDS)))
                or dict(CHECK_ALIASES) != aliases
                or any(CASES.get(cid) is not value for cid, value in prior_cases.items())):
            raise RuntimeError('Workbench registration changed a predecessor')
    except Exception:
        CHECKS[:] = before
        CHECK_ALIASES.clear()
        CHECK_ALIASES.update(aliases)
        for cid in CHECK_IDS:
            if cid in old_cases:
                CASES[cid] = old_cases[cid]
            else:
                CASES.pop(cid, None)
        raise


EVALUATORS = dict(zip(CHECK_IDS, (terminal_access_disabled, file_download_disabled,
                                auto_upgrade_schedule_declared)))
_CANDIDATE_FUNCTIONS = dict(candidate.EVALUATORS)
_IMPORTS = (
    (candidate, 're', re), (projection, 're', re), (projection, 'deepcopy', deepcopy),
    (candidate, 'Unavailable', facts.Unavailable), (candidate, 'get', facts.get),
    (candidate, 'guard', facts.guard), (candidate, 'complete_items', facts.complete_items),
    (candidate, 'supported_schedule', projection.supported_schedule),
    (sys.modules[__name__], 'candidate', candidate), (sys.modules[__name__], 'projection', projection),
    (sys.modules[__name__], 'facts', facts), (sys.modules[__name__], 'gcp', gcp),
    (sys.modules[__name__], 'deepcopy', deepcopy), (facts, 'Unavailable', facts.Unavailable),
    (facts, 'MemoIndex', facts.MemoIndex), (copy, 'deepcopy', deepcopy),
    (re, 'fullmatch', re.fullmatch), (re, 'escape', re.escape), (re, 'subn', re.subn),
    (json, 'loads', json.loads), (json, 'dumps', json.dumps), (ast, 'parse', ast.parse),
    (builtins, 'compile', builtins.compile), (hashlib, 'sha256', hashlib.sha256),
)
_IMPORT_CODES = tuple((value, value.__code__) for _, _, value in _IMPORTS if isinstance(value, types.FunctionType))
_ORIGINALS = _runtime()
_CODES = {key: value.__code__ for key, value in _ORIGINALS.items()}
_DEFAULTS = {key: value.__defaults__ for key, value in _ORIGINALS.items()}
_KWDEFAULTS = {key: value.__kwdefaults__ for key, value in _ORIGINALS.items()}
_CLOSURES = {key: value.__closure__ for key, value in _ORIGINALS.items()}
_CELLS = {key: tuple(cell.cell_contents for cell in value.__closure__ or ()) for key, value in _ORIGINALS.items()}
