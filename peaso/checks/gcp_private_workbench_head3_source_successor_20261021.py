"""Finite private successor for unchanged Workbench head-three native admission.

The old Workbench guard and receipts remain intact. Only its reviewed_inputs
alias is replaced; live method proof compiles the actual current source.
"""
from copy import deepcopy
import ast
import builtins
import importlib.util
import hashlib
import inspect
import json
from pathlib import Path
import re
import sys
from types import CodeType, FunctionType

from . import gcp_workbench_head3_admission_20261020 as original
from .gcp_workbench_head3_admission_20261020 import (
    _runtime, _lookup, _compiled_functions, _constants, _self,
    _ORIGINALS, _CODES, _DEFAULTS, _KWDEFAULTS, _CLOSURES, _CELLS,
    _IMPORTS, _IMPORT_CODES, _CANDIDATE_FUNCTIONS, candidate, EVALUATORS, CHECK_IDS,
)
from peaso import private_secret_source_epoch_20261021 as private_source
from peaso import rawv2_private_source_successor_20261021 as raw_source
from peaso import gcp_private_source_successor_20261021 as gcp_source

RECEIPT = 'gcp_cloudrun_job_image_workbench_source_successor_20261020.json'
RECEIPT_SHA256 = '2ed55a5426abb32446e4a182e2542fb4754075cb99256c71cb40d4071ac0ebda'
PRIVATE_RECEIPT = 'gcp_private_workbench_head3_source_successor_20261021.json'
PRIVATE_RECEIPT_SHA256 = 'cc785adfc95ca2a87ef32c58c8db86ec4e61277d2376e08bc3103f167b6bed22'


def _private_self(root):
    path = root / 'peaso/checks' / PRIVATE_RECEIPT
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != PRIVATE_RECEIPT_SHA256:
        raise RuntimeError('Private Workbench receipt changed')
    receipt = json.loads(raw)
    own = Path(__file__).resolve()
    if own != (root / 'peaso/checks/gcp_private_workbench_head3_source_successor_20261021.py').resolve():
        raise RuntimeError('Private Workbench module location changed')
    normalized, count = re.subn(
        rb"(?m)^PRIVATE_RECEIPT_SHA256 = '[0-9a-f]{64}'$",
        b"PRIVATE_RECEIPT_SHA256 = '" + b'0' * 64 + b"'", own.read_bytes())
    if count != 1 or hashlib.sha256(normalized).hexdigest() != receipt['normalized_source_sha256']:
        raise RuntimeError('Private Workbench module source changed')
    pins = {
        'peaso/private_secret_source_epoch_20261021.py': (private_source, 'common_source_sha256'),
        'peaso/private_secret_source_epoch_20261021.json': (None, 'common_receipt_sha256'),
        'peaso/rawv2_private_source_successor_20261021.py': (raw_source, 'raw_source_sha256'),
        'peaso/checks/rawv2_private_source_successor_20261021.json': (None, 'raw_receipt_sha256'),
        'peaso/gcp_private_source_successor_20261021.py': (gcp_source, 'gcp_source_sha256'),
        'peaso/checks/gcp_private_source_successor_20261021.json': (None, 'gcp_receipt_sha256'),
        'peaso/checks/gcp_cloudrun_job_image_workbench_source_successor_20261020.py': (None, 'canonical_source_sha256'),
        'peaso/checks/gcp_cloudrun_job_image_workbench_source_successor_20261020.json': (None, 'canonical_receipt_sha256'),
    }
    for name, (module, key) in pins.items():
        file = (root / name).resolve()
        data = file.read_bytes()
        if (name == 'peaso/rawv2_private_source_successor_20261021.py'
                and hashlib.sha256(data).hexdigest() != receipt[key]):
            from . import private_secret_shared_source_successor_20261021 as current
            current._private_self()
            data = current.rawv2_bootstrap_source(data, receipt[key], root)
        if not file.is_relative_to(root / 'peaso') or hashlib.sha256(data).hexdigest() != receipt[key]:
            raise RuntimeError('Private Workbench dependency changed: ' + name)
        if module is not None and (sys.modules.get(module.__name__) is not module
                or Path(module.__file__).resolve() != file):
            raise RuntimeError('Private Workbench dependency binding changed: ' + name)
    if private_source._RECEIPT_SHA256 != receipt['common_receipt_sha256']:
        raise RuntimeError('Common receipt binding changed')
    if raw_source.RECEIPT_SHA256 != receipt['raw_receipt_sha256']:
        raise RuntimeError('Raw receipt binding changed')
    if gcp_source.PRIVATE_RECEIPT_SHA256 != receipt['gcp_receipt_sha256']:
        raise RuntimeError('GCP receipt binding changed')
    if original.RECEIPT_SHA256 != receipt['workbench_receipt_sha256']:
        raise RuntimeError('Workbench receipt binding changed')
    if (sys.modules.get(original.__name__) is not original
            or Path(original.__file__).resolve() != (root / 'peaso/checks/gcp_workbench_head3_admission_20261020.py').resolve()):
        raise RuntimeError('Workbench original module binding changed')
    for name in ('_runtime', '_lookup', '_compiled_functions', '_constants', '_self',
                 '_ORIGINALS', '_CODES', '_DEFAULTS', '_KWDEFAULTS', '_CLOSURES', '_CELLS',
                 '_IMPORTS', '_IMPORT_CODES', '_CANDIDATE_FUNCTIONS', 'candidate',
                 'EVALUATORS', 'CHECK_IDS'):
        if globals()[name] is not vars(original)[name]:
            raise RuntimeError('Workbench original import changed: ' + name)
    if __name__ != 'peaso.checks.gcp_private_workbench_head3_source_successor_20261021' or __package__ != 'peaso.checks':
        raise RuntimeError('Private Workbench namespace metadata changed')
    namespace = vars(sys.modules[__name__])
    tree = ast.parse(own.read_bytes())
    nodes = {node.name: node for node in tree.body if isinstance(node, ast.FunctionDef)}
    actual = {name: value for name, value in namespace.items()
              if type(value) is FunctionType and value.__module__ == __name__}
    if set(actual) != set(receipt['functions']) or set(actual) != set(nodes):
        raise RuntimeError('Private Workbench callable roster changed')
    filename = next(iter(actual.values())).__code__.co_filename
    if Path(filename).resolve() != own:
        raise RuntimeError('Private Workbench callable source location changed')
    compiled_module = compile(own.read_bytes(), filename, 'exec', dont_inherit=True, optimize=sys.flags.optimize)
    compiled = {code.co_name: code for code in compiled_module.co_consts if type(code) is CodeType}
    constants = private_source._constants(tree, str(own))
    import_names = set()
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                binding = alias.asname or alias.name.split('.')[0]
                expected = sys.modules.get(alias.name if alias.asname else alias.name.split('.')[0])
                if expected is None or namespace.get(binding) is not expected:
                    raise RuntimeError('Private Workbench import binding changed: ' + binding)
                import_names.add(binding)
        elif isinstance(node, ast.ImportFrom):
            module_name = importlib.util.resolve_name('.' * node.level + (node.module or ''), __package__) if node.level else node.module
            imported = sys.modules.get(module_name)
            for alias in node.names:
                binding = alias.asname or alias.name
                expected = getattr(imported, alias.name, None) if imported is not None else None
                if expected is None or namespace.get(binding) is not expected:
                    raise RuntimeError('Private Workbench from-import binding changed: ' + binding)
                import_names.add(binding)
    for key, value in constants.items():
        if not private_source._same(namespace.get(key), value):
            raise RuntimeError('Private Workbench literal binding changed: ' + key)
    for name, function in actual.items():
        if (function.__globals__ is not namespace or function.__qualname__ != name
                or function.__closure__ is not None
                or not private_source._code_equal(function.__code__, compiled[name])):
            raise RuntimeError('Private Workbench live function changed: ' + name)
        private_source._check_defaults(function, nodes[name], constants, filename)
        for key in private_source._globals_used(function.__code__):
            if key in import_names or key in nodes or key in constants or key in ('__name__', '__file__', '__package__'):
                continue
            if key in namespace or not hasattr(builtins, key):
                raise RuntimeError('Private Workbench undeclared global binding: ' + key)
    private_source.source_rows()
    return receipt


def _historical_source(name, current, expected, root):
    if name == raw_source.SCANNER:
        return raw_source.source_bytes(name, current, expected, root)
    row = private_source.source_rows().get(name)
    if row is None or hashlib.sha256(current).hexdigest() == expected:
        return current
    if expected != row['before_sha256']:
        raise RuntimeError('Unreviewed Workbench private source')
    return private_source.predecessor_bytes(name, current, expected, root)


def _reviewed_delta(root):
    raw = (root / 'peaso/checks' / RECEIPT).read_bytes()
    if hashlib.sha256(raw).hexdigest() != RECEIPT_SHA256:
        raise RuntimeError('Job image Workbench successor receipt changed')
    receipt = json.loads(raw)
    for name, expected in receipt['sources'].items():
        data = (root / name).read_bytes()
        if name.endswith('gcp_cloudrun_job_image_workbench_source_successor_20261020.py'):
            data = original._self(data)
        if hashlib.sha256(data).hexdigest() != expected:
            raise RuntimeError('Job image Workbench successor source changed')
    delta_raw = (root / receipt['collector_delta']).read_bytes()
    if hashlib.sha256(delta_raw).hexdigest() != gcp_source.RECEIPT_SHA256:
        raise RuntimeError('Job image Workbench collector delta receipt changed')
    delta = json.loads(delta_raw)
    private_row = private_source.source_rows()['peaso/collectors/gcp.py']
    if (private_row['before_sha256'] != delta['collector_after_sha256']
            or gcp_source.reviewed_source._receipt()['sources']['peaso/collectors/gcp.py']['epoch_after_sha256'] != private_row['after_sha256']):
        raise RuntimeError('Private Workbench collector epoch mismatch')
    current = gcp_source.reviewed_source.predecessor_bytes('peaso/collectors/gcp.py',
        (root / 'peaso/collectors/gcp.py').read_bytes(), private_row['before_sha256'], root)
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
        from . import azure_function_package_shared_successor_20261020 as shared
        projected = shared.current_producer_row(function, dict(path=row['path'], qualname=row['qualname'], sha256=row['body_sha256']), root)
        row = dict(row, body_sha256=projected['sha256'])
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
    _private_self(root)
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
        data = delta if name == 'peaso/collectors/gcp.py' else _historical_source(name, path.read_bytes(), digest, root)
        if name == receipt['admission_path']:
            data = original._self(data)
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
