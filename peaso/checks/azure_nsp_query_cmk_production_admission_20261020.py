"""Atomic production admission; preserves the immutable parent-context review."""
from copy import deepcopy
import ast
import inspect
import json
from pathlib import Path
import sys
import types

from . import azure_nsp_query_cmk_runtime_admission_20261020 as prepared
from . import azure_nsp_query_cmk_runtime_review_20261020 as candidate
from peaso.collectors import azure
from peaso.collectors import azure_nsp_query_cmk_runtime_20261020 as producer

proof = prepared.predecessor
RECEIPT = 'azure_nsp_query_cmk_production_admission_20261020.json'
RECEIPT_SHA256 = '609add97abfa4ce5ae1d8f7f0bb4c890c4d8d9512aec6d3d8cbdb5068573a35f'
CASES_FILE = 'azure_nsp_query_cmk_production_cases_20261020.json'
IDS = candidate.IDS
MARK = '_azure_nsp_query_cmk_production_admission_20261020'


def _runtime():
    values = {__name__ + ':' + name: fn for name, fn in vars(sys.modules[__name__]).items()
              if isinstance(fn, types.FunctionType) and fn.__module__ == __name__}
    values.update({'peaso.collectors.azure:collect': azure.collect,
                   'peaso.collectors.azure:_selected': azure._selected})
    return values


def reviewed_inputs(root=None):
    """Validate portable source/code identity and native production decisions."""
    _, _, declarations = prepared.reviewed_inputs(root)
    root = Path(root or Path(__file__).resolve().parents[2]).resolve()
    try:
        raw = (root / 'peaso/checks' / RECEIPT).read_bytes()
        if proof._hash(raw) != RECEIPT_SHA256:
            raise RuntimeError('production receipt changed')
        receipt = json.loads(raw, object_pairs_hook=proof._pairs)
        if (receipt['ids'] != list(IDS) or receipt['declarations'] != candidate.DECLARATIONS
                or receipt['prepared_receipt_sha256'] != prepared.RECEIPT_SHA256
                or proof._hash(proof._self_source((root / receipt['helper_path']).read_bytes())) != receipt['helper_sha256']):
            raise RuntimeError('production admission source/schema changed')
        current = _runtime()
        if set(current) != set(_ORIGINALS) or set(current) != set(receipt['functions']):
            raise RuntimeError('production callable set changed')
        compiled = {}
        for name, fn in current.items():
            record = receipt['functions'][name]
            path = (root / record['path']).resolve()
            if not path.is_relative_to(root):
                raise RuntimeError('production callable escaped repository')
            if record['path'] not in compiled:
                compiled[record['path']] = proof._compiled(path.read_bytes(), str(path))
            codes = compiled[record['path']].get(record['qualname'], [])
            disk = path.read_text(); disk_lines = disk.splitlines(keepends=True)
            definitions = [node for node in ast.parse(disk).body
                           if isinstance(node, ast.FunctionDef) and node.name == record['qualname']]
            if len(definitions) != 1:
                raise RuntimeError('production exact source definition changed')
            node = definitions[0]
            source = ''.join(disk_lines[min([node.lineno] + [d.lineno for d in node.decorator_list])-1:node.end_lineno])
            if proof._hash(source.encode()) != record['source_sha256']:
                raise RuntimeError('production disk callable source changed')
            module = sys.modules.get(fn.__module__)
            if (fn is not _ORIGINALS[name] or module is None or fn.__globals__ is not vars(module)
                    or fn.__qualname__ != record['qualname'] or fn.__closure__
                    or proof._hash(inspect.getsource(fn).encode()) != record['source_sha256']
                    or len(codes) != 1 or proof._code(fn.__code__) != proof._code(codes[0])
                    or json.dumps(fn.__defaults__, sort_keys=True) != json.dumps(record['defaults'], sort_keys=True)
                    or json.dumps(fn.__kwdefaults__, sort_keys=True) != json.dumps(record['kwdefaults'], sort_keys=True)):
                raise RuntimeError('production executing callable changed')
        if (azure.azure_nsp_query_cmk_runtime_20261020 is not producer
                or candidate is not prepared.candidate or producer is not prepared.producer
                or any(azure.TYPES.count(kind) != 1 or kind in azure.ENDPOINTS for kind in producer.KINDS)
                or not set(producer.KINDS).issubset(azure._selected({}, None))
                or any(azure._selected({}, [kind]) != {kind, 'subscription'} for kind in producer.KINDS)):
            raise RuntimeError('production collector binding changed')
        for row in receipt['fixtures']:
            path = (root / row['path']).resolve()
            if not path.is_relative_to(root) or proof._hash(path.read_bytes()) != row['sha256']:
                raise RuntimeError('production native fixture changed')
        cases = json.loads((root / 'peaso/checks' / CASES_FILE).read_bytes(), object_pairs_hook=proof._pairs)
        if set(cases) != set(IDS):
            raise RuntimeError('production CASES identities changed')
        for spec, fn in declarations:
            case = cases[spec['id']]
            for branch in ('pass', 'fail', 'unknown', 'not_applicable'):
                if branch in case and fn(deepcopy(case[branch]), deepcopy(case[branch + '_index']))[0] != branch.upper():
                    raise RuntimeError('production native decision changed')
            for branch in ('missing', 'malformed'):
                if fn(deepcopy(case[branch]), deepcopy(case['index']))[0] != 'UNKNOWN':
                    raise RuntimeError('production unavailable decision changed')
        return receipt, cases, declarations
    except RuntimeError:
        raise
    except (OSError, ValueError, TypeError, KeyError, AttributeError, IndexError):
        raise RuntimeError('malformed production admission inputs') from None


def _verify(check, receipt):
    function = candidate.nsp if check.id == IDS[0] else candidate.query
    safe = check.evaluate
    if (json.dumps(proof._metadata(check), sort_keys=True) != json.dumps(receipt['metadata'][check.id], sort_keys=True)
            or not isinstance(safe, types.FunctionType) or getattr(safe, MARK, None) != check.id
            or safe.__globals__ is not vars(sys.modules['peaso.checks'])
            or safe.__wrapped__ is not function):
        raise RuntimeError('production registered metadata/callable changed')
    closure = proof._bindings(safe)
    if (set(closure) != {'checked', 'id', 'kind', 'provider', 'target'}
            or any(closure[key] != getattr(check, key) for key in ('id', 'kind', 'provider', 'target'))):
        raise RuntimeError('production safe closure changed')
    checked = closure['checked']
    if (not isinstance(checked, types.FunctionType) or checked.__globals__ is not safe.__globals__
            or proof._bindings(checked) != {'function': function}):
        raise RuntimeError('production checked closure changed')
    if check.id in _INSTALLED and (safe, checked) != _INSTALLED[check.id]:
        raise RuntimeError('production wrapper replacement')
    register = sys.modules['peaso.checks'].register
    path = Path(inspect.getsourcefile(register))
    compiled = proof._compiled(path.read_bytes(), str(path))
    for wrapper, name in ((safe, 'register.<locals>.decorate.<locals>.safe'),
                          (checked, 'register.<locals>.decorate.<locals>.checked')):
        if (wrapper.__defaults__ is not None or wrapper.__kwdefaults__ is not None
                or wrapper is safe and wrapper.__qualname__ != function.__qualname__
                or len(compiled.get(name, [])) != 1 or proof._code(wrapper.__code__) != proof._code(compiled[name][0])):
            raise RuntimeError('production executing wrapper changed')


def install():
    """Install exactly two checks/CASES atomically, with verified idempotence."""
    from . import CHECKS, CHECK_ALIASES, register
    from .fixtures import CASES
    receipt, cases, declarations = reviewed_inputs()
    if any(cid in CHECK_ALIASES or cid in CHECK_ALIASES.values() for cid in IDS):
        raise RuntimeError('production alias collision')
    found = {cid: [check for check in CHECKS if check.id == cid] for cid in IDS}
    if any(len(rows) > 1 for rows in found.values()) or any(found.values()) and not all(found.values()):
        raise RuntimeError('production registration collision')
    if all(found.values()):
        if set(_INSTALLED) != set(IDS):
            raise RuntimeError('production registration collision')
        for cid, rows in found.items():
            _verify(rows[0], receipt)
            if json.dumps(CASES.get(cid), sort_keys=True) != json.dumps(cases[cid], sort_keys=True):
                raise RuntimeError('production registered CASES changed')
        return
    if any(cid in CASES for cid in IDS):
        raise RuntimeError('production CASES collision')
    before = tuple(CHECKS)
    try:
        for spec, function in declarations:
            register(spec['id'], 'azure', spec['category'], spec['kind'], spec['title'], spec['severity'],
                     'security_configuration', spec['remediation'], dependencies=spec['dependencies'])(function)
            check = CHECKS[-1]
            setattr(check.evaluate, MARK, check.id)
            _verify(check, receipt)
            CASES[check.id] = deepcopy(cases[check.id])
        _INSTALLED.update({cid: (found.evaluate, proof._bindings(found.evaluate)['checked'])
                           for cid, found in zip(IDS, CHECKS[-2:])})
    except Exception:
        CHECKS[:] = before
        for cid in IDS:
            CASES.pop(cid, None)
        raise


_ORIGINALS = _runtime()
_INSTALLED = {}
