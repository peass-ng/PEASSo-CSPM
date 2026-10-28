"""Uninstalled atomic source/native-case admission for two ARM declarations.

No registry hook is installed by importing this module. Compile-only code checks
use the running interpreter, including Python 3.10; reviewed source is not exec'd.
"""
from copy import deepcopy
import hashlib
import inspect
import json
from pathlib import Path
import re
import sys
import types
from urllib import parse

from . import azure_nsp_query_cmk_metadata_proposal_20261020 as candidate
from peaso.collectors import azure_nsp_query_cmk_metadata_proposal_20261020 as producer
from peaso.collectors import azure

RECEIPT = 'azure_nsp_query_cmk_metadata_admission_20261020.json'
RECEIPT_SHA256 = '09e89f5043a3d9477d7df2a899da33cfdd8a765b7bb297f4c48e2f772b78b401'
CASES_FILE = 'azure_nsp_query_cmk_metadata_admitted_cases_20261020.json'
IDS = ('azure.review.network.perimeter_association_enforced',
       'azure.review.log_analytics.query_storage_cmk_declared')
MARK = '_azure_nsp_query_cmk_metadata_admission_20261020'


def _hash(raw):
    return hashlib.sha256(raw).hexdigest()


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise RuntimeError('duplicate admission JSON field')
        result[key] = value
    return result


def _self_source(raw):
    # Avoid a circular receipt/helper hash: exactly this one literal is masked.
    normalized, count = re.subn(rb"(?m)^RECEIPT_SHA256 = '[0-9a-f]{64}'$",
                                b"RECEIPT_SHA256 = '" + b'0' * 64 + b"'", raw)
    if count != 1:
        raise RuntimeError('metadata admission digest binding changed')
    return normalized


def _constant(value):
    if isinstance(value, types.CodeType):
        return ('code', _code(value))
    if isinstance(value, tuple):
        return ('tuple', tuple(_constant(v) for v in value))
    if isinstance(value, frozenset):
        return ('frozenset', frozenset(_constant(v) for v in value))
    return (type(value).__name__, value)


def _code(code):
    # Line tables/filenames relocate; executable operations, constants, lexical
    # bindings, arguments, flags and exception handlers remain exact.
    return (code.co_code, tuple(_constant(v) for v in code.co_consts),
            code.co_names, code.co_varnames, code.co_freevars, code.co_cellvars,
            code.co_argcount, code.co_posonlyargcount, code.co_kwonlyargcount,
            code.co_nlocals, code.co_stacksize, code.co_flags,
            getattr(code, 'co_exceptiontable', b''))


def _compiled(raw, filename):
    compiled = compile(raw, filename, 'exec', dont_inherit=True, optimize=sys.flags.optimize)
    records = {}
    def visit(code, prefix=''):
        for value in code.co_consts:
            if not isinstance(value, types.CodeType):
                continue
            qualname = prefix + value.co_name
            if not value.co_name.startswith('<'):
                records.setdefault(qualname, []).append(value)
            visit(value, qualname + ('.<locals>.' if value.co_flags & inspect.CO_NEWLOCALS else '.'))
    visit(compiled)
    return records


def _bindings(function):
    return {key: cell.cell_contents for key, cell in
            zip(function.__code__.co_freevars, function.__closure__ or ())}


def _runtime():
    from . import register, facts
    values = {}
    for module in (producer, candidate, sys.modules[__name__]):
        for name, value in vars(module).items():
            if isinstance(value, types.FunctionType) and value.__module__ == module.__name__:
                values[module.__name__ + ':' + name] = value
    for name, value in vars(producer.Capture).items():
        if isinstance(value, types.FunctionType):
            values[producer.__name__ + ':Capture.' + name] = value
    for name, function in {
            'AzureTransport.__init__': azure.AzureTransport.__init__,
            'AzureTransport.token': azure.AzureTransport.token,
            '_Reader.__init__': azure._Reader.__init__,
            '_Reader.check_cancelled': azure._Reader.check_cancelled,
            '_Reader.call': azure._Reader.call, '_Reader._read': azure._Reader._read,
            '_Reader.run': azure._Reader.run, '_Reader.metadata': azure._Reader.metadata,
            '_metadata_only': azure._metadata_only, '_safe_error': azure._safe_error,
            '_NoRedirect.redirect_request': azure._NoRedirect.redirect_request}.items():
        values[azure.__name__ + ':' + name] = function
    values['peaso.checks:register'] = register
    values['peaso.checks.facts:guard'] = facts.guard
    return values


def _schema():
    names = ('ARM', 'NSP_VERSION', 'LINK_VERSION', 'STORAGE_VERSION', 'WORKSPACE_VERSION',
             'NSP_KIND', 'QUERY_KIND', 'KINDS', 'NSP', 'WORKSPACE', 'STORAGE',
             'LINK_TYPES', 'GUID', 'SEGMENT', 'SCHEMA', 'MAX_BYTES', 'MAX_ROWS', 'MAX_PAGES')
    return json.loads(json.dumps({'producer': {name: getattr(producer, name) for name in names},
                                 'ids': [candidate.NSP_CHECK, candidate.QUERY_CHECK],
                                 'declarations': candidate.DECLARATIONS}))


def _classes():
    from . import Check
    return (producer.Capture, azure.AzureTransport, azure._Reader, Check)


def _metadata(check):
    return {key: getattr(check, key) for key in ('id', 'provider', 'category', 'kind', 'title',
        'severity', 'control', 'remediation', 'target', 'allow_incomplete_failure')} | {
        'declared_dependencies': list(check.declared_dependencies),
        'empty_applicability_dependencies': list(check.empty_applicability_dependencies)}


def _execution(function, record, compiled):
    module = sys.modules.get(function.__module__) if isinstance(function, types.FunctionType) else None
    if (module is None or function.__globals__ is not vars(module)
            or function.__qualname__ != record['qualname']
            or function.__name__ != record['qualname'].rsplit('.', 1)[-1]
            or json.dumps(function.__defaults__, sort_keys=True) != json.dumps(record['defaults'], sort_keys=True)
            or json.dumps(function.__kwdefaults__, sort_keys=True) != json.dumps(record['kwdefaults'], sort_keys=True)
            or function.__closure__):
        raise RuntimeError('metadata runtime callable binding changed')
    trusted = compiled.get(record['qualname'], [])
    if len(trusted) != 1 or _code(function.__code__) != _code(trusted[0]):
        raise RuntimeError('metadata executing code changed')


def reviewed_inputs(root=None):
    """Return (immutable receipt, fresh native CASES, (declaration, evaluator)s)."""
    root = Path(root or Path(__file__).resolve().parents[2]).resolve()
    try:
        raw = (root / 'peaso/checks' / RECEIPT).read_bytes()
        if _hash(raw) != RECEIPT_SHA256:
            raise RuntimeError('metadata admission receipt changed')
        receipt = json.loads(raw, object_pairs_hook=_pairs)
        if (receipt['schema_version'] != 1 or receipt['ids'] != list(IDS)
                or json.dumps(receipt['schema'], sort_keys=True) != json.dumps(_schema(), sort_keys=True)):
            raise RuntimeError('metadata declaration/schema changed')
        compiled = {}
        for relative, expected in receipt['sources'].items():
            path = (root / relative).resolve()
            if not path.is_relative_to(root):
                raise RuntimeError('metadata source escaped repository')
            source = path.read_bytes()
            if relative == receipt['helper_path']:
                source = _self_source(source)
            if _hash(source) != expected:
                raise RuntimeError('metadata reviewed source changed')
            compiled[relative] = _compiled(source, str(path))
        for fixture in receipt['fixtures']:
            path = (root / fixture['path']).resolve()
            if not path.is_relative_to(root) or _hash(path.read_bytes()) != fixture['sha256']:
                raise RuntimeError('metadata native fixture/proposal changed')
        current = _runtime()
        if set(current) != set(receipt['functions']) or set(current) != set(_ORIGINALS):
            raise RuntimeError('metadata runtime function set changed')
        if any(left is not right for left, right in zip(_classes(), _ORIGINAL_CLASSES)):
            raise RuntimeError('metadata runtime class replacement')
        for name, function in current.items():
            record = receipt['functions'][name]
            if function is not _ORIGINALS[name]:
                raise RuntimeError('metadata runtime callable replacement')
            path = (root / record['path']).resolve()
            if not path.is_relative_to(root):
                raise RuntimeError('metadata callable escaped repository')
            source = inspect.getsource(function)
            if _hash(source.encode()) != record['source_sha256']:
                raise RuntimeError('metadata runtime helper source changed')
            if record['path'] not in compiled:
                # Shared modules remain extensible: only the named callable's
                # source bytes are pinned. Compiling surrounding code executes none.
                compiled[record['path']] = _compiled(path.read_bytes(), str(path))
            _execution(function, record, compiled[record['path']])
        if (candidate.native is not producer or producer.json is not json or producer.re is not re
                or producer.urlsplit is not parse.urlsplit or producer.parse_qs is not parse.parse_qs):
            raise RuntimeError('metadata imported runtime helper identity changed')
        cases = json.loads((root / 'peaso/checks' / CASES_FILE).read_bytes(), object_pairs_hook=_pairs)
        if set(cases) != set(IDS):
            raise RuntimeError('metadata native CASES identities changed')
        declarations = []
        for spec, function in zip(candidate.DECLARATIONS, (candidate.nsp, candidate.query)):
            case = cases[spec['id']]
            expected = {'pass', 'pass_index', 'fail', 'fail_index', 'unknown', 'unknown_index', 'missing', 'malformed', 'index'}
            if spec['id'] == candidate.QUERY_CHECK:
                expected |= {'not_applicable', 'not_applicable_index'}
            if set(case) != expected:
                raise RuntimeError('metadata native CASES branches changed')
            for branch in ('pass', 'fail', 'unknown'):
                if function(deepcopy(case[branch]), deepcopy(case[branch + '_index']))[0] != branch.upper():
                    raise RuntimeError('metadata native decision witness changed')
            for branch in ('missing', 'malformed'):
                if function(deepcopy(case[branch]), deepcopy(case['index']))[0] != 'UNKNOWN':
                    raise RuntimeError('metadata unavailable witness changed')
            if 'not_applicable' in case and function(deepcopy(case['not_applicable']), deepcopy(case['not_applicable_index']))[0] != 'NOT_APPLICABLE':
                raise RuntimeError('metadata empty Query witness changed')
            declarations.append((deepcopy(spec), function))
        return receipt, cases, declarations
    except RuntimeError:
        raise
    except (OSError, ValueError, TypeError, KeyError, AttributeError, IndexError):
        raise RuntimeError('malformed metadata admission inputs') from None


def _verify(check, receipt):
    if (json.dumps(_metadata(check), sort_keys=True) != json.dumps(receipt['metadata'][check.id], sort_keys=True)
            or getattr(check.evaluate, MARK, None) != check.id):
        raise RuntimeError('metadata registered declaration changed')
    function = candidate.nsp if check.id == candidate.NSP_CHECK else candidate.query
    safe = check.evaluate
    if not isinstance(safe, types.FunctionType) or safe.__globals__ is not vars(sys.modules['peaso.checks']):
        raise RuntimeError('metadata safe wrapper changed')
    closure = _bindings(safe)
    if (set(closure) != {'checked', 'id', 'kind', 'provider', 'target'}
            or any(closure[key] != getattr(check, key) for key in ('id', 'kind', 'provider', 'target'))
            or safe.__wrapped__ is not function):
        raise RuntimeError('metadata safe wrapper binding changed')
    checked = closure['checked']
    if (not isinstance(checked, types.FunctionType) or checked.__globals__ is not safe.__globals__
            or _bindings(checked) != {'function': function}):
        raise RuntimeError('metadata checked wrapper binding changed')
    prior = _INSTALLED.get(check.id)
    if prior is not None and (safe is not prior[0] or checked is not prior[1]):
        raise RuntimeError('metadata registered callable replacement')
    register = sys.modules['peaso.checks'].register
    path = Path(inspect.getsourcefile(register))
    compiled = _compiled(path.read_bytes(), str(path))
    for wrapper, name in ((safe, 'register.<locals>.decorate.<locals>.safe'),
                          (checked, 'register.<locals>.decorate.<locals>.checked')):
        if (wrapper.__defaults__ is not None or wrapper.__kwdefaults__ is not None
                or wrapper.__qualname__ != function.__qualname__ and wrapper is safe
                or len(compiled.get(name, [])) != 1 or _code(wrapper.__code__) != _code(compiled[name][0])):
            raise RuntimeError('metadata executing registry wrapper changed')


def install():
    """Explicit later integration hook; validate both checks before any mutation."""
    from . import CHECKS, CHECK_ALIASES, register
    from .fixtures import CASES
    receipt, cases, declarations = reviewed_inputs()
    if any(cid in CHECK_ALIASES or cid in CHECK_ALIASES.values() for cid in IDS):
        raise RuntimeError('metadata alias collision')
    found = {cid: [check for check in CHECKS if check.id == cid] for cid in IDS}
    if any(len(rows) > 1 for rows in found.values()) or any(found.values()) and not all(found.values()):
        raise RuntimeError('metadata registration collision')
    for kind in producer.KINDS:
        if azure.TYPES.count(kind) > 1 or kind in azure.ENDPOINTS:
            raise RuntimeError('metadata dedicated kind collision')
    if all(found.values()):
        if set(_INSTALLED) != set(IDS):
            raise RuntimeError('metadata registration collision')
        for cid, rows in found.items():
            _verify(rows[0], receipt)
            if json.dumps(CASES.get(cid), sort_keys=True) != json.dumps(cases[cid], sort_keys=True):
                raise RuntimeError('metadata registered CASES changed')
        return
    if any(cid in CASES for cid in IDS):
        raise RuntimeError('metadata CASES collision')
    before, previous = tuple(CHECKS), {cid: deepcopy(CASES[cid]) for cid in IDS if cid in CASES}
    try:
        for spec, function in declarations:
            register(spec['id'], 'azure', spec['category'], spec['kind'], spec['title'], spec['severity'],
                     'security_configuration', spec['remediation'], dependencies=spec['dependencies'])(function)
            check = CHECKS[-1]
            setattr(check.evaluate, MARK, check.id)
            _verify(check, receipt)
            CASES[check.id] = deepcopy(cases[check.id])
        _INSTALLED.update({cid: (CHECKS[-2 + offset].evaluate,
                                _bindings(CHECKS[-2 + offset].evaluate)['checked'])
                           for offset, cid in enumerate(IDS)})
    except Exception:
        CHECKS[:] = before
        for cid in IDS:
            if cid in previous:
                CASES[cid] = previous[cid]
            else:
                CASES.pop(cid, None)
        raise


_ORIGINALS = _runtime()
_ORIGINAL_CLASSES = _classes()
_INSTALLED = {}
