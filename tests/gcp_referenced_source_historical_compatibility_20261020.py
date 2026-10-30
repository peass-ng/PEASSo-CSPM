"""Exact predecessor reproductions followed by current consumers on the same data.

Loaded by the new collected regression module, never by production. Only the
literal node IDs below are intercepted. Original functions execute unchanged;
only their pinned terminal AssertionError is an expected historical observation.
No report rewriting, markers, deselection, registry patches or capture synthesis.
"""
from __future__ import annotations

import ast
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import dataclass
import hashlib
import importlib
import inspect
from pathlib import Path
import sys
from types import CodeType, MappingProxyType
from types import FunctionType

import pytest

ROOT = Path(__file__).resolve().parents[1]
INDEPENDENT = 'tests/gcp_referenced_source_independent_review_20261020_test.py'
WORKBENCH = 'tests/gcp_workbench_referenced_source_20261020_test.py'
BATCH_REVIEW = 'tests/gcp_batch_independent_review_20261020_test.py'
BATCH = 'tests/gcp_batch_referenced_source_20261020_test.py'

# These are the existing sealed proposal/review identities, never regenerated.
SOURCES = MappingProxyType({
    INDEPENDENT: 'efcb1a4448ba5eceddd13c111f15984e2d11118d4787b05826d8ccdc2b5d1f83',
    WORKBENCH: '12bca5b68db1413fc9b5a8e4040a266f7bb0367485523aba8ca0086642bddb2a',
    BATCH_REVIEW: 'f59616f46691be68b6ee4ea9233645809bf11dbdfd97f769f065809717134184',
    BATCH: '5e20b06c5c439dde81d6b2d85d7b38ca1a8158d335898d64ba8e1e0c8872a964',
    'tests/gcp_dataflow_referenced_source_20261020_test.py': 'd2afae932cc0ffb90ea6f9dd6ef97b8c8c77f523b842c12d7ab36c9df0211ff7',
    'peaso/checks/gcp_workbench_source_runtime_consumer_20261020.py': 'c72dacd26ccba160b22a919d5d4885984f69bf3aebc5c2e08539cf7ddf751ad7',
    'peaso/checks/gcp_dataflow_referenced_source_request_binding_20261020.py': '509741729db3c225f0c32a5707e56a5e9fb42a8c4b77458cad1ebfd0af215f4a',
    'peaso/checks/gcp_workbench_referenced_source_20261020.py': '475399b2a09db35282535891993809d416eb0252a37752e94b0622f61cdd3567',
    'peaso/checks/gcp_dataflow_referenced_source_20261020.py': '25a16777c0973ee99cf761827da6a13089d0d240758626b990aa50a8bc1f00b6',
    'peaso/checks/gcp_batch_referenced_source_20261020.py': '17bfaf26a194892cd7ca1b08c28ee470a480a35226a5922ffaa60834329c0c41',
})


@dataclass(frozen=True)
class Historical:
    path: str
    function: str
    line: int
    semantics: str
    parameters: tuple = ()


_workbench_fn = 'test_workbench_invalid_sibling_cannot_establish_complete_capture'
_batch_fn = 'test_malformed_selected_sibling_cannot_erase_trusted_own_hit'
NODES = MappingProxyType({
    WORKBENCH + '::test_proposal_not_installed': Historical(WORKBENCH, 'test_proposal_not_installed', 399, 'workbench_proposal'),
    INDEPENDENT + '::' + _workbench_fn + '[clean_sibling_invalid]': Historical(INDEPENDENT, _workbench_fn, 64, 'workbench', (('hit', False),)),
    INDEPENDENT + '::' + _workbench_fn + '[trusted_hit_sibling_invalid]': Historical(INDEPENDENT, _workbench_fn, 64, 'workbench', (('hit', True),)),
    INDEPENDENT + '::test_dataflow_closing_request_must_bind_opening_request': Historical(INDEPENDENT, 'test_dataflow_closing_request_must_bind_opening_request', 77, 'dataflow'),
    BATCH_REVIEW + '::' + _batch_fn + '[null_marker-trusted_hit]': Historical(BATCH_REVIEW, _batch_fn, 115, 'batch', (('hit', True), ('shape', 'null_marker'))),
    BATCH + '::test_unregistered_declaration': Historical(BATCH, 'test_unregistered_declaration', 390, 'batch_proposal'),
})


# Reviewed later edits keep SOURCES frozen and are admitted only through their
# exact signed successor record (historical digest -> normalized current bytes).
SOURCE_SUCCESSORS = MappingProxyType({
    'tests/gcp_dataflow_referenced_source_20261020_test.py': (
        'docs/gcp-review/recheck-20261020/gcp_dataflow_referenced_source_20261023_successor.json',
        '213505fc14aa6474b8abbeb7fa3a9b41f601b3e2e2e37dcfe0b3937cac3d16d8'),
})


def _successor_digest(relative, raw):
    import json
    import re
    record, pinned = SOURCE_SUCCESSORS[relative]
    record_raw = (ROOT / record).read_bytes()
    if hashlib.sha256(record_raw).hexdigest() != pinned:
        raise AssertionError('Historical/current successor record changed: ' + record)
    successor = json.loads(record_raw)
    normalized, count = re.subn(rb"(?m)^    assert hashlib.sha256\(successor_raw\).hexdigest\(\) == '[0-9a-f]{64}'$",
                                b"    assert hashlib.sha256(successor_raw).hexdigest() == '" + b'0' * 64 + b"'", raw)
    if count != 1 or hashlib.sha256(normalized).hexdigest() != successor['current_test_normalized_sha256']:
        raise AssertionError('Historical/current source changed: ' + relative)
    return successor['historical_test_sha256']


def attest_sources():
    for relative, digest in SOURCES.items():
        raw = (ROOT / relative).read_bytes()
        current = hashlib.sha256(raw).hexdigest()
        if current != digest and (relative not in SOURCE_SUCCESSORS or _successor_digest(relative, raw) != digest):
            raise AssertionError('Historical/current source changed: ' + relative)


def _code(code):
    """Structural executing-code identity, including source and line mapping."""
    return tuple((name, tuple(_code(c) if isinstance(c, CodeType) else c for c in value)
                  if name == 'co_consts' else value)
                 for name in ('co_code', 'co_consts', 'co_names', 'co_varnames',
                     'co_freevars', 'co_cellvars', 'co_argcount', 'co_posonlyargcount',
                     'co_kwonlyargcount', 'co_flags', 'co_firstlineno', 'co_filename',
                     'co_name', 'co_qualname', 'co_linetable', 'co_exceptiontable')
                 for value in [getattr(code, name)])


def bound_function(module, spec, config=None):
    """Bind the live function to pristine source, allowing pytest's own rewrite."""
    if spec not in NODES.values():
        raise AssertionError('Unreviewed historical source mapping')
    path = ROOT / spec.path
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != SOURCES[spec.path]:
        raise AssertionError('Historical source changed: ' + spec.path)
    function = getattr(module, spec.function)
    if (Path(module.__file__).resolve() != path or function.__globals__ is not vars(module)
            or function.__name__ != spec.function or inspect.unwrap(function) is not function):
        raise AssertionError('Historical callable mapping changed')
    expected = []
    for rewritten in (False, True):
        tree = ast.parse(raw, filename=str(path))
        if rewritten:
            from _pytest.assertion.rewrite import rewrite_asserts
            rewrite_asserts(tree, raw, str(path), config)
        compiled = compile(tree, str(path), 'exec', dont_inherit=True, optimize=sys.flags.optimize)
        expected.extend(c for c in compiled.co_consts if isinstance(c, CodeType) and c.co_name == spec.function)
    if not any(_code(function.__code__) == _code(code) for code in expected):
        raise AssertionError('Historical executing code or source mapping changed')
    return function


def historical_frame(function, spec, arguments):
    """Earlier assertions, other exceptions and unexpected success remain red."""
    try:
        function(**arguments)
    except AssertionError as error:
        last = error.__traceback__
        while last.tb_next is not None:
            last = last.tb_next
        if (type(error) is not AssertionError or last.tb_frame.f_code is not function.__code__
                or last.tb_lineno != spec.line or Path(last.tb_frame.f_code.co_filename).resolve() != ROOT / spec.path):
            raise
        return last.tb_frame
    raise AssertionError('Historical predecessor unexpectedly passed: ' + spec.function)


def _module(name):
    return importlib.import_module('peaso.checks.' + name)


@contextmanager
def reviewed_epoch(files):
    """Show only these signed files at their reviewed bytes while a sealed verifier runs.

    Each changed file must be rebuilt exactly by the production RawV2/private
    source epoch; unpinned paths and unreviewed edits stay unchanged and fail.
    """
    from peaso import rawv2_private_source_successor_20261021 as rawv2
    import os
    pinned = {os.path.realpath(ROOT / relative): (relative, expected) for relative, expected in files.items()}
    current = Path.read_bytes
    active = []

    def read_bytes(path):
        raw = current(path)
        row = None if active else pinned.get(os.path.realpath(path))
        if row is None:
            return raw
        # The epoch itself reads current files; those reads see the real bytes.
        active.append(row)
        try:
            return rawv2.source_bytes(row[0], raw, row[1], ROOT)
        finally:
            active.pop()
    @contextmanager
    def suspended():
        """Let a nested epoch proof read the current bytes it verifies."""
        active.append(None)
        try:
            yield
        finally:
            active.pop()
    Path.read_bytes = read_bytes
    try:
        yield suspended
    finally:
        Path.read_bytes = current


def _reviewed_declarations(name):
    """Declarations of one admission, through the finite source view production uses."""
    import json
    from peaso import rawv2_private_source_successor_20261021 as rawv2
    admission = _module(name)
    if name not in rawv2._LATER_ADMISSIONS:
        return admission.reviewed_inputs()[2]
    # Production installs this admission only through a transformed clone that
    # checks sources with the RawV2 epoch; the predecessor body rejects reviewed edits.
    raw = (ROOT / 'peaso/checks' / (name + '.json')).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == admission.RECEIPT_SHA256
    signed = json.loads(raw)
    for relative, digest in signed['sources'].items():
        assert rawv2._admitted_source_digest(relative, ROOT / relative, digest, ROOT) == digest, relative
    consumer = _module(signed['module'])
    return [(metadata, getattr(consumer, row['evaluate'].rsplit(':', 1)[1]))
            for row in signed['checks'] if row['id'] in admission.CHECK_IDS
            for metadata in consumer.DECLARATIONS if metadata['id'] == row['id']]


def admitted(profile):
    from peaso import engine
    name = ('gcp_workbench_source_runtime_admission_20261020' if profile == 'workbench'
            else 'gcp_dataflow_batch_source_runtime_admission_20261020')
    metadata, function = next((m, f) for m, f in _reviewed_declarations(name) if profile in m['id'])
    check, = [c for c in engine._registry() if c.id == metadata['id']]
    assert inspect.unwrap(check.evaluate) is function
    return check, function


def proposal_boundary(profile):
    """Reimport the sealed proposal without reinstalling unrelated admissions."""
    from peaso import checks
    from peaso.checks import fixtures
    from peaso.azure_function_package_index_20261020 import _Admitted, _Assertions
    from tests.gcp_clarity_combined_successor_20261020 import cases_fingerprint
    # _registry() performs global admission installation. Calling it while
    # measuring proposal import effects can regenerate unrelated CASES.
    # Inspect the already installed registry and validate this exact admission.
    name = ('gcp_workbench_source_runtime_admission_20261020' if profile == 'workbench'
            else 'gcp_dataflow_batch_source_runtime_admission_20261020')
    import json
    from peaso import rawv2_private_source_successor_20261021 as rawv2
    metadata, function = next((m, f) for m, f in _reviewed_declarations(name) if profile in m['id'])
    check, = [c for c in checks.CHECKS if c.id == metadata['id']]
    assert inspect.unwrap(check.evaluate) is function
    registry, case_map, alias_map = checks.CHECKS, fixtures.CASES, checks.CHECK_ALIASES
    before = tuple(registry)
    aliases = deepcopy(alias_map)
    # Capability objects use identity equality; deepcopy creates different grants.
    # The graph fingerprint checks every mutable slot and graph link, while the
    # explicit references below additionally forbid replacing admission objects.
    def capabilities(value, seen=None):
        seen = set() if seen is None else seen
        if id(value) in seen:
            return []
        seen.add(id(value))
        if type(value) is dict:
            return [obj for key in sorted(value) for obj in capabilities(value[key], seen)]
        if type(value) in (list, tuple):
            return [obj for part in value for obj in capabilities(part, seen)]
        if type(value) in (_Admitted, _Assertions):
            return [value, *[obj for field in ('snapshot', 'expected', 'scope')
                            for obj in capabilities(getattr(value, field), seen)]]
        return []
    cases = cases_fingerprint(case_map)
    grants = capabilities(case_map)
    proposal = _module('gcp_' + profile + '_referenced_source_20261020_proposal')
    proposal = importlib.reload(proposal)
    signed_proposal = json.loads(proposal.RECEIPT.read_bytes())
    files, dependencies = signed_proposal['files'], signed_proposal['dependencies']

    view = []

    class ReviewedInspect:
        """Signed dependency bodies; only reviewed scanner edits map to their epoch."""
        unwrap = staticmethod(inspect.unwrap)

        @staticmethod
        def getsource(fn):
            with view[0]():
                return ReviewedInspect._getsource(fn)

        @staticmethod
        def _getsource(fn):
            current = inspect.getsource(fn)
            expected = dependencies[fn.__module__ + ':' + fn.__qualname__]
            if hashlib.sha256(current.encode()).hexdigest() == expected:
                return current
            row = rawv2.producer_row(fn, {'path': rawv2.SCANNER, 'sha256': expected}, ROOT)
            assert hashlib.sha256(current.encode()).hexdigest() == row['sha256']
            for epoch in (rawv2.SCANNER_BEFORE, rawv2.SCANNER_MIDDLE):
                raw = rawv2.source_bytes(rawv2.SCANNER, (ROOT / rawv2.SCANNER).read_bytes(), epoch, ROOT)
                nodes = [n for n in ast.parse(raw).body if isinstance(n, ast.FunctionDef) and n.name == fn.__name__]
                if len(nodes) == 1:
                    lines = raw.decode().splitlines(keepends=True)
                    node, = nodes
                    body = ''.join(lines[min([node.lineno] + [d.lineno for d in node.decorator_list]) - 1:node.end_lineno])
                    if hashlib.sha256(body.encode()).hexdigest() == expected:
                        return body
            raise AssertionError('Unreviewed proposal dependency: ' + fn.__qualname__)
    assert proposal.inspect is inspect
    proposal.inspect = ReviewedInspect
    try:
        with reviewed_epoch(files) as suspended:
            view.append(suspended)
            receipt = proposal.validate_proposal()
    finally:
        proposal.inspect = inspect
    assert receipt['registration'] == 'unregistered_proposal_only'
    assert checks.CHECKS is registry and fixtures.CASES is case_map and checks.CHECK_ALIASES is alias_map
    assert tuple(registry) == before and all(a is b for a, b in zip(registry, before))
    assert alias_map == aliases and cases_fingerprint(case_map) == cases
    current_grants = capabilities(case_map)
    assert len(current_grants) == len(grants) and all(a is b for a, b in zip(current_grants, grants))
    installed, = [c for c in registry if c.id == check.id]
    assert installed is check and inspect.unwrap(installed.evaluate) is function
    if profile == 'batch':
        predecessor = _module('gcp_batch_referenced_source_20261020')
        assert predecessor.DECLARATION['requirements'] == []
        assert predecessor.DECLARATION['dependencies'] == [predecessor.source.KIND]
    return {'current_id': check.id, 'proposal_registration_delta': 0}


@dataclass(frozen=True)
class Current:
    owner: object
    evaluate: object
    functions: tuple


def prepare_current(spec):
    """Attest before native HTTP harnesses install their narrowly scoped fakes."""
    if spec.semantics.endswith('_proposal'):
        return None
    if spec.semantics == 'workbench':
        _, function = admitted('workbench')
        owner = importlib.import_module(function.__module__)
    elif spec.semantics == 'dataflow':
        owner = _module('gcp_dataflow_referenced_source_request_binding_20261020')
        import json
        signed = json.loads((ROOT / 'peaso/checks/gcp_dataflow_referenced_source_request_binding_20261020.json').read_bytes())
        with reviewed_epoch(signed['files']):
            owner.validate_successor()
        function = owner.evaluate
    else:
        admitted('batch')
        owner = _module('gcp_batch_source_row_successor_20261020')
        function = owner.evaluate
    functions = tuple((name, value, _code(value.__code__)) for name, value in vars(owner).items()
                      if isinstance(value, FunctionType) and value.__globals__ is vars(owner))
    return Current(owner, function, functions)


def current_on_same_capture(spec, frame, current):
    local = frame.f_locals
    if spec.semantics.endswith('_proposal'):
        return proposal_boundary(spec.semantics.removesuffix('_proposal'))
    assert isinstance(current, Current)
    for name, function, code in current.functions:
        assert getattr(current.owner, name) is function and _code(function.__code__) == code, 'Current pure consumer changed during capture'
    evaluate = current.evaluate
    if spec.semantics == 'workbench':
        first, second, index, hit = (local[n] for n in ('first', 'second', 'index', 'hit'))
        before = deepcopy(index)
        assert local['status'] == ('FAIL' if hit else 'PASS') and local['details']['complete'] is True
        assert second[frame.f_globals['workbench'].source.MARKER]['parts'][0]['engines'][0]['version'] == '0.0.0'
        assert evaluate(second, index)[0] == 'UNKNOWN'
        status, details = evaluate(first, index)
        assert status == ('FAIL' if hit else 'UNKNOWN') and details['complete'] is False
        assert index == before
    elif spec.semantics == 'dataflow':
        capture = local['capture']; before = deepcopy(capture)
        assert local['status'] == 'PASS' and local['opening']['request'] != local['closing']['request']
        status, details = evaluate(capture['items'][0], capture)
        assert status == 'UNKNOWN' and details['complete'] is False
        assert capture == before
    else:
        evidence, first = local['evidence'], local['first']; before = deepcopy(evidence)
        assert local['rows'][0][0] == 'UNKNOWN' and local['hit'] is True and local['shape'] == 'null_marker'
        assert local['sibling'][frame.f_globals['source'].MARKER] is None
        status, details = evaluate(first, evidence, frame.f_globals['batch'].SCOPE)
        assert status == 'FAIL' and details['complete'] is False
        assert evaluate(local['sibling'], evidence, frame.f_globals['batch'].SCOPE)[0] == 'UNKNOWN'
        assert evidence == before
    if status == 'FAIL':
        leak, = details['secret_leaks']
        assert {d['engine'] for d in leak['detectors']} == {'kingfisher', 'trufflehog'}
    return {'predecessor_final_assertion_line': spec.line, 'current_status': status, 'complete': details['complete']}


@pytest.hookimpl(tryfirst=True)
def pytest_pyfunc_call(pyfuncitem):
    spec = NODES.get(pyfuncitem.nodeid)
    if spec is None:
        return None
    attest_sources()
    function = bound_function(pyfuncitem.module, spec, pyfuncitem.config)
    assert pyfuncitem.obj is function
    current = prepare_current(spec)
    arguments = {name: pyfuncitem.funcargs[name] for name in pyfuncitem._fixtureinfo.argnames}
    for name, value in spec.parameters:
        assert arguments[name] == value and type(arguments[name]) is type(value)
    frame = historical_frame(function, spec, arguments)
    try:
        proof = current_on_same_capture(spec, frame, current)
        pyfuncitem.user_properties.append(('historical_to_current', str(proof)))
    finally:
        del frame
    return True
