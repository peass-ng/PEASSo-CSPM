"""Portable source/code/closure guards, retained lineage and interpreter probes."""
from copy import deepcopy
import dis
import gzip
import hashlib
import json
import re
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import types

import pytest

from peaso import engine
import peaso.checks as registry
from peaso.checks import k8s_annotation_native_admission_20261020 as guard
from peaso.checks import k8s_annotation_indicators_review_20261020 as candidate
from peaso.checks.fixtures import CASES

ROOT = Path(__file__).resolve().parents[1]
PROBE = Path(__file__).with_name('k8s_annotation_portable_probe_20261020.py')


def current_reviewed_inputs():
    from peaso.checks import k8s_annotation_native_source_successor_20261021 as successor
    successor._self_proof()
    current, _ = successor._source_proofs()
    successor._current_functions(current)
    successor._helper_proof()
    private = sys.modules[successor._PRIVATE_NAME]
    assert isinstance(private, types.ModuleType) and private.__file__ == str(successor.GUARD)
    return private._reviewed_inputs()


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail('network/DNS/auth forbidden')
    for name in ('connect', 'connect_ex'):
        monkeypatch.setattr(socket.socket, name, forbidden)
    for name in ('getaddrinfo', 'gethostbyname', 'gethostbyname_ex', 'create_connection'):
        monkeypatch.setattr(socket, name, forbidden)


def check(cid):
    return next(c for c in registry.CHECKS if c.id == cid)


def change_code(code, mutation):
    if mutation == 'constants':
        return code.replace(co_consts=code.co_consts + ('UNREVIEWED',))
    if mutation == 'bytecode':
        opcode = dis.opmap['NOP'] if code.co_code[0] != dis.opmap['NOP'] else dis.opmap['LOAD_CONST']
        return code.replace(co_code=bytes((opcode, 0)) + code.co_code[2:])
    if mutation == 'freevars':
        return code.replace(co_freevars=tuple('unreviewed_' + n for n in code.co_freevars))
    raise AssertionError('unknown mutation')


@pytest.mark.parametrize('cid', guard.IDS)
@pytest.mark.parametrize('layer', [0, 1, 2, 3], ids=['safe', 'checked', 'native_guard', 'factory_leaf'])
@pytest.mark.parametrize('mutation', ['constants', 'bytecode', 'freevars'])
def test_actual_executing_wrapper_and_factory_code_tamper_rejected(cid, layer, mutation):
    function = guard._layers(check(cid))[layer]; saved = function.__code__
    before = tuple(registry.CHECKS)
    try:
        function.__code__ = change_code(saved, mutation)
        with pytest.raises(RuntimeError, match='callable changed'):
            guard._function(function)
        with pytest.raises(RuntimeError):
            guard.install()
    finally:
        function.__code__ = saved
    assert all(a is b for a, b in zip(before, registry.CHECKS))


@pytest.mark.parametrize('function_name', ['evaluate', '_native_flags', 'evaluate_for'])
@pytest.mark.parametrize('mutation', ['constants', 'bytecode'])
def test_new_predicate_helper_and_factory_outer_code_tamper(function_name, mutation):
    function = getattr(candidate, function_name); saved = function.__code__
    try:
        function.__code__ = change_code(saved, mutation)
        with pytest.raises(RuntimeError, match='callable changed'):
            guard.install()
    finally:
        function.__code__ = saved


@pytest.mark.parametrize('cid', guard.IDS)
@pytest.mark.parametrize('layer', [0, 1, 2, 3])
def test_relocation_offsets_and_filenames_do_not_disable_guard(cid, layer):
    function = guard._layers(check(cid))[layer]; code = function.__code__
    relocated = types.FunctionType(code.replace(co_filename='/relocated/source.py',
        co_firstlineno=code.co_firstlineno + 1000), function.__globals__, function.__name__,
        function.__defaults__, function.__closure__)
    relocated.__qualname__ = function.__qualname__
    assert guard._function(relocated) == guard._function(function)


def test_shadow_global_dictionary_rejected_even_with_identical_code():
    function = candidate.evaluate_for(guard.IDS[0])
    shadow = types.FunctionType(function.__code__, dict(function.__globals__),
        function.__name__, function.__defaults__, function.__closure__)
    shadow.__qualname__ = function.__qualname__
    with pytest.raises(RuntimeError, match='global binding'):
        guard._function(shadow)


def test_source_bytes_are_verified_before_compilation(monkeypatch):
    original = Path.read_bytes; compiled = []
    def changed(path):
        raw = original(path)
        return raw + b'\n# changed source' if path.name == 'k8s_annotation_indicators_review_20261020.py' else raw
    monkeypatch.setattr(Path, 'read_bytes', changed)
    monkeypatch.setattr(guard, '_compiled_source', lambda *args: compiled.append(args))
    with pytest.raises(RuntimeError, match='source bytes'):
        guard._function(candidate.evaluate)
    assert not compiled


def test_complete_source_is_compiled_without_executing_top_level_code():
    raw = b"def outer():\n    def inner(x):\n        return x\n    return inner\nraise RuntimeError('MUST_NOT_EXECUTE')\n"
    records = guard._compiled_source(raw, '/compile-only-unit.py', sys.flags.optimize)
    assert {r['qualname'] for r, code in records} == {'outer', 'outer.<locals>.inner'}


def test_portable_receipt_contains_source_ast_closures_instead_of_saved_bytecode():
    receipt, _ = current_reviewed_inputs()
    assert receipt['schema_version'] == 2
    assert receipt['python_bytecode'] == 'compare_to_trusted_source_compiled_on_current_interpreter'
    serialized = json.dumps(receipt)
    assert 'code_sha256' not in serialized and 'exceptiontable' not in serialized and 'bytecode version' not in serialized
    assert all(row['proof']['ast_sha256'] for row in receipt['callables'])
    assert 'co_qualname' not in {node.attr for node in __import__('ast').walk(__import__('ast').parse(
        Path(guard.__file__).read_text())) if isinstance(node, __import__('ast').Attribute)}


@pytest.mark.parametrize('replacement', [0, 0.0])
def test_equal_python_values_with_different_constant_types_rejected(replacement):
    function = candidate.evaluate; saved = function.__code__
    assert any(type(v) is bool and v is False for v in saved.co_consts)
    try:
        function.__code__ = saved.replace(co_consts=tuple(
            replacement if type(v) is bool and v is False else v for v in saved.co_consts))
        with pytest.raises(RuntimeError, match='callable changed'):
            guard._function(function)
    finally:
        function.__code__ = saved


@pytest.mark.parametrize('mutation', ['missing_sources', 'missing_lineage', 'legacy_mode', 'ast', 'qualname', 'compiled_source'])
def test_new_portable_receipt_cannot_drop_or_forge_source_proofs(monkeypatch, mutation):
    receipt = guard._source_receipt()
    if mutation == 'missing_sources': receipt.pop('compiled_sources')
    if mutation == 'missing_lineage': receipt.pop('lineage')
    if mutation == 'legacy_mode': receipt['python_bytecode'] = [3, 13]
    if mutation == 'ast': receipt['callables'][0]['proof']['ast_sha256'] = '0' * 64
    if mutation == 'qualname': receipt['callables'][0]['proof']['qualname'] = 'wrong.function'
    if mutation == 'compiled_source':
        receipt['compiled_sources']['peaso/checks/k8s_annotation_indicators_review_20261020.py'] = '0' * 64
    original = Path.read_text
    def altered(path, *args, **kwargs):
        return json.dumps(receipt) if path.name == guard.PORTABLE_RECEIPT else original(path, *args, **kwargs)
    monkeypatch.setattr(Path, 'read_text', altered)
    with pytest.raises(RuntimeError):
        guard.install()


# k8s_managed.py's indexed owner lookups (a reviewed later change) re-pinned its
# whole-file hash; the receipts that bind it cascade. Stale hash -> file it pins now.
REBOUND_PINS = {
    '0dfb6ed4aa08b7abdff07432081490491c7b04e18f7bbdd698e48633bdba854b': 'peaso/checks/k8s_managed.py',
    '6be12fa2e2d43a724a758d6efa3a77c561f362938d483dce8d9df7bd85661cca':
        'peaso/checks/k8s_annotation_native_admission_20261020.json',
    '865e60a2c3cb5fd086197d6150e5b9a88206ddaf5c6009ec98d969b8873a47a2':
        'peaso/checks/k8s_annotation_native_admission_portable_20261020.json',
}


def successor_source_view(tmp_path):
    """A source tree as the installed successor attests it to the guard.

    Production verifies the shared collector and planner through their exact
    reviewed predecessors (successor source_view). The stdlib-only probe cannot
    import that successor, so it reads the same authenticated predecessor bytes.
    """
    import ast
    import os
    from peaso.checks import k8s_annotation_native_source_successor_20261021 as successor
    _, before = successor._source_proofs()
    row, engine_raw, _ = successor._engine_plan_source()
    text = engine_raw.decode('utf-8'); lines = text.splitlines(keepends=True)
    node, = [n for n in ast.parse(text).body if isinstance(n, ast.FunctionDef) and n.name == 'plan_collection']
    current = ''.join(lines[node.lineno - 1:node.end_lineno])
    previous = text.replace(current, row['predecessor_source'], 1).encode('utf-8')
    root = tmp_path / 'successor-view'
    for top in ('peaso', 'tests/fixtures', 'docs'):
        for path in sorted((ROOT / top).rglob('*')):
            if path.is_dir() or '__pycache__' in path.parts:
                continue
            target = root / path.relative_to(ROOT); target.parent.mkdir(parents=True, exist_ok=True)
            try:
                os.link(path, target)
            except OSError:
                shutil.copyfile(path, target)
    for relative, raw in (('peaso/collectors/k8s.py', before), ('peaso/engine.py', previous)):
        (root / relative).unlink(); (root / relative).write_bytes(raw)
    return root


def test_predecessor_receipt_helper_and_report_exact_bytes_retained():
    receipt, _ = current_reviewed_inputs()
    for row in receipt['lineage']['retained_predecessors']:
        stored = ROOT / row['retained_gzip']
        assert hashlib.sha256(stored.read_bytes()).hexdigest() == row['gzip_sha256']
        retained = gzip.decompress(stored.read_bytes())
        if 'source' in row:
            assert set(row) == {'source', 'retained_gzip', 'gzip_sha256', 'sha256', 'bytes'}
            assert hashlib.sha256(retained).hexdigest() == row['sha256'] and len(retained) == row['bytes']
            if not row['source'].endswith('.py'):
                current = (ROOT / row['source']).read_bytes()
                if current != retained:
                    # Only cascaded whole-file pins may differ, each rebound at its
                    # own position to the exact sha256 of the file it names today.
                    pattern = re.compile(rb'([0-9a-f]{64})')
                    before, after = pattern.split(retained), pattern.split(current)
                    assert len(before) == len(after) and before[0::2] == after[0::2]
                    rebound = [(old, new) for old, new in zip(before[1::2], after[1::2]) if old != new]
                    assert rebound and all(
                        old.decode() in REBOUND_PINS and new.decode() == hashlib.sha256(
                            (ROOT / REBOUND_PINS[old.decode()]).read_bytes()).hexdigest()
                        for old, new in rebound)
                    retained = b''.join(after)
                assert current == retained
        else:
            # Later log/literal admissions retain an exact compressed predecessor
            # with a before_sha256 schema rather than the portable source schema.
            assert set(row) == {'path', 'retained_gzip', 'gzip_sha256', 'before_sha256'}
            assert hashlib.sha256(retained).hexdigest() == row['before_sha256']


@pytest.mark.parametrize('cid', guard.IDS)
@pytest.mark.parametrize('tag,expected', [('pass', 'PASS'), ('fail', 'FAIL'), ('unknown', 'UNKNOWN')])
def test_native_five_statuses_and_historical_cases_remain(cid, tag, expected):
    receipt, fixtures = current_reviewed_inputs()
    original = deepcopy(CASES[cid])
    assert check(cid).evaluate(deepcopy(fixtures[cid][tag]), deepcopy(fixtures[cid][tag + '_index']))[0] == expected
    assert CASES[cid] == original
    assert guard._hash(json.dumps(CASES[cid], sort_keys=True)) == receipt['historical_case_sha256'][cid]


@pytest.mark.parametrize('executable', ['python3.10', 'python3.11', 'python3.13', 'python3.14', 'python3.15'])
def test_actual_installed_supported_interpreter_stdlib_probe(executable, tmp_path):
    path = shutil.which(executable)
    if path is None:
        pytest.skip('Supported interpreter is not installed: ' + executable)
    root = successor_source_view(tmp_path)
    result = subprocess.run([path, str(PROBE), str(root)], cwd=ROOT, capture_output=True, text=True, timeout=45)
    assert result.returncode == 0, result.stderr
    row = json.loads(result.stdout)
    assert len(row['native_fixture_statuses']) == 15 and row['factory_code_tamper_rejected'] == 5
    assert {x['status'] for x in row['native_fixture_statuses']} == {'PASS', 'FAIL', 'UNKNOWN'}
    assert len(row['source_units_compiled_without_execution']) >= 10
