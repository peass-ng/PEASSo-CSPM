"""Production compile/parse reuse must be invisible to every caller."""
import ast
import json
import os
import subprocess
import sys
from pathlib import Path

import peaso.compile_cache as cc

ROOT = Path(__file__).resolve().parents[1]


def test_disabled_in_always_mode():
    # tests/conftest runs every proof in always mode.
    assert cc.install() is False
    assert ast.parse is cc._ORIGINAL_PARSE


def test_code_cache_shares_only_identical_compilations(monkeypatch):
    monkeypatch.setattr(cc, '_ROOTS', (str(Path(__file__).parent) + '/',))
    cc.clear()
    first = cc._compile('x = 1\n', 'a.py', 'exec')
    assert cc._compile('x = 1\n', 'a.py', 'exec') is first
    assert cc._compile(b'x = 1\n', 'a.py', 'exec') is not first
    assert cc._compile('x = 1\n', 'b.py', 'exec') is not first
    assert cc._compile('x = 1\n', 'a.py', 'exec', optimize=2) is not first
    assert cc._compile('x = 1\n', 'a.py', 'exec').co_filename == 'a.py'
    cc.clear()


def test_inherited_future_flags_match_builtin(monkeypatch):
    monkeypatch.setattr(cc, '_ROOTS', (str(Path(__file__).parent) + '/',))
    namespace = {'cc': cc}
    exec(compile('from __future__ import annotations\n'
                 'def run(c):\n    return c("def f(x: undefined): pass\\n", "f.py", "exec")\n',
                 str(Path(__file__)), 'exec', dont_inherit=True), namespace)
    expected = namespace['run'](cc._ORIGINAL_COMPILE)
    actual = namespace['run'](cc._compile)
    assert actual.co_flags == expected.co_flags
    assert actual.co_flags & 0x1000000
    plain = cc._compile('def f(x: int): pass\n', 'f.py', 'exec', dont_inherit=True)
    assert not plain.co_flags & 0x1000000
    cc.clear()


def test_unreviewed_callers_always_get_fresh_trees(monkeypatch):
    monkeypatch.setattr(cc, '_ROOTS', (str(Path(__file__).parent) + '/',))
    assert cc._parse('x = 1\n') is not cc._parse('x = 1\n')
    assert ast.dump(cc._parse('x = 1\n')) == ast.dump(ast.parse('x = 1\n'))


def test_production_import_never_mutates_shared_trees():
    script = '''
import ast, json, sys
import peaso.compile_cache as cc
made = []
orig = cc._ORIGINAL_PARSE
def recording(source, filename="<unknown>", mode="exec", **kw):
    tree = orig(source, filename, mode, **kw)
    if sys._getframe(1).f_code is cc._parse.__code__:
        made.append((tree, ast.dump(tree, include_attributes=True)))
    return tree
cc._ORIGINAL_PARSE = recording
import peaso.checks, peaso.engine
cached = {id(tree) for tree in cc._TREES.values()}
print(json.dumps({"installed": ast.parse is cc._parse, "cached": len(cached), "code": len(cc._CODE),
                  "mutated": sum(ast.dump(t, include_attributes=True) != d for t, d in made if id(t) in cached)}))
'''
    env = {k: v for k, v in os.environ.items() if k != 'PEASO_SOURCE_ATTESTATION'}
    env['PEASO_SOURCE_ATTESTATION'] = 'once'  # the proofs that parse and compile run here
    env['PYTHONPATH'] = str(ROOT)
    out = subprocess.run([sys.executable, '-c', script], cwd=ROOT, env=env, check=True,
                         capture_output=True, text=True, timeout=900).stdout
    result = json.loads(out.strip().splitlines()[-1])
    assert result['installed'] and result['cached'] and result['code']
    assert result['mutated'] == 0
