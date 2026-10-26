"""Trusted mode skips pure source proofs but builds the same native runtime.

The suite itself runs with PEASO_SOURCE_ATTESTATION=always (conftest), so the
in-process registry here is the fully proven one.  A child process imports the
package in the explicit immutable-image mode (``trusted``) and both sides fingerprint
the registry and replay every signed native case.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import types

import pytest

from peaso import source_attestation_mode as mode
from peaso import trusted_sources

ROOT = Path(__file__).resolve().parents[1]

FINGERPRINT = r'''
import copy, hashlib, inspect, json, re
import peaso.checks as checks
import peaso.engine  # noqa: F401
from peaso.checks.fixtures import CASES

def _code(c):
    if isinstance(c, type(_code.__code__)):
        return ['code', c.co_qualname, c.co_filename, c.co_firstlineno, c.co_code.hex(),
                [_code(x) for x in c.co_consts], c.co_names, c.co_varnames, c.co_freevars,
                c.co_flags, c.co_argcount, c.co_kwonlyargcount]
    if isinstance(c, (tuple, frozenset)):
        return [type(c).__name__, [_code(x) for x in (sorted(c, key=repr) if isinstance(c, frozenset) else c)]]
    return repr(c)

def _plain(value):
    return re.sub(' at 0x[0-9a-f]+', '', repr(value))

def _function(fn):
    fn = inspect.unwrap(fn)
    code = getattr(fn, '__code__', None)
    if code is None:
        return _plain(type(fn))
    return [fn.__module__, fn.__qualname__, hashlib.sha256(json.dumps(_code(code)).encode()).hexdigest(),
            _plain(fn.__defaults__), _plain(fn.__kwdefaults__), fn.__globals__.get('__name__')]

registry = [[c.id, _function(c.evaluate),
             json.dumps({k: getattr(c, k) for k in ('id', 'provider', 'category', 'kind', 'title', 'severity',
                                                      'control', 'remediation', 'target', 'dependencies',
                                                      'allow_incomplete_failure') if hasattr(c, k)},
                        sort_keys=True, default=_plain)]
            for c in checks.CHECKS]
outcomes = {}
for ident in sorted(CASES):
    case = CASES[ident]
    for branch in ('pass', 'fail', 'unknown'):
        if branch not in case or not isinstance(case, dict):
            continue
        index = case.get(branch + '_index', case.get('index'))
        try:
            result = checks.evaluate_check(ident, copy.deepcopy(case[branch]), copy.deepcopy(index))
        except Exception as exc:  # noqa: BLE001 - compared, not judged
            result = ('raised', type(exc).__name__)
        if (isinstance(result, (tuple, list)) and len(result) > 1 and isinstance(result[1], dict)
                and result[1].get('time_source') == 'evaluation_clock'):
            result = (result[0], sorted(result[1]))  # wall-clock ages differ per run
        outcomes[ident + ':' + branch] = json.dumps(result, sort_keys=True, default=_plain)
RESULT = {
    'registry': hashlib.sha256(json.dumps(registry, sort_keys=True).encode()).hexdigest(),
    'cases': hashlib.sha256(json.dumps(sorted(CASES), sort_keys=True).encode()).hexdigest(),
    'outcomes': hashlib.sha256(json.dumps(outcomes, sort_keys=True).encode()).hexdigest(),
    'checks': len(registry), 'replayed': len(outcomes),
}
'''


def _child(attestation, code):
    env = dict(os.environ, PYTHONPATH=str(ROOT))
    if attestation is None:
        env.pop('PEASO_SOURCE_ATTESTATION', None)
    else:
        env['PEASO_SOURCE_ATTESTATION'] = attestation
    done = subprocess.run([sys.executable, '-c', code], cwd=ROOT, env=env, capture_output=True,
                          text=True, timeout=600)
    assert done.returncode == 0, done.stderr[-4000:]
    return done.stdout


def test_trusted_requires_explicit_opt_in_and_unknown_values_fail_closed():
    probe = ('from peaso import source_attestation_mode as m;'
             'print(m.MODE, m.TRUSTED, m.ALWAYS)')
    assert _child(None, probe).split() == ['once', 'False', 'False']
    assert _child('trusted', probe).split() == ['trusted', 'True', 'False']
    assert _child('once', probe).split() == ['once', 'False', 'False']
    assert _child('always', probe).split() == ['always', 'False', 'True']
    assert _child('bogus', probe).split() == ['always', 'False', 'True']


def test_trusted_import_builds_the_always_registry_and_evaluations():
    namespace = {}
    exec(compile(FINGERPRINT, '<fingerprint>', 'exec'), namespace)
    proven = namespace['RESULT']
    assert proven['checks'] > 4000 and proven['replayed'] > 1000
    trusted = json.loads(_child('trusted', FINGERPRINT + '\nprint(json.dumps(RESULT))').splitlines()[-1])
    assert trusted == proven


def test_trusted_hook_swaps_code_in_place_and_never_installs_outside_trusted():
    assert mode.ALWAYS and not mode.TRUSTED
    assert trusted_sources.install() is False
    from peaso.checks import private_secret_shared_source_successor_20261021 as shared
    assert shared._check_function.__code__.co_name == '_check_function'
    probe = (
        'import peaso.checks, sys\n'
        'from peaso import trusted_sources as t\n'
        'from peaso.checks import private_secret_shared_source_successor_20261021 as s\n'
        'from peaso.checks import gcp_private_workbench_head3_source_successor_20261021 as w\n'
        'print(s._check_function.__code__ is t._skip.__code__,'
        ' w.reviewed_inputs.__code__ is t.CONSTRUCTIVE[w.__name__]["reviewed_inputs"].__code__,'
        ' w.reviewed_inputs.__globals__ is vars(w),'
        ' sorted(set(t.PURE) | set(t.CONSTRUCTIVE)) == sorted(t._PATCHED))\n')
    assert _child('trusted', probe).split() == ['True', 'True', 'True', 'True']
    assert _child('once', probe.replace('print(', 'print(t._PATCHED == set(),')).split()[0] == 'True'


def test_swap_rejects_closures():
    def outer():
        value = 1

        def inner():
            return value
        return inner
    with pytest.raises(RuntimeError, match='plain function'):
        trusted_sources._swap(outer(), trusted_sources._SKIP_CODE)
    plain = types.FunctionType(trusted_sources._skip.__code__, {})
    trusted_sources._swap(plain, trusted_sources._SKIP_CODE)


def test_always_mode_still_rejects_a_tampered_reviewed_source(monkeypatch):
    from peaso.checks import private_secret_shared_source_successor_20261021 as shared
    root = Path(shared.__file__).resolve().parents[2]
    original = Path.read_bytes
    receipt = (root / 'peaso/checks' / shared.historical_bridge.RECEIPT).resolve()

    def tampered(path):
        raw = original(path)
        return raw + b'\n' if Path(path).resolve() == receipt else raw

    monkeypatch.setattr(Path, 'read_bytes', tampered)
    with pytest.raises(RuntimeError, match='receipt changed'):
        shared._verify_bridge(root)
    assert hashlib.sha256(original(receipt)).hexdigest() == shared.historical_bridge.RECEIPT_SHA256


def test_trusted_prove_once_never_runs_the_verifier(monkeypatch):
    monkeypatch.setattr(mode, 'TRUSTED', True)
    monkeypatch.setattr(mode, '_ONCE', {})
    calls = []
    mode.prove_once(lambda: calls.append(1))
    assert calls == [] and mode._ONCE == {}
