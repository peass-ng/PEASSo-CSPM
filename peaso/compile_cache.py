"""Production-only reuse of immutable compilation results during source proofs.

Source admissions re-read and re-compile the same reviewed files many times in
one process.  Code objects are immutable, so a code compile of identical
source text, filename, mode, effective flags and optimisation level returns a
shared object.  Syntax trees are mutable, so a cached tree is handed out only
to reviewed callers listed in ``_READ_ONLY_PARSERS`` that only inspect it.

Disabled when PEASO_SOURCE_ATTESTATION=always (CI and image builds), so every
proof there still parses and compiles fresh.
"""
import __future__
import ast
import builtins
import hashlib
import sys
from pathlib import Path

from peaso import source_attestation_mode as _mode

_ROOTS = tuple({str(Path(__file__).parent) + '/', str(Path(__file__).resolve().parent) + '/'})
_ORIGINAL_COMPILE = builtins.compile
_ORIGINAL_PARSE = ast.parse
# Future-statement bits a caller passes implicitly when dont_inherit is false
# (CPython PyCF_MASK; nested_scopes is an obsolete no-op flag).
_INHERITED = 0
for _name in __future__.all_feature_names:
    if _name != 'nested_scopes':
        _INHERITED |= getattr(__future__, _name).compiler_flag
_CODE_LIMIT, _TREE_LIMIT = 1024, 128
_CODE = {}
_TREES = {}
# (path relative to peaso/, function name) of callers reviewed to only read the
# returned tree: they walk it, slice source lines and compile copies.
_READ_ONLY_PARSERS = frozenset({
    ('private_reviewed_collector_successor_20261022.py', 'fragment'),
    ('private_reviewed_collector_successor_20261022.py', 'trusted_definition'),
    ('private_secret_source_epoch_20261021.py', '_check_helper_import'),
    ('private_secret_source_epoch_20261021.py', '_check_contextmanager_helper'),
    ('private_secret_source_epoch_20261021.py', '_alias_source'),
    ('checks/k8s_annotation_native_admission_20261020.py', '_verified_source'),
    ('checks/k8s_annotation_native_source_successor_20261021.py', '_current_functions'),
    ('checks/k8s_annotation_native_source_successor_20261021.py', '_engine_plan_source'),
})


def _digest(source):
    return hashlib.sha256(source if type(source) is bytes else source.encode('utf-8', 'surrogatepass')).digest()


def _reviewed_parser(code):
    path = code.co_filename
    return any(path.startswith(root) and (path[len(root):], code.co_name) in _READ_ONLY_PARSERS
               for root in _ROOTS)


def _compile(source, filename, mode, flags=0, dont_inherit=False, optimize=-1, **extra):
    caller = sys._getframe(1).f_code
    if (extra or type(source) not in (str, bytes) or flags & ast.PyCF_ONLY_AST
            or type(filename) is not str or type(mode) is not str
            or type(flags) is not int or type(optimize) is not int
            or not caller.co_filename.startswith(_ROOTS)):
        if not dont_inherit:
            flags |= caller.co_flags & _INHERITED
        return _ORIGINAL_COMPILE(source, filename, mode, flags, True, optimize, **extra)
    if not dont_inherit:
        flags |= caller.co_flags & _INHERITED
    key = (_digest(source), type(source), filename, mode, flags, optimize)
    code = _CODE.get(key)
    if code is None:
        code = _ORIGINAL_COMPILE(source, filename, mode, flags, True, optimize)
        if len(_CODE) >= _CODE_LIMIT:
            _CODE.clear()
        _CODE[key] = code
    return code


def _parse(source, filename='<unknown>', mode='exec', *, type_comments=False, feature_version=None, **extra):
    caller = sys._getframe(1).f_code
    if (extra or type(source) not in (str, bytes) or not _reviewed_parser(caller)
            or type(filename) is not str or type(mode) is not str or feature_version is not None):
        return _ORIGINAL_PARSE(source, filename, mode, type_comments=type_comments,
                               feature_version=feature_version, **extra)
    key = (_digest(source), type(source), filename, mode, bool(type_comments))
    tree = _TREES.get(key)
    if tree is None:
        tree = _ORIGINAL_PARSE(source, filename, mode, type_comments=type_comments)
        if len(_TREES) >= _TREE_LIMIT:
            _TREES.clear()
        _TREES[key] = tree
    return tree


def install():
    """Install the caches once, in production mode only."""
    if _mode.TRUSTED:
        from peaso import trusted_sources
        trusted_sources.install()
    if _mode.ALWAYS or builtins.compile is _compile:
        return False
    builtins.compile = _compile
    ast.parse = _parse
    return True


def clear():
    _CODE.clear()
    _TREES.clear()
