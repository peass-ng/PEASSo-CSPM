"""Fail CI when shipped Python code references an undefined name.

Only source-replacement functions and seven historical compiler visitors have
verified dynamic bindings that pyflakes cannot see.  Star-import warnings are
outside this gate; they are not UndefinedName diagnostics.
"""

import ast
from pathlib import Path

from pyflakes.checker import Checker
from pyflakes.messages import UndefinedName


ROOT = Path(__file__).resolve().parents[1]
TRUSTED = Path('peaso/trusted_sources.py')
TRUSTED_NAMES = frozenset({
    'CASES_FILE', 'GUARD', 'IDS', 'MARK', 'PRIVATE_NAME', 'PRIVATE_RECEIPT',
    'Path', 'RECEIPT', '_PREDECESSORS', '_PRIVATE_NAME', '_clone_guard',
    '_namespace', '_pairs', '_source_receipt', '_successor',
    'annotation_successor', 'json', 'original', 'private_source', 'proof',
})
VISITOR_FILES = frozenset(Path('peaso/checks') / name for name in (
    'azure_metadata_only_shared_successor_20261020.py',
    'collector_noop_authorization_shared_successor_20261020.py',
    'aws_deployed_ai_shared_successor_20261020.py',
    'gcp_positive_conservation_shared_source_successor_20261020.py',
    'private_secret_shared_source_successor_20261021.py',
    'azure_jit_parent_type_shared_successor_20261020.py',
    'native_admission_cpu_shared_successor_20261020.py',
))


def _constructive_lines(tree):
    """Trusted replacement bodies execute with the target module's globals."""
    lines = set()
    for node in tree.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if any(isinstance(dec, ast.Call) and isinstance(dec.func, ast.Name)
               and dec.func.id == '_constructive' for dec in node.decorator_list):
            lines.update(range(node.lineno, node.end_lineno + 1))
    return lines


def _visitor_names(tree):
    """These recursive visitors are local functions deleted after their use."""
    allowed = set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        body = node.body
        for name in ('visit', 'walk'):
            if (any(isinstance(child, ast.FunctionDef) and child.name == name for child in body)
                    and any(isinstance(child, ast.Delete) and any(
                        isinstance(target, ast.Name) and target.id == name
                        for target in child.targets) for child in body)):
                allowed.add(name)
    return allowed


def test_no_undefined_names_in_peaso():
    failures = []
    for path in sorted((ROOT / 'peaso').rglob('*.py')):
        relative = path.relative_to(ROOT)
        tree = ast.parse(path.read_bytes(), filename=str(relative))
        checker = Checker(tree, filename=str(relative))
        trusted_lines = _constructive_lines(tree) if relative == TRUSTED else set()
        visitors = _visitor_names(tree) if relative in VISITOR_FILES else set()
        for message in checker.messages:
            if not isinstance(message, UndefinedName):
                continue
            name = message.message_args[0]
            if relative == TRUSTED and name in TRUSTED_NAMES and message.lineno in trusted_lines:
                continue
            if relative in VISITOR_FILES and name in visitors:
                continue
            failures.append(f'{relative}:{message.lineno}:{message.col + 1}: undefined name {name!r}')
    assert not failures, '\n'.join(failures)
