"""Guard against silently shadowed exposure handlers during source unions."""

import ast
from collections import Counter
from pathlib import Path


def test_exposure_module_has_no_duplicate_top_level_definitions():
    source = Path(__file__).resolve().parents[1] / "peaso/analysis/internet_exposure.py"
    tree = ast.parse(source.read_text())
    counts = Counter(node.name for node in tree.body
                     if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)))
    assert {name: count for name, count in counts.items() if count > 1} == {}
