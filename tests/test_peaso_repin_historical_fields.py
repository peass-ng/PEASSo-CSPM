"""The source re-pin tool never rewrites historical witnesses (NEXT-PROVENANCE-1)."""
import ast
import hashlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_SPEC = importlib.util.spec_from_file_location('peaso_repin_sources', ROOT / 'scripts/peaso_repin_sources.py')
repin = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(repin)


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _git(cwd, *args):
    subprocess.run(['git', *args], cwd=cwd, check=True, capture_output=True)












def test_registered_python_pins_are_current_in_tree():
    """A stale current pin fails here (and in push_locked's gate) instead of rotting."""
    registered = {path for path, _ in (*repin.PY_PIN_BLOCKS, *repin.CURRENT_PIN_CONSTANTS)}
    for rel in sorted(registered):
        text = (ROOT / rel).read_text(encoding='utf-8', errors='surrogateescape')
        assert {name for path, name in repin.PY_PIN_BLOCKS if path == rel} <= {
            node.targets[0].id for node in ast.parse(text).body
            if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name)}, rel
        assert repin.refresh_current_pins(rel, text) == text, f'{rel}: stale current pin; run scripts/peaso_repin_sources.py'
