"""Exact source routing and immutable revision evidence, independent of runtime admission."""
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACK = ROOT / "peaso" / "rulepacks"


def reviews():
    return [(path, json.loads(path.read_text())) for pattern in ("reviewed_gcp_ports*.json", "reviewed_k8s_ports*.json") for path in PACK.glob(pattern)]


def test_every_supported_or_replacement_identifier_has_real_native_implementation():
    from peaso.checks import CHECKS
    parent_ids = tuple(check.id for check in CHECKS)
    # Some retained source checks are not in the signed runtime registry. Import
    # them in a child so this source audit cannot add their IDs to the parent
    # process before the signed-registry equality test runs.
    child = """
import importlib, json
from pathlib import Path
from peaso.checks import CHECKS
imported_modules = []
for path in (Path.cwd() / 'peaso' / 'checks').glob('*_ports_*.py'):
    if path.name.startswith(('gcp_', 'k8s_')):
        importlib.import_module('peaso.checks.' + path.stem)
        imported_modules.append(path.stem)
print(json.dumps({'imported_modules': imported_modules,
                  'checks': {check.id: {'dependencies': bool(check.dependencies),
                                        'provider': check.provider} for check in CHECKS}}))
"""
    completed = subprocess.run([sys.executable, "-c", child], cwd=ROOT,
                               capture_output=True, text=True, check=True)
    result = json.loads(completed.stdout)
    assert result["imported_modules"], "the isolated source check must import actual port modules"
    registry = result["checks"]
    checked = 0
    for _, rows in reviews():
        for row in rows.values():
            for cid in row.get("native_checks", []) + row.get("replacement_checks", []):
                checked += 1
                assert cid in registry, cid
                assert registry[cid]["dependencies"] and registry[cid]["provider"] in ("gcp", "k8s")
    assert checked > 0, "the source review must validate actual native references"
    assert tuple(check.id for check in CHECKS) == parent_ids, "source test polluted the published parent registry"
