"""The compliance compiler output must not depend on Python's hash seed."""
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
PACK = ROOT / "peaso/rulepacks"


def _compile_into(tmp_path, seed):
    output = tmp_path / str(seed)
    output.mkdir()
    paths = {name: output / name for name in
             ("compliance_requirements.json", "compliance_lookup.json", "check_descriptions.json")}
    environment = os.environ.copy()
    environment.update(PYTHONHASHSEED=str(seed), PYTHONDONTWRITEBYTECODE="1")
    command = [sys.executable, "scripts/peaso_compliance_compile.py",
               "--ledger-root", "docs/compliance-ledgers",
               "--audit-matrix", "docs/compliance-ledgers/inputs/compliance-requirements-matrix.json.gz",
               "--audit-summary", "docs/compliance-ledgers/inputs/compliance-requirements-summary.json",
               "--native-catalog", str(PACK / "native_catalog.json"),
               "--requirements-output", str(paths["compliance_requirements.json"]),
               "--lookup-output", str(paths["compliance_lookup.json"]),
               "--descriptions-output", str(paths["check_descriptions.json"])]
    subprocess.run(command, cwd=ROOT, env=environment, text=True,
                   capture_output=True, check=True, timeout=120)
    return {name: path.read_bytes() for name, path in paths.items()}


def _edges_from_requirements(pack):
    return {(check_id, framework["id"], requirement["requirement_id"],
             requirement["decision"], requirement["runtime_status"])
            for framework in pack["frameworks"]
            for requirement in framework["requirements"]
            for check_id in requirement["native_checks"]}


def _edges_from_reverse(mapping):
    return {(check_id, tag["framework_id"], tag["requirement_id"],
             tag["decision"], tag["runtime_status"])
            for check_id, tags in mapping.items() for tag in tags}


def test_compiler_outputs_are_identical_across_hash_seeds_and_indexes_agree(tmp_path):
    first = _compile_into(tmp_path, 0)
    second = _compile_into(tmp_path, 167)
    assert first == second
    requirements = json.loads(first["compliance_requirements.json"])
    lookup = json.loads(first["compliance_lookup.json"])
    forward = _edges_from_requirements(requirements)
    assert forward
    # Forward requirement edges and both reverse indexes describe the same mapping.
    assert forward == _edges_from_reverse(requirements["by_check"])
    assert forward == _edges_from_reverse(lookup["by_check"])
    native = json.loads((PACK / "native_catalog.json").read_bytes())
    active = {row["id"] for row in native["checks"]}
    archived = {row["id"] for row in native["archived_checks"]}
    assert not active.intersection(archived)
