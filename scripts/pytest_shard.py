"""Run one deterministic shard of the ordinary pytest suite.

Every test file is collected from the ``tests`` root. A few historically slow
modules are collected on multiple jobs, then their individual node IDs are
assigned to exactly one job. This retains the full-suite draft-isolation and
source-admission hooks in tests/conftest.py.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys


TESTS = Path("tests")
# The shard count comes from the caller (the CI matrix passes --shards); the
# collection hook reads it back from the environment, so any count works.
_SHARD_ENV = "PEASO_CI_PYTEST_SHARD"
_SHARDS_ENV = "PEASO_CI_PYTEST_SHARDS"

# Per-file seconds summed from the JUnit reports of a complete CI run (refresh
# with --record-junit). Files without a measurement use source size. Hints
# schedule work only; they never select test outcomes.
SECONDS_FILE = Path(__file__).with_name("pytest_shard_seconds.json")

# Loadfile keeps each module on one xdist worker. Modules measured at 100+
# seconds would set a job's critical path, and their tests are independent, so
# spread their node IDs across isolated Actions jobs.
SPLIT_COUNTS = {
    "test_peaso_gcp_remaining_clarity_reviewed.py": 4,
    "test_azure_acr_image_secret_review_20261020.py": 2,
    "test_aws_selected_configuration_secret_review_20261020.py": 2,
    "test_peaso_collectors_aws.py": 2,
    "test_k8s_selected_metadata_production_20261020.py": 2,
    "test_gcp_configuration_secret_review_20261019.py": 2,
    "test_gcp_dataflow_batch_source_runtime_20261020.py": 2,
    "test_aws_s3_selected_source_integration_20261020.py": 2,
    "test_aws_code_log_content_review_20261019.py": 2,
}


def _measured_seconds() -> dict[str, float]:
    try:
        return json.loads(SECONDS_FILE.read_text())
    except FileNotFoundError:
        return {}


def test_files() -> list[Path]:
    return sorted(
        path for path in TESTS.rglob("*.py")
        if path.name.startswith("test_") or path.name.endswith("_test.py")
    )


def _weight(path: Path, measured: dict[str, float]) -> float:
    return measured.get(path.as_posix(), max(1, path.stat().st_size * 0.0003))


def _splits(path: Path, count: int) -> int:
    return min(SPLIT_COUNTS.get(path.name, 1), count)


def partition(files: list[Path], count: int) -> list[list[Path]]:
    if count < 1 or count > len(files):
        raise ValueError("shard count must be between 1 and the number of test files")
    shards: list[list[Path]] = [[] for _ in range(count)]
    # Shard zero runs the isolated performance gate before its ordinary tests.
    weights = [240.0] + [0.0] * (count - 1)
    measured = _measured_seconds()
    units = [
        (path, slot, _weight(path, measured) / _splits(path, count))
        for path in files
        for slot in range(_splits(path, count))
    ]
    for path, _, weight in sorted(units, key=lambda unit: (-unit[2], str(unit[0]), unit[1])):
        choices = [i for i in range(count) if path not in shards[i]]
        index = min(choices, key=lambda i: (weights[i], i))
        shards[index].append(path)
        weights[index] += weight
    return [sorted(shard) for shard in shards]


def _placements(shards: list[list[Path]]) -> dict[Path, list[int]]:
    result: dict[Path, list[int]] = {}
    for i, shard in enumerate(shards):
        for path in shard:
            result.setdefault(path, []).append(i)
    return result


def _verify(files: list[Path], shards: list[list[Path]]) -> None:
    placements = _placements(shards)
    if set(placements) != set(files) or any(not shard for shard in shards):
        raise RuntimeError("test shard file coverage is incomplete")
    for path in files:
        if len(placements[path]) != _splits(path, len(shards)):
            raise RuntimeError(f"incorrect shard count for {path}")


def owner_for(nodeid: str, path: Path, placements: dict[Path, list[int]]) -> int:
    owners = placements[path]
    slot = int.from_bytes(hashlib.sha256(nodeid.encode()).digest()[:8], "big") % len(owners)
    return owners[slot]


_SELECTED: dict[tuple[str, str], frozenset[Path]] = {}


def _selected_files() -> frozenset[Path] | None:
    shard_text, count_text = os.environ.get(_SHARD_ENV), os.environ.get(_SHARDS_ENV)
    if shard_text is None or count_text is None:
        return None
    key = (shard_text, count_text)
    if key not in _SELECTED:
        _SELECTED[key] = frozenset(partition(test_files(), int(count_text))[int(shard_text)])
    return _SELECTED[key]


def _ignore_unselected(collection_path, config):
    """Skip other shards' test files with one set lookup.

    Thousands of ``--ignore`` options make pytest compare every collected path
    against every option (minutes per job), and the tests conftest would parse
    each skipped file. Every file is still collected by exactly one shard.
    """
    selected = _selected_files()
    if selected is None:
        return None
    path = Path(collection_path)
    if path.suffix != ".py" or not (path.name.startswith("test_") or path.name.endswith("_test.py")):
        return None
    try:
        relative = path.relative_to(Path.cwd())
    except ValueError:
        return None
    return None if relative in selected or relative.parts[:1] != (TESTS.name,) else True


try:
    import pytest
except ImportError:  # main() only needs pytest in the child process.
    pass
else:
    pytest_ignore_collect = pytest.hookimpl(tryfirst=True)(_ignore_unselected)


def pytest_collection_modifyitems(config, items) -> None:
    """Assign each collected node ID of a split module to exactly one job."""
    shard_text = os.environ.get(_SHARD_ENV)
    if shard_text is None:
        return
    shard = int(shard_text)
    placements = _placements(partition(test_files(), int(os.environ[_SHARDS_ENV])))
    selected, deselected = [], []
    for item in items:
        path = Path(item.path).relative_to(Path.cwd())
        owners = placements.get(path)
        if owners is None:
            raise RuntimeError(f"collected test outside shard plan: {item.nodeid}")
        owner = owner_for(item.nodeid, path, placements)
        (selected if owner == shard else deselected).append(item)
    if deselected:
        config.hook.pytest_deselected(items=deselected)
        items[:] = selected


def record_junit(reports: list[str]) -> dict[str, float]:
    """Sum testcase seconds per test file across JUnit reports."""
    import xml.etree.ElementTree as ET

    seconds: dict[str, float] = {}
    for report in reports:
        for case in ET.parse(report).iter("testcase"):
            parts = case.get("classname", "").split(".")
            while parts and not Path(*parts[:-1], parts[-1] + ".py").is_file():
                parts.pop()
            if parts:
                name = Path(*parts[:-1], parts[-1] + ".py").as_posix()
                seconds[name] = seconds.get(name, 0.0) + float(case.get("time") or 0)
    return {name: round(value, 1) for name, value in sorted(seconds.items()) if value >= 0.5}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--record-junit", nargs="+", metavar="REPORT", help=f"rewrite {SECONDS_FILE.name} from JUnit reports")
    parser.add_argument("--shard", type=int)
    parser.add_argument("--shards", type=int)
    parser.add_argument("--verify", action="store_true", help="check coverage and print shard sizes without pytest")
    args, pytest_args = parser.parse_known_args()
    if args.record_junit:
        SECONDS_FILE.write_text(json.dumps(record_junit(args.record_junit), indent=0) + "\n")
        return 0
    if args.shard is None or args.shards is None:
        parser.error("--shard and --shards are required")
    if pytest_args and pytest_args[0] == "--":
        pytest_args.pop(0)
    files = test_files()
    if not files or not 0 <= args.shard < args.shards:
        parser.error("invalid shard or no test files")
    shards = partition(files, args.shards)
    _verify(files, shards)
    print(
        f"shard {args.shard + 1}/{args.shards}: {len(shards[args.shard])}/{len(files)} "
        f"test files, {sum(path.stat().st_size for path in shards[args.shard])} source bytes",
        flush=True,
    )
    if args.verify:
        return 0
    if not pytest_args:
        parser.error("pass pytest options after --")
    command = [sys.executable, "-m", "pytest", "-p", "scripts.pytest_shard", *pytest_args, str(TESTS)]
    env = {**os.environ, _SHARD_ENV: str(args.shard), _SHARDS_ENV: str(args.shards)}
    return subprocess.call(command, env=env)


if __name__ == "__main__":
    raise SystemExit(main())
