"""Run one deterministic shard of the ordinary pytest suite.

Every test file is collected from the ``tests`` root. A few historically slow
modules are collected on multiple jobs, then their individual node IDs are
assigned to exactly one job. This retains the full-suite draft-isolation and
source-admission hooks in tests/conftest.py.
"""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import subprocess
import sys


TESTS = Path("tests")
# The shard count comes from the caller (the CI matrix passes --shards); the
# collection hook reads it back from the environment, so any count works.
_SHARD_ENV = "PEASO_CI_PYTEST_SHARD"
_SHARDS_ENV = "PEASO_CI_PYTEST_SHARDS"

# Seconds summed from the completed JUnit files in Actions run 39701781083.
# The previous run was interrupted on shards 0 and 6, so unmeasured files use
# source size. Hints schedule work only; they never select test outcomes.
HISTORIC_SECONDS = {
    "test_azure_databricks_notebook_secret_integration_20261020.py": 1501.49,
    "test_gcp_dataflow_batch_source_runtime_20261020.py": 1229,
    "test_peaso_compliance_draft_isolation.py": 1019,
    "test_k8s_selected_metadata_production_20261020.py": 824,
    "test_k8s_selected_metadata_runtime_gates_20261020.py": 588,
    "test_peaso_native_pipeline_acceptance.py": 543,
    "test_azure_function_package_integrated_20261020.py": 525,
    "test_peaso_privesc_integration.py": 501,
    "test_peaso_cli_connector_parity.py": 394,
    "test_peaso_related_snapshots.py": 382,
    "test_peaso_gcp_remaining_clarity_reviewed.py": 354,
    "test_aws_codebuild_buildspec_runtime_20261020.py": 304,
    "test_gcp_function_secret_paired_integration_20261020.py": 303,
    "test_peaso_graph_scale.py": 206,
    "test_peaso_engine.py": 196,
    "test_gcp_function_source_secret_review_20261019.py": 137,
    "test_gcp_function_secret_partial_page_20261020.py": 121,
    "test_api_finding_types_static_20261020.py": 107,
    "test_aws_selected_configuration_secret_review_20261020.py": 107,
    "test_peaso_iam_grants_api.py": 99,
    "test_peaso_cli_cancellation.py": 99,
    "test_peaso_privesc_schema_ext_k8s_blockers.py": 99,
    "test_native_policy_validation_static_20261020.py": 98,
    "test_aws_identity_sdk_closure_review.py": 95,
    "gcp_batch_referenced_source_20261020_test.py": 92,
    "test_gcp_configuration_secret_review_20261019.py": 92,
    "test_peaso_compliance_compiler_determinism.py": 88,
    "test_azure_acr_image_secret_review_20261020.py": 86,
    "test_aws_identity_closure_review.py": 79,
    "test_azure_function_package_source_20261020.py": 77,
}

# Individual testcase seconds from the completed shard 11 JUnit in Actions run
# 39723210201. With loadfile, the module took 1,501.49 seconds on one worker;
# these seven cases account for 1,492.45 seconds of it. Assign them longest
# first so each occupies a different job; unknown nodes retain their hash owner.
MEASURED_NODE_SECONDS = {
    "test_azure_databricks_notebook_secret_integration_20261020.py": {
        "test_reviewed_bytes_cannot_change_before_admission[consumer]": 223.60,
        "test_reviewed_bytes_cannot_change_before_admission[producer]": 222.51,
        "test_reviewed_bytes_cannot_change_before_admission[fixture]": 212.27,
        "test_typed_consumer_and_reachable_helper_identity_guard[helper]": 210.41,
        "test_reviewed_bytes_cannot_change_before_admission[receipt]": 210.13,
        "test_typed_consumer_and_reachable_helper_identity_guard[function]": 208.01,
        "test_reviewed_bytes_cannot_change_before_admission[proposal]": 205.52,
    },
}

# Loadfile keeps each selected module on one xdist worker. These modules have
# independent parametrized cases and dominated the old critical path, so spread
# their node IDs across isolated Actions jobs without raising per-job CPU use.
SPLIT_COUNTS = {
    "test_azure_databricks_notebook_secret_integration_20261020.py": 7,
    "test_gcp_dataflow_batch_source_runtime_20261020.py": 4,
    "test_peaso_compliance_draft_isolation.py": 4,
    "test_k8s_selected_metadata_production_20261020.py": 4,
    "test_k8s_selected_metadata_runtime_gates_20261020.py": 2,
    "test_peaso_native_pipeline_acceptance.py": 2,
    "test_azure_function_package_integrated_20261020.py": 2,
    "test_peaso_privesc_integration.py": 2,
    "test_peaso_cli_connector_parity.py": 2,
    "test_peaso_gcp_remaining_clarity_reviewed.py": 2,
    "test_aws_codebuild_buildspec_runtime_20261020.py": 2,
    "test_gcp_function_secret_paired_integration_20261020.py": 2,
}


def test_files() -> list[Path]:
    return sorted(
        path for path in TESTS.rglob("*.py")
        if path.name.startswith("test_") or path.name.endswith("_test.py")
    )


def _weight(path: Path) -> float:
    return HISTORIC_SECONDS.get(path.name, max(1, path.stat().st_size * 0.0003))


def _splits(path: Path, count: int) -> int:
    return min(SPLIT_COUNTS.get(path.name, 1), count)


def partition(files: list[Path], count: int) -> list[list[Path]]:
    if count < 1 or count > len(files):
        raise ValueError("shard count must be between 1 and the number of test files")
    shards: list[list[Path]] = [[] for _ in range(count)]
    # Shard zero runs the isolated performance gate before its ordinary tests.
    weights = [240.0] + [0.0] * (count - 1)
    units = [
        (path, slot, _weight(path) / _splits(path, count))
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
    measured = MEASURED_NODE_SECONDS.get(path.name, {})
    prefix = f"{path}::"
    if nodeid.startswith(prefix) and nodeid[len(prefix):] in measured:
        loads = {owner: 0.0 for owner in owners}
        assigned = {}
        for name, seconds in sorted(measured.items(), key=lambda item: (-item[1], item[0])):
            owner = min(owners, key=lambda index: (loads[index], index))
            assigned[name] = owner
            loads[owner] += seconds
        return assigned[nodeid[len(prefix):]]
    slot = int.from_bytes(hashlib.sha256(nodeid.encode()).digest()[:8], "big") % len(owners)
    return owners[slot]


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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--shard", type=int, required=True)
    parser.add_argument("--shards", type=int, required=True)
    parser.add_argument("--verify", action="store_true", help="check coverage and print shard sizes without pytest")
    args, pytest_args = parser.parse_known_args()
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
    selected = set(shards[args.shard])
    ignored = [f"--ignore={path}" for path in files if path not in selected]
    command = [sys.executable, "-m", "pytest", "-p", "scripts.pytest_shard", *pytest_args, *ignored, str(TESTS)]
    env = {**os.environ, _SHARD_ENV: str(args.shard), _SHARDS_ENV: str(args.shards)}
    return subprocess.call(command, env=env)


if __name__ == "__main__":
    raise SystemExit(main())
