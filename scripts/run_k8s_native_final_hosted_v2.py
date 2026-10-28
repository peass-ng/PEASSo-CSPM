"""Run the prepared K8s paired Hardening replay after root releases its slot.

`--preflight` is entirely offline. `--launch` starts model containers and
requires the exact root release marker in CODEX_FINDINGS.txt.
"""
from __future__ import annotations

import argparse
from collections import deque
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time


HOME = Path.home() / "peaso-work"
PRIVATE = HOME / "native-final-k8s-private"
REPLAY = PRIVATE / "hosted-pair-05a1919e-v3-run1"
SOURCE = PRIVATE / "pinned-d3"
TOKEN = HOME / "replay/platform-codex-token.txt"
ARM = HOME / "replay/hardening_84_container_arm.py"
IMAGE = "sha256:ad277f7ec3677d5e78bf723d42256ea41f69528309483a07304b64914111e312"
RELEASE = "ROOT_RELEASE_K8S_NATIVE_FINAL_V2_05A1919E"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def private_json(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump(value, stream, sort_keys=True, separators=(",", ":"))
        stream.write("\n")


sys.path.insert(0, str(SOURCE))
from peaso.ai.collection_coverage import index  # noqa: E402
from peaso.ai.contracts import validate_reviews  # noqa: E402
from peaso.ai.pipeline import compact_document, findings_document, review_context  # noqa: E402
from peaso.ai.review_groups import chunks, expand  # noqa: E402


def document(common, ids):
    rows = {row["id"]: row for row in common["hardening"]}
    batch = [rows[ident] for ident in ids]
    context = review_context(common["report"], common["resources"], batch,
                             _coverage=index(common["report"]["coverage"]))
    return compact_document(findings_document(
        context["scan"], batch, context["resources"]))


def preflight():
    receipt = json.loads((REPLAY / "preflight.json").read_text())
    common = json.loads((REPLAY / "common.json").read_text())
    plans = json.loads((REPLAY / "plans.json").read_text())
    if (receipt["status"] != "prepared_no_model_calls"
            or receipt["version"] != 2
            or receipt["image_id"] != IMAGE
            or sha(Path(__file__).resolve().parents[1] / "peaso/ai/k8s_native_final_allowlist.json") != receipt["manifest_sha256"]
            or sha(Path(__file__).resolve().parents[1] / "outputs/k8s-native-final-saved-pairs-v2.json") != receipt["audit_receipt_sha256"]
            or sha(REPLAY / "common.json") != receipt["common_sha256"]
            or sha(REPLAY / "plans.json") != receipt["plans_sha256"]
            or sha(TOKEN) != "5863a3e6bc00982791d214c1f3346db8a6a6fa7438cdb1afecd2a1dc5e80ddce"
            or TOKEN.stat().st_mode & 0o777 != 0o600
            or sha(ARM) != "711ad4dbd4651982f1bbbb3bcc84f7ac97322eaeee021f09617b171eae765066"):
        raise ValueError("hosted_preflight_pin_drift")
    image = subprocess.check_output(["docker", "image", "inspect", IMAGE,
        "--format", "{{.Id}}|{{.Os}}/{{.Architecture}}|{{.Config.User}}"], text=True).strip()
    if image != IMAGE + "|linux/amd64|10001:10001":
        raise ValueError("image_runtime_drift")
    if (len(common["hardening"]) != 1594 or len(common["native_ids"]) != 679
            or len(plans["baseline"]["selected_ids"]) != 1594
            or len(plans["candidate"]["selected_ids"]) != 915):
        raise ValueError("input_counts_drift")
    for arm in ("baseline", "candidate"):
        plan = plans[arm]
        selected = set(plan["selected_ids"])
        representatives = [ident for batch in plan["initial_batches"] for ident in batch]
        if (len(representatives) != len(set(representatives))
                or set(representatives) != set(plan["representative_ids"])
                or selected != set(representatives) | {
                    member for values in plan["members"].values() for member in values}):
            raise ValueError("review_plan_invalid")
        hashes = [hashlib.sha256(json.dumps(document(common, batch), sort_keys=True,
                  default=str).encode()).hexdigest() for batch in plan["initial_batches"]]
        if hashes != receipt[arm]["document_hashes"]:
            raise ValueError("staged_document_drift")
    return common, plans, receipt


def stage(common, arm, number, ids):
    directory = REPLAY / arm / f"launch-{number:03d}"
    directory.mkdir(mode=0o700)
    private_json(directory / "findings.json", document(common, ids))
    private_json(directory / "credentials.json", {"version": 2, "entries": []})
    return directory


def launch_one(directory):
    command = ["docker", "run", "--rm", "--platform", "linux/amd64",
               "--entrypoint", "python", "--user", "0:0", "--cpus", "0.5",
               "--memory", "2g", "--pids-limit", "256", "--read-only",
               "--tmpfs", "/tmp:rw,noexec,nosuid,size=512m",
               "--env", "PYTHONPATH=/app", "--env", "AWS_EC2_METADATA_DISABLED=true",
               "--mount", f"type=bind,src={directory},dst=/workspace",
               "--mount", f"type=bind,src={TOKEN},dst=/run/secrets/platform-codex-token,readonly",
               "--mount", f"type=bind,src={ARM},dst=/run/hardening_84_container_arm.py,readonly",
               IMAGE, "/run/hardening_84_container_arm.py"]
    result = subprocess.run(command, capture_output=True, text=True, timeout=510)
    if result.returncode or not (directory / "result.json").is_file():
        raise RuntimeError(f"model_launch_failed:{directory.name}:exit={result.returncode}")
    return (json.loads((directory / "runtime-metrics.json").read_text()),
            json.loads((directory / "result.json").read_text()))


def run_arm(common, plan, arm):
    by_id = {row["id"]: row for row in common["hardening"]}
    queue = deque((batch, True) for batch in plan["initial_batches"])
    output, launches = {}, []
    directory = REPLAY / arm
    directory.mkdir(mode=0o700, exist_ok=False)
    started = time.monotonic()
    next_number = 0
    with ThreadPoolExecutor(max_workers=6) as pool:
        pending = {}
        while queue or pending:
            if time.monotonic() - started > 1200:
                raise TimeoutError("arm_budget_1200_exceeded")
            while queue and len(pending) < 6:
                ids, grouped = queue.popleft()
                work = stage(common, arm, next_number, ids)
                next_number += 1
                pending[pool.submit(launch_one, work)] = (ids, grouped, work)
            done, _ = wait(pending, timeout=20, return_when=FIRST_COMPLETED)
            for future in done:
                ids, grouped, work = pending.pop(future)
                metric, data = future.result()
                checked = validate_reviews(data, [by_id[ident] for ident in ids])["items"]
                expanded, recheck = expand(checked, {
                    ident: [by_id[member] for member in plan["members"].get(ident, ())]
                    for ident in ids} if grouped else {})
                for review in expanded:
                    ident = review["finding_id"]
                    if ident in output:
                        raise ValueError("duplicate_review_id")
                    output[ident] = review
                queue.extendleft((part, False) for part in reversed(chunks(
                    [row["id"] for row in recheck])))
                launches.append({"launch_id": work.name, "task_ids": ids, **metric})
    if set(output) != set(plan["selected_ids"]):
        raise ValueError("review_coverage_invalid")
    result = {"arm": arm, "reviews": [output[ident] for ident in plan["selected_ids"]],
              "launches": launches, "wall_seconds": time.monotonic() - started,
              "model_calls": sum(row["model_calls"] for row in launches),
              "input_tokens": sum(row["input_tokens"] for row in launches),
              "output_tokens": sum(row["output_tokens"] for row in launches),
              "cpu_x_peak_rss_byte_seconds": sum(
                  row["cpu_seconds"] * row["peak_rss_bytes"] for row in launches)}
    private_json(directory / "arm-result.json", result)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("preflight", "launch"))
    parser.add_argument("--run", type=int, choices=(1, 2), required=True)
    args = parser.parse_args()
    global REPLAY
    REPLAY = PRIVATE / f"hosted-pair-05a1919e-v3-run{args.run}"
    common, plans, receipt = preflight()
    if args.mode == "preflight":
        print(json.dumps({arm: {key: receipt[arm][key] for key in
                          ("input_count", "representatives", "initial_batches")}
                          for arm in ("baseline", "candidate")}, sort_keys=True))
        return
    release_lines = (HOME / "CODEX_FINDINGS.txt").read_text().splitlines()
    if RELEASE not in {line.strip() for line in release_lines}:
        raise PermissionError("exclusive_model_slot_not_released_by_root")
    for arm in ("baseline", "candidate"):
        run_arm(common, plans[arm], arm)


if __name__ == "__main__":
    main()
