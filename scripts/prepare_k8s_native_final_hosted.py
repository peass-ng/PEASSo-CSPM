"""Prepare a pinned, same-snapshot K8s Hardening paired model replay offline.

This script never starts Docker or a model. Private inputs and staged model
documents stay outside the repository; stdout and the receipt are numeric.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
SCAN = "05a1919efd1849d99c2ae8e6b8637b6f"
SOURCE_COMMIT = "d3e0e0ebfc8cf85196951460ed6db99f59e99c19"
IMAGE = "sha256:ad277f7ec3677d5e78bf723d42256ea41f69528309483a07304b64914111e312"
TOKEN_SHA = "5863a3e6bc00982791d214c1f3346db8a6a6fa7438cdb1afecd2a1dc5e80ddce"
CHECKS = frozenset({"k8s.deployment.non_root", "k8s.replicaset.non_root"})


def sha(path: Path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(path: Path):
    body = path.read_bytes()
    return json.loads(gzip.decompress(body) if body[:2] == b"\x1f\x8b" else body)


def private_json(path: Path, value):
    if path.exists():
        raise FileExistsError(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump(value, stream, sort_keys=True, separators=(",", ":"))
        stream.write("\n")


def prepare(private: Path, replay: Path):
    source = private / "pinned-d3"
    token = Path.home() / "peaso-work/replay/platform-codex-token.txt"
    if not (source / "peaso/ai/runner.py").is_file():
        raise ValueError("pinned_d3_source_missing")
    expected = {"runner.py", "output_validation.py", "prompting.py",
                "agents/hardening.yaml"}
    for name in expected:
        if sha(source / "peaso/ai" / name) != sha(
                Path.home() / "peaso-work/replay/image-baseline-ai" / name):
            raise ValueError("pinned_image_source_drift:" + name)
    if token.stat().st_mode & 0o777 != 0o600 or sha(token) != TOKEN_SHA:
        raise ValueError("private_model_token_drift")
    image = subprocess.check_output([
        "docker", "image", "inspect", IMAGE, "--format",
        "{{.Id}}|{{.Os}}/{{.Architecture}}|{{.Config.User}}"], text=True).strip()
    if image != IMAGE + "|linux/amd64|10001:10001":
        raise ValueError("pinned_image_drift")
    pair_receipt = read(private / "pair-chunk-receipt.json")
    matches = [pair for pair in pair_receipt["pairs"] if pair["scan_id"] == SCAN]
    if len(matches) != 1:
        raise ValueError("exact_pair_missing")
    pair = matches[0]
    scan_dir = private / SCAN
    pre_manifest = read(scan_dir / pair["pre_manifest"])
    final_manifest = read(scan_dir / pair["final_manifest"])
    if (pre_manifest["summary"]["snapshot_id"] != pair["snapshot_id"]
            or final_manifest["summary"]["snapshot_id"] != pair["snapshot_id"]):
        raise ValueError("same_snapshot_pin_invalid")
    ai = read(scan_dir / Path(pair["ai_review"]).name)
    if (len(ai["stage_inputs"]["hardening"]) != 1594
            or len(ai["reviews"]["hardening"]) != 1594
            or set(ai["stage_inputs"]["hardening"]) != {
                row["finding_id"] for row in ai["reviews"]["hardening"]}):
        raise ValueError("saved_hardening_review_coverage_invalid")

    # Import the immutable d3 source, which supplied the pinned image's AI
    # runner and prompt. This is a new-model replay, not a historical model pin.
    sys.path.insert(0, str(source))
    from peaso.ai.collection_coverage import index
    from peaso.ai.pipeline import compact_document, findings_document, review_context
    from peaso.ai.review_groups import chunks, plan
    from peaso.engine import hydrate_finding

    pre_report_path = scan_dir / Path(pre_manifest["report_json"]).name
    report = read(pre_report_path)
    if report["snapshot_id"] != pair["snapshot_id"] or report["provider"] != "k8s":
        raise ValueError("pre_report_snapshot_invalid")
    hardening = [hydrate_finding(observation, report["check_frameworks"],
                 report["check_meta"], report["check_meta_encoding"],
                 report["remediation_templates"])
                 for group in report["findings"]
                 for observation in (group.get("observations") or [group])
                 if observation.get("category", group.get("category")) == "hardening"
                 and observation["status"] == "FAIL"]
    ids = {row["id"] for row in hardening}
    if len(hardening) != 1594 or ids != set(ai["stage_inputs"]["hardening"]):
        raise ValueError("pre_report_hardening_inputs_invalid")
    native = [row for row in hardening if row["check_id"] in CHECKS]
    remaining = [row for row in hardening if row["check_id"] not in CHECKS]
    if len(native) != 30 or len(remaining) != 1564:
        raise ValueError("candidate_partition_invalid")
    if any(row.get("scanner_status", "FAIL") != "FAIL" or
           "incomplete_dependencies" in row.get("evidence", {}) for row in native):
        raise ValueError("candidate_source_incomplete")
    inventory = {row["id"]: row for row in report["resources"]}
    if len(inventory) != len(report["resources"]):
        raise ValueError("resource_id_duplicate")
    stage_report = {key: report[key] for key in
                    ("provider", "snapshot_id", "created_at", "coverage")}
    row_by_id = {row["id"]: row for row in hardening}
    coverage = index(report["coverage"])
    plans = {}
    document_hashes = {}
    document_bytes = {}
    for arm, selected in (("baseline", hardening), ("candidate", remaining)):
        representatives, members = plan(selected)
        batches = chunks(representatives)
        plans[arm] = {
            "selected_ids": sorted(row["id"] for row in selected),
            "representative_ids": [row["id"] for row in representatives],
            "members": {ident: [row["id"] for row in values]
                        for ident, values in members.items()},
            "initial_batches": [[row["id"] for row in batch] for batch in batches],
        }
        hashes = []
        lengths = []
        for batch in batches:
            items = [row_by_id[row["id"]] for row in batch]
            context = review_context(stage_report, inventory, items, _coverage=coverage)
            document = compact_document(findings_document(
                context["scan"], items, context["resources"]))
            if {item["id"] for item in document["items"]} != {row["id"] for row in batch}:
                raise ValueError("batch_document_id_drift")
            body = json.dumps(document, sort_keys=True, default=str).encode()
            hashes.append(hashlib.sha256(body).hexdigest())
            lengths.append(len(body))
        document_hashes[arm] = hashes
        document_bytes[arm] = lengths
    common = {"report": stage_report, "hardening": hardening,
              "resources": inventory, "native_ids": sorted(row["id"] for row in native)}
    replay.mkdir(mode=0o700, parents=True, exist_ok=False)
    private_json(replay / "common.json", common)
    private_json(replay / "plans.json", plans)
    receipt = {
        "version": 1, "status": "prepared_no_model_calls",
        "source_commit": SOURCE_COMMIT, "image_id": IMAGE,
        "model": {"provider": "codex", "model": "gpt-5.6-sol", "thinking": "high"},
        "model_basis": "current_entitlement_not_historical_scan_model",
        "scan_id": SCAN, "snapshot_id": pair["snapshot_id"],
        "pre_manifest_sha256": sha(scan_dir / pair["pre_manifest"]),
        "final_manifest_sha256": sha(scan_dir / pair["final_manifest"]),
        "ai_review_sha256": sha(scan_dir / Path(pair["ai_review"]).name),
        "common_sha256": sha(replay / "common.json"),
        "plans_sha256": sha(replay / "plans.json"),
        "baseline": {"input_count": len(hardening),
                     "representatives": len(plans["baseline"]["representative_ids"]),
                     "initial_batches": len(plans["baseline"]["initial_batches"]),
                     "document_hashes": document_hashes["baseline"],
                     "document_bytes": document_bytes["baseline"]},
        "candidate": {"input_count": len(remaining),
                      "native_count": len(native),
                      "representatives": len(plans["candidate"]["representative_ids"]),
                      "initial_batches": len(plans["candidate"]["initial_batches"]),
                      "document_hashes": document_hashes["candidate"],
                      "document_bytes": document_bytes["candidate"]},
        "saved_action_ids": sorted({ident for action in ai["actions"]
                                     for ident in action.get("finding_ids", [])}),
        "saved_ai_status": ai["status"],
        "saved_hardening_coverage": len(ai["reviews"]["hardening"]),
        "exclusive_slot": "pending_root_release_after_aws_scan",
    }
    private_json(replay / "preflight.json", receipt)
    return receipt


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("private_dir", type=Path)
    parser.add_argument("replay_dir", type=Path)
    args = parser.parse_args()
    result = prepare(args.private_dir, args.replay_dir)
    print(json.dumps({arm: {key: value for key, value in result[arm].items()
                            if key != "document_hashes"}
                      for arm in ("baseline", "candidate")}, sort_keys=True))


if __name__ == "__main__":
    main()
