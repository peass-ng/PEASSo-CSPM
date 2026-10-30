#!/usr/bin/env python3
"""Project exact 992 numeric Hardening queues for all source-proven IDs."""
import argparse
from collections import Counter
import gzip
import hashlib
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from peaso.ai.review_groups import chunks, plan  # noqa: E402


SCAN_ID = "992d7b8cbd4340a79e41139ba1a44c1e"
PRE_SHA256 = "4dcaa76a21c6b3bfff2b4859c1d4c763964c92c69041fe2d95702315fffde2ba"
FINAL_SHA256 = "399024cf7f69b4b7dd99921766b087514a44512cba244ad9d50de696f83d85b0"
CHUNK_MANIFEST_SHA256 = "b06bffd4ad367a0301afd949525d78657bc8c6ff5b00f16483f0170dbfa3f379"
SOURCE_PROOF_SHA256 = "7e85b20f209585643b7deee45ba7937b8e73f2071bb30e3f5da9a519d6c08fcb"
CANDIDATE_SHA256 = "ee5ee501855a6ed0bfa2558f94adfd768fb1efc8872a0358566a973ce061e633"
MEASURED_MIXED_WALL_SECONDS = 1287.173
FIXED_EXPOSURE_TASKS = 8


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def read_pinned(path, expected):
    raw = Path(path).read_bytes()
    if digest(raw) != expected:
        raise ValueError("exact input SHA256 changed: " + str(path))
    return json.loads(gzip.decompress(raw) if raw.startswith(b"\x1f\x8b") else raw)


def shape(findings, reviews):
    representatives, members = plan(findings)
    initial = chunks(representatives)
    recheck = [[member for rep in batch if reviews[rep["id"]] != "FAIL"
                for member in members.get(rep["id"], ())] for batch in initial]
    return {"representatives": len(representatives), "initial_tasks": len(initial),
            "last_initial_task_size": len(initial[-1]) if initial else 0,
            "observed_recheck_group_sizes": [len(group) for group in recheck],
            "observed_recheck_rows": sum(map(len, recheck)),
            "observed_recheck_tasks": sum(len(chunks(group)) for group in recheck)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pre_ai_report")
    parser.add_argument("final_report")
    parser.add_argument("--chunk-manifest", required=True)
    parser.add_argument("--chunks-dir", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    pre = read_pinned(args.pre_ai_report, PRE_SHA256)
    final = read_pinned(args.final_report, FINAL_SHA256)
    chunk_manifest = read_pinned(args.chunk_manifest, CHUNK_MANIFEST_SHA256)
    candidate = read_pinned(ROOT / "docs/ai-review/native-final-code-manifest-v2-candidate.json", CANDIDATE_SHA256)
    revisit = read_pinned(ROOT / "docs/ai-review/native-final-high-rep-revisit-v4.json", SOURCE_PROOF_SHA256)
    if candidate["replay_qualification"] != {"status": "pending", "receipt_sha256": None}:
        raise ValueError("candidate is not pending")
    final_reviews = final["ai"]["reviews"]["hardening"]
    reviews = {r["finding_id"]: r["verdict"] for r in final_reviews}
    if len(reviews) != 16113:
        raise ValueError("exact final review ID coverage changed")
    refs = chunk_manifest["finding_chunks"]
    files = sorted(Path(args.chunks_dir).glob("*.json.gz"))
    if len(refs) != 419 or len(files) != len(refs):
        raise ValueError("exact 992 finding chunks changed")
    pre_by_id = {o["id"]: o for group in pre["findings"]
                 for o in group.get("observations", []) if o["id"] in reviews}
    findings = []
    for number, ref in enumerate(refs):
        if f"/{SCAN_ID}/findings-" not in ref["reference"]:
            raise ValueError("finding chunk references another scan")
        path = Path(args.chunks_dir) / f"{number:04d}.json.gz"
        rows = json.load(gzip.open(path))["items"]
        if (len(rows) != ref["count"] or rows[0]["id"] != ref["first_id"]
                or rows[-1]["id"] != ref["last_id"]):
            raise ValueError("finding chunk index/order changed")
        findings.extend(pre_by_id[row["id"]] for row in rows if row["id"] in reviews)
    pre_ids = set(pre_by_id)
    if (len(findings) != 16113 or len({o["id"] for o in findings}) != 16113
            or {o["id"] for o in findings} != set(reviews) or pre_ids != set(reviews)
            or any(o["status"] != "FAIL" or o["category"] != "hardening" for o in findings)):
        raise ValueError("pre-AI native FAIL/review join changed")
    approved84 = {r["check_id"] for r in candidate["checks"]}
    extra = set(revisit["additional_source_proven_check_ids"])
    if len(approved84) != 84 or len(extra) != 3 or approved84 & extra:
        raise ValueError("source-proven approval boundary changed")
    approved = approved84 | extra
    counts = Counter(o["check_id"] for o in findings)
    if len(counts) != 341 or not approved <= set(counts):
        raise ValueError("exact native check population changed")
    numeric = {r["check_id"]: r for r in json.loads(
        (ROOT / "outputs/native-final-audit-992-v3-numeric.json").read_text())["per_check"]}
    if set(numeric) != set(counts):
        raise ValueError("signed per-check numeric population changed")
    rows = []
    for ident in sorted(counts):
        subset = [r for r in findings if r["check_id"] == ident]
        representatives, members = plan(subset)
        recheck = sum(len(members.get(rep["id"], ())) for rep in representatives
                      if reviews[rep["id"]] != "FAIL")
        prior = numeric[ident]
        if (len(subset) != prior["native_fail"] or len(representatives) != prior["initial_representatives"]
                or recheck != prior["observed_non_fail_recheck_members"]
                or Counter(reviews[r["id"]] for r in subset) != prior["ai_verdicts"]):
            raise ValueError("per-check representative/review mismatch: " + ident)
        rows.append({"check_id": ident, "native_fail_count": len(subset),
                     "initial_representatives": len(representatives),
                     "observed_non_fail_recheck_members": recheck,
                     "ai_verdict_counts": dict(sorted(Counter(reviews[r["id"]] for r in subset).items())),
                     "source_proven_proposal": ident in approved})
    baseline = shape(findings, reviews)
    pending84 = shape([r for r in findings if r["check_id"] not in approved84], reviews)
    remaining_rows = [r for r in findings if r["check_id"] not in approved]
    remaining = shape(remaining_rows, reviews)
    if (baseline["representatives"] != 778 or baseline["initial_tasks"] != 20 or
            baseline["observed_recheck_tasks"] != 7 or len(findings) != 16113):
        raise ValueError("exact baseline queue changed")
    if (pending84["representatives"] != 439 or pending84["initial_tasks"] != 11 or
            pending84["observed_recheck_tasks"] != 6):
        raise ValueError("signed 84-ID queue changed")
    if (sum(r["initial_representatives"] for r in rows if r["source_proven_proposal"])
            != baseline["representatives"] - remaining["representatives"]):
        raise ValueError("removed representative accounting changed")
    baseline_tasks = baseline["initial_tasks"] + baseline["observed_recheck_tasks"]
    remaining_tasks = remaining["initial_tasks"] + remaining["observed_recheck_tasks"]
    all_baseline = baseline_tasks + FIXED_EXPOSURE_TASKS
    all_remaining = remaining_tasks + FIXED_EXPOSURE_TASKS
    receipt = {"schema_version": 2, "scan_id": SCAN_ID, "status": "source_proposal_only",
               "pre_ai_report_sha256": PRE_SHA256, "final_report_sha256": FINAL_SHA256,
               "finding_chunk_manifest_sha256": CHUNK_MANIFEST_SHA256,
               "pending_84_candidate_sha256": CANDIDATE_SHA256,
               "additional_high_rep_proof_sha256": SOURCE_PROOF_SHA256,
               "native_fail_ids": len(findings), "final_ai_review_ids": len(reviews),
               "check_id_count": len(counts), "source_proven_check_ids": len(approved),
               "source_proven_native_fail_rows": len(findings) - len(remaining_rows),
               "remaining_native_fail_rows": len(remaining_rows),
               "removed_initial_representatives": baseline["representatives"] - remaining["representatives"],
               "baseline_hardening_queue": baseline,
               "pending_84_hardening_queue": pending84,
               "remaining_hardening_queue": remaining,
               "baseline_hardening_tasks": baseline_tasks, "remaining_hardening_tasks": remaining_tasks,
               "ai_tail_planning_proxy": {
                   "kind": "linear_task_count_proxy_not_hosted_measurement",
                   "measured_mixed_reviewer_wall_seconds": MEASURED_MIXED_WALL_SECONDS,
                   "fixed_exposure_tasks": FIXED_EXPOSURE_TASKS,
                   "baseline_hardening_plus_exposure_tasks": all_baseline,
                   "remaining_hardening_plus_exposure_tasks": all_remaining,
                   "estimated_mixed_ai_tail_seconds": round(MEASURED_MIXED_WALL_SECONDS * all_remaining / all_baseline, 3),
                   "hosted_replay_measured": False},
               "per_check": rows}
    Path(args.output).write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"source_proven_check_ids": len(approved),
                      "removed_representatives": receipt["removed_initial_representatives"],
                      "baseline_tasks": baseline_tasks, "remaining_tasks": remaining_tasks,
                      "tail_proxy_seconds": receipt["ai_tail_planning_proxy"]["estimated_mixed_ai_tail_seconds"]}))


if __name__ == "__main__":
    main()
