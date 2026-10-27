#!/usr/bin/env python3
"""Write a numeric-only v3 receipt from the exact 992 replay and reviewed manifest."""
import argparse
import json
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pre_ai_numeric_receipt")
    parser.add_argument("reviewed_manifest")
    parser.add_argument("queue_audit")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    pre = json.loads(Path(args.pre_ai_numeric_receipt).read_text())
    manifest = json.loads(Path(args.reviewed_manifest).read_text())
    audit = json.loads(Path(args.queue_audit).read_text())
    scan = "992d7b8cbd4340a79e41139ba1a44c1e"
    if {pre["scan_id"], manifest["scan_id"], audit["scan_id"]} != {scan}:
        raise ValueError("exact scan identity changed")
    if pre["native_fail_ids"] != audit["hardening_native_fail"] or pre["native_fail_ids"] != 16113:
        raise ValueError("pre-AI native FAIL count changed")
    if pre["ai_review_ids"] != 16113 or pre["unmatched_review_ids"] or pre["unreviewed_native_fail_ids"]:
        raise ValueError("pre-AI/review identity coverage changed")
    if pre["total_ai_disagreements"] != 130 or pre["published_severity_changes"] != 0:
        raise ValueError("review disagreement or severity changed")
    by_id = {r["check_id"]: r for r in pre["per_check"]}
    source = {r["check_id"]: r for r in manifest["checks"]}
    if set(audit["checks"]) != set(by_id) or not set(source) <= set(by_id):
        raise ValueError("check set changed")
    approved = set(manifest["native_final_check_ids"])
    if approved != set(audit["proposal"]["check_ids"]):
        raise ValueError("queue and proof approvals differ")
    rows = []
    for ident in sorted(by_id):
        numeric = by_id[ident]
        replay = audit["checks"][ident]
        if (numeric["native_fail_count"] != replay["native_fail"] or
                numeric["ai_disagreement_count"] != replay["ai_disagreement"]):
            raise ValueError("pre-AI and replay check count differ: " + ident)
        if ident in approved and (numeric["ai_disagreement_count"] or ident not in source):
            raise ValueError("unproven or disagreed check approved: " + ident)
        rows.append({"check_id": ident, "native_fail": numeric["native_fail_count"],
                     "ai_verdicts": numeric["ai_verdict_counts"],
                     "ai_disagreement": numeric["ai_disagreement_count"],
                     "published_severity_changes": numeric["published_severity_change_count"],
                     "initial_representatives": replay["initial_representatives"],
                     "observed_non_fail_recheck_members": replay["observed_non_fail_recheck_members"],
                     "v3_decision": "native_final_proposed" if ident in approved else "retain_ai"})
    baseline = audit["baseline"]
    proposed = {k: audit["proposal"][k] for k in (
        "representatives", "initial_tasks", "last_task_size", "observed_recheck_rows",
        "observed_recheck_tasks", "native_fail_rows", "remaining_native_fail_rows")}
    # A planning proxy only: the measured mixed 992 reviewer wall covered more than
    # Hardening and cannot establish a replay wall or model cost improvement.
    measured_wall = 1287.173
    exposure_tasks = 8
    baseline_total = baseline["initial_tasks"] + baseline["observed_recheck_tasks"] + exposure_tasks
    proposed_total = proposed["initial_tasks"] + proposed["observed_recheck_tasks"] + exposure_tasks
    receipt = {
        "schema_version": 1, "proposal_version": manifest["proposal_version"],
        "status": "proposal_only", "scan_id": scan,
        "source_commit": manifest["source_commit"],
        "source_sha256": pre["source_sha256"], "native_source_sha256": pre["native_source_sha256"],
        "native_fail_ids": pre["native_fail_ids"], "ai_review_ids": pre["ai_review_ids"],
        "check_id_count": pre["check_id_count"],
        "zero_disagreement_check_ids": pre["zero_disagreement_check_ids"],
        "zero_disagreement_native_fail": pre["zero_disagreement_native_fail_count"],
        "ai_verdicts": audit["hardening_ai_verdicts"],
        "ai_disagreements": pre["total_ai_disagreements"],
        "published_severity_changes": pre["published_severity_changes"],
        "approved_check_ids": len(approved),
        "reviewed_high_representative_checks": sum(r["initial_representatives"] >= 3 for r in source.values()),
        "independent_low_representative_receipt_included": False,
        "baseline_hardening_queue": baseline,
        "proposed_hardening_queue": proposed,
        "removed_initial_representatives": baseline["representatives"] - proposed["representatives"],
        "hardening_task_reduction": (baseline["initial_tasks"] + baseline["observed_recheck_tasks"]
                                     - proposed["initial_tasks"] - proposed["observed_recheck_tasks"]),
        "wall_planning_proxy": {
            "measured_mixed_reviewer_wall_seconds": measured_wall,
            "fixed_exposure_tasks": exposure_tasks,
            "baseline_hardening_plus_exposure_tasks": baseline_total,
            "proposed_hardening_plus_exposure_tasks": proposed_total,
            "linear_task_ratio_seconds": round(measured_wall * proposed_total / baseline_total, 3),
            "validated_replay_wall": False,
        },
        "per_check": rows,
    }
    Path(args.output).write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
