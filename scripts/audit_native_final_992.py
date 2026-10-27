#!/usr/bin/env python3
"""Summarize one saved report and AI review without emitting finding evidence.

Inputs are private artifacts. Output contains check IDs, titles, severities, and
counts only. No cloud calls or model invocation occur here.
"""
import argparse
from collections import Counter, defaultdict
import gzip
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from peaso.ai.review_groups import chunks, plan

SCAN_ID = "992d7b8cbd4340a79e41139ba1a44c1e"


def read_json(path):
    body = Path(path).read_bytes()
    return json.loads(gzip.decompress(body) if body.startswith(b"\x1f\x8b") else body)


def summarize(report, ai, allowlist, findings=None):
    meta = report.get("check_meta") or {}
    reviews = {r["finding_id"]: r for r in ai["reviews"]["hardening"]}
    findings = [r for r in (report["findings"] if findings is None else findings)
                if r.get("category", (meta.get(r.get("check_id")) or {}).get("category")) == "hardening"
                and r.get("scanner_status", r.get("status")) == "FAIL"]
    finding_ids = {r["id"] for r in findings}
    if set(reviews) != finding_ids:
        raise ValueError(f"review/finding ID mismatch: reviews={len(reviews)}, native={len(finding_ids)}, "
                         f"reviews_without_native={len(set(reviews)-finding_ids)}, "
                         f"native_without_review={len(finding_ids-set(reviews))}")
    by_check = defaultdict(lambda: {"native_fail": 0, "verdicts": Counter(), "severity": Counter()})
    for row in findings:
        ident = row["check_id"]
        entry = by_check[ident]
        verdict = reviews[row["id"]]["verdict"]
        severity = row.get("severity", (meta.get(ident) or {}).get("severity", "info"))
        entry["native_fail"] += 1
        entry["verdicts"][verdict] += 1
        entry["severity"][severity] += 1
    per_check = {}
    for ident, entry in sorted(by_check.items()):
        check_rows = [row for row in findings if row["check_id"] == ident]
        check_reps, check_members = plan(check_rows)
        recheck_members = sum(len(check_members.get(rep["id"], ()))
                              for rep in check_reps if reviews[rep["id"]]["verdict"] != "FAIL")
        per_check[ident] = {
            "title": (meta.get(ident) or {}).get("title", ""),
            "native_fail": entry["native_fail"],
            "ai_verdicts": dict(sorted(entry["verdicts"].items())),
            "ai_disagreement": entry["native_fail"] - entry["verdicts"]["FAIL"],
            "native_fail_by_severity": dict(sorted(entry["severity"].items())),
            "initial_representatives": len(check_reps),
            "observed_non_fail_recheck_members": recheck_members,
        }
    unknown = set(allowlist) - set(per_check)
    if unknown:
        raise ValueError(f"allowlist has IDs absent from this scan: {sorted(unknown)}")
    remaining = [r for r in findings if r["check_id"] not in allowlist]
    removed = [r for r in findings if r["check_id"] in allowlist]
    def queue_shape(rows):
        reps, members = plan(rows)
        initial = chunks(reps)
        recheck_groups = [[member for rep in batch if reviews[rep["id"]]["verdict"] != "FAIL"
                           for member in members.get(rep["id"], ())] for batch in initial]
        return {"representatives": len(reps), "initial_tasks": len(initial),
                "last_task_size": len(initial[-1]) if initial else 0,
                "observed_recheck_rows": sum(map(len, recheck_groups)),
                "observed_recheck_tasks": sum(len(chunks(group)) for group in recheck_groups)}
    return {
        "scan_id": SCAN_ID,
        "source_snapshot_id": report.get("snapshot_id", (report.get("summary") or {}).get("snapshot_id")),
        "source_ai_status": ai.get("status"),
        "hardening_native_fail": len(findings),
        "hardening_ai_verdicts": dict(sorted(Counter(r["verdict"] for r in reviews.values()).items())),
        "effective_fail_by_severity": dict(sorted(Counter(
            r.get("severity", (meta.get(r["check_id"]) or {}).get("severity", "info"))
            for r in findings if reviews[r["id"]]["verdict"] == "FAIL").items())),
        "downgraded_fail_by_severity": dict(sorted(Counter(
            r.get("severity", (meta.get(r["check_id"]) or {}).get("severity", "info"))
            for r in findings if reviews[r["id"]]["verdict"] != "FAIL").items())),
        "baseline": queue_shape(findings),
        "proposal": {"check_ids": sorted(allowlist), "native_fail_rows": len(removed),
                     **queue_shape(remaining), "remaining_native_fail_rows": len(remaining)},
        "checks": per_check,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report")
    parser.add_argument("ai_review")
    parser.add_argument("--chunks-dir", help="Exact finding chunks referenced by a report manifest")
    parser.add_argument("--allowlist", help="JSON object with a check_ids list")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    allowlist = set(read_json(args.allowlist)["check_ids"]) if args.allowlist else set()
    report = read_json(args.report)
    ai = read_json(args.ai_review)
    findings = None
    if args.chunks_dir:
        refs = report["finding_chunks"]
        if not refs or any(f"/{SCAN_ID}/findings-" not in row["reference"] for row in refs):
            raise ValueError("finding chunk references do not belong to the exact 992 scan")
        files = sorted(Path(args.chunks_dir).glob("*.json.gz"))
        if len(files) != len(refs):
            raise ValueError(f"finding chunk count mismatch: local={len(files)}, manifest={len(refs)}")
        review_ids = {r["finding_id"] for r in ai["reviews"]["hardening"]}
        findings = []
        for index in range(len(refs)):
            rows = read_json(Path(args.chunks_dir) / f"{index:04d}.json.gz")["items"]
            findings.extend(row for row in rows if row["id"] in review_ids)
    result = summarize(report, ai, allowlist, findings)
    Path(args.output).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
