"""Numeric, private-input audit of saved same-snapshot K8s Hardening pairs.

Inputs are downloaded into a mode-0700 directory outside the repository.
Output contains only scan/check IDs, object hashes and counts, never findings.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import gzip
import hashlib
import json
from pathlib import Path

from peaso.checks import CHECKS
from peaso.snapshot import resources


ROOT = Path(__file__).resolve().parents[1]
CANDIDATES = ROOT / "outputs/k8s-native-final-source-audit-20261027.json"
OUTPUT = ROOT / "outputs/k8s-native-final-saved-pairs-20261027.json"


def load(path: Path):
    body = path.read_bytes()
    return json.loads(gzip.decompress(body) if body[:2] == b"\x1f\x8b" else body)


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def observations(directory: Path, manifest: dict) -> dict:
    rows = {}
    for chunk in manifest["finding_chunks"]:
        path = directory / Path(chunk["reference"]).name
        items = load(path)["items"]
        assert len(items) == chunk["count"]
        for item in items:
            assert item["id"] not in rows
            rows[item["id"]] = item
    assert len(rows) == manifest["observation_count"]
    return rows


def audit(private: Path) -> dict:
    pair_source = private / "pair-chunk-receipt.json"
    input_receipt = load(pair_source)
    pairs = input_receipt["pairs"]
    for obj in input_receipt["objects"]:
        path = private / obj["reference"].split("/")[1] / Path(obj["reference"]).name
        assert path.stat().st_size == obj["bytes"] and sha(path) == obj["sha256"]
    for receipt_name in ("manifest-download-receipt.json", "download-receipt.json"):
        values = load(private / receipt_name)
        for obj in values if isinstance(values, list) else values["objects"]:
            relative = obj["key"].removeprefix("artifacts/")
            path = private / relative.split("/")[1] / Path(relative).name
            assert path.stat().st_size == obj["size"] and sha(path) == obj["sha256"]
    source_candidates = load(CANDIDATES)
    candidate_ids = {row["check_id"] for row in source_candidates["checks"]}
    assert len(candidate_ids) == 24
    registry = {check.id: check for check in CHECKS}
    rows = []
    per_check = defaultdict(Counter)
    selected_ids = set()
    for pair in pairs:
        directory = private / pair["scan_id"]
        pre_path = directory / pair["pre_manifest"]
        final_path = directory / pair["final_manifest"]
        pre, final = load(pre_path), load(final_path)
        assert pre["summary"]["snapshot_id"] == final["summary"]["snapshot_id"] == pair["snapshot_id"]
        assert not pre.get("ai_review") and final["ai_review"] == pair["ai_review"]
        ai_path = directory / Path(pair["ai_review"]).name
        ai = load(ai_path)
        original = observations(directory, pre)
        published = observations(directory, final)
        stage_ids = ai["stage_inputs"]["hardening"]
        reviews = {row["finding_id"]: row for row in ai["reviews"]["hardening"]}
        assert len(reviews) == len(ai["reviews"]["hardening"])
        assert set(stage_ids) == set(reviews)
        assert all(original[ident]["status"] == "FAIL" for ident in stage_ids)
        candidate = [row for row in original.values()
                     if row["check_id"] in candidate_ids and row["status"] == "FAIL"]
        native_ids = set()
        for row in candidate:
            ident = row["id"]
            verdict = reviews.get(ident, {}).get("verdict", "MISSING")
            per_check[row["check_id"]]["reviewed_failures"] += 1
            per_check[row["check_id"]]["disagreements"] += verdict != "FAIL"
            per_check[row["check_id"]]["missing_reviews"] += verdict == "MISSING"
            assert ident in published and published[ident]["status"] == verdict
            assert published[ident]["evidence"] == row["evidence"]
            if verdict == "FAIL":
                native_ids.add(ident)
                selected_ids.add(ident)
        remaining_ids = set(stage_ids) - native_ids
        assert native_ids.isdisjoint(remaining_ids)
        assert native_ids | remaining_ids == set(stage_ids)
        # Synthetic native FAIL plus every retained saved AI review is exactly
        # the original verdict map, keyed by finding ID.
        substituted = {ident: "FAIL" for ident in native_ids}
        substituted.update({ident: reviews[ident]["verdict"] for ident in remaining_ids})
        assert substituted == {ident: review["verdict"] for ident, review in reviews.items()}
        source_checked = 0
        if native_ids:
            snapshot_path = directory / "snapshot-def371d2204b4cca87153a5b4599efd5.json"
            snapshot = load(snapshot_path)
            assert snapshot["snapshot_id"] == pair["snapshot_id"]
            inventory = {resource["id"]: resource for resource in resources(snapshot)}
            for row in candidate:
                resource = inventory[row["resource_id"]]
                check = registry[row["check_id"]]
                status, evidence = check.evaluate(resource["data"], {})
                assert status == "FAIL" and evidence == row["evidence"]
                source_checked += 1
                per_check[row["check_id"]]["source_rechecks"] += 1
        rows.append({
            "scan_id": pair["scan_id"],
            "snapshot_id": pair["snapshot_id"],
            "pre_manifest_sha256": sha(pre_path),
            "final_manifest_sha256": sha(final_path),
            "ai_review_sha256": sha(ai_path),
            "ai_status": ai["status"],
            "hardening_stage_inputs": len(stage_ids),
            "candidate_failures": len(candidate),
            "native_substitutions": len(native_ids),
            "remaining_ai_inputs": len(remaining_ids),
            "source_rechecks": source_checked,
            "verdict_parity": True,
            "evidence_parity": True,
        })
    measures = ("reviewed_failures", "disagreements", "missing_reviews", "source_rechecks")
    checks = [{"check_id": check_id,
               **{measure: per_check[check_id][measure] for measure in measures}}
              for check_id in sorted(candidate_ids)]
    return {
        "version": 1,
        "private_input_receipt_sha256": sha(pair_source),
        "source_candidate_receipt_sha256": sha(CANDIDATES),
        "pair_count": len(rows),
        "unique_scan_count": len({row["scan_id"] for row in rows}),
        "candidate_count": len(candidate_ids),
        "observed_candidate_failures": sum(row["candidate_failures"] for row in rows),
        "substituted_findings": len(selected_ids),
        "checks": checks,
        "pairs": rows,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("private_dir", type=Path)
    args = parser.parse_args()
    receipt = audit(args.private_dir)
    OUTPUT.write_text(json.dumps(receipt, sort_keys=True, indent=2) + "\n")
    print(f"{receipt['pair_count']} pairs, {receipt['observed_candidate_failures']} candidate FAILs, "
          f"{receipt['substituted_findings']} substitution rows")


if __name__ == "__main__":
    main()
