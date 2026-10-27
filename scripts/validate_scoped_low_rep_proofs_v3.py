#!/usr/bin/env python3
"""Verify 72 explicit scoped/index decisions against source and integration tree."""
import argparse
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("proof_receipt")
    parser.add_argument("integration_root")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    receipt_path = Path(args.proof_receipt)
    receipt = json.loads(receipt_path.read_text())
    frozen = json.loads((ROOT / "docs/ai-review/native-final-scoped-low-rep-slice-v3.json").read_text())
    numeric = {row["check_id"]: row for row in json.loads(
        (ROOT / "outputs/native-final-audit-992-v3-numeric.json").read_text())["per_check"]}
    expected = {row["check_id"] for row in frozen["checks"]}
    rows = receipt["checks"]
    if (receipt["scan_id"] != frozen["scan_id"] or len(rows) != 72 or
            {row["check_id"] for row in rows} != expected or
            receipt["source_low_rep_receipt_sha256"] != frozen["source_low_rep_receipt_sha256"]):
        raise ValueError("frozen 72-ID slice changed")
    integration = Path(args.integration_root).resolve()
    checked_files = set()
    approved = excluded = representatives = failures = 0
    for row in rows:
        ident = row["check_id"]
        source = numeric[ident]
        if (source["native_fail"] != row["native_fail_count"] or
                source["initial_representatives"] != row["initial_representatives"] or
                source["ai_disagreement"] != 0 or
                row["ai_verdict_counts"] != {"FAIL": row["native_fail_count"]}):
            raise ValueError("numeric review mismatch: " + ident)
        if row["decision"] == "native_final_source_proven":
            proof = row["predicate_proof"]
            refs = [proof["predicate_source"], *proof["completeness_sources"], *proof["helper_sources"]]
            if (len(proof["completeness_sources"]) < 1 or not proof["predicate"] or
                    proof["predicate_source"].split(":", 1)[0] != row["evaluator"]["path"]):
                raise ValueError("installed predicate or completeness proof missing: " + ident)
            approved += 1
            representatives += row["initial_representatives"]
            failures += row["native_fail_count"]
        elif row["decision"] == "retain_ai":
            refs = [row["exclusion"]["source"]]
            if not row["exclusion"]["reason"]:
                raise ValueError("empty exclusion")
            excluded += 1
        else:
            raise ValueError("unknown decision")
        for ref in refs:
            filename, line = ref.rsplit(":", 1)
            digest = row["source_file_sha256"].get(filename)
            local = (ROOT / filename).resolve()
            target = (integration / filename).resolve()
            if (not line.isdecimal() or int(line) < 1 or not local.is_relative_to(ROOT) or
                    not target.is_relative_to(integration) or not local.is_file() or
                    not target.is_file() or int(line) > len(local.read_text().splitlines()) or
                    not isinstance(digest, str) or
                    hashlib.sha256(local.read_bytes()).hexdigest() != digest or
                    hashlib.sha256(target.read_bytes()).hexdigest() != digest):
                raise ValueError("local/integration source binding changed: " + ident)
            checked_files.add(filename)
    if (approved, excluded, representatives, failures) != (64, 8, 88, 2644):
        raise ValueError("decision or numeric scope changed")
    out = {"schema_version": 1, "scan_id": receipt["scan_id"],
           "proof_receipt_sha256": hashlib.sha256(receipt_path.read_bytes()).hexdigest(),
           "source_low_rep_receipt_sha256": frozen["source_low_rep_receipt_sha256"],
           "reviewed_ids": len(rows), "source_proven_ids": approved,
           "retain_ai_ids": excluded, "source_proven_initial_representatives": representatives,
           "source_proven_native_fail": failures,
           "whole_file_hashes_checked_in_integration": len(checked_files),
           "integration_hash_mismatches": 0,
           "merged_into_code_manifest": False,
           "model_replay_run": False}
    Path(args.output).write_text(json.dumps(out, indent=2, sort_keys=True) + "\n")
    print(json.dumps(out, sort_keys=True))


if __name__ == "__main__":
    main()
