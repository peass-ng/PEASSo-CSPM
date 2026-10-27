#!/usr/bin/env python3
"""Build a fail-closed native-final proposal from explicit per-check proofs."""
import argparse
import ast
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source_inventory")
    parser.add_argument("proofs")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    inventory = json.loads(Path(args.source_inventory).read_text())
    decisions = json.loads(Path(args.proofs).read_text())
    if inventory.get("zero_disagreement_checks") != 293 or len(inventory["checks"]) != 293:
        raise ValueError("exact zero-disagreement source set changed")
    if (decisions.get("schema_version") != 1 or
            decisions.get("scan_id") != inventory.get("scan_id") or
            decisions.get("source_commit") != inventory.get("source_commit")):
        raise ValueError("proof source binding changed")
    proofs = decisions["approved_check_proofs"]
    if not isinstance(proofs, dict):
        raise ValueError("invalid proof map")
    ids = {row["check_id"] for row in inventory["checks"]}
    if set(proofs) - ids:
        raise ValueError("proof references unknown check IDs")
    exclusions = decisions.get("explicit_exclusions", {})
    if set(exclusions) - ids or set(exclusions) & set(proofs):
        raise ValueError("exclusion conflicts with proof")
    for row in inventory["checks"]:
        ident = row["check_id"]
        if (not row["evidence_keys"] or not row["code_path"] or
                not row["evaluator_source_sha256"] or row["native_fail_count"] < 1):
            raise ValueError("source or recorded evidence absent: " + ident)
        proof = proofs.get(ident)
        if proof is None:
            row["decision"] = "retain_ai"
            row["rationale"] = exclusions.get(ident, "No check-specific evaluator and helper proof approved in v3; AI review retained.")
            continue
        installed_paths = row["code_path"] + [path for delegate in row["delegate_code_path"]
                                                for path in delegate["code_path"]]
        if proof.get("predicate_source") not in installed_paths or not proof.get("predicate"):
            raise ValueError("predicate proof does not bind to installed evaluator: " + ident)
        if proof.get("evaluator_source_sha256") != row["evaluator_source_sha256"]:
            raise ValueError("evaluator source digest changed: " + ident)
        source_name, source_line = proof["predicate_source"].rsplit(":", 1)
        source_path = (ROOT / source_name).resolve()
        binding = proof.get("code_path_audit_ref", {})
        if (not source_path.is_relative_to(ROOT) or not source_line.isdecimal() or
                not source_path.is_file() or int(source_line) < 1 or
                int(source_line) > len(source_path.read_text().splitlines()) or
                hashlib.sha256(source_path.read_bytes()).hexdigest() != proof.get("source_file_sha256") or
                binding.get("path") != source_name or
                binding.get("source_sha256") != proof.get("source_file_sha256") or
                binding.get("audit_ref") != "docs/ai-review/native-final-proofs-v3.json#" + ident or
                not isinstance(binding.get("symbol"), str) or
                not any(isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and
                        node.name == binding["symbol"] for node in ast.walk(ast.parse(source_path.read_text())))):
            raise ValueError("source file digest changed: " + ident)
        helpers = proof.get("helper_sources", [])
        if not isinstance(helpers, list):
            raise ValueError("invalid helper proof")
        for reference in helpers:
            try:
                filename, line = reference.rsplit(":", 1)
                path = (ROOT / filename).resolve()
                if (not path.is_relative_to(ROOT) or not line.isdecimal() or
                        int(line) < 1 or int(line) > sum(1 for _ in path.open())):
                    raise ValueError()
            except (OSError, ValueError):
                raise ValueError("invalid helper source: " + ident) from None
        if not set(proof.get("observed_evidence_keys", [])) <= set(row["evidence_keys"]):
            raise ValueError("proof evidence keys not observed: " + ident)
        row["decision"] = "native_final_proposed"
        row["predicate_proof"] = proof
        row["rationale"] = proof["predicate"]
    inventory["proposal_version"] = "2026-10-27-v3"
    inventory["status"] = "proposal_only"
    inventory["native_final_check_ids"] = sorted(proofs)
    inventory["retain_ai_check_ids"] = sorted(ids - set(proofs))
    Path(args.output).write_text(json.dumps(inventory, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"native_final": len(proofs), "retain_ai": len(ids - set(proofs))}))


if __name__ == "__main__":
    main()
