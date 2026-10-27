#!/usr/bin/env python3
"""Validate the pending 84-ID candidate against exact 992 and the reviewed gate."""
import argparse
from collections import defaultdict
import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import tempfile

from validate_native_final_code_candidate_v2 import descend


ROOT = Path(__file__).resolve().parents[1]
SCOPED_SHA256 = "d244169401807d3ebb2f98cc87c50b934d637b9841a4edac2f273ea0e0120889"
SOURCE_LOW_SHA256 = "333ccb7146e02db59f14b2f8056c54bcbad266c5b55e696ced3ab5f19eb52eb3"
HIGH_SHA256 = "9a2d6b0dcb5b93f3ec87ce01d756178fff77ebe5c9db3fd55025afa8d904aca4"
EXPECTED_CANDIDATE_SHA256 = "b4f6ae81fd961d81c084c51219b41fd54b6c21b90b6b51517531550b6aa59d13"
REVIEWED_GATE_SHA256 = "314c3e5bb18ccc851be5489931e86097a4a267610d2476aed32842f552f54b65"
EXPECTED_REFERENCES = {"high20": 62, "scoped64": 186}
COLLECTION = re.compile(r"#collections\[type=([^]]+)\](.*)$")


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def load_gate(path):
    spec = importlib.util.spec_from_file_location("unchanged_native_final_gate", path)
    gate = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gate)
    return gate


def gate_admission(gate, candidate, checks, qualified):
    with tempfile.TemporaryDirectory(prefix="native-final-84-validation-") as temp:
        manifest = {**candidate, "checks": checks}
        if qualified:
            receipt = Path(temp) / "test-only-receipt.json"
            receipt.write_text('{"test_only":true}\n')
            manifest["replay_qualification"] = {
                "status": "qualified", "receipt_sha256": digest(receipt.read_bytes())}
        raw = (json.dumps(manifest, sort_keys=True) + "\n").encode()
        path = Path(temp) / "manifest.json"
        path.write_bytes(raw)
        os.environ["PEASO_HARDENING_NATIVE_FINAL_ENABLED"] = "1"
        os.environ["PEASO_HARDENING_NATIVE_FINAL_SHA256"] = digest(raw)
        admitted = gate.admitted_check_ids(path)
        path.write_bytes(raw + b" ")
        if gate.admitted_check_ids(path):
            raise ValueError("changed manifest bypassed exact SHA gate")
        return admitted


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("candidate")
    parser.add_argument("snapshot")
    parser.add_argument("code_gate")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    candidate_raw = Path(args.candidate).read_bytes()
    if digest(candidate_raw) != EXPECTED_CANDIDATE_SHA256:
        raise ValueError("reviewed 84-ID candidate SHA changed")
    candidate = json.loads(candidate_raw)
    scoped_raw = (ROOT / "docs/ai-review/native-final-scoped-low-rep-proofs-v3.json").read_bytes()
    scoped = json.loads(scoped_raw)
    high_raw = (ROOT / "docs/ai-review/native-final-code-manifest-v2-candidate-high20.json").read_bytes()
    high = json.loads(high_raw)
    if (digest(scoped_raw) != SCOPED_SHA256 or digest(high_raw) != HIGH_SHA256 or
            scoped["source_low_rep_receipt_sha256"] != SOURCE_LOW_SHA256):
        raise ValueError("source proof chain changed")
    if candidate["replay_qualification"] != {"status": "pending", "receipt_sha256": None}:
        raise ValueError("candidate is not pending")
    checks = candidate["checks"]
    by_id = {r["check_id"]: r for r in checks}
    approved = {r["check_id"]: r for r in scoped["checks"]
                if r["decision"] == "native_final_source_proven"}
    high_ids = {r["check_id"] for r in high["checks"]}
    if (len(checks) != 84 or len(by_id) != 84 or len(approved) != 64 or len(high_ids) != 20
            or set(by_id) != set(approved) | high_ids or set(approved) & high_ids):
        raise ValueError("84-ID signed proof boundary changed")
    high_checks = {r["check_id"]: r for r in high["checks"]}
    snapshot_raw = Path(args.snapshot).read_bytes()
    snapshot_sha = digest(snapshot_raw)
    snapshot = json.loads(gzip.decompress(snapshot_raw))
    if not isinstance(snapshot.get("created_at"), str) or not snapshot["created_at"]:
        raise ValueError("exact snapshot clock absent")
    collections = defaultdict(list)
    rows = defaultdict(list)
    for collection in snapshot["collections"]:
        collections[collection["type"]].append(collection)
        rows[collection["type"]].extend(collection["items"])
    references = 0
    references_by_proof = {"high20": 0, "scoped64": 0}
    clocks = 0
    for ident, check in by_id.items():
        proof = approved.get(ident)
        expected_receipt = SCOPED_SHA256 if proof else high_checks[ident]["audit_receipt_sha256"]
        if check["audit_receipt_sha256"] != expected_receipt:
            raise ValueError("audit receipt changed: " + ident)
        if proof and (check["prod992_reviewed_failures"] != proof["native_fail_count"] or
                      proof["ai_verdict_counts"] != {"FAIL": proof["native_fail_count"]}):
            raise ValueError("native/review count changed: " + ident)
        det = check["deterministic_evidence"]
        ref = det["code_path_audit_ref"]
        if proof and (ref["path"] != proof["evaluator"]["path"] or
                      ref["symbol"] != proof["evaluator"]["symbol"] or
                      ref["source_sha256"] != proof["source_file_sha256"][ref["path"]]):
            raise ValueError("evaluator source proof changed: " + ident)
        if digest((ROOT / ref["path"]).read_bytes()) != ref["source_sha256"]:
            raise ValueError("whole-file source hash changed: " + ident)
        for field in det["source_fields"]:
            evidence_ref = field["recorded_evidence_ref"]
            if not evidence_ref.startswith("sha256:" + snapshot_sha + "#"):
                raise ValueError("snapshot field binding changed: " + ident)
            match = COLLECTION.search(evidence_ref)
            if not match:
                raise ValueError("invalid snapshot reference: " + ident)
            kind, suffix = match.groups()
            if suffix == ".status":
                found = [entry["status"] for entry in collections[kind]]
            elif suffix.startswith(".items[]"):
                found = descend(rows[kind], suffix[len(".items[]"):].lstrip("."))
            else:
                raise ValueError("unsupported snapshot reference: " + ident)
            if not found:
                raise ValueError("unresolved snapshot field: " + ident)
            references += 1
            references_by_proof["scoped64" if proof else "high20"] += 1
        clock = det["scan_time"]
        if clock is not None:
            if det["operation"]["kind"] == "versioned_lookup_date":
                if (ident != "aws.cb.lambda.runtime_not_deprecated_list" or
                        clock != {"source_field": "context.created_at",
                                  "recorded_evidence_ref": "sha256:" + snapshot_sha + "#created_at"}):
                    raise ValueError("versioned lookup clock changed: " + ident)
            elif (not clock["source_field"].endswith("or snapshot.created_at") or
                  not clock["recorded_evidence_ref"].startswith("sha256:" + snapshot_sha + "#") or
                  not clock["recorded_evidence_ref"].endswith("|created_at")):
                raise ValueError("captured clock reference changed: " + ident)
            clocks += 1
    if references_by_proof != EXPECTED_REFERENCES or references != 248:
        raise ValueError("84-ID snapshot-reference count changed")
    gate_raw = Path(args.code_gate).read_bytes()
    if digest(gate_raw) != REVIEWED_GATE_SHA256:
        raise ValueError("reviewed integration gate SHA changed")
    gate = load_gate(args.code_gate)
    pending = gate_admission(gate, candidate, checks, False)
    combined_qualified = gate_admission(gate, candidate, checks, True)
    if pending or combined_qualified != set(by_id):
        raise ValueError("reviewed gate did not admit exactly all 84 only in temporary qualified copy")
    admitted = set()
    rejected = []
    for check in checks:
        ident = check["check_id"]
        single = gate_admission(gate, candidate, [check], True)
        if single == {ident}:
            admitted.add(ident)
        else:
            raise ValueError("reviewed gate rejected or over-admitted single row: " + ident)
    if rejected or len(admitted) != 84:
        raise ValueError("reviewed gate did not admit exactly 84 isolated rows")
    receipt = {
        "schema_version": 2, "candidate_sha256": digest(candidate_raw),
        "snapshot_sha256": snapshot_sha, "code_gate_sha256": digest(gate_raw),
        "high20_candidate_sha256": HIGH_SHA256,
        "scoped_source_proof_sha256": SCOPED_SHA256,
        "code_worker_low_rep_source_receipt_sha256": SOURCE_LOW_SHA256,
        "candidate_checks": 84, "high_approved_checks": 20, "scoped_approved_checks": 64,
        "whole_file_source_hashes_verified": len(checks),
        "resolved_recorded_evidence_references": references,
        "resolved_references_by_proof": references_by_proof,
        "captured_clock_references_verified": clocks,
        "pending_admitted": len(pending),
        "combined_temporary_qualified_admitted": len(combined_qualified),
        "individual_temporary_qualified_admitted": len(admitted),
        "individual_temporary_qualified_rejected": rejected,
        "sha_tamper_admitted": 0, "production_manifest_modified": False,
        "gate_modified": False, "model_replay_run": False,
        "replay_qualification": "pending",
    }
    Path(args.output).write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"candidate_checks": 84, "snapshot_references": references,
                      "individual_admitted": len(admitted), "individual_rejected": len(rejected),
                      "combined_admitted": len(combined_qualified)}, sort_keys=True))


if __name__ == "__main__":
    main()
