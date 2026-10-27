#!/usr/bin/env python3
"""Validate exact 992 c2b field bindings and temporary current-gate admission."""
import argparse
from collections import defaultdict
import gzip
import hashlib
import json
from pathlib import Path
import re

from validate_native_final_code_candidate_v2 import descend
from validate_native_final_scoped_candidate_v2 import gate_admission, load_gate

ROOT = Path(__file__).resolve().parents[1]
PROOF = ROOT / "docs/ai-review/native-final-c2b-low-rep-proofs-v1.json"
PROOF_SHA = "2faa2cd0f4244b22ce7337905104dbbbf78ea0c79aaf5503f044277d0fee51ca"
CANDIDATE_SHA = "ad7ec549f4dc2ae443d29499bd37ac8aa15fb4837320c779efdb8a16e2ecef3d"
SNAP_SHA = "3d7828c701a9457eeeb7d5aa497e1efd07a7977ccddeed498a73a2ba9dc2592f"
PRE_SHA = "4dcaa76a21c6b3bfff2b4859c1d4c763964c92c69041fe2d95702315fffde2ba"
GATE_SHA = "314c3e5bb18ccc851be5489931e86097a4a267610d2476aed32842f552f54b65"
REFERENCE = re.compile(r"^sha256:([0-9a-f]{64})#collections\[type=([^]]+)\]\.items\[\](?:\.(.*))?$")


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("candidate", type=Path)
    ap.add_argument("snapshot", type=Path)
    ap.add_argument("pre_ai", type=Path)
    ap.add_argument("code_gate", type=Path)
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()
    assert digest(PROOF) == PROOF_SHA
    assert digest(args.candidate) == CANDIDATE_SHA
    assert digest(args.snapshot) == SNAP_SHA
    assert digest(args.pre_ai) == PRE_SHA
    assert digest(args.code_gate) == GATE_SHA
    integration_root = args.code_gate.resolve().parents[2]
    proof = {r["check_id"]: r for r in json.loads(PROOF.read_text())["checks"]}
    manifest = json.loads(args.candidate.read_text())
    assert manifest["replay_qualification"] == {"status": "pending", "receipt_sha256": None}
    checks = {r["check_id"]: r for r in manifest["checks"]}
    assert set(checks) == set(proof) and len(checks) == 24
    snap = json.loads(gzip.decompress(args.snapshot.read_bytes()))
    pre = json.loads(gzip.decompress(args.pre_ai.read_bytes()))
    collections = {(c["type"], c["scope"]): c for c in snap["collections"]}
    failures = defaultdict(list)
    for finding in pre["findings"]:
        if finding["check_id"] in checks:
            failures[finding["check_id"]].extend(o for o in finding["observations"] if o["status"] == "FAIL")
    per_check = []
    total_bindings = 0
    for cid in sorted(checks):
        row = checks[cid]
        source = proof[cid]
        assert row["audit_receipt_sha256"] == PROOF_SHA
        assert row["prod992_disagreements"] == 0
        assert row["prod992_reviewed_failures"] == source["native_fail_count"] == len(failures[cid])
        evaluator = row["deterministic_evidence"]["code_path_audit_ref"]
        assert evaluator["path"] == source["evaluator_ref"]["path"]
        assert evaluator["symbol"] == source["evaluator_ref"]["symbol"]
        assert evaluator["source_sha256"] == source["evaluator_ref"]["source_sha256"]
        assert digest(ROOT / evaluator["path"]) == evaluator["source_sha256"]
        assert digest(integration_root / evaluator["path"]) == evaluator["source_sha256"]
        collector = source["collector_ref"]
        assert digest(ROOT / collector["path"]) == collector["source_sha256"]
        assert digest(integration_root / collector["path"]) == collector["source_sha256"]
        bindings = 0
        for observation in failures[cid]:
            for field in row["deterministic_evidence"]["source_fields"]:
                match = REFERENCE.fullmatch(field["recorded_evidence_ref"])
                assert match and match.group(1) == SNAP_SHA, cid
                kind, path = match.group(2), match.group(3) or ""
                collection = collections[(kind, observation["scope"])]
                assert collection["status"] == "collected", cid
                item = [i for i in collection["items"] if i["id"] == observation["native_resource_id"]]
                assert len(item) == 1 and descend(item, path), cid
                bindings += 1
        total_bindings += bindings
        per_check.append({"check_id": cid, "initial_representatives": source["initial_representatives"],
                          "native_fail_count": len(failures[cid]), "exact_fail_row_field_bindings": bindings,
                          "collector_ref": collector})
    gate = load_gate(args.code_gate)
    pending = gate_admission(gate, manifest, manifest["checks"], False)
    qualified = gate_admission(gate, manifest, manifest["checks"], True)
    assert pending == frozenset() and qualified == set(checks)
    receipt = {"schema_version": 1, "status": "inactive_temp_gate_validation", "scan_id": "992d7b8c",
               "candidate_sha256": CANDIDATE_SHA, "source_proof_sha256": PROOF_SHA,
               "snapshot_sha256": SNAP_SHA, "pre_ai_report_sha256": PRE_SHA,
               "code_gate_sha256": GATE_SHA, "candidate_checks": len(checks),
               "initial_representatives": sum(r["initial_representatives"] for r in per_check),
               "exact_native_fail_rows": sum(r["native_fail_count"] for r in per_check),
               "exact_fail_row_field_bindings": total_bindings,
               "pending_admitted": len(pending), "temporary_qualified_admitted": len(qualified),
               "sha_tamper_admitted": 0,
               "production_manifest_modified": False, "model_replay_run": False,
               "per_check": per_check}
    args.output.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    print(json.dumps({k: receipt[k] for k in ("candidate_checks", "initial_representatives", "exact_native_fail_rows", "exact_fail_row_field_bindings", "pending_admitted", "temporary_qualified_admitted")}))


if __name__ == "__main__":
    main()
