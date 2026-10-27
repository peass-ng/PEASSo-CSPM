#!/usr/bin/env python3
"""Check the inactive v2 candidate against exact 992 facts and the code gate."""
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


COLLECTION = re.compile(r"#collections\[type=([^]]+)\](.*)$")


def descend(values, path):
    if not path:
        return values
    for part in path.split("."):
        many = part.endswith("[]")
        key = part[:-2] if many else part
        selected = []
        for value in values:
            if isinstance(value, dict) and key in value:
                child = value[key]
                if many:
                    if isinstance(child, list):
                        selected.extend(child)
                else:
                    selected.append(child)
        values = selected
    return values


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("candidate")
    parser.add_argument("snapshot")
    parser.add_argument("code_gate")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    raw = Path(args.candidate).read_bytes()
    candidate = json.loads(raw)
    if candidate["replay_qualification"] != {"status": "pending", "receipt_sha256": None}:
        raise ValueError("candidate must remain inactive")
    snapshot_raw = Path(args.snapshot).read_bytes()
    snapshot_sha = hashlib.sha256(snapshot_raw).hexdigest()
    snapshot = json.loads(gzip.decompress(snapshot_raw))
    collections = defaultdict(list)
    rows = defaultdict(list)
    for collection in snapshot["collections"]:
        collections[collection["type"]].append(collection)
        rows[collection["type"]].extend(collection["items"])
    count = 0
    for check in candidate["checks"]:
        for field in check["deterministic_evidence"]["source_fields"]:
            ref = field["recorded_evidence_ref"]
            if not ref.startswith("sha256:" + snapshot_sha + "#"):
                raise ValueError("snapshot binding changed")
            match = COLLECTION.search(ref)
            if match is None:
                raise ValueError("invalid collection evidence reference")
            kind, suffix = match.groups()
            if suffix == ".status":
                found = [collection["status"] for collection in collections[kind]]
            elif suffix.startswith(".items[]"):
                path = suffix[len(".items[]"):].lstrip(".")
                found = descend(rows[kind], path)
            else:
                raise ValueError("unsupported evidence reference")
            if not found:
                raise ValueError("unobserved evidence reference: " + check["check_id"])
            count += 1
    spec = importlib.util.spec_from_file_location("native_final_code_gate", args.code_gate)
    gate = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gate)
    with tempfile.TemporaryDirectory(prefix="native-final-v2-validation-") as temp:
        path = Path(temp) / "manifest.json"
        path.write_bytes(raw)
        os.environ["PEASO_HARDENING_NATIVE_FINAL_ENABLED"] = "1"
        os.environ["PEASO_HARDENING_NATIVE_FINAL_SHA256"] = hashlib.sha256(raw).hexdigest()
        if gate.admitted_check_ids(path):
            raise ValueError("pending candidate was admitted")
        receipt = Path(temp) / "temporary-test-receipt.json"
        receipt.write_text('{"temporary_gate_validation_only":true}\n')
        qualified = json.loads(raw)
        qualified["replay_qualification"] = {
            "status": "qualified",
            "receipt_sha256": hashlib.sha256(receipt.read_bytes()).hexdigest(),
        }
        qualified_raw = (json.dumps(qualified, sort_keys=True) + "\n").encode()
        path.write_bytes(qualified_raw)
        os.environ["PEASO_HARDENING_NATIVE_FINAL_SHA256"] = hashlib.sha256(qualified_raw).hexdigest()
        admitted = gate.admitted_check_ids(path)
        expected = {entry["check_id"] for entry in candidate["checks"]}
        if admitted != expected:
            raise ValueError("temporary qualified candidate failed code gate")
        path.write_bytes(qualified_raw + b" ")
        if gate.admitted_check_ids(path):
            raise ValueError("changed manifest bypassed exact SHA pin")
    receipt = {
        "schema_version": 1,
        "candidate_sha256": hashlib.sha256(raw).hexdigest(),
        "snapshot_sha256": snapshot_sha,
        "candidate_checks": len(candidate["checks"]),
        "resolved_recorded_evidence_references": count,
        "unresolved_recorded_evidence_references": 0,
        "pending_admitted": 0,
        "temporary_qualified_admitted": len(expected),
        "sha_tamper_admitted": 0,
        "production_manifest_modified": False,
        "model_replay_run": False,
    }
    Path(args.output).write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    print(json.dumps(receipt, sort_keys=True))


if __name__ == "__main__":
    main()
