#!/usr/bin/env python3
"""Build the inactive, exact-992 source-proven high-three schema-v2 fragment."""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
AUDIT = ROOT / "docs/ai-review/native-final-high-rep-revisit-v4.json"
AUDIT_SHA = "7e85b20f209585643b7deee45ba7937b8e73f2071bb30e3f5da9a519d6c08fcb"
SNAP_SHA = "3d7828c701a9457eeeb7d5aa497e1efd07a7977ccddeed498a73a2ba9dc2592f"
OUT = ROOT / "docs/ai-review/native-final-code-manifest-v2-fragment-high3.json"


def ref(kind, path):
    return "sha256:" + SNAP_SHA + "#collections[type=" + kind + "].items[]" + ("." + path if path else "")


def field(api, path, typ, kind, evidence_path=None):
    return {"api": api, "field_path": path, "field_type": typ,
            "source_semantics": "recorded_api_timestamp" if typ == "timestamp" else "recorded_api_field",
            "recorded_evidence_ref": ref(kind, evidence_path if evidence_path is not None else path)}


def main():
    assert hashlib.sha256(AUDIT.read_bytes()).hexdigest() == AUDIT_SHA
    audit = json.loads(AUDIT.read_text())
    approved = {r["check_id"]: r for r in audit["checks"] if r["decision"] == "native_final_source_proven_fail_branch"}
    assert set(approved) == {
        "aws.claude_a.iam.user_bedrock_access_not_stale",
        "aws.claude_a.iam.user_sagemaker_access_not_stale",
        "aws.c2b.lambda.env_vars_cmk",
    }
    rows = []
    for cid, proof in sorted(approved.items()):
        iam = cid.startswith("aws.claude_a.iam.")
        if iam:
            days = 60 if "bedrock" in cid else 90
            fields = [
                field("iam:GetServiceLastAccessedDetails", "ServicesLastAccessed[].ServiceNamespace", "enum", "iam_user"),
                field("iam:GetServiceLastAccessedDetails", "ServicesLastAccessed[].LastAuthenticated", "timestamp", "iam_user"),
                field("iam:GetServiceLastAccessedDetails", "ServicesLastAccessedStatus.collection_status", "enum", "iam_user"),
            ]
            operation = {"kind": "age_comparison", "comparison": "gt", "threshold": days, "threshold_unit": "days"}
            scan_time = {"source_field": "_provenance.collected_at or context.created_at",
                         "recorded_evidence_ref": ref("iam_user", "_provenance.collected_at")}
            path, symbol = "peaso/checks/claude_aws_a_iam.py", "_stale"
        else:
            fields = [
                field("lambda:ListFunctions", "FunctionArn", "enum", "lambda_function"),
                # The entire recorded item is the reference for optional omission;
                # the source-pinned absent_or helper binds it to FunctionArn.
                field("lambda:ListFunctions", "KMSKeyArn", "enum", "lambda_function", ""),
                field("lambda:GetFunctionConfiguration", "Environment.VariableCount", "number", "lambda_function"),
            ]
            operation = {"kind": "boolean_combination", "comparison": "and", "threshold": None, "threshold_unit": None}
            scan_time = None
            path, symbol = "peaso/checks/claude2_aws_b_compute.py", "lambda_env_cmk"
        source_sha = hashlib.sha256((ROOT / path).read_bytes()).hexdigest()
        assert source_sha == next(r["whole_file_sha256"] for r in proof["source_proof"] if r["path"] == path)
        rows.append({"check_id": cid, "prod992_disagreements": 0,
                     "prod992_reviewed_failures": proof["native_fail_count"],
                     "audit_receipt_sha256": AUDIT_SHA,
                     "deterministic_evidence": {
                         "source_fields": fields, "operation": operation, "scan_time": scan_time,
                         "code_path_audit_ref": {"path": path, "symbol": symbol, "source_sha256": source_sha,
                                                 "audit_ref": "docs/ai-review/native-final-high-rep-revisit-v4.json#" + cid}}})
    fragment = {"version": 2, "source_scan_id": "992d7b8cbd4340a79e41139ba1a44c1e",
                "base_commit": "d3e0e0ebfc8cf85196951460ed6db99f59e99c19",
                "replay_qualification": {"status": "pending", "receipt_sha256": None}, "checks": rows}
    OUT.write_text(json.dumps(fragment, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"checks": len(rows), "reviewed_failures": sum(r["prod992_reviewed_failures"] for r in rows),
                      "sha256": hashlib.sha256(OUT.read_bytes()).hexdigest()}))


if __name__ == "__main__":
    main()
