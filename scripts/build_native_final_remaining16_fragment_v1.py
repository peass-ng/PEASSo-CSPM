"""Build the single inactive Config fragment from the signed remaining-16 proof."""

import argparse
import hashlib
import json
from pathlib import Path


SNAPSHOT_SHA = "3d7828c701a9457eeeb7d5aa497e1efd07a7977ccddeed498a73a2ba9dc2592f"


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def run(args):
    proof = json.loads(Path(args.proof).read_text())
    approved = [r for r in proof["checks"] if r["decision"] == "approve_inactive"]
    assert len(approved) == 1 and approved[0]["check_id"] == "aws_config_all_resources_recorded"
    assert approved[0]["native_fail_count"] == 2 and approved[0]["prod992_ai_disagreements"] == 0
    assert proof["input_sha256"]["snapshot"] == SNAPSHOT_SHA
    source = "peaso/checks/aws_config_recording.py"
    source_hash = approved[0]["source_file_sha256"][source]
    assert source_hash == sha(Path(args.source) / source)
    fragment = {
        "version": 2, "source_scan_id": "992d7b8cbd4340a79e41139ba1a44c1e",
        "base_commit": "d3e0e0ebfc8cf85196951460ed6db99f59e99c19",
        "replay_qualification": {"status": "pending", "receipt_sha256": None},
        "checks": [{"check_id": "aws_config_all_resources_recorded", "prod992_disagreements": 0,
                    "prod992_reviewed_failures": 2, "audit_receipt_sha256": sha(args.proof),
                    "deterministic_evidence": {
                        "source_fields": [{"api": "config:DescribeConfigurationRecorders", "field_path": "collections[type=config_recorder].items",
                                           "field_type": "list", "source_semantics": "recorded_api_field",
                                           "recorded_evidence_ref": "sha256:" + SNAPSHOT_SHA + "#collections[type=config_recorder].items"}],
                        "operation": {"kind": "count_comparison", "comparison": "eq", "threshold": 0, "threshold_unit": "items"},
                        "scan_time": None,
                        "code_path_audit_ref": {"path": source, "symbol": "config_all_supported", "source_sha256": source_hash,
                                                "audit_ref": "docs/ai-review/native-final-remaining16-source-proof-v1.json#aws_config_all_resources_recorded"}}}]}
    Path(args.output).write_text(json.dumps(fragment, sort_keys=True, indent=2) + "\n")


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    for name in ("proof", "source", "output"):
        p.add_argument("--" + name, required=True)
    run(p.parse_args())
