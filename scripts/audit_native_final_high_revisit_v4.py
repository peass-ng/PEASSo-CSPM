#!/usr/bin/env python3
"""Recheck seven high-rep exclusions and a pinned Runtime lookup, numeric only."""
import argparse
import ast
from collections import Counter
from datetime import date, datetime, timedelta
import gzip
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SNAPSHOT_SHA256 = "3d7828c701a9457eeeb7d5aa497e1efd07a7977ccddeed498a73a2ba9dc2592f"
PRE_AI_SHA256 = "4dcaa76a21c6b3bfff2b4859c1d4c763964c92c69041fe2d95702315fffde2ba"
NATIVE_NUMERIC = ROOT / "outputs/native-final-audit-992-v3-numeric.json"
IDS = (
    "aws.claude_a.ec2.stopped_instance_30_days",
    "aws.claude_a.ec2.stopped_instance_90_days",
    "aws.claude_a.ec2.stopped_instance_more_than_30_days",
    "aws.claude_a.iam.user_bedrock_access_not_stale",
    "aws.claude_a.iam.user_sagemaker_access_not_stale",
    "aws.c2b.lambda.env_vars_cmk",
    "aws.gap.s3.bucket_policy_denies_insecure_transport",
)
APPROVED = {
    "aws.claude_a.iam.user_bedrock_access_not_stale": ("bedrock", 60),
    "aws.claude_a.iam.user_sagemaker_access_not_stale": ("sagemaker", 90),
}
LAMBDA = "aws.c2b.lambda.env_vars_cmk"
RUNTIME = "aws.cb.lambda.runtime_not_deprecated_list"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def source(path, line):
    body = (ROOT / path).read_bytes()
    if line < 1 or line > len(body.decode().splitlines()):
        raise ValueError("source line changed: " + path)
    return {"path": path, "line": line, "whole_file_sha256": sha(body)}


def observations(report, ident):
    return [o for f in report["findings"] if f["check_id"] == ident
            for o in f.get("observations", []) if o["status"] == "FAIL"]


def parse(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def row_match(items, observation):
    matches = [x for x in items if x.get("id") == observation["native_resource_id"]]
    if len(matches) != 1:
        raise ValueError("scoped source row not uniquely bound")
    return matches[0]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("snapshot")
    parser.add_argument("pre_ai_report")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    snapshot_raw = Path(args.snapshot).read_bytes()
    pre_raw = Path(args.pre_ai_report).read_bytes()
    if sha(snapshot_raw) != SNAPSHOT_SHA256 or sha(pre_raw) != PRE_AI_SHA256:
        raise ValueError("exact 992 inputs changed")
    snapshot = json.loads(gzip.decompress(snapshot_raw))
    report = json.loads(gzip.decompress(pre_raw))
    numeric = {x["check_id"]: x for x in json.loads(NATIVE_NUMERIC.read_text())["per_check"]}
    by_kind = {}
    for kind in ("iam_user", "lambda_function"):
        by_kind[kind] = [x for c in snapshot["collections"] if c["type"] == kind
                         and c["status"] in ("collected", "empty") for x in c["items"]]
    decisions = []
    for ident in IDS:
        row = numeric[ident]
        obs = observations(report, ident)
        if (len(obs) != row["native_fail"] or row["ai_disagreement"] != 0 or
                row["ai_verdicts"] != {"FAIL": len(obs)} or
                any(o["category"] != "hardening" for o in obs)):
            raise ValueError("native/review check changed: " + ident)
        entry = {"check_id": ident, "native_fail_count": len(obs),
                 "initial_representatives": row["initial_representatives"],
                 "ai_verdict_counts": row["ai_verdicts"]}
        if ident in APPROVED:
            namespace, days = APPROVED[ident]
            counts = Counter()
            for o in obs:
                item = row_match(by_kind["iam_user"], o)
                status = item.get("ServicesLastAccessedStatus")
                if (not isinstance(status, dict) or status.get("collection_status") != "collected"
                        or not isinstance(item.get("ServicesLastAccessed"), list)):
                    raise ValueError("IAM service-access report incomplete: " + ident)
                matches = [x for x in item["ServicesLastAccessed"]
                           if x.get("ServiceNamespace") == namespace]
                if len(matches) != 1:
                    raise ValueError("IAM namespace row not unique: " + ident)
                access = matches[0]
                if "LastAuthenticated" not in access or access["LastAuthenticated"] is None:
                    marker = (access.get("_coverage") or {}).get("LastAuthenticated")
                    if marker is not None and (not isinstance(marker, dict)
                                               or marker.get("status") != "empty"):
                        raise ValueError("IAM last-auth absence not proven: " + ident)
                    counts["recorded_timestamp_absent"] += 1
                else:
                    stamp = (item.get("_provenance") or {}).get("collected_at") or snapshot["created_at"]
                    if (parse(stamp) - parse(access["LastAuthenticated"])).days <= days:
                        raise ValueError("IAM recorded age does not fail: " + ident)
                    counts["recorded_age_exceeds_threshold"] += 1
                counts["complete_service_report"] += 1
            entry.update({"decision": "native_final_source_proven_fail_branch",
                          "proof_counts": dict(sorted(counts.items())),
                          "deterministic_inputs": ["iam:GetServiceLastAccessedDetails.ServicesLastAccessed[].ServiceNamespace",
                                                   "iam:GetServiceLastAccessedDetails.ServicesLastAccessed[].LastAuthenticated",
                                                   "ServicesLastAccessedStatus.collection_status", "captured_scan_time"],
                          "source_proof": [source("peaso/checks/claude_aws_a_iam.py", 1041),
                                           source("peaso/checks/claude_aws_a_iam.py", 1074),
                                           source("peaso/checks/claude_aws_a_common.py", 177),
                                           source("peaso/checks/aws_a_facts.py", 49),
                                           source("peaso/collectors/aws.py", 1576)],
                          "rationale": "All exact 992 FAIL rows have a completed service-level access report and one matching namespace. The policy-derived not_collected branch cannot be their source. FAIL is recorded LastAuthenticated absence or fixed whole-day age at captured time."})
        elif ident == LAMBDA:
            counts = Counter()
            for o in obs:
                item = row_match(by_kind["lambda_function"], o)
                marker = (item.get("_coverage") or {}).get("KMSKeyArn")
                if (not item.get("FunctionArn") or "KMSKeyArn" in item or
                        marker is not None and (not isinstance(marker, dict) or marker.get("status") != "empty")):
                    raise ValueError("Lambda KMS omission not bound: " + ident)
                env = item.get("Environment")
                if (not isinstance(env, dict) or type(env.get("VariableCount")) is not int
                        or env["VariableCount"] <= 0 or "Variables" in env):
                    raise ValueError("Lambda positive count not recorded safely: " + ident)
                counts["positive_recorded_variable_count"] += 1
                counts["kms_key_arn_absent_with_function_identity"] += 1
            entry.update({"decision": "native_final_source_proven_fail_branch",
                          "proof_counts": dict(sorted(counts.items())),
                          "deterministic_inputs": ["lambda:ListFunctions.FunctionArn",
                                                   "lambda:ListFunctions.KMSKeyArn optional omission",
                                                   "lambda:GetFunctionConfiguration.Environment.VariableCount"],
                          "source_proof": [source("peaso/checks/claude2_aws_b_compute.py", 105),
                                           source("peaso/checks/claude_aws_b_common.py", 91),
                                           source("peaso/collectors/aws_facts_compute_edge.py", 268)],
                          "rationale": "All exact 992 FAIL rows have a positive count-only environment projection and an absent KMSKeyArn under a bound function identity. This proves the configured-key absence branch only; no KMS key ownership or encryption effectiveness is inferred."})
        elif "stopped_instance" in ident:
            entry.update({"decision": "retain_ai", "source_proof": [source("peaso/checks/claude_aws_a_ec2.py", 656),
                                                                          source("peaso/checks/claude_aws_a_ec2.py", 659),
                                                                          source("peaso/checks/claude_aws_a_ec2.py", 674)],
                          "rationale": "Stop time is parsed by regex from free-text EC2 StateTransitionReason before the clock comparison; excluded free-text interpretation."})
        else:
            entry.update({"decision": "retain_ai", "source_proof": [source("peaso/checks/aws_gap_core.py", 431),
                                                                          source("peaso/checks/aws_gap_core.py", 470)],
                          "rationale": "Delegated bucket-policy evaluator interprets Effect, Principal, Action, Resource wildcard coverage and Condition intent; policy interpretation remains AI reviewed."})
        decisions.append(entry)

    # Runtime is separately source-proven as a code-pinned enum lookup, but the
    # current gate cannot describe it without inventing an API timestamp.
    runtime_obs = observations(report, RUNTIME)
    runtime_row = numeric[RUNTIME]
    code_path = ROOT / "peaso/checks/claude_aws_b_compute.py"
    syntax = ast.parse(code_path.read_text())
    table_node = next(n.value for n in syntax.body if isinstance(n, ast.Assign)
                      and any(isinstance(t, ast.Name) and t.id == "RUNTIME_DEPRECATION" for t in n.targets))
    table = ast.literal_eval(table_node)
    runtime_counts = Counter()
    for o in runtime_obs:
        item = row_match(by_kind["lambda_function"], o)
        runtime = item.get("Runtime")
        if item.get("PackageType") != "Zip" or runtime not in table:
            raise ValueError("runtime FAIL row lacks listed managed Runtime")
        stamp = (item.get("_provenance") or {}).get("collected_at") or snapshot["created_at"]
        observed = parse(stamp).date()
        if observed > date.fromisoformat("2026-10-12") + timedelta(days=180):
            raise ValueError("runtime review window expired")
        if observed < date.fromisoformat(table[runtime]):
            raise ValueError("runtime FAIL row not deprecated at captured clock")
        runtime_counts["zip_runtime_in_pinned_table_and_deprecated_at_clock"] += 1
    if (len(runtime_obs) != runtime_row["native_fail"] or runtime_row["ai_disagreement"] != 0
            or runtime_row["ai_verdicts"] != {"FAIL": len(runtime_obs)}):
        raise ValueError("runtime numeric receipt changed")
    receipt = {"schema_version": 1, "scan_id": "992d7b8cbd4340a79e41139ba1a44c1e",
               "status": "source_proposal_only", "snapshot_sha256": SNAPSHOT_SHA256,
               "pre_ai_report_sha256": PRE_AI_SHA256, "checks": decisions,
               "additional_source_proven_check_ids": sorted([*APPROVED, LAMBDA]),
               "additional_native_fail_count": sum(x["native_fail_count"] for x in decisions if x["decision"].startswith("native_final")),
               "additional_initial_representatives": sum(x["initial_representatives"] for x in decisions if x["decision"].startswith("native_final")),
               "runtime_lookup_proposal": {
                   "check_id": RUNTIME, "status": "pending_gate_schema_review",
                   "native_fail_count": len(runtime_obs),
                   "initial_representatives": runtime_row["initial_representatives"],
                   "proof_counts": dict(sorted(runtime_counts.items())),
                   "operation_kind_proposed": "pinned_enum_date_lookup_at_captured_scan_date",
                   "operation": "Runtime enum -> source-pinned RUNTIME_DEPRECATION[Runtime]; captured scan date >= mapped date within fixed 180-day review window",
                   "source_fields": ["lambda:ListFunctions.Runtime", "lambda:ListFunctions.PackageType", "captured_scan_time"],
                   "source_proof": [source("peaso/checks/claude_aws_b_compute.py", 107),
                                    source("peaso/checks/claude_aws_b_compute.py", 141),
                                    source("peaso/checks/claude_aws_a_common.py", 177),
                                    source("peaso/checks/aws_a_facts.py", 49)],
                   "reason_current_gate_rejects": "age_comparison schema requires a recorded API timestamp, but the deprecation date is a fixed source-pinned lookup constant"}}
    Path(args.output).write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"approved": len(receipt["additional_source_proven_check_ids"]),
                      "native_fail": receipt["additional_native_fail_count"],
                      "initial_reps": receipt["additional_initial_representatives"],
                      "runtime_lookup_fail_rows": len(runtime_obs)}))


if __name__ == "__main__":
    main()
