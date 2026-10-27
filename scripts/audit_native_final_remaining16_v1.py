"""Source-pinned, inactive proof for the disjoint 16 zero-disagreement IDs."""

import argparse
import gzip
import hashlib
import json
from pathlib import Path

from peaso.checks import evaluate_check


PROOF = {
 "aws.b.ecr.effective_scan_configuration": ("retain_ai", "peaso/checks/aws_b_ecr.py:33-62", "Enhanced scanning branch interprets wildcard registry filters; the complete policy matching grammar is outside the direct setting proof."),
 "aws.c2b.ecr.latest_image_no_medium_plus_findings": ("retain_ai", "peaso/checks/claude2_aws_b_devtools.py:623-677", "Image-tag suffix parsing and vulnerability severity/content selection are free-text/content judgment."),
 "aws.claude_a.ec2.stopped_instance_30_days": ("retain_ai", "peaso/checks/claude_aws_a_ec2.py:656-702", "Timestamp is regex-parsed from StateTransitionReason free text."),
 "aws.claude_a.ec2.stopped_instance_90_days": ("retain_ai", "peaso/checks/claude_aws_a_ec2.py:656-702", "Timestamp is regex-parsed from StateTransitionReason free text."),
 "aws.claude_a.ec2.stopped_instance_more_than_30_days": ("retain_ai", "peaso/checks/claude_aws_a_ec2.py:656-702", "Timestamp is regex-parsed from StateTransitionReason free text."),
 "aws.claude_a.iam.prowler_user_hardware_mfa": ("retain_ai", "peaso/checks/claude_aws_a_iam.py:1006-1026", "Hardware classification parses MFA SerialNumber text; missing MFA collection status can also reach a decision."),
 "aws.claude_a.iam.role_bedrock_access_not_stale": ("retain_ai", "peaso/checks/claude_aws_a_iam.py:1041-1095", "ServicesLastAccessedStatus completeness is not guarded by evaluator; future partial service list can FAIL."),
 "aws.gap.cloudtrail.trail_security_best_practices": ("retain_ai", "peaso/checks/aws_gap_core.py:105-137;peaso/checks/aws_gap_core.py:284-307", "CloudTrail event selector management coverage interprets policy intent."),
 "aws.gap.s3.bucket_policy_denies_insecure_transport": ("retain_ai", "peaso/checks/aws_gap_core.py:470-477", "Bucket policy Deny parsing interprets policy intent."),
 "aws.nist.all_iam_policies_no_star_star": ("retain_ai", "peaso/checks/aws_all_policies.py:1-115", "IAM policy Action and Resource wildcard parsing interprets policy content."),
 "aws.nist.all_managed_policies_no_service_wildcard": ("retain_ai", "peaso/checks/aws_all_policies.py:1-115", "IAM policy Action wildcard parsing interprets policy content."),
 "aws.review.cloudwatch.sampled_log_secret_indicators": ("retain_ai", "peaso/checks/aws_code_log_content_review_20261019.py:103-190", "Sampled log secret indicators require content judgment."),
 "aws.review.ecr_repository.package_content_secret_indicators": ("retain_ai", "peaso/checks/aws_package_content_review_20261019.py:87-175", "Package secret indicators require content judgment."),
 "aws.review.secretsmanager.explicit_principal_deny": ("retain_ai", "peaso/checks/aws_policy_constraints_review_20261019.py:311-380", "Resource policy explicit-principal Deny requires policy intent interpretation."),
 "aws_api_customer_log_delivery": ("retain_ai", "peaso/checks/compliance_new_sw49.py:198-260", "Stage-format free-text tokens and delivery inference exceed a direct recorded setting."),
 "aws_config_all_resources_recorded": ("approve_inactive", "peaso/checks/aws_config_recording.py:126-169;peaso/checks/aws_a_facts.py:1-100", "Both FAIL scopes have a complete, empty regional DescribeConfigurationRecorders inventory; complete_items guards collection status/scope. Cardinality zero is pure.")
}


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def run(args):
    files = {name: Path(getattr(args, name)) for name in ("numeric", "high84", "high3", "low190", "snapshot")}
    numeric = json.loads(files["numeric"].read_text())
    high84 = json.loads(files["high84"].read_text())
    high3 = json.loads(files["high3"].read_text())
    low190 = json.loads(files["low190"].read_text())
    zero = {r["check_id"] for r in numeric["per_check"] if r["ai_disagreement"] == 0 and r["native_fail"] > 0}
    claimed = {r["check_id"] for r in high84["checks"] + high3["checks"] + low190["checks"]}
    assert len(zero) == 293 and len(claimed) == 277 and len(zero - claimed) == 16
    assert zero - claimed == set(PROOF)
    per = {r["check_id"]: r for r in numeric["per_check"]}
    assert sum(per[x]["initial_representatives"] for x in PROOF) == 86
    assert sum(per[x]["native_fail"] for x in PROOF) == 764
    with gzip.open(files["snapshot"]) as stream:
        snapshot = json.load(stream)
    config = [c for c in snapshot["collections"] if c["type"] == "config_recorder" and c["scope"] in snapshot["scopes"]]
    assert len(config) == 2 and all(c["status"] == "empty" and c["items"] == [] for c in config)
    for c in config:
        index = {"context": {"provider": "aws", "scope": c["scope"], "metadata": snapshot["metadata"]}, "collections": {"config_recorder": [c]}}
        assert evaluate_check("aws_config_all_resources_recorded", {"scope": c["scope"]}, index)[0] == "FAIL"
    rows = []
    for check, (decision, ref, reason) in PROOF.items():
        source_hashes = {part.split(":")[0]: sha(Path(args.source) / part.split(":")[0]) for part in ref.split(";")}
        rows.append({"check_id": check, "decision": decision, "initial_representatives": per[check]["initial_representatives"],
                     "native_fail_count": per[check]["native_fail"], "prod992_ai_disagreements": 0,
                     "source_refs": ref.split(";"), "source_file_sha256": source_hashes, "reason": reason})
    out = {"schema_version": 1, "status": "inactive_source_proof", "input_sha256": {k: sha(v) for k,v in files.items()},
           "disjoint_count": 16, "initial_representatives": 86, "native_fail_count": 764,
           "approved_inactive_count": 1, "retained_ai_count": 15, "checks": rows,
           "config_exact_scope_proof": {"scope_count": 2, "complete_empty_collection_count": 2, "native_re_evaluation_fail_count": 2}}
    Path(args.output).write_text(json.dumps(out, sort_keys=True, indent=2) + "\n")


if __name__ == "__main__":
    p=argparse.ArgumentParser()
    for name in ("numeric", "high84", "high3", "low190", "snapshot", "source", "output"):
        p.add_argument("--"+name.replace("_","-"),required=True)
    run(p.parse_args())
