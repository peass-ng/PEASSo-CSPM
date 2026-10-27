"""Fail-closed, numeric-only audit of the other 12 hosted baseline downgrades."""

import argparse
import gzip
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path

from peaso.checks import CHECKS, evaluate_check


# Count, recorded applicability paths, evaluator source, exact branch proof,
# and global-path decision. No evidence values or resource identifiers are saved.
SPEC = {
    "aws.c2b.cloudformation.termination_protection_root_stacks": (22, ("RootId", "EnableTerminationProtection"), "peaso/checks/claude2_aws_b_devtools.py:394-405", "Absent RootId identifies a root stack; recorded protection is false.", "retain_candidate"),
    "aws.c2b.athena.results_encrypted_prowler": (2, ("WorkGroup.collection_status", "WorkGroup.WorkGroup.State"), "peaso/checks/claude2_aws_b_data.py:172-185;peaso/checks/claude2_aws_b_common.py:135-143", "Nested workgroup is ENABLED; detail helper accepts missing collection_status and missing encryption defaults to failure.", "retain_ai_until_detail_status_guard"),
    "aws.c2b.athena.enforce_configuration_prowler": (2, ("WorkGroup.collection_status", "WorkGroup.WorkGroup.State"), "peaso/checks/claude2_aws_b_data.py:185-216;peaso/checks/claude2_aws_b_common.py:135-143", "Nested workgroup is ENABLED; detail helper accepts missing collection_status and missing setting defaults to failure.", "retain_ai_until_detail_status_guard"),
    "aws.c2b.athena.cloudwatch_metrics_prowler": (3, ("WorkGroup.collection_status", "WorkGroup.WorkGroup.State"), "peaso/checks/claude2_aws_b_data.py:185-216;peaso/checks/claude2_aws_b_common.py:135-143", "Nested workgroup is ENABLED; detail helper accepts missing collection_status and missing setting defaults to failure.", "retain_ai_until_detail_status_guard"),
    "aws.cb.rds.instance_enhanced_monitoring_except_m1_small": (4, ("DBInstanceClass",), "peaso/checks/claude_aws_b_db.py:369-381", "Recorded class is not exempt; optional monitoring ARN is absent.", "retain_candidate"),
    "aws.cb.rds.instance_iam_auth_supported_engines": (4, ("Engine", "IAMDatabaseAuthenticationEnabled"), "peaso/checks/claude_aws_b_db.py:619-632", "Recorded engine is in supported set and IAM authentication is false.", "retain_candidate"),
    "aws.cb.rds.instance_multi_az_non_aurora": (1, ("Engine", "MultiAZ"), "peaso/checks/claude_aws_b_db.py:679-690", "Recorded engine is non-Aurora and MultiAZ is false.", "retain_candidate"),
    "aws.cb.route53.public_zone_query_logging": (8, ("Config.PrivateZone", "QueryLoggingConfigs.collection_status", "QueryLoggingConfigs.QueryLoggingConfigs"), "peaso/checks/claude_aws_b_security.py:419-434", "Public zone has a collected empty logging config; evaluator does not validate child collection_status before failing.", "retain_ai_until_logging_status_guard"),
    "aws.claude_a.s3.prowler_acl_disabled": (1, ("OwnershipControls.collection_status", "OwnershipControls.absent"), "peaso/checks/claude_aws_a_s3.py:63-80;peaso/checks/claude_aws_a_s3.py:538-548", "Documented absent-configuration marker is verified by section helper.", "retain_candidate"),
    "aws.claude_a.ec2.launch_template_default_imdsv2": (2, ("Versions",), "peaso/checks/claude_aws_a_ec2.py:1004-1030", "One default version exists, but HttpTokens is absent; evaluator lacks version-detail completeness guard and treats absence as FAIL.", "retain_ai_until_version_completeness_guard"),
    "aws.claude_a.iam.admin_user_has_mfa": (1, ("AttachedManagedPolicies", "MFADevices.collection_status", "MFADevices.items"), "peaso/checks/claude_aws_a_iam.py:206-209;peaso/checks/claude_aws_a_iam.py:585-595", "AdministratorAccess is directly attached and captured MFA list is empty; evaluator ignores MFA collection_status on future rows.", "retain_ai_until_mfa_status_guard"),
    "aws.claude_a.ec2.instance_ebs_delete_on_termination": (1, ("BlockDeviceMappings",), "peaso/checks/claude_aws_a_ec2.py:706-719", "Recorded EBS mapping has explicit DeleteOnTermination false; missing flag cannot produce this FAIL.", "retain_candidate"),
}


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def at(row, path):
    for part in path.split("."):
        if not isinstance(row, dict) or part not in row:
            return None, False
        row = row[part]
    return row, True


def branch(check, item):
    if check == "aws.c2b.cloudformation.termination_protection_root_stacks":
        return "RootId" not in item and item["EnableTerminationProtection"] is False
    if check.startswith("aws.c2b.athena."):
        return item["WorkGroup"]["collection_status"] == "collected" and item["WorkGroup"]["WorkGroup"]["State"] == "ENABLED"
    if check == "aws.cb.rds.instance_enhanced_monitoring_except_m1_small":
        return item["DBInstanceClass"] != "db.m1.small" and not item.get("EnhancedMonitoringResourceArn")
    if check == "aws.cb.rds.instance_iam_auth_supported_engines":
        return item["Engine"] in ("postgres", "mysql", "mariadb", "aurora-postgresql", "aurora-mysql", "aurora") and item["IAMDatabaseAuthenticationEnabled"] is False
    if check == "aws.cb.rds.instance_multi_az_non_aurora":
        return "aurora" not in item["Engine"].lower() and item["MultiAZ"] is False
    if check == "aws.cb.route53.public_zone_query_logging":
        return item["Config"]["PrivateZone"] is False and item["QueryLoggingConfigs"]["collection_status"] == "collected" and not item["QueryLoggingConfigs"]["QueryLoggingConfigs"]
    if check == "aws.claude_a.s3.prowler_acl_disabled":
        return item["OwnershipControls"]["collection_status"] == "empty" and item["OwnershipControls"]["absent"] is True
    if check == "aws.claude_a.ec2.launch_template_default_imdsv2":
        defaults = [v for v in item["Versions"] if v.get("DefaultVersion") is True]
        return len(defaults) == 1 and "HttpTokens" not in defaults[0]["LaunchTemplateData"].get("MetadataOptions", {})
    if check == "aws.claude_a.iam.admin_user_has_mfa":
        return any(p.get("PolicyName") == "AdministratorAccess" for p in item["AttachedManagedPolicies"]) and item["MFADevices"]["collection_status"] == "empty" and item["MFADevices"]["items"] == []
    if check == "aws.claude_a.ec2.instance_ebs_delete_on_termination":
        return any(m.get("Ebs", {}).get("DeleteOnTermination") is False for m in item["BlockDeviceMappings"])
    raise AssertionError(check)


def run(args):
    files = {k: Path(getattr(args, k)) for k in ("snapshot", "pre_ai", "common", "arm", "candidate")}
    with gzip.open(files["snapshot"]) as stream:
        snapshot = json.load(stream)
    with gzip.open(files["pre_ai"]) as stream:
        pre = json.load(stream)
    common = json.loads(files["common"].read_text())
    arm = json.loads(files["arm"].read_text())
    candidate = json.loads(files["candidate"].read_text())
    candidate_ids = {x["check_id"] for x in candidate["checks"]}
    staged = {x["id"]: x for x in common["hardening"]}
    downgraded = [r for r in arm["reviews"] if staged[r["finding_id"]]["check_id"] in candidate_ids and r["verdict"] != "FAIL"]
    assert len(candidate_ids) == 248 and len(downgraded) == 80
    selected = [r for r in downgraded if staged[r["finding_id"]]["check_id"] in SPEC]
    assert len(selected) == 51 and all(r["verdict"] in ("UNKNOWN", "MANUAL") for r in selected)
    assert Counter(staged[r["finding_id"]]["check_id"] for r in selected) == Counter({k: v[0] for k, v in SPEC.items()})
    pre_obs = {o["id"]: o for g in pre["findings"] for o in g.get("observations", [g])}
    checks = {c.id: c for c in CHECKS}
    collections = defaultdict(list)
    for c in snapshot["collections"]:
        collections[c["type"]].append(c)
    launches = {}
    for path in files["arm"].parent.glob("launch-*/findings.json"):
        launches.update({x["id"]: x for x in json.loads(path.read_text())["items"]})
    counts = Counter()
    for review in selected:
        rid = review["finding_id"]
        row = staged[rid]
        check = row["check_id"]
        meta = checks[check]
        assert pre_obs[rid]["status"] == "FAIL"
        assert rid in launches and launches[rid]["check_id"] == check
        scope = row["scope"]
        matching = [(col, item) for col in collections[meta.kind] if col["scope"] in (scope, scope.split("/")[0] + "/global") for item in col["items"] if item.get("id") == row["native_resource_id"]]
        assert len(matching) == 1
        col, item = matching[0]
        assert col["status"] == "collected" and branch(check, item)
        _, fields, _, _, _ = SPEC[check]
        for path in fields:
            value, present = at(item, path)
            if check == "aws.c2b.cloudformation.termination_protection_root_stacks" and path == "RootId":
                assert not present
            else:
                assert present and value is not None
            assert path.split(".")[-1] not in row["evidence"]
            assert path.split(".")[-1] not in launches[rid]["evidence"]
        assert all(isinstance(x, dict) and "data" not in x for x in launches[rid]["supporting_resources"])
        index = {"context": {"provider": "aws", "scope": scope, "created_at": snapshot["created_at"], "metadata": snapshot["metadata"]}, "collections": {}}
        for kind in set([meta.kind] + list(meta.dependencies)):
            pages = [c for c in collections[kind] if c["scope"] in (scope, scope.split("/")[0] + "/global")]
            index["collections"][kind] = pages
            index[kind] = [{"data": item, "type": kind, "scope": page["scope"], "provider": "aws"} for page in pages for item in page["items"]]
        assert evaluate_check(check, item, index)[0] == "FAIL"
        counts[check] += 1
    out = {"schema_version": 1, "status": "inactive_source_audit", "input_sha256": {k: sha(v) for k, v in files.items()},
           "downgraded_candidate_rows": 80, "remaining_twelve_rows": 51,
           "checks": [{"check_id": check, "downgrade_count": count, "snapshot_branch_fields": list(fields),
                       "native_snapshot_re_evaluation_fail_count": counts[check], "staged_applicability_omitted_count": counts[check],
                       "evaluator_path": source,
                       "source_file_sha256": {ref.split(":")[0]: sha(Path(args.source) / ref.split(":")[0]) for ref in source.split(";")},
                       "branch_proof": proof, "global_decision": decision}
                      for check, (count, fields, source, proof, decision) in SPEC.items()],
           "interpretation": "All 51 exact-snapshot rows support native FAIL. Hosted UNKNOWN/MANUAL reasons correspond to applicability or decisive fields omitted from staged AI inputs. Global source safety is assessed separately per check.",
           "caveat": "retain_candidate means this audit found no additional future-path defect; runtime admission remains subject to root integration and replay gate."}
    assert all(x["downgrade_count"] == x["native_snapshot_re_evaluation_fail_count"] for x in out["checks"])
    Path(args.output).write_text(json.dumps(out, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    for arg in ("snapshot", "pre_ai", "common", "arm", "candidate", "source", "output"):
        p.add_argument("--" + arg.replace("_", "-"), required=True)
    run(p.parse_args())
