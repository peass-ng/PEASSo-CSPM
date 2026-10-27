"""Exact-row, source-pinned audit of all 245-candidate hosted non-FAIL reviews.

Reads private replay inputs. Emits only finding hashes, snapshot row hashes,
boolean/count facts, source refs, and numeric verdicts.
"""

import argparse
import copy
import gzip
import hashlib
import json
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

from peaso.checks import CHECKS, evaluate_check


EXPECTED = {
    "aws.c2b.cloudformation.termination_protection_root_stacks": (22, "peaso/checks/claude2_aws_b_devtools.py:394-405", "future_fail_closed"),
    "aws.a.iam.active_key_age_90": (20, "peaso/checks/aws_a_iam_lifecycle.py:25-35", "future_fail_closed"),
    "aws.cb.rds.instance_enhanced_monitoring_except_m1_small": (4, "peaso/checks/claude_aws_b_db.py:369-381", "future_fail_closed"),
    "aws.cb.rds.instance_iam_auth_supported_engines": (4, "peaso/checks/claude_aws_b_db.py:619-632", "future_fail_closed"),
    "aws_g6_ecs_all_containers_logging": (2, "peaso/checks/batch_remaining_aws.py:88-145;peaso/checks/batch_remaining_aws.py:226-239", "retain_ai_until_detail_status_guard"),
    "aws_route53_hosted_zone_dnssec_enabled": (2, "peaso/checks/batch_remaining_aws.py:88-145;peaso/checks/batch_remaining_aws.py:543-557", "future_fail_closed"),
    "aws_nist_cloudtrail_trail_logs_encrypted_with_kms_cmk": (2, "peaso/checks/batch_remaining_aws.py:88-145;peaso/checks/batch_remaining_aws.py:1072-1134", "future_fail_closed"),
    "aws.claude_a.s3.prowler_acl_disabled": (1, "peaso/checks/claude_aws_a_s3.py:63-80;peaso/checks/claude_aws_a_s3.py:538-548", "retain_ai_until_detail_status_guard"),
    "aws_sns_delivery_failure_alarm_present": (1, "peaso/checks/batch_remaining_aws.py:88-145;peaso/checks/batch_remaining_aws.py:418-462;peaso/checks/batch_remaining_aws.py:1055-1070", "future_fail_closed"),
    "aws.cb.rds.instance_multi_az_non_aurora": (1, "peaso/checks/claude_aws_b_db.py:679-690", "future_fail_closed"),
    "aws.claude_a.ec2.instance_ebs_delete_on_termination": (1, "peaso/checks/claude_aws_a_ec2.py:706-719", "future_fail_closed"),
}

FUTURE_REASON = {
    "aws.c2b.cloudformation.termination_protection_root_stacks": "StackName sentinel proves the DescribeStacks row; absent RootId is the API's root-stack case, while protection requires an explicit boolean.",
    "aws.a.iam.active_key_age_90": "Status must be Active and CreateDate must parse against captured scan time; absent or other status cannot FAIL.",
    "aws.cb.rds.instance_enhanced_monitoring_except_m1_small": "DBInstanceClass is required and excludes db.m1.small; optional monitoring ARN absence is interpreted only after DBInstanceArn proves the DescribeDBInstances row.",
    "aws.cb.rds.instance_iam_auth_supported_engines": "Engine is required and tested before optional IAM auth; DBInstanceArn proves the complete DescribeDBInstances row.",
    "aws_g6_ecs_all_containers_logging": "The evaluator reads Definition.taskDefinition without requiring Definition.collection_status; removing that marker from an otherwise identical FAIL row still returns FAIL. Require collected status before evaluating.",
    "aws_route53_hosted_zone_dnssec_enabled": "_member validates same-scope inventory; Config.PrivateZone is required and DNSSEC collection_status plus HostedZoneId are checked before FAIL.",
    "aws_nist_cloudtrail_trail_logs_encrypted_with_kms_cmk": "_member and home-region check precede collected IsLogging guard; complete KMS and log-group inventories and key metadata are required.",
    "aws.claude_a.s3.prowler_acl_disabled": "section() validates the documented empty marker but accepts a nonempty OwnershipControls response without requiring collection_status; a synthetic missing-status detail with ObjectWriter still FAILs. Require collected status for nonempty detail.",
    "aws_sns_delivery_failure_alarm_present": "Topic attributes must be collected with positive confirmed subscriptions; _alarm requires complete same-scope alarm inventory and refuses absence if relevant alarms are unresolved.",
    "aws.cb.rds.instance_multi_az_non_aurora": "Engine is required and Aurora excluded before an explicit MultiAZ false can FAIL.",
    "aws.claude_a.ec2.instance_ebs_delete_on_termination": "FAIL requires at least one explicit Ebs.DeleteOnTermination false; missing mapping or flag cannot produce FAIL.",
}

MANIFEST_APPLICABILITY_GAP = {
    "aws.c2b.cloudformation.termination_protection_root_stacks": ["RootId"],
    "aws_route53_hosted_zone_dnssec_enabled": ["Config.PrivateZone"],
    "aws_nist_cloudtrail_trail_logs_encrypted_with_kms_cmk": ["Status.IsLogging"],
    "aws.claude_a.s3.prowler_acl_disabled": ["OwnershipControls.collection_status"],
    "aws_sns_delivery_failure_alarm_present": ["Attributes.Attributes.SubscriptionsConfirmed"],
}


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def canonical_hash(row):
    return hashlib.sha256(json.dumps(row, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


def facts(check, item, snapshot, index, evidence):
    if check == "aws.c2b.cloudformation.termination_protection_root_stacks":
        assert item.get("StackName") and "RootId" not in item and item["EnableTerminationProtection"] is False
        return {"root_id_absent": True, "protection_disabled": True}
    if check == "aws.a.iam.active_key_age_90":
        assert item["Status"] == "Active"
        created = datetime.fromisoformat(item["CreateDate"].replace("Z", "+00:00"))
        clock = datetime.fromisoformat(snapshot["created_at"].replace("Z", "+00:00"))
        cutoff = clock.astimezone(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=90)
        assert created <= cutoff
        return {"status_active": True, "at_or_before_90_day_cutoff": True}
    if check == "aws.cb.rds.instance_enhanced_monitoring_except_m1_small":
        assert item["DBInstanceClass"] != "db.m1.small" and not item.get("EnhancedMonitoringResourceArn")
        return {"class_exempt": False, "monitoring_arn_present": False}
    if check == "aws.cb.rds.instance_iam_auth_supported_engines":
        engine = item["Engine"]
        assert any(x in engine for x in ("postgres", "aurora-postgresql", "mysql", "mariadb", "aurora-mysql", "aurora"))
        assert item["IAMDatabaseAuthenticationEnabled"] is False
        return {"engine_supported": True, "iam_auth_enabled": False}
    if check == "aws_g6_ecs_all_containers_logging":
        detail = item["Definition"]["taskDefinition"]
        assert item["Definition"]["collection_status"] == "collected" and detail["status"] == "ACTIVE"
        bad = sum(not c.get("logConfiguration", {}).get("logDriver") for c in detail["containerDefinitions"])
        assert bad > 0
        return {"detail_collected": True, "task_active": True, "containers_without_log_driver_count": bad}
    if check == "aws_route53_hosted_zone_dnssec_enabled":
        detail = item["DNSSEC"]
        assert item["Config"]["PrivateZone"] is False and detail["collection_status"] == "collected"
        assert detail["Status"]["ServeSignature"] == "NOT_SIGNING"
        return {"public_zone": True, "dnssec_detail_collected": True, "not_signing": True,
                "active_key_count": sum(k["Status"] == "ACTIVE" for k in detail["KeySigningKeys"])}
    if check == "aws_nist_cloudtrail_trail_logs_encrypted_with_kms_cmk":
        status = item["Status"]
        assert status["collection_status"] == "collected" and status["IsLogging"] is True
        assert evidence["trail_customer_key_enabled"] is False or evidence["destination_customer_key_enabled"] is False
        return {"trail_status_collected": True, "trail_logging": True,
                "trail_customer_key_enabled": evidence["trail_customer_key_enabled"],
                "destination_log_group_present": evidence["destination_log_group_present"],
                "destination_customer_key_enabled": evidence["destination_customer_key_enabled"]}
    if check == "aws.claude_a.s3.prowler_acl_disabled":
        detail = item["OwnershipControls"]
        assert detail["collection_status"] == "empty" and detail["absent"] is True
        return {"documented_absent_ownership_controls": True}
    if check == "aws_sns_delivery_failure_alarm_present":
        attrs = item["Attributes"]
        assert attrs["collection_status"] == "collected" and int(attrs["Attributes"]["SubscriptionsConfirmed"]) > 0
        pages = index["collections"]["cloudwatch_alarm"]
        assert len(pages) == 1 and pages[0]["status"] in ("collected", "empty")
        assert evidence["matching_alarm_arns"] == []
        return {"topic_attributes_collected": True, "confirmed_subscriber_count_positive": True,
                "alarm_inventory_complete": True, "matching_alarm_count": 0}
    if check == "aws.cb.rds.instance_multi_az_non_aurora":
        assert "aurora" not in item["Engine"].lower() and item["MultiAZ"] is False
        return {"aurora_engine": False, "multi_az": False}
    if check == "aws.claude_a.ec2.instance_ebs_delete_on_termination":
        count = sum(m.get("Ebs", {}).get("DeleteOnTermination") is False for m in item["BlockDeviceMappings"])
        assert count > 0
        return {"explicit_false_ebs_mapping_count": count}
    raise AssertionError(check)


def run(args):
    inputs = {name: Path(getattr(args, name)) for name in ("snapshot", "pre_ai", "common", "arm", "candidate")}
    with gzip.open(inputs["snapshot"]) as stream:
        snapshot = json.load(stream)
    with gzip.open(inputs["pre_ai"]) as stream:
        pre = json.load(stream)
    common = json.loads(inputs["common"].read_text())
    arm = json.loads(inputs["arm"].read_text())
    candidate = json.loads(inputs["candidate"].read_text())
    assert len(candidate["checks"]) == 245
    selected_ids = {x["check_id"] for x in candidate["checks"]}
    candidate_by_id = {x["check_id"]: x for x in candidate["checks"]}
    for check, missing in MANIFEST_APPLICABILITY_GAP.items():
        declared = {f["field_path"] for f in candidate_by_id[check]["deterministic_evidence"]["source_fields"]}
        assert not declared.intersection(missing)
    staged = {x["id"]: x for x in common["hardening"]}
    reviews = [r for r in arm["reviews"] if staged[r["finding_id"]]["check_id"] in selected_ids and r["verdict"] != "FAIL"]
    assert len(reviews) == 60 and Counter(staged[r["finding_id"]]["check_id"] for r in reviews) == Counter({k: v[0] for k, v in EXPECTED.items()})
    pre_obs = {o["id"]: o for g in pre["findings"] for o in g.get("observations", [g])}
    checks = {x.id: x for x in CHECKS}
    collections = defaultdict(list)
    for c in snapshot["collections"]:
        collections[c["type"]].append(c)
    launch = {}
    for path in inputs["arm"].parent.glob("launch-*/findings.json"):
        launch.update({x["id"]: x for x in json.loads(path.read_text())["items"]})
    rows, counts, unsafe_probes = [], Counter(), Counter()
    for review in reviews:
        rid = review["finding_id"]
        row = staged[rid]
        check = row["check_id"]
        meta = checks[check]
        assert pre_obs[rid]["status"] == "FAIL" and launch[rid]["check_id"] == check
        scope = row["scope"]
        found = [(c, item) for c in collections[meta.kind] if c["scope"] in (scope, scope.split("/")[0] + "/global") for item in c["items"] if item.get("id") == row["native_resource_id"]]
        assert len(found) == 1
        col, item = found[0]
        assert col["status"] == "collected"
        index = {"context": {"provider": "aws", "scope": scope, "created_at": snapshot["created_at"], "metadata": snapshot["metadata"]}, "collections": {}}
        deps = set([meta.kind] + list(meta.dependencies))
        if check == "aws_nist_cloudtrail_trail_logs_encrypted_with_kms_cmk":
            deps.update(("kms_key", "log_group"))
        if check == "aws_sns_delivery_failure_alarm_present":
            deps.add("cloudwatch_alarm")
        for kind in deps:
            pages = [c for c in collections[kind] if c["scope"] in (scope, scope.split("/")[0] + "/global")]
            index["collections"][kind] = pages
            index[kind] = [{"data": x, "type": kind, "scope": p["scope"], "provider": "aws"} for p in pages for x in p["items"]]
        verdict, evidence = evaluate_check(check, item, index)
        assert verdict == "FAIL"
        proof = facts(check, item, snapshot, index, evidence)
        if check in ("aws_g6_ecs_all_containers_logging", "aws.claude_a.s3.prowler_acl_disabled"):
            mutated = copy.deepcopy(item)
            if check == "aws_g6_ecs_all_containers_logging":
                mutated["Definition"].pop("collection_status")
            else:
                mutated["OwnershipControls"] = {"OwnershipControls": {"Rules": [{"ObjectOwnership": "ObjectWriter"}]}}
            probe_index = copy.deepcopy(index)
            probe_pages = probe_index["collections"][meta.kind]
            for page in probe_pages:
                page["items"] = [mutated if x.get("id") == item.get("id") else x for x in page["items"]]
            probe_index[meta.kind] = [{"data": x, "type": meta.kind, "scope": page["scope"], "provider": "aws"} for page in probe_pages for x in page["items"]]
            assert evaluate_check(check, mutated, probe_index)[0] == "FAIL"
            unsafe_probes[check] += 1
        assert all(isinstance(x, dict) and "data" not in x for x in launch[rid]["supporting_resources"])
        rows.append({"check_id": check, "finding_id": rid, "snapshot_item_sha256": canonical_hash(item),
                     "hosted_verdict": review["verdict"], "pre_ai_native_verdict": "FAIL", "snapshot_re_evaluation": "FAIL",
                     "recorded_branch_facts": proof, "staged_evidence_keys": sorted(row["evidence"]),
                     "staged_supporting_resources_have_native_data": False})
        counts[check] += 1
    result = {"schema_version": 1, "status": "inactive_hosted245_exact_row_audit",
              "inputs_sha256": {k: sha(v) for k, v in inputs.items()}, "selected_check_count": 245,
              "non_fail_review_count": 60, "native_fail_re_evaluation_count": 60,
              "rows": sorted(rows, key=lambda r: (r["check_id"], r["finding_id"])),
              "checks": [{"check_id": check, "non_fail_count": n, "snapshot_native_fail_count": counts[check],
                          "source_refs": refs.split(";"),
                          "source_file_sha256": {ref.split(":")[0]: sha(Path(args.source) / ref.split(":")[0]) for ref in refs.split(";")},
                          "future_path_verdict": future,
                          "future_path_reason": FUTURE_REASON[check],
                          "candidate_manifest_omitted_applicability_fields": MANIFEST_APPLICABILITY_GAP.get(check, []),
                          "missing_detail_status_synthetic_fail_count": unsafe_probes[check],
                          "disposition": ("drop_from_global_candidate_pending_evaluator_fix_and_reproof"
                                          if future != "future_fail_closed" else
                                          "retain_in_inactive_candidate; prompt must carry recorded applicability and decisive facts")}
                         for check, (n, refs, future) in EXPECTED.items()],
              "adjudication": "All 60 exact 992 native FAIL rows are supported by recorded API facts and reproduce FAIL. Hosted non-FAIL reviews saw compact staged evidence without native supporting data. Two check IDs admit future FAIL with missing nested detail status and must leave the global candidate pending evaluator fixes.",
              "limits": "Future-path verdict is based on evaluator guards and collector omission semantics; it does not qualify hosted replay or activate the manifest."}
    Path(args.output).write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    for name in ("snapshot", "pre_ai", "common", "arm", "candidate", "source", "output"):
        parser.add_argument("--" + name.replace("_", "-"), required=True)
    run(parser.parse_args())
