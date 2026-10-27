"""Sanitized, fail-closed audit of hosted 84-arm applicability downgrades."""

import argparse
import gzip
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path

from peaso.checks import evaluate_check


EXPECTED = {
    "aws.a.iam.active_key_age_90": ("iam_access_key", 20, ("Status", "CreateDate"), "peaso/checks/aws_a_iam_lifecycle.py:25-35"),
    "aws_g6_ecs_all_containers_logging": ("ecs_task_definition", 2, ("Definition.collection_status", "Definition.taskDefinition.status", "Definition.taskDefinition.containerDefinitions"), "peaso/checks/batch_remaining_aws.py:226-239"),
    "aws_lambda_code_signing_configured": ("lambda_function", 2, ("Configuration.State", "PackageType", "Configuration.PackageType", "CodeSigning.collection_status"), "peaso/checks/batch_remaining_aws.py:559-603"),
    "aws_nist_cloudtrail_trail_logs_encrypted_with_kms_cmk": ("cloudtrail", 2, ("Status.collection_status", "Status.IsLogging"), "peaso/checks/batch_remaining_aws.py:1072-1134"),
    "aws_route53_hosted_zone_dnssec_enabled": ("route53_zone", 2, ("Config.PrivateZone", "DNSSEC.collection_status"), "peaso/checks/batch_remaining_aws.py:543-557"),
    "aws_sns_delivery_failure_alarm_present": ("sns_topic", 1, ("Attributes.collection_status", "Attributes.Attributes.SubscriptionsConfirmed"), "peaso/checks/batch_remaining_aws.py:1055-1070"),
}


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def field(row, path):
    for part in path.split("."):
        assert isinstance(row, dict) and part in row, path
        row = row[part]
    return row


def run(args):
    paths = {name: Path(getattr(args, name)) for name in ("snapshot", "pre_ai", "common", "arm")}
    source = Path(args.source)
    with gzip.open(paths["snapshot"]) as stream:
        snapshot = json.load(stream)
    with gzip.open(paths["pre_ai"]) as stream:
        pre_ai = json.load(stream)
    common = json.loads(paths["common"].read_text())
    arm = json.loads(paths["arm"].read_text())
    native_ids = set(common["native_ids"])
    staged = {row["id"]: row for row in common["hardening"]}
    assert len(staged) == 16113 and len(native_ids) == 7971
    downgraded = [r for r in arm["reviews"] if r["finding_id"] in native_ids and r["verdict"] != "FAIL"]
    assert len(downgraded) == 29
    assert Counter(staged[r["finding_id"]]["check_id"] for r in downgraded) == Counter({k: v[1] for k, v in EXPECTED.items()})
    assert all(r["verdict"] == "UNKNOWN" for r in downgraded)

    observations = {}
    for group in pre_ai["findings"]:
        for obs in group.get("observations", [group]):
            observations[obs["id"]] = obs
    collections = {(c["type"], c["scope"]): c for c in snapshot["collections"]}
    launch_rows = {}
    for path in paths["arm"].parent.glob("launch-*/findings.json"):
        for row in json.loads(path.read_text())["items"]:
            launch_rows[row["id"]] = row
    assert all(r["finding_id"] in launch_rows for r in downgraded)

    counts = defaultdict(Counter)
    for review in downgraded:
        rid = review["finding_id"]
        stage = staged[rid]
        pre = observations[rid]
        launch = launch_rows[rid]
        check = stage["check_id"]
        kind, _, fields, _ = EXPECTED[check]
        assert pre["status"] == "FAIL" and pre["check_id"] == check
        assert launch["check_id"] == check
        collection = collections[(kind, stage["scope"])]
        assert collection["status"] == "collected"
        matches = [item for item in collection["items"] if item.get("id") == stage["native_resource_id"]]
        assert len(matches) == 1
        item = matches[0]
        for path in fields:
            value = field(item, path)
            assert value is not None
            assert path.split(".")[-1] not in stage["evidence"]
            assert path.split(".")[-1] not in launch["evidence"]
        assert all(isinstance(x, dict) and not ({"data", "Status", "Config", "Attributes", "Definition", "CodeSigning"} & x.keys()) for x in launch["supporting_resources"])
        if check == "aws.a.iam.active_key_age_90":
            assert item["Status"] == "Active"
        elif check == "aws_g6_ecs_all_containers_logging":
            assert item["Definition"]["taskDefinition"]["status"] == "ACTIVE"
        elif check == "aws_lambda_code_signing_configured":
            assert item["Configuration"]["State"] == "Active"
            assert item["PackageType"] == item["Configuration"]["PackageType"] == "Zip"
        elif check == "aws_nist_cloudtrail_trail_logs_encrypted_with_kms_cmk":
            assert item["Status"]["IsLogging"] is True
        elif check == "aws_route53_hosted_zone_dnssec_enabled":
            assert item["Config"]["PrivateZone"] is False
        elif check == "aws_sns_delivery_failure_alarm_present":
            assert int(item["Attributes"]["Attributes"]["SubscriptionsConfirmed"]) > 0
        deps = [kind]
        if check == "aws_nist_cloudtrail_trail_logs_encrypted_with_kms_cmk":
            deps += ["kms_key", "log_group"]
        elif check == "aws_sns_delivery_failure_alarm_present":
            deps += ["cloudwatch_alarm"]
        index = {"context": {"provider": "aws", "scope": stage["scope"], "created_at": snapshot["created_at"], "metadata": snapshot["metadata"]}, "collections": {}}
        for dep in deps:
            c = collections[(dep, stage["scope"])]
            index["collections"][dep] = [c]
            index[dep] = [{"data": x, "type": dep, "scope": stage["scope"], "provider": "aws"} for x in c["items"]]
        assert evaluate_check(check, item, index)[0] == "FAIL"
        counts[check]["snapshot_applicable"] += 1
        counts[check]["staged_applicability_omitted"] += 1
        counts[check]["native_re_evaluation_fail"] += 1

    check_rows = []
    for check, (kind, expected, fields, predicate) in EXPECTED.items():
        assert counts[check] == Counter(snapshot_applicable=expected, staged_applicability_omitted=expected, native_re_evaluation_fail=expected)
        source_path = source / predicate.split(":")[0]
        check_rows.append({"check_id": check, "downgrade_unknown_count": expected,
                           "resource_kind": kind, "snapshot_applicability_fields": list(fields),
                           "staged_evidence_omits_applicability_count": expected,
                           "native_snapshot_re_evaluation_fail_count": expected,
                           "evaluator_path": predicate, "evaluator_file_sha256": digest(source_path),
                           "assessment": "snapshot supports native FAIL; staged AI input omits applicability fields"})
    result = {"schema_version": 1, "status": "inactive_source_audit", "inputs_sha256": {name: digest(path) for name, path in paths.items()},
              "total_unknown_downgrades": len(downgraded), "checks": check_rows,
              "caveats": ["Lambda evaluator permits missing package type as a future-path FAIL; require an explicit Zip guard before global admission.",
                          "This audit verifies exact 992 rows and staged payloads; it does not measure hosted model behavior after prompt repair."]}
    Path(args.output).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    for name in ("snapshot", "pre_ai", "common", "arm", "source", "output"):
        parser.add_argument("--" + name.replace("_", "-"), required=True)
    run(parser.parse_args())
