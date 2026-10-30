"""Adverse S3 cross-Region replication fixtures for the signed NIST predicate."""
from peaso.checks import evaluate_check
from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot
from peaso.checks import compliance_new_aws_s3  # noqa: F401  (registration side effect)


CHECK_ID = "aws_nist_s3_bucket_cross_region_replication_enabled"
ABSENT = {"collection_status": "empty", "absent": True}


def bucket(name, region=None, rules=None):
    return {
        "Name": name,
        "AccountId": "111111111111",
        "Location": {"collection_status": "collected", "LocationConstraint": region},
        "Replication": ABSENT if rules is None else {
            "collection_status": "collected", "ReplicationConfiguration": {"Rules": rules}},
    }


def rule(destination, status="Enabled"):
    return {"Status": status, "Destination": {"Bucket": f"arn:aws:s3:::{destination}"}}


def scoped(*buckets, status="collected"):
    return {
        "context": {"provider": "aws", "scope": "111111111111/global", "Account": "111111111111",
                    "metadata": {"caller_identities": [
                        {"Account": "111111111111", "Arn": "arn:aws:sts::111111111111:assumed-role/audit/session"}]}},
        "collections": {"bucket": [{"type": "bucket", "scope": "111111111111/global",
                                    "account_id": "111111111111", "global": True,
                                    "status": status, "items": list(buckets)}]},
        "bucket": [{"type": "bucket", "scope": "111111111111/global", "data": item}
                   for item in buckets],
    }


def evaluate(source, index):
    return evaluate_check(CHECK_ID, source, index)


def test_cross_region_requires_enabled_rule_and_resolved_different_destination():
    source = bucket("source-example", None, [rule("destination-example")])
    other = bucket("destination-example", "eu-west-1")
    assert evaluate(source, scoped(source, other))[0] == "PASS"
    assert evaluate(source, scoped(source, bucket("destination-example")))[0] == "FAIL"
    absent = bucket("source-example", None)
    assert evaluate(absent, scoped(absent))[0] == "FAIL"
    disabled = bucket("source-example", None, [rule("destination-example", "Disabled")])
    assert evaluate(disabled, scoped(disabled))[0] == "FAIL"
    # The older Prowler check additionally reads versioning; this signed
    # predicate is restricted to the replication rule and destination Region.


def test_unresolved_region_or_incomplete_inventory_never_passes_or_fails_safe():
    source = bucket("source-example", None, [rule("external-destination")])
    assert evaluate(source, scoped(source))[0] == "UNKNOWN"
    same = bucket("same-region", None)
    source["Replication"]["ReplicationConfiguration"]["Rules"].append(rule("same-region"))
    assert evaluate(source, scoped(source, same))[0] == "UNKNOWN"
    assert evaluate(source, scoped(source, status="partial"))[0] == "UNKNOWN"
    assert evaluate(source, {})[0] == "UNKNOWN"
    source["Replication"] = {"collection_status": "denied"}
    assert evaluate(source, scoped(source))[0] == "UNKNOWN"
    source["Replication"] = {"collection_status": "empty"}
    assert evaluate(source, scoped(source))[0] == "UNKNOWN"


def test_malformed_or_unknown_rules_and_locations_are_unknown():
    source = bucket("source-example", None, [rule("destination-example", "FutureState")])
    destination = bucket("destination-example", "eu-west-1")
    assert evaluate(source, scoped(source, destination))[0] == "UNKNOWN"
    source["Replication"]["ReplicationConfiguration"]["Rules"] = [rule("destination-example")]
    destination["Location"] = {"collection_status": "denied"}
    assert evaluate(source, scoped(source, destination))[0] == "UNKNOWN"
    source["Replication"]["ReplicationConfiguration"]["Rules"] = [{"Status": "Enabled", "Destination": {"Bucket": "bad-arn"}}]
    assert evaluate(source, scoped(source, destination))[0] == "UNKNOWN"
    source["Replication"]["ReplicationConfiguration"]["Rules"] = "bad-list"
    assert evaluate(source, scoped(source, destination))[0] == "UNKNOWN"


def test_bucket_join_requires_same_account_partition_and_authoritative_scope():
    source = bucket("source-example", None, [rule("destination-example")])
    destination = bucket("destination-example", "eu-west-1")
    assert evaluate(source, scoped(source, destination))[0] == "PASS"

    foreign = bucket("destination-example", "eu-west-1")
    foreign["AccountId"] = "222222222222"
    assert evaluate(source, scoped(source, foreign))[0] == "UNKNOWN"

    other_partition = bucket("source-example", None, [
        {"Status": "Enabled", "Destination": {"Bucket": "arn:aws-cn:s3:::destination-example"}}])
    assert evaluate(other_partition, scoped(other_partition, destination))[0] == "UNKNOWN"

    duplicated = scoped(source, destination)
    duplicated["collections"]["bucket"].append(dict(duplicated["collections"]["bucket"][0]))
    assert evaluate(source, duplicated)[0] == "UNKNOWN"

    bad_scope = scoped(source, destination)
    bad_scope["collections"]["bucket"][0]["account_id"] = "222222222222"
    assert evaluate(source, bad_scope)[0] == "UNKNOWN"

    no_identity = scoped(source, destination)
    no_identity["context"]["metadata"]["caller_identities"] = []
    assert evaluate(source, no_identity)[0] == "UNKNOWN"

    divergent_source = bucket("source-example", None, [rule("destination-example")])
    divergent_source["Location"]["LocationConstraint"] = "ap-south-1"
    assert evaluate(divergent_source, scoped(source, destination))[0] == "UNKNOWN"


def test_unrecognized_status_cannot_be_hidden_by_same_region_rule():
    source = bucket("source-example", None, [rule("same-region"), rule("unknown-destination", "FutureState")])
    same = bucket("same-region", None)
    assert evaluate(source, scoped(source, same))[0] == "UNKNOWN"


def test_production_engine_scoped_index_preserves_collector_authority_metadata():
    source = bucket("source-example", None, [rule("destination-example")])
    destination = bucket("destination-example", "eu-west-1")
    snapshot = make_snapshot(
        "aws", ["111111111111/us-east-1"],
        [{"type": "bucket", "scope": "111111111111/global", "service": "s3",
          "status": "collected", "account_id": "111111111111", "global": True,
          "items": [source, destination]}],
        created_at="2026-10-12T05:00:00+00:00",
        metadata={"caller_identities": [
            {"Account": "111111111111", "Arn": "arn:aws:sts::111111111111:assumed-role/audit/session"}]})
    report = evaluate_snapshot(snapshot, categories=["hardening"], checks=[CHECK_ID])
    findings = [f for f in report["findings"] if f["check_id"] == CHECK_ID]
    assert len(findings) == 2
    assert {f["evidence"].get("source_bucket"): f["status"] for f in findings} == {
        "source-example": "PASS", "destination-example": "FAIL"}
