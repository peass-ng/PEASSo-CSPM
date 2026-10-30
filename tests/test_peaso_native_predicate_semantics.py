"""Regression cases for native facts that previously produced misleading PASS/FAIL."""
from __future__ import annotations

import copy

from peaso.checks import CHECKS
from peaso.checks.fixtures import CASES
from peaso.checks import claude_aws_a, claude_aws_b, claude2_aws_b  # noqa: F401 - register ports


CHECK = {check.id: check for check in CHECKS}


def status(cid, item, index=None):
    return CHECK[cid].evaluate(copy.deepcopy(item), copy.deepcopy(index or {}))[0]


def cloudtrail_index(*, advanced=None, basic=None, logging=True, region="us-east-1"):
    source = CASES["aws.cb.lambda.cloudtrail_data_events"]["pass_index"]
    index = copy.deepcopy(source)
    trail = index["cloudtrail"][0]["data"]
    trail["Status"] = {"IsLogging": logging}
    trail["HomeRegion"] = region
    trail["EventSelectors"] = {"EventSelectors": basic or [], "AdvancedEventSelectors": advanced or []}
    return index


def advanced(*fields):
    return [{"FieldSelectors": [{"Field": name, "Equals": [value]} for name, value in fields]}]


def test_lambda_cloudtrail_requires_data_resource_invoke_scope_and_logging():
    cid = "aws.cb.lambda.cloudtrail_data_events"
    item = CASES[cid]["pass"]
    arn = item["FunctionArn"]
    valid = advanced(("eventCategory", "Data"), ("resources.type", "AWS::Lambda::Function"),
                     ("resources.ARN", arn), ("eventName", "Invoke"))
    assert status(cid, item, cloudtrail_index(advanced=valid)) == "PASS"
    assert status(cid, item, cloudtrail_index(advanced=valid, logging=False)) == "FAIL"
    assert status(cid, item, cloudtrail_index(advanced=valid, region="us-west-2")) == "FAIL"
    # A field named eventName cannot stand in for mandatory category/type; the
    # incomplete selector is malformed, so it is UNKNOWN rather than PASS.
    assert status(cid, item, cloudtrail_index(advanced=advanced(("eventName", "AWS::Lambda::Function")))) == "UNKNOWN"
    for selectors in (
        advanced(("eventCategory", "Management"), ("resources.type", "AWS::Lambda::Function")),
        advanced(("eventCategory", "Data"), ("resources.type", "AWS::S3::Object")),
        advanced(("eventCategory", "Data"), ("resources.type", "AWS::Lambda::Function"),
                 ("resources.ARN", "arn:aws:lambda:us-east-1:111111111111:function:other")),
        advanced(("eventCategory", "Data"), ("resources.type", "AWS::Lambda::Function"),
                 ("eventName", "DeleteFunction")),
    ):
        assert status(cid, item, cloudtrail_index(advanced=selectors)) == "FAIL"
    missing = cloudtrail_index(advanced=valid)
    del missing["cloudtrail"][0]["data"]["Status"]
    assert status(cid, item, missing) == "UNKNOWN"
    malformed = cloudtrail_index(advanced=[{"FieldSelectors": [
        {"Field": "eventCategory", "Equals": ["Data"]},
        {"Field": "resources.type", "Equals": ["AWS::Lambda::Function"]},
        {"Field": "resources.ARN", "UnexpectedOperator": [arn]},
    ]}])
    assert status(cid, item, malformed) == "UNKNOWN"
    malformed["cloudtrail"][0]["data"]["EventSelectors"]["AdvancedEventSelectors"][0]["FieldSelectors"].append(
        {"Field": "resources.type", "Equals": ["AWS::Lambda::Function"]})
    assert status(cid, item, malformed) == "UNKNOWN"
    restricted = advanced(("eventCategory", "Data"), ("resources.type", "AWS::Lambda::Function"),
                          ("userIdentity.arn", "arn:aws:iam::111111111111:role:only-one-caller"))
    assert status(cid, item, cloudtrail_index(advanced=restricted)) == "UNKNOWN"
    assert status(cid, item, cloudtrail_index(advanced=restricted + valid)) == "PASS"
    console_only = advanced(("eventCategory", "Data"), ("resources.type", "AWS::Lambda::Function"),
                            ("sessionCredentialFromConsole", "true"))
    assert status(cid, item, cloudtrail_index(advanced=console_only)) == "UNKNOWN"
    assert status(cid, item, cloudtrail_index(advanced=console_only + valid)) == "PASS"
    wrong_operator = cloudtrail_index(advanced=[{"FieldSelectors": [
        {"Field": "eventCategory", "Equals": ["Data"]},
        {"Field": "resources.type", "Equals": ["AWS::Lambda::Function"], "NotEquals": ["AWS::S3::Object"]},
    ]}])
    assert status(cid, item, wrong_operator) == "UNKNOWN"
    wrong_operator["cloudtrail"][0]["data"]["EventSelectors"]["AdvancedEventSelectors"][0]["FieldSelectors"][0]["Equals"] = []
    assert status(cid, item, wrong_operator) == "UNKNOWN"


def test_lambda_basic_selector_accepts_account_prefix_but_not_wrong_account_or_qualifier():
    cid = "aws.cb.lambda.cloudtrail_data_events"
    item = CASES[cid]["pass"]
    arn = item["FunctionArn"]
    def basic(value):
        return cloudtrail_index(basic=[{"ReadWriteType": "All", "DataResources": [
            {"Type": "AWS::Lambda::Function", "Values": [value]}]}])
    assert status(cid, item, basic("arn:aws:lambda:us-east-1:111111111111:function:")) == "PASS"
    assert status(cid, item, basic("arn:aws:lambda:us-east-1:222222222222:function:")) == "FAIL"
    assert status(cid, item, basic(arn + ":alias")) == "FAIL"
    assert status(cid, item, cloudtrail_index(basic=[{"ReadWriteType": "ReadOnly", "DataResources": [
        {"Type": "AWS::Lambda::Function", "Values": [arn]}]}])) == "FAIL"


def test_lambda_runtime_lifecycle_is_date_aware_and_custom_is_unassessed():
    cid = "aws.cb.lambda.runtime_not_deprecated_list"
    item = copy.deepcopy(CASES[cid]["pass"])
    def at(runtime, when):
        row = dict(item, Runtime=runtime)
        return status(cid, row, {"context": {"created_at": when}})
    assert at("nodejs16.x", "2024-06-11T00:00:00+00:00") == "PASS"
    assert at("nodejs16.x", "2024-06-12T00:00:00+00:00") == "FAIL"
    assert at("python3.9", "2026-10-12T00:00:00+00:00") == "FAIL"
    assert at("python3.13", "2026-10-12T00:00:00+00:00") == "PASS"
    assert at("nodejs26.x", "2026-10-12T00:00:00+00:00") == "UNKNOWN"
    assert at("python3.10", "2026-10-30T00:00:00+00:00") == "PASS"
    assert at("python3.10", "2026-10-31T00:00:00+00:00") == "FAIL"
    assert at("python3.12", "2027-01-01T00:00:00+00:00") == "PASS"
    assert at("python3.12", "2027-05-01T00:00:00+00:00") == "UNKNOWN"
    assert at("provided.al2023", "2026-10-12T00:00:00+00:00") == "NOT_APPLICABLE"
    assert status(cid, dict(item, PackageType="Image")) == "NOT_APPLICABLE"


def test_guardduty_historical_and_archived_findings_are_not_active_severity_eight():
    cid = "aws.claude_a.guardduty.detector_no_findings"
    item = copy.deepcopy(CASES[cid]["pass"])
    item["FindingIds"]["items"] = ["archived-or-low"]
    assert status(cid, item) == "PASS"
    item["HighSeverityFindingIds"]["items"] = ["active-eight"]
    assert status(cid, item) == "FAIL"
    item["HighSeverityFindingIds"] = {"collection_status": "denied"}
    assert status(cid, item) == "UNKNOWN"


def test_lightsail_rdp_and_nat_routes_are_not_misclassified():
    cid = "aws.cb.lightsail.ssh_rdp_http_world_closed"
    base = copy.deepcopy(CASES[cid]["pass"])
    base["networking"]["ports"] = [{"fromPort": 3389, "toPort": 3389, "protocol": "tcp",
                                    "cidrs": ["0.0.0.0/0"], "ipv6Cidrs": [], "accessType": "public"}]
    assert status(cid, base) == "FAIL"
    base["networking"]["ports"][0]["cidrs"] = ["10.0.0.0/8"]
    assert status(cid, base) == "PASS"
    for cid in ("aws.cb.neptune.no_public_subnet_steampipe", "aws.c2b.elasticache.cluster_public_subnet_prowler"):
        fixture = CASES[cid]
        index = copy.deepcopy(fixture["fail_index"])
        for table in index["route_table"]:
            routes = table["data"]["Routes"]
            for route in routes:
                if route.get("GatewayId", "").startswith("igw-"):
                    route.pop("GatewayId")
                    route["NatGatewayId"] = "nat-1"
        assert status(cid, fixture["pass"], index) == "PASS"
        assert status(cid, fixture["pass"], fixture["fail_index"]) == "FAIL"


def test_msk_latest_uses_cluster_compatible_targets_regardless_of_list_order():
    cid = "aws.cb.kafka.latest_version"
    fixture = CASES[cid]
    index = copy.deepcopy(fixture["index"])
    index["kafka_version"].reverse()
    assert status(cid, fixture["pass"], index) == "PASS"
    assert status(cid, fixture["fail"], index) == "FAIL"
    # The global highest version is not a target for this Standard cluster.
    index["kafka_version"][0]["data"]["Status"] = "DEPRECATED"
    assert status(cid, fixture["pass"], index) == "PASS"
    current = next(row["data"] for row in index["kafka_version"] if row["data"]["Version"] == "3.7.x")
    current["Status"] = "DEPRECATED"
    assert status(cid, fixture["pass"], index) == "FAIL"
    del current["Status"]
    assert status(cid, fixture["pass"], index) == "UNKNOWN"
