"""Account-global resource policies are read once per account, whatever the Region list."""
import json

import pytest

boto3 = pytest.importorskip("boto3")
from botocore.stub import Stubber

from peaso.collectors import aws

ACCOUNT, FOREIGN = "123456789012", "999988887777"
BUCKET_ARN = "arn:aws:s3:::shared-bucket"
ROLE_ARN = f"arn:aws:iam::{ACCOUNT}:role/partner"
# A CloudFront-scope WAF rule group lives at us-east-1, even when that Region is not scanned.
RULE_GROUP_ARN = f"arn:aws:wafv2:us-east-1:{ACCOUNT}:global/rulegroup/shared/abc"
BUCKET_POLICY = {"Version": "2012-10-17", "Statement": [
    {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": BUCKET_ARN + "/*"}]}
TRUST = {"Version": "2012-10-17", "Statement": [
    {"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{FOREIGN}:root"}, "Action": "sts:AssumeRole"}]}
RULE_GROUP_POLICY = {"Version": "2012-10-17", "Statement": [
    {"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{FOREIGN}:root"},
     "Action": ["wafv2:CreateWebACL", "wafv2:UpdateWebACL", "wafv2:PutFirewallManagerRuleGroups"], "Resource": RULE_GROUP_ARN}]}


def _scan(monkeypatch, regions):
    calls = []

    def pages(self, session, service, region, operation, expression, _tokens=None, _page_limit=None, **arguments):
        calls.append((service, operation))
        if (service, operation) == ("s3", "list_buckets"):
            return aws.ReadResult([{"Name": "shared-bucket"}], "collected")
        if (service, operation) == ("iam", "list_roles"):
            return aws.ReadResult([{"Arn": ROLE_ARN, "RoleName": "partner", "AssumeRolePolicyDocument": TRUST}], "collected")
        if (service, operation) == ("wafv2", "list_rule_groups") and arguments.get("Scope") == "CLOUDFRONT":
            calls.append(("wafv2", "list_cloudfront_rule_groups"))
            return aws.ReadResult([{"ARN": RULE_GROUP_ARN, "Name": "shared", "Id": "abc"}], "collected")
        return aws.ReadResult([], "empty")

    def detail(self, session, service, region, operation, *, absent=(), **arguments):
        calls.append((service, operation))
        if (service, operation) == ("s3", "get_bucket_location"):
            return {"collection_status": "collected", "LocationConstraint": None}
        if (service, operation) == ("s3", "get_bucket_policy"):
            return {"collection_status": "collected", "Policy": json.dumps(BUCKET_POLICY)}
        if (service, operation) == ("wafv2", "get_permission_policy") and arguments.get("ResourceArn") == RULE_GROUP_ARN:
            return {"collection_status": "collected", "Policy": json.dumps(RULE_GROUP_POLICY)}
        return {"collection_status": "empty", "absent": True}

    session = boto3.Session(aws_access_key_id="INERT", aws_secret_access_key="INERT", region_name=regions[0])
    sts = session.client("sts", region_name=regions[0])
    monkeypatch.setattr(aws, "_session", lambda auth, region: (session, "fixture"))
    monkeypatch.setattr(aws.Requests, "client", lambda self, _session, service, region: sts)
    monkeypatch.setattr(aws.Requests, "pages", pages)
    monkeypatch.setattr(aws.Requests, "detail", detail)
    with Stubber(sts) as stub:
        stub.add_response("get_caller_identity", {"Account": ACCOUNT,
            "Arn": f"arn:aws:iam::{ACCOUNT}:user/reviewer", "UserId": "AIDAREVIEWER"}, {})
        snapshot = aws.collect({"provider": "aws", "scopes": [ACCOUNT], "auth": {"profile": "fixture"},
            "options": {"regions": list(regions), "retry_attempts": 1, "service_concurrency": 2, "scope_concurrency": 1}},
            ["aws_resource_policy"])
    return snapshot, calls


def _rows(snapshot):
    return [(c["scope"], row["ResourceArn"]) for c in snapshot["collections"]
            if c["type"] == "aws_resource_policy" for row in c["items"]]


def _assessed(snapshot):
    from peaso.analysis import analyze
    from peaso.engine import evaluate_snapshot
    exposure = [f for f in analyze(snapshot)["findings"] if f["check_id"] == "analysis.internet_exposure"
                and f["evidence"].get("exposure_kind") == "external_generic_policy_grant"]
    check = "aws_cis_aws_resource_policy_unrestricted_principal"
    cis = [f for f in evaluate_snapshot(snapshot, checks=[check])["findings"] if f["check_id"] == check]
    return exposure, cis


@pytest.mark.parametrize("regions", [
    ("us-west-2", "eu-west-1", "us-east-1", "ap-south-1"),
    ("eu-west-1", "eu-central-1", "ap-southeast-2"),  # no us-east-1 in the list
])
def test_global_policies_are_read_once_and_reported_once(monkeypatch, regions):
    snapshot, calls = _scan(monkeypatch, regions)
    assert calls.count(("s3", "list_buckets")) == 1
    assert calls.count(("s3", "get_bucket_policy")) == 1
    assert calls.count(("iam", "list_roles")) == 1
    assert calls.count(("wafv2", "list_cloudfront_rule_groups")) == 1
    # Regional families are still read in every scanned Region.
    assert calls.count(("sqs", "list_queues")) == len(regions)
    home = f"{ACCOUNT}/{min(regions)}"
    assert sorted(_rows(snapshot)) == sorted([(home, BUCKET_ARN), (home, ROLE_ARN), (home, RULE_GROUP_ARN)])
    statuses = {c["scope"]: c["status"] for c in snapshot["collections"] if c["type"] == "aws_resource_policy"}
    assert set(statuses) == {f"{ACCOUNT}/{region}" for region in regions}
    assert set(statuses.values()) <= {"collected", "empty"}

    exposure, cis = _assessed(snapshot)
    # One foreign-access result per policy (bucket, role trust, rule group), in the home scope.
    assert len(exposure) == len({f["resource_id"] for f in exposure}) == 3
    assert {(f["scope"], f["status"]) for f in exposure} == {(home, "FAIL")}
    per_policy = sorted((f["resource_name"], f["scope"], f["status"]) for f in cis if f.get("resource_name"))
    assert per_policy == [(ROLE_ARN, home, "PASS"), (BUCKET_ARN, home, "FAIL"), (RULE_GROUP_ARN, home, "PASS")]
