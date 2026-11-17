"""A managed policy used only as a permissions boundary grants nothing."""
from __future__ import annotations

import peaso.engine  # noqa: F401  registers every native check
from peaso.checks import CHECKS, evaluate_check
from peaso.checks.aws_policy_boundary_usage import POLICY_KINDS, USAGE_CHECKS

ACCOUNT = "123456789012"
SCOPE = ACCOUNT + "/global"
ARN = f"arn:aws:iam::{ACCOUNT}:policy/ci-boundary"
DOCUMENT = {"Version": "2012-10-17", "Statement": [
    {"Effect": "Allow", "Action": "*", "Resource": "*"},
    {"Effect": "Allow", "Action": "kms:Decrypt", "Resource": "*"},
    {"Effect": "Deny", "Action": ["iam:CreateUser", "organizations:*"], "Resource": "*"}]}


def policy(attached, boundary):
    return {"PolicyName": "ci-boundary", "Arn": ARN, "Path": "/", "DefaultVersionId": "v1",
            "AttachmentCount": attached, "PermissionsBoundaryUsageCount": boundary, "IsAttachable": True,
            "PolicyVersionList": [{"VersionId": "v1", "IsDefaultVersion": True, "Document": DOCUMENT}],
            "DefaultDocument": {"collection_status": "collected", "VersionId": "v1", "Document": DOCUMENT},
            "AttachedUsers": [], "AttachedGroups": [], "AttachedRoles": []}


def index(row):
    meta = {"compliance": {"account_id": ACCOUNT, "iam_policy_inventory": {
        "status": "collected", "managed_scope": "All", "inline_complete": True, "account_id": ACCOUNT}}}
    kinds = {"iam_policy": [row], "iam_customer_policy": [row], "iam_user": [], "iam_group": [], "iam_role": []}
    return {"context": {"provider": "aws", "scope": SCOPE, "metadata": meta},
            "collections": {kind: [{"type": kind, "scope": SCOPE, "account_id": ACCOUNT, "global": True,
                                    "status": "collected"}] for kind in kinds},
            **{kind: [{"data": value} for value in values] for kind, values in kinds.items()}}


def grant_checks():
    return [c for c in CHECKS if c.provider == "aws" and c.kind in POLICY_KINDS and c.target == "resource"
            and c.id not in USAGE_CHECKS]


def verdicts(row):
    return {c.id: evaluate_check(c.id, row, index(row))[0] for c in grant_checks()}


def test_boundary_only_policy_fails_no_grant_check():
    row = policy(attached=0, boundary=3)
    results = verdicts(row)
    assert results and not [cid for cid, status in results.items() if status == "FAIL"]
    status, evidence = evaluate_check("aws.iam.no_full_admin", row, index(row))
    assert status == "NOT_APPLICABLE" and evidence["permissions_boundary_usage_count"] == 3


def test_same_policy_attached_as_permissions_still_fails():
    for attached, boundary in ((1, 3), (1, 0), (0, 0)):
        results = verdicts(policy(attached=attached, boundary=boundary))
        assert results["aws.iam.no_full_admin"] == "FAIL"
        assert results["aws.claude_a.iam.custom_policy_no_star_star"] == "FAIL"


def customer_index(row):
    row = dict(row, _provenance={"operation": "iam:ListPolicies", "managed_scope": "Local", "only_attached": False,
                                 "account_id": ACCOUNT, "default_operation": "iam:GetPolicyVersion"})
    return {"context": {"provider": "aws", "scope": SCOPE, "Account": ACCOUNT},
            "collections": {"iam_customer_policy": [{"type": "iam_customer_policy", "scope": SCOPE, "status": "collected",
                                                     "items": [row]}]},
            "iam_customer_policy": [{"type": "iam_customer_policy", "scope": SCOPE, "data": row}]}


def test_account_wide_customer_policy_scans_skip_boundary_only_policies():
    ids = ("aws.nist.all_iam_policies_no_star_star", "aws.nist.all_managed_policies_no_service_wildcard",
           "aws_g6_iam_all_policy_star_star", "aws_fedramp_iam_all_policies_no_admin_star",
           "aws_fedramp_iam_all_policies_no_service_wildcard")
    for cid in ids:
        assert evaluate_check(cid, {"scope": SCOPE}, customer_index(policy(attached=1, boundary=1)))[0] == "FAIL", cid
        assert evaluate_check(cid, {"scope": SCOPE}, customer_index(policy(attached=0, boundary=1)))[0] == "PASS", cid


def test_boundary_usage_still_counts_as_policy_use():
    row = policy(attached=0, boundary=2)
    assert evaluate_check("aws.claude_a.iam.custom_policy_in_use", row, index(row))[0] == "PASS"
