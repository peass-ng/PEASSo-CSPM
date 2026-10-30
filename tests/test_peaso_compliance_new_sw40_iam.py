"""Isolated signed IAM sw40 predicates."""
from __future__ import annotations

import copy
import pytest

from peaso.checks import CHECKS, evaluate_check
from peaso.checks import compliance_new_sw40 as sw40

ACCOUNT = "123456789012"
SCOPE = ACCOUNT + "/global"
ARN = "arn:aws:iam::" + ACCOUNT + ":policy/Example"
USER = "arn:aws:iam::" + ACCOUNT + ":user/Alice"
GROUP = "arn:aws:iam::" + ACCOUNT + ":group/Ops"
ROLE = "arn:aws:iam::" + ACCOUNT + ":role/Worker"


def teardown_module():
    CHECKS[:] = [c for c in CHECKS if c.id not in sw40.SPECS]


def policy(action="s3:GetObject", resource="arn:aws:s3:::example/object", **extra):
    statement = {"Effect": "Allow", "Action": action, "Resource": resource, **extra}
    return {"Arn": ARN, "DefaultVersionId": "v1", "PolicyVersionList": [{"VersionId": "v1", "IsDefaultVersion": True,
        "Document": {"Statement": [statement]}}],
        "AttachedUsers": [], "AttachedGroups": [], "AttachedRoles": []}


def index(row=None, *, status="collected", coverage=True):
    row = policy() if row is None else row
    meta = {"compliance": {"account_id": ACCOUNT,
        "iam_policy_inventory": {"status": "collected", "managed_scope": "All",
            "inline_complete": True, "account_id": ACCOUNT}}} if coverage else {}
    kinds = {"iam_policy": [row], "iam_user": [], "iam_group": [], "iam_role": []}
    return {"context": {"provider": "aws", "scope": SCOPE, "metadata": meta},
        "collections": {kind: [{"type": kind, "scope": SCOPE, "account_id": ACCOUNT,
            "global": True, "status": status}] for kind in kinds},
        **{kind: [{"data": value} for value in values] for kind, values in kinds.items()}}


def status(cid, row, facts=None):
    return evaluate_check(cid, row, index(row) if facts is None else facts)[0]


@pytest.mark.parametrize("cid,mode", [
    ("aws.nist.all_iam_policies_no_star_star", "star"),
    ("aws.nist.all_managed_policies_no_service_wildcard", "service"),
    ("aws_g6_iam_all_policy_star_star", "star"),
    ("aws_nist_iam_policy_no_star_star", "star"),
    ("aws_nist_iam_all_policy_no_service_wild_card", "service"),
    ("aws_g6_iam_all_policy_service_wildcard", "scoped_service"),
])
def test_account_policy_predicates_pass_fail_unknown(cid, mode):
    safe = policy()
    unsafe = policy("*" if mode == "star" else "s3:*",
                    "arn:aws:s3:::example/object" if mode == "scoped_service" else "*")
    assert status(cid, safe, index(safe)["context"]) == "UNKNOWN"  # malformed index
    assert status(cid, safe) == "PASS"
    if cid == "aws.nist.all_managed_policies_no_service_wildcard":
        managed_facts = index(safe)
        del managed_facts["context"]["metadata"]["compliance"]["iam_policy_inventory"]["inline_complete"]
        assert status(cid, safe, managed_facts) == "PASS"
    assert status(cid, unsafe) == "FAIL"
    assert status(cid, unsafe, index(unsafe, status="partial")) == "UNKNOWN"
    assert status(cid, unsafe, index(unsafe, coverage=False)) == "UNKNOWN"
    malformed = policy()
    malformed["PolicyVersionList"][0]["Document"] = {"Statement": ["bad"]}
    assert status(cid, malformed) == "UNKNOWN"
    foreign = index(unsafe)
    foreign["collections"]["iam_policy"][0]["account_id"] = "999999999999"
    assert status(cid, unsafe, foreign) == "UNKNOWN"


def test_policy_attachment_active_user_group_role_and_missing_fact():
    cid = "aws.pci.iam.policy_attached_to_active_principal"
    row = policy()
    assert status(cid, row) == "FAIL"
    row["AttachedUsers"] = [USER]
    facts = index(row)
    facts["iam_user"] = [{"data": {"Arn": USER}}]
    assert status(cid, row, facts) == "PASS"
    row["AttachedUsers"] = []
    row["AttachedGroups"] = [GROUP]
    facts = index(row)
    facts["iam_group"] = [{"data": {"Arn": GROUP, "Users": [{"UserName": "Alice"}]}}]
    facts["iam_user"] = [{"data": {"Arn": USER, "UserName": "Alice"}}]
    assert status(cid, row, facts) == "PASS"
    row["AttachedGroups"] = []
    row["AttachedRoles"] = [ROLE]
    facts = index(row)
    facts["iam_role"] = [{"data": {"Arn": ROLE, "AssumeRolePolicyDocument": {
        "Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole", "Principal": {"AWS": USER}}]}}}]
    assert status(cid, row, facts) == "PASS"
    del row["AttachedRoles"]
    assert status(cid, row) == "UNKNOWN"


def test_customer_policy_all_actions_scoped_resource_and_unknowns():
    cid = "aws.pci.iam.wildcard_action_scoped_resource"
    safe = policy()
    assert status(cid, safe) == "PASS"
    unsafe = policy("*", "arn:aws:s3:::example/object")
    assert status(cid, unsafe) == "FAIL"
    conditioned = policy("*", "arn:aws:s3:::example/object", Condition={"StringEquals": {"aws:PrincipalTag/Team": "ops"}})
    assert status(cid, conditioned) == "FAIL"
    aws_owned = copy.deepcopy(unsafe)
    aws_owned["Arn"] = "arn:aws:iam::aws:policy/Example"
    assert status(cid, aws_owned) == "NOT_APPLICABLE"
    del safe["PolicyVersionList"]
    assert status(cid, safe) == "UNKNOWN"


def test_admin_api_mfa_is_conservative_about_effective_access():
    cid = "aws.pci.iam.nonconsole_mfa_policy"
    safe = policy("iam:*", "*", Condition={"Bool": {"aws:MultiFactorAuthPresent": "true"}})
    assert status(cid, safe) == "PASS"
    unsafe = policy("iam:*", "*")
    assert status(cid, unsafe) == "FAIL"
    malformed = policy("iam:*", "*")
    malformed["PolicyVersionList"][0]["Document"] = "not json"
    assert status(cid, malformed) == "UNKNOWN"



def test_scope_policy_reads_inline_and_aws_managed_defaults():
    cid = "aws.nist.all_iam_policies_no_star_star"
    safe = policy()
    facts = index(safe)
    facts["iam_user"] = [{"data": {"Arn": USER, "UserName": "Alice",
        "UserPolicyList": [{"PolicyName": "InlineAdmin", "PolicyDocument": {
            "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}}]}}]
    assert status(cid, facts["context"], facts) == "FAIL"
    facts["iam_user"][0]["data"]["UserPolicyList"][0]["PolicyDocument"] = {"Statement": []}
    aws_policy = policy("s3:*", "*")
    aws_policy["Arn"] = "arn:aws:iam::aws:policy/Example"
    facts["iam_policy"] = [{"data": aws_policy}]
    assert status("aws.nist.all_managed_policies_no_service_wildcard", facts["context"], facts) == "FAIL"
